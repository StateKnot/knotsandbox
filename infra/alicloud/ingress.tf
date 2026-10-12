locals {
  entrances = {
    kubernetes = { role = "control", port = 6443, backend_port = 6443, sources = setunion(var.management_cidrs, toset([for k, s in local.subnets : s.cidr if s.role != "data"])) }
    management = { role = "platform", port = 443, backend_port = 32443, sources = var.api_client_cidrs }
  }
}
resource "alicloud_slb_load_balancer" "private" {
  for_each             = local.entrances
  load_balancer_name   = "${var.name_prefix}-${each.key}"
  address_type         = "intranet"
  address_ip_version   = "ipv4"
  vswitch_id           = alicloud_vswitch.role["platform-0"].id
  master_zone_id       = var.availability_zones[0]
  slave_zone_id        = var.availability_zones[1]
  load_balancer_spec   = var.load_balancer_spec
  payment_type         = "PayAsYouGo"
  instance_charge_type = "PayBySpec"
  internet_charge_type = "PayByTraffic"
  delete_protection    = "on"
  resource_group_id    = alicloud_resource_manager_resource_group.environment.id
  tags                 = local.tags
  lifecycle { prevent_destroy = true }
}
resource "alicloud_slb_acl" "private" {
  for_each   = local.entrances
  name       = "${var.name_prefix}-${each.key}"
  ip_version = "ipv4"

}
resource "alicloud_slb_acl_entry_attachment" "source" {
  for_each = { for r in flatten([for key, entrance in local.entrances : [for cidr in entrance.sources : { key = "${key}-${cidr}", entrance = key, cidr = cidr }]]) : r.key => r }
  acl_id   = alicloud_slb_acl.private[each.value.entrance].id
  entry    = each.value.cidr
}
resource "alicloud_security_group_rule" "kubernetes_vip" {
  for_each          = alicloud_security_group.nodes
  security_group_id = each.value.id
  type              = "egress"
  ip_protocol       = "tcp"
  port_range        = "6443/6443"
  cidr_ip           = "${alicloud_slb_load_balancer.private["kubernetes"].address}/32"
  nic_type          = "intranet"
  policy            = "accept"
  priority          = 10
}
resource "alicloud_slb_server_group" "private" {
  for_each         = local.entrances
  load_balancer_id = alicloud_slb_load_balancer.private[each.key].id
  name             = "${var.name_prefix}-${each.key}"
}
resource "alicloud_slb_server_group_server_attachment" "node" {
  for_each        = { for k, node in local.nodes : k => node if node.role != "kata" }
  server_group_id = alicloud_slb_server_group.private[each.value.role == "control" ? "kubernetes" : "management"].id
  server_id       = alicloud_instance.node[each.key].id
  port            = each.value.role == "control" ? 6443 : 32443
  type            = "ecs"
  weight          = 100
}
resource "alicloud_slb_listener" "private" {
  for_each                     = local.entrances
  load_balancer_id             = alicloud_slb_load_balancer.private[each.key].id
  protocol                     = "tcp"
  frontend_port                = each.value.port
  backend_port                 = each.value.backend_port
  bandwidth                    = -1
  server_group_id              = alicloud_slb_server_group.private[each.key].id
  acl_status                   = "on"
  acl_type                     = "white"
  acl_ids                      = [alicloud_slb_acl.private[each.key].id]
  health_check_type            = "tcp"
  healthy_threshold            = 3
  unhealthy_threshold          = 3
  health_check_timeout         = 3
  health_check_interval        = 5
  delete_protection_validation = true
}
