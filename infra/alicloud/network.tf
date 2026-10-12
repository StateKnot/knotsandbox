locals {
  roles = ["control", "platform", "kata", "data"]
  tags  = { Product = "sandbox-platform", Environment = var.environment, Deployment = var.name_prefix, ManagedBy = "terraform" }
  subnets = merge([for ri, role in local.roles : {
    for zi, zone in var.availability_zones : "${role}-${zi}" => {
      role = role, zone = zone, cidr = cidrsubnet(var.vpc_cidr, 4, ri * 3 + zi)
    }
  }]...)
  address_ranges = { for c in setunion(var.enterprise_cidrs, var.management_cidrs, var.api_client_cidrs, toset([var.vpc_cidr])) : c => {
    first = sum([for i, octet in split(".", cidrhost(c, 0)) : parseint(octet, 10) * pow(256, 3 - i)])
    last  = sum([for i, octet in split(".", cidrhost(c, -1)) : parseint(octet, 10) * pow(256, 3 - i)])
  } }
}
resource "alicloud_resource_manager_resource_group" "environment" {
  resource_group_name = var.name_prefix
  display_name        = "${var.name_prefix} ${var.environment}"
}
resource "alicloud_vpc" "environment" {
  vpc_name          = var.name_prefix
  cidr_block        = var.vpc_cidr
  resource_group_id = alicloud_resource_manager_resource_group.environment.id
  tags              = local.tags
  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = alltrue([for c in var.enterprise_cidrs : local.address_ranges[c].last < local.address_ranges[var.vpc_cidr].first || local.address_ranges[c].first > local.address_ranges[var.vpc_cidr].last])
      error_message = "The environment VPC overlaps an enterprise network."
    }
    precondition {
      condition     = alltrue([for c in setunion(var.management_cidrs, var.api_client_cidrs) : anytrue([for e in var.enterprise_cidrs : local.address_ranges[c].first >= local.address_ranges[e].first && local.address_ranges[c].last <= local.address_ranges[e].last])])
      error_message = "Management and API clients must be declared enterprise network ranges."
    }
  }
}
resource "alicloud_vswitch" "role" {
  for_each     = local.subnets
  vpc_id       = alicloud_vpc.environment.id
  zone_id      = each.value.zone
  cidr_block   = each.value.cidr
  vswitch_name = "${var.name_prefix}-${each.key}"
  tags         = merge(local.tags, { Role = each.value.role })
}
resource "alicloud_security_group" "nodes" {
  for_each            = toset(["control", "platform", "kata"])
  vpc_id              = alicloud_vpc.environment.id
  security_group_name = "${var.name_prefix}-${each.key}"
  security_group_type = "normal"
  inner_access_policy = "Drop"
  tags                = merge(local.tags, { Role = each.key })
}
# Security groups' implicit egress allow is overridden by an explicit final deny.
resource "alicloud_security_group_rule" "deny_egress" {
  for_each          = alicloud_security_group.nodes
  security_group_id = each.value.id
  type              = "egress"
  ip_protocol       = "all"
  port_range        = "-1/-1"
  nic_type          = "intranet"
  policy            = "drop"
  priority          = 100
  cidr_ip           = "0.0.0.0/0"
}
locals {
  # Cilium VXLAN mode; no flat allow-all VPC rule, no tenant access to host ports.
  peer_flows = concat(
    [for role in ["control", "platform", "kata"] : { source = role, target = "control", protocol = "tcp", port = "6443/6443" }],
    [for role in ["control", "platform", "kata"] : { source = "control", target = role, protocol = "tcp", port = "10250/10250" }],
    [{ source = "control", target = "control", protocol = "tcp", port = "2379/2380" }, { source = "control", target = "platform", protocol = "tcp", port = "8443/8443" }],
    flatten([for source in ["control", "platform", "kata"] : [for target in ["control", "platform", "kata"] : { source = source, target = target, protocol = "udp", port = "8472/8472" }]]),
    # Trusted termination controller to the exact host mTLS gate. Tenants receive
    # no host-port rule; Cilium still isolates sandbox endpoints from node IPs.
    [for port in [9444, 9445] : { source = "platform", target = "kata", protocol = "tcp", port = "${port}/${port}" }]
  )
  peer_rules = { for r in flatten([for i, f in local.peer_flows : [
    { key = "${i}-ingress", role = f.target, peer = f.source, direction = "ingress", protocol = f.protocol, port = f.port },
    { key = "${i}-egress", role = f.source, peer = f.target, direction = "egress", protocol = f.protocol, port = f.port }
  ]]) : r.key => r }
  source_rules = { for r in concat(
    flatten([for role in ["control", "platform", "kata"] : [for c in var.management_cidrs : { key = "ssh-${role}-${c}", role = role, cidr = c, port = "22/22" }]]),
    [for c in setunion(var.management_cidrs, var.load_balancer_health_cidrs) : { key = "kube-${c}", role = "control", cidr = c, port = "6443/6443" }],
    [for c in setunion(var.api_client_cidrs, var.load_balancer_health_cidrs) : { key = "api-${c}", role = "platform", cidr = c, port = "32443/32443" }],
    # Operator enrollment is private and requires the separate client PKI.
    [for c in var.management_cidrs : { key = "nodeguard-${c}", role = "kata", cidr = c, port = "9444/9444" }]
  ) : r.key => r }
  service_egress = { for r in flatten([for role in ["control", "platform", "kata"] : [for k, s in var.egress_services : { key = "${role}-${k}", role = role, service = s }]]) : r.key => r }
}
resource "alicloud_security_group_rule" "peer" {
  for_each                 = local.peer_rules
  security_group_id        = alicloud_security_group.nodes[each.value.role].id
  source_security_group_id = alicloud_security_group.nodes[each.value.peer].id
  type                     = each.value.direction
  ip_protocol              = each.value.protocol
  port_range               = each.value.port
  nic_type                 = "intranet"
  policy                   = "accept"
  priority                 = 10
}
resource "alicloud_security_group_rule" "management" {
  for_each          = local.source_rules
  security_group_id = alicloud_security_group.nodes[each.value.role].id
  type              = "ingress"
  ip_protocol       = "tcp"
  port_range        = each.value.port
  cidr_ip           = each.value.cidr
  nic_type          = "intranet"
  policy            = "accept"
  priority          = 10
}
resource "alicloud_security_group_rule" "services" {
  for_each          = local.service_egress
  security_group_id = alicloud_security_group.nodes[each.value.role].id
  type              = "egress"
  ip_protocol       = each.value.service.protocol
  port_range        = "${each.value.service.port}/${each.value.service.port}"
  cidr_ip           = each.value.service.cidr
  nic_type          = "intranet"
  policy            = "accept"
  priority          = 10
}
