locals {
  nodes = merge([for role in ["control", "platform", "kata"] : merge([for zi, zone in var.availability_zones : {
    for index in range(role == "kata" ? var.kata_nodes_per_zone : 1) : "${role}-${zi}-${index}" => { role = role, zone = zone, subnet = "${role}-${zi}" }
  }]...)]...)
}
resource "alicloud_ecs_key_pair" "operations" {
  key_pair_name     = "${var.name_prefix}-operations"
  public_key        = trimspace(var.ssh_public_key)
  resource_group_id = alicloud_resource_manager_resource_group.environment.id
  tags              = local.tags
}
resource "alicloud_instance" "node" {
  for_each                      = local.nodes
  instance_name                 = "${var.name_prefix}-${each.key}"
  host_name                     = "${var.name_prefix}-${each.key}"
  availability_zone             = each.value.zone
  vswitch_id                    = alicloud_vswitch.role[each.value.subnet].id
  security_groups               = [alicloud_security_group.nodes[each.value.role].id]
  instance_type                 = var.node_skus[each.value.role]
  image_id                      = var.host_image_id
  instance_charge_type          = "PostPaid"
  internet_charge_type          = "PayByTraffic"
  internet_max_bandwidth_out    = 0
  key_name                      = alicloud_ecs_key_pair.operations.key_pair_name
  http_tokens                   = "required"
  http_endpoint                 = "enabled"
  system_disk_category          = "cloud_essd"
  system_disk_size              = each.value.role == "kata" ? 200 : 100
  system_disk_encrypted         = true
  system_disk_kms_key_id        = alicloud_kms_key.data["compute"].id
  system_disk_encrypt_algorithm = "aes-256"
  deletion_protection           = true
  force_delete                  = false
  spot_strategy                 = "NoSpot"
  resource_group_id             = alicloud_resource_manager_resource_group.environment.id
  tags                          = merge(local.tags, { Role = each.value.role })
  # No RAM role on the host. CSI, gateway and fencing use different OIDC SAs.
  # Immutable reviewed images already contain cloud-init/sshd/packages; no curl|sh.
  user_data = base64encode("#cloud-config\n${jsonencode({
    ssh_pwauth = false, disable_root = true,
    users      = [{ name = "platform-admin", shell = "/bin/bash", lock_passwd = true, sudo = ["ALL=(ALL) NOPASSWD:ALL"], ssh_authorized_keys = [trimspace(var.ssh_public_key)] }]
  })}\n")
  lifecycle { prevent_destroy = true }
  depends_on = [alicloud_security_group_rule.deny_egress, alicloud_security_group_rule.peer, alicloud_security_group_rule.management, alicloud_security_group_rule.services]
}
