terraform {
  required_version = "= 1.14.7"
  required_providers {
    alicloud = { source = "aliyun/alicloud", version = "= 1.293.0" }
  }
  backend "oss" {}
}
provider "alicloud" { region = var.region }
variable "account_id" { type = string }
variable "region" { type = string }
variable "name_prefix" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,30}$", var.name_prefix))
    error_message = "Use a reviewed deployment prefix."
  }
}
variable "vpc_id" { type = string }
variable "resource_group_id" { type = string }
variable "origins" {
  type = map(object({ zone = string, vswitch_id = string }))
  validation {
    condition     = length(var.origins) == 2 && length(toset([for origin in values(var.origins) : origin.zone])) == 2
    error_message = "Exactly two independent availability zones are required."
  }
}
variable "image_id" {
  description = "Reviewed Ubuntu 24.04 image with patched Nginx, Python 3.12/venv, OpenSSL, sshd and cloud-init; never a mutable latest image selector."
  type        = string
}
variable "instance_type" { type = string }
variable "disk_kms_key_id" { type = string }
variable "admin_public_key" {
  type = string
  validation {
    condition     = can(regex("^ssh-ed25519 [A-Za-z0-9+/=]+( [^\\r\\n]+)?$", trimspace(var.admin_public_key)))
    error_message = "Provide only an Ed25519 public key, never a private key."
  }
}
variable "management_cidrs" {
  type = set(string)
  validation {
    condition     = length(var.management_cidrs) > 0 && alltrue([for cidr in var.management_cidrs : can(cidrnetmask(cidr)) && tonumber(split("/", cidr)[1]) >= 24])
    error_message = "Explicit IPv4 management ranges /24 or narrower are required."
  }
}
variable "ntp_server_ips" {
  description = "Exact IPv4 NTP peers already configured in the reviewed host image."
  type        = set(string)
  validation {
    condition     = length(var.ntp_server_ips) > 0 && alltrue([for ip in var.ntp_server_ips : can(cidrnetmask("${ip}/32"))])
    error_message = "Declare fixed IPv4 NTP servers matching the image configuration."
  }
}
data "alicloud_caller_identity" "deployment" {
  lifecycle {
    postcondition {
      condition     = self.account_id == var.account_id
      error_message = "Cloud account differs from the reviewed publisher account."
    }
  }
}
resource "alicloud_security_group" "publisher" {
  security_group_name = "${var.name_prefix}-workload-identity"
  vpc_id              = var.vpc_id
  inner_access_policy = "Drop"
  resource_group_id   = var.resource_group_id
}
resource "alicloud_security_group_rule" "deny_out" {
  type              = "egress"
  ip_protocol       = "all"
  nic_type          = "intranet"
  policy            = "drop"
  priority          = 100
  port_range        = "-1/-1"
  cidr_ip           = "0.0.0.0/0"
  security_group_id = alicloud_security_group.publisher.id
}
resource "alicloud_security_group_rule" "https" {
  type              = "ingress"
  ip_protocol       = "tcp"
  nic_type          = "intranet"
  policy            = "accept"
  priority          = 10
  port_range        = "443/443"
  cidr_ip           = "0.0.0.0/0"
  security_group_id = alicloud_security_group.publisher.id
}
# IMDSv2 is needed for cloud-init public user_data; this VM has no RAM role.
resource "alicloud_security_group_rule" "metadata" {
  type              = "egress"
  ip_protocol       = "tcp"
  nic_type          = "intranet"
  policy            = "accept"
  priority          = 10
  port_range        = "80/80"
  cidr_ip           = "100.100.100.200/32"
  security_group_id = alicloud_security_group.publisher.id
}
resource "alicloud_security_group_rule" "ntp" {
  for_each          = var.ntp_server_ips
  type              = "egress"
  ip_protocol       = "udp"
  nic_type          = "intranet"
  policy            = "accept"
  priority          = 10
  port_range        = "123/123"
  cidr_ip           = "${each.value}/32"
  security_group_id = alicloud_security_group.publisher.id
}
resource "alicloud_security_group_rule" "ssh" {
  for_each          = var.management_cidrs
  type              = "ingress"
  ip_protocol       = "tcp"
  nic_type          = "intranet"
  policy            = "accept"
  priority          = 10
  port_range        = "22/22"
  cidr_ip           = each.value
  security_group_id = alicloud_security_group.publisher.id
}
resource "alicloud_instance" "publisher" {
  for_each                   = var.origins
  instance_name              = "${var.name_prefix}-identity-${each.key}"
  availability_zone          = each.value.zone
  vswitch_id                 = each.value.vswitch_id
  security_groups            = [alicloud_security_group.publisher.id]
  image_id                   = var.image_id
  instance_type              = var.instance_type
  instance_charge_type       = "PostPaid"
  internet_charge_type       = "PayByTraffic"
  internet_max_bandwidth_out = 5
  system_disk_category       = "cloud_essd"
  system_disk_size           = 40
  system_disk_encrypted      = true
  system_disk_kms_key_id     = var.disk_kms_key_id
  deletion_protection        = true
  force_delete               = false
  spot_strategy              = "NoSpot"
  # cloud-init needs metadata to obtain the public-key-only user_data. No RAM
  # role is attached, so this endpoint has no workload/cloud credentials.
  http_endpoint               = "enabled"
  http_tokens                 = "required"
  http_put_response_hop_limit = 1
  resource_group_id           = var.resource_group_id
  tags                        = { Deployment = var.name_prefix, Role = "public-workload-identity" }
  user_data = base64encode("#cloud-config\n${jsonencode({
    ssh_pwauth = false, disable_root = true,
    users      = [{ name = "platform-admin", shell = "/bin/bash", lock_passwd = true, sudo = ["ALL=(ALL) NOPASSWD:ALL"], ssh_authorized_keys = [trimspace(var.admin_public_key)] }]
  })}\n")
  lifecycle { prevent_destroy = true }
  depends_on = [alicloud_security_group_rule.deny_out, alicloud_security_group_rule.metadata, alicloud_security_group_rule.ssh, alicloud_security_group_rule.https, data.alicloud_caller_identity.deployment]
  # Static origins have no RAM role, cloud token, Kubernetes credentials or API route.
}
output "publisher_origins" {
  value = { for name, instance in alicloud_instance.publisher : name => { id = instance.id, public_ip = instance.public_ip, private_ip = instance.private_ip, zone = var.origins[name].zone } }
}
