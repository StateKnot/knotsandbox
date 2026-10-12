# One-time security-owner bootstrap. Its initially local state is migrated to
# the created backend under a separate prefix after the owner verifies recovery.
terraform {
  required_version = "= 1.14.7"
  required_providers {
    alicloud = { source = "aliyun/alicloud", version = "= 1.293.0" }
  }
}
provider "alicloud" { region = var.region }
variable "region" { type = string }
variable "state_bucket_name" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{5,61}[a-z0-9]$", var.state_bucket_name))
    error_message = "Provide an explicitly approved globally unique state bucket name."
  }
}
variable "lock_instance_name" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,14}$", var.lock_instance_name))
    error_message = "Provide a distinct 3-15 character TableStore instance name."
  }
}
variable "state_operator_role_name" { type = string }
variable "cloud_account_id" { type = string }
resource "alicloud_kms_key" "state" {
  description                     = "Terraform state encryption key"
  key_spec                        = "Aliyun_AES_256"
  status                          = "Enabled"
  automatic_rotation              = "Enabled"
  rotation_interval               = "365d"
  deletion_protection             = "Enabled"
  deletion_protection_description = "Required to recover production infrastructure state"
  pending_window_in_days          = 30
  lifecycle { prevent_destroy = true }
}
resource "alicloud_oss_bucket" "state" {
  bucket          = var.state_bucket_name
  storage_class   = "Standard"
  redundancy_type = "ZRS"
  force_destroy   = false
  lifecycle { prevent_destroy = true }
}
resource "alicloud_oss_bucket_acl" "state" {
  bucket = alicloud_oss_bucket.state.bucket
  acl    = "private"
}
resource "alicloud_oss_bucket_public_access_block" "state" {
  bucket              = alicloud_oss_bucket.state.bucket
  block_public_access = true
}
resource "alicloud_oss_bucket_versioning" "state" {
  bucket = alicloud_oss_bucket.state.bucket
  status = "Enabled"
}
resource "alicloud_oss_bucket_server_side_encryption" "state" {
  bucket            = alicloud_oss_bucket.state.bucket
  sse_algorithm     = "KMS"
  kms_master_key_id = alicloud_kms_key.state.id
}
resource "alicloud_oss_bucket_policy" "state" {
  bucket = alicloud_oss_bucket.state.bucket
  policy = jsonencode({ Version = "1", Statement = [{
    Effect    = "Deny", Principal = ["*"], Action = ["oss:*"],
    Resource  = ["acs:oss:*:*:${var.state_bucket_name}", "acs:oss:*:*:${var.state_bucket_name}/*"],
    Condition = { Bool = { "acs:SecureTransport" = "false" } }
  }] })
}
resource "alicloud_ots_instance" "lock" {
  name          = var.lock_instance_name
  instance_type = "Capacity"
  description   = "Terraform state locking only"
  # Authenticated HTTPS APIs allow bootstrap before the environment VPC exists.
  # This grants no anonymous access and no public read access to state objects.
  network_type_acl   = ["INTERNET", "VPC"]
  network_source_acl = []
  lifecycle { prevent_destroy = true }
}
resource "alicloud_ots_table" "lock" {
  instance_name = alicloud_ots_instance.lock.name
  table_name    = "terraform_locks"
  primary_key {
    name = "LockID"
    type = "String"
  }
  time_to_live = -1
  max_version  = 1
  enable_sse   = true
  sse_key_type = "SSE_KMS_SERVICE"
  lifecycle { prevent_destroy = true }
}
resource "alicloud_ram_policy" "state_operator" {
  policy_name = "${var.lock_instance_name}-state-access"
  policy_document = jsonencode({ Version = "1", Statement = [
    { Effect = "Allow", Action = ["oss:ListObjects"], Resource = ["acs:oss:*:*:${var.state_bucket_name}"] },
    { Effect = "Allow", Action = ["oss:GetObject", "oss:PutObject", "oss:DeleteObject"], Resource = ["acs:oss:*:*:${var.state_bucket_name}/*"] },
    { Effect = "Allow", Action = ["kms:GenerateDataKey", "kms:Decrypt"], Resource = [alicloud_kms_key.state.arn] },
    { Effect = "Allow", Action = ["ots:GetRow", "ots:PutRow", "ots:DeleteRow", "ots:UpdateRow", "ots:DescribeTable"], Resource = ["acs:ots:${var.region}:${var.cloud_account_id}:instance/${var.lock_instance_name}/table/terraform_locks"] }
  ] })
}
resource "alicloud_ram_role_policy_attachment" "state_operator" {
  role_name   = var.state_operator_role_name
  policy_name = alicloud_ram_policy.state_operator.policy_name
  policy_type = "Custom"
  depends_on = [
    alicloud_oss_bucket_acl.state,
    alicloud_oss_bucket_public_access_block.state,
    alicloud_oss_bucket_versioning.state,
    alicloud_oss_bucket_server_side_encryption.state,
    alicloud_oss_bucket_policy.state,
  ]
}
output "backend" {
  value = {
    bucket              = alicloud_oss_bucket.state.bucket, region = var.region,
    tablestore_endpoint = "https://${var.lock_instance_name}.${var.region}.ots.aliyuncs.com",
    tablestore_table    = alicloud_ots_table.lock.table_name,
    # Backend encrypt=true would request AES256 and override bucket SSE-KMS.
    encrypt = false, acl = "private"
  }
}
data "alicloud_caller_identity" "deployment" {
  lifecycle {
    postcondition {
      condition     = self.account_id == var.cloud_account_id
      error_message = "The state bootstrap credentials are for the wrong cloud account."
    }
  }
}
