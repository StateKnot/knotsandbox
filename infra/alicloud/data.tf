locals {
  buckets          = toset(["output", "backup", "backup-vault", "audit", "temporary"])
  retained_buckets = { output = var.object_retention_days.output, audit = var.object_retention_days.audit, backup-vault = var.object_retention_days.backup_vault }
  database_sources = concat([for k, s in local.subnets : s.cidr if s.role == "platform"], sort(tolist(var.management_cidrs)))
}
# Separate regional customer-managed keys. No key material or passwords in state.
# Default KMS keys are a supported provider/API resource; dedicated HSM is not
# implied. RAM grants are key-scoped, rotation and deletion protection explicit.
resource "alicloud_kms_key" "data" {
  for_each                        = setunion(local.buckets, toset(["compute", "database"]))
  description                     = "${var.name_prefix} ${each.key} encryption"
  key_spec                        = "Aliyun_AES_256"
  key_usage                       = "ENCRYPT/DECRYPT"
  origin                          = "Aliyun_KMS"
  protection_level                = "SOFTWARE"
  status                          = "Enabled"
  automatic_rotation              = "Enabled"
  rotation_interval               = "365d"
  pending_window_in_days          = 30
  deletion_protection             = "Enabled"
  deletion_protection_description = "Retained sandbox data and recovery depend on this key"
  tags                            = merge(local.tags, { Purpose = each.key })
  lifecycle { prevent_destroy = true }
}
resource "alicloud_db_instance" "platform" {
  engine                     = "PostgreSQL"
  engine_version             = "17.0"
  target_minor_version       = var.database.minor_version
  category                   = "HighAvailability"
  instance_type              = var.database.instance_type
  instance_storage           = var.database.storage_gib
  db_instance_storage_type   = "cloud_essd"
  instance_charge_type       = "Postpaid"
  zone_id                    = var.availability_zones[0]
  zone_id_slave_a            = var.availability_zones[1]
  vswitch_id                 = join(",", [alicloud_vswitch.role["data-0"].id, alicloud_vswitch.role["data-1"].id])
  security_ips               = local.database_sources
  port                       = "5432"
  ssl_action                 = "Open"
  encryption_key             = alicloud_kms_key.data["database"].id
  deletion_protection        = true
  force_delete               = false
  maintain_time              = var.database.maintenance_time
  auto_upgrade_minor_version = "Manual"
  resource_group_id          = alicloud_resource_manager_resource_group.environment.id
  tags                       = local.tags
  dynamic "pg_hba_conf" {
    for_each = { for index, cidr in local.database_sources : index => cidr }
    content {
      priority_id = tonumber(pg_hba_conf.key) + 1
      type        = "hostssl"
      address     = pg_hba_conf.value
      database    = "all"
      user        = "all"
      method      = "scram-sha-256"
    }
  }
  # Explicit last reject prevents a provider/service default host rule bypass.
  pg_hba_conf {
    priority_id = 10000
    type        = "host"
    address     = "0.0.0.0/0"
    database    = "all"
    user        = "all"
    method      = "reject"
  }
  parameters {
    name  = "password_encryption"
    value = "scram-sha-256"
  }
  lifecycle { prevent_destroy = true }
}
resource "alicloud_security_group_rule" "database" {
  security_group_id = alicloud_security_group.nodes["platform"].id
  type              = "egress"
  ip_protocol       = "tcp"
  port_range        = "5432/5432"
  cidr_ip           = "${alicloud_db_instance.platform.private_ip_address}/32"
  nic_type          = "intranet"
  policy            = "accept"
  priority          = 10
}
resource "alicloud_db_backup_policy" "platform" {
  instance_id                 = alicloud_db_instance.platform.id
  preferred_backup_period     = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
  preferred_backup_time       = "18:00Z-19:00Z"
  backup_retention_period     = var.database.backup_retention_days
  enable_backup_log           = true
  log_backup_retention_period = var.database.backup_retention_days
  released_keep_policy        = "All"
}
resource "alicloud_oss_bucket" "data" {
  for_each          = local.buckets
  bucket            = "${var.name_prefix}-${each.key}"
  storage_class     = "Standard"
  redundancy_type   = "ZRS"
  force_destroy     = false
  resource_group_id = alicloud_resource_manager_resource_group.environment.id
  tags              = merge(local.tags, { Purpose = each.key })
  dynamic "lifecycle_rule" {
    for_each = each.key == "temporary" ? [var.object_retention_days.temporary] : []
    content {
      id      = "expire-temporary-uploads"
      enabled = true
      prefix  = ""
      expiration { days = lifecycle_rule.value }
      abort_multipart_upload { days = 1 }
    }
  }
  # No automatic backup/audit/output expiration: product references and durable
  # manifests must be retired first by their authorized retention controller.
  lifecycle { prevent_destroy = true }
}
resource "alicloud_oss_bucket_acl" "private" {
  for_each = local.buckets
  bucket   = alicloud_oss_bucket.data[each.key].bucket
  acl      = "private"
}
resource "alicloud_oss_bucket_public_access_block" "data" {
  for_each            = local.buckets
  bucket              = alicloud_oss_bucket.data[each.key].bucket
  block_public_access = true
}
resource "alicloud_oss_bucket_server_side_encryption" "data" {
  for_each          = local.buckets
  bucket            = alicloud_oss_bucket.data[each.key].bucket
  sse_algorithm     = "KMS"
  kms_master_key_id = alicloud_kms_key.data[each.key].id
}
resource "alicloud_oss_bucket_versioning" "backup" {
  bucket = alicloud_oss_bucket.data["backup"].bucket
  status = "Enabled"
}
resource "alicloud_oss_bucket_worm" "retention" {
  for_each                 = local.retained_buckets
  bucket                   = alicloud_oss_bucket.data[each.key].bucket
  retention_period_in_days = each.value
  status                   = "Locked"
  lifecycle { prevent_destroy = true }
  depends_on = [alicloud_oss_bucket_server_side_encryption.data, alicloud_oss_bucket_public_access_block.data]
}
resource "alicloud_oss_bucket_policy" "transport" {
  for_each = local.buckets
  bucket   = alicloud_oss_bucket.data[each.key].bucket
  policy = jsonencode({ Version = "1", Statement = [{
    Effect    = "Deny", Principal = ["*"], Action = ["oss:*"],
    Resource  = ["acs:oss:*:*:${alicloud_oss_bucket.data[each.key].bucket}", "acs:oss:*:*:${alicloud_oss_bucket.data[each.key].bucket}/*"],
    Condition = { Bool = { "acs:SecureTransport" = "false" } }
  }] })
}
