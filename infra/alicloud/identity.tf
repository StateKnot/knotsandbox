locals {
  # Admission and untrusted Pods receive no RAM role. Trusted file components
  # assume separately scoped data identities; database/Kubernetes grants remain separate.
  workload_subjects = {
    backup-reader  = "system:serviceaccount:sandbox-system:sandbox-backup-controller"
    output-reader  = "system:serviceaccount:sandbox-system:sandbox-api"
    file-upload    = "system:serviceaccount:sandbox-system:sandbox-api"
    file-reader    = "system:serviceaccount:sandbox-system:sandbox-api"
    file-gateway   = "system:serviceaccount:sandbox-system:sandbox-gateway"
    file-cleaner   = "system:serviceaccount:sandbox-system:sandbox-worker"
    gateway        = "system:serviceaccount:sandbox-system:sandbox-gateway"
    backup         = "system:serviceaccount:sandbox-system:sandbox-backup"
    backup-export  = "system:serviceaccount:sandbox-system:sandbox-backup-export"
    restore        = "system:serviceaccount:sandbox-system:sandbox-restore"
    audit          = "system:serviceaccount:sandbox-system:sandbox-audit-archive"
    upload         = "system:serviceaccount:sandbox-system:sandbox-upload"
    csi-controller = "system:serviceaccount:kube-system:sandbox-csi-controller"
    csi-node       = "system:serviceaccount:kube-system:sandbox-csi-node"
    fencing        = "system:serviceaccount:sandbox-system:sandbox-fencing"
    volume-deleter = "system:serviceaccount:sandbox-system:sandbox-volume-deleter"
  }
  object_grants = {
    output-reader = [{ bucket = "output", actions = ["oss:GetObject"], list = false, write = false }]
    file-upload   = [{ bucket = "temporary", actions = ["oss:PutObject", "oss:GetObject"], list = false, write = true }]
    file-reader   = [{ bucket = "temporary", actions = ["oss:GetObject"], list = false, write = false }]
    file-gateway  = [{ bucket = "temporary", actions = ["oss:PutObject", "oss:GetObject"], list = false, write = true }]
    file-cleaner  = [{ bucket = "temporary", actions = ["oss:DeleteObject", "oss:GetObject"], list = false, write = false }]
    gateway       = [{ bucket = "output", actions = ["oss:PutObject", "oss:GetObject"], list = false, write = true }]
    backup        = [{ bucket = "backup", actions = ["oss:PutObject", "oss:GetObject", "oss:DeleteObject", "oss:AbortMultipartUpload", "oss:ListParts"], list = true, write = true }]
    backup-export = [
      { bucket = "backup", actions = ["oss:GetObject", "oss:GetObjectVersion"], list = true, write = false },
      { bucket = "backup-vault", actions = ["oss:PutObject", "oss:GetObject", "oss:AbortMultipartUpload", "oss:ListParts"], list = true, write = true }
    ]
    restore = [{ bucket = "backup-vault", actions = ["oss:GetObject"], list = true, write = false }]
    audit   = [{ bucket = "audit", actions = ["oss:PutObject"], list = false, write = true }]
    upload  = [{ bucket = "temporary", actions = ["oss:PutObject", "oss:GetObject", "oss:DeleteObject", "oss:AbortMultipartUpload", "oss:ListParts"], list = true, write = true }]
  }
  kata_instance_arns = [for k, node in alicloud_instance.node : "acs:ecs:${var.region}:${var.cloud_account_id}:instance/${node.id}" if local.nodes[k].role == "kata"]
  csi_instance_arns  = [for k, node in alicloud_instance.node : "acs:ecs:${var.region}:${var.cloud_account_id}:instance/${node.id}" if contains(["kata", "platform"], local.nodes[k].role)]
  ecs_data_arns      = [for kind in ["disk", "snapshot"] : "acs:ecs:${var.region}:${var.cloud_account_id}:${kind}/*"]
  csi_read_actions   = ["ecs:DescribeDisks", "ecs:DescribeInstanceAttribute", "ecs:DescribeInstanceHistoryEvents", "ecs:DescribeInstances", "ecs:DescribeSnapshots", "ecs:DescribeTags", "ecs:DescribeTaskAttribute", "ecs:DescribeTasks", "ecs:ListTagResources"]
}
resource "alicloud_ims_oidc_provider" "workloads" {
  oidc_provider_name = "${var.name_prefix}-kubernetes"
  issuer_url         = var.workload_oidc.issuer
  client_ids         = [var.workload_oidc.audience]
  fingerprints       = var.workload_oidc.ca_sha1_fingerprints
  description        = "Projected Kubernetes service accounts for ${var.name_prefix}; not customer login identities"
}
resource "alicloud_ram_role" "workload" {
  for_each             = local.workload_subjects
  role_name            = "${var.name_prefix}-${each.key}"
  max_session_duration = 3600
  force                = false
  description          = "Dedicated ${each.key} workload identity"
  assume_role_policy_document = jsonencode({ Version = "1", Statement = [{
    Effect    = "Allow", Action = "sts:AssumeRoleWithOIDC",
    Principal = { Federated = [alicloud_ims_oidc_provider.workloads.arn] },
    Condition = { StringEquals = { "oidc:iss" = var.workload_oidc.issuer, "oidc:aud" = var.workload_oidc.audience, "oidc:sub" = each.value } }
  }] })
  tags = merge(local.tags, { Component = each.key })
}
resource "alicloud_ram_policy" "object_access" {
  for_each    = local.object_grants
  policy_name = "${var.name_prefix}-${each.key}"
  description = "Exact bucket/key permissions; no ACL/policy/retention administration"
  policy_document = jsonencode({ Version = "1", Statement = flatten([for grant in each.value : concat([
    {
      Effect   = "Allow", Action = grant.actions,
      Resource = ["acs:oss:*:*:${alicloud_oss_bucket.data[grant.bucket].bucket}/${contains(["file-upload", "file-reader", "file-gateway", "file-cleaner"], each.key) ? "tenants/*/file-transfers/*/content/*/parts/*" : grant.bucket == "output" ? "tenants/*" : "*"}"]
    },
    {
      Effect   = "Allow", Action = grant.write ? ["kms:GenerateDataKey", "kms:Decrypt"] : ["kms:Decrypt"],
      Resource = [alicloud_kms_key.data[grant.bucket].arn]
    }
    ], grant.list ? [{
      Effect   = "Allow", Action = ["oss:ListObjects", "oss:ListMultipartUploads"],
      Resource = ["acs:oss:*:*:${alicloud_oss_bucket.data[grant.bucket].bucket}"]
  }] : [])]) })
}
resource "alicloud_ram_role_policy_attachment" "object_access" {
  for_each    = local.object_grants
  role_name   = alicloud_ram_role.workload[each.key].role_name
  policy_name = alicloud_ram_policy.object_access[each.key].policy_name
  policy_type = "Custom"
  depends_on = [
    alicloud_oss_bucket_acl.private,
    alicloud_oss_bucket_public_access_block.data,
    alicloud_oss_bucket_server_side_encryption.data,
    alicloud_oss_bucket_policy.transport,
    alicloud_oss_bucket_worm.retention,
  ]
}
# Control-plane verification identity. It cannot copy, restore, write or erase.
resource "alicloud_ram_policy" "backup_reader" {
  policy_name = "${var.name_prefix}-backup-reader"
  policy_document = jsonencode({ Version = "1", Statement = [
    { Effect = "Allow", Action = ["oss:GetObject"], Resource = ["acs:oss:*:*:${alicloud_oss_bucket.data["backup-vault"].bucket}/tenants/*/backups/*/*"] },
    { Effect = "Allow", Action = ["oss:ListObjects"], Resource = ["acs:oss:*:*:${alicloud_oss_bucket.data["backup-vault"].bucket}"], Condition = { StringLike = { "oss:Prefix" = ["tenants/*/backups/*/repository/"] } } },
    { Effect = "Allow", Action = ["kms:Decrypt"], Resource = [alicloud_kms_key.data["backup-vault"].arn] }
  ] })
}
resource "alicloud_ram_role_policy_attachment" "backup_reader" {
  role_name   = alicloud_ram_role.workload["backup-reader"].role_name
  policy_name = alicloud_ram_policy.backup_reader.policy_name
  policy_type = "Custom"
  depends_on  = [alicloud_oss_bucket_worm.retention, alicloud_oss_bucket_policy.transport]
}
resource "alicloud_ram_policy" "fencing" {
  policy_name = "${var.name_prefix}-fencing"
  policy_document = jsonencode({ Version = "1", Statement = [
    { Effect = "Allow", Action = ["ecs:StopInstance"], Resource = local.kata_instance_arns },
    { Effect = "Allow", Action = ["ecs:DescribeInstanceStatus", "ecs:DescribeInstances"], Resource = ["*"] },
    { Effect = "Allow", Action = ["ecs:DescribeDisks"], Resource = ["acs:ecs:${var.region}:${var.cloud_account_id}:disk/*"] }
  ] })
}
resource "alicloud_ram_role_policy_attachment" "fencing" {
  role_name   = alicloud_ram_role.workload["fencing"].role_name
  policy_name = alicloud_ram_policy.fencing.policy_name
  policy_type = "Custom"
}
# This is a deliberately fail-closed subset of upstream disk CSI actions. The
# StorageClass/CSI installer must attach Deployment=<prefix> at resource CREATE;
# it gets no permission to relabel unrelated disks into its own authorization.
# Snapshot groups/NAS/CPFS and control-plane attachment are outside this product.
# Platform attachment is required only for separately retained metrics WAL PVCs.
resource "alicloud_ram_policy" "csi_controller" {
  policy_name = "${var.name_prefix}-csi-controller"
  policy_document = jsonencode({ Version = "1", Statement = [
    { Effect = "Allow", Action = local.csi_read_actions, Resource = ["*"] },
    {
      Effect    = "Allow", Action = ["ecs:CreateDisk", "ecs:CreateSnapshot"], Resource = local.ecs_data_arns,
      Condition = { StringEquals = { "acs:RequestTag/Deployment" = var.name_prefix } }
    },
    {
      Effect    = "Allow", Action = ["ecs:AttachDisk", "ecs:DetachDisk", "ecs:DeleteSnapshot", "ecs:ModifyDiskAttribute", "ecs:ModifyDiskSpec", "ecs:ResizeDisk"], Resource = local.ecs_data_arns,
      Condition = { StringEquals = { "acs:ResourceTag/Deployment" = var.name_prefix } }
    },
    { Effect = "Allow", Action = ["ecs:AttachDisk", "ecs:DetachDisk"], Resource = local.csi_instance_arns },
    { Effect = "Allow", Action = ["kms:GenerateDataKey", "kms:Decrypt"], Resource = [alicloud_kms_key.data["compute"].arn] }
  ] })
}
resource "alicloud_ram_policy" "csi_node" {
  policy_name = "${var.name_prefix}-csi-node"
  policy_document = jsonencode({ Version = "1", Statement = [
    { Effect = "Allow", Action = local.csi_read_actions, Resource = ["*"] }
  ] })
}
resource "alicloud_ram_role_policy_attachment" "csi_controller" {
  role_name   = alicloud_ram_role.workload["csi-controller"].role_name
  policy_name = alicloud_ram_policy.csi_controller.policy_name
  policy_type = "Custom"
}
resource "alicloud_ram_role_policy_attachment" "csi_node" {
  role_name   = alicloud_ram_role.workload["csi-node"].role_name
  policy_name = alicloud_ram_policy.csi_node.policy_name
  policy_type = "Custom"
}

# Physical workspace destruction is separately authorized and accounted. The
# generic ResourceTag condition is documented by AliyunServiceRolePolicyForEskOnEcs.
resource "alicloud_ram_policy" "volume_deleter" {
  policy_name = "${var.name_prefix}-volume-deleter"
  policy_document = jsonencode({ Version = "1", Statement = [
    { Effect = "Allow", Action = ["ecs:DescribeDisks"], Resource = ["acs:ecs:${var.region}:${var.cloud_account_id}:disk/*"] },
    { Effect = "Allow", Action = ["ecs:DeleteDisk", "ecs:ModifyDiskAttribute"], Resource = ["acs:ecs:${var.region}:${var.cloud_account_id}:disk/*"],
    Condition = { StringEquals = { "acs:ResourceTag/Deployment" = var.name_prefix } } }
  ] })
}
resource "alicloud_ram_role_policy_attachment" "volume_deleter" {
  role_name   = alicloud_ram_role.workload["volume-deleter"].role_name
  policy_name = alicloud_ram_policy.volume_deleter.policy_name
  policy_type = "Custom"
}
