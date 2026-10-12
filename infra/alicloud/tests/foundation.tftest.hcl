mock_provider "alicloud" {
  override_during = plan
  mock_data "alicloud_caller_identity" { defaults = { account_id = "1234567890123456" } }
  mock_resource "alicloud_ims_oidc_provider" { defaults = { arn = "acs:ram::1234567890123456:oidc-provider/fixture" } }
  mock_resource "alicloud_kms_key" { defaults = { arn = "acs:kms:cn-hangzhou:1234567890123456:key/fixture", id = "fixture-key" } }
  mock_resource "alicloud_instance" { defaults = { id = "i-fixture", private_ip = "10.240.1.10" } }
  mock_resource "alicloud_slb_load_balancer" { defaults = { address = "10.240.48.10" } }
  mock_resource "alicloud_db_instance" { defaults = { private_ip_address = "10.240.144.10" } }
}
variables {
  region                     = "cn-hangzhou"
  environment                = "preproduction"
  name_prefix                = "sbx-fixture-only"
  availability_zones         = ["cn-hangzhou-i", "cn-hangzhou-j", "cn-hangzhou-k"]
  vpc_cidr                   = "10.240.0.0/16"
  enterprise_cidrs           = ["10.0.0.0/12"]
  management_cidrs           = ["10.1.1.0/24"]
  api_client_cidrs           = ["10.2.0.0/16"]
  host_image_id              = "m-fixture-reviewed-x86"
  node_skus                  = { control = "ecs.g8i.large", platform = "ecs.g8i.xlarge", kata = "ecs.ebmc8i.24xlarge" }
  kata_nodes_per_zone        = 1
  ssh_public_key             = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNoCloudAuthentication fixture"
  egress_services            = { dns = { cidr = "10.1.2.53/32", protocol = "udp", port = 53 }, proxy = { cidr = "10.1.2.10/32", protocol = "tcp", port = 3128 } }
  load_balancer_spec         = "slb.s2.small"
  load_balancer_health_cidrs = ["100.64.0.0/10"]
  database                   = { instance_type = "pg.n2.2c.2m", storage_gib = 100, minor_version = "rds_postgres_1700_fixture", maintenance_time = "18:00Z-19:00Z", backup_retention_days = 30 }
  object_retention_days      = { output = 7, audit = 365, backup_vault = 31, temporary = 1 }
  cloud_account_id           = "1234567890123456"
  workload_oidc              = { issuer = "https://kubernetes-issuer.fixture.invalid", audience = "sts-fixture", ca_sha1_fingerprints = ["1111111111111111111111111111111111111111"] }

}
run "private_ha_foundation" {
  command = plan
  variables { enterprise_cidrs = ["10.0.0.0/12"] }
  assert {
    condition     = length(alicloud_instance.node) == 9 && length(alicloud_vswitch.role) == 12 && alltrue([for n in alicloud_instance.node : n.internet_max_bandwidth_out == 0 && n.http_endpoint == "enabled" && n.http_tokens == "required" && n.system_disk_encrypted && n.deletion_protection && n.password == null])
    error_message = "Three isolated node pools across three zones must remain private, encrypted and passwordless."
  }
  assert {
    condition     = alltrue([for g in alicloud_security_group.nodes : g.inner_access_policy == "Drop"]) && alltrue([for r in alicloud_security_group_rule.deny_egress : r.policy == "drop" && r.priority == 100]) && alltrue([for lb in alicloud_slb_load_balancer.private : lb.address_type == "intranet" && lb.delete_protection == "on"])
    error_message = "Default isolation and private ingress cannot be weakened."
  }
  assert {
    condition     = length([for f in local.peer_flows : f if f.port == "9444/9444"]) == 1 && alltrue([for f in local.peer_flows : f.source == "platform" && f.target == "kata" && f.protocol == "tcp" if f.port == "9444/9444"]) && alltrue([for r in local.source_rules : r.role == "kata" && contains(var.management_cidrs, r.cidr) if r.port == "9444/9444"])
    error_message = "Nodeguard mTLS may be reached only by platform controllers or declared private management ranges."
  }

}
run "reject_overlapping_enterprise_network" {
  variables { enterprise_cidrs = ["10.0.0.0/8"] }
  command         = plan
  expect_failures = [alicloud_vpc.environment]
}
run "reject_public_management" {
  command = plan
  variables { management_cidrs = ["0.0.0.0/0"] }
  expect_failures = [var.management_cidrs]
}
run "reject_non_baremetal_workers" {
  command = plan
  variables { node_skus = { control = "ecs.g8i.large", platform = "ecs.g8i.xlarge", kata = "ecs.g8i.8xlarge" } }
  expect_failures = [var.node_skus]
}
run "reject_two_zone_cluster" {
  command = plan
  variables { availability_zones = ["cn-hangzhou-i", "cn-hangzhou-j", "cn-hangzhou-j"] }
  expect_failures = [var.availability_zones]
}
run "encrypted_data_and_scoped_identity" {
  command = plan
  override_resource {
    override_during = plan
    target          = alicloud_instance.node["kata-0-0"]
    values          = { id = "i-offline-kata-0" }
  }
  override_resource {
    override_during = plan
    target          = alicloud_instance.node["kata-1-0"]
    values          = { id = "i-offline-kata-1" }
  }
  override_resource {
    override_during = plan
    target          = alicloud_instance.node["kata-2-0"]
    values          = { id = "i-offline-kata-2" }
  }
  override_resource {
    override_during = plan
    target          = alicloud_instance.node["platform-0-0"]
    values          = { id = "i-offline-platform-0" }
  }
  override_resource {
    override_during = plan
    target          = alicloud_instance.node["platform-1-0"]
    values          = { id = "i-offline-platform-1" }
  }
  override_resource {
    override_during = plan
    target          = alicloud_instance.node["platform-2-0"]
    values          = { id = "i-offline-platform-2" }
  }
  override_resource {
    override_during = plan
    target          = alicloud_instance.node["control-0-0"]
    values          = { id = "i-offline-control-0" }
  }
  override_resource {
    override_during = plan
    target          = alicloud_instance.node["control-1-0"]
    values          = { id = "i-offline-control-1" }
  }
  override_resource {
    override_during = plan
    target          = alicloud_instance.node["control-2-0"]
    values          = { id = "i-offline-control-2" }
  }
  assert {
    condition     = alicloud_db_instance.platform.category == "HighAvailability" && alicloud_db_instance.platform.zone_id != alicloud_db_instance.platform.zone_id_slave_a && alicloud_db_instance.platform.ssl_action == "Open" && alltrue([for h in alicloud_db_instance.platform.pg_hba_conf : (h.type == "hostssl" && h.method == "scram-sha-256") || (h.type == "host" && h.method == "reject")]) && alicloud_db_backup_policy.platform.enable_backup_log
    error_message = "RDS requires cross-zone HA, SSL-only authenticated rules, default reject, and log backup."
  }
  assert {
    condition     = length(alicloud_oss_bucket.data) == 5 && alltrue([for b in alicloud_oss_bucket.data : !b.force_destroy && b.redundancy_type == "ZRS"]) && alltrue([for e in alicloud_oss_bucket_server_side_encryption.data : e.sse_algorithm == "KMS"]) && alltrue([for b in alicloud_oss_bucket_public_access_block.data : b.block_public_access]) && !contains(keys(alicloud_oss_bucket_worm.retention), "backup") && alicloud_oss_bucket_versioning.backup.status == "Enabled" && alicloud_oss_bucket_worm.retention["backup-vault"].status == "Locked"
    error_message = "Mutable Kopia storage and immutable archive storage must remain isolated, private and encrypted."
  }
  assert {
    condition     = length(alicloud_ram_role.workload) == 16 && alltrue([for name, role in alicloud_ram_role.workload : jsondecode(role.assume_role_policy_document).Statement[0].Condition.StringEquals["oidc:sub"] == local.workload_subjects[name]]) && !contains(keys(alicloud_ram_role.workload), "api") && !contains(keys(alicloud_ram_role.workload), "worker") && !contains(keys(alicloud_ram_role.workload), "admission")
    error_message = "Each cloud capability must trust only its exact service-account subject; no generic API/worker/admission role."
  }
  assert {
    condition     = length(local.csi_instance_arns) == 6 && toset(jsondecode(alicloud_ram_policy.csi_controller.policy_document).Statement[3].Resource) == toset(local.csi_instance_arns) && length(local.kata_instance_arns) == 3 && alltrue([for k, node in alicloud_instance.node : contains(local.csi_instance_arns, "acs:ecs:${var.region}:${var.cloud_account_id}:instance/${node.id}") == contains(["kata", "platform"], local.nodes[k].role)])
    error_message = "CSI Attach/Detach must cover only reviewed Kata and platform instances; fencing remains Kata-only."
  }
  assert {
    condition     = length(jsondecode(alicloud_ram_policy.fencing.policy_document).Statement[0].Resource) == 3 && jsondecode(alicloud_ram_policy.fencing.policy_document).Statement[0].Action == ["ecs:StopInstance"] && !strcontains(alicloud_ram_policy.object_access["gateway"].policy_document, "DeleteObject") && !strcontains(alicloud_ram_policy.object_access["backup"].policy_document, "DeleteObjectVersion")
    error_message = "Fencing targets only known Kata nodes; gateway cannot delete output and backup cannot erase versions."
  }
  assert {
    condition     = jsondecode(alicloud_ram_policy.fencing.policy_document).Statement[2].Action == ["ecs:DescribeDisks"] && jsondecode(alicloud_ram_policy.fencing.policy_document).Statement[2].Resource == ["acs:ecs:cn-hangzhou:1234567890123456:disk/*"] && !strcontains(alicloud_ram_policy.fencing.policy_document, "DeleteDisk") && !strcontains(alicloud_ram_policy.fencing.policy_document, "DetachDisk")
    error_message = "Fencing may observe disks in the exact account/region but must not detach or delete them."
  }
  assert {
    condition     = local.workload_subjects["output-reader"] == "system:serviceaccount:sandbox-system:sandbox-api" && jsondecode(alicloud_ram_policy.object_access["output-reader"].policy_document).Statement[0].Action == ["oss:GetObject"] && endswith(jsondecode(alicloud_ram_policy.object_access["output-reader"].policy_document).Statement[0].Resource[0], "/tenants/*") && jsondecode(alicloud_ram_policy.object_access["output-reader"].policy_document).Statement[1].Action == ["kms:Decrypt"] && length(jsondecode(alicloud_ram_policy.object_access["output-reader"].policy_document).Statement) == 2
    error_message = "API output-reader may only Get/Head tenant output objects and decrypt that bucket key; no Put/Delete/List."
  }

  assert {
    condition     = local.workload_subjects["backup-reader"] == "system:serviceaccount:sandbox-system:sandbox-backup-controller" && jsondecode(alicloud_ram_policy.backup_reader.policy_document).Statement[0].Action == ["oss:GetObject"] && jsondecode(alicloud_ram_policy.backup_reader.policy_document).Statement[1].Action == ["oss:ListObjects"] && jsondecode(alicloud_ram_policy.backup_reader.policy_document).Statement[1].Condition.StringLike["oss:Prefix"] == ["tenants/*/backups/*/repository/"] && jsondecode(alicloud_ram_policy.backup_reader.policy_document).Statement[2].Action == ["kms:Decrypt"] && !strcontains(alicloud_ram_policy.backup_reader.policy_document, "PutObject") && !strcontains(alicloud_ram_policy.backup_reader.policy_document, "Delete")
    error_message = "Backup verification may only GET one vault and list repository prefixes; no output/source/restore write or retention administration."
  }

  assert {
    condition     = alltrue([for name in ["file-upload", "file-reader", "file-gateway", "file-cleaner"] : endswith(jsondecode(alicloud_ram_policy.object_access[name].policy_document).Statement[0].Resource[0], "/tenants/*/file-transfers/*/content/*/parts/*") && length(jsondecode(alicloud_ram_policy.object_access[name].policy_document).Statement) == 2]) && jsondecode(alicloud_ram_policy.object_access["file-upload"].policy_document).Statement[0].Action == ["oss:PutObject", "oss:GetObject"] && jsondecode(alicloud_ram_policy.object_access["file-reader"].policy_document).Statement[0].Action == ["oss:GetObject"] && jsondecode(alicloud_ram_policy.object_access["file-gateway"].policy_document).Statement[0].Action == ["oss:PutObject", "oss:GetObject"] && jsondecode(alicloud_ram_policy.object_access["file-cleaner"].policy_document).Statement[0].Action == ["oss:DeleteObject", "oss:GetObject"] && local.workload_subjects["file-cleaner"] == "system:serviceaccount:sandbox-system:sandbox-worker" && local.workload_subjects["file-upload"] == "system:serviceaccount:sandbox-system:sandbox-api" && local.workload_subjects["file-reader"] == "system:serviceaccount:sandbox-system:sandbox-api" && local.workload_subjects["file-gateway"] == "system:serviceaccount:sandbox-system:sandbox-gateway"
    error_message = "File capabilities must be limited to staged file parts with independent PUT, read, gateway and cleanup permissions; no bucket list, multipart, retention or other namespaces."
  }
  assert {
    condition     = local.workload_subjects["volume-deleter"] == "system:serviceaccount:sandbox-system:sandbox-volume-deleter" && jsondecode(alicloud_ram_policy.volume_deleter.policy_document).Statement[0].Action == ["ecs:DescribeDisks"] && jsondecode(alicloud_ram_policy.volume_deleter.policy_document).Statement[1].Action == ["ecs:DeleteDisk", "ecs:ModifyDiskAttribute"] && jsondecode(alicloud_ram_policy.volume_deleter.policy_document).Statement[1].Condition.StringEquals["acs:ResourceTag/Deployment"] == var.name_prefix && !strcontains(alicloud_ram_policy.csi_controller.policy_document, "ecs:DeleteDisk")
    error_message = "Only the separately scoped volume controller may destroy workspace disks; CSI Retain must not silently bypass platform evidence."
  }

}
run "reject_unverified_workload_issuer" {
  command = plan
  variables { workload_oidc = { issuer = "http://issuer.fixture.invalid", audience = "*", ca_sha1_fingerprints = ["invalid"] } }
  expect_failures = [var.workload_oidc]
}
run "reject_unbounded_temporary_retention" {
  command = plan
  variables { object_retention_days = { output = 7, audit = 365, backup_vault = 31, temporary = 30 } }
  expect_failures = [var.object_retention_days]
}

run "reject_wrong_cloud_account" {
  command = plan
  variables { cloud_account_id = "9876543210123456" }
  expect_failures = [data.alicloud_caller_identity.deployment]
}

run "reject_vault_below_api_minimum" {
  command = plan
  variables { object_retention_days = { output = 7, audit = 365, backup_vault = 30, temporary = 1 } }
  expect_failures = [var.object_retention_days]
}
