mock_provider "alicloud" {
  mock_data "alicloud_caller_identity" { defaults = { account_id = "1234567890123456" } }
}
variables {
  region                   = "cn-hangzhou"
  state_bucket_name        = "sandbox-state-fixture-only"
  lock_instance_name       = "sbx-fixture"
  state_operator_role_name = "fixture-ci-state"
  cloud_account_id         = "1234567890123456"
}
run "encrypted_versioned_locked_backend" {
  command = plan
  assert {
    condition     = alicloud_oss_bucket_public_access_block.state.block_public_access && alicloud_oss_bucket_versioning.state.status == "Enabled" && alicloud_oss_bucket_server_side_encryption.state.sse_algorithm == "KMS" && !alicloud_oss_bucket.state.force_destroy && alicloud_kms_key.state.deletion_protection == "Enabled"
    error_message = "State requires public-access blocking, encrypted versioned storage and protected encryption keys."
  }
  assert {
    condition     = alicloud_ots_table.lock.primary_key[0].name == "LockID" && alicloud_ots_table.lock.primary_key[0].type == "String" && alicloud_ots_table.lock.time_to_live == -1
    error_message = "Backend lock schema must match Terraform OSS and must never expire a live lock automatically."
  }
}

run "reject_wrong_cloud_account" {
  command = plan
  variables { cloud_account_id = "9876543210123456" }
  expect_failures = [data.alicloud_caller_identity.deployment]
}
