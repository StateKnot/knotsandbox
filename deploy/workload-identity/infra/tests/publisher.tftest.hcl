mock_provider "alicloud" {
  mock_data "alicloud_caller_identity" { defaults = { account_id = "1234567890123456" } }
}
variables {
  account_id        = "1234567890123456"
  region            = "cn-hangzhou"
  name_prefix       = "sandbox-test"
  vpc_id            = "vpc-test"
  resource_group_id = "rg-test"
  origins           = { first = { zone = "cn-hangzhou-h", vswitch_id = "vsw-first" }, second = { zone = "cn-hangzhou-i", vswitch_id = "vsw-second" } }
  image_id          = "m-reviewed-test"
  instance_type     = "ecs.c7.large"
  disk_kms_key_id   = "key-test-only"
  admin_public_key  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA public-test-only"
  management_cidrs  = ["10.0.0.0/24"]
  ntp_server_ips    = ["10.0.0.5"]
}
run "two_public_origins_have_narrow_access_and_no_cloud_identity" {
  command = plan
  assert {
    condition     = length(alicloud_instance.publisher) == 2 && alltrue([for origin in alicloud_instance.publisher : origin.http_tokens == "required" && origin.http_put_response_hop_limit == 1 && origin.deletion_protection && origin.system_disk_encrypted && origin.internet_max_bandwidth_out == 5])
    error_message = "Public origins must have protected storage and no metadata credentials."
  }
  assert {
    condition     = alicloud_security_group_rule.https.port_range == "443/443" && alicloud_security_group_rule.deny_out.policy == "drop" && alicloud_security_group_rule.metadata.cidr_ip == "100.100.100.200/32" && alicloud_security_group_rule.metadata.port_range == "80/80" && alltrue([for rule in alicloud_security_group_rule.ssh : rule.cidr_ip != "0.0.0.0/0"])
    error_message = "Only HTTPS is public; SSH remains restricted and egress denied by default."
  }
}
run "reject_single_zone" {
  command = plan
  variables { origins = { first = { zone = "same-zone", vswitch_id = "vsw-first" }, second = { zone = "same-zone", vswitch_id = "vsw-second" } } }
  expect_failures = [var.origins]
}
run "reject_public_ssh" {
  command = plan
  variables { management_cidrs = ["0.0.0.0/0"] }
  expect_failures = [var.management_cidrs]
}
