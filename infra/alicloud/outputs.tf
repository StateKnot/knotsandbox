output "vpc_id" { value = alicloud_vpc.environment.id }
output "deployment_identity" {
  description = "Account observed by the provider and reviewed deployment identity; used to bind node enrollment to this inventory."
  value = {
    cloud_account_id = data.alicloud_caller_identity.deployment.account_id
    region           = var.region
    deployment       = var.name_prefix
    environment      = var.environment
  }
}
output "subnets" { value = { for k, s in alicloud_vswitch.role : k => { id = s.id, zone = s.zone_id, cidr = s.cidr_block } } }
output "node_inventory" {
  description = "Kubespray input only; provisioning instances does not install or certify Kubernetes."
  value       = { for k, n in alicloud_instance.node : k => { id = n.id, private_ip = n.private_ip, role = local.nodes[k].role, zone = local.nodes[k].zone } }
}
output "private_entrances" { value = { for k, lb in alicloud_slb_load_balancer.private : k => { address = lb.address, port = local.entrances[k].port } } }
output "database" {
  description = "TLS endpoint and engine identity; credentials/database roles are installed separately with audited secret injection."
  value       = { id = alicloud_db_instance.platform.id, endpoint = alicloud_db_instance.platform.connection_string, port = 5432, engine = "PostgreSQL", major_version = 17 }
}
output "object_storage" { value = { for purpose, bucket in alicloud_oss_bucket.data : purpose => { bucket = bucket.bucket, internal_endpoint = bucket.intranet_endpoint, kms_key_id = alicloud_kms_key.data[purpose].id } } }
output "workload_roles" { value = { for component, role in alicloud_ram_role.workload : component => { arn = role.arn, role_id = role.role_id, subject = local.workload_subjects[component], issuer = var.workload_oidc.issuer, audience = var.workload_oidc.audience } } }
output "workload_oidc_provider_arn" { value = alicloud_ims_oidc_provider.workloads.arn }
output "workspace_kms_key_id" { value = alicloud_kms_key.data["compute"].id }
