variable "region" {
  description = "Approved Alibaba Cloud region; intentionally no deployable default."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-z]+-[a-z0-9-]+[0-9]?$", var.region))
    error_message = "Supply an explicit Alibaba Cloud region identifier."
  }
}
variable "environment" {
  type = string
  validation {
    condition     = contains(["preproduction", "production"], var.environment)
    error_message = "Use a separate preproduction or production deployment and state."
  }
}
variable "name_prefix" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{3,19}$", var.name_prefix))
    error_message = "Use a globally distinct 4-20 character environment prefix."
  }
}
variable "availability_zones" {
  description = "Exactly three distinct, explicitly selected zones in region; SKU compatibility requires live certification."
  type        = list(string)
  validation {
    condition     = length(var.availability_zones) == 3 && length(toset(var.availability_zones)) == 3 && alltrue([for z in var.availability_zones : startswith(z, "${var.region}-")])
    error_message = "Select three distinct availability zones in the selected region."
  }
}
variable "vpc_cidr" {
  description = "New environment IPv4 RFC1918 network (/16-/20). Twelve nonoverlapping role/AZ subnets are derived."
  type        = string
  validation {
    condition     = can(cidrnetmask(var.vpc_cidr)) && can(regex("/(1[6-9]|20)$", var.vpc_cidr)) && can(regex("^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)", var.vpc_cidr))
    error_message = "Use an RFC1918 IPv4 CIDR with prefix /16 through /20."
  }
}
variable "enterprise_cidrs" {
  description = "Existing enterprise address space, used to reject overlapping VPC allocation; connectivity is supplied by the enterprise network owner."
  type        = set(string)
  validation {
    condition     = length(var.enterprise_cidrs) > 0 && alltrue([for c in var.enterprise_cidrs : can(cidrnetmask(c)) && !endswith(c, "/0")])
    error_message = "Declare enterprise IPv4 CIDRs, never the default route."
  }
}
variable "management_cidrs" {
  description = "Private VPN/bastion/CI source CIDRs authorized for SSH and Kubernetes management; must be inside enterprise_cidrs."
  type        = set(string)
  validation {
    condition     = length(var.management_cidrs) > 0 && alltrue([for c in var.management_cidrs : can(cidrnetmask(c)) && !endswith(c, "/0")])
    error_message = "Explicit management sources are required; 0.0.0.0/0 is prohibited."
  }
}
variable "api_client_cidrs" {
  description = "Private enterprise microservice/control-console source CIDRs allowed to reach the product TLS ingress."
  type        = set(string)
  validation {
    condition     = length(var.api_client_cidrs) > 0 && alltrue([for c in var.api_client_cidrs : can(cidrnetmask(c)) && !endswith(c, "/0")])
    error_message = "Supply explicit IPv4 service client sources."
  }
}
variable "host_image_id" {
  description = "Previously reviewed x86_64 Linux image ID with pinned kernel and bootstrap dependencies; never an image search or latest alias."
  type        = string
  validation {
    condition     = length(var.host_image_id) > 8 && !strcontains(lower(var.host_image_id), "latest")
    error_message = "Supply a fixed reviewed Linux image ID."
  }
}
variable "node_skus" {
  description = "Explicit approved control/platform ECS and elastic bare-metal Kata SKU. Availability in all three zones remains a cloud acceptance gate."
  type        = object({ control = string, platform = string, kata = string })
  validation {
    condition     = alltrue([for sku in values(var.node_skus) : startswith(sku, "ecs.")]) && startswith(var.node_skus.kata, "ecs.ebm")
    error_message = "All SKUs must be ECS identifiers; Kata nodes require an ecs.ebm elastic bare-metal family."
  }
}
variable "kata_nodes_per_zone" {
  type = number
  validation {
    condition     = var.kata_nodes_per_zone >= 1 && var.kata_nodes_per_zone <= 100 && floor(var.kata_nodes_per_zone) == var.kata_nodes_per_zone
    error_message = "Provision 1-100 Kata nodes in each of the three zones; capacity requires a workload measurement."
  }
}
variable "ssh_public_key" {
  description = "Enterprise-managed public SSH key only. No private key or instance password enters Terraform."
  type        = string
  validation {
    condition     = can(regex("^ssh-(rsa|ed25519) [A-Za-z0-9+/=]+( .*)?$", trimspace(var.ssh_public_key)))
    error_message = "Supply an SSH public key, not a private key."
  }
}
variable "egress_services" {
  description = "Audited host-only private services (DNS/NTP/proxy/registry/cloud endpoints). Each explicit CIDR/port gets a rule; no general Internet egress."
  type        = map(object({ cidr = string, protocol = string, port = number }))
  validation {
    condition     = length(var.egress_services) > 0 && alltrue([for s in values(var.egress_services) : can(cidrnetmask(s.cidr)) && !endswith(s.cidr, "/0") && contains(["tcp", "udp"], s.protocol) && s.port >= 1 && s.port <= 65535 && floor(s.port) == s.port])
    error_message = "Declare exact DNS/NTP/egress-proxy service destinations; wildcard routes are prohibited."
  }
}
variable "load_balancer_spec" {
  description = "Approved regional CLB SKU; both internal load balancers use TCP passthrough so TLS remains terminated by the API server/ingress."
  type        = string
  validation {
    condition     = startswith(var.load_balancer_spec, "slb.")
    error_message = "Supply an explicit supported CLB SKU."
  }
}
variable "load_balancer_health_cidrs" {
  description = "Regional CLB health-check source CIDRs confirmed from Alibaba documentation; restricted to each service port."
  type        = set(string)
  validation {
    condition     = length(var.load_balancer_health_cidrs) > 0 && alltrue([for c in var.load_balancer_health_cidrs : can(cidrnetmask(c)) && !endswith(c, "/0")])
    error_message = "Supply explicit load-balancer health-check sources."
  }
}
variable "database" {
  description = "Approved RDS PostgreSQL 17 HA SKU, storage and maintenance window. Region/dual-zone support must be certified before apply."
  type        = object({ instance_type = string, storage_gib = number, minor_version = string, maintenance_time = string, backup_retention_days = number })
  validation {
    condition     = startswith(var.database.instance_type, "pg.") && var.database.storage_gib >= 100 && var.database.storage_gib <= 32000 && floor(var.database.storage_gib) == var.database.storage_gib && startswith(var.database.minor_version, "rds_postgres_1700_") && var.database.backup_retention_days >= 7 && var.database.backup_retention_days <= 730 && can(regex("^[0-2][0-9]:[0-5][0-9]Z-[0-2][0-9]:[0-5][0-9]Z$", var.database.maintenance_time))
    error_message = "Use a reviewed PostgreSQL 17 minor version/SKU, >=100 GiB and 7-730 days of backup retention."
  }
}
variable "object_retention_days" {
  description = "Object retention contract. Output/audit/vault WORM locks cannot be shortened; backup repository itself stays mutable."
  type        = object({ output = number, audit = number, backup_vault = number, temporary = number })
  validation {
    condition     = alltrue([for days in values(var.object_retention_days) : days >= 1 && days <= 25550 && floor(days) == days]) && var.object_retention_days.temporary <= 7 && var.object_retention_days.backup_vault >= 31
    error_message = "Choose explicit integral retention periods (1-25550 days); backup vault requires at least 31 days; temporary uploads expire within seven days."
  }
}
variable "cloud_account_id" {
  description = "Deployment account ID for precise RAM resource ARNs; never inferred from another environment."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{16}$", var.cloud_account_id))
    error_message = "Provide the Alibaba Cloud account ID."
  }
}
variable "workload_oidc" {
  description = "Trusted Kubernetes projected-service-account issuer (not the product's user-login issuer). Public HTTPS discovery/JWKS must be installed before assuming these roles."
  type        = object({ issuer = string, audience = string, ca_sha1_fingerprints = set(string) })
  validation {
    condition     = can(regex("^https://[^/?#]+(/[^?#]*)?$", var.workload_oidc.issuer)) && length(var.workload_oidc.audience) > 0 && !strcontains(var.workload_oidc.audience, "*") && length(var.workload_oidc.ca_sha1_fingerprints) > 0 && alltrue([for f in var.workload_oidc.ca_sha1_fingerprints : can(regex("^[0-9a-fA-F]{40}$", f))])
    error_message = "Declare an HTTPS issuer, exact STS audience and reviewed CA SHA-1 fingerprint(s)."
  }
}
