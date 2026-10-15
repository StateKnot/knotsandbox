//! Explicit, owner-authorized installation bootstrap. This module is not routed
//! through HTTP and never issues tokens, stores IdP secrets, or changes an
//! existing identity binding, grant, policy, quota limit, or cluster epoch.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use thiserror::Error;
use url::{Host, Url};
use uuid::Uuid;

use crate::db::Database;

pub const MAX_BOOTSTRAP_BYTES: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum AdminError {
    #[error("invalid bootstrap input: {0}")]
    Invalid(&'static str),
    #[error("bootstrap conflicts with existing {0}; no state was replaced")]
    Conflict(&'static str),
    #[error("bootstrap requires a dedicated database/table owner connection")]
    OwnerRequired,
    #[error("bootstrap database operation failed (class {0}); verify state before retrying")]
    Database(String),
}

impl From<sqlx::Error> for AdminError {
    fn from(error: sqlx::Error) -> Self {
        // SQL error detail can contain supplied identity/policy data. Keep only
        // the SQLSTATE, never the SQL statement, URL, parameters, or row detail.
        Self::Database(
            error
                .as_database_error()
                .and_then(|e| e.code())
                .map(|c| c.into_owned())
                .unwrap_or_else(|| "transport-or-protocol".into()),
        )
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapSpec {
    pub tenant: NamedId,
    pub project: BootstrapProject,
    pub initial_principal: BootstrapPrincipal,
    pub approved_template: BootstrapTemplate,
    pub security_policy: BootstrapPolicy,
    pub quotas: BootstrapQuotas,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamedId {
    pub id: Uuid,
    pub name: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapProject {
    pub id: Uuid,
    pub name: String,
    pub runtime_namespace: String,
    pub storage_class: String,
    pub max_ttl_seconds: i64,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub enum PrincipalKind {
    #[serde(rename = "USER")]
    User,
    #[serde(rename = "SERVICE")]
    Service,
}
impl PrincipalKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "USER",
            Self::Service => "SERVICE",
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapPrincipal {
    pub id: Uuid,
    pub issuer: String,
    pub subject: String,
    /// Mandatory for SERVICE, absent for USER. Never inferred from a subject.
    #[serde(default)]
    pub client_id: Option<String>,
    pub kind: PrincipalKind,
    pub display_name: String,
    /// Explicit grants only, scoped to this project. No implicit tenant-wide admin.
    pub project_actions: Vec<String>,
    /// Explicit tenant identity administration only; omitted grants nothing.
    #[serde(default)]
    pub tenant_actions: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapTemplate {
    pub id: Uuid,
    pub name: String,
    pub version: i64,
    /// OCI repository without tag/digest; image_digest is mandatory separately.
    pub image_ref: String,
    pub image_digest: String,
    pub runner_version: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapPolicy {
    pub id: Uuid,
    pub name: String,
    pub version: i64,
    pub rules: BootstrapRules,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRules {
    pub profile: String,
    pub dns: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapQuotas {
    pub tenant: QuotaLimits,
    pub project: QuotaLimits,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaLimits {
    pub instances: i64,
    pub cpu_millis: i64,
    pub memory_mib: i64,
    pub workspace_gib: i64,
    pub executions: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_gib: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_temp_gib: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_transfers: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_transfer_bytes: Option<i64>,
}
impl QuotaLimits {
    fn dimensions(&self) -> [(&'static str, Option<i64>); 9] {
        [
            ("INSTANCES", Some(self.instances)),
            ("CPU_MILLIS", Some(self.cpu_millis)),
            ("MEMORY_MIB", Some(self.memory_mib)),
            ("WORKSPACE_GIB", Some(self.workspace_gib)),
            ("EXECUTIONS", Some(self.executions)),
            ("BACKUP_GIB", self.backup_gib),
            ("BACKUP_TEMP_GIB", self.backup_temp_gib),
            ("FILE_TRANSFERS", self.file_transfers),
            ("FILE_TRANSFER_BYTES", self.file_transfer_bytes),
        ]
    }
}

#[derive(Debug, Serialize)]
pub struct BootstrapReport {
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub principal_id: Uuid,
    pub template_version_id: Uuid,
    pub security_policy_version_id: Uuid,
    pub cluster_epoch: Uuid,
    pub safe_mode: bool,
    pub request_id: Uuid,
    pub spec_sha256: String,
    pub changed: bool,
}

pub fn parse_spec(bytes: &[u8], allow_loopback_http: bool) -> Result<BootstrapSpec, AdminError> {
    if bytes.len() > MAX_BOOTSTRAP_BYTES {
        return Err(AdminError::Invalid("file exceeds 65536 bytes"));
    }
    let spec: BootstrapSpec = serde_json::from_slice(bytes)
        .map_err(|_| AdminError::Invalid("file must match the strict bootstrap JSON schema"))?;
    spec.validate(allow_loopback_http)?;
    Ok(spec)
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceIdentityBindingRequest {
    pub issuer: String,
    pub subject: String,
    /// null for the initial binding of an existing unbound SERVICE identity.
    pub expected_client_id: Option<String>,
    pub client_id: String,
    pub reason: String,
}
impl ServiceIdentityBindingRequest {
    pub fn parse(bytes: &[u8]) -> Result<Self, AdminError> {
        if bytes.len() > MAX_BOOTSTRAP_BYTES {
            return Err(AdminError::Invalid("file exceeds 65536 bytes"));
        }
        let request: Self = serde_json::from_slice(bytes)
            .map_err(|_| AdminError::Invalid("invalid service binding JSON"))?;
        validate_issuer(&request.issuer, false)?;
        if !text(&request.subject, 512)
            || !crate::auth::valid_client_id(&request.client_id)
            || !text(&request.reason, 256)
            || request
                .expected_client_id
                .as_ref()
                .is_some_and(|client| !crate::auth::valid_client_id(client))
        {
            return Err(AdminError::Invalid(
                "invalid service binding identifiers or reason",
            ));
        }
        // Requiring the field distinguishes an operator's explicit initial CAS
        // from an accidental omission while constructing a rotation request.
        let shape: Value = serde_json::from_slice(bytes)
            .map_err(|_| AdminError::Invalid("invalid service binding JSON"))?;
        if shape.get("expected_client_id").is_none() {
            return Err(AdminError::Invalid(
                "expected_client_id must be explicit, including null",
            ));
        }
        Ok(request)
    }
}

pub async fn bind_service_identity(
    database: &Database,
    request: &ServiceIdentityBindingRequest,
) -> Result<Uuid, AdminError> {
    let mut tx = database.pool.begin().await?;
    let owner: bool = sqlx::query_scalar("SELECT bool_and(pg_has_role(current_user,c.relowner,'USAGE')) FROM pg_class c WHERE c.oid=ANY(ARRAY['public.principal_identities'::regclass,'public.principals'::regclass,'public.service_identity_binding_audit'::regclass])")
        .fetch_one(&mut *tx).await?;
    if !owner {
        return Err(AdminError::OwnerRequired);
    }
    let principal = sqlx::query_scalar("SELECT sandbox_bind_service_identity($1,$2,$3,$4,$5)")
        .bind(&request.issuer)
        .bind(&request.subject)
        .bind(&request.expected_client_id)
        .bind(&request.client_id)
        .bind(&request.reason)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(principal)
}

impl BootstrapSpec {
    pub fn validate(&self, allow_loopback_http: bool) -> Result<(), AdminError> {
        for id in [
            self.tenant.id,
            self.project.id,
            self.initial_principal.id,
            self.approved_template.id,
            self.security_policy.id,
        ] {
            if id.is_nil() {
                return Err(AdminError::Invalid("resource IDs must not be nil"));
            }
        }
        for name in [
            &self.tenant.name,
            &self.project.name,
            &self.initial_principal.display_name,
            &self.approved_template.name,
            &self.security_policy.name,
        ] {
            if !text(name, 128) {
                return Err(AdminError::Invalid(
                    "names must contain 1..128 non-control characters",
                ));
            }
        }
        if !(2..=63).contains(&self.project.runtime_namespace.len())
            || !dns_label(&self.project.runtime_namespace)
        {
            return Err(AdminError::Invalid(
                "runtime namespace must be a DNS label of 2..63 characters",
            ));
        }
        if self.project.storage_class.len() > 253
            || !self.project.storage_class.split('.').all(dns_label)
        {
            return Err(AdminError::Invalid("storage class must be a DNS subdomain"));
        }
        if !(60..=604800).contains(&self.project.max_ttl_seconds) {
            return Err(AdminError::Invalid(
                "project max_ttl_seconds must be 60..604800",
            ));
        }
        validate_issuer(&self.initial_principal.issuer, allow_loopback_http)?;
        if !text(&self.initial_principal.subject, 512) {
            return Err(AdminError::Invalid(
                "subject must contain 1..512 non-control characters",
            ));
        }
        match (
            self.initial_principal.kind,
            self.initial_principal.client_id.as_deref(),
        ) {
            (PrincipalKind::Service, Some(client)) if crate::auth::valid_client_id(client) => {}
            (PrincipalKind::User, None) => {}
            _ => {
                return Err(AdminError::Invalid(
                    "SERVICE requires client_id; USER must omit client_id",
                ));
            }
        }
        let actions = &self.initial_principal.project_actions;
        let actions_allowed = crate::grants::PROJECT_ACTIONS;
        let unique: HashSet<_> = actions.iter().collect();
        if actions.is_empty()
            || actions.len() > actions_allowed.len()
            || unique.len() != actions.len()
            || actions
                .iter()
                .any(|a| !actions_allowed.contains(&a.as_str()))
            || (actions.iter().any(|a| a == "*") && actions.len() != 1)
        {
            return Err(AdminError::Invalid(
                "project_actions must explicitly list unique supported permissions, or only *",
            ));
        }
        let tenant_actions = &self.initial_principal.tenant_actions;
        let unique: HashSet<_> = tenant_actions.iter().collect();
        if unique.len() != tenant_actions.len()
            || tenant_actions
                .iter()
                .any(|a| !crate::service_clients::TENANT_IDENTITY_ACTIONS.contains(&a.as_str()))
        {
            return Err(AdminError::Invalid(
                "tenant_actions only accepts unique service_clients:read/write and tenant_audit:read permissions",
            ));
        }
        let template = &self.approved_template;
        if template.version < 1 || self.security_policy.version < 1 {
            return Err(AdminError::Invalid("version numbers must be positive"));
        }
        if !text(&template.runner_version, 64) {
            return Err(AdminError::Invalid(
                "runner_version is required and limited to 64 characters",
            ));
        }
        let image = &template.image_ref;
        if image.is_empty()
            || image.len() > 2048
            || image.contains('@')
            || image.contains("://")
            || image
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || image
                .rsplit('/')
                .next()
                .is_some_and(|part| part.contains(':'))
            || !image
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-:/".contains(&b))
        {
            return Err(AdminError::Invalid(
                "image_ref must be an OCI repository without tag or digest",
            ));
        }
        let digest = template
            .image_digest
            .strip_prefix("sha256:")
            .ok_or(AdminError::Invalid(
                "image_digest must be a lowercase SHA256 digest",
            ))?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(AdminError::Invalid(
                "image_digest must be a lowercase SHA256 digest",
            ));
        }
        if self.security_policy.rules.profile != "deny-all" || !self.security_policy.rules.dns {
            return Err(AdminError::Invalid(
                "only security rules {profile: deny-all, dns: true} are supported",
            ));
        }
        for ((_, tenant), (_, project)) in self
            .quotas
            .tenant
            .dimensions()
            .iter()
            .zip(self.quotas.project.dimensions().iter())
        {
            let (tenant, project) = match (tenant, project) {
                (None, None) => continue,
                (Some(tenant), Some(project)) => (tenant, project),
                _ => {
                    return Err(AdminError::Invalid(
                        "optional quota dimensions require both tenant and project limits",
                    ));
                }
            };
            if *tenant < 0 || *project < 0 || project > tenant {
                return Err(AdminError::Invalid(
                    "explicit nonnegative project quotas must not exceed tenant quotas",
                ));
            }
            if *tenant == i64::MAX {
                return Err(AdminError::Invalid(
                    "unlimited sentinel quotas are not allowed",
                ));
            }
        }
        Ok(())
    }

    pub fn sha256(&self) -> Result<String, AdminError> {
        let value = serde_json::to_value(self)
            .map_err(|_| AdminError::Invalid("cannot encode bootstrap spec"))?;
        let bytes = serde_json::to_vec(&value)
            .map_err(|_| AdminError::Invalid("cannot encode bootstrap spec"))?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

/// Atomic and repeatable initialization. Existing configured values are compared,
/// never overwritten. This does not provision a namespace, storage class, IdP,
/// image registry, or approved runtime: those are independently operated systems.
pub async fn apply_bootstrap(
    database: &Database,
    spec: &BootstrapSpec,
    initialize_cluster_epoch: Option<Uuid>,
    allow_loopback_http: bool,
) -> Result<BootstrapReport, AdminError> {
    spec.validate(allow_loopback_http)?;
    if initialize_cluster_epoch.is_some_and(|epoch| epoch.is_nil()) {
        return Err(AdminError::Invalid("cluster epoch must not be nil"));
    }
    let mut tx = database.pool.begin().await?;
    sqlx::query("SET LOCAL search_path = pg_catalog, public")
        .execute(&mut *tx)
        .await?;
    let owner: bool=sqlx::query_scalar("SELECT count(*)=10 AND bool_and(pg_has_role(current_user,c.relowner,'USAGE')) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY['tenants','projects','principals','principal_identities','grants','template_versions','security_policy_versions','quota_accounts','audit_events','platform_configuration'])")
        .fetch_one(&mut *tx).await?;
    if !owner {
        return Err(AdminError::OwnerRequired);
    }
    let database_role: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(spec.tenant.id.to_string())
        .execute(&mut *tx)
        .await?;
    // ponytail: bootstrap is an infrequent operator action; one DB transaction
    // lock avoids an upsert framework. Split locks only if onboarding throughput warrants it.
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(0x5342_5842_4f4f_5401_i64)
        .execute(&mut *tx)
        .await?;
    let mut changed = false;
    let configuration = sqlx::query(
        "SELECT cluster_epoch,safe_mode FROM platform_configuration WHERE singleton FOR UPDATE",
    )
    .fetch_optional(&mut *tx)
    .await?;
    let (cluster_epoch, safe_mode) = if let Some(row) = configuration {
        let epoch: Uuid = row.try_get("cluster_epoch")?;
        if initialize_cluster_epoch.is_some_and(|requested| requested != epoch) {
            return Err(AdminError::Conflict("cluster epoch"));
        }
        (epoch, row.try_get::<bool, _>("safe_mode")?)
    } else {
        let epoch = initialize_cluster_epoch.ok_or(AdminError::Invalid(
            "first initialization requires --initialize-cluster-epoch UUID",
        ))?;
        sqlx::query("INSERT INTO platform_configuration(singleton,cluster_epoch,safe_mode) VALUES(true,$1,true)").bind(epoch).execute(&mut *tx).await?;
        changed = true;
        (epoch, true)
    };
    changed |= sqlx::query("INSERT INTO tenants(id,name) VALUES($1,$2) ON CONFLICT(id) DO NOTHING")
        .bind(spec.tenant.id)
        .bind(&spec.tenant.name)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        > 0;
    let actual: Value =
        sqlx::query_scalar("SELECT to_jsonb(t) FROM tenants t WHERE id=$1 FOR UPDATE")
            .bind(spec.tenant.id)
            .fetch_one(&mut *tx)
            .await?;
    compare(
        &actual,
        &json!({"id":spec.tenant.id,"name":spec.tenant.name,"enabled":true}),
        "tenant",
    )?;
    let project = &spec.project;
    changed|=sqlx::query("INSERT INTO projects(id,tenant_id,name,max_ttl_seconds,runtime_namespace,storage_class) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO NOTHING")
        .bind(project.id).bind(spec.tenant.id).bind(&project.name).bind(project.max_ttl_seconds).bind(&project.runtime_namespace).bind(&project.storage_class).execute(&mut *tx).await?.rows_affected()>0;
    let actual: Value =
        sqlx::query_scalar("SELECT to_jsonb(p) FROM projects p WHERE id=$1 FOR UPDATE")
            .bind(project.id)
            .fetch_one(&mut *tx)
            .await?;
    compare(
        &actual,
        &json!({"id":project.id,"tenant_id":spec.tenant.id,"name":project.name,"max_ttl_seconds":project.max_ttl_seconds,"runtime_namespace":project.runtime_namespace,"storage_class":project.storage_class,"enabled":true}),
        "project",
    )?;
    let principal = &spec.initial_principal;
    changed |= sqlx::query(
        "INSERT INTO principals(id,kind,display_name) VALUES($1,$2,$3) ON CONFLICT(id) DO NOTHING",
    )
    .bind(principal.id)
    .bind(principal.kind.as_str())
    .bind(&principal.display_name)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        > 0;
    let actual: Value =
        sqlx::query_scalar("SELECT to_jsonb(p) FROM principals p WHERE id=$1 FOR UPDATE")
            .bind(principal.id)
            .fetch_one(&mut *tx)
            .await?;
    compare(
        &actual,
        &json!({"id":principal.id,"kind":principal.kind.as_str(),"display_name":principal.display_name,"enabled":true}),
        "principal",
    )?;
    let existing: Option<(Uuid,bool,Option<String>)>=sqlx::query_as("SELECT principal_id,enabled,service_client_id FROM principal_identities WHERE issuer=$1 AND subject=$2 FOR UPDATE")
        .bind(&principal.issuer).bind(&principal.subject).fetch_optional(&mut *tx).await?;
    if let Some((id, enabled, client_id)) = existing {
        if id != principal.id || !enabled || client_id != principal.client_id {
            return Err(AdminError::Conflict("identity binding"));
        }
    } else {
        let bound: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM principal_identities WHERE principal_id=$1)",
        )
        .bind(principal.id)
        .fetch_one(&mut *tx)
        .await?;
        if bound {
            return Err(AdminError::Conflict(
                "principal identity; IdP migration requires a separate reviewed workflow",
            ));
        }
        sqlx::query(
            "INSERT INTO principal_identities(principal_id,issuer,subject,service_client_id,service_binding_generation) VALUES($1,$2,$3,$4,CASE WHEN $4::text IS NULL THEN 0 ELSE 1 END)",
        )
        .bind(principal.id)
        .bind(&principal.issuer)
        .bind(&principal.subject)
        .bind(&principal.client_id)
        .execute(&mut *tx)
        .await?;
        changed = true;
    }
    let mut desired_actions = principal.project_actions.clone();
    desired_actions.sort();
    let mut desired_grants: Vec<(Option<Uuid>, String)> = desired_actions
        .iter()
        .map(|a| (Some(project.id), a.clone()))
        .chain(principal.tenant_actions.iter().map(|a| (None, a.clone())))
        .collect();
    desired_grants.sort();
    let existing=sqlx::query("SELECT project_id,action,enabled,expires_at,revoked_at FROM grants WHERE tenant_id=$1 AND principal_id=$2 AND (project_id=$3 OR project_id IS NULL) ORDER BY project_id NULLS FIRST,action FOR UPDATE")
        .bind(spec.tenant.id).bind(principal.id).bind(project.id).fetch_all(&mut *tx).await?;
    if existing.is_empty() {
        for (grant_project, action) in &desired_grants {
            sqlx::query(
                "INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4)",
            )
            .bind(spec.tenant.id)
            .bind(grant_project)
            .bind(principal.id)
            .bind(action)
            .execute(&mut *tx)
            .await?;
        }
        changed = true;
    } else {
        let mut actual_grants = Vec::new();
        for grant in existing {
            if !grant.try_get::<bool, _>("enabled")?
                || grant
                    .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("expires_at")?
                    .is_some()
                || grant
                    .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("revoked_at")?
                    .is_some()
            {
                return Err(AdminError::Conflict("principal grants"));
            }
            actual_grants.push((
                grant.try_get::<Option<Uuid>, _>("project_id")?,
                grant.try_get::<String, _>("action")?,
            ));
        }
        actual_grants.sort();
        if actual_grants != desired_grants {
            return Err(AdminError::Conflict("principal grants"));
        }
    }
    let membership_enabled: Option<bool> = sqlx::query_scalar(
        "SELECT enabled FROM tenant_principals WHERE tenant_id=$1 AND principal_id=$2",
    )
    .bind(spec.tenant.id)
    .bind(principal.id)
    .fetch_optional(&mut *tx)
    .await?;
    if membership_enabled != Some(true) {
        return Err(AdminError::Conflict("tenant principal membership"));
    }
    let template = &spec.approved_template;
    changed|=sqlx::query("INSERT INTO template_versions(id,tenant_id,name,version,image_ref,image_digest,runner_version,status,capabilities) VALUES($1,$2,$3,$4,$5,$6,$7,'APPROVED','{}'::jsonb) ON CONFLICT(id) DO NOTHING")
        .bind(template.id).bind(spec.tenant.id).bind(&template.name).bind(template.version).bind(&template.image_ref).bind(&template.image_digest).bind(&template.runner_version).execute(&mut *tx).await?.rows_affected()>0;
    let actual: Value =
        sqlx::query_scalar("SELECT to_jsonb(t) FROM template_versions t WHERE id=$1 FOR UPDATE")
            .bind(template.id)
            .fetch_one(&mut *tx)
            .await?;
    compare(
        &actual,
        &json!({"id":template.id,"tenant_id":spec.tenant.id,"name":template.name,"version":template.version,"image_ref":template.image_ref,"image_digest":template.image_digest,"runner_version":template.runner_version,"status":"APPROVED","capabilities":{}}),
        "template version",
    )?;
    let policy = &spec.security_policy;
    let rules = serde_json::to_value(&policy.rules)
        .map_err(|_| AdminError::Invalid("cannot encode security rules"))?;
    changed|=sqlx::query("INSERT INTO security_policy_versions(id,tenant_id,name,version,status,rules) VALUES($1,$2,$3,$4,'APPROVED',$5) ON CONFLICT(id) DO NOTHING")
        .bind(policy.id).bind(spec.tenant.id).bind(&policy.name).bind(policy.version).bind(&rules).execute(&mut *tx).await?.rows_affected()>0;
    let actual: Value = sqlx::query_scalar(
        "SELECT to_jsonb(p) FROM security_policy_versions p WHERE id=$1 FOR UPDATE",
    )
    .bind(policy.id)
    .fetch_one(&mut *tx)
    .await?;
    compare(
        &actual,
        &json!({"id":policy.id,"tenant_id":spec.tenant.id,"name":policy.name,"version":policy.version,"status":"APPROVED","rules":rules}),
        "security policy version",
    )?;
    changed |= quotas(&mut tx, spec.tenant.id, None, &spec.quotas.tenant).await?;
    changed |= quotas(
        &mut tx,
        spec.tenant.id,
        Some(project.id),
        &spec.quotas.project,
    )
    .await?;
    let request_id = Uuid::new_v4();
    let spec_sha256 = spec.sha256()?;
    sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,resource_id,action,outcome,details) VALUES($1,$2,NULL,$3,$2,'platform:bootstrap','SUCCEEDED',$4)")
        .bind(spec.tenant.id).bind(project.id).bind(request_id)
        .bind(json!({"authorization_source":"database_table_owner","database_role":database_role,"spec_sha256":spec_sha256,"initial_principal_id":principal.id,"project_actions":desired_actions,"tenant_actions":principal.tenant_actions,"template_version_id":template.id,"security_policy_version_id":policy.id,"cluster_epoch":cluster_epoch,"safe_mode":safe_mode,"changed":changed}))
        .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(BootstrapReport {
        tenant_id: spec.tenant.id,
        project_id: project.id,
        principal_id: principal.id,
        template_version_id: template.id,
        security_policy_version_id: policy.id,
        cluster_epoch,
        safe_mode,
        request_id,
        spec_sha256,
        changed,
    })
}

async fn quotas(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    project: Option<Uuid>,
    limits: &QuotaLimits,
) -> Result<bool, AdminError> {
    let mut changed = false;
    for (dimension, limit) in limits.dimensions() {
        let Some(limit) = limit else {
            continue;
        };
        let existing=sqlx::query("SELECT limit_value FROM quota_accounts WHERE tenant_id=$1 AND project_id IS NOT DISTINCT FROM $2 AND dimension=$3 FOR UPDATE")
            .bind(tenant).bind(project).bind(dimension).fetch_optional(&mut **tx).await?;
        if let Some(row) = existing {
            if row.try_get::<i64, _>("limit_value")? != limit {
                return Err(AdminError::Conflict("quota limits"));
            }
        } else {
            sqlx::query("INSERT INTO quota_accounts(tenant_id,project_id,dimension,limit_value) VALUES($1,$2,$3,$4)")
                .bind(tenant).bind(project).bind(dimension).bind(limit).execute(&mut **tx).await?;
            changed = true;
        }
    }
    Ok(changed)
}

fn compare(actual: &Value, expected: &Value, resource: &'static str) -> Result<(), AdminError> {
    let expected = expected
        .as_object()
        .ok_or(AdminError::Invalid("invalid internal comparison"))?;
    if expected
        .iter()
        .any(|(key, value)| actual.get(key) != Some(value))
    {
        return Err(AdminError::Conflict(resource));
    }
    Ok(())
}

fn text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.chars().count() <= max && !value.chars().any(char::is_control)
}
fn dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub(crate) fn validate_issuer(value: &str, allow_loopback_http: bool) -> Result<(), AdminError> {
    let url = Url::parse(value).map_err(|_| AdminError::Invalid("invalid issuer URL"))?;
    let loopback = matches!(url.host(),Some(Host::Ipv4(ip)) if ip.is_loopback())
        || matches!(url.host(),Some(Host::Ipv6(ip)) if ip.is_loopback());
    if value.len() > 2048
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || (url.scheme() == "http" && allow_loopback_http && loopback))
    {
        return Err(AdminError::Invalid(
            "issuer must use HTTPS, except explicit literal loopback development",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn optional_feature_quotas_preserve_legacy_encoding_and_require_matched_scopes() {
        let legacy = example();
        let spec =
            parse_spec(legacy.to_string().as_bytes(), false).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            serde_json::to_value(&spec.quotas).unwrap_or_default(),
            legacy["quotas"]
        );
        for field in [
            "backup_gib",
            "backup_temp_gib",
            "file_transfers",
            "file_transfer_bytes",
        ] {
            let mut value = legacy.clone();
            value["quotas"]["tenant"][field] = json!(100);
            assert!(parse_spec(value.to_string().as_bytes(), false).is_err());
            value["quotas"]["project"][field] = json!(50);
            assert!(parse_spec(value.to_string().as_bytes(), false).is_ok());
            value["quotas"]["project"][field] = json!(101);
            assert!(parse_spec(value.to_string().as_bytes(), false).is_err());
        }
    }
    fn example() -> Value {
        json!({"tenant":{"id":"00000000-0000-4000-8000-000000000001","name":"Example"},
        "project":{"id":"00000000-0000-4000-8000-000000000002","name":"Agents","runtime_namespace":"sandbox-agents","storage_class":"sandbox-csi","max_ttl_seconds":3600},
        "initial_principal":{"id":"00000000-0000-4000-8000-000000000003","issuer":"https://id.example.com/realms/sandbox","subject":"operator-sub","kind":"USER","display_name":"Initial operator","project_actions":["*"]},
        "approved_template":{"id":"00000000-0000-4000-8000-000000000004","name":"python","version":1,"image_ref":"registry.example.com/sandbox/python","image_digest":format!("sha256:{}","a".repeat(64)),"runner_version":"1.0.0"},
        "security_policy":{"id":"00000000-0000-4000-8000-000000000005","name":"deny-all","version":1,"rules":{"profile":"deny-all","dns":true}},
        "quotas":{"tenant":{"instances":10,"cpu_millis":10000,"memory_mib":20480,"workspace_gib":200,"executions":10},"project":{"instances":2,"cpu_millis":2000,"memory_mib":4096,"workspace_gib":40,"executions":2}}})
    }
    #[test]
    fn strict_input_rejects_missing_limits_unknown_secrets_and_unsupported_security() {
        let value = example();
        let bytes = value.to_string();
        assert!(parse_spec(bytes.as_bytes(), false).is_ok());
        let mut missing = value.clone();
        missing["quotas"]["project"]
            .as_object_mut()
            .map(|v| v.remove("cpu_millis"));
        assert!(parse_spec(missing.to_string().as_bytes(), false).is_err());
        let mut secret = value.clone();
        secret["initial_principal"]["client_secret"] = json!("never-accepted");
        assert!(parse_spec(secret.to_string().as_bytes(), false).is_err());
        let mut policy = value.clone();
        policy["security_policy"]["rules"]["egress"] = json!(["*"]);
        assert!(parse_spec(policy.to_string().as_bytes(), false).is_err());
        let mut excessive = value.clone();
        excessive["quotas"]["project"]["instances"] = json!(11);
        assert!(parse_spec(excessive.to_string().as_bytes(), false).is_err());
        let mut nil = value.clone();
        nil["tenant"]["id"] = json!(Uuid::nil());
        assert!(parse_spec(nil.to_string().as_bytes(), false).is_err());
    }
    #[test]
    fn comparisons_do_not_silently_replace_revocations_or_binding_changes() {
        assert!(
            compare(
                &json!({"id":1,"enabled":true,"created_at":"irrelevant"}),
                &json!({"id":1,"enabled":true}),
                "principal"
            )
            .is_ok()
        );
        assert!(
            compare(
                &json!({"id":1,"enabled":false}),
                &json!({"id":1,"enabled":true}),
                "principal"
            )
            .is_err()
        );
        assert!(
            compare(
                &json!({"principal_id":1}),
                &json!({"principal_id":2}),
                "identity"
            )
            .is_err()
        );
    }
}
