use std::{str::FromStr, time::Duration};

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{
    PgPool, Postgres, Row, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use uuid::Uuid;

#[path = "database_process_identity.rs"]
mod process_identity;
use process_identity::DatabaseProcessIdentity;
pub use process_identity::DatabaseProcessRole;

use crate::{
    auth::VerifiedIdentity,
    domain::ComputeLease,
    error::ApiError,
    model::{Accepted, CreateInstance, Instance, Operation},
    request::request_digest,
};

#[derive(Clone)]
pub struct Database {
    pub pool: PgPool,
}

#[derive(Clone, Debug)]
pub struct Actor {
    pub tenant_id: Uuid,
    pub principal_id: Uuid,
    pub request_id: Uuid,
    /// HTTP actors always retain their verified identity. None is reserved for
    /// trusted in-process controllers whose dedicated SQL gates validate their
    /// durable authority; no request body can supply an Actor.
    pub authorization: Option<VerifiedIdentity>,
}

#[derive(Debug)]
pub struct MutationResult {
    pub status: u16,
    pub body: Accepted,
}

fn database_connect_options(
    url: &str,
    identity: Option<&DatabaseProcessIdentity>,
) -> anyhow::Result<PgConnectOptions> {
    // Do not log the URL: it contains credentials.
    let options =
        PgConnectOptions::from_str(url).map_err(|_| anyhow::anyhow!("Invalid database URL"))?;
    let loopback = options
        .get_host()
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback());
    anyhow::ensure!(
        loopback || matches!(options.get_ssl_mode(), PgSslMode::VerifyFull),
        "Remote database connections require sslmode=verify-full and a trusted server certificate"
    );
    Ok(match identity {
        Some(identity) => identity.apply(options),
        None => options,
    })
}

impl Database {
    /// API refuses to bind its listener if identity migration or the dedicated
    /// runtime grants are incomplete. The owner migration endpoint stays private.
    pub async fn check_identity_api_schema(&self) -> anyhow::Result<()> {
        let safe: bool = sqlx::query_scalar("SELECT current_user='sandbox_app' AND session_user='sandbox_app' AND has_function_privilege(current_user,'sandbox_resolve_identity(text,text,text)','EXECUTE') AND has_function_privilege(current_user,'sandbox_mutate_service_client(uuid,text,uuid,text,text,text,text,boolean,bigint)','EXECUTE') AND NOT has_function_privilege(current_user,'sandbox_bind_service_identity(text,text,text,text,text)','EXECUTE') AND NOT has_table_privilege(current_user,'principal_identities','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND NOT has_table_privilege(current_user,'service_identity_binding_audit','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')")
            .fetch_one(&self.pool).await?;
        anyhow::ensure!(
            safe,
            "API requires current SERVICE binding schema, exact app login and dedicated grants with no owner identity access"
        );
        Ok(())
    }
    pub async fn connect(url: &str, max_connections: u32) -> anyhow::Result<Self> {
        Self::connect_inner(url, max_connections, None).await
    }

    /// Executable-selected process telemetry; does not authorize a database role
    /// or prove a connection, operation, compute quota, or VM was released.
    pub async fn connect_for_process(
        url: &str,
        max_connections: u32,
        role: DatabaseProcessRole,
    ) -> anyhow::Result<Self> {
        let identity = DatabaseProcessIdentity::current(role)?;
        Self::connect_inner(url, max_connections, Some(&identity)).await
    }

    async fn connect_inner(
        url: &str,
        max_connections: u32,
        identity: Option<&DatabaseProcessIdentity>,
    ) -> anyhow::Result<Self> {
        let options = database_connect_options(url, identity)?;
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(3))
            .after_connect(|conn, _| {
                Box::pin(async move {
                    sqlx::query("SET statement_timeout = '10s'")
                        .execute(&mut *conn)
                        .await?;
                    sqlx::query("SET lock_timeout = '3s'")
                        .execute(&mut *conn)
                        .await?;
                    sqlx::query("SET idle_in_transaction_session_timeout = '15s'")
                        .execute(&mut *conn)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await
            .map_err(|_| anyhow::anyhow!("Database connection failed"))?;
        if let Some(identity) = identity {
            tracing::info!(
                role = identity.role.tag(), process_id = %identity.process_id,
                pod_uid = ?identity.pod_uid, application_name = identity.application_name(),
                max_connections, "database pool process telemetry configured"
            );
        }
        Ok(Self { pool })
    }

    pub async fn verify_runtime_role(&self) -> anyhow::Result<()> {
        // Check the authenticated login as well as an assumed current role:
        // RESET ROLE must not restore an owner/superuser or another component.
        // MEMBER is intentional: NOINHERIT can still permit SET ROLE.
        let unsafe_role: bool = sqlx::query_scalar(r#"
            SELECT EXISTS (
                SELECT 1 FROM pg_roles r WHERE r.rolname IN(current_user,session_user)
                AND (r.rolsuper OR r.rolbypassrls OR r.rolcreatedb OR r.rolcreaterole
                    OR EXISTS (SELECT 1 FROM pg_class c WHERE c.relnamespace='public'::regnamespace
                        AND pg_has_role(r.oid,c.relowner,'MEMBER'))
                    OR EXISTS (SELECT 1 FROM pg_roles peer
                        WHERE peer.rolname IN('sandbox_app','sandbox_worker','sandbox_gateway','sandbox_admission','sandbox_termination','sandbox_fencing','sandbox_volume_deleter','sandbox_backup','sandbox_automation')
                          AND peer.oid<>r.oid
                          AND (pg_has_role(r.oid,peer.oid,'MEMBER') OR pg_has_role(peer.oid,r.oid,'MEMBER'))))
            )
        "#)
            .fetch_one(&self.pool).await?;
        anyhow::ensure!(
            !unsafe_role,
            "Runtime login/current role must be unprivileged, own no tables and have no cross-component role membership"
        );
        let installed: Vec<(i64, bool, Vec<u8>)> = sqlx::query_as(
            "SELECT version,success,checksum FROM _sqlx_migrations ORDER BY version",
        )
        .fetch_all(&self.pool)
        .await?;
        verify_migration_ledger(&installed)?;
        crate::workspace_restore::verify_component_schema(&self.pool).await?;
        crate::resource_accounting_schema::verify(&self.pool).await
    }

    pub async fn resolve_actor(
        &self,
        identity: &VerifiedIdentity,
        tenant_id: Uuid,
        request_id: Uuid,
    ) -> Result<Actor, ApiError> {
        if identity.expires_at <= Utc::now().timestamp() {
            return Err(crate::request::unauthenticated());
        }
        let principal: Option<(Uuid, bool)> =
            sqlx::query_as("SELECT principal_id, enabled FROM sandbox_resolve_identity($1,$2,$3)")
                .bind(&identity.issuer)
                .bind(&identity.subject)
                .bind(&identity.client_id)
                .fetch_optional(&self.pool)
                .await?;
        let Some((principal_id, true)) = principal else {
            return Err(ApiError::forbidden());
        };
        Ok(Actor {
            tenant_id,
            principal_id,
            request_id,
            authorization: Some(identity.clone()),
        })
    }

    pub async fn begin(&self, tenant_id: Uuid) -> Result<Transaction<'_, Postgres>, ApiError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(tenant_id.to_string())
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    pub async fn authorize(
        tx: &mut Transaction<'_, Postgres>,
        actor: &Actor,
        project: Uuid,
        action: &str,
    ) -> Result<(), ApiError> {
        if let Some(identity) = &actor.authorization {
            if !identity.permits(action) {
                return Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    "INSUFFICIENT_SCOPE",
                    "OAuth action scope is missing",
                ));
            }
            // Evaluate identity and product authority in one statement snapshot;
            // project/grant waits cannot reuse an earlier successful token check.
            // The outer volatile clock is read only after both materialized checks.
            let (identity_live, allowed, token_live): (bool,bool,bool) = sqlx::query_as(r#"WITH identity AS MATERIALIZED (
                SELECT EXISTS(SELECT 1 FROM sandbox_resolve_identity($5,$6,$7) i WHERE i.principal_id=$2 AND i.enabled) AS live
            ), permitted AS MATERIALIZED (
                SELECT sandbox_principal_enabled($2) AS principal_live,coalesce(bool_or(g.expires_at IS NULL) FILTER(WHERE p.enabled AND t.enabled),false) AS indefinite,max(g.expires_at) FILTER(WHERE p.enabled AND t.enabled) AS grant_until
                FROM grants g JOIN projects p ON p.tenant_id=g.tenant_id AND p.id=$3 JOIN tenants t ON t.id=g.tenant_id WHERE g.tenant_id=$1 AND g.principal_id=$2 AND (g.project_id=$3 OR g.project_id IS NULL) AND (g.action=$4 OR g.action='*') AND g.enabled AND g.revoked_at IS NULL
            ), evaluated AS MATERIALIZED (SELECT identity.live,permitted.*,clock_timestamp() AS as_of FROM identity CROSS JOIN permitted)
            SELECT live,principal_live AND (indefinite OR coalesce(grant_until>as_of,false)),as_of<to_timestamp($8::double precision) FROM evaluated"#)
                .bind(actor.tenant_id).bind(actor.principal_id).bind(project).bind(action)
                .bind(&identity.issuer).bind(&identity.subject).bind(&identity.client_id).bind(identity.expires_at)
                .fetch_one(&mut **tx).await?;
            if !identity_live || !token_live || identity.expires_at <= Utc::now().timestamp() {
                return Err(crate::request::unauthenticated());
            }
            if !allowed {
                return Err(ApiError::forbidden());
            }
            return Ok(());
        }
        let allowed: bool = sqlx::query_scalar("SELECT sandbox_principal_enabled($2) AND EXISTS (SELECT 1 FROM grants g JOIN projects p ON p.tenant_id=g.tenant_id AND p.id=$3 JOIN tenants t ON t.id=g.tenant_id WHERE g.tenant_id=$1 AND g.principal_id=$2 AND (g.project_id=$3 OR g.project_id IS NULL) AND (g.action=$4 OR g.action='*') AND g.enabled AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>clock_timestamp()) AND p.enabled AND t.enabled)")
            .bind(actor.tenant_id).bind(actor.principal_id).bind(project).bind(action).fetch_one(&mut **tx).await?;
        if !allowed {
            return Err(ApiError::forbidden());
        }
        Ok(())
    }

    /// Shared authorization context seam. It is also called in the fresh
    /// post-I/O transaction, so identity remapping, disable, client rotation and
    /// token expiration cannot survive an external storage wait.
    pub async fn authorize_identity(
        tx: &mut Transaction<'_, Postgres>,
        actor: &Actor,
        action: &str,
    ) -> Result<(), ApiError> {
        let Some(identity) = &actor.authorization else {
            return Ok(());
        };
        if !identity.permits(action) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "INSUFFICIENT_SCOPE",
                "OAuth action scope is missing",
            ));
        }
        let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sandbox_resolve_identity($1,$2,$3) i WHERE i.principal_id=$4 AND i.enabled) AND clock_timestamp()<to_timestamp($5::double precision)")
            .bind(&identity.issuer).bind(&identity.subject).bind(&identity.client_id)
            .bind(actor.principal_id).bind(identity.expires_at).fetch_one(&mut **tx).await?;
        if !live || identity.expires_at <= Utc::now().timestamp() {
            return Err(crate::request::unauthenticated());
        }
        Ok(())
    }

    pub async fn get_instance(&self, actor: &Actor, id: Uuid) -> Result<Instance, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let instance = load_instance(&mut tx, actor.tenant_id, id, false).await?;
        Self::authorize_resource(&mut tx, actor, instance.project_id, "instances:read").await?;
        tx.commit().await?;
        Ok(instance)
    }

    pub async fn list_instances(
        &self,
        actor: &Actor,
        project: Uuid,
        limit: i64,
        after: Option<Uuid>,
    ) -> Result<Vec<Instance>, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        Self::authorize(&mut tx, actor, project, "instances:read").await?;
        let rows = sqlx::query_as::<_, Instance>("SELECT * FROM instances WHERE tenant_id=$1 AND project_id=$2 AND ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT $4")
            .bind(actor.tenant_id).bind(project).bind(after).bind(limit).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        Ok(rows)
    }

    pub async fn get_operation(&self, actor: &Actor, id: Uuid) -> Result<Operation, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let op = load_operation(&mut tx, actor.tenant_id, id).await?;
        Self::authorize_resource(&mut tx, actor, op.project_id, "operations:read").await?;
        tx.commit().await?;
        Ok(op)
    }

    pub async fn authorize_resource(
        tx: &mut Transaction<'_, Postgres>,
        actor: &Actor,
        project: Uuid,
        action: &str,
    ) -> Result<(), ApiError> {
        Self::authorize(tx, actor, project, action)
            .await
            .map_err(|error| {
                if error.status == StatusCode::FORBIDDEN {
                    ApiError::not_found()
                } else {
                    error
                }
            })
    }

    pub async fn create_instance(
        &self,
        actor: &Actor,
        request: &CreateInstance,
        key: &str,
        default_ttl: i64,
        max_ttl: i64,
    ) -> Result<MutationResult, ApiError> {
        let ttl = request.validate(default_ttl, max_ttl)?;
        let mut tx = self.begin(actor.tenant_id).await?;
        Self::authorize(&mut tx, actor, request.project_id, "instances:create").await?;
        let digest = request_digest(request, None)?;
        let idempotency =
            Idempotency::new(actor, request.project_id, "instances:create", key, &digest);
        if let Some(previous) = idempotency.replay(&mut tx).await? {
            tx.commit().await?;
            return Ok(previous);
        }
        let epoch = runnable_epoch(&mut tx).await?;
        let project = sqlx::query("SELECT max_ttl_seconds,runtime_namespace,storage_class FROM projects WHERE tenant_id=$1 AND id=$2")
            .bind(actor.tenant_id).bind(request.project_id).fetch_one(&mut *tx).await?;
        let namespace: Option<String> = project.try_get("runtime_namespace")?;
        let storage_class: Option<String> = project.try_get("storage_class")?;
        let (Some(namespace), Some(storage_class)) = (namespace, storage_class) else {
            return Err(ApiError::conflict(
                "PROJECT_NOT_PROVISIONED",
                "Project runtime has not been provisioned",
            ));
        };
        let approved: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM template_versions WHERE tenant_id=$1 AND id=$2 AND status='APPROVED') AND EXISTS(SELECT 1 FROM security_policy_versions WHERE tenant_id=$1 AND id=$3 AND status='APPROVED')")
            .bind(actor.tenant_id).bind(request.template_version_id).bind(request.security_profile_id).fetch_one(&mut *tx).await?;
        if !approved {
            return Err(ApiError::invalid(
                "Template and security profile must be approved versions in this tenant",
            ));
        }
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let lease = ComputeLease::new(
            Uuid::new_v4(),
            now,
            ttl,
            max_ttl.min(project.try_get("max_ttl_seconds")?),
        )
        .map_err(domain_error)?;
        let instance_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        let (cpu, memory) = request.flavor.resources();
        sqlx::query("INSERT INTO workspaces(id,tenant_id,project_id,size_gib,storage_class,namespace,pvc_name) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(workspace_id).bind(actor.tenant_id).bind(request.project_id).bind(request.workspace.size_gib).bind(storage_class).bind(&namespace).bind(format!("ws-{workspace_id}")).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO instances(id,tenant_id,project_id,name,template_version_id,security_policy_version_id,workspace_id,cpu_millis,memory_mib,desired_state,cluster_epoch,launch_id,namespace,pod_name,active_operation_id,compute_lease_id,compute_lease_started_at,compute_lease_expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'RUNNING',$10,$11,$12,$13,$14,$15,$16,$17)")
            .bind(instance_id).bind(actor.tenant_id).bind(request.project_id).bind(&request.name).bind(request.template_version_id).bind(request.security_profile_id).bind(workspace_id).bind(cpu).bind(memory).bind(epoch).bind(Uuid::new_v4()).bind(namespace).bind(format!("sbx-ws-{workspace_id}")).bind(operation_id).bind(lease.id).bind(lease.started_at).bind(lease.expires_at).execute(&mut *tx).await?;
        insert_operation(
            &mut tx,
            actor,
            operation_id,
            request.project_id,
            instance_id,
            workspace_id,
            "CREATE",
            &serde_json::to_value(request).map_err(|_| ApiError::invalid("Invalid request"))?,
            lease.expires_at,
        )
        .await?;
        reserve_quota(
            &mut tx,
            actor,
            request.project_id,
            operation_id,
            instance_id,
            workspace_id,
            &[
                ("INSTANCES", 1),
                ("CPU_MILLIS", cpu),
                ("MEMORY_MIB", memory),
                ("WORKSPACE_GIB", request.workspace.size_gib),
            ],
        )
        .await?;
        let resource = load_instance(&mut tx, actor.tenant_id, instance_id, false).await?;
        let operation = load_operation(&mut tx, actor.tenant_id, operation_id).await?;
        record_acceptance(&mut tx, actor, &resource, &operation, "instances:create").await?;
        let body = Accepted {
            resource,
            operation,
            idempotency_expires_at: now + chrono::Duration::days(7),
        };
        idempotency.persist(&mut tx, &body, 202, now).await?;
        tx.commit().await?;
        Ok(MutationResult { status: 202, body })
    }
}

fn verify_migration_ledger(installed: &[(i64, bool, Vec<u8>)]) -> anyhow::Result<()> {
    anyhow::ensure!(
        installed.iter().all(|(_, success, _)| *success),
        "Database contains an unsuccessful migration"
    );
    // MAX(version) cannot detect a missing intermediate migration. Validate
    // every embedded migration; never repair the ledger during application startup.
    for required in sqlx::migrate!("./migrations").iter() {
        let recorded = installed
            .iter()
            .find(|(version, _, _)| *version == required.version);
        anyhow::ensure!(
            recorded.is_some_and(|(_, success, checksum)| *success
                && checksum.as_slice() == required.checksum.as_ref()),
            "Database migration {} is missing or differs from this application build",
            required.version
        );
    }
    Ok(())
}

pub fn domain_error(error: crate::domain::DomainError) -> ApiError {
    ApiError::conflict(error.code(), error.to_string())
}

pub async fn load_instance(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    id: Uuid,
    lock: bool,
) -> Result<Instance, ApiError> {
    let sql = if lock {
        "SELECT * FROM instances WHERE tenant_id=$1 AND id=$2 FOR UPDATE"
    } else {
        "SELECT * FROM instances WHERE tenant_id=$1 AND id=$2"
    };
    sqlx::query_as(sql)
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(ApiError::not_found)
}

pub async fn load_operation(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    id: Uuid,
) -> Result<Operation, ApiError> {
    sqlx::query_as("SELECT * FROM operations WHERE tenant_id=$1 AND id=$2")
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(ApiError::not_found)
}

pub async fn runnable_epoch(tx: &mut Transaction<'_, Postgres>) -> Result<Uuid, ApiError> {
    let epoch: Option<Uuid> = sqlx::query_scalar(
        "SELECT cluster_epoch FROM platform_configuration WHERE singleton AND NOT safe_mode",
    )
    .fetch_optional(&mut **tx)
    .await?;
    epoch.ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "PLATFORM_SAFE_MODE",
            "Compute mutations are disabled by the operator",
        )
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_operation(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    id: Uuid,
    project: Uuid,
    instance: Uuid,
    workspace: Uuid,
    kind: &str,
    request: &Value,
    deadline: DateTime<Utc>,
) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO operations(id,tenant_id,project_id,instance_id,workspace_id,kind,request,actor_principal_id,request_id,deadline) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind(id).bind(actor.tenant_id).bind(project).bind(instance).bind(workspace).bind(kind).bind(request).bind(actor.principal_id).bind(actor.request_id).bind(deadline).execute(&mut **tx).await?;
    Ok(())
}

pub async fn record_acceptance(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    resource: &Instance,
    operation: &Operation,
    action: &str,
) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome) VALUES($1,$2,$3,$4,$5,$6,$7,'ACCEPTED')")
        .bind(actor.tenant_id).bind(resource.project_id).bind(actor.principal_id).bind(actor.request_id).bind(operation.id).bind(resource.id).bind(action).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(actor.tenant_id).bind(resource.project_id).bind(resource.id).bind(resource.spec_version).bind(format!("{action}.accepted")).bind(operation.id).bind(actor.request_id).bind(json!({"desired_state":resource.desired_state,"operation_id":operation.id})).execute(&mut **tx).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn reserve_quota(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    project: Uuid,
    op: Uuid,
    instance: Uuid,
    workspace: Uuid,
    dimensions: &[(&str, i64)],
) -> Result<(), ApiError> {
    let accounts = sqlx::query("SELECT id,project_id,dimension,limit_value,pending,allocated FROM quota_accounts WHERE tenant_id=$1 AND (project_id=$2 OR project_id IS NULL) ORDER BY id FOR UPDATE")
        .bind(actor.tenant_id).bind(project).fetch_all(&mut **tx).await?;
    for (dimension, amount) in dimensions {
        let matching: Vec<_> = accounts
            .iter()
            .filter(|r| r.get::<String, _>("dimension") == *dimension)
            .collect();
        if matching.len() != 2 {
            return Err(ApiError::conflict(
                "QUOTA_NOT_CONFIGURED",
                format!("Tenant and project {dimension} quotas must be configured"),
            ));
        }
        for account in matching {
            let limit: i64 = account.try_get("limit_value")?;
            let pending: i64 = account.try_get("pending")?;
            let allocated: i64 = account.try_get("allocated")?;
            if i128::from(pending) + i128::from(allocated) + i128::from(*amount) > i128::from(limit)
            {
                return Err(ApiError::conflict(
                    "QUOTA_EXCEEDED",
                    format!("{dimension} quota exceeded"),
                ));
            }
            let account_id: Uuid = account.try_get("id")?;
            sqlx::query("UPDATE quota_accounts SET pending=pending+$2,version=version+1,updated_at=clock_timestamp() WHERE id=$1 AND tenant_id=$3").bind(account_id).bind(amount).bind(actor.tenant_id).execute(&mut **tx).await?;
            sqlx::query("INSERT INTO quota_reservations(tenant_id,project_id,quota_account_id,operation_id,resource_id,amount) VALUES($1,$2,$3,$4,$5,$6)")
                .bind(actor.tenant_id).bind(project).bind(account_id).bind(op).bind(if *dimension=="WORKSPACE_GIB" {workspace} else {instance}).bind(amount).execute(&mut **tx).await?;
        }
    }
    Ok(())
}

pub struct Idempotency {
    actor: Actor,
    target: Uuid,
    operation: String,
    key_hash: String,
    request_hash: String,
}

impl Idempotency {
    pub fn new(actor: &Actor, target: Uuid, operation: &str, key: &str, digest: &[u8]) -> Self {
        Self {
            actor: actor.clone(),
            target,
            operation: operation.to_owned(),
            key_hash: hex::encode(Sha256::digest(key.as_bytes())),
            request_hash: hex::encode(digest),
        }
    }

    pub async fn replay(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<Option<MutationResult>, ApiError> {
        let Some((status, value)) = self.replay_json(tx).await? else {
            return Ok(None);
        };
        let body = serde_json::from_value(value).map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INVALID_RECEIPT",
                "Stored receipt cannot be decoded",
            )
        })?;
        Ok(Some(MutationResult { status, body }))
    }

    pub async fn replay_json(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<Option<(u16, Value)>, ApiError> {
        let lock_hash = Sha256::digest(
            format!(
                "{}:{}:{}:{}:{}",
                self.actor.tenant_id,
                self.actor.principal_id,
                self.operation,
                self.target,
                self.key_hash
            )
            .as_bytes(),
        );
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&lock_hash[..8]);
        // Hash collisions only serialize unrelated requests; full identity is in the unique key.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(i64::from_be_bytes(bytes))
            .execute(&mut **tx)
            .await?;
        let previous = sqlx::query("SELECT k.request_hash,k.response_status,k.response_body,k.expires_at>clock_timestamp() AS fresh,o.status IN ('QUEUED','RUNNING','WAITING') AS active FROM idempotency_keys k JOIN operations o ON o.tenant_id=k.tenant_id AND o.id=k.operation_id WHERE k.tenant_id=$1 AND k.principal_id=$2 AND k.operation_name=$3 AND k.target_id=$4 AND k.key_hash=$5")
            .bind(self.actor.tenant_id).bind(self.actor.principal_id).bind(&self.operation).bind(self.target).bind(&self.key_hash).fetch_optional(&mut **tx).await?;
        let Some(row) = previous else {
            return Ok(None);
        };
        if row.try_get::<String, _>("request_hash")? != self.request_hash {
            return Err(ApiError::conflict(
                "IDEMPOTENCY_CONFLICT",
                "This key was already used with different request semantics",
            ));
        }
        if !row.try_get::<bool, _>("fresh")? && !row.try_get::<bool, _>("active")? {
            return Err(ApiError::new(
                StatusCode::GONE,
                "IDEMPOTENCY_EXPIRED",
                "This key has expired; do not automatically submit with a new key",
            ));
        }
        Ok(Some((
            row.try_get::<i16, _>("response_status")? as u16,
            row.try_get("response_body")?,
        )))
    }

    pub async fn persist(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        body: &Accepted,
        status: i16,
        now: DateTime<Utc>,
    ) -> Result<(), ApiError> {
        self.persist_json(
            tx,
            body.resource.project_id,
            body.operation.id,
            body.resource.id,
            &serde_json::to_value(body).map_err(|_| ApiError::invalid("Cannot encode response"))?,
            status,
            now,
            body.idempotency_expires_at,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn persist_json(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        project: Uuid,
        operation: Uuid,
        resource: Uuid,
        body: &Value,
        status: i16,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<(), ApiError> {
        sqlx::query("INSERT INTO idempotency_keys(tenant_id,project_id,principal_id,operation_name,target_id,key_hash,request_hash,operation_id,resource_id,response_status,response_body,created_at,expires_at,tombstone_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)")
            .bind(self.actor.tenant_id).bind(project).bind(self.actor.principal_id).bind(&self.operation).bind(self.target).bind(&self.key_hash).bind(&self.request_hash).bind(operation).bind(resource).bind(status).bind(body).bind(now).bind(expires_at).bind(expires_at+chrono::Duration::days(90)).execute(&mut **tx).await?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "db_cancellation_tests.rs"]
mod cancellation_tests;

#[cfg(test)]
mod migration_guard_tests {
    use super::verify_migration_ledger;

    #[test]
    fn a_later_version_cannot_hide_a_missing_or_changed_required_migration() {
        let installed: Vec<_> = sqlx::migrate!("./migrations")
            .iter()
            .map(|m| (m.version, true, m.checksum.to_vec()))
            .collect();
        assert!(verify_migration_ledger(&installed).is_ok());
        assert!(verify_migration_ledger(&[]).is_err());
        let mut missing = installed.clone();
        missing.remove(0);
        assert!(verify_migration_ledger(&missing).is_err());
        let mut changed = installed.clone();
        changed[0].2 = vec![0; 48];
        assert!(verify_migration_ledger(&changed).is_err());
        let mut failed = installed.clone();
        failed[0].1 = false;
        assert!(verify_migration_ledger(&failed).is_err());
        let mut newer = installed;
        newer.push((i64::MAX, true, vec![1; 48]));
        assert!(verify_migration_ledger(&newer).is_ok());
        if let Some(row) = newer.last_mut() {
            row.1 = false;
        }
        assert!(verify_migration_ledger(&newer).is_err());
    }
}
