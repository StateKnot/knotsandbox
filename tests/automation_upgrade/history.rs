//! Nonempty historical accounting and acceptance facts. Accounting transitions
//! below do not register a runtime, close a VM, or certify a storage object.
use anyhow::ensure;
use chrono::{DateTime, Duration, Utc};
use sandbox_platform::{
    db::{
        Idempotency, insert_operation, load_instance, load_operation, record_acceptance,
        reserve_quota,
    },
    grants::{CreateGrant, GrantReceipt, ProjectGrant},
    model::{Accepted, CreateInstance, Flavor, WorkspaceSpec},
    request::request_digest,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use super::{Scope, tenant_tx};

pub(super) async fn seed_nonempty_history(owner: &PgPool, scopes: &[Scope]) -> anyhow::Result<()> {
    ensure!(
        scopes.len() == 2,
        "Historical coverage requires two tenants"
    );
    for scope in scopes {
        let mut tx = tenant_tx(owner, scope.tenant).await?;
        let actor = scope.actor();
        let resource = load_instance(&mut tx, scope.tenant, scope.instance, false)
            .await
            .map_err(|e| anyhow::anyhow!("Historical resource: {}", e.code))?;
        let request = CreateInstance {
            project_id: scope.project,
            name: resource.name.clone(),
            template_version_id: resource.template_version_id,
            security_profile_id: resource.security_policy_version_id,
            flavor: Flavor::Cpu1Mem2,
            workspace: WorkspaceSpec { size_gib: 20 },
            ttl_seconds: Some(3600),
            client_reference: Some("historical-upgrade-acceptance".into()),
        };
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let operation_id = Uuid::new_v4();
        insert_operation(
            &mut tx,
            &actor,
            operation_id,
            scope.project,
            scope.instance,
            scope.workspace,
            "CREATE",
            &json!(request),
            now + Duration::hours(1),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Historical operation: {}", e.code))?;

        // The same tenant and project accounts required by normal acceptance.
        for project in [None, Some(scope.project)] {
            for (dimension, limit) in [
                ("INSTANCES", 10_i64),
                ("CPU_MILLIS", 10000),
                ("MEMORY_MIB", 20480),
                ("WORKSPACE_GIB", 200),
            ] {
                sqlx::query("INSERT INTO quota_accounts(tenant_id,project_id,dimension,limit_value) VALUES($1,$2,$3,$4)")
                    .bind(scope.tenant).bind(project).bind(dimension).bind(limit)
                    .execute(&mut *tx).await?;
            }
        }
        reserve_quota(
            &mut tx,
            &actor,
            scope.project,
            operation_id,
            scope.instance,
            scope.workspace,
            &[
                ("INSTANCES", 1),
                ("CPU_MILLIS", 1000),
                ("MEMORY_MIB", 2048),
                ("WORKSPACE_GIB", 20),
            ],
        )
        .await
        .map_err(|e| anyhow::anyhow!("Historical reservation: {}", e.code))?;

        // Capture legal preexisting accounting states with exact balanced
        // amounts. No ready/termination/storage receipt is inserted: those
        // capabilities cannot be inferred from quota accounting alone.
        let reservations: Vec<(Uuid, Uuid, String, i64)> = sqlx::query_as(
            "SELECT r.id,r.quota_account_id,q.dimension,r.amount FROM quota_reservations r JOIN quota_accounts q ON q.tenant_id=r.tenant_id AND q.id=r.quota_account_id WHERE r.tenant_id=$1 AND r.operation_id=$2 ORDER BY q.id,r.id"
        ).bind(scope.tenant).bind(operation_id).fetch_all(&mut *tx).await?;
        ensure!(
            reservations.len() == 8,
            "All paired quotas must be reserved"
        );
        for (reservation, account, dimension, amount) in reservations {
            if matches!(dimension.as_str(), "CPU_MILLIS" | "WORKSPACE_GIB") {
                sqlx::query("UPDATE quota_accounts SET pending=pending-$3,allocated=allocated+$3,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
                    .bind(scope.tenant).bind(account).bind(amount).execute(&mut *tx).await?;
                sqlx::query("UPDATE quota_reservations SET status='ALLOCATED',updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND status='PENDING'")
                    .bind(scope.tenant).bind(reservation).execute(&mut *tx).await?;
            } else if dimension == "MEMORY_MIB" {
                sqlx::query("UPDATE quota_accounts SET pending=pending-$3,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
                    .bind(scope.tenant).bind(account).bind(amount).execute(&mut *tx).await?;
                sqlx::query("UPDATE quota_reservations SET status='RELEASED',released_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND status='PENDING'")
                    .bind(scope.tenant).bind(reservation).execute(&mut *tx).await?;
            }
        }

        let operation = load_operation(&mut tx, scope.tenant, operation_id)
            .await
            .map_err(|e| anyhow::anyhow!("Historical accepted operation: {}", e.code))?;
        record_acceptance(&mut tx, &actor, &resource, &operation, "instances:create")
            .await
            .map_err(|e| anyhow::anyhow!("Historical acceptance event: {}", e.code))?;
        let accepted = Accepted {
            resource,
            operation,
            idempotency_expires_at: now + Duration::days(7),
        };
        let digest = request_digest(&request, None)
            .map_err(|e| anyhow::anyhow!("Historical create digest: {}", e.code))?;
        Idempotency::new(
            &actor,
            scope.project,
            "instances:create",
            "historical-create",
            &digest,
        )
        .persist(&mut tx, &accepted, 202, now)
        .await
        .map_err(|e| anyhow::anyhow!("Historical idempotency acceptance: {}", e.code))?;

        // A management receipt has the normal typed resource + expiry shape,
        // rather than an arbitrary JSON object that the reader cannot replay.
        let grant: ProjectGrant = sqlx::query_as("SELECT * FROM grants WHERE tenant_id=$1 AND project_id=$2 AND principal_id=$3 AND action='instances:renew'")
            .bind(scope.tenant).bind(scope.project).bind(scope.principal)
            .fetch_one(&mut *tx).await?;
        let create_grant = CreateGrant {
            principal_id: grant.principal_id,
            action: grant.action.clone(),
            expires_at: grant.expires_at,
        };
        let digest = request_digest(&create_grant, None)
            .map_err(|e| anyhow::anyhow!("Historical grant digest: {}", e.code))?;
        let grant_id = grant.id;
        let receipt = GrantReceipt {
            resource: grant,
            idempotency_expires_at: now + Duration::days(7),
        };
        sqlx::query("INSERT INTO management_receipts(tenant_id,project_id,principal_id,action,target_id,key_hash,request_hash,resource_id,response_status,response_body,created_at,expires_at,tombstone_until) VALUES($1,$2,$3,'grants:create',$2,$4,$5,$6,201,$7,$8,$9,$10)")
            .bind(scope.tenant).bind(scope.project).bind(scope.principal)
            .bind(format!("{:x}", Sha256::digest(b"historical-grant-create")))
            .bind(digest).bind(grant_id).bind(json!(receipt)).bind(now)
            .bind(receipt.idempotency_expires_at)
            .bind(receipt.idempotency_expires_at + Duration::days(90))
            .execute(&mut *tx).await?;

        // LEGAL protection has no guest/storage prerequisites. A BACKUP hold
        // would require a genuinely accepted, fully closed-source backup; this
        // fixture has no such capability and deliberately creates none.
        for released in [false, true] {
            let hold = Uuid::new_v4();
            sqlx::query("INSERT INTO workspace_holds(id,tenant_id,project_id,workspace_id,kind,reference_id,reason) VALUES($1,$2,$3,$4,'LEGAL',$5,'Historical legal preservation intent')")
                .bind(hold).bind(scope.tenant).bind(scope.project).bind(scope.workspace)
                .bind(Uuid::new_v4()).execute(&mut *tx).await?;
            if released {
                sqlx::query("INSERT INTO workspace_hold_releases(hold_id,tenant_id,reason) VALUES($1,$2,'Historical legal authority released')")
                    .bind(hold).bind(scope.tenant).execute(&mut *tx).await?;
            }
        }
        tx.commit().await?;
    }
    assert_nonempty_history(owner, scopes).await
}

pub(super) async fn assert_nonempty_history(
    owner: &PgPool,
    scopes: &[Scope],
) -> anyhow::Result<()> {
    ensure!(
        scopes.len() == 2,
        "Historical coverage requires two tenants"
    );
    for scope in scopes {
        let mut tx = tenant_tx(owner, scope.tenant).await?;
        let counts: (i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM quota_accounts WHERE tenant_id=$1),(SELECT count(*) FROM quota_reservations WHERE tenant_id=$1),(SELECT count(*) FROM quota_reservations WHERE tenant_id=$1 AND status='PENDING'),(SELECT count(*) FROM quota_reservations WHERE tenant_id=$1 AND status='ALLOCATED'),(SELECT count(*) FROM quota_reservations WHERE tenant_id=$1 AND status='RELEASED'),(SELECT count(*) FROM workspace_holds WHERE tenant_id=$1 AND project_id=$2 AND workspace_id=$3 AND kind='LEGAL'),(SELECT count(*) FROM workspace_hold_releases r JOIN workspace_holds h ON h.tenant_id=r.tenant_id AND h.id=r.hold_id WHERE h.tenant_id=$1 AND h.project_id=$2 AND h.workspace_id=$3 AND h.kind='LEGAL')"
        ).bind(scope.tenant).bind(scope.project).bind(scope.workspace).fetch_one(&mut *tx).await?;
        ensure!(
            counts == (8, 8, 2, 4, 2, 2, 1),
            "Historical facts cannot be empty or lose any accounting/hold state"
        );
        let balanced: bool = sqlx::query_scalar(
            "SELECT bool_and(q.pending=coalesce((SELECT sum(r.amount) FROM quota_reservations r WHERE r.tenant_id=q.tenant_id AND r.quota_account_id=q.id AND r.status='PENDING'),0) AND q.allocated=coalesce((SELECT sum(r.amount) FROM quota_reservations r WHERE r.tenant_id=q.tenant_id AND r.quota_account_id=q.id AND r.status='ALLOCATED'),0)) FROM quota_accounts q WHERE q.tenant_id=$1"
        ).bind(scope.tenant).fetch_one(&mut *tx).await?;
        ensure!(
            balanced,
            "Historical quota balances must equal reservation amounts"
        );

        let bodies: Vec<Value> = sqlx::query_scalar("SELECT response_body FROM idempotency_keys WHERE tenant_id=$1 AND project_id=$2 AND principal_id=$3 AND operation_name='instances:create' AND target_id=$2 AND response_status=202")
            .bind(scope.tenant).bind(scope.project).bind(scope.principal).fetch_all(&mut *tx).await?;
        ensure!(
            bodies.len() == 1,
            "A real create acceptance receipt is required per tenant"
        );
        let accepted: Accepted = serde_json::from_value(bodies[0].clone())?;
        ensure!(
            accepted.resource.id == scope.instance
                && accepted.resource.tenant_id == scope.tenant
                && accepted.resource.project_id == scope.project
                && accepted.resource.workspace_id == scope.workspace
                && accepted.operation.tenant_id == scope.tenant
                && accepted.operation.project_id == scope.project
                && accepted.operation.instance_id == Some(scope.instance)
                && accepted.operation.workspace_id == Some(scope.workspace)
                && accepted.operation.kind == "CREATE"
                && accepted.operation.status == "QUEUED"
                && accepted.resource.observed_state == "PENDING",
            "Historical accepted JSON must retain exact resource and operation scope"
        );
        let receipt_links: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM idempotency_keys k JOIN operations o ON o.tenant_id=k.tenant_id AND o.project_id=k.project_id AND o.id=k.operation_id WHERE k.tenant_id=$1 AND k.operation_name='instances:create' AND k.resource_id=$2 AND k.operation_id=$3 AND o.kind='CREATE' AND o.request->>'client_reference'='historical-upgrade-acceptance' AND k.response_body->>'idempotency_expires_at' IS NOT NULL)")
            .bind(scope.tenant).bind(scope.instance).bind(accepted.operation.id).fetch_one(&mut *tx).await?;
        ensure!(
            receipt_links,
            "Historical acceptance must reference its persisted operation"
        );

        let bodies: Vec<Value> = sqlx::query_scalar("SELECT response_body FROM management_receipts WHERE tenant_id=$1 AND project_id=$2 AND principal_id=$3 AND action='grants:create' AND target_id=$2 AND response_status=201")
            .bind(scope.tenant).bind(scope.project).bind(scope.principal).fetch_all(&mut *tx).await?;
        ensure!(
            bodies.len() == 1,
            "A real grant management receipt is required per tenant"
        );
        let receipt: GrantReceipt = serde_json::from_value(bodies[0].clone())?;
        ensure!(
            receipt.resource.tenant_id == scope.tenant
                && receipt.resource.project_id == scope.project
                && receipt.resource.principal_id == scope.principal
                && receipt.resource.action == "instances:renew"
                && receipt.resource.enabled
                && receipt.resource.revoked_at.is_none(),
            "Historical management JSON must retain exact enabled grant scope"
        );
        let grant_links: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM management_receipts m JOIN grants g ON g.tenant_id=m.tenant_id AND g.project_id=m.project_id AND g.id=m.resource_id WHERE m.tenant_id=$1 AND m.action='grants:create' AND m.resource_id=$2 AND m.response_body->'resource'->>'id'=g.id::text)")
            .bind(scope.tenant).bind(receipt.resource.id).fetch_one(&mut *tx).await?;
        ensure!(
            grant_links,
            "Historical management receipt must reference its persisted grant"
        );
        tx.commit().await?;
    }
    Ok(())
}
