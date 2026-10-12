//! Compute expiry and idle stopping share the instance lock with renewal. The
//! system actor can stop compute after user grant revocation, but never delete data.

use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    db::{Actor, Database, insert_operation, load_instance, load_operation, record_acceptance},
    error::ApiError,
};

impl Database {
    pub async fn due_instances(&self) -> Result<Vec<(Uuid, Uuid)>, ApiError> {
        // The database atomically marks the bounded candidates as attempted.
        // Fair scheduling metadata never changes their real expiry deadline.
        Ok(
            sqlx::query_as("SELECT tenant_id,instance_id FROM sandbox_due_instances(100)")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn accept_due_stop(&self, tenant: Uuid, id: Uuid) -> Result<Option<Uuid>, ApiError> {
        self.accept_due_stop_inner(tenant, id, false).await
    }

    /// Timer scans defer a contested row immediately. Interactive renewal and
    /// STOP still use the same lock order and deadline check; a busy item must
    /// not spend the whole bounded scan on its per-row lock timeout.
    pub(crate) async fn try_accept_due_stop(
        &self,
        tenant: Uuid,
        id: Uuid,
    ) -> Result<Option<Uuid>, ApiError> {
        self.accept_due_stop_inner(tenant, id, true).await
    }

    async fn accept_due_stop_inner(
        &self,
        tenant: Uuid,
        id: Uuid,
        nonblocking: bool,
    ) -> Result<Option<Uuid>, ApiError> {
        let mut tx = self.begin(tenant).await?;
        if nonblocking {
            // Cover implicit FK/trigger/event-stream locks too. SET LOCAL is
            // restored on COMMIT/ROLLBACK and never changes interactive pools.
            sqlx::query("SET LOCAL lock_timeout='100ms'")
                .execute(&mut *tx)
                .await?;
        }
        let initial = load_instance(&mut tx, tenant, id, false).await?;
        let workspace_lock = if nonblocking {
            "SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE NOWAIT"
        } else {
            "SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE"
        };
        sqlx::query(workspace_lock)
            .bind(tenant)
            .bind(initial.workspace_id)
            .fetch_one(&mut *tx)
            .await?;
        let instance = if nonblocking {
            sqlx::query("SELECT id FROM instances WHERE tenant_id=$1 AND id=$2 FOR UPDATE NOWAIT")
                .bind(tenant)
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
            load_instance(&mut tx, tenant, id, false).await?
        } else {
            load_instance(&mut tx, tenant, id, true).await?
        };
        // Obtain wall time after waiting for the same lock used by renewal.
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        if instance.desired_state != "RUNNING" || instance.stop_accepted_at.is_some() {
            tx.commit().await?;
            return Ok(None);
        }
        let idle_due:bool=sqlx::query_scalar("SELECT NOT slot_held AND idle_timeout_seconds IS NOT NULL AND idle_since IS NOT NULL AND idle_since+make_interval(secs=>idle_timeout_seconds::double precision)<=clock_timestamp() FROM instances WHERE tenant_id=$1 AND id=$2")
            .bind(tenant).bind(id).fetch_one(&mut *tx).await?;
        let reason = if now >= instance.compute_lease_expires_at {
            "LEASE_EXPIRED"
        } else if idle_due {
            "IDLE"
        } else {
            tx.commit().await?;
            return Ok(None);
        };
        let principal: Uuid = sqlx::query_scalar(
            "SELECT safety_principal_id FROM platform_configuration WHERE singleton",
        )
        .fetch_one(&mut *tx)
        .await?;
        let actor = Actor {
            tenant_id: tenant,
            principal_id: principal,
            request_id: Uuid::new_v4(),
            authorization: None,
        };
        if let Some(active) = instance.active_operation_id {
            let operation_lock = if nonblocking {
                "SELECT kind,status FROM operations WHERE tenant_id=$1 AND id=$2 FOR UPDATE NOWAIT"
            } else {
                "SELECT kind,status FROM operations WHERE tenant_id=$1 AND id=$2 FOR UPDATE"
            };
            let previous = sqlx::query(operation_lock)
                .bind(tenant)
                .bind(active)
                .fetch_one(&mut *tx)
                .await?;
            let kind: String = previous.try_get("kind")?;
            let status: String = previous.try_get("status")?;
            if !matches!(kind.as_str(), "CREATE" | "START" | "RESTART")
                || !matches!(status.as_str(), "QUEUED" | "RUNNING" | "WAITING")
            {
                return Err(ApiError::conflict(
                    "OPERATION_RECONCILIATION_REQUIRED",
                    "Expiry found an incompatible active operation",
                ));
            }
            sqlx::query("UPDATE operations SET status='CANCELLED',stage='SUPERSEDED_BY_SAFETY_STOP',cancel_requested=true,lease_owner=NULL,lease_until=NULL,lease_token=lease_token+1,completed_at=$3,updated_at=$3 WHERE tenant_id=$1 AND id=$2")
                .bind(tenant).bind(active).bind(now).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details) VALUES($1,$2,$3,$4,$5,$6,'operations:cancel','ACCEPTED',$7)")
                .bind(tenant).bind(instance.project_id).bind(principal).bind(actor.request_id).bind(active).bind(id).bind(json!({"reason":reason,"termination_confirmed":false})).execute(&mut *tx).await?;
        }
        let op = Uuid::new_v4();
        insert_operation(
            &mut tx,
            &actor,
            op,
            instance.project_id,
            id,
            instance.workspace_id,
            "STOP",
            &json!({"reason":reason,"compute_lease_id":instance.compute_lease_id}),
            now + Duration::minutes(30),
        )
        .await?;
        sqlx::query(
            "UPDATE operations SET compute_lease_id=$3,stop_reason=$4 WHERE tenant_id=$1 AND id=$2",
        )
        .bind(tenant)
        .bind(op)
        .bind(instance.compute_lease_id)
        .bind(reason)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE instances SET desired_state='STOPPED',spec_version=spec_version+1,active_operation_id=$3,stop_reason=$4,stop_accepted_at=$5,idle_since=NULL,updated_at=$5 WHERE tenant_id=$1 AND id=$2")
            .bind(tenant).bind(id).bind(op).bind(reason).bind(now).execute(&mut *tx).await?;
        let workspace_update=sqlx::query("UPDATE workspaces SET active_operation_id=$3,updated_at=$4 WHERE tenant_id=$1 AND id=$2 AND (active_operation_id IS NULL OR active_operation_id=$5)")
            .bind(tenant).bind(instance.workspace_id).bind(op).bind(now).bind(instance.active_operation_id).execute(&mut *tx).await?;
        if workspace_update.rows_affected() != 1 {
            return Err(ApiError::conflict(
                "WORKSPACE_RECONCILIATION_REQUIRED",
                "The workspace has a conflicting operation; reconcile ownership before progressing",
            ));
        }
        let updated = load_instance(&mut tx, tenant, id, false).await?;
        let operation = load_operation(&mut tx, tenant, op).await?;
        record_acceptance(
            &mut tx,
            &actor,
            &updated,
            &operation,
            if reason == "LEASE_EXPIRED" {
                "instances:expire"
            } else {
                "instances:idle_stop"
            },
        )
        .await?;
        tx.commit().await?;
        Ok(Some(op))
    }
}
