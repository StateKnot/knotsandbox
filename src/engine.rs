//! Durable operation leasing. A lease fences database progress only; Kubernetes
//! resource identity and admission must independently fence remote side effects.

use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{db::Database, error::ApiError};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Claim {
    pub tenant_id: Uuid,
    pub operation_id: Uuid,
    pub lease_token: i64,
}

#[derive(Clone)]
pub struct OperationEngine {
    pub database: Database,
    worker_id: String,
}

impl OperationEngine {
    pub(crate) fn worker_id(&self) -> &str {
        &self.worker_id
    }
    pub fn new(database: Database, worker_id: String) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !worker_id.is_empty()
                && worker_id.len() <= 128
                && !worker_id.chars().any(char::is_control),
            "Invalid worker identity"
        );
        Ok(Self {
            database,
            worker_id,
        })
    }

    pub async fn claim(&self) -> Result<Option<Claim>, ApiError> {
        // The definer function can only return a claim, never arbitrary tenant data.
        let mut tx = self.database.pool.begin().await?;
        let claim = sqlx::query_as(
            "SELECT tenant_id,operation_id,lease_token FROM sandbox_claim_operation($1)",
        )
        .bind(&self.worker_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(claim)
    }

    /// Dedicated queue: only EXECUTE operations can be claimed by a gateway.
    pub async fn claim_execution(&self) -> Result<Option<Claim>, ApiError> {
        let mut tx = self.database.pool.begin().await?;
        let claim = sqlx::query_as(
            "SELECT tenant_id,operation_id,lease_token FROM sandbox_claim_execution($1)",
        )
        .bind(&self.worker_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(claim)
    }

    /// Only a termination identity may claim work requiring trusted VM evidence.
    pub async fn claim_termination(&self) -> Result<Option<Claim>, ApiError> {
        let mut tx = self.database.pool.begin().await?;
        let claim = sqlx::query_as(
            "SELECT tenant_id,operation_id,lease_token FROM sandbox_claim_termination($1)",
        )
        .bind(&self.worker_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(claim)
    }

    pub async fn claim_volume_deletion(&self) -> Result<Option<Claim>, ApiError> {
        let mut tx = self.database.pool.begin().await?;
        let claim = sqlx::query_as(
            "SELECT tenant_id,operation_id,lease_token FROM sandbox_claim_volume_deletion($1)",
        )
        .bind(&self.worker_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(claim)
    }

    pub async fn claim_backup(&self) -> Result<Option<Claim>, ApiError> {
        let mut tx = self.database.pool.begin().await?;
        let claim = sqlx::query_as(
            "SELECT tenant_id,operation_id,lease_token FROM sandbox_claim_backup($1)",
        )
        .bind(&self.worker_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(claim)
    }

    pub async fn heartbeat(&self, claim: &Claim) -> Result<bool, ApiError> {
        let mut tx = self.database.begin(claim.tenant_id).await?;
        let result=sqlx::query("UPDATE operations SET lease_until=clock_timestamp()+interval '30 seconds',updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND lease_owner=$3 AND lease_token=$4 AND lease_until>clock_timestamp() AND status='RUNNING'")
            .bind(claim.tenant_id).bind(claim.operation_id).bind(&self.worker_id).bind(claim.lease_token).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    /// Call after acquiring workspace -> instance locks. Never hold a DB
    /// transaction across a Kubernetes/cloud request.
    pub async fn assert_claim(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        claim: &Claim,
    ) -> Result<(), ApiError> {
        let valid:Option<bool>=sqlx::query_scalar("SELECT COALESCE(lease_owner=$3 AND lease_token=$4 AND lease_until>clock_timestamp() AND status='RUNNING',false) FROM operations WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(claim.tenant_id).bind(claim.operation_id).bind(&self.worker_id).bind(claim.lease_token).fetch_optional(&mut **tx).await?;
        if valid != Some(true) {
            return Err(ApiError::conflict(
                "WORKER_LEASE_LOST",
                "This worker no longer owns the operation",
            ));
        }
        Ok(())
    }

    /// Persist a reconciler observation without claiming a remote action ended.
    /// Waiting stops retry pressure while preserving the operation and resources.
    pub async fn wait(
        &self,
        claim: &Claim,
        stage: &str,
        reason: &str,
        retry_seconds: i64,
    ) -> Result<(), ApiError> {
        if stage.is_empty()
            || stage.len() > 128
            || reason.is_empty()
            || reason.len() > 256
            || !(1..=300).contains(&retry_seconds)
        {
            return Err(ApiError::invalid("Invalid reconciliation wait"));
        }
        let mut tx = self.database.begin(claim.tenant_id).await?;
        self.assert_claim(&mut tx, claim).await?;
        let operation = sqlx::query(
            "SELECT project_id,request_id FROM operations WHERE tenant_id=$1 AND id=$2",
        )
        .bind(claim.tenant_id)
        .bind(claim.operation_id)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("UPDATE operations SET status='WAITING',stage=$3,wait_reason=$4,next_attempt_at=clock_timestamp()+make_interval(secs=>$5::double precision),lease_owner=NULL,lease_until=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(claim.tenant_id).bind(claim.operation_id).bind(stage).bind(reason).bind(retry_seconds as f64).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload) VALUES($1,$2,$3,$4,'operation.waiting',$3,$5,$6)")
            .bind(claim.tenant_id).bind(operation.try_get::<Uuid,_>("project_id")?).bind(claim.operation_id).bind(claim.lease_token).bind(operation.try_get::<Uuid,_>("request_id")?).bind(json!({"stage":stage,"reason":reason})).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn lease_deadline(&self, claim: &Claim) -> Result<Option<DateTime<Utc>>, ApiError> {
        let mut tx = self.database.begin(claim.tenant_id).await?;
        let deadline=sqlx::query_scalar("SELECT lease_until FROM operations WHERE tenant_id=$1 AND id=$2 AND lease_owner=$3 AND lease_token=$4 AND status='RUNNING'")
            .bind(claim.tenant_id).bind(claim.operation_id).bind(&self.worker_id).bind(claim.lease_token).fetch_optional(&mut *tx).await?;
        tx.commit().await?;
        Ok(deadline.flatten())
    }
}
