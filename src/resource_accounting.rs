//! Immutable quota facts. A requested compute contract is not a Pod resource
//! observation or a utilization denominator. Tenant/project accounts are distinct.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::{
    db::{Actor, Database, load_instance},
    error::ApiError,
    history::{CursorSigner, HistoryPage, HistoryQuery, HistoryRow, Window},
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceAccountingQuery {
    pub launch_id: Option<Uuid>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct LaunchResourceContract {
    pub id: Uuid,
    pub instance_id: Uuid,
    pub workspace_id: Uuid,
    pub generation: String,
    pub launch_id: Uuid,
    pub cluster_epoch: Uuid,
    pub operation_id: Uuid,
    pub cpu_millis: String,
    pub memory_mib: String,
    pub source: String,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct QuotaResourceReceipt {
    pub id: Uuid,
    pub reservation_id: Uuid,
    pub quota_account_id: Uuid,
    pub operation_id: Uuid,
    pub resource_id: Uuid,
    pub operation_kind: String,
    pub purpose: String,
    pub dimension: String,
    pub unit: String,
    pub account_scope: String,
    pub account_project_id: Option<Uuid>,
    pub amount: String,
    pub limit_value: String,
    pub account_version: String,
    pub pending_value: String,
    pub allocated_value: String,
    pub previous_status: Option<String>,
    pub status: String,
    pub history_start: String,
    pub captured_at: DateTime<Utc>,
    pub contract_id: Option<Uuid>,
    pub generation: Option<String>,
    pub launch_id: Option<Uuid>,
    pub cluster_epoch: Option<Uuid>,
}

impl HistoryRow for QuotaResourceReceipt {
    fn time(&self) -> DateTime<Utc> {
        self.captured_at
    }
    fn id(&self) -> Uuid {
        self.id
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceAccounting {
    pub instance_id: Uuid,
    pub selected_launch_id: Uuid,
    pub cluster_epoch: Uuid,
    pub request_evidence: String,
    pub pod_resource_evidence: String,
    pub contract: Option<LaunchResourceContract>,
    pub receipts: HistoryPage<QuotaResourceReceipt>,
}

#[derive(PartialEq, Eq)]
struct Binding {
    project: Uuid,
    workspace: Uuid,
    generation: i64,
    current_launch: Uuid,
    selected_launch: Uuid,
    epoch: Uuid,
}

impl Database {
    async fn resource_accounting_binding(
        &self,
        actor: &Actor,
        id: Uuid,
        requested: Option<Uuid>,
    ) -> Result<Binding, ApiError> {
        let mut tx = self.begin(actor.tenant_id).await?;
        let instance = load_instance(&mut tx, actor.tenant_id, id, false).await?;
        Self::authorize_resource(&mut tx, actor, instance.project_id, "instances:read").await?;
        let epoch: Uuid =
            sqlx::query_scalar("SELECT cluster_epoch FROM platform_configuration WHERE singleton")
                .fetch_one(&mut *tx)
                .await?;
        let row = sqlx::query("SELECT runtime_generation,launch_id,cluster_epoch FROM instances WHERE tenant_id=$1 AND id=$2")
            .bind(actor.tenant_id).bind(id).fetch_one(&mut *tx).await?;
        let current_launch = row.try_get("launch_id")?;
        if row.try_get::<Uuid, _>("cluster_epoch")? != epoch {
            return Err(ApiError::conflict(
                "RESOURCE_ACCOUNTING_EPOCH_CHANGED",
                "The instance belongs to a previous platform epoch",
            ));
        }
        let selected_launch = requested.unwrap_or(current_launch);
        if requested.is_some() && selected_launch != current_launch {
            let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM launch_resource_contracts WHERE tenant_id=$1 AND instance_id=$2 AND launch_id=$3 AND cluster_epoch=$4)")
                .bind(actor.tenant_id).bind(id).bind(selected_launch).bind(epoch).fetch_one(&mut *tx).await?;
            if !exists {
                return Err(ApiError::not_found());
            }
        }
        let binding = Binding {
            project: instance.project_id,
            workspace: instance.workspace_id,
            generation: row.try_get("runtime_generation")?,
            current_launch,
            selected_launch,
            epoch,
        };
        tx.commit().await?;
        Ok(binding)
    }

    /// A fresh authorization transaction after the read observes revocations
    /// that committed while the page query was waiting for a database lock.
    pub async fn resource_accounting(
        &self,
        actor: &Actor,
        id: Uuid,
        query: &ResourceAccountingQuery,
        signer: &CursorSigner,
    ) -> Result<ResourceAccounting, ApiError> {
        let binding = self
            .resource_accounting_binding(actor, id, query.launch_id)
            .await?;
        let kind = format!(
            "resource-accounting:{}:{}:{}",
            binding.epoch,
            binding.selected_launch,
            query
                .launch_id
                .map_or_else(|| "all".into(), |v| v.to_string())
        );
        let history_query = HistoryQuery {
            project_id: binding.project,
            instance_id: Some(id),
            limit: query.limit,
            cursor: query.cursor.clone(),
        };
        let window = Window::new(&history_query, actor, &kind, signer, Utc::now())?;
        let mut tx = self.begin(actor.tenant_id).await?;
        let contract = sqlx::query_as::<_, LaunchResourceContract>("SELECT id,instance_id,workspace_id,generation::text AS generation,launch_id,cluster_epoch,operation_id,cpu_millis::text AS cpu_millis,memory_mib::text AS memory_mib,source,recorded_at FROM launch_resource_contracts WHERE tenant_id=$1 AND instance_id=$2 AND launch_id=$3 AND cluster_epoch=$4 AND recorded_at<=$5")
            .bind(actor.tenant_id).bind(id).bind(binding.selected_launch).bind(binding.epoch).bind(window.cutoff)
            .fetch_optional(&mut *tx).await?;
        let fetched = sqlx::query_as::<_, QuotaResourceReceipt>(r#"
            SELECT r.id,r.reservation_id,r.quota_account_id,r.operation_id,r.resource_id,
              r.operation_kind,r.purpose,r.dimension,r.unit,r.account_scope,r.account_project_id,
              r.amount::text AS amount,r.limit_value::text AS limit_value,
              r.account_version::text AS account_version,r.pending_value::text AS pending_value,
              r.allocated_value::text AS allocated_value,r.previous_status,r.status,r.history_start,
              r.captured_at,c.id AS contract_id,c.generation::text AS generation,c.launch_id,c.cluster_epoch
            FROM quota_resource_receipts r
            JOIN operations o ON o.tenant_id=r.tenant_id AND o.id=r.operation_id
            LEFT JOIN launch_quota_bindings b ON b.tenant_id=r.tenant_id AND b.reservation_id=r.reservation_id
            LEFT JOIN launch_resource_contracts c ON c.tenant_id=b.tenant_id AND c.id=b.contract_id
            WHERE r.tenant_id=$1 AND r.project_id=$2
              AND (o.instance_id=$3 OR (o.instance_id IS NULL AND o.workspace_id=$4))
              AND ($5::uuid IS NULL OR (c.launch_id=$5 AND c.cluster_epoch=$6))
              AND r.captured_at<=$7
              AND ($8::timestamptz IS NULL OR (r.captured_at,r.id)<($8,$9))
            ORDER BY r.captured_at DESC,r.id DESC LIMIT $10
        "#).bind(actor.tenant_id).bind(binding.project).bind(id).bind(binding.workspace)
            .bind(query.launch_id).bind(binding.epoch).bind(window.cutoff).bind(window.after_time)
            .bind(window.after_id).bind(window.limit + 1).fetch_all(&mut *tx).await;
        tx.commit().await?;
        let after = self
            .resource_accounting_binding(actor, id, query.launch_id)
            .await?;
        if binding != after {
            return Err(ApiError::conflict(
                "RESOURCE_ACCOUNTING_BINDING_CHANGED",
                "The instance launch changed during the query; select it again",
            ));
        }
        Ok(ResourceAccounting {
            instance_id: id,
            selected_launch_id: binding.selected_launch,
            cluster_epoch: binding.epoch,
            request_evidence: if contract.is_some() {
                "CAPTURED"
            } else {
                "HISTORY_START_NOT_CAPTURED"
            }
            .into(),
            pod_resource_evidence: "NOT_CAPTURED".into(),
            contract,
            receipts: window.page(fetched?, &history_query, actor, &kind, signer)?,
        })
    }
}
