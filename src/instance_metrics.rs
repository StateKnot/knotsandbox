//! Bounded historical metrics for an exact, tenant-authorized launch. Neither
//! an available time series nor a missing one proves application health/death.
use crate::{
    db::{Actor, Database, load_instance},
    error::ApiError,
    metrics::{
        MetricRange, MetricSeries, MetricsError, PrometheusMetrics, RuntimeMetric,
        RuntimeMetricBinding,
    },
};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceMetricQuery {
    pub metric: RuntimeMetric,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub step_seconds: i64,
    /// An omitted launch means the current launch. Explicit historical launches
    /// must still belong to this instance and the current platform epoch.
    pub launch_id: Option<Uuid>,
}
#[derive(Debug, Serialize)]
pub struct InstanceMetricResult {
    pub instance_id: Uuid,
    pub generation: i64,
    pub launch_id: Uuid,
    pub cluster_epoch: Uuid,
    pub queried_at: DateTime<Utc>,
    pub series: MetricSeries,
}

impl Database {
    async fn metric_binding(
        &self,
        actor: &Actor,
        id: Uuid,
        requested_launch: Option<Uuid>,
    ) -> Result<RuntimeMetricBinding, ApiError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(actor.tenant_id.to_string())
            .execute(&mut *tx)
            .await?;
        let instance = load_instance(&mut tx, actor.tenant_id, id, false).await?;
        Self::authorize_resource(&mut tx, actor, instance.project_id, "instances:read").await?;
        let row = sqlx::query("SELECT p.generation,p.launch_id,p.cluster_epoch,n.node_uid,n.boot_id FROM launch_permits p JOIN runtime_nodes n ON n.id=p.runtime_node_id JOIN instances i ON i.tenant_id=p.tenant_id AND i.id=p.instance_id CROSS JOIN platform_configuration c WHERE p.tenant_id=$1 AND p.project_id=$2 AND p.instance_id=$3 AND p.launch_id=COALESCE($4,i.launch_id) AND p.cluster_epoch=c.cluster_epoch AND c.singleton")
            .bind(actor.tenant_id).bind(instance.project_id).bind(id).bind(requested_launch).fetch_optional(&mut *tx).await?
            .ok_or_else(|| ApiError::conflict("METRICS_RUNTIME_UNBOUND", "No authorized runtime binding exists for the requested launch in this platform epoch"))?;
        let result = RuntimeMetricBinding {
            tenant_id: actor.tenant_id,
            project_id: instance.project_id,
            instance_id: id,
            generation: row.try_get("generation")?,
            launch_id: row.try_get("launch_id")?,
            cluster_epoch: row.try_get("cluster_epoch")?,
            node_uid: row.try_get("node_uid")?,
            host_boot_id: row.try_get("boot_id")?,
        };
        tx.commit().await?;
        Ok(result)
    }

    pub async fn instance_metrics(
        &self,
        actor: &Actor,
        id: Uuid,
        query: &InstanceMetricQuery,
        backend: Option<&PrometheusMetrics>,
    ) -> Result<InstanceMetricResult, ApiError> {
        let range =
            MetricRange::new(query.start, query.end, query.step_seconds).map_err(metric_error)?;
        let before = self.metric_binding(actor, id, query.launch_id).await?;
        let backend = backend.ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "METRICS_BACKEND_UNAVAILABLE",
                "The metrics backend is not configured",
            )
        })?;
        let fetched = backend.query(&before, query.metric, range).await;
        // A fresh transaction rechecks local identity, tenant/project authority,
        // current launch selection and DR epoch after slow external I/O. Even
        // errors from the backend do not override a revoked grant.
        let after = self.metric_binding(actor, id, query.launch_id).await?;
        if before != after {
            return Err(ApiError::conflict(
                "METRICS_RUNTIME_CHANGED",
                "The runtime binding changed during the query; select the launch again",
            ));
        }
        Ok(InstanceMetricResult {
            instance_id: id,
            generation: before.generation,
            launch_id: before.launch_id,
            cluster_epoch: before.cluster_epoch,
            queried_at: Utc::now(),
            series: fetched.map_err(metric_error)?,
        })
    }
}

fn metric_error(error: MetricsError) -> ApiError {
    match error {
        MetricsError::Query => ApiError::invalid(
            "Metrics require a range within the last 90 days, no future time, at most 7 days, step 15..3600 seconds, and at most 1441 points",
        ),
        MetricsError::Response => ApiError::new(
            StatusCode::BAD_GATEWAY,
            "METRICS_RESPONSE_INVALID",
            "The backend returned incomplete or inconsistent metrics",
        ),
        MetricsError::Overloaded => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "METRICS_READ_OVERLOADED",
            "This replica is at its metrics read concurrency limit",
        ),
        _ => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "METRICS_BACKEND_UNAVAILABLE",
            "The metrics backend is unavailable",
        ),
    }
}
