//! One installation-authorized node read. No tenant scope, discovery, or writes.
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::{
    auth::VerifiedIdentity,
    db::Database,
    error::ApiError,
    metrics::{MetricsError, NodeImageMetricBinding, NodeImageMetrics, PrometheusMetrics},
    operator_access::NODE_IMAGE_READ_ACTION,
};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeImageStatus {
    pub installation_id: Uuid,
    pub cluster_epoch: Uuid,
    pub grant_id: Uuid,
    pub runtime_node_id: Uuid,
    pub node_uid: Uuid,
    pub host_boot_id: Uuid,
    pub profile_sha256: String,
    pub metrics: NodeImageMetrics,
}

#[derive(PartialEq, Eq)]
struct Binding {
    installation_id: Uuid,
    grant_id: Uuid,
    runtime_node_id: Uuid,
    metric: NodeImageMetricBinding,
}

impl Database {
    async fn node_image_binding(
        &self,
        identity: &VerifiedIdentity,
        node: Uuid,
    ) -> Result<Binding, ApiError> {
        if identity.expires_at <= Utc::now().timestamp() {
            return Err(crate::request::unauthenticated());
        }
        if !identity.permits(NODE_IMAGE_READ_ACTION) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "INSUFFICIENT_SCOPE",
                "OAuth action scope is missing",
            ));
        }
        let row = sqlx::query("SELECT * FROM sandbox_node_image_binding($1,$2,$3,$4,$5)")
            .bind(&identity.issuer)
            .bind(&identity.subject)
            .bind(&identity.client_id)
            .bind(identity.expires_at)
            .bind(node)
            .fetch_optional(&self.pool)
            .await?;
        // Recheck after acquiring a database connection and executing the gate.
        if identity.expires_at <= Utc::now().timestamp() {
            return Err(crate::request::unauthenticated());
        }
        let row = row.ok_or_else(ApiError::forbidden)?;
        let runtime_node_id = row
            .try_get::<Option<Uuid>, _>("runtime_node_id")?
            .ok_or_else(ApiError::not_found)?;
        let certified_until: DateTime<Utc> = row.try_get("certified_until")?;
        let grant_expires_at: DateTime<Utc> = row.try_get("grant_expires_at")?;
        if certified_until <= Utc::now() {
            return Err(ApiError::not_found());
        }
        if grant_expires_at <= Utc::now() {
            return Err(ApiError::forbidden());
        }
        Ok(Binding {
            installation_id: row.try_get("installation_id")?,
            grant_id: row.try_get("grant_id")?,
            runtime_node_id,
            metric: NodeImageMetricBinding {
                cluster_epoch: row.try_get("cluster_epoch")?,
                node_uid: row.try_get("node_uid")?,
                host_boot_id: row.try_get("host_boot_id")?,
                profile_sha256: row.try_get("profile_sha256")?,
            },
        })
    }

    pub async fn node_image_status(
        &self,
        identity: &VerifiedIdentity,
        node: Uuid,
        backend: Option<&PrometheusMetrics>,
    ) -> Result<NodeImageStatus, ApiError> {
        let before = self.node_image_binding(identity, node).await?;
        let result = match backend {
            Some(backend) => backend.node_image_status(&before.metric).await,
            None => Err(MetricsError::Unavailable),
        };
        // Even failed external I/O cannot bypass revocation or return a response
        // under a replacement grant. Certification renewals of this exact node
        // are allowed, but never extend the OAuth or grant deadline.
        let after = self.node_image_binding(identity, node).await?;
        if before != after {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "NODE_IMAGE_BINDING_CHANGED",
                "Installation authority or node binding changed during the read",
            ));
        }
        Ok(NodeImageStatus {
            installation_id: before.installation_id,
            cluster_epoch: before.metric.cluster_epoch,
            grant_id: before.grant_id,
            runtime_node_id: before.runtime_node_id,
            node_uid: before.metric.node_uid,
            host_boot_id: before.metric.host_boot_id,
            profile_sha256: before.metric.profile_sha256,
            metrics: result.map_err(metric_error)?,
        })
    }
}

fn metric_error(error: MetricsError) -> ApiError {
    match error {
        MetricsError::Response => ApiError::new(
            StatusCode::BAD_GATEWAY,
            "METRICS_RESPONSE_INVALID",
            "Metrics backend returned an invalid response",
        ),
        MetricsError::Overloaded => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "NODE_METRICS_OVERLOADED",
            "Node metrics read budget is busy",
        ),
        _ => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "METRICS_UNAVAILABLE",
            "Node metrics are temporarily unavailable",
        ),
    }
}
