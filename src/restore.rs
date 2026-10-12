//! Restores create a distinct target workspace. The signed backup identity is
//! immutable source evidence and never rewritten to describe that target.
use crate::{error::ApiError, model::Flavor};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRestore {
    pub target_project_id: Uuid,
    pub name: String,
    /// Current approved runtime/cloud profile, not the source's historical approval.
    pub profile_id: Uuid,
    pub template_version_id: Uuid,
    pub security_profile_id: Uuid,
    pub flavor: Flavor,
}
impl CreateRestore {
    pub fn validate(&self) -> Result<(), ApiError> {
        if [
            self.target_project_id,
            self.profile_id,
            self.template_version_id,
            self.security_profile_id,
        ]
        .iter()
        .any(Uuid::is_nil)
            || !crate::backup_manifest::valid_name(&self.name)
        {
            return Err(ApiError::invalid(
                "Restore requires current target/profile identities and a DNS label name",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Restore {
    pub id: Uuid,
    pub backup_id: Uuid,
    pub source_project_id: Uuid,
    pub target_project_id: Uuid,
    pub workspace_id: Uuid,
    pub instance_id: Uuid,
    pub operation_id: Uuid,
    pub status: String,
    pub version: i64,
    pub size_gib: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct RestoreAccepted {
    pub resource: Restore,
    pub operation: crate::model::Operation,
    pub idempotency_expires_at: DateTime<Utc>,
}
pub struct RestoreMutationResult {
    pub status: u16,
    pub body: RestoreAccepted,
}

#[path = "restore_host.rs"]
pub(crate) mod host;
#[path = "restore_host_ledger.rs"]
pub(crate) mod host_ledger;
#[path = "restore_ledger.rs"]
pub(crate) mod ledger;
#[path = "restore_manifest.rs"]
pub(crate) mod manifest;
#[path = "restore_node_topology_owner.rs"]
pub(crate) mod node_topology_owner;
#[path = "restore_policy.rs"]
pub(crate) mod policy;
#[path = "restore_resources.rs"]
pub(crate) mod resources;
#[path = "restore_storage.rs"]
pub(crate) mod storage;
#[path = "restore_storage_contract.rs"]
pub(crate) mod storage_contract;
#[cfg(test)]
#[path = "restore_tests.rs"]
mod tests;
#[path = "restore_vendor_profile.rs"]
pub(crate) mod vendor_profile;

#[derive(Clone, sqlx::FromRow)]
pub(crate) struct RestoreRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub backup_id: Uuid,
    pub source_project_id: Uuid,
    pub target_project_id: Uuid,
    pub workspace_id: Uuid,
    pub instance_id: Uuid,
    pub operation_id: Uuid,
    pub profile_id: Uuid,
    pub cluster_epoch: Uuid,
    pub source_manifest_sha256: String,
    pub source_identity: serde_json::Value,
    pub storage_contract: serde_json::Value,
    pub size_gib: i64,
    pub status: String,
    pub version: i64,
    pub deadline: DateTime<Utc>,
}
impl RestoreRecord {
    pub(crate) fn storage(&self) -> Result<storage_contract::RestoreStorageContract, ApiError> {
        let contract = storage_contract::RestoreStorageContract::parse(&self.storage_contract)
            .map_err(|_| policy::invalid())?;
        if contract.profile_id != self.profile_id || contract.cluster_epoch != self.cluster_epoch {
            return Err(policy::invalid());
        }
        Ok(contract)
    }
}

#[path = "restore_csi.rs"]
pub(crate) mod csi;
#[path = "restore_snapshot_ledger.rs"]
pub(crate) mod snapshot_ledger;

#[path = "restore_completion.rs"]
pub(crate) mod completion;

#[path = "restore_gc.rs"]
pub(crate) mod gc;

#[path = "restore_gc_admission.rs"]
pub(crate) mod gc_admission;

#[path = "restore_admission.rs"]
pub(crate) mod admission;

// Closed restore development boundary; no public API/activation.
#[cfg(test)]
#[path = "restore_raw_bound_collector.rs"]
pub(crate) mod raw_bound_collector;
#[cfg(test)]
#[path = "restore_raw_volume.rs"]
pub(crate) mod raw_volume;

#[path = "restore_profile_owner.rs"]
pub(crate) mod profile_owner;

#[path = "restore_csi_pod_projection.rs"]
pub(crate) mod csi_pod_projection;
