//! Versioned, exact-identity protocol for the trusted host guard. These messages
//! are valid only on the mutually authenticated control-plane/host connection.
//! A deserialized response is not, by itself, accepted termination evidence.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_CONTROL_BODY: usize = 64 * 1024;
pub const MAX_SANDBOX_ATTEMPTS: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeBinding {
    pub cluster_epoch: Uuid,
    pub node_uid: Uuid,
    pub node_name: String,
    pub boot_id: Uuid,
    /// SHA256 of the operator-certified, immutable runtime profile.
    pub profile_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeIdentityResponse {
    pub protocol: u32,
    pub node: NodeBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackupStage {
    Capture,
    Seal,
    Restore,
}
impl BackupStage {
    pub fn name(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::Seal => "seal",
            Self::Restore => "restore",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum LaunchPurpose {
    #[default]
    Workload,
    Backup {
        backup_id: Uuid,
        /// This immutable stage attempt equals launch_id; it never follows Job retries.
        attempt_id: Uuid,
        job_uid: Uuid,
        stage: BackupStage,
        image_ref: String,
        source_pvc_uid: Uuid,
    },
}

pub fn backup_job_name(attempt: Uuid, stage: BackupStage) -> String {
    format!("sbx-bkp-{attempt}-{}", stage.name())
}
pub fn pinned_image(value: &str) -> bool {
    value.split_once("@sha256:").is_some_and(|(name, hash)| {
        !name.is_empty()
            && name.len() <= 2048
            && name.contains('/')
            && !name.starts_with('/')
            && !name.ends_with('/')
            && !name.contains("//")
            && valid_sha256(hash)
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._/:".contains(&b))
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchBinding {
    /// Missing only in pre-backup WORKLOAD journals; unknown kinds are rejected.
    #[serde(default)]
    pub purpose: LaunchPurpose,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub instance_id: Uuid,
    pub workspace_id: Uuid,
    pub generation: i64,
    pub launch_id: Uuid,
    pub pod_uid: Uuid,
    pub namespace: String,
    pub pod_name: String,
    pub pvc_uid: Uuid,
    pub pv_uid: Uuid,
    pub pv_name: String,
    pub csi_volume_handle: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterLaunchRequest {
    pub protocol: u32,
    pub permit_id: Uuid,
    pub node: NodeBinding,
    pub launch: LaunchBinding,
    /// Bounds admission of further CRI starts; it never proves an old VM dead.
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterLaunchResponse {
    pub protocol: u32,
    pub permit_id: Uuid,
    pub node: NodeBinding,
    pub launch: LaunchBinding,
    pub state: GateState,
    /// Effective durable MAX of the original and all accepted extension leases.
    pub effective_expires_at: DateTime<Utc>,
    pub journal_revision: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GateState {
    Open,
    Closed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CloseReason {
    Stop,
    Delete,
    Restart,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseRequest {
    pub protocol: u32,
    pub challenge_id: Uuid,
    pub node: NodeBinding,
    pub launch: LaunchBinding,
    pub reason: CloseReason,
    /// A response to an expired challenge must not be consumed by the controller.
    pub challenge_expires_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationState {
    WaitingInFlight,
    UnknownStart,
    WaitingRuntime,
    WaitingProcessExit,
    WaitingUnmount,
    Terminated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessRole {
    Hypervisor,
    Virtiofs,
    Shim,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub role: ProcessRole,
    pub pid: u32,
    pub start_time_ticks: u64,
    pub executable_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CgroupIdentity {
    pub relative_path: String,
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxObservation {
    pub sandbox_id: String,
    pub cgroup: CgroupIdentity,
    pub processes: Vec<ProcessIdentity>,
    pub registered_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalTerminationEvidence {
    /// Monotonic journal revision covering CLOSED plus all settled starts.
    pub journal_revision: i64,
    /// An empty list is valid only when the guard has never forwarded a start.
    pub observed_sandboxes: Vec<SandboxObservation>,
    pub forwarded_starts: u64,
    pub closed_at: DateTime<Utc>,
    pub processes_exited_at: DateTime<Utc>,
    /// The Pod-specific CSI target mount is absent; global staging may remain.
    pub pod_mounts_absent_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseResponse {
    pub protocol: u32,
    pub challenge_id: Uuid,
    pub node: NodeBinding,
    pub launch: LaunchBinding,
    pub state: ObservationState,
    pub observed_at: DateTime<Utc>,
    pub evidence: Option<LocalTerminationEvidence>,
}

pub fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl NodeBinding {
    pub fn validate(&self) -> bool {
        !self.cluster_epoch.is_nil()
            && !self.node_uid.is_nil()
            && !self.boot_id.is_nil()
            && dns_name(&self.node_name)
            && valid_sha256(&self.profile_sha256)
    }
}
impl LaunchBinding {
    pub fn validate(&self) -> bool {
        let volume_valid = !self.pvc_uid.is_nil()
            && !self.pv_uid.is_nil()
            && dns_name(&self.pv_name)
            && !self.csi_volume_handle.is_empty()
            && self.csi_volume_handle.len() <= 256
            && self
                .csi_volume_handle
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._:/".contains(&b));
        let purpose_valid = match &self.purpose {
            LaunchPurpose::Workload => {
                volume_valid && self.pod_name == format!("sbx-ws-{}", self.workspace_id)
            }
            LaunchPurpose::Backup {
                backup_id,
                attempt_id,
                job_uid,
                stage,
                image_ref,
                source_pvc_uid,
            } => {
                let prefix = format!("{}-", backup_job_name(*attempt_id, *stage));
                let pod_name_valid = self.pod_name.strip_prefix(&prefix).is_some_and(|suffix| {
                    suffix.len() == 5
                        && suffix
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                });
                let block_valid = match stage {
                    BackupStage::Seal => {
                        self.pvc_uid.is_nil()
                            && self.pv_uid.is_nil()
                            && self.pv_name.is_empty()
                            && self.csi_volume_handle.is_empty()
                    }
                    BackupStage::Capture | BackupStage::Restore => {
                        volume_valid
                            && self.pvc_uid != *source_pvc_uid
                            && self.csi_volume_handle.strip_prefix("d-").is_some_and(|s| {
                                !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric())
                            })
                    }
                };
                !backup_id.is_nil()
                    && !attempt_id.is_nil()
                    && !job_uid.is_nil()
                    && !source_pvc_uid.is_nil()
                    && *attempt_id == self.launch_id
                    && self.namespace == "sandbox-system"
                    && pinned_image(image_ref)
                    && pod_name_valid
                    && block_valid
            }
        };
        [
            self.tenant_id,
            self.project_id,
            self.instance_id,
            self.workspace_id,
            self.launch_id,
            self.pod_uid,
        ]
        .iter()
        .all(|id| !id.is_nil())
            && self.generation > 0
            && dns_name(&self.namespace)
            && self.namespace.len() <= 63
            && purpose_valid
    }
    pub fn container_name(&self) -> String {
        match self.purpose {
            LaunchPurpose::Workload => format!("workload-{}", self.launch_id),
            LaunchPurpose::Backup { .. } => "backup".into(),
        }
    }
}

fn dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && part
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
