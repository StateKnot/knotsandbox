//! Read-only cloud disk observations. Neither Available nor an empty query is a
//! fence, deletion receipt, or permission to release a workspace/storage quota.
use super::*;

/// Only construct from the trusted workspace/PVC/PV ledger and deployment
/// configuration. Tenant-supplied disk IDs or tags are not ownership evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudDiskBinding {
    pub account_id: String,
    pub region: String,
    pub disk_id: String,
    pub zone_id: String,
    pub deployment: String,
    pub namespace: String,
    pub pvc_name: String,
    pub pv_name: String,
    pub kms_key_id: String,
    pub size_gib: u32,
}

/// An immutable cloud identity pinned in the trusted volume-deletion ledger.
/// Construct initially with `CloudDiskObservation::identity`, then persist it
/// before any deletion intent. It is not a termination/ownership authorization.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudDiskIdentity {
    pub binding: CloudDiskBinding,
    pub serial_number: String,
    pub creation_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CloudDiskState {
    InUse,
    Available,
    Attaching,
    Detaching,
    Creating,
    ReInitializing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CloudDiskAttachmentState {
    /// All four documented attachment representations are explicitly empty.
    ExplicitlyEmpty,
    /// At least one representation still references a mount/attachment.
    Present,
    /// Missing information is not converted into an empty attachment set.
    Incomplete,
}

#[derive(Debug, Clone, Serialize)]
pub struct CloudDiskObservation {
    binding: CloudDiskBinding,
    state: CloudDiskState,
    attachment_state: CloudDiskAttachmentState,
    attached_instance_ids: Vec<String>,
    delete_auto_snapshot: bool,
    serial_number: Option<String>,
    creation_time: Option<DateTime<Utc>>,
    evidence: CloudRequestEvidence,
}
impl CloudDiskObservation {
    pub fn binding(&self) -> &CloudDiskBinding {
        &self.binding
    }
    pub fn state(&self) -> CloudDiskState {
        self.state
    }
    pub fn attachment_state(&self) -> CloudDiskAttachmentState {
        self.attachment_state
    }
    pub fn attached_instance_ids(&self) -> &[String] {
        &self.attached_instance_ids
    }
    pub fn delete_auto_snapshot(&self) -> bool {
        self.delete_auto_snapshot
    }
    pub fn evidence(&self) -> &CloudRequestEvidence {
        &self.evidence
    }
    pub fn identity(&self) -> Result<CloudDiskIdentity, CloudError> {
        let missing = || CloudError {
            code: CloudErrorCode::MalformedResponse,
            evidence: Some(self.evidence.clone()),
        };
        Ok(CloudDiskIdentity {
            binding: self.binding.clone(),
            serial_number: self.serial_number.clone().ok_or_else(missing)?,
            creation_time: self.creation_time.ok_or_else(missing)?,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CloudDiskAbsence {
    binding: CloudDiskBinding,
    evidence: CloudRequestEvidence,
}
impl CloudDiskAbsence {
    pub fn binding(&self) -> &CloudDiskBinding {
        &self.binding
    }
    pub fn evidence(&self) -> &CloudRequestEvidence {
        &self.evidence
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(
    tag = "observation",
    content = "details",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum CloudDiskLookup {
    Present(CloudDiskObservation),
    Absent(CloudDiskAbsence),
}

impl AlibabaCloudFencing {
    pub async fn observe_disk(
        &self,
        binding: &CloudDiskBinding,
    ) -> Result<CloudDiskLookup, CloudError> {
        self.validate_disk_binding(binding)?;
        tokio::time::timeout(Duration::from_secs(45), self.observe_disk_inner(binding))
            .await
            .map_err(|_| err(CloudErrorCode::Transport))?
    }

    fn validate_disk_binding(&self, b: &CloudDiskBinding) -> Result<(), CloudError> {
        let name = |s: &str, limit: usize| {
            !s.is_empty()
                && s.len() <= limit
                && s.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"-.".contains(&c))
                && s.as_bytes()[0].is_ascii_alphanumeric()
                && s.as_bytes()[s.len() - 1].is_ascii_alphanumeric()
        };
        if b.account_id != self.inner.config.account_id
            || b.region != self.inner.config.region
            || !resource_id(&b.disk_id, "d-")
            || !name(&b.zone_id, 64)
            || !b.zone_id.starts_with(&format!("{}-", b.region))
            || !(self.inner.disk_deployment.as_deref() == Some(&b.deployment)
                || self
                    .inner
                    .bindings
                    .values()
                    .any(|n| n.deployment == b.deployment))
            || !name(&b.namespace, 63)
            || b.namespace.contains('.')
            || !name(&b.pvc_name, 253)
            || !name(&b.pv_name, 253)
            || b.kms_key_id.is_empty()
            || b.kms_key_id.len() > 128
            || !b
                .kms_key_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            || b.size_gib == 0
        {
            return Err(err(CloudErrorCode::Configuration));
        }
        Ok(())
    }

    async fn observe_disk_inner(
        &self,
        binding: &CloudDiskBinding,
    ) -> Result<CloudDiskLookup, CloudError> {
        let credentials = self.credentials().await?;
        // Only exact ID and region filters: filtering by state, attachment, tag,
        // zone, or encryption would hide drift as a false absence observation.
        let query = BTreeMap::from([
            ("RegionId".into(), binding.region.clone()),
            (
                "DiskIds".into(),
                serde_json::to_string(&[&binding.disk_id])
                    .map_err(|_| err(CloudErrorCode::Configuration))?,
            ),
            ("MaxResults".into(), "10".into()),
        ]);
        let response = self
            .read_request(
                "DescribeDisks",
                ECS_VERSION,
                &self.inner.ecs,
                &query,
                Some(&credentials),
            )
            .await?;
        let result: DescribeDisks = parse_response(&response)?;
        if !result.next_token.as_deref().unwrap_or("").is_empty() || result.disks.disk.len() > 1 {
            return Err(response_error(CloudErrorCode::IdentityMismatch, &response));
        }
        let Some(disk) = result.disks.disk.into_iter().next() else {
            return Ok(CloudDiskLookup::Absent(CloudDiskAbsence {
                binding: binding.clone(),
                evidence: response.evidence,
            }));
        };
        let mut tags = BTreeMap::new();
        for tag in &disk.tags.tag {
            if tags
                .insert(tag.tag_key.as_str(), tag.tag_value.as_str())
                .is_some()
            {
                return Err(response_error(CloudErrorCode::IdentityMismatch, &response));
            }
        }
        if disk.disk_id != binding.disk_id
            || disk.region_id != binding.region
            || disk.zone_id != binding.zone_id
            || disk.disk_type != "data"
            || disk.category != "cloud_essd"
            || !disk.portable
            || !disk.encrypted
            || disk.kms_key_id != binding.kms_key_id
            || disk.size != binding.size_gib
            || disk.disk_charge_type != "PostPaid"
            || disk.delete_with_instance
            || disk.multi_attach != "Disabled"
            || tags.get("Deployment") != Some(&binding.deployment.as_str())
            || tags.get("kubernetes.io/created-for/pvc/namespace")
                != Some(&binding.namespace.as_str())
            || tags.get("kubernetes.io/created-for/pvc/name") != Some(&binding.pvc_name.as_str())
            || tags.get("kubernetes.io/created-for/pv/name") != Some(&binding.pv_name.as_str())
        {
            return Err(response_error(CloudErrorCode::IdentityMismatch, &response));
        }
        let state = match disk.status.as_str() {
            "In_use" => CloudDiskState::InUse,
            "Available" => CloudDiskState::Available,
            "Attaching" => CloudDiskState::Attaching,
            "Detaching" => CloudDiskState::Detaching,
            "Creating" => CloudDiskState::Creating,
            "ReIniting" => CloudDiskState::ReInitializing,
            _ => return Err(response_error(CloudErrorCode::MalformedResponse, &response)),
        };
        if disk
            .serial_number
            .as_deref()
            .is_some_and(|s| !valid_serial(s))
            || disk
                .creation_time
                .is_some_and(|t| t.timestamp() <= 0 || t > Utc::now() + ChronoDuration::seconds(30))
        {
            return Err(response_error(CloudErrorCode::MalformedResponse, &response));
        }
        let mut ids = std::collections::BTreeSet::new();
        if let Some(id) = disk.instance_id.as_deref().filter(|id| !id.is_empty()) {
            ids.insert(id.to_owned());
        }
        for attachment in disk
            .attachments
            .as_ref()
            .and_then(|a| a.attachment.as_ref())
            .into_iter()
            .flatten()
            .chain(
                disk.mount_instances
                    .as_ref()
                    .and_then(|a| a.mount_instance.as_ref())
                    .into_iter()
                    .flatten(),
            )
        {
            if !resource_id(&attachment.instance_id, "i-") {
                return Err(response_error(CloudErrorCode::MalformedResponse, &response));
            }
            ids.insert(attachment.instance_id.clone());
        }
        if ids.iter().any(|id| !resource_id(id, "i-")) {
            return Err(response_error(CloudErrorCode::MalformedResponse, &response));
        }
        let attachment_state = if !ids.is_empty() || disk.mount_instance_num.is_some_and(|n| n > 0)
        {
            CloudDiskAttachmentState::Present
        } else if disk.instance_id.as_deref() == Some("")
            && disk.mount_instance_num == Some(0)
            && disk
                .attachments
                .as_ref()
                .and_then(|a| a.attachment.as_ref())
                .is_some_and(Vec::is_empty)
            && disk
                .mount_instances
                .as_ref()
                .and_then(|a| a.mount_instance.as_ref())
                .is_some_and(Vec::is_empty)
        {
            CloudDiskAttachmentState::ExplicitlyEmpty
        } else {
            CloudDiskAttachmentState::Incomplete
        };
        Ok(CloudDiskLookup::Present(CloudDiskObservation {
            binding: binding.clone(),
            state,
            attachment_state,
            attached_instance_ids: ids.into_iter().collect(),
            delete_auto_snapshot: disk.delete_auto_snapshot,
            serial_number: disk.serial_number,
            creation_time: disk.creation_time,
            evidence: response.evidence,
        }))
    }
}

pub(super) fn valid_serial(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DescribeDisks {
    disks: Disks,
    next_token: Option<String>,
    // As documented, TotalCount is meaningless with token pagination.
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Disks {
    disk: Vec<Disk>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Disk {
    disk_id: String,
    region_id: String,
    zone_id: String,
    #[serde(rename = "Type")]
    disk_type: String,
    category: String,
    portable: bool,
    encrypted: bool,
    #[serde(rename = "KMSKeyId")]
    kms_key_id: String,
    size: u32,
    disk_charge_type: String,
    delete_with_instance: bool,
    delete_auto_snapshot: bool,
    multi_attach: String,
    tags: Tags,
    status: String,
    serial_number: Option<String>,
    creation_time: Option<DateTime<Utc>>,
    instance_id: Option<String>,
    mount_instance_num: Option<u32>,
    attachments: Option<Attachments>,
    mount_instances: Option<MountInstances>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Attachments {
    attachment: Option<Vec<Attachment>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MountInstances {
    mount_instance: Option<Vec<Attachment>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Attachment {
    instance_id: String,
}
