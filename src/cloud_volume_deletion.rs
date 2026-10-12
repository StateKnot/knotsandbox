//! Separately credentialed data-disk deletion. No node stop/detach, snapshots,
//! tagging, or general disk mutation is exposed. A narrow preservation method
//! can only disable automatic-snapshot cascade deletion. Authorization belongs to the
//! caller's workspace deletion ledger, never to this transport's observations.
use super::*;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudVolumeDeletionConfig {
    pub account_id: String,
    pub region: String,
    pub role_arn: String,
    pub role_id: String,
    pub oidc_provider_arn: String,
    pub oidc_issuer: String,
    pub oidc_audience: String,
    pub oidc_subject: String,
    pub oidc_token_file: PathBuf,
    pub deployment: String,
    pub requests_per_second: u32,
    pub max_in_flight: usize,
}
impl From<&CloudVolumeDeletionConfig> for CloudIdentityConfig {
    fn from(c: &CloudVolumeDeletionConfig) -> Self {
        Self {
            account_id: c.account_id.clone(),
            region: c.region.clone(),
            role_arn: c.role_arn.clone(),
            role_id: c.role_id.clone(),
            oidc_provider_arn: c.oidc_provider_arn.clone(),
            oidc_issuer: c.oidc_issuer.clone(),
            oidc_audience: c.oidc_audience.clone(),
            oidc_subject: c.oidc_subject.clone(),
            oidc_token_file: c.oidc_token_file.clone(),
            requests_per_second: c.requests_per_second,
            max_in_flight: c.max_in_flight,
            session_policy: None,
        }
    }
}

#[derive(Clone)]
pub struct AlibabaCloudVolumeDeletion {
    // No Deref or accessor: callers cannot obtain the fencing API. This private
    // transport also has an empty node allowlist, not invented node bindings.
    transport: AlibabaCloudFencing,
}

#[derive(Debug, Serialize)]
pub struct CloudDiskDeleteSubmission {
    attempt_id: Uuid,
    preflight: CloudDiskObservation,
    evidence: CloudRequestEvidence,
}
impl CloudDiskDeleteSubmission {
    pub fn attempt_id(&self) -> Uuid {
        self.attempt_id
    }
    pub fn preflight(&self) -> &CloudDiskObservation {
        &self.preflight
    }
    pub fn evidence(&self) -> &CloudRequestEvidence {
        &self.evidence
    }
}

#[derive(Debug, Serialize)]
#[serde(
    tag = "outcome",
    content = "observation",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum CloudDiskDeleteOutcome {
    Accepted(CloudDiskDeleteSubmission),
    AlreadyAbsent(CloudDiskAbsence),
    OutcomeUnknown(CloudDiskDeleteSubmission),
}

/// This receipt cannot stand in for a DeleteDisk attempt or an absence proof.
#[derive(Debug, Serialize)]
pub struct CloudDiskPreserveSubmission {
    attempt_id: Uuid,
    preflight: CloudDiskObservation,
    evidence: CloudRequestEvidence,
}
impl CloudDiskPreserveSubmission {
    pub fn attempt_id(&self) -> Uuid {
        self.attempt_id
    }
    pub fn preflight(&self) -> &CloudDiskObservation {
        &self.preflight
    }
    pub fn evidence(&self) -> &CloudRequestEvidence {
        &self.evidence
    }
}
#[derive(Debug, Serialize)]
#[serde(
    tag = "outcome",
    content = "observation",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum CloudDiskPreserveOutcome {
    Accepted(CloudDiskPreserveSubmission),
    AlreadyPreserved(CloudDiskObservation),
    AlreadyAbsent(CloudDiskAbsence),
    OutcomeUnknown(CloudDiskPreserveSubmission),
}
enum WriteResult {
    Accepted(CloudRequestEvidence),
    Unknown(CloudRequestEvidence),
}

impl AlibabaCloudVolumeDeletion {
    // Reuse the mature disk protocol only with an already scoped sibling
    // transport. No public accessor widens the regular volume-deleter role.
    pub(super) fn from_scoped_transport(transport: AlibabaCloudFencing) -> Self {
        Self { transport }
    }

    pub fn new(config: CloudVolumeDeletionConfig) -> Result<Self, CloudError> {
        Self::validate(&config)?;
        let sts = url::Url::parse(&format!("https://sts.{}.aliyuncs.com/", config.region))
            .map_err(|_| err(CloudErrorCode::Configuration))?;
        let ecs = url::Url::parse(&format!("https://ecs.{}.aliyuncs.com/", config.region))
            .map_err(|_| err(CloudErrorCode::Configuration))?;
        Self::build(config, sts, ecs, true)
    }

    fn validate(config: &CloudVolumeDeletionConfig) -> Result<(), CloudError> {
        validate_identity_config(&CloudIdentityConfig::from(config))?;
        if !deployment_name(&config.deployment)
            || config.oidc_subject != "system:serviceaccount:sandbox-system:sandbox-volume-deleter"
        {
            return Err(err(CloudErrorCode::Configuration));
        }
        Ok(())
    }

    fn build(
        config: CloudVolumeDeletionConfig,
        sts: url::Url,
        ecs: url::Url,
        https: bool,
    ) -> Result<Self, CloudError> {
        Ok(Self {
            transport: AlibabaCloudFencing::build_transport(
                CloudIdentityConfig::from(&config),
                BTreeMap::new(),
                Some(config.deployment),
                sts,
                ecs,
                https,
            )?,
        })
    }

    #[cfg(test)]
    fn for_test(config: CloudVolumeDeletionConfig, endpoint: url::Url) -> Result<Self, CloudError> {
        Self::validate(&config)?;
        Self::build(config, endpoint.clone(), endpoint, false)
    }

    pub async fn observe_disk(
        &self,
        binding: &CloudDiskBinding,
    ) -> Result<CloudDiskLookup, CloudError> {
        self.transport.observe_disk(binding).await
    }

    /// The caller must commit an exact identity and DISPATCHING intent first.
    /// Sends at most once, never automatically retries or deletes snapshots.
    /// Cancellation/crash after dispatch is UNKNOWN even without a return value.
    /// The returned observations alone cannot release PVC/PV/storage quota.
    pub async fn delete_disk(
        &self,
        identity: &CloudDiskIdentity,
        attempt_id: Uuid,
    ) -> Result<CloudDiskDeleteOutcome, CloudError> {
        let preflight = match self.bound_preflight(identity, attempt_id).await? {
            CloudDiskLookup::Absent(absence) => {
                return Ok(CloudDiskDeleteOutcome::AlreadyAbsent(absence));
            }
            CloudDiskLookup::Present(observation) => observation,
        };
        // Available disks normally omit InstanceId/shared-block mount fields.
        // Missing fields remain Incomplete, NOT a fence or an empty-set proof.
        // DeleteDisk itself atomically refuses a disk no longer Available.
        if preflight.state() != CloudDiskState::Available
            || preflight.attachment_state() == CloudDiskAttachmentState::Present
            || preflight.delete_auto_snapshot()
        {
            return Err(CloudError {
                code: CloudErrorCode::InvalidState,
                evidence: Some(preflight.evidence().clone()),
            });
        }
        // Official DeleteDisk has DiskId only. No invented Force or ClientToken,
        // no tag/state filters that could hide ownership drift as absence.
        let query = BTreeMap::from([("DiskId".into(), identity.binding.disk_id.clone())]);
        let result = self.write_once("DeleteDisk", &query, &preflight).await?;
        Ok(match result {
            WriteResult::Accepted(evidence) => {
                CloudDiskDeleteOutcome::Accepted(CloudDiskDeleteSubmission {
                    attempt_id,
                    preflight,
                    evidence,
                })
            }
            WriteResult::Unknown(evidence) => {
                CloudDiskDeleteOutcome::OutcomeUnknown(CloudDiskDeleteSubmission {
                    attempt_id,
                    preflight,
                    evidence,
                })
            }
        })
    }

    /// CreateDisk defaults DeleteAutoSnapshot=true. Before destroying a disk,
    /// the caller durably records a separate preservation intent, invokes this
    /// once, and freshly observes false before recording a DELETE intent. A
    /// successful response cannot substitute for that read-back verification.
    pub async fn preserve_automatic_snapshots(
        &self,
        identity: &CloudDiskIdentity,
        attempt_id: Uuid,
    ) -> Result<CloudDiskPreserveOutcome, CloudError> {
        let preflight = match self.bound_preflight(identity, attempt_id).await? {
            CloudDiskLookup::Absent(absence) => {
                return Ok(CloudDiskPreserveOutcome::AlreadyAbsent(absence));
            }
            CloudDiskLookup::Present(observation) => observation,
        };
        if preflight.state() != CloudDiskState::Available
            || preflight.attachment_state() == CloudDiskAttachmentState::Present
        {
            return Err(CloudError {
                code: CloudErrorCode::InvalidState,
                evidence: Some(preflight.evidence().clone()),
            });
        }
        if !preflight.delete_auto_snapshot() {
            return Ok(CloudDiskPreserveOutcome::AlreadyPreserved(preflight));
        }
        // No caller-controlled attributes, multiple disks, tag updates or true
        // value. Other optional ModifyDiskAttribute properties remain unchanged.
        let query = BTreeMap::from([
            ("DiskId".into(), identity.binding.disk_id.clone()),
            ("DeleteAutoSnapshot".into(), "false".into()),
        ]);
        Ok(
            match self
                .write_once("ModifyDiskAttribute", &query, &preflight)
                .await?
            {
                WriteResult::Accepted(evidence) => {
                    CloudDiskPreserveOutcome::Accepted(CloudDiskPreserveSubmission {
                        attempt_id,
                        preflight,
                        evidence,
                    })
                }
                WriteResult::Unknown(evidence) => {
                    CloudDiskPreserveOutcome::OutcomeUnknown(CloudDiskPreserveSubmission {
                        attempt_id,
                        preflight,
                        evidence,
                    })
                }
            },
        )
    }

    async fn bound_preflight(
        &self,
        identity: &CloudDiskIdentity,
        attempt_id: Uuid,
    ) -> Result<CloudDiskLookup, CloudError> {
        if attempt_id.is_nil()
            || !disks::valid_serial(&identity.serial_number)
            || identity.creation_time.timestamp() <= 0
            || identity.creation_time > Utc::now() + ChronoDuration::seconds(30)
        {
            return Err(err(CloudErrorCode::Configuration));
        }
        let result = self.observe_disk(&identity.binding).await?;
        if let CloudDiskLookup::Present(observation) = &result {
            let current = observation.identity()?;
            if current.serial_number != identity.serial_number
                || current.creation_time != identity.creation_time
            {
                return Err(CloudError {
                    code: CloudErrorCode::IdentityMismatch,
                    evidence: Some(observation.evidence().clone()),
                });
            }
        }
        Ok(result)
    }

    async fn write_once(
        &self,
        action: &'static str,
        query: &BTreeMap<String, String>,
        preflight: &CloudDiskObservation,
    ) -> Result<WriteResult, CloudError> {
        let credentials =
            tokio::time::timeout(Duration::from_secs(45), self.transport.credentials())
                .await
                .map_err(|_| err(CloudErrorCode::CredentialUnavailable))??;
        match self
            .transport
            .send(
                action,
                ECS_VERSION,
                &self.transport.inner.ecs,
                query,
                Some(&credentials),
                Some(preflight.evidence().received_at() + ChronoDuration::seconds(5)),
            )
            .await
        {
            Ok(response) => {
                if response.status.is_success() {
                    if response.evidence.provider_request_id.is_none()
                        || provider_code(&response.body).is_some()
                    {
                        return Ok(WriteResult::Unknown(response.evidence));
                    }
                    Ok(WriteResult::Accepted(response.evidence))
                } else if response.status.is_server_error() {
                    Ok(WriteResult::Unknown(response.evidence))
                } else {
                    Err(provider_error(&response))
                }
            }
            Err(failure) => {
                if let Some(evidence) = failure.evidence {
                    Ok(WriteResult::Unknown(evidence))
                } else {
                    Err(failure)
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "cloud_volume_deletion_tests.rs"]
pub(crate) mod tests;
