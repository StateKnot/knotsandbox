//! Independently credentialed, exact-resource restore temporary storage GC.
//! Snapshot deletion acknowledgement is never a cloud absence or writer proof.
use super::*;
use serde_json::{Value, json};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreGcCloudConfig {
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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RestoreGcCloudScope {
    pub restore_id: Uuid,
    pub raw_disk_id: String,
    pub snapshot_id: String,
    pub target_disk_id: String,
}
#[derive(Clone)]
pub struct AlibabaCloudRestoreGc {
    transport: AlibabaCloudFencing,
    scope: RestoreGcCloudScope,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RestoreSnapshotBinding {
    pub scope: RestoreGcCloudScope,
    pub account_id: String,
    pub region: String,
    pub kms_key_id: String,
    pub size_gib: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RestoreSnapshotIdentity {
    pub binding: RestoreSnapshotBinding,
    pub serial_number: String,
    pub created_at: DateTime<Utc>,
}
#[derive(Debug, Serialize)]
pub struct RestoreSnapshotObservation {
    identity: RestoreSnapshotIdentity,
    usage: String,
    evidence: CloudRequestEvidence,
}
impl RestoreSnapshotObservation {
    pub fn identity(&self) -> &RestoreSnapshotIdentity {
        &self.identity
    }
    pub fn evidence(&self) -> &CloudRequestEvidence {
        &self.evidence
    }
    pub fn requires_force(&self) -> bool {
        self.usage == "disk"
    }
}
#[derive(Debug, Serialize)]
pub struct RestoreSnapshotAbsence {
    binding: RestoreSnapshotBinding,
    evidence: CloudRequestEvidence,
}
impl RestoreSnapshotAbsence {
    pub fn binding(&self) -> &RestoreSnapshotBinding {
        &self.binding
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
pub enum RestoreSnapshotLookup {
    Present(RestoreSnapshotObservation),
    Absent(RestoreSnapshotAbsence),
}
#[derive(Debug, Serialize)]
pub struct RestoreSnapshotDeleteSubmission {
    pub attempt_id: Uuid,
    pub preflight: RestoreSnapshotObservation,
    pub evidence: CloudRequestEvidence,
    pub force_created_disk: bool,
}
#[derive(Debug, Serialize)]
#[serde(
    tag = "outcome",
    content = "observation",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum RestoreSnapshotDeleteOutcome {
    Accepted(RestoreSnapshotDeleteSubmission),
    AlreadyAbsent(RestoreSnapshotAbsence),
    OutcomeUnknown(RestoreSnapshotDeleteSubmission),
}
fn resource_id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|v| {
        !v.is_empty() && v.len() <= 128 && v.bytes().all(|b| b.is_ascii_alphanumeric())
    })
}
impl RestoreGcCloudScope {
    fn validate(&self) -> Result<(), CloudError> {
        if self.restore_id.is_nil()
            || !resource_id(&self.raw_disk_id, "d-")
            || !resource_id(&self.target_disk_id, "d-")
            || self.raw_disk_id == self.target_disk_id
            || !resource_id(&self.snapshot_id, "s-")
        {
            return Err(err(CloudErrorCode::Configuration));
        }
        Ok(())
    }
}
impl AlibabaCloudRestoreGc {
    pub fn new(
        config: RestoreGcCloudConfig,
        scope: RestoreGcCloudScope,
    ) -> Result<Self, CloudError> {
        let sts = url::Url::parse(&format!("https://sts.{}.aliyuncs.com/", config.region))
            .map_err(|_| err(CloudErrorCode::Configuration))?;
        let ecs = url::Url::parse(&format!("https://ecs.{}.aliyuncs.com/", config.region))
            .map_err(|_| err(CloudErrorCode::Configuration))?;
        Self::build(config, scope, sts, ecs, true)
    }
    fn build(
        config: RestoreGcCloudConfig,
        scope: RestoreGcCloudScope,
        sts: url::Url,
        ecs: url::Url,
        https: bool,
    ) -> Result<Self, CloudError> {
        scope.validate()?;
        if config.oidc_subject != "system:serviceaccount:sandbox-system:sandbox-restore-gc"
            || !deployment_name(&config.deployment)
        {
            return Err(err(CloudErrorCode::Configuration));
        }
        let snapshot = format!(
            "acs:ecs:{}:{}:snapshot/{}",
            config.region, config.account_id, scope.snapshot_id
        );
        let raw = format!(
            "acs:ecs:{}:{}:disk/{}",
            config.region, config.account_id, scope.raw_disk_id
        );
        let target = format!(
            "acs:ecs:{}:{}:disk/{}",
            config.region, config.account_id, scope.target_disk_id
        );
        // STS session policy intersects the RAM role policy. No wildcard,
        // source backup snapshot, tagging, detach, node stop or cascade action.
        let policy=serde_json::to_string(&json!({"Version":"1","Statement":[
            {"Effect":"Allow","Action":["ecs:DescribeSnapshots","ecs:DeleteSnapshot"],"Resource":[snapshot]},
            {"Effect":"Allow","Action":["ecs:DescribeDisks","ecs:DeleteDisk","ecs:ModifyDiskAttribute"],"Resource":[raw]},
            {"Effect":"Allow","Action":["ecs:DescribeDisks"],"Resource":[target]},
            {"Effect":"Allow","Action":["sts:GetCallerIdentity"],"Resource":["*"]}
        ]})).map_err(|_|err(CloudErrorCode::Configuration))?;
        if policy.len() > 2048 {
            return Err(err(CloudErrorCode::Configuration));
        }
        let identity = CloudIdentityConfig {
            account_id: config.account_id,
            region: config.region,
            role_arn: config.role_arn,
            role_id: config.role_id,
            oidc_provider_arn: config.oidc_provider_arn,
            oidc_issuer: config.oidc_issuer,
            oidc_audience: config.oidc_audience,
            oidc_subject: config.oidc_subject,
            oidc_token_file: config.oidc_token_file,
            requests_per_second: config.requests_per_second,
            max_in_flight: config.max_in_flight,
            session_policy: Some(policy),
        };
        validate_identity_config(&identity)?;
        Ok(Self {
            transport: AlibabaCloudFencing::build_transport(
                identity,
                BTreeMap::new(),
                Some(config.deployment),
                sts,
                ecs,
                https,
            )?,
            scope,
        })
    }
    fn binding(&self, b: &RestoreSnapshotBinding) -> Result<(), CloudError> {
        if b.scope != self.scope
            || b.account_id != self.transport.inner.config.account_id
            || b.region != self.transport.inner.config.region
            || b.kms_key_id.is_empty()
            || b.kms_key_id.len() > 256
            || !b.kms_key_id.bytes().all(|v| v.is_ascii_graphic())
            || !(20..=1024).contains(&b.size_gib)
        {
            return Err(err(CloudErrorCode::IdentityMismatch));
        }
        Ok(())
    }
    pub async fn observe_snapshot(
        &self,
        b: &RestoreSnapshotBinding,
    ) -> Result<RestoreSnapshotLookup, CloudError> {
        self.binding(b)?;
        let credentials = self.transport.credentials().await?;
        // Query only the exact snapshot, with no state/type/source filters that
        // could turn a changed identity or state into a false empty-set proof.
        let query = BTreeMap::from([
            ("RegionId".into(), b.region.clone()),
            (
                "SnapshotIds".into(),
                serde_json::to_string(&vec![&b.scope.snapshot_id])
                    .map_err(|_| err(CloudErrorCode::Configuration))?,
            ),
            ("MaxResults".into(), "10".into()),
        ]);
        let r = self
            .transport
            .read_request(
                "DescribeSnapshots",
                ECS_VERSION,
                &self.transport.inner.ecs,
                &query,
                Some(&credentials),
            )
            .await?;
        parse_snapshot(b, &r)
    }
    /// Caller must first durably pin the identity, independently close every
    /// writer and commit a DISPATCHING intent with the reviewed force policy.
    /// This method performs exactly one write; timeouts require a fresh query.
    pub async fn delete_snapshot(
        &self,
        identity: &RestoreSnapshotIdentity,
        attempt_id: Uuid,
        force_created_disk: bool,
        expected_target: Option<&CloudDiskIdentity>,
    ) -> Result<RestoreSnapshotDeleteOutcome, CloudError> {
        if attempt_id.is_nil() {
            return Err(err(CloudErrorCode::Configuration));
        }
        let preflight = match self.observe_snapshot(&identity.binding).await? {
            RestoreSnapshotLookup::Absent(v) => {
                return Ok(RestoreSnapshotDeleteOutcome::AlreadyAbsent(v));
            }
            RestoreSnapshotLookup::Present(v) => v,
        };
        if &preflight.identity != identity || (!force_created_disk && preflight.usage != "none") {
            return Err(CloudError {
                code: CloudErrorCode::IdentityMismatch,
                evidence: Some(preflight.evidence),
            });
        }
        if force_created_disk {
            self.verify_target_lineage(
                expected_target.ok_or_else(|| err(CloudErrorCode::Configuration))?,
            )
            .await?;
        }
        let credentials = self.transport.credentials().await?;
        let query = BTreeMap::from([
            ("RegionId".into(), identity.binding.region.clone()),
            (
                "SnapshotId".into(),
                identity.binding.scope.snapshot_id.clone(),
            ),
            ("Force".into(), force_created_disk.to_string()),
        ]);
        let r = self
            .transport
            .send(
                "DeleteSnapshot",
                ECS_VERSION,
                &self.transport.inner.ecs,
                &query,
                Some(&credentials),
                Some(preflight.evidence.received_at + ChronoDuration::seconds(5)),
            )
            .await;
        let (accepted, evidence) = match r {
            Ok(r) if r.status.is_success() => (
                r.evidence.provider_request_id.is_some() && provider_code(&r.body).is_none(),
                r.evidence,
            ),
            Ok(r) if r.status.is_server_error() => (false, r.evidence),
            Ok(r) => return Err(provider_error(&r)),
            Err(failure) => match failure.evidence {
                Some(evidence) => (false, evidence),
                None => return Err(failure),
            },
        };
        let receipt = RestoreSnapshotDeleteSubmission {
            attempt_id,
            preflight,
            evidence,
            force_created_disk,
        };
        Ok(if accepted {
            RestoreSnapshotDeleteOutcome::Accepted(receipt)
        } else {
            RestoreSnapshotDeleteOutcome::OutcomeUnknown(receipt)
        })
    }
    /// Raw disks use the existing strict tag/serial/creation-time transport.
    pub async fn observe_raw_disk(
        &self,
        b: &CloudDiskBinding,
    ) -> Result<CloudDiskLookup, CloudError> {
        if b.disk_id != self.scope.raw_disk_id {
            return Err(err(CloudErrorCode::IdentityMismatch));
        }
        self.transport.observe_disk(b).await
    }
    pub async fn observe_target_disk(
        &self,
        binding: &CloudDiskBinding,
    ) -> Result<CloudDiskLookup, CloudError> {
        if binding.disk_id != self.scope.target_disk_id {
            return Err(err(CloudErrorCode::IdentityMismatch));
        }
        self.transport.observe_disk(binding).await
    }
    async fn verify_target_lineage(&self, expected: &CloudDiskIdentity) -> Result<(), CloudError> {
        let CloudDiskLookup::Present(observed) =
            self.observe_target_disk(&expected.binding).await?
        else {
            return Err(err(CloudErrorCode::IdentityMismatch));
        };
        if serde_json::to_value(observed.identity()?).ok() != serde_json::to_value(expected).ok() {
            return Err(CloudError {
                code: CloudErrorCode::IdentityMismatch,
                evidence: Some(observed.evidence().clone()),
            });
        }
        let credentials = self.transport.credentials().await?;
        let query = BTreeMap::from([
            ("RegionId".into(), expected.binding.region.clone()),
            (
                "DiskIds".into(),
                json!([self.scope.target_disk_id]).to_string(),
            ),
            ("MaxResults".into(), "10".into()),
        ]);
        let response = self
            .transport
            .read_request(
                "DescribeDisks",
                ECS_VERSION,
                &self.transport.inner.ecs,
                &query,
                Some(&credentials),
            )
            .await?;
        let value: Value = parse_response(&response)?;
        let rows = value
            .pointer("/Disks/Disk")
            .and_then(Value::as_array)
            .ok_or_else(|| response_error(CloudErrorCode::MalformedResponse, &response))?;
        let identity_matches = rows.len() == 1
            && rows[0].get("DiskId") == Some(&json!(self.scope.target_disk_id))
            && rows[0].get("SourceSnapshotId") == Some(&json!(self.scope.snapshot_id))
            && rows[0].get("SerialNumber") == Some(&json!(expected.serial_number))
            && rows[0]
                .get("CreationTime")
                .and_then(Value::as_str)
                .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                .map(|v| v.with_timezone(&Utc))
                == Some(expected.creation_time);
        if !identity_matches
            || value
                .get("NextToken")
                .is_some_and(|v| v.as_str() != Some(""))
            || observed.evidence().received_at() < Utc::now() - ChronoDuration::seconds(5)
        {
            return Err(response_error(CloudErrorCode::IdentityMismatch, &response));
        }
        Ok(())
    }
    pub async fn preserve_raw_automatic_snapshots(
        &self,
        identity: &CloudDiskIdentity,
        attempt_id: Uuid,
    ) -> Result<CloudDiskPreserveOutcome, CloudError> {
        if identity.binding.disk_id != self.scope.raw_disk_id {
            return Err(err(CloudErrorCode::IdentityMismatch));
        }
        AlibabaCloudVolumeDeletion::from_scoped_transport(self.transport.clone())
            .preserve_automatic_snapshots(identity, attempt_id)
            .await
    }
    pub async fn delete_raw_disk(
        &self,
        identity: &CloudDiskIdentity,
        attempt_id: Uuid,
    ) -> Result<CloudDiskDeleteOutcome, CloudError> {
        if identity.binding.disk_id != self.scope.raw_disk_id {
            return Err(err(CloudErrorCode::IdentityMismatch));
        }
        AlibabaCloudVolumeDeletion::from_scoped_transport(self.transport.clone())
            .delete_disk(identity, attempt_id)
            .await
    }
}
fn parse_snapshot(
    b: &RestoreSnapshotBinding,
    r: &Response,
) -> Result<RestoreSnapshotLookup, CloudError> {
    let v: Value = parse_response(r)?;
    let failure = || response_error(CloudErrorCode::MalformedResponse, r);
    // NextToken pagination is authoritative; TotalCount is explicitly not
    // reliable with MaxResults. A non-empty/malformed token is incomplete.
    if v.get("NextToken").is_some_and(|t| t.as_str() != Some("")) {
        return Err(failure());
    }
    let rows = v
        .pointer("/Snapshots/Snapshot")
        .and_then(Value::as_array)
        .ok_or_else(failure)?;
    if rows.is_empty() {
        return Ok(RestoreSnapshotLookup::Absent(RestoreSnapshotAbsence {
            binding: b.clone(),
            evidence: r.evidence.clone(),
        }));
    }
    if rows.len() != 1 {
        return Err(failure());
    }
    let s = &rows[0];
    let text = |key: &str| s.get(key).and_then(Value::as_str);
    let size = s
        .get("SourceDiskSize")
        .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok()));
    if text("SnapshotId") != Some(&b.scope.snapshot_id)
        || text("SourceDiskId") != Some(&b.scope.raw_disk_id)
        || text("RegionId") != Some(&b.region)
        || text("KMSKeyId") != Some(&b.kms_key_id)
        || text("SourceDiskType") != Some("data")
        || text("Status") != Some("accomplished")
        || text("SnapshotType") != Some("user")
        || s.get("Encrypted") != Some(&json!(true))
        || size != Some(u64::from(b.size_gib))
        || !matches!(text("Usage"), Some("none" | "disk"))
    {
        return Err(response_error(CloudErrorCode::IdentityMismatch, r));
    }
    let serial = text("SnapshotSN")
        .filter(|v| disks::valid_serial(v))
        .ok_or_else(failure)?;
    let created = text("CreationTime")
        .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
        .map(|v| v.with_timezone(&Utc))
        .ok_or_else(failure)?;
    if created.timestamp() <= 0 || created > Utc::now() + ChronoDuration::seconds(30) {
        return Err(failure());
    }
    Ok(RestoreSnapshotLookup::Present(RestoreSnapshotObservation {
        identity: RestoreSnapshotIdentity {
            binding: b.clone(),
            serial_number: serial.into(),
            created_at: created,
        },
        usage: text("Usage").ok_or_else(failure)?.into(),
        evidence: r.evidence.clone(),
    }))
}

#[cfg(test)]
#[path = "cloud_restore_gc_tests.rs"]
pub(crate) mod tests;
