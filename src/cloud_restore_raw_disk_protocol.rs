//! PRIVATE callable read-only protocol candidate. Only a current strict14
//! sealed scope supplies authority facts; bare source/receipt JSON is not an API.
//! No production module/route/writer activation or mutation/absence API exists.
use super::*;
use crate::restore::{
    admission::{RawBoundDiskPurpose, RawBoundDiskScope, RawBoundRecordedDiskFacts},
    raw_volume::RawPvDiskFacts,
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, time::Instant as AbsoluteDeadline};

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadPurpose {
    Admission,
    BackupController,
}
impl ReadPurpose {
    fn subject(self) -> &'static str {
        match self {
            Self::Admission => "system:serviceaccount:sandbox-system:sandbox-admission",
            Self::BackupController => {
                "system:serviceaccount:sandbox-system:sandbox-backup-controller"
            }
        }
    }
}
// Reviewed installation configuration only; no token values, endpoint override,
// arbitrary subject allowlist, Debug, Deserialize or default credentials.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RawDiskCloudConfig {
    pub(crate) account_id: String,
    pub(crate) region: String,
    pub(crate) role_arn: String,
    pub(crate) role_id: String,
    pub(crate) oidc_provider_arn: String,
    pub(crate) oidc_issuer: String,
    pub(crate) oidc_subject: String,
    pub(crate) oidc_token_file: PathBuf,
    pub(crate) requests_per_second: u32,
    pub(crate) max_in_flight: usize,
}
/// Per-component process budget. Sharing these exact guards limits only
/// calls using this object; it is not a cross-replica capacity certification.
pub(crate) struct RawDiskReadBudget {
    identity: RawDiskCloudConfig,
    purpose: ReadPurpose,
    next_request: Arc<Mutex<Instant>>,
    in_flight: Arc<Semaphore>,
    #[cfg(test)]
    test_endpoint: Option<url::Url>,
}
fn validate_read_identity(c: &RawDiskCloudConfig, purpose: ReadPurpose) -> Result<(), CloudError> {
    if c.oidc_subject != purpose.subject() {
        return Err(err(CloudErrorCode::Configuration));
    }
    validate_identity_config(&CloudIdentityConfig {
        account_id: c.account_id.clone(),
        region: c.region.clone(),
        role_arn: c.role_arn.clone(),
        role_id: c.role_id.clone(),
        oidc_provider_arn: c.oidc_provider_arn.clone(),
        oidc_issuer: c.oidc_issuer.clone(),
        oidc_audience: "sts.aliyuncs.com".into(),
        oidc_subject: c.oidc_subject.clone(),
        oidc_token_file: c.oidc_token_file.clone(),
        requests_per_second: c.requests_per_second,
        max_in_flight: c.max_in_flight,
        session_policy: None,
    })
}
impl RawDiskReadBudget {
    // Address-only protocol seam; no proof/authority constructor. Every request
    // still uses production OIDC/STS/identity/signing/parsing/deadline code.
    #[cfg(test)]
    pub(crate) fn use_loopback_test_endpoint(
        &mut self,
        endpoint: url::Url,
    ) -> Result<(), CloudError> {
        if endpoint.scheme() != "http"
            || endpoint
                .host_str()
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                .is_none_or(|a| !a.is_loopback())
            || endpoint.port().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(err(CloudErrorCode::Configuration));
        }
        self.test_endpoint = Some(endpoint);
        Ok(())
    }
    fn new(c: &RawDiskCloudConfig, purpose: ReadPurpose) -> Result<Self, CloudError> {
        validate_read_identity(c, purpose)?;
        Ok(Self {
            identity: c.clone(),
            purpose,
            next_request: Arc::new(Mutex::new(Instant::now())),
            in_flight: Arc::new(Semaphore::new(c.max_in_flight)),
            #[cfg(test)]
            test_endpoint: None,
        })
    }
}
// Private protocol comparison inputs. There is NO constructor or external
// observation API accepting these; only expected_from_scope forms normal inputs.
// A future caller must derive every field from that sealed read + raw locator,
// never a tenant DTO or an independent unpinned source lookup.
struct ExpectedDisk {
    restore_id: Uuid,
    parent_uid: Uuid,
    account_id: String,
    region: String,
    disk_id: String,
    zone_id: String,
    deployment: String,
    kms_key_id: String,
    size_gib: u32,
    selected_instance_id: String,
    source_disk_id: String,
    clone_disk_ids: BTreeSet<String>,
    parent_intent_created_at: DateTime<Utc>,
    recorded_identity: Option<RecordedIdentity>,
}
struct RecordedIdentity {
    serial_number: String,
    creation_time: DateTime<Utc>,
}
impl ExpectedDisk {
    fn pvc_name(&self) -> String {
        format!("sbx-bvol-{}", self.restore_id)
    }
    fn pv_name(&self) -> String {
        format!("disk-{}", self.parent_uid)
    }
    fn validate(&self) -> Result<(), CloudError> {
        let region = (4..=32).contains(&self.region.len())
            && self.region.starts_with("cn-")
            && self
                .region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        let zone = self.zone_id.len() <= 64
            && self
                .zone_id
                .strip_prefix(&format!("{}-", self.region))
                .is_some_and(|s| {
                    !s.is_empty()
                        && s.bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                });
        if self.restore_id.is_nil()
            || self.parent_uid.is_nil()
            || self.account_id.len() != 16
            || !self.account_id.bytes().all(|b| b.is_ascii_digit())
            || !region
            || !zone
            || !cloud_id(&self.disk_id, "d-")
            || !cloud_id(&self.selected_instance_id, "i-")
            || !cloud_id(&self.source_disk_id, "d-")
            || self.clone_disk_ids.len() > 256
            || self.clone_disk_ids.iter().any(|s| !cloud_id(s, "d-"))
            || self.disk_id == self.source_disk_id
            || self.clone_disk_ids.contains(&self.disk_id)
            || !crate::backup_job::valid_deployment(&self.deployment)
            || !(1..=256).contains(&self.kms_key_id.len())
            || !self
                .kms_key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_:-".contains(&b))
            || !(20..=1024).contains(&self.size_gib)
            || self.parent_intent_created_at.timestamp() <= 0
            || self.recorded_identity.as_ref().is_some_and(|r| {
                !visible(&r.serial_number, 128) || r.creation_time.timestamp() <= 0
            })
        {
            return Err(err(CloudErrorCode::Configuration));
        }
        Ok(())
    }
}
// No Clone: each observation consumes its newly scoped transport, so its STS
// account/RoleID validation cannot silently reuse another attempt's cache.
struct ProtocolClient {
    transport: AlibabaCloudFencing,
    expected: ExpectedDisk,
    purpose: ReadPurpose,
}
// Distinct protocol wrappers: later admission integration cannot pass its type
// to the backup publication path. Neither wrapper has an external constructor
// mutation/proof constructor; callable observers require a sealed current14 scope.
pub(crate) struct AdmissionRawDiskProtocolClient(ProtocolClient);
pub(crate) struct BackupRawDiskProtocolClient(ProtocolClient);
pub(crate) struct AdmissionDiskProtocolObservation(DiskProtocolObservation);
pub(crate) struct BackupDiskProtocolObservation(DiskProtocolObservation);
fn scope_error(_: crate::admission::Denial) -> CloudError {
    err(CloudErrorCode::IdentityMismatch)
}
fn recorded_target(
    recorded: Option<&RawBoundRecordedDiskFacts>,
    disk_id: &str,
) -> Result<Option<RecordedIdentity>, CloudError> {
    match recorded {
        None => Ok(None),
        Some(r)
            if r.disk_id == disk_id
                && visible(&r.serial_number, 128)
                && r.creation_time.timestamp() > 0 =>
        {
            Ok(Some(RecordedIdentity {
                serial_number: r.serial_number.clone(),
                creation_time: r.creation_time,
            }))
        }
        Some(_) => Err(err(CloudErrorCode::IdentityMismatch)),
    }
}
fn expected_from_scope(
    scope: &RawBoundDiskScope,
    disk_id: &str,
    purpose: ReadPurpose,
) -> Result<ExpectedDisk, CloudError> {
    scope.current().map_err(scope_error)?;
    let expected_purpose = match purpose {
        ReadPurpose::Admission => RawBoundDiskPurpose::Admission,
        ReadPurpose::BackupController => RawBoundDiskPurpose::Backup,
    };
    if scope.purpose() != &expected_purpose {
        return Err(err(CloudErrorCode::Configuration));
    }
    let facts = scope.facts();
    let collection = scope.collection();
    let expected = ExpectedDisk {
        restore_id: facts.restore_id,
        parent_uid: facts.pvc_uid,
        account_id: facts.account_id.clone(),
        region: facts.region.clone(),
        disk_id: disk_id.into(),
        zone_id: facts.zone_id.clone(),
        deployment: facts.deployment.clone(),
        kms_key_id: facts.workspace_kms_key_id.clone(),
        size_gib: facts.size_gib,
        selected_instance_id: facts.cloud_instance_id.clone(),
        source_disk_id: facts.source_disk_id.clone(),
        clone_disk_ids: BTreeSet::from([facts.clone_disk_id.clone()]),
        parent_intent_created_at: facts.parent_intent_created_at,
        recorded_identity: recorded_target(collection.recorded.as_ref(), disk_id)?,
    };
    expected.validate()?;
    scope.current().map_err(scope_error)?;
    Ok(expected)
}
fn scope_identity(
    config: &RawDiskCloudConfig,
    scope: &RawBoundDiskScope,
) -> Result<(), CloudError> {
    scope.current().map_err(scope_error)?;
    let settings = &scope.collection().cloud_settings;
    if config.account_id != scope.facts().account_id
        || config.region != scope.facts().region
        || config.oidc_issuer != settings.issuer
        || config.oidc_provider_arn != settings.oidc_provider_arn
    {
        return Err(err(CloudErrorCode::Configuration));
    }
    Ok(())
}
impl AdmissionRawDiskProtocolClient {
    pub(crate) fn budget(config: &RawDiskCloudConfig) -> Result<RawDiskReadBudget, CloudError> {
        RawDiskReadBudget::new(config, ReadPurpose::Admission)
    }

    pub(crate) fn validate_scope(
        config: &RawDiskCloudConfig,
        scope: &RawBoundDiskScope,
    ) -> Result<(), CloudError> {
        scope_identity(config, scope)?;
        validate_read_identity(config, ReadPurpose::Admission)?;
        let expected = RawBoundDiskPurpose::Admission;
        if config.oidc_subject != ReadPurpose::Admission.subject() || scope.purpose() != &expected {
            return Err(err(CloudErrorCode::Configuration));
        }
        Ok(())
    }

    /// Fresh transport per call: no cached STS identity from another attempt or
    /// from the first observation can authorize the second observation.
    pub(crate) async fn observe_scope(
        config: RawDiskCloudConfig,
        scope: &RawBoundDiskScope,
        disk_id: &str,
        budget: &RawDiskReadBudget,
    ) -> Result<AdmissionDiskProtocolObservation, CloudError> {
        Self::validate_scope(&config, scope)?;
        let expected = expected_from_scope(scope, disk_id, ReadPurpose::Admission)?;
        if budget.identity != config || budget.purpose != ReadPurpose::Admission {
            return Err(err(CloudErrorCode::Configuration));
        }
        let mut client = Self::new(config, expected)?;
        client.0.attach_budget(budget)?;
        let observed = client.observe_protocol(scope.deadline()).await?;
        scope.current().map_err(scope_error)?;
        observed.current()?;
        Ok(observed)
    }

    fn new(identity: RawDiskCloudConfig, expected: ExpectedDisk) -> Result<Self, CloudError> {
        Ok(Self(ProtocolClient::new(
            identity,
            expected,
            ReadPurpose::Admission,
        )?))
    }
    async fn observe_protocol(
        self,
        original_deadline: AbsoluteDeadline,
    ) -> Result<AdmissionDiskProtocolObservation, CloudError> {
        self.0
            .observe_protocol(original_deadline)
            .await
            .map(AdmissionDiskProtocolObservation)
    }
}
impl BackupRawDiskProtocolClient {
    pub(crate) fn budget(config: &RawDiskCloudConfig) -> Result<RawDiskReadBudget, CloudError> {
        RawDiskReadBudget::new(config, ReadPurpose::BackupController)
    }

    pub(crate) fn validate_scope(
        config: &RawDiskCloudConfig,
        scope: &RawBoundDiskScope,
    ) -> Result<(), CloudError> {
        scope_identity(config, scope)?;
        validate_read_identity(config, ReadPurpose::BackupController)?;
        let expected = RawBoundDiskPurpose::Backup;
        if config.oidc_subject != ReadPurpose::BackupController.subject()
            || scope.purpose() != &expected
        {
            return Err(err(CloudErrorCode::Configuration));
        }
        Ok(())
    }

    /// Fresh transport per call: no cached STS identity from another attempt or
    /// from the first observation can authorize the second observation.
    pub(crate) async fn observe_scope(
        config: RawDiskCloudConfig,
        scope: &RawBoundDiskScope,
        disk_id: &str,
        budget: &RawDiskReadBudget,
    ) -> Result<BackupDiskProtocolObservation, CloudError> {
        Self::validate_scope(&config, scope)?;
        let expected = expected_from_scope(scope, disk_id, ReadPurpose::BackupController)?;
        if budget.identity != config || budget.purpose != ReadPurpose::BackupController {
            return Err(err(CloudErrorCode::Configuration));
        }
        let mut client = Self::new(config, expected)?;
        client.0.attach_budget(budget)?;
        let observed = client.observe_protocol(scope.deadline()).await?;
        scope.current().map_err(scope_error)?;
        observed.current()?;
        Ok(observed)
    }

    fn new(identity: RawDiskCloudConfig, expected: ExpectedDisk) -> Result<Self, CloudError> {
        Ok(Self(ProtocolClient::new(
            identity,
            expected,
            ReadPurpose::BackupController,
        )?))
    }
    async fn observe_protocol(
        self,
        original_deadline: AbsoluteDeadline,
    ) -> Result<BackupDiskProtocolObservation, CloudError> {
        self.0
            .observe_protocol(original_deadline)
            .await
            .map(BackupDiskProtocolObservation)
    }
}
// This is authenticated cloud protocol evidence only. Private fields and all
// methods prevent turning bare JSON into a published restore proof. It does not
// attest SQL authority, Node identity, attachment exclusivity or VM absence.
struct DiskProtocolObservation {
    expected: ExpectedDisk,
    serial_number: String,
    creation_time: DateTime<Utc>,
    status: DiskStatus,
    attached_instance_ids: BTreeSet<String>,
    evidence: CloudRequestEvidence,
    original_deadline: AbsoluteDeadline,
}
impl BackupDiskProtocolObservation {
    pub(crate) fn current(&self) -> Result<(), CloudError> {
        self.0.current()
    }
    pub(crate) fn disk_facts(&self) -> Result<RawPvDiskFacts, CloudError> {
        self.0.disk_facts()
    }
    pub(crate) fn same_identity(&self, other: &Self) -> Result<(), CloudError> {
        self.0.same_identity(&other.0)
    }
}
impl AdmissionDiskProtocolObservation {
    pub(crate) fn current(&self) -> Result<(), CloudError> {
        self.0.current()
    }
    pub(crate) fn disk_facts(&self) -> Result<RawPvDiskFacts, CloudError> {
        self.0.disk_facts()
    }
    pub(crate) fn same_identity(&self, other: &Self) -> Result<(), CloudError> {
        self.0.same_identity(&other.0)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiskStatus {
    Available,
    InUse,
}
fn visible(s: &str, limit: usize) -> bool {
    !s.is_empty() && s.len() <= limit && s.bytes().all(|b| b.is_ascii_graphic())
}
fn cloud_id(s: &str, prefix: &str) -> bool {
    s.len() <= 128
        && s.strip_prefix(prefix)
            .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric()))
}
fn current(deadline: AbsoluteDeadline) -> Result<(), CloudError> {
    if AbsoluteDeadline::now() >= deadline {
        return Err(err(CloudErrorCode::ObservationStale));
    }
    Ok(())
}
fn utc(s: &str) -> Result<DateTime<Utc>, CloudError> {
    let bytes = s.as_bytes();
    let clock = bytes.len() >= 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[..19]
            .iter()
            .enumerate()
            .all(|(i, b)| matches!(i, 4 | 7 | 10 | 13 | 16) || b.is_ascii_digit())
        && &bytes[11..13] <= b"23".as_slice()
        && &bytes[14..16] <= b"59".as_slice()
        && &bytes[17..19] <= b"59".as_slice();
    if !clock {
        return Err(err(CloudErrorCode::MalformedResponse));
    }
    let tail = &s[19..];
    let fraction = tail
        .strip_suffix('Z')
        .or_else(|| tail.strip_suffix("+00:00"))
        .ok_or_else(|| err(CloudErrorCode::MalformedResponse))?;
    if !fraction.is_empty()
        && !(fraction.starts_with('.')
            && (2..=7).contains(&fraction.len())
            && fraction.as_bytes()[1..].iter().all(u8::is_ascii_digit))
    {
        return Err(err(CloudErrorCode::MalformedResponse));
    }
    let t = DateTime::parse_from_rfc3339(s)
        .map_err(|_| err(CloudErrorCode::MalformedResponse))?
        .with_timezone(&Utc);
    if t.timestamp() <= 0 {
        return Err(err(CloudErrorCode::MalformedResponse));
    }
    Ok(t)
}
impl ProtocolClient {
    fn attach_budget(&mut self, budget: &RawDiskReadBudget) -> Result<(), CloudError> {
        #[cfg(test)]
        if let Some(endpoint) = &budget.test_endpoint {
            let c = &self.transport.inner.config;
            // Rebuild the same production transport with only endpoint+HTTPS
            // requirement changed for the local HTTP stand-in. Exact config and
            // generated session policy are preserved; cache is fresh and empty.
            self.transport = AlibabaCloudFencing::build_transport(
                CloudIdentityConfig {
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
                    session_policy: c.session_policy.clone(),
                },
                BTreeMap::new(),
                Some(self.expected.deployment.clone()),
                endpoint.clone(),
                endpoint.clone(),
                false,
            )?;
        }
        if self.purpose != budget.purpose {
            return Err(err(CloudErrorCode::Configuration));
        }
        // Fresh transport is uniquely owned. Only guards are shared, never its
        // credential cache, account/RoleID result or disk session policy.
        let inner = Arc::get_mut(&mut self.transport.inner)
            .ok_or_else(|| err(CloudErrorCode::Configuration))?;
        inner.next_request = budget.next_request.clone();
        inner.in_flight = budget.in_flight.clone();
        Ok(())
    }

    // Private, deliberately not an AdmissionRawDiskClient/BackupRawDiskClient
    // constructor; normal entry must first validate its fixed-purpose sealed scope.
    fn new(
        identity: RawDiskCloudConfig,
        expected: ExpectedDisk,
        purpose: ReadPurpose,
    ) -> Result<Self, CloudError> {
        expected.validate()?;
        if identity.account_id != expected.account_id
            || identity.region != expected.region
            || identity.oidc_subject != purpose.subject()
        {
            return Err(err(CloudErrorCode::Configuration));
        }
        let policy = serde_json::to_string(&json!({"Version":"1","Statement":[
            {"Effect":"Allow","Action":["ecs:DescribeDisks"],"Resource":[format!(
                "acs:ecs:{}:{}:disk/{}",expected.region,expected.account_id,expected.disk_id)]},
            {"Effect":"Allow","Action":["sts:GetCallerIdentity"],"Resource":["*"]}
        ]}))
        .map_err(|_| err(CloudErrorCode::Configuration))?;
        if policy.len() > 2048 {
            return Err(err(CloudErrorCode::Configuration));
        }
        let sts = url::Url::parse(&format!("https://sts.{}.aliyuncs.com/", identity.region))
            .map_err(|_| err(CloudErrorCode::Configuration))?;
        let ecs = url::Url::parse(&format!("https://ecs.{}.aliyuncs.com/", identity.region))
            .map_err(|_| err(CloudErrorCode::Configuration))?;
        let transport_identity = CloudIdentityConfig {
            account_id: identity.account_id,
            region: identity.region,
            role_arn: identity.role_arn,
            role_id: identity.role_id,
            oidc_provider_arn: identity.oidc_provider_arn,
            oidc_issuer: identity.oidc_issuer,
            oidc_audience: "sts.aliyuncs.com".into(),
            oidc_subject: identity.oidc_subject,
            oidc_token_file: identity.oidc_token_file,
            requests_per_second: identity.requests_per_second,
            max_in_flight: identity.max_in_flight,
            session_policy: Some(policy),
        };
        validate_identity_config(&transport_identity)?;
        let transport = AlibabaCloudFencing::build_transport(
            transport_identity,
            BTreeMap::new(),
            Some(expected.deployment.clone()),
            sts,
            ecs,
            true,
        )?;
        Ok(Self {
            transport,
            expected,
            purpose,
        })
    }
    async fn observe_protocol(
        self,
        original_deadline: AbsoluteDeadline,
    ) -> Result<DiskProtocolObservation, CloudError> {
        // Future typed caller must supply min(original RawBoundAttempt+10s,
        // first14pin horizon). This private method never starts/resets a timer.
        current(original_deadline)?;
        let call_deadline = if self.purpose == ReadPurpose::Admission {
            original_deadline.min(AbsoluteDeadline::now() + Duration::from_secs(3))
        } else {
            original_deadline
        };
        let observed = tokio::time::timeout_at(Instant::from_std(call_deadline), async move {
            current(original_deadline)?;
            let credentials = self.transport.credentials().await?;
            current(original_deadline)?;
            let query = BTreeMap::from([
                ("RegionId".into(), self.expected.region.clone()),
                (
                    "DiskIds".into(),
                    serde_json::to_string(&[&self.expected.disk_id])
                        .map_err(|_| err(CloudErrorCode::Configuration))?,
                ),
                ("MaxResults".into(), "10".into()),
            ]);
            // No status, encryption, tag, instance or zone filter can hide drift.
            let r = self
                .transport
                .read_request(
                    "DescribeDisks",
                    ECS_VERSION,
                    &self.transport.inner.ecs,
                    &query,
                    Some(&credentials),
                )
                .await?;
            current(original_deadline)?;
            let observed = decode(self.expected, &r, original_deadline)?;
            observed.current()?;
            Ok(observed)
        })
        .await
        .map_err(|_| err(CloudErrorCode::ObservationStale))??;
        current(call_deadline)?; // Ready-first cannot bypass the finite admission sub-budget.
        observed.current()?;
        Ok(observed)
    }
}
impl DiskProtocolObservation {
    fn disk_facts(&self) -> Result<RawPvDiskFacts, CloudError> {
        self.current()?;
        let e = &self.expected;
        Ok(RawPvDiskFacts {
            account_id: e.account_id.clone(),
            region: e.region.clone(),
            disk_id: e.disk_id.clone(),
            zone_id: e.zone_id.clone(),
            deployment: e.deployment.clone(),
            namespace: "sandbox-system".into(),
            pvc_name: e.pvc_name(),
            pv_name: e.pv_name(),
            kms_key_id: e.kms_key_id.clone(),
            size_gib: e.size_gib,
            serial_number: self.serial_number.clone(),
            creation_time: self.creation_time,
        })
    }
    fn same_identity(&self, other: &Self) -> Result<(), CloudError> {
        self.current()?;
        other.current()?;
        let (a, _) = self.identity_and_evidence()?;
        let (b, _) = other.identity_and_evidence()?;
        if a != b || self.original_deadline != other.original_deadline {
            return Err(err(CloudErrorCode::IdentityMismatch));
        }
        self.current()?;
        other.current()
    }

    fn current(&self) -> Result<(), CloudError> {
        current(self.original_deadline)?;
        let now = Utc::now();
        if self.evidence.received_at < now - ChronoDuration::seconds(10)
            || self.evidence.received_at > now + ChronoDuration::seconds(2)
        {
            return Err(err(CloudErrorCode::ObservationStale));
        }
        Ok(())
    }
    // Fixed output shape is ready for later strong writer comparison only; this
    // private function neither INSERTs nor issues a binding/launch permit.
    fn identity_and_evidence(&self) -> Result<(Value, Value), CloudError> {
        self.current()?;
        let request_id = self
            .evidence
            .provider_request_id
            .as_deref()
            .filter(|s| visible(s, 256))
            .ok_or_else(|| err(CloudErrorCode::MalformedResponse))?;
        let response_sha = self
            .evidence
            .response_sha256
            .as_deref()
            .filter(|s| crate::nodeguard::protocol::valid_sha256(s))
            .ok_or_else(|| err(CloudErrorCode::MalformedResponse))?;
        let b = &self.expected;
        let identity = json!({"binding":{"account_id":b.account_id,"region":b.region,
            "disk_id":b.disk_id,"zone_id":b.zone_id,"deployment":b.deployment,
            "namespace":"sandbox-system","pvc_name":b.pvc_name(),"pv_name":b.pv_name(),
            "kms_key_id":b.kms_key_id,"size_gib":b.size_gib},
            "serial_number":self.serial_number,
            "creation_time":self.creation_time.to_rfc3339_opts(SecondsFormat::Micros,true)});
        let evidence = json!({"request_id":request_id,"response_sha256":response_sha,
            "observed_at":self.evidence.received_at.to_rfc3339_opts(SecondsFormat::Micros,true)});
        self.current()?;
        Ok((identity, evidence))
    }
}
fn decode(
    expected: ExpectedDisk,
    r: &Response,
    deadline: AbsoluteDeadline,
) -> Result<DiskProtocolObservation, CloudError> {
    expected.validate()?;
    current(deadline)?;
    if !r.status.is_success() || r.evidence.action != "DescribeDisks" {
        return Err(response_error(CloudErrorCode::MalformedResponse, r));
    }
    let response: DescribeRawDisks = parse_response(r)?;
    if !visible(&response.request_id, 256)
        || r.evidence.provider_request_id.as_deref() != Some(response.request_id.as_str())
        || r.evidence
            .response_sha256
            .as_deref()
            .is_none_or(|s| !crate::nodeguard::protocol::valid_sha256(s))
        || !response.next_token.as_deref().unwrap_or("").is_empty()
        || response.disks.disk.len() != 1
    {
        return Err(response_error(CloudErrorCode::IdentityMismatch, r));
    }
    let d = &response.disks.disk[0];
    if d.disk_id != expected.disk_id
        || d.region_id != expected.region
        || d.zone_id != expected.zone_id
        || d.disk_type != "data"
        || d.category != "cloud_essd"
        || d.performance_level != "PL1"
        || !d.portable
        || !d.encrypted
        || d.kms_key_id != expected.kms_key_id
        || d.size != expected.size_gib
        || d.disk_charge_type != "PostPaid"
        || d.delete_with_instance
        || d.multi_attach != "Disabled"
        || !d.source_disk_id.as_deref().unwrap_or("").is_empty()
        || !d.source_snapshot_id.as_deref().unwrap_or("").is_empty()
        || !d.image_id.as_deref().unwrap_or("").is_empty()
        || d.data_source
            .as_ref()
            .is_some_and(|v| !v.is_null() && v != &json!({}))
        || !visible(&d.serial_number, 128)
    {
        return Err(response_error(CloudErrorCode::IdentityMismatch, r));
    }
    let creation_time = utc(&d.creation_time)?;
    if creation_time > r.evidence.received_at
        || creation_time < expected.parent_intent_created_at - ChronoDuration::seconds(2)
        || expected.recorded_identity.as_ref().is_some_and(|old| {
            old.serial_number != d.serial_number || old.creation_time != creation_time
        })
    {
        return Err(response_error(CloudErrorCode::IdentityMismatch, r));
    }
    let mut tags = BTreeMap::new();
    if d.tags.tag.len() > 256 {
        return Err(response_error(CloudErrorCode::ResponseLimit, r));
    }
    for t in &d.tags.tag {
        if !visible(&t.tag_key, 256)
            || t.tag_value.len() > 256
            || t.tag_value.chars().any(char::is_control)
            || tags
                .insert(t.tag_key.as_str(), t.tag_value.as_str())
                .is_some()
        {
            return Err(response_error(CloudErrorCode::IdentityMismatch, r));
        }
    }
    let pvc = expected.pvc_name();
    let pv = expected.pv_name();
    for (key, value) in [
        ("Deployment", expected.deployment.as_str()),
        ("kubernetes.io/created-for/pvc/namespace", "sandbox-system"),
        ("kubernetes.io/created-for/pvc/name", pvc.as_str()),
        ("kubernetes.io/created-for/pv/name", pv.as_str()),
    ] {
        if tags.get(key) != Some(&value) {
            return Err(response_error(CloudErrorCode::IdentityMismatch, r));
        }
    }
    let status = match d.status.as_str() {
        "Available" => DiskStatus::Available,
        "In_use" => DiskStatus::InUse,
        _ => return Err(response_error(CloudErrorCode::InvalidState, r)),
    };
    let mut ids = BTreeSet::new();
    if let Some(id) = d.instance_id.as_deref().filter(|s| !s.is_empty()) {
        if !cloud_id(id, "i-") {
            return Err(response_error(CloudErrorCode::MalformedResponse, r));
        }
        ids.insert(id.to_owned());
    }
    let lists = [
        d.attachments.as_ref().map(|a| &a.attachment),
        d.mount_instances.as_ref().map(|a| &a.mount_instance),
    ];
    for list in lists.into_iter().flatten() {
        if list.len() > 16 {
            return Err(response_error(CloudErrorCode::ResponseLimit, r));
        }
        let mut unique = BTreeSet::new();
        for a in list {
            if !cloud_id(&a.instance_id, "i-") || !unique.insert(a.instance_id.as_str()) {
                return Err(response_error(CloudErrorCode::IdentityMismatch, r));
            }
            ids.insert(a.instance_id.clone());
        }
    }
    if ids.iter().any(|s| s != &expected.selected_instance_id)
        || d.mount_instance_num.is_some_and(|n| n > 1)
        || (status == DiskStatus::Available
            && (!ids.is_empty() || d.mount_instance_num.is_some_and(|n| n > 0)))
        || (status == DiskStatus::InUse
            && (ids.len() != 1
                || d.instance_id.as_deref() != Some(expected.selected_instance_id.as_str())))
    {
        return Err(response_error(CloudErrorCode::IdentityMismatch, r));
    }
    // Omitted optional attachment arrays for a nonshared Available disk stay
    // omitted: acceptance is identity-only, never an empty-writer/absence proof.
    let mut evidence = r.evidence.clone();
    evidence.received_at = DateTime::from_timestamp_micros(evidence.received_at.timestamp_micros())
        .ok_or_else(|| err(CloudErrorCode::MalformedResponse))?;
    let observed = DiskProtocolObservation {
        expected,
        serial_number: d.serial_number.clone(),
        creation_time,
        status,
        attached_instance_ids: ids,
        evidence,
        original_deadline: deadline,
    };
    observed.current()?;
    Ok(observed)
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DescribeRawDisks {
    request_id: String,
    #[serde(default)]
    next_token: Option<String>,
    disks: RawDisks,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawDisks {
    disk: Vec<RawDisk>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawDisk {
    disk_id: String,
    region_id: String,
    zone_id: String,
    #[serde(rename = "Type")]
    disk_type: String,
    category: String,
    performance_level: String,
    portable: bool,
    encrypted: bool,
    #[serde(rename = "KMSKeyId")]
    kms_key_id: String,
    size: u32,
    disk_charge_type: String,
    delete_with_instance: bool,
    multi_attach: String,
    tags: Tags,
    status: String,
    serial_number: String,
    creation_time: String,
    #[serde(default)]
    source_disk_id: Option<String>,
    #[serde(default)]
    source_snapshot_id: Option<String>,
    #[serde(default)]
    image_id: Option<String>,
    #[serde(default)]
    data_source: Option<Value>,
    #[serde(default)]
    instance_id: Option<String>,
    #[serde(default)]
    mount_instance_num: Option<u32>,
    #[serde(default)]
    attachments: Option<RawAttachments>,
    #[serde(default)]
    mount_instances: Option<RawMountInstances>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawAttachments {
    attachment: Vec<RawAttachment>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawMountInstances {
    mount_instance: Vec<RawAttachment>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawAttachment {
    instance_id: String,
}

#[cfg(test)]
#[path = "cloud_restore_raw_disk_protocol_tests.rs"]
mod tests;
