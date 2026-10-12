//! Alibaba Cloud transport observations are not a durable fence. A successful
//! StopInstance or a single Stopped read cannot authorize quota/storage release.
//! The fencing client has no Start/Delete API and never retries Stop. The
//! separately credentialed volume client can delete only a bound data disk.
use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use reqwest::{
    Client, Method, StatusCode,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, net::IpAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::AsyncReadExt,
    sync::{Mutex, Semaphore},
    time::Instant,
};
use uuid::Uuid;

const STS_VERSION: &str = "2015-04-01";
const ECS_VERSION: &str = "2014-05-26";
const BODY_LIMIT: usize = 1024 * 1024;

#[cfg(test)]
#[path = "cloud_admission_node_topology.rs"]
pub(crate) mod admission_node_topology;
#[cfg(test)]
#[path = "cloud_node_topology.rs"]
pub(crate) mod node_topology;

#[path = "cloud_credential_agent.rs"]
pub mod credential_agent;

#[path = "cloud_disks.rs"]
mod disks;
pub use disks::{
    CloudDiskAbsence, CloudDiskAttachmentState, CloudDiskBinding, CloudDiskIdentity,
    CloudDiskLookup, CloudDiskObservation, CloudDiskState,
};
#[path = "cloud_restore_gc.rs"]
pub mod restore_gc;
#[path = "cloud_volume_deletion.rs"]
pub(crate) mod volume_deletion;
pub use volume_deletion::{
    AlibabaCloudVolumeDeletion, CloudDiskDeleteOutcome, CloudDiskDeleteSubmission,
    CloudDiskPreserveOutcome, CloudDiskPreserveSubmission, CloudVolumeDeletionConfig,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudInstanceBinding {
    pub instance_id: String,
    pub vpc_id: String,
    pub private_ip: IpAddr,
    pub deployment: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudFencingConfig {
    pub account_id: String,
    pub region: String,
    pub role_arn: String,
    pub role_id: String,
    pub oidc_provider_arn: String,
    pub oidc_issuer: String,
    pub oidc_audience: String,
    pub oidc_subject: String,
    pub oidc_token_file: PathBuf,
    pub instances: Vec<CloudInstanceBinding>,
    /// Shared across STS, identity checks, queries, writes, and cloned clients.
    pub requests_per_second: u32,
    pub max_in_flight: usize,
}
// Transport identity is shared; node and disk authorization remain separate.
struct CloudIdentityConfig {
    account_id: String,
    region: String,
    role_arn: String,
    role_id: String,
    oidc_provider_arn: String,
    oidc_issuer: String,
    oidc_audience: String,
    oidc_subject: String,
    oidc_token_file: PathBuf,
    requests_per_second: u32,
    max_in_flight: usize,
    // Generated only by a narrow component; absent for existing transports.
    session_policy: Option<String>,
}
impl From<&CloudFencingConfig> for CloudIdentityConfig {
    fn from(c: &CloudFencingConfig) -> Self {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CloudErrorCode {
    Configuration,
    CredentialUnavailable,
    CredentialIdentityMismatch,
    UnknownInstance,
    IdentityMismatch,
    MalformedResponse,
    ResponseLimit,
    Transport,
    Overloaded,
    AccessDenied,
    Throttled,
    InvalidState,
    ObservationStale,
    ProviderRejected,
}
#[derive(Debug, thiserror::Error)]
#[error("cloud transport failed: {code:?}")]
pub struct CloudError {
    pub code: CloudErrorCode,
    pub evidence: Option<CloudRequestEvidence>,
}
fn err(code: CloudErrorCode) -> CloudError {
    CloudError {
        code,
        evidence: None,
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CloudInstanceState {
    Pending,
    Running,
    Starting,
    Stopping,
    Stopped,
}
#[derive(Debug, Clone, Serialize)]
pub struct CloudRequestEvidence {
    action: &'static str,
    local_request_id: Uuid,
    provider_request_id: Option<String>,
    sent_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
    http_status: Option<u16>,
    response_sha256: Option<String>,
}
impl CloudRequestEvidence {
    pub fn action(&self) -> &str {
        self.action
    }
    pub fn local_request_id(&self) -> Uuid {
        self.local_request_id
    }
    pub fn provider_request_id(&self) -> Option<&str> {
        self.provider_request_id.as_deref()
    }
    pub fn sent_at(&self) -> DateTime<Utc> {
        self.sent_at
    }
    pub fn received_at(&self) -> DateTime<Utc> {
        self.received_at
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct CloudInstanceObservation {
    account_id: String,
    region: String,
    instance_id: String,
    vpc_id: String,
    private_ip: IpAddr,
    state: CloudInstanceState,
    evidence: CloudRequestEvidence,
}
impl CloudInstanceObservation {
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    pub fn region(&self) -> &str {
        &self.region
    }
    pub fn state(&self) -> CloudInstanceState {
        self.state
    }
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }
    pub fn evidence(&self) -> &CloudRequestEvidence {
        &self.evidence
    }
}
#[derive(Debug, Serialize)]
pub struct CloudStopSubmission {
    attempt_id: Uuid,
    preflight: CloudInstanceObservation,
    evidence: CloudRequestEvidence,
}
impl CloudStopSubmission {
    pub fn attempt_id(&self) -> Uuid {
        self.attempt_id
    }
    pub fn preflight(&self) -> &CloudInstanceObservation {
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
pub enum CloudStopOutcome {
    Accepted(CloudStopSubmission),
    AlreadyStopped(CloudInstanceObservation),
    OutcomeUnknown(CloudStopSubmission),
}

#[derive(Clone)]
pub struct AlibabaCloudFencing {
    inner: Arc<Inner>,
}
struct Inner {
    config: CloudIdentityConfig,
    client: Client,
    sts: url::Url,
    ecs: url::Url,
    bindings: BTreeMap<String, CloudInstanceBinding>,
    disk_deployment: Option<String>,
    credentials: Mutex<Option<Arc<Credentials>>>,
    next_request: Arc<Mutex<Instant>>,
    in_flight: Arc<Semaphore>,
}
// No Debug/Serialize for credentials, request URLs, or the client containing them.
struct Credentials {
    access_key_id: String,
    secret: String,
    token: String,
    expires: DateTime<Utc>,
}
struct Response {
    status: StatusCode,
    body: Vec<u8>,
    evidence: CloudRequestEvidence,
    retry_after: Option<Duration>,
}

impl AlibabaCloudFencing {
    pub fn validate_binding(
        &self,
        account_id: &str,
        region: &str,
        instance_id: &str,
        private_ip: IpAddr,
    ) -> bool {
        self.inner.config.account_id == account_id
            && self.inner.config.region == region
            && self
                .inner
                .bindings
                .get(instance_id)
                .is_some_and(|binding| binding.private_ip == private_ip)
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        config: CloudFencingConfig,
        endpoint: url::Url,
    ) -> Result<Self, CloudError> {
        validate_config(&config)?;
        Self::build(config, endpoint.clone(), endpoint, false)
    }

    pub fn new(config: CloudFencingConfig) -> Result<Self, CloudError> {
        validate_config(&config)?;
        let sts = url::Url::parse(&format!("https://sts.{}.aliyuncs.com/", config.region))
            .map_err(|_| err(CloudErrorCode::Configuration))?;
        let ecs = url::Url::parse(&format!("https://ecs.{}.aliyuncs.com/", config.region))
            .map_err(|_| err(CloudErrorCode::Configuration))?;
        Self::build(config, sts, ecs, true)
    }
    fn build(
        config: CloudFencingConfig,
        sts: url::Url,
        ecs: url::Url,
        https: bool,
    ) -> Result<Self, CloudError> {
        let identity = CloudIdentityConfig::from(&config);
        let bindings = config
            .instances
            .into_iter()
            .map(|i| (i.instance_id.clone(), i))
            .collect();
        Self::build_transport(identity, bindings, None, sts, ecs, https)
    }
    fn build_transport(
        config: CloudIdentityConfig,
        bindings: BTreeMap<String, CloudInstanceBinding>,
        disk_deployment: Option<String>,
        sts: url::Url,
        ecs: url::Url,
        https: bool,
    ) -> Result<Self, CloudError> {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .https_only(https)
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(8))
            .pool_max_idle_per_host(4)
            .build()
            .map_err(|_| err(CloudErrorCode::Configuration))?;
        let in_flight = Arc::new(Semaphore::new(config.max_in_flight));
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                client,
                sts,
                ecs,
                bindings,
                disk_deployment,
                credentials: Mutex::new(None),
                next_request: Arc::new(Mutex::new(Instant::now())),
                in_flight,
            }),
        })
    }
    pub async fn observe(&self, instance_id: &str) -> Result<CloudInstanceObservation, CloudError> {
        tokio::time::timeout(Duration::from_secs(45), self.observe_inner(instance_id))
            .await
            .map_err(|_| err(CloudErrorCode::Transport))?
    }
    async fn observe_inner(
        &self,
        instance_id: &str,
    ) -> Result<CloudInstanceObservation, CloudError> {
        let target = self
            .inner
            .bindings
            .get(instance_id)
            .ok_or_else(|| err(CloudErrorCode::UnknownInstance))?;
        let credentials = self.credentials().await?;
        let query = BTreeMap::from([
            ("RegionId".into(), self.inner.config.region.clone()),
            (
                "InstanceIds".into(),
                serde_json::to_string(&[instance_id])
                    .map_err(|_| err(CloudErrorCode::Configuration))?,
            ),
            ("MaxResults".into(), "10".into()),
        ]);
        let response = self
            .read_request(
                "DescribeInstances",
                ECS_VERSION,
                &self.inner.ecs,
                &query,
                Some(&credentials),
            )
            .await?;
        let value: DescribeResponse = parse_response(&response)?;
        if !value.next_token.as_deref().unwrap_or("").is_empty()
            || value.instances.instance.len() != 1
        {
            return Err(CloudError {
                code: CloudErrorCode::IdentityMismatch,
                evidence: Some(response.evidence),
            });
        }
        let instance = &value.instances.instance[0];
        let mut tags = BTreeMap::new();
        for tag in &instance.tags.tag {
            if tags
                .insert(tag.tag_key.as_str(), tag.tag_value.as_str())
                .is_some()
            {
                return Err(response_error(CloudErrorCode::IdentityMismatch, &response));
            }
        }
        let ips: Result<Vec<IpAddr>, _> = instance
            .vpc_attributes
            .private_ip_address
            .ip_address
            .iter()
            .map(|s| s.parse())
            .collect();
        if instance.instance_id != target.instance_id
            || instance.region_id != self.inner.config.region
            || instance.instance_network_type != "vpc"
            || instance.vpc_attributes.vpc_id != target.vpc_id
            || !ips
                .map_err(|_| response_error(CloudErrorCode::IdentityMismatch, &response))?
                .contains(&target.private_ip)
            || tags.get("Deployment") != Some(&target.deployment.as_str())
            || tags.get("Role") != Some(&"kata")
        {
            return Err(CloudError {
                code: CloudErrorCode::IdentityMismatch,
                evidence: Some(response.evidence),
            });
        }
        let state = match instance.status.as_str() {
            "Pending" => CloudInstanceState::Pending,
            "Running" => CloudInstanceState::Running,
            "Starting" => CloudInstanceState::Starting,
            "Stopping" => CloudInstanceState::Stopping,
            "Stopped" => CloudInstanceState::Stopped,
            _ => return Err(response_error(CloudErrorCode::MalformedResponse, &response)),
        };
        Ok(CloudInstanceObservation {
            account_id: self.inner.config.account_id.clone(),
            region: self.inner.config.region.clone(),
            instance_id: target.instance_id.clone(),
            vpc_id: target.vpc_id.clone(),
            private_ip: target.private_ip,
            state,
            evidence: response.evidence,
        })
    }
    /// Caller must durably record DISPATCHING before invoking this once. The local
    /// attempt ID is evidence correlation, NOT a cloud ClientToken/idempotency key.
    pub async fn force_stop(
        &self,
        instance_id: &str,
        attempt_id: Uuid,
    ) -> Result<CloudStopOutcome, CloudError> {
        if attempt_id.is_nil() {
            return Err(err(CloudErrorCode::Configuration));
        }
        let preflight = self.observe(instance_id).await?;
        if preflight.state == CloudInstanceState::Stopped {
            return Ok(CloudStopOutcome::AlreadyStopped(preflight));
        }
        // Refresh before writing, then perform precisely one HTTP send. No outer
        // cancellation timeout may turn an attempted write into a retryable error.
        let credentials = tokio::time::timeout(Duration::from_secs(45), self.credentials())
            .await
            .map_err(|_| err(CloudErrorCode::CredentialUnavailable))??;
        let query = BTreeMap::from([
            ("InstanceId".into(), instance_id.into()),
            ("ForceStop".into(), "true".into()),
            ("StoppedMode".into(), "KeepCharging".into()),
        ]);
        match self
            .send(
                "StopInstance",
                ECS_VERSION,
                &self.inner.ecs,
                &query,
                Some(&credentials),
                Some(preflight.evidence.received_at + ChronoDuration::seconds(5)),
            )
            .await
        {
            Ok(response) => {
                let receipt = CloudStopSubmission {
                    attempt_id,
                    preflight,
                    evidence: response.evidence.clone(),
                };
                if response.status.is_success() {
                    if response.evidence.provider_request_id.is_none()
                        || provider_code(&response.body).is_some()
                    {
                        return Ok(CloudStopOutcome::OutcomeUnknown(receipt));
                    }
                    Ok(CloudStopOutcome::Accepted(receipt))
                } else if response.status.is_server_error() {
                    Ok(CloudStopOutcome::OutcomeUnknown(receipt))
                } else {
                    Err(provider_error(&response))
                }
            }
            Err(failure) => {
                if let Some(evidence) = failure.evidence {
                    Ok(CloudStopOutcome::OutcomeUnknown(CloudStopSubmission {
                        attempt_id,
                        preflight,
                        evidence,
                    }))
                } else {
                    Err(failure)
                }
            }
        }
    }
    async fn credentials(&self) -> Result<Arc<Credentials>, CloudError> {
        let mut cache = self.inner.credentials.lock().await;
        if let Some(c) = cache
            .as_ref()
            .filter(|c| c.expires > Utc::now() + ChronoDuration::seconds(90))
        {
            return Ok(c.clone());
        }
        *cache = None; // Expired/refresh-window credentials never become fallback.
        let oidc = read_oidc_token(&self.inner.config.oidc_token_file).await?;
        let purpose = if self.inner.disk_deployment.is_some() {
            "volume"
        } else if self.inner.bindings.is_empty() {
            "storage"
        } else {
            "fencing"
        };
        let session = format!("{purpose}-{}", Uuid::new_v4().simple());
        let mut query = BTreeMap::from([
            (
                "OIDCProviderArn".into(),
                self.inner.config.oidc_provider_arn.clone(),
            ),
            ("RoleArn".into(), self.inner.config.role_arn.clone()),
            ("RoleSessionName".into(), session.clone()),
            ("DurationSeconds".into(), "900".into()),
            ("OIDCToken".into(), oidc),
        ]);
        if let Some(policy) = &self.inner.config.session_policy {
            query.insert("Policy".into(), policy.clone());
        }
        let response = self
            .read_request(
                "AssumeRoleWithOIDC",
                STS_VERSION,
                &self.inner.sts,
                &query,
                None,
            )
            .await?;
        let assumed: AssumeResponse = parse_response(&response)?;
        let expected_arn = format!("{}/{}", self.inner.config.role_arn, session);
        let info = &assumed.oidc_token_info;
        let now = Utc::now();
        if assumed.assumed_role_user.arn != expected_arn
            || info.issuer != self.inner.config.oidc_issuer
            || info.subject != self.inner.config.oidc_subject
            || info.client_ids != self.inner.config.oidc_audience
            || info.verification_info != "Success"
            || info.expiration_time <= now
            || info.issuance_time > now + ChronoDuration::seconds(30)
            || assumed.credentials.expiration <= now + ChronoDuration::seconds(120)
            || assumed.credentials.expiration > now + ChronoDuration::seconds(930)
            || !assumed.credentials.access_key_id.starts_with("STS.")
            || assumed.credentials.access_key_secret.is_empty()
            || assumed.credentials.security_token.is_empty()
        {
            return Err(response_error(
                CloudErrorCode::CredentialIdentityMismatch,
                &response,
            ));
        }
        let credentials = Arc::new(Credentials {
            access_key_id: assumed.credentials.access_key_id,
            secret: assumed.credentials.access_key_secret,
            token: assumed.credentials.security_token,
            expires: assumed.credentials.expiration,
        });
        let identity_response = self
            .read_request(
                "GetCallerIdentity",
                STS_VERSION,
                &self.inner.sts,
                &BTreeMap::new(),
                Some(&credentials),
            )
            .await?;
        let identity: IdentityResponse = parse_response(&identity_response)?;
        if identity.identity_type != "AssumedRoleUser"
            || identity.account_id != self.inner.config.account_id
            || identity.arn != expected_arn
            || identity.role_id != self.inner.config.role_id
        {
            return Err(response_error(
                CloudErrorCode::CredentialIdentityMismatch,
                &identity_response,
            ));
        }
        *cache = Some(credentials.clone());
        Ok(credentials)
    }
    async fn read_request(
        &self,
        action: &'static str,
        version: &str,
        endpoint: &url::Url,
        query: &BTreeMap<String, String>,
        credentials: Option<&Credentials>,
    ) -> Result<Response, CloudError> {
        for attempt in 0..3 {
            let mut minimum_delay = Duration::ZERO;
            let result = self
                .send(action, version, endpoint, query, credentials, None)
                .await;
            match result {
                Ok(response) if response.status.is_success() => {
                    if response.evidence.provider_request_id.is_none() {
                        return Err(response_error(CloudErrorCode::MalformedResponse, &response));
                    }
                    return Ok(response);
                }
                Ok(response) => {
                    let retry = response.status == StatusCode::TOO_MANY_REQUESTS
                        || response.status.is_server_error()
                        || provider_code(&response.body)
                            .is_some_and(|s| s.starts_with("Throttling"));
                    if attempt == 2
                        || !retry
                        || response
                            .retry_after
                            .is_some_and(|d| d > Duration::from_secs(10))
                    {
                        return Err(provider_error(&response));
                    }
                    minimum_delay = response.retry_after.unwrap_or_default();
                }
                Err(failure) => {
                    if attempt == 2 || failure.code != CloudErrorCode::Transport {
                        return Err(failure);
                    }
                }
            }
            let jitter = u64::from(Uuid::new_v4().as_bytes()[0]);
            tokio::time::sleep(
                minimum_delay.max(Duration::from_millis(200 * (1 << attempt) + jitter)),
            )
            .await;
        }
        Err(err(CloudErrorCode::Transport))
    }
    async fn send(
        &self,
        action: &'static str,
        version: &str,
        endpoint: &url::Url,
        query: &BTreeMap<String, String>,
        credentials: Option<&Credentials>,
        latest_send: Option<DateTime<Utc>>,
    ) -> Result<Response, CloudError> {
        let _permit = self
            .inner
            .in_flight
            .try_acquire()
            .map_err(|_| err(CloudErrorCode::Overloaded))?;
        let mut next = self.inner.next_request.lock().await;
        tokio::time::sleep_until(*next).await;
        *next = Instant::now()
            + Duration::from_secs_f64(1.0 / f64::from(self.inner.config.requests_per_second));
        drop(next);
        if latest_send.is_some_and(|deadline| deadline <= Utc::now()) {
            return Err(err(CloudErrorCode::ObservationStale));
        }
        if credentials.is_some_and(|c| c.expires <= Utc::now() + ChronoDuration::seconds(15)) {
            return Err(err(CloudErrorCode::CredentialUnavailable));
        }
        let nonce = Uuid::new_v4();
        let sent_at = Utc::now();
        let mut query = query.clone();
        // This anonymous RPC operation follows the official STS SDK's common
        // query parameters; it intentionally has no AccessKey or Signature.
        if credentials.is_none() {
            query.insert("Action".into(), action.into());
            query.insert("Version".into(), version.into());
            query.insert("Format".into(), "JSON".into());
        }
        let canonical_query = canonical_query(&query);
        let mut url = endpoint.clone();
        url.set_query(Some(&canonical_query));
        let headers = signed_headers(
            endpoint,
            action,
            version,
            &canonical_query,
            credentials,
            sent_at,
            &nonce.to_string(),
        )?;
        let mut evidence = CloudRequestEvidence {
            action,
            local_request_id: nonce,
            provider_request_id: None,
            sent_at,
            received_at: sent_at,
            http_status: None,
            response_sha256: None,
        };
        let response = self
            .inner
            .client
            .request(Method::POST, url)
            .headers(headers)
            .body(Vec::new())
            .send()
            .await;
        let mut response = match response {
            Ok(r) => r,
            Err(_) => {
                evidence.received_at = Utc::now();
                return Err(CloudError {
                    code: CloudErrorCode::Transport,
                    evidence: Some(evidence),
                });
            }
        };
        evidence.http_status = Some(response.status().as_u16());
        let status = response.status();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs);
        if status == StatusCode::TOO_MANY_REQUESTS
            && let Some(delay) = retry_after.filter(|d| *d <= Duration::from_secs(10))
        {
            let mut next = self.inner.next_request.lock().await;
            *next = (*next).max(Instant::now() + delay);
        }
        let mut body = Vec::new();
        if response
            .content_length()
            .is_some_and(|n| n > BODY_LIMIT as u64)
        {
            evidence.received_at = Utc::now();
            return Err(CloudError {
                code: CloudErrorCode::ResponseLimit,
                evidence: Some(evidence),
            });
        }
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if body.len().saturating_add(chunk.len()) > BODY_LIMIT {
                        evidence.received_at = Utc::now();
                        return Err(CloudError {
                            code: CloudErrorCode::ResponseLimit,
                            evidence: Some(evidence),
                        });
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(_) => {
                    evidence.received_at = Utc::now();
                    return Err(CloudError {
                        code: CloudErrorCode::Transport,
                        evidence: Some(evidence),
                    });
                }
            }
        }
        evidence.received_at = Utc::now();
        evidence.provider_request_id = serde_json::from_slice::<RequestId>(&body)
            .ok()
            .and_then(|r| valid_request_id(&r.request_id).then_some(r.request_id));
        // Never keep even a credential payload digest in public evidence.
        if action != "AssumeRoleWithOIDC" {
            evidence.response_sha256 = Some(hex::encode(Sha256::digest(&body)));
        }
        Ok(Response {
            status,
            body,
            evidence,
            retry_after,
        })
    }
}

fn validate_config(c: &CloudFencingConfig) -> Result<(), CloudError> {
    validate_identity_config(&CloudIdentityConfig::from(c))?;
    if c.instances.is_empty() || c.instances.len() > 10_000 {
        return Err(err(CloudErrorCode::Configuration));
    }
    let mut seen = BTreeMap::new();
    for i in &c.instances {
        let private = match i.private_ip {
            IpAddr::V4(v) => v.is_private(),
            IpAddr::V6(v) => (v.segments()[0] & 0xfe00) == 0xfc00,
        };
        if !resource_id(&i.instance_id, "i-")
            || !resource_id(&i.vpc_id, "vpc-")
            || !private
            || !deployment_name(&i.deployment)
            || seen.insert(&i.instance_id, ()).is_some()
        {
            return Err(err(CloudErrorCode::Configuration));
        }
    }
    Ok(())
}
fn deployment_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}
fn validate_identity_config(c: &CloudIdentityConfig) -> Result<(), CloudError> {
    let account = c.account_id.len() >= 8
        && c.account_id.len() <= 32
        && c.account_id.bytes().all(|b| b.is_ascii_digit());
    let region = (3..=40).contains(&c.region.len())
        && c.region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !c.region.starts_with('-')
        && !c.region.ends_with('-');
    let issuer = url::Url::parse(&c.oidc_issuer).map_err(|_| err(CloudErrorCode::Configuration))?;
    let role_prefix = format!("acs:ram::{}:role/", c.account_id);
    let provider_prefix = format!("acs:ram::{}:oidc-provider/", c.account_id);
    if !account
        || !region
        || !arn_suffix(&c.role_arn, &role_prefix)
        || !arn_suffix(&c.oidc_provider_arn, &provider_prefix)
        || c.role_id.is_empty()
        || !c.role_id.bytes().all(|b| b.is_ascii_digit())
        || c.role_id.len() > 32
        || issuer.scheme() != "https"
        || issuer.host_str().is_none()
        || !issuer.username().is_empty()
        || issuer.password().is_some()
        || issuer.query().is_some()
        || issuer.fragment().is_some()
        || c.oidc_audience.is_empty()
        || c.oidc_audience.len() > 256
        || c.oidc_audience.contains(',')
        || !c.oidc_subject.starts_with("system:serviceaccount:")
        || c.oidc_subject.len() > 256
        || !c.oidc_token_file.is_absolute()
        || !(1..=20).contains(&c.requests_per_second)
        || !(1..=16).contains(&c.max_in_flight)
    {
        return Err(err(CloudErrorCode::Configuration));
    }
    Ok(())
}
fn arn_suffix(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|s| {
        !s.is_empty()
            && s.len() <= 128
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    })
}
fn resource_id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|s| {
        !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric())
    })
}
async fn read_oidc_token(path: &PathBuf) -> Result<String, CloudError> {
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits());
    let file = options
        .open(path)
        .await
        .map_err(|_| err(CloudErrorCode::CredentialUnavailable))?;
    let metadata = file
        .metadata()
        .await
        .map_err(|_| err(CloudErrorCode::CredentialUnavailable))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !matches!(
            metadata.permissions().mode() & 0o7777,
            0o400 | 0o440 | 0o600 | 0o640
        ) {
            return Err(err(CloudErrorCode::CredentialUnavailable));
        }
    }
    if !metadata.is_file() || metadata.len() > 20000 {
        return Err(err(CloudErrorCode::CredentialUnavailable));
    }
    let mut bytes = Vec::new();
    file.take(20001)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| err(CloudErrorCode::CredentialUnavailable))?;
    let token = String::from_utf8(bytes).map_err(|_| err(CloudErrorCode::CredentialUnavailable))?;
    let token = token.trim();
    if !(4..=20000).contains(&token.len()) || token.chars().any(char::is_whitespace) {
        return Err(err(CloudErrorCode::CredentialUnavailable));
    }
    Ok(token.to_owned())
}
fn encode(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(b"0123456789ABCDEF"[usize::from(b >> 4)]));
            out.push(char::from(b"0123456789ABCDEF"[usize::from(b & 15)]));
        }
    }
    out
}
fn canonical_query(query: &BTreeMap<String, String>) -> String {
    query
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}
fn signature(
    headers: &BTreeMap<String, String>,
    query: &str,
    secret: &str,
) -> Result<(String, String), CloudError> {
    let signed = headers
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers = headers
        .iter()
        .map(|(k, v)| format!("{k}:{}\n", v.trim()))
        .collect::<String>();
    let payload = hex::encode(Sha256::digest([]));
    let canonical = format!("POST\n/\n{query}\n{canonical_headers}\n{signed}\n{payload}");
    let to_sign = format!(
        "ACS3-HMAC-SHA256\n{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| err(CloudErrorCode::CredentialUnavailable))?;
    mac.update(to_sign.as_bytes());
    Ok((signed, hex::encode(mac.finalize().into_bytes())))
}
fn signed_headers(
    endpoint: &url::Url,
    action: &str,
    version: &str,
    query: &str,
    credentials: Option<&Credentials>,
    now: DateTime<Utc>,
    nonce: &str,
) -> Result<HeaderMap, CloudError> {
    let host = endpoint
        .host_str()
        .ok_or_else(|| err(CloudErrorCode::Configuration))?;
    let host = match endpoint.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    let mut values = BTreeMap::from([
        ("host".into(), host),
        ("x-acs-action".into(), action.into()),
        ("x-acs-version".into(), version.into()),
        (
            "x-acs-date".into(),
            now.to_rfc3339_opts(SecondsFormat::Secs, true),
        ),
        ("x-acs-signature-nonce".into(), nonce.into()),
        (
            "x-acs-content-sha256".into(),
            hex::encode(Sha256::digest([])),
        ),
    ]);
    if let Some(c) = credentials {
        values.insert("x-acs-security-token".into(), c.token.clone());
        let (signed, digest) = signature(&values, query, &c.secret)?;
        values.insert(
            "authorization".into(),
            format!(
                "ACS3-HMAC-SHA256 Credential={},SignedHeaders={signed},Signature={digest}",
                c.access_key_id
            ),
        );
    }
    values.insert("accept".into(), "application/json".into());
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        let mut parsed = HeaderValue::from_str(&value)
            .map_err(|_| err(CloudErrorCode::CredentialUnavailable))?;
        if matches!(name.as_str(), "authorization" | "x-acs-security-token") {
            parsed.set_sensitive(true);
        }
        headers.insert(
            HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| err(CloudErrorCode::Configuration))?,
            parsed,
        );
    }
    Ok(headers)
}
fn response_error(code: CloudErrorCode, response: &Response) -> CloudError {
    CloudError {
        code,
        evidence: Some(response.evidence.clone()),
    }
}
fn parse_response<T: serde::de::DeserializeOwned>(response: &Response) -> Result<T, CloudError> {
    serde_json::from_slice(&response.body)
        .map_err(|_| response_error(CloudErrorCode::MalformedResponse, response))
}
fn valid_request_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control)
}
fn provider_code(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<ProviderError>(body)
        .ok()
        .map(|e| e.code)
}
fn provider_error(response: &Response) -> CloudError {
    let code = provider_code(&response.body).unwrap_or_default();
    let classified =
        if response.status == StatusCode::TOO_MANY_REQUESTS || code.starts_with("Throttling") {
            CloudErrorCode::Throttled
        } else if matches!(
            code.as_str(),
            "IncorrectInstanceStatus"
                | "InvalidInstanceId.NotFound"
                | "IncorrectDiskStatus"
                | "IncorrectDiskStatus.Initializing"
                | "DiskStillAttached"
                | "DiskCreatingSnapshot"
                | "DiskNotPortable"
                | "DiskTypeViolation"
                | "InvalidDiskStatus.DeleteProtection"
                | "InvalidDiskId.NotFound"
        ) {
            CloudErrorCode::InvalidState
        } else if response.status == StatusCode::UNAUTHORIZED
            || response.status == StatusCode::FORBIDDEN
        {
            CloudErrorCode::AccessDenied
        } else {
            CloudErrorCode::ProviderRejected
        };
    CloudError {
        code: classified,
        evidence: Some(response.evidence.clone()),
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RequestId {
    request_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ProviderError {
    code: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AssumeResponse {
    #[serde(rename = "OIDCTokenInfo")]
    oidc_token_info: OidcInfo,
    assumed_role_user: AssumedUser,
    credentials: StsCredentials,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AssumedUser {
    arn: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct OidcInfo {
    subject: String,
    issuer: String,
    client_ids: String,
    expiration_time: DateTime<Utc>,
    issuance_time: DateTime<Utc>,
    verification_info: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct StsCredentials {
    access_key_id: String,
    access_key_secret: String,
    security_token: String,
    expiration: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct IdentityResponse {
    identity_type: String,
    account_id: String,
    arn: String,
    role_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DescribeResponse {
    instances: Instances,
    #[serde(default)]
    next_token: Option<String>,
    // TotalCount is explicitly undefined for MaxResults/NextToken pagination.
    // Exact cardinality is checked from Instance and an exhausted NextToken.
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Instances {
    instance: Vec<Instance>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Instance {
    instance_id: String,
    region_id: String,
    instance_network_type: String,
    status: String,
    vpc_attributes: VpcAttributes,
    tags: Tags,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct VpcAttributes {
    vpc_id: String,
    private_ip_address: PrivateIpAddresses,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PrivateIpAddresses {
    ip_address: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Tags {
    tag: Vec<Tag>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Tag {
    tag_key: String,
    tag_value: String,
}

#[cfg(test)]
#[path = "cloud_fencing_tests.rs"]
mod tests;

// Same closed restore development boundary; fixed read-only subject types.
#[cfg(test)]
#[path = "cloud_restore_raw_disk_protocol.rs"]
pub(crate) mod raw_disk;
