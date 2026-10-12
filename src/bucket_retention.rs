//! Read-only OSS retention certification. Only live authenticated HTTPS reads
//! create the private capability. A serialized receipt is an audit artifact,
//! never a substitute for a fresh verification when activating a profile.
use axum::http::{HeaderMap, Method, Request};
use chrono::{DateTime, Duration as ChronoDuration, NaiveDateTime, Utc};
use quick_xml::{Reader, events::Event};
use reqsign_aliyun_oss::{Credential, RequestSigner, SigningVersion};
use reqsign_core::{Context, SignRequest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::io::AsyncReadExt;
use uuid::Uuid;

const BODY_LIMIT: usize = 64 * 1024;
const CLOCK_SKEW: i64 = 30;
const ACTIVATION_SECONDS: i64 = 300;
const MAX_RUN_SECONDS: i64 = 6 * 3600;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BucketRetentionExpectation {
    pub profile_id: Uuid,
    pub cluster_epoch: Uuid,
    pub deployment: String,
    /// SHA256 of the exact immutable profile settings that the owner will insert.
    pub profile_settings_sha256: String,
    pub account_id: String,
    pub region: String,
    pub bucket: String,
    pub kms_key_id: String,
    pub vault_retention_days: u16,
    pub certified_until: DateTime<Utc>,
    /// Exact pre-existing, ordinary object that prevents an empty-bucket delete
    /// and recreation during this profile's activation/launch horizon.
    pub anchor_key: String,
    pub anchor_etag: String,
    pub anchor_size_bytes: u64,
}
impl BucketRetentionExpectation {
    pub fn validate(&self) -> Result<(), RetentionError> {
        let now = Utc::now();
        let ascii_id = |s: &str, max: usize| {
            !s.is_empty()
                && s.len() <= max
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        };
        let account =
            self.account_id.len() == 16 && self.account_id.bytes().all(|b| b.is_ascii_digit());
        let prefix = format!("certification/{}/{}/", self.cluster_epoch, self.profile_id);
        ensure(
            !self.profile_id.is_nil()
                && !self.cluster_epoch.is_nil()
                && ascii_id(&self.deployment, 63)
                && crate::nodeguard::protocol::valid_sha256(&self.profile_settings_sha256)
                && account
                && self.region.starts_with("cn-")
                && self.region.len() <= 32
                && self
                    .region
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && (3..=63).contains(&self.bucket.len())
                && self
                    .bucket
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !self.bucket.starts_with('-')
                && !self.bucket.ends_with('-')
                && ascii_id(&self.kms_key_id, 128)
                && (31..=3650).contains(&self.vault_retention_days)
                && self.certified_until > now + ChronoDuration::minutes(10)
                && self.certified_until <= now + ChronoDuration::days(30)
                && self
                    .anchor_key
                    .strip_prefix(&prefix)
                    .is_some_and(|s| ascii_id(s, 128))
                && !self.anchor_key.contains("..")
                && self.anchor_etag.starts_with('"')
                && self.anchor_etag.ends_with('"')
                && self.anchor_etag.len() >= 3
                && self.anchor_etag.len() <= 128
                && self.anchor_etag.bytes().all(|b| (33..=126).contains(&b))
                && (1..=1024 * 1024).contains(&self.anchor_size_bytes),
            RetentionCode::Configuration,
        )
    }
    fn endpoint(&self) -> String {
        format!(
            "https://{}.oss-{}-internal.aliyuncs.com",
            self.bucket, self.region
        )
    }
}
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetentionCode {
    Configuration,
    Credentials,
    Transport,
    AccessDenied,
    Missing,
    Throttled,
    ResponseLimit,
    MalformedResponse,
    ClockSkew,
    IdentityMismatch,
    NotLocked,
    RetentionTooShort,
    VersioningUnsupported,
    AnchorUnprotected,
    Changed,
    Expired,
}
#[derive(Debug, thiserror::Error)]
#[error("bucket retention verification failed: {code:?}")]
pub struct RetentionError {
    pub code: RetentionCode,
}
fn fail(code: RetentionCode) -> RetentionError {
    RetentionError { code }
}
fn ensure(value: bool, code: RetentionCode) -> Result<(), RetentionError> {
    if value { Ok(()) } else { Err(fail(code)) }
}
#[derive(Debug, Clone, Serialize)]
pub struct RetentionRequestEvidence {
    pub operation: String,
    pub provider_request_id: String,
    pub provider_date: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub response_sha256: String,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RetentionBucketObservation {
    pub creation_date: DateTime<Utc>,
    pub owner_id: String,
    pub name: String,
    pub location: String,
    pub kms_key_id: String,
    pub worm_id: String,
    pub worm_creation_date: DateTime<Utc>,
    pub retention_days: u16,
    pub versioning: String,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RetentionAnchorObservation {
    pub key: String,
    pub etag: String,
    pub size_bytes: u64,
    pub last_modified: DateTime<Utc>,
    pub protected_until: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize)]
pub struct BucketRetentionReceipt {
    pub protocol: String,
    pub expectation: BucketRetentionExpectation,
    pub endpoint: String,
    pub started_at: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub activation_not_after: DateTime<Utc>,
    pub bucket: RetentionBucketObservation,
    pub anchor: RetentionAnchorObservation,
    pub requests: Vec<RetentionRequestEvidence>,
    pub evidence_kind: String,
}
/// There is intentionally no Deserialize, constructor, or JSON-to-proof helper.
pub struct VerifiedBucketRetention {
    receipt: BucketRetentionReceipt,
}
impl VerifiedBucketRetention {
    pub fn receipt(&self) -> &BucketRetentionReceipt {
        &self.receipt
    }
    /// Call immediately before the owner transaction commits. This proves the
    /// same settings/epoch/profile, not independent RAM or recovery certification.
    pub fn check_current(
        &self,
        expected: &BucketRetentionExpectation,
    ) -> Result<(), RetentionError> {
        ensure(
            &self.receipt.expectation == expected,
            RetentionCode::IdentityMismatch,
        )?;
        let now = Utc::now();
        ensure(
            self.receipt.observed_at <= now + ChronoDuration::seconds(2)
                && now < self.receipt.activation_not_after
                && expected.certified_until > now,
            RetentionCode::Expired,
        )
    }
}

pub struct BucketRetentionVerifier {
    client: reqwest::Client,
    expected: BucketRetentionExpectation,
    sts_file: PathBuf,
    endpoint: String,
}
impl BucketRetentionVerifier {
    pub fn new(
        expected: BucketRetentionExpectation,
        sts_file: PathBuf,
    ) -> Result<Self, RetentionError> {
        expected.validate()?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .http1_only()
            .build()
            .map_err(|_| fail(RetentionCode::Configuration))?;
        let endpoint = expected.endpoint();
        Ok(Self {
            client,
            expected,
            sts_file,
            endpoint,
        })
    }
    pub async fn verify(&self) -> Result<VerifiedBucketRetention, RetentionError> {
        self.expected.validate()?;
        tokio::time::timeout(Duration::from_secs(90), self.verify_inner())
            .await
            .map_err(|_| fail(RetentionCode::Transport))?
    }
    async fn verify_inner(&self) -> Result<VerifiedBucketRetention, RetentionError> {
        let started_at = Utc::now();
        let mut requests = Vec::new();
        let first = self.round(&mut requests).await?;
        // Two separately signed observations; no cache validators, no redirect,
        // proxy, environment/default credential provider, or fallback region.
        tokio::time::sleep(Duration::from_secs(1)).await;
        let second = self.round(&mut requests).await?;
        ensure(first == second, RetentionCode::Changed)?;
        for pair in requests.windows(2) {
            ensure(
                pair[1].provider_date + ChronoDuration::seconds(2) >= pair[0].provider_date,
                RetentionCode::ClockSkew,
            )?;
        }
        let observed_at = Utc::now();
        let receipt = BucketRetentionReceipt {
            protocol: "oss-bucket-retention/v1".into(),
            expectation: self.expected.clone(),
            endpoint: self.expected.endpoint(),
            started_at,
            observed_at,
            activation_not_after: (observed_at + ChronoDuration::seconds(ACTIVATION_SECONDS))
                .min(self.expected.certified_until),
            bucket: first.0,
            anchor: first.1,
            requests,
            evidence_kind: "LIVE_AUTHENTICATED_OSS_READS_NOT_PROVIDER_SIGNED_ARTIFACT".into(),
        };
        Ok(VerifiedBucketRetention { receipt })
    }
    async fn round(
        &self,
        evidence: &mut Vec<RetentionRequestEvidence>,
    ) -> Result<(RetentionBucketObservation, RetentionAnchorObservation), RetentionError> {
        let info = self
            .request("GetBucketInfo", Method::GET, "/?bucketInfo", evidence)
            .await?;
        let worm = self
            .request("GetBucketWorm", Method::GET, "/?worm", evidence)
            .await?;
        let version = self
            .request("GetBucketVersioning", Method::GET, "/?versioning", evidence)
            .await?;
        let anchor = self
            .request(
                "HeadRetentionAnchor",
                Method::HEAD,
                &format!("/{}", self.expected.anchor_key),
                evidence,
            )
            .await?;
        let bucket = validate_bucket(&self.expected, &info.body, &worm.body, &version.body)?;
        let anchor = validate_anchor(&self.expected, &bucket, &anchor.headers, Utc::now())?;
        Ok((bucket, anchor))
    }
    async fn request(
        &self,
        operation: &str,
        method: Method,
        path: &str,
        evidence: &mut Vec<RetentionRequestEvidence>,
    ) -> Result<CloudResponse, RetentionError> {
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(250 * (1 << attempt))).await;
            }
            let credential = credentials(&self.sts_file).await?;
            let mut parts = Request::builder()
                .method(method.clone())
                .uri(format!("{}{path}", self.endpoint))
                .header("cache-control", "no-cache")
                .body(())
                .map_err(|_| fail(RetentionCode::Configuration))?
                .into_parts()
                .0;
            RequestSigner::new(&self.expected.bucket)
                .with_region(&self.expected.region)
                .with_signing_version(SigningVersion::V4)
                .sign_request(&Context::new(), &mut parts, Some(&credential), None)
                .await
                .map_err(|_| fail(RetentionCode::Credentials))?;
            for name in ["authorization", "x-oss-security-token"] {
                if let Some(value) = parts.headers.get_mut(name) {
                    value.set_sensitive(true);
                }
            }
            let began = Instant::now();
            let mut response = match self
                .client
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .send()
                .await
            {
                Ok(r) => r,
                Err(_) if attempt < 2 => continue,
                Err(_) => return Err(fail(RetentionCode::Transport)),
            };
            let status = response.status().as_u16();
            if (status == 429 || status >= 500) && attempt < 2 {
                continue;
            }
            ensure(
                status == 200,
                match status {
                    401 | 403 => RetentionCode::AccessDenied,
                    404 => RetentionCode::Missing,
                    429 | 500..=599 => RetentionCode::Throttled,
                    _ => RetentionCode::Transport,
                },
            )?;
            let headers = response.headers().clone();
            let received_at = Utc::now();
            let date = http_date(header(&headers, "date")?)?;
            ensure(
                (received_at - date).num_seconds().abs() <= CLOCK_SKEW
                    && began.elapsed() < Duration::from_secs(11),
                RetentionCode::ClockSkew,
            )?;
            let request_id = header(&headers, "x-oss-request-id")?;
            ensure(opaque(request_id, 256), RetentionCode::MalformedResponse)?;
            let mut body = Vec::new();
            if method != Method::HEAD {
                ensure(
                    response
                        .content_length()
                        .is_none_or(|v| v <= BODY_LIMIT as u64),
                    RetentionCode::ResponseLimit,
                )?;
                while let Some(chunk) = response
                    .chunk()
                    .await
                    .map_err(|_| fail(RetentionCode::Transport))?
                {
                    ensure(
                        body.len() + chunk.len() <= BODY_LIMIT,
                        RetentionCode::ResponseLimit,
                    )?;
                    body.extend_from_slice(&chunk);
                }
                ensure(!body.is_empty(), RetentionCode::MalformedResponse)?;
            }
            let response_sha256 = if method == Method::HEAD {
                // Only these allowlisted, credential-free fields enter evidence.
                let map: BTreeMap<_, _> = [
                    "etag",
                    "last-modified",
                    "content-length",
                    "x-oss-object-type",
                    "x-oss-server-side-encryption",
                    "x-oss-server-side-encryption-key-id",
                ]
                .into_iter()
                .map(|k| Ok((k, header(&headers, k)?)))
                .collect::<Result<_, RetentionError>>()?;
                hex::encode(Sha256::digest(
                    serde_json::to_vec(&map).map_err(|_| fail(RetentionCode::MalformedResponse))?,
                ))
            } else {
                hex::encode(Sha256::digest(&body))
            };
            evidence.push(RetentionRequestEvidence {
                operation: operation.into(),
                provider_request_id: request_id.into(),
                provider_date: date,
                received_at,
                response_sha256,
            });
            return Ok(CloudResponse { headers, body });
        }
        Err(fail(RetentionCode::Transport))
    }
}
struct CloudResponse {
    headers: HeaderMap,
    body: Vec<u8>,
}
fn opaque(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| (32..=126).contains(&b))
}
fn header<'a>(h: &'a HeaderMap, key: &str) -> Result<&'a str, RetentionError> {
    ensure(
        h.get_all(key).iter().count() == 1,
        RetentionCode::MalformedResponse,
    )?;
    h.get(key)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| fail(RetentionCode::MalformedResponse))
}
fn http_date(s: &str) -> Result<DateTime<Utc>, RetentionError> {
    DateTime::parse_from_rfc2822(s)
        .map(|v| v.with_timezone(&Utc))
        .map_err(|_| fail(RetentionCode::MalformedResponse))
}
fn utc_date(s: &str) -> Result<DateTime<Utc>, RetentionError> {
    // OSS GetBucketWorm's official example is UTC without a Z suffix.
    DateTime::parse_from_rfc3339(s)
        .map(|v| v.with_timezone(&Utc))
        .or_else(|_| NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").map(|v| v.and_utc()))
        .map_err(|_| fail(RetentionCode::MalformedResponse))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StsFile {
    access_key_id: String,
    access_key_secret: String,
    security_token: String,
    expires_at: DateTime<Utc>,
}
async fn credentials(path: &Path) -> Result<Credential, RetentionError> {
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits());
    let file = options
        .open(path)
        .await
        .map_err(|_| fail(RetentionCode::Credentials))?;
    let info = file
        .metadata()
        .await
        .map_err(|_| fail(RetentionCode::Credentials))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure(
            matches!(info.permissions().mode() & 0o777, 0o400 | 0o600),
            RetentionCode::Credentials,
        )?;
    }
    ensure(
        info.is_file() && info.len() <= 16384,
        RetentionCode::Credentials,
    )?;
    let mut raw = Vec::new();
    file.take(16385)
        .read_to_end(&mut raw)
        .await
        .map_err(|_| fail(RetentionCode::Credentials))?;
    ensure(raw.len() <= 16384, RetentionCode::Credentials)?;
    let value: StsFile =
        serde_json::from_slice(&raw).map_err(|_| fail(RetentionCode::Credentials))?;
    let now = Utc::now();
    ensure(
        value.access_key_id.starts_with("STS.")
            && opaque(&value.access_key_id, 256)
            && opaque(&value.access_key_secret, 256)
            && opaque(&value.security_token, 12288)
            && value.expires_at > now + ChronoDuration::seconds(120)
            && value.expires_at <= now + ChronoDuration::hours(1),
        RetentionCode::Credentials,
    )?;
    Ok(Credential {
        access_key_id: value.access_key_id,
        access_key_secret: value.access_key_secret,
        security_token: Some(value.security_token),
        expires_in: Some(
            value
                .expires_at
                .to_rfc3339()
                .parse()
                .map_err(|_| fail(RetentionCode::Credentials))?,
        ),
    })
}

/// Small bounded XML projection. Duplicate paths, DTDs/entities/CDATA, mixed
/// content, attributes other than the documented default xmlns, and deep trees
/// are rejected. SDK-generated response text never reaches logs or errors.
fn xml(body: &[u8], root: &str) -> Result<BTreeMap<String, String>, RetentionError> {
    ensure(body.len() <= BODY_LIMIT, RetentionCode::ResponseLimit)?;
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut stack: Vec<String> = Vec::new();
    let mut result = BTreeMap::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut root_seen = false;
    let mut parents = std::collections::BTreeSet::new();
    loop {
        let event = reader
            .read_event()
            .map_err(|_| fail(RetentionCode::MalformedResponse))?;
        let empty = matches!(&event, Event::Empty(_));
        match event {
            Event::Start(e) | Event::Empty(e) => {
                let name = std::str::from_utf8(e.name().as_ref())
                    .map_err(|_| fail(RetentionCode::MalformedResponse))?
                    .to_owned();
                ensure(
                    !name.is_empty()
                        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                    RetentionCode::MalformedResponse,
                )?;
                for attr in e.attributes() {
                    let attr = attr.map_err(|_| fail(RetentionCode::MalformedResponse))?;
                    ensure(
                        stack.is_empty()
                            && attr.key.as_ref() == b"xmlns"
                            && attr.value.as_ref().starts_with(b"http://doc.oss-")
                            && attr.value.as_ref().ends_with(b".aliyuncs.com"),
                        RetentionCode::MalformedResponse,
                    )?;
                }
                if stack.is_empty() {
                    ensure(!root_seen && name == root, RetentionCode::MalformedResponse)?;
                    root_seen = true;
                }
                if !stack.is_empty() {
                    let parent = stack.join("/");
                    ensure(
                        result.get(&parent).is_some_and(String::is_empty),
                        RetentionCode::MalformedResponse,
                    )?;
                    parents.insert(parent);
                }
                stack.push(name);
                ensure(stack.len() <= 8, RetentionCode::ResponseLimit)?;
                let path = stack.join("/");
                ensure(seen.insert(path.clone()), RetentionCode::MalformedResponse)?;
                result.insert(path, String::new());
                if empty {
                    stack.pop();
                }
            }
            Event::Text(e) => {
                ensure(
                    !stack.is_empty() && e.len() <= 4096,
                    RetentionCode::MalformedResponse,
                )?;
                let text = std::str::from_utf8(e.as_ref())
                    .map_err(|_| fail(RetentionCode::MalformedResponse))?;
                ensure(
                    !text.contains('&') && !text.chars().any(char::is_control),
                    RetentionCode::MalformedResponse,
                )?;
                let key = stack.join("/");
                ensure(!parents.contains(&key), RetentionCode::MalformedResponse)?;
                let old = result
                    .get_mut(&key)
                    .ok_or_else(|| fail(RetentionCode::MalformedResponse))?;
                ensure(old.is_empty(), RetentionCode::MalformedResponse)?;
                *old = text.into();
            }
            Event::End(_) => {
                ensure(stack.pop().is_some(), RetentionCode::MalformedResponse)?;
            }
            Event::Decl(_) if !root_seen => {}
            Event::Eof => {
                ensure(
                    root_seen && stack.is_empty(),
                    RetentionCode::MalformedResponse,
                )?;
                break;
            }
            _ => return Err(fail(RetentionCode::MalformedResponse)),
        }
    }
    Ok(result)
}
fn field<'a>(map: &'a BTreeMap<String, String>, path: &str) -> Result<&'a str, RetentionError> {
    map.get(path)
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| fail(RetentionCode::MalformedResponse))
}
fn validate_bucket(
    e: &BucketRetentionExpectation,
    info: &[u8],
    worm: &[u8],
    version: &[u8],
) -> Result<RetentionBucketObservation, RetentionError> {
    let i = xml(info, "BucketInfo")?;
    let w = xml(worm, "WormConfiguration")?;
    let v = xml(version, "VersioningConfiguration")?;
    ensure(
        !v.contains_key("VersioningConfiguration/Status")
            && i.get("BucketInfo/Bucket/Versioning")
                .is_none_or(String::is_empty),
        RetentionCode::VersioningUnsupported,
    )?;
    ensure(
        field(&w, "WormConfiguration/State")? == "Locked",
        RetentionCode::NotLocked,
    )?;
    let days: u16 = field(&w, "WormConfiguration/RetentionPeriodInDays")?
        .parse()
        .map_err(|_| fail(RetentionCode::MalformedResponse))?;
    ensure(
        days >= e.vault_retention_days && days <= 25550,
        RetentionCode::RetentionTooShort,
    )?;
    ensure(
        field(&i, "BucketInfo/Bucket/Owner/ID")? == e.account_id
            && field(&i, "BucketInfo/Bucket/Name")? == e.bucket
            && field(&i, "BucketInfo/Bucket/Location")? == format!("oss-{}", e.region)
            && field(&i, "BucketInfo/Bucket/IntranetEndpoint")?
                == format!("oss-{}-internal.aliyuncs.com", e.region)
            && field(&i, "BucketInfo/Bucket/ExtranetEndpoint")?
                == format!("oss-{}.aliyuncs.com", e.region)
            && field(&i, "BucketInfo/Bucket/AccessControlList/Grant")? == "private"
            && field(
                &i,
                "BucketInfo/Bucket/ServerSideEncryptionRule/SSEAlgorithm",
            )? == "KMS"
            && field(
                &i,
                "BucketInfo/Bucket/ServerSideEncryptionRule/KMSMasterKeyID",
            )? == e.kms_key_id
            && i.get("BucketInfo/Bucket/ServerSideEncryptionRule/KMSDataEncryption")
                .is_none_or(|s| s.is_empty() || s == "AES256"),
        RetentionCode::IdentityMismatch,
    )?;
    let worm_id = field(&w, "WormConfiguration/WormId")?;
    ensure(opaque(worm_id, 128), RetentionCode::MalformedResponse)?;
    let creation_date = utc_date(field(&i, "BucketInfo/Bucket/CreationDate")?)?;
    let worm_creation_date = utc_date(field(&w, "WormConfiguration/CreationDate")?)?;
    ensure(
        creation_date <= worm_creation_date
            && worm_creation_date <= Utc::now() + ChronoDuration::seconds(CLOCK_SKEW),
        RetentionCode::ClockSkew,
    )?;
    Ok(RetentionBucketObservation {
        creation_date,
        owner_id: e.account_id.clone(),
        name: e.bucket.clone(),
        location: format!("oss-{}", e.region),
        kms_key_id: e.kms_key_id.clone(),
        worm_id: worm_id.into(),
        worm_creation_date,
        retention_days: days,
        versioning: "Disabled".into(),
    })
}
fn validate_anchor(
    e: &BucketRetentionExpectation,
    bucket: &RetentionBucketObservation,
    h: &HeaderMap,
    now: DateTime<Utc>,
) -> Result<RetentionAnchorObservation, RetentionError> {
    let modified = http_date(header(h, "last-modified")?)?;
    let protected_until = modified + ChronoDuration::days(i64::from(bucket.retention_days));
    let size: u64 = header(h, "content-length")?
        .parse()
        .map_err(|_| fail(RetentionCode::MalformedResponse))?;
    ensure(
        header(h, "etag")? == e.anchor_etag
            && size == e.anchor_size_bytes
            && header(h, "x-oss-object-type")? == "Normal"
            && header(h, "x-oss-server-side-encryption")? == "KMS"
            && header(h, "x-oss-server-side-encryption-key-id")? == e.kms_key_id
            && h.get("x-oss-versionid").is_none()
            && h.get("x-oss-version-id").is_none()
            && modified >= bucket.worm_creation_date
            && modified <= now + ChronoDuration::seconds(CLOCK_SKEW)
            && protected_until
                >= e.certified_until + ChronoDuration::seconds(MAX_RUN_SECONDS + 2 * CLOCK_SKEW),
        RetentionCode::AnchorUnprotected,
    )?;
    Ok(RetentionAnchorObservation {
        key: e.anchor_key.clone(),
        etag: e.anchor_etag.clone(),
        size_bytes: size,
        last_modified: modified,
        protected_until,
    })
}
#[cfg(test)]
#[path = "bucket_retention_tests.rs"]
mod tests;

/// Real TLS mock transport for cross-module integration tests, never a proof constructor.
#[cfg(test)]
pub(crate) async fn test_live_verifier(
    expected: BucketRetentionExpectation,
) -> (
    tempfile::TempDir,
    BucketRetentionVerifier,
    axum_server::Handle<std::net::SocketAddr>,
) {
    let (directory, verifier, _, server) = tests::fixture_for(expected).await;
    (directory, verifier, server)
}
