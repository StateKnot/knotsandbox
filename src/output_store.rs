//! Native OSS output storage. Receipts are returned only after conditional PUT
//! or a bounded read-back verifies identical bytes at the immutable object key.
use std::{path::PathBuf, sync::Arc, time::Duration};

use axum::http::{Request, Response};
use chrono::{DateTime, Utc};
use futures_util::{StreamExt, TryStreamExt};
use opendal::{Buffer, HttpBody, HttpTransport, HttpTransporter, Operator};
use opendal_http_transport_reqwest::ReqwestTransport;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::{io::AsyncReadExt, sync::Mutex};
use uuid::Uuid;

use crate::{gateway_ledger::StoredOutputSegment, model::ExecutionResultRef};

const REQUEST_BUDGET: Duration = Duration::from_secs(20);
const MIN_CREDENTIAL_SECONDS: i64 = 120;
const MAX_OBJECT_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct OssOutputConfig {
    /// Regional service endpoint, e.g. https://oss-cn-hangzhou-internal.aliyuncs.com.
    pub endpoint: String,
    pub bucket: String,
    pub kms_key_id: String,
    /// Atomically replaced regular file, readable only by the gateway UID.
    pub sts_credentials_file: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum OutputStoreError {
    #[error("invalid output storage configuration")]
    Configuration,
    #[error("output STS credentials are unavailable, invalid or near expiry")]
    Credentials,
    #[error("invalid output object")]
    InvalidObject,
    #[error("output storage operation failed")]
    Unavailable,
    #[error("existing output object differs from immutable receipt")]
    Conflict,
}

// Deliberately no Debug: this structure contains short-lived secrets.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StsCredentials {
    access_key_id: String,
    access_key_secret: String,
    security_token: String,
    expires_at: DateTime<Utc>,
}

struct CachedOperator {
    credential_hash: [u8; 32],
    operator: Operator,
}

#[derive(Clone)]
pub struct OssOutputStore {
    config: OssOutputConfig,
    transport: HttpTransporter,
    cached: Arc<Mutex<Option<CachedOperator>>>,
}

/// API-facing storage capability. This type exposes no PUT operation; deploy
/// it with a separate GET/HEAD-only STS identity, never gateway credentials.
#[derive(Clone)]
pub struct OssOutputReader {
    store: OssOutputStore,
}
impl OssOutputReader {
    pub fn new(config: OssOutputConfig) -> Result<Self, OutputStoreError> {
        Ok(Self {
            store: OssOutputStore::new(config)?,
        })
    }
    pub fn from_transport(
        config: OssOutputConfig,
        transport: HttpTransporter,
    ) -> Result<Self, OutputStoreError> {
        Ok(Self {
            store: OssOutputStore::from_transport(config, transport)?,
        })
    }
    pub async fn check_credentials(&self) -> Result<(), OutputStoreError> {
        self.store.check_credentials().await
    }
    pub(crate) async fn read_verified(
        &self,
        key: &str,
        sha256: &str,
        size: u64,
        max: u64,
    ) -> Result<Vec<u8>, OutputStoreError> {
        if size == 0
            || size > max
            || max > MAX_OBJECT_BYTES as u64
            || key.len() > 512
            || !key.starts_with("tenants/")
            || key
                .split('/')
                .any(|s| s.is_empty() || s == "." || s == "..")
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
            || sha256.len() != 64
            || !sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(OutputStoreError::InvalidObject);
        }
        let operator = self.store.operator().await?;
        tokio::time::timeout(REQUEST_BUDGET, async {
            let metadata = operator
                .stat(key)
                .await
                .map_err(|_| OutputStoreError::Unavailable)?;
            if metadata.content_length() != size {
                return Err(OutputStoreError::Conflict);
            }
            let bytes = read_exact_bounded(&operator, key, size).await?;
            if bytes.len() as u64 != size || hex::encode(Sha256::digest(&bytes)) != sha256 {
                return Err(OutputStoreError::Conflict);
            }
            Ok(bytes)
        })
        .await
        .map_err(|_| OutputStoreError::Unavailable)?
    }
}

pub struct SegmentPayload {
    pub tenant_id: Uuid,
    pub execution_id: Uuid,
    pub dispatch_attempt_id: Uuid,
    pub sequence: i64,
    pub first_frame_sequence: i64,
    pub last_frame_sequence: i64,
    pub raw_bytes: i64,
    pub ndjson: Vec<u8>,
}

/// Enforces the bucket origin before delegating HTTP/TLS to the official
/// OpenDAL reqwest transport. No credential-chain metadata or redirect target
/// can use this transport. OSS internal regional endpoints are supported.
struct BucketTransport {
    inner: ReqwestTransport,
    host: String,
}
impl HttpTransport for BucketTransport {
    async fn fetch(&self, req: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
        if req.uri().scheme_str() != Some("https")
            || req.uri().host() != Some(self.host.as_str())
            || req.uri().port_u16().is_some_and(|port| port != 443)
            || req.extensions().get::<opendal::HttpRedirect>().is_some()
            || !matches!(req.method().as_str(), "PUT" | "GET" | "HEAD")
        {
            return Err(opendal::Error::new(
                opendal::ErrorKind::PermissionDenied,
                "output transport target rejected",
            ));
        }
        let limit = if req.method() == "GET" || req.method() == "HEAD" {
            MAX_OBJECT_BYTES
        } else {
            64 * 1024
        };
        let response = self.inner.fetch(req).await?;
        bound_http_response(response, limit)
    }
}

impl OssOutputStore {
    /// Explicit dependency injection for trusted embedders and protocol tests.
    /// The service CLI always uses `new`, which enforces the bucket HTTPS origin.
    pub fn from_transport(
        config: OssOutputConfig,
        transport: HttpTransporter,
    ) -> Result<Self, OutputStoreError> {
        validate_config(&config)?;
        Ok(Self {
            config,
            transport,
            cached: Arc::new(Mutex::new(None)),
        })
    }

    pub fn new(config: OssOutputConfig) -> Result<Self, OutputStoreError> {
        let host = validate_config(&config)?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest_oss::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest_oss::redirect::Policy::none())
            .retry(reqwest_oss::retry::never())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| OutputStoreError::Configuration)?;
        Ok(Self {
            config,
            transport: HttpTransporter::new(BucketTransport {
                inner: ReqwestTransport::new(client),
                host,
            }),
            cached: Arc::new(Mutex::new(None)),
        })
    }

    /// Checks the currently mounted credential file without issuing a cloud call.
    pub async fn check_credentials(&self) -> Result<(), OutputStoreError> {
        self.operator().await.map(|_| ())
    }

    pub async fn put_segment(
        &self,
        payload: SegmentPayload,
    ) -> Result<StoredOutputSegment, OutputStoreError> {
        let sha256 = hex::encode(Sha256::digest(&payload.ndjson));
        let receipt = StoredOutputSegment {
            execution_id: payload.execution_id,
            dispatch_attempt_id: payload.dispatch_attempt_id,
            sequence: payload.sequence,
            first_frame_sequence: payload.first_frame_sequence,
            last_frame_sequence: payload.last_frame_sequence,
            raw_bytes: payload.raw_bytes,
            object_bytes: payload.ndjson.len() as i64,
            object_key: format!(
                "tenants/{}/executions/{}/attempts/{}/segments/{}-{sha256}.ndjson",
                payload.tenant_id,
                payload.execution_id,
                payload.dispatch_attempt_id,
                payload.sequence
            ),
            sha256,
        };
        if payload.tenant_id.is_nil()
            || payload.execution_id.is_nil()
            || payload.dispatch_attempt_id.is_nil()
            || !payload.ndjson.ends_with(b"\n")
            || receipt.validate(payload.tenant_id).is_err()
        {
            return Err(OutputStoreError::InvalidObject);
        }
        self.put_immutable(&receipt.object_key, payload.ndjson, "application/x-ndjson")
            .await?;
        Ok(receipt)
    }

    /// The caller constructs the manifest from committed segment receipts; a
    /// manifest PUT alone does not mark an execution complete in PostgreSQL.
    pub async fn put_manifest(
        &self,
        tenant: Uuid,
        execution: Uuid,
        attempt: Uuid,
        json: Vec<u8>,
    ) -> Result<ExecutionResultRef, OutputStoreError> {
        if tenant.is_nil()
            || execution.is_nil()
            || attempt.is_nil()
            || json.is_empty()
            || json.len() > MAX_OBJECT_BYTES
            || !valid_json(&json)
        {
            return Err(OutputStoreError::InvalidObject);
        }
        let sha256 = hex::encode(Sha256::digest(&json));
        let receipt = ExecutionResultRef {
            object_key: format!(
                "tenants/{tenant}/executions/{execution}/attempts/{attempt}/manifest-{sha256}.json"
            ),
            sha256,
            size_bytes: json.len() as u64,
        };
        self.put_immutable(&receipt.object_key, json, "application/json")
            .await?;
        Ok(receipt)
    }

    pub(crate) async fn put_immutable(
        &self,
        key: &str,
        bytes: Vec<u8>,
        content_type: &str,
    ) -> Result<(), OutputStoreError> {
        if bytes.is_empty() || bytes.len() > MAX_OBJECT_BYTES {
            return Err(OutputStoreError::InvalidObject);
        }
        let operator = self.operator().await?;
        let expected = Buffer::from(bytes);
        // No retry layer is installed: the total budget cannot cross validated
        // STS expiry. A caller may repeat the identical immutable receipt only.
        tokio::time::timeout(REQUEST_BUDGET, async {
            match operator
                .write_with(key, expected.clone())
                .if_not_exists(true)
                .content_type(content_type)
                .await
            {
                Ok(_) => Ok(()),
                Err(error) if error.kind() == opendal::ErrorKind::ConditionNotMatch => {
                    let meta = operator
                        .stat(key)
                        .await
                        .map_err(|_| OutputStoreError::Unavailable)?;
                    if meta.content_length() != expected.len() as u64 {
                        return Err(OutputStoreError::Conflict);
                    }
                    let existing =
                        read_exact_bounded(&operator, key, expected.len() as u64).await?;
                    if existing.as_slice() != expected.to_bytes().as_ref() {
                        return Err(OutputStoreError::Conflict);
                    }
                    Ok(())
                }
                Err(_) => Err(OutputStoreError::Unavailable),
            }
        })
        .await
        .map_err(|_| OutputStoreError::Unavailable)?
    }

    // Only crate-local typed capabilities may use these helpers. Public API
    // callers never supply an object key; each capability validates its exact
    // namespace and identity before calling here.
    pub(crate) async fn read_verified_object(
        &self,
        key: &str,
        sha256: &str,
        size: u64,
    ) -> Result<Vec<u8>, OutputStoreError> {
        if size == 0 || size > MAX_OBJECT_BYTES as u64 {
            return Err(OutputStoreError::InvalidObject);
        }
        let operator = self.operator().await?;
        tokio::time::timeout(REQUEST_BUDGET, async {
            let meta = operator
                .stat(key)
                .await
                .map_err(|_| OutputStoreError::Unavailable)?;
            if meta.content_length() != size {
                return Err(OutputStoreError::Conflict);
            }
            let bytes = read_exact_bounded(&operator, key, size).await?;
            if hex::encode(Sha256::digest(&bytes)) != sha256 {
                return Err(OutputStoreError::Conflict);
            }
            Ok(bytes)
        })
        .await
        .map_err(|_| OutputStoreError::Unavailable)?
    }

    pub(crate) async fn delete_and_confirm_absent(
        &self,
        key: &str,
    ) -> Result<DateTime<Utc>, OutputStoreError> {
        let operator = self.operator().await?;
        tokio::time::timeout(REQUEST_BUDGET, async {
            operator
                .delete(key)
                .await
                .map_err(|_| OutputStoreError::Unavailable)?;
            match operator.stat(key).await {
                Err(error) if error.kind() == opendal::ErrorKind::NotFound => Ok(Utc::now()),
                Ok(_) => Err(OutputStoreError::Conflict),
                Err(_) => Err(OutputStoreError::Unavailable),
            }
        })
        .await
        .map_err(|_| OutputStoreError::Unavailable)?
    }

    async fn operator(&self) -> Result<Operator, OutputStoreError> {
        let mut options = tokio::fs::OpenOptions::new();
        options.read(true);
        // A replaced credential FIFO must not block the runtime before the
        // regular-file check. Projected Secret symlinks still resolve normally.
        #[cfg(unix)]
        options.custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits());
        let mut file = options
            .open(&self.config.sts_credentials_file)
            .await
            .map_err(|_| OutputStoreError::Credentials)?;
        let metadata = file
            .metadata()
            .await
            .map_err(|_| OutputStoreError::Credentials)?;
        if !metadata.is_file() || metadata.len() > 16384 {
            return Err(OutputStoreError::Credentials);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if !matches!(metadata.permissions().mode() & 0o7777, 0o400 | 0o600) {
                return Err(OutputStoreError::Credentials);
            }
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(16385)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| OutputStoreError::Credentials)?;
        if bytes.len() > 16384 {
            return Err(OutputStoreError::Credentials);
        }
        let credentials = parse_credentials(&bytes, Utc::now())?;
        let credential_hash: [u8; 32] = Sha256::digest(&bytes).into();
        let mut cache = self.cached.lock().await;
        if let Some(cached) = cache.as_ref()
            && cached.credential_hash == credential_hash
        {
            return Ok(cached.operator.clone());
        }
        // reqsign-aliyun-oss 3.2.0's static provider always returns Some and has
        // no expiry/failure fallback. Expiry is checked above on EVERY use.
        // Never configure role_arn or OIDC here; a sidecar supplies STS atomically.
        let builder = opendal::services::Oss::default()
            .bucket(&self.config.bucket)
            .endpoint(&self.config.endpoint)
            .addressing_style("virtual")
            .access_key_id(&credentials.access_key_id)
            .access_key_secret(&credentials.access_key_secret)
            .security_token(&credentials.security_token)
            .server_side_encryption("KMS")
            .server_side_encryption_key_id(&self.config.kms_key_id);
        let operator = Operator::new(builder).map_err(|_| OutputStoreError::Configuration)?;
        let region = self
            .config
            .endpoint
            .strip_prefix("https://oss-")
            .and_then(|v| v.strip_suffix(".aliyuncs.com"))
            .ok_or(OutputStoreError::Configuration)?
            .trim_end_matches("-internal")
            .to_owned();
        let context = operator
            .base_context()
            .with_http_transport(HttpTransporter::new(crate::oss_signing::V4Transport {
                inner: self.transport.clone(),
                bucket: self.config.bucket.clone(),
                region,
                credential: reqsign_aliyun_oss::Credential {
                    access_key_id: credentials.access_key_id,
                    access_key_secret: credentials.access_key_secret,
                    security_token: Some(credentials.security_token),
                    expires_in: None,
                },
                expires_at: credentials.expires_at,
            }));
        let operator = operator.with_context(context);
        if !operator.info().capability().write_with_if_not_exists {
            return Err(OutputStoreError::Configuration);
        }
        *cache = Some(CachedOperator {
            credential_hash,
            operator: operator.clone(),
        });
        Ok(operator)
    }
}

fn valid_json(bytes: &[u8]) -> bool {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    serde::de::IgnoredAny::deserialize(&mut decoder).is_ok() && decoder.end().is_ok()
}

/// OpenDAL 0.59 `read_with` collects until EOF and HttpBody checks advertised
/// length only at EOF. Use streaming with an independent before-append bound;
/// never trust Range or Content-Length as an allocation limit.
async fn read_exact_bounded(
    operator: &Operator,
    key: &str,
    size: u64,
) -> Result<Vec<u8>, OutputStoreError> {
    let mut stream = operator
        .reader(key)
        .await
        .map_err(|_| OutputStoreError::Unavailable)?
        .into_stream(0..size)
        .await
        .map_err(|_| OutputStoreError::Unavailable)?;
    let mut bytes = Vec::with_capacity(size as usize);
    while let Some(buffer) = stream
        .try_next()
        .await
        .map_err(|_| OutputStoreError::Unavailable)?
    {
        if buffer.len() > size as usize - bytes.len() {
            return Err(OutputStoreError::Conflict);
        }
        for chunk in buffer {
            bytes.extend_from_slice(&chunk);
        }
    }
    if bytes.len() as u64 != size {
        return Err(OutputStoreError::Conflict);
    }
    Ok(bytes)
}
pub(crate) fn bound_http_response(
    response: Response<HttpBody>,
    limit: usize,
) -> opendal::Result<Response<HttpBody>> {
    if response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|len| len > limit as u64)
    {
        return Err(opendal::Error::new(
            opendal::ErrorKind::Unexpected,
            "output HTTP response size rejected",
        ));
    }
    let (parts, body) = response.into_parts();
    let body = body.map_inner(|stream| {
        Box::new(stream.scan((0usize, false), move |state, item| {
            if state.1 {
                return futures_util::future::ready(None);
            }
            let result = match item {
                Ok(buffer) if buffer.len() <= limit - state.0 => {
                    state.0 += buffer.len();
                    Ok(buffer)
                }
                Ok(_) => {
                    state.1 = true;
                    Err(opendal::Error::new(
                        opendal::ErrorKind::Unexpected,
                        "output HTTP body limit exceeded",
                    ))
                }
                Err(error) => {
                    state.1 = true;
                    Err(error)
                }
            };
            futures_util::future::ready(Some(result))
        }))
    });
    Ok(Response::from_parts(parts, body))
}

fn parse_credentials(bytes: &[u8], now: DateTime<Utc>) -> Result<StsCredentials, OutputStoreError> {
    let credentials: StsCredentials =
        serde_json::from_slice(bytes).map_err(|_| OutputStoreError::Credentials)?;
    let valid = |value: &str, max: usize| {
        !value.is_empty() && value.len() <= max && value.bytes().all(|b| b.is_ascii_graphic())
    };
    if !valid(&credentials.access_key_id, 256)
        || !valid(&credentials.access_key_secret, 256)
        || !valid(&credentials.security_token, 12288)
        || credentials.expires_at <= now + chrono::Duration::seconds(MIN_CREDENTIAL_SECONDS)
    {
        return Err(OutputStoreError::Credentials);
    }
    Ok(credentials)
}

pub(crate) fn validate_config(config: &OssOutputConfig) -> Result<String, OutputStoreError> {
    let endpoint =
        url::Url::parse(&config.endpoint).map_err(|_| OutputStoreError::Configuration)?;
    let host = endpoint.host_str().ok_or(OutputStoreError::Configuration)?;
    let region = host
        .strip_prefix("oss-")
        .and_then(|v| v.strip_suffix(".aliyuncs.com"));
    if endpoint.scheme() != "https"
        || endpoint.port().is_some()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.path() != "/"
        || !region.is_some_and(|r| {
            !r.is_empty()
                && r.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        || config.endpoint != format!("https://{host}")
        || !(3..=63).contains(&config.bucket.len())
        || !config
            .bucket
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || config.bucket.starts_with('-')
        || config.bucket.ends_with('-')
        || config.kms_key_id.is_empty()
        || config.kms_key_id.len() > 256
        || !config.kms_key_id.bytes().all(|b| b.is_ascii_graphic())
        || !config.sts_credentials_file.is_absolute()
    {
        return Err(OutputStoreError::Configuration);
    }
    Ok(format!("{}.{host}", config.bucket))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use axum::http::StatusCode;
    use std::collections::BTreeMap;

    #[derive(Clone, Default)]
    struct OssWireMock {
        objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
        requests: Arc<Mutex<Vec<(String, String)>>>,
    }
    fn response(status: StatusCode, body: Vec<u8>) -> Response<HttpBody> {
        let size = body.len() as u64;
        Response::builder()
            .status(status)
            .header("content-length", size)
            .header("last-modified", "Sat, 03 Oct 2026 00:00:00 GMT")
            .header("etag", "\"test-etag\"")
            .body(HttpBody::new(
                futures_util::stream::iter([Ok(Buffer::from(body))]),
                Some(size),
            ))
            .unwrap()
    }
    impl HttpTransport for OssWireMock {
        async fn fetch(&self, req: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
            assert_eq!(req.uri().scheme_str(), Some("https"));
            assert_eq!(
                req.uri().host(),
                Some("sandbox-output.oss-cn-hangzhou-internal.aliyuncs.com")
            );
            assert!(
                req.headers()
                    .get("authorization")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("OSS4-HMAC-SHA256 ")
            );
            assert_eq!(
                req.headers()
                    .get("x-oss-content-sha256")
                    .unwrap()
                    .to_str()
                    .unwrap(),
                hex::encode(Sha256::digest(req.body().to_vec()))
            );
            assert!(req.headers().contains_key("x-oss-security-token"));
            self.requests
                .lock()
                .await
                .push((req.method().to_string(), req.uri().path().to_owned()));
            let mut objects = self.objects.lock().await;
            let key = req.uri().path().to_owned();
            match req.method().as_str() {
                "PUT" => {
                    assert_eq!(req.headers().get("x-oss-forbid-overwrite").unwrap(), "true");
                    assert_eq!(
                        req.headers().get("x-oss-server-side-encryption").unwrap(),
                        "KMS"
                    );
                    assert_eq!(
                        req.headers()
                            .get("x-oss-server-side-encryption-key-id")
                            .unwrap(),
                        "test-kms-key"
                    );
                    if objects.contains_key(&key) {
                        return Ok(response(StatusCode::CONFLICT, b"<Error><Code>FileAlreadyExists</Code><Message>exists</Message></Error>".to_vec()));
                    }
                    objects.insert(key, req.body().to_vec());
                    Ok(response(StatusCode::OK, Vec::new()))
                }
                "HEAD" => {
                    let data = objects.get(&key).unwrap();
                    let mut reply = response(StatusCode::OK, Vec::new());
                    reply
                        .headers_mut()
                        .insert("content-length", data.len().into());
                    Ok(reply)
                }
                "GET" => {
                    let data = objects.get(&key).unwrap().clone();
                    let mut reply = response(StatusCode::PARTIAL_CONTENT, data.clone());
                    reply.headers_mut().insert(
                        "content-range",
                        format!("bytes 0-{}/{}", data.len() - 1, data.len())
                            .parse()
                            .unwrap(),
                    );
                    Ok(reply)
                }
                _ => panic!("unexpected OSS method"),
            }
        }
    }
    fn config(path: PathBuf) -> OssOutputConfig {
        OssOutputConfig {
            endpoint: "https://oss-cn-hangzhou-internal.aliyuncs.com".into(),
            bucket: "sandbox-output".into(),
            kms_key_id: "test-kms-key".into(),
            sts_credentials_file: path,
        }
    }
    fn credentials(expiry: DateTime<Utc>, token: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"access_key_id":"TEST_ONLY_AK", "access_key_secret":"TEST_ONLY_SECRET", "security_token":token, "expires_at":expiry})).unwrap()
    }
    async fn store() -> (tempfile::TempDir, OssOutputStore, OssWireMock) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sts.json");
        tokio::fs::write(
            &path,
            credentials(
                Utc::now() + chrono::Duration::minutes(10),
                "TEST_ONLY_TOKEN",
            ),
        )
        .await
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .await
                .unwrap();
        }
        let mock = OssWireMock::default();
        let mut store = OssOutputStore::new(config(path)).unwrap();
        store.transport = HttpTransporter::new(mock.clone());
        (dir, store, mock)
    }

    #[tokio::test]
    async fn native_oss_conditional_put_precedes_receipt_and_identical_retry_is_verified() {
        let (_dir, store, mock) = store().await;
        let tenant = Uuid::new_v4();
        let execution = Uuid::new_v4();
        let attempt = Uuid::new_v4();
        let payload = || SegmentPayload {
            tenant_id: tenant,
            execution_id: execution,
            dispatch_attempt_id: attempt,
            sequence: 0,
            first_frame_sequence: 1,
            last_frame_sequence: 1,
            raw_bytes: 1,
            ndjson: b"{\"data\":\"YQ==\"}\n".to_vec(),
        };
        let first = store.put_segment(payload()).await.unwrap();
        assert_eq!(
            mock.objects
                .lock()
                .await
                .get(&format!("/{}", first.object_key))
                .unwrap(),
            &payload().ndjson
        );
        let second = store.put_segment(payload()).await.unwrap();
        assert_eq!(first.sha256, second.sha256);
        let methods: Vec<_> = mock
            .requests
            .lock()
            .await
            .iter()
            .map(|(m, _)| m.clone())
            .collect();
        assert_eq!(methods, ["PUT", "PUT", "HEAD", "GET"]);
        // A corrupt pre-existing key cannot produce a successful receipt.
        mock.objects.lock().await.insert(
            format!("/{}", first.object_key),
            vec![b'x'; payload().ndjson.len()],
        );
        assert!(matches!(
            store.put_segment(payload()).await,
            Err(OutputStoreError::Conflict)
        ));
    }

    #[tokio::test]
    async fn expired_or_missing_rotated_credentials_never_reuse_cached_operator() {
        let (_dir, store, mock) = store().await;
        store.check_credentials().await.unwrap();
        let first_hash = store.cached.lock().await.as_ref().unwrap().credential_hash;
        tokio::fs::write(
            &store.config.sts_credentials_file,
            credentials(
                Utc::now() + chrono::Duration::minutes(10),
                "NEW_TEST_ONLY_TOKEN",
            ),
        )
        .await
        .unwrap();
        store.check_credentials().await.unwrap();
        assert_ne!(
            first_hash,
            store.cached.lock().await.as_ref().unwrap().credential_hash
        );
        tokio::fs::write(
            &store.config.sts_credentials_file,
            credentials(
                Utc::now() + chrono::Duration::seconds(90),
                "NEW_TEST_ONLY_TOKEN",
            ),
        )
        .await
        .unwrap();
        assert!(matches!(
            store.check_credentials().await,
            Err(OutputStoreError::Credentials)
        ));
        tokio::fs::remove_file(&store.config.sts_credentials_file)
            .await
            .unwrap();
        assert!(matches!(
            store.check_credentials().await,
            Err(OutputStoreError::Credentials)
        ));
        assert!(mock.requests.lock().await.is_empty());
    }

    #[test]
    fn endpoints_and_credential_shape_fail_closed() {
        let mut config = config(PathBuf::from("/run/credentials/sts.json"));
        assert!(validate_config(&config).is_ok());
        for bad in [
            "http://oss-cn-hangzhou.aliyuncs.com",
            "https://169.254.169.254",
            "https://oss-cn-hangzhou.aliyuncs.com.evil.test",
            "https://oss-cn-hangzhou.aliyuncs.com/?q=x",
            "https://u:p@oss-cn-hangzhou.aliyuncs.com",
            "https://oss-cn-hangzhou.aliyuncs.com/",
        ] {
            config.endpoint = bad.into();
            assert!(validate_config(&config).is_err());
        }
        assert!(parse_credentials(br#"{"access_key_id":"x"}"#, Utc::now()).is_err());
        let bytes = credentials(
            Utc::now() + chrono::Duration::seconds(119),
            "TEST_ONLY_TOKEN",
        );
        assert!(parse_credentials(&bytes, Utc::now()).is_err());
    }

    #[tokio::test]
    async fn unbounded_response_body_is_stopped_before_collection() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        #[derive(Clone)]
        struct LyingTransport(Arc<AtomicUsize>);
        impl HttpTransport for LyingTransport {
            async fn fetch(&self, req: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
                if req.method() == "HEAD" {
                    return Ok(Response::builder()
                        .status(200)
                        .header("content-length", "4")
                        .body(HttpBody::new(futures_util::stream::empty(), Some(0)))
                        .unwrap());
                }
                let reads = self.0.clone();
                // Ignores requested Range and lies in the response length.
                let body = futures_util::stream::repeat_with(move || {
                    reads.fetch_add(1, Ordering::SeqCst);
                    Ok(Buffer::from(vec![b'x'; 4]))
                });
                Ok(Response::builder()
                    .status(200)
                    .header("content-length", "4")
                    .body(HttpBody::new(body, None))
                    .unwrap())
            }
        }
        let (_dir, mut store, _) = store().await;
        let reads = Arc::new(AtomicUsize::new(0));
        store.transport = HttpTransporter::new(LyingTransport(reads.clone()));
        let reader = OssOutputReader { store };
        let hash = hex::encode(Sha256::digest(b"xxxx"));
        let result = reader
            .read_verified("tenants/fixture/object", &hash, 4, 524288)
            .await;
        assert!(matches!(result, Err(OutputStoreError::Conflict)));
        assert!(
            reads.load(Ordering::SeqCst) <= 2,
            "must not collect the unbounded body"
        );

        let chunks = futures_util::stream::iter([
            Ok(Buffer::from(vec![0; 4])),
            Ok(Buffer::from(vec![0; 4])),
        ]);
        let response = Response::builder()
            .status(500)
            .body(HttpBody::new(chunks, None))?;
        let mut limited = bound_http_response(response, 4)?.into_body();
        assert!(
            limited.to_buffer().await.is_err(),
            "even OSS error XML is independently bounded"
        );
        Ok(())
    }
}
