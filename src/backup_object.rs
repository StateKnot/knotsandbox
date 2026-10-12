//! Read-only verification of a sealed backup vault. This proof is deliberately
//! narrower than AVAILABLE: certified WORM/RAM policy and trusted SEAL shutdown
//! are separate controller prerequisites. Pack hashes are attested by SEAL;
//! only config/snapshot bytes are independently hashed here. Restore must still
//! authenticate every pack and verify the reconstructed raw-device checksum.
use std::{collections::VecDeque, path::PathBuf, sync::Arc, time::Duration};

use axum::http::{Request, Response};
use chrono::{DateTime, Utc};
use futures_util::{StreamExt, TryStreamExt};
use opendal::{Buffer, Entry, HttpBody, HttpTransport, HttpTransporter, Operator};
use opendal_http_transport_reqwest::ReqwestTransport;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{io::AsyncReadExt, sync::Semaphore};
use uuid::Uuid;

const METADATA_LIMIT: usize = 1024 * 1024;
const MAX_INVENTORY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_OBJECTS: u64 = 2_000_000;
const MAX_REPOSITORY_BYTES: u64 = 32 * 1024_u64.pow(4);
const MAX_OBJECT_BYTES: u64 = 128 * 1024 * 1024;
const ED25519_SPKI: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

#[derive(Clone)]
pub struct BackupVaultConfig {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub account_id: String,
    /// Dedicated backup-reader STS file, not execution-output or restore identity.
    pub sts_credentials_file: PathBuf,
    /// Approved Ed25519 public key, 44-byte DER SubjectPublicKeyInfo.
    pub signing_public_key_spki: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum BackupObjectError {
    #[error("invalid backup vault configuration")]
    Configuration,
    #[error("backup reader credentials unavailable or expired")]
    Credentials,
    #[error("backup vault read unavailable")]
    Unavailable,
    #[error("backup vault verification deadline exceeded")]
    Deadline,
    #[error("backup manifest signature rejected")]
    Signature,
    #[error("backup manifest identity or format rejected")]
    Manifest,
    #[error("backup repository inventory or checksum rejected")]
    Integrity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupIdentity {
    pub protocol: u32,
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub backup_id: Uuid,
    pub source_instance_id: Uuid,
    pub source_generation: i64,
    pub source_pvc_uid: Uuid,
    pub snapshot_content_uid: Uuid,
    pub clone_pvc_uid: Uuid,
    pub seal_attempt_id: Uuid,
    pub cluster_epoch: Uuid,
    pub size_bytes: u64,
    pub data_timestamp: String,
    pub consistency: String,
    pub retention_until: String,
    pub key_ref: String,
    pub region: String,
    pub account_id: String,
    pub bucket: String,
    pub vault_bucket: String,
    pub kms_key_id: String,
    pub vault_kms_key_id: String,
    pub template_digest: String,
}
#[derive(Clone, Debug)]
pub struct BackupVaultExpectation {
    /// Must come from persisted backup intent, not a caller-supplied object URL.
    pub identity: BackupIdentity,
    pub snapshot_id: String,
    pub disk_sha256: String,
    pub manifest_sha256: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupDisk {
    pub size_bytes: u64,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupInventoryShard {
    pub key: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub object_count: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupInventory {
    pub format: String,
    pub object_count: u64,
    pub total_bytes: u64,
    pub shards: Vec<BackupInventoryShard>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupVaultManifest {
    pub protocol: u32,
    pub format: String,
    pub backup: BackupIdentity,
    pub snapshot_id: String,
    pub disk: BackupDisk,
    pub repository_prefix: String,
    pub sealed_at: String,
    pub retain_objects_until: String,
    pub repository_read_data_verified: bool,
    pub raw_restore_sha256_verified: bool,
    pub cloud_restore_tested_at: Option<String>,
    pub inventory: BackupInventory,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryShard {
    protocol: u32,
    tenant_id: Uuid,
    backup_id: Uuid,
    seal_attempt_id: Uuid,
    cluster_epoch: Uuid,
    objects: Vec<InventoryObject>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryObject {
    key: String,
    size_bytes: u64,
    sha256: String,
}

/// Only the verifier can construct this type. It is not a VM/WORM/cloud-restore
/// certificate, and has no Deserialize implementation or unchecked constructor.
pub struct VerifiedBackupVault {
    manifest: BackupVaultManifest,
    manifest_sha256: String,
    signing_key_sha256: String,
    vault_endpoint: String,
    verified_at: DateTime<Utc>,
}
impl VerifiedBackupVault {
    pub fn identity(&self) -> &BackupIdentity {
        &self.manifest.backup
    }
    pub fn manifest(&self) -> &BackupVaultManifest {
        &self.manifest
    }
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }
    pub fn signing_key_sha256(&self) -> &str {
        &self.signing_key_sha256
    }
    pub fn vault_endpoint(&self) -> &str {
        &self.vault_endpoint
    }
    pub fn snapshot_id(&self) -> &str {
        &self.manifest.snapshot_id
    }
    pub fn disk_sha256(&self) -> &str {
        &self.manifest.disk.sha256
    }
    pub fn verified_at(&self) -> DateTime<Utc> {
        self.verified_at
    }
}

#[derive(Clone)]
pub struct BackupVaultVerifier {
    config: BackupVaultConfig,
    inner: ReqwestTransport,
    /// Bound aggregate verification work across clones of this component.
    permits: Arc<Semaphore>,
    #[cfg(test)]
    test_transport: Option<HttpTransporter>,
}
impl BackupVaultVerifier {
    pub fn new(config: BackupVaultConfig) -> Result<Self, BackupObjectError> {
        validate_config(&config)?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest_oss::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest_oss::redirect::Policy::none())
            .retry(reqwest_oss::retry::never())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| BackupObjectError::Configuration)?;
        Ok(Self {
            config,
            inner: ReqwestTransport::new(client),
            permits: Arc::new(Semaphore::new(2)),
            #[cfg(test)]
            test_transport: None,
        })
    }
    #[cfg(test)]
    pub(crate) fn with_test_transport(mut self, transport: HttpTransporter) -> Self {
        self.test_transport = Some(transport);
        self
    }
    pub async fn verify(
        &self,
        expected: &BackupVaultExpectation,
    ) -> Result<VerifiedBackupVault, BackupObjectError> {
        validate_expectation(expected, &self.config)?;
        tokio::time::timeout(Duration::from_secs(3600), async {
            let _permit = self
                .permits
                .acquire()
                .await
                .map_err(|_| BackupObjectError::Unavailable)?;
            self.verify_inner(expected).await
        })
        .await
        .map_err(|_| BackupObjectError::Deadline)?
    }
    async fn verify_inner(
        &self,
        expected: &BackupVaultExpectation,
    ) -> Result<VerifiedBackupVault, BackupObjectError> {
        let root = format!(
            "tenants/{}/backups/{}",
            expected.identity.tenant_id, expected.identity.backup_id
        );
        let repository = format!("{root}/repository/");
        let raw = self
            .read(&root, "manifest.json", METADATA_LIMIT as u64, None)
            .await?;
        let signature = self.read(&root, "manifest.sig", 64, Some(64)).await?;
        let digest = hex::encode(Sha256::digest(&raw));
        if expected
            .manifest_sha256
            .as_ref()
            .is_some_and(|v| v != &digest)
        {
            return Err(BackupObjectError::Integrity);
        }
        verify_signature(&self.config.signing_public_key_spki, &raw, &signature)?;
        let manifest: BackupVaultManifest = canonical_decode(&raw)?;
        validate_manifest(&manifest, expected)?;
        let mut count = 0u64;
        let mut total = 0u64;
        let mut prior = String::new();
        let mut groups = [false; 5];
        let mut listed = VecDeque::new();
        let mut listing_after = String::new();
        for descriptor in &manifest.inventory.shards {
            let bytes = self
                .read(
                    &root,
                    &descriptor.key,
                    METADATA_LIMIT as u64,
                    Some(descriptor.size_bytes),
                )
                .await?;
            if hex::encode(Sha256::digest(&bytes)) != descriptor.sha256 {
                return Err(BackupObjectError::Integrity);
            }
            let shard: InventoryShard = canonical_decode(&bytes)?;
            if shard.protocol != 1
                || shard.tenant_id != expected.identity.tenant_id
                || shard.backup_id != expected.identity.backup_id
                || shard.seal_attempt_id != expected.identity.seal_attempt_id
                || shard.cluster_epoch != expected.identity.cluster_epoch
                || shard.objects.len() as u64 != descriptor.object_count
            {
                return Err(BackupObjectError::Integrity);
            }
            for object in shard.objects {
                let group = object_group(&object, &manifest.snapshot_id)?;
                if object.key <= prior {
                    return Err(BackupObjectError::Integrity);
                }
                prior.clone_from(&object.key);
                groups[group] = true;
                count += 1;
                total = total
                    .checked_add(object.size_bytes)
                    .ok_or(BackupObjectError::Integrity)?;
                if count > MAX_OBJECTS || total > MAX_REPOSITORY_BYTES {
                    return Err(BackupObjectError::Integrity);
                }
                if listed.is_empty() {
                    listed = self.list_page(&root, &repository, &listing_after).await?;
                }
                let entry = listed.pop_front().ok_or(BackupObjectError::Integrity)?;
                let key = format!("{repository}{}", object.key);
                if entry.path() != key
                    || !entry.metadata().mode().is_file()
                    || entry.metadata().content_length() != object.size_bytes
                    || entry.path() <= listing_after.as_str()
                {
                    return Err(BackupObjectError::Integrity);
                }
                listing_after = entry.path().to_owned();
                if group == 0 || group == 4 {
                    let body = self
                        .read(
                            &root,
                            &format!("repository/{}", object.key),
                            METADATA_LIMIT as u64,
                            Some(object.size_bytes),
                        )
                        .await?;
                    if hex::encode(Sha256::digest(&body)) != object.sha256 {
                        return Err(BackupObjectError::Integrity);
                    }
                }
            }
        }
        if !listed.is_empty()
            || !self
                .list_page(&root, &repository, &listing_after)
                .await?
                .is_empty()
            || groups != [true; 5]
            || count != manifest.inventory.object_count
            || total != manifest.inventory.total_bytes
        {
            return Err(BackupObjectError::Integrity);
        }
        // Re-read the commit pointer to detect an unprotected concurrent change.
        // This does not replace independently certified object retention policy.
        if self
            .read(
                &root,
                "manifest.json",
                METADATA_LIMIT as u64,
                Some(raw.len() as u64),
            )
            .await?
            != raw
        {
            return Err(BackupObjectError::Integrity);
        }
        Ok(VerifiedBackupVault {
            manifest,
            manifest_sha256: digest,
            signing_key_sha256: hex::encode(Sha256::digest(&self.config.signing_public_key_spki)),
            vault_endpoint: self.config.endpoint.clone(),
            verified_at: Utc::now(),
        })
    }
    async fn read(
        &self,
        root: &str,
        relative: &str,
        max: u64,
        size: Option<u64>,
    ) -> Result<Vec<u8>, BackupObjectError> {
        let operator = self.operator(root).await?;
        let key = format!("{root}/{relative}");
        tokio::time::timeout(Duration::from_secs(30), async {
            let info = operator
                .stat(&key)
                .await
                .map_err(|_| BackupObjectError::Unavailable)?;
            let length = info.content_length();
            if !info.mode().is_file()
                || length == 0
                || length > max
                || size.is_some_and(|s| s != length)
            {
                return Err(BackupObjectError::Integrity);
            }
            let mut reader = operator
                .reader(&key)
                .await
                .map_err(|_| BackupObjectError::Unavailable)?
                .into_stream(0..length)
                .await
                .map_err(|_| BackupObjectError::Unavailable)?;
            let mut bytes = Vec::with_capacity(length as usize);
            while let Some(buffer) = reader
                .try_next()
                .await
                .map_err(|_| BackupObjectError::Unavailable)?
            {
                if buffer.len() > length as usize - bytes.len() {
                    return Err(BackupObjectError::Integrity);
                }
                for chunk in buffer {
                    bytes.extend_from_slice(&chunk);
                }
            }
            if bytes.len() as u64 != length {
                return Err(BackupObjectError::Integrity);
            }
            Ok(bytes)
        })
        .await
        .map_err(|_| BackupObjectError::Deadline)?
    }
    async fn list_page(
        &self,
        root: &str,
        prefix: &str,
        after: &str,
    ) -> Result<VecDeque<Entry>, BackupObjectError> {
        let operator = self.operator(root).await?;
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut entries = operator
                .lister_with(prefix)
                .recursive(true)
                .limit(1000)
                .start_after(after)
                .await
                .map_err(|_| BackupObjectError::Unavailable)?;
            let mut page = VecDeque::new();
            while page.len() < 1000 {
                match entries
                    .try_next()
                    .await
                    .map_err(|_| BackupObjectError::Unavailable)?
                {
                    Some(entry) => page.push_back(entry),
                    None => break,
                }
            }
            Ok(page)
        })
        .await
        .map_err(|_| BackupObjectError::Deadline)?
    }
    pub async fn check_credentials(&self) -> Result<(), BackupObjectError> {
        self.credentials().await.map(|_| ())
    }
    async fn credentials(&self) -> Result<StsCredentials, BackupObjectError> {
        let mut options = tokio::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits());
        let mut file = options
            .open(&self.config.sts_credentials_file)
            .await
            .map_err(|_| BackupObjectError::Credentials)?;
        let metadata = file
            .metadata()
            .await
            .map_err(|_| BackupObjectError::Credentials)?;
        if !metadata.is_file() || metadata.len() > 16384 {
            return Err(BackupObjectError::Credentials);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if !matches!(metadata.permissions().mode() & 0o7777, 0o400 | 0o600) {
                return Err(BackupObjectError::Credentials);
            }
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(16385)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| BackupObjectError::Credentials)?;
        if bytes.len() > 16384 {
            return Err(BackupObjectError::Credentials);
        }
        let credentials: StsCredentials =
            serde_json::from_slice(&bytes).map_err(|_| BackupObjectError::Credentials)?;
        let now = Utc::now();
        if !credentials.access_key_id.starts_with("STS.")
            || !graphic(&credentials.access_key_id, 256)
            || !graphic(&credentials.access_key_secret, 256)
            || !graphic(&credentials.security_token, 12288)
            || credentials.expires_at <= now + chrono::Duration::seconds(120)
            || credentials.expires_at > now + chrono::Duration::seconds(930)
        {
            return Err(BackupObjectError::Credentials);
        }
        Ok(credentials)
    }
    async fn operator(&self, root: &str) -> Result<Operator, BackupObjectError> {
        let credentials = self.credentials().await?;
        let builder = opendal::services::Oss::default()
            .bucket(&self.config.bucket)
            .endpoint(&self.config.endpoint)
            .addressing_style("virtual")
            .access_key_id(&credentials.access_key_id)
            .access_key_secret(&credentials.access_key_secret)
            .security_token(&credentials.security_token);
        let operator = Operator::new(builder).map_err(|_| BackupObjectError::Configuration)?;
        let transport = HttpTransporter::new(VaultTransport {
            inner: self.inner.clone(),
            host: validate_config(&self.config)?,
            root: root.into(),
        });
        #[cfg(test)]
        let transport = self.test_transport.clone().unwrap_or(transport);
        let context = operator
            .base_context()
            .with_http_transport(HttpTransporter::new(crate::oss_signing::V4Transport {
                inner: transport,
                bucket: self.config.bucket.clone(),
                region: self.config.region.clone(),
                credential: reqsign_aliyun_oss::Credential {
                    access_key_id: credentials.access_key_id,
                    access_key_secret: credentials.access_key_secret,
                    security_token: Some(credentials.security_token),
                    expires_in: None,
                },
                expires_at: credentials.expires_at,
            }));
        Ok(operator.with_context(context))
    }
}

// No Debug: short-lived bearer material is never logged or embedded in errors.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StsCredentials {
    access_key_id: String,
    access_key_secret: String,
    security_token: String,
    expires_at: DateTime<Utc>,
}
struct VaultTransport {
    inner: ReqwestTransport,
    host: String,
    root: String,
}
impl HttpTransport for VaultTransport {
    async fn fetch(&self, request: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
        if !valid_target(&request, &self.host, &self.root) {
            return Err(opendal::Error::new(
                opendal::ErrorKind::PermissionDenied,
                "backup vault target rejected",
            ));
        }
        let response = self.inner.fetch(request).await?;
        // HEAD content-length describes a potentially large object, not a body.
        let (parts, body) = response.into_parts();
        let body = body.map_inner(|stream| {
            Box::new(stream.scan((0usize, false), |state, item| {
                if state.1 {
                    return futures_util::future::ready(None);
                }
                let value = match item {
                    Ok(buffer) if buffer.len() <= 2 * METADATA_LIMIT - state.0 => {
                        state.0 += buffer.len();
                        Ok(buffer)
                    }
                    _ => {
                        state.1 = true;
                        Err(opendal::Error::new(
                            opendal::ErrorKind::Unexpected,
                            "backup HTTP body rejected",
                        ))
                    }
                };
                futures_util::future::ready(Some(value))
            }))
        });
        Ok(Response::from_parts(parts, body))
    }
}
fn valid_target(request: &Request<Buffer>, host: &str, root: &str) -> bool {
    if request.uri().scheme_str() != Some("https")
        || request.uri().host() != Some(host)
        || request.uri().port_u16().is_some_and(|p| p != 443)
        || request
            .extensions()
            .get::<opendal::HttpRedirect>()
            .is_some()
        || !matches!(request.method().as_str(), "GET" | "HEAD")
    {
        return false;
    }
    let path = request.uri().path();
    if path == "/" && request.method() == "GET" {
        let query: Vec<_> =
            url::form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
                .collect();
        let mut seen = std::collections::HashSet::new();
        return query.iter().all(|(k, _)| {
            seen.insert(k.as_ref())
                && matches!(
                    k.as_ref(),
                    "list-type"
                        | "prefix"
                        | "max-keys"
                        | "start-after"
                        | "delimiter"
                        | "continuation-token"
                )
        }) && query.iter().any(|(k, v)| k == "list-type" && v == "2")
            && query
                .iter()
                .any(|(k, v)| k == "prefix" && v == &format!("{root}/repository/"))
            && query.iter().all(|(k, v)| {
                k != "start-after" || v.is_empty() || v.starts_with(&format!("{root}/repository/"))
            });
    }
    request.uri().query().is_none()
        && path.starts_with(&format!("/{root}/"))
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
        && !path.split('/').any(|p| p == "." || p == "..")
}
fn graphic(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|b| b.is_ascii_graphic())
}
fn sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn bucket(value: &str) -> bool {
    (3..=63).contains(&value.len())
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn time(value: &str) -> Result<DateTime<Utc>, BackupObjectError> {
    DateTime::parse_from_rfc3339(value)
        .map(|v| v.with_timezone(&Utc))
        .map_err(|_| BackupObjectError::Manifest)
}
fn validate_config(c: &BackupVaultConfig) -> Result<String, BackupObjectError> {
    if !bucket(&c.bucket)
        || !c.sts_credentials_file.is_absolute()
        || c.account_id.len() != 16
        || !c.account_id.bytes().all(|v| v.is_ascii_digit())
        || !graphic(&c.region, 32)
        || !c
            .region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || ![
            format!("https://oss-{}.aliyuncs.com", c.region),
            format!("https://oss-{}-internal.aliyuncs.com", c.region),
        ]
        .contains(&c.endpoint)
        || c.signing_public_key_spki.len() != 44
        || !c.signing_public_key_spki.starts_with(ED25519_SPKI)
    {
        return Err(BackupObjectError::Configuration);
    }
    Ok(format!(
        "{}.{}",
        c.bucket,
        c.endpoint.trim_start_matches("https://")
    ))
}
fn validate_expectation(
    e: &BackupVaultExpectation,
    c: &BackupVaultConfig,
) -> Result<(), BackupObjectError> {
    let i = &e.identity;
    if i.protocol != 1
        || [
            i.tenant_id,
            i.project_id,
            i.backup_id,
            i.source_instance_id,
            i.source_pvc_uid,
            i.snapshot_content_uid,
            i.clone_pvc_uid,
            i.seal_attempt_id,
            i.cluster_epoch,
        ]
        .iter()
        .any(Uuid::is_nil)
        || i.source_generation <= 0
        || i.size_bytes == 0
        || i.size_bytes > 16 * 1024_u64.pow(4)
        || !i.size_bytes.is_multiple_of(512)
        || !matches!(
            i.consistency.as_str(),
            "CRASH_CONSISTENT" | "STOPPED_CONSISTENT"
        )
        || i.region != c.region
        || i.account_id != c.account_id
        || i.vault_bucket != c.bucket
        || i.bucket == i.vault_bucket
        || !bucket(&i.bucket)
        || i.kms_key_id == i.vault_kms_key_id
        || [&i.key_ref, &i.kms_key_id, &i.vault_kms_key_id]
            .iter()
            .any(|v| {
                !graphic(v, 256)
                    || !v
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"/_:-".contains(&b))
            })
        || !i.template_digest.strip_prefix("sha256:").is_some_and(sha)
        || !sha(&e.snapshot_id)
        || !sha(&e.disk_sha256)
        || e.manifest_sha256.as_ref().is_some_and(|v| !sha(v))
        || time(&i.data_timestamp)? > Utc::now()
        || time(&i.retention_until)? < time(&i.data_timestamp)? + chrono::Duration::days(30)
    {
        return Err(BackupObjectError::Manifest);
    }
    Ok(())
}
pub(crate) fn canonical_decode<T: for<'de> Deserialize<'de>>(
    raw: &[u8],
) -> Result<T, BackupObjectError> {
    let value: serde_json::Value =
        serde_json::from_slice(raw).map_err(|_| BackupObjectError::Manifest)?;
    // This version has an ASCII-only domain. Exact re-encoding also rejects
    // duplicate keys, alternate numbers, escapes, whitespace and trailing bytes.
    fn ascii(v: &serde_json::Value) -> bool {
        match v {
            serde_json::Value::String(s) => s.is_ascii(),
            serde_json::Value::Array(a) => a.iter().all(ascii),
            serde_json::Value::Object(m) => m.iter().all(|(k, v)| k.is_ascii() && ascii(v)),
            _ => true,
        }
    }
    if !ascii(&value) || serde_json::to_vec(&value).map_err(|_| BackupObjectError::Manifest)? != raw
    {
        return Err(BackupObjectError::Manifest);
    }
    serde_json::from_slice(raw).map_err(|_| BackupObjectError::Manifest)
}
fn verify_signature(spki: &[u8], raw: &[u8], signature: &[u8]) -> Result<(), BackupObjectError> {
    if spki.len() != 44 || !spki.starts_with(ED25519_SPKI) || signature.len() != 64 {
        return Err(BackupObjectError::Signature);
    }
    let provider = rustls::crypto::ring::default_provider();
    let algorithm = provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .find(|(s, _)| *s == rustls::SignatureScheme::ED25519)
        .and_then(|(_, a)| a.first())
        .ok_or(BackupObjectError::Configuration)?;
    algorithm
        .verify_signature(&spki[12..], raw, signature)
        .map_err(|_| BackupObjectError::Signature)
}
fn validate_manifest(
    m: &BackupVaultManifest,
    e: &BackupVaultExpectation,
) -> Result<(), BackupObjectError> {
    if m.protocol != 2
        || m.format != "restic-raw-disk-v2"
        || m.backup != e.identity
        || m.snapshot_id != e.snapshot_id
        || m.disk.size_bytes != e.identity.size_bytes
        || m.disk.sha256 != e.disk_sha256
        || !m.repository_read_data_verified
        || !m.raw_restore_sha256_verified
        || m.cloud_restore_tested_at.is_some()
        || m.repository_prefix
            != format!(
                "tenants/{}/backups/{}/repository",
                e.identity.tenant_id, e.identity.backup_id
            )
        || time(&m.sealed_at)? < time(&e.identity.data_timestamp)?
        || time(&m.sealed_at)? > Utc::now()
        || time(&m.retain_objects_until)? < time(&e.identity.retention_until)?
        || time(&m.retain_objects_until)? < time(&m.sealed_at)? + chrono::Duration::days(30)
    {
        return Err(BackupObjectError::Manifest);
    }
    let i = &m.inventory;
    if i.format != "restic-object-inventory-v1"
        || !(5..=MAX_OBJECTS).contains(&i.object_count)
        || i.total_bytes == 0
        || i.total_bytes > MAX_REPOSITORY_BYTES
        || i.shards.is_empty()
        || i.shards.len() > 1024
    {
        return Err(BackupObjectError::Integrity);
    }
    let mut count = 0u64;
    let mut bytes = 0u64;
    for (index, s) in i.shards.iter().enumerate() {
        if s.key != format!("inventory/{index:06}.json")
            || s.size_bytes == 0
            || s.size_bytes > METADATA_LIMIT as u64
            || !sha(&s.sha256)
            || s.object_count == 0
            || s.object_count > MAX_OBJECTS
        {
            return Err(BackupObjectError::Integrity);
        }
        count += s.object_count;
        bytes += s.size_bytes;
    }
    if count != i.object_count || bytes > MAX_INVENTORY_BYTES {
        return Err(BackupObjectError::Integrity);
    }
    Ok(())
}
fn object_group(o: &InventoryObject, snapshot: &str) -> Result<usize, BackupObjectError> {
    if o.size_bytes == 0 || o.size_bytes > MAX_OBJECT_BYTES || !sha(&o.sha256) {
        return Err(BackupObjectError::Integrity);
    }
    if o.key == "config" {
        return Ok(0);
    }
    let p: Vec<_> = o.key.split('/').collect();
    let group = match p.as_slice() {
        ["data", prefix, name] if prefix.len() == 2 && sha(name) && name.starts_with(prefix) => 1,
        ["index", name] if sha(name) => 2,
        ["keys", name] if sha(name) => 3,
        ["snapshots", name] if *name == snapshot => 4,
        _ => return Err(BackupObjectError::Integrity),
    };
    if p.last().copied() != Some(o.sha256.as_str()) {
        return Err(BackupObjectError::Integrity);
    }
    Ok(group)
}

#[cfg(test)]
#[path = "backup_object_tests.rs"]
mod tests;
