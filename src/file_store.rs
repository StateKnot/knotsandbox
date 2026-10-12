//! Temporary single-file staging, with separate writer, reader and cleanup
//! capabilities. Object names come only from persisted transfer identities.
use crate::output_store::{OssOutputConfig, OssOutputStore, OutputStoreError, bound_http_response};
use axum::http::{Request, Response};
use chrono::{DateTime, Utc};
use opendal::{Buffer, HttpBody, HttpTransport, HttpTransporter};
use opendal_http_transport_reqwest::ReqwestTransport;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::Duration};
use uuid::Uuid;

pub const FILE_PART_BYTES: usize = 1024 * 1024;
pub const MAX_FILE_PARTS: u32 = 100;

/// Shared nonsecret settings. Each service opens only its own credential file;
/// no component falls back to another component's STS identity.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileStorageSettings {
    pub endpoint: String,
    pub bucket: String,
    pub kms_key_id: String,
    pub api_upload_sts_file: PathBuf,
    pub gateway_sts_file: PathBuf,
    pub read_sts_file: PathBuf,
    pub cleanup_sts_file: PathBuf,
    pub max_file_bytes: u64,
}
impl FileStorageSettings {
    pub fn validate(&self) -> Result<(), OutputStoreError> {
        let paths = [
            &self.api_upload_sts_file,
            &self.gateway_sts_file,
            &self.read_sts_file,
            &self.cleanup_sts_file,
        ];
        if self.max_file_bytes == 0
            || self.max_file_bytes > FILE_PART_BYTES as u64 * MAX_FILE_PARTS as u64
            || paths.iter().any(|path| !path.is_absolute())
            || paths
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != paths.len()
        {
            return Err(OutputStoreError::Configuration);
        }
        // Reuse the native bucket/region and encryption configuration checks.
        crate::output_store::validate_config(
            &self.config(self.api_upload_sts_file.clone()).into(),
        )?;
        Ok(())
    }
    fn config(&self, sts_credentials_file: PathBuf) -> OssFileConfig {
        OssFileConfig {
            endpoint: self.endpoint.clone(),
            bucket: self.bucket.clone(),
            kms_key_id: self.kms_key_id.clone(),
            sts_credentials_file,
        }
    }
    pub fn api_upload(&self) -> OssFileConfig {
        self.config(self.api_upload_sts_file.clone())
    }
    pub fn gateway(&self) -> OssFileConfig {
        self.config(self.gateway_sts_file.clone())
    }
    pub fn reader(&self) -> OssFileConfig {
        self.config(self.read_sts_file.clone())
    }
    pub fn cleanup(&self) -> OssFileConfig {
        self.config(self.cleanup_sts_file.clone())
    }
}

#[derive(Clone)]
pub struct OssFileConfig {
    pub endpoint: String,
    pub bucket: String,
    pub kms_key_id: String,
    /// Separate STS identity scoped only to temporary file objects.
    pub sts_credentials_file: PathBuf,
}
impl From<OssFileConfig> for OssOutputConfig {
    fn from(value: OssFileConfig) -> Self {
        Self {
            endpoint: value.endpoint,
            bucket: value.bucket,
            kms_key_id: value.kms_key_id,
            sts_credentials_file: value.sts_credentials_file,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilePartIdentity {
    pub tenant_id: Uuid,
    pub transfer_id: Uuid,
    pub content_id: Uuid,
    pub index: u32,
}
impl FilePartIdentity {
    pub fn object_key(self) -> Result<String, OutputStoreError> {
        if self.tenant_id.is_nil()
            || self.transfer_id.is_nil()
            || self.content_id.is_nil()
            || self.index >= MAX_FILE_PARTS
        {
            return Err(OutputStoreError::InvalidObject);
        }
        Ok(format!(
            "tenants/{}/file-transfers/{}/content/{}/parts/{}",
            self.tenant_id, self.transfer_id, self.content_id, self.index
        ))
    }
}

/// Internal receipt; the HTTP resource must not expose the storage key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilePartReceipt {
    pub identity: FilePartIdentity,
    pub object_key: String,
    pub byte_length: u64,
    pub sha256: String,
}
impl FilePartReceipt {
    pub fn validate(&self) -> Result<(), OutputStoreError> {
        if self.object_key != self.identity.object_key()?
            || self.byte_length == 0
            || self.byte_length > FILE_PART_BYTES as u64
            || self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(OutputStoreError::InvalidObject);
        }
        Ok(())
    }
}

pub struct FilePartCleanupReceipt {
    pub part: FilePartReceipt,
    /// Observation only. The ledger must independently establish that every
    /// cloud write attempt has ended before releasing this part's byte budget.
    pub confirmed_absent_at: DateTime<Utc>,
}

#[derive(Clone, Copy)]
enum Capability {
    Write,
    Read,
    Cleanup,
}
struct FileBucketTransport {
    inner: ReqwestTransport,
    host: String,
    capability: Capability,
}

fn canonical_part_path(path: &str) -> bool {
    let parts: Vec<_> = path.strip_prefix('/').unwrap_or(path).split('/').collect();
    if parts.len() != 8
        || parts[0] != "tenants"
        || parts[2] != "file-transfers"
        || parts[4] != "content"
        || parts[6] != "parts"
    {
        return false;
    }
    let uuid = |value: &str| {
        Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
    };
    uuid(parts[1])
        && uuid(parts[3])
        && uuid(parts[5])
        && parts[7]
            .parse::<u32>()
            .is_ok_and(|index| index < MAX_FILE_PARTS && index.to_string() == parts[7])
}

impl HttpTransport for FileBucketTransport {
    async fn fetch(&self, req: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
        let allowed = match self.capability {
            Capability::Write => matches!(req.method().as_str(), "PUT" | "GET" | "HEAD"),
            Capability::Read => matches!(req.method().as_str(), "GET" | "HEAD"),
            Capability::Cleanup => matches!(req.method().as_str(), "DELETE" | "HEAD"),
        };
        if !allowed
            || req.uri().scheme_str() != Some("https")
            || req.uri().host() != Some(self.host.as_str())
            || req.uri().port_u16().is_some_and(|v| v != 443)
            || req.uri().query().is_some()
            || req.extensions().get::<opendal::HttpRedirect>().is_some()
            || !canonical_part_path(req.uri().path())
            || req.body().len() > FILE_PART_BYTES
        {
            return Err(opendal::Error::new(
                opendal::ErrorKind::PermissionDenied,
                "file transport target rejected",
            ));
        }
        let limit = if req.method() == "GET" {
            FILE_PART_BYTES
        } else {
            64 * 1024
        };
        bound_http_response(self.inner.fetch(req).await?, limit)
    }
}

fn client(
    config: OssFileConfig,
    capability: Capability,
) -> Result<OssOutputStore, OutputStoreError> {
    let endpoint =
        url::Url::parse(&config.endpoint).map_err(|_| OutputStoreError::Configuration)?;
    let host = format!(
        "{}.{}",
        config.bucket,
        endpoint.host_str().ok_or(OutputStoreError::Configuration)?
    );
    let _ = rustls::crypto::ring::default_provider().install_default();
    let http = reqwest_oss::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest_oss::redirect::Policy::none())
        .retry(reqwest_oss::retry::never())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| OutputStoreError::Configuration)?;
    OssOutputStore::from_transport(
        config.into(),
        HttpTransporter::new(FileBucketTransport {
            inner: ReqwestTransport::new(http),
            host,
            capability,
        }),
    )
}

#[derive(Clone)]
pub struct OssFileWriter {
    store: OssOutputStore,
}
#[derive(Clone)]
pub struct OssFileReader {
    store: OssOutputStore,
}
#[derive(Clone)]
pub struct OssFileCleaner {
    store: OssOutputStore,
}

impl OssFileWriter {
    pub fn new(config: OssFileConfig) -> Result<Self, OutputStoreError> {
        Ok(Self {
            store: client(config, Capability::Write)?,
        })
    }
    /// Trusted transport injection for protocol tests; the CLI uses `new`.
    pub fn from_transport(
        config: OssFileConfig,
        transport: HttpTransporter,
    ) -> Result<Self, OutputStoreError> {
        Ok(Self {
            store: OssOutputStore::from_transport(config.into(), transport)?,
        })
    }
    pub async fn check_credentials(&self) -> Result<(), OutputStoreError> {
        self.store.check_credentials().await
    }
    pub async fn put_part(
        &self,
        identity: FilePartIdentity,
        bytes: Vec<u8>,
    ) -> Result<FilePartReceipt, OutputStoreError> {
        let part = FilePartReceipt {
            identity,
            object_key: identity.object_key()?,
            byte_length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&bytes)),
        };
        part.validate()?;
        // A changed body at the same part index conflicts; hashes are receipts,
        // never alternative keys allowing an overwrite to escape accounting.
        self.store
            .put_immutable(&part.object_key, bytes, "application/octet-stream")
            .await?;
        Ok(part)
    }
    pub async fn read_part(&self, part: &FilePartReceipt) -> Result<Vec<u8>, OutputStoreError> {
        part.validate()?;
        self.store
            .read_verified_object(&part.object_key, &part.sha256, part.byte_length)
            .await
    }
}
impl OssFileReader {
    pub fn new(config: OssFileConfig) -> Result<Self, OutputStoreError> {
        Ok(Self {
            store: client(config, Capability::Read)?,
        })
    }
    pub fn from_transport(
        config: OssFileConfig,
        transport: HttpTransporter,
    ) -> Result<Self, OutputStoreError> {
        Ok(Self {
            store: OssOutputStore::from_transport(config.into(), transport)?,
        })
    }
    pub async fn check_credentials(&self) -> Result<(), OutputStoreError> {
        self.store.check_credentials().await
    }
    pub async fn read_part(&self, part: &FilePartReceipt) -> Result<Vec<u8>, OutputStoreError> {
        part.validate()?;
        self.store
            .read_verified_object(&part.object_key, &part.sha256, part.byte_length)
            .await
    }
}
impl OssFileCleaner {
    pub fn new(config: OssFileConfig) -> Result<Self, OutputStoreError> {
        Ok(Self {
            store: client(config, Capability::Cleanup)?,
        })
    }
    pub fn from_transport(
        config: OssFileConfig,
        transport: HttpTransporter,
    ) -> Result<Self, OutputStoreError> {
        Ok(Self {
            store: OssOutputStore::from_transport(config.into(), transport)?,
        })
    }
    pub async fn check_credentials(&self) -> Result<(), OutputStoreError> {
        self.store.check_credentials().await
    }
    pub async fn delete_part(
        &self,
        part: &FilePartReceipt,
    ) -> Result<FilePartCleanupReceipt, OutputStoreError> {
        part.validate()?;
        let confirmed_absent_at = self
            .store
            .delete_and_confirm_absent(&part.object_key)
            .await?;
        Ok(FilePartCleanupReceipt {
            part: part.clone(),
            confirmed_absent_at,
        })
    }
}

#[cfg(test)]
#[path = "file_store_tests.rs"]
mod tests;
