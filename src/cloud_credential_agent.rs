//! Storage credentials are minted only for the deployment's exact component
//! identity. This process has no database or Kubernetes client.
use super::{AlibabaCloudFencing, CloudIdentityConfig, validate_identity_config};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StoragePurpose {
    FileUpload,
    FileReader,
    FileGateway,
    FileCleaner,
    OutputReader,
    Gateway,
}

impl StoragePurpose {
    pub fn name(self) -> &'static str {
        match self {
            Self::FileUpload => "file-upload",
            Self::FileReader => "file-reader",
            Self::FileGateway => "file-gateway",
            Self::FileCleaner => "file-cleaner",
            Self::OutputReader => "output-reader",
            Self::Gateway => "gateway",
        }
    }

    pub fn subject(self) -> &'static str {
        match self {
            Self::FileUpload | Self::FileReader | Self::OutputReader => {
                "system:serviceaccount:sandbox-system:sandbox-api"
            }
            Self::FileGateway | Self::Gateway => {
                "system:serviceaccount:sandbox-system:sandbox-gateway"
            }
            Self::FileCleaner => "system:serviceaccount:sandbox-system:sandbox-worker",
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialAgentConfig {
    pub deployment: String,
    pub account_id: String,
    pub region: String,
    pub purpose: StoragePurpose,
    pub role_id: String,
    pub oidc_issuer: String,
    pub oidc_token_file: PathBuf,
    pub output_file: PathBuf,
}

fn canonical_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        && !path.as_os_str().is_empty()
        && !path.to_string_lossy().contains(['\0', '\n', '\r'])
        && path.to_str().is_some_and(|s| {
            s.split('/')
                .skip(1)
                .all(|c| !c.is_empty() && c != "." && c != "..")
        })
}

impl CredentialAgentConfig {
    fn identity(&self) -> CloudIdentityConfig {
        CloudIdentityConfig {
            session_policy: None,
            account_id: self.account_id.clone(),
            region: self.region.clone(),
            role_arn: format!(
                "acs:ram::{}:role/{}-{}",
                self.account_id,
                self.deployment,
                self.purpose.name()
            ),
            role_id: self.role_id.clone(),
            oidc_provider_arn: format!(
                "acs:ram::{}:oidc-provider/{}-kubernetes",
                self.account_id, self.deployment
            ),
            oidc_issuer: self.oidc_issuer.clone(),
            oidc_audience: "sts.aliyuncs.com".into(),
            oidc_subject: self.purpose.subject().into(),
            oidc_token_file: self.oidc_token_file.clone(),
            requests_per_second: 2,
            max_in_flight: 1,
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            (3..=32).contains(&self.deployment.len())
                && self
                    .deployment
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                && !self.deployment.starts_with('-')
                && !self.deployment.ends_with('-'),
            "invalid credential deployment"
        );
        anyhow::ensure!(
            self.account_id.len() == 16 && self.account_id.bytes().all(|c| c.is_ascii_digit()),
            "invalid credential account"
        );
        anyhow::ensure!(
            canonical_absolute(&self.oidc_token_file)
                && canonical_absolute(&self.output_file)
                && self
                    .output_file
                    .file_name()
                    .is_some_and(|n| n == "sts.json")
                && self
                    .output_file
                    .parent()
                    .is_some_and(|p| p.file_name().is_some_and(|n| n == "private"))
                && self.oidc_token_file != self.output_file,
            "invalid credential paths"
        );
        let issuer = url::Url::parse(&self.oidc_issuer)
            .map_err(|_| anyhow::anyhow!("invalid workload issuer"))?;
        anyhow::ensure!(
            issuer.port().is_none_or(|p| p == 443),
            "invalid workload issuer port"
        );
        validate_identity_config(&self.identity())
            .map_err(|_| anyhow::anyhow!("invalid storage workload identity"))
    }

    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        anyhow::ensure!(
            canonical_absolute(path),
            "absolute credential configuration required"
        );
        let bytes = bounded_file(path, 8192, false)?;
        let config: Self = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid credential configuration"))?;
        config.validate()?;
        Ok(config)
    }
}

fn bounded_file(path: &Path, limit: usize, private: bool) -> anyhow::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let flags = nix::fcntl::OFlag::O_NONBLOCK
            | if private {
                nix::fcntl::OFlag::O_NOFOLLOW
            } else {
                nix::fcntl::OFlag::empty()
            };
        options.custom_flags(flags.bits());
    }
    let file = options
        .open(path)
        .map_err(|_| anyhow::anyhow!("credential file unavailable"))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= limit as u64,
        "credential file type or size rejected"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if private {
            anyhow::ensure!(
                matches!(metadata.permissions().mode() & 0o7777, 0o400 | 0o600)
                    && metadata.uid() == nix::unistd::geteuid().as_raw(),
                "credential permissions rejected"
            );
        }
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= limit, "credential file size rejected");
    Ok(bytes)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCredentials {
    access_key_id: String,
    access_key_secret: String,
    security_token: String,
    expires_at: DateTime<Utc>,
}

fn valid_secret(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && value.bytes().all(|c| (33..=126).contains(&c))
}

pub fn check_credentials(config: &CredentialAgentConfig) -> anyhow::Result<()> {
    config.validate()?;
    let data: StoredCredentials =
        serde_json::from_slice(&bounded_file(&config.output_file, 16384, true)?)
            .map_err(|_| anyhow::anyhow!("credential record rejected"))?;
    anyhow::ensure!(
        data.access_key_id.starts_with("STS.")
            && valid_secret(&data.access_key_id, 256)
            && valid_secret(&data.access_key_secret, 256)
            && valid_secret(&data.security_token, 12288)
            && data.expires_at > Utc::now() + ChronoDuration::seconds(120)
            && data.expires_at <= Utc::now() + ChronoDuration::seconds(930),
        "credential record expired or rejected"
    );
    Ok(())
}

/// Owns the private directory lock for the entire publisher lifetime. A failed
/// competing publisher cannot remove the active publisher's credential file.
struct Publisher {
    output: PathBuf,
    directory: File,
    _lock: nix::fcntl::Flock<File>,
}

impl Publisher {
    #[cfg(unix)]
    fn new(output: &Path) -> anyhow::Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
        let parent = output
            .parent()
            .ok_or_else(|| anyhow::anyhow!("credential directory missing"))?;
        match std::fs::DirBuilder::new().mode(0o700).create(parent) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => anyhow::bail!("credential directory unavailable"),
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags((nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_NOFOLLOW).bits())
            .open(parent)
            .map_err(|_| anyhow::anyhow!("credential directory rejected"))?;
        let info = directory.metadata()?;
        anyhow::ensure!(
            info.is_dir()
                && info.permissions().mode() & 0o7777 == 0o700
                && info.uid() == nix::unistd::geteuid().as_raw(),
            "private credential directory rejected"
        );
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
            .open(parent.join("refresh.lock"))
            .map_err(|_| anyhow::anyhow!("credential publisher lock rejected"))?;
        let info = lock.metadata()?;
        anyhow::ensure!(
            info.is_file()
                && info.permissions().mode() & 0o7777 == 0o600
                && info.uid() == nix::unistd::geteuid().as_raw(),
            "credential publisher lock rejected"
        );
        let lock = nix::fcntl::Flock::lock(lock, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .map_err(|_| anyhow::anyhow!("credential publisher already active"))?;
        // Keep the flock guard itself; converting back to File would unlock it.
        Ok(Self {
            output: output.to_owned(),
            directory,
            _lock: lock,
        })
    }

    fn publish(&self, data: &[u8]) -> anyhow::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let temporary = self
            .output
            .with_file_name(format!(".sts-{}", uuid::Uuid::new_v4().simple()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
                .open(&temporary)?;
            file.write_all(data)?;
            file.sync_all()?;
            std::fs::rename(&temporary, &self.output)?;
            self.directory.sync_all()?;
            Ok::<_, std::io::Error>(())
        })();
        let _ = std::fs::remove_file(&temporary);
        result.map_err(|_| anyhow::anyhow!("credential publication failed"))
    }

    fn remove(&self) {
        let _ = std::fs::remove_file(&self.output);
        let _ = self.directory.sync_all();
    }
}

pub struct CredentialAgent {
    config: CredentialAgentConfig,
    transport: AlibabaCloudFencing,
}

impl CredentialAgent {
    pub fn new(config: CredentialAgentConfig) -> anyhow::Result<Self> {
        config.validate()?;
        let endpoint = url::Url::parse(&format!("https://sts.{}.aliyuncs.com/", config.region))?;
        let transport = AlibabaCloudFencing::build_transport(
            config.identity(),
            BTreeMap::new(),
            None,
            endpoint.clone(),
            endpoint,
            true,
        )
        .map_err(|_| anyhow::anyhow!("credential transport unavailable"))?;
        Ok(Self { config, transport })
    }

    async fn refresh(&self, publisher: &Publisher) -> anyhow::Result<()> {
        // Re-read the projected identity and mint a new session, never extend a
        // cached session's file age or use it after failed identity verification.
        *self.transport.inner.credentials.lock().await = None;
        let credentials =
            tokio::time::timeout(Duration::from_secs(45), self.transport.credentials())
                .await
                .map_err(|_| anyhow::anyhow!("credential exchange deadline"))?
                .map_err(|_| anyhow::anyhow!("credential identity unavailable"))?;
        anyhow::ensure!(
            valid_secret(&credentials.access_key_id, 256)
                && valid_secret(&credentials.secret, 256)
                && valid_secret(&credentials.token, 12288)
                && credentials.expires > Utc::now() + ChronoDuration::seconds(120),
            "credential shape rejected"
        );
        let data = serde_json::to_vec(&serde_json::json!({
            "access_key_id":credentials.access_key_id, "access_key_secret":credentials.secret,
            "security_token":credentials.token, "expires_at":credentials.expires,
        }))
        .map_err(|_| anyhow::anyhow!("credential encoding failed"))?;
        anyhow::ensure!(data.len() <= 16384, "credential record too large");
        publisher.publish(&data)
    }

    pub async fn run(self, once: bool, shutdown: CancellationToken) -> anyhow::Result<()> {
        let publisher = Publisher::new(&self.config.output_file)?;
        let mut delay = 5;
        loop {
            let result = tokio::select! {
                _ = shutdown.cancelled() => { publisher.remove(); return Ok(()); },
                result = self.refresh(&publisher) => result,
            };
            if shutdown.is_cancelled() {
                publisher.remove();
                return Ok(());
            }
            let wait = match result {
                Ok(()) => {
                    if once {
                        return Ok(());
                    }
                    delay = 5;
                    Duration::from_secs(300 + u64::from(uuid::Uuid::new_v4().as_bytes()[0] % 31))
                }
                Err(_) => {
                    publisher.remove();
                    tracing::warn!(
                        purpose = self.config.purpose.name(),
                        "storage credential refresh unavailable"
                    );
                    if once {
                        anyhow::bail!("storage credential initialization failed");
                    }
                    let wait = Duration::from_secs(delay);
                    delay = (delay * 2).min(60);
                    wait
                }
            };
            tokio::select! {
                _ = shutdown.cancelled() => { publisher.remove(); return Ok(()); },
                _ = tokio::time::sleep(wait) => {},
            }
        }
    }
}

#[cfg(test)]
#[path = "cloud_credential_agent_tests.rs"]
mod tests;
