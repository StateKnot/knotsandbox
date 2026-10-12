use std::{io::Read, net::SocketAddr, path::PathBuf, time::Duration};

use clap::Parser;

use crate::auth::AuthConfig;

/// Environment variables holding secrets are deliberately not included in Debug output.
#[derive(Parser)]
#[command(
    name = "sandboxd",
    version,
    about = "Multi-tenant sandbox control plane"
)]
pub struct Config {
    #[arg(long, value_enum, default_value = "api")]
    pub role: Role,
    #[arg(long, env = "SANDBOX_LISTEN", default_value = "127.0.0.1:8080")]
    pub listen: SocketAddr,
    #[arg(long, env = "SANDBOX_API_TLS_CERT_FILE")]
    pub api_tls_cert_file: Option<PathBuf>,
    #[arg(long, env = "SANDBOX_API_TLS_KEY_FILE")]
    pub api_tls_key_file: Option<PathBuf>,
    #[arg(long, env = "SANDBOX_API_TLS_CA_FILE")]
    pub api_tls_ca_file: Option<PathBuf>,
    /// Exact DNS/IPv4 SAN checked against the configured server certificate.
    #[arg(long, env = "SANDBOX_API_TLS_SERVER_NAME")]
    pub api_tls_server_name: Option<String>,
    #[arg(long, env = "SANDBOX_DATABASE_URL", hide_env_values = true)]
    pub database_url: String,
    #[arg(long, env = "SANDBOX_DB_MAX_CONNECTIONS", default_value_t = 20)]
    pub db_max_connections: u32,
    #[arg(long, env = "SANDBOX_OIDC_ISSUER")]
    pub oidc_issuer: Option<String>,
    #[arg(long, env = "SANDBOX_OIDC_AUDIENCE", default_value = "sandbox-api")]
    pub oidc_audience: String,
    #[arg(long, env = "SANDBOX_OIDC_JWKS_URL")]
    pub oidc_jwks_url: Option<String>,
    #[arg(
        long,
        env = "SANDBOX_OIDC_REQUIRED_SCOPE",
        default_value = "sandbox:access"
    )]
    pub oidc_required_scope: String,
    #[arg(
        long,
        env = "SANDBOX_OIDC_SCOPE_PROFILE",
        value_enum,
        default_value = "generic-access"
    )]
    pub oidc_scope_profile: crate::auth::ScopeProfile,
    /// Shared cursor signing key ring. All API replicas must use the same keys.
    #[arg(long, env = "SANDBOX_CURSOR_SIGNING_KEY_FILE")]
    pub cursor_signing_key_file: Option<PathBuf>,
    /// Optional server-side browser OIDC BFF; absent keeps a bearer-only API.
    #[arg(long, env = "SANDBOX_BROWSER_CONFIG_FILE")]
    pub browser_config_file: Option<PathBuf>,
    #[arg(long, env = "SANDBOX_ALLOW_LOOPBACK_HTTP", default_value_t = false)]
    pub allow_loopback_http: bool,
    #[arg(long, env = "SANDBOX_DEFAULT_TTL_SECONDS", default_value_t = 3600)]
    pub default_ttl_seconds: i64,
    #[arg(long, env = "SANDBOX_MAX_TTL_SECONDS", default_value_t = 86400)]
    pub max_ttl_seconds: i64,
    #[arg(long, env = "SANDBOX_WORKER_CONCURRENCY", default_value_t = 4)]
    pub worker_concurrency: usize,
    #[arg(long, env = "SANDBOX_GATEWAY_CONCURRENCY", default_value_t = 4)]
    pub gateway_concurrency: usize,
    /// Additional file queue concurrency, independent of command execution.
    #[arg(long, env = "SANDBOX_FILE_GATEWAY_CONCURRENCY", default_value_t = 2)]
    pub file_gateway_concurrency: usize,
    #[arg(long, env = "SANDBOX_TERMINATION_CONCURRENCY", default_value_t = 4)]
    pub termination_concurrency: usize,
    #[arg(long, env = "SANDBOX_NODEGUARD_SERVER_CA_FILE")]
    pub nodeguard_server_ca_file: Option<PathBuf>,
    /// Reviewed cloud identity and exact resource allowlist; contains no static access keys.
    #[arg(long, env = "SANDBOX_CLOUD_FENCING_CONFIG_FILE")]
    pub cloud_fencing_config_file: Option<PathBuf>,
    #[arg(long, env = "SANDBOX_VOLUME_DELETION_CONFIG_FILE")]
    pub volume_deletion_config_file: Option<PathBuf>,
    /// Dedicated controller client certificate and private key in one PEM file.
    #[arg(long, env = "SANDBOX_NODEGUARD_CLIENT_IDENTITY_FILE")]
    pub nodeguard_client_identity_file: Option<PathBuf>,
    #[arg(long, env = "SANDBOX_OUTPUT_OSS_ENDPOINT")]
    pub output_oss_endpoint: Option<String>,
    #[arg(long, env = "SANDBOX_OUTPUT_OSS_BUCKET")]
    pub output_oss_bucket: Option<String>,
    #[arg(long, env = "SANDBOX_OUTPUT_OSS_KMS_KEY_ID")]
    pub output_oss_kms_key_id: Option<String>,
    #[arg(long, env = "SANDBOX_OUTPUT_STS_FILE")]
    pub output_sts_file: Option<PathBuf>,
    /// API-only read credentials; never fall back to the gateway writer identity.
    #[arg(long, env = "SANDBOX_OUTPUT_READ_STS_FILE")]
    pub output_read_sts_file: Option<PathBuf>,
    /// Nonsecret temporary file storage settings with separate STS identities.
    #[arg(long, env = "SANDBOX_FILES_CONFIG_FILE")]
    pub files_config_file: Option<PathBuf>,
    /// Fixed-query reader endpoint and private credential file references.
    #[arg(long, env = "SANDBOX_METRICS_CONFIG_FILE")]
    pub metrics_config_file: Option<PathBuf>,
    #[arg(long, env = "SANDBOX_BACKUP_VAULT_CONFIG_FILE")]
    pub backup_vault_config_file: Option<PathBuf>,
    /// Dedicated vault reader; never the mutable repository or output writer.
    #[arg(long, env = "SANDBOX_BACKUP_READ_STS_FILE")]
    pub backup_read_sts_file: Option<PathBuf>,
    #[arg(long, env = "SANDBOX_BACKUP_CONCURRENCY", default_value_t = 2)]
    pub backup_concurrency: usize,
    /// Reference to independently reviewed cluster isolation/admission evidence.
    #[arg(long, env = "SANDBOX_DEPLOYMENT_CERTIFICATION_ID")]
    pub deployment_certification_id: Option<String>,
    #[arg(long, env = "SANDBOX_DNS_NAMESPACE", default_value = "kube-system")]
    pub dns_namespace: String,
    #[arg(long, env = "SANDBOX_DNS_LABEL", default_value = "k8s-app=kube-dns")]
    pub dns_label: String,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum Role {
    Api,
    Worker,
    Gateway,
    Termination,
    Fencing,
    VolumeDeleter,
    Backup,
    Migrate,
}

/// Validate URL shape before SQLx can interpret aliases or log unknown
/// query parameters. Errors deliberately contain no URL or credentials.
pub fn validate_database_url(
    value: &str,
    allow_literal_loopback_development: bool,
) -> anyhow::Result<()> {
    const ERROR: &str = "Database URL requires canonical postgres/postgresql host/database and sslmode=verify-full with an absolute sslrootcert; only explicit literal loopback development may omit TLS";
    anyhow::ensure!(value.len() <= 4096, ERROR);
    let url = url::Url::parse(value).map_err(|_| anyhow::anyhow!(ERROR))?;
    anyhow::ensure!(
        matches!(url.scheme(), "postgres" | "postgresql")
            && url.host_str().is_some_and(|host| !host.is_empty())
            && !url.username().is_empty()
            && url.path().len() > 1
            && url.fragment().is_none()
            && !value.chars().any(char::is_control),
        ERROR
    );
    // postgres is not a WHATWG special scheme: Url::host() can represent
    // an IPv4 literal as Domain. Parse only canonical literal IP text.
    let loopback = url.host_str().is_some_and(|host| {
        host.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    });
    let mut seen = std::collections::BTreeSet::new();
    let mut mode = None;
    let mut root = None;
    for (key, value) in url.query_pairs() {
        anyhow::ensure!(seen.insert(key.to_string()), ERROR);
        match key.as_ref() {
            "sslmode" => {
                anyhow::ensure!(matches!(value.as_ref(), "verify-full" | "disable"), ERROR);
                mode = Some(value.into_owned());
            }
            "sslrootcert" => {
                let path = std::path::Path::new(value.as_ref());
                anyhow::ensure!(
                    value.len() <= 1024
                        && !value.chars().any(char::is_control)
                        && path.is_absolute()
                        && path.file_name().is_some()
                        && !value.split('/').any(|part| matches!(part, "." | ".."))
                        && path.components().all(|part| matches!(
                            part,
                            std::path::Component::RootDir | std::path::Component::Normal(_)
                        )),
                    ERROR
                );
                root = Some(value.into_owned());
            }
            "application_name" => {
                anyhow::ensure!(
                    !value.is_empty()
                        && value.len() <= 63
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
                    ERROR
                );
            }
            _ => anyhow::bail!(ERROR),
        }
    }
    let tls = mode.as_deref() == Some("verify-full") && root.is_some();
    let development = allow_literal_loopback_development
        && loopback
        && matches!(mode.as_deref(), None | Some("disable"))
        && root.is_none();
    anyhow::ensure!(tls || development, ERROR);
    Ok(())
}

impl Config {
    pub fn validate_database_url(&self) -> anyhow::Result<()> {
        validate_database_url(&self.database_url, self.allow_loopback_http)
    }

    pub fn api_tls_files(&self) -> anyhow::Result<Option<crate::api_tls::ApiTlsFiles>> {
        match (
            &self.api_tls_cert_file,
            &self.api_tls_key_file,
            &self.api_tls_ca_file,
            &self.api_tls_server_name,
        ) {
            (None, None, None, None) => {
                anyhow::ensure!(
                    self.listen.ip().is_loopback() && self.allow_loopback_http,
                    "API TLS is required except explicit loopback HTTP development"
                );
                Ok(None)
            }
            (Some(certificate), Some(private_key), Some(ca), Some(server_name)) => {
                anyhow::ensure!(
                    [certificate, private_key, ca]
                        .iter()
                        .all(|path| path.is_absolute()),
                    "API TLS paths must be absolute"
                );
                anyhow::ensure!(!server_name.is_empty(), "API TLS server name is required");
                Ok(Some(crate::api_tls::ApiTlsFiles {
                    certificate: certificate.clone(),
                    private_key: private_key.clone(),
                    ca: ca.clone(),
                    server_name: server_name.clone(),
                }))
            }
            _ => anyhow::bail!(
                "API TLS certificate, key, CA and server name must be configured together"
            ),
        }
    }
    pub fn file_storage_config(
        &self,
    ) -> anyhow::Result<Option<crate::file_store::FileStorageSettings>> {
        let Some(path) = &self.files_config_file else {
            return Ok(None);
        };
        anyhow::ensure!(
            path.is_absolute(),
            "file storage configuration path must be absolute"
        );
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits());
        }
        let file = options
            .open(path)
            .map_err(|_| anyhow::anyhow!("cannot open file storage configuration"))?;
        anyhow::ensure!(
            file.metadata()?.is_file(),
            "file storage configuration must be a regular file"
        );
        let mut bytes = Vec::new();
        file.take(8193)
            .read_to_end(&mut bytes)
            .map_err(|_| anyhow::anyhow!("cannot read file storage configuration"))?;
        anyhow::ensure!(
            bytes.len() <= 8192,
            "file storage configuration exceeds size limit"
        );
        let settings: crate::file_store::FileStorageSettings = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid file storage configuration"))?;
        settings.validate()?;
        Ok(Some(settings))
    }
    pub fn browser_config(&self) -> anyhow::Result<Option<crate::bff_config::BrowserConfig>> {
        self.browser_config_file
            .as_ref()
            .map(|path| {
                crate::bff_config::BrowserConfig::from_file(
                    path,
                    self.oidc_issuer
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("SANDBOX_OIDC_ISSUER is required"))?,
                )
            })
            .transpose()
    }
    pub fn backup_vault_config(&self) -> anyhow::Result<crate::backup_object::BackupVaultConfig> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Settings {
            endpoint: String,
            bucket: String,
            region: String,
            account_id: String,
            signing_public_key_file: PathBuf,
        }
        fn read(path: &std::path::Path, max: usize) -> anyhow::Result<Vec<u8>> {
            anyhow::ensure!(
                path.is_absolute(),
                "backup configuration paths must be absolute"
            );
            let mut options = std::fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits());
            }
            let file = options
                .open(path)
                .map_err(|_| anyhow::anyhow!("cannot open backup configuration file"))?;
            anyhow::ensure!(
                file.metadata()?.is_file(),
                "backup configuration must be a regular file"
            );
            let mut data = Vec::new();
            file.take(max as u64 + 1).read_to_end(&mut data)?;
            anyhow::ensure!(data.len() <= max, "backup configuration exceeds size limit");
            Ok(data)
        }
        let path = self
            .backup_vault_config_file
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SANDBOX_BACKUP_VAULT_CONFIG_FILE is required"))?;
        let settings: Settings = serde_json::from_slice(&read(path, 32768)?)
            .map_err(|_| anyhow::anyhow!("invalid backup vault configuration"))?;
        let raw = read(&settings.signing_public_key_file, 4096)?;
        let key = if raw.starts_with(b"-----BEGIN PUBLIC KEY-----") {
            use rustls::pki_types::{SubjectPublicKeyInfoDer, pem::PemObject};
            SubjectPublicKeyInfoDer::from_pem_slice(&raw)
                .map_err(|_| anyhow::anyhow!("invalid backup public key encoding"))?
                .as_ref()
                .to_vec()
        } else {
            raw
        };
        const ED25519_SPKI: &[u8] = &[
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        anyhow::ensure!(
            key.len() == 44 && key.starts_with(ED25519_SPKI),
            "backup signing public key must be Ed25519 SPKI PEM or DER"
        );
        let credentials = self
            .backup_read_sts_file
            .clone()
            .ok_or_else(|| anyhow::anyhow!("SANDBOX_BACKUP_READ_STS_FILE is required"))?;
        anyhow::ensure!(
            credentials.is_absolute(),
            "backup reader credentials require an absolute file path"
        );
        Ok(crate::backup_object::BackupVaultConfig {
            endpoint: settings.endpoint,
            bucket: settings.bucket,
            region: settings.region,
            account_id: settings.account_id,
            sts_credentials_file: credentials,
            signing_public_key_spki: key,
        })
    }
    pub fn metrics_config(&self) -> anyhow::Result<Option<crate::metrics::MetricsBackendConfig>> {
        let Some(path) = &self.metrics_config_file else {
            return Ok(None);
        };
        let file =
            std::fs::File::open(path).map_err(|_| anyhow::anyhow!("cannot open metrics config"))?;
        anyhow::ensure!(
            file.metadata()?.is_file(),
            "metrics config must be a regular file"
        );
        let mut bytes = Vec::new();
        file.take(32769).read_to_end(&mut bytes)?;
        anyhow::ensure!(bytes.len() <= 32768, "metrics config exceeds 32 KiB");
        Ok(Some(
            serde_json::from_slice(&bytes)
                .map_err(|_| anyhow::anyhow!("invalid metrics config"))?,
        ))
    }
    pub fn cloud_fencing_config(&self) -> anyhow::Result<crate::cloud_fencing::CloudFencingConfig> {
        let path = self
            .cloud_fencing_config_file
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SANDBOX_CLOUD_FENCING_CONFIG_FILE is required"))?;
        let file = std::fs::File::open(path)
            .map_err(|_| anyhow::anyhow!("cannot open cloud fencing config"))?;
        anyhow::ensure!(
            file.metadata()?.is_file(),
            "cloud fencing config must be a regular file"
        );
        let mut contents = Vec::new();
        file.take(1_048_577).read_to_end(&mut contents)?;
        anyhow::ensure!(
            contents.len() <= 1_048_576,
            "cloud fencing config exceeds 1 MiB"
        );
        serde_json::from_slice(&contents)
            .map_err(|_| anyhow::anyhow!("invalid cloud fencing config"))
    }

    pub fn volume_deletion_config(
        &self,
    ) -> anyhow::Result<crate::volume_deletion::VolumeDeletionConfig> {
        let path = self
            .volume_deletion_config_file
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SANDBOX_VOLUME_DELETION_CONFIG_FILE is required"))?;
        let contents = crate::api_tls::read(path, 1_048_576, false)
            .map_err(|_| anyhow::anyhow!("volume deletion config requires an absolute, bounded, regular file without group/world write or special permissions"))?;
        let config: crate::volume_deletion::VolumeDeletionConfig =
            serde_json::from_slice(&contents)
                .map_err(|_| anyhow::anyhow!("invalid volume deletion config"))?;
        anyhow::ensure!(
            config.cloud.deployment == config.storage.deployment,
            "cloud and storage deletion configuration must use the same deployment"
        );
        Ok(config)
    }

    pub fn nodeguard_credentials(
        &self,
    ) -> anyhow::Result<crate::termination_client::NodeguardCredentials> {
        let ca_path = self
            .nodeguard_server_ca_file
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SANDBOX_NODEGUARD_SERVER_CA_FILE is required"))?;
        let identity_path = self
            .nodeguard_client_identity_file
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SANDBOX_NODEGUARD_CLIENT_IDENTITY_FILE is required"))?;
        crate::termination_client::NodeguardCredentials::from_files(ca_path, identity_path)
    }

    pub fn output_reader_config(
        &self,
    ) -> anyhow::Result<Option<crate::output_store::OssOutputConfig>> {
        let Some(path) = &self.output_read_sts_file else {
            return Ok(None);
        };
        Ok(Some(crate::output_store::OssOutputConfig {
            endpoint: self.output_oss_endpoint.clone().ok_or_else(|| {
                anyhow::anyhow!("SANDBOX_OUTPUT_OSS_ENDPOINT is required for output reads")
            })?,
            bucket: self.output_oss_bucket.clone().ok_or_else(|| {
                anyhow::anyhow!("SANDBOX_OUTPUT_OSS_BUCKET is required for output reads")
            })?,
            kms_key_id: self.output_oss_kms_key_id.clone().ok_or_else(|| {
                anyhow::anyhow!("SANDBOX_OUTPUT_OSS_KMS_KEY_ID is required for output reads")
            })?,
            sts_credentials_file: path.clone(),
        }))
    }

    pub fn cursor_signing_key_json(&self) -> anyhow::Result<String> {
        let path = self.cursor_signing_key_file.as_ref().ok_or_else(|| {
            anyhow::anyhow!("SANDBOX_CURSOR_SIGNING_KEY_FILE is required for the API role")
        })?;
        // Follow projected Secret symlinks, then inspect the opened inode. This
        // supports Kubernetes atomic key rotation without a path-check race.
        let file = std::fs::File::open(path)
            .map_err(|_| anyhow::anyhow!("cannot open cursor signing key file"))?;
        let metadata = file
            .metadata()
            .map_err(|_| anyhow::anyhow!("cannot inspect cursor signing key file"))?;
        anyhow::ensure!(
            metadata.is_file(),
            "cursor signing key must be a regular file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode() & 0o7777;
            anyhow::ensure!(
                matches!(mode, 0o400 | 0o600),
                "cursor signing key file requires mode 0400 or 0600"
            );
        }
        let mut contents = String::new();
        file.take(8193)
            .read_to_string(&mut contents)
            .map_err(|_| anyhow::anyhow!("cannot read cursor signing key file"))?;
        anyhow::ensure!(
            contents.len() <= 8192,
            "cursor signing key file exceeds 8 KiB"
        );
        Ok(contents)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if matches!(self.role, Role::Api) {
            self.api_tls_files()?;
        }
        self.validate_database_url()?;
        anyhow::ensure!(
            (1..=16).contains(&self.file_gateway_concurrency),
            "file gateway concurrency must be 1..=16"
        );
        anyhow::ensure!(
            (1..=200).contains(&self.db_max_connections),
            "DB connection limit must be 1..=200"
        );
        anyhow::ensure!(
            self.default_ttl_seconds >= 60,
            "default TTL must be at least 60 seconds"
        );
        anyhow::ensure!(
            self.max_ttl_seconds >= self.default_ttl_seconds && self.max_ttl_seconds <= 604800,
            "maximum TTL must cover default and cannot exceed 7 days"
        );
        if self.allow_loopback_http {
            anyhow::ensure!(
                self.listen.ip().is_loopback(),
                "loopback HTTP identity mode requires a loopback application listener"
            );
        }
        Ok(())
    }

    pub fn auth_config(&self) -> anyhow::Result<AuthConfig> {
        Ok(AuthConfig {
            issuer: self
                .oidc_issuer
                .clone()
                .ok_or_else(|| anyhow::anyhow!("SANDBOX_OIDC_ISSUER is required"))?,
            audience: self.oidc_audience.clone(),
            jwks_url: self
                .oidc_jwks_url
                .clone()
                .ok_or_else(|| anyhow::anyhow!("SANDBOX_OIDC_JWKS_URL is required"))?,
            required_scopes: self
                .oidc_required_scope
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
            scope_profile: self.oidc_scope_profile,
            jwks_ttl_seconds: 300,
            clock_skew_seconds: 30,
            allow_loopback_http: self.allow_loopback_http,
            max_token_lifetime_seconds: 300,
        })
    }

    pub fn db_acquire_timeout(&self) -> Duration {
        Duration::from_secs(3)
    }
}
