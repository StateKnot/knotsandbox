//! Installation reader client. Authority is checked by the API on every read;
//! this command never opens an owner database connection or stores a grant.
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Result, anyhow, ensure};
use sandbox_platform::node_image_query::NodeImageStatus;
use tokio::io::AsyncReadExt;
use url::{Host, Url};
use uuid::Uuid;

const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_CA_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(clap::Args)]
pub struct NodeImageStatusArgs {
    /// Trusted HTTPS API prefix, without credentials, query, or fragment.
    #[arg(long)]
    endpoint: String,
    /// Exact enrolled runtime node UUID; this command cannot enumerate nodes.
    #[arg(long)]
    runtime_node_id: Uuid,
    /// Current OAuth access token in a private regular file (0400 or 0600).
    #[arg(long)]
    token_file: PathBuf,
    /// Additional trusted server CA in a bounded regular PEM file.
    #[arg(long)]
    ca_file: Option<PathBuf>,
    /// Development only: permit HTTP at a literal loopback IP.
    #[arg(long)]
    allow_loopback_http: bool,
}

pub async fn run(args: NodeImageStatusArgs) -> Result<()> {
    let target = target(&args)?;
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .retry(reqwest::retry::never())
        .redirect(reqwest::redirect::Policy::none())
        .https_only(target.scheme() == "https")
        .http1_only()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10));
    if let Some(path) = &args.ca_file {
        let pem = read_file(path, MAX_CA_BYTES, false).await?;
        let certificate = reqwest::Certificate::from_pem(&pem)
            .map_err(|_| anyhow!("node image reader CA is invalid"))?;
        builder = builder.add_root_certificate(certificate);
    }
    let client = builder
        .build()
        .map_err(|_| anyhow!("node image reader HTTP configuration is invalid"))?;
    // Read the opened inode immediately before this one request. Symlink-based
    // credential rotation is supported; there is no token or grant cache.
    let token = read_file(&args.token_file, MAX_TOKEN_BYTES, true).await?;
    ensure!(
        token.iter().all(|byte| (0x21..=0x7e).contains(byte)),
        "node image reader token is invalid"
    );
    let token =
        std::str::from_utf8(&token).map_err(|_| anyhow!("node image reader token is invalid"))?;
    let mut response = client
        .get(target)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| anyhow!("node image API request failed"))?;
    if !response.status().is_success() {
        return Err(anyhow!(match response.status().as_u16() {
            401 => "node image API authentication failed",
            403 => "node image API access is forbidden",
            404 => "node image API node is unavailable",
            409 => "node image API binding changed; perform a new authorized read",
            429 | 503 => "node image API is temporarily unavailable",
            _ => "node image API returned an unsuccessful response",
        }));
    }
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= MAX_RESPONSE_BYTES as u64),
        "node image API response exceeds size limit"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow!("node image API response could not be read"))?
    {
        ensure!(
            chunk.len() <= MAX_RESPONSE_BYTES.saturating_sub(bytes.len()),
            "node image API response exceeds size limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    let status: NodeImageStatus = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow!("node image API response is invalid"))?;
    validate_status(
        &status,
        args.runtime_node_id,
        chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
    )?;
    // Serialize the validated schema rather than relaying untrusted response
    // bytes. Failures above never print a server body, token, URL, or path.
    println!(
        "{}",
        serde_json::to_string(&status)
            .map_err(|_| anyhow!("node image API response is invalid"))?
    );
    Ok(())
}

fn target(args: &NodeImageStatusArgs) -> Result<Url> {
    ensure!(
        !args.runtime_node_id.is_nil(),
        "node image reader requires a non-nil runtime node UUID"
    );
    ensure!(
        args.endpoint.len() <= 2048
            && !args
                .endpoint
                .chars()
                .any(|ch| ch.is_control() || ch.is_whitespace()),
        "node image reader endpoint is invalid"
    );
    let mut url =
        Url::parse(&args.endpoint).map_err(|_| anyhow!("node image reader endpoint is invalid"))?;
    let userinfo = args.endpoint.split_once("://").is_some_and(|(_, rest)| {
        rest.split(['/', '?', '#'])
            .next()
            .is_some_and(|authority| authority.contains('@'))
    });
    ensure!(
        !userinfo
            && !url.cannot_be_a_base()
            && url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "node image reader endpoint is invalid"
    );
    let loopback = matches!(url.host(), Some(Host::Ipv4(ip)) if ip.is_loopback())
        || matches!(url.host(), Some(Host::Ipv6(ip)) if ip.is_loopback());
    ensure!(
        url.scheme() == "https" || args.allow_loopback_http && url.scheme() == "http" && loopback,
        "node image reader endpoint requires HTTPS; HTTP development mode requires a literal loopback IP"
    );
    url.set_path(&format!(
        "{}/v1/operator/nodes/{}/image-status",
        url.path().trim_end_matches('/'),
        args.runtime_node_id
    ));
    Ok(url)
}

async fn read_file(path: &Path, limit: usize, private: bool) -> Result<Vec<u8>> {
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    // Reject FIFOs without blocking a filesystem worker. Inspect the opened
    // inode so projected Secret symlinks remain usable during rotation.
    #[cfg(unix)]
    options.custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits());
    let file = options
        .open(path)
        .await
        .map_err(|_| anyhow!("node image reader credential file cannot be read"))?;
    let metadata = file
        .metadata()
        .await
        .map_err(|_| anyhow!("node image reader credential file cannot be read"))?;
    ensure!(
        metadata.is_file() && metadata.len() <= limit as u64,
        "node image reader credential file is invalid"
    );
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            matches!(metadata.permissions().mode() & 0o7777, 0o400 | 0o600),
            "node image reader token file must have mode 0400 or 0600"
        );
    }
    #[cfg(not(unix))]
    ensure!(
        !private,
        "node image reader private token files require Unix permissions"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| anyhow!("node image reader credential file cannot be read"))?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= limit,
        "node image reader credential file is invalid"
    );
    Ok(bytes)
}

fn validate_status(status: &NodeImageStatus, node: Uuid, now: f64) -> Result<()> {
    let invalid = || anyhow!("node image API response binding or observation is invalid");
    if status.runtime_node_id != node
        || [
            status.installation_id,
            status.cluster_epoch,
            status.grant_id,
            status.runtime_node_id,
            status.node_uid,
            status.host_boot_id,
        ]
        .iter()
        .any(Uuid::is_nil)
        || !digest(&status.profile_sha256)
        || !fresh(status.metrics.evaluated_at_seconds, now)
    {
        return Err(invalid());
    }
    if let Some(inventory) = &status.metrics.inventory
        && (status.metrics.inventory_observation_success != Some(true)
            || !replica(&inventory.collector_replica)
            || !fresh(inventory.scraped_at_seconds, now)
            || inventory.scraped_at_seconds > status.metrics.evaluated_at_seconds
            || !fresh(inventory.observed_at_seconds, now)
            || !quantity(inventory.count)
            || !quantity(inventory.compressed_logical_bytes))
    {
        return Err(invalid());
    }
    if let Some(report) = &status.metrics.filesystem {
        if status.metrics.filesystem_observation_success != Some(true)
            || !replica(&report.collector_replica)
            || !fresh(report.scraped_at_seconds, now)
            || report.scraped_at_seconds > status.metrics.evaluated_at_seconds
            || !fresh(report.observed_at_seconds, now)
            || report.filesystems.len() > 16
        {
            return Err(invalid());
        }
        let mut ids = BTreeSet::new();
        for filesystem in &report.filesystems {
            if !digest(&filesystem.filesystem_id)
                || !ids.insert(&filesystem.filesystem_id)
                || !fresh(filesystem.reported_at_seconds, now)
                || filesystem.used_bytes.is_some_and(|value| !quantity(value))
                || filesystem.inodes_used.is_some_and(|value| !quantity(value))
            {
                return Err(invalid());
            }
        }
    }
    Ok(())
}
fn fresh(value: f64, now: f64) -> bool {
    value.is_finite() && value > 0.0 && value <= now + 5.0 && now - value < 60.0
}
fn quantity(value: f64) -> bool {
    value.is_finite() && value >= 0.0
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn replica(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
}

#[cfg(test)]
#[path = "admin_node_image_cli_tests.rs"]
mod tests;
