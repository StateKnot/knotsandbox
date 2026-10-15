//! Owned native CRI → mTLS → dual Agent → receiver → operator acceptance.
//! IPC drives external failures; all product observations use HTTPS/API/CLI.
use super::*;
use node_images::{TlsServer, query_app};
use sandbox_platform::{
    metrics::{
        MetricsBackendConfig, NodeImageAccuracy, NodeImageCompleteness, NodeImageMetricSource,
        PrometheusMetrics,
    },
    node_image_query::NodeImageStatus,
    nodeguard::protocol::NodeBinding,
};
use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};
use tokio::io::AsyncReadExt;
use tokio::time::Instant;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeFixture {
    backend: MetricsBackendConfig,
    node: NodeBinding,
    expected_compressed_logical_bytes: String,
    control_directory: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Action {
    Fresh,
    Unknown,
    RevokeInflight,
    RegrantFresh,
    Stop,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    sequence: u8,
    action: Action,
}

fn private_path(path: &Path, directory: bool, limit: u64) -> anyhow::Result<fs::Metadata> {
    ensure!(path.is_absolute() && !path.components().any(|p| matches!(p, Component::ParentDir)));
    for ancestor in path.ancestors() {
        ensure!(!fs::symlink_metadata(ancestor)?.file_type().is_symlink());
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(if directory {
        metadata.is_dir()
    } else {
        metadata.is_file()
    });
    ensure!(metadata.uid() == nix::unistd::geteuid().as_raw());
    ensure!(metadata.permissions().mode() & 0o7777 == if directory { 0o700 } else { 0o600 });
    ensure!(directory || metadata.len() <= limit);
    Ok(metadata)
}

fn read_private<T: serde::de::DeserializeOwned>(path: &Path, limit: u64) -> anyhow::Result<T> {
    let expected = private_path(path, false, limit)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let actual = file.metadata()?;
    ensure!(actual.is_file() && actual.dev() == expected.dev() && actual.ino() == expected.ino());
    ensure!(
        actual.uid() == expected.uid()
            && actual.permissions().mode() & 0o7777 == 0o600
            && actual.len() <= limit
    );
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit);
    Ok(serde_json::from_slice(&bytes)?)
}

fn publish(directory: &Path, filename: &str, value: &Value) -> anyhow::Result<()> {
    private_path(directory, true, 0)?;
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= 64 * 1024);
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(directory.join(filename))?;
    Ok(())
}

fn release_query(directory: &Path) -> anyhow::Result<()> {
    private_path(directory, true, 0)?;
    let path = directory.join("query-release");
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(file) => {
            file.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure!(private_path(&path, false, 0)?.len() == 0);
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

async fn wait_file(path: &Path, deadline: Instant) -> anyhow::Result<()> {
    loop {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                private_path(path, false, 512)?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        ensure!(
            Instant::now() < deadline,
            "Native operator global budget expired"
        );
        tokio::time::sleep_until((Instant::now() + Duration::from_millis(20)).min(deadline)).await;
    }
}

async fn https_read(
    endpoint: String,
    node: Uuid,
    bearer: HeaderValue,
) -> anyhow::Result<(StatusCode, Value)> {
    let ca = reqwest::Certificate::from_pem(include_bytes!("../fixtures/admission/server-ca.pem"))?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(10))
        .add_root_certificate(ca)
        .build()?;
    let mut response = client
        .get(format!("{endpoint}/v1/operator/nodes/{node}/image-status"))
        .header("authorization", bearer)
        .send()
        .await?;
    let status = response.status();
    ensure!(
        response
            .headers()
            .get("cache-control")
            .is_some_and(|v| v == "no-store")
    );
    ensure!(
        response
            .headers()
            .get("x-content-type-options")
            .is_some_and(|v| v == "nosniff")
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(bytes.len() + chunk.len() <= 256 * 1024);
        bytes.extend_from_slice(&chunk);
    }
    Ok((status, serde_json::from_slice(&bytes)?))
}

async fn cli_read(
    endpoint: &str,
    node: Uuid,
    bearer: &HeaderValue,
    directory: &Path,
    pending: &mut Option<tokio::process::Child>,
) -> anyhow::Result<std::process::Output> {
    ensure!(pending.is_none());
    let mut token = tempfile::NamedTempFile::new_in(directory)?;
    token.write_all(
        bearer
            .to_str()?
            .strip_prefix("Bearer ")
            .context("Bearer token")?
            .as_bytes(),
    )?;
    token.flush()?;
    *pending = Some(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_sandbox-admin"))
            .args([
                "node-image-status",
                "--endpoint",
                endpoint,
                "--runtime-node-id",
                &node.to_string(),
                "--token-file",
            ])
            .arg(token.path())
            .arg("--ca-file")
            .arg(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/admission/server-ca.pem"),
            )
            .env(
                "SANDBOX_ADMIN_DATABASE_URL",
                "postgresql://unused-owner.invalid/no-database",
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?,
    );
    let child = pending.as_mut().context("Live read-only CLI")?;
    let stdout = child.stdout.take().context("CLI stdout")?;
    let stderr = child.stderr.take().context("CLI stderr")?;
    let bounded_read = async |reader: tokio::process::ChildStdout| {
        let mut bytes = Vec::new();
        reader.take(256 * 1024 + 1).read_to_end(&mut bytes).await?;
        ensure!(bytes.len() <= 256 * 1024, "CLI output bound exceeded");
        Ok::<_, anyhow::Error>(bytes)
    };
    let error_read = async {
        let mut bytes = Vec::new();
        stderr.take(8193).read_to_end(&mut bytes).await?;
        ensure!(bytes.len() <= 8192, "CLI diagnostic bound exceeded");
        Ok::<_, anyhow::Error>(bytes)
    };
    let (stdout, stderr, status) = tokio::try_join!(bounded_read(stdout), error_read, async {
        Ok::<_, anyhow::Error>(child.wait().await?)
    })?;
    pending.take();
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

fn assert_binding(
    status: &NodeImageStatus,
    fixture: &NativeFixture,
    node: Uuid,
    grant: &GrantNodeImageReader,
) -> anyhow::Result<()> {
    ensure!(status.installation_id == grant.installation_id && status.grant_id == grant.grant_id);
    ensure!(status.runtime_node_id == node && status.cluster_epoch == fixture.node.cluster_epoch);
    ensure!(
        status.node_uid == fixture.node.node_uid
            && status.host_boot_id == fixture.node.boot_id
            && status.profile_sha256 == fixture.node.profile_sha256
    );
    ensure!(
        status.metrics.source == NodeImageMetricSource::RuntimeReported
            && status.metrics.completeness == NodeImageCompleteness::Unknown
            && status.metrics.accuracy == NodeImageAccuracy::ApproximateF64
    );
    Ok(())
}

fn assert_observation(
    status: &NodeImageStatus,
    expected_bytes: u64,
    unknown: bool,
) -> anyhow::Result<()> {
    if unknown {
        ensure!(
            status.metrics.inventory.is_none() && status.metrics.filesystem.is_none(),
            "Unavailable observations must clear old quantities"
        );
    } else {
        let inventory = status
            .metrics
            .inventory
            .as_ref()
            .context("Fresh native inventory required")?;
        ensure!(status.metrics.inventory_observation_success == Some(true));
        ensure!(
            inventory.count == 1.0 && inventory.compressed_logical_bytes == expected_bytes as f64
        );
        ensure!(
            (-5.0..60.0)
                .contains(&(status.metrics.evaluated_at_seconds - inventory.observed_at_seconds))
        );
        // Native ImageFsInfo may return an independently old report. The API
        // must omit it; inventory freshness cannot manufacture FS freshness.
        if let Some(filesystem) = &status.metrics.filesystem {
            ensure!(status.metrics.filesystem_observation_success == Some(true));
            ensure!(
                (-5.0..60.0).contains(
                    &(status.metrics.evaluated_at_seconds - filesystem.observed_at_seconds)
                )
            );
            for entry in &filesystem.filesystems {
                ensure!(
                    (-5.0..60.0).contains(
                        &(status.metrics.evaluated_at_seconds - entry.reported_at_seconds)
                    )
                );
            }
        }
    }
    Ok(())
}

async fn refreshed_bearer(expected: &VerifiedIdentity) -> anyhow::Result<HeaderValue> {
    let (_, actual, bearer) = live_machine_identity().await?;
    ensure!(
        actual.issuer == expected.issuer
            && actual.subject == expected.subject
            && actual.client_id == expected.client_id
    );
    Ok(bearer)
}

#[tokio::test]
#[ignore = "Requires the owned native containerd, mTLS, dual Agent, receiver, real Keycloak and disposable PostgreSQL runner"]
async fn native_image_pipeline_to_operator_and_admin_is_revocable() -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(180);
    let path = PathBuf::from(
        env::var_os("SANDBOX_NATIVE_OPERATOR_FIXTURE").context("Native operator fixture path")?,
    );
    let native: NativeFixture = read_private(&path, 16 * 1024)?;
    private_path(&native.control_directory, true, 0)?;
    ensure!(native.node.validate());
    let digits = &native.expected_compressed_logical_bytes;
    ensure!(!digits.is_empty() && digits.len() <= 20 && digits.bytes().all(|b| b.is_ascii_digit()));
    let expected_bytes: u64 = digits.parse()?;
    ensure!(expected_bytes > 0 && expected_bytes <= (1_u64 << 53));
    let _serial = tokio::time::timeout_at(deadline, support::serial()).await?;
    let (fixture, auth, identity, _) =
        tokio::time::timeout_at(deadline, prepare_live_fixture()).await??;
    let mut original_epoch = None;
    let mut api = None;
    let mut pending_request = None;
    let mut pending_cli = None;
    let outcome = tokio::time::timeout_at(deadline, async {
        let old: Uuid = sqlx::query_scalar("SELECT cluster_epoch FROM platform_configuration WHERE singleton").fetch_one(&fixture.owner).await?;
        original_epoch = Some(old);
        sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton").bind(native.node.cluster_epoch).execute(&fixture.owner).await?;
        let node = Uuid::new_v4();
        let mut tx = fixture.owner.begin().await?;
        sqlx::query("INSERT INTO runtime_nodes(id,cluster_epoch,node_uid,node_name,cloud_provider,cloud_account_id,region,cloud_instance_id,private_ip,profile_sha256,boot_id,enabled) VALUES($1,$2,$3,$4,'alicloud','synthetic-native-chain-account','synthetic-native-chain-region',$5,'10.2.3.4',$6,$7,true)")
            .bind(node).bind(native.node.cluster_epoch).bind(native.node.node_uid).bind(&native.node.node_name).bind(node.to_string()).bind(&native.node.profile_sha256).bind(native.node.boot_id).execute(&mut *tx).await?;
        support::seed_test_node_certification(&mut tx, node, Utc::now() + ChronoDuration::seconds(180)).await?;
        tx.commit().await?;
        let owner = Database { pool: fixture.owner.clone() };
        let mut document = live_grant_document(&fixture, &identity).await?;
        document["expires_at"] = json!((Utc::now() + ChronoDuration::seconds(180)).to_rfc3339_opts(chrono::SecondsFormat::Micros, true));
        let mut grant = GrantNodeImageReader::parse(&serde_json::to_vec(&document)?, true)?;
        grant_node_image_reader(&owner, &grant).await?;
        let backend = PrometheusMetrics::new(native.backend.clone()).await?;
        let server = TlsServer::start(query_app(&fixture, auth, backend)?).await?;
        let endpoint = server.endpoint.clone();
        api = Some(server);
        println!("OPERATOR_IMAGE_CHAIN_READY {}", json!({"runtime_node_id":node,"api_endpoint":endpoint,"grant_id":grant.grant_id}));
        std::io::stdout().flush()?;
        let (mut fresh, mut unknown, mut revoked, mut regranted) = (false, false, false, false);
        for sequence in 1..=8 {
            let request_path = native.control_directory.join(format!("request-{sequence}.json"));
            wait_file(&request_path, deadline).await?;
            let request: Request = read_private(&request_path, 512)?;
            ensure!(request.sequence == sequence);
            let result = async {
                if request.action == Action::Stop {
                    ensure!(fresh && unknown && revoked && regranted, "Incomplete native operator phases");
                    return Ok::<_, anyhow::Error>(json!({"sequence":sequence,"action":request.action,"status":null}));
                }
                let bearer = refreshed_bearer(&identity).await?;
                if request.action == Action::RevokeInflight {
                    ensure!(!revoked);
                    let e = endpoint.clone(); let b = bearer.clone();
                    pending_request = Some(tokio::spawn(async move { https_read(e, node, b).await }));
                    let injection = async {
                        wait_file(&native.control_directory.join("query-held"), deadline).await?;
                        ensure!(private_path(&native.control_directory.join("query-held"), false, 0)?.len() == 0);
                        let revoke = RevokeNodeImageReader::parse(&serde_json::to_vec(&json!({"grant_id":grant.grant_id,"installation_id":grant.installation_id,"cluster_epoch":grant.cluster_epoch,"reason":"Owned native operator in-flight revocation"}))?)?;
                        revoke_node_image_reader(&owner, &revoke).await?;
                        Ok::<(), anyhow::Error>(())
                    }.await;
                    let released = release_query(&native.control_directory);
                    let joined = tokio::time::timeout_at(deadline, pending_request.as_mut().context("In-flight HTTPS request")?).await;
                    let response = match joined { Ok(result) => { pending_request.take(); result? }, Err(error) => return Err(error.into()) };
                    injection?; released?;
                    let (status, body) = response?;
                    ensure!(status == StatusCode::FORBIDDEN && body["code"] == "PERMISSION_DENIED");
                    ensure!(body.get("metrics").is_none() && body.get("inventory").is_none());
                    let output = cli_read(&endpoint, node, &bearer, &native.control_directory, &mut pending_cli).await?;
                    ensure!(!output.status.success() && output.stdout.is_empty());
                    ensure!(String::from_utf8_lossy(&output.stderr).contains("node image API access is forbidden"));
                    revoked = true;
                    return Ok(json!({"sequence":sequence,"action":request.action,"errorCode":"PERMISSION_DENIED"}));
                }
                if request.action == Action::RegrantFresh {
                    ensure!(revoked && !regranted);
                    grant.grant_id = Uuid::new_v4();
                    // The original absolute expiration is preserved.
                    grant_node_image_reader(&owner, &grant).await?;
                    regranted = true;
                } else { ensure!(!revoked || regranted); }
                let (status, body) = https_read(endpoint.clone(), node, bearer.clone()).await?;
                ensure!(status == StatusCode::OK, "Operator phase returned {status}");
                let status: NodeImageStatus = serde_json::from_value(body)?;
                let is_unknown = request.action == Action::Unknown;
                assert_binding(&status, &native, node, &grant)?;
                assert_observation(&status, expected_bytes, is_unknown)?;
                let output = cli_read(&endpoint, node, &bearer, &native.control_directory, &mut pending_cli).await?;
                ensure!(output.status.success(), "Native operator CLI failed");
                let read: NodeImageStatus = serde_json::from_slice(&output.stdout)?;
                assert_binding(&read, &native, node, &grant)?;
                assert_observation(&read, expected_bytes, is_unknown)?;
                fresh |= !is_unknown; unknown |= is_unknown;
                Ok(json!({"sequence":sequence,"action":request.action,"status":status,"cli_status":read}))
            }.await;
            let receipt = match &result { Ok(value) => value.clone(), Err(_) => json!({"sequence":sequence,"action":request.action,"errorCode":"FIXTURE_PHASE_FAILED"}) };
            publish(&native.control_directory, &format!("response-{sequence}.json"), &receipt)?;
            result?;
            if request.action == Action::Stop { return Ok(()); }
        }
        anyhow::bail!("Native operator phases did not stop within eight requests")
    }).await.map_err(anyhow::Error::from).and_then(|value| value);
    // Releasing the fixture proxy is mandatory even when a phase is cancelled.
    let released = release_query(&native.control_directory);
    let request_retired = if let Some(mut request) = pending_request {
        match tokio::time::timeout(Duration::from_secs(2), &mut request).await {
            Ok(_) => Ok(()),
            Err(_) => {
                request.abort();
                let _joined = request.await;
                Err(anyhow::anyhow!(
                    "In-flight HTTPS fixture did not retire within cleanup bound"
                ))
            }
        }
    } else {
        Ok(())
    };
    let cli_retired = if let Some(mut child) = pending_cli {
        let killed = child.start_kill();
        let waited = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
        killed.map_err(anyhow::Error::from).and_then(|_| {
            waited
                .map_err(anyhow::Error::from)?
                .map(|_| ())
                .map_err(anyhow::Error::from)
        })
    } else {
        Ok(())
    };
    let retired = match api {
        Some(server) => server.close().await,
        None => Ok(()),
    };
    let restored = match original_epoch {
        Some(epoch) => {
            sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton")
                .bind(epoch)
                .execute(&fixture.owner)
                .await
                .map(|_| ())
                .map_err(anyhow::Error::from)
        }
        None => Ok(()),
    };
    let cleanup = [released, request_retired, cli_retired, retired, restored]
        .into_iter()
        .collect::<anyhow::Result<Vec<_>>>();
    let outcome = match (outcome, cleanup) {
        (Ok(()), Ok(_)) => Ok(()),
        (Err(error), Ok(_)) => Err(error),
        (Ok(()), Err(error)) => Err(error.context("Native operator cleanup failed")),
        (Err(error), Err(cleanup)) => {
            Err(error.context(format!("Native operator cleanup also failed: {cleanup}")))
        }
    };
    finish_live_fixture(fixture, &identity, outcome).await?;
    println!("OPERATOR_IMAGE_CHAIN_COMPLETE");
    Ok(())
}
