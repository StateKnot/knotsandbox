//! Long-lived native source for the separately owned, internal-network chain.
//! This module exists only in the Linux lib-test artifact. It changes neither
//! the production daemon nor the original isolated native acceptance contract.
use super::*;
use anyhow::{Context, ensure};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use serde::Deserialize;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    process::Stdio,
};
use tokio::{process::Command, task::JoinHandle, time::Instant};

const FIXTURE_BUDGET: Duration = Duration::from_secs(180);
const CLEANUP_RESERVE: Duration = Duration::from_secs(10);
const STOP_FILE: &str = "/tmp/native-image-chain-stop";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    epoch: Uuid,
    node_uid: Uuid,
}

fn bounded_file(path: &Path, limit: u64) -> anyhow::Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(metadata.is_file() && metadata.len() <= limit);
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit);
    Ok(bytes)
}

async fn ctr(arguments: &[&str]) -> anyhow::Result<String> {
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new("/usr/local/bin/ctr")
            .args([
                "--address",
                "/run/containerd/containerd.sock",
                "--namespace",
                "k8s.io",
            ])
            .args(arguments)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("Bounded native ctr command timed out")??;
    ensure!(
        output.stdout.len() <= 64 * 1024 && output.stderr.len() <= 64 * 1024,
        "Bounded native ctr command output exceeded its fixture limit"
    );
    ensure!(output.status.success(), "Native ctr command failed");
    Ok(String::from_utf8(output.stdout)?)
}

struct Running {
    daemon: tokio::process::Child,
    shutdown: CancellationToken,
    server: Option<JoinHandle<std::io::Result<()>>>,
    collector: Option<JoinHandle<Result<(), crate::nodeguard::GuardError>>>,
    journal: Option<GateJournal>,
    images: Option<Arc<ImageObserver>>,
    directory: Option<tempfile::TempDir>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.shutdown.cancel();
        // Preserve ownership on an interrupted/failed fixture too. A stopped
        // child cannot delay container retirement; never signal another PID.
        if let Some(pid) = self.daemon.id()
            && let Ok(pid) = i32::try_from(pid)
        {
            let _ = kill(Pid::from_raw(pid), Signal::SIGCONT);
            let _ = self.daemon.start_kill();
        }
    }
}

impl Running {
    async fn serve(&mut self, identity: Identity, expected: &str) -> anyhow::Result<()> {
        let ready = Instant::now() + Duration::from_secs(15);
        loop {
            ensure!(
                self.daemon.try_wait()?.is_none(),
                "Owned native containerd exited during startup"
            );
            if let Ok(plugins) = ctr(&["plugins", "list"]).await {
                let plugins_ready = [
                    ("io.containerd.cri.v1", "images"),
                    ("io.containerd.snapshotter.v1", "overlayfs"),
                ]
                .into_iter()
                .all(|(kind, name)| {
                    plugins.lines().any(|line| {
                        let fields: Vec<_> = line.split_whitespace().collect();
                        fields.len() >= 3
                            && fields[0] == kind
                            && fields[1] == name
                            && fields.last() == Some(&"ok")
                    })
                });
                if plugins_ready {
                    break;
                }
            }
            ensure!(
                Instant::now() < ready,
                "Native image plugins did not become ready"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let version = ctr(&["version"]).await?;
        let versions: Vec<_> = version
            .lines()
            .filter_map(|line| line.trim().strip_prefix("Version:"))
            .map(|version| version.trim().trim_start_matches('v'))
            .collect();
        ensure!(
            versions == ["2.3.5", "2.3.5"],
            "Exact native containerd client and server are required"
        );
        ensure!(
            ctr(&["images", "list", "--quiet"]).await?.trim().is_empty(),
            "The fixture requires its own initially empty containerd"
        );
        ctr(&["images", "import", "--no-unpack", "/fixture/image.tar"]).await?;

        let profile = PathBuf::from(std::env::var("SANDBOX_NATIVE_IMAGE_PROFILE")?);
        let profile_bytes = bounded_file(&profile, 64 * 1024)?;
        let node = NodeBinding {
            cluster_epoch: identity.epoch,
            node_uid: identity.node_uid,
            node_name: "native-image-chain-fixture".into(),
            boot_id: Uuid::parse_str(
                std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
            )?,
            profile_sha256: hex::encode(Sha256::digest(&profile_bytes)),
        };
        ensure!(node.validate(), "The real host binding must be valid");
        let images = ImageObserver::connect(node.clone(), &profile).await?;
        self.images = Some(images.clone());
        self.directory = Some(tempfile::tempdir()?);
        let directory = self
            .directory
            .as_ref()
            .context("Owned fixture journal directory")?;
        let journal =
            GateJournal::open(&directory.path().join("journal.sqlite3"), node.clone()).await?;
        self.journal = Some(journal.clone());
        journal.verify_coverage().await?;
        let proxy = Arc::new(CriProxy {
            journal,
            observer: Arc::new(HostObserver::test_unobserved(node.clone())),
            upstream:
                crate::nodeguard::cri_proto::runtime_service_client::RuntimeServiceClient::new(
                    tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
                ),
            tasks: tokio_util::task::TaskTracker::new(),
            read_shutdown: CancellationToken::new(),
        });
        let app = router(proxy, "native-chain".into(), Some(images.clone()))?;
        let tls = crate::tls::metrics_mutual_tls(
            &bounded_file(Path::new("/fixture/chain/server.pem"), 64 * 1024)?,
            &bounded_file(Path::new("/fixture/chain/server.key"), 64 * 1024)?,
            &bounded_file(Path::new("/fixture/chain/scraper-ca.pem"), 64 * 1024)?,
        )?;
        let listener = tokio::net::TcpListener::bind("0.0.0.0:9445").await?;
        self.server = Some(tokio::spawn(crate::tls::serve_metrics(
            listener,
            tls,
            app,
            self.shutdown.clone(),
        )));
        self.collector = Some(tokio::spawn(images.clone().run(self.shutdown.clone())));
        loop {
            self.require_running()?;
            let status = images.status();
            if status.inventory.observation_success && status.filesystems.observation_success {
                ensure!(status.enabled);
                ensure!(status.inventory.image_count.as_deref() == Some("1"));
                ensure!(status.inventory.compressed_logical_bytes.as_deref() == Some(expected));
                ensure!(
                    !status.filesystems.entries.is_empty()
                        && status.filesystems.entries.len() <= 16
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let pid = self.daemon.id().context("Owned native containerd PID")?;
        ensure!(pid > 1, "Native containerd must be an owned non-PID1 child");
        println!(
            "NATIVE_IMAGE_CHAIN_READY {}",
            serde_json::to_string(&serde_json::json!({
                "node": node,
                "runtime_pid": pid,
                "metrics_port": 9445,
                "expected_compressed_logical_bytes": expected,
            }))?
        );
        std::io::stdout().flush()?;
        loop {
            self.require_running()?;
            match std::fs::symlink_metadata(STOP_FILE) {
                Ok(metadata) => {
                    ensure!(
                        metadata.is_file() && metadata.len() == 0,
                        "The fixed stop marker must be a regular empty file"
                    );
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let check = ctr(&["images", "check"]).await?;
        let rows: Vec<_> = check.lines().skip(1).collect();
        ensure!(!rows.is_empty() && rows.iter().all(|row| row.trim_end().ends_with(" false")));
        for kind in ["snapshots", "containers", "tasks"] {
            ensure!(
                ctr(&[kind, "list"]).await?.trim().lines().count() <= 1,
                "The native image chain must never unpack or execute a workload"
            );
        }
        Ok(())
    }

    fn require_running(&mut self) -> anyhow::Result<()> {
        ensure!(
            self.daemon.try_wait()?.is_none(),
            "Owned native containerd exited"
        );
        ensure!(
            self.server.as_ref().is_some_and(|task| !task.is_finished())
                && self
                    .collector
                    .as_ref()
                    .is_some_and(|task| !task.is_finished()),
            "The genuine native collector and mTLS listener must remain live"
        );
        Ok(())
    }

    async fn retire(&mut self) -> anyhow::Result<()> {
        self.shutdown.cancel();
        // The fault injector may have stopped the exact owned peer. Resume it
        // before draining CRI ownership as well as before killing/reaping it.
        let continued = self
            .daemon
            .id()
            .map(i32::try_from)
            .transpose()?
            .map(|pid| kill(Pid::from_raw(pid), Signal::SIGCONT));
        let server = self.server.take();
        let collector = self.collector.take();
        let (served, collected) = tokio::join!(
            async {
                if let Some(task) = server {
                    task.await??;
                }
                Ok::<_, anyhow::Error>(())
            },
            async {
                if let Some(task) = collector {
                    task.await??;
                }
                Ok::<_, anyhow::Error>(())
            },
        );
        if let Some(journal) = self.journal.take() {
            journal.shutdown().await;
        }
        let mut retirement_error = None;
        if self.daemon.try_wait()?.is_some() {
            retirement_error = Some(anyhow::anyhow!(
                "Owned native daemon exited before retirement"
            ));
        } else {
            let pid = i32::try_from(self.daemon.id().context("Owned native daemon PID")?)?;
            if let Err(error) = kill(Pid::from_raw(pid), Signal::SIGCONT) {
                retirement_error = Some(error.into());
            }
            let killed = self.daemon.start_kill();
            let waited = self.daemon.wait().await;
            if let Err(error) = killed {
                retirement_error = Some(error.into());
            }
            if let Err(error) = waited {
                retirement_error = Some(error.into());
            }
        }
        served?;
        collected?;
        if let Some(result) = continued {
            result?;
        }
        if let Some(error) = retirement_error {
            return Err(error);
        }
        if let Some(images) = &self.images {
            let stopped = images.status();
            ensure!(
                !stopped.inventory.observation_success && stopped.inventory.image_count.is_none()
            );
            ensure!(
                !stopped.filesystems.observation_success && stopped.filesystems.entries.is_empty()
            );
        }
        Ok(())
    }
}

#[tokio::test]
#[ignore = "Requires its exact owned Linux containerd, immutable chain PKI and bounded internal Docker network"]
async fn native_image_chain_service_fixture() -> anyhow::Result<()> {
    let deadline = Instant::now() + FIXTURE_BUDGET;
    ensure!(
        matches!(std::fs::symlink_metadata(STOP_FILE), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
        "A pre-existing stop marker cannot complete this fixture"
    );
    let identity: Identity = serde_json::from_slice(&bounded_file(
        Path::new("/fixture/chain/identity.json"),
        1024,
    )?)?;
    ensure!(!identity.epoch.is_nil() && !identity.node_uid.is_nil());
    let expected = std::env::var("SANDBOX_NATIVE_IMAGE_LOGICAL_BYTES")?;
    ensure!(
        expected
            .parse::<u64>()
            .is_ok_and(|value| value > 0 && value.to_string() == expected),
        "An independent positive canonical OCI logical byte expectation is required"
    );
    let daemon = Command::new("/usr/local/bin/containerd")
        .args(["--config=/etc/containerd/config.toml", "--log-level=error"])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let mut running = Running {
        daemon,
        shutdown: CancellationToken::new(),
        server: None,
        collector: None,
        journal: None,
        images: None,
        directory: None,
    };
    // Cleanup is inside the same fixed 180-second budget. No production RPC,
    // collection, TLS, shutdown or thread-stack limit is extended for the test.
    let outcome = tokio::time::timeout_at(
        deadline - CLEANUP_RESERVE,
        running.serve(identity, &expected),
    )
    .await
    .context("Native image chain exceeded its fixed service budget")
    .and_then(|result| result);
    let retired = tokio::time::timeout_at(deadline, running.retire())
        .await
        .context("Native image chain could not retire inside its fixed total budget")
        .and_then(|result| result);
    outcome?;
    retired?;
    println!("NATIVE_IMAGE_CHAIN_COMPLETE");
    std::io::stdout().flush()?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires the exact owned non-root sidecar and genuine HTTPS receiver on the internal chain network"]
async fn native_image_chain_receiver_query() -> anyhow::Result<()> {
    use base64::Engine;

    let path = std::env::var("SANDBOX_NATIVE_CHAIN_QUERY_PATH")?;
    ensure!(matches!(path.as_str(), "/-/ready" | "/api/v1/query"));
    let form = std::env::var("SANDBOX_NATIVE_CHAIN_QUERY_FORM").ok();
    if path == "/-/ready" {
        ensure!(form.is_none(), "The fixed readiness request is GET only");
    } else {
        let body = form.as_ref().context("Fixed query form required")?;
        ensure!(!body.is_empty() && body.len() <= 64 * 1024);
        ensure!(
            !body.contains('\0')
                && url::form_urlencoded::parse(body.as_bytes())
                    .next()
                    .is_some()
        );
    }
    let ca = bounded_file(Path::new("/fixture/chain/server-ca.pem"), 64 * 1024)?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .http1_only()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(5))
        .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
        .build()?;
    let endpoint = format!("https://receiver:9090{path}");
    let request = if let Some(form) = form {
        client
            .post(endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form)
    } else {
        client.get(endpoint)
    };
    let mut response = request
        .basic_auth("reader", Some("PUBLIC_CHAIN_READER"))
        .send()
        .await?;
    let status = response.status().as_u16();
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= 256 * 1024)
    );
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            body.len()
                .checked_add(chunk.len())
                .is_some_and(|length| length <= 256 * 1024)
        );
        body.extend_from_slice(&chunk);
    }
    println!(
        "NATIVE_IMAGE_RECEIVER_RESPONSE {}",
        serde_json::to_string(&serde_json::json!({
            "status": status,
            "body_base64": base64::engine::general_purpose::STANDARD.encode(body),
        }))?
    );
    std::io::stdout().flush()?;
    Ok(())
}
