//! Native containerd acceptance runs inside a disposable, isolated container.
//! The fixture does not enroll a production node or execute a sandbox/VM.
use super::*;
use crate::nodeguard::{host::HostObserver, journal::GateJournal, protocol::NodeBinding};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[tokio::test]
#[ignore = "Requires the exact isolated containerd 2.3.5 fixture and native Linux filesystem"]
async fn native_containerd_inventory_status_is_scraper_only_without_vms() -> anyhow::Result<()> {
    let profile = PathBuf::from(std::env::var("SANDBOX_NATIVE_IMAGE_PROFILE")?);
    let profile_bytes = std::fs::read(&profile)?;
    let expected_bytes = std::env::var("SANDBOX_NATIVE_IMAGE_LOGICAL_BYTES")?;
    anyhow::ensure!(
        expected_bytes.parse::<u64>()? > 0,
        "the independent OCI fixture must contain real nonempty image content"
    );
    let node = NodeBinding {
        cluster_epoch: Uuid::new_v4(),
        node_uid: Uuid::new_v4(),
        node_name: "native-image-fixture".into(),
        boot_id: Uuid::parse_str(
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        )?,
        profile_sha256: hex::encode(Sha256::digest(&profile_bytes)),
    };
    let images = ImageObserver::connect(node.clone(), &profile).await?;
    let directory = tempfile::tempdir()?;
    let journal =
        GateJournal::open(&directory.path().join("journal.sqlite3"), node.clone()).await?;
    journal.verify_coverage().await?;
    let proxy = Arc::new(CriProxy {
        journal: journal.clone(),
        observer: Arc::new(HostObserver::test_unobserved(node.clone())),
        upstream: crate::nodeguard::cri_proto::runtime_service_client::RuntimeServiceClient::new(
            tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
        ),
        tasks: tokio_util::task::TaskTracker::new(),
        read_shutdown: CancellationToken::new(),
    });
    let app = router(proxy, "native-fixture".into(), Some(images.clone()))?;
    let tls = crate::tls::metrics_mutual_tls(
        include_bytes!("../../tests/fixtures/admission/server.pem"),
        include_bytes!("../../tests/fixtures/admission/server.key"),
        include_bytes!("../../tests/fixtures/admission/apiserver-ca.pem"),
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let shutdown = CancellationToken::new();
    let server = tokio::spawn(crate::tls::serve_metrics(
        listener,
        tls,
        app,
        shutdown.clone(),
    ));
    let collector = tokio::spawn(images.clone().run(shutdown.clone()));
    let started = Utc::now();
    let outcome = async {
        let anonymous = super::tests::client(None)?;
        let controller = super::tests::client(Some((
            include_bytes!("../../tests/fixtures/nodeguard/client.pem"),
            include_bytes!("../../tests/fixtures/nodeguard/client.key"),
        )))?;
        let scraper = super::tests::client(Some((
            include_bytes!("../../tests/fixtures/admission/apiserver.pem"),
            include_bytes!("../../tests/fixtures/admission/apiserver.key"),
        )))?;
        let url = format!("https://{address}/v1/node-image-status");
        anyhow::ensure!(anonymous.get(&url).send().await.is_err());
        anyhow::ensure!(controller.get(&url).send().await.is_err());
        let body = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let response = scraper.get(&url).send().await?;
                anyhow::ensure!(response.status() == StatusCode::OK);
                anyhow::ensure!(response.headers()["cache-control"] == "no-store");
                let bytes = response.bytes().await?;
                anyhow::ensure!(bytes.len() <= 64 * 1024);
                let body: serde_json::Value = serde_json::from_slice(&bytes)?;
                if body["inventory"]["observation_success"] == true {
                    return Ok::<_, anyhow::Error>(body);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await??;
        anyhow::ensure!(body["enabled"] == true);
        anyhow::ensure!(body["source"] == "RUNTIME_REPORTED");
        anyhow::ensure!(body["completeness"] == "UNKNOWN");
        anyhow::ensure!(body["node"] == serde_json::to_value(&node)?);
        anyhow::ensure!(body["inventory"]["image_count"] == "1");
        anyhow::ensure!(body["inventory"]["compressed_logical_bytes"] == expected_bytes);
        let observed = chrono::DateTime::parse_from_rfc3339(
            body["observed_at"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("observation timestamp"))?,
        )?;
        anyhow::ensure!(observed >= started - chrono::Duration::seconds(1));
        anyhow::ensure!(body["filesystems"]["observation_success"] == true);
        let filesystems = body["filesystems"]["entries"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("native filesystem observation"))?;
        anyhow::ensure!(!filesystems.is_empty() && filesystems.len() <= 16);
        for filesystem in filesystems {
            anyhow::ensure!(
                filesystem["filesystem_id"]
                    .as_str()
                    .is_some_and(|v| v.len() == 64)
            );
            anyhow::ensure!(
                filesystem["runtime_reported_at_ns"]
                    .as_str()
                    .is_some_and(|v| v.parse::<i64>().is_ok_and(|v| v > 0))
            );
        }
        let text = body.to_string();
        for forbidden in [
            "/var/lib/",
            "fixture.invalid",
            "example.invalid",
            "sha256:",
            "repo_tags",
            "repo_digests",
            "capacity_bytes",
            "available_bytes",
            "reclaimable_bytes",
        ] {
            anyhow::ensure!(
                !text.contains(forbidden),
                "host status leaked a path/name or asserted unmeasured capacity"
            );
        }
        let vm = scraper
            .get(format!("https://{address}/metrics"))
            .send()
            .await?;
        anyhow::ensure!(vm.status() == StatusCode::OK);
        let vm = vm.text().await?;
        anyhow::ensure!(!vm.contains("sandbox_vm_observation_success{"));
        anyhow::ensure!(!vm.contains("sandbox_vm_memory_bytes{"));
        anyhow::ensure!(
            !vm.contains("sandbox_node_image_"),
            "P0b is not implemented; do not emit unconsumed node samples"
        );
        anyhow::ensure!(
            scraper.post(&url).send().await?.status() == StatusCode::METHOD_NOT_ALLOWED
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    shutdown.cancel();
    let (served, collected) = tokio::join!(server, collector);
    let retired = (|| -> anyhow::Result<()> {
        served??;
        collected??;
        let stopped = images.status();
        anyhow::ensure!(
            !stopped.inventory.observation_success && stopped.inventory.image_count.is_none()
        );
        anyhow::ensure!(
            !stopped.filesystems.observation_success && stopped.filesystems.entries.is_empty()
        );
        Ok(())
    })();
    journal.shutdown().await;
    outcome?;
    retired?;
    println!("NODEGUARD_NATIVE_IMAGE_OBSERVATION_SCRAPER_ONLY_VERIFIED");
    Ok(())
}
