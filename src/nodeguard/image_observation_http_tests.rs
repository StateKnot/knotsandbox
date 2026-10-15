//! Native containerd acceptance runs inside a disposable, isolated container.
//! The fixture does not enroll a production node or execute a sandbox/VM.
use super::*;
use crate::nodeguard::{host::HostObserver, journal::GateJournal, protocol::NodeBinding};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::PathBuf};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[cfg(target_os = "linux")]
#[path = "image_chain_fixture.rs"]
mod chain;

fn assert_node_image_metric_contract(
    text: &str,
    node: &NodeBinding,
    deployment: &str,
    filesystem_ids: &BTreeSet<&str>,
) -> anyhow::Result<()> {
    anyhow::ensure!(text.len() <= 64 * 1024);
    let mut seen = BTreeSet::new();
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        let (series, value) = line
            .rsplit_once(' ')
            .ok_or_else(|| anyhow::anyhow!("metric sample"))?;
        let value = value.parse::<f64>()?;
        anyhow::ensure!(value.is_finite() && value >= 0.0);
        let (name, labels) = series
            .strip_suffix('}')
            .and_then(|series| series.split_once('{'))
            .ok_or_else(|| anyhow::anyhow!("fixed labels without an explicit sample timestamp"))?;
        anyhow::ensure!(matches!(
            name,
            "sandbox_node_image_inventory_observation_success"
                | "sandbox_node_image_filesystem_observation_success"
                | "sandbox_node_image_observed_at_seconds"
                | "sandbox_node_image_inventory_count"
                | "sandbox_node_image_compressed_logical_bytes"
                | "sandbox_node_image_filesystem_reported_at_seconds"
                | "sandbox_node_image_filesystem_used_bytes"
                | "sandbox_node_image_filesystem_inodes_used"
        ));
        anyhow::ensure!(seen.insert(series), "duplicate node metric identity");
        let mut values = BTreeMap::new();
        for label in labels.split(',') {
            let (key, value) = label
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("metric label"))?;
            let value = value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .ok_or_else(|| anyhow::anyhow!("quoted label"))?;
            anyhow::ensure!(
                values.insert(key, value).is_none(),
                "duplicate metric label"
            );
        }
        for (key, value) in [
            ("deployment", deployment.to_owned()),
            ("cluster_epoch", node.cluster_epoch.to_string()),
            ("node_uid", node.node_uid.to_string()),
            ("host_boot_id", node.boot_id.to_string()),
            ("profile_sha256", node.profile_sha256.clone()),
            ("source", "RUNTIME_REPORTED".into()),
            ("completeness", "UNKNOWN".into()),
        ] {
            anyhow::ensure!(
                values.remove(key) == Some(value.as_str()),
                "node label binding"
            );
        }
        if matches!(
            name,
            "sandbox_node_image_filesystem_reported_at_seconds"
                | "sandbox_node_image_filesystem_used_bytes"
                | "sandbox_node_image_filesystem_inodes_used"
        ) {
            let id = values
                .remove("filesystem_id")
                .ok_or_else(|| anyhow::anyhow!("filesystem label"))?;
            anyhow::ensure!(crate::nodeguard::protocol::valid_sha256(id));
            anyhow::ensure!(
                filesystem_ids.contains(id),
                "unexpected filesystem identity"
            );
        }
        anyhow::ensure!(values.is_empty(), "unexpected node metric label");
    }
    anyhow::ensure!(seen.len() <= 53);
    Ok(())
}

fn node_image_metric_value(
    text: &str,
    name: &str,
    filesystem: Option<&str>,
) -> anyhow::Result<Option<f64>> {
    let mut found = None;
    for line in text
        .lines()
        .filter(|line| line.starts_with(&format!("{name}{{")))
    {
        if filesystem.is_some_and(|id| !line.contains(&format!("filesystem_id=\"{id}\""))) {
            continue;
        }
        anyhow::ensure!(found.is_none(), "duplicate metric sample");
        found = Some(
            line.rsplit_once(' ')
                .ok_or_else(|| anyhow::anyhow!("metric value"))?
                .1
                .parse()?,
        );
    }
    Ok(found)
}

#[tokio::test]
async fn node_image_metrics_unknown_is_scraper_only_and_available_without_vms() -> anyhow::Result<()>
{
    let node = NodeBinding {
        cluster_epoch: Uuid::new_v4(),
        node_uid: Uuid::new_v4(),
        node_name: "image-metrics-fixture".into(),
        boot_id: Uuid::new_v4(),
        profile_sha256: "a".repeat(64),
    };
    let images = ImageObserver::disabled(node.clone());
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
    let mut other_node = node.clone();
    other_node.boot_id = Uuid::new_v4();
    let app = router(proxy.clone(), "metrics-fixture".into(), Some(images))?.nest(
        "/crossed",
        router(
            proxy,
            "metrics-fixture".into(),
            Some(ImageObserver::disabled(other_node)),
        )?,
    );
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
        let url = format!("https://{address}/metrics/node-images");
        anyhow::ensure!(anonymous.get(&url).send().await.is_err());
        anyhow::ensure!(controller.get(&url).send().await.is_err());
        let response = scraper.get(&url).send().await?;
        anyhow::ensure!(
            response.status() == StatusCode::OK,
            "node image metrics must be available without any VM, including UNKNOWN observations; got {}",
            response.status()
        );
        anyhow::ensure!(response.headers()["cache-control"] == "no-store");
        anyhow::ensure!(
            response.headers()["content-type"] == "text/plain; version=0.0.4; charset=utf-8"
        );
        let text = response.text().await?;
        assert_node_image_metric_contract(&text, &node, "metrics-fixture", &BTreeSet::new())?;
        let samples: Vec<_> = text.lines().filter(|line| !line.starts_with('#')).collect();
        anyhow::ensure!(samples.len() == 2, "UNKNOWN must not become zero quantities");
        for metric in [
            "sandbox_node_image_inventory_observation_success",
            "sandbox_node_image_filesystem_observation_success",
        ] {
            anyhow::ensure!(samples.iter().any(|line| {
                line.starts_with(&format!("{metric}{{")) && line.ends_with(" 0")
            }));
        }
        for label in [
            "deployment=\"metrics-fixture\"".into(),
            format!("cluster_epoch=\"{}\"", node.cluster_epoch),
            format!("node_uid=\"{}\"", node.node_uid),
            format!("host_boot_id=\"{}\"", node.boot_id),
            format!("profile_sha256=\"{}\"", node.profile_sha256),
            "source=\"RUNTIME_REPORTED\"".into(),
            "completeness=\"UNKNOWN\"".into(),
        ] {
            anyhow::ensure!(samples.iter().all(|line| line.contains(&label)));
        }
        anyhow::ensure!(
            scraper.post(&url).send().await?.status() == StatusCode::METHOD_NOT_ALLOWED
        );
        let crossed = scraper
            .get(format!("https://{address}/crossed/metrics/node-images"))
            .send()
            .await?;
        anyhow::ensure!(crossed.status() == StatusCode::SERVICE_UNAVAILABLE);
        anyhow::ensure!(!crossed.text().await?.contains("sandbox_node_image_"));
        let vm = scraper
            .get(format!("https://{address}/metrics"))
            .send()
            .await?;
        anyhow::ensure!(vm.status() == StatusCode::OK);
        let vm = vm.text().await?;
        anyhow::ensure!(!vm.contains("sandbox_node_image_"));
        anyhow::ensure!(!vm.contains("sandbox_vm_observation_success{"));
        // The node cache remains independently readable when the VM scrape's
        // real journal dependency is unavailable; it must not query that pool.
        journal.clone().shutdown().await;
        anyhow::ensure!(scraper.get(&url).send().await?.status() == StatusCode::OK);
        anyhow::ensure!(
            scraper.get(format!("https://{address}/metrics")).send().await?.status()
                == StatusCode::SERVICE_UNAVAILABLE
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    shutdown.cancel();
    let served = server.await;
    journal.shutdown().await;
    outcome?;
    served??;
    Ok(())
}

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
            "node samples belong to their independent route, never the VM scrape"
        );
        let metrics_url = format!("https://{address}/metrics/node-images");
        anyhow::ensure!(anonymous.get(&metrics_url).send().await.is_err());
        anyhow::ensure!(controller.get(&metrics_url).send().await.is_err());
        let response = scraper.get(&metrics_url).send().await?;
        anyhow::ensure!(response.status() == StatusCode::OK);
        anyhow::ensure!(response.headers()["cache-control"] == "no-store");
        anyhow::ensure!(
            response.headers()["content-type"] == "text/plain; version=0.0.4; charset=utf-8"
        );
        let metrics = response.text().await?;
        let filesystem_ids = filesystems
            .iter()
            .map(|filesystem| {
                filesystem["filesystem_id"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("filesystem identity"))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        assert_node_image_metric_contract(&metrics, &node, "native-fixture", &filesystem_ids)?;
        for name in [
            "sandbox_node_image_inventory_observation_success",
            "sandbox_node_image_filesystem_observation_success",
        ] {
            anyhow::ensure!(node_image_metric_value(&metrics, name, None)? == Some(1.0));
        }
        anyhow::ensure!(
            node_image_metric_value(&metrics, "sandbox_node_image_inventory_count", None)?
                == Some(1.0)
        );
        anyhow::ensure!(
            node_image_metric_value(
                &metrics,
                "sandbox_node_image_compressed_logical_bytes",
                None
            )? == Some(expected_bytes.parse::<u64>()? as f64)
        );
        let observed_seconds =
            node_image_metric_value(&metrics, "sandbox_node_image_observed_at_seconds", None)?
                .ok_or_else(|| anyhow::anyhow!("node observation time"))?;
        let expected_seconds =
            observed.timestamp() as f64 + f64::from(observed.timestamp_subsec_nanos()) / 1e9;
        anyhow::ensure!((observed_seconds - expected_seconds).abs() < 0.000001);
        for filesystem in filesystems {
            let id = filesystem["filesystem_id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("filesystem identity"))?;
            let nanoseconds = filesystem["runtime_reported_at_ns"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("runtime timestamp"))?
                .parse::<i64>()?;
            let reported = node_image_metric_value(
                &metrics,
                "sandbox_node_image_filesystem_reported_at_seconds",
                Some(id),
            )?
            .ok_or_else(|| anyhow::anyhow!("filesystem observation time"))?;
            anyhow::ensure!((reported - nanoseconds as f64 / 1e9).abs() < 0.000001);
            for (field, name) in [
                ("used_bytes", "sandbox_node_image_filesystem_used_bytes"),
                ("inodes_used", "sandbox_node_image_filesystem_inodes_used"),
            ] {
                let exact = filesystem[field]
                    .as_str()
                    .map(str::parse::<u64>)
                    .transpose()?;
                anyhow::ensure!(
                    node_image_metric_value(&metrics, name, Some(id))?
                        == exact.map(|value| value as f64)
                );
            }
        }
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
                !metrics.contains(forbidden),
                "node metrics leaked a path/name or asserted unmeasured capacity"
            );
        }
        anyhow::ensure!(
            scraper.post(&metrics_url).send().await?.status() == StatusCode::METHOD_NOT_ALLOWED
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
