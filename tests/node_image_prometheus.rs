//! Invoked only by scripts/test-node-image-query.py against its owned Prometheus.
use std::{env, fs, os::unix::fs::PermissionsExt};

use anyhow::{Context, ensure};
use sandbox_platform::metrics::{
    MetricsBackendConfig, NodeImageAccuracy, NodeImageCompleteness, NodeImageMetricBinding,
    NodeImageMetricSource, PrometheusMetrics,
};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    backend: MetricsBackendConfig,
    binding: Binding,
    expected_mode: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    cluster_epoch: Uuid,
    node_uid: Uuid,
    host_boot_id: Uuid,
    profile_sha256: String,
}

#[tokio::test]
#[ignore = "Owned, pinned real Prometheus and HTTPS proxy required; use the Python runner"]
async fn node_image_public_query_through_real_prometheus() -> anyhow::Result<()> {
    let path = env::var_os("SANDBOX_NODE_IMAGE_QUERY_FIXTURE").context("Fixture path")?;
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(metadata.is_file() && metadata.len() <= 16384);
    ensure!(metadata.permissions().mode() & 0o7777 == 0o600);
    let fixture: Fixture = serde_json::from_slice(&fs::read(path)?)?;
    let binding = NodeImageMetricBinding {
        cluster_epoch: fixture.binding.cluster_epoch,
        node_uid: fixture.binding.node_uid,
        host_boot_id: fixture.binding.host_boot_id,
        profile_sha256: fixture.binding.profile_sha256,
    };
    let backend = PrometheusMetrics::new(fixture.backend).await?;
    let status = backend.node_image_status(&binding).await?;
    ensure!(status.source == NodeImageMetricSource::RuntimeReported);
    ensure!(status.completeness == NodeImageCompleteness::Unknown);
    ensure!(status.accuracy == NodeImageAccuracy::ApproximateF64);
    println!(
        "NODE_IMAGE_PROMETHEUS_RESULT {}",
        serde_json::to_string(&status)?
    );
    match fixture.expected_mode.as_str() {
        "fresh" => {
            ensure!(status.inventory_observation_success == Some(true));
            ensure!(status.filesystem_observation_success == Some(true));
            let inventory = status
                .inventory
                .context("All inventory gauges must survive real PromQL union")?;
            let filesystem = status.filesystem.context("Filesystem observation")?;
            ensure!(inventory.collector_replica == filesystem.collector_replica);
            ensure!(inventory.scraped_at_seconds == filesystem.scraped_at_seconds);
            ensure!(inventory.observed_at_seconds == filesystem.observed_at_seconds);
            ensure!(
                (0.0..60.0)
                    .contains(&(status.evaluated_at_seconds - inventory.observed_at_seconds))
            );
            ensure!(filesystem.filesystems.len() == 1);
            let report = &filesystem.filesystems[0];
            ensure!(report.reported_at_seconds == inventory.observed_at_seconds - 1.0);
            let expected = match inventory.collector_replica.as_str() {
                "a" => (7.0, 200.0, "a".repeat(64), Some(700.0), Some(3.0)),
                "b" => (9.0, 100.0, "b".repeat(64), Some(900.0), Some(5.0)),
                _ => anyhow::bail!("Unconfigured replica"),
            };
            ensure!(
                (
                    inventory.count,
                    inventory.compressed_logical_bytes,
                    report.filesystem_id.clone(),
                    report.used_bytes,
                    report.inodes_used
                ) == expected,
                "HA must preserve one entire tuple without summing or mixing fields"
            );
        }
        "latest_zero" | "stale" | "absent" => {
            let expected = match fixture.expected_mode.as_str() {
                "latest_zero" => Some(false),
                "stale" => Some(true),
                _ => None,
            };
            ensure!(status.inventory_observation_success == expected);
            ensure!(status.filesystem_observation_success == expected);
            ensure!(
                status.inventory.is_none() && status.filesystem.is_none(),
                "Unknown/stale observations must clear old quantities"
            );
        }
        _ => anyhow::bail!("Unreviewed fixture mode"),
    }
    println!(
        "NODE_IMAGE_PROMETHEUS_QUERY_VERIFIED {}",
        fixture.expected_mode
    );
    Ok(())
}
