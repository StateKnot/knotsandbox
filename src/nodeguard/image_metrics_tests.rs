use super::*;
use crate::nodeguard::image_observation::{
    FilesystemObservation, FilesystemStatus, InventoryStatus,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

fn report() -> anyhow::Result<ImageObservationStatus> {
    Ok(ImageObservationStatus {
        enabled: true,
        node: NodeBinding {
            cluster_epoch: Uuid::from_u128(1),
            node_uid: Uuid::from_u128(2),
            node_name: "image-metrics-fixture".into(),
            boot_id: Uuid::from_u128(3),
            profile_sha256: "a".repeat(64),
        },
        source: ObservationSource::RuntimeReported,
        completeness: Completeness::Unknown,
        observed_at: Some(
            DateTime::<Utc>::from_timestamp(1_700_000_000, 123_456_789)
                .ok_or_else(|| anyhow::anyhow!("fixture timestamp"))?,
        ),
        filesystem_report_scope: "RUNTIME_SNAPSHOTSTORE_REPORTED_USAGE",
        inventory_report_scope: "CRI_INDEX_COMPRESSED_LOGICAL",
        inventory: InventoryStatus {
            observation_success: true,
            image_count: Some("1".into()),
            compressed_logical_bytes: Some("9007199254740993".into()),
        },
        filesystems: FilesystemStatus {
            observation_success: true,
            entries: vec![FilesystemObservation {
                filesystem_id: "b".repeat(64),
                runtime_reported_at_ns: "1699999999123456789".into(),
                used_bytes: Some("42".into()),
                inodes_used: None,
            }],
        },
    })
}

fn samples(text: &str) -> Vec<&str> {
    text.lines().filter(|line| !line.starts_with('#')).collect()
}

#[test]
fn bounded_exposition_preserves_original_times_and_explicitly_approximates_large_integers()
-> anyhow::Result<()> {
    let mut status = report()?;
    let text = encode_node_image_metrics(&status, &status.node, "fixture")?;
    assert_eq!(samples(&text).len(), 7);
    for (name, value) in [
        ("sandbox_node_image_inventory_count", "1"),
        (
            "sandbox_node_image_compressed_logical_bytes",
            "9007199254740992",
        ),
        (
            "sandbox_node_image_observed_at_seconds",
            "1700000000.123456789",
        ),
        (
            "sandbox_node_image_filesystem_reported_at_seconds",
            "1699999999.123456789",
        ),
        ("sandbox_node_image_filesystem_used_bytes", "42"),
    ] {
        assert!(samples(&text).iter().any(|line| {
            line.starts_with(&format!("{name}{{")) && line.ends_with(&format!(" {value}"))
        }));
    }
    assert!(
        !text
            .lines()
            .any(|line| line.starts_with("sandbox_node_image_filesystem_inodes_used{"))
    );
    assert!(text.contains("approximate f64 gauge"));
    assert_eq!(
        serde_json::to_value(&status)?["inventory"]["compressed_logical_bytes"],
        "9007199254740993",
        "Prometheus approximation must not change the exact diagnostic value"
    );
    assert!(
        samples(&text)
            .iter()
            .all(|line| line.split_whitespace().count() == 2)
    );

    // Failure of one report must not suppress the other or invent zero values.
    status.filesystems.observation_success = false;
    let text = encode_node_image_metrics(&status, &status.node, "fixture")?;
    assert_eq!(samples(&text).len(), 5);
    assert!(
        !text
            .lines()
            .any(|line| line.starts_with("sandbox_node_image_filesystem_used_bytes{"))
    );
    status.inventory.observation_success = false;
    status.filesystems.observation_success = true;
    let text = encode_node_image_metrics(&status, &status.node, "fixture")?;
    assert_eq!(samples(&text).len(), 5);
    assert!(
        !text
            .lines()
            .any(|line| line.starts_with("sandbox_node_image_inventory_count{"))
    );
    status.filesystems.observation_success = false;
    let text = encode_node_image_metrics(&status, &status.node, "fixture")?;
    assert_eq!(samples(&text).len(), 2);
    assert!(samples(&text).iter().all(|line| line.ends_with(" 0")));
    Ok(())
}

#[test]
fn sixteen_filesystems_fit_fifty_three_samples_and_larger_or_duplicate_sets_are_rejected()
-> anyhow::Result<()> {
    let mut status = report()?;
    status.filesystems.entries = (1..=16)
        .map(|index| FilesystemObservation {
            filesystem_id: format!("{index:064x}"),
            runtime_reported_at_ns: "1700000000000000001".into(),
            used_bytes: Some("18446744073709551615".into()),
            inodes_used: Some("1".into()),
        })
        .collect();
    let text = encode_node_image_metrics(&status, &status.node, &"d".repeat(63))?;
    assert_eq!(samples(&text).len(), 53);
    assert!(text.len() <= 64 * 1024);
    let entry = status.filesystems.entries[0].clone();
    status.filesystems.entries.push(entry);
    assert!(encode_node_image_metrics(&status, &status.node, "fixture").is_err());
    let _ = status.filesystems.entries.pop();
    status.filesystems.entries[1] = status.filesystems.entries[0].clone();
    assert!(encode_node_image_metrics(&status, &status.node, "fixture").is_err());
    Ok(())
}

#[test]
fn crossed_node_unbounded_labels_and_invalid_success_quantities_fail_closed() -> anyhow::Result<()>
{
    let status = report()?;
    let mut other_node = status.node.clone();
    other_node.boot_id = Uuid::from_u128(4);
    assert!(encode_node_image_metrics(&status, &other_node, "fixture").is_err());
    for deployment in ["bad\"label", "", &"d".repeat(64)] {
        assert!(encode_node_image_metrics(&status, &status.node, deployment).is_err());
    }
    for value in ["18446744073709551616", "01", "+1", "-1", "NaN", ""] {
        let mut invalid = status.clone();
        invalid.inventory.compressed_logical_bytes = Some(value.into());
        assert!(encode_node_image_metrics(&invalid, &invalid.node, "fixture").is_err());
    }
    let mut invalid = status.clone();
    invalid.filesystems.entries[0].filesystem_id = "/var/lib/private".into();
    assert!(encode_node_image_metrics(&invalid, &invalid.node, "fixture").is_err());
    invalid = status.clone();
    invalid.observed_at = None;
    assert!(encode_node_image_metrics(&invalid, &invalid.node, "fixture").is_err());
    invalid = status;
    invalid.enabled = false;
    assert!(encode_node_image_metrics(&invalid, &invalid.node, "fixture").is_err());
    Ok(())
}
