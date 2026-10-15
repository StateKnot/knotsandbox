//! Bounded Prometheus view of the host image observation cache. Quantities in
//! this view are approximate f64 gauges; the diagnostic JSON's decimal strings
//! remain authoritative. Neither report establishes physical storage capacity
//! or a preparation budget.
use super::{
    GuardError,
    image_observation::{
        Completeness, ImageObservationStatus, MAX_FILESYSTEMS, MAX_IMAGES, ObservationSource,
    },
    protocol::{NodeBinding, valid_sha256},
};
use std::{collections::BTreeSet, fmt::Write};

pub(super) const MAX_NODE_IMAGE_BODY_BYTES: usize = 64 * 1024;
pub(super) const MAX_NODE_IMAGE_SAMPLES: usize = 53;

const METRICS: [(&str, &str); 8] = [
    (
        "sandbox_node_image_inventory_observation_success",
        "Whether the bound CRI inventory RPC and response validation succeeded; completeness remains UNKNOWN, not a storage budget or health proof.",
    ),
    (
        "sandbox_node_image_filesystem_observation_success",
        "Whether the bound runtime filesystem report and identity validation succeeded; completeness remains UNKNOWN, not a physical cache total.",
    ),
    (
        "sandbox_node_image_observed_at_seconds",
        "Original successful observation cycle time in Unix seconds, not the scrape time or an explicit Prometheus sample timestamp.",
    ),
    (
        "sandbox_node_image_inventory_count",
        "Runtime-reported CRI inventory entry count as an approximate f64 gauge; not all native content objects. Exact decimal values are in diagnostic JSON.",
    ),
    (
        "sandbox_node_image_compressed_logical_bytes",
        "Sum of runtime-reported compressed logical image sizes as an approximate f64 gauge; shared content may repeat, never physical usage or a budget. Exact decimal values are in diagnostic JSON.",
    ),
    (
        "sandbox_node_image_filesystem_reported_at_seconds",
        "Original runtime filesystem report time in Unix seconds; not the scrape time or an explicit Prometheus sample timestamp.",
    ),
    (
        "sandbox_node_image_filesystem_used_bytes",
        "Runtime-reported snapshot store usage as an approximate f64 gauge; excludes a complete content-store total and is never capacity or a budget. Exact decimal values are in diagnostic JSON.",
    ),
    (
        "sandbox_node_image_filesystem_inodes_used",
        "Runtime-reported snapshot store inode usage as an approximate f64 gauge; completeness remains UNKNOWN and is never a budget. Exact decimal values are in diagnostic JSON.",
    ),
];

fn quantity(value: &str) -> Result<u64, GuardError> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(GuardError::Invalid);
    }
    value.parse().map_err(|_| GuardError::Invalid)
}

fn sample(
    output: &mut String,
    samples: &mut usize,
    name: &str,
    labels: &str,
    value: impl std::fmt::Display,
) -> Result<(), GuardError> {
    *samples += 1;
    if *samples > MAX_NODE_IMAGE_SAMPLES {
        return Err(GuardError::Invalid);
    }
    writeln!(output, "{name}{{{labels}}} {value}").map_err(|_| GuardError::Unknown)?;
    if output.len() > MAX_NODE_IMAGE_BODY_BYTES {
        return Err(GuardError::Invalid);
    }
    Ok(())
}

pub(super) fn encode_node_image_metrics(
    status: &ImageObservationStatus,
    expected_node: &NodeBinding,
    deployment: &str,
) -> Result<String, GuardError> {
    if !expected_node.validate() || &status.node != expected_node {
        return Err(GuardError::IdentityMismatch);
    }
    // Every label has a fixed, bounded alphabet; no caller-controlled text,
    // runtime paths, image identifiers or repository names reach the output.
    if deployment.is_empty()
        || deployment.len() > 63
        || !deployment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
    {
        return Err(GuardError::Invalid);
    }
    let source = match status.source {
        ObservationSource::RuntimeReported => "RUNTIME_REPORTED",
    };
    let completeness = match status.completeness {
        Completeness::Unknown => "UNKNOWN",
    };
    let labels = format!(
        "deployment=\"{deployment}\",cluster_epoch=\"{}\",node_uid=\"{}\",host_boot_id=\"{}\",profile_sha256=\"{}\",source=\"{source}\",completeness=\"{completeness}\"",
        expected_node.cluster_epoch,
        expected_node.node_uid,
        expected_node.boot_id,
        expected_node.profile_sha256,
    );
    let observed = status.inventory.observation_success || status.filesystems.observation_success;
    if observed && (!status.enabled || status.observed_at.is_none()) {
        return Err(GuardError::Invalid);
    }
    let mut output = String::new();
    for (name, help) in METRICS {
        writeln!(output, "# HELP {name} {help}\n# TYPE {name} gauge")
            .map_err(|_| GuardError::Unknown)?;
    }
    let mut samples = 0;
    for (name, success) in [
        (METRICS[0].0, status.inventory.observation_success),
        (METRICS[1].0, status.filesystems.observation_success),
    ] {
        sample(&mut output, &mut samples, name, &labels, u8::from(success))?;
    }
    // read_report also records attempted cycles. With no successful component
    // emit only the two failure markers, not a fresh-looking observation time.
    if observed {
        let timestamp = status.observed_at.ok_or(GuardError::Invalid)?;
        if timestamp.timestamp() <= 0 {
            return Err(GuardError::Invalid);
        }
        sample(
            &mut output,
            &mut samples,
            METRICS[2].0,
            &labels,
            format_args!(
                "{}.{:09}",
                timestamp.timestamp(),
                timestamp.timestamp_subsec_nanos()
            ),
        )?;
    }
    if status.inventory.observation_success {
        let count = quantity(
            status
                .inventory
                .image_count
                .as_deref()
                .ok_or(GuardError::Invalid)?,
        )?;
        if count > MAX_IMAGES as u64 {
            return Err(GuardError::Invalid);
        }
        let bytes = quantity(
            status
                .inventory
                .compressed_logical_bytes
                .as_deref()
                .ok_or(GuardError::Invalid)?,
        )?;
        sample(
            &mut output,
            &mut samples,
            METRICS[3].0,
            &labels,
            count as f64,
        )?;
        sample(
            &mut output,
            &mut samples,
            METRICS[4].0,
            &labels,
            bytes as f64,
        )?;
    }
    if status.filesystems.observation_success {
        if status.filesystems.entries.len() > MAX_FILESYSTEMS {
            return Err(GuardError::Invalid);
        }
        let mut seen = BTreeSet::new();
        for filesystem in &status.filesystems.entries {
            if !valid_sha256(&filesystem.filesystem_id)
                || !seen.insert(filesystem.filesystem_id.as_str())
            {
                return Err(GuardError::Invalid);
            }
            let nanoseconds = quantity(&filesystem.runtime_reported_at_ns)?;
            if nanoseconds == 0 || nanoseconds > i64::MAX as u64 {
                return Err(GuardError::Invalid);
            }
            let filesystem_labels =
                format!("{labels},filesystem_id=\"{}\"", filesystem.filesystem_id);
            sample(
                &mut output,
                &mut samples,
                METRICS[5].0,
                &filesystem_labels,
                format_args!(
                    "{}.{:09}",
                    nanoseconds / 1_000_000_000,
                    nanoseconds % 1_000_000_000
                ),
            )?;
            for (name, value) in [
                (METRICS[6].0, &filesystem.used_bytes),
                (METRICS[7].0, &filesystem.inodes_used),
            ] {
                if let Some(value) = value {
                    sample(
                        &mut output,
                        &mut samples,
                        name,
                        &filesystem_labels,
                        quantity(value)? as f64,
                    )?;
                }
            }
        }
    }
    Ok(output)
}

#[cfg(test)]
#[path = "image_metrics_tests.rs"]
mod tests;
