//! The real owned daemon supplies snapshot metadata, while the expected config
//! and single-layer ChainID originate in independently generated OCI bytes.
//! An empty committed snapshot deliberately proves no layer was applied.
use anyhow::{Context, ensure};
use serde_json::Value;
use std::os::unix::fs::MetadataExt;

use super::cli_tests::{
    CliOutput, Fixture, invoke_command as invoke, invoke_program, public_value,
    receipt as native_receipt,
};

const CTR: &str = "/usr/local/bin/ctr";
const LABEL: &str = "containerd.io/gc.ref.snapshot.overlayfs";
const ACTIVE: &str = "public-snapshot-metadata-active";
const FLAGS: [&str; 6] = [
    "approval_checked",
    "pull_selection_checked",
    "runtime_handler_checked",
    "layer_payloads_verified",
    "gc_protection_checked",
    "preparation_allowed",
];

fn public_digest(name: &str) -> anyhow::Result<String> {
    let value = public_value(name, 71)?;
    ensure!(
        value.len() == 71
            && value.starts_with("sha256:")
            && value.as_bytes()[7..]
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)),
        "independent SHA256 fixture digest required"
    );
    Ok(value)
}

async fn ctr(arguments: &[&str]) -> anyhow::Result<CliOutput> {
    let mut command = vec![
        "--address",
        "/run/containerd/containerd.sock",
        "--namespace",
        "k8s.io",
    ];
    command.extend_from_slice(arguments);
    invoke_program(CTR, &command).await
}

async fn ctr_ok(arguments: &[&str]) -> anyhow::Result<Vec<u8>> {
    let output = ctr(arguments).await?;
    ensure!(
        output.success && output.stderr.is_empty(),
        "owned bounded ctr fixture command must succeed: {arguments:?}"
    );
    Ok(output.stdout)
}

async fn snapshot_command(arguments: &[&str]) -> anyhow::Result<Vec<u8>> {
    let mut command = vec!["snapshots", "--snapshotter", "overlayfs"];
    command.extend_from_slice(arguments);
    ctr_ok(&command).await
}

async fn set_label(config: &str, value: &str) -> anyhow::Result<()> {
    ctr_ok(&["content", "label", config, &format!("{LABEL}={value}")]).await?;
    Ok(())
}

fn rejected(output: CliOutput, code: &str) -> anyhow::Result<()> {
    ensure!(
        !output.success && output.stdout.is_empty(),
        "rejection must have no success receipt"
    );
    ensure!(
        output.stderr
            == format!("Error: native snapshot identity inspection failed: {code}\n").as_bytes(),
        "snapshot CLI rejection must return only its stable error code"
    );
    Ok(())
}

async fn rejected_reference(fixture: &Fixture, code: &str) -> anyhow::Result<()> {
    let error =
        match super::inspect_snapshot(&fixture.reference, &fixture.digest, &fixture.platform).await
        {
            Ok(_) => anyhow::bail!("invalid snapshot reference metadata must fail closed"),
            Err(error) => error,
        };
    ensure!(error.code() == code, "public rejection code must be stable");
    rejected(
        invoke(
            "inspect-snapshot",
            &fixture.reference,
            &fixture.digest,
            &fixture.platform,
        )
        .await?,
        code,
    )
}

fn receipt(
    bytes: &[u8],
    fixture: &Fixture,
    config: &str,
    chain: &str,
    index: bool,
) -> anyhow::Result<()> {
    let text = std::str::from_utf8(bytes)?;
    ensure!(
        bytes.len() <= 64 * 1024
            && !text.contains("PUBLIC_ENV_MARKER")
            && !text.contains("DO_NOT_ECHO_NATIVE_METADATA_ENV"),
        "bounded snapshot receipt must never return config environment"
    );
    let value: Value = serde_json::from_slice(bytes)?;
    ensure!(
        value["scope"] == "NATIVE_SNAPSHOT_REFERENCE_METADATA_ONLY"
            && value["snapshotter"] == "overlayfs"
            && value["chain_id"] == chain
            && value["parent_chain_id"].is_null()
            && value["reference_label_matches"] == true
            && value["snapshot_committed_observed"] == true
            && FLAGS.iter().all(|flag| value[*flag] == false),
        "single-layer snapshot reference observation must grant no preparation or GC authority"
    );
    let native = &value["native"];
    native_receipt(&serde_json::to_vec(native)?, fixture, index)?;
    ensure!(
        native["metadata"]["config"]["digest"] == config
            && native["metadata"]["layers"][0]["diff_id"] == chain,
        "snapshot reference must match independent config and DiffID expectations"
    );
    Ok(())
}

async fn empty_snapshots() -> anyhow::Result<()> {
    let listing = snapshot_command(&["list"]).await?;
    ensure!(
        std::str::from_utf8(&listing)?.lines().count() == 1,
        "owned snapshot inventory must be empty"
    );
    Ok(())
}

async fn cleanup(config: &str, chain: &str) -> anyhow::Result<()> {
    // Restore exactly this fixture's label and keys even after an assertion or
    // subprocess failure. The outer runner independently checks no snapshots,
    // no containers/tasks, unpacked=false and exact daemon/image retirement.
    let label_removed = set_label(config, "").await;
    let listing = snapshot_command(&["list"]).await?;
    for line in std::str::from_utf8(&listing)?.lines().skip(1) {
        let key = line
            .split_whitespace()
            .next()
            .context("owned snapshot key required")?;
        ensure!(
            key == ACTIVE || key == chain,
            "only owned fixture keys may be removed"
        );
        snapshot_command(&["remove", key]).await?;
    }
    label_removed?;
    let labels = ctr_ok(&["content", "label", config]).await?;
    ensure!(
        !std::str::from_utf8(&labels)?
            .split(',')
            .any(|label| label.trim().starts_with(&format!("{LABEL}="))),
        "owned config snapshot label must be absent after cleanup"
    );
    empty_snapshots().await
}

async fn exercise(fixture: &Fixture, config: &str, chain: &str) -> anyhow::Result<()> {
    empty_snapshots().await?;
    rejected_reference(fixture, "SNAPSHOT_REFERENCE_MISMATCH").await?;
    set_label(config, chain).await?;
    rejected_reference(fixture, "SNAPSHOT_UNAVAILABLE").await?;

    // Official ctr Prepare without --target/--mounts only creates metadata and
    // an empty directory. Commit gives it the known one-layer ChainID; no layer
    // payload is extracted, mounted, executed or claimed as verified.
    snapshot_command(&["prepare", ACTIVE]).await?;
    snapshot_command(&["commit", chain, ACTIVE]).await?;
    for (reference, digest, index) in [
        (&fixture.reference, &fixture.digest, true),
        (&fixture.manifest_reference, &fixture.manifest_digest, false),
    ] {
        let observed = super::inspect_snapshot(reference, digest, &fixture.platform).await?;
        receipt(
            &serde_json::to_vec(&observed)?,
            fixture,
            config,
            chain,
            index,
        )?;
        let output = invoke("inspect-snapshot", reference, digest, &fixture.platform).await?;
        ensure!(
            output.success && output.stderr.is_empty(),
            "actual snapshot metadata CLI inspection must succeed"
        );
        receipt(&output.stdout, fixture, config, chain, index)?;
    }

    set_label(config, &format!("sha256:{}", "0".repeat(64))).await?;
    rejected_reference(fixture, "SNAPSHOT_REFERENCE_MISMATCH").await?;
    set_label(config, chain).await?;
    let absent = format!("fixture.invalid/snapshot-unregistered@{}", fixture.digest);
    rejected(
        invoke(
            "inspect-snapshot",
            &absent,
            &fixture.digest,
            &fixture.platform,
        )
        .await?,
        "RUNTIME_METADATA_UNAVAILABLE",
    )?;
    let wrong_platform = if fixture.platform == "linux/arm64" {
        "linux/amd64"
    } else {
        "linux/arm64"
    };
    rejected(
        invoke(
            "inspect-snapshot",
            &fixture.reference,
            &fixture.digest,
            wrong_platform,
        )
        .await?,
        "PLATFORM_MISMATCH",
    )?;
    rejected(
        invoke(
            "inspect-snapshot",
            "fixture.invalid/native-metadata-index:mutable-tag",
            &fixture.digest,
            &fixture.platform,
        )
        .await?,
        "INVALID_IMAGE_REFERENCE",
    )?;

    snapshot_command(&["remove", chain]).await?;
    snapshot_command(&["prepare", chain]).await?;
    rejected_reference(fixture, "SNAPSHOT_IDENTITY_MISMATCH").await?;

    for command in ["inspect-native", "inspect-cri"] {
        let output = invoke(
            command,
            &fixture.reference,
            &fixture.digest,
            &fixture.platform,
        )
        .await?;
        ensure!(
            output.success && output.stderr.is_empty(),
            "existing native and CRI commands must remain usable"
        );
        if command == "inspect-cri" {
            let cri: Value = serde_json::from_slice(&output.stdout)?;
            ensure!(
                cri["scope"] == "CRI_INDEX_CONFIG_IDENTITY_ONLY"
                    && cri["cri_image_id"] == config
                    && cri["preparation_allowed"] == false,
                "CRI compatibility control must preserve config identity and scope"
            );
            native_receipt(&serde_json::to_vec(&cri["native"])?, fixture, true)?;
        } else {
            native_receipt(&output.stdout, fixture, true)?;
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned no-network native containerd fixture and ordinary admin ELF"]
async fn snapshot_metadata_readback_and_admin_cli_remain_reference_only() -> anyhow::Result<()> {
    let fixture = Fixture::read()?;
    let config = public_digest("SANDBOX_NATIVE_METADATA_CONFIG_DIGEST")?;
    let chain = public_digest("SANDBOX_NATIVE_METADATA_DIFF_ID")?;
    let metadata = std::fs::symlink_metadata(CTR)?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && metadata.mode() & 0o111 != 0,
        "immutable root-owned pinned ctr executable required"
    );
    let result = exercise(&fixture, &config, &chain).await;
    let cleanup_result = cleanup(&config, &chain).await;
    cleanup_result.context("owned snapshot fixture cleanup must succeed")?;
    result?;
    println!("NODEGUARD_SNAPSHOT_METADATA_CLI_VERIFIED");
    Ok(())
}
