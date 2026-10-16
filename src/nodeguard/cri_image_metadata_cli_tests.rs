//! Exercise public CRI inspection and the ordinary admin ELF against the real,
//! owned containerd. Expected config identity comes only from the independently
//! generated public OCI archive, never from a runtime response under test.
use anyhow::{Context, ensure};
use serde_json::Value;
use std::os::unix::fs::MetadataExt;

use super::cli_tests::{CliOutput, invoke_command as invoke};

const ADMIN: &str = "/fixture/sandbox-admin";
const OUTPUT_LIMIT: usize = 64 * 1024;
const FLAGS: [&str; 7] = [
    "approval_checked",
    "pull_selection_checked",
    "runtime_handler_checked",
    "snapshotter_checked",
    "unpack_checked",
    "gc_protection_checked",
    "preparation_allowed",
];

struct Fixture {
    reference: String,
    digest: String,
    platform: String,
    manifest_reference: String,
    manifest_digest: String,
    config_digest: String,
}

fn public_value(name: &str, limit: usize) -> anyhow::Result<String> {
    let value = std::env::var(name).context("generated public fixture environment required")?;
    ensure!(
        !value.is_empty() && value.len() <= limit && value.is_ascii(),
        "bounded public fixture environment required"
    );
    Ok(value)
}

impl Fixture {
    fn read() -> anyhow::Result<Self> {
        ensure!(
            rustix::process::geteuid().is_root(),
            "owned Linux root fixture required"
        );
        let fixture = Self {
            reference: public_value("SANDBOX_NATIVE_METADATA_REFERENCE", 2048)?,
            digest: public_value("SANDBOX_NATIVE_METADATA_EXPECTED_DIGEST", 71)?,
            platform: public_value("SANDBOX_NATIVE_METADATA_PLATFORM", 32)?,
            manifest_reference: public_value("SANDBOX_NATIVE_METADATA_MANIFEST_REFERENCE", 2048)?,
            manifest_digest: public_value("SANDBOX_NATIVE_METADATA_MANIFEST_DIGEST", 71)?,
            config_digest: public_value("SANDBOX_NATIVE_METADATA_CONFIG_DIGEST", 71)?,
        };
        for digest in [
            &fixture.digest,
            &fixture.manifest_digest,
            &fixture.config_digest,
        ] {
            ensure!(
                digest.len() == 71
                    && digest.starts_with("sha256:")
                    && digest[7..]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
                "independent SHA256 fixture digest required"
            );
        }
        ensure!(
            fixture.reference
                == format!("fixture.invalid/native-metadata-index@{}", fixture.digest)
                && fixture.manifest_reference
                    == format!(
                        "fixture.invalid/native-metadata-manifest@{}",
                        fixture.manifest_digest
                    )
                && matches!(fixture.platform.as_str(), "linux/amd64" | "linux/arm64"),
            "exact owned public fixture references required"
        );
        let metadata = std::fs::symlink_metadata(ADMIN)?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0
                && metadata.mode() & 0o111 != 0,
            "immutable root-owned ordinary admin executable required"
        );
        Ok(fixture)
    }
}

fn receipt(bytes: &[u8], fixture: &Fixture, index: bool, cri: bool) -> anyhow::Result<()> {
    ensure!(
        bytes.len() <= OUTPUT_LIMIT,
        "bounded metadata receipt required"
    );
    let text = std::str::from_utf8(bytes)?;
    ensure!(
        !text.contains("PUBLIC_ENV_MARKER") && !text.contains("DO_NOT_ECHO_NATIVE_METADATA_ENV"),
        "image config environment must never be returned"
    );
    let value: Value = serde_json::from_slice(bytes)?;
    let native = if cri {
        ensure!(
            value["scope"] == "CRI_INDEX_CONFIG_IDENTITY_ONLY"
                && value["cri_image_id"] == fixture.config_digest
                && FLAGS.iter().all(|flag| value[*flag] == false),
            "CRI index identity must bind the independent config and grant no preparation authority"
        );
        &value["native"]
    } else {
        &value
    };
    ensure!(
        native["scope"] == "NATIVE_CONTAINERD_METADATA_ONLY"
            && native["namespace"] == "k8s.io"
            && native["runtime_version"] == "2.3.5"
            && native["reference"].as_str()
                == Some(if index {
                    fixture.reference.as_str()
                } else {
                    fixture.manifest_reference.as_str()
                }),
        "original native metadata boundary must be preserved"
    );
    chrono::DateTime::parse_from_rfc3339(
        native["observed_at"]
            .as_str()
            .context("observation timestamp required")?,
    )?;
    let metadata = &native["metadata"];
    ensure!(
        metadata["scope"] == "OCI_METADATA_ONLY"
            && metadata["approval_checked"] == false
            && metadata["layer_payloads_verified"] == false
            && metadata["preparation_allowed"] == false
            && metadata["platform"]["os"] == "linux"
            && metadata["platform"]["architecture"]
                == fixture.platform.strip_prefix("linux/").unwrap_or_default()
            && metadata["platform"]["variant"].is_null()
            && metadata["root"]["digest"].as_str()
                == Some(if index {
                    fixture.digest.as_str()
                } else {
                    fixture.manifest_digest.as_str()
                })
            && metadata["selected_manifest"]["digest"] == fixture.manifest_digest
            && metadata["config"]["digest"] == fixture.config_digest,
        "exact OCI root, platform, selected manifest and config must match independent fixture inputs"
    );
    ensure!(
        if index {
            metadata["index"]["digest"] == fixture.digest
        } else {
            metadata["index"].is_null()
        },
        "index presence must match the independently supplied root"
    );
    Ok(())
}

fn rejected(output: CliOutput, code: &str) -> anyhow::Result<()> {
    ensure!(
        !output.success && output.stdout.is_empty(),
        "rejection must have no success receipt"
    );
    ensure!(
        output.stderr
            == format!("Error: CRI image identity inspection failed: {code}\n").as_bytes(),
        "CLI rejection must return only its stable error code"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned no-network native containerd fixture and ordinary admin ELF"]
async fn cri_metadata_readback_and_admin_cli_remain_index_only() -> anyhow::Result<()> {
    let fixture = Fixture::read()?;
    for (reference, digest, index) in [
        (&fixture.reference, &fixture.digest, true),
        (&fixture.manifest_reference, &fixture.manifest_digest, false),
    ] {
        let inspected = super::inspect_cri(reference, digest, &fixture.platform).await?;
        receipt(&serde_json::to_vec(&inspected)?, &fixture, index, true)?;
        let output = invoke("inspect-cri", reference, digest, &fixture.platform).await?;
        ensure!(
            output.success && output.stderr.is_empty(),
            "actual CRI index/config CLI inspection must succeed"
        );
        receipt(&output.stdout, &fixture, index, true)?;
    }

    let wrong_platform = if fixture.platform == "linux/arm64" {
        "linux/amd64"
    } else {
        "linux/arm64"
    };
    rejected(
        invoke(
            "inspect-cri",
            &fixture.reference,
            &fixture.digest,
            wrong_platform,
        )
        .await?,
        "PLATFORM_MISMATCH",
    )?;
    let absent = format!("fixture.invalid/cri-unregistered@{}", fixture.digest);
    rejected(
        invoke("inspect-cri", &absent, &fixture.digest, &fixture.platform).await?,
        "CRI_IMAGE_UNAVAILABLE",
    )?;
    let mismatch = format!("sha256:{}", "0".repeat(64));
    rejected(
        invoke(
            "inspect-cri",
            &fixture.reference,
            &mismatch,
            &fixture.platform,
        )
        .await?,
        "INVALID_IMAGE_REFERENCE",
    )?;
    rejected(
        invoke(
            "inspect-cri",
            "fixture.invalid/native-metadata-index:mutable-tag",
            &fixture.digest,
            &fixture.platform,
        )
        .await?,
        "INVALID_IMAGE_REFERENCE",
    )?;

    // Keep the pre-existing public command as a real compatibility control in
    // the same daemon. CRI-only failures cannot be hidden by breaking native.
    let native = invoke(
        "inspect-native",
        &fixture.reference,
        &fixture.digest,
        &fixture.platform,
    )
    .await?;
    ensure!(
        native.success && native.stderr.is_empty(),
        "existing native CLI must remain usable"
    );
    receipt(&native.stdout, &fixture, true, false)?;
    println!("NODEGUARD_CRI_METADATA_CLI_VERIFIED");
    Ok(())
}
