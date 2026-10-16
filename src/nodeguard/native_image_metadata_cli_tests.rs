//! Real owned containerd plus the ordinary admin executable exercise the public
//! read-only native inspection boundary. Expected digests originate in the
//! runner's independently generated OCI fixture, never in provider responses.
use anyhow::{Context, ensure};
use serde_json::Value;
use std::{os::unix::fs::MetadataExt, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
};

const ADMIN: &str = "/fixture/sandbox-admin";
const OUTPUT_LIMIT: usize = 64 * 1024;
const PUBLIC_ENV_KEY: &str = "PUBLIC_ENV_MARKER";
const PUBLIC_ENV_VALUE: &str = "DO_NOT_ECHO_NATIVE_METADATA_ENV";

struct Fixture {
    reference: String,
    digest: String,
    platform: String,
    manifest_reference: String,
    manifest_digest: String,
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
        };
        for digest in [&fixture.digest, &fixture.manifest_digest] {
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

async fn bounded_output(pipe: impl AsyncRead + Unpin) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    pipe.take(OUTPUT_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .await?;
    ensure!(bytes.len() <= OUTPUT_LIMIT, "admin output bound exceeded");
    Ok(bytes)
}

struct CliOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

async fn invoke(reference: &str, digest: &str, platform: &str) -> anyhow::Result<CliOutput> {
    let mut child = Command::new(ADMIN)
        .args([
            "image-artifact",
            "inspect-native",
            "--reference",
            reference,
            "--expected-digest",
            digest,
            "--platform",
            platform,
        ])
        .env_clear()
        .current_dir("/fixture")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let stdout = child.stdout.take().context("owned admin stdout required")?;
    let stderr = child.stderr.take().context("owned admin stderr required")?;
    // Limit both pipes while reading, and own the process through cancellation.
    // Waiting after an output-only check would permit unbounded pipe allocation.
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::try_join!(bounded_output(stdout), bounded_output(stderr), async {
            Ok::<_, anyhow::Error>(child.wait().await?)
        })
    })
    .await;
    match result {
        Ok(Ok((stdout, stderr, status))) => Ok(CliOutput {
            success: status.success(),
            stdout,
            stderr,
        }),
        result => {
            // try_join drops readers on the first failure. Retire and reap the
            // exact owned process before returning even if it already exited.
            let _ = child.start_kill();
            child.wait().await?;
            match result {
                Ok(Err(error)) => Err(error),
                Err(_) => anyhow::bail!("admin subprocess exceeded its five-second deadline"),
                Ok(Ok(_)) => unreachable!(),
            }
        }
    }
}

fn receipt(bytes: &[u8], fixture: &Fixture, index: bool) -> anyhow::Result<()> {
    ensure!(
        bytes.len() <= OUTPUT_LIMIT,
        "bounded native receipt required"
    );
    let text = std::str::from_utf8(bytes)?;
    ensure!(
        !text.contains(PUBLIC_ENV_KEY) && !text.contains(PUBLIC_ENV_VALUE),
        "image config environment must never be returned"
    );
    let value: Value = serde_json::from_slice(bytes)?;
    ensure!(
        value["scope"] == "NATIVE_CONTAINERD_METADATA_ONLY"
            && value["namespace"] == "k8s.io"
            && value["runtime_version"] == "2.3.5"
            && value["reference"].as_str()
                == Some(if index {
                    fixture.reference.as_str()
                } else {
                    fixture.manifest_reference.as_str()
                }),
        "native receipt must bind the exact public readback scope"
    );
    let observed_at = value["observed_at"]
        .as_str()
        .context("observation timestamp required")?;
    chrono::DateTime::parse_from_rfc3339(observed_at)?;
    let metadata = &value["metadata"];
    ensure!(
        metadata["scope"] == "OCI_METADATA_ONLY"
            && metadata["approval_checked"] == false
            && metadata["layer_payloads_verified"] == false
            && metadata["preparation_allowed"] == false,
        "metadata readback must grant no approval or preparation authority"
    );
    ensure!(
        metadata["platform"]["os"] == "linux"
            && metadata["platform"]["architecture"]
                == fixture.platform.strip_prefix("linux/").unwrap_or_default()
            && metadata["platform"]["variant"].is_null()
            && metadata["root"]["digest"].as_str()
                == Some(if index {
                    fixture.digest.as_str()
                } else {
                    fixture.manifest_digest.as_str()
                })
            && metadata["selected_manifest"]["digest"] == fixture.manifest_digest,
        "native root and selected platform must match independent fixture inputs"
    );
    if index {
        ensure!(
            metadata["index"]["digest"] == fixture.digest,
            "index receipt required"
        );
    } else {
        ensure!(
            metadata["index"].is_null(),
            "direct manifest must not invent an index"
        );
    }
    ensure!(
        metadata["layers"]
            .as_array()
            .is_some_and(|layers| layers.len() == 1)
            && metadata["config"]["media_type"] == "application/vnd.oci.image.config.v1+json",
        "actual imported manifest and config closure required"
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
            == format!("Error: native image metadata inspection failed: {code}\n").as_bytes(),
        "CLI rejection must return only its stable error code"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned no-network native containerd fixture and ordinary admin ELF"]
async fn native_metadata_readback_and_admin_cli_remain_metadata_only() -> anyhow::Result<()> {
    let fixture = Fixture::read()?;
    let native = super::inspect(&fixture.reference, &fixture.digest, &fixture.platform).await?;
    receipt(&serde_json::to_vec(&native)?, &fixture, true)?;

    let index = invoke(&fixture.reference, &fixture.digest, &fixture.platform).await?;
    ensure!(
        index.success && index.stderr.is_empty(),
        "index CLI inspection must succeed"
    );
    receipt(&index.stdout, &fixture, true)?;
    let manifest = invoke(
        &fixture.manifest_reference,
        &fixture.manifest_digest,
        &fixture.platform,
    )
    .await?;
    ensure!(
        manifest.success && manifest.stderr.is_empty(),
        "manifest CLI inspection must succeed"
    );
    receipt(&manifest.stdout, &fixture, false)?;

    rejected(
        invoke(
            "fixture.invalid/native-metadata-index:mutable-tag",
            &fixture.digest,
            &fixture.platform,
        )
        .await?,
        "INVALID_IMAGE_REFERENCE",
    )?;
    let mismatch = format!("sha256:{}", "0".repeat(64));
    rejected(
        invoke(&fixture.reference, &mismatch, &fixture.platform).await?,
        "INVALID_IMAGE_REFERENCE",
    )?;
    let wrong_platform = if fixture.platform == "linux/arm64" {
        "linux/amd64"
    } else {
        "linux/arm64"
    };
    rejected(
        invoke(&fixture.reference, &fixture.digest, wrong_platform).await?,
        "PLATFORM_MISMATCH",
    )?;
    let absent = format!("fixture.invalid/native-metadata-absent@{}", fixture.digest);
    rejected(
        invoke(&absent, &fixture.digest, &fixture.platform).await?,
        "RUNTIME_METADATA_UNAVAILABLE",
    )?;
    println!("NODEGUARD_NATIVE_METADATA_CLI_VERIFIED");
    Ok(())
}
