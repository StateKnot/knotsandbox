//! Metadata inspection; this command neither checks approval nor prepares an image.
use std::path::PathBuf;

use clap::{Args, Subcommand};
use sandbox_platform::image_artifact::verify_oci_metadata;

#[derive(Args)]
pub struct ImageArtifactArgs {
    #[command(subcommand)]
    command: ImageArtifactCommand,
}

#[derive(Subcommand)]
enum ImageArtifactCommand {
    /// Verify OCI metadata against an external expected digest and exact platform.
    Verify(VerifyArgs),
    /// Read existing OCI metadata from this Linux host's fixed containerd endpoint.
    InspectNative(NativeArgs),
    /// Match the current CRI image index ID to verified local OCI configuration.
    InspectCri(NativeArgs),
    /// Observe the fixed snapshotter's rootfs snapshot and config reference metadata.
    InspectSnapshot(NativeArgs),
}

#[derive(Args)]
struct VerifyArgs {
    /// Read-only OCI layout directory. No layer payloads are read or unpacked.
    #[arg(long)]
    layout: PathBuf,
    /// Independently trusted root digest; this command does not check approval.
    #[arg(long)]
    expected_digest: String,
    /// Exact linux/amd64 or linux/arm64 platform, optionally followed by /variant.
    #[arg(long)]
    platform: String,
}

#[derive(Args)]
struct NativeArgs {
    /// Exact local repository@sha256 reference. Tags are not accepted.
    #[arg(long)]
    reference: String,
    /// Independently trusted root digest; this command does not check approval.
    #[arg(long)]
    expected_digest: String,
    /// Exact linux/amd64 or linux/arm64 platform, optionally followed by /variant.
    #[arg(long)]
    platform: String,
}

pub async fn run(args: ImageArtifactArgs) -> anyhow::Result<()> {
    match args.command {
        ImageArtifactCommand::Verify(args) => {
            let metadata = verify_oci_metadata(&args.layout, &args.expected_digest, &args.platform)
                .map_err(|error| {
                    anyhow::anyhow!(
                        "image artifact metadata verification failed: {}",
                        error.code()
                    )
                })?;
            println!("{}", serde_json::to_string(&metadata)?);
        }
        ImageArtifactCommand::InspectNative(args) => {
            let metadata = sandbox_platform::nodeguard::native_image_metadata::inspect(
                &args.reference,
                &args.expected_digest,
                &args.platform,
            )
            .await
            .map_err(|error| {
                anyhow::anyhow!("native image metadata inspection failed: {}", error.code())
            })?;
            println!("{}", serde_json::to_string(&metadata)?);
        }
        ImageArtifactCommand::InspectCri(args) => {
            let metadata = sandbox_platform::nodeguard::native_image_metadata::inspect_cri(
                &args.reference,
                &args.expected_digest,
                &args.platform,
            )
            .await
            .map_err(|error| {
                anyhow::anyhow!("CRI image identity inspection failed: {}", error.code())
            })?;
            println!("{}", serde_json::to_string(&metadata)?);
        }
        ImageArtifactCommand::InspectSnapshot(args) => {
            let metadata = sandbox_platform::nodeguard::native_image_metadata::inspect_snapshot(
                &args.reference,
                &args.expected_digest,
                &args.platform,
            )
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "native snapshot identity inspection failed: {}",
                    error.code()
                )
            })?;
            println!("{}", serde_json::to_string(&metadata)?);
        }
    }
    Ok(())
}
