//! Read-only artifact inspection; no approval checks or image preparation.
use std::path::PathBuf;

use clap::{Args, Subcommand};
use sandbox_platform::image_artifact::{PayloadLimits, verify_oci_metadata, verify_oci_payloads};

#[derive(Args)]
pub struct ImageArtifactArgs {
    #[command(subcommand)]
    command: ImageArtifactCommand,
}

#[derive(Subcommand)]
enum ImageArtifactCommand {
    /// Verify OCI metadata against an external expected digest and exact platform.
    Verify(VerifyArgs),
    /// Verify actual raw/gzip layer streams and DiffIDs within explicit byte limits.
    VerifyPayloads(PayloadArgs),
    /// Read existing OCI metadata from this Linux host's fixed containerd endpoint.
    InspectNative(NativeArgs),
    /// Match the current CRI image index ID to verified local OCI configuration.
    InspectCri(NativeArgs),
    /// Observe the fixed snapshotter's rootfs snapshot and config reference metadata.
    InspectSnapshot(NativeArgs),
}

#[derive(Args)]
struct VerifyArgs {
    /// Read-only OCI layout directory; symbolic-link path components are rejected.
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

#[derive(Args)]
struct PayloadArgs {
    #[command(flatten)]
    image: VerifyArgs,
    /// Maximum original blob bytes for one layer; must be positive.
    #[arg(long)]
    max_layer_bytes: u64,
    /// Maximum original blob bytes across all layer references, including duplicates.
    #[arg(long)]
    max_total_layer_bytes: u64,
    /// Maximum decoded stream bytes for one layer; not extracted disk usage.
    #[arg(long)]
    max_decoded_layer_bytes: u64,
    /// Maximum decoded bytes across all layer references, including duplicates.
    #[arg(long)]
    max_total_decoded_bytes: u64,
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
        ImageArtifactCommand::VerifyPayloads(args) => {
            let verified = PayloadLimits::new(
                args.max_layer_bytes,
                args.max_total_layer_bytes,
                args.max_decoded_layer_bytes,
                args.max_total_decoded_bytes,
            )
            .and_then(|limits| {
                verify_oci_payloads(
                    &args.image.layout,
                    &args.image.expected_digest,
                    &args.image.platform,
                    limits,
                )
            })
            .map_err(|error| {
                anyhow::anyhow!("image payload verification failed: {}", error.code())
            })?;
            println!("{}", serde_json::to_string(&verified)?);
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
