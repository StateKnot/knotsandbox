//! Artifact inspection and canonical bootstrap output; no runtime preparation.
use std::path::PathBuf;

use clap::{Args, Subcommand};
use sandbox_platform::image_artifact::{
    BootstrapArchiveLimits, PayloadLimits, export_bootstrap_archive, verify_oci_metadata,
    verify_oci_payloads,
};

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
    /// Export a verified direct-manifest OCI archive to binary stdout for bootstrap.
    ExportBootstrapArchive(BootstrapArchiveArgs),
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

#[derive(Args)]
struct BootstrapArchiveArgs {
    #[command(flatten)]
    payloads: PayloadArgs,
    /// Qualified repository@expected-digest; source naming annotations are ignored.
    #[arg(long)]
    reference: String,
    /// Complete USTAR stream byte ceiling, including headers, padding and EOF.
    #[arg(long)]
    max_archive_bytes: u64,
    /// Cooperative export deadline in seconds, positive and at most 300.
    #[arg(long)]
    deadline_seconds: u64,
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
        ImageArtifactCommand::ExportBootstrapArchive(args) => {
            let result = PayloadLimits::new(
                args.payloads.max_layer_bytes,
                args.payloads.max_total_layer_bytes,
                args.payloads.max_decoded_layer_bytes,
                args.payloads.max_total_decoded_bytes,
            )
            .and_then(|payloads| {
                BootstrapArchiveLimits::new(
                    payloads,
                    args.max_archive_bytes,
                    std::time::Duration::from_secs(args.deadline_seconds),
                )
            })
            .and_then(|limits| {
                export_bootstrap_archive(
                    &args.payloads.image.layout,
                    &args.payloads.image.expected_digest,
                    &args.payloads.image.platform,
                    &args.reference,
                    limits,
                    &mut std::io::stdout().lock(),
                )
            });
            // stdout is an archive, never a mixed JSON/diagnostic stream. A
            // consumer must require exit success before importing any bytes.
            result.map_err(|error| {
                anyhow::anyhow!("bootstrap archive export failed: {}", error.code())
            })?;
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
