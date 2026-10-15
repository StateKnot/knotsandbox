//! Offline metadata inspection; this command neither checks approval nor prepares an image.
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

pub fn run(args: ImageArtifactArgs) -> anyhow::Result<()> {
    let ImageArtifactCommand::Verify(args) = args.command;
    let metadata = verify_oci_metadata(&args.layout, &args.expected_digest, &args.platform)
        .map_err(|error| {
            anyhow::anyhow!(
                "image artifact metadata verification failed: {}",
                error.code()
            )
        })?;
    println!("{}", serde_json::to_string(&metadata)?);
    Ok(())
}
