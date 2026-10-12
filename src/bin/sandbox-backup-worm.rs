//! Standalone read-only现场 evidence. Never creates a cloud resource or changes
//! bucket retention. Owner activation must independently call the verifier API.
use clap::Parser;
use sandbox_platform::bucket_retention::{
    BucketRetentionExpectation, BucketRetentionVerifier, RetentionError,
};
use std::{
    io::{Read, Write},
    path::PathBuf,
};

#[derive(Parser)]
#[command(about = "Read-only OSS bucket retention certification; no cloud mutation")]
struct Args {
    #[arg(long)]
    expectation: PathBuf,
    #[arg(long)]
    sts_file: PathBuf,
    #[arg(long)]
    output: PathBuf,
}
#[tokio::main]
async fn main() {
    let args = Args::parse();
    if let Err(error) = run(args).await {
        if let Some(error) = error.downcast_ref::<RetentionError>() {
            eprintln!(
                "BUCKET_RETENTION_CERTIFICATION_REJECTED {:?}; no profile was activated",
                error.code
            );
        } else {
            eprintln!(
                "BUCKET_RETENTION_CERTIFICATION_REJECTED LOCAL_INPUT_OR_OUTPUT; no profile was activated"
            );
        }
        std::process::exit(1);
    }
}
async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits());
    }
    let file = options.open(&args.expectation)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > 16384 {
        return Err("Invalid expectation file".into());
    }
    let mut raw = Vec::new();
    file.take(16385).read_to_end(&mut raw)?;
    if raw.len() > 16384 {
        return Err("Invalid expectation size".into());
    }
    let expectation: BucketRetentionExpectation = serde_json::from_slice(&raw)?;
    let proof = BucketRetentionVerifier::new(expectation.clone(), args.sts_file)?
        .verify()
        .await?;
    proof.check_current(&expectation)?;
    let bytes = serde_json::to_vec_pretty(proof.receipt())?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(args.output)?;
    output.write_all(&bytes)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    println!(
        "OSS read-only retention evidence recorded; profile activation, RAM isolation and recovery certification remain separate."
    );
    Ok(())
}
