use clap::{ArgGroup, ValueEnum};
use sandbox_platform::{
    backup_profile::{ReviewedBackupProfile, activate_profile, register_profile, revoke_profile},
    bucket_retention::{BucketRetentionExpectation, BucketRetentionVerifier},
    db::Database,
    runtime::KubernetesRuntime,
};
use std::{
    io::Read,
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
enum Action {
    Register,
    Activate,
    Revoke,
}

#[derive(clap::Args)]
#[command(group(ArgGroup::new("backup_profile_mode").required(true).args(["validate_only", "apply"])))]
pub struct BackupProfileArgs {
    #[arg(value_enum)]
    action: Action,
    /// Canonical reviewed artifact; required for register/activate, rejected for revoke.
    #[arg(long)]
    file: Option<PathBuf>,
    #[arg(long)]
    certification_report: Option<PathBuf>,
    /// Used only for revoke, including expired profiles from an old recovery epoch.
    #[arg(long)]
    profile_id: Option<Uuid>,
    #[arg(long)]
    request_id: Uuid,
    /// Reference to the reviewed change; never secret contents.
    #[arg(long)]
    approval_reference: String,
    #[arg(long)]
    validate_only: bool,
    #[arg(long)]
    apply: bool,
    #[arg(long, env = "SANDBOX_ADMIN_DATABASE_URL", hide_env_values = true)]
    database_url: Option<String>,
    /// Read-only OSS verification target. Serialized verification receipts are not accepted.
    #[arg(long)]
    retention_expectation: Option<PathBuf>,
    /// Separate read-only backup-certifier STS file, never a backup writer credential.
    #[arg(long)]
    retention_sts_file: Option<PathBuf>,
}
fn read(path: &Path, limit: usize) -> anyhow::Result<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits());
    }
    let file = options
        .open(path)
        .map_err(|_| anyhow::anyhow!("cannot open backup profile input"))?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "backup profile input must be a regular file"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= limit,
        "backup profile input exceeds size limit"
    );
    Ok(bytes)
}
pub async fn run(args: BackupProfileArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        !args.request_id.is_nil()
            && !args.approval_reference.trim().is_empty()
            && args.approval_reference.len() <= 256
            && !args.approval_reference.chars().any(char::is_control),
        "exact request UUID and bounded approval reference required"
    );
    if args.action == Action::Revoke {
        anyhow::ensure!(
            args.file.is_none()
                && args.certification_report.is_none()
                && args.retention_expectation.is_none()
                && args.retention_sts_file.is_none(),
            "revocation requires only the profile UUID and owner action reference"
        );
        let id = args
            .profile_id
            .filter(|v| !v.is_nil())
            .ok_or_else(|| anyhow::anyhow!("--profile-id required for revoke"))?;
        if args.validate_only {
            println!(
                "{}",
                serde_json::json!({"validated":true,"database_checked":false,"revoked":false,"profile_id":id})
            );
            return Ok(());
        }
        let db = database(&args).await?;
        let receipt = revoke_profile(&db, id, args.request_id, &args.approval_reference).await?;
        println!("{}", serde_json::to_string(&receipt)?);
        db.pool.close().await;
        return Ok(());
    }
    anyhow::ensure!(
        args.profile_id.is_none(),
        "register/activate identity comes from the reviewed profile"
    );
    let file = args
        .file
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--file required"))?;
    let report = args
        .certification_report
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--certification-report required"))?;
    let profile = ReviewedBackupProfile::parse(&read(file, 65536)?, &read(report, 131072)?)?;
    let expectation = if args.action == Action::Activate {
        let path = args
            .retention_expectation
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--retention-expectation required for activation"))?;
        let expectation: BucketRetentionExpectation =
            serde_json::from_slice(&read(path, 16384)?)
                .map_err(|_| anyhow::anyhow!("invalid backup retention expectation"))?;
        profile.validate_retention_expectation(&expectation)?;
        Some(expectation)
    } else {
        anyhow::ensure!(
            args.retention_expectation.is_none() && args.retention_sts_file.is_none(),
            "registration does not accept live activation inputs"
        );
        None
    };
    if args.validate_only {
        println!("{}", serde_json::to_string(&profile.static_receipt())?);
        return Ok(());
    }
    let db = database(&args).await?;
    let receipt = if let Some(expectation) = expectation {
        let credentials = args
            .retention_sts_file
            .ok_or_else(|| anyhow::anyhow!("--retention-sts-file required for activation"))?;
        let runtime = KubernetesRuntime::connect().await?;
        let kubernetes = profile.verify_kubernetes(&runtime).await?;
        let vault = BucketRetentionVerifier::new(expectation, credentials)?
            .verify()
            .await?;
        activate_profile(
            &db,
            &profile,
            args.request_id,
            &args.approval_reference,
            &kubernetes,
            &vault,
        )
        .await?
    } else {
        register_profile(&db, &profile, args.request_id, &args.approval_reference).await?
    };
    println!("{}", serde_json::to_string(&receipt)?);
    db.pool.close().await;
    Ok(())
}
async fn database(args: &BackupProfileArgs) -> anyhow::Result<Database> {
    Database::connect_for_process(
        args.database_url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("SANDBOX_ADMIN_DATABASE_URL required for --apply"))?,
        2,
        sandbox_platform::db::DatabaseProcessRole::Admin,
    )
    .await
}
