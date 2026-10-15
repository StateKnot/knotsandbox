//! Installation owner tool; this binary is never served over HTTP.
use std::{fs::File, io::Read, path::PathBuf};

use clap::{ArgGroup, Parser, Subcommand};
use sandbox_platform::{
    admin::{MAX_BOOTSTRAP_BYTES, apply_bootstrap, parse_spec},
    db::{Database, DatabaseProcessRole},
    node_enrollment::{EnrollmentPlan, MAX_ENROLLMENT_BYTES, enroll_node},
    runtime::KubernetesRuntime,
    termination_client::NodeguardCredentials,
};
use uuid::Uuid;

#[path = "../admin_backup_cli.rs"]
mod backup_cli;

#[derive(Parser)]
#[command(
    name = "sandbox-admin",
    about = "Explicit, atomic sandbox installation administration",
    subcommand_negates_reqs = true,
    args_conflicts_with_subcommands = true
)]
#[command(group(ArgGroup::new("mode").required(true).args(["validate_only","apply"])))]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(long, required = true)]
    file: Option<PathBuf>,
    /// Validate the file only; no database/network connection or state changes.
    #[arg(long)]
    validate_only: bool,
    /// Apply through a dedicated database owner connection, never the API login.
    #[arg(long)]
    apply: bool,
    #[arg(long, env = "SANDBOX_ADMIN_DATABASE_URL", hide_env_values = true)]
    database_url: Option<String>,
    /// Required only for a previously uninitialized installation; never rotates an existing epoch.
    #[arg(long)]
    initialize_cluster_epoch: Option<Uuid>,
    /// Development only: permit a literal loopback HTTP issuer.
    #[arg(long, default_value_t = false)]
    allow_loopback_http: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Bind or rotate a reviewed SERVICE OAuth client with exact previous value.
    BindServiceIdentity(FenceArgs),
    /// Explicit installation-wide node image read authority; never a tenant grant.
    NodeImageReader(OperatorGrantArgs),
    /// Enroll one quarantined node through reviewed inventory, live K8s and mTLS.
    EnrollNode(EnrollArgs),
    /// Record a node-wide SYSTEM incident affecting all tenants on that node.
    NodeFence(FenceArgs),
    /// Activate or revoke a reviewed, versioned CRI guard contract.
    GuardContract(FenceArgs),
    /// Register disabled backup profiles, activate using live checks, or revoke.
    BackupProfile(backup_cli::BackupProfileArgs),
}

#[derive(clap::Args)]
#[command(group(ArgGroup::new("operator_mode").required(true).args(["validate_only","apply"])))]
struct OperatorGrantArgs {
    #[arg(long)]
    file: PathBuf,
    #[arg(long)]
    revoke: bool,
    #[arg(long)]
    validate_only: bool,
    #[arg(long)]
    apply: bool,
    #[arg(long, env = "SANDBOX_ADMIN_DATABASE_URL", hide_env_values = true)]
    database_url: Option<String>,
    /// Development only: allow HTTP issuers at literal loopback IPs.
    #[arg(long)]
    allow_loopback_http: bool,
}

async fn node_image_reader(args: OperatorGrantArgs) -> anyhow::Result<()> {
    use sandbox_platform::operator_access::{
        GrantNodeImageReader, MAX_OPERATOR_GRANT_BYTES, RevokeNodeImageReader,
    };
    let mut bytes = Vec::new();
    File::open(&args.file)?
        .take((MAX_OPERATOR_GRANT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    let grant = if args.revoke {
        None
    } else {
        Some(GrantNodeImageReader::parse(
            &bytes,
            args.allow_loopback_http,
        )?)
    };
    let revoke = if args.revoke {
        Some(RevokeNodeImageReader::parse(&bytes)?)
    } else {
        None
    };
    if args.validate_only {
        println!(
            "{}",
            serde_json::json!({"validated":true,"database_checked":false,"changed":false})
        );
        return Ok(());
    }
    let url = args
        .database_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("SANDBOX_ADMIN_DATABASE_URL required"))?;
    let database = Database::connect_for_process(url, 2, DatabaseProcessRole::Admin).await?;
    let outcome = async {
        if let Some(request) = grant {
            let receipt =
                sandbox_platform::operator_access::grant_node_image_reader(&database, &request)
                    .await?;
            println!("{}", serde_json::to_string(&receipt)?);
        } else if let Some(request) = revoke {
            sandbox_platform::operator_access::revoke_node_image_reader(&database, &request)
                .await?;
            println!(
                "{}",
                serde_json::json!({"grant_id":request.grant_id,"revoked":true})
            );
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    database.pool.close().await;
    outcome
}
async fn bind_service_identity(args: FenceArgs) -> anyhow::Result<()> {
    let request = sandbox_platform::admin::ServiceIdentityBindingRequest::parse(&read_enrollment(
        &args.file,
    )?)?;
    if args.validate_only {
        println!(
            "{}",
            serde_json::json!({"validated":true,"database_checked":false,"changed":false})
        );
        return Ok(());
    }
    let url = args
        .database_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("SANDBOX_ADMIN_DATABASE_URL required"))?;
    let db = Database::connect_for_process(url, 2, DatabaseProcessRole::Admin).await?;
    let principal = sandbox_platform::admin::bind_service_identity(&db, &request).await?;
    println!(
        "{}",
        serde_json::json!({"principal_id":principal,"binding_applied":true})
    );
    db.pool.close().await;
    Ok(())
}
#[derive(clap::Args)]
#[command(group(ArgGroup::new("fence_mode").required(true).args(["validate_only","apply"])))]
struct FenceArgs {
    #[arg(long)]
    file: PathBuf,
    #[arg(long)]
    validate_only: bool,
    /// Apply the explicitly reviewed owner action through a dedicated connection.
    #[arg(long)]
    apply: bool,
    #[arg(long, env = "SANDBOX_ADMIN_DATABASE_URL", hide_env_values = true)]
    database_url: Option<String>,
}
async fn guard_contract(args: FenceArgs) -> anyhow::Result<()> {
    let request = sandbox_platform::launch_authority::GuardContractRequest::parse(
        &read_enrollment(&args.file)?,
    )?;
    if args.validate_only {
        println!(
            "{}",
            serde_json::json!({"validated":true,"database_checked":false,"activated":false})
        );
        return Ok(());
    }
    let url = args
        .database_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("SANDBOX_ADMIN_DATABASE_URL required"))?;
    let db = Database::connect_for_process(url, 2, DatabaseProcessRole::Admin).await?;
    let receipt = sandbox_platform::launch_authority::apply_guard_contract(&db, &request).await?;
    println!("{}", serde_json::to_string(&receipt)?);
    db.pool.close().await;
    Ok(())
}
async fn fence(args: FenceArgs) -> anyhow::Result<()> {
    let request =
        sandbox_platform::node_fencing::NodeFenceRequest::parse(&read_enrollment(&args.file)?)?;
    if args.validate_only {
        println!(
            "{}",
            serde_json::json!({"validated":true,"database_checked":false,"incident_id":request.incident_id,"scope":"SYSTEM_NODE_ALL_TENANTS"})
        );
        return Ok(());
    }
    let url = args
        .database_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("SANDBOX_ADMIN_DATABASE_URL required"))?;
    let db = Database::connect_for_process(url, 2, DatabaseProcessRole::Admin).await?;
    let receipt = sandbox_platform::node_fencing::request_node_fence(&db, &request).await?;
    println!("{}", serde_json::to_string(&receipt)?);
    db.pool.close().await;
    Ok(())
}
#[derive(clap::Args)]
#[command(group(ArgGroup::new("node_mode").required(true).args(["validate_only", "apply"])))]
struct EnrollArgs {
    /// Append newer reviewed evidence for an existing enabled identity, without changing scheduling.
    #[arg(long)]
    renew_certification: bool,
    #[arg(long)]
    file: PathBuf,
    #[arg(long)]
    terraform_output: PathBuf,
    #[arg(long)]
    cluster_settings: PathBuf,
    #[arg(long)]
    certification_report: PathBuf,
    #[arg(long)]
    validate_only: bool,
    #[arg(long)]
    apply: bool,
    #[arg(long, env = "SANDBOX_ADMIN_DATABASE_URL", hide_env_values = true)]
    database_url: Option<String>,
    #[arg(long, env = "SANDBOX_NODEGUARD_SERVER_CA_FILE")]
    nodeguard_server_ca_file: Option<PathBuf>,
    #[arg(long, env = "SANDBOX_NODEGUARD_CLIENT_IDENTITY_FILE")]
    nodeguard_client_identity_file: Option<PathBuf>,
}
fn read_enrollment(path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    let file = File::open(path)?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "enrollment input must be a regular file"
    );
    let mut bytes = Vec::new();
    file.take((MAX_ENROLLMENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= MAX_ENROLLMENT_BYTES,
        "enrollment input exceeds 1 MiB"
    );
    Ok(bytes)
}
async fn enroll(args: EnrollArgs) -> anyhow::Result<()> {
    let plan = EnrollmentPlan::parse(
        &read_enrollment(&args.file)?,
        &read_enrollment(&args.terraform_output)?,
        &read_enrollment(&args.cluster_settings)?,
        &read_enrollment(&args.certification_report)?,
        chrono::Utc::now(),
    )?;
    let plan = if args.renew_certification {
        plan.renewing_certification()
    } else {
        plan
    };
    if args.validate_only {
        println!("{}", plan.validation_report());
        return Ok(());
    }
    let ca = args
        .nodeguard_server_ca_file
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--nodeguard-server-ca-file is required for --apply"))?;
    let identity = args
        .nodeguard_client_identity_file
        .as_deref()
        .ok_or_else(|| {
            anyhow::anyhow!("--nodeguard-client-identity-file is required for --apply")
        })?;
    let credentials = NodeguardCredentials::from_files(ca, identity)?;
    let url = args
        .database_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("SANDBOX_ADMIN_DATABASE_URL is required for --apply"))?;
    let db = Database::connect_for_process(url, 2, DatabaseProcessRole::Admin).await?;
    let runtime = KubernetesRuntime::connect().await?;
    let receipt = enroll_node(&db, &runtime, &credentials, &plan).await?;
    println!("{}", serde_json::to_string(&receipt)?);
    db.pool.close().await;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if let Some(command) = args.command {
        return match command {
            Command::BindServiceIdentity(binding) => bind_service_identity(binding).await,
            Command::NodeImageReader(request) => node_image_reader(request).await,
            Command::EnrollNode(enrollment) => enroll(enrollment).await,
            Command::NodeFence(incident) => fence(incident).await,
            Command::GuardContract(contract) => guard_contract(contract).await,
            Command::BackupProfile(profile) => backup_cli::run(profile).await,
        };
    }
    let mut bytes = Vec::new();
    File::open(
        args.file
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--file is required"))?,
    )?
    .take((MAX_BOOTSTRAP_BYTES + 1) as u64)
    .read_to_end(&mut bytes)?;
    let spec = parse_spec(&bytes, args.allow_loopback_http)?;
    if args
        .initialize_cluster_epoch
        .is_some_and(|epoch| epoch.is_nil())
    {
        anyhow::bail!("cluster epoch must not be nil");
    }
    if args.validate_only {
        println!(
            "{}",
            serde_json::json!({"validated":true,"database_checked":false,"spec_sha256":spec.sha256()?,"tenant_id":spec.tenant.id,"project_id":spec.project.id})
        );
        return Ok(());
    }
    let url = args
        .database_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("SANDBOX_ADMIN_DATABASE_URL is required for --apply"))?;
    let database = Database::connect_for_process(url, 2, DatabaseProcessRole::Admin).await?;
    let report = apply_bootstrap(
        &database,
        &spec,
        args.initialize_cluster_epoch,
        args.allow_loopback_http,
    )
    .await?;
    println!("{}", serde_json::to_string(&report)?);
    database.pool.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backup_profile_actions_require_durable_reference_and_explicit_mode() {
        let base = [
            "sandbox-admin",
            "backup-profile",
            "register",
            "--file",
            "profile.json",
            "--certification-report",
            "report.json",
            "--request-id",
            "00000000-0000-4000-8000-000000000001",
            "--approval-reference",
            "CHANGE-123",
        ];
        assert!(Args::try_parse_from(base).is_err());
        let mut args = base.to_vec();
        args.push("--validate-only");
        assert!(Args::try_parse_from(&args).is_ok());
        args.push("--apply");
        assert!(Args::try_parse_from(args).is_err());
        assert!(
            Args::try_parse_from([
                "sandbox-admin",
                "backup-profile",
                "revoke",
                "--profile-id",
                "00000000-0000-4000-8000-000000000002",
                "--request-id",
                "00000000-0000-4000-8000-000000000001",
                "--approval-reference",
                "CHANGE-123",
                "--apply"
            ])
            .is_ok()
        );
    }
    #[test]
    fn node_fence_requires_one_explicit_mode() {
        let args = [
            "sandbox-admin",
            "node-fence",
            "--file",
            "incident.json",
            "--validate-only",
        ];
        assert!(Args::try_parse_from(args).is_ok());
        assert!(Args::try_parse_from(&args[..args.len() - 1]).is_err());
        let mut both = args.to_vec();
        both.push("--apply");
        assert!(Args::try_parse_from(both).is_err());
    }
    #[test]
    fn legacy_bootstrap_and_enrollment_have_separate_explicit_modes() {
        assert!(
            Args::try_parse_from([
                "sandbox-admin",
                "--file",
                "bootstrap.json",
                "--validate-only"
            ])
            .is_ok()
        );
        let args = [
            "sandbox-admin",
            "enroll-node",
            "--file",
            "node.json",
            "--terraform-output",
            "terraform.json",
            "--cluster-settings",
            "settings.json",
            "--certification-report",
            "report.json",
            "--validate-only",
        ];
        assert!(Args::try_parse_from(args).is_ok());
        assert!(Args::try_parse_from(&args[..args.len() - 1]).is_err());
        let mut both = args.to_vec();
        both.push("--apply");
        assert!(Args::try_parse_from(both).is_err());
        assert!(
            Args::try_parse_from([
                "sandbox-admin",
                "--file",
                "bootstrap.json",
                "--validate-only",
                "enroll-node",
                "--help"
            ])
            .is_err()
        );
    }
}
