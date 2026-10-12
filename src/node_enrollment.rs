//! Owner-only enrollment binds reviewed inventory to two live identities. A
//! successful enrollment never clears node quarantine or certifies test evidence.
use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, ensure};
use chrono::{DateTime, Utc};
use k8s_openapi::api::core::v1::Node;
use kube::Api;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::{
    db::Database,
    nodeguard::protocol::{NodeBinding, valid_sha256},
    runtime::KubernetesRuntime,
    termination_client::{NodeguardClient, NodeguardCredentials},
};

pub const MAX_ENROLLMENT_BYTES: usize = 1024 * 1024;
pub const CERTIFICATION_CHECKS: [&str; 9] = [
    "kata_process_coverage",
    "cri_start_fencing",
    "crash_recovery_unknown",
    "workspace_single_writer",
    "csi_late_publish_unmount",
    "first_packet_network_isolation",
    "node_boot_reenrollment",
    "cloud_fence_prevents_revival",
    "cloud_volume_detach_safety",
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentArtifact {
    pub protocol: u32,
    pub node: NodeBinding,
    pub cloud_account_id: String,
    pub region: String,
    pub cloud_instance_id: String,
    pub private_ip: IpAddr,
    pub guard_port: u16,
    pub certification_id: String,
}

// These fields are a subset of the independently reviewed cluster settings.
#[derive(Deserialize)]
struct EnrollmentSettings {
    deployment: String,
    region: String,
    oidc_provider_arn: String,
    cluster_epoch: Uuid,
    certification_id: String,
    certification_report_sha256: String,
    nodeguard_binary_sha256: String,
    versions_lock_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificationReport {
    protocol: u32,
    certification_id: String,
    cluster_epoch: Uuid,
    versions_lock_sha256: String,
    nodeguard_binary_sha256: String,
    reviewed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    nodes: Vec<CertifiedNode>,
    checks: BTreeMap<String, CertificationCheck>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CertifiedNode {
    node: NodeBinding,
    cloud_instance_id: String,
    private_ip: IpAddr,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificationCheck {
    status: String,
    evidence_sha256: String,
}
#[derive(Deserialize)]
struct TerraformOutput<T> {
    value: T,
    sensitive: bool,
}
#[derive(Deserialize)]
struct TerraformOutputs {
    deployment_identity: TerraformOutput<DeploymentIdentity>,
    node_inventory: TerraformOutput<BTreeMap<String, InventoryNode>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentIdentity {
    cloud_account_id: String,
    region: String,
    deployment: String,
    environment: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryNode {
    id: String,
    private_ip: IpAddr,
    role: String,
    zone: String,
}

/// Constructed only by validation of all four inputs. The content hashes record
/// exact reviewed bytes, not a lossy reserialization of a JSON document.
pub struct EnrollmentPlan {
    artifact: EnrollmentArtifact,
    artifact_sha256: String,
    terraform_output_sha256: String,
    settings_sha256: String,
    certification_report_sha256: String,
    expires_at: DateTime<Utc>,
    reviewed_at: DateTime<Utc>,
    renewal: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentReceipt {
    pub protocol: u32,
    pub enrollment_id: Uuid,
    pub runtime_node_id: Uuid,
    pub node: NodeBinding,
    pub cloud_account_id: String,
    pub region: String,
    pub cloud_instance_id: String,
    pub private_ip: IpAddr,
    pub guard_port: u16,
    pub certification_id: String,
    pub certification_report_sha256: String,
    pub artifact_sha256: String,
    pub terraform_output_sha256: String,
    pub registered_at: DateTime<Utc>,
    pub changed: bool,
    pub enabled: bool,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> anyhow::Result<T> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_ENROLLMENT_BYTES,
        "enrollment input exceeds the 1 MiB limit"
    );
    serde_json::from_slice(bytes).context("invalid enrollment JSON schema")
}
fn private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private(),
        IpAddr::V6(ip) => ip.is_unique_local(),
    }
}
fn identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

impl EnrollmentPlan {
    pub fn parse(
        artifact: &[u8],
        terraform: &[u8],
        settings: &[u8],
        report: &[u8],
        now: DateTime<Utc>,
    ) -> anyhow::Result<Self> {
        let artifact_sha256 = digest(artifact);
        let terraform_output_sha256 = digest(terraform);
        let settings_sha256 = digest(settings);
        let certification_report_sha256 = digest(report);
        let artifact: EnrollmentArtifact = parse(artifact)?;
        let terraform: TerraformOutputs = parse(terraform)?;
        let settings: EnrollmentSettings = parse(settings)?;
        let report: CertificationReport = parse(report)?;
        ensure!(
            artifact.protocol == 1
                && artifact.node.validate()
                && artifact.guard_port == 9444
                && private_ip(artifact.private_ip),
            "invalid node enrollment identity or private endpoint"
        );
        ensure!(
            artifact.cloud_account_id.len() == 16
                && artifact
                    .cloud_account_id
                    .bytes()
                    .all(|b| b.is_ascii_digit())
                && identifier(&artifact.region, 64)
                && identifier(&artifact.cloud_instance_id, 128)
                && artifact.cloud_instance_id.strip_prefix("i-").is_some_and(
                    |id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric())
                )
                && identifier(&artifact.certification_id, 128),
            "invalid cloud identity or certification reference"
        );
        ensure!(
            !terraform.deployment_identity.sensitive && !terraform.node_inventory.sensitive,
            "use nonsecret terraform output -json inventory"
        );
        let arn_prefix = format!("acs:ram::{}:oidc-provider/", artifact.cloud_account_id);
        let provider = settings
            .oidc_provider_arn
            .strip_prefix(&arn_prefix)
            .context("cloud account differs from the independently reviewed OIDC provider ARN")?;
        ensure!(
            identifier(provider, 128),
            "invalid independently reviewed OIDC provider ARN"
        );
        let deployment = terraform.deployment_identity.value;
        ensure!(
            deployment.cloud_account_id == artifact.cloud_account_id
                && deployment.region == artifact.region
                && deployment.region == settings.region
                && deployment.deployment == settings.deployment
                && matches!(
                    deployment.environment.as_str(),
                    "production" | "preproduction"
                ),
            "Terraform deployment identity does not match reviewed settings"
        );
        ensure!(
            settings.cluster_epoch == artifact.node.cluster_epoch
                && report.cluster_epoch == settings.cluster_epoch
                && report.protocol == 1
                && report.certification_id == artifact.certification_id
                && settings.certification_id == artifact.certification_id
                && settings.certification_report_sha256 == certification_report_sha256,
            "certification report is not the independently pinned report for this epoch"
        );
        let versions_hash = digest(include_bytes!("../deploy/cluster/versions.lock.json"));
        ensure!(
            settings.versions_lock_sha256 == versions_hash
                && report.versions_lock_sha256 == versions_hash
                && valid_sha256(&settings.nodeguard_binary_sha256)
                && report.nodeguard_binary_sha256 == settings.nodeguard_binary_sha256,
            "certification runtime versions or nodeguard binary differ"
        );
        ensure!(
            report.reviewed_at <= now
                && report.expires_at > now
                && report.expires_at > report.reviewed_at
                && report.expires_at <= report.reviewed_at + chrono::Duration::days(30),
            "certification review is expired, future dated or exceeds 30 days"
        );
        ensure!(
            report.checks.len() == CERTIFICATION_CHECKS.len()
                && CERTIFICATION_CHECKS
                    .iter()
                    .all(|key| report.checks.get(*key).is_some_and(
                        |check| check.status == "PASS" && valid_sha256(&check.evidence_sha256)
                    )),
            "certification is missing required reviewed test evidence"
        );
        let inventory = terraform.node_inventory.value;
        let kata: BTreeMap<_, _> = inventory
            .iter()
            .filter(|(_, entry)| entry.role == "kata")
            .collect();
        ensure!(
            !kata.is_empty() && kata.len() <= 4096 && report.nodes.len() == kata.len(),
            "report must cover exactly the Terraform Kata pool"
        );
        let mut names = HashSet::new();
        let mut uids = HashSet::new();
        let mut boots = HashSet::new();
        let mut instances = HashSet::new();
        let mut addresses = HashSet::new();
        for item in &report.nodes {
            ensure!(
                item.node.validate()
                    && item.node.cluster_epoch == report.cluster_epoch
                    && names.insert(&item.node.node_name)
                    && uids.insert(item.node.node_uid)
                    && boots.insert(item.node.boot_id)
                    && instances.insert(&item.cloud_instance_id)
                    && addresses.insert(item.private_ip),
                "duplicate or invalid certified node"
            );
            let expected = kata
                .get(&item.node.node_name)
                .context("certified node is not in the Kata inventory")?;
            ensure!(
                item.cloud_instance_id == expected.id
                    && item.private_ip == expected.private_ip
                    && private_ip(item.private_ip)
                    && identifier(&expected.zone, 64),
                "certified cloud node differs from Terraform inventory"
            );
        }
        ensure!(
            report.nodes.iter().any(|item| item.node == artifact.node
                && item.cloud_instance_id == artifact.cloud_instance_id
                && item.private_ip == artifact.private_ip),
            "host artifact is not an exact certified node"
        );
        Ok(Self {
            artifact,
            artifact_sha256,
            terraform_output_sha256,
            settings_sha256,
            certification_report_sha256,
            expires_at: report.expires_at,
            reviewed_at: report.reviewed_at,
            renewal: false,
        })
    }
    /// Explicit operator intent: append newer certification for the exact
    /// existing enabled identity; never rebind, reactivate or clear quarantine.
    pub fn renewing_certification(mut self) -> Self {
        self.renewal = true;
        self
    }
    pub fn validation_report(&self) -> serde_json::Value {
        serde_json::json!({"validated":true,"database_checked":false,"live_identity_checked":false,"quarantine_removed":false,"renew_certification":self.renewal,"node":self.artifact.node,"artifact_sha256":self.artifact_sha256,"certification_report_sha256":self.certification_report_sha256})
    }
}

fn validate_live_node(
    node: &Node,
    artifact: &EnrollmentArtifact,
    renewal: bool,
) -> anyhow::Result<String> {
    ensure!(
        node.metadata.name.as_deref() == Some(artifact.node.node_name.as_str())
            && node.metadata.uid.as_deref() == Some(artifact.node.node_uid.to_string().as_str())
            && node.metadata.deletion_timestamp.is_none(),
        "live Kubernetes Node identity differs"
    );
    let version = node
        .metadata
        .resource_version
        .clone()
        .filter(|v| !v.is_empty())
        .context("Node has no resource version")?;
    let status = node.status.as_ref().context("Node status is absent")?;
    let info = status
        .node_info
        .as_ref()
        .context("Node system identity is absent")?;
    ensure!(
        info.boot_id == artifact.node.boot_id.to_string()
            && info.operating_system == "linux"
            && info.architecture == "amd64",
        "Node boot identity or platform differs"
    );
    ensure!(
        status.addresses.as_ref().is_some_and(|addresses| addresses
            .iter()
            .any(|address| address.type_ == "InternalIP"
                && address.address.parse::<IpAddr>().ok() == Some(artifact.private_ip))),
        "Node InternalIP differs from enrolled private endpoint"
    );
    ensure!(
        node.metadata
            .labels
            .as_ref()
            .and_then(|v| v.get("sandbox.platform/worker-pool"))
            .map(String::as_str)
            == Some("kata")
            && node
                .metadata
                .annotations
                .as_ref()
                .and_then(|v| v.get("sandbox.platform/runtime-profile-sha256"))
                == Some(&artifact.node.profile_sha256),
        "Node runtime profile or worker pool differs"
    );
    // Initial enrollment requires quarantine. Explicit renewal keeps the exact
    // existing identity and can occur while the node continues serving work.
    let taints = node
        .spec
        .as_ref()
        .and_then(|spec| spec.taints.as_ref())
        .context("Node quarantine taints are absent")?;
    for key in ["sandbox.platform/untrusted", "sandbox.platform/unverified"] {
        if renewal && key == "sandbox.platform/unverified" {
            continue;
        }
        ensure!(
            taints.iter().any(|taint| taint.key == key
                && taint.value.as_deref() == Some("true")
                && taint.effect == "NoSchedule"),
            "Node quarantine or untrusted taint is absent"
        );
    }
    ensure!(
        status
            .conditions
            .as_ref()
            .is_some_and(|conditions| conditions
                .iter()
                .any(|condition| condition.type_ == "Ready" && condition.status == "True")),
        "Node is not Ready for enrollment"
    );
    Ok(version)
}

struct LiveEnrollment {
    resource_version: String,
    observed_at: DateTime<Utc>,
}
async fn observe_node(
    runtime: &KubernetesRuntime,
    client: &NodeguardClient,
    artifact: &EnrollmentArtifact,
    renewal: bool,
) -> anyhow::Result<LiveEnrollment> {
    ensure!(
        client.node_binding() == &artifact.node,
        "node enrollment client identity differs from the reviewed node"
    );
    let nodes: Api<Node> = Api::all(runtime.client_clone());
    let before = nodes
        .get(&artifact.node.node_name)
        .await
        .map_err(|_| anyhow::anyhow!("cannot read enrollment Node"))?;
    validate_live_node(&before, artifact, renewal)?;
    client.verify_node().await?;
    let after = nodes
        .get(&artifact.node.node_name)
        .await
        .map_err(|_| anyhow::anyhow!("cannot recheck enrollment Node"))?;
    let resource_version = validate_live_node(&after, artifact, renewal)?;
    Ok(LiveEnrollment {
        resource_version,
        observed_at: Utc::now(),
    })
}

pub async fn enroll_node(
    database: &Database,
    runtime: &KubernetesRuntime,
    credentials: &NodeguardCredentials,
    plan: &EnrollmentPlan,
) -> anyhow::Result<EnrollmentReceipt> {
    // Verify owner before making any privileged network request.
    let owner: bool = sqlx::query_scalar("SELECT count(*)=3 AND bool_and(pg_has_role(current_user,c.relowner,'USAGE')) FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relname=ANY(ARRAY['runtime_nodes','runtime_node_enrollments','platform_configuration'])").fetch_one(&database.pool).await?;
    ensure!(
        owner,
        "node enrollment requires the dedicated installation owner connection"
    );
    let client = NodeguardClient::new(
        plan.artifact.node.clone(),
        SocketAddr::new(plan.artifact.private_ip, plan.artifact.guard_port),
        credentials,
    )?;
    let live = tokio::time::timeout(
        Duration::from_secs(25),
        observe_node(runtime, &client, &plan.artifact, plan.renewal),
    )
    .await
    .context("live node enrollment verification timed out")??;
    commit_enrollment(database, plan, live).await
}

// Test-only loopback transport seam. The private LiveEnrollment is created only
// by the same actual Node/mTLS/Node reads as production, never by test data.
#[cfg(test)]
pub(crate) async fn enroll_with_client_test(
    database: &Database,
    runtime: &KubernetesRuntime,
    client: &NodeguardClient,
    plan: &EnrollmentPlan,
) -> anyhow::Result<EnrollmentReceipt> {
    let owner: bool = sqlx::query_scalar("SELECT count(*)=3 AND bool_and(pg_has_role(current_user,c.relowner,'USAGE')) FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relname=ANY(ARRAY['runtime_nodes','runtime_node_enrollments','platform_configuration'])")
        .fetch_one(&database.pool).await?;
    ensure!(
        owner,
        "node enrollment requires the dedicated installation owner connection"
    );
    let live = tokio::time::timeout(
        Duration::from_secs(25),
        observe_node(runtime, client, &plan.artifact, plan.renewal),
    )
    .await
    .context("live node enrollment verification timed out")??;
    commit_enrollment(database, plan, live).await
}

async fn commit_enrollment(
    database: &Database,
    plan: &EnrollmentPlan,
    live: LiveEnrollment,
) -> anyhow::Result<EnrollmentReceipt> {
    let a = &plan.artifact;
    let mut tx = database.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(0x5342_584e_4f44_4501_i64)
        .execute(&mut *tx)
        .await?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    ensure!(
        now < plan.expires_at
            && live.observed_at >= now - chrono::Duration::seconds(10)
            && live.observed_at <= now + chrono::Duration::seconds(2),
        "node identity observation or certification expired before commit"
    );
    let epoch: Uuid = sqlx::query_scalar(
        "SELECT cluster_epoch FROM platform_configuration WHERE singleton FOR SHARE",
    )
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
        epoch == a.node.cluster_epoch,
        "node belongs to a different database cluster epoch"
    );
    let existing = sqlx::query("SELECT id,enabled FROM runtime_nodes WHERE cluster_epoch=$1 AND node_uid=$2 AND boot_id=$3 FOR UPDATE").bind(epoch).bind(a.node.node_uid).bind(a.node.boot_id).fetch_optional(&mut *tx).await?;
    let id = if let Some(row) = existing {
        let id: Uuid = row.try_get("id")?;
        ensure!(
            row.try_get::<bool, _>("enabled")?,
            "disabled node cannot be reactivated by enrollment"
        );
        let previous: Option<(serde_json::Value, String, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as("SELECT receipt,settings_sha256,certification_expires_at,certification_reviewed_at FROM runtime_node_enrollments WHERE runtime_node_id=$1 ORDER BY certification_expires_at DESC, registered_at DESC,id DESC LIMIT 1").bind(id).fetch_optional(&mut *tx).await?;
        let (previous, settings_hash, previous_expiry, previous_review) = previous
            .context("existing node has no audited enrollment; use explicit maintenance")?;
        let mut receipt: EnrollmentReceipt = serde_json::from_value(previous)?;
        ensure!(
            receipt.node == a.node
                && receipt.cloud_account_id == a.cloud_account_id
                && receipt.region == a.region
                && receipt.cloud_instance_id == a.cloud_instance_id
                && receipt.private_ip == a.private_ip
                && receipt.guard_port == a.guard_port,
            "existing node identity is immutable and differs from these inputs"
        );
        if receipt.artifact_sha256 == plan.artifact_sha256
            && receipt.terraform_output_sha256 == plan.terraform_output_sha256
            && receipt.certification_report_sha256 == plan.certification_report_sha256
            && settings_hash == plan.settings_sha256
        {
            receipt.changed = false;
            tx.commit().await?;
            return Ok(receipt);
        }
        ensure!(
            plan.renewal,
            "existing enrollment differs; use explicit --renew-certification with newer reviewed evidence"
        );
        ensure!(
            plan.expires_at > previous_expiry && plan.reviewed_at > previous_review,
            "certification renewal must advance both review time and expiry"
        );
        id
    } else {
        ensure!(
            !plan.renewal,
            "certification renewal requires an existing audited node identity"
        );
        let occupied: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM runtime_nodes WHERE (enabled AND cluster_epoch=$1 AND (node_uid=$2 OR node_name=$3)) OR (cloud_account_id=$4 AND region=$5 AND (cloud_instance_id=$6 OR (enabled AND private_ip=$7::inet))))")
            .bind(epoch).bind(a.node.node_uid).bind(&a.node.node_name).bind(&a.cloud_account_id).bind(&a.region).bind(&a.cloud_instance_id).bind(a.private_ip.to_string()).fetch_one(&mut *tx).await?;
        ensure!(
            !occupied,
            "historical cloud instance or active node identity requires the independent fenced-maintenance workflow"
        );
        sqlx::query_scalar("INSERT INTO runtime_nodes(cluster_epoch,node_uid,node_name,cloud_provider,cloud_account_id,region,cloud_instance_id,private_ip,guard_port,profile_sha256,boot_id,enabled) VALUES($1,$2,$3,'alicloud',$4,$5,$6,$7::inet,$8,$9,$10,true) RETURNING id")
            .bind(epoch).bind(a.node.node_uid).bind(&a.node.node_name).bind(&a.cloud_account_id).bind(&a.region).bind(&a.cloud_instance_id).bind(a.private_ip.to_string()).bind(i32::from(a.guard_port)).bind(&a.node.profile_sha256).bind(a.node.boot_id).fetch_one(&mut *tx).await?
    };
    let receipt = EnrollmentReceipt {
        protocol: 1,
        enrollment_id: Uuid::new_v4(),
        runtime_node_id: id,
        node: a.node.clone(),
        cloud_account_id: a.cloud_account_id.clone(),
        region: a.region.clone(),
        cloud_instance_id: a.cloud_instance_id.clone(),
        private_ip: a.private_ip,
        guard_port: a.guard_port,
        certification_id: a.certification_id.clone(),
        certification_report_sha256: plan.certification_report_sha256.clone(),
        artifact_sha256: plan.artifact_sha256.clone(),
        terraform_output_sha256: plan.terraform_output_sha256.clone(),
        registered_at: now,
        changed: true,
        enabled: true,
    };
    sqlx::query("INSERT INTO runtime_node_enrollments(id,runtime_node_id,cluster_epoch,artifact_sha256,terraform_output_sha256,settings_sha256,certification_report_sha256,certification_expires_at,observed_node_resource_version,observed_at,database_role,receipt,registered_at,certification_reviewed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,current_user,$11,$12,$13)")
        .bind(receipt.enrollment_id).bind(id).bind(epoch).bind(&plan.artifact_sha256).bind(&plan.terraform_output_sha256).bind(&plan.settings_sha256).bind(&plan.certification_report_sha256).bind(plan.expires_at).bind(live.resource_version).bind(live.observed_at).bind(serde_json::to_value(&receipt)?).bind(now).bind(plan.reviewed_at).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(receipt)
}

#[cfg(test)]
#[path = "node_enrollment_tests.rs"]
mod tests;
