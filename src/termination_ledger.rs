//! Trusted host termination and Kubernetes cleanup are separate, durable gates.
//! No caller-provided JSON, Pod absence, elapsed timeout or guest receipt can
//! release a running launch. Remote requests never hold these transactions.
use crate::{
    db::{Actor, Database, reserve_quota},
    engine::{Claim, OperationEngine},
    error::ApiError,
    gateway_runtime::KnownRuntimeResources,
    nodeguard::protocol::{
        CloseReason, CloseRequest, GateState, LaunchBinding, NodeBinding, ObservationState,
        PROTOCOL_VERSION, RegisterLaunchRequest,
    },
    runtime_manifest::RuntimeManifestContext,
    termination_client::{VerifiedLaunchRegistration, VerifiedLocalTermination},
    termination_runtime::VerifiedPodCleanup,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[path = "instance_deletion.rs"]
mod instance_deletion;
#[path = "never_authorized.rs"]
mod never_authorized;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TerminationCandidate {
    pub tenant_id: Uuid,
    pub operation_id: Uuid,
}
#[derive(Debug, Clone)]
pub struct RuntimeNode {
    pub id: Uuid,
    pub node: NodeBinding,
    pub private_ip: String,
    pub guard_port: u16,
    pub cloud_account_id: String,
    pub region: String,
    pub cloud_instance_id: String,
    pub enabled: bool,
}
#[derive(Debug, Clone)]
pub struct LaunchPermit {
    pub request: RegisterLaunchRequest,
    pub node: RuntimeNode,
}
/// The base permit identifies a launch forever; a newer registration request
/// extends only its admission deadline and never changes termination identity.
#[derive(Debug, Clone)]
pub struct LaunchAuthorization {
    pub base_permit: LaunchPermit,
    pub request: RegisterLaunchRequest,
    pub lease_version: i64,
}
#[derive(Debug, Clone)]
pub struct TerminationChallenge {
    pub request: CloseRequest,
    pub permit: LaunchPermit,
}
#[derive(Debug, Clone)]
pub struct TerminationTarget {
    pub tenant_id: Uuid,
    pub project_id: Uuid,
    pub operation_id: Uuid,
    pub instance_id: Uuid,
    pub workspace_id: Uuid,
    pub kind: String,
    pub stage: String,
    pub observed_state: String,
    pub generation: i64,
    pub launch_id: Uuid,
    pub cluster_epoch: Uuid,
    pub pod_uid: Option<Uuid>,
    pub namespace: String,
    pub pod_name: String,
    pub pvc_name: String,
    pub compute_lease_expires_at: DateTime<Utc>,
    pub permit: Option<LaunchPermit>,
    pub context: RuntimeManifestContext,
    pub known_resources: Option<KnownRuntimeResources>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationCompletion {
    Stopped,
    RestartQueued,
    RestartBlocked,
    InstanceDeleted,
}
impl TerminationCompletion {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "STOPPED",
            Self::RestartQueued => "RESTART_QUEUED",
            Self::RestartBlocked => "RESTART_BLOCKED",
            Self::InstanceDeleted => "INSTANCE_DELETED",
        }
    }
}
#[derive(sqlx::FromRow)]
struct Current {
    tenant_id: Uuid,
    project_id: Uuid,
    instance_id: Uuid,
    workspace_id: Uuid,
    operation_id: Uuid,
    kind: String,
    stage: String,
    observed_state: String,
    generation: i64,
    launch_id: Uuid,
    cluster_epoch: Uuid,
    pod_uid: Option<Uuid>,
    namespace: String,
    pod_name: String,
    pvc_name: String,
    actor_principal_id: Uuid,
    request_id: Uuid,
    compute_lease_expires_at: DateTime<Utc>,
    compute_lease_id: Uuid,
    compute_lease_version: i64,
    restart_generation: Option<i64>,
    current_epoch: Uuid,
    safe_mode: bool,
    desired_state: String,
    stop_accepted_at: Option<DateTime<Utc>>,
    workspace_status: String,
    policy_approved: bool,
    template_approved: bool,
    cpu_millis: i64,
    memory_mib: i64,
    storage_class: String,
    image_ref: String,
    image_digest: String,
    policy_rules: Value,
    size_gib: i64,
    slot_held: bool,
    activity_id: Option<Uuid>,
    activity_kind: Option<String>,
    activity_generation: Option<i64>,
    #[sqlx(skip)]
    restore_binding: Option<crate::workspace_restore::WorkspaceRestoreBinding>,
}
impl Current {
    fn compute(&self) -> bool {
        matches!(self.kind.as_str(), "CREATE" | "START")
            || (self.kind == "RESTART" && self.restart_generation == Some(self.generation))
    }
    fn matches(&self, b: &LaunchBinding) -> bool {
        self.tenant_id == b.tenant_id
            && self.project_id == b.project_id
            && self.instance_id == b.instance_id
            && self.workspace_id == b.workspace_id
            && self.generation == b.generation
            && self.launch_id == b.launch_id
            && self.pod_uid == Some(b.pod_uid)
            && self.namespace == b.namespace
            && self.pod_name == b.pod_name
    }
    fn context(&self) -> RuntimeManifestContext {
        RuntimeManifestContext {
            tenant_id: self.tenant_id,
            project_id: self.project_id,
            instance_id: self.instance_id,
            workspace_id: self.workspace_id,
            launch_id: self.launch_id,
            cluster_epoch: self.cluster_epoch,
            generation: self.generation,
            namespace: self.namespace.clone(),
            storage_class: self.storage_class.clone(),
            workspace_snapshot: self
                .restore_binding
                .as_ref()
                .map(|v| v.snapshot_name.clone()),
            image_ref: self.image_ref.clone(),
            image_digest: self.image_digest.clone(),
            template_approved: self.template_approved || !self.compute(),
            security_policy_approved: self.policy_approved || !self.compute(),
            security_policy_rules: self.policy_rules.clone(),
            cpu_millis: self.cpu_millis,
            memory_mib: self.memory_mib,
            workspace_size_gib: self.size_gib,
        }
    }
    fn actor(&self) -> Actor {
        Actor {
            authorization: None,
            tenant_id: self.tenant_id,
            principal_id: self.actor_principal_id,
            request_id: self.request_id,
        }
    }
}
#[derive(sqlx::FromRow)]
struct NodeRow {
    id: Uuid,
    cluster_epoch: Uuid,
    node_uid: Uuid,
    node_name: String,
    boot_id: Uuid,
    profile_sha256: String,
    private_ip: String,
    guard_port: i32,
    cloud_account_id: String,
    region: String,
    cloud_instance_id: String,
    enabled: bool,
}
impl TryFrom<NodeRow> for RuntimeNode {
    type Error = ApiError;
    fn try_from(r: NodeRow) -> Result<Self, ApiError> {
        Ok(Self {
            id: r.id,
            node: NodeBinding {
                cluster_epoch: r.cluster_epoch,
                node_uid: r.node_uid,
                node_name: r.node_name,
                boot_id: r.boot_id,
                profile_sha256: r.profile_sha256,
            },
            private_ip: r.private_ip,
            guard_port: r
                .guard_port
                .try_into()
                .map_err(|_| blocked("NODE_INVENTORY_INVALID"))?,
            cloud_account_id: r.cloud_account_id,
            region: r.region,
            cloud_instance_id: r.cloud_instance_id,
            enabled: r.enabled,
        })
    }
}
#[derive(sqlx::FromRow)]
struct PermitRow {
    id: Uuid,
    tenant_id: Uuid,
    project_id: Uuid,
    instance_id: Uuid,
    workspace_id: Uuid,
    runtime_node_id: Uuid,
    generation: i64,
    launch_id: Uuid,
    pod_uid: Uuid,
    namespace: String,
    pod_name: String,
    pvc_uid: Uuid,
    pv_uid: Uuid,
    pv_name: String,
    csi_volume_handle: String,
    expires_at: DateTime<Utc>,
}
#[derive(sqlx::FromRow)]
struct ChallengeRow {
    id: Uuid,
    permit_id: Uuid,
    operation_id: Uuid,
    lease_token: i64,
    reason: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}
const CURRENT_SQL: &str = "SELECT i.tenant_id,i.project_id,i.id AS instance_id,i.workspace_id,o.id AS operation_id,o.kind,o.stage,i.observed_state,i.runtime_generation AS generation,i.launch_id,i.cluster_epoch,i.pod_uid,i.namespace,i.pod_name,w.pvc_name,o.actor_principal_id,o.request_id,i.compute_lease_expires_at,i.compute_lease_id,i.compute_lease_version,o.restart_generation,c.cluster_epoch AS current_epoch,c.safe_mode,i.desired_state,i.stop_accepted_at,w.status AS workspace_status,p.status='APPROVED' AS policy_approved,t.status='APPROVED' AS template_approved,i.cpu_millis,i.memory_mib,w.storage_class,t.image_ref,t.image_digest,p.rules AS policy_rules,w.size_gib,i.slot_held,i.activity_id,i.activity_kind,i.activity_generation FROM operations o JOIN instances i ON i.tenant_id=o.tenant_id AND i.id=o.instance_id AND i.workspace_id=o.workspace_id JOIN workspaces w ON w.tenant_id=i.tenant_id AND w.id=i.workspace_id JOIN template_versions t ON t.tenant_id=i.tenant_id AND t.id=i.template_version_id JOIN security_policy_versions p ON p.tenant_id=i.tenant_id AND p.id=i.security_policy_version_id CROSS JOIN platform_configuration c WHERE o.tenant_id=$1 AND o.id=$2 AND i.active_operation_id=o.id AND (w.active_operation_id IS NULL OR w.active_operation_id=o.id) AND o.status IN('QUEUED','RUNNING','WAITING') AND c.singleton";

impl Database {
    pub async fn launch_registration_candidates(
        &self,
        limit: i32,
    ) -> Result<Vec<TerminationCandidate>, ApiError> {
        if !(1..=100).contains(&limit) {
            return Err(ApiError::invalid("candidate limit must be 1..100"));
        }
        Ok(
            sqlx::query_as("SELECT * FROM sandbox_launch_registration_candidates($1)")
                .bind(limit)
                .fetch_all(&self.pool)
                .await?,
        )
    }
    pub async fn load_termination_target(
        &self,
        tenant: Uuid,
        operation: Uuid,
    ) -> Result<TerminationTarget, ApiError> {
        let mut tx = self.begin(tenant).await?;
        let s = current(&mut tx, tenant, operation).await?;
        let permit = find_permit(&mut tx, &s).await?;
        let context = s.context();
        let known_resources = known_resources(&mut tx, &s).await?;
        let result = TerminationTarget {
            tenant_id: s.tenant_id,
            project_id: s.project_id,
            operation_id: s.operation_id,
            instance_id: s.instance_id,
            workspace_id: s.workspace_id,
            kind: s.kind,
            stage: s.stage,
            observed_state: s.observed_state,
            generation: s.generation,
            launch_id: s.launch_id,
            cluster_epoch: s.cluster_epoch,
            pod_uid: s.pod_uid,
            namespace: s.namespace,
            pod_name: s.pod_name,
            pvc_name: s.pvc_name,
            compute_lease_expires_at: s.compute_lease_expires_at,
            permit,
            context,
            known_resources,
        };
        tx.commit().await?;
        Ok(result)
    }
    pub async fn registered_runtime_node(
        &self,
        node: &NodeBinding,
    ) -> Result<RuntimeNode, ApiError> {
        if !node.validate() {
            return Err(blocked("NODE_INVENTORY_INVALID"));
        }
        let mut tx = self.pool.begin().await?;
        let r:Option<NodeRow>=sqlx::query_as("SELECT id,cluster_epoch,node_uid,node_name,boot_id,profile_sha256,host(private_ip) AS private_ip,guard_port,cloud_account_id,region,cloud_instance_id,enabled FROM runtime_nodes WHERE cluster_epoch=$1 AND node_uid=$2 AND boot_id=$3 AND enabled")
            .bind(node.cluster_epoch).bind(node.node_uid).bind(node.boot_id).fetch_optional(&mut *tx).await?;
        let r = RuntimeNode::try_from(r.ok_or_else(|| blocked("NODE_NOT_ENROLLED"))?)?;
        if &r.node != node {
            return Err(blocked("NODE_IDENTITY_CHANGED"));
        }
        require_certification(&mut tx, r.id, None).await?;
        tx.commit().await?;
        Ok(r)
    }
    pub async fn prepare_launch_permit(
        &self,
        tenant: Uuid,
        operation: Uuid,
        node: &NodeBinding,
        launch: &LaunchBinding,
    ) -> Result<LaunchPermit, ApiError> {
        Ok(self
            .prepare_launch_authorization(tenant, operation, node, launch)
            .await?
            .base_permit)
    }
    pub async fn prepare_launch_authorization(
        &self,
        tenant: Uuid,
        operation: Uuid,
        node: &NodeBinding,
        launch: &LaunchBinding,
    ) -> Result<LaunchAuthorization, ApiError> {
        if !node.validate() || !launch.validate() {
            return Err(blocked("LAUNCH_BINDING_INVALID"));
        }
        let (mut tx, s) = lock_current(self, tenant, operation).await?;
        if s.restore_binding
            .as_ref()
            .is_some_and(|binding| !binding.matches_launch(launch))
        {
            return Err(blocked("RESTORED_VOLUME_IDENTITY_CHANGED"));
        }
        if !s.compute() || !s.matches(launch) || s.cluster_epoch != node.cluster_epoch {
            return Err(blocked("LAUNCH_IDENTITY_CHANGED"));
        }
        authorize_compute(&mut tx, &s).await?;
        let n:Option<NodeRow>=sqlx::query_as("SELECT id,cluster_epoch,node_uid,node_name,boot_id,profile_sha256,host(private_ip) AS private_ip,guard_port,cloud_account_id,region,cloud_instance_id,enabled FROM runtime_nodes WHERE cluster_epoch=$1 AND node_uid=$2 AND boot_id=$3 AND enabled")
            .bind(node.cluster_epoch).bind(node.node_uid).bind(node.boot_id).fetch_optional(&mut *tx).await?;
        let n = RuntimeNode::try_from(n.ok_or_else(|| blocked("NODE_NOT_ENROLLED"))?)?;
        if &n.node != node {
            return Err(blocked("NODE_IDENTITY_CHANGED"));
        }
        require_certification(&mut tx, n.id, Some(s.compute_lease_expires_at)).await?;
        let pvc:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM external_resources WHERE tenant_id=$1 AND instance_id=$2 AND workspace_id=$3 AND provider='kubernetes' AND kind='PVC' AND provider_id=$4 AND owner_id=$3 AND generation=1 AND status='ACTIVE')")
            .bind(tenant).bind(s.instance_id).bind(s.workspace_id).bind(launch.pvc_uid.to_string()).fetch_one(&mut *tx).await?;
        let pod:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM external_resources WHERE tenant_id=$1 AND instance_id=$2 AND workspace_id=$3 AND provider='kubernetes' AND kind='POD' AND provider_id=$4 AND owner_id=$2 AND generation=$5 AND status='ACTIVE')")
            .bind(tenant).bind(s.instance_id).bind(s.workspace_id).bind(launch.pod_uid.to_string()).bind(s.generation).fetch_one(&mut *tx).await?;
        if !pvc || !pod {
            return Err(blocked("RESOURCE_LEDGER_MISMATCH"));
        }
        if let Some(existing) = find_permit(&mut tx, &s).await? {
            if existing.node.id != n.id
                || &existing.request.node != node
                || &existing.request.launch != launch
            {
                return Err(blocked("LAUNCH_PERMIT_CONFLICT"));
            }
            let authorization = authorization_for_lease(&mut tx, &s, existing).await?;
            tx.commit().await?;
            return Ok(authorization);
        }
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO launch_permits(id,tenant_id,project_id,instance_id,workspace_id,operation_id,runtime_node_id,cluster_epoch,generation,launch_id,pod_uid,namespace,pod_name,pvc_uid,pv_uid,pv_name,csi_volume_handle,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)")
            .bind(id).bind(tenant).bind(s.project_id).bind(s.instance_id).bind(s.workspace_id).bind(operation).bind(n.id).bind(s.cluster_epoch).bind(s.generation).bind(s.launch_id).bind(launch.pod_uid).bind(&launch.namespace).bind(&launch.pod_name).bind(launch.pvc_uid).bind(launch.pv_uid).bind(&launch.pv_name).bind(&launch.csi_volume_handle).bind(s.compute_lease_expires_at).execute(&mut *tx).await?;
        let updated=sqlx::query("UPDATE workspaces SET csi_volume_id=$3,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND (csi_volume_id IS NULL OR csi_volume_id=$3)").bind(tenant).bind(s.workspace_id).bind(&launch.csi_volume_handle).execute(&mut *tx).await?;
        if updated.rows_affected() != 1 {
            return Err(blocked("VOLUME_IDENTITY_CHANGED"));
        }
        let base_permit = LaunchPermit {
            request: RegisterLaunchRequest {
                protocol: PROTOCOL_VERSION,
                permit_id: id,
                node: node.clone(),
                launch: launch.clone(),
                expires_at: s.compute_lease_expires_at,
            },
            node: n,
        };
        let authorization = authorization_for_lease(&mut tx, &s, base_permit).await?;
        tx.commit().await?;
        Ok(authorization)
    }
    pub async fn record_launch_registration(
        &self,
        permit: &LaunchPermit,
        verified: &VerifiedLaunchRegistration,
    ) -> Result<(), ApiError> {
        self.record_launch_authorization(
            &LaunchAuthorization {
                base_permit: permit.clone(),
                request: permit.request.clone(),
                lease_version: 0,
            },
            verified,
        )
        .await
    }
    pub async fn record_launch_authorization(
        &self,
        authorization: &LaunchAuthorization,
        verified: &VerifiedLaunchRegistration,
    ) -> Result<(), ApiError> {
        let r = verified.response();
        let request = &authorization.request;
        if r.protocol != PROTOCOL_VERSION
            || r.permit_id != request.permit_id
            || r.node != request.node
            || r.launch != request.launch
            || r.state != GateState::Open
            || r.journal_revision <= 0
            || r.effective_expires_at < request.expires_at
        {
            return Err(blocked("LAUNCH_REGISTRATION_MISMATCH"));
        }
        let tenant = request.launch.tenant_id;
        let mut tx = self.begin(tenant).await?;
        let stored =
            load_permit(&mut tx, tenant, authorization.base_permit.request.permit_id).await?;
        if stored.request.node != request.node
            || stored.request.launch != request.launch
            || !stored.node.enabled
        {
            return Err(blocked("LAUNCH_REGISTRATION_MISMATCH"));
        }
        // A delayed ACK may legitimately report a newer, longer permit. It is
        // acceptable only while the latest operator certification covers it.
        require_certification(&mut tx, stored.node.id, Some(request.expires_at)).await?;
        require_certification(&mut tx, stored.node.id, Some(r.effective_expires_at)).await?;
        if request.permit_id == stored.request.permit_id {
            if request.expires_at != stored.request.expires_at {
                return Err(blocked("LAUNCH_REGISTRATION_MISMATCH"));
            }
            let previous:Option<i64>=sqlx::query_scalar("SELECT journal_revision FROM launch_permit_receipts WHERE tenant_id=$1 AND permit_id=$2").bind(tenant).bind(r.permit_id).fetch_optional(&mut *tx).await?;
            if previous.is_some_and(|v| v > r.journal_revision) {
                return Err(blocked("NODE_JOURNAL_REGRESSED"));
            }
            sqlx::query("INSERT INTO launch_permit_receipts(permit_id,tenant_id,journal_revision) VALUES($1,$2,$3) ON CONFLICT(permit_id) DO NOTHING").bind(r.permit_id).bind(tenant).bind(r.journal_revision).execute(&mut *tx).await?;
        } else {
            let extension:Option<(i64,DateTime<Utc>)>=sqlx::query_as("SELECT compute_lease_version,expires_at FROM launch_permit_extensions WHERE tenant_id=$1 AND id=$2 AND base_permit_id=$3")
                .bind(tenant).bind(request.permit_id).bind(stored.request.permit_id).fetch_optional(&mut *tx).await?;
            if extension != Some((authorization.lease_version, request.expires_at)) {
                return Err(blocked("LAUNCH_REGISTRATION_MISMATCH"));
            }
            let previous:Option<i64>=sqlx::query_scalar("SELECT journal_revision FROM launch_permit_extension_receipts WHERE tenant_id=$1 AND extension_id=$2")
                .bind(tenant).bind(request.permit_id).fetch_optional(&mut *tx).await?;
            if previous.is_some_and(|v| v > r.journal_revision) {
                return Err(blocked("NODE_JOURNAL_REGRESSED"));
            }
            sqlx::query("INSERT INTO launch_permit_extension_receipts(extension_id,tenant_id,journal_revision,effective_expires_at) VALUES($1,$2,$3,$4) ON CONFLICT(extension_id) DO NOTHING")
                .bind(request.permit_id).bind(tenant).bind(r.journal_revision).bind(r.effective_expires_at).execute(&mut *tx).await?;
        }
        // A delayed older ACK cannot move the durable high water mark backwards.
        sqlx::query("INSERT INTO runtime_node_journal_highwater(runtime_node_id,max_revision) VALUES($1,$2) ON CONFLICT(runtime_node_id) DO UPDATE SET max_revision=GREATEST(runtime_node_journal_highwater.max_revision,EXCLUDED.max_revision),observed_at=clock_timestamp()")
            .bind(stored.node.id).bind(r.journal_revision).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn prepare_termination_challenge(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<TerminationChallenge, ApiError> {
        let (mut tx, s) = lock_current(self, claim.tenant_id, claim.operation_id).await?;
        engine.assert_claim(&mut tx, claim).await?;
        if s.compute() || !matches!(s.kind.as_str(), "STOP" | "RESTART" | "DELETE") {
            return Err(blocked("TERMINATION_OPERATION_MISMATCH"));
        }
        let permit = find_permit(&mut tx, &s)
            .await?
            .ok_or_else(|| blocked("LAUNCH_NOT_REGISTERED"))?;
        if s.cluster_epoch != s.current_epoch {
            return Err(blocked("NODE_OR_EPOCH_UNTRUSTED"));
        }
        // A lost registration response is recoverable: close itself verifies the
        // durable host journal. An unregistered host returns UNKNOWN, not proof.
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let lease: DateTime<Utc> =
            sqlx::query_scalar("SELECT lease_until FROM operations WHERE tenant_id=$1 AND id=$2")
                .bind(claim.tenant_id)
                .bind(claim.operation_id)
                .fetch_one(&mut *tx)
                .await?;
        let expires = (now + Duration::seconds(25)).min(lease);
        if expires <= now + Duration::seconds(1) {
            return Err(blocked("WORKER_LEASE_LOST"));
        }
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO termination_challenges(id,tenant_id,project_id,permit_id,operation_id,lease_token,reason,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(id).bind(claim.tenant_id).bind(s.project_id).bind(permit.request.permit_id).bind(claim.operation_id).bind(claim.lease_token).bind(&s.kind).bind(now).bind(expires).execute(&mut *tx).await?;
        let reason = match s.kind.as_str() {
            "STOP" => CloseReason::Stop,
            "RESTART" => CloseReason::Restart,
            _ => CloseReason::Delete,
        };
        tx.commit().await?;
        Ok(TerminationChallenge {
            request: CloseRequest {
                protocol: PROTOCOL_VERSION,
                challenge_id: id,
                node: permit.request.node.clone(),
                launch: permit.request.launch.clone(),
                reason,
                challenge_expires_at: expires,
            },
            permit,
        })
    }
    pub async fn record_local_termination(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        verified: &VerifiedLocalTermination,
    ) -> Result<Uuid, ApiError> {
        let r = verified.response();
        let (mut tx, s) = lock_current(self, claim.tenant_id, claim.operation_id).await?;
        engine.assert_claim(&mut tx, claim).await?;
        let (challenge, permit) = validate_challenge(&mut tx, &s, claim, r.challenge_id).await?;
        let evidence = r
            .evidence
            .as_ref()
            .ok_or_else(|| blocked("TERMINATION_EVIDENCE_REQUIRED"))?;
        if r.protocol != PROTOCOL_VERSION
            || r.state != ObservationState::Terminated
            || r.node != permit.request.node
            || r.launch != permit.request.launch
            || evidence.journal_revision <= 0
            || r.observed_at < challenge.created_at - Duration::seconds(2)
        {
            return Err(blocked("TERMINATION_EVIDENCE_MISMATCH"));
        }
        let previous:Option<i64>=sqlx::query_scalar("SELECT journal_revision FROM launch_permit_receipts WHERE tenant_id=$1 AND permit_id=$2").bind(claim.tenant_id).bind(permit.request.permit_id).fetch_optional(&mut *tx).await?;
        if previous.is_some_and(|revision| revision > evidence.journal_revision) {
            return Err(blocked("NODE_JOURNAL_REGRESSED"));
        }
        sqlx::query("INSERT INTO runtime_node_journal_highwater(runtime_node_id,max_revision) VALUES($1,$2) ON CONFLICT(runtime_node_id) DO NOTHING").bind(permit.node.id).bind(evidence.journal_revision).execute(&mut *tx).await?;
        let watermark:i64=sqlx::query_scalar("SELECT max_revision FROM runtime_node_journal_highwater WHERE runtime_node_id=$1 FOR UPDATE").bind(permit.node.id).fetch_one(&mut *tx).await?;
        if evidence.journal_revision < watermark {
            return Err(blocked("NODE_JOURNAL_REGRESSED"));
        }
        sqlx::query("UPDATE runtime_node_journal_highwater SET max_revision=$2,observed_at=clock_timestamp() WHERE runtime_node_id=$1").bind(permit.node.id).bind(evidence.journal_revision).execute(&mut *tx).await?;
        let value = serde_json::to_value(r).map_err(|_| blocked("TERMINATION_EVIDENCE_INVALID"))?;
        let bytes =
            serde_json::to_vec(&value).map_err(|_| blocked("TERMINATION_EVIDENCE_INVALID"))?;
        if bytes.len() > 65536 {
            return Err(blocked("TERMINATION_EVIDENCE_INVALID"));
        }
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let existing:Option<(Uuid,String)>=sqlx::query_as("SELECT id,evidence_sha256 FROM local_termination_proofs WHERE tenant_id=$1 AND challenge_id=$2").bind(claim.tenant_id).bind(challenge.id).fetch_optional(&mut *tx).await?;
        if let Some((id, hash)) = existing {
            if hash != digest {
                return Err(blocked("TERMINATION_EVIDENCE_CONFLICT"));
            }
            tx.commit().await?;
            return Ok(id);
        }
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO local_termination_proofs(id,tenant_id,project_id,challenge_id,permit_id,instance_id,workspace_id,generation,launch_id,pod_uid,cluster_epoch,runtime_node_id,journal_revision,evidence,evidence_sha256,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)")
            .bind(id).bind(s.tenant_id).bind(s.project_id).bind(challenge.id).bind(permit.request.permit_id).bind(s.instance_id).bind(s.workspace_id).bind(s.generation).bind(s.launch_id).bind(s.pod_uid).bind(s.cluster_epoch).bind(permit.node.id).bind(evidence.journal_revision).bind(value).bind(digest).bind(r.observed_at).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(id)
    }
}

impl Database {
    pub async fn complete_termination(
        &self,
        engine: &OperationEngine,
        claim: &Claim,
        proof_id: Uuid,
        cleanup: &VerifiedPodCleanup,
    ) -> Result<TerminationCompletion, ApiError> {
        let (mut tx, s) = lock_current(self, claim.tenant_id, claim.operation_id).await?;
        engine.assert_claim(&mut tx, claim).await?;
        let claim_deadline: DateTime<Utc> =
            sqlx::query_scalar("SELECT lease_until FROM operations WHERE tenant_id=$1 AND id=$2")
                .bind(claim.tenant_id)
                .bind(claim.operation_id)
                .fetch_one(&mut *tx)
                .await?;
        let proof:Option<(Uuid,DateTime<Utc>)>=sqlx::query_as("SELECT challenge_id,recorded_at FROM local_termination_proofs WHERE tenant_id=$1 AND id=$2")
            .bind(claim.tenant_id).bind(proof_id).fetch_optional(&mut *tx).await?;
        let (challenge_id, recorded_at) =
            proof.ok_or_else(|| blocked("TERMINATION_PROOF_NOT_FOUND"))?;
        let (_, permit) = validate_challenge(&mut tx, &s, claim, challenge_id).await?;
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        if cleanup.proof_challenge_id() != challenge_id
            || cleanup.node() != &permit.request.node
            || cleanup.launch() != &permit.request.launch
            || cleanup.pod_absent_at() < recorded_at - Duration::seconds(2)
            || cleanup.volume_checked_at() < recorded_at - Duration::seconds(2)
            || cleanup.pod_absent_at() > now + Duration::seconds(2)
            || cleanup.volume_checked_at() > now + Duration::seconds(2)
            || cleanup.pod_absent_at() < now - Duration::seconds(30)
            || cleanup.volume_checked_at() < now - Duration::seconds(30)
        {
            return Err(blocked("TERMINATION_CLEANUP_MISMATCH"));
        }
        let exact:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM local_termination_proofs WHERE tenant_id=$1 AND id=$2 AND instance_id=$3 AND workspace_id=$4 AND generation=$5 AND launch_id=$6 AND pod_uid=$7 AND cluster_epoch=$8 AND runtime_node_id=$9 AND permit_id=$10)")
            .bind(s.tenant_id).bind(proof_id).bind(s.instance_id).bind(s.workspace_id).bind(s.generation).bind(s.launch_id).bind(s.pod_uid).bind(s.cluster_epoch).bind(permit.node.id).bind(permit.request.permit_id).fetch_one(&mut *tx).await?;
        if !exact {
            return Err(blocked("TERMINATION_PROOF_IDENTITY_MISMATCH"));
        }
        let executions:Vec<(Uuid,Uuid,Option<Uuid>,String)>=sqlx::query_as("SELECT id,operation_id,dispatch_attempt_id,status FROM executions WHERE tenant_id=$1 AND instance_id=$2 AND slot_held ORDER BY id FOR UPDATE")
            .bind(s.tenant_id).bind(s.instance_id).fetch_all(&mut *tx).await?;
        let files:Vec<(Uuid,Uuid,Option<Uuid>,String,String,bool)>=sqlx::query_as("SELECT id,operation_id,dispatch_attempt_id,status,direction,slot_held FROM file_transfers WHERE tenant_id=$1 AND instance_id=$2 AND process_status NOT IN('EXITED','VM_TERMINATED') ORDER BY id FOR UPDATE")
            .bind(s.tenant_id).bind(s.instance_id).fetch_all(&mut *tx).await?;
        let writers: Vec<_> = files.iter().filter(|f| f.5).collect();
        let held = executions.len() + writers.len();
        let slot_matches = if let Some(execution) = executions.first() {
            s.activity_kind.as_deref() == Some("EXECUTION") && s.activity_id == Some(execution.0)
        } else if let Some(file) = writers.first() {
            s.activity_kind.as_deref() == Some("FILE_WRITE") && s.activity_id == Some(file.0)
        } else {
            true
        };
        if held > 1
            || s.slot_held != (held == 1)
            || s.slot_held && (!slot_matches || s.activity_generation != Some(s.generation))
        {
            return Err(blocked("ACTIVITY_LEDGER_MISMATCH"));
        }
        let exact_files:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM file_transfers WHERE tenant_id=$1 AND instance_id=$2 AND process_status NOT IN('EXITED','VM_TERMINATED') AND(runtime_generation<>$3 OR launch_id<>$4 OR pod_uid<>$5 OR cluster_epoch<>$6))")
            .bind(s.tenant_id).bind(s.instance_id).bind(s.generation).bind(s.launch_id).bind(s.pod_uid).bind(s.cluster_epoch).fetch_one(&mut *tx).await?;
        if !exact_files {
            return Err(blocked("FILE_TRANSFER_IDENTITY_CHANGED"));
        }
        let exact_executions:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM executions WHERE tenant_id=$1 AND instance_id=$2 AND slot_held AND (runtime_generation<>$3 OR launch_id<>$4 OR pod_uid<>$5 OR cluster_epoch IS DISTINCT FROM $6))")
            .bind(s.tenant_id).bind(s.instance_id).bind(s.generation).bind(s.launch_id).bind(s.pod_uid).bind(s.cluster_epoch).fetch_one(&mut *tx).await?;
        if !exact_executions {
            return Err(blocked("EXECUTION_IDENTITY_CHANGED"));
        }
        // Lock the full quota account set in the same order as acceptance and
        // restart reservation, before locking individual reservation receipts.
        let accounts:Vec<(Uuid,String,i64,i64,i64)>=sqlx::query_as("SELECT id,dimension,limit_value,pending,allocated FROM quota_accounts WHERE tenant_id=$1 AND (project_id=$2 OR project_id IS NULL) ORDER BY id FOR UPDATE")
            .bind(s.tenant_id).bind(s.project_id).fetch_all(&mut *tx).await?;
        let reservations:Vec<(Uuid,Uuid,i64,String,String,Uuid)>=sqlx::query_as("SELECT r.id,r.quota_account_id,r.amount,r.status,q.dimension,r.operation_id FROM quota_reservations r JOIN quota_accounts q ON q.tenant_id=r.tenant_id AND q.id=r.quota_account_id WHERE r.tenant_id=$1 AND r.resource_id=$2 AND r.status IN('PENDING','ALLOCATED') AND (q.dimension IN('CPU_MILLIS','MEMORY_MIB','EXECUTIONS','FILE_TRANSFERS') OR ($3 AND q.dimension='INSTANCES')) ORDER BY r.quota_account_id,r.id FOR UPDATE OF r")
            .bind(s.tenant_id).bind(s.instance_id).bind(s.kind == "DELETE").fetch_all(&mut *tx).await?;
        for (dimension, amount) in [("CPU_MILLIS", s.cpu_millis), ("MEMORY_MIB", s.memory_mib)] {
            let rows: Vec<_> = reservations.iter().filter(|r| r.4 == dimension).collect();
            if rows.len() != 2 || rows.iter().any(|r| r.2 != amount) {
                return Err(blocked("COMPUTE_QUOTA_LEDGER_MISMATCH"));
            }
        }
        if s.kind == "DELETE" {
            let counts: Vec<_> = reservations.iter().filter(|r| r.4 == "INSTANCES").collect();
            if counts.len() != 2 || counts.iter().any(|r| r.2 != 1) {
                return Err(blocked("INSTANCE_QUOTA_LEDGER_MISMATCH"));
            }
        }
        let exec_reservations: Vec<_> = reservations
            .iter()
            .filter(|r| r.4 == "EXECUTIONS")
            .collect();
        if exec_reservations.len() != executions.len() * 2
            || exec_reservations
                .iter()
                .any(|r| r.2 != 1 || Some(r.5) != executions.first().map(|e| e.1))
        {
            return Err(blocked("EXECUTION_QUOTA_LEDGER_MISMATCH"));
        }
        let file_reservations: Vec<_> = reservations
            .iter()
            .filter(|r| r.4 == "FILE_TRANSFERS")
            .collect();
        if file_reservations.len() != files.len() * 2
            || file_reservations
                .iter()
                .any(|r| r.2 != 1 || !files.iter().any(|f| f.1 == r.5))
            || files
                .iter()
                .any(|f| file_reservations.iter().filter(|r| r.5 == f.1).count() != 2)
        {
            return Err(blocked("FILE_TRANSFER_QUOTA_LEDGER_MISMATCH"));
        }
        let completion = if s.kind == "RESTART" {
            let current_authority = authorize_compute(&mut tx, &s).await.is_ok();
            let budgets = accounts
                .iter()
                .filter(|a| matches!(a.1.as_str(), "CPU_MILLIS" | "MEMORY_MIB"))
                .all(|a| i128::from(a.3) + i128::from(a.4) <= i128::from(a.2));
            if current_authority && budgets {
                TerminationCompletion::RestartQueued
            } else {
                TerminationCompletion::RestartBlocked
            }
        } else if s.kind == "DELETE" {
            TerminationCompletion::InstanceDeleted
        } else {
            TerminationCompletion::Stopped
        };
        sqlx::query("INSERT INTO termination_cleanup_receipts(proof_id,tenant_id,old_pod_uid,pod_resource_version,pod_absent_at,volume_checked_at,completion) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(proof_id).bind(s.tenant_id).bind(permit.request.launch.pod_uid).bind(cleanup.pod_resource_version()).bind(cleanup.pod_absent_at()).bind(cleanup.volume_checked_at()).bind(completion.as_str()).execute(&mut *tx).await?;
        // The same authenticated whole-VM proof closes every concurrent
        // download as well as the exclusive uploader. Retained object bytes
        // are deliberately excluded from this reservation release.
        for (id, operation, attempt, status, _, _) in &files {
            let file_version: i64 = sqlx::query_scalar(
                "SELECT version FROM file_transfers WHERE tenant_id=$1 AND id=$2",
            )
            .bind(s.tenant_id)
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
            let resolved = if status == "OUTCOME_UNKNOWN" || attempt.is_some() {
                "OUTCOME_UNKNOWN"
            } else if status == "TIMED_OUT" {
                "TIMED_OUT"
            } else {
                "CANCELLED"
            };
            sqlx::query("UPDATE file_transfers SET process_status='VM_TERMINATED',slot_held=false,termination_proof_id=$3,status=$4,completed_at=COALESCE(completed_at,clock_timestamp()),content_status=CASE WHEN direction='DOWNLOAD' AND content_status='STAGING' THEN 'UNAVAILABLE' ELSE content_status END WHERE tenant_id=$1 AND id=$2")
                .bind(s.tenant_id).bind(id).bind(proof_id).bind(resolved).execute(&mut *tx).await?;
            sqlx::query("UPDATE operations SET status='CANCELLED',stage='VM_TERMINATED',cancel_requested=true,lease_owner=NULL,lease_until=NULL,lease_token=lease_token+1,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND status IN('QUEUED','RUNNING','WAITING')")
                .bind(s.tenant_id).bind(operation).execute(&mut *tx).await?;
            let details = json!({"termination_proof_id":proof_id,"stop_operation_id":s.operation_id,"process_status":"VM_TERMINATED","status":resolved,"retained_bytes_released":false});
            sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details) VALUES($1,$2,$3,$4,$5,$6,'files:vm_terminated','SUCCEEDED',$7)")
                .bind(s.tenant_id).bind(s.project_id).bind(s.actor_principal_id).bind(s.request_id).bind(operation).bind(id).bind(&details).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload) VALUES($1,$2,$3,$4,'files:vm_terminated',$5,$6,$7)")
                .bind(s.tenant_id).bind(s.project_id).bind(id).bind(file_version+1).bind(operation).bind(s.request_id).bind(details).execute(&mut *tx).await?;
        }
        for (reservation, account, amount, status, _, _) in reservations {
            let changed=sqlx::query("UPDATE quota_accounts SET pending=pending-CASE WHEN $4='PENDING' THEN $3 ELSE 0 END,allocated=allocated-CASE WHEN $4='ALLOCATED' THEN $3 ELSE 0 END,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
                .bind(s.tenant_id).bind(account).bind(amount).bind(status).execute(&mut *tx).await?;
            if changed.rows_affected() != 1 {
                return Err(blocked("QUOTA_ACCOUNT_MISSING"));
            }
            sqlx::query("UPDATE quota_reservations SET status='RELEASED',released_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(s.tenant_id).bind(reservation).execute(&mut *tx).await?;
        }
        for (id, operation, attempt, status) in executions {
            let resolved = if status == "OUTCOME_UNKNOWN" || attempt.is_some() {
                "OUTCOME_UNKNOWN"
            } else if status == "TIMED_OUT" {
                "TIMED_OUT"
            } else {
                "CANCELLED"
            };
            sqlx::query("UPDATE executions SET termination_status='CONFIRMED',termination_proof_id=$3,activity_completion_kind='VM_TERMINATED',slot_held=false,status=$4,completed_at=COALESCE(completed_at,clock_timestamp()),output_status=CASE WHEN output_status='PENDING' THEN 'LOST' ELSE output_status END WHERE tenant_id=$1 AND id=$2")
                .bind(s.tenant_id).bind(id).bind(proof_id).bind(resolved).execute(&mut *tx).await?;
            sqlx::query("UPDATE operations SET status='CANCELLED',stage='VM_TERMINATED',cancel_requested=true,lease_owner=NULL,lease_until=NULL,lease_token=lease_token+1,wait_reason=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND status IN('QUEUED','RUNNING','WAITING')")
                .bind(s.tenant_id).bind(operation).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE instances SET desired_state=CASE WHEN desired_state='DELETED' THEN 'DELETED' ELSE 'STOPPED' END,observed_state=CASE WHEN $4 THEN 'DELETED' ELSE 'STOPPED' END,deleted_at=CASE WHEN $4 THEN clock_timestamp() ELSE deleted_at END,observed_at=clock_timestamp(),last_termination_proof_id=$3,slot_held=false,activity_id=NULL,activity_kind=NULL,activity_generation=NULL,ready_generation=NULL,ready_launch_id=NULL,ready_pod_uid=NULL,ready_cluster_epoch=NULL,ready_observed_at=NULL,idle_since=NULL,active_operation_id=NULL,spec_version=spec_version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(s.tenant_id).bind(s.instance_id).bind(proof_id).bind(completion == TerminationCompletion::InstanceDeleted).execute(&mut *tx).await?;
        sqlx::query("UPDATE workspaces SET status='AVAILABLE',active_operation_id=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(s.tenant_id).bind(s.workspace_id).execute(&mut *tx).await?;
        let deleted=sqlx::query("UPDATE external_resources SET status='DELETED',observed_at=clock_timestamp(),deleted_at=clock_timestamp() WHERE tenant_id=$1 AND instance_id=$2 AND workspace_id=$3 AND provider='kubernetes' AND kind='POD' AND provider_id=$4 AND generation=$5 AND owner_id=$2")
            .bind(s.tenant_id).bind(s.instance_id).bind(s.workspace_id).bind(permit.request.launch.pod_uid.to_string()).bind(s.generation).execute(&mut *tx).await?;
        if deleted.rows_affected() != 1 {
            return Err(blocked("POD_LEDGER_MISMATCH"));
        }
        match completion {
            TerminationCompletion::RestartQueued => {
                let generation = s
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| blocked("GENERATION_EXHAUSTED"))?;
                reserve_quota(
                    &mut tx,
                    &s.actor(),
                    s.project_id,
                    s.operation_id,
                    s.instance_id,
                    s.workspace_id,
                    &[("CPU_MILLIS", s.cpu_millis), ("MEMORY_MIB", s.memory_mib)],
                )
                .await?;
                sqlx::query("UPDATE instances SET desired_state='RUNNING',observed_state='PENDING',runtime_generation=$3,launch_id=$4,pod_uid=NULL,active_operation_id=$5,stop_reason=NULL,stop_accepted_at=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
                    .bind(s.tenant_id).bind(s.instance_id).bind(generation).bind(Uuid::new_v4()).bind(s.operation_id).execute(&mut *tx).await?;
                sqlx::query("UPDATE workspaces SET active_operation_id=$3,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(s.tenant_id).bind(s.workspace_id).bind(s.operation_id).execute(&mut *tx).await?;
                sqlx::query("UPDATE operations SET restart_generation=$3,status='QUEUED',stage='RESTART_STARTING',wait_reason=NULL,error=NULL,lease_owner=NULL,lease_until=NULL,lease_token=lease_token+1,next_attempt_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
                    .bind(s.tenant_id).bind(s.operation_id).bind(generation).execute(&mut *tx).await?;
            }
            _ => {
                let failed = completion == TerminationCompletion::RestartBlocked;
                sqlx::query("UPDATE operations SET status=$3,stage=$4,error=$5,wait_reason=NULL,lease_owner=NULL,lease_until=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
                    .bind(s.tenant_id).bind(s.operation_id).bind(if failed{"FAILED"}else{"SUCCEEDED"}).bind(if failed{"RESTART_REAUTHORIZATION_FAILED"}else{"COMPLETED"})
                    .bind(if failed{Some(json!({"code":"OPERATION_FAILED","retryable":false}))}else{None}).execute(&mut *tx).await?;
            }
        }
        let details = json!({"generation":s.generation,"launch_id":s.launch_id,"proof_id":proof_id,"completion":completion.as_str(),"workspace_preserved":true,"compute_lease_id":s.compute_lease_id});
        sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details) VALUES($1,$2,$3,$4,$5,$6,'runtime:termination','SUCCEEDED',$7)")
            .bind(s.tenant_id).bind(s.project_id).bind(s.actor_principal_id).bind(s.request_id).bind(s.operation_id).bind(s.instance_id).bind(&details).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload) VALUES($1,$2,$3,$4,'instance.terminated',$5,$6,$7)")
            .bind(s.tenant_id).bind(s.project_id).bind(s.instance_id).bind(s.generation).bind(s.operation_id).bind(s.request_id).bind(details).execute(&mut *tx).await?;
        if completion == TerminationCompletion::InstanceDeleted {
            instance_deletion::deletion_events(&mut tx, &s, proof_id).await?;
        }
        // The stream head may have blocked the event insertion. Never commit
        // quota release after our lease or the cluster epoch has changed.
        let still_current: bool = sqlx::query_scalar("SELECT clock_timestamp()<$1 AND cluster_epoch=$2 FROM platform_configuration WHERE singleton")
            .bind(claim_deadline).bind(s.cluster_epoch).fetch_one(&mut *tx).await?;
        if !still_current {
            return Err(blocked("WORKER_LEASE_LOST"));
        }
        tx.commit().await?;
        Ok(completion)
    }
}
async fn authorization_for_lease(
    tx: &mut Transaction<'_, Postgres>,
    s: &Current,
    base_permit: LaunchPermit,
) -> Result<LaunchAuthorization, ApiError> {
    let mut request = base_permit.request.clone();
    if s.compute_lease_expires_at < request.expires_at {
        return Err(blocked("LAUNCH_LEASE_REGRESSED"));
    }
    if s.compute_lease_expires_at > request.expires_at {
        let existing:Option<(Uuid,Uuid,DateTime<Utc>)>=sqlx::query_as("SELECT id,compute_lease_id,expires_at FROM launch_permit_extensions WHERE tenant_id=$1 AND base_permit_id=$2 AND compute_lease_version=$3")
            .bind(s.tenant_id).bind(request.permit_id).bind(s.compute_lease_version).fetch_optional(&mut **tx).await?;
        let id = if let Some((id, lease_id, expiry)) = existing {
            if lease_id != s.compute_lease_id || expiry != s.compute_lease_expires_at {
                return Err(blocked("LAUNCH_EXTENSION_CONFLICT"));
            }
            id
        } else {
            let id = Uuid::new_v4();
            sqlx::query("INSERT INTO launch_permit_extensions(id,tenant_id,base_permit_id,compute_lease_id,compute_lease_version,expires_at) VALUES($1,$2,$3,$4,$5,$6)")
                .bind(id).bind(s.tenant_id).bind(request.permit_id).bind(s.compute_lease_id).bind(s.compute_lease_version).bind(s.compute_lease_expires_at).execute(&mut **tx).await?;
            id
        };
        request.permit_id = id;
        request.expires_at = s.compute_lease_expires_at;
    }
    Ok(LaunchAuthorization {
        base_permit,
        request,
        lease_version: s.compute_lease_version,
    })
}
async fn current(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    op: Uuid,
) -> Result<Current, ApiError> {
    let mut value: Current = sqlx::query_as(CURRENT_SQL)
        .bind(tenant)
        .bind(op)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| blocked("TERMINATION_OPERATION_CHANGED"))?;
    value.restore_binding = crate::workspace_restore::load(tx, &value.context()).await?;
    Ok(value)
}
async fn lock_current(
    db: &Database,
    tenant: Uuid,
    op: Uuid,
) -> Result<(Transaction<'_, Postgres>, Current), ApiError> {
    let mut tx = db.begin(tenant).await?;
    let ids: Option<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT instance_id,workspace_id FROM operations WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant)
    .bind(op)
    .fetch_optional(&mut *tx)
    .await?;
    let (instance, workspace) = ids.ok_or_else(|| blocked("TERMINATION_OPERATION_CHANGED"))?;
    sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(tenant)
        .bind(workspace)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("SELECT id FROM instances WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(tenant)
        .bind(instance)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("SELECT id FROM executions WHERE tenant_id=$1 AND instance_id=$2 AND slot_held ORDER BY id FOR UPDATE").bind(tenant).bind(instance).fetch_all(&mut *tx).await?;
    sqlx::query("SELECT id FROM operations WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(tenant)
        .bind(op)
        .fetch_one(&mut *tx)
        .await?;
    let s = current(&mut tx, tenant, op).await?;
    Ok((tx, s))
}
async fn authorize_compute(
    tx: &mut Transaction<'_, Postgres>,
    s: &Current,
) -> Result<(), ApiError> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    if s.safe_mode
        || s.cluster_epoch != s.current_epoch
        || s.desired_state != "RUNNING"
        || s.stop_accepted_at.is_some()
        || s.compute_lease_expires_at <= now
        || !s.template_approved
        || !s.policy_approved
        || !matches!(
            s.workspace_status.as_str(),
            "PENDING" | "AVAILABLE" | "IN_USE"
        )
    {
        return Err(blocked("COMPUTE_NO_LONGER_AUTHORIZED"));
    }
    let action = match s.kind.as_str() {
        "CREATE" => "instances:create",
        "START" => "instances:start",
        "RESTART" => "instances:restart",
        _ => return Err(blocked("COMPUTE_OPERATION_MISMATCH")),
    };
    Database::authorize(tx, &s.actor(), s.project_id, action).await?;
    if s.kind == "RESTART" {
        Database::authorize(tx, &s.actor(), s.project_id, "instances:hard_stop").await?;
    }
    Ok(())
}
async fn find_permit(
    tx: &mut Transaction<'_, Postgres>,
    s: &Current,
) -> Result<Option<LaunchPermit>, ApiError> {
    let id:Option<Uuid>=sqlx::query_scalar("SELECT id FROM launch_permits WHERE tenant_id=$1 AND instance_id=$2 AND generation=$3 AND launch_id=$4").bind(s.tenant_id).bind(s.instance_id).bind(s.generation).bind(s.launch_id).fetch_optional(&mut **tx).await?;
    match id {
        Some(id) => Ok(Some(load_permit(tx, s.tenant_id, id).await?)),
        None => Ok(None),
    }
}
async fn load_permit(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    id: Uuid,
) -> Result<LaunchPermit, ApiError> {
    let p: PermitRow = sqlx::query_as("SELECT * FROM launch_permits WHERE tenant_id=$1 AND id=$2")
        .bind(tenant)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| blocked("LAUNCH_PERMIT_MISSING"))?;
    let n:NodeRow=sqlx::query_as("SELECT id,cluster_epoch,node_uid,node_name,boot_id,profile_sha256,host(private_ip) AS private_ip,guard_port,cloud_account_id,region,cloud_instance_id,enabled FROM runtime_nodes WHERE id=$1").bind(p.runtime_node_id).fetch_one(&mut **tx).await?;
    let node = RuntimeNode::try_from(n)?;
    Ok(LaunchPermit {
        request: RegisterLaunchRequest {
            protocol: PROTOCOL_VERSION,
            permit_id: p.id,
            node: node.node.clone(),
            launch: LaunchBinding {
                purpose: crate::nodeguard::protocol::LaunchPurpose::Workload,
                tenant_id: p.tenant_id,
                project_id: p.project_id,
                instance_id: p.instance_id,
                workspace_id: p.workspace_id,
                generation: p.generation,
                launch_id: p.launch_id,
                pod_uid: p.pod_uid,
                namespace: p.namespace,
                pod_name: p.pod_name,
                pvc_uid: p.pvc_uid,
                pv_uid: p.pv_uid,
                pv_name: p.pv_name,
                csi_volume_handle: p.csi_volume_handle,
            },
            expires_at: p.expires_at,
        },
        node,
    })
}
async fn validate_challenge(
    tx: &mut Transaction<'_, Postgres>,
    s: &Current,
    claim: &Claim,
    id: Uuid,
) -> Result<(ChallengeRow, LaunchPermit), ApiError> {
    let c: ChallengeRow =
        sqlx::query_as("SELECT * FROM termination_challenges WHERE tenant_id=$1 AND id=$2")
            .bind(s.tenant_id)
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(|| blocked("TERMINATION_CHALLENGE_MISSING"))?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    let permit = load_permit(tx, s.tenant_id, c.permit_id).await?;
    if c.operation_id != claim.operation_id
        || c.lease_token != claim.lease_token
        || c.reason != s.kind
        || c.expires_at <= now
        || !s.matches(&permit.request.launch)
        || s.cluster_epoch != permit.request.node.cluster_epoch
        || s.cluster_epoch != s.current_epoch
        || s.compute()
    {
        return Err(blocked("TERMINATION_CHALLENGE_STALE"));
    }
    Ok((c, permit))
}
async fn require_certification(
    tx: &mut Transaction<'_, Postgres>,
    node: Uuid,
    lease_expiry: Option<DateTime<Utc>>,
) -> Result<(), ApiError> {
    let expiry: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT sandbox_node_certified_until($1)")
            .bind(node)
            .fetch_one(&mut **tx)
            .await?;
    let expiry = expiry.ok_or_else(|| blocked("NODE_CERTIFICATION_EXPIRED"))?;
    if lease_expiry.is_some_and(|requested| requested > expiry) {
        return Err(blocked("CERTIFICATION_LEASE_LIMIT"));
    }
    Ok(())
}

fn blocked(code: &'static str) -> ApiError {
    ApiError::conflict(
        code,
        "Trusted launch identity, current operation and termination evidence must reconcile before resources can be released",
    )
}
async fn known_resources(
    tx: &mut Transaction<'_, Postgres>,
    s: &Current,
) -> Result<Option<KnownRuntimeResources>, ApiError> {
    let rows:Vec<(String,String,i64,Uuid,Uuid,String)>=sqlx::query_as("SELECT kind,provider_id,generation,owner_id,workspace_id,status FROM external_resources WHERE tenant_id=$1 AND instance_id=$2 AND provider='kubernetes' AND ((kind='POD' AND generation=$3) OR kind IN('PVC','CILIUM_POLICY'))")
        .bind(s.tenant_id).bind(s.instance_id).bind(s.generation).fetch_all(&mut **tx).await?;
    let mut map = std::collections::BTreeMap::new();
    for (kind, uid, generation, owner, workspace, status) in rows {
        if workspace != s.workspace_id
            || generation != if kind == "POD" { s.generation } else { 1 }
            || owner
                != if kind == "PVC" {
                    s.workspace_id
                } else {
                    s.instance_id
                }
            || !matches!(status.as_str(), "ACTIVE" | "DELETING")
            || map.insert(kind, uid).is_some()
        {
            return Err(blocked("RESOURCE_LEDGER_MISMATCH"));
        }
    }
    if let Some(pod) = map.get("POD") {
        if s.pod_uid.map(|u| u.to_string()).as_ref() != Some(pod) {
            return Err(blocked("POD_LEDGER_MISMATCH"));
        }
    } else if s.pod_uid.is_some() {
        return Err(blocked("POD_LEDGER_MISMATCH"));
    }
    match (s.pod_uid, map.remove("PVC"), map.remove("CILIUM_POLICY")) {
        (Some(pod_uid), Some(pvc_uid), Some(policy_uid)) => Ok(Some(KnownRuntimeResources {
            pod_uid,
            pvc_uid,
            policy_uid,
        })),
        _ => Ok(None),
    }
}

#[cfg(test)]
#[path = "termination_ledger_tests.rs"]
pub(crate) mod tests;
