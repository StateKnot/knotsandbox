//! Node-wide SYSTEM quarantine and one-shot cloud stop. Cloud observations never
//! become local termination proofs and this module has no quota/storage release.
use crate::{
    cloud_fencing::{
        AlibabaCloudFencing, CloudError, CloudInstanceObservation, CloudInstanceState,
        CloudStopOutcome,
    },
    db::Database,
    nodeguard::protocol::NodeBinding,
};
use anyhow::{Context, ensure};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use std::{net::IpAddr, time::Duration as StdDuration};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IncidentReason {
    NodeUnreachable,
    RuntimeIntegrityFailure,
    OperatorNodeMaintenance,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeFenceRequest {
    pub incident_id: Uuid,
    pub runtime_node_id: Uuid,
    pub node: NodeBinding,
    pub cloud_account_id: String,
    pub region: String,
    pub cloud_instance_id: String,
    pub reason: IncidentReason,
    /// Operator incident/ticket reference, never interpreted as a URL or command.
    pub reference: String,
}
impl NodeFenceRequest {
    pub fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(bytes.len() <= 16384, "node incident input exceeds 16 KiB");
        let value: Self = serde_json::from_slice(bytes).context("invalid node incident input")?;
        ensure!(
            !value.incident_id.is_nil() && !value.runtime_node_id.is_nil() && value.node.validate(),
            "invalid node incident identity"
        );
        for field in [
            &value.cloud_account_id,
            &value.region,
            &value.cloud_instance_id,
            &value.reference,
        ] {
            ensure!(
                !field.is_empty() && field.len() <= 256 && !field.chars().any(char::is_control),
                "invalid node incident reference"
            );
        }
        Ok(value)
    }
}
#[derive(Debug, Serialize)]
pub struct NodeFenceReceipt {
    pub incident_id: Uuid,
    pub affected_launches: i64,
    pub state: String,
    pub changed: bool,
}

/// Installation owner only. No runtime role receives INSERT or request-function
/// privileges, and no tenant HTTP handler calls this entry point.
pub async fn request_node_fence(
    db: &Database,
    request: &NodeFenceRequest,
) -> anyhow::Result<NodeFenceReceipt> {
    let bytes = serde_json::to_vec(request)?;
    let _ = NodeFenceRequest::parse(&bytes)?;
    let owner:bool=sqlx::query_scalar("SELECT count(*)=2 AND bool_and(pg_has_role(current_user,c.relowner,'USAGE')) FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relname IN('runtime_nodes','node_fence_incidents')")
        .fetch_one(&db.pool).await?;
    ensure!(
        owner,
        "node-wide incidents require the installation owner; tenant hard_stop is not sufficient"
    );
    let hash = format!("{:x}", Sha256::digest(&bytes));
    let mut tx = db.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array($1::text,$2::text,$3::text)::text,24020))")
        .bind(&request.cloud_account_id).bind(&request.region).bind(&request.cloud_instance_id).execute(&mut *tx).await?;
    sqlx::query("SELECT id FROM runtime_nodes WHERE (cloud_account_id,region,cloud_instance_id)=($1,$2,$3) ORDER BY id FOR UPDATE")
        .bind(&request.cloud_account_id).bind(&request.region).bind(&request.cloud_instance_id).execute(&mut *tx).await?;
    let node:NodeRecord=sqlx::query_as("SELECT id,cluster_epoch,node_uid,node_name,boot_id,profile_sha256,cloud_account_id,region,cloud_instance_id,host(private_ip) AS private_ip,enabled FROM runtime_nodes WHERE id=$1 FOR UPDATE")
        .bind(request.runtime_node_id).fetch_one(&mut *tx).await?;
    ensure!(
        node.binding() == request.node
            && node.cloud_account_id == request.cloud_account_id
            && node.region == request.region
            && node.cloud_instance_id == request.cloud_instance_id,
        "incident input does not match immutable enrolled node"
    );
    let current: Uuid = sqlx::query_scalar(
        "SELECT cluster_epoch FROM platform_configuration WHERE singleton FOR SHARE",
    )
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
        node.cluster_epoch == current,
        "incident belongs to another cluster epoch"
    );
    let existing:Option<(Uuid,String,String)>=sqlx::query_as("SELECT id,request_sha256,state FROM node_fence_incidents WHERE runtime_node_id=$1 OR id=$2")
        .bind(node.id).bind(request.incident_id).fetch_optional(&mut *tx).await?;
    if let Some((id, previous, state)) = existing {
        ensure!(
            id == request.incident_id && previous == hash,
            "node incident conflicts with permanent existing tombstone"
        );
        let count = target_count(&mut tx, id).await?;
        tx.commit().await?;
        return Ok(NodeFenceReceipt {
            incident_id: id,
            affected_launches: count,
            state,
            changed: false,
        });
    }
    sqlx::query("INSERT INTO node_fence_incidents(id,runtime_node_id,cluster_epoch,cloud_account_id,region,cloud_instance_id,request,request_sha256,requested_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,session_user)")
        .bind(request.incident_id).bind(node.id).bind(node.cluster_epoch).bind(&node.cloud_account_id).bind(&node.region).bind(&node.cloud_instance_id).bind(serde_json::to_value(request)?).bind(hash).execute(&mut *tx).await?;
    sqlx::query("UPDATE runtime_nodes SET enabled=false WHERE (cloud_account_id,region,cloud_instance_id)=($1,$2,$3)")
        .bind(&node.cloud_account_id).bind(&node.region).bind(&node.cloud_instance_id)
        .execute(&mut *tx)
        .await?;
    // The node row lock waits for all previously accepted permit insertions.
    // Later permits/extensions see disabled and fail before they can commit.
    sqlx::query("INSERT INTO node_fence_targets(incident_id,permit_id,tenant_id) SELECT $1,l.permit_id,l.tenant_id FROM runtime_launch_index l JOIN runtime_nodes n ON n.id=l.runtime_node_id WHERE (n.cloud_account_id,n.region,n.cloud_instance_id)=($2,$3,$4)")
        .bind(request.incident_id).bind(&node.cloud_account_id).bind(&node.region).bind(&node.cloud_instance_id).execute(&mut *tx).await?;
    let count = target_count(&mut tx, request.incident_id).await?;
    event(&mut tx,request.incident_id,"REQUESTED",None,0,json!({"reason":request.reason,"affected_launches":count,"operator_database_role_recorded":true})).await?;
    tx.commit().await?;
    Ok(NodeFenceReceipt {
        incident_id: request.incident_id,
        affected_launches: count,
        state: "FREEZING".into(),
        changed: true,
    })
}
async fn target_count(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM node_fence_targets WHERE incident_id=$1")
        .bind(id)
        .fetch_one(&mut **tx)
        .await
}
#[derive(sqlx::FromRow)]
struct NodeRecord {
    id: Uuid,
    cluster_epoch: Uuid,
    node_uid: Uuid,
    node_name: String,
    boot_id: Uuid,
    profile_sha256: String,
    cloud_account_id: String,
    region: String,
    cloud_instance_id: String,
    private_ip: String,
    enabled: bool,
}
impl NodeRecord {
    fn binding(&self) -> NodeBinding {
        NodeBinding {
            cluster_epoch: self.cluster_epoch,
            node_uid: self.node_uid,
            node_name: self.node_name.clone(),
            boot_id: self.boot_id,
            profile_sha256: self.profile_sha256.clone(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct FenceClaim {
    id: Uuid,
    token: i64,
    worker: String,
}
#[derive(sqlx::FromRow)]
struct Incident {
    id: Uuid,
    runtime_node_id: Uuid,
    cluster_epoch: Uuid,
    cloud_account_id: String,
    region: String,
    cloud_instance_id: String,
    state: String,
    attempt_id: Option<Uuid>,
    dispatched_at: Option<DateTime<Utc>>,
    stopped_observed_at: Option<DateTime<Utc>>,
    lease_owner: Option<String>,
    lease_token: i64,
    lease_until: Option<DateTime<Utc>>,
}
#[derive(Clone)]
pub struct NodeFencingController {
    db: Database,
    cloud: AlibabaCloudFencing,
    worker: String,
}
impl NodeFencingController {
    pub fn new(db: Database, cloud: AlibabaCloudFencing, worker: String) -> anyhow::Result<Self> {
        ensure!(
            !worker.is_empty() && worker.len() <= 128 && !worker.chars().any(char::is_control),
            "invalid fencing worker identity"
        );
        Ok(Self { db, cloud, worker })
    }
    pub async fn run(&self, shutdown: CancellationToken) -> anyhow::Result<()> {
        self.db.verify_runtime_role().await?;
        let role: String = sqlx::query_scalar("SELECT current_user")
            .fetch_one(&self.db.pool)
            .await?;
        ensure!(
            role == "sandbox_fencing",
            "fencing requires its dedicated database login"
        );
        loop {
            tokio::select! {_=shutdown.cancelled()=>return Ok(()),_=tokio::time::sleep(StdDuration::from_secs(1))=>{}}
            match self.claim().await {
                Ok(Some(claim)) => {
                    let result = tokio::select! {_=shutdown.cancelled()=>return Ok(()),result=tokio::time::timeout(StdDuration::from_secs(100),self.reconcile(&claim))=>result};
                    if !matches!(result, Ok(Ok(()))) {
                        tracing::warn!(incident_id=%claim.id,"node fencing deferred; cloud stop will never be replayed after dispatch intent");
                    }
                }
                Ok(None) => {}
                Err(_) => tracing::warn!("node fencing queue unavailable"),
            }
        }
    }
    pub async fn claim(&self) -> anyhow::Result<Option<FenceClaim>> {
        let mut tx = self.db.pool.begin().await?;
        let found:Option<(Uuid,i64)>=sqlx::query_as("UPDATE node_fence_incidents SET lease_owner=$1,lease_token=lease_token+1,lease_until=clock_timestamp()+interval '120 seconds' WHERE id=(SELECT id FROM node_fence_incidents WHERE state<>'BREACH' AND cluster_epoch=(SELECT cluster_epoch FROM platform_configuration WHERE singleton) AND next_attempt_at<=clock_timestamp() AND (lease_until IS NULL OR lease_until<=clock_timestamp()) ORDER BY next_attempt_at,id FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING id,lease_token")
            .bind(&self.worker).fetch_optional(&mut *tx).await?;
        tx.commit().await?;
        Ok(found.map(|(id, token)| FenceClaim {
            id,
            token,
            worker: self.worker.clone(),
        }))
    }
    pub async fn reconcile(&self, claim: &FenceClaim) -> anyhow::Result<()> {
        let mut tx = self.db.pool.begin().await?;
        let current = assert_claim(&mut tx, claim).await?;
        let node:NodeRecord=sqlx::query_as("SELECT id,cluster_epoch,node_uid,node_name,boot_id,profile_sha256,cloud_account_id,region,cloud_instance_id,host(private_ip) AS private_ip,enabled FROM runtime_nodes WHERE id=$1")
            .bind(current.runtime_node_id).fetch_one(&mut *tx).await?;
        ensure!(
            !node.enabled && node.cluster_epoch == current.cluster_epoch,
            "node tombstone identity changed"
        );
        ensure!(
            self.cloud.validate_binding(
                &current.cloud_account_id,
                &current.region,
                &current.cloud_instance_id,
                node.private_ip.parse::<IpAddr>()?
            ),
            "cloud client is not bound to the exact enrolled node"
        );
        tx.commit().await?;
        if current.state == "FREEZING" {
            self.freeze(claim).await?;
            return Ok(());
        }
        let ticket = self.begin_dispatch(claim).await?;
        if let Some(attempt) = ticket {
            let outcome = self
                .cloud
                .force_stop(&current.cloud_instance_id, attempt)
                .await;
            self.record_stop(claim, attempt, outcome).await
        } else {
            // Includes crash before send, lost response, accepted and preflight
            // errors. A durable attempt can never authorize a second Stop call.
            match self.cloud.observe(&current.cloud_instance_id).await {
                Ok(observation) => self.record_observation(claim, &observation).await,
                Err(error) => self.record_error(claim, error).await,
            }
        }
    }
    async fn freeze(&self, claim: &FenceClaim) -> anyhow::Result<()> {
        for _ in 0..16 {
            let permit:Option<Uuid>=sqlx::query_scalar("SELECT permit_id FROM node_fence_targets WHERE incident_id=$1 AND state='PENDING' ORDER BY tenant_id,permit_id LIMIT 1").bind(claim.id).fetch_optional(&self.db.pool).await?;
            let Some(permit) = permit else {
                break;
            };
            sqlx::query_scalar::<_, bool>("SELECT sandbox_freeze_node_launch($1,$2,$3,$4)")
                .bind(claim.id)
                .bind(permit)
                .bind(&claim.worker)
                .bind(claim.token)
                .fetch_one(&self.db.pool)
                .await?;
        }
        let mut tx = self.db.pool.begin().await?;
        let _ = assert_claim(&mut tx, claim).await?;
        sqlx::query("UPDATE node_fence_incidents SET state=CASE WHEN EXISTS(SELECT 1 FROM node_fence_targets WHERE incident_id=$1 AND state='PENDING') THEN 'FREEZING' ELSE 'READY_TO_STOP' END,lease_owner=NULL,lease_until=NULL,next_attempt_at=clock_timestamp() WHERE id=$1")
            .bind(claim.id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    async fn begin_dispatch(&self, claim: &FenceClaim) -> anyhow::Result<Option<Uuid>> {
        let mut tx = self.db.pool.begin().await?;
        let current = assert_claim(&mut tx, claim).await?;
        if current.attempt_id.is_some() {
            tx.commit().await?;
            return Ok(None);
        }
        ensure!(
            current.state == "READY_TO_STOP",
            "all affected launches must freeze before stop"
        );
        let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM node_fence_targets WHERE incident_id=$1 AND state='PENDING')").bind(claim.id).fetch_one(&mut *tx).await?;
        ensure!(!pending, "incident still has unfrozen launches");
        let id = Uuid::new_v4();
        sqlx::query("UPDATE node_fence_incidents SET state='DISPATCHING',attempt_id=$2,dispatched_at=clock_timestamp() WHERE id=$1").bind(claim.id).bind(id).execute(&mut *tx).await?;
        event(&mut tx,claim.id,"DISPATCHING",Some(id),claim.token,json!({"force_stop":true,"stopped_mode":"KeepCharging","automatic_replay_allowed":false})).await?;
        tx.commit().await?;
        Ok(Some(id))
    }
    async fn record_stop(
        &self,
        claim: &FenceClaim,
        attempt: Uuid,
        result: Result<CloudStopOutcome, CloudError>,
    ) -> anyhow::Result<()> {
        match result {
            Err(error) => self.record_error(claim, error).await,
            Ok(CloudStopOutcome::AlreadyStopped(observation)) => {
                self.record_observation(claim, &observation).await
            }
            Ok(outcome) => {
                let mut tx = self.db.pool.begin().await?;
                let current = assert_claim(&mut tx, claim).await?;
                ensure!(current.attempt_id == Some(attempt), "cloud attempt changed");
                let submitted = match &outcome {
                    CloudStopOutcome::Accepted(s) | CloudStopOutcome::OutcomeUnknown(s) => s,
                    CloudStopOutcome::AlreadyStopped(_) => unreachable!(),
                };
                ensure!(
                    submitted.attempt_id() == attempt
                        && submitted.preflight().account_id() == current.cloud_account_id
                        && submitted.preflight().region() == current.region
                        && submitted.preflight().instance_id() == current.cloud_instance_id,
                    "cloud stop identity mismatch"
                );
                event(
                    &mut tx,
                    claim.id,
                    "STOP_RESULT",
                    Some(attempt),
                    claim.token,
                    serde_json::to_value(outcome)?,
                )
                .await?;
                release(&mut tx, claim.id, "OBSERVING").await?;
                tx.commit().await?;
                Ok(())
            }
        }
    }
    async fn record_observation(
        &self,
        claim: &FenceClaim,
        observation: &CloudInstanceObservation,
    ) -> anyhow::Result<()> {
        let mut tx = self.db.pool.begin().await?;
        let current = assert_claim(&mut tx, claim).await?;
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        ensure!(
            current.attempt_id.is_some()
                && observation.account_id() == current.cloud_account_id
                && observation.region() == current.region
                && observation.instance_id() == current.cloud_instance_id,
            "cloud observation identity mismatch"
        );
        ensure!(
            observation.evidence().sent_at()
                >= current.dispatched_at.context("missing dispatch intent")? - Duration::seconds(2)
                && observation.evidence().received_at() >= now - Duration::seconds(60)
                && observation.evidence().received_at() <= now + Duration::seconds(2),
            "cloud observation expired"
        );
        let state = if current.stopped_observed_at.is_some()
            && observation.state() != CloudInstanceState::Stopped
        {
            "BREACH"
        } else if observation.state() == CloudInstanceState::Stopped {
            "STOPPED_OBSERVED"
        } else {
            "OBSERVING"
        };
        event(
            &mut tx,
            claim.id,
            if state == "BREACH" {
                "BREACH"
            } else {
                "OBSERVATION"
            },
            current.attempt_id,
            claim.token,
            serde_json::to_value(observation)?,
        )
        .await?;
        if state == "STOPPED_OBSERVED" {
            sqlx::query("UPDATE node_fence_incidents SET stopped_observed_at=COALESCE(stopped_observed_at,$2) WHERE id=$1").bind(claim.id).bind(observation.evidence().received_at()).execute(&mut *tx).await?;
        }
        // State and breach timestamp must change together under the CHECK.
        sqlx::query("UPDATE node_fence_incidents SET state=$2,breach_at=CASE WHEN $2='BREACH' THEN clock_timestamp() ELSE breach_at END,lease_owner=NULL,lease_until=NULL,next_attempt_at=clock_timestamp()+interval '5 seconds' WHERE id=$1").bind(claim.id).bind(state).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    async fn record_error(&self, claim: &FenceClaim, error: CloudError) -> anyhow::Result<()> {
        let mut tx = self.db.pool.begin().await?;
        let current = assert_claim(&mut tx, claim).await?;
        event(
            &mut tx,
            claim.id,
            "ERROR",
            current.attempt_id,
            claim.token,
            json!({"code":error.code,"transport_evidence":error.evidence}),
        )
        .await?;
        let state = if current.stopped_observed_at.is_some() {
            "STOPPED_OBSERVED"
        } else {
            "OBSERVING"
        };
        release(&mut tx, claim.id, state).await?;
        tx.commit().await?;
        Ok(())
    }
}
async fn assert_claim(
    tx: &mut Transaction<'_, Postgres>,
    claim: &FenceClaim,
) -> anyhow::Result<Incident> {
    let row:Incident=sqlx::query_as("SELECT id,runtime_node_id,cluster_epoch,cloud_account_id,region,cloud_instance_id,state,attempt_id,dispatched_at,stopped_observed_at,lease_owner,lease_token,lease_until FROM node_fence_incidents WHERE id=$1 FOR UPDATE").bind(claim.id).fetch_one(&mut **tx).await?;
    let (now, epoch): (DateTime<Utc>, Uuid) = sqlx::query_as(
        "SELECT clock_timestamp(),cluster_epoch FROM platform_configuration WHERE singleton",
    )
    .fetch_one(&mut **tx)
    .await?;
    ensure!(
        row.id == claim.id
            && row.lease_owner.as_deref() == Some(&claim.worker)
            && row.lease_token == claim.token
            && row.lease_until.is_some_and(|until| until > now)
            && row.cluster_epoch == epoch
            && row.state != "BREACH",
        "fencing lease or cluster epoch changed"
    );
    Ok(row)
}
async fn event(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    kind: &str,
    attempt: Option<Uuid>,
    token: i64,
    evidence: Value,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO node_fence_events(incident_id,kind,attempt_id,lease_token,evidence) VALUES($1,$2,$3,$4,$5)").bind(id).bind(kind).bind(attempt).bind(token).bind(evidence).execute(&mut **tx).await?;
    Ok(())
}
async fn release(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    state: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE node_fence_incidents SET state=$2,lease_owner=NULL,lease_until=NULL,next_attempt_at=clock_timestamp()+interval '5 seconds' WHERE id=$1").bind(id).bind(state).execute(&mut **tx).await?;
    Ok(())
}
#[cfg(test)]
#[path = "node_fencing_tests.rs"]
mod tests;
