//! Private fault tests against the same sealed proof and real PostgreSQL.
//! Shares only the existing bounded SCRAM/COMMIT proxy; no fake ACK/proof/clock.
use super::super::admission::commit::CommitProxy;
use super::{
    CloudFixture, KubeFixture, NodeTopologyRequest, TopologyOwnerError, collect_with_client, count,
    insert_profile, record_node_topology,
};
use crate::{db::Database, termination_client::test_support::FixtureGuard};
use anyhow::{Context, ensure};
use chrono::{DateTime, Duration as Days, Utc};
use serde_json::Value;
use std::{sync::atomic::Ordering, time::Duration};
use uuid::Uuid;

pub(super) struct PublicationCase<'a> {
    pub owner: &'a Database,
    pub kube: &'a KubeFixture,
    pub guard: &'a FixtureGuard,
    pub cloud: &'a CloudFixture,
    pub request: NodeTopologyRequest,
    pub raw: &'a [u8],
    pub canonical: &'a str,
    pub source_profile: Uuid,
    pub epoch: Uuid,
    pub backup_until: DateTime<Utc>,
    pub restore_until: DateTime<Utc>,
}
impl PublicationCase<'_> {
    async fn request_until(&self, until: DateTime<Utc>) -> anyhow::Result<NodeTopologyRequest> {
        Ok(NodeTopologyRequest {
            restore_profile_id: insert_profile(
                self.owner,
                self.source_profile,
                self.epoch,
                self.canonical,
                self.backup_until,
                Utc::now(),
                until,
            )
            .await?,
            ..self.request
        })
    }
}
async fn backend_pid(database: &Database) -> anyhow::Result<i32> {
    Ok(sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&database.pool)
        .await?)
}
async fn committed(owner: &Database, pid: i32) -> anyhow::Result<()> {
    let released: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND granted AND locktype IN('relation','transactionid'))"
    ).bind(pid).fetch_one(&owner.pool).await?;
    ensure!(
        released,
        "actual backend COMMIT must release real transaction locks before held/lost ACK"
    );
    Ok(())
}
async fn row(owner: &Database, id: Uuid) -> anyhow::Result<Option<Value>> {
    Ok(
        sqlx::query_scalar("SELECT to_jsonb(r) FROM restore_node_topology_receipts r WHERE id=$1")
            .bind(id)
            .fetch_optional(&owner.pool)
            .await?,
    )
}
async fn historical_same_payload(owner: &Database, saved: &Value) -> anyhow::Result<()> {
    let mut payload = saved.clone();
    payload
        .as_object_mut()
        .context("persisted historical row")?
        .remove("recorded_at");
    let replay: Value = sqlx::query_scalar("SELECT sandbox_record_restore_node_topology($1)")
        .bind(payload)
        .fetch_one(&owner.pool)
        .await?;
    ensure!(
        &replay == saved,
        "historical original payload must return old recorded_at, never refresh authority/evidence"
    );
    Ok(())
}
async fn target_counts(
    case: &PublicationCase<'_>,
    node: usize,
    csi: usize,
    mtls_before: usize,
    mtls_added: usize,
    cloud_before: usize,
    actions: &[&str],
) -> anyhow::Result<()> {
    {
        let state = case
            .kube
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("Kube fixture state"))?;
        ensure!(
            state.node_reads == node && state.csi_reads == csi,
            "exact targeted owner ACK I/O stage"
        );
    }
    ensure!(
        case.guard.identity_verifications.load(Ordering::SeqCst) == mtls_before + mtls_added,
        "targeted actual mTLS arrival count"
    );
    {
        let state = case
            .cloud
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("cloud fixture state"))?;
        let actual: Vec<&str> = state.actions[cloud_before..]
            .iter()
            .map(String::as_str)
            .collect();
        ensure!(
            actual == actions,
            "exact signed cloud sequence at targeted ACK stage"
        );
    }
    Ok(())
}

async fn source_ack(case: &PublicationCase<'_>, held: usize) -> anyhow::Result<()> {
    // A fresh, legal immutable certification supplies a 2s authority horizon.
    // Frozen enrollment/profile/source are never updated to manufacture expiry.
    let request = case.request_until(Utc::now() + Days::seconds(2)).await?;
    case.kube.mode(0)?;
    let before = count(case.owner).await?;
    let mtls_before = case.guard.identity_verifications.load(Ordering::SeqCst);
    let cloud_before = case
        .cloud
        .shared
        .lock()
        .map_err(|_| anyhow::anyhow!("cloud fixture state"))?
        .actions
        .len();
    let cloud = case.cloud.client(0)?;
    let (mut proxy, database) = CommitProxy::connect_owner(held).await?;
    let pid = backend_pid(&database).await?;
    // This outer fixture bound does not modify the production TOTAL_BUDGET.
    // join owns both futures; a client cancellation cannot detach a request.
    let (outcome, observation) = tokio::join!(
        tokio::time::timeout(
            Duration::from_secs(4),
            Box::pin(collect_with_client(
                &database,
                &case.kube.runtime,
                &case.guard.client,
                &cloud,
                request,
                case.raw
            ))
        ),
        async {
            let event = if held == 1 {
                &proxy.first
            } else {
                &proxy.final_commit
            };
            tokio::time::timeout(Duration::from_secs(2), event.notified()).await?;
            ensure!(
                proxy.completed.load(Ordering::SeqCst) == held,
                "exact selected owner COMMIT"
            );
            committed(case.owner, pid).await?;
            if held == 1 {
                target_counts(case, 0, 0, mtls_before, 0, cloud_before, &[]).await?;
            } else {
                target_counts(
                    case,
                    2,
                    2,
                    mtls_before,
                    1,
                    cloud_before,
                    &[
                        "AssumeRoleWithOIDC",
                        "GetCallerIdentity",
                        "DescribeInstances",
                    ],
                )
                .await?;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
            if held == 1 {
                proxy.first_ack.notify_one();
            } else {
                proxy.final_ack.notify_one();
            }
            anyhow::Ok(())
        }
    );
    proxy.first_ack.notify_one();
    proxy.final_ack.notify_one();
    let cleanup = proxy.finish_owner(&database, &case.owner.pool, pid).await;
    observation?;
    ensure!(
        matches!(outcome?, Err(TopologyOwnerError::Expired)),
        "held source ACK must cross original finite horizon and return Expired, not fixture timeout/other failure"
    );
    cleanup?;
    ensure!(
        count(case.owner).await? == before,
        "source ACK cannot publish any proof/receipt"
    );
    eprintln!(
        "VERIFIED owner source COMMIT ordinal={held}, actual locks released before ACK, original 2s authority expiry rejected, proxy joined/backend PID absent"
    );
    Ok(())
}

async fn publication_lock_wait(case: &PublicationCase<'_>) -> anyhow::Result<()> {
    case.kube.mode(0)?;
    let request = case.request_until(case.restore_until).await?;
    let cloud = case.cloud.client(0)?;
    let proof = collect_with_client(
        case.owner,
        &case.kube.runtime,
        &case.guard.client,
        &cloud,
        request,
        case.raw,
    )
    .await?;
    let id = proof.id();
    let before = count(case.owner).await?;
    let (mut proxy, database) = CommitProxy::connect_owner(1).await?;
    let pid = backend_pid(&database).await?;
    // Consume the original proof's budget before taking the lock. The fixed
    // production SQL lock_timeout remains 3s; a fresh 11s lock would prove
    // only that unrelated SQL timeout, not the original observation horizon.
    tokio::time::sleep(Duration::from_secs(8)).await;
    let mut lock = case.owner.pool.begin().await?;
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *lock)
        .await?;
    sqlx::query("SELECT singleton FROM platform_configuration WHERE singleton FOR UPDATE")
        .execute(&mut *lock)
        .await?;
    let (outcome, observation) = tokio::join!(
        tokio::time::timeout(
            Duration::from_secs(12),
            Box::pin(record_node_topology(&database, &proof))
        ),
        async {
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let blocked: bool = sqlx::query_scalar("SELECT $2=ANY(pg_blocking_pids($1))")
                        .bind(pid)
                        .bind(blocker)
                        .fetch_one(&case.owner.pool)
                        .await?;
                    if blocked {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                anyhow::Ok(())
            })
            .await??;
            ensure!(
                proxy.completed.load(Ordering::SeqCst) == 0,
                "publication really waits before COMMIT"
            );
            tokio::time::sleep(Duration::from_secs(3)).await;
            anyhow::Ok(())
        }
    );
    // No INSERT/COMMIT during the lock. Release the real holder, then pool drain
    // settles SQLx's actual pending transaction/rollback before PID inspection.
    lock.rollback().await?;
    let cleanup = proxy.finish_owner(&database, &case.owner.pool, pid).await;
    observation?;
    ensure!(
        matches!(outcome?, Err(TopologyOwnerError::Expired)),
        "actual lock wait must consume original sealed observation budget"
    );
    cleanup?;
    ensure!(
        row(case.owner, id).await?.is_none() && count(case.owner).await? == before,
        "expired locked publication may not persist a receipt"
    );
    eprintln!(
        "VERIFIED original sealed proof publication actually blocked on reviewed configuration row, original budget rejected, no row and real proxy/PID drained"
    );
    Ok(())
}

async fn publication_ack(case: &PublicationCase<'_>, lost: bool) -> anyhow::Result<()> {
    case.kube.mode(0)?;
    let request = case.request_until(case.restore_until).await?;
    let cloud = case.cloud.client(0)?;
    let proof = collect_with_client(
        case.owner,
        &case.kube.runtime,
        &case.guard.client,
        &cloud,
        request,
        case.raw,
    )
    .await?;
    let id = proof.id();
    let before = count(case.owner).await?;
    let (mut proxy, database) = CommitProxy::connect_owner(1).await?;
    let pid = backend_pid(&database).await?;
    let bound = if lost {
        Duration::from_secs(4)
    } else {
        Duration::from_secs(12)
    };
    let (outcome, observation) = tokio::join!(
        tokio::time::timeout(bound, Box::pin(record_node_topology(&database, &proof))),
        async {
            tokio::time::timeout(Duration::from_secs(2), proxy.first.notified()).await?;
            ensure!(
                proxy.completed.load(Ordering::SeqCst) == 1,
                "publication has only one actual COMMIT"
            );
            committed(case.owner, pid).await?;
            let saved = row(case.owner, id)
                .await?
                .context("actual COMMIT must persist original row before ACK")?;
            ensure!(
                count(case.owner).await? == before + 1,
                "one actual committed row before ACK"
            );
            if lost {
                // Close the real transport while its COMMIT response is held.
                // This is not an artificial returned Database error.
                proxy.stop.cancel();
            } else {
                tokio::time::sleep(Duration::from_secs(11)).await;
                proxy.first_ack.notify_one();
            }
            anyhow::Ok(saved)
        }
    );
    proxy.first_ack.notify_one();
    let cleanup = proxy.finish_owner(&database, &case.owner.pool, pid).await;
    let saved = observation?;
    let answer = outcome?;
    if lost {
        ensure!(
            matches!(answer, Err(TopologyOwnerError::Database)),
            "actual lost ACK must return Database uncertainty, not fabricated success/fixture timeout"
        );
    } else {
        ensure!(
            matches!(answer, Err(TopologyOwnerError::Expired)),
            "committed delayed ACK must cross original observation horizon and refuse current authority"
        );
    }
    cleanup?;
    if lost {
        let replay = record_node_topology(case.owner, &proof).await?;
        ensure!(
            replay.row() == &saved && count(case.owner).await? == before + 1,
            "after real ACK loss the same original proof/id/payload returns exactly one old receipt"
        );
        tokio::time::sleep(Duration::from_secs(11)).await;
    }
    ensure!(
        matches!(
            record_node_topology(case.owner, &proof).await,
            Err(TopologyOwnerError::Expired)
        ),
        "expired original proof cannot reacquire/refresh current publication authority"
    );
    historical_same_payload(case.owner, &saved).await?;
    ensure!(
        row(case.owner, id).await?.as_ref() == Some(&saved)
            && count(case.owner).await? == before + 1,
        "historical same-payload reconciliation preserves original timestamps/identity and one row"
    );
    eprintln!(
        "VERIFIED publication lost_ACK={lost}, real COMMIT lock release+row, uncertainty/expiry, original proof budget preserved, exact historical row without refresh, actual proxy/PID drained"
    );
    Ok(())
}

pub(super) async fn exercise(case: PublicationCase<'_>) -> anyhow::Result<()> {
    Box::pin(source_ack(&case, 1)).await?;
    Box::pin(source_ack(&case, 2)).await?;
    Box::pin(publication_lock_wait(&case)).await?;
    Box::pin(publication_ack(&case, false)).await?;
    Box::pin(publication_ack(&case, true)).await?;
    Ok(())
}
