//! PRIVATE v8 boundary phases. Only normal enrollment and current mutable
//! authority are used. Live PV presence is an HTTP observation, never a ledger
//! binding/permit/proof. No production, migration or timeout change is made.
use super::*;
use crate::{engine::OperationEngine, nodeguard::protocol::NodeBinding};
use std::sync::atomic::Ordering;

pub(super) async fn run(case: &SelectedCase<'_>, node_name: &str) -> anyhow::Result<()> {
    let registered_inventory = inventory(&case.source.f.base.f.owner).await?;
    Box::pin(live_storage_boundaries(case)).await?;
    Box::pin(duplicate_normal_enrollment(case, node_name)).await?;
    Box::pin(node_lock_wait(case, node_name)).await?;
    for drift in [
        Drift::Epoch,
        Drift::PrincipalRevision,
        Drift::ProfileDisabled,
        Drift::NodeDisabled,
    ] {
        Box::pin(final_authority_drift(case, node_name, drift)).await?;
    }
    Box::pin(super::identity::run(case, node_name)).await?;
    // This phase intentionally changes the actual claim through the ordinary
    // queue. Nothing after it heartbeats or replays the old worker claim.
    Box::pin(final_claim_replacement(case)).await?;
    no_future(&facts(&case.source.f.base.f.owner, case.t, case.r).await?)?;
    ensure!(
        inventory(&case.source.f.base.f.owner).await? == registered_inventory,
        "all original Node/enrollment/topology rows remain immutable after fixture maintenance and claim transfer"
    );
    eprintln!(
        "VERIFIED private selected live Bound first/second reads and RESET404->200, normal duplicate-name enrollment refusal, observed node-lock wait disable, final epoch/principal/profile/node authority and normal claim replacement; no count2 inventory, CSI provisioning or VMbirth certification"
    );
    Ok(())
}

fn pv_path(case: &SelectedCase<'_>) -> anyhow::Result<String> {
    Ok(format!(
        "/api/v1/persistentvolumes/disk-{}",
        case.w.get(case.pvc_path)?["metadata"]["uid"]
            .as_str()
            .context("actual parent PVCUID")?
    ))
}
fn full_cloud(case: &SelectedCase<'_>) -> anyhow::Result<()> {
    ensure!(
        case.cloud.actions()?
            == vec![
                "AssumeRoleWithOIDC",
                "GetCallerIdentity",
                "DescribeInstances"
            ],
        "target drift occurs after one fresh signed admission cloud observation"
    );
    Ok(())
}
fn denial_message(case: &SelectedCase<'_>, expected: &'static str) -> anyhow::Result<()> {
    let state = case
        .w
        .shared
        .lock()
        .map_err(|_| anyhow::anyhow!("boundary decision state"))?;
    ensure!(
        state.decision_messages == vec![(403, expected)],
        "exact targeted production Denial category, not a prior dependency or timeout"
    );
    Ok(())
}
async fn live_storage_boundaries(case: &SelectedCase<'_>) -> anyhow::Result<()> {
    let pv = pv_path(case)?;
    let uid = case.w.get(case.pvc_path)?["metadata"]["uid"].clone();
    for (fault, expected) in [(Fault::FirstPvcBound, 1), (Fault::SecondPvcBound, 2)] {
        case.configure(0, fault)?;
        case.put("select", case.changed(|_| {})?, StatusCode::FORBIDDEN)
            .await?;
        denial_message(case, "PVC must remain exact unbound Pending Block intent")?;
        let expected_reads = if expected == 1 {
            vec![(
                case.pvc_path.to_owned(),
                200,
                uid.as_str().map(str::to_owned),
                Some("Bound".into()),
            )]
        } else {
            vec![
                (
                    case.pvc_path.to_owned(),
                    200,
                    uid.as_str().map(str::to_owned),
                    Some("Pending".into()),
                ),
                (
                    case.pvc_path.to_owned(),
                    200,
                    uid.as_str().map(str::to_owned),
                    Some("Bound".into()),
                ),
            ]
        };
        {
            let state = case
                .w
                .shared
                .lock()
                .map_err(|_| anyhow::anyhow!("Bound read state"))?;
            ensure!(
                state.raw_read_responses == expected_reads,
                "actual stored parent sameUID reads hit the targeted Bound round"
            );
            ensure!(
                state.pv_read_responses.is_empty(),
                "Bound does not create a PV observation authority"
            );
        }
        ensure!(
            case.w.reads(&pv)? == 0,
            "Bound PVC refuses without adopting/looking up a future PV"
        );
        if expected == 1 {
            ensure!(
                case.cloud.actions()?.is_empty(),
                "first Bound refuses before cloud"
            );
        } else {
            full_cloud(case)?;
        }
    }
    for fault in [Fault::SecondExistingPv, Fault::SecondChangedPv] {
        case.configure(0, fault)?;
        case.put("reset", case.changed(reset)?, StatusCode::FORBIDDEN)
            .await?;
        denial_message(
            case,
            "Generated raw PV exists; metadata reset cannot erase future authority",
        )?;
        case.complete_rounds(false)?;
        {
            let state = case
                .w
                .shared
                .lock()
                .map_err(|_| anyhow::anyhow!("RESET PV state"))?;
            ensure!(
                state.pv_read_responses == vec![404, 200],
                "real RESET first PV404 then second PV200 is observed"
            );
        }
        ensure!(
            case.w.reads(&pv)? == 2 && case.cloud.actions()?.is_empty(),
            "RESET second presence refuses without oldNode/cloud or quota release"
        );
    }
    Ok(())
}

async fn current_node(case: &SelectedCase<'_>, name: &str) -> anyhow::Result<Value> {
    let row: Value = sqlx::query_scalar("SELECT to_jsonb(n) FROM runtime_nodes n WHERE n.enabled AND n.cluster_epoch=$1 AND n.node_name=$2")
        .bind(case.job.record.cluster_epoch)
        .bind(name)
        .fetch_one(&case.source.f.base.f.owner)
        .await?;
    ensure!(row.is_object(), "actual enabled current runtime Node row");
    Ok(row)
}
async fn inventory(owner: &sqlx::PgPool) -> anyhow::Result<Value> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_object('nodes',COALESCE((SELECT jsonb_agg(to_jsonb(n) ORDER BY n.id) FROM runtime_nodes n),'[]'::jsonb),'enrollments',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY e.id) FROM runtime_node_enrollments e),'[]'::jsonb),'topology',COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY t.id) FROM restore_node_topology_receipts t),'[]'::jsonb))")
        .fetch_one(owner).await?)
}
async fn duplicate_normal_enrollment(case: &SelectedCase<'_>, name: &str) -> anyhow::Result<()> {
    let original = current_node(case, name).await?;
    let before = inventory(&case.source.f.base.f.owner).await?;
    let binding = NodeBinding {
        cluster_epoch: serde_json::from_value(original["cluster_epoch"].clone())?,
        node_uid: "20000000-0000-4000-8000-000000000002".parse()?,
        node_name: name.to_owned(),
        boot_id: Uuid::new_v4(),
        profile_sha256: original["profile_sha256"]
            .as_str()
            .context("enrolled profile digest")?
            .to_owned(),
    };
    let mut cloud = case.cloud.binding.clone();
    cloud.instance_id = format!("i-duplicate{}", Uuid::new_v4().simple());
    cloud.private_ip = "10.0.0.9".parse()?;
    ensure!(
        original["node_uid"] != json!(binding.node_uid)
            && original["boot_id"] != json!(binding.boot_id)
            && original["cloud_instance_id"] != json!(cloud.instance_id)
            && original["private_ip"] != json!(cloud.private_ip.to_string()),
        "duplicate-name probe has a distinct otherwise-valid physical identity"
    );
    let mut tf = terraform(&binding, &cloud);
    // Factory's first pool address is intentionally fixed for ordinary tests.
    // Only this new artifact is changed; the original raw/canonical TF and
    // original enrollment/topology/source receipts remain untouched.
    tf["node_inventory"]["value"][name]["private_ip"] = json!(cloud.private_ip.to_string());
    let raw = serde_json::to_vec_pretty(&tf)?;
    let plan = enrollment_plan(&binding, &cloud, &tf, &raw, Utc::now() + Days::days(1))?;
    let kube = KubeFixture::new(&binding, &cloud).await?;
    let credentials = crate::termination_client::NodeguardCredentials::from_pem(
        include_bytes!("../tests/fixtures/nodeguard/second-server-ca.pem"),
        &[
            include_bytes!("../tests/fixtures/nodeguard/client.pem").as_slice(),
            include_bytes!("../tests/fixtures/nodeguard/client.key").as_slice(),
        ]
        .concat(),
    )?;
    let guard = FixtureGuard::start_with_server_identity(
        binding.clone(),
        include_bytes!("../tests/fixtures/nodeguard/second-server.pem"),
        include_bytes!("../tests/fixtures/nodeguard/second-server.key"),
        &credentials,
    )
    .await?;
    let owner = Database {
        pool: case.source.f.base.f.owner.clone(),
    };
    let outcome = Box::pin(async {
        let error = enroll_with_client_test(&owner, kube.runtime.runtime(), &guard.client, &plan)
            .await.err().context("normal registration must not admit an enabled duplicate name")?;
        ensure!(error.to_string() == "historical cloud instance or active node identity requires the independent fenced-maintenance workflow", "normal duplicate-name refusal comes from the exact commit inventory guard");
        {
            let state = kube.shared.lock().map_err(|_| anyhow::anyhow!("duplicate probe GET state"))?;
            ensure!(state.node_reads == 2 && state.csi_reads == 0, "normal duplicate registration completed actual Node/identity/Node observation before the DB refusal");
        }
        ensure!(guard.identity_verifications.load(Ordering::SeqCst) == 1, "actual duplicate candidate mTLS identity endpoint was reached once");
        let duplicate: i64 = sqlx::query_scalar("SELECT count(*) FROM runtime_nodes WHERE cluster_epoch=$1 AND node_uid=$2")
            .bind(binding.cluster_epoch).bind(binding.node_uid).fetch_one(&owner.pool).await?;
        let same_name: i64 = sqlx::query_scalar("SELECT count(*) FROM runtime_nodes WHERE enabled AND cluster_epoch=$1 AND node_name=$2")
            .bind(binding.cluster_epoch).bind(name).fetch_one(&owner.pool).await?;
        ensure!(duplicate == 0 && same_name == 1 && inventory(&owner.pool).await? == before, "normal rejected duplicate cannot append or mutate any Node/enrollment/topology fact; not an actual count2 test");
        ensure!(facts(&owner.pool, case.t, case.r).await? == *case.baseline, "normal enrollment refusal preserves complete source/target/hold/quota facts");
        Ok::<_, anyhow::Error>(())
    }).await;
    let kube_closed = kube.finish().await;
    let guard_closed = guard.shutdown().await;
    if kube_closed.is_err() || guard_closed.is_err() {
        eprintln!("PRIVATE duplicate-name fixture cleanup failed; not certified drained");
    }
    outcome?;
    kube_closed?;
    guard_closed?;
    Ok(())
}

async fn node_lock_wait(case: &SelectedCase<'_>, name: &str) -> anyhow::Result<()> {
    let row = current_node(case, name).await?;
    let id: Uuid = serde_json::from_value(row["id"].clone())?;
    case.configure(0, Fault::None)?;
    let mut blocker = case.source.f.base.f.owner_transaction().await?;
    sqlx::query("SELECT id FROM runtime_nodes WHERE id=$1 AND enabled FOR UPDATE")
        .bind(id)
        .fetch_one(&mut *blocker)
        .await?;
    sqlx::query("UPDATE runtime_nodes SET enabled=false WHERE id=$1")
        .bind(id)
        .execute(&mut *blocker)
        .await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    let (decision, committed) = tokio::join!(
        case.put("select", case.changed(|_| {})?, StatusCode::FORBIDDEN),
        async {
            let mut blocked = false;
            for _ in 0..30 {
                blocked = sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename='sandbox_admission' AND $1=ANY(pg_blocking_pids(pid)))")
                    .bind(pid).fetch_one(&case.source.f.base.f.owner).await?;
                if blocked {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            ensure!(
                blocked,
                "actual selected reader waits on the exact original runtime Node lock"
            );
            blocker.commit().await?;
            anyhow::Ok(())
        }
    );
    // Restore only the fixture's mutable enabled flag; do not update immutable
    // Node identity, enrollment, certification or proof data.
    sqlx::query("UPDATE runtime_nodes SET enabled=true WHERE id=$1")
        .bind(id)
        .execute(&case.source.f.base.f.owner)
        .await?;
    committed?;
    decision?;
    denial_message(case, "Current raw scheduling authority unavailable")?;
    ensure!(
        case.w.reads(case.pvc_path)? == 0 && case.cloud.actions()?.is_empty(),
        "post-node-lock disabled inventory is refused before all live/cloud observations"
    );
    ensure!(
        current_node(case, name).await? == row,
        "original registered identity and row are restored exactly"
    );
    Ok(())
}

// The handler waits before acquiring an objects Mutex. A release guard wakes
// it on every mutation result, including a failed setup/assertion; no detached
// metadata request/owner task is created by this barrier.
struct ResumeRead(Arc<ReadPause>);
impl Drop for ResumeRead {
    fn drop(&mut self) {
        self.0.resume.notify_one();
    }
}
fn pause_second_node(case: &SelectedCase<'_>, name: &str) -> anyhow::Result<Arc<ReadPause>> {
    let pause = Arc::new(ReadPause {
        path: format!("/api/v1/nodes/{name}"),
        hit: 2,
        arrived: tokio::sync::Notify::new(),
        resume: tokio::sync::Notify::new(),
    });
    case.w
        .shared
        .lock()
        .map_err(|_| anyhow::anyhow!("read barrier state"))?
        .read_pause = Some(pause.clone());
    Ok(pause)
}
async fn reached_second_node(case: &SelectedCase<'_>, pause: &ReadPause) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(3), pause.arrived.notified())
        .await
        .context("second actual Node GET barrier not reached before bounded observation")?;
    full_cloud(case)?;
    ensure!(
        case.w.reads(&pause.path)? == 2,
        "actual second Node GET arrived after cloud before final reader"
    );
    Ok(())
}
#[derive(Clone, Copy)]
enum Drift {
    Epoch,
    PrincipalRevision,
    ProfileDisabled,
    NodeDisabled,
}
async fn final_authority_drift(
    case: &SelectedCase<'_>,
    name: &str,
    drift: Drift,
) -> anyhow::Result<()> {
    let row = current_node(case, name).await?;
    let node_id: Uuid = serde_json::from_value(row["id"].clone())?;
    let (actor, original_revision): (Uuid, i64) = {
        let mut tx = case.source.f.base.f.owner_transaction().await?;
        let actor = sqlx::query_as(
            "SELECT p.id,p.authz_version FROM operations o JOIN principals p ON p.id=o.actor_principal_id WHERE o.tenant_id=$1 AND o.id=$2",
        )
        .bind(case.t)
        .bind(case.job.record.operation_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        actor
    };
    case.configure(0, Fault::None)?;
    let pause = pause_second_node(case, name)?;
    let (decision, changed) = tokio::join!(
        case.put("select", case.changed(|_| {})?, StatusCode::FORBIDDEN),
        async {
            let _resume = ResumeRead(pause.clone());
            reached_second_node(case, &pause).await?;
            let mut tx = case.source.f.base.f.owner_transaction().await?;
            let count = match drift {
                Drift::Epoch => sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton AND cluster_epoch=$2")
                    .bind(Uuid::new_v4()).bind(case.job.record.cluster_epoch).execute(&mut *tx).await?.rows_affected(),
                // Explicit current-principal authorization revision. Its
                // monotone value is never reset to manufacture the old pin.
                Drift::PrincipalRevision => sqlx::query("UPDATE principals SET authz_version=authz_version+1,updated_at=clock_timestamp() WHERE id=$1 AND enabled")
                    .bind(actor).execute(&mut *tx).await?.rows_affected(),
                Drift::ProfileDisabled => sqlx::query("UPDATE backup_profiles SET enabled=false WHERE id=$1 AND enabled")
                    .bind(case.job.record.profile_id).execute(&mut *tx).await?.rows_affected(),
                Drift::NodeDisabled => sqlx::query("UPDATE runtime_nodes SET enabled=false WHERE id=$1 AND enabled")
                    .bind(node_id).execute(&mut *tx).await?.rows_affected(),
            };
            ensure!(
                count == 1,
                "exact one mutable current-authority row changed"
            );
            tx.commit().await?;
            anyhow::Ok(())
        }
    );
    case.w
        .shared
        .lock()
        .map_err(|_| anyhow::anyhow!("release barrier state"))?
        .read_pause = None;
    // Ordinary fixture restoration runs on failure too. No immutable receipt,
    // deadline or principal revision is rewritten and no successful retry is
    // substituted for the required403 decision.
    match drift {
        Drift::Epoch => {
            sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton")
                .bind(case.job.record.cluster_epoch)
                .execute(&case.source.f.base.f.owner)
                .await?;
        }
        Drift::ProfileDisabled => {
            sqlx::query("UPDATE backup_profiles SET enabled=true WHERE id=$1")
                .bind(case.job.record.profile_id)
                .execute(&case.source.f.base.f.owner)
                .await?;
        }
        Drift::NodeDisabled => {
            sqlx::query("UPDATE runtime_nodes SET enabled=true WHERE id=$1")
                .bind(node_id)
                .execute(&case.source.f.base.f.owner)
                .await?;
        }
        Drift::PrincipalRevision => {}
    }
    changed?;
    decision?;
    if matches!(drift, Drift::PrincipalRevision) {
        let revision: i64 = sqlx::query_scalar("SELECT authz_version FROM principals WHERE id=$1")
            .bind(actor)
            .fetch_one(&case.source.f.base.f.owner)
            .await?;
        ensure!(
            revision
                == original_revision
                    .checked_add(1)
                    .context("revision overflow")?,
            "actual principal authority revision advances and is never restored backwards"
        );
    }
    denial_message(
        case,
        match drift {
            Drift::PrincipalRevision => {
                "Scheduling authority, operation claim or enrolled node changed during observation"
            }
            _ => "Current raw scheduling authority unavailable",
        },
    )?;
    case.complete_rounds(true)?;
    full_cloud(case)?;
    ensure!(
        budget(case, Some(name)).await?.is_some(),
        "current authority is live again only for independent following trials"
    );
    Ok(())
}

async fn operation_identity(case: &SelectedCase<'_>) -> anyhow::Result<Value> {
    let mut tx = case.source.f.base.f.owner_transaction().await?;
    let row = sqlx::query_scalar("SELECT jsonb_build_object('id',id,'tenant_id',tenant_id,'project_id',project_id,'instance_id',instance_id,'workspace_id',workspace_id,'kind',kind,'request',request,'actor_principal_id',actor_principal_id,'request_id',request_id,'deadline',deadline,'created_at',created_at) FROM operations WHERE tenant_id=$1 AND id=$2")
        .bind(case.t).bind(case.job.record.operation_id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(row)
}
async fn final_claim_replacement(case: &SelectedCase<'_>) -> anyhow::Result<()> {
    let name = case
        .w
        .objects
        .lock()
        .map_err(|_| anyhow::anyhow!("claim Node name"))?
        .values()
        .find(|v| v["kind"] == "Node")
        .and_then(|v| v["metadata"]["name"].as_str())
        .context("actual Node name")?
        .to_owned();
    let original = operation_identity(case).await?;
    case.configure(0, Fault::None)?;
    let pause = pause_second_node(case, &name)?;
    let replacement = OperationEngine::new(
        case.source.f.backup.database.clone(),
        format!("selected-claim-replacement-{}", Uuid::new_v4().simple()),
    )?;
    let (decision, transferred) = tokio::join!(
        case.put("select", case.changed(|_| {})?, StatusCode::FORBIDDEN),
        async {
            let _resume = ResumeRead(pause.clone());
            reached_second_node(case, &pause).await?;
            case.source
                .f
                .backup
                .wait(
                    case.claim,
                    "SELECTED_PRIVATE_CLAIM_TRANSFER",
                    "Independent queued replacement of metadata reader authority",
                    1,
                )
                .await
                .map_err(api_failure)?;
            let transferred = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Some(next) = replacement.claim_backup().await.map_err(api_failure)? {
                        break anyhow::Ok(next);
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .context("ordinary backup queue did not return the eligible original operation")??;
            ensure!(
                transferred.tenant_id == case.t
                    && transferred.operation_id == case.claim.operation_id
                    && transferred.lease_token > case.claim.lease_token,
                "normal queue changes only actual owner/token of the same original operation"
            );
            ensure!(
                !case
                    .source
                    .f
                    .backup
                    .heartbeat(case.claim)
                    .await
                    .map_err(api_failure)?
                    && replacement
                        .heartbeat(&transferred)
                        .await
                        .map_err(api_failure)?,
                "old worker is truly fenced and replacement claim alone is live"
            );
            Ok::<_, anyhow::Error>(transferred)
        }
    );
    case.w
        .shared
        .lock()
        .map_err(|_| anyhow::anyhow!("claim release barrier state"))?
        .read_pause = None;
    let transferred = transferred?;
    decision?;
    denial_message(
        case,
        "Scheduling authority, operation claim or enrolled node changed during observation",
    )?;
    case.complete_rounds(true)?;
    full_cloud(case)?;
    ensure!(
        operation_identity(case).await? == original,
        "claim replacement cannot rewrite original request/resource/action/IfMatch/deadline identity"
    );
    ensure!(
        !case
            .source
            .f
            .backup
            .heartbeat(case.claim)
            .await
            .map_err(api_failure)?
            && replacement
                .heartbeat(&transferred)
                .await
                .map_err(api_failure)?,
        "HTTP denial does not roll back or masquerade as cancellation of the current queued owner"
    );
    Ok(())
}
