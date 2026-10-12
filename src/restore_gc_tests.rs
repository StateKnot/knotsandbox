//! Dedicated SCRAM PostgreSQL plus real signed TCP; Kubernetes/cloud state
//! transitions remain protocol fixtures, not live Alibaba/Kata certification.
use super::super::gc::{GcClaim, RestoreGcController};
use crate::{
    cloud_fencing::{
        CloudDiskBinding, CloudDiskLookup,
        restore_gc::{RestoreGcCloudScope, tests::Fixture},
    },
    termination_ledger::tests::FixtureRuntime,
    test_support_db::api_failure,
};
use anyhow::{Context, ensure};
use axum::{
    body::Body,
    http::{Method, Request, Response},
};
use chrono::{Duration, Utc};
use kube::{Client, client::Body as KubeBody};
use serde_json::{Value, json};
use sqlx::Row;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use uuid::Uuid;
pub(super) struct GcCase<'a> {
    pub base: &'a FixtureRuntime,
    pub restore: Uuid,
    pub objects: &'a Arc<Mutex<BTreeMap<String, Value>>>,
    pub guards: bool,
    pub admission: bool,
}
fn client(objects: Arc<Mutex<BTreeMap<String, Value>>>) -> Client {
    let service = tower::service_fn(move |request: Request<KubeBody>| {
        let objects = objects.clone();
        async move {
            let path = request.uri().path().to_owned();
            let method = request.method().clone();
            let body = axum::body::to_bytes(Body::new(request.into_body()), 131072)
                .await
                .unwrap_or_default();
            let payload: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let mut state = objects
                .lock()
                .map_err(|_| std::io::Error::other("Kube fixture lock poisoned"))?;
            let (status, value) = if path.ends_with("/pods") || path.ends_with("/volumeattachments")
            {
                (
                    200,
                    json!({"apiVersion":if path.ends_with("/pods"){"v1"}else{"storage.k8s.io/v1"},"kind":if path.ends_with("/pods"){"PodList"}else{"VolumeAttachmentList"},"metadata":{},"items":[]}),
                )
            } else if let Some(current) = state.get(&path).cloned() {
                if method == Method::PATCH {
                    if payload.pointer("/metadata/uid") != current.pointer("/metadata/uid")
                        || payload.pointer("/metadata/resourceVersion")
                            != current.pointer("/metadata/resourceVersion")
                    {
                        (
                            409,
                            json!({"apiVersion":"v1","kind":"Status","reason":"Conflict","status":"Failure","code":409}),
                        )
                    } else {
                        let mut updated = current.clone();
                        updated["metadata"]["finalizers"] =
                            payload["metadata"]["finalizers"].clone();
                        updated["metadata"]["resourceVersion"] = json!("2");
                        state.insert(path.clone(), updated.clone());
                        (200, updated)
                    }
                } else if method == Method::DELETE {
                    if payload.pointer("/preconditions/uid") != current.pointer("/metadata/uid")
                        || payload.pointer("/preconditions/resourceVersion")
                            != current.pointer("/metadata/resourceVersion")
                    {
                        (
                            409,
                            json!({"apiVersion":"v1","kind":"Status","reason":"Conflict","status":"Failure","code":409}),
                        )
                    } else if current
                        .pointer("/metadata/finalizers")
                        .and_then(Value::as_array)
                        .is_some_and(|v| !v.is_empty())
                    {
                        let mut retained = current.clone();
                        retained["metadata"]["deletionTimestamp"] = json!(Utc::now());
                        state.insert(path.clone(), retained.clone());
                        (202, retained)
                    } else {
                        state.remove(&path);
                        (
                            200,
                            json!({"apiVersion":"v1","kind":"Status","status":"Success"}),
                        )
                    }
                } else {
                    (200, current)
                }
            } else {
                (
                    404,
                    json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}),
                )
            };
            Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(Body::from(value.to_string()))
                .map_err(std::io::Error::other)
        }
    });
    Client::new(service, "default")
}
pub(super) async fn run(c: GcCase<'_>) -> anyhow::Result<()> {
    let f = &c.base.f;
    sqlx::raw_sql(include_str!(
        "../tests/fixtures/restore/0038_restore_gc.sql"
    ))
    .execute(&f.owner)
    .await?;
    sqlx::raw_sql(include_str!("../scripts/sql/restore-gc-role.sql"))
        .execute(&f.owner)
        .await?;
    let gc_url = std::env::var("TEST_RESTORE_GC_DATABASE_URL")?;
    let mut parsed = url::Url::parse(&gc_url)?;
    ensure!(
        parsed.host_str() == Some("127.0.0.1") && parsed.username() == "sandbox_restore_gc",
        "host SCRAM and independent GC identity required"
    );
    parsed
        .set_password(Some("PUBLIC_INTENTIONALLY_WRONG_RESTORE_GC_PASSWORD"))
        .map_err(|_| anyhow::anyhow!("test URL"))?;
    assert!(
        sqlx::PgPool::connect(parsed.as_str()).await.is_err(),
        "wrong host SCRAM password must fail"
    );
    let database = crate::db::Database::connect(&gc_url, 4).await?;
    let login: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&database.pool)
        .await?;
    assert_eq!(login, "sandbox_restore_gc");
    assert!(
        database.verify_runtime_role().await.is_err(),
        "private draft is never a production migration"
    );
    for statement in [
        "UPDATE instances SET updated_at=clock_timestamp()",
        "UPDATE quota_accounts SET allocated=allocated",
        "INSERT INTO restore_gc_reviews(id) VALUES(gen_random_uuid())",
        "UPDATE restore_gc_runs SET status='SUCCEEDED'",
        "SELECT * FROM file_transfer_parts",
    ] {
        let mut tx = database
            .begin(f.actor.tenant_id)
            .await
            .map_err(api_failure)?;
        assert!(sqlx::query(statement).execute(&mut *tx).await.is_err());
        tx.rollback().await?;
    }
    let mut tx = f.owner_transaction().await?;
    let r=sqlx::query("SELECT r.backup_id,r.target_project_id,r.cluster_epoch,r.source_identity,raw.cloud_disk AS raw_disk,raw.pv_name AS raw_pv,d.cloud_disk AS target_disk,d.pv_name AS target_pv,d.namespace,s.cloud_snapshot,w.pvc_name,w.storage_class,w.id AS workspace_id,bs.cloud_snapshot AS source_snapshot FROM restores r JOIN restore_block_receipts raw ON raw.tenant_id=r.tenant_id AND raw.restore_id=r.id JOIN restore_delivery_receipts d ON d.tenant_id=r.tenant_id AND d.restore_id=r.id JOIN restore_snapshot_receipts s ON s.tenant_id=r.tenant_id AND s.restore_id=r.id JOIN workspaces w ON w.tenant_id=r.tenant_id AND w.id=r.workspace_id JOIN backups b ON b.tenant_id=r.tenant_id AND b.id=r.backup_id JOIN backup_snapshot_receipts bs ON bs.tenant_id=b.tenant_id AND bs.backup_id=b.id WHERE r.tenant_id=$1 AND r.id=$2")
  .bind(f.actor.tenant_id).bind(c.restore).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    let source: Value = r.try_get("source_identity")?;
    let class_path = format!(
        "/apis/storage.k8s.io/v1/storageclasses/{}",
        r.try_get::<String, _>("storage_class")?
    );
    let kms = c
        .objects
        .lock()
        .map_err(|_| anyhow::anyhow!("Kube fixture lock poisoned"))?
        .get(&class_path)
        .and_then(|v| v.pointer("/parameters/kmsKeyId"))
        .and_then(Value::as_str)
        .context("certified fixture KMS")?
        .to_owned();
    let raw = CloudDiskBinding {
        account_id: source["account_id"].as_str().context("account")?.into(),
        region: source["region"].as_str().context("region")?.into(),
        disk_id: r.try_get("raw_disk")?,
        zone_id: "cn-hangzhou-h".into(),
        deployment: "production-a".into(),
        namespace: "sandbox-system".into(),
        pvc_name: format!("sbx-bvol-{}", c.restore),
        pv_name: r.try_get("raw_pv")?,
        kms_key_id: kms,
        size_gib: 20,
    };
    let target = CloudDiskBinding {
        disk_id: r.try_get("target_disk")?,
        namespace: r.try_get("namespace")?,
        pvc_name: r.try_get("pvc_name")?,
        pv_name: r.try_get("target_pv")?,
        ..raw.clone()
    };
    let cloud = Fixture::with_bindings(
        RestoreGcCloudScope {
            restore_id: c.restore,
            raw_disk_id: raw.disk_id.clone(),
            snapshot_id: r.try_get("cloud_snapshot")?,
            target_disk_id: target.disk_id.clone(),
        },
        &raw,
        &target,
    )
    .await?;
    let CloudDiskLookup::Present(raw_obs) = cloud.client.observe_raw_disk(&raw).await? else {
        anyhow::bail!("raw expected")
    };
    let CloudDiskLookup::Present(target_obs) = cloud.client.observe_target_disk(&target).await?
    else {
        anyhow::bail!("target expected")
    };
    let raw_identity = json!(raw_obs.identity()?);
    let target_identity = json!(target_obs.identity()?);
    let snapshot_identity = json!(cloud.identity().await?);
    let review = Uuid::new_v4();
    let insert = "INSERT INTO restore_gc_reviews(id,tenant_id,restore_id,source_backup_id,cluster_epoch,raw_identity,snapshot_identity,target_identity,force_created_disk,retain_until,valid_until,reviewed_by,approval_reference,report_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'reviewed-local-protocol-test',$13)";
    for (altered, force, retain) in [
        (true, true, Utc::now() - Duration::seconds(1)),
        (false, false, Utc::now() + Duration::seconds(60)),
    ] {
        let mut snapshot = snapshot_identity.clone();
        if altered {
            snapshot["binding"]["scope"]["snapshot_id"] =
                json!(r.try_get::<String, _>("source_snapshot")?);
        }
        let mut tx = f.owner_transaction().await?;
        let result = sqlx::query(insert)
            .bind(review)
            .bind(f.actor.tenant_id)
            .bind(c.restore)
            .bind(r.try_get::<Uuid, _>("backup_id")?)
            .bind(r.try_get::<Uuid, _>("cluster_epoch")?)
            .bind(&raw_identity)
            .bind(snapshot)
            .bind(&target_identity)
            .bind(force)
            .bind(retain)
            .bind(Utc::now() + Duration::hours(1))
            .bind(f.actor.principal_id)
            .bind("b".repeat(64))
            .execute(&mut *tx)
            .await;
        if altered {
            assert!(
                result.is_err(),
                "source backup snapshot can never be GC scope"
            );
        } else {
            result?;
            let available:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sandbox_claim_restore_gc($1,$2,'retention-denied',300))").bind(f.actor.tenant_id).bind(c.restore).fetch_one(&mut *tx).await?;
            assert!(!available, "retention must prevent claim");
        }
        tx.rollback().await?;
    }
    let mut tx = f.owner_transaction().await?;
    sqlx::query(insert)
        .bind(review)
        .bind(f.actor.tenant_id)
        .bind(c.restore)
        .bind(r.try_get::<Uuid, _>("backup_id")?)
        .bind(r.try_get::<Uuid, _>("cluster_epoch")?)
        .bind(&raw_identity)
        .bind(&snapshot_identity)
        .bind(&target_identity)
        .bind(true)
        .bind(Utc::now() - Duration::seconds(1))
        .bind(Utc::now() + Duration::hours(1))
        .bind(f.actor.principal_id)
        .bind("b".repeat(64))
        .execute(&mut *tx)
        .await?;
    let resource_rows=sqlx::query("SELECT i.kind,i.name,i.namespace,b.uid FROM restore_resource_intents i JOIN restore_resource_bindings b ON b.tenant_id=i.tenant_id AND b.intent_id=i.id WHERE i.tenant_id=$1 AND i.restore_id=$2 AND i.kind IN('BLOCK_PVC','BLOCK_PV','RESTORED_SNAPSHOT','RESTORED_CONTENT','DELIVERY_SNAPSHOT','DELIVERY_CONTENT')")
  .bind(f.actor.tenant_id).bind(c.restore).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    let mut paths = Vec::new();
    for resource in resource_rows {
        let kind: String = resource.try_get("kind")?;
        let name: String = resource.try_get("name")?;
        let ns: String = resource.try_get("namespace")?;
        let path = match kind.as_str() {
            "BLOCK_PVC" => format!("/api/v1/namespaces/{ns}/persistentvolumeclaims/{name}"),
            "BLOCK_PV" => format!("/api/v1/persistentvolumes/{name}"),
            "RESTORED_SNAPSHOT" | "DELIVERY_SNAPSHOT" => {
                format!("/apis/snapshot.storage.k8s.io/v1/namespaces/{ns}/volumesnapshots/{name}")
            }
            _ => format!("/apis/snapshot.storage.k8s.io/v1/volumesnapshotcontents/{name}"),
        };
        let mut map = c
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("Kube fixture lock poisoned"))?;
        let object = map
            .get_mut(&path)
            .context("persisted resource must exist in Kube fixture")?;
        assert_eq!(
            object["metadata"]["uid"],
            json!(resource.try_get::<Uuid, _>("uid")?)
        );
        object["metadata"]["resourceVersion"] = json!("1");
        paths.push(path);
    }
    let controller = RestoreGcController {
        database,
        client: client(c.objects.clone()),
        cloud: cloud.client.clone(),
    };
    if c.admission {
        return Box::pin(super::gc_admission::run(
            c.base, c.restore, c.objects, controller, &cloud, &paths,
        ))
        .await;
    }
    assert!(
        controller
            .candidates()
            .await
            .map_err(api_failure)?
            .contains(&(f.actor.tenant_id, c.restore))
    );
    let mut foreign = controller
        .database
        .begin(Uuid::new_v4())
        .await
        .map_err(api_failure)?;
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM restore_gc_reviews")
        .fetch_one(&mut *foreign)
        .await?;
    assert_eq!(rows, 0);
    foreign.commit().await?;
    // A valid pre-read cannot survive expiry while waiting on the workspace.
    let mut lease_tx = controller
        .database
        .begin(f.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    let expiring:GcClaim=sqlx::query_as("SELECT tenant_id,restore_id,review_id,lease_token,lease_owner FROM sandbox_claim_restore_gc($1,$2,'expiring-behind-workspace-lock',10)")
        .bind(f.actor.tenant_id).bind(c.restore).fetch_one(&mut *lease_tx).await?;
    lease_tx.commit().await?;
    let mut blocker = f.owner_transaction().await?;
    sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(f.actor.tenant_id)
        .bind(r.try_get::<Uuid, _>("workspace_id")?)
        .fetch_one(&mut *blocker)
        .await?;
    let mut waiting = controller
        .database
        .begin(f.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    // Only this private test transaction waits beyond the production timeout,
    // so the actual definer's post-wait clock check is exercised.
    sqlx::query("SET LOCAL lock_timeout='20s'")
        .execute(&mut *waiting)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='20s'")
        .execute(&mut *waiting)
        .await?;
    let (stale_result, release_result) = tokio::join!(
        sqlx::query_scalar::<_, bool>("SELECT sandbox_assert_restore_gc_claim($1,$2,$3,$4)")
            .bind(expiring.tenant_id)
            .bind(expiring.restore_id)
            .bind(&expiring.lease_owner)
            .bind(expiring.lease_token)
            .fetch_one(&mut *waiting),
        async move {
            tokio::time::sleep(std::time::Duration::from_secs(11)).await;
            blocker.commit().await
        }
    );
    release_result?;
    assert!(
        !stale_result?,
        "expiry after W lock wait must prevent dispatch"
    );
    waiting.commit().await?;
    assert!(controller.reconcile(&expiring).await.is_err());
    assert_eq!(cloud.count("DeleteDisk"), 0);
    assert_eq!(cloud.count("DeleteSnapshot"), 0);
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE restore_gc_runs SET status='WAITING',lease_owner=NULL,lease_until=NULL,next_attempt_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND restore_id=$2")
        .bind(f.actor.tenant_id).bind(c.restore).execute(&mut *tx).await?;
    tx.commit().await?;
    let mut claim = controller
        .claim(f.actor.tenant_id, c.restore, "gc-real-controller")
        .await
        .map_err(api_failure)?
        .context("GC claim")?;
    if c.guards {
        claim = direct_result_guards(&controller, &claim, &raw_identity, c.base).await?;
        assert_eq!(cloud.count("DeleteDisk"), 0);
        assert_eq!(cloud.count("DeleteSnapshot"), 0);
    }
    let (other_a, other_b) = tokio::join!(
        controller.claim(f.actor.tenant_id, c.restore, "competing-a"),
        controller.claim(f.actor.tenant_id, c.restore, "competing-b")
    );
    assert!(other_a.map_err(api_failure)?.is_none() && other_b.map_err(api_failure)?.is_none());
    assert!(!controller.reconcile(&claim).await.map_err(api_failure)?);
    assert_eq!(cloud.count("DeleteDisk"), 1);
    let mut tx = f.owner_transaction().await?;
    let quota:i64=sqlx::query_scalar("SELECT sum(q.amount)::bigint FROM quota_reservations q JOIN quota_accounts a ON a.tenant_id=q.tenant_id AND a.id=q.quota_account_id WHERE q.tenant_id=$1 AND q.operation_id=(SELECT operation_id FROM restores WHERE id=$2) AND a.dimension='BACKUP_TEMP_GIB' AND q.status='ALLOCATED'").bind(f.actor.tenant_id).bind(c.restore).fetch_one(&mut *tx).await?;
    assert_eq!(quota, 80);
    tx.commit().await?;
    cloud.raw_absent();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let claim = controller
        .claim(f.actor.tenant_id, c.restore, "gc-after-restart")
        .await
        .map_err(api_failure)?
        .context("reclaim raw")?;
    assert!(!controller.reconcile(&claim).await.map_err(api_failure)?);
    assert_eq!(cloud.count("DeleteSnapshot"), 1);
    cloud.snapshot_absent();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let mut claim = controller
        .claim(f.actor.tenant_id, c.restore, "gc-final-cleanup")
        .await
        .map_err(api_failure)?
        .context("final claim")?;
    let raw_pvc_path = format!(
        "/api/v1/namespaces/sandbox-system/persistentvolumeclaims/{}",
        raw.pvc_name
    );
    let original_uid = {
        let mut map = c
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("Kube fixture poisoned"))?;
        let current = map.get_mut(&raw_pvc_path).context("raw PVC")?;
        let uid = current["metadata"]["uid"].clone();
        current["metadata"]["uid"] = json!(Uuid::new_v4());
        uid
    };
    assert!(
        controller.reconcile(&claim).await.is_err(),
        "same-name replacement PVC cannot produce cleanup evidence"
    );
    {
        let mut map = c
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("Kube fixture poisoned"))?;
        map.get_mut(&raw_pvc_path).context("raw PVC")?["metadata"]["uid"] = original_uid;
    }
    if c.guards {
        // These absences come from the actual typed TCP transport and exact
        // Kubernetes UID cleanup, never owner-created physical proofs.
        assert!(
            controller
                .reconcile_resources(&claim)
                .await
                .map_err(api_failure)?
        );
        claim =
            event_wait_guard(&controller, &claim, c.base, r.try_get("target_project_id")?).await?;
    } else {
        assert!(controller.reconcile(&claim).await.map_err(api_failure)?);
    }
    for path in paths {
        assert!(
            !c.objects
                .lock()
                .map_err(|_| anyhow::anyhow!("Kube fixture lock poisoned"))?
                .contains_key(&path),
            "temporary Kube resource must be absent"
        );
    }
    let mut tx = f.owner_transaction().await?;
    let released:i64=sqlx::query_scalar("SELECT count(*) FROM quota_reservations q JOIN quota_accounts a ON a.tenant_id=q.tenant_id AND a.id=q.quota_account_id WHERE q.tenant_id=$1 AND q.operation_id=(SELECT operation_id FROM restores WHERE id=$2) AND a.dimension='BACKUP_TEMP_GIB' AND q.status='RELEASED'").bind(f.actor.tenant_id).bind(c.restore).fetch_one(&mut *tx).await?;
    assert_eq!(released, 2);
    let retained: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM backups WHERE tenant_id=$1 AND id=$2 AND status='AVAILABLE'",
    )
    .bind(f.actor.tenant_id)
    .bind(r.try_get::<Uuid, _>("backup_id")?)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(retained, 1);
    tx.commit().await?;
    let mut tx = controller
        .database
        .begin(f.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    let repeat: bool = sqlx::query_scalar("SELECT sandbox_finish_restore_gc($1,$2,$3,$4)")
        .bind(f.actor.tenant_id)
        .bind(c.restore)
        .bind(&claim.lease_owner)
        .bind(claim.lease_token)
        .fetch_one(&mut *tx)
        .await?;
    assert!(repeat);
    tx.commit().await?;
    let stale = GcClaim {
        lease_token: claim.lease_token - 1,
        ..claim
    };
    assert!(controller.reconcile(&stale).await.is_err());
    eprintln!(
        "VERIFIED independent host SCRAM positive/negative, GC least privilege/RLS, retained source rejection, lease expiry during workspace lock wait denies writes, dual TEMP kept after acknowledgement, restart reconciliation, same-name UID denial, exact cloud absences, six UID/finalizer cleanup and one settlement"
    );
    Ok(())
}

fn constraint(error: sqlx::Error) -> anyhow::Result<()> {
    ensure!(
        error.as_database_error().and_then(|e| e.code()).as_deref() == Some("23514"),
        "a database provenance constraint must reject the operation"
    );
    Ok(())
}

async fn direct_result_guards(
    controller: &RestoreGcController,
    claim: &GcClaim,
    raw: &Value,
    base: &FixtureRuntime,
) -> anyhow::Result<GcClaim> {
    let mut tx = controller
        .database
        .begin(claim.tenant_id)
        .await
        .map_err(api_failure)?;
    let completed = Uuid::new_v4();
    let pending = Uuid::new_v4();
    for id in [completed, pending] {
        sqlx::query("INSERT INTO restore_gc_dispatches(id,tenant_id,restore_id,review_id,lease_token,kind,identity,force_created_disk) VALUES($1,$2,$3,$4,$5,'PRESERVE_RAW_SNAPSHOTS',$6,false)")
            .bind(id).bind(claim.tenant_id).bind(claim.restore_id).bind(claim.review_id).bind(claim.lease_token).bind(raw).execute(&mut *tx).await?;
    }
    // A direct role can record an unknown acknowledgement for its live intent.
    // This is not provider absence and must never satisfy settlement.
    sqlx::query("INSERT INTO restore_gc_results(dispatch_id,tenant_id,restore_id,outcome,evidence) VALUES($1,$2,$3,'UNKNOWN',$4)")
        .bind(completed).bind(claim.tenant_id).bind(claim.restore_id).bind(json!({"test_only_intent_no_provider_io":true})).execute(&mut *tx).await?;
    let finish: bool = sqlx::query_scalar("SELECT sandbox_finish_restore_gc($1,$2,$3,$4)")
        .bind(claim.tenant_id)
        .bind(claim.restore_id)
        .bind(&claim.lease_owner)
        .bind(claim.lease_token)
        .fetch_one(&mut *tx)
        .await?;
    assert!(!finish, "an outcome alone cannot become physical absence");
    let absence: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM restore_gc_cloud_absences WHERE tenant_id=$1 AND restore_id=$2",
    )
    .bind(claim.tenant_id)
    .bind(claim.restore_id)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(absence, 0);
    tx.commit().await?;
    let mut tx = base.f.owner_transaction().await?;
    let allocated: i64 = sqlx::query_scalar("SELECT sum(q.amount)::bigint FROM quota_reservations q JOIN quota_accounts a ON a.tenant_id=q.tenant_id AND a.id=q.quota_account_id JOIN restores r ON r.tenant_id=q.tenant_id AND r.operation_id=q.operation_id WHERE r.tenant_id=$1 AND r.id=$2 AND a.dimension='BACKUP_TEMP_GIB' AND q.status='ALLOCATED'")
        .bind(claim.tenant_id).bind(claim.restore_id).fetch_one(&mut *tx).await?;
    assert_eq!(
        allocated, 80,
        "an acknowledgement keeps both temporary storage reservations"
    );
    tx.commit().await?;
    let insert = "INSERT INTO restore_gc_results(dispatch_id,tenant_id,restore_id,outcome,evidence,recorded_at) VALUES($1,$2,$3,'ACCEPTED','{}',$4)";
    for (tenant, restore, at) in [
        (
            claim.tenant_id,
            claim.restore_id,
            Utc::now() - Duration::days(1),
        ),
        (
            claim.tenant_id,
            claim.restore_id,
            Utc::now() + Duration::days(1),
        ),
        (Uuid::new_v4(), claim.restore_id, Utc::now()),
        (claim.tenant_id, Uuid::new_v4(), Utc::now()),
    ] {
        let mut tx = controller
            .database
            .begin(tenant)
            .await
            .map_err(api_failure)?;
        constraint(
            sqlx::query(insert)
                .bind(pending)
                .bind(tenant)
                .bind(restore)
                .bind(at)
                .execute(&mut *tx)
                .await
                .err()
                .context("changed scope/time must be rejected")?,
        )?;
        tx.rollback().await?;
    }
    let renewed = requeue_and_claim(controller, claim, 300, "new-result-claim").await?;
    let mut tx = controller
        .database
        .begin(claim.tenant_id)
        .await
        .map_err(api_failure)?;
    constraint(
        sqlx::query(insert)
            .bind(pending)
            .bind(claim.tenant_id)
            .bind(claim.restore_id)
            .bind(Utc::now())
            .execute(&mut *tx)
            .await
            .err()
            .context("old dispatch must not attach outcome under a new lease")?,
    )?;
    tx.rollback().await?;
    eprintln!(
        "VERIFIED direct GC SQL outcomes require current dispatch/claim/scope/time; UNKNOWN alone cannot settle or create provider absence"
    );
    Ok(renewed)
}

async fn requeue_and_claim(
    controller: &RestoreGcController,
    claim: &GcClaim,
    seconds: i32,
    worker: &str,
) -> anyhow::Result<GcClaim> {
    let mut tx = controller
        .database
        .begin(claim.tenant_id)
        .await
        .map_err(api_failure)?;
    let waited: bool = sqlx::query_scalar(
        "SELECT sandbox_wait_restore_gc($1,$2,$3,$4,'PRIVATE_TEST_STAGE_BOUNDARY',1)",
    )
    .bind(claim.tenant_id)
    .bind(claim.restore_id)
    .bind(&claim.lease_owner)
    .bind(claim.lease_token)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(waited, "current claim must requeue");
    tx.commit().await?;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let mut tx = controller
        .database
        .begin(claim.tenant_id)
        .await
        .map_err(api_failure)?;
    let next = sqlx::query_as("SELECT tenant_id,restore_id,review_id,lease_token,lease_owner FROM sandbox_claim_restore_gc($1,$2,$3,$4)")
        .bind(claim.tenant_id).bind(claim.restore_id).bind(worker).bind(seconds).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(next)
}

async fn event_wait_guard(
    controller: &RestoreGcController,
    claim: &GcClaim,
    base: &FixtureRuntime,
    project: Uuid,
) -> anyhow::Result<GcClaim> {
    let expiring =
        requeue_and_claim(controller, claim, 10, "expiring-during-event-publication").await?;
    let mut blocker = base.f.owner_transaction().await?;
    sqlx::query(
        "SELECT project_id FROM event_stream_heads WHERE tenant_id=$1 AND project_id=$2 FOR UPDATE",
    )
    .bind(claim.tenant_id)
    .bind(project)
    .fetch_one(&mut *blocker)
    .await?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    let mut waiting = controller
        .database
        .begin(claim.tenant_id)
        .await
        .map_err(api_failure)?;
    // Production timeouts remain unchanged; only this test transaction waits
    // long enough to exercise the finish function's final clock check.
    sqlx::query("SET LOCAL lock_timeout='20s'")
        .execute(&mut *waiting)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='20s'")
        .execute(&mut *waiting)
        .await?;
    let waiter_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *waiting)
        .await?;
    let (finish, released) = tokio::join!(
        sqlx::query_scalar::<_, bool>("SELECT sandbox_finish_restore_gc($1,$2,$3,$4)")
            .bind(expiring.tenant_id)
            .bind(expiring.restore_id)
            .bind(&expiring.lease_owner)
            .bind(expiring.lease_token)
            .fetch_one(&mut *waiting),
        async {
            let mut blocked = false;
            for _ in 0..30 {
                blocked = sqlx::query_scalar::<_, bool>("SELECT $2=ANY(pg_blocking_pids($1))")
                    .bind(waiter_pid)
                    .bind(blocker_pid)
                    .fetch_one(&base.f.owner)
                    .await?;
                if blocked {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            ensure!(blocked, "finish must actually wait on this event head lock");
            tokio::time::sleep(std::time::Duration::from_secs(11)).await;
            blocker.commit().await?;
            anyhow::Ok(())
        }
    );
    released?;
    constraint(
        finish
            .err()
            .context("expired event publication must abort settlement")?,
    )?;
    waiting.rollback().await?;
    let mut tx = base.f.owner_transaction().await?;
    let amounts = sqlx::query("SELECT count(*) FILTER(WHERE q.status='ALLOCATED')::bigint AS allocated,count(*) FILTER(WHERE q.status='RELEASED')::bigint AS released,sum(q.amount) FILTER(WHERE q.status='ALLOCATED')::bigint AS gib FROM quota_reservations q JOIN quota_accounts a ON a.tenant_id=q.tenant_id AND a.id=q.quota_account_id JOIN restores r ON r.tenant_id=q.tenant_id AND r.operation_id=q.operation_id WHERE r.tenant_id=$1 AND r.id=$2 AND a.dimension='BACKUP_TEMP_GIB'")
        .bind(claim.tenant_id).bind(claim.restore_id).fetch_one(&mut *tx).await?;
    assert_eq!(amounts.try_get::<i64, _>("allocated")?, 2);
    assert_eq!(amounts.try_get::<i64, _>("released")?, 0);
    assert_eq!(amounts.try_get::<i64, _>("gib")?, 80);
    for query in [
        "SELECT count(*) FROM restore_gc_settlements WHERE tenant_id=$1 AND restore_id=$2",
        "SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND resource_id=$2 AND action='restores:gc'",
        "SELECT count(*) FROM domain_events WHERE tenant_id=$1 AND aggregate_id=$2 AND event_type='restore.temporary_storage_reclaimed'",
    ] {
        let count: i64 = sqlx::query_scalar(query)
            .bind(claim.tenant_id)
            .bind(claim.restore_id)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(count, 0, "all settlement side effects must roll back");
    }
    let run: String = sqlx::query_scalar(
        "SELECT status FROM restore_gc_runs WHERE tenant_id=$1 AND restore_id=$2",
    )
    .bind(claim.tenant_id)
    .bind(claim.restore_id)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(run, "RUNNING");
    tx.commit().await?;
    let next = controller
        .claim(
            claim.tenant_id,
            claim.restore_id,
            "after-event-expiry-restart",
        )
        .await
        .map_err(api_failure)?
        .context("fresh restart claim")?;
    assert!(controller.reconcile(&next).await.map_err(api_failure)?);
    eprintln!(
        "VERIFIED actual event head wait expires claim; quota, settlement, audit and event roll back atomically; fresh claim settles exactly once"
    );
    Ok(next)
}
