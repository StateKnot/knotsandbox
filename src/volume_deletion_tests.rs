#![allow(clippy::expect_used)]
use super::*;
use crate::{
    domain::InstanceAction,
    termination_ledger::tests::{FixtureRuntime, cleanup_runtime},
    test_support_db::{self, api_failure, require_pg_error},
    workspaces::DeleteWorkspace,
};
use anyhow::{Context, ensure};
use axum::{
    body::Body,
    http::{Request, Response},
};
use kube::{Client, client::Body as KubeBody};
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
};

struct Fixture {
    base: FixtureRuntime,
    controller: VolumeDeletionController,
    cloud: crate::cloud_fencing::volume_deletion::tests::Fixture,
    kube: Arc<Mutex<KubeState>>,
    client: Client,
}
struct KubeState {
    pvc: Value,
    pv: Value,
    deleted: Vec<String>,
    attachment: bool,
}
impl Fixture {
    async fn new() -> anyhow::Result<Self> {
        let base = FixtureRuntime::new(true).await?;
        base.running().await?;
        let stop = base.accept(InstanceAction::Delete).await?;
        let (proof, id) = base.proof(&stop).await?;
        let (runtime, _) = cleanup_runtime(&base.launch, false);
        let cleanup = runtime.cleanup(&proof).await?.context("trusted cleanup")?;
        base.engine
            .database
            .complete_termination(&base.engine, &stop, id, &cleanup)
            .await
            .map_err(api_failure)?;
        let mut tx = base.f.owner_transaction().await?;
        for action in ["workspaces:read", "workspaces:delete"] {
            sqlx::query(
                "INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4)",
            )
            .bind(base.f.actor.tenant_id)
            .bind(base.launch.project_id)
            .bind(base.f.actor.principal_id)
            .bind(action)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        sqlx::raw_sql(include_str!("../scripts/sql/volume-deleter-role.sql"))
            .execute(&base.f.owner)
            .await?;
        let url = std::env::var("TEST_VOLUME_DELETER_DATABASE_URL")
            .context("TEST_VOLUME_DELETER_DATABASE_URL required")?;
        let actual = url::Url::parse(&url)?;
        let expected = url::Url::parse(&std::env::var("TEST_DATABASE_URL")?)?;
        ensure!(
            actual.username() == "sandbox_volume_deleter"
                && actual.path().ends_with("_test")
                && actual.path() == expected.path()
                && actual.host_str() == expected.host_str()
                && actual.port() == expected.port(),
            "dedicated role must target the disposable test database"
        );
        let db = Database::connect(&url, 5).await?;
        db.verify_runtime_role().await?;
        let engine = OperationEngine::new(db, format!("volume-test-{}", Uuid::new_v4()))?;
        let cloud = crate::cloud_fencing::volume_deletion::tests::Fixture::new().await?;
        let profile = WorkspaceStorageProfile {
            storage_class: base.f.request.workspace.size_gib.to_string(),
            kms_key_id: "kms-workspace001".into(),
            zones: vec!["cn-hangzhou-h".into()],
            deployment: "production-a".into(),
            certification_id: "test-only-volume-evidence".into(),
        };
        let mut tx = base.f.owner_transaction().await?;
        let class: String =
            sqlx::query_scalar("SELECT storage_class FROM workspaces WHERE tenant_id=$1 AND id=$2")
                .bind(base.f.actor.tenant_id)
                .bind(base.launch.workspace_id)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        let profile = WorkspaceStorageProfile {
            storage_class: class.clone(),
            ..profile
        };
        let pvc = json!({"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":{"name":format!("ws-{}",base.launch.workspace_id),"namespace":base.launch.namespace,"uid":base.launch.pvc_uid,"resourceVersion":"10"},"spec":{"volumeName":base.launch.pv_name,"storageClassName":class,"volumeMode":"Filesystem","accessModes":["ReadWriteOnce"]},"status":{"phase":"Bound"}});
        let pv = json!({"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":base.launch.pv_name,"uid":base.launch.pv_uid,"resourceVersion":"20"},"spec":{"persistentVolumeReclaimPolicy":"Retain","storageClassName":class,"volumeMode":"Filesystem","accessModes":["ReadWriteOnce"],"capacity":{"storage":"20Gi"},"claimRef":{"namespace":base.launch.namespace,"name":format!("ws-{}",base.launch.workspace_id),"uid":base.launch.pvc_uid},"csi":{"driver":"diskplugin.csi.alibabacloud.com","volumeHandle":base.launch.csi_volume_handle},"nodeAffinity":{"required":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"topology.diskplugin.csi.alibabacloud.com/zone","operator":"In","values":["cn-hangzhou-h"]}]}]}}},"status":{"phase":"Bound"}});
        let kube = Arc::new(Mutex::new(KubeState {
            pvc,
            pv,
            deleted: vec![],
            attachment: false,
        }));
        let observed = kube.clone();
        let ns = json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":base.launch.namespace,"labels":{"sandbox.platform/managed":"true","sandbox.platform/tenant-id":base.f.actor.tenant_id,"sandbox.platform/project-id":base.launch.project_id,"sandbox.platform/cluster-epoch":base.node.cluster_epoch},"annotations":{"sandbox.platform/certification-id":profile.certification_id}}});
        let class = json!({"apiVersion":"storage.k8s.io/v1","kind":"StorageClass","metadata":{"name":class},"provisioner":"diskplugin.csi.alibabacloud.com","reclaimPolicy":"Retain","parameters":{"encrypted":"true","kmsKeyId":profile.kms_key_id,"diskTags/Deployment":profile.deployment}});
        let svc = tower::service_fn(move |request: Request<KubeBody>| {
            let state = observed.clone();
            let ns = ns.clone();
            let class = class.clone();
            async move {
                let mut s = state.lock().expect("test Kube state");
                let path = request.uri().path();
                let method = request.method().as_str();
                let mut code = 200;
                let value = if path.contains("/storageclasses/") {
                    class
                } else if path.ends_with("/volumeattachments") {
                    json!({"apiVersion":"storage.k8s.io/v1","kind":"VolumeAttachmentList","metadata":{},"items":if s.attachment {vec![json!({"metadata":{"name":"old-attachment"},"spec":{"attacher":"diskplugin.csi.alibabacloud.com","nodeName":"node","source":{"persistentVolumeName":s.pv["metadata"]["name"]}}})]}else{vec![]}})
                } else if path.ends_with("/pods") {
                    json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":[]})
                } else if path.contains("/persistentvolumeclaims/") {
                    if method == "DELETE" {
                        s.deleted.push("PVC".into());
                        s.pvc = Value::Null;
                        json!({"apiVersion":"v1","kind":"Status","status":"Success"})
                    } else if s.pvc.is_null() {
                        code = 404;
                        json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404})
                    } else {
                        s.pvc.clone()
                    }
                } else if path.contains("/persistentvolumes/") {
                    if method == "DELETE" {
                        s.deleted.push("PV".into());
                        s.pv = Value::Null;
                        json!({"apiVersion":"v1","kind":"Status","status":"Success"})
                    } else if s.pv.is_null() {
                        code = 404;
                        json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404})
                    } else {
                        s.pv.clone()
                    }
                } else {
                    ns
                };
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(code)
                        .header("content-type", "application/json")
                        .body(Body::from(value.to_string()))
                        .expect("response"),
                )
            }
        });
        let client = Client::new(svc, "default");
        let runtime = VolumeDeletionRuntime::new(
            crate::runtime::KubernetesRuntime::from_client(client.clone()),
            profile,
        )?;
        let controller = VolumeDeletionController::new(engine, runtime, cloud.client.clone(), 1)?;
        Ok(Self {
            base,
            controller,
            cloud,
            kube,
            client,
        })
    }
    async fn accept(
        &self,
        key: &str,
    ) -> anyhow::Result<crate::workspaces::WorkspaceMutationResult> {
        let ws = self
            .base
            .f
            .database
            .get_workspace(&self.base.f.actor, self.base.launch.workspace_id)
            .await
            .map_err(api_failure)?;
        self.base
            .f
            .database
            .delete_workspace(
                &self.base.f.actor,
                ws.id,
                &DeleteWorkspace {
                    confirm_workspace_id: ws.id,
                },
                key,
                ws.spec_version,
            )
            .await
            .map_err(api_failure)
    }
    async fn claim(&self, op: Uuid) -> anyhow::Result<Claim> {
        let mut tx = self.base.f.owner_transaction().await?;
        sqlx::query("UPDATE operations SET lease_owner=CASE WHEN lease_until<=clock_timestamp() THEN NULL ELSE lease_owner END,lease_until=CASE WHEN lease_until<=clock_timestamp() THEN NULL ELSE lease_until END,next_attempt_at=(SELECT COALESCE(min(eligible_at),clock_timestamp())-interval '1 day' FROM operation_dispatch WHERE queue_role='VOLUME') WHERE tenant_id=$1 AND id=$2").bind(self.base.f.actor.tenant_id).bind(op).execute(&mut *tx).await?;
        tx.commit().await?;
        let claim = self
            .controller
            .engine
            .claim_volume_deletion()
            .await
            .map_err(api_failure)?
            .context("volume claim")?;
        ensure!(claim.operation_id == op, "claim own prioritized volume");
        Ok(claim)
    }
    async fn seed_cloud(&self, claim: &Claim) -> anyhow::Result<()> {
        let state = self
            .controller
            .engine
            .database
            .volume_delete_state(&self.controller.engine, claim)
            .await
            .map_err(api_failure)?;
        let observed = self
            .controller
            .runtime
            .observe(&state.target().map_err(api_failure)?)
            .await?;
        self.cloud.set_binding(&observed.binding);
        Ok(())
    }
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL, dedicated volume role, real loopback STS/ECS and mTLS"]
async fn authorized_disk_destruction_recovers_after_dispatch_and_releases_storage_once()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = Fixture::new().await?;
    let accepted = f.accept("delete-data").await?;
    let op = accepted.body.operation.id;
    let claim = f.claim(op).await?;
    f.seed_cloud(&claim).await?;
    f.controller.reconcile(&claim).await.map_err(api_failure)?;
    assert_eq!(f.cloud.count("DeleteDisk"), 1);
    assert!(f.kube.lock().expect("Kube").deleted.is_empty());
    assert_eq!(f.base.pending_dimension("WORKSPACE_GIB").await?, 40);
    // A later exact query proves physical disappearance; a DELETE response did not.
    f.cloud
        .set_disk_response(json!({"RequestId":"disk-absence-verified","Disks":{"Disk":[]}}));
    for _ in 0..3 {
        let claim = f.claim(op).await?;
        f.controller.reconcile(&claim).await.map_err(api_failure)?;
    }
    assert_eq!(f.cloud.count("DeleteDisk"), 1);
    assert_eq!(f.base.pending_dimension("WORKSPACE_GIB").await?, 0);
    assert_eq!(f.kube.lock().expect("Kube").deleted, vec!["PVC", "PV"]);
    let ws = f
        .base
        .f
        .database
        .get_workspace(&f.base.f.actor, f.base.launch.workspace_id)
        .await
        .map_err(api_failure)?;
    assert_eq!(ws.status, "DELETED");
    let replay = f
        .base
        .f
        .database
        .delete_workspace(
            &f.base.f.actor,
            ws.id,
            &DeleteWorkspace {
                confirm_workspace_id: ws.id,
            },
            "delete-data",
            1,
        )
        .await
        .map_err(api_failure)?;
    assert_eq!(replay.body.operation.id, op);
    assert_eq!(replay.body.resource.status, "DELETING");
    let mut tx = f.base.f.owner_transaction().await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM workspace_delete_results WHERE tenant_id=$1 AND operation_id=$2",
    )
    .bind(f.base.f.actor.tenant_id)
    .bind(op)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(count, 1);
    tx.commit().await?;
    f.base.guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL and loopback mTLS"]
async fn holds_retention_revocation_and_scope_block_data_deletion() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    for kind in ["LEGAL", "BACKUP", "RESTORE"] {
        let f = Fixture::new().await?;
        let ws = f.base.launch.workspace_id;
        let mut tx = f.base.f.owner_transaction().await?;
        let hold:Uuid=sqlx::query_scalar("INSERT INTO workspace_holds(tenant_id,project_id,workspace_id,kind,reference_id,source_generation,source_pvc_uid,reason) VALUES($1,$2,$3,$4,$5,1,$6,'test-only active hold') RETURNING id").bind(f.base.f.actor.tenant_id).bind(f.base.launch.project_id).bind(ws).bind(kind).bind(Uuid::new_v4()).bind(f.base.launch.pvc_uid).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        assert!(f.accept(kind).await.is_err());
        if kind == "BACKUP" {
            // An orphan hold represents unknown backup activity, never proof of
            // a completed backup. It must remain effective after release fails.
            let mut tx = f.base.f.owner_transaction().await?;
            let error = sqlx::query("INSERT INTO workspace_hold_releases(tenant_id,hold_id,reason) VALUES($1,$2,'test-only attempted orphan release')")
                .bind(f.base.f.actor.tenant_id)
                .bind(hold)
                .execute(&mut *tx)
                .await
                .expect_err("orphan BACKUP hold must reject release");
            let database_error = error
                .as_database_error()
                .context("database guard rejection")?;
            assert_eq!(database_error.code().as_deref(), Some("23514"));
            assert_eq!(
                database_error.message(),
                "unknown backup activity cannot release workspace hold"
            );
            tx.rollback().await?;
            let mut tx = f.base.f.owner_transaction().await?;
            let releases: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM workspace_hold_releases WHERE tenant_id=$1 AND hold_id=$2",
            )
            .bind(f.base.f.actor.tenant_id)
            .bind(hold)
            .fetch_one(&mut *tx)
            .await?;
            tx.commit().await?;
            assert_eq!(releases, 0);
            assert!(f.accept("backup-release-rejected").await.is_err());
        } else if kind == "LEGAL" {
            let mut tx = f.base.f.owner_transaction().await?;
            let inserted = sqlx::query("INSERT INTO workspace_hold_releases(tenant_id,hold_id,reason) VALUES($1,$2,'test-only legal hold release')")
                .bind(f.base.f.actor.tenant_id)
                .bind(hold)
                .execute(&mut *tx)
                .await?;
            assert_eq!(inserted.rows_affected(), 1);
            tx.commit().await?;
            let mut tx = f.base.f.owner_transaction().await?;
            let releases: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM workspace_hold_releases WHERE tenant_id=$1 AND hold_id=$2",
            )
            .bind(f.base.f.actor.tenant_id)
            .bind(hold)
            .fetch_one(&mut *tx)
            .await?;
            tx.commit().await?;
            assert_eq!(releases, 1);
            f.accept("legal-released").await?;
        }
        // RESTORE asserts only active hold protection, without claiming that
        // the draft restore workflow has established safe release evidence.
        f.base.guard.shutdown().await?;
    }
    let f = Fixture::new().await?;
    let ws = f.base.launch.workspace_id;
    let mut tx = f.base.f.owner_transaction().await?;
    sqlx::query("UPDATE workspaces SET retention_until=clock_timestamp()+interval '1 day' WHERE tenant_id=$1 AND id=$2").bind(f.base.f.actor.tenant_id).bind(ws).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(f.accept("retained").await.is_err());
    let mut tx = f.base.f.owner_transaction().await?;
    sqlx::query("UPDATE workspaces SET retention_until=NULL WHERE tenant_id=$1 AND id=$2")
        .bind(f.base.f.actor.tenant_id)
        .bind(ws)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let accepted = f.accept("allowed").await?;
    let mut tx = f.base.f.owner_transaction().await?;
    require_pg_error(sqlx::query("INSERT INTO workspace_holds(tenant_id,project_id,workspace_id,kind,reference_id,reason) VALUES($1,$2,$3,'LEGAL',$4,'too late')").bind(f.base.f.actor.tenant_id).bind(f.base.launch.project_id).bind(ws).bind(Uuid::new_v4()).execute(&mut *tx).await,"23514")?;
    tx.rollback().await?;
    let mut tx = f.base.f.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='workspaces:delete'").bind(f.base.f.actor.tenant_id).bind(f.base.f.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(
        f.base
            .f
            .database
            .delete_workspace(
                &f.base.f.actor,
                ws,
                &DeleteWorkspace {
                    confirm_workspace_id: ws
                },
                "allowed",
                1
            )
            .await
            .is_err()
    );
    let claim = f.claim(accepted.body.operation.id).await?;
    f.seed_cloud(&claim).await?;
    assert!(f.controller.reconcile(&claim).await.is_err());
    assert_eq!(f.cloud.count("DeleteDisk"), 0);
    assert_eq!(f.base.pending_dimension("WORKSPACE_GIB").await?, 40);
    f.base.guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL and local authenticated cloud protocol substitute"]
async fn physical_absence_without_dispatch_and_kube_uid_drift_never_release_storage()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    for absent in [false, true] {
        let f = Fixture::new().await?;
        let accepted = f.accept("proof-required").await?;
        let claim = f.claim(accepted.body.operation.id).await?;
        f.seed_cloud(&claim).await?;
        if absent {
            f.cloud
                .set_disk_response(json!({"RequestId":"missing-original","Disks":{"Disk":[]}}));
        } else {
            f.kube.lock().expect("Kube").pvc["metadata"]["uid"] = json!(Uuid::new_v4());
        }
        assert!(f.controller.reconcile(&claim).await.is_err());
        assert_eq!(f.cloud.count("DeleteDisk"), 0);
        assert_eq!(f.base.pending_dimension("WORKSPACE_GIB").await?, 40);
        assert!(f.kube.lock().expect("Kube").deleted.is_empty());
        let mut tx = f.base.f.owner_transaction().await?;
        let absence: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workspace_disk_absences WHERE tenant_id=$1 AND operation_id=$2",
        )
        .bind(f.base.f.actor.tenant_id)
        .bind(claim.operation_id)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(absence, 0);
        tx.commit().await?;
        f.base.guard.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL and local authenticated cloud protocol substitute"]
async fn original_disk_may_retry_only_after_fresh_identity_and_denied_delete_requires_operator()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    for denied in [false, true] {
        let f = Fixture::new().await?;
        let accepted = f.accept("bounded-retry").await?;
        let op = accepted.body.operation.id;
        let claim = f.claim(op).await?;
        f.seed_cloud(&claim).await?;
        if denied {
            f.cloud.set_delete_mode(3);
        } else {
            f.cloud.set_delete_mode(1);
        }
        f.controller.reconcile(&claim).await.map_err(api_failure)?;
        assert_eq!(f.cloud.count("DeleteDisk"), 1);
        if denied {
            let mut tx = f.base.f.owner_transaction().await?;
            let result:(String,bool,String)=sqlx::query_as("SELECT o.stage,o.next_attempt_at='infinity',r.evidence->>'code' FROM operations o JOIN workspace_delete_results r ON r.tenant_id=o.tenant_id AND r.operation_id=o.id WHERE o.tenant_id=$1 AND o.id=$2").bind(f.base.f.actor.tenant_id).bind(op).fetch_one(&mut *tx).await?;
            assert_eq!(
                result,
                (
                    "WAITING_OPERATOR_REVIEW".into(),
                    true,
                    "ACCESS_DENIED".into()
                )
            );
            tx.commit().await?;
            let operator = Uuid::new_v4();
            let mut tx = f.base.f.owner_transaction().await?;
            sqlx::query("INSERT INTO principals(id,kind,display_name) VALUES($1,'USER','test-only reviewed recovery operator')").bind(operator).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,'workspaces:delete')").bind(f.base.f.actor.tenant_id).bind(f.base.launch.project_id).bind(operator).execute(&mut *tx).await?;
            let digest:String=sqlx::query_scalar("SELECT encode(sha256(convert_to(cloud_identity::text,'UTF8')),'hex') FROM workspace_delete_bindings WHERE tenant_id=$1 AND operation_id=$2").bind(f.base.f.actor.tenant_id).bind(op).fetch_one(&mut *tx).await?;
            tx.commit().await?;
            let script = |hash: &str| {
                include_str!("../scripts/sql/resume-workspace-deletion.sql")
                    .lines()
                    .filter(|line| !line.starts_with('\\'))
                    .collect::<Vec<_>>()
                    .join("\n")
                    .replace(":'tenant_id'", &format!("'{}'", f.base.f.actor.tenant_id))
                    .replace(":'operation_id'", &format!("'{op}'"))
                    .replace(":'operator_id'", &format!("'{operator}'"))
                    .replace(":'binding_sha256'", &format!("'{hash}'"))
                    .replace(":'incident_reference'", "'test-only reviewed incident'")
            };
            let mut connection = f.base.f.owner.acquire().await?;
            require_pg_error(
                sqlx::raw_sql(&script(&"0".repeat(64)))
                    .execute(&mut *connection)
                    .await,
                "P0001",
            )?;
            sqlx::query("ROLLBACK").execute(&mut *connection).await?;
            sqlx::raw_sql(&script(&digest))
                .execute(&mut *connection)
                .await?;
            let mut tx = f.base.f.owner_transaction().await?;
            let resumed:bool=sqlx::query_scalar("SELECT stage='RESUMING_AFTER_OPERATOR_REVIEW' AND next_attempt_at<=clock_timestamp() FROM operations WHERE tenant_id=$1 AND id=$2").bind(f.base.f.actor.tenant_id).bind(op).fetch_one(&mut *tx).await?;
            assert!(resumed);
            tx.commit().await?;
        } else {
            let claim = f.claim(op).await?;
            f.controller.reconcile(&claim).await.map_err(api_failure)?;
            assert_eq!(f.cloud.count("DeleteDisk"), 2);
            let mut tx = f.base.f.owner_transaction().await?;
            let attempts:i64=sqlx::query_scalar("SELECT count(*) FROM workspace_delete_attempts WHERE tenant_id=$1 AND operation_id=$2").bind(f.base.f.actor.tenant_id).bind(op).fetch_one(&mut *tx).await?;
            assert_eq!(attempts, 2);
            tx.commit().await?;
        }
        assert_eq!(f.base.pending_dimension("WORKSPACE_GIB").await?, 40);
        assert!(f.kube.lock().expect("Kube").deleted.is_empty());
        f.base.guard.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL and local authenticated cloud protocol substitute"]
async fn committed_dispatch_without_result_recovers_by_query_and_unprivileged_receipts_are_rejected()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = Fixture::new().await?;
    let accepted = f.accept("crash-before-response").await?;
    let op = accepted.body.operation.id;
    let claim = f.claim(op).await?;
    f.seed_cloud(&claim).await?;
    let db = &f.controller.engine.database;
    let state = db
        .volume_delete_state(&f.controller.engine, &claim)
        .await
        .map_err(api_failure)?;
    let kube = f
        .controller
        .runtime
        .observe(&state.target().map_err(api_failure)?)
        .await?;
    let CloudDiskLookup::Present(cloud) = f.cloud.client.observe_disk(&kube.binding).await? else {
        anyhow::bail!("present fixture disk");
    };
    db.bind_workspace_disk(&f.controller.engine, &claim, &kube, &cloud)
        .await
        .map_err(api_failure)?;
    db.begin_workspace_disk_delete(&f.controller.engine, &claim, &cloud)
        .await
        .map_err(api_failure)?;
    // A lost response/process has no outcome row. Only a later signed query can
    // prove absence; this does not invent the unobserved DeleteDisk response.
    f.cloud
        .set_disk_response(json!({"RequestId":"post-crash-read","Disks":{"Disk":[]}}));
    f.controller.reconcile(&claim).await.map_err(api_failure)?;
    assert_eq!(f.cloud.count("DeleteDisk"), 0);
    for _ in 0..2 {
        let claim = f.claim(op).await?;
        f.controller.reconcile(&claim).await.map_err(api_failure)?;
    }
    assert_eq!(f.base.pending_dimension("WORKSPACE_GIB").await?, 0);
    let mut tx = f
        .base
        .f
        .database
        .begin(f.base.f.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    require_pg_error(
        sqlx::query("INSERT INTO workspace_disk_absences DEFAULT VALUES")
            .execute(&mut *tx)
            .await,
        "42501",
    )?;
    tx.rollback().await?;
    let mut tx = db
        .begin(f.base.f.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    require_pg_error(sqlx::query("UPDATE workspace_delete_attempts SET dispatched_at=clock_timestamp() WHERE tenant_id=$1 AND operation_id=$2").bind(f.base.f.actor.tenant_id).bind(op).execute(&mut *tx).await,"42501")?;
    tx.rollback().await?;
    let mut tx = f.base.f.owner_transaction().await?;
    require_pg_error(sqlx::query("UPDATE workspace_delete_attempts SET dispatched_at=clock_timestamp() WHERE tenant_id=$1 AND operation_id=$2").bind(f.base.f.actor.tenant_id).bind(op).execute(&mut *tx).await,"23514")?;
    tx.rollback().await?;
    f.base.guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL, dedicated admission role and local cloud protocol substitute"]
async fn storage_admission_requires_cloud_absence_exact_service_account_and_uid_binding()
-> anyhow::Result<()> {
    use crate::admission::{AdmissionConfig, AdmissionRequest, AdmissionService};
    let _serial = test_support_db::serial().await;
    let f = Fixture::new().await?;
    sqlx::raw_sql(include_str!("../scripts/sql/admission-role.sql"))
        .execute(&f.base.f.owner)
        .await?;
    let mut config: Value =
        serde_json::from_str(include_str!("../deploy/admission/config.example.json"))?;
    for value in config
        .as_object_mut()
        .context("config object")?
        .values_mut()
    {
        if let Some(values) = value.as_array_mut() {
            for v in values {
                if v.get("uid").is_some() {
                    v["uid"] = json!(Uuid::new_v4());
                }
            }
        } else if value.get("uid").is_some() {
            value["uid"] = json!(Uuid::new_v4());
        }
    }
    config["certification_id"] = json!("test-only-volume-evidence");
    let config: AdmissionConfig = serde_json::from_value(config)?;
    config.validate()?;
    let volume = config.volume_deleter.as_ref().context("volume identity")?;
    let user =
        json!({"username":volume.username,"uid":volume.uid,"groups":["system:authenticated"]});
    let worker = json!({"username":config.worker.username,"uid":config.worker.uid,"groups":["system:authenticated"]});
    let (pvc, pv) = {
        let s = f.kube.lock().expect("Kube");
        (s.pvc.clone(), s.pv.clone())
    };
    let build = |object: Value, pv: bool, who: Value| -> anyhow::Result<AdmissionRequest> {
        Ok(serde_json::from_value(
            json!({"uid":Uuid::new_v4(),"operation":"DELETE","resource":{"group":"","version":"v1","resource":if pv{"persistentvolumes"}else{"persistentvolumeclaims"}},"kind":{"group":"","version":"v1","kind":if pv{"PersistentVolume"}else{"PersistentVolumeClaim"}},"name":object["metadata"]["name"],"namespace":if pv{""}else{&f.base.launch.namespace},"userInfo":who,"oldObject":object,"object":null,"dryRun":false}),
        )?)
    };
    let service = AdmissionService {
        database: Database::connect(&std::env::var("TEST_ADMISSION_DATABASE_URL")?, 3).await?,
        kubernetes: f.client.clone(),
        config,
    };
    let accepted = f.accept("admission-cloud-proof").await?;
    let op = accepted.body.operation.id;
    let claim = f.claim(op).await?;
    f.seed_cloud(&claim).await?;
    f.controller.reconcile(&claim).await.map_err(api_failure)?;
    assert!(
        service
            .decide(&build(pvc.clone(), false, user.clone())?)
            .await
            .is_err()
    );
    assert!(
        service
            .decide(&build(pv.clone(), true, user.clone())?)
            .await
            .is_err()
    );
    f.cloud
        .set_disk_response(json!({"RequestId":"admission-absence","Disks":{"Disk":[]}}));
    let claim = f.claim(op).await?;
    f.controller.reconcile(&claim).await.map_err(api_failure)?;
    let _active = f.claim(op).await?;
    assert!(
        service
            .decide(&build(pvc.clone(), false, user.clone())?)
            .await
            .is_ok()
    );
    assert!(
        service
            .decide(&build(pv.clone(), true, user.clone())?)
            .await
            .is_ok()
    );
    assert!(
        service
            .decide(&build(pv.clone(), true, worker)?)
            .await
            .is_err()
    );
    let mut wrong_uid = pv.clone();
    wrong_uid["metadata"]["uid"] = json!(Uuid::new_v4());
    assert!(
        service
            .decide(&build(wrong_uid, true, user.clone())?)
            .await
            .is_err()
    );
    let mut wrong_disk = pv.clone();
    wrong_disk["spec"]["csi"]["volumeHandle"] = json!("d-otherdisk");
    assert!(
        service
            .decide(&build(wrong_disk, true, user.clone())?)
            .await
            .is_err()
    );
    let mut deleting = pv.clone();
    deleting["spec"]["persistentVolumeReclaimPolicy"] = json!("Delete");
    assert!(service.decide(&build(deleting, true, user)?).await.is_err());
    assert_eq!(f.base.pending_dimension("WORKSPACE_GIB").await?, 40);
    f.base.guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires PostgreSQL and a real event-stream-head lock wait"]
async fn quota_completion_cannot_outlive_claim_while_waiting_for_event_head() -> anyhow::Result<()>
{
    let _serial = test_support_db::serial().await;
    let f = Fixture::new().await?;
    let op = f.accept("completion-lease").await?.body.operation.id;
    let claim = f.claim(op).await?;
    f.seed_cloud(&claim).await?;
    f.controller.reconcile(&claim).await.map_err(api_failure)?;
    f.cloud
        .set_disk_response(json!({"RequestId":"destroyed","Disks":{"Disk":[]}}));
    for _ in 0..2 {
        let claim = f.claim(op).await?;
        f.controller.reconcile(&claim).await.map_err(api_failure)?;
    }
    let claim = f.claim(op).await?;
    let mut tx = f.base.f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET lease_until=clock_timestamp()+interval '1 second' WHERE tenant_id=$1 AND id=$2")
        .bind(claim.tenant_id).bind(op).execute(&mut *tx).await?;
    tx.commit().await?;
    let mut blocker = f.base.f.owner_transaction().await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    sqlx::query(
        "SELECT project_id FROM event_stream_heads WHERE tenant_id=$1 AND project_id=$2 FOR UPDATE",
    )
    .bind(claim.tenant_id)
    .bind(f.base.launch.project_id)
    .execute(&mut *blocker)
    .await?;
    let controller = f.controller.clone();
    let pending = tokio::spawn(async move { controller.reconcile(&claim).await });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
            )
            .bind(pid)
            .fetch_one(&f.base.f.owner)
            .await?;
            if waiting {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok::<(), sqlx::Error>(())
    })
    .await??;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    blocker.commit().await?;
    assert!(matches!(pending.await?, Err(e) if e.code=="WORKER_LEASE_LOST"));
    assert_eq!(f.base.pending_dimension("WORKSPACE_GIB").await?, 40);
    let claim = f.claim(op).await?;
    f.controller.reconcile(&claim).await.map_err(api_failure)?;
    assert_eq!(f.base.pending_dimension("WORKSPACE_GIB").await?, 0);
    assert_eq!(f.cloud.count("DeleteDisk"), 1);
    f.base.guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires PostgreSQL and loopback JWKS; tests the actual workspace HTTP contract"]
async fn workspace_http_requires_scope_confirmation_etag_and_idempotency() -> anyhow::Result<()> {
    use axum::{Router, http::StatusCode, routing::get};
    use http_body_util::BodyExt;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use tower::ServiceExt;
    let _serial = test_support_db::serial().await;
    let f = Fixture::new().await?;
    let jwk: Value = serde_json::from_str(include_str!("../tests/fixtures/auth/jwk-a.json"))?;
    let kid = jwk["kid"].as_str().context("kid")?.to_owned();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/jwks",
                get(move || {
                    let jwk = jwk.clone();
                    async move { axum::Json(json!({"keys":[jwk]})) }
                }),
            ),
        )
        .await
    });
    f.base.f.bind_client_id("workspace-test").await?;
    let auth = crate::auth::JwtAuthenticator::new(crate::auth::AuthConfig {
        scope_profile: Default::default(),
        issuer: "https://issuer.example.test".into(),
        audience: "sandbox-api".into(),
        jwks_url: format!("http://{address}/jwks"),
        required_scopes: vec!["sandbox:access".into()],
        jwks_ttl_seconds: 300,
        clock_skew_seconds: 0,
        allow_loopback_http: true,
        max_token_lifetime_seconds: 300,
    })?;
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("at+jwt".into());
    header.kid = Some(kid);
    let now = Utc::now().timestamp();
    let token = encode(
        &header,
        &json!({"iss":"https://issuer.example.test","sub":f.base.f.actor.principal_id.to_string(),"aud":"sandbox-api","client_id":"workspace-test","jti":Uuid::new_v4().to_string(),"iat":now,"exp":now+300,"scope":"sandbox:access"}),
        &EncodingKey::from_rsa_der(include_bytes!("../tests/fixtures/auth/rsa-a.der")),
    )?;
    let app = crate::api::router(Arc::new(crate::api::AppState {
        database: f.base.f.database.clone(),
        auth,
        cursor_signer: crate::history::CursorSigner::from_json(include_str!(
            "../tests/fixtures/history/cursor-keys.json"
        ))?,
        output_reader: None,
        metrics: None,
        default_ttl_seconds: 300,
        max_ttl_seconds: 86400,
    }));
    let ws = f.base.launch.workspace_id;
    let request = |method: &str,
                   id: Uuid,
                   confirmation: Uuid,
                   etag: Option<&str>,
                   tenant: Uuid|
     -> anyhow::Result<Request<Body>> {
        let mut r = Request::builder()
            .method(method)
            .uri(format!("/v1/workspaces/{id}"))
            .header("authorization", format!("Bearer {token}"))
            .header("x-tenant-id", tenant.to_string())
            .header("content-type", "application/json")
            .header("idempotency-key", "http-workspace-delete");
        if let Some(v) = etag {
            r = r.header("if-match", v);
        }
        Ok(r.body(if method == "DELETE" {
            Body::from(json!({"confirm_workspace_id":confirmation}).to_string())
        } else {
            Body::empty()
        })?)
    };
    let response = app
        .clone()
        .oneshot(request("GET", ws, ws, None, f.base.f.actor.tenant_id)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let etag = response
        .headers()
        .get("etag")
        .context("workspace etag")?
        .to_str()?
        .to_owned();
    assert_eq!(
        app.clone()
            .oneshot(request("DELETE", ws, ws, None, f.base.f.actor.tenant_id)?)
            .await?
            .status(),
        StatusCode::PRECONDITION_REQUIRED
    );
    assert_eq!(
        app.clone()
            .oneshot(request(
                "DELETE",
                ws,
                Uuid::new_v4(),
                Some(&etag),
                f.base.f.actor.tenant_id
            )?)
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    for id in [ws, Uuid::new_v4()] {
        assert_eq!(
            app.clone()
                .oneshot(request("GET", id, id, None, Uuid::new_v4())?)
                .await?
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    let response = app
        .clone()
        .oneshot(request(
            "DELETE",
            ws,
            ws,
            Some(&etag),
            f.base.f.actor.tenant_id,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(
        response
            .headers()
            .get("location")
            .context("operation location")?
            .to_str()?
            .starts_with("/v1/operations/")
    );
    assert!(response.headers().contains_key("etag"));
    let original = response.into_body().collect().await?.to_bytes();
    let replay = app
        .clone()
        .oneshot(request(
            "DELETE",
            ws,
            ws,
            Some(&etag),
            f.base.f.actor.tenant_id,
        )?)
        .await?;
    assert_eq!(replay.status(), StatusCode::ACCEPTED);
    assert_eq!(original, replay.into_body().collect().await?.to_bytes());
    let mut tx = f.base.f.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action IN('workspaces:read','workspaces:delete')").bind(f.base.f.actor.tenant_id).bind(f.base.f.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    assert_eq!(
        app.oneshot(request(
            "DELETE",
            ws,
            ws,
            Some(&etag),
            f.base.f.actor.tenant_id
        )?)
        .await?
        .status(),
        StatusCode::NOT_FOUND
    );
    server.abort();
    f.base.guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires PostgreSQL and signed loopback ECS preservation/read-back"]
async fn default_auto_snapshot_policy_is_preserved_and_ack_without_readback_never_deletes()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    for ack_only in [false, true] {
        let f = Fixture::new().await?;
        let op = f.accept("preserve-snapshots").await?.body.operation.id;
        let claim = f.claim(op).await?;
        f.seed_cloud(&claim).await?;
        f.cloud.set_delete_auto_snapshot(true);
        if ack_only {
            f.cloud.set_preserve_mode(9);
        }
        f.controller.reconcile(&claim).await.map_err(api_failure)?;
        assert_eq!(f.cloud.count("ModifyDiskAttribute"), 1);
        assert_eq!(f.cloud.count("DeleteDisk"), 0);
        assert_eq!(f.base.pending_dimension("WORKSPACE_GIB").await?, 40);
        let claim = f.claim(op).await?;
        f.controller.reconcile(&claim).await.map_err(api_failure)?;
        assert_eq!(f.cloud.count("DeleteDisk"), if ack_only { 0 } else { 1 });
        assert_eq!(
            f.cloud.count("ModifyDiskAttribute"),
            if ack_only { 2 } else { 1 }
        );
        let mut tx = f.base.f.owner_transaction().await?;
        let (attempts,results):(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM workspace_snapshot_preserve_attempts WHERE tenant_id=$1 AND operation_id=$2),(SELECT count(*) FROM workspace_snapshot_preserve_results WHERE tenant_id=$1 AND operation_id=$2)")
            .bind(f.base.f.actor.tenant_id).bind(op).fetch_one(&mut *tx).await?;
        assert_eq!(attempts, if ack_only { 2 } else { 1 });
        assert_eq!(attempts, results);
        tx.commit().await?;
        f.base.guard.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires PostgreSQL and loopback ECS; preservation is never deletion evidence"]
async fn preservation_unknown_or_absence_never_creates_destruction_receipt() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = Fixture::new().await?;
    let op = f.accept("unknown-preservation").await?.body.operation.id;
    let claim = f.claim(op).await?;
    f.seed_cloud(&claim).await?;
    f.cloud.set_delete_auto_snapshot(true);
    f.cloud.set_preserve_mode(1);
    f.controller.reconcile(&claim).await.map_err(api_failure)?;
    assert_eq!(f.cloud.count("ModifyDiskAttribute"), 1);
    assert_eq!(f.cloud.count("DeleteDisk"), 0);
    let mut tx = f.base.f.owner_transaction().await?;
    let outcome:String=sqlx::query_scalar("SELECT outcome FROM workspace_snapshot_preserve_results WHERE tenant_id=$1 AND operation_id=$2")
        .bind(f.base.f.actor.tenant_id).bind(op).fetch_one(&mut *tx).await?;
    assert_eq!(outcome, "OUTCOME_UNKNOWN");
    tx.commit().await?;
    // A preservation call is not permission to erase a disk. Unexplained absence
    // must never get a receipt by borrowing its different-kind attempt UUID.
    f.cloud
        .set_disk_response(json!({"RequestId":"unexplained-absence","Disks":{"Disk":[]}}));
    let claim = f.claim(op).await?;
    assert!(
        matches!(f.controller.reconcile(&claim).await,Err(e) if e.code=="DISK_ABSENT_WITHOUT_DELETE_INTENT")
    );
    let mut tx = f.base.f.owner_transaction().await?;
    let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM workspace_delete_attempts WHERE tenant_id=$1 AND operation_id=$2),(SELECT count(*) FROM workspace_disk_absences WHERE tenant_id=$1 AND operation_id=$2)")
        .bind(f.base.f.actor.tenant_id).bind(op).fetch_one(&mut *tx).await?;
    assert_eq!(counts, (0, 0));
    tx.commit().await?;
    assert_eq!(f.base.pending_dimension("WORKSPACE_GIB").await?, 40);
    assert!(f.kube.lock().expect("Kube").deleted.is_empty());
    f.base.guard.shutdown().await?;
    Ok(())
}
