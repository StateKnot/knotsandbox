//! Real PG and signed loopback STS/ECS deletion. Kubernetes objects below are
//! stateful protocol fixtures, not evidence of real cloud/CSI/Kata certification.
use crate::{
    db::Database,
    domain::InstanceAction,
    engine::{Claim, OperationEngine},
    model::StartRequest,
    runtime::KubernetesRuntime,
    termination_ledger::tests::FixtureRuntime,
    test_support_db::api_failure,
    volume_deletion::VolumeDeletionController,
    volume_deletion_runtime::{VolumeDeletionRuntime, VolumeTarget, WorkspaceStorageProfile},
    workspaces::DeleteWorkspace,
};
use anyhow::{Context, ensure};
use axum::{
    body::Body,
    http::{Method, Request, Response},
};
use kube::{Client, client::Body as KubeBody};
use serde_json::{Value, json};
use sqlx::Row;
use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

pub(super) struct DeleteCase<'a> {
    pub base: &'a FixtureRuntime,
    pub instance: Uuid,
    pub workspace: Uuid,
    pub restore: Uuid,
    pub objects: &'a Arc<Mutex<BTreeMap<String, Value>>>,
}
struct Objects {
    pvc: Value,
    pv: Value,
    deleted: Vec<String>,
}

fn kube_client(objects: Arc<Mutex<Objects>>, namespace: Value, class: Value) -> Client {
    let service = tower::service_fn(move |request: Request<KubeBody>| {
        let objects = objects.clone();
        let namespace = namespace.clone();
        let class = class.clone();
        async move {
            let path = request.uri().path().to_owned();
            let method = request.method().clone();
            let body = axum::body::to_bytes(Body::new(request.into_body()), 131072)
                .await
                .unwrap_or_default();
            let payload: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let (status, response) = if let Ok(mut state) = objects.lock() {
                if path.contains("/storageclasses/") {
                    (200, class)
                } else if path.ends_with("/volumeattachments") {
                    (
                        200,
                        json!({"apiVersion":"storage.k8s.io/v1","kind":"VolumeAttachmentList","metadata":{},"items":[]}),
                    )
                } else if path.ends_with("/pods") {
                    (
                        200,
                        json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":[]}),
                    )
                } else if path.contains("/persistentvolumeclaims/")
                    || path.contains("/persistentvolumes/")
                {
                    let pvc = path.contains("/persistentvolumeclaims/");
                    let current = if pvc { &state.pvc } else { &state.pv };
                    if current.is_null() {
                        (
                            404,
                            json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}),
                        )
                    } else if method == Method::DELETE {
                        if payload.pointer("/preconditions/uid") != current.pointer("/metadata/uid")
                            || payload.pointer("/preconditions/resourceVersion")
                                != current.pointer("/metadata/resourceVersion")
                        {
                            (
                                409,
                                json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Conflict","code":409}),
                            )
                        } else {
                            state.deleted.push(if pvc { "PVC" } else { "PV" }.into());
                            if pvc {
                                state.pvc = Value::Null;
                            } else {
                                state.pv = Value::Null;
                            }
                            (
                                200,
                                json!({"apiVersion":"v1","kind":"Status","status":"Success"}),
                            )
                        }
                    } else {
                        (200, current.clone())
                    }
                } else {
                    (200, namespace)
                }
            } else {
                (
                    500,
                    json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"InternalError","code":500}),
                )
            };
            Ok::<_, Infallible>(
                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(Body::from(response.to_string()))
                    .unwrap_or_default(),
            )
        }
    });
    Client::new(service, "default")
}
async fn volume_claim(
    engine: &OperationEngine,
    case: &DeleteCase<'_>,
    operation: Uuid,
) -> anyhow::Result<Claim> {
    let mut tx = case.base.f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET next_attempt_at=(SELECT COALESCE(min(eligible_at),clock_timestamp())-interval '1 day' FROM operation_dispatch WHERE queue_role='VOLUME') WHERE tenant_id=$1 AND id=$2")
        .bind(case.base.f.actor.tenant_id).bind(operation).execute(&mut *tx).await?;
    tx.commit().await?;
    let claim = engine
        .claim_volume_deletion()
        .await
        .map_err(api_failure)?
        .context("restored volume deletion claim")?;
    ensure!(
        claim.operation_id == operation,
        "must claim exact restored workspace deletion"
    );
    Ok(claim)
}
pub(super) async fn run(case: DeleteCase<'_>) -> anyhow::Result<()> {
    let f = &case.base.f;
    let mut tx = f.owner_transaction().await?;
    let r=sqlx::query("SELECT i.project_id,w.namespace,w.storage_class,w.size_gib,r.cluster_epoch,d.pvc_uid,d.pv_uid,d.pv_name,d.cloud_disk,r.source_identity->>'account_id' AS account_id,r.source_identity->>'region' AS region FROM restores r JOIN instances i ON i.tenant_id=r.tenant_id AND i.id=r.instance_id JOIN workspaces w ON w.tenant_id=r.tenant_id AND w.id=r.workspace_id JOIN restore_delivery_receipts d ON d.tenant_id=r.tenant_id AND d.restore_id=r.id WHERE r.tenant_id=$1 AND r.id=$2")
        .bind(f.actor.tenant_id).bind(case.restore).fetch_one(&mut *tx).await?;
    let target = VolumeTarget {
        tenant_id: f.actor.tenant_id,
        project_id: r.try_get("project_id")?,
        workspace_id: case.workspace,
        cluster_epoch: r.try_get("cluster_epoch")?,
        namespace: r.try_get("namespace")?,
        pvc_name: format!("ws-{}", case.workspace),
        storage_class: r.try_get("storage_class")?,
        size_gib: r.try_get::<i64, _>("size_gib")?.try_into()?,
        pvc_uid: r.try_get("pvc_uid")?,
        pv_uid: r.try_get("pv_uid")?,
        pv_name: r.try_get("pv_name")?,
        handle: r.try_get("cloud_disk")?,
        account_id: r.try_get("account_id")?,
        region: r.try_get("region")?,
    };
    for action in [
        "instances:delete",
        "instances:hard_stop",
        "instances:read",
        "operations:read",
        "workspaces:read",
        "workspaces:delete",
    ] {
        for project in [None, Some(target.project_id)] {
            sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
                .bind(f.actor.tenant_id).bind(project).bind(f.actor.principal_id).bind(action).execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    let instance = f
        .database
        .get_instance(&f.actor, case.instance)
        .await
        .map_err(api_failure)
        .context("read restored instance before never-started DELETE")?;
    let (first, replay) = tokio::join!(
        f.database.lifecycle_action(
            &f.actor,
            case.instance,
            InstanceAction::Delete,
            &StartRequest { ttl_seconds: None },
            "restore-never-started-delete",
            instance.spec_version,
            300,
            86400
        ),
        f.database.lifecycle_action(
            &f.actor,
            case.instance,
            InstanceAction::Delete,
            &StartRequest { ttl_seconds: None },
            "restore-never-started-delete",
            instance.spec_version,
            300,
            86400
        )
    );
    let accepted = first
        .map_err(api_failure)
        .context("accept restored never-started DELETE")?;
    assert_eq!(
        accepted.body.operation.id,
        replay.map_err(api_failure)?.body.operation.id
    );
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET next_attempt_at=(SELECT COALESCE(min(eligible_at),clock_timestamp())-interval '1 day' FROM operation_dispatch WHERE queue_role='TERMINATION') WHERE tenant_id=$1 AND id=$2")
        .bind(f.actor.tenant_id).bind(accepted.body.operation.id).execute(&mut *tx).await?;
    tx.commit().await?;
    let claim = case
        .base
        .engine
        .claim_termination()
        .await
        .map_err(api_failure)?
        .context("never-started DELETE claim")?;
    ensure!(
        claim.operation_id == accepted.body.operation.id,
        "claim restored instance DELETE"
    );
    let (a, b) = tokio::join!(
        case.base
            .engine
            .database
            .complete_never_authorized_deletion(&case.base.engine, &claim),
        case.base
            .engine
            .database
            .complete_never_authorized_deletion(&case.base.engine, &claim)
    );
    ensure!(
        [&a, &b].iter().filter(|r| matches!(r, Ok(true))).count() == 1,
        "exactly one concurrent compute completion"
    );
    let mut tx = f.owner_transaction().await?;
    let compute:(String,Option<Uuid>,i64,i64,i64)=sqlx::query_as("SELECT i.observed_state,i.last_termination_proof_id,(SELECT count(*) FROM launch_permits p WHERE p.tenant_id=i.tenant_id AND p.instance_id=i.id),(SELECT count(*) FROM quota_reservations q JOIN quota_accounts a ON a.tenant_id=q.tenant_id AND a.id=q.quota_account_id WHERE q.tenant_id=i.tenant_id AND q.resource_id=i.id AND q.status='RELEASED' AND a.dimension IN('CPU_MILLIS','MEMORY_MIB')),(SELECT count(*) FROM domain_events e WHERE e.tenant_id=i.tenant_id AND e.aggregate_id=i.id AND e.event_type='instance.deleted') FROM instances i WHERE i.tenant_id=$1 AND i.id=$2")
        .bind(f.actor.tenant_id).bind(case.instance).fetch_one(&mut *tx).await?;
    ensure!(
        compute == ("DELETED".into(), None, 0, 4, 1),
        "no ordinary writer proof invented; CPU/memory release remains exactly four original reservations"
    );
    tx.commit().await?;
    for script in [
        include_str!("../scripts/sql/volume-deleter-role.sql"),
        include_str!("../scripts/sql/restore-role.sql"),
    ] {
        sqlx::raw_sql(script).execute(&f.owner).await?;
    }
    let database =
        Database::connect(&std::env::var("TEST_VOLUME_DELETER_DATABASE_URL")?, 4).await?;
    assert!(
        database.verify_runtime_role().await.is_err(),
        "draft is not production migration"
    );
    let engine = OperationEngine::new(database, format!("restore-volume-{}", Uuid::new_v4()))?;
    let cloud = crate::cloud_fencing::volume_deletion::tests::Fixture::new().await?;
    let (pvc, mut pv, kms_key_id) = {
        let o = case
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture poisoned"))?;
        (
            o.get(&format!(
                "/api/v1/namespaces/{}/persistentvolumeclaims/{}",
                target.namespace, target.pvc_name
            ))
            .cloned()
            .context("delivered PVC")?,
            o.get(&format!("/api/v1/persistentvolumes/{}", target.pv_name))
                .cloned()
                .context("delivered PV")?,
            o.get(&format!(
                "/apis/storage.k8s.io/v1/storageclasses/{}",
                target.storage_class
            ))
            .and_then(|v| v.pointer("/parameters/kmsKeyId"))
            .and_then(Value::as_str)
            .context("reviewed target storage KMS")?
            .to_owned(),
        )
    };
    // Explicit CSI fixture adds reviewed zone affinity after the actual restore
    // delivered immutable PVC/PV identities; these are not cloud attestations.
    pv["metadata"]["resourceVersion"] = json!("20");
    pv["spec"]["nodeAffinity"] = json!({"required":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"topology.diskplugin.csi.alibabacloud.com/zone","operator":"In","values":["cn-hangzhou-h"]}]}]}});
    let profile = WorkspaceStorageProfile {
        storage_class: target.storage_class.clone(),
        kms_key_id,
        zones: vec!["cn-hangzhou-h".into()],
        deployment: "production-a".into(),
        certification_id: "fixture-target".into(),
    };
    let objects = Arc::new(Mutex::new(Objects {
        pvc,
        pv,
        deleted: vec![],
    }));
    let namespace = json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":target.namespace,"labels":{"sandbox.platform/managed":"true","sandbox.platform/tenant-id":target.tenant_id,"sandbox.platform/project-id":target.project_id,"sandbox.platform/cluster-epoch":target.cluster_epoch},"annotations":{"sandbox.platform/certification-id":profile.certification_id}}});
    let class = json!({"apiVersion":"storage.k8s.io/v1","kind":"StorageClass","metadata":{"name":target.storage_class},"provisioner":"diskplugin.csi.alibabacloud.com","reclaimPolicy":"Retain","parameters":{"encrypted":"true","kmsKeyId":profile.kms_key_id,"diskTags/Deployment":profile.deployment}});
    let runtime = VolumeDeletionRuntime::new(
        KubernetesRuntime::from_client(kube_client(objects.clone(), namespace, class)),
        profile,
    )?;
    let binding = runtime.observe(&target).await?.binding;
    cloud.set_binding(&binding);
    let controller = VolumeDeletionController::new(engine, runtime, cloud.client.clone(), 1)?;
    let workspace = f
        .database
        .get_workspace(&f.actor, case.workspace)
        .await
        .map_err(api_failure)?;
    let request = DeleteWorkspace {
        confirm_workspace_id: case.workspace,
    };
    let (a, b) = tokio::join!(
        f.database.delete_workspace(
            &f.actor,
            case.workspace,
            &request,
            "restore-never-started-storage",
            workspace.spec_version
        ),
        f.database.delete_workspace(
            &f.actor,
            case.workspace,
            &request,
            "restore-never-started-storage",
            workspace.spec_version
        )
    );
    let accepted = a.map_err(api_failure)?;
    assert_eq!(
        accepted.body.operation.id,
        b.map_err(api_failure)?.body.operation.id
    );
    let operation = accepted.body.operation.id;
    let claim = volume_claim(&controller.engine, &case, operation).await?;
    // Identical names with changed UIDs or disk never cause cloud mutation.
    for (pvc, pointer, value) in [
        (true, "/metadata/uid", json!(Uuid::new_v4())),
        (false, "/metadata/uid", json!(Uuid::new_v4())),
        (false, "/spec/csi/volumeHandle", json!("d-replacedTarget01")),
    ] {
        let original = {
            let mut s = objects
                .lock()
                .map_err(|_| anyhow::anyhow!("fixture poisoned"))?;
            let v = if pvc { &mut s.pvc } else { &mut s.pv };
            let original = v.clone();
            *v.pointer_mut(pointer).context("replacement path")? = value;
            original
        };
        assert!(controller.reconcile(&claim).await.is_err());
        assert_eq!(cloud.count("DeleteDisk"), 0);
        let mut s = objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture poisoned"))?;
        if pvc {
            s.pvc = original;
        } else {
            s.pv = original;
        }
    }
    controller.reconcile(&claim).await.map_err(api_failure)?;
    assert_eq!(cloud.count("DeleteDisk"), 1);
    assert!(
        objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture poisoned"))?
            .deleted
            .is_empty()
    );
    cloud.set_disk_response(json!({"RequestId":"restore-target-absent","Disks":{"Disk":[]}}));
    for _ in 0..3 {
        let claim = volume_claim(&controller.engine, &case, operation).await?;
        controller.reconcile(&claim).await.map_err(api_failure)?;
    }
    assert_eq!(cloud.count("DeleteDisk"), 1);
    assert_eq!(
        objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture poisoned"))?
            .deleted,
        vec!["PVC", "PV"]
    );
    let workspace = f
        .database
        .get_workspace(&f.actor, case.workspace)
        .await
        .map_err(api_failure)?;
    assert_eq!(workspace.status, "DELETED");
    let replay = f
        .database
        .delete_workspace(
            &f.actor,
            case.workspace,
            &request,
            "restore-never-started-storage",
            accepted.body.resource.spec_version - 1,
        )
        .await
        .map_err(api_failure)?;
    assert_eq!(replay.body.operation.id, operation);
    let mut tx = f.owner_transaction().await?;
    let result:(i64,i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM workspace_delete_results WHERE tenant_id=$1 AND operation_id=$2),(SELECT count(*) FROM workspace_delete_bindings WHERE tenant_id=$1 AND operation_id=$2 AND permit_id IS NULL AND restore_id=$3),(SELECT count(*) FROM quota_reservations q JOIN quota_accounts a ON a.tenant_id=q.tenant_id AND a.id=q.quota_account_id WHERE q.tenant_id=$1 AND q.resource_id=$4 AND a.dimension='WORKSPACE_GIB' AND q.status='RELEASED'),(SELECT count(*) FROM restores WHERE tenant_id=$1 AND id=$3)")
        .bind(f.actor.tenant_id).bind(operation).bind(case.restore).bind(case.workspace).fetch_one(&mut *tx).await?;
    ensure!(
        result == (1, 1, 2, 1),
        "single source-backed provenance and storage release; independent backup lineage retained"
    );
    let temporary:(i64,i64)=sqlx::query_as("SELECT count(*),sum(q.amount)::bigint FROM quota_reservations q JOIN quota_accounts a ON a.tenant_id=q.tenant_id AND a.id=q.quota_account_id JOIN restores r ON r.tenant_id=q.tenant_id AND r.operation_id=q.operation_id WHERE r.tenant_id=$1 AND r.id=$2 AND a.dimension='BACKUP_TEMP_GIB' AND q.status='ALLOCATED'")
        .bind(f.actor.tenant_id).bind(case.restore).fetch_one(&mut *tx).await?;
    ensure!(
        temporary == (2, 80),
        "temporary raw/snapshot quota remains until independent exact GC"
    );
    tx.commit().await?;
    Ok(())
}
