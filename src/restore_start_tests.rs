//! Actual ordinary worker/admission/permit methods against PG and the stateful
//! Kube service. Host transport is real mTLS; CSI/Kata observations are fixtures.
use crate::{
    admission::{AdmissionConfig, AdmissionRequest, AdmissionService},
    db::Database,
    domain::InstanceAction,
    engine::Claim,
    model::StartRequest,
    nodeguard::protocol::{LaunchBinding, LaunchPurpose},
    runtime::KubernetesRuntime,
    runtime_manifest::{RuntimeManifestContext, build_manifests},
    termination_ledger::tests::FixtureRuntime,
    test_support_db::{api_failure, runtime_class_guard},
    worker::Worker,
};
use anyhow::{Context, ensure};
use serde_json::{Value, json};
use sqlx::Row;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

pub(super) struct StartCase<'a> {
    pub base: &'a FixtureRuntime,
    pub instance: Uuid,
    pub workspace: Uuid,
    pub runtime: &'a KubernetesRuntime,
    pub objects: &'a Arc<Mutex<BTreeMap<String, Value>>>,
}
async fn claim(worker: &Worker, case: &StartCase<'_>, operation: Uuid) -> anyhow::Result<Claim> {
    let mut tx = case.base.f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET next_attempt_at=clock_timestamp()-interval '1 day' WHERE tenant_id=$1 AND id=$2")
        .bind(case.base.f.actor.tenant_id).bind(operation).execute(&mut *tx).await?;
    tx.commit().await?;
    let claim = worker
        .engine
        .claim()
        .await
        .map_err(api_failure)?
        .context("ordinary START claim")?;
    ensure!(
        claim.operation_id == operation,
        "must claim the target START"
    );
    Ok(claim)
}
async fn context(case: &StartCase<'_>) -> anyhow::Result<RuntimeManifestContext> {
    let mut tx = case.base.f.owner_transaction().await?;
    let r=sqlx::query("SELECT i.*,w.storage_class,w.size_gib,t.image_ref,t.image_digest,p.rules FROM instances i JOIN workspaces w ON w.tenant_id=i.tenant_id AND w.id=i.workspace_id JOIN template_versions t ON t.tenant_id=i.tenant_id AND t.id=i.template_version_id JOIN security_policy_versions p ON p.tenant_id=i.tenant_id AND p.id=i.security_policy_version_id WHERE i.tenant_id=$1 AND i.id=$2")
        .bind(case.base.f.actor.tenant_id).bind(case.instance).fetch_one(&mut *tx).await?;
    let mut c = RuntimeManifestContext {
        tenant_id: r.try_get("tenant_id")?,
        project_id: r.try_get("project_id")?,
        instance_id: case.instance,
        workspace_id: case.workspace,
        launch_id: r.try_get("launch_id")?,
        cluster_epoch: r.try_get("cluster_epoch")?,
        generation: r.try_get("runtime_generation")?,
        namespace: r.try_get("namespace")?,
        storage_class: r.try_get("storage_class")?,
        workspace_snapshot: None,
        image_ref: r.try_get("image_ref")?,
        image_digest: r.try_get("image_digest")?,
        template_approved: true,
        security_policy_approved: true,
        security_policy_rules: r.try_get("rules")?,
        cpu_millis: r.try_get("cpu_millis")?,
        memory_mib: r.try_get("memory_mib")?,
        workspace_size_gib: r.try_get("size_gib")?,
    };
    crate::workspace_restore::apply(&mut tx, &mut c)
        .await
        .map_err(api_failure)?;
    tx.commit().await?;
    Ok(c)
}
pub(super) async fn run(case: StartCase<'_>) -> anyhow::Result<()> {
    let f = &case.base.f;
    // Explicit private draft uses connected business methods; production
    // startup remains rejected until the normal ordered migration is installed.
    for script in [
        include_str!("../scripts/sql/worker-role.sql"),
        include_str!("../scripts/sql/admission-role.sql"),
        include_str!("../scripts/sql/restore-role.sql"),
    ] {
        sqlx::raw_sql(script).execute(&f.owner).await?;
    }
    let original = context(&case).await?;
    let mut tx = f.owner_transaction().await?;
    let provenance = crate::workspace_restore::load(&mut tx, &original)
        .await
        .map_err(api_failure)?
        .context("published delivery provenance")?;
    assert_eq!(provenance.delivery_storage_class, original.storage_class);
    let mut wrong_class = original.clone();
    wrong_class.storage_class = "unreviewed-restored-class".into();
    assert!(
        provenance.apply(&mut wrong_class).is_err(),
        "ordinary START must consume the frozen delivery class"
    );
    tx.commit().await?;
    let mut tx = f.owner_transaction().await?;
    for action in ["instances:start", "instances:read", "operations:read"] {
        for project in [None, Some(original.project_id)] {
            sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
                .bind(f.actor.tenant_id).bind(project).bind(f.actor.principal_id).bind(action).execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    let instance = f
        .database
        .get_instance(&f.actor, case.instance)
        .await
        .map_err(api_failure)?;
    let accepted = f
        .database
        .lifecycle_action(
            &f.actor,
            case.instance,
            InstanceAction::Start,
            &StartRequest {
                ttl_seconds: Some(300),
            },
            "restore-first-start",
            instance.spec_version,
            300,
            86400,
        )
        .await
        .map_err(api_failure)?;
    let worker_db = Database::connect(&std::env::var("TEST_WORKER_DATABASE_URL")?, 4).await?;
    let admission_db = Database::connect(&std::env::var("TEST_ADMISSION_DATABASE_URL")?, 4).await?;
    assert!(worker_db.verify_runtime_role().await.is_err());
    assert!(admission_db.verify_runtime_role().await.is_err());
    let worker = Worker::new(
        worker_db,
        case.runtime.clone(),
        "private-restore-start".into(),
        "fixture-target".into(),
        1,
        "kube-system".into(),
        BTreeMap::from([("k8s-app".into(), "kube-dns".into())]),
    )?;
    case.objects
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture poisoned"))?
        .extend(runtime_class_guard::objects(None));
    let first = claim(&worker, &case, accepted.body.operation.id).await?;
    worker
        .reconcile(&first)
        .await
        .map_err(api_failure)
        .context("ordinary worker first stage")?;
    let c = context(&case).await?;
    let config: AdmissionConfig = serde_json::from_value(json!({
        "gateway":{"username":"system:serviceaccount:sandbox-system:sandbox-gateway","uid":Uuid::new_v4()},
        "termination":{"username":"system:serviceaccount:sandbox-system:sandbox-termination","uid":Uuid::new_v4()},
        "worker":{"username":"system:serviceaccount:sandbox-system:sandbox-worker","uid":Uuid::new_v4()},
        "namespace_provisioner":{"username":"system:serviceaccount:sandbox-system:namespace-provisioner","uid":Uuid::new_v4()},
        "scheduler":{"kind":"control_plane","username":"system:kube-scheduler"},
        "storage_controllers":[{"kind":"service_account","username":"system:serviceaccount:kube-system:csi-provisioner","uid":Uuid::new_v4()}],
        "policy_status_controllers":[{"kind":"service_account","username":"system:serviceaccount:kube-system:cilium","uid":Uuid::new_v4()}],
        "namespace_status_controllers":[{"kind":"control_plane","username":"system:kube-controller-manager"}],
        "pod_garbage_collectors":[{"kind":"control_plane","username":"system:kube-controller-manager"}],
        "storage_provisioner":"diskplugin.csi.alibabacloud.com","certification_id":"fixture-target",
        "dns_namespace":"kube-system","dns_labels":{"k8s-app":"kube-dns"},"ephemeral_storage_mib":1024,"tmp_size_mib":256
    }))?;
    config.validate()?;
    let m = build_manifests(&c, &config.runtime())?;
    let mut candidate = serde_json::to_value(m.pod)?;
    candidate["metadata"]["uid"] = json!(Uuid::new_v4());
    candidate["metadata"]["resourceVersion"] = json!("1");
    let review: AdmissionRequest = serde_json::from_value(
        json!({"uid":Uuid::new_v4(),"resource":{"group":"","version":"v1","resource":"pods"},"operation":"CREATE","namespace":c.namespace,"name":candidate["metadata"]["name"],"userInfo":{"username":config.worker.username,"uid":config.worker.uid},"object":candidate}),
    )?;
    let service = AdmissionService {
        database: admission_db,
        kubernetes: case.runtime.client_clone(),
        config: config.clone(),
    };
    let pvc_path = format!(
        "/api/v1/namespaces/{}/persistentvolumeclaims/ws-{}",
        c.namespace, c.workspace_id
    );
    let saved_pvc = case
        .objects
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture poisoned"))?
        .get(&pvc_path)
        .cloned()
        .context("fixed target PVC")?;
    let pv_name = saved_pvc["spec"]["volumeName"]
        .as_str()
        .context("fixed PV name")?;
    let pv_path = format!("/api/v1/persistentvolumes/{pv_name}");
    let saved_pv = case
        .objects
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture poisoned"))?
        .get(&pv_path)
        .cloned()
        .context("fixed target PV")?;
    for (path, field, value) in [
        (&pvc_path, "/metadata/uid", json!(Uuid::new_v4())),
        (&pv_path, "/metadata/uid", json!(Uuid::new_v4())),
        (
            &pv_path,
            "/spec/csi/volumeHandle",
            json!("d-sameNameReplacement01"),
        ),
    ] {
        {
            let mut map = case
                .objects
                .lock()
                .map_err(|_| anyhow::anyhow!("fixture poisoned"))?;
            *map.get_mut(path)
                .context("replace observed identity")?
                .pointer_mut(field)
                .context("identity field")? = value;
        }
        assert!(
            service.decide(&review).await.is_err(),
            "actual admission rejects replaced {field}"
        );
        let mut map = case
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture poisoned"))?;
        map.insert(pvc_path.clone(), saved_pvc.clone());
        map.insert(pv_path.clone(), saved_pv.clone());
    }
    service
        .decide(&review)
        .await
        .map_err(|e| anyhow::anyhow!("admission {}: {}", e.code, e.message))?;
    let second = claim(&worker, &case, accepted.body.operation.id).await?;
    worker
        .reconcile(&second)
        .await
        .map_err(api_failure)
        .context("ordinary worker Pod stage")?;
    let pod_name = crate::runtime_manifest::pod_name(c.workspace_id);
    let pod_path = format!("/api/v1/namespaces/{}/pods/{pod_name}", c.namespace);
    let pod_uid = {
        let mut map = case
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture poisoned"))?;
        let pod = map.get_mut(&pod_path).context("worker-created Pod")?;
        pod["spec"]["nodeName"] = json!(case.base.node.node_name);
        Uuid::parse_str(pod["metadata"]["uid"].as_str().context("created Pod UID")?)?
    };
    let launch = LaunchBinding {
        purpose: LaunchPurpose::Workload,
        tenant_id: c.tenant_id,
        project_id: c.project_id,
        instance_id: c.instance_id,
        workspace_id: c.workspace_id,
        generation: c.generation,
        launch_id: c.launch_id,
        pod_uid,
        namespace: c.namespace.clone(),
        pod_name,
        pvc_uid: Uuid::parse_str(saved_pvc["metadata"]["uid"].as_str().context("PVC UID")?)?,
        pv_uid: Uuid::parse_str(saved_pv["metadata"]["uid"].as_str().context("PV UID")?)?,
        pv_name: pv_name.into(),
        csi_volume_handle: saved_pv["spec"]["csi"]["volumeHandle"]
            .as_str()
            .context("cloud disk")?
            .into(),
    };
    for change in 0..3 {
        let mut replaced = launch.clone();
        match change {
            0 => replaced.pvc_uid = Uuid::new_v4(),
            1 => replaced.pv_uid = Uuid::new_v4(),
            _ => replaced.csi_volume_handle = "d-forgedLaunch01".into(),
        }
        let error = case
            .base
            .engine
            .database
            .prepare_launch_authorization(
                c.tenant_id,
                accepted.body.operation.id,
                &case.base.node,
                &replaced,
            )
            .await
            .err()
            .context("fixed launch replacement refused")?;
        assert_eq!(error.code, "RESTORED_VOLUME_IDENTITY_CHANGED");
    }
    let authorization = case
        .base
        .engine
        .database
        .prepare_launch_authorization(
            c.tenant_id,
            accepted.body.operation.id,
            &case.base.node,
            &launch,
        )
        .await
        .map_err(api_failure)?;
    case.base
        .guard
        .registration_revision
        .store(5, std::sync::atomic::Ordering::SeqCst);
    let ack = case
        .base
        .guard
        .client
        .register(&authorization.request)
        .await?;
    let target = case
        .base
        .engine
        .database
        .load_termination_target(c.tenant_id, accepted.body.operation.id)
        .await
        .map_err(api_failure)?;
    let observed = crate::termination_runtime::TerminationRuntime::new(
        case.runtime.clone(),
        config.runtime(),
        "fixture-target".into(),
    )
    .observe_launch(
        &c,
        target
            .known_resources
            .as_ref()
            .context("restored known runtime")?,
    )
    .await?;
    case.base
        .engine
        .database
        .record_launch_authorization(&authorization, &ack, &observed.resources)
        .await
        .map_err(api_failure)?;
    {
        let mut map = case
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture poisoned"))?;
        let pod = map.get_mut(&pod_path).context("registered Pod")?;
        pod["status"] = json!({"phase":"Running","conditions":[{"type":"Ready","status":"True"}],"containerStatuses":[{"name":crate::runtime_manifest::container_name(c.launch_id),"ready":true,"restartCount":0,"image":"fixture","imageID":"fixture","state":{"running":{"startedAt":chrono::Utc::now()}}}]});
    }
    let ready = claim(&worker, &case, accepted.body.operation.id).await?;
    worker
        .reconcile(&ready)
        .await
        .map_err(api_failure)
        .context("ordinary worker ready stage")?;
    let mut tx = f.owner_transaction().await?;
    let status:(String,String)=sqlx::query_as("SELECT i.observed_state,o.status FROM instances i JOIN operations o ON o.tenant_id=i.tenant_id AND o.id=$3 WHERE i.tenant_id=$1 AND i.id=$2")
        .bind(c.tenant_id).bind(c.instance_id).bind(accepted.body.operation.id).fetch_one(&mut *tx).await?;
    assert_eq!(status, ("RUNNING".into(), "SUCCEEDED".into()));
    tx.commit().await?;
    Ok(())
}
