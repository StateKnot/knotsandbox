//! Real PG, real mTLS nodeguard protocol, stateful synthetic apiserver. These
//! tests do not claim the target CSI/Kata/OSS combination has been certified.
use super::tests::Fixture;
use super::*;
use crate::{
    backup_admission::expected_pod,
    backup_job::{BackupJobExit, BackupJobRuntime, ObservedBackupPod},
    backup_manifest::{NAMESPACE, block_pvc_name},
    backup_runtime::{BoundBackupVolume, CloneObservation, SnapshotReady},
    runtime::KubernetesRuntime,
    termination_client::TerminationObservation,
    test_support_db::{self, api_failure},
};
use anyhow::{Context, ensure};
use axum::{
    body::Body,
    http::{Method, Request, Response},
};
use kube::{Client, client::Body as KubeBody};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};
type KubeObjects = Arc<Mutex<BTreeMap<String, Value>>>;
#[path = "backup_legacy_deployment_tests.rs"]
mod legacy_deployment;
pub(crate) struct Pipeline {
    pub(crate) f: Fixture,
    pub(crate) claim: Claim,
    pub(crate) plan: JobPlan,
    volume: BoundBackupVolume,
    pod: Value,
    runtime: BackupJobRuntime,
    objects: KubeObjects,
}
impl Pipeline {
    async fn new() -> anyhow::Result<Self> {
        Self::with_cloud(super::tests::cloud_settings()).await
    }
    async fn with_cloud(cloud: Value) -> anyhow::Result<Self> {
        let f = Fixture::with_cloud(true, cloud).await?;
        Self::from_fixture(f).await
    }
    pub(crate) fn fixture_secret_objects(&self) -> anyhow::Result<BTreeMap<String, Value>> {
        let objects = self
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("source fixture Secret map"))?;
        let mut secrets = BTreeMap::new();
        for (_, _, identity) in self.plan.cloud.secret_bindings.entries() {
            let path = format!("/api/v1/namespaces/{NAMESPACE}/secrets/{}", identity.name);
            secrets.insert(
                path.clone(),
                objects
                    .get(&path)
                    .context("source fixture actual Secret")?
                    .clone(),
            );
        }
        Ok(secrets)
    }
    pub(crate) fn install_fixture_secret_objects(
        &self,
        secrets: BTreeMap<String, Value>,
    ) -> anyhow::Result<()> {
        let mut objects = self
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("source fixture Secret map"))?;
        for (_, _, identity) in self.plan.cloud.secret_bindings.entries() {
            let path = format!("/api/v1/namespaces/{NAMESPACE}/secrets/{}", identity.name);
            let value = secrets
                .get(&path)
                .context("generated source profile Secret")?;
            ensure!(
                value["metadata"]["uid"] == json!(identity.uid)
                    && value["metadata"]["name"] == json!(identity.name),
                "ordinary Secret fixture matches recorded name/UID"
            );
            objects.insert(path, value.clone());
        }
        Ok(())
    }
    pub(crate) async fn from_fixture(f: Fixture) -> anyhow::Result<Self> {
        let accepted = f.accept("pipeline").await.map_err(api_failure)?;
        let claim = f.claim(accepted.body.operation.id).await?;
        let storage = f
            .backup
            .database
            .prepare_backup_storage(&f.backup, &claim)
            .await
            .map_err(api_failure)?;
        let observation = SnapshotObservation {
            snapshot_uid: Uuid::new_v4(),
            ready: Some(SnapshotReady {
                snapshot_uid: Uuid::nil(),
                content_uid: Uuid::new_v4(),
                content_name: "snapcontent-fixture".into(),
                cloud_snapshot: "s-fixture0001".into(),
                created_at: Utc::now() - Duration::seconds(1),
                restore_size: storage.source.size_bytes,
            }),
        };
        let observation = SnapshotObservation {
            ready: observation.ready.map(|mut r| {
                r.snapshot_uid = observation.snapshot_uid;
                r
            }),
            ..observation
        };
        f.backup
            .database
            .record_backup_snapshot(&f.backup, &claim, &observation)
            .await
            .map_err(api_failure)?;
        // Retry the same nanosecond observation after PG canonicalized microseconds.
        f.backup
            .database
            .record_backup_snapshot(&f.backup, &claim, &observation)
            .await
            .map_err(api_failure)?;
        f.backup
            .database
            .prepare_backup_storage(&f.backup, &claim)
            .await
            .map_err(api_failure)?;
        let volume = BoundBackupVolume {
            pvc_uid: Uuid::new_v4(),
            pv_uid: Uuid::new_v4(),
            pv_name: format!("pvc-{}", Uuid::new_v4()),
            cloud_disk: "d-backupclone01".into(),
            size_bytes: storage.source.size_bytes,
        };
        f.backup
            .database
            .record_backup_clone(
                &f.backup,
                &claim,
                &CloneObservation {
                    delegated_content_uid: Uuid::new_v4(),
                    delegated_snapshot_uid: Uuid::new_v4(),
                    pvc_uid: volume.pvc_uid,
                    bound: Some(volume.clone()),
                },
            )
            .await
            .map_err(api_failure)?;
        let mut plan = f
            .backup
            .database
            .prepare_backup_job(&f.backup, &claim)
            .await
            .map_err(api_failure)?;
        let job = Uuid::new_v4();
        let cfg = Uuid::new_v4();
        f.backup
            .database
            .record_backup_job_objects(&f.backup, &claim, plan.context.attempt_id, cfg, job)
            .await
            .map_err(api_failure)?;
        plan.known_job = Some(job);
        plan.known_config = Some(cfg);
        let admission =
            Database::connect(&std::env::var("TEST_ADMISSION_DATABASE_URL")?, 4).await?;
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let db = admission.clone();
            let tenant = claim.tenant_id;
            let attempt = plan.context.attempt_id;
            tasks.spawn(async move {
                let mut tx = db.begin(tenant).await.map_err(api_failure)?;
                let review = Uuid::new_v4();
                let ok: bool = sqlx::query_scalar("SELECT sandbox_admit_backup_pod($1,$2,$3,$4)")
                    .bind(tenant)
                    .bind(attempt)
                    .bind(review)
                    .bind(job)
                    .fetch_one(&mut *tx)
                    .await?;
                tx.commit().await?;
                Ok::<_, anyhow::Error>(ok)
            });
        }
        let mut winners = 0;
        while let Some(v) = tasks.join_next().await {
            winners += usize::from(v??)
        }
        assert_eq!(winners, 1);
        let name = format!(
            "{}-abcde",
            crate::nodeguard::protocol::backup_job_name(
                plan.context.attempt_id,
                plan.context.stage
            )
        );
        let pod_id = Uuid::new_v4();
        let mut pod =
            expected_pod(&plan.context, job, &name).map_err(|d| anyhow::anyhow!(d.message))?;
        pod["metadata"]["uid"] = json!(pod_id);
        pod["metadata"]["resourceVersion"] = json!("1");
        pod["spec"]["nodeName"] = json!(f.base.node.node_name);
        f.backup
            .database
            .record_backup_pod(
                &f.backup,
                &claim,
                plan.context.attempt_id,
                job,
                &ObservedBackupPod {
                    uid: pod_id,
                    name,
                    node_name: Some(f.base.node.node_name.clone()),
                    exit: None,
                },
            )
            .await
            .map_err(api_failure)?;
        plan.known_pod = Some(pod_id);
        let (mut objects, runtime) = runtime_objects(&plan, &volume, &f.base.node, &pod)?;
        // Native and Cilium policies are actual objects read by the kube Client.
        let observed = objects.clone();
        let _ = &mut objects;
        Ok(Self {
            f,
            claim,
            plan,
            volume,
            pod,
            runtime,
            objects: observed,
        })
    }
}
pub(crate) fn runtime_objects(
    plan: &JobPlan,
    v: &BoundBackupVolume,
    node: &crate::nodeguard::protocol::NodeBinding,
    pod: &Value,
) -> anyhow::Result<(KubeObjects, BackupJobRuntime)> {
    let cnp = json!({"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"sandbox-backup-egress","namespace":NAMESPACE,"uid":Uuid::new_v4()},"spec":plan.cloud.network_spec()});
    let np = json!({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"sandbox-backup-default-deny","namespace":NAMESPACE,"uid":Uuid::new_v4()},"spec":{"podSelector":{"matchExpressions":[{"key":"sandbox.platform/backup-id","operator":"Exists"}]},"policyTypes":["Ingress","Egress"]}});
    let pvc = json!({"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":{"name":block_pvc_name(plan.context.attempt_id),"namespace":NAMESPACE,"uid":v.pvc_uid},"spec":{"volumeName":v.pv_name,"volumeMode":"Block"},"status":{"phase":"Bound"}});
    let pv = json!({"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":v.pv_name,"uid":v.pv_uid},"spec":{"volumeMode":"Block","accessModes":["ReadWriteOnce"],"persistentVolumeReclaimPolicy":"Retain","csi":{"driver":"diskplugin.csi.alibabacloud.com","volumeHandle":v.cloud_disk},"claimRef":{"uid":v.pvc_uid,"namespace":NAMESPACE,"name":block_pvc_name(plan.context.attempt_id)}},"status":{"phase":"Bound"}});
    let node_object = json!({"apiVersion":"v1","kind":"Node","metadata":{"name":node.node_name,"uid":node.node_uid,"annotations":{"sandbox.platform/runtime-profile-sha256":node.profile_sha256},"labels":{"sandbox.platform/worker-pool":"kata","sandbox.platform/node-pool":"kata"}},"spec":{"unschedulable":false,"taints":[{"key":"sandbox.platform/untrusted","value":"true","effect":"NoSchedule"}]},"status":{"conditions":[{"type":"Ready","status":"True"}],"nodeInfo":{"bootID":node.boot_id,"architecture":"amd64","containerRuntimeVersion":"containerd://2.3.5","kernelVersion":"6.12","kubeletVersion":"v1.36.4","machineID":"fixture","operatingSystem":"linux","osImage":"fixture","systemUUID":"fixture"}}});
    let list =
        |items: Vec<Value>| json!({"apiVersion":"v1","kind":"List","metadata":{},"items":items});
    let mut objects = BTreeMap::from([
        (
            format!(
                "/apis/storage.k8s.io/v1/storageclasses/{}",
                plan.clone_storage_class
            ),
            json!({"apiVersion":"storage.k8s.io/v1","kind":"StorageClass","metadata":{"name":plan.clone_storage_class},"provisioner":"diskplugin.csi.alibabacloud.com","reclaimPolicy":"Retain","volumeBindingMode":"WaitForFirstConsumer","allowVolumeExpansion":false,"parameters":{"type":"cloud_essd","encrypted":"true","kmsKeyId":plan.cloud.clone_kms_key_id,"diskTags/Deployment":plan.cloud.deployment}}),
        ),
        (
            format!(
                "/apis/cilium.io/v2/namespaces/{NAMESPACE}/ciliumnetworkpolicies/sandbox-backup-egress"
            ),
            cnp.clone(),
        ),
        (
            format!("/apis/cilium.io/v2/namespaces/{NAMESPACE}/ciliumnetworkpolicies"),
            list(vec![cnp]),
        ),
        (
            format!(
                "/apis/networking.k8s.io/v1/namespaces/{NAMESPACE}/networkpolicies/sandbox-backup-default-deny"
            ),
            np.clone(),
        ),
        (
            format!("/apis/networking.k8s.io/v1/namespaces/{NAMESPACE}/networkpolicies"),
            list(vec![np]),
        ),
        (
            "/apis/cilium.io/v2/ciliumclusterwidenetworkpolicies".into(),
            list(vec![
                json!({"apiVersion":"cilium.io/v2","kind":"CiliumClusterwideNetworkPolicy","metadata":{"name":"sandbox-trusted-bootstrap"},"spec":{"endpointSelector":{"matchExpressions":[{"key":"k8s:io.kubernetes.pod.namespace","operator":"In","values":["kube-system","sandbox-system"]},{"key":"k8s:sandbox.platform/backup-id","operator":"DoesNotExist"}]}}}),
                json!({"apiVersion":"cilium.io/v2","kind":"CiliumClusterwideNetworkPolicy","metadata":{"name":"sandbox-host-bootstrap"},"spec":{"nodeSelector":{}}}),
            ]),
        ),
        (
            "/apis/node.k8s.io/v1/runtimeclasses/kata-backup-qemu".into(),
            json!({"apiVersion":"node.k8s.io/v1","kind":"RuntimeClass","metadata":{"name":"kata-backup-qemu"},"handler":"kata-qemu"}),
        ),
        (format!("/api/v1/nodes/{}", node.node_name), node_object),
        (
            format!(
                "/api/v1/namespaces/{NAMESPACE}/persistentvolumeclaims/{}",
                block_pvc_name(plan.context.attempt_id)
            ),
            pvc,
        ),
        (format!("/api/v1/persistentvolumes/{}", v.pv_name), pv),
        (
            format!(
                "/api/v1/namespaces/{NAMESPACE}/pods/{}",
                pod["metadata"]["name"].as_str().context("name")?
            ),
            pod.clone(),
        ),
        (
            "/apis/storage.k8s.io/v1/volumeattachments".into(),
            json!({"apiVersion":"storage.k8s.io/v1","kind":"VolumeAttachmentList","metadata":{},"items":[]}),
        ),
    ]);
    objects.insert("/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/sandbox-runtime-protection".to_owned(),json!({"apiVersion":"admissionregistration.k8s.io/v1","kind":"ValidatingWebhookConfiguration","metadata":{"name":"sandbox-runtime-protection"},"webhooks":[{"name":"runtime.sandbox.platform","failurePolicy":"Fail","sideEffects":"None","admissionReviewVersions":["v1"],"clientConfig":{"caBundle":"Zml4dHVyZQ==","service":{"name":"sandbox-admission","namespace":NAMESPACE,"path":"/validate","port":443}},"rules":[{"apiGroups":[""],"apiVersions":["v1"],"resources":["secrets"],"operations":["CREATE","UPDATE","DELETE"],"scope":"Namespaced"}]}]}));
    for (_, key, binding) in plan.cloud.secret_bindings.entries() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        objects.insert(format!("/api/v1/namespaces/{NAMESPACE}/secrets/{}",binding.name), json!({"apiVersion":"v1","kind":"Secret","metadata":{"name":binding.name,"namespace":NAMESPACE,"uid":binding.uid},"immutable":true,"type":"Opaque","data":{key:STANDARD.encode(format!("test-only-backup-key-{key}"))}}));
    }
    let shared = Arc::new(Mutex::new(objects));
    let stored = shared.clone();
    let svc = tower::service_fn(move |r: Request<KubeBody>| {
        let shared = stored.clone();
        async move {
            let path = r.uri().path().to_owned();
            let method = r.method().clone();
            let body = axum::body::to_bytes(Body::new(r.into_body()), 131072)
                .await
                .unwrap_or_default();
            let payload: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let (status, response) = if let Ok(mut map) = shared.lock() {
                if method == Method::POST {
                    if let Some(name) = payload.pointer("/metadata/name").and_then(Value::as_str) {
                        let item_path = format!("{path}/{name}");
                        if let std::collections::btree_map::Entry::Vacant(entry) =
                            map.entry(item_path)
                        {
                            let mut created = payload;
                            created["metadata"]["uid"] = json!(Uuid::new_v4());
                            created["metadata"]["resourceVersion"] = json!("1");
                            entry.insert(created.clone());
                            (201, created)
                        } else {
                            (
                                409,
                                json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"AlreadyExists","code":409}),
                            )
                        }
                    } else {
                        (
                            400,
                            json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"BadRequest","code":400}),
                        )
                    }
                } else if method == Method::DELETE {
                    if map.get(&path).is_some_and(|v| {
                        matches!(
                            v.get("kind").and_then(Value::as_str),
                            Some("Job" | "ConfigMap")
                        )
                    }) {
                        // Simulate the API controller's completed metadata GC;
                        // cloud volume absence is never inferred by this fixture.
                        let removed = map.remove(&path).unwrap_or(Value::Null);
                        (200, removed)
                    } else if let Some(p) = map.get_mut(&path) {
                        p["metadata"]["deletionTimestamp"] = json!(Utc::now());
                        (200, p.clone())
                    } else {
                        (
                            404,
                            json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}),
                        )
                    }
                } else if method == Method::PATCH {
                    if let Some(p) = map.get_mut(&path) {
                        p["metadata"]["finalizers"] = payload["metadata"]["finalizers"].clone();
                        let response = p.clone();
                        if p["metadata"]["finalizers"].as_array().is_some_and(|f| {
                            !f.iter()
                                .any(|v| v == "sandbox.platform/termination-protection")
                        }) {
                            map.remove(&path);
                        }
                        (200, response)
                    } else {
                        (
                            404,
                            json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}),
                        )
                    }
                } else {
                    map.get(&path).cloned().map(|v|(200,v)).unwrap_or((404,json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404})))
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
    Ok((
        shared,
        BackupJobRuntime::new(KubernetesRuntime::from_client(Client::new(svc, "default"))),
    ))
}
#[tokio::test]
#[ignore = "requires isolated PostgreSQL and authenticated loopback nodeguard"]
async fn capture_uses_once_only_authority_then_trusted_close_before_handoff() -> anyhow::Result<()>
{
    let _serial = test_support_db::serial().await;
    let mut p = Pipeline::new().await?;
    let pod_name = p.pod["metadata"]["name"].as_str().context("pod")?;
    let observation = p
        .runtime
        .observe_launch(&p.plan, pod_name, Some(&p.volume))
        .await?;
    let permit =
        p.f.backup
            .database
            .prepare_backup_launch(&p.f.backup, &p.claim, &observation)
            .await
            .map_err(api_failure)?;
    let replay =
        p.f.backup
            .database
            .prepare_backup_launch(&p.f.backup, &p.claim, &observation)
            .await
            .map_err(api_failure)?;
    assert_eq!(permit.request.permit_id, replay.request.permit_id);
    let receipt = p.f.base.guard.client.register(&permit.request).await?;
    p.f.backup
        .database
        .record_backup_registration(&p.f.backup, &p.claim, &receipt)
        .await
        .map_err(api_failure)?;
    assert!(
        !p.f.backup
            .database
            .cancel_quiescent_backup(&p.f.backup, &p.claim)
            .await
            .map_err(api_failure)?
    );
    let report = BackupJobExit {
        exit_code: 0,
        report: Some(
            json!({"snapshot_id":"c".repeat(64),"disk":{"size_bytes":p.volume.size_bytes,"sha256":"d".repeat(64)}}),
        ),
        finished_at: Utc::now(),
    };
    p.f.backup
        .database
        .close_backup_attempt(&p.f.backup, &p.claim, Some(&report))
        .await
        .map_err(api_failure)?;
    assert!(
        p.f.backup
            .database
            .prepare_backup_launch(&p.f.backup, &p.claim, &observation)
            .await
            .is_err()
    );
    p.plan =
        p.f.backup
            .database
            .prepare_backup_job(&p.f.backup, &p.claim)
            .await
            .map_err(api_failure)?;
    let challenge =
        p.f.backup
            .database
            .prepare_backup_close(&p.f.backup, &p.claim)
            .await
            .map_err(api_failure)?;
    p.runtime
        .request_close(&p.plan, &challenge.permit.request.launch)
        .await?;
    let TerminationObservation::Verified(proof) =
        p.f.base.guard.client.close(&challenge.request).await?
    else {
        anyhow::bail!("mock trusted proof")
    };
    let proof_id =
        p.f.backup
            .database
            .record_backup_termination(&p.f.backup, &p.claim, &proof)
            .await
            .map_err(api_failure)?;
    // Proof alone still cannot release the workspace or compute accounting.
    assert!(
        !p.f.backup
            .database
            .cancel_quiescent_backup(&p.f.backup, &p.claim)
            .await
            .map_err(api_failure)?
    );
    let cleanup = p
        .runtime
        .finish_cleanup(&p.plan, &proof)
        .await?
        .context("mock kube cleanup")?;
    p.f.backup
        .database
        .record_backup_cleanup(&p.f.backup, &p.claim, proof_id, &cleanup)
        .await
        .map_err(api_failure)?;
    let record =
        p.f.backup
            .database
            .backup_record(&p.f.backup, &p.claim)
            .await
            .map_err(api_failure)?;
    assert_eq!(record.status, "SEAL_PENDING");
    // Revocation after CAPTURE cleanup cannot create SEAL or retain a needless writer hold.
    let mut tx = p.f.base.f.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND action='backups:create'")
        .bind(p.claim.tenant_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    assert!(
        p.f.backup
            .database
            .prepare_backup_job(&p.f.backup, &p.claim)
            .await
            .is_err()
    );
    assert!(
        p.f.backup
            .database
            .cancel_quiescent_backup(&p.f.backup, &p.claim)
            .await
            .map_err(api_failure)?
    );
    let mut tx = p.f.base.f.owner_transaction().await?;
    let(status,hold,compute,storage):(String,bool,i64,i64)=sqlx::query_as("SELECT b.status,EXISTS(SELECT 1 FROM workspace_hold_releases r WHERE r.tenant_id=b.tenant_id AND r.hold_id=b.hold_id),(SELECT count(*) FROM quota_reservations r JOIN quota_accounts q ON q.id=r.quota_account_id WHERE r.tenant_id=b.tenant_id AND r.operation_id=b.operation_id AND q.dimension IN('CPU_MILLIS','MEMORY_MIB') AND r.status='RELEASED'),(SELECT count(*) FROM quota_reservations r JOIN quota_accounts q ON q.id=r.quota_account_id WHERE r.tenant_id=b.tenant_id AND r.operation_id=b.operation_id AND q.dimension IN('BACKUP_GIB','BACKUP_TEMP_GIB') AND r.status='ALLOCATED') FROM backups b WHERE b.tenant_id=$1 AND b.id=$2").bind(p.claim.tenant_id).bind(record.id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    assert_eq!(
        (status, hold, compute, storage),
        ("CANCELLED".into(), true, 4, 4)
    );
    Ok(())
}
#[tokio::test]
#[ignore = "requires isolated PostgreSQL and component roles"]
async fn node_gate_and_live_resource_identity_reject_replacement_and_expiry() -> anyhow::Result<()>
{
    let _serial = test_support_db::serial().await;
    let p = Pipeline::new().await?;
    let admission = Database::connect(&std::env::var("TEST_ADMISSION_DATABASE_URL")?, 2).await?;
    for (boot, want) in [(p.f.base.node.boot_id, true), (Uuid::new_v4(), false)] {
        let mut tx = admission
            .begin(p.claim.tenant_id)
            .await
            .map_err(api_failure)?;
        let ok: bool = sqlx::query_scalar("SELECT sandbox_backup_node_binding($1,$2,$3,$4,$5,$6)")
            .bind(p.claim.tenant_id)
            .bind(p.plan.context.attempt_id)
            .bind(p.f.base.node.node_uid)
            .bind(&p.f.base.node.node_name)
            .bind(boot)
            .bind(&p.f.base.node.profile_sha256)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        assert_eq!(ok, want);
    }
    let policy_path = format!(
        "/apis/cilium.io/v2/namespaces/{NAMESPACE}/ciliumnetworkpolicies/sandbox-backup-egress"
    );
    for path in [
        policy_path.clone(),
        "/apis/cilium.io/v2/ciliumclusterwidenetworkpolicies".into(),
    ] {
        let original = p
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("mutex"))?
            .get(&path)
            .cloned()
            .context("policy")?;
        {
            let mut objects = p.objects.lock().map_err(|_| anyhow::anyhow!("mutex"))?;
            let value = objects.get_mut(&path).context("policy")?;
            let target = if path == policy_path {
                value
            } else {
                &mut value["items"][0]
            };
            target["specs"] = json!([{"endpointSelector":{},"egress":[{"toEntities":["all"]}]}]);
        }
        assert!(
            p.runtime.verify_network(&p.plan.cloud).await.is_err(),
            "extra specs must not union-Allow backup egress"
        );
        p.objects
            .lock()
            .map_err(|_| anyhow::anyhow!("mutex"))?
            .insert(path, original);
    }
    let path = format!("/api/v1/persistentvolumes/{}", p.volume.pv_name);
    p.objects
        .lock()
        .map_err(|_| anyhow::anyhow!("mutex"))?
        .get_mut(&path)
        .context("pv")?["metadata"]["uid"] = json!(Uuid::new_v4());
    assert!(
        p.runtime
            .observe_launch(
                &p.plan,
                p.pod["metadata"]["name"].as_str().context("pod")?,
                Some(&p.volume)
            )
            .await
            .is_err()
    );
    let mut tx = p.f.base.f.owner_transaction().await?;
    sqlx::query("UPDATE runtime_nodes SET enabled=false WHERE cluster_epoch=$1 AND node_uid=$2 AND boot_id=$3").bind(p.f.base.node.cluster_epoch).bind(p.f.base.node.node_uid).bind(p.f.base.node.boot_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let mut tx = admission
        .begin(p.claim.tenant_id)
        .await
        .map_err(api_failure)?;
    let ok: bool = sqlx::query_scalar("SELECT sandbox_backup_node_binding($1,$2,$3,$4,$5,$6)")
        .bind(p.claim.tenant_id)
        .bind(p.plan.context.attempt_id)
        .bind(p.f.base.node.node_uid)
        .bind(&p.f.base.node.node_name)
        .bind(p.f.base.node.boot_id)
        .bind(&p.f.base.node.profile_sha256)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    ensure!(!ok, "disabled node rejected");
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and component roles"]
async fn controller_cancels_revoked_unstarted_backup_without_remote_mutation() -> anyhow::Result<()>
{
    let _serial = test_support_db::serial().await;
    let f = Fixture::new(true).await?;
    let accepted = f.accept("early-revoke").await.map_err(api_failure)?;
    let claim = f.claim(accepted.body.operation.id).await?;
    let mut tx = f.base.f.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND action='backups:create'")
        .bind(claim.tenant_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = calls.clone();
    let svc = tower::service_fn(move |_: Request<KubeBody>| {
        let calls = count.clone();
        async move {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, Infallible>(
                Response::builder()
                    .status(500)
                    .body(Body::empty())
                    .unwrap_or_default(),
            )
        }
    });
    let runtime = KubernetesRuntime::from_client(Client::new(svc, "default"));
    let key = [hex::decode("302a300506032b6570032100")?, vec![42u8; 32]].concat();
    let vault =
        crate::backup_object::BackupVaultVerifier::new(crate::backup_object::BackupVaultConfig {
            endpoint: "https://oss-cn-hangzhou-internal.aliyuncs.com".into(),
            bucket: "fixture-backup-vault".into(),
            region: "cn-hangzhou".into(),
            account_id: "1234567890123456".into(),
            sts_credentials_file: "/nonexistent/fixture-no-cloud".into(),
            signing_public_key_spki: key,
        })?;
    let mut controller = crate::backup_controller::BackupController::new(
        f.backup.database.clone(),
        runtime,
        crate::termination_client::test_support::credentials(),
        Arc::new(vault),
        "backup-early-test".into(),
        1,
    )?;
    controller.engine = f.backup.clone();
    controller.reconcile(&claim).await.map_err(api_failure)?;
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    let mut tx = f.base.f.owner_transaction().await?;
    let(status,release,compute):(String,bool,i64)=sqlx::query_as("SELECT b.status,EXISTS(SELECT 1 FROM workspace_hold_releases r WHERE r.hold_id=b.hold_id),(SELECT count(*) FROM quota_reservations r JOIN quota_accounts q ON q.id=r.quota_account_id WHERE r.tenant_id=b.tenant_id AND r.operation_id=b.operation_id AND q.dimension IN('CPU_MILLIS','MEMORY_MIB') AND r.status='RELEASED') FROM backups b WHERE b.tenant_id=$1 AND b.id=$2").bind(claim.tenant_id).bind(accepted.body.resource.id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    assert_eq!((status, release, compute), ("CANCELLED".into(), true, 4));
    Ok(())
}

impl Pipeline {
    async fn close_current(&mut self, exit: BackupJobExit) -> anyhow::Result<()> {
        let observed = self
            .runtime
            .observe_launch(
                &self.plan,
                self.pod["metadata"]["name"].as_str().context("Pod name")?,
                if self.plan.context.stage == crate::nodeguard::protocol::BackupStage::Capture {
                    Some(&self.volume)
                } else {
                    None
                },
            )
            .await?;
        let permit = self
            .f
            .backup
            .database
            .prepare_backup_launch(&self.f.backup, &self.claim, &observed)
            .await
            .map_err(api_failure)?;
        let ack = self.f.base.guard.client.register(&permit.request).await?;
        self.f
            .backup
            .database
            .record_backup_registration(&self.f.backup, &self.claim, &ack)
            .await
            .map_err(api_failure)?;
        self.f
            .backup
            .database
            .close_backup_attempt(&self.f.backup, &self.claim, Some(&exit))
            .await
            .map_err(api_failure)?;
        self.plan = self
            .f
            .backup
            .database
            .prepare_backup_job(&self.f.backup, &self.claim)
            .await
            .map_err(api_failure)?;
        let challenge = self
            .f
            .backup
            .database
            .prepare_backup_close(&self.f.backup, &self.claim)
            .await
            .map_err(api_failure)?;
        self.runtime
            .request_close(&self.plan, &challenge.permit.request.launch)
            .await?;
        let TerminationObservation::Verified(proof) =
            self.f.base.guard.client.close(&challenge.request).await?
        else {
            anyhow::bail!("trusted host pending")
        };
        let id = self
            .f
            .backup
            .database
            .record_backup_termination(&self.f.backup, &self.claim, &proof)
            .await
            .map_err(api_failure)?;
        let cleanup = self
            .runtime
            .finish_cleanup(&self.plan, &proof)
            .await?
            .context("exact cleanup")?;
        self.f
            .backup
            .database
            .record_backup_cleanup(&self.f.backup, &self.claim, id, &cleanup)
            .await
            .map_err(api_failure)?;
        Ok(())
    }
    async fn admit_seal(&mut self) -> anyhow::Result<()> {
        let mut plan = self
            .f
            .backup
            .database
            .prepare_backup_job(&self.f.backup, &self.claim)
            .await
            .map_err(api_failure)?;
        assert_eq!(
            plan.context.stage,
            crate::nodeguard::protocol::BackupStage::Seal
        );
        let job = Uuid::new_v4();
        let config = Uuid::new_v4();
        self.f
            .backup
            .database
            .record_backup_job_objects(
                &self.f.backup,
                &self.claim,
                plan.context.attempt_id,
                config,
                job,
            )
            .await
            .map_err(api_failure)?;
        let db = Database::connect(&std::env::var("TEST_ADMISSION_DATABASE_URL")?, 2).await?;
        let mut tx = db.begin(self.claim.tenant_id).await.map_err(api_failure)?;
        let ok: bool = sqlx::query_scalar("SELECT sandbox_admit_backup_pod($1,$2,$3,$4)")
            .bind(self.claim.tenant_id)
            .bind(plan.context.attempt_id)
            .bind(Uuid::new_v4())
            .bind(job)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        ensure!(ok, "SEAL admitted once");
        plan.known_job = Some(job);
        plan.known_config = Some(config);
        let name = format!(
            "{}-fghij",
            crate::nodeguard::protocol::backup_job_name(
                plan.context.attempt_id,
                plan.context.stage
            )
        );
        let uid = Uuid::new_v4();
        let mut pod =
            expected_pod(&plan.context, job, &name).map_err(|d| anyhow::anyhow!(d.message))?;
        pod["metadata"]["uid"] = json!(uid);
        pod["metadata"]["resourceVersion"] = json!("1");
        pod["spec"]["nodeName"] = json!(self.f.base.node.node_name);
        self.f
            .backup
            .database
            .record_backup_pod(
                &self.f.backup,
                &self.claim,
                plan.context.attempt_id,
                job,
                &ObservedBackupPod {
                    uid,
                    name,
                    node_name: Some(self.f.base.node.node_name.clone()),
                    exit: None,
                },
            )
            .await
            .map_err(api_failure)?;
        plan.known_pod = Some(uid);
        let (objects, runtime) = runtime_objects(&plan, &self.volume, &self.f.base.node, &pod)?;
        self.plan = plan;
        self.pod = pod;
        self.objects = objects;
        self.runtime = runtime;
        Ok(())
    }
}
#[tokio::test]
#[ignore = "requires isolated PostgreSQL and authenticated loopback nodeguard"]
async fn failed_seal_only_releases_hold_after_both_trusted_vm_cleanups() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let mut p = Pipeline::new().await?;
    p.close_current(BackupJobExit{exit_code:0,report:Some(json!({"snapshot_id":"c".repeat(64),"disk":{"size_bytes":p.volume.size_bytes,"sha256":"d".repeat(64)}})),finished_at:Utc::now()}).await?;
    p.admit_seal().await?;
    assert!(
        !p.f.backup
            .database
            .cancel_quiescent_backup(&p.f.backup, &p.claim)
            .await
            .map_err(api_failure)?
    );
    p.close_current(BackupJobExit {
        exit_code: 1,
        report: None,
        finished_at: Utc::now(),
    })
    .await?;
    assert!(
        p.f.backup
            .database
            .backup_completion_expired_or_failed(&p.f.backup, &p.claim)
            .await
            .map_err(api_failure)?
    );
    assert!(
        p.f.backup
            .database
            .cancel_quiescent_backup(&p.f.backup, &p.claim)
            .await
            .map_err(api_failure)?
    );
    let backup =
        p.f.base
            .f
            .database
            .get_backup(&p.f.base.f.actor, p.plan.backup.id)
            .await
            .map_err(api_failure)?;
    assert_eq!(backup.status, "CANCELLED");
    Ok(())
}

#[path = "backup_vault_pipeline_tests.rs"]
pub(crate) mod vault;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and real component roles"]
async fn immutable_key_identity_and_live_mutation_protection_are_required() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let p = Pipeline::new().await?;
    let receipt = p.runtime.verify_profile_secrets(&p.plan.cloud).await?;
    assert_eq!(
        receipt,
        serde_json::to_value(&p.plan.cloud.secret_bindings)?
    );
    assert!(
        serde_json::to_value(&p.plan.cloud)?
            .get("secret_bindings")
            .is_none()
    );
    let secret_path = format!(
        "/api/v1/namespaces/{NAMESPACE}/secrets/{}",
        p.plan.cloud.secret_bindings.password.name
    );
    let hook_path = "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/sandbox-runtime-protection";
    let original = p
        .objects
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture lock"))?
        .clone();
    for (path, pointer, value) in [
        (secret_path.as_str(), "/metadata/uid", json!(Uuid::new_v4())),
        (secret_path.as_str(), "/immutable", json!(false)),
        (
            secret_path.as_str(),
            "/data/password",
            json!("YW5vdGhlci1wYXNzd29yZA=="),
        ),
        (hook_path, "/webhooks/0/failurePolicy", json!("Ignore")),
        (
            hook_path,
            "/webhooks/0/rules/0/operations",
            json!(["CREATE", "UPDATE"]),
        ),
        (
            hook_path,
            "/webhooks/0/clientConfig/service/name",
            json!("other-admission"),
        ),
    ] {
        {
            let mut objects = p
                .objects
                .lock()
                .map_err(|_| anyhow::anyhow!("fixture lock"))?;
            *objects = original.clone();
            *objects
                .get_mut(path)
                .and_then(|v| v.pointer_mut(pointer))
                .context("fixture pointer")? = value;
        }
        assert!(
            p.runtime
                .verify_profile_secrets(&p.plan.cloud)
                .await
                .is_err(),
            "accepted {pointer}"
        );
    }
    for (path, key, value) in [
        (
            secret_path.as_str(),
            "ownerReferences",
            json!([{"apiVersion":"v1","kind":"Pod","name":"bad-owner","uid":Uuid::new_v4()}]),
        ),
        (
            secret_path.as_str(),
            "finalizers",
            json!(["attacker.invalid/finalizer"]),
        ),
        (
            hook_path,
            "matchConditions",
            json!([{"name":"skip","expression":"false"}]),
        ),
        (
            hook_path,
            "namespaceSelector",
            json!({"matchLabels":{"skip":"backup"}}),
        ),
    ] {
        {
            let mut objects = p
                .objects
                .lock()
                .map_err(|_| anyhow::anyhow!("fixture lock"))?;
            *objects = original.clone();
            let target = objects.get_mut(path).context("fixture object")?;
            let object = if path == hook_path {
                &mut target["webhooks"][0]
            } else {
                &mut target["metadata"]
            };
            object[key] = value;
        }
        assert!(
            p.runtime
                .verify_profile_secrets(&p.plan.cloud)
                .await
                .is_err(),
            "accepted {key}"
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and admission role"]
async fn reserved_backup_keys_are_permanent_even_when_profile_is_disabled() -> anyhow::Result<()> {
    use crate::admission::{AdmissionRequest, AdmissionService};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let _serial = test_support_db::serial().await;
    let p = Pipeline::new().await?;
    let service = AdmissionService {
        database: Database::connect(&std::env::var("TEST_ADMISSION_DATABASE_URL")?, 2).await?,
        kubernetes: p.runtime.runtime().client_clone(),
        config: serde_json::from_str(include_str!("../deploy/admission/config.example.json"))?,
    };
    service.database.verify_runtime_role().await?;
    let name = format!("sbx-bkey-{}", Uuid::new_v4());
    let object = json!({"apiVersion":"v1","kind":"Secret","metadata":{"name":name,"namespace":NAMESPACE},"type":"Opaque","immutable":true,"data":{"password":STANDARD.encode(b"test-only-strong-backup-password")}});
    let mut request: AdmissionRequest = serde_json::from_value(
        json!({"uid":Uuid::new_v4(),"resource":{"group":"","version":"v1","resource":"secrets"},"operation":"CREATE","namespace":NAMESPACE,"name":name,"userInfo":{"username":"oidc:key-installer","uid":"fixture-user","groups":["sandbox:backup-key-installers"]},"object":object}),
    )?;
    assert!(service.decide(&request).await.is_ok());
    let original = request.clone();
    for operation in ["UPDATE", "DELETE"] {
        request = original.clone();
        request.operation = operation.into();
        request.old_object = request.object.clone();
        assert!(service.decide(&request).await.is_err());
    }
    for username in [
        "system:serviceaccount:sandbox-system:attacker",
        "system:masters",
    ] {
        request = original.clone();
        request.user_info.username = username.into();
        assert!(service.decide(&request).await.is_err());
    }
    request = original.clone();
    request.user_info.groups.clear();
    assert!(service.decide(&request).await.is_err());
    request = original.clone();
    request.object.as_mut().context("object")?["metadata"]["ownerReferences"] =
        json!([{"kind":"Pod"}]);
    assert!(service.decide(&request).await.is_err());
    let mut tx = p.f.base.f.owner_transaction().await?;
    sqlx::query("UPDATE backup_profiles SET enabled=false WHERE id=$1")
        .bind(p.f.profile)
        .execute(&mut *tx)
        .await?;
    // Pre-prefix historical records are protected too; disabling/re-certifying a
    // profile cannot accidentally turn its old key name into an unprotected one.
    sqlx::query("INSERT INTO backup_profiles(id,cluster_epoch,enabled,certification_sha256,certified_until,image,snapshot_class,clone_storage_class,password_secret,signing_private_secret,signing_public_secret,settings) SELECT $2,cluster_epoch,false,certification_sha256,certified_until,image,snapshot_class,clone_storage_class,'legacy-backup-key',signing_private_secret,signing_public_secret,settings FROM backup_profiles WHERE id=$1")
        .bind(p.f.profile).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    tx.commit().await?;
    for (name, operation) in [
        p.plan.cloud.secret_bindings.password.name.as_str(),
        "legacy-backup-key",
    ]
    .into_iter()
    .flat_map(|name| ["CREATE", "UPDATE", "DELETE"].map(|operation| (name, operation)))
    {
        request = original.clone();
        request.name = name.to_owned();
        request.operation = operation.into();
        request.object.as_mut().context("object")?["metadata"]["name"] = json!(request.name);
        request.old_object = request.object.clone();
        assert!(service.decide(&request).await.is_err());
    }
    Ok(())
}
