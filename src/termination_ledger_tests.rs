//! Real PostgreSQL + real authenticated TLS, with explicitly mocked Kube/host
//! observations. This validates the trust/ledger boundary, not a real Kata VM.
use super::*;
use crate::test_support_db::{
    self, Fixture, VerifiedFixtureConnections, VerifiedRuntimeDatabase, api_failure,
    require_pg_error,
};
use crate::{
    domain::InstanceAction,
    model::{CreateExecution, ExecutionTimeoutPolicy, StartRequest},
    runtime::KubernetesRuntime,
    runtime_manifest::{RuntimeManifestConfig, build_manifests, network_policy_name, pvc_name},
    termination_client::{TerminationObservation, test_support::FixtureGuard},
    termination_runtime::{TerminationRuntime, VerifiedLaunchResources},
};
use anyhow::{Context, ensure};
use axum::{
    body::Body,
    http::{Request, Response},
};
use kube::{Client, client::Body as KubeBody};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};

pub(crate) struct FixtureRuntime {
    pub(crate) f: Fixture,
    pub(crate) engine: OperationEngine,
    pub(crate) node: NodeBinding,
    pub(crate) launch: LaunchBinding,
    pub(crate) create_op: Uuid,
    pub(crate) guard: FixtureGuard,
}
impl FixtureRuntime {
    pub(crate) async fn observe_resources(&self) -> anyhow::Result<VerifiedLaunchResources> {
        self.observe_resources_with(None, "fixture-pod-rv", "fixture-class-rv")
            .await
    }

    pub(crate) async fn observe_resources_with(
        &self,
        overhead: Option<&serde_json::Value>,
        pod_rv: &str,
        class_rv: &str,
    ) -> anyhow::Result<VerifiedLaunchResources> {
        let target = self
            .engine
            .database
            .load_termination_target(self.f.actor.tenant_id, self.create_op)
            .await
            .map_err(api_failure)?;
        let context = &target.context;
        let known = target
            .known_resources
            .context("recorded runtime resources")?;
        let config = RuntimeManifestConfig {
            runtime_class_name: "kata-qemu".into(),
            dns_namespace: "kube-system".into(),
            dns_labels: [("k8s-app".into(), "kube-dns".into())].into(),
            ephemeral_storage_mib: 1024,
            tmp_size_mib: 256,
        };
        let manifests = build_manifests(context, &config)?;
        let mut pod = serde_json::to_value(manifests.pod)?;
        pod["metadata"]["uid"] = json!(self.launch.pod_uid);
        pod["metadata"]["resourceVersion"] = json!(pod_rv);
        pod["spec"]["nodeName"] = json!(self.node.node_name);
        if let Some(overhead) = overhead {
            pod["spec"]["overhead"] = overhead.clone();
        }
        let mut pvc = serde_json::to_value(manifests.pvc)?;
        pvc["metadata"]["uid"] = json!(self.launch.pvc_uid);
        pvc["spec"]["volumeName"] = json!(self.launch.pv_name);
        pvc["status"] = json!({"phase":"Bound"});
        let mut policy = serde_json::to_value(manifests.network_policy)?;
        policy["metadata"]["uid"] = json!(known.policy_uid);
        let mut objects = test_support_db::runtime_class_guard::objects(overhead);
        objects
            .get_mut("/apis/node.k8s.io/v1/runtimeclasses/kata-qemu")
            .context("class fixture")?["metadata"]["resourceVersion"] = json!(class_rv);
        objects.extend(BTreeMap::from([
            (format!("/api/v1/namespaces/{}", context.namespace), json!({
                "apiVersion":"v1","kind":"Namespace","metadata":{"name":context.namespace,
                "labels":{"sandbox.platform/managed":"true","sandbox.platform/tenant-id":context.tenant_id,"sandbox.platform/project-id":context.project_id,"sandbox.platform/cluster-epoch":context.cluster_epoch},
                "annotations":{"sandbox.platform/certification-id":"test-resource-observation"}}})),
            (format!("/apis/networking.k8s.io/v1/namespaces/{}/networkpolicies/sandbox-default-deny",context.namespace),json!({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"sandbox-default-deny","namespace":context.namespace},"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"]}})),
            (format!("/apis/cilium.io/v2/namespaces/{}/ciliumnetworkpolicies/{}",context.namespace,network_policy_name(context.workspace_id)),policy),
            (format!("/api/v1/namespaces/{}/pods/{}",context.namespace,self.launch.pod_name),pod),
            (format!("/api/v1/namespaces/{}/persistentvolumeclaims/{}",context.namespace,pvc_name(context.workspace_id)),pvc),
            (format!("/api/v1/persistentvolumes/{}",self.launch.pv_name),json!({"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":self.launch.pv_name,"uid":self.launch.pv_uid},"spec":{"storageClassName":context.storage_class,"volumeMode":"Filesystem","accessModes":["ReadWriteOnce"],"persistentVolumeReclaimPolicy":"Retain","csi":{"driver":"diskplugin.csi.alibabacloud.com","volumeHandle":self.launch.csi_volume_handle},"claimRef":{"kind":"PersistentVolumeClaim","uid":self.launch.pvc_uid,"namespace":context.namespace,"name":pvc_name(context.workspace_id)}},"status":{"phase":"Bound"}})),
            (format!("/api/v1/nodes/{}",self.node.node_name),json!({"apiVersion":"v1","kind":"Node","metadata":{"name":self.node.node_name,"uid":self.node.node_uid,"labels":{"sandbox.platform/worker-pool":"kata"},"annotations":{"sandbox.platform/runtime-profile-sha256":self.node.profile_sha256}},"spec":{"taints":[{"key":"sandbox.platform/untrusted","value":"true","effect":"NoSchedule"}]},"status":{"conditions":[{"type":"Ready","status":"True"}],"nodeInfo":{"architecture":"arm64","bootID":self.node.boot_id,"containerRuntimeVersion":"containerd://fixture","kernelVersion":"fixture","kubeProxyVersion":"fixture","kubeletVersion":"v1.35.0","machineID":"fixture","operatingSystem":"linux","osImage":"fixture","systemUUID":"fixture"}}})),
        ]));
        let service = tower::service_fn(move |request: Request<KubeBody>| {
            let value = if request.method() == axum::http::Method::GET {
                objects.get(request.uri().path()).cloned()
            } else {
                None
            };
            async move {
                let (code, body) = match value {
                    Some(body) => (200, body),
                    None => (
                        404,
                        json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","message":"fixture resource missing","code":404}),
                    ),
                };
                let mut response = Response::new(Body::from(body.to_string()));
                *response.status_mut() = axum::http::StatusCode::from_u16(code)
                    .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
                response.headers_mut().insert(
                    "content-type",
                    axum::http::HeaderValue::from_static("application/json"),
                );
                Ok::<_, Infallible>(response)
            }
        });
        let runtime = TerminationRuntime::new(
            KubernetesRuntime::from_client(Client::new(service, "fixture")),
            config,
            "test-resource-observation".into(),
        );
        let observed = runtime.observe_launch(context, &known).await?;
        ensure!(
            observed.node == self.node && observed.launch == self.launch,
            "resource fixture must pass the original exact launch/node checks"
        );
        Ok(observed.resources)
    }

    pub(crate) async fn new(register: bool) -> anyhow::Result<Self> {
        Self::with_certification(register, Some(Utc::now() + Duration::days(2))).await
    }
    async fn with_certification(
        register: bool,
        expiry: Option<DateTime<Utc>>,
    ) -> anyhow::Result<Self> {
        Self::with_certification_inner(register, expiry, None).await
    }
    pub(crate) async fn new_with_verified_connections(
        register: bool,
        fixture: &VerifiedFixtureConnections,
        termination: &VerifiedRuntimeDatabase,
    ) -> anyhow::Result<Self> {
        Self::with_certification_inner(
            register,
            Some(Utc::now() + Duration::days(2)),
            Some((fixture, termination)),
        )
        .await
    }
    async fn with_certification_inner(
        register: bool,
        expiry: Option<DateTime<Utc>>,
        verified: Option<(&VerifiedFixtureConnections, &VerifiedRuntimeDatabase)>,
    ) -> anyhow::Result<Self> {
        let (mut f, db) = if let Some((fixture, termination)) = verified {
            (
                Fixture::new_with_verified_connections(10, fixture).await?,
                termination.database_for("sandbox_termination")?,
            )
        } else {
            let f = Fixture::new(10).await?;
            sqlx::raw_sql(include_str!("../scripts/sql/termination-role.sql"))
                .execute(&f.owner)
                .await?;
            let url = std::env::var("TEST_TERMINATION_DATABASE_URL")
                .context("TEST_TERMINATION_DATABASE_URL required")?;
            let actual = url::Url::parse(&url)?;
            let expected = url::Url::parse(&std::env::var("TEST_DATABASE_URL")?)?;
            ensure!(
                actual.username() == "sandbox_termination"
                    && actual.path().ends_with("_test")
                    && actual.host_str() == expected.host_str()
                    && actual.port_or_known_default() == expected.port_or_known_default()
                    && actual.path() == expected.path(),
                "isolated termination role must use disposable test DB"
            );
            let db = Database::connect(&url, 5).await?;
            db.verify_runtime_role().await?;
            (f, db)
        };
        // This fixture now exercises the production Kubernetes verifier. Seed
        // an approved policy supported by that verifier before accepting its
        // instance; the generic database fixture's empty policy is insufficient.
        let policy = Uuid::new_v4();
        let mut tx = f.owner_transaction().await?;
        sqlx::query("INSERT INTO security_policy_versions(id,tenant_id,name,version,status,rules) VALUES($1,$2,'termination-deny-all',1,'APPROVED',$3)")
            .bind(policy).bind(f.actor.tenant_id).bind(json!({"profile":"deny-all","dns":true}))
            .execute(&mut *tx).await?;
        tx.commit().await?;
        f.request.security_profile_id = policy;
        let engine = OperationEngine::new(db, format!("termination-test-{}", Uuid::new_v4()))?;
        let created = f
            .create("termination-instance")
            .await
            .map_err(api_failure)?;
        let instance = &created.body.resource;
        let mut tx = f.owner_transaction().await?;
        let (epoch,launch_id,namespace,pod_name):(Uuid,Uuid,String,String)=sqlx::query_as("SELECT cluster_epoch,launch_id,namespace,pod_name FROM instances WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(instance.id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        let mut node = crate::termination_client::test_support::node();
        node.cluster_epoch = epoch;
        let launch = LaunchBinding {
            purpose: crate::nodeguard::protocol::LaunchPurpose::Workload,
            tenant_id: f.actor.tenant_id,
            project_id: instance.project_id,
            instance_id: instance.id,
            workspace_id: instance.workspace_id,
            generation: instance.runtime_generation,
            launch_id,
            pod_uid: Uuid::new_v4(),
            namespace,
            pod_name,
            pvc_uid: Uuid::new_v4(),
            pv_uid: Uuid::new_v4(),
            pv_name: format!("pvc-{}", Uuid::new_v4()),
            csi_volume_handle: format!("d-{}", Uuid::new_v4().simple()),
        };
        let mut tx = f.owner_transaction().await?;
        sqlx::query("UPDATE runtime_nodes SET enabled=false WHERE cluster_epoch=$1 AND node_uid=$2 AND enabled").bind(node.cluster_epoch).bind(node.node_uid).execute(&mut *tx).await?;
        let node_id: Uuid = sqlx::query_scalar("INSERT INTO runtime_nodes(cluster_epoch,node_uid,node_name,cloud_provider,cloud_account_id,region,cloud_instance_id,private_ip,guard_port,profile_sha256,boot_id,enabled) VALUES($1,$2,$3,'alicloud','1234567890123456','cn-hangzhou',$4,'10.2.3.4',9444,$5,$6,true) RETURNING id")
            .bind(node.cluster_epoch).bind(node.node_uid).bind(&node.node_name).bind(format!("i-{}",Uuid::new_v4())).bind(&node.profile_sha256).bind(node.boot_id).fetch_one(&mut *tx).await?;
        if let Some(expiry) = expiry {
            test_support_db::seed_test_node_certification(&mut tx, node_id, expiry).await?;
        }
        sqlx::query("UPDATE instances SET pod_uid=$3 WHERE tenant_id=$1 AND id=$2")
            .bind(f.actor.tenant_id)
            .bind(instance.id)
            .bind(launch.pod_uid)
            .execute(&mut *tx)
            .await?;
        for (kind, uid, generation, owner) in [
            (
                "POD",
                launch.pod_uid,
                instance.runtime_generation,
                instance.id,
            ),
            ("PVC", launch.pvc_uid, 1, instance.workspace_id),
            ("CILIUM_POLICY", Uuid::new_v4(), 1, instance.id),
        ] {
            sqlx::query("INSERT INTO external_resources(tenant_id,project_id,operation_id,instance_id,workspace_id,provider,kind,provider_id,generation,owner_id,status) VALUES($1,$2,$3,$4,$5,'kubernetes',$6,$7,$8,$9,'ACTIVE')")
                .bind(f.actor.tenant_id).bind(instance.project_id).bind(created.body.operation.id).bind(instance.id).bind(instance.workspace_id).bind(kind).bind(uid.to_string()).bind(generation).bind(owner).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        let guard = FixtureGuard::start(node.clone()).await?;
        let result = Self {
            f,
            engine,
            node,
            launch,
            create_op: created.body.operation.id,
            guard,
        };
        if register {
            let permit = result
                .engine
                .database
                .prepare_launch_permit(
                    result.f.actor.tenant_id,
                    result.create_op,
                    &result.node,
                    &result.launch,
                )
                .await
                .map_err(api_failure)?;
            let ack = result.guard.client.register(&permit.request).await?;
            result
                .engine
                .database
                .record_launch_registration(&permit, &ack, &result.observe_resources().await?)
                .await
                .map_err(api_failure)?;
        }
        Ok(result)
    }
    pub(crate) async fn running(&self) -> anyhow::Result<()> {
        self.f
            .seed_observed_state(self.launch.instance_id, "RUNNING")
            .await
    }
    pub(crate) async fn accept(&self, action: InstanceAction) -> anyhow::Result<Claim> {
        let instance = self
            .f
            .database
            .get_instance(&self.f.actor, self.launch.instance_id)
            .await
            .map_err(api_failure)?;
        let accepted = self
            .f
            .database
            .lifecycle_action(
                &self.f.actor,
                self.launch.instance_id,
                action,
                &StartRequest { ttl_seconds: None },
                &Uuid::new_v4().to_string(),
                instance.spec_version,
                300,
                86400,
            )
            .await
            .map_err(api_failure)?;
        let mut tx = self.f.owner_transaction().await?;
        sqlx::query("UPDATE operations SET next_attempt_at=(SELECT COALESCE(min(eligible_at),clock_timestamp())-interval '1 day' FROM operation_dispatch WHERE queue_role='TERMINATION') WHERE tenant_id=$1 AND id=$2").bind(self.f.actor.tenant_id).bind(accepted.body.operation.id).execute(&mut *tx).await?;
        tx.commit().await?;
        let claim = self
            .engine
            .claim_termination()
            .await
            .map_err(api_failure)?
            .context("termination claim")?;
        ensure!(
            claim.operation_id == accepted.body.operation.id,
            "test must claim own prioritized op"
        );
        Ok(claim)
    }
    pub(crate) async fn proof(
        &self,
        claim: &Claim,
    ) -> anyhow::Result<(VerifiedLocalTermination, Uuid)> {
        let challenge = self
            .engine
            .database
            .prepare_termination_challenge(&self.engine, claim)
            .await
            .map_err(api_failure)?;
        let TerminationObservation::Verified(proof) =
            self.guard.client.close(&challenge.request).await?
        else {
            anyhow::bail!("expected mock trusted observation")
        };
        let id = self
            .engine
            .database
            .record_local_termination(&self.engine, claim, &proof)
            .await
            .map_err(api_failure)?;
        Ok((proof, id))
    }
    pub(crate) async fn pending_dimension(&self, dimension: &str) -> anyhow::Result<i64> {
        let mut tx = self.f.owner_transaction().await?;
        let total:i64=sqlx::query_scalar("SELECT COALESCE(sum(pending+allocated),0)::bigint FROM quota_accounts WHERE tenant_id=$1 AND dimension=$2")
            .bind(self.f.actor.tenant_id).bind(dimension).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(total)
    }
}
pub(crate) fn cleanup_runtime(
    launch: &LaunchBinding,
    attached: bool,
) -> (TerminationRuntime, Arc<Mutex<Vec<String>>>) {
    let binding = launch.clone();
    let requests = Arc::new(Mutex::new(vec![]));
    let seen = requests.clone();
    let service = tower::service_fn(move |request: Request<KubeBody>| {
        let l = binding.clone();
        let seen = seen.clone();
        async move {
            let path = request.uri().path().to_owned();
            if let Ok(mut requests) = seen.lock() {
                requests.push(path.clone());
            }
            let (status, value) = if path.contains("/pods/") {
                (
                    404,
                    json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}),
                )
            } else if path.contains("/persistentvolumeclaims/") {
                (
                    200,
                    json!({"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":{"name":format!("ws-{}",l.workspace_id),"namespace":l.namespace,"uid":l.pvc_uid},"spec":{"volumeName":l.pv_name},"status":{"phase":"Bound"}}),
                )
            } else if path.contains("/persistentvolumes/") {
                (
                    200,
                    json!({"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":l.pv_name,"uid":l.pv_uid},"spec":{"csi":{"driver":"diskplugin.csi.alibabacloud.com","volumeHandle":l.csi_volume_handle},"volumeMode":"Filesystem","accessModes":["ReadWriteOnce"],"persistentVolumeReclaimPolicy":"Retain","claimRef":{"uid":l.pvc_uid,"namespace":l.namespace,"name":format!("ws-{}",l.workspace_id)}}}),
                )
            } else if path == "/apis/storage.k8s.io/v1/volumeattachments" {
                (
                    200,
                    json!({"apiVersion":"storage.k8s.io/v1","kind":"VolumeAttachmentList","metadata":{},"items":if attached{vec![json!({"metadata":{"name":"still-attached"},"spec":{"attacher":"diskplugin.csi.alibabacloud.com","nodeName":"old-node","source":{"persistentVolumeName":l.pv_name}}})]}else{vec![]}}),
                )
            } else {
                (500, json!({"message":"unexpected mock route"}))
            };
            Ok::<_, Infallible>(
                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(Body::from(value.to_string()))
                    .unwrap_or_else(|_| Response::new(Body::empty())),
            )
        }
    });
    (
        TerminationRuntime::new(
            KubernetesRuntime::from_client(Client::new(service, "test")),
            RuntimeManifestConfig {
                runtime_class_name: "kata-qemu".into(),
                dns_namespace: "kube-system".into(),
                dns_labels: BTreeMap::from([("k8s-app".into(), "kube-dns".into())]),
                ephemeral_storage_mib: 1024,
                tmp_size_mib: 256,
            },
            "test-certification".into(),
        ),
        requests,
    )
}
#[tokio::test]
#[ignore = "Requires local PostgreSQL and dedicated TEST_TERMINATION_DATABASE_URL plus real loopback mTLS"]
async fn verified_stop_releases_compute_and_unknown_execution_only_after_volume_cleanup()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = FixtureRuntime::new(true).await?;
    f.running().await?;
    let mut tx = f.f.owner_transaction().await?;
    for action in ["executions:create", "executions:read"] {
        sqlx::query(
            "INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4)",
        )
        .bind(f.f.actor.tenant_id)
        .bind(f.launch.project_id)
        .bind(f.f.actor.principal_id)
        .bind(action)
        .execute(&mut *tx)
        .await?;
    }
    for project in [None, Some(f.launch.project_id)] {
        sqlx::query("INSERT INTO quota_accounts(tenant_id,project_id,dimension,limit_value) VALUES($1,$2,'EXECUTIONS',10)").bind(f.f.actor.tenant_id).bind(project).execute(&mut *tx).await?;
    }
    sqlx::query("UPDATE instances SET ready_generation=runtime_generation,ready_launch_id=launch_id,ready_pod_uid=pod_uid,ready_cluster_epoch=cluster_epoch,ready_observed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(f.f.actor.tenant_id).bind(f.launch.instance_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let instance =
        f.f.database
            .get_instance(&f.f.actor, f.launch.instance_id)
            .await
            .map_err(api_failure)?;
    let execution =
        f.f.database
            .create_execution(
                &f.f.actor,
                instance.id,
                &CreateExecution {
                    argv: vec!["/usr/bin/true".into()],
                    public_env: Default::default(),
                    cwd: "/workspace".into(),
                    timeout_seconds: 60,
                    on_timeout: ExecutionTimeoutPolicy::HardStopInstance,
                    output_limit_bytes: 1024,
                    client_reference: None,
                },
                "terminal-test",
                instance.spec_version,
            )
            .await
            .map_err(api_failure)?
            .body
            .resource;
    let mut tx = f.f.owner_transaction().await?;
    sqlx::query("UPDATE executions SET dispatch_attempt_id=gen_random_uuid(),dispatch_attempted_at=clock_timestamp(),dispatch_lease_token=1,status='DISPATCHING' WHERE tenant_id=$1 AND id=$2").bind(f.f.actor.tenant_id).bind(execution.id).execute(&mut *tx).await?;
    sqlx::query("UPDATE executions SET status='OUTCOME_UNKNOWN',termination_status='UNKNOWN' WHERE tenant_id=$1 AND id=$2").bind(f.f.actor.tenant_id).bind(execution.id).execute(&mut *tx).await?;
    tx.commit().await?;
    let claim = f.accept(InstanceAction::Stop).await?;
    let (proof, id) = f.proof(&claim).await?;
    let (pending, _) = cleanup_runtime(&f.launch, true);
    assert!(pending.cleanup(&proof).await?.is_none());
    assert_eq!(f.pending_dimension("CPU_MILLIS").await?, 2000);
    assert_eq!(f.pending_dimension("EXECUTIONS").await?, 2);
    let (runtime, _) = cleanup_runtime(&f.launch, false);
    let cleanup = runtime.cleanup(&proof).await?.context("safe cleanup")?;
    let (left, right) = tokio::join!(
        f.engine
            .database
            .complete_termination(&f.engine, &claim, id, &cleanup),
        f.engine
            .database
            .complete_termination(&f.engine, &claim, id, &cleanup)
    );
    assert_eq!(
        [&left, &right]
            .iter()
            .filter(|r| matches!(r, Ok(TerminationCompletion::Stopped)))
            .count(),
        1
    );
    assert_eq!([&left, &right].iter().filter(|r| r.is_err()).count(), 1);
    for dimension in ["CPU_MILLIS", "MEMORY_MIB", "EXECUTIONS"] {
        assert_eq!(f.pending_dimension(dimension).await?, 0);
    }
    assert_eq!(f.pending_dimension("INSTANCES").await?, 2);
    assert_eq!(f.pending_dimension("WORKSPACE_GIB").await?, 40);
    let got =
        f.f.database
            .get_execution(&f.f.actor, execution.id)
            .await
            .map_err(api_failure)?;
    assert_eq!(got.status, "OUTCOME_UNKNOWN");
    assert_eq!(got.termination_status, "CONFIRMED");
    assert!(!got.slot_held);
    let mut tx = f.f.owner_transaction().await?;
    let ws: String =
        sqlx::query_scalar("SELECT status FROM workspaces WHERE tenant_id=$1 AND id=$2")
            .bind(f.f.actor.tenant_id)
            .bind(f.launch.workspace_id)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(ws, "AVAILABLE");
    tx.commit().await?;
    assert!(
        f.engine
            .database
            .complete_termination(&f.engine, &claim, id, &cleanup)
            .await
            .is_err()
    );
    assert_eq!(f.pending_dimension("CPU_MILLIS").await?, 0);
    f.guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires PostgreSQL, dedicated termination role and loopback mTLS"]
async fn old_unregistered_launch_and_unprivileged_proof_writes_fail_closed() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = FixtureRuntime::new(false).await?;
    f.running().await?;
    let claim = f.accept(InstanceAction::Stop).await?;
    assert!(
        matches!(f.engine.database.prepare_termination_challenge(&f.engine,&claim).await,Err(e) if e.code=="LAUNCH_NOT_REGISTERED")
    );
    assert_eq!(f.pending_dimension("CPU_MILLIS").await?, 2000);
    let mut tx =
        f.f.database
            .begin(f.f.actor.tenant_id)
            .await
            .map_err(api_failure)?;
    require_pg_error(
        sqlx::query("INSERT INTO local_termination_proofs DEFAULT VALUES")
            .execute(&mut *tx)
            .await,
        "42501",
    )?;
    tx.rollback().await?;
    let mut tx =
        f.f.database
            .begin(f.f.actor.tenant_id)
            .await
            .map_err(api_failure)?;
    require_pg_error(
        sqlx::query("UPDATE instances SET observed_state='STOPPED' WHERE tenant_id=$1 AND id=$2")
            .bind(f.f.actor.tenant_id)
            .bind(f.launch.instance_id)
            .execute(&mut *tx)
            .await,
        "42501",
    )?;
    tx.rollback().await?;
    let mut tx = f.f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET status='CANCELLED',completed_at=clock_timestamp(),lease_owner=NULL,lease_until=NULL WHERE tenant_id=$1 AND id=$2").bind(f.f.actor.tenant_id).bind(claim.operation_id).execute(&mut *tx).await?;
    tx.commit().await?;
    f.guard.shutdown().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "Requires PostgreSQL, dedicated termination role and loopback mTLS"]
async fn restart_is_new_generation_only_after_fresh_authority_and_delete_keeps_storage()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    for (action, revoke, expected) in [
        (
            InstanceAction::Restart,
            false,
            TerminationCompletion::RestartQueued,
        ),
        (
            InstanceAction::Restart,
            true,
            TerminationCompletion::RestartBlocked,
        ),
        (
            InstanceAction::Delete,
            false,
            TerminationCompletion::InstanceDeleted,
        ),
    ] {
        let f = FixtureRuntime::new(true).await?;
        f.running().await?;
        let claim = f.accept(action).await?;
        if revoke {
            let mut tx = f.f.owner_transaction().await?;
            sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='instances:restart'").bind(f.f.actor.tenant_id).bind(f.f.actor.principal_id).execute(&mut *tx).await?;
            tx.commit().await?;
        }
        let (proof, id) = f.proof(&claim).await?;
        let (runtime, _) = cleanup_runtime(&f.launch, false);
        let cleanup = runtime.cleanup(&proof).await?.context("cleanup")?;
        assert_eq!(
            f.engine
                .database
                .complete_termination(&f.engine, &claim, id, &cleanup)
                .await
                .map_err(api_failure)?,
            expected
        );
        let mut tx = f.f.owner_transaction().await?;
        let observed:(i64,Uuid,String,Option<Uuid>)=sqlx::query_as("SELECT runtime_generation,launch_id,observed_state,active_operation_id FROM instances WHERE tenant_id=$1 AND id=$2").bind(f.f.actor.tenant_id).bind(f.launch.instance_id).fetch_one(&mut *tx).await?;
        let route: Option<String> =
            sqlx::query_scalar("SELECT queue_role FROM operation_dispatch WHERE operation_id=$1")
                .bind(claim.operation_id)
                .fetch_optional(&mut *tx)
                .await?;
        let old_releases: i64 = sqlx::query_scalar("SELECT count(*) FROM quota_resource_receipts r JOIN launch_quota_bindings b ON(b.tenant_id,b.reservation_id)=(r.tenant_id,r.reservation_id) JOIN launch_resource_contracts c ON(c.tenant_id,c.id)=(b.tenant_id,b.contract_id) WHERE r.tenant_id=$1 AND c.instance_id=$2 AND c.launch_id=$3 AND r.status='RELEASED' AND r.purpose='ORDINARY_COMPUTE'")
            .bind(f.f.actor.tenant_id).bind(f.launch.instance_id).bind(f.launch.launch_id).fetch_one(&mut *tx).await?;
        ensure!(
            old_releases == 4,
            "trusted cleanup releases only reservations owned by the old launch"
        );
        let new_pending: Vec<(Uuid,i64,i64)> = sqlx::query_as("SELECT c.launch_id,c.generation,count(*) FROM quota_resource_receipts r JOIN launch_quota_bindings b ON(b.tenant_id,b.reservation_id)=(r.tenant_id,r.reservation_id) JOIN launch_resource_contracts c ON(c.tenant_id,c.id)=(b.tenant_id,b.contract_id) WHERE r.tenant_id=$1 AND c.instance_id=$2 AND c.operation_id=$3 AND r.status='PENDING' AND r.purpose='ORDINARY_COMPUTE' GROUP BY c.launch_id,c.generation")
            .bind(f.f.actor.tenant_id).bind(f.launch.instance_id).bind(claim.operation_id).fetch_all(&mut *tx).await?;
        if expected == TerminationCompletion::RestartQueued {
            assert_eq!(observed.0, f.launch.generation + 1);
            assert_ne!(observed.1, f.launch.launch_id);
            assert_eq!(observed.2, "PENDING");
            assert_eq!(route.as_deref(), Some("WORKER"));
            ensure!(
                new_pending == vec![(observed.1, observed.0, 4)],
                "restart's pending receipts belong to the committed new launch"
            );
        } else {
            ensure!(
                new_pending.is_empty(),
                "blocked restart and delete must not acquire a new compute contract"
            );
            assert_eq!(observed.0, f.launch.generation);
            assert_eq!(observed.1, f.launch.launch_id);
            assert_eq!(
                observed.2,
                if expected == TerminationCompletion::InstanceDeleted {
                    "DELETED"
                } else {
                    "STOPPED"
                }
            );
        }
        // Dispose this test's still-queued restart/deletion intent without changing quotas.
        sqlx::query("UPDATE operations SET status='CANCELLED',completed_at=clock_timestamp(),lease_owner=NULL,lease_until=NULL WHERE tenant_id=$1 AND id=$2 AND status IN('QUEUED','WAITING','RUNNING')").bind(f.f.actor.tenant_id).bind(claim.operation_id).execute(&mut *tx).await?;
        tx.commit().await?;
        assert_eq!(f.pending_dimension("WORKSPACE_GIB").await?, 40);
        assert_eq!(
            f.pending_dimension("INSTANCES").await?,
            if expected == TerminationCompletion::InstanceDeleted {
                0
            } else {
                2
            }
        );
        assert_eq!(
            f.pending_dimension("CPU_MILLIS").await?,
            if expected == TerminationCompletion::RestartQueued {
                2000
            } else {
                0
            }
        );
        f.guard.shutdown().await?;
    }
    Ok(())
}
#[tokio::test]
#[ignore = "Requires PostgreSQL, dedicated termination role and loopback mTLS"]
async fn stale_challenge_foreign_launch_and_regressed_node_journal_cannot_release_resources()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = FixtureRuntime::new(true).await?;
    f.running().await?;
    let claim = f.accept(InstanceAction::Stop).await?;
    let challenge = f
        .engine
        .database
        .prepare_termination_challenge(&f.engine, &claim)
        .await
        .map_err(api_failure)?;
    for mutation in 0..4 {
        let mut foreign = challenge.request.clone();
        match mutation {
            0 => foreign.launch.tenant_id = Uuid::new_v4(),
            1 => foreign.launch.generation += 1,
            2 => foreign.launch.launch_id = Uuid::new_v4(),
            _ => foreign.launch.pod_uid = Uuid::new_v4(),
        }
        let TerminationObservation::Verified(proof) = f.guard.client.close(&foreign).await? else {
            anyhow::bail!("expected trusted wire response")
        };
        assert!(
            matches!(f.engine.database.record_local_termination(&f.engine,&claim,&proof).await,
            Err(e) if e.code=="TERMINATION_EVIDENCE_MISMATCH")
        );
    }
    let mut foreign_node = f.node.clone();
    foreign_node.boot_id = Uuid::new_v4();
    let other_guard = FixtureGuard::start(foreign_node.clone()).await?;
    let mut wrong_node = challenge.request.clone();
    wrong_node.node = foreign_node;
    let TerminationObservation::Verified(proof) = other_guard.client.close(&wrong_node).await?
    else {
        anyhow::bail!("expected separately authenticated node response")
    };
    assert!(
        matches!(f.engine.database.record_local_termination(&f.engine,&claim,&proof).await,
        Err(e) if e.code=="TERMINATION_EVIDENCE_MISMATCH")
    );
    other_guard.shutdown().await?;
    let TerminationObservation::Verified(proof) = f.guard.client.close(&challenge.request).await?
    else {
        anyhow::bail!("expected proof")
    };
    let mut tx = f.f.owner_transaction().await?;
    sqlx::query("UPDATE runtime_node_journal_highwater SET max_revision=100 WHERE runtime_node_id=(SELECT runtime_node_id FROM launch_permits WHERE tenant_id=$1 AND id=$2)").bind(f.f.actor.tenant_id).bind(challenge.permit.request.permit_id).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(
        matches!(f.engine.database.record_local_termination(&f.engine,&claim,&proof).await,Err(e) if e.code=="NODE_JOURNAL_REGRESSED")
    );
    let stale = Claim {
        lease_token: claim.lease_token + 1,
        ..claim.clone()
    };
    assert!(
        f.engine
            .database
            .record_local_termination(&f.engine, &stale, &proof)
            .await
            .is_err()
    );
    assert_eq!(f.pending_dimension("CPU_MILLIS").await?, 2000);
    let mut tx = f.f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET status='CANCELLED',completed_at=clock_timestamp(),lease_owner=NULL,lease_until=NULL WHERE tenant_id=$1 AND id=$2").bind(f.f.actor.tenant_id).bind(claim.operation_id).execute(&mut *tx).await?;
    tx.commit().await?;
    f.guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires PostgreSQL, dedicated termination role and loopback mTLS"]
async fn expired_challenge_cannot_be_extended_by_worker_heartbeat() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = FixtureRuntime::new(true).await?;
    f.running().await?;
    let claim = f.accept(InstanceAction::Stop).await?;
    let mut tx = f.f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET lease_until=clock_timestamp()+interval '2 seconds' WHERE tenant_id=$1 AND id=$2")
        .bind(f.f.actor.tenant_id).bind(claim.operation_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let challenge = f
        .engine
        .database
        .prepare_termination_challenge(&f.engine, &claim)
        .await
        .map_err(api_failure)?;
    let TerminationObservation::Verified(proof) = f.guard.client.close(&challenge.request).await?
    else {
        anyhow::bail!("expected private mTLS proof")
    };
    assert!(f.engine.heartbeat(&claim).await.map_err(api_failure)?);
    // Challenge lifetime is immutable even while the independent worker lease renews.
    let remaining = (challenge.request.challenge_expires_at - Utc::now())
        .to_std()
        .unwrap_or_default();
    tokio::time::sleep(remaining + std::time::Duration::from_millis(50)).await;
    assert!(
        matches!(f.engine.database.record_local_termination(&f.engine,&claim,&proof).await,
        Err(e) if e.code=="TERMINATION_CHALLENGE_STALE")
    );
    assert_eq!(f.pending_dimension("CPU_MILLIS").await?, 2000);
    let mut tx = f.f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET status='CANCELLED',completed_at=clock_timestamp(),lease_owner=NULL,lease_until=NULL WHERE tenant_id=$1 AND id=$2")
        .bind(f.f.actor.tenant_id).bind(claim.operation_id).execute(&mut *tx).await?;
    tx.commit().await?;
    f.guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires PostgreSQL, dedicated termination role and loopback mTLS"]
async fn starting_renewal_uses_immutable_extension_and_out_of_order_ack_cannot_regress()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = FixtureRuntime::new(true).await?;
    let mut tx = f.f.owner_transaction().await?;
    sqlx::query("UPDATE instances SET observed_state='STARTING' WHERE tenant_id=$1 AND id=$2")
        .bind(f.f.actor.tenant_id)
        .bind(f.launch.instance_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let base = f
        .engine
        .database
        .prepare_launch_authorization(f.f.actor.tenant_id, f.create_op, &f.node, &f.launch)
        .await
        .map_err(api_failure)?;
    let mut authorizations = vec![];
    for _ in 0..2 {
        let current =
            f.f.database
                .get_instance(&f.f.actor, f.launch.instance_id)
                .await
                .map_err(api_failure)?;
        let renewed =
            f.f.database
                .renew_instance(
                    &f.f.actor,
                    current.id,
                    &crate::model::RenewRequest {
                        expires_at: current.compute_lease_expires_at + Duration::seconds(300),
                    },
                    &Uuid::new_v4().to_string(),
                    current.spec_version,
                    86400,
                )
                .await
                .map_err(api_failure)?;
        assert_eq!(
            renewed.body.resource.runtime_generation,
            f.launch.generation
        );
        assert!(candidate_includes(&f).await?);
        let (left, right) = tokio::join!(
            f.engine.database.prepare_launch_authorization(
                f.f.actor.tenant_id,
                f.create_op,
                &f.node,
                &f.launch
            ),
            f.engine.database.prepare_launch_authorization(
                f.f.actor.tenant_id,
                f.create_op,
                &f.node,
                &f.launch
            )
        );
        let authorization = left.map_err(api_failure)?;
        assert_eq!(
            authorization.request.permit_id,
            right.map_err(api_failure)?.request.permit_id
        );
        assert_eq!(
            authorization.base_permit.request.permit_id,
            base.request.permit_id
        );
        assert_ne!(authorization.request.permit_id, base.request.permit_id);
        assert_eq!(
            authorization.request.expires_at,
            renewed.body.resource.compute_lease_expires_at
        );
        assert!(
            !ready_registered(&f).await?,
            "Ready must wait for the renewed lease ACK"
        );
        let ack = f.guard.client.register(&authorization.request).await?;
        authorizations.push((authorization, ack));
    }
    let (newest, newest_ack) = &authorizations[1];
    f.engine
        .database
        .record_launch_authorization(newest, newest_ack, &f.observe_resources().await?)
        .await
        .map_err(api_failure)?;
    assert!(!candidate_includes(&f).await?);
    assert!(
        ready_registered(&f).await?,
        "newest ACK covers the current lease"
    );
    let (older, older_ack) = &authorizations[0];
    f.engine
        .database
        .record_launch_authorization(older, older_ack, &f.observe_resources().await?)
        .await
        .map_err(api_failure)?;
    f.engine
        .database
        .record_launch_authorization(older, older_ack, &f.observe_resources().await?)
        .await
        .map_err(api_failure)?;
    assert!(!candidate_includes(&f).await?);
    assert!(
        ready_registered(&f).await?,
        "late older ACK cannot undo the valid newest ACK"
    );
    // Replaying an older idempotent host request can report a legitimately
    // longer effective permit after the newer request has already arrived.
    *f.guard
        .acknowledged_expiry
        .lock()
        .map_err(|_| anyhow::anyhow!("test fixture lock"))? = Some(newest.request.expires_at);
    let replayed_ack = f.guard.client.register(&older.request).await?;
    assert_eq!(
        replayed_ack.response().effective_expires_at,
        newest.request.expires_at
    );
    f.engine
        .database
        .record_launch_authorization(older, &replayed_ack, &f.observe_resources().await?)
        .await
        .map_err(api_failure)?;
    let mut forged = older.clone();
    forged.lease_version += 1;
    assert!(
        matches!(f.engine.database.record_launch_authorization(&forged,older_ack,&f.observe_resources().await?).await,
        Err(e) if e.code=="LAUNCH_REGISTRATION_MISMATCH")
    );
    let mut tx = f.f.owner_transaction().await?;
    let (count,expiry):(i64,DateTime<Utc>)=sqlx::query_as("SELECT count(*),max(e.expires_at) FROM launch_permit_extensions e JOIN launch_permit_extension_receipts r ON r.tenant_id=e.tenant_id AND r.extension_id=e.id WHERE e.tenant_id=$1 AND e.base_permit_id=$2")
        .bind(f.f.actor.tenant_id).bind(base.request.permit_id).fetch_one(&mut *tx).await?;
    assert_eq!(count, 2);
    assert_eq!(expiry, newest.request.expires_at);
    let saved: DateTime<Utc> =
        sqlx::query_scalar("SELECT expires_at FROM launch_permits WHERE tenant_id=$1 AND id=$2")
            .bind(f.f.actor.tenant_id)
            .bind(base.request.permit_id)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(saved, base.request.expires_at);
    tx.commit().await?;
    let mut tx =
        f.f.database
            .begin(f.f.actor.tenant_id)
            .await
            .map_err(api_failure)?;
    require_pg_error(
        sqlx::query("INSERT INTO launch_permit_extensions DEFAULT VALUES")
            .execute(&mut *tx)
            .await,
        "42501",
    )?;
    tx.rollback().await?;
    let mut tx = f
        .engine
        .database
        .begin(Uuid::new_v4())
        .await
        .map_err(api_failure)?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM launch_permit_extensions WHERE base_permit_id=$1"
        )
        .bind(base.request.permit_id)
        .fetch_one(&mut *tx)
        .await?,
        0
    );
    tx.rollback().await?;
    let claim = f.accept(InstanceAction::Stop).await?;
    assert!(
        f.engine
            .database
            .prepare_launch_authorization(f.f.actor.tenant_id, f.create_op, &f.node, &f.launch)
            .await
            .is_err()
    );
    let (proof, id) = f.proof(&claim).await?;
    let (runtime, _) = cleanup_runtime(&f.launch, false);
    let cleanup = runtime
        .cleanup(&proof)
        .await?
        .context("closed launch cleanup")?;
    assert_eq!(
        f.engine
            .database
            .complete_termination(&f.engine, &claim, id, &cleanup)
            .await
            .map_err(api_failure)?,
        TerminationCompletion::Stopped
    );
    f.guard.shutdown().await?;
    Ok(())
}

async fn ready_registered(f: &FixtureRuntime) -> anyhow::Result<bool> {
    let mut tx = f.f.owner_transaction().await?;
    let ready = sqlx::query_scalar("SELECT sandbox_launch_registered($1,$2,$3,$4,$5,$6)")
        .bind(f.f.actor.tenant_id)
        .bind(f.launch.instance_id)
        .bind(f.launch.generation)
        .bind(f.launch.launch_id)
        .bind(f.launch.pod_uid)
        .bind(f.node.cluster_epoch)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(ready)
}

async fn candidate_includes(f: &FixtureRuntime) -> anyhow::Result<bool> {
    let mut tx = f.f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET launch_registration_next_attempt_at=(SELECT COALESCE(min(launch_registration_eligible_at),clock_timestamp())-interval '1 day' FROM operation_dispatch WHERE queue_role='WORKER') WHERE tenant_id=$1 AND id=$2")
        .bind(f.f.actor.tenant_id).bind(f.create_op).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(f.engine
        .database
        .launch_registration_candidates(1)
        .await
        .map_err(api_failure)?
        .iter()
        .any(|c| c.operation_id == f.create_op && c.tenant_id == f.f.actor.tenant_id))
}

#[tokio::test]
#[ignore = "Requires PostgreSQL, dedicated termination role and loopback mTLS"]
async fn disabled_node_blocks_new_authorization_but_preserves_verified_safety_stop()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = FixtureRuntime::new(true).await?;
    let mut tx = f.f.owner_transaction().await?;
    sqlx::query("UPDATE runtime_nodes SET enabled=false WHERE node_uid=$1 AND boot_id=$2 AND cluster_epoch=$3")
        .bind(f.node.node_uid).bind(f.node.boot_id).bind(f.node.cluster_epoch).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(
        matches!(f.engine.database.prepare_launch_authorization(f.f.actor.tenant_id,f.create_op,&f.node,&f.launch).await,
        Err(e) if e.code=="NODE_NOT_ENROLLED")
    );
    let claim = f.accept(InstanceAction::Stop).await?;
    let (proof, id) = f.proof(&claim).await?;
    let (runtime, _) = cleanup_runtime(&f.launch, false);
    let cleanup = runtime
        .cleanup(&proof)
        .await?
        .context("disabled node safety cleanup")?;
    assert_eq!(
        f.engine
            .database
            .complete_termination(&f.engine, &claim, id, &cleanup)
            .await
            .map_err(api_failure)?,
        TerminationCompletion::Stopped
    );
    assert_eq!(f.pending_dimension("CPU_MILLIS").await?, 0);
    assert_eq!(f.pending_dimension("WORKSPACE_GIB").await?, 40);
    f.guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires PostgreSQL, dedicated termination role and loopback mTLS"]
async fn extension_ack_recovers_lost_base_ack_without_rewriting_base_evidence() -> anyhow::Result<()>
{
    let _serial = test_support_db::serial().await;
    let f = FixtureRuntime::new(false).await?;
    let base = f
        .engine
        .database
        .prepare_launch_authorization(f.f.actor.tenant_id, f.create_op, &f.node, &f.launch)
        .await
        .map_err(api_failure)?;
    // A real registration succeeded remotely, but its response was lost before DB commit.
    let _lost = f.guard.client.register(&base.request).await?;
    let current =
        f.f.database
            .get_instance(&f.f.actor, f.launch.instance_id)
            .await
            .map_err(api_failure)?;
    f.f.database
        .renew_instance(
            &f.f.actor,
            current.id,
            &crate::model::RenewRequest {
                expires_at: current.compute_lease_expires_at + Duration::seconds(300),
            },
            "renew-after-lost-ack",
            current.spec_version,
            86400,
        )
        .await
        .map_err(api_failure)?;
    let extension = f
        .engine
        .database
        .prepare_launch_authorization(f.f.actor.tenant_id, f.create_op, &f.node, &f.launch)
        .await
        .map_err(api_failure)?;
    let ack = f.guard.client.register(&extension.request).await?;
    f.engine
        .database
        .record_launch_authorization(&extension, &ack, &f.observe_resources().await?)
        .await
        .map_err(api_failure)?;
    let mut tx = f.f.owner_transaction().await?;
    let acknowledged: bool =
        sqlx::query_scalar("SELECT sandbox_launch_registered($1,$2,$3,$4,$5,$6)")
            .bind(f.f.actor.tenant_id)
            .bind(f.launch.instance_id)
            .bind(f.launch.generation)
            .bind(f.launch.launch_id)
            .bind(f.launch.pod_uid)
            .bind(f.node.cluster_epoch)
            .fetch_one(&mut *tx)
            .await?;
    assert!(acknowledged);
    let base_receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM launch_permit_receipts WHERE tenant_id=$1 AND permit_id=$2",
    )
    .bind(f.f.actor.tenant_id)
    .bind(base.request.permit_id)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(base_receipts, 0);
    tx.commit().await?;
    assert!(!candidate_includes(&f).await?);
    let claim = f.accept(InstanceAction::Stop).await?;
    let (proof, id) = f.proof(&claim).await?;
    let (runtime, _) = cleanup_runtime(&f.launch, false);
    let cleanup = runtime
        .cleanup(&proof)
        .await?
        .context("extension-backed launch cleanup")?;
    assert_eq!(
        f.engine
            .database
            .complete_termination(&f.engine, &claim, id, &cleanup)
            .await
            .map_err(api_failure)?,
        TerminationCompletion::Stopped
    );
    f.guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires PostgreSQL, dedicated termination role and loopback mTLS"]
async fn certification_must_cover_new_permit_and_assigned_renewal() -> anyhow::Result<()> {
    use chrono::SubsecRound;

    let _serial = test_support_db::serial().await;
    for expiry in [
        None,
        Some(Utc::now() - Duration::days(1)),
        Some(Utc::now() + Duration::seconds(30)),
    ] {
        let f = FixtureRuntime::with_certification(false, expiry).await?;
        let error = f
            .engine
            .database
            .prepare_launch_authorization(f.f.actor.tenant_id, f.create_op, &f.node, &f.launch)
            .await
            .err()
            .context("uncertified launch must fail")?;
        assert_eq!(
            error.code,
            if expiry.is_some_and(|v| v > Utc::now()) {
                "CERTIFICATION_LEASE_LIMIT"
            } else {
                "NODE_CERTIFICATION_EXPIRED"
            }
        );
        let mut tx = f.f.owner_transaction().await?;
        let permits: i64 =
            sqlx::query_scalar("SELECT count(*) FROM launch_permits WHERE tenant_id=$1")
                .bind(f.f.actor.tenant_id)
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(permits, 0);
        tx.commit().await?;
        f.guard.shutdown().await?;
    }
    // PostgreSQL timestamptz retains microseconds. Normalize only this fixture
    // before its round trip so the lease comparisons remain exact.
    let horizon = (Utc::now() + Duration::hours(1)).trunc_subsecs(6);
    let f = FixtureRuntime::with_certification(true, Some(horizon)).await?;
    let current =
        f.f.database
            .get_instance(&f.f.actor, f.launch.instance_id)
            .await
            .map_err(api_failure)?;
    let request = crate::model::RenewRequest {
        expires_at: horizon + Duration::seconds(300),
    };
    let denied =
        f.f.database
            .renew_instance(
                &f.f.actor,
                current.id,
                &request,
                "beyond-node-cert",
                current.spec_version,
                86400,
            )
            .await
            .err()
            .context("renewal past certification must fail")?;
    assert_eq!(denied.code, "CERTIFICATION_LEASE_LIMIT");
    let unchanged =
        f.f.database
            .get_instance(&f.f.actor, current.id)
            .await
            .map_err(api_failure)?;
    assert_eq!(
        unchanged.compute_lease_version,
        current.compute_lease_version
    );
    let base = f
        .engine
        .database
        .prepare_launch_authorization(f.f.actor.tenant_id, f.create_op, &f.node, &f.launch)
        .await
        .map_err(api_failure)?;
    // Real authenticated transport carrying a synthetic host ACK; certification
    // must be checked independently of both its request and its mTLS identity.
    *f.guard
        .acknowledged_expiry
        .lock()
        .map_err(|_| anyhow::anyhow!("test fixture lock"))? =
        Some(horizon + Duration::seconds(600));
    let oversized_ack = f.guard.client.register(&base.request).await?;
    let rejected = f
        .engine
        .database
        .record_launch_authorization(&base, &oversized_ack, &f.observe_resources().await?)
        .await
        .err()
        .context("ACK must not exceed latest certification")?;
    assert_eq!(rejected.code, "CERTIFICATION_LEASE_LIMIT");
    let mut tx = f.f.owner_transaction().await?;
    let node: Uuid = sqlx::query_scalar(
        "SELECT runtime_node_id FROM launch_permits WHERE tenant_id=$1 AND instance_id=$2",
    )
    .bind(f.f.actor.tenant_id)
    .bind(current.id)
    .fetch_one(&mut *tx)
    .await?;
    // Model an old database accepted lease. A runtime controller must independently
    // reject extending the host permit even when API acceptance was bypassed.
    sqlx::query("UPDATE instances SET compute_lease_expires_at=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(f.f.actor.tenant_id)
        .bind(current.id)
        .bind(request.expires_at)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let denied = f
        .engine
        .database
        .prepare_launch_authorization(f.f.actor.tenant_id, f.create_op, &f.node, &f.launch)
        .await
        .err()
        .context("legacy overlong lease must not extend host gate")?;
    assert_eq!(denied.code, "CERTIFICATION_LEASE_LIMIT");
    let mut tx = f.f.owner_transaction().await?;
    sqlx::query("UPDATE instances SET compute_lease_expires_at=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(f.f.actor.tenant_id)
        .bind(current.id)
        .bind(current.compute_lease_expires_at)
        .execute(&mut *tx)
        .await?;
    test_support_db::seed_test_node_certification(&mut tx, node, horizon + Duration::days(1))
        .await?;
    tx.commit().await?;
    let renewed =
        f.f.database
            .renew_instance(
                &f.f.actor,
                current.id,
                &request,
                "beyond-node-cert",
                current.spec_version,
                86400,
            )
            .await
            .map_err(api_failure)?;
    assert_eq!(
        renewed.body.resource.compute_lease_expires_at,
        request.expires_at
    );
    let extension = f
        .engine
        .database
        .prepare_launch_authorization(f.f.actor.tenant_id, f.create_op, &f.node, &f.launch)
        .await
        .map_err(api_failure)?;
    assert_eq!(extension.request.expires_at, request.expires_at);
    let mut tx =
        f.f.database
            .begin(Uuid::new_v4())
            .await
            .map_err(api_failure)?;
    let leaked: Vec<(bool, Option<DateTime<Utc>>)> =
        sqlx::query_as("SELECT assigned,valid_until FROM sandbox_instance_certification($1,$2)")
            .bind(f.f.actor.tenant_id)
            .bind(current.id)
            .fetch_all(&mut *tx)
            .await?;
    assert!(
        leaked.is_empty(),
        "scoped definer must not leak another tenant's certification"
    );
    tx.rollback().await?;
    f.guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires PostgreSQL, dedicated termination role and loopback mTLS"]
async fn expired_certification_blocks_ready_but_does_not_block_existing_safety_stop()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    // Real expiry transition, no mutable certification or fake production clock.
    let horizon = Utc::now() + Duration::seconds(8);
    let f = FixtureRuntime::with_certification(false, Some(horizon)).await?;
    let mut tx = f.f.owner_transaction().await?;
    sqlx::query("UPDATE instances SET compute_lease_expires_at=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(f.f.actor.tenant_id)
        .bind(f.launch.instance_id)
        .bind(horizon - Duration::seconds(1))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let permit = f
        .engine
        .database
        .prepare_launch_permit(f.f.actor.tenant_id, f.create_op, &f.node, &f.launch)
        .await
        .map_err(api_failure)?;
    let ack = f.guard.client.register(&permit.request).await?;
    f.engine
        .database
        .record_launch_registration(&permit, &ack, &f.observe_resources().await?)
        .await
        .map_err(api_failure)?;
    f.running().await?;
    let wait =
        (horizon - Utc::now()).to_std().unwrap_or_default() + std::time::Duration::from_millis(30);
    tokio::time::sleep(wait).await;
    let mut tx = f.f.owner_transaction().await?;
    let ready: bool = sqlx::query_scalar("SELECT sandbox_launch_registered($1,$2,$3,$4,$5,$6)")
        .bind(f.f.actor.tenant_id)
        .bind(f.launch.instance_id)
        .bind(f.launch.generation)
        .bind(f.launch.launch_id)
        .bind(f.launch.pod_uid)
        .bind(f.node.cluster_epoch)
        .fetch_one(&mut *tx)
        .await?;
    assert!(!ready);
    tx.commit().await?;
    assert!(
        matches!(f.engine.database.registered_runtime_node(&f.node).await,Err(e) if e.code=="NODE_CERTIFICATION_EXPIRED")
    );
    let claim = f.accept(InstanceAction::Stop).await?;
    let (proof, id) = f.proof(&claim).await?;
    let (runtime, _) = cleanup_runtime(&f.launch, false);
    let cleanup = runtime
        .cleanup(&proof)
        .await?
        .context("expired certification safety cleanup")?;
    assert_eq!(
        f.engine
            .database
            .complete_termination(&f.engine, &claim, id, &cleanup)
            .await
            .map_err(api_failure)?,
        TerminationCompletion::Stopped
    );
    f.guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires PostgreSQL and dedicated runtime roles"]
async fn running_without_assignment_cannot_renew_but_unassigned_pending_can() -> anyhow::Result<()>
{
    let _serial = test_support_db::serial().await;
    let f = Fixture::new(10).await?;
    let created = f.create("unassigned-lease").await.map_err(api_failure)?;
    let original = created.body.resource;
    let renewed = f
        .database
        .renew_instance(
            &f.actor,
            original.id,
            &crate::model::RenewRequest {
                expires_at: original.compute_lease_expires_at + Duration::seconds(300),
            },
            "pending-renew",
            original.spec_version,
            86400,
        )
        .await
        .map_err(api_failure)?;
    f.seed_observed_state(original.id, "RUNNING").await?;
    let current = renewed.body.resource;
    let rejected = f
        .database
        .renew_instance(
            &f.actor,
            current.id,
            &crate::model::RenewRequest {
                expires_at: current.compute_lease_expires_at + Duration::seconds(300),
            },
            "running-unassigned-renew",
            current.spec_version,
            86400,
        )
        .await
        .err()
        .context("unassigned running renewal must fail")?;
    assert_eq!(rejected.code, "CERTIFICATION_LEASE_LIMIT");
    Ok(())
}

#[tokio::test]
#[ignore = "Requires PostgreSQL, dedicated termination role and loopback mTLS"]
async fn registration_retry_clock_updates_dispatch_and_requeues_fairly() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = FixtureRuntime::new(false).await?;
    let mut tx = f.f.owner_transaction().await?;
    let scheduled:DateTime<Utc>=sqlx::query_scalar("UPDATE operations SET launch_registration_next_attempt_at=(SELECT COALESCE(min(launch_registration_eligible_at),clock_timestamp())-interval '1 day' FROM operation_dispatch WHERE queue_role='WORKER') WHERE tenant_id=$1 AND id=$2 RETURNING launch_registration_next_attempt_at")
        .bind(f.f.actor.tenant_id).bind(f.create_op).fetch_one(&mut *tx).await?;
    let indexed: DateTime<Utc> = sqlx::query_scalar(
        "SELECT launch_registration_eligible_at FROM operation_dispatch WHERE operation_id=$1",
    )
    .bind(f.create_op)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(
        indexed, scheduled,
        "changing only registration retry time must update the discovery index"
    );
    tx.commit().await?;
    let candidates = f
        .engine
        .database
        .launch_registration_candidates(1)
        .await
        .map_err(api_failure)?;
    assert!(
        candidates
            .iter()
            .any(|c| c.tenant_id == f.f.actor.tenant_id && c.operation_id == f.create_op)
    );
    let mut tx = f.f.owner_transaction().await?;
    let (next,indexed):(DateTime<Utc>,DateTime<Utc>)=sqlx::query_as("SELECT o.launch_registration_next_attempt_at,d.launch_registration_eligible_at FROM operations o JOIN operation_dispatch d ON d.operation_id=o.id WHERE o.tenant_id=$1 AND o.id=$2")
        .bind(f.f.actor.tenant_id).bind(f.create_op).fetch_one(&mut *tx).await?;
    assert!(next > scheduled);
    assert_eq!(
        next, indexed,
        "the bounded scan must move the candidate behind later eligible work"
    );
    tx.commit().await?;
    f.guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL and authenticated loopback nodeguard"]
async fn stopped_and_historical_waiting_instance_deletes_finish_without_touching_storage()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    for historical in [false, true] {
        let f = FixtureRuntime::new(true).await?;
        f.running().await?;
        let initial = f
            .accept(if historical {
                InstanceAction::Delete
            } else {
                InstanceAction::Stop
            })
            .await?;
        let (proof, id) = f.proof(&initial).await?;
        let (runtime, _) = cleanup_runtime(&f.launch, false);
        let cleanup = runtime.cleanup(&proof).await?.context("cleanup")?;
        let claim = if historical {
            // Reproduce the exact persisted pre-0023 DELETE state without
            // rewriting an immutable receipt or inventing trusted host proof.
            let mut tx = f.f.owner_transaction().await?;
            sqlx::query("INSERT INTO termination_cleanup_receipts(proof_id,tenant_id,old_pod_uid,pod_resource_version,pod_absent_at,volume_checked_at,completion) VALUES($1,$2,$3,$4,$5,$6,'AWAITING_VOLUME_DELETION')")
                .bind(id).bind(f.f.actor.tenant_id).bind(f.launch.pod_uid).bind(cleanup.pod_resource_version()).bind(cleanup.pod_absent_at()).bind(cleanup.volume_checked_at()).execute(&mut *tx).await?;
            sqlx::query("UPDATE quota_accounts SET pending=0,allocated=0 WHERE tenant_id=$1 AND dimension IN('CPU_MILLIS','MEMORY_MIB')").bind(f.f.actor.tenant_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE quota_reservations r SET status='RELEASED',released_at=clock_timestamp() FROM quota_accounts q WHERE q.tenant_id=r.tenant_id AND q.id=r.quota_account_id AND r.tenant_id=$1 AND q.dimension IN('CPU_MILLIS','MEMORY_MIB')").bind(f.f.actor.tenant_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE instances SET observed_state='STOPPED',last_termination_proof_id=$3 WHERE tenant_id=$1 AND id=$2").bind(f.f.actor.tenant_id).bind(f.launch.instance_id).bind(id).execute(&mut *tx).await?;
            sqlx::query("UPDATE workspaces SET status='AVAILABLE',active_operation_id=NULL WHERE tenant_id=$1 AND id=$2").bind(f.f.actor.tenant_id).bind(f.launch.workspace_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE external_resources SET status='DELETED',deleted_at=clock_timestamp() WHERE tenant_id=$1 AND instance_id=$2 AND kind='POD'").bind(f.f.actor.tenant_id).bind(f.launch.instance_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE operations SET stage='WAITING_VOLUME_DELETION',status='WAITING',wait_reason='VOLUME_DELETION_PROOF_REQUIRED',lease_owner=NULL,lease_until=NULL,next_attempt_at=(SELECT COALESCE(min(eligible_at),clock_timestamp())-interval '1 day' FROM operation_dispatch WHERE queue_role='TERMINATION') WHERE tenant_id=$1 AND id=$2").bind(f.f.actor.tenant_id).bind(initial.operation_id).execute(&mut *tx).await?;
            tx.commit().await?;
            let claim = f
                .engine
                .claim_termination()
                .await
                .map_err(api_failure)?
                .context("recovery claim")?;
            ensure!(
                claim.operation_id == initial.operation_id,
                "claim own historical operation"
            );
            claim
        } else {
            f.engine
                .database
                .complete_termination(&f.engine, &initial, id, &cleanup)
                .await
                .map_err(api_failure)?;
            f.accept(InstanceAction::Delete).await?
        };
        let (a, b) = tokio::join!(
            f.engine
                .database
                .complete_stopped_instance_deletion(&f.engine, &claim),
            f.engine
                .database
                .complete_stopped_instance_deletion(&f.engine, &claim)
        );
        assert_eq!([&a, &b].iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(f.pending_dimension("INSTANCES").await?, 0);
        assert_eq!(f.pending_dimension("CPU_MILLIS").await?, 0);
        assert_eq!(f.pending_dimension("WORKSPACE_GIB").await?, 40);
        let mut tx = f.f.owner_transaction().await?;
        let result:(String,String,String,Option<DateTime<Utc>>)=sqlx::query_as("SELECT i.observed_state,o.status,w.status,w.delete_requested_at FROM instances i JOIN workspaces w ON w.tenant_id=i.tenant_id AND w.id=i.workspace_id JOIN operations o ON o.tenant_id=i.tenant_id AND o.id=$3 WHERE i.tenant_id=$1 AND i.id=$2")
            .bind(f.f.actor.tenant_id).bind(f.launch.instance_id).bind(claim.operation_id).fetch_one(&mut *tx).await?;
        assert_eq!(
            result,
            (
                "DELETED".into(),
                "SUCCEEDED".into(),
                "AVAILABLE".into(),
                None
            )
        );
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM domain_events WHERE tenant_id=$1 AND aggregate_id=$2 AND event_type='instance.deleted'").bind(f.f.actor.tenant_id).bind(f.launch.instance_id).fetch_one(&mut *tx).await?;
        assert_eq!(count, 1);
        tx.commit().await?;
        // Runtime application cannot turn a retained record back into live compute.
        let mut tx =
            f.f.database
                .begin(f.f.actor.tenant_id)
                .await
                .map_err(api_failure)?;
        require_pg_error(sqlx::query("UPDATE instances SET observed_state='STOPPED',desired_state='STOPPED' WHERE tenant_id=$1 AND id=$2").bind(f.f.actor.tenant_id).bind(f.launch.instance_id).execute(&mut *tx).await,"42501")?;
        tx.rollback().await?;
        f.guard.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL and authenticated loopback nodeguard"]
async fn instance_delete_rejects_fake_stop_or_remaining_compute_and_runtime_role_bypass()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = FixtureRuntime::new(true).await?;
    f.running().await?;
    let claim = f.accept(InstanceAction::Delete).await?;
    let mut tx =
        f.f.database
            .begin(f.f.actor.tenant_id)
            .await
            .map_err(api_failure)?;
    require_pg_error(sqlx::query("UPDATE instances SET observed_state='DELETED',deleted_at=clock_timestamp(),active_operation_id=NULL WHERE tenant_id=$1 AND id=$2").bind(f.f.actor.tenant_id).bind(f.launch.instance_id).execute(&mut *tx).await,"42501")?;
    tx.rollback().await?;
    let mut tx = f.f.owner_transaction().await?;
    sqlx::query("UPDATE instances SET observed_state='STOPPED' WHERE tenant_id=$1 AND id=$2")
        .bind(f.f.actor.tenant_id)
        .bind(f.launch.instance_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE workspaces SET status='AVAILABLE' WHERE tenant_id=$1 AND id=$2")
        .bind(f.f.actor.tenant_id)
        .bind(f.launch.workspace_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    assert!(
        matches!(f.engine.database.complete_stopped_instance_deletion(&f.engine,&claim).await,Err(e) if e.code=="INSTANCE_DELETE_TERMINATION_PROOF_REQUIRED")
    );
    let (proof, id) = f.proof(&claim).await?;
    let (runtime, _) = cleanup_runtime(&f.launch, false);
    let cleanup = runtime.cleanup(&proof).await?.context("cleanup")?;
    let mut tx = f.f.owner_transaction().await?;
    sqlx::query("INSERT INTO termination_cleanup_receipts(proof_id,tenant_id,old_pod_uid,pod_resource_version,pod_absent_at,volume_checked_at,completion) VALUES($1,$2,$3,$4,$5,$6,'STOPPED')").bind(id).bind(f.f.actor.tenant_id).bind(f.launch.pod_uid).bind(cleanup.pod_resource_version()).bind(cleanup.pod_absent_at()).bind(cleanup.volume_checked_at()).execute(&mut *tx).await?;
    sqlx::query("UPDATE instances SET last_termination_proof_id=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(f.f.actor.tenant_id)
        .bind(f.launch.instance_id)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE external_resources SET status='DELETED',deleted_at=clock_timestamp() WHERE tenant_id=$1 AND instance_id=$2 AND kind='POD'").bind(f.f.actor.tenant_id).bind(f.launch.instance_id).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(
        matches!(f.engine.database.complete_stopped_instance_deletion(&f.engine,&claim).await,Err(e) if e.code=="INSTANCE_DELETE_QUOTA_LEDGER_MISMATCH")
    );
    assert_eq!(f.pending_dimension("INSTANCES").await?, 2);
    assert_eq!(f.pending_dimension("CPU_MILLIS").await?, 2000);
    let mut tx = f.f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET status='CANCELLED',completed_at=clock_timestamp(),lease_owner=NULL,lease_until=NULL WHERE tenant_id=$1 AND id=$2").bind(f.f.actor.tenant_id).bind(claim.operation_id).execute(&mut *tx).await?;
    tx.commit().await?;
    f.guard.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL and authenticated loopback nodeguard"]
async fn instance_delete_event_head_wait_cannot_commit_after_worker_lease_expiry()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    for stopped in [false, true] {
        let f = FixtureRuntime::new(true).await?;
        f.running().await?;
        let initial = f
            .accept(if stopped {
                InstanceAction::Stop
            } else {
                InstanceAction::Delete
            })
            .await?;
        let (proof, id) = f.proof(&initial).await?;
        let (runtime, _) = cleanup_runtime(&f.launch, false);
        let cleanup = runtime.cleanup(&proof).await?.context("cleanup")?;
        let claim = if stopped {
            f.engine
                .database
                .complete_termination(&f.engine, &initial, id, &cleanup)
                .await
                .map_err(api_failure)?;
            f.accept(InstanceAction::Delete).await?
        } else {
            initial
        };
        let mut tx = f.f.owner_transaction().await?;
        sqlx::query("UPDATE operations SET lease_until=clock_timestamp()+interval '1 second' WHERE tenant_id=$1 AND id=$2").bind(f.f.actor.tenant_id).bind(claim.operation_id).execute(&mut *tx).await?;
        tx.commit().await?;
        let mut blocker = f.f.owner_transaction().await?;
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        sqlx::query("SELECT project_id FROM event_stream_heads WHERE tenant_id=$1 AND project_id=$2 FOR UPDATE").bind(f.f.actor.tenant_id).bind(f.launch.project_id).execute(&mut *blocker).await?;
        let engine = f.engine.clone();
        let pending = tokio::spawn(async move {
            if stopped {
                engine
                    .database
                    .complete_stopped_instance_deletion(&engine, &claim)
                    .await
            } else {
                engine
                    .database
                    .complete_termination(&engine, &claim, id, &cleanup)
                    .await
                    .map(|_| ())
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(2),async {
            loop {
                let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))").bind(blocker_pid).fetch_one(&f.f.owner).await?;
                if waiting {break;}
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Ok::<(),sqlx::Error>(())
        }).await??;
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        blocker.commit().await?;
        assert!(matches!(pending.await?,Err(e) if e.code=="WORKER_LEASE_LOST"));
        assert_eq!(f.pending_dimension("INSTANCES").await?, 2);
        assert_eq!(f.pending_dimension("WORKSPACE_GIB").await?, 40);
        assert_eq!(
            f.pending_dimension("CPU_MILLIS").await?,
            if stopped { 0 } else { 2000 }
        );
        let mut tx = f.f.owner_transaction().await?;
        let state: String =
            sqlx::query_scalar("SELECT observed_state FROM instances WHERE tenant_id=$1 AND id=$2")
                .bind(f.f.actor.tenant_id)
                .bind(f.launch.instance_id)
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(state, if stopped { "STOPPED" } else { "RUNNING" });
        sqlx::query("UPDATE operations SET status='CANCELLED',completed_at=clock_timestamp(),lease_owner=NULL,lease_until=NULL WHERE tenant_id=$1 AND instance_id=$2 AND status IN('QUEUED','RUNNING','WAITING')").bind(f.f.actor.tenant_id).bind(f.launch.instance_id).execute(&mut *tx).await?;
        tx.commit().await?;
        f.guard.shutdown().await?;
    }
    Ok(())
}

#[path = "file_transfer_termination_tests.rs"]
mod file_transfer_tests;
