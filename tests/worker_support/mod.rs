//! Shared owned Kubernetes transport fixture for the real-PG worker suites.
pub(super) mod checkpoint_faults;
use crate::support::{Fixture, api_failure};
use anyhow::{Context, ensure};
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, Response},
};
use kube::{Client, client::Body as KubeBody};
use sandbox_platform::{
    db::Database, engine::Claim, model::Instance, runtime::KubernetesRuntime, worker::Worker,
};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::Semaphore;
use uuid::Uuid;

#[derive(Default)]
pub(super) struct KubeState {
    pub(super) objects: BTreeMap<String, Value>,
    pub(super) posts: BTreeMap<String, usize>,
    pub(super) deletes: usize,
}
#[derive(Clone)]
pub(super) struct MockKube {
    pub(super) state: Arc<Mutex<KubeState>>,
    pub(super) expire_pod_create: Arc<AtomicBool>,
    pub(super) not_ready: Arc<AtomicBool>,
    pub(super) pause_policy_create_response: Arc<AtomicBool>,
    pub(super) pause_policy_get: Arc<AtomicBool>,
    pub(super) pause_pvc_get: Arc<AtomicBool>,
    pub(super) pause_pod_get: Arc<AtomicBool>,
    pub(super) paused: Arc<Semaphore>,
    pub(super) resume: Arc<Semaphore>,
    pub(super) slow_posts: Arc<AtomicBool>,
    pub(super) require_committed_predecessor: Arc<AtomicBool>,
    pub(super) arm_commit: Option<Arc<AtomicBool>>,
    owner: PgPool,
    tenant: Uuid,
    operation: Uuid,
    namespace: String,
    project: Uuid,
    epoch: Uuid,
}
impl MockKube {
    pub(super) async fn new(
        f: &Fixture,
        instance: &Instance,
        operation: Uuid,
    ) -> anyhow::Result<Self> {
        let mut tx = f.owner_transaction().await?;
        let (namespace, epoch): (String, Uuid) =
            sqlx::query_as("SELECT namespace,cluster_epoch FROM instances WHERE id=$1")
                .bind(instance.id)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(Self {
            state: Default::default(),
            expire_pod_create: Default::default(),
            not_ready: Default::default(),
            pause_policy_create_response: Default::default(),
            pause_policy_get: Default::default(),
            pause_pvc_get: Default::default(),
            pause_pod_get: Default::default(),
            paused: Arc::new(Semaphore::new(0)),
            resume: Arc::new(Semaphore::new(0)),
            slow_posts: Default::default(),
            require_committed_predecessor: Default::default(),
            arm_commit: None,
            owner: f.owner.clone(),
            tenant: f.actor.tenant_id,
            operation,
            namespace,
            project: instance.project_id,
            epoch,
        })
    }
    pub(super) fn runtime(&self) -> KubernetesRuntime {
        let mock = self.clone();
        let service = tower::service_fn(move |req: Request<KubeBody>| {
            let mock = mock.clone();
            async move {
                let response=mock.respond(req).await.unwrap_or_else(|_|json_response(500,json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"InternalError","code":500,"message":"mock failed"})));
                Ok::<_, Infallible>(response)
            }
        });
        KubernetesRuntime::from_client(Client::new(service, "default"))
    }
    async fn respond(&self, req: Request<KubeBody>) -> anyhow::Result<Response<Body>> {
        let method = req.method().clone();
        let path = req.uri().path().to_owned();
        if method == Method::GET {
            let known = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("mock lock"))?
                .objects
                .contains_key(&path);
            let pause = known
                && if path.contains("/ciliumnetworkpolicies/") {
                    self.pause_policy_get.swap(false, Ordering::SeqCst)
                } else if path.contains("/persistentvolumeclaims/") {
                    self.pause_pvc_get.swap(false, Ordering::SeqCst)
                } else if path.contains("/pods/") {
                    self.pause_pod_get.swap(false, Ordering::SeqCst)
                } else {
                    false
                };
            if pause {
                self.paused.add_permits(1);
                self.resume.acquire().await?.forget();
            }
        }
        if method == Method::GET && path == "/apis/node.k8s.io/v1/runtimeclasses/kata-qemu" {
            return Ok(json_response(
                200,
                json!({"apiVersion":"node.k8s.io/v1","kind":"RuntimeClass","metadata":{"name":"kata-qemu"},"handler":"kata-qemu","scheduling":{"nodeSelector":{"sandbox.platform/worker-pool":"kata"}}}),
            ));
        }
        if method == Method::GET && path == format!("/api/v1/namespaces/{}", self.namespace) {
            return Ok(json_response(
                200,
                json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":self.namespace,"labels":{"sandbox.platform/managed":"true","sandbox.platform/tenant-id":self.tenant,"sandbox.platform/project-id":self.project,"sandbox.platform/cluster-epoch":self.epoch},"annotations":{"sandbox.platform/certification-id":"integration-evidence-reference"}}}),
            ));
        }
        if method == Method::GET
            && path
                == format!(
                    "/apis/networking.k8s.io/v1/namespaces/{}/networkpolicies/sandbox-default-deny",
                    self.namespace
                )
        {
            return Ok(json_response(
                200,
                json!({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"sandbox-default-deny","namespace":self.namespace},"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"]}}),
            ));
        }
        let mut body = if method == Method::POST {
            serde_json::from_slice::<Value>(
                &to_bytes(Body::new(req.into_body()), 1024 * 1024).await?,
            )?
        } else {
            Value::Null
        };
        if method == Method::POST && self.require_committed_predecessor.load(Ordering::SeqCst) {
            let predecessor = match body["kind"].as_str() {
                Some("PersistentVolumeClaim") => Some("CILIUM_POLICY"),
                Some("Pod") => Some("PVC"),
                _ => None,
            };
            if let Some(kind) = predecessor {
                let mut tx = self.owner.begin().await?;
                sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
                    .bind(self.tenant.to_string())
                    .execute(&mut *tx)
                    .await?;
                let committed: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM external_resources r JOIN domain_events e ON e.tenant_id=r.tenant_id AND e.operation_id=r.operation_id AND e.event_type='operation.progressed' AND e.payload->>'resource_kind'=r.kind AND e.payload->>'provider_id'=r.provider_id WHERE r.tenant_id=$1 AND r.operation_id=$2 AND r.kind=$3 AND r.status='ACTIVE')")
                    .bind(self.tenant).bind(self.operation).bind(kind).fetch_one(&mut *tx).await?;
                tx.commit().await?;
                ensure!(
                    committed,
                    "next resource arrived before its predecessor UID/checkpoint committed"
                );
            }
        }
        if method == Method::POST && self.slow_posts.load(Ordering::SeqCst) {
            let delay = match body["kind"].as_str() {
                Some("CiliumNetworkPolicy") => 12,
                Some("PersistentVolumeClaim") => 8,
                _ => 0,
            };
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
        }
        let response = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("mock lock poisoned"))?;
            if method == Method::POST {
                *state
                    .posts
                    .entry(body["kind"].as_str().context("kind")?.to_owned())
                    .or_default() += 1;
                let name = body["metadata"]["name"]
                    .as_str()
                    .context("name")?
                    .to_owned();
                let key = format!("{path}/{name}");
                ensure!(
                    !state.objects.contains_key(&key),
                    "test should not duplicate POST existing fixed object"
                );
                body["metadata"]["uid"] = json!(Uuid::new_v4());
                body["metadata"]["resourceVersion"] = json!("1");
                if body["kind"] == "Pod" {
                    body["status"] = json!({"phase":"Running","conditions":[{"type":"Ready","status":"True"}],"containerStatuses":[{"name":body["spec"]["containers"][0]["name"],"ready":true,"restartCount":0,"image":"test","imageID":"test","state":{"running":{}}}]});
                    if self.not_ready.load(Ordering::SeqCst) {
                        body["status"]["conditions"][0]["status"] = json!("False");
                    }
                }
                if body["kind"] == "PersistentVolumeClaim" {
                    body["status"] = json!({"phase":"Bound"});
                }
                state.objects.insert(key, body.clone());
                json_response(201, body)
            } else if method == Method::DELETE {
                state.deletes += 1;
                if let Some(object) = state.objects.get_mut(&path) {
                    object["metadata"]["deletionTimestamp"] = json!("2026-10-03T00:00:00Z");
                }
                json_response(
                    200,
                    json!({"apiVersion":"v1","kind":"Status","status":"Success","code":200}),
                )
            } else if let Some(object) = state.objects.get(&path) {
                json_response(200, object.clone())
            } else {
                json_response(
                    404,
                    json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404,"message":"absent"}),
                )
            }
        };
        // The object is already present in the remote fixture, but the caller
        // cannot record its UID/checkpoint until this response is released.
        // No mock-state mutex is held across the barrier.
        if method == Method::POST
            && path.ends_with("/ciliumnetworkpolicies")
            && self
                .pause_policy_create_response
                .swap(false, Ordering::SeqCst)
        {
            self.paused.add_permits(1);
            self.resume.acquire().await?.forget();
        }
        if method == Method::POST
            && path.ends_with("/pods")
            && self.expire_pod_create.swap(false, Ordering::SeqCst)
        {
            let mut tx = self.owner.begin().await?;
            sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
                .bind(self.tenant.to_string())
                .execute(&mut *tx)
                .await?;
            sqlx::query("UPDATE operations SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1").bind(self.operation).execute(&mut *tx).await?;
            tx.commit().await?;
        }
        if method == Method::POST
            && path.ends_with("/ciliumnetworkpolicies")
            && let Some(armed) = &self.arm_commit
        {
            armed.store(true, Ordering::SeqCst);
        }
        Ok(response)
    }
    pub(super) fn posts(&self, kind: &str) -> anyhow::Result<usize> {
        Ok(*self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("mock lock"))?
            .posts
            .get(kind)
            .unwrap_or(&0))
    }
    pub(super) fn remove(&self, kind: &str) -> anyhow::Result<()> {
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("mock lock"))?
            .objects
            .retain(|_, v| v["kind"] != kind);
        Ok(())
    }
}
fn json_response(status: u16, value: Value) -> Response<Body> {
    let mut response = Response::new(Body::from(value.to_string()));
    *response.status_mut() = axum::http::StatusCode::from_u16(status)
        .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    response.headers_mut().insert(
        "content-type",
        axum::http::HeaderValue::from_static("application/json"),
    );
    response
}

pub(super) async fn fixture() -> anyhow::Result<Fixture> {
    let mut f = Fixture::new(10).await?;
    let policy = Uuid::new_v4();
    let mut tx = f.owner_transaction().await?;
    sqlx::query("INSERT INTO security_policy_versions(id,tenant_id,name,version,status,rules) VALUES($1,$2,'worker-deny-all',1,'APPROVED',$3)").bind(policy).bind(f.actor.tenant_id).bind(json!({"profile":"deny-all","dns":true})).execute(&mut *tx).await?;
    tx.commit().await?;
    f.request.security_profile_id = policy;
    Ok(f)
}
pub(super) async fn worker(f: &Fixture, mock: &MockKube, name: &str) -> anyhow::Result<Worker> {
    let url = std::env::var("TEST_WORKER_DATABASE_URL")
        .context("TEST_WORKER_DATABASE_URL required for non-owner worker test")?;
    let parsed = url::Url::parse(&url)?;
    let expected = url::Url::parse(&std::env::var("TEST_DATABASE_URL")?)?;
    ensure!(
        parsed.path().ends_with("_test")
            && parsed.path() == expected.path()
            && parsed.host_str() == expected.host_str()
            && parsed.port_or_known_default() == expected.port_or_known_default()
            && parsed.username() == "sandbox_worker",
        "Worker URL must use sandbox_worker on the same disposable database"
    );
    sqlx::raw_sql(include_str!("../../scripts/sql/worker-role.sql"))
        .execute(&f.owner)
        .await?;
    let db = Database::connect(&url, 8).await?;
    db.verify_runtime_role().await?;
    Worker::new(
        db,
        mock.runtime(),
        name.into(),
        "integration-evidence-reference".into(),
        2,
        "kube-system".into(),
        [("k8s-app".into(), "kube-dns".into())].into(),
    )
}
pub(super) async fn claim(f: &Fixture, w: &Worker, op: Uuid) -> anyhow::Result<Claim> {
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET next_attempt_at='1000-01-01 00:00:00+00',lease_until=CASE WHEN lease_until<=clock_timestamp() THEN '1000-01-01 00:00:00+00'::timestamptz ELSE lease_until END WHERE id=$1")
        .bind(op)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let claim = w
        .engine
        .claim()
        .await
        .map_err(api_failure)?
        .context("expected claim")?;
    ensure!(
        claim.operation_id == op,
        "test expected its priority operation"
    );
    Ok(claim)
}
pub(super) async fn stage(f: &Fixture, w: &Worker, op: Uuid) -> anyhow::Result<()> {
    let claim = claim(f, w, op).await?;
    w.reconcile(&claim).await.map_err(api_failure)
}

/// This suite mocks all Kubernetes/host observations. Seed only the owner-side
/// test fixture; production registration and mTLS proofs have separate PG tests.
pub(super) async fn register_mock_launch(
    f: &Fixture,
    op: Uuid,
    instance: Uuid,
) -> anyhow::Result<()> {
    let mut tx = f.owner_transaction().await?;
    let epoch: Uuid =
        sqlx::query_scalar("SELECT cluster_epoch FROM instances WHERE tenant_id=$1 AND id=$2")
            .bind(f.actor.tenant_id)
            .bind(instance)
            .fetch_one(&mut *tx)
            .await?;
    let node = Uuid::new_v4();
    let permit = Uuid::new_v4();
    sqlx::query("INSERT INTO runtime_nodes(id,cluster_epoch,node_uid,node_name,cloud_provider,cloud_account_id,region,cloud_instance_id,private_ip,profile_sha256,boot_id,enabled) VALUES($1,$2,$3,'mock-kata','alicloud','mock-account','mock-region',$4,'10.2.3.4',$5,$6,true)")
        .bind(node).bind(epoch).bind(Uuid::new_v4()).bind(format!("mock-{node}")).bind("a".repeat(64)).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    crate::support::seed_test_node_certification(
        &mut tx,
        node,
        chrono::Utc::now() + chrono::Duration::days(2),
    )
    .await?;
    sqlx::query("INSERT INTO launch_permits(id,tenant_id,project_id,instance_id,workspace_id,operation_id,runtime_node_id,cluster_epoch,generation,launch_id,pod_uid,namespace,pod_name,pvc_uid,pv_uid,pv_name,csi_volume_handle,expires_at) SELECT $1,i.tenant_id,i.project_id,i.id,i.workspace_id,$2,$3,i.cluster_epoch,i.runtime_generation,i.launch_id,i.pod_uid,i.namespace,i.pod_name,r.provider_id::uuid,$4,'pvc-mock','d-mock',i.compute_lease_expires_at FROM instances i JOIN external_resources r ON r.tenant_id=i.tenant_id AND r.workspace_id=i.workspace_id AND r.kind='PVC' AND r.status='ACTIVE' WHERE i.tenant_id=$5 AND i.id=$6")
        .bind(permit).bind(op).bind(node).bind(Uuid::new_v4()).bind(f.actor.tenant_id).bind(instance).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO launch_permit_receipts(permit_id,tenant_id,journal_revision) VALUES($1,$2,1)",
    )
    .bind(permit)
    .bind(f.actor.tenant_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}
