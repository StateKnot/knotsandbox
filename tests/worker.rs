//! Real PostgreSQL, separate non-owner worker identity, mock Kubernetes transport.
//! These tests verify control-plane recovery, never physical Kata/CNI isolation.
#![allow(dead_code)]
mod support;

use anyhow::{Context, ensure};
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, Response},
};
use kube::{Client, client::Body as KubeBody};
use sandbox_platform::{
    db::Database,
    domain::InstanceAction,
    engine::Claim,
    model::{Instance, StartRequest},
    runtime::KubernetesRuntime,
    worker::Worker,
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
use support::{Fixture, api_failure};
use uuid::Uuid;

#[derive(Default)]
struct KubeState {
    objects: BTreeMap<String, Value>,
    posts: BTreeMap<String, usize>,
    deletes: usize,
}
#[derive(Clone)]
struct MockKube {
    state: Arc<Mutex<KubeState>>,
    expire_pod_create: Arc<AtomicBool>,
    owner: PgPool,
    tenant: Uuid,
    operation: Uuid,
    namespace: String,
    project: Uuid,
    epoch: Uuid,
}
impl MockKube {
    async fn new(f: &Fixture, instance: &Instance, operation: Uuid) -> anyhow::Result<Self> {
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
            owner: f.owner.clone(),
            tenant: f.actor.tenant_id,
            operation,
            namespace,
            project: instance.project_id,
            epoch,
        })
    }
    fn runtime(&self) -> KubernetesRuntime {
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
        Ok(response)
    }
    fn posts(&self, kind: &str) -> anyhow::Result<usize> {
        Ok(*self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("mock lock"))?
            .posts
            .get(kind)
            .unwrap_or(&0))
    }
    fn remove(&self, kind: &str) -> anyhow::Result<()> {
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

async fn fixture() -> anyhow::Result<Fixture> {
    let mut f = Fixture::new(10).await?;
    let policy = Uuid::new_v4();
    let mut tx = f.owner_transaction().await?;
    sqlx::query("INSERT INTO security_policy_versions(id,tenant_id,name,version,status,rules) VALUES($1,$2,'worker-deny-all',1,'APPROVED',$3)").bind(policy).bind(f.actor.tenant_id).bind(json!({"profile":"deny-all","dns":true})).execute(&mut *tx).await?;
    tx.commit().await?;
    f.request.security_profile_id = policy;
    Ok(f)
}
async fn worker(f: &Fixture, mock: &MockKube, name: &str) -> anyhow::Result<Worker> {
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
    sqlx::raw_sql(include_str!("../scripts/sql/worker-role.sql"))
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
async fn claim(f: &Fixture, w: &Worker, op: Uuid) -> anyhow::Result<Claim> {
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
async fn stage(f: &Fixture, w: &Worker, op: Uuid) -> anyhow::Result<()> {
    let claim = claim(f, w, op).await?;
    w.reconcile(&claim).await.map_err(api_failure)
}

/// This suite mocks all Kubernetes/host observations. Seed only the owner-side
/// test fixture; production registration and mTLS proofs have separate PG tests.
async fn register_mock_launch(f: &Fixture, op: Uuid, instance: Uuid) -> anyhow::Result<()> {
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
    support::seed_test_node_certification(
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

#[tokio::test]
#[ignore = "Requires PostgreSQL and explicit TEST_WORKER_DATABASE_URL; no cluster isolation claim"]
async fn crash_after_pod_create_recovers_uid_once_and_requires_trusted_launch_registration()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let f = fixture().await?;
    let accepted = f.create("worker-recovery").await.map_err(api_failure)?;
    let i = &accepted.body.resource;
    let op = accepted.body.operation.id;
    let mock = MockKube::new(&f, i, op).await?;
    let first = worker(&f, &mock, "worker-before-crash").await?;
    stage(&f, &first, op).await?;
    stage(&f, &first, op).await?;
    mock.expire_pod_create.store(true, Ordering::SeqCst);
    let old_claim = claim(&f, &first, op).await?;
    let error = first
        .reconcile(&old_claim)
        .await
        .err()
        .context("stale worker should fail")?;
    assert_eq!(error.code, "WORKER_LEASE_LOST");
    let mut tx = f.owner_transaction().await?;
    let pod_records: i64 =
        sqlx::query_scalar("SELECT count(*) FROM external_resources WHERE kind='POD'")
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(pod_records, 0);
    tx.commit().await?;
    let restarted = worker(&f, &mock, "worker-after-crash").await?;
    stage(&f, &restarted, op).await?;
    let unregistered = claim(&f, &restarted, op).await?;
    let denied = restarted
        .reconcile(&unregistered)
        .await
        .err()
        .context("Ready without trusted host registration must fail")?;
    assert_eq!(denied.code, "TRUSTED_LAUNCH_REGISTRATION_REQUIRED");
    restarted
        .engine
        .wait(
            &unregistered,
            "WAITING_REGISTRATION",
            "TEST_REGISTRATION_PENDING",
            1,
        )
        .await
        .map_err(api_failure)?;
    register_mock_launch(&f, op, i.id).await?;
    stage(&f, &restarted, op).await?;
    for kind in ["Pod", "PersistentVolumeClaim", "CiliumNetworkPolicy"] {
        assert_eq!(
            mock.posts(kind)?,
            1,
            "recovery must adopt verified fixed identity"
        );
    }
    assert!(
        !first
            .engine
            .heartbeat(&old_claim)
            .await
            .map_err(api_failure)?
    );
    let mut tx = f.owner_transaction().await?;
    let (state,operation,ready):(String,String,bool)=sqlx::query_as("SELECT i.observed_state,o.status,i.ready_generation=i.runtime_generation AND i.ready_launch_id=i.launch_id AND i.ready_pod_uid=i.pod_uid AND i.ready_cluster_epoch=i.cluster_epoch FROM instances i JOIN operations o ON o.id=$1 WHERE i.id=$2").bind(op).bind(i.id).fetch_one(&mut *tx).await?;
    assert_eq!(
        (state.as_str(), operation.as_str(), ready),
        ("RUNNING", "SUCCEEDED", true)
    );
    let pending: i64 = sqlx::query_scalar("SELECT sum(pending)::bigint FROM quota_accounts")
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(pending, 0);
    tx.commit().await?;
    let stopped = f
        .database
        .lifecycle_action(
            &f.actor,
            i.id,
            InstanceAction::Stop,
            &StartRequest::default(),
            "worker-stop",
            i.spec_version,
            300,
            86400,
        )
        .await
        .map_err(api_failure)?;
    assert!(
        restarted.engine.claim_termination().await.is_err(),
        "compute worker must not claim trusted termination work"
    );
    let mut tx = f.owner_transaction().await?;
    let (state,status,queue):(String,String,String)=sqlx::query_as("SELECT i.observed_state,o.status,d.queue_role FROM instances i JOIN operations o ON o.id=i.active_operation_id JOIN operation_dispatch d ON d.operation_id=o.id WHERE i.id=$1 AND o.id=$2")
        .bind(i.id).bind(stopped.body.operation.id).fetch_one(&mut *tx).await?;
    assert_ne!(state, "STOPPED");
    assert_ne!(status, "SUCCEEDED");
    assert_eq!(queue, "TERMINATION");
    let allocated:i64=sqlx::query_scalar("SELECT sum(allocated)::bigint FROM quota_accounts WHERE dimension IN ('CPU_MILLIS','MEMORY_MIB')").fetch_one(&mut *tx).await?;
    ensure!(
        allocated > 0,
        "uncertain termination must retain compute quota"
    );
    tx.commit().await?;
    let state = mock
        .state
        .lock()
        .map_err(|_| anyhow::anyhow!("mock lock"))?;
    assert_eq!(state.deletes, 0);
    let pod = state
        .objects
        .values()
        .find(|v| v["kind"] == "Pod")
        .context("pod retained")?;
    assert!(
        pod["metadata"]["finalizers"]
            .as_array()
            .context("finalizers")?
            .contains(&json!("sandbox.platform/termination-protection"))
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires PostgreSQL and TEST_WORKER_DATABASE_URL"]
async fn missing_known_pvc_fails_closed_without_replacement_or_ready() -> anyhow::Result<()> {
    let _serial = support::serial().await;
    let f = fixture().await?;
    let a = f.create("worker-lost-pvc").await.map_err(api_failure)?;
    let mock = MockKube::new(&f, &a.body.resource, a.body.operation.id).await?;
    let w = worker(&f, &mock, "worker-lost-volume").await?;
    stage(&f, &w, a.body.operation.id).await?;
    stage(&f, &w, a.body.operation.id).await?;
    mock.remove("PersistentVolumeClaim")?;
    let c = claim(&f, &w, a.body.operation.id).await?;
    let e = w
        .reconcile(&c)
        .await
        .err()
        .context("missing known volume must fail")?;
    assert_eq!(e.code, "RUNTIME_RESOURCE_DRIFT");
    assert_eq!(mock.posts("PersistentVolumeClaim")?, 1);
    assert_eq!(mock.posts("Pod")?, 0);
    let mut tx = f.owner_transaction().await?;
    let state: String = sqlx::query_scalar("SELECT observed_state FROM instances WHERE id=$1")
        .bind(a.body.resource.id)
        .fetch_one(&mut *tx)
        .await?;
    assert_ne!(state, "RUNNING");
    // Historical deletion evidence must not authorize a new empty PVC for the
    // same workspace. Restrict fixture mutation explicitly as well as by RLS.
    sqlx::query("UPDATE external_resources SET status='DELETED',deleted_at=clock_timestamp() WHERE tenant_id=$1 AND instance_id=$2 AND kind='PVC'")
        .bind(f.actor.tenant_id).bind(a.body.resource.id).execute(&mut *tx).await?;
    tx.commit().await?;
    assert_eq!(
        w.reconcile(&c)
            .await
            .err()
            .context("deleted volume ledger must block")?
            .code,
        "RESOURCE_LEDGER_MISMATCH"
    );
    assert_eq!(mock.posts("PersistentVolumeClaim")?, 1);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires PostgreSQL and TEST_WORKER_DATABASE_URL"]
async fn safe_mode_and_live_revocation_block_remote_create() -> anyhow::Result<()> {
    let _serial = support::serial().await;
    let f = fixture().await?;
    let a = f.create("worker-safe-mode").await.map_err(api_failure)?;
    let mock = MockKube::new(&f, &a.body.resource, a.body.operation.id).await?;
    let w = worker(&f, &mock, "worker-safe-mode").await?;
    let c = claim(&f, &w, a.body.operation.id).await?;
    sqlx::query("UPDATE platform_configuration SET safe_mode=true")
        .execute(&f.owner)
        .await?;
    let result = w.reconcile(&c).await;
    sqlx::query("UPDATE platform_configuration SET safe_mode=false")
        .execute(&f.owner)
        .await?;
    assert_eq!(
        result.err().context("safe mode must block")?.code,
        "SAFE_MODE"
    );
    assert_eq!(mock.posts("CiliumNetworkPolicy")?, 0);
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE grants SET revoked_at=clock_timestamp() WHERE action='instances:create'")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    assert_eq!(
        w.reconcile(&c)
            .await
            .err()
            .context("revocation must block")?
            .code,
        "PERMISSION_DENIED"
    );
    assert_eq!(mock.posts("CiliumNetworkPolicy")?, 0);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL and a same-database non-owner TEST_WORKER_DATABASE_URL"]
async fn supervised_timer_skips_hundred_locked_workspaces_and_accepts_later_expiry()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let f = Fixture::new(110).await?;
    let mut workspaces = Vec::new();
    let mut blocked_instances = Vec::new();
    for n in 0..100 {
        let created = f
            .create(&format!("timer-lock-{n}"))
            .await
            .map_err(api_failure)?;
        workspaces.push(created.body.resource.workspace_id);
        blocked_instances.push(created.body.resource.id);
    }
    let healthy = f
        .create("timer-lock-later-healthy")
        .await
        .map_err(api_failure)?;
    let mock = MockKube::new(&f, &healthy.body.resource, healthy.body.operation.id).await?;
    let w = worker(&f, &mock, "timer-physical-locks").await?;
    let runtime_pool = w.engine.database.pool.clone();
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE instances SET compute_lease_started_at='0001-01-01T00:00:00Z',compute_lease_expires_at='0001-01-01T00:01:00Z' WHERE tenant_id=$1 AND id=ANY($2)")
        .bind(f.actor.tenant_id).bind(&blocked_instances).execute(&mut *tx).await?;
    sqlx::query("UPDATE instances SET compute_lease_started_at='0002-01-01T00:00:00Z',compute_lease_expires_at='0002-01-01T00:01:00Z' WHERE tenant_id=$1 AND id=$2")
        .bind(f.actor.tenant_id).bind(healthy.body.resource.id).execute(&mut *tx).await?;
    tx.commit().await?;
    let mut holder = f.owner_transaction().await?;
    let locked: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM workspaces WHERE tenant_id=$1 AND id=ANY($2) ORDER BY id FOR UPDATE",
    )
    .bind(f.actor.tenant_id)
    .bind(&workspaces)
    .fetch_all(&mut *holder)
    .await?;
    ensure!(
        locked.len() == 100,
        "Trial must own all hundred physical workspace row locks"
    );
    let shutdown = tokio_util::sync::CancellationToken::new();
    let mut task = tokio::spawn(w.run(shutdown.clone()));
    let outcome=async{
        let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(15);
        loop{
            ensure!(!task.is_finished(),"A contested row was classified as permanent controller failure");
            let mut tx=f.owner_transaction().await?;
            let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM operations WHERE tenant_id=$1 AND instance_id=$2 AND kind='STOP'),(SELECT count(*) FROM operations WHERE tenant_id=$1 AND instance_id=ANY($3) AND kind='STOP')")
                .bind(f.actor.tenant_id).bind(healthy.body.resource.id).bind(&blocked_instances).fetch_one(&mut *tx).await?;
            tx.commit().await?;
            ensure!(tokio::time::Instant::now()<deadline && counts.0<=1 && counts.1==0,
                "Later expiry was starved, duplicated or a held workspace lock was bypassed");
            if counts.0==1{break;}
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        // The holder is still live. Success therefore proves timer progress
        // without releasing/resetting the hundred earlier row locks.
        let mut tx=f.owner_transaction().await?;
        let retained:i64=sqlx::query_scalar("SELECT count(*) FROM instances WHERE tenant_id=$1 AND id=ANY($2) AND desired_state='RUNNING' AND stop_accepted_at IS NULL AND compute_lease_expires_at='0001-01-01T00:01:00Z'")
            .bind(f.actor.tenant_id).bind(&blocked_instances).fetch_one(&mut *tx).await?;
        ensure!(retained==100,"Timer retry changed deadlines or mutated a contested instance");
        tx.commit().await?;
        ensure!(mock.posts("Pod")?==0,"Expired work must not create a guest Pod");
        Ok::<(),anyhow::Error>(())
    }.await;
    shutdown.cancel();
    let joined = match tokio::time::timeout(std::time::Duration::from_secs(35), &mut task).await {
        Ok(result) => result
            .context("Actual worker task failed")
            .and_then(|result| result),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(anyhow::anyhow!(
                "Actual worker failed bounded timer shutdown"
            ))
        }
    };
    let released = holder.rollback().await;
    runtime_pool.close().await;
    f.database.pool.close().await;
    f.owner.close().await;
    outcome?;
    released?;
    joined?;
    println!("WORKER_TIMER_HUNDRED_LOCKS_LATER_STOP_WITHOUT_DEADLINE_CHANGE_VERIFIED");
    Ok(())
}
