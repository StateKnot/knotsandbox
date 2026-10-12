use super::*;

#[test]
fn incident_input_requires_explicit_platform_identity_and_bounded_reference() {
    assert!(NodeFenceRequest::parse(b"{}").is_err());
    assert!(NodeFenceRequest::parse(&vec![b' '; 16385]).is_err());
}

use crate::{
    cloud_fencing::{CloudFencingConfig, CloudInstanceBinding},
    model::{CreateExecution, ExecutionTimeoutPolicy},
    test_support_db::{self, Fixture, api_failure, require_pg_error},
};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, Response},
    routing::any,
};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
};
const ACCOUNT: &str = "1234567890123456";
const REGION: &str = "cn-hangzhou";
#[derive(Clone)]
struct MockCloud {
    instance: String,
    mode: Arc<AtomicU8>,
    stops: Arc<AtomicUsize>,
    session: Arc<Mutex<String>>,
}
struct CloudFixture {
    client: AlibabaCloudFencing,
    state: MockCloud,
    server: tokio::task::JoinHandle<()>,
    _token: tempfile::NamedTempFile,
}
impl Drop for CloudFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl CloudFixture {
    async fn new(instance: String) -> anyhow::Result<Self> {
        let token = tempfile::NamedTempFile::new()?;
        std::fs::write(token.path(), "PUBLIC_NODE_FENCING_TEST_OIDC")?;
        let state = MockCloud {
            instance: instance.clone(),
            mode: Arc::new(AtomicU8::new(0)),
            stops: Arc::new(AtomicUsize::new(0)),
            session: Arc::new(Mutex::new(String::new())),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = url::Url::parse(&format!("http://{}/", listener.local_addr()?))?;
        let app = Router::new()
            .fallback(any(cloud_request))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = AlibabaCloudFencing::for_test(
            CloudFencingConfig {
                account_id: ACCOUNT.into(),
                region: REGION.into(),
                role_arn: format!("acs:ram::{ACCOUNT}:role/sandbox-fencing"),
                role_id: "1234567890123457".into(),
                oidc_provider_arn: format!("acs:ram::{ACCOUNT}:oidc-provider/sandbox"),
                oidc_issuer: "https://node-test.example.test".into(),
                oidc_audience: "sts.aliyuncs.com".into(),
                oidc_subject: "system:serviceaccount:sandbox-system:sandbox-fencing".into(),
                oidc_token_file: token.path().to_owned(),
                instances: vec![CloudInstanceBinding {
                    instance_id: instance,
                    vpc_id: "vpc-testnetwork".into(),
                    private_ip: "10.0.1.4".parse()?,
                    deployment: "node-fencing-test".into(),
                }],
                requests_per_second: 20,
                max_in_flight: 4,
            },
            endpoint,
        )?;
        Ok(Self {
            client,
            state,
            server,
            _token: token,
        })
    }
}
async fn cloud_request(State(s): State<MockCloud>, r: Request<Body>) -> Response<Body> {
    let query: BTreeMap<String, String> =
        url::form_urlencoded::parse(r.uri().query().unwrap_or("").as_bytes())
            .into_owned()
            .collect();
    let mode = s.mode.load(Ordering::SeqCst);
    let action = r
        .headers()
        .get("x-acs-action")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (status, body) = match action {
        "AssumeRoleWithOIDC" => {
            let session = query.get("RoleSessionName").cloned().unwrap_or_default();
            if let Ok(mut saved) = s.session.lock() {
                *saved = session.clone();
            }
            (
                200,
                json!({"RequestId":"test-sts","AssumedRoleUser":{"Arn":format!("acs:ram::{ACCOUNT}:role/sandbox-fencing/{session}"),"AssumedRoleId":"test-id"},"OIDCTokenInfo":{"Issuer":"https://node-test.example.test","Subject":"system:serviceaccount:sandbox-system:sandbox-fencing","ClientIds":"sts.aliyuncs.com","VerificationInfo":"Success","ExpirationTime":Utc::now()+Duration::seconds(600),"IssuanceTime":Utc::now()-Duration::seconds(10)},"Credentials":{"AccessKeyId":"STS.public-test","AccessKeySecret":"PUBLIC_TEST_SECRET","SecurityToken":"PUBLIC_TEST_TOKEN","Expiration":Utc::now()+Duration::seconds(900)}}),
            )
        }
        "GetCallerIdentity" => {
            let session = s.session.lock().map(|v| v.clone()).unwrap_or_default();
            (
                200,
                json!({"RequestId":"test-identity","AccountId":ACCOUNT,"IdentityType":"AssumedRoleUser","Arn":format!("acs:ram::{ACCOUNT}:role/sandbox-fencing/{session}"),"RoleId":"1234567890123457"}),
            )
        }
        "DescribeInstances" => {
            if mode == 3 {
                (403, json!({"RequestId":"test-denied","Code":"Forbidden"}))
            } else {
                (
                    200,
                    json!({"RequestId":"test-observe","NextToken":"","Instances":{"Instance":[{"InstanceId":s.instance,"RegionId":REGION,"InstanceNetworkType":"vpc","Status":if mode==2{"Stopped"}else{"Running"},"VpcAttributes":{"VpcId":"vpc-testnetwork","PrivateIpAddress":{"IpAddress":["10.0.1.4"]}},"Tags":{"Tag":[{"TagKey":"Deployment","TagValue":"node-fencing-test"},{"TagKey":"Role","TagValue":"kata"}]}}]}}),
                )
            }
        }
        "StopInstance" => {
            s.stops.fetch_add(1, Ordering::SeqCst);
            assert_eq!(query.get("ForceStop").map(String::as_str), Some("true"));
            assert_eq!(
                query.get("StoppedMode").map(String::as_str),
                Some("KeepCharging")
            );
            if mode == 1 {
                (
                    503,
                    json!({"RequestId":"test-unknown","Code":"Unavailable"}),
                )
            } else {
                (200, json!({"RequestId":"test-stop"}))
            }
        }
        _ => (
            400,
            json!({"RequestId":"unknown-action","Code":"InvalidAction"}),
        ),
    };
    let mut response = Response::new(Body::from(body.to_string()));
    *response.status_mut() = axum::http::StatusCode::from_u16(status)
        .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    response
}
struct TenantLaunch {
    f: Fixture,
    instance: Uuid,
    permit: Uuid,
}
struct IncidentFixture {
    tenants: Vec<TenantLaunch>,
    owner: Database,
    controller: NodeFencingController,
    request: NodeFenceRequest,
    cloud: CloudFixture,
}
impl IncidentFixture {
    async fn new() -> anyhow::Result<Self> {
        let first = Fixture::new(10).await?;
        sqlx::raw_sql(include_str!("../scripts/sql/fencing-role.sql"))
            .execute(&first.owner)
            .await?;
        let url = std::env::var("TEST_FENCING_DATABASE_URL")
            .context("TEST_FENCING_DATABASE_URL required")?;
        let actual = url::Url::parse(&url)?;
        let expected = url::Url::parse(&std::env::var("TEST_DATABASE_URL")?)?;
        ensure!(
            actual.username() == "sandbox_fencing"
                && actual.path().ends_with("_test")
                && actual.host_str() == expected.host_str()
                && actual.port_or_known_default() == expected.port_or_known_default()
                && actual.path() == expected.path(),
            "dedicated fencing login must use disposable test DB"
        );
        let db = Database::connect(&url, 5).await?;
        db.verify_runtime_role().await?;
        let second = Fixture::new(10).await?;
        let owner = Database {
            pool: first.owner.clone(),
        };
        let epoch: Uuid =
            sqlx::query_scalar("SELECT cluster_epoch FROM platform_configuration WHERE singleton")
                .fetch_one(&owner.pool)
                .await?;
        let node = NodeBinding {
            cluster_epoch: epoch,
            node_uid: Uuid::new_v4(),
            node_name: format!("node-{}", Uuid::new_v4().simple()),
            boot_id: Uuid::new_v4(),
            profile_sha256: "ab".repeat(32),
        };
        let cloud_id = format!("i-{}", Uuid::new_v4().simple());
        let node_id = Uuid::new_v4();
        sqlx::query("INSERT INTO runtime_nodes(id,cluster_epoch,node_uid,node_name,boot_id,profile_sha256,cloud_provider,cloud_account_id,region,cloud_instance_id,private_ip,enabled) VALUES($1,$2,$3,$4,$5,$6,'alicloud',$7,$8,$9,'10.0.1.4',true)")
            .bind(node_id).bind(epoch).bind(node.node_uid).bind(&node.node_name).bind(node.boot_id).bind(&node.profile_sha256).bind(ACCOUNT).bind(REGION).bind(&cloud_id).execute(&owner.pool).await?;
        let mut cert = owner.pool.begin().await?;
        test_support_db::seed_test_node_certification(
            &mut cert,
            node_id,
            Utc::now() + Duration::days(1),
        )
        .await?;
        cert.commit().await?;
        let mut tenants = vec![];
        for f in [first, second] {
            let created = f.create("node-fence-vm").await.map_err(api_failure)?;
            let instance = created.body.resource.id;
            let permit = Uuid::new_v4();
            let mut tx = f.owner_transaction().await?;
            sqlx::query("UPDATE instances SET pod_uid=$3,observed_state='STARTING',ready_generation=runtime_generation,ready_launch_id=launch_id,ready_pod_uid=$3,ready_cluster_epoch=cluster_epoch,ready_observed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
                .bind(f.actor.tenant_id).bind(instance).bind(Uuid::new_v4()).execute(&mut *tx).await?;
            seed_permit(&mut tx, f.actor.tenant_id, instance, node_id, permit).await?;
            tx.commit().await?;
            tenants.push(TenantLaunch {
                f,
                instance,
                permit,
            });
        }
        let cloud = CloudFixture::new(cloud_id.clone()).await?;
        let controller =
            NodeFencingController::new(db, cloud.client.clone(), Uuid::new_v4().to_string())?;
        Ok(Self {
            tenants,
            owner,
            controller,
            request: NodeFenceRequest {
                incident_id: Uuid::new_v4(),
                runtime_node_id: node_id,
                node,
                cloud_account_id: ACCOUNT.into(),
                region: REGION.into(),
                cloud_instance_id: cloud_id,
                reason: IncidentReason::NodeUnreachable,
                reference: "TEST-ONLY-NODE-INCIDENT".into(),
            },
            cloud,
        })
    }
    async fn accept(&self) -> anyhow::Result<()> {
        let receipt = request_node_fence(&self.owner, &self.request).await?;
        assert_eq!(receipt.affected_launches, 2);
        Ok(())
    }
    async fn due_claim(&self) -> anyhow::Result<FenceClaim> {
        sqlx::query("UPDATE node_fence_incidents SET next_attempt_at=(SELECT min(next_attempt_at)-interval '1 day' FROM node_fence_incidents) WHERE id=$1").bind(self.request.incident_id).execute(&self.owner.pool).await?;
        let c = self
            .controller
            .claim()
            .await?
            .context("test incident claim")?;
        assert_eq!(c.id, self.request.incident_id);
        Ok(c)
    }
    async fn stage(&self) -> anyhow::Result<()> {
        let c = self.due_claim().await?;
        self.controller.reconcile(&c).await
    }
    async fn state(&self) -> anyhow::Result<String> {
        Ok(
            sqlx::query_scalar("SELECT state FROM node_fence_incidents WHERE id=$1")
                .bind(self.request.incident_id)
                .fetch_one(&self.owner.pool)
                .await?,
        )
    }
}
async fn seed_permit(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    instance: Uuid,
    node: Uuid,
    permit: Uuid,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO launch_permits(id,tenant_id,project_id,instance_id,workspace_id,operation_id,runtime_node_id,cluster_epoch,generation,launch_id,pod_uid,namespace,pod_name,pvc_uid,pv_uid,pv_name,csi_volume_handle,expires_at) SELECT $1,tenant_id,project_id,id,workspace_id,active_operation_id,$2,cluster_epoch,runtime_generation,launch_id,pod_uid,namespace,pod_name,$3,$4,'test-only-pv','test-only-disk',compute_lease_expires_at FROM instances WHERE tenant_id=$5 AND id=$6")
        .bind(permit).bind(node).bind(Uuid::new_v4()).bind(Uuid::new_v4()).bind(tenant).bind(instance).execute(&mut **tx).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL dedicated fencing role and loopback cloud HTTP"]
async fn system_incident_freezes_all_tenants_but_never_releases_resources() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = IncidentFixture::new().await?;
    let row = &f.tenants[0];
    row.f.seed_observed_state(row.instance, "RUNNING").await?;
    let mut tx = row.f.owner_transaction().await?;
    sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,'executions:create')").bind(row.f.actor.tenant_id).bind(row.f.request.project_id).bind(row.f.actor.principal_id).execute(&mut *tx).await?;
    for project in [None, Some(row.f.request.project_id)] {
        sqlx::query("INSERT INTO quota_accounts(tenant_id,project_id,dimension,limit_value) VALUES($1,$2,'EXECUTIONS',5)").bind(row.f.actor.tenant_id).bind(project).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    let command = CreateExecution {
        argv: vec!["/usr/bin/true".into()],
        public_env: BTreeMap::new(),
        cwd: "/workspace".into(),
        timeout_seconds: 60,
        on_timeout: ExecutionTimeoutPolicy::HardStopInstance,
        output_limit_bytes: 1024,
        client_reference: None,
    };
    let execution = row
        .f
        .database
        .create_execution(&row.f.actor, row.instance, &command, "fence-exec", 1)
        .await
        .map_err(api_failure)?;
    ensure!(
        request_node_fence(&row.f.database, &f.request)
            .await
            .is_err(),
        "tenant hard_stop must not authorize node incidents"
    );
    f.accept().await?;
    assert!(!request_node_fence(&f.owner, &f.request).await?.changed);
    let mut changed = f.request.clone();
    changed.reference = "different".into();
    assert!(request_node_fence(&f.owner, &changed).await.is_err());
    f.stage().await?;
    assert_eq!(f.state().await?, "READY_TO_STOP");
    for row in &f.tenants {
        let i = row
            .f
            .database
            .get_instance(&row.f.actor, row.instance)
            .await
            .map_err(api_failure)?;
        assert_eq!(i.desired_state, "STOPPED");
        let mut tx = row.f.owner_transaction().await?;
        let system:bool=sqlx::query_scalar("SELECT p.kind='SYSTEM' FROM operations o JOIN principals p ON p.id=o.actor_principal_id WHERE o.id=$1").bind(i.active_operation_id).fetch_one(&mut *tx).await?;
        assert!(system);
        let released: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM quota_reservations WHERE tenant_id=$1 AND status='RELEASED'",
        )
        .bind(row.f.actor.tenant_id)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(released, 0);
        let audits:i64=sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='instances:node_fence'").bind(row.f.actor.tenant_id).fetch_one(&mut *tx).await?;
        assert_eq!(audits, 1);
        tx.commit().await?;
    }
    let mut tx = row.f.owner_transaction().await?;
    let status: (String, String, bool) =
        sqlx::query_as("SELECT status,termination_status,slot_held FROM executions WHERE id=$1")
            .bind(execution.body.resource.id)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(status, ("CANCELLED".into(), "PENDING".into(), true));
    tx.commit().await?;
    f.stage().await?;
    assert_eq!(f.cloud.state.stops.load(Ordering::SeqCst), 1);
    assert_eq!(f.state().await?, "OBSERVING");
    f.cloud.state.mode.store(2, Ordering::SeqCst);
    f.stage().await?;
    assert_eq!(f.state().await?, "STOPPED_OBSERVED");
    for row in &f.tenants {
        let mut tx = row.f.owner_transaction().await?;
        let released: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM quota_reservations WHERE tenant_id=$1 AND status='RELEASED'",
        )
        .bind(row.f.actor.tenant_id)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(released, 0);
        tx.commit().await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL dedicated fencing role and loopback cloud HTTP"]
async fn unknown_stop_is_not_replayed_and_reanimation_becomes_permanent_breach()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = IncidentFixture::new().await?;
    f.accept().await?;
    f.stage().await?;
    f.cloud.state.mode.store(1, Ordering::SeqCst);
    f.stage().await?;
    assert_eq!(f.state().await?, "OBSERVING");
    f.stage().await?;
    assert_eq!(f.cloud.state.stops.load(Ordering::SeqCst), 1);
    f.cloud.state.mode.store(2, Ordering::SeqCst);
    f.stage().await?;
    assert_eq!(f.state().await?, "STOPPED_OBSERVED");
    f.cloud.state.mode.store(0, Ordering::SeqCst);
    f.stage().await?;
    assert_eq!(f.state().await?, "BREACH");
    assert_eq!(f.cloud.state.stops.load(Ordering::SeqCst), 1);
    require_pg_error(
        sqlx::query("UPDATE node_fence_incidents SET state='OBSERVING',breach_at=NULL WHERE id=$1")
            .bind(f.request.incident_id)
            .execute(&f.owner.pool)
            .await,
        "23514",
    )?;
    require_pg_error(
        sqlx::query("DELETE FROM node_fence_incidents WHERE id=$1")
            .bind(f.request.incident_id)
            .execute(&f.owner.pool)
            .await,
        "23514",
    )?;
    require_pg_error(
        sqlx::query("UPDATE runtime_nodes SET enabled=true WHERE id=$1")
            .bind(f.request.runtime_node_id)
            .execute(&f.owner.pool)
            .await,
        "23514",
    )?;
    require_pg_error(sqlx::query("INSERT INTO runtime_nodes(cluster_epoch,node_uid,node_name,boot_id,profile_sha256,cloud_provider,cloud_account_id,region,cloud_instance_id,private_ip,enabled) SELECT cluster_epoch,$2,'replacement-name',$3,profile_sha256,cloud_provider,cloud_account_id,region,cloud_instance_id,private_ip,false FROM runtime_nodes WHERE id=$1").bind(f.request.runtime_node_id).bind(Uuid::new_v4()).bind(Uuid::new_v4()).execute(&f.owner.pool).await,"23514")?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL dedicated fencing role and loopback cloud HTTP"]
async fn committed_dispatch_crash_and_preflight_failure_both_recover_by_observation_only()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    for preflight_failure in [false, true] {
        let f = IncidentFixture::new().await?;
        f.accept().await?;
        f.stage().await?;
        if preflight_failure {
            f.cloud.state.mode.store(3, Ordering::SeqCst);
            f.stage().await?;
        } else {
            let claim = f.due_claim().await?;
            let (left, right) = tokio::join!(
                f.controller.begin_dispatch(&claim),
                f.controller.begin_dispatch(&claim)
            );
            let tickets = [left?, right?];
            assert_eq!(tickets.iter().filter(|t| t.is_some()).count(), 1);
            // Simulate process death after durable intent, before HTTP send.
            sqlx::query("UPDATE node_fence_incidents SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1").bind(f.request.incident_id).execute(&f.owner.pool).await?;
        }
        f.cloud.state.mode.store(0, Ordering::SeqCst);
        f.stage().await?;
        assert_eq!(f.cloud.state.stops.load(Ordering::SeqCst), 0);
        assert_eq!(f.state().await?, "OBSERVING");
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL dedicated fencing role"]
async fn freeze_waiting_on_tenant_or_stream_lock_cannot_commit_after_its_lease_expires()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    for stream_head in [false, true] {
        let f = IncidentFixture::new().await?;
        f.accept().await?;
        let claim = f.due_claim().await?;
        let row = &f.tenants[0];
        let mut blocking = row.f.owner_transaction().await?;
        if stream_head {
            sqlx::query("SELECT project_id FROM event_stream_heads WHERE tenant_id=$1 AND project_id=$2 FOR UPDATE")
            .bind(row.f.actor.tenant_id).bind(row.f.request.project_id).execute(&mut *blocking).await?;
        } else {
            sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=(SELECT workspace_id FROM instances WHERE tenant_id=$1 AND id=$2) FOR UPDATE")
            .bind(row.f.actor.tenant_id).bind(row.instance).execute(&mut *blocking).await?;
        }
        let expires: DateTime<Utc> = sqlx::query_scalar("UPDATE node_fence_incidents SET lease_until=clock_timestamp()+interval '1 second' WHERE id=$1 RETURNING lease_until").bind(f.request.incident_id).fetch_one(&f.owner.pool).await?;
        let mut connection = f.controller.db.pool.acquire().await?;
        let waiting_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *connection)
            .await?;
        let blocking_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocking)
            .await?;
        let permit = row.permit;
        let pending = tokio::spawn(async move {
            sqlx::query_scalar::<_, bool>("SELECT sandbox_freeze_node_launch($1,$2,$3,$4)")
                .bind(claim.id)
                .bind(permit)
                .bind(claim.worker)
                .bind(claim.token)
                .fetch_one(&mut *connection)
                .await
        });
        wait_for_blocker(&f.owner, waiting_pid, blocking_pid).await?;
        loop {
            let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&f.owner.pool)
                .await?;
            if now > expires {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(25)).await;
        }
        blocking.commit().await?;
        require_pg_error(pending.await?, "40001")?;
        let state: String = sqlx::query_scalar(
            "SELECT state FROM node_fence_targets WHERE incident_id=$1 AND permit_id=$2",
        )
        .bind(f.request.incident_id)
        .bind(row.permit)
        .fetch_one(&f.owner.pool)
        .await?;
        assert_eq!(state, "PENDING");
        assert_eq!(
            row.f
                .database
                .get_instance(&row.f.actor, row.instance)
                .await
                .map_err(api_failure)?
                .desired_state,
            "RUNNING"
        );
    }
    Ok(())
}

// These fixtures synthesize prerequisite DB identities only; they are not KVM,
// cloud, host-journal or termination evidence.
async fn wait_for_blocker(db: &Database, waiting: i32, blocking: i32) -> anyhow::Result<()> {
    tokio::time::timeout(StdDuration::from_secs(2), async {
        loop {
            let waits: bool = sqlx::query_scalar("SELECT $1=ANY(pg_blocking_pids($2))")
                .bind(blocking)
                .bind(waiting)
                .fetch_one(&db.pool)
                .await?;
            if waits {
                return Ok::<_, sqlx::Error>(());
            }
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
    })
    .await
    .context("expected database lock wait was not observed")??;
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL dedicated fencing role"]
async fn incident_waits_for_accepted_permit_and_rejects_every_late_launch_path()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = IncidentFixture::new().await?;
    let row = &f.tenants[0];
    let extra = row
        .f
        .create("concurrent-permit")
        .await
        .map_err(api_failure)?
        .body
        .resource
        .id;
    let mut writer = row.f.owner_transaction().await?;
    sqlx::query("UPDATE instances SET pod_uid=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(row.f.actor.tenant_id)
        .bind(extra)
        .bind(Uuid::new_v4())
        .execute(&mut *writer)
        .await?;
    let accepted = Uuid::new_v4();
    seed_permit(
        &mut writer,
        row.f.actor.tenant_id,
        extra,
        f.request.runtime_node_id,
        accepted,
    )
    .await?;
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await?;
    let incident = f.request.clone();
    // A single-connection owner pool gives the exact backend for the lock-wait assertion.
    let owner = Database::connect(&std::env::var("TEST_MIGRATION_DATABASE_URL")?, 1).await?;
    let waiter: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&owner.pool)
        .await?;
    let request = tokio::spawn(async move {
        let result = request_node_fence(&owner, &incident).await;
        owner.pool.close().await;
        result
    });
    wait_for_blocker(&f.owner, waiter, blocker).await?;
    writer.commit().await?;
    assert_eq!(request.await??.affected_launches, 3);
    let present: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM node_fence_targets WHERE incident_id=$1 AND permit_id=$2)",
    )
    .bind(f.request.incident_id)
    .bind(accepted)
    .fetch_one(&f.owner.pool)
    .await?;
    assert!(present);
    let late = row
        .f
        .create("late-permit")
        .await
        .map_err(api_failure)?
        .body
        .resource
        .id;
    let mut tx = row.f.owner_transaction().await?;
    sqlx::query("UPDATE instances SET pod_uid=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(row.f.actor.tenant_id)
        .bind(late)
        .bind(Uuid::new_v4())
        .execute(&mut *tx)
        .await?;
    let err = match seed_permit(
        &mut tx,
        row.f.actor.tenant_id,
        late,
        f.request.runtime_node_id,
        Uuid::new_v4(),
    )
    .await
    {
        Err(error) => error,
        Ok(()) => anyhow::bail!("fenced permit must fail"),
    };
    assert_eq!(
        err.downcast_ref::<sqlx::Error>()
            .and_then(sqlx::Error::as_database_error)
            .and_then(|e| e.code())
            .as_deref(),
        Some("23514")
    );
    tx.rollback().await?;
    let mut tx = row.f.owner_transaction().await?;
    require_pg_error(sqlx::query("INSERT INTO launch_permit_extensions(tenant_id,base_permit_id,compute_lease_id,compute_lease_version,expires_at) SELECT tenant_id,$2,compute_lease_id,compute_lease_version+1,compute_lease_expires_at+interval '1 minute' FROM instances WHERE tenant_id=$1 AND id=$3")
        .bind(row.f.actor.tenant_id).bind(row.permit).bind(row.instance).execute(&mut *tx).await,"23514")?;
    tx.rollback().await?;
    let mut tx = row.f.owner_transaction().await?;
    let cert: (bool, Option<DateTime<Utc>>) =
        sqlx::query_as("SELECT assigned,valid_until FROM sandbox_instance_certification($1,$2)")
            .bind(row.f.actor.tenant_id)
            .bind(row.instance)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(
        cert,
        (true, None),
        "existing Ready/CONNECT and renew share this mandatory certification gate"
    );
    tx.commit().await?;
    // The runtime identity cannot mint incidents or mutate resources/proofs.
    for statement in [
        "INSERT INTO node_fence_incidents(id) VALUES(gen_random_uuid())",
        "UPDATE runtime_nodes SET enabled=true WHERE false",
        "UPDATE quota_reservations SET status='RELEASED' WHERE false",
        "INSERT INTO local_termination_proofs(id) VALUES(gen_random_uuid())",
    ] {
        require_pg_error(
            sqlx::query(statement).execute(&f.controller.db.pool).await,
            "42501",
        )?;
    }
    require_pg_error(
        sqlx::query("SELECT sandbox_freeze_node_launch($1,$2,$3,$4)")
            .bind(f.request.incident_id)
            .bind(row.permit)
            .bind("tenant-forgery")
            .bind(1_i64)
            .execute(&row.f.database.pool)
            .await,
        "42501",
    )?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL dedicated fencing role"]
async fn cloud_tombstone_covers_historical_node_identity_and_its_launches() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = IncidentFixture::new().await?;
    let previous = f.request.runtime_node_id;
    sqlx::query("UPDATE runtime_nodes SET enabled=false WHERE id=$1")
        .bind(previous)
        .execute(&f.owner.pool)
        .await?;
    let next = Uuid::new_v4();
    let mut incident = f.request.clone();
    incident.runtime_node_id = next;
    incident.node.node_uid = Uuid::new_v4();
    incident.node.boot_id = Uuid::new_v4();
    sqlx::query("INSERT INTO runtime_nodes(id,cluster_epoch,node_uid,node_name,boot_id,profile_sha256,cloud_provider,cloud_account_id,region,cloud_instance_id,private_ip,enabled) SELECT $2,cluster_epoch,$3,node_name,$4,profile_sha256,cloud_provider,cloud_account_id,region,cloud_instance_id,private_ip,true FROM runtime_nodes WHERE id=$1")
        .bind(previous).bind(next).bind(incident.node.node_uid).bind(incident.node.boot_id).execute(&f.owner.pool).await?;
    assert_eq!(
        request_node_fence(&f.owner, &incident)
            .await?
            .affected_launches,
        2
    );
    f.stage().await?;
    assert_eq!(f.state().await?, "READY_TO_STOP");
    for row in &f.tenants {
        assert_eq!(
            row.f
                .database
                .get_instance(&row.f.actor, row.instance)
                .await
                .map_err(api_failure)?
                .desired_state,
            "STOPPED"
        );
    }
    require_pg_error(
        sqlx::query("UPDATE runtime_nodes SET enabled=true WHERE id=$1")
            .bind(previous)
            .execute(&f.owner.pool)
            .await,
        "23514",
    )?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL dedicated fencing role"]
async fn null_empty_or_unclaimed_fencing_identity_cannot_freeze_any_launch() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = IncidentFixture::new().await?;
    f.accept().await?;
    let row = &f.tenants[0];
    for (worker, token, code) in [
        (None, None, "22023"),
        (Some(""), Some(1_i64), "22023"),
        (Some("forged"), None, "22023"),
        (None, Some(1_i64), "22023"),
        (Some("forged"), Some(0_i64), "22023"),
        (Some("forged"), Some(1_i64), "40001"),
    ] {
        require_pg_error(
            sqlx::query("SELECT sandbox_freeze_node_launch($1,$2,$3,$4)")
                .bind(f.request.incident_id)
                .bind(row.permit)
                .bind(worker)
                .bind(token)
                .execute(&f.controller.db.pool)
                .await,
            code,
        )?;
    }
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM node_fence_targets WHERE incident_id=$1 AND state='PENDING'",
    )
    .bind(f.request.incident_id)
    .fetch_one(&f.owner.pool)
    .await?;
    assert_eq!(pending, 2);
    assert_eq!(
        row.f
            .database
            .get_instance(&row.f.actor, row.instance)
            .await
            .map_err(api_failure)?
            .desired_state,
        "RUNNING"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL dedicated fencing role"]
async fn historical_epoch_incidents_do_not_starve_current_node_safety_work() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = IncidentFixture::new().await?;
    f.accept().await?;
    sqlx::query("UPDATE node_fence_incidents SET next_attempt_at=(SELECT min(next_attempt_at)-interval '1 day' FROM node_fence_incidents) WHERE id=$1")
        .bind(f.request.incident_id).execute(&f.owner.pool).await?;
    // Synthetic restored-history fixture. No current epoch is changed and no
    // test claims this owner-seeded row is real cloud evidence.
    let old_node = Uuid::new_v4();
    let old_epoch = Uuid::new_v4();
    let old_incident = Uuid::new_v4();
    sqlx::query("INSERT INTO runtime_nodes(id,cluster_epoch,node_uid,node_name,boot_id,profile_sha256,cloud_provider,cloud_account_id,region,cloud_instance_id,private_ip,enabled) VALUES($1,$2,$3,$4,$5,$6,'alicloud',$7,$8,$9,'10.0.1.5',false)")
        .bind(old_node).bind(old_epoch).bind(Uuid::new_v4()).bind(format!("historical-{}",Uuid::new_v4().simple())).bind(Uuid::new_v4()).bind("bc".repeat(32)).bind(ACCOUNT).bind(REGION).bind(format!("i-{}",Uuid::new_v4().simple())).execute(&f.owner.pool).await?;
    sqlx::query("INSERT INTO node_fence_incidents(id,runtime_node_id,cluster_epoch,cloud_account_id,region,cloud_instance_id,request,request_sha256,requested_by,next_attempt_at) SELECT $1,id,cluster_epoch,cloud_account_id,region,cloud_instance_id,'{}'::jsonb,$3,'TEST_ONLY_RESTORE',(SELECT next_attempt_at-interval '1 day' FROM node_fence_incidents WHERE id=$4) FROM runtime_nodes WHERE id=$2")
        .bind(old_incident).bind(old_node).bind("00".repeat(32)).bind(f.request.incident_id).execute(&f.owner.pool).await?;
    let claim = f
        .controller
        .claim()
        .await?
        .context("current incident remains selectable")?;
    assert_eq!(claim.id, f.request.incident_id);
    let token: i64 = sqlx::query_scalar("SELECT lease_token FROM node_fence_incidents WHERE id=$1")
        .bind(old_incident)
        .fetch_one(&f.owner.pool)
        .await?;
    assert_eq!(token, 0);
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and the real restricted fencing login"]
async fn deferred_activity_checks_freeze_two_tenants_without_grants_or_context_leak()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = IncidentFixture::new().await?;
    f.accept().await?;
    let claim = f.due_claim().await?;
    let mut connection = f.controller.db.pool.acquire().await?;
    let boundary: (String, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT current_user::text,has_table_privilege(current_user,'public.instances','SELECT,INSERT,UPDATE,DELETE'),has_table_privilege(current_user,'public.file_transfers','SELECT,INSERT,UPDATE,DELETE'),has_function_privilege(current_user,'public.sandbox_file_activity_match()','EXECUTE'),(SELECT count(*)=2 AND bool_and(relrowsecurity AND relforcerowsecurity) FROM pg_class WHERE oid IN('public.instances'::regclass,'public.file_transfers'::regclass))",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(
        boundary,
        ("sandbox_fencing".into(), false, false, false, true)
    );
    let original_context: String =
        sqlx::query_scalar("SELECT COALESCE(current_setting('app.tenant_id',true),'')")
            .fetch_one(&mut *connection)
            .await?;
    let unrelated_tenant = Uuid::new_v4().to_string();
    let mut tx = sqlx::Connection::begin(&mut *connection).await?;
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(&unrelated_tenant)
        .execute(&mut *tx)
        .await?;
    for row in &f.tenants {
        let frozen: bool = sqlx::query_scalar("SELECT sandbox_freeze_node_launch($1,$2,$3,$4)")
            .bind(claim.id)
            .bind(row.permit)
            .bind(&claim.worker)
            .bind(claim.token)
            .fetch_one(&mut *tx)
            .await?;
        assert!(frozen);
        let current_context: String =
            sqlx::query_scalar("SELECT current_setting('app.tenant_id',true)")
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(current_context, unrelated_tenant);
    }
    // Both tenants' deferred instance checks must run under the exact NEW row
    // scope, although the physical caller cannot read either application table.
    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *tx)
        .await?;
    let after_checks: String = sqlx::query_scalar("SELECT current_setting('app.tenant_id',true)")
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(after_checks, unrelated_tenant);
    tx.commit().await?;
    let after_commit: String =
        sqlx::query_scalar("SELECT COALESCE(current_setting('app.tenant_id',true),'')")
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(after_commit, original_context);
    drop(connection);
    f.controller.reconcile(&claim).await?;
    assert_eq!(f.state().await?, "READY_TO_STOP");
    for row in &f.tenants {
        let instance = row
            .f
            .database
            .get_instance(&row.f.actor, row.instance)
            .await
            .map_err(api_failure)?;
        assert_eq!(instance.desired_state, "STOPPED");
        let mut tx = row.f.owner_transaction().await?;
        let released: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM quota_reservations WHERE tenant_id=$1 AND status='RELEASED'",
        )
        .bind(row.f.actor.tenant_id)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(released, 0);
        tx.commit().await?;
    }
    Ok(())
}
