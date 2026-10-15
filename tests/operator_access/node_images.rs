//! Installation node reads use the production HTTP router without tenant scope.
use super::*;
use axum::{
    body::{Body, to_bytes},
    extract::State,
    http::Request,
    response::IntoResponse,
    routing::post,
};
use sandbox_platform::{
    metrics::{
        MetricsAuthentication, MetricsBackendConfig, NodeImageMetricBinding, PrometheusMetrics,
    },
    node_image_query::NodeImageStatus,
};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
};
use tokio::sync::Notify;

async fn seed_node(
    fixture: &Fixture,
    expiry: chrono::DateTime<Utc>,
) -> anyhow::Result<(Uuid, NodeImageMetricBinding)> {
    let node = Uuid::new_v4();
    let binding = NodeImageMetricBinding {
        cluster_epoch: sqlx::query_scalar(
            "SELECT cluster_epoch FROM platform_configuration WHERE singleton",
        )
        .fetch_one(&fixture.owner)
        .await?,
        node_uid: Uuid::new_v4(),
        host_boot_id: Uuid::new_v4(),
        profile_sha256: "a".repeat(64),
    };
    let mut tx = fixture.owner.begin().await?;
    sqlx::query("INSERT INTO runtime_nodes(id,cluster_epoch,node_uid,node_name,cloud_provider,cloud_account_id,region,cloud_instance_id,private_ip,profile_sha256,boot_id,enabled) VALUES($1,$2,$3,'test-only-image-query','alicloud','test-account','test-region',$4,'10.2.3.4',$5,$6,true)")
        .bind(node).bind(binding.cluster_epoch).bind(binding.node_uid).bind(node.to_string()).bind(&binding.profile_sha256).bind(binding.host_boot_id).execute(&mut *tx).await?;
    support::seed_test_node_certification(&mut tx, node, expiry).await?;
    tx.commit().await?;
    Ok((node, binding))
}

#[derive(Clone)]
struct BackendState {
    binding: NodeImageMetricBinding,
    pause: Arc<AtomicBool>,
    reached: Arc<Notify>,
    release: Arc<Notify>,
    mode: Arc<AtomicU8>,
    hits: Arc<AtomicUsize>,
}
impl BackendState {
    fn new(binding: NodeImageMetricBinding) -> Self {
        Self {
            binding,
            pause: Arc::new(AtomicBool::new(false)),
            reached: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
            mode: Arc::new(AtomicU8::new(0)),
            hits: Arc::new(AtomicUsize::new(0)),
        }
    }
}

// Protocol fixture only: reports are synthetic, not physical-runtime certification.
fn report(binding: &NodeImageMetricBinding, evaluated: i64) -> Value {
    let mut rows = Vec::new();
    for (name, number) in [
        ("sandbox_node_image_inventory_observation_success", 1.0),
        ("sandbox_node_image_filesystem_observation_success", 0.0),
        (
            "sandbox_node_image_observed_at_seconds",
            (evaluated - 3) as f64,
        ),
        ("sandbox_node_image_inventory_count", 7.0),
        ("sandbox_node_image_compressed_logical_bytes", 10789.0),
        ("up", 1.0),
    ] {
        let mut labels = BTreeMap::from([
            ("__name__", name.to_owned()),
            ("deployment", "production-a".into()),
            ("cluster_epoch", binding.cluster_epoch.to_string()),
            ("collector_replica", "a".into()),
            ("job", format!("node-images-{}", binding.node_uid)),
            ("instance", "node.example:9443".into()),
        ]);
        if name == "up" {
            labels.extend([
                ("scrape_node_uid", binding.node_uid.to_string()),
                ("scrape_host_boot_id", binding.host_boot_id.to_string()),
                ("scrape_profile_sha256", binding.profile_sha256.clone()),
            ]);
        } else {
            labels.extend([
                ("node_uid", binding.node_uid.to_string()),
                ("host_boot_id", binding.host_boot_id.to_string()),
                ("profile_sha256", binding.profile_sha256.clone()),
                ("source", "RUNTIME_REPORTED".into()),
                ("completeness", "UNKNOWN".into()),
            ]);
        }
        for (kind, value) in [("value", number), ("sampled_at", (evaluated - 1) as f64)] {
            labels.insert("sandbox_value_kind", kind.into());
            rows.push(json!({"metric":labels,"value":[evaluated,value.to_string()]}));
        }
    }
    json!({"status":"success","data":{"resultType":"vector","result":rows}})
}

async fn backend_response(
    State(state): State<BackendState>,
    request: Request<Body>,
) -> axum::response::Response {
    let valid_auth = request
        .headers()
        .get("authorization")
        .is_some_and(|value| value == "Bearer PUBLIC_OPERATOR_QUERY_TEST_TOKEN");
    let body = match to_bytes(request.into_body(), 64 * 1024).await {
        Ok(body) => body,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let form: BTreeMap<String, String> = url::form_urlencoded::parse(&body).into_owned().collect();
    let Some(evaluated) = form.get("time").and_then(|v| v.parse::<i64>().ok()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !valid_auth
        || form.get("limit").map(String::as_str) != Some("217")
        || !form.get("query").is_some_and(|v| {
            v.contains(&state.binding.node_uid.to_string()) && !v.contains("sandbox_vm_")
        })
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    state.hits.fetch_add(1, Ordering::SeqCst);
    if state.pause.load(Ordering::SeqCst) {
        state.reached.notify_one();
        if tokio::time::timeout(Duration::from_secs(5), state.release.notified())
            .await
            .is_err()
        {
            return StatusCode::GATEWAY_TIMEOUT.into_response();
        }
    }
    match state.mode.load(Ordering::SeqCst) {
        1 => axum::Json(json!({"status":"success","data":{"resultType":"vector","result":[]}})).into_response(),
        2 => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        3 => axum::Json(json!({"status":"success","data":{"resultType":"vector","result":[],"unexpected":"private"}})).into_response(),
        _ => axum::Json(report(&state.binding,evaluated)).into_response(),
    }
}

struct TlsServer {
    endpoint: String,
    handle: axum_server::Handle<std::net::SocketAddr>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}
impl TlsServer {
    async fn start(router: Router) -> anyhow::Result<Self> {
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            include_bytes!("../fixtures/admission/server.pem").to_vec(),
            include_bytes!("../fixtures/admission/server.key").to_vec(),
        )
        .await?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let handle = axum_server::Handle::new();
        let server = axum_server::from_tcp_rustls(listener, tls)?.handle(handle.clone());
        let task = tokio::spawn(async move { server.serve(router.into_make_service()).await });
        Ok(Self {
            endpoint: format!("https://{address}"),
            handle,
            task,
        })
    }
    async fn close(mut self) -> anyhow::Result<()> {
        self.handle.graceful_shutdown(Some(Duration::from_secs(2)));
        match tokio::time::timeout(Duration::from_secs(3), &mut self.task).await {
            Ok(result) => {
                result??;
                Ok(())
            }
            Err(_) => {
                self.task.abort();
                let _joined = self.task.await;
                anyhow::bail!("Node query TLS fixture did not retire")
            }
        }
    }
}

async fn observed_node(
    fixture: &Fixture,
    expiry: chrono::DateTime<Utc>,
) -> anyhow::Result<(Uuid, BackendState, TlsServer, tempfile::NamedTempFile)> {
    let (node, binding) = seed_node(fixture, expiry).await?;
    let state = BackendState::new(binding);
    let token = tempfile::NamedTempFile::new()?;
    std::fs::write(token.path(), "PUBLIC_OPERATOR_QUERY_TEST_TOKEN")?;
    let server = TlsServer::start(
        Router::new()
            .route("/api/v1/query", post(backend_response))
            .with_state(state.clone()),
    )
    .await?;
    Ok((node, state, server, token))
}

fn query_app(
    fixture: &Fixture,
    auth: JwtAuthenticator,
    backend: PrometheusMetrics,
) -> anyhow::Result<Router> {
    Ok(router(Arc::new(AppState {
        database: fixture.database.clone(),
        auth,
        cursor_signer: sandbox_platform::history::CursorSigner::from_json(include_str!(
            "../fixtures/history/cursor-keys.json"
        ))?,
        output_reader: None,
        metrics: Some(backend),
        default_ttl_seconds: 300,
        max_ttl_seconds: 86400,
    })))
}

#[tokio::test]
#[ignore = "Requires real Keycloak, disposable PostgreSQL and SANDBOX_MACHINE_* credentials"]
async fn node_image_query_requires_current_installation_authority() -> anyhow::Result<()> {
    let _serial = support::serial().await;
    let (fixture, auth, identity, authorization) = prepare_live_fixture().await?;
    let outcome = async {
        let app = app(&fixture, auth)?;
        let path = format!("/v1/operator/nodes/{}/image-status", Uuid::new_v4());
        operator_response(&app, Some(&authorization), &path, StatusCode::FORBIDDEN).await?;
        operator_response(&app, None, &path, StatusCode::UNAUTHORIZED).await?;
        let document = live_grant_document(&fixture, &identity).await?;
        let grant = GrantNodeImageReader::parse(&serde_json::to_vec(&document)?, true)?;
        grant_node_image_reader(
            &Database {
                pool: fixture.owner.clone(),
            },
            &grant,
        )
        .await?;
        operator_response(&app, Some(&authorization), &path, StatusCode::NOT_FOUND).await?;
        operator_response(
            &app,
            Some(&authorization),
            &(path + "?query=up"),
            StatusCode::BAD_REQUEST,
        )
        .await?;
        let (node, _) = seed_node(&fixture, Utc::now() + ChronoDuration::minutes(10)).await?;
        let path = format!("/v1/operator/nodes/{node}/image-status");
        operator_response(
            &app,
            Some(&authorization),
            &path,
            StatusCode::SERVICE_UNAVAILABLE,
        )
        .await?;
        Ok(())
    }
    .await;
    finish_live_fixture(fixture, &identity, outcome).await
}

#[tokio::test]
#[ignore = "Requires real Keycloak, disposable PostgreSQL and SANDBOX_MACHINE_* credentials"]
async fn node_image_query_rechecks_authority_after_real_https_io() -> anyhow::Result<()> {
    let _serial = support::serial().await;
    let (fixture, auth, identity, authorization) = prepare_live_fixture().await?;
    let (node, state, server, token) =
        match observed_node(&fixture, Utc::now() + ChronoDuration::minutes(10)).await {
            Ok(setup) => setup,
            Err(error) => return finish_live_fixture(fixture, &identity, Err(error)).await,
        };
    let binding = state.binding.clone();
    let outcome=async {
        let backend=PrometheusMetrics::new(MetricsBackendConfig {endpoint:server.endpoint.clone(),deployment:"production-a".into(),auth:MetricsAuthentication::Bearer{token_file:token.path().into()},ca_file:Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/admission/server-ca.pem")),replicas:vec!["a".into(),"b".into()]}).await?;
        let app=query_app(&fixture,auth,backend)?;
        let owner=Database{pool:fixture.owner.clone()};
        let document=live_grant_document(&fixture,&identity).await?;
        let mut grant=GrantNodeImageReader::parse(&serde_json::to_vec(&document)?,true)?;
        grant_node_image_reader(&owner,&grant).await?;
        let path=format!("/v1/operator/nodes/{node}/image-status");
        let actual=operator_response(&app,Some(&authorization),&path,StatusCode::OK).await?;
        let status:NodeImageStatus=serde_json::from_value(actual)?;
        ensure!(status.runtime_node_id==node && status.node_uid==binding.node_uid && status.grant_id==grant.grant_id);
        ensure!(status.metrics.inventory.as_ref().is_some_and(|v|v.count==7.0 && v.compressed_logical_bytes==10789.0));
        ensure!(status.metrics.filesystem.is_none() && status.metrics.filesystem_observation_success==Some(false));
        for (mode,expected) in [(1,StatusCode::OK),(2,StatusCode::SERVICE_UNAVAILABLE),(3,StatusCode::BAD_GATEWAY)] {
            state.mode.store(mode,Ordering::SeqCst);
            let response=operator_response(&app,Some(&authorization),&path,expected).await?;
            if mode==1 { ensure!(response["metrics"]["inventory"].is_null() && response["metrics"]["inventory_observation_success"].is_null()); }
        }
        state.mode.store(0,Ordering::SeqCst);
        let api=TlsServer::start(app.clone()).await?;
        let cli_outcome=async {
            let bearer=tempfile::NamedTempFile::new()?;
            std::fs::write(bearer.path(),authorization.to_str()?.strip_prefix("Bearer ").context("Bearer token")?)?;
            let output=tokio::process::Command::new(env!("CARGO_BIN_EXE_sandbox-admin"))
                .args(["node-image-status","--endpoint",&api.endpoint,"--runtime-node-id",&node.to_string(),"--token-file"])
                .arg(bearer.path()).arg("--ca-file").arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/admission/server-ca.pem"))
                .env("SANDBOX_ADMIN_DATABASE_URL","postgresql://unused-owner.invalid/no-database")
                .kill_on_drop(true).output().await?;
            ensure!(output.status.success(),"Read-only CLI failed: {}",String::from_utf8_lossy(&output.stderr));
            let read:NodeImageStatus=serde_json::from_slice(&output.stdout)?;
            ensure!(read.runtime_node_id==node && read.grant_id==grant.grant_id && read.metrics.inventory.is_some());
            std::fs::write(bearer.path(),"PUBLIC_INVALID_ACCESS_TOKEN")?;
            let denied=tokio::process::Command::new(env!("CARGO_BIN_EXE_sandbox-admin"))
                .args(["node-image-status","--endpoint",&api.endpoint,"--runtime-node-id",&node.to_string(),"--token-file"])
                .arg(bearer.path()).arg("--ca-file").arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/admission/server-ca.pem"))
                .kill_on_drop(true).output().await?;
            ensure!(!denied.status.success() && denied.stdout.is_empty());
            ensure!(!String::from_utf8_lossy(&denied.stderr).contains("PUBLIC_INVALID_ACCESS_TOKEN"));
            Ok::<(),anyhow::Error>(())
        }.await;
        let cli_retired=api.close().await;
        cli_outcome.and(cli_retired)?;
        // Each fault starts after the backend received the fixed query; every
        // response is observed through HTTP, not a call to the internal gate.
        for fault in 0..4 {
            state.pause.store(true,Ordering::SeqCst);
            state.mode.store(if fault==1 {2}else{0},Ordering::SeqCst);
            let cloned_app=app.clone();let bearer=authorization.clone();let request_path=path.clone();
            let expected=match fault {2=>StatusCode::CONFLICT,3=>StatusCode::NOT_FOUND,_=>StatusCode::FORBIDDEN};
            let request=tokio::spawn(async move {operator_response(&cloned_app,Some(&bearer),&request_path,expected).await});
            let injection=async {
                tokio::time::timeout(Duration::from_secs(3),state.reached.notified()).await?;
                if fault==3 {
                    sqlx::query("UPDATE runtime_nodes SET enabled=false WHERE id=$1").bind(node).execute(&fixture.owner).await?;
                } else {
                    let revoke=RevokeNodeImageReader::parse(&serde_json::to_vec(&json!({"grant_id":grant.grant_id,"installation_id":grant.installation_id,"cluster_epoch":grant.cluster_epoch,"reason":"Test in-flight revocation"}))?)?;
                    revoke_node_image_reader(&owner,&revoke).await?;
                    if fault==2 { grant.grant_id=Uuid::new_v4();grant_node_image_reader(&owner,&grant).await?; }
                }
                Ok::<(),anyhow::Error>(())
            }.await;
            state.release.notify_one();
            let response=request.await?;
            injection?;response?;
            state.pause.store(false,Ordering::SeqCst);
            if fault<2 {grant.grant_id=Uuid::new_v4();grant_node_image_reader(&owner,&grant).await?;}
        }
        ensure!(state.hits.load(Ordering::SeqCst)==9,"Each accepted read performed one bounded backend query");
        Ok(())
    }.await;
    state.release.notify_waiters();
    let retired = server.close().await;
    let outcome = outcome.and(retired);
    finish_live_fixture(fixture, &identity, outcome).await
}

#[tokio::test]
#[ignore = "Requires real Keycloak, disposable PostgreSQL and SANDBOX_MACHINE_* credentials"]
async fn node_certification_expiry_during_https_io_cannot_return_old_data() -> anyhow::Result<()> {
    let _serial = support::serial().await;
    let (fixture, auth, identity, authorization) = prepare_live_fixture().await?;
    let setup = async {
        let expiry: chrono::DateTime<Utc> =
            sqlx::query_scalar("SELECT clock_timestamp()+interval '1 second'")
                .fetch_one(&fixture.owner)
                .await?;
        let (node, state, server, token) = observed_node(&fixture, expiry).await?;
        Ok::<_, anyhow::Error>((expiry, node, state, server, token))
    }
    .await;
    let (expiry, node, state, server, token) = match setup {
        Ok(setup) => setup,
        Err(error) => return finish_live_fixture(fixture, &identity, Err(error)).await,
    };
    state.pause.store(true, Ordering::SeqCst);
    let outcome = async {
        let backend = PrometheusMetrics::new(MetricsBackendConfig {
            endpoint: server.endpoint.clone(),
            deployment: "production-a".into(),
            auth: MetricsAuthentication::Bearer {
                token_file: token.path().into(),
            },
            ca_file: Some(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/admission/server-ca.pem"),
            ),
            replicas: vec!["a".into(), "b".into()],
        })
        .await?;
        let app = query_app(&fixture, auth, backend)?;
        let document = live_grant_document(&fixture, &identity).await?;
        let grant = GrantNodeImageReader::parse(&serde_json::to_vec(&document)?, true)?;
        grant_node_image_reader(
            &Database {
                pool: fixture.owner.clone(),
            },
            &grant,
        )
        .await?;
        let request_app = app.clone();
        let bearer = authorization.clone();
        let path = format!("/v1/operator/nodes/{node}/image-status");
        let request = tokio::spawn(async move {
            operator_response(&request_app, Some(&bearer), &path, StatusCode::NOT_FOUND).await
        });
        let injection = async {
            tokio::time::timeout(Duration::from_secs(3), state.reached.notified()).await?;
            let until = tokio::time::Instant::now() + Duration::from_secs(2);
            loop {
                let expired: bool = sqlx::query_scalar("SELECT clock_timestamp()>=$1")
                    .bind(expiry)
                    .fetch_one(&fixture.owner)
                    .await?;
                if expired {
                    break;
                }
                ensure!(
                    tokio::time::Instant::now() < until,
                    "Database clock did not reach original certification expiry"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        state.release.notify_one();
        let response = request.await?;
        injection?;
        response?;
        ensure!(
            state.hits.load(Ordering::SeqCst) == 1,
            "Query really crossed original certification deadline"
        );
        Ok(())
    }
    .await;
    state.release.notify_waiters();
    let retired = server.close().await;
    finish_live_fixture(fixture, &identity, outcome.and(retired)).await
}

#[tokio::test]
#[ignore = "Requires disposable PostgreSQL with normal owner and application roles"]
async fn node_query_preflight_rejects_function_source_and_inventory_acl_or_structure_drift()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let fixture = Fixture::new(1).await?;
    let outcome=async {
        fixture.database.verify_runtime_role().await?;
        for (mutate,restore) in [
            ("GRANT EXECUTE ON FUNCTION sandbox_node_image_binding(text,text,text,bigint,uuid) TO PUBLIC","REVOKE ALL ON FUNCTION sandbox_node_image_binding(text,text,text,bigint,uuid) FROM PUBLIC"),
            ("GRANT UPDATE(enabled) ON runtime_nodes TO sandbox_app","REVOKE UPDATE(enabled) ON runtime_nodes FROM sandbox_app"),
            ("GRANT SELECT(certification_expires_at) ON runtime_node_enrollments TO sandbox_app","REVOKE SELECT(certification_expires_at) ON runtime_node_enrollments FROM sandbox_app"),
            ("GRANT INSERT(certification_expires_at) ON runtime_node_enrollments TO sandbox_app","REVOKE INSERT(certification_expires_at) ON runtime_node_enrollments FROM sandbox_app"),
            ("ALTER TABLE runtime_node_enrollments DISABLE TRIGGER runtime_node_enrollments_append_only","ALTER TABLE runtime_node_enrollments ENABLE TRIGGER runtime_node_enrollments_append_only"),
            ("ALTER TABLE runtime_node_enrollments ADD COLUMN unreviewed_binding text","ALTER TABLE runtime_node_enrollments DROP COLUMN unreviewed_binding"),
            ("ALTER FUNCTION sandbox_node_image_binding(text,text,text,bigint,uuid) SET search_path=public","ALTER FUNCTION sandbox_node_image_binding(text,text,text,bigint,uuid) SET search_path=pg_catalog"),
        ] {
            sqlx::raw_sql(mutate).execute(&fixture.owner).await?;
            let checked=fixture.database.verify_runtime_role().await;
            let restored=sqlx::raw_sql(restore).execute(&fixture.owner).await;
            restored?;
            ensure!(checked.is_err(),"Changed node query contract must reject startup: {mutate}");
            fixture.database.verify_runtime_role().await?;
        }
        let original=include_str!("../../migrations/0048_operator_node_image_binding.sql").replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION");
        let changed=original.replace(" WITH access AS MATERIALIZED", " -- Unreviewed function body change\n WITH access AS MATERIALIZED");
        sqlx::raw_sql(&changed).execute(&fixture.owner).await?;
        let checked=fixture.database.verify_runtime_role().await;
        sqlx::raw_sql(&original).execute(&fixture.owner).await?;
        ensure!(checked.is_err(),"Even a changed function body with the same signature must reject startup");
        fixture.database.verify_runtime_role().await?;
        let guard=include_str!("../../migrations/0014_trusted_termination.sql").split_once("CREATE FUNCTION sandbox_preserve_runtime_node()").context("Reviewed node identity guard")?.1.split_once("CREATE TRIGGER").context("Reviewed guard end")?.0;
        let original_guard=format!("CREATE OR REPLACE FUNCTION sandbox_preserve_runtime_node(){guard}");
        sqlx::raw_sql("CREATE OR REPLACE FUNCTION sandbox_preserve_runtime_node() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN RETURN NEW; END $$;").execute(&fixture.owner).await?;
        let checked=fixture.database.verify_runtime_role().await;
        sqlx::raw_sql(&original_guard).execute(&fixture.owner).await?;
        ensure!(checked.is_err(),"Node identity guard body drift must reject startup");
        fixture.database.verify_runtime_role().await?;
        Ok(())
    }.await;
    fixture.database.pool.close().await;
    fixture.owner.close().await;
    outcome
}
