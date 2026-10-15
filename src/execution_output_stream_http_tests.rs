//! Real PG/RLS + HTTP bodies/JWKS + signed OSS transport. Database owner seeds
//! immutable output receipts only; this is not a claim of guest/KVM execution.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::{
    output_store::OssOutputConfig,
    test_support_db::{Fixture, api_failure, serial},
};
use anyhow::Context;
use axum::{
    Router,
    body::Body,
    http::{Request, Response},
    routing::get,
};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use opendal::{Buffer, HttpBody, HttpTransport, HttpTransporter};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU8, Ordering},
};
use tokio::sync::Mutex;
use tower::ServiceExt;

#[path = "execution_output_stream_sdk_test.rs"]
mod sdk;

#[derive(Clone, Default)]
struct Objects {
    bytes: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    mode: Arc<AtomicU8>,
    revoke: Option<(sqlx::PgPool, Uuid, Uuid)>,
}
impl HttpTransport for Objects {
    async fn fetch(&self, req: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
        assert!(req.headers().contains_key("authorization"));
        assert!(req.headers().contains_key("x-oss-security-token"));
        assert!(matches!(req.method().as_str(), "GET" | "HEAD"));
        if matches!(self.mode.load(Ordering::SeqCst), 2..=4) {
            let (pool, tenant, principal) = self.revoke.as_ref().unwrap();
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
                .bind(tenant.to_string())
                .execute(&mut *tx)
                .await
                .unwrap();
            if self.mode.load(Ordering::SeqCst) == 2 {
                sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='executions:output:read'").bind(tenant).bind(principal).execute(&mut *tx).await.unwrap();
            } else if self.mode.load(Ordering::SeqCst) == 3 {
                sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton")
                    .bind(Uuid::new_v4())
                    .execute(&mut *tx)
                    .await
                    .unwrap();
            } else {
                sqlx::query("UPDATE principal_identities SET enabled=false WHERE principal_id=$1")
                    .bind(principal)
                    .execute(&mut *tx)
                    .await
                    .unwrap();
            }
            tx.commit().await.unwrap();
        }
        if self
            .mode
            .compare_exchange(5, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        let all = self.bytes.lock().await;
        let bytes = all.get(req.uri().path()).unwrap();
        let is_head = req.method() == "HEAD";
        let mut body = if is_head { vec![] } else { bytes.clone() };
        if !is_head && self.mode.load(Ordering::SeqCst) == 1 {
            body[0] ^= 1;
        }
        let length = body.len() as u64;
        let mut response = Response::builder()
            .status(if is_head { 200 } else { 206 })
            .header("content-length", bytes.len())
            .header("etag", "\"test-immutable-output\"")
            .header("last-modified", "Sat, 03 Oct 2026 00:00:00 GMT");
        if !is_head {
            response = response.header(
                "content-range",
                format!("bytes 0-{}/{}", bytes.len() - 1, bytes.len()),
            );
        }
        Ok(response
            .body(HttpBody::new(
                futures_util::stream::iter([Ok(Buffer::from(body))]),
                Some(length),
            ))
            .unwrap())
    }
}

struct OutputFixture {
    db: Fixture,
    execution: Uuid,
    attempt: Uuid,
    objects: Objects,
    reader: Arc<OssOutputReader>,
    _credentials: tempfile::NamedTempFile,
}
impl OutputFixture {
    async fn new() -> anyhow::Result<Self> {
        let db = Fixture::new(10).await?;
        db.bind_client_id("output-test").await?;
        let created = db
            .create("stream-output-fixture")
            .await
            .map_err(api_failure)?;
        let instance = created.body.resource.id;
        let operation = Uuid::new_v4();
        let execution = Uuid::new_v4();
        let attempt = Uuid::new_v4();
        let mut tx = db.owner_transaction().await?;
        sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,'executions:output:read')").bind(db.actor.tenant_id).bind(db.request.project_id).bind(db.actor.principal_id).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO operations(id,tenant_id,project_id,instance_id,kind,request,actor_principal_id,request_id,deadline,workspace_id) VALUES($1,$2,$3,$4,'EXECUTE','{}',$5,$6,clock_timestamp()+interval '1 hour',$7)").bind(operation).bind(db.actor.tenant_id).bind(db.request.project_id).bind(instance).bind(db.actor.principal_id).bind(db.actor.request_id).bind(created.body.resource.workspace_id).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO executions(id,tenant_id,project_id,instance_id,operation_id,runtime_generation,launch_id,pod_uid,cluster_epoch,deadline,timeout_seconds) SELECT $1,i.tenant_id,i.project_id,i.id,$2,i.runtime_generation,i.launch_id,$3,i.cluster_epoch,clock_timestamp()+interval '1 hour',60 FROM instances i WHERE i.tenant_id=$4 AND i.id=$5")
            .bind(execution).bind(operation).bind(Uuid::new_v4()).bind(db.actor.tenant_id).bind(instance).execute(&mut *tx).await?;
        sqlx::query("UPDATE executions SET status='DISPATCHING',dispatch_attempt_id=$3,dispatch_attempted_at=clock_timestamp(),dispatch_lease_token=1,output_status='PARTIAL' WHERE tenant_id=$1 AND id=$2").bind(db.actor.tenant_id).bind(execution).bind(attempt).execute(&mut *tx).await?;
        tx.commit().await?;
        let objects = Objects {
            revoke: Some((db.owner.clone(), db.actor.tenant_id, db.actor.principal_id)),
            ..Default::default()
        };
        let credentials = tempfile::NamedTempFile::new()?;
        std::fs::write(
            credentials.path(),
            serde_json::to_vec(
                &json!({"access_key_id":"TEST_ONLY_AK","access_key_secret":"TEST_ONLY_SECRET","security_token":"TEST_ONLY_TOKEN","expires_at":Utc::now()+chrono::Duration::minutes(10)}),
            )?,
        )?;
        let reader = OssOutputReader::from_transport(
            OssOutputConfig {
                endpoint: "https://oss-cn-hangzhou-internal.aliyuncs.com".into(),
                bucket: "sandbox-output".into(),
                kms_key_id: "test-only-key".into(),
                sts_credentials_file: credentials.path().to_path_buf(),
            },
            HttpTransporter::new(objects.clone()),
        )?;
        Ok(Self {
            db,
            execution,
            attempt,
            objects,
            reader: Arc::new(reader),
            _credentials: credentials,
        })
    }
    async fn segment(&self, sequence: i64, data: &str) -> anyhow::Result<Value> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let frame = json!({"sequence":sequence,"stream":"stdout","offset":sequence,"data":STANDARD.encode(data.as_bytes())});
        let bytes = format!("{frame}\n").into_bytes();
        let sha = hex::encode(Sha256::digest(&bytes));
        let key = format!(
            "tenants/{}/executions/{}/attempts/{}/segments/{sequence}-{sha}.ndjson",
            self.db.actor.tenant_id, self.execution, self.attempt
        );
        self.objects
            .bytes
            .lock()
            .await
            .insert(format!("/{key}"), bytes.clone());
        let mut tx = self.db.owner_transaction().await?;
        sqlx::query("INSERT INTO execution_output_segments(tenant_id,project_id,execution_id,dispatch_attempt_id,sequence,first_frame_sequence,last_frame_sequence,raw_bytes,object_bytes,sha256,object_key) VALUES($1,$2,$3,$4,$5,$5,$5,$6,$7,$8,$9)").bind(self.db.actor.tenant_id).bind(self.db.request.project_id).bind(self.execution).bind(self.attempt).bind(sequence).bind(data.len() as i64).bind(bytes.len() as i64).bind(&sha).bind(key).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(
            json!({"sequence":sequence,"first_frame_sequence":sequence,"last_frame_sequence":sequence,"raw_bytes":data.len(),"object_bytes":bytes.len(),"sha256":sha}),
        )
    }
    async fn close(&self, manifest: Option<Vec<Value>>) -> anyhow::Result<()> {
        let reference = if let Some(segments) = manifest {
            let bytes = serde_json::to_vec(
                &json!({"schema_version":1,"tenant_id":self.db.actor.tenant_id,"execution_id":self.execution,"dispatch_attempt_id":self.attempt,"output_status":"COMPLETE","segments":segments}),
            )?;
            let sha = hex::encode(Sha256::digest(&bytes));
            let key = format!(
                "tenants/{}/executions/{}/attempts/{}/manifest-{sha}.json",
                self.db.actor.tenant_id, self.execution, self.attempt
            );
            let reference = json!({"object_key":key,"sha256":sha,"size_bytes":bytes.len()});
            self.objects
                .bytes
                .lock()
                .await
                .insert(format!("/{key}"), bytes);
            Some(reference)
        } else {
            None
        };
        let mut tx = self.db.owner_transaction().await?;
        // OUTCOME_UNKNOWN closes output publication while retaining the VM slot.
        sqlx::query("UPDATE executions SET status='OUTCOME_UNKNOWN',termination_status='UNKNOWN',output_status=$3,output_manifest=$4 WHERE tenant_id=$1 AND id=$2").bind(self.db.actor.tenant_id).bind(self.execution).bind(if reference.is_some(){"COMPLETE"}else{"PARTIAL"}).bind(reference).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    async fn app(
        &self,
        lifetime: i64,
        shutdown: CancellationToken,
    ) -> anyhow::Result<(Router, String, tokio::task::JoinHandle<()>)> {
        self.app_with_scope(
            lifetime,
            shutdown,
            crate::auth::ScopeProfile::GenericAccess,
            "sandbox:access",
        )
        .await
    }
    async fn app_with_scope(
        &self,
        lifetime: i64,
        shutdown: CancellationToken,
        scope_profile: crate::auth::ScopeProfile,
        scope: &str,
    ) -> anyhow::Result<(Router, String, tokio::task::JoinHandle<()>)> {
        let jwk: Value = serde_json::from_str(include_str!("../tests/fixtures/auth/jwk-a.json"))?;
        let kid = jwk["kid"].as_str().context("kid")?.to_owned();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                Router::new().route(
                    "/jwks",
                    get(move || {
                        let jwk = jwk.clone();
                        async move { axum::Json(json!({"keys":[jwk]})) }
                    }),
                ),
            )
            .await;
        });
        let auth = crate::auth::JwtAuthenticator::new(crate::auth::AuthConfig {
            scope_profile,
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
        let state = Arc::new(AppState {
            database: self.db.database.clone(),
            auth,
            cursor_signer: CursorSigner::from_json(include_str!(
                "../tests/fixtures/history/cursor-keys.json"
            ))?,
            output_reader: Some(self.reader.clone()),
            metrics: None,
            default_ttl_seconds: 300,
            max_ttl_seconds: 86400,
        });
        let runtime = Arc::new(crate::automation::api::AutomationApiRuntime { app: state.clone() });
        runtime.check_schema().await?;
        let now = Utc::now().timestamp();
        let token = encode(
            &header,
            &json!({"iss":"https://issuer.example.test","sub":self.db.actor.principal_id.to_string(),"aud":"sandbox-api","client_id":"output-test","jti":Uuid::new_v4().to_string(),"iat":now,"exp":now+lifetime,"scope":scope}),
            &EncodingKey::from_rsa_der(include_bytes!("../tests/fixtures/auth/rsa-a.der")),
        )?;
        let app = crate::api::router_with_automations(state, shutdown, None, None, Some(runtime));
        Ok((app, token, task))
    }
    fn request(&self, token: &str, cursor: Option<&str>) -> Request<Body> {
        let mut req = Request::builder()
            .uri(format!("/v1/executions/{}/output/stream", self.execution))
            .header("authorization", format!("Bearer {token}"))
            .header("x-tenant-id", self.db.actor.tenant_id.to_string());
        if let Some(cursor) = cursor {
            req = req.header("last-event-id", cursor);
        }
        req.body(Body::empty()).unwrap()
    }
}
async fn next(body: &mut Body) -> anyhow::Result<Option<String>> {
    let Some(frame) = tokio::time::timeout(Duration::from_secs(3), body.frame()).await? else {
        return Ok(None);
    };
    Ok(Some(String::from_utf8(
        frame?
            .into_data()
            .map_err(|_| anyhow::anyhow!("data"))?
            .to_vec(),
    )?))
}
fn cursor(frame: &str) -> anyhow::Result<&str> {
    frame
        .lines()
        .find_map(|line| line.strip_prefix("id: "))
        .context("cursor")
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL and loopback JWKS; modifies then restores cluster epoch"]
async fn output_restore_epoch_during_object_io_invalidates_cursor_without_leaking_segment()
-> anyhow::Result<()> {
    let _serial = serial().await;
    let f = OutputFixture::new().await?;
    f.segment(0, "a").await?;
    let (app, token, server) = f.app(300, CancellationToken::new()).await?;
    let mut body = app
        .clone()
        .oneshot(f.request(&token, None))
        .await?
        .into_body();
    let checkpoint = next(&mut body).await?.context("checkpoint")?;
    let resume = cursor(&checkpoint)?.to_owned();
    let old_epoch: Uuid =
        sqlx::query_scalar("SELECT cluster_epoch FROM platform_configuration WHERE singleton")
            .fetch_one(&f.db.owner)
            .await?;
    f.objects.mode.store(3, Ordering::SeqCst);
    let outcome = async {
        let error = next(&mut body).await?.context("restore error")?;
        anyhow::ensure!(
            error.contains("OUTPUT_HISTORY_UNAVAILABLE") && !error.contains("YQ=="),
            "restored output was not fenced"
        );
        anyhow::ensure!(next(&mut body).await?.is_none(), "stream must close");
        let response = app
            .clone()
            .oneshot(f.request(&token, Some(&resume)))
            .await?;
        anyhow::ensure!(
            response.status() == StatusCode::GONE,
            "old cursor must reject before headers"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton")
        .bind(old_epoch)
        .execute(&f.db.owner)
        .await?;
    server.abort();
    outcome
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL and loopback JWKS; exercises live body limits and token deadlines"]
async fn output_body_connections_are_bounded_release_on_drop_and_close_on_expiry_or_shutdown()
-> anyhow::Result<()> {
    let _serial = serial().await;
    let f = OutputFixture::new().await?;
    let shutdown = CancellationToken::new();
    let (app, token, server) = f.app(300, shutdown.clone()).await?;
    let mut bodies = Vec::new();
    for _ in 0..4 {
        let response = app.clone().oneshot(f.request(&token, None)).await?;
        assert_eq!(response.status(), StatusCode::OK);
        bodies.push(response.into_body());
    }
    assert_eq!(
        app.clone().oneshot(f.request(&token, None)).await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    drop(bodies);
    let mut body = app
        .clone()
        .oneshot(f.request(&token, None))
        .await?
        .into_body();
    assert!(
        next(&mut body)
            .await?
            .unwrap()
            .contains("output.checkpoint")
    );
    shutdown.cancel();
    assert!(next(&mut body).await?.is_none());
    server.abort();
    let (app, token, server) = f.app(2, CancellationToken::new()).await?;
    let mut body = app.oneshot(f.request(&token, None)).await?.into_body();
    assert!(
        next(&mut body)
            .await?
            .unwrap()
            .contains("output.checkpoint")
    );
    assert!(next(&mut body).await?.is_none());
    server.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL and loopback JWKS; native signed OSS transport mock"]
async fn http_output_reconnects_at_committed_segment_and_retains_unknown_vm_slot()
-> anyhow::Result<()> {
    let _serial = serial().await;
    let f = OutputFixture::new().await?;
    f.segment(0, "a").await?;
    let (app, token, server) = f.app(300, CancellationToken::new()).await?;
    let response = app.clone().oneshot(f.request(&token, None)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-accel-buffering"], "no");
    let mut body = response.into_body();
    assert!(
        next(&mut body)
            .await?
            .unwrap()
            .contains("output.checkpoint")
    );
    let first = next(&mut body).await?.unwrap();
    assert!(first.contains("output.segment"));
    assert!(first.contains("YQ=="));
    let resume = cursor(&first)?.to_owned();
    drop(body);
    f.segment(1, "b").await?;
    f.close(None).await?;
    let response = app
        .clone()
        .oneshot(f.request(&token, Some(&resume)))
        .await?;
    let mut body = response.into_body();
    assert!(
        next(&mut body)
            .await?
            .unwrap()
            .contains("\"after_segment\":0")
    );
    let second = next(&mut body).await?.unwrap();
    assert!(second.contains("Yg=="));
    assert!(!second.contains("YQ=="));
    let end = next(&mut body).await?.unwrap();
    assert!(end.contains("output.end"));
    assert!(end.contains("PARTIAL"));
    assert!(end.contains("\"manifest_verified\":false"));
    assert!(next(&mut body).await?.is_none());
    let mut tx = f.db.owner_transaction().await?;
    let remains:bool=sqlx::query_scalar("SELECT slot_held AND termination_status='UNKNOWN' FROM executions WHERE tenant_id=$1 AND id=$2").bind(f.db.actor.tenant_id).bind(f.execution).fetch_one(&mut *tx).await?;
    assert!(remains);
    tx.commit().await?;
    server.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL and loopback JWKS; native signed OSS transport mock"]
async fn http_output_checks_manifest_corruption_and_revocation_after_object_read()
-> anyhow::Result<()> {
    let _serial = serial().await;
    let f = OutputFixture::new().await?;
    let entry = f.segment(0, "a").await?;
    f.close(Some(vec![entry])).await?;
    let (app, token, server) = f.app(300, CancellationToken::new()).await?;
    let mut body = app
        .clone()
        .oneshot(f.request(&token, None))
        .await?
        .into_body();
    next(&mut body).await?;
    assert!(next(&mut body).await?.unwrap().contains("output.segment"));
    let end = next(&mut body).await?.unwrap();
    assert!(end.contains("output.end"));
    assert!(end.contains("\"manifest_verified\":true"));
    assert!(end.contains("\"final_segment_sequence\":0"));
    drop(body);
    for (mode, code) in [(1, "OUTPUT_INTEGRITY_FAILED"), (2, "RESOURCE_NOT_FOUND")] {
        f.objects.mode.store(mode, Ordering::SeqCst);
        let mut body = app
            .clone()
            .oneshot(f.request(&token, None))
            .await?
            .into_body();
        next(&mut body).await?;
        let error = next(&mut body).await?.unwrap();
        assert!(error.contains("stream.error"));
        assert!(error.contains(code));
        assert!(!error.contains("YQ=="));
        assert!(!error.contains("TEST_ONLY"));
        assert!(next(&mut body).await?.is_none());
    }
    server.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL startup lock wait, loopback JWKS and signed OSS transport"]
async fn output_short_lived_token_is_issued_after_startup_preflight_wait() -> anyhow::Result<()> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let _serial = serial().await;
    let f = OutputFixture::new().await?;
    f.segment(0, "after-startup-preflight").await?;
    let mut blocker = f.db.owner.begin().await?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    sqlx::query("LOCK TABLE public._sqlx_migrations IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await?;

    // Observe the real restricted API login waiting on this exact owner lock.
    // No pg_stat_activity query text or extra monitoring privileges are needed.
    let waiters = "SELECT a.pid FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid \
        WHERE a.datname=current_database() AND a.usename='sandbox_app' \
        AND l.locktype='relation' AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database()) \
        AND l.relation='public._sqlx_migrations'::regclass AND l.mode='AccessShareLock' AND NOT l.granted \
        AND $1=ANY(pg_blocking_pids(a.pid))";
    let release = async {
        let held = async {
            let waiter = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let pids: Vec<i32> = sqlx::query_scalar(waiters)
                        .bind(blocker_pid)
                        .fetch_all(&f.db.owner)
                        .await?;
                    anyhow::ensure!(pids.len() <= 1, "ambiguous startup schema lock waiter");
                    if let Some(pid) = pids.first() {
                        return Ok::<_, anyhow::Error>(*pid);
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .context("startup preflight did not wait on the exact migration relation lock")??;
            // Only after PostgreSQL proves the app is blocked, outwait the
            // unchanged two-second token lifetime while staying below the
            // normal three-second database lock timeout. No storage delay.
            tokio::time::sleep(Duration::from_millis(2_250)).await;
            let still_waiting: Vec<i32> = sqlx::query_scalar(waiters)
                .bind(blocker_pid)
                .fetch_all(&f.db.owner)
                .await?;
            anyhow::ensure!(
                still_waiting == [waiter],
                "startup must remain blocked until this owner releases the schema lock"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        // JWT times have whole-second precision. Sample immediately before
        // rollback so issuance in the release second is accepted as well.
        let release_second = Utc::now().timestamp();
        let released = blocker.rollback().await;
        held?;
        released?;
        Ok::<_, anyhow::Error>(release_second)
    };
    // Always release the barrier, even on observer failure, then recover the
    // normal helper's JWKS handle before checking any response assertion.
    let (ready, released) = tokio::join!(f.app(2, CancellationToken::new()), release);
    let (app, token, server) = ready?;
    let outcome = async {
        let release_second = released?;
        let claims: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(token.split('.').nth(1).context("JWT claims")?)?,
        )?;
        let issued = claims["iat"].as_i64().context("JWT issued-at")?;
        let expires = claims["exp"].as_i64().context("JWT expires-at")?;
        anyhow::ensure!(expires - issued == 2, "retain the exact short token lifetime");
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/executions/{}/output", f.execution))
                    .header("authorization", format!("Bearer {token}"))
                    .header("x-tenant-id", f.db.actor.tenant_id.to_string())
                    .body(Body::empty())?,
            )
            .await?;
        let status = response.status();
        let body = response.into_body().collect().await?.to_bytes();
        anyhow::ensure!(
            issued >= release_second && status == StatusCode::OK,
            "short token must be issued after startup releases its schema lock: issued={issued}, release_second={release_second}, HTTP={status}"
        );
        let body: Value = serde_json::from_slice(&body)?;
        anyhow::ensure!(
            body["segments"].as_array().is_some_and(|v| v.len() == 1)
                && body["segments"][0]["frames"]
                    .as_array()
                    .is_some_and(|v| v.len() == 1)
                && body["segments"][0]["frames"][0]["data"] == "YWZ0ZXItc3RhcnR1cC1wcmVmbGlnaHQ=",
            "the real authorized output page must contain the single stored segment"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    server.abort();
    let _ = server.await;
    outcome
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL, loopback JWKS and signed OSS transport"]
async fn output_page_rechecks_identity_and_expiry_after_storage_io() -> anyhow::Result<()> {
    let _serial = serial().await;
    for (mode, lifetime, expected) in [
        (0, 300, StatusCode::OK),
        (4, 300, StatusCode::UNAUTHORIZED),
        (5, 2, StatusCode::UNAUTHORIZED),
    ] {
        let f = OutputFixture::new().await?;
        f.segment(0, "private-output-marker").await?;
        let (app, token, server) = f.app(lifetime, CancellationToken::new()).await?;
        f.objects.mode.store(mode, Ordering::SeqCst);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/executions/{}/output", f.execution))
                    .header("authorization", format!("Bearer {token}"))
                    .header("x-tenant-id", f.db.actor.tenant_id.to_string())
                    .body(Body::empty())?,
            )
            .await?;
        let status = response.status();
        let body = response.into_body().collect().await?.to_bytes();
        server.abort();
        anyhow::ensure!(
            status == expected,
            "output page must reflect post-I/O authority: mode {mode}, got {status}"
        );
        let body: Value = serde_json::from_slice(&body)?;
        if expected == StatusCode::OK {
            anyhow::ensure!(
                body["segments"]
                    .as_array()
                    .is_some_and(|segments| segments.len() == 1)
            );
        } else {
            anyhow::ensure!(
                body["code"] == "UNAUTHENTICATED" && body.get("segments").is_none(),
                "no segment in an expired or revoked identity response"
            );
            if mode == 4 {
                let enabled: bool = sqlx::query_scalar(
                    "SELECT enabled FROM principal_identities WHERE principal_id=$1",
                )
                .bind(f.db.actor.principal_id)
                .fetch_one(&f.db.owner)
                .await?;
                anyhow::ensure!(!enabled, "identity was disabled during actual object read");
            } else {
                anyhow::ensure!(
                    f.objects.mode.load(Ordering::SeqCst) == 0,
                    "object read crossed token expiry"
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires normal PostgreSQL migrations and real signed HTTP authorization"]
async fn action_scope_ceiling_blocks_mutations_streams_and_delegation() -> anyhow::Result<()> {
    let _serial = serial().await;
    let f = OutputFixture::new().await?;
    let mut tx = f.db.owner_transaction().await?;
    let instance: Uuid =
        sqlx::query_scalar("SELECT instance_id FROM executions WHERE tenant_id=$1 AND id=$2")
            .bind(f.db.actor.tenant_id)
            .bind(f.execution)
            .fetch_one(&mut *tx)
            .await?;
    // The shared fixture already grants instances:renew; retain that grant.
    sqlx::query(
        "INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,'automations:write')",
    )
    .bind(f.db.actor.tenant_id)
    .bind(f.db.request.project_id)
    .bind(f.db.actor.principal_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let request =
        |method: &str, path: String, token: &str, body: Value| -> anyhow::Result<Request<Body>> {
            Ok(Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("x-tenant-id", f.db.actor.tenant_id.to_string())
                .header("content-type", "application/json")
                .header("idempotency-key", Uuid::new_v4().to_string())
                .header("if-match", "\"1\"")
                .body(Body::from(serde_json::to_vec(&body)?))?)
        };
    let (app, token, server) = f
        .app_with_scope(
            300,
            CancellationToken::new(),
            crate::auth::ScopeProfile::ActionScopes,
            "sandbox:access instances:read",
        )
        .await?;
    for (method, path, body, expected) in [
        (
            "GET",
            format!("/v1/instances/{instance}"),
            Value::Null,
            StatusCode::OK,
        ),
        (
            "POST",
            "/v1/instances".into(),
            serde_json::to_value(&f.db.request)?,
            StatusCode::FORBIDDEN,
        ),
        (
            "GET",
            format!("/v1/executions/{}/output", f.execution),
            Value::Null,
            StatusCode::NOT_FOUND,
        ),
        (
            "GET",
            format!("/v1/executions/{}/output/stream", f.execution),
            Value::Null,
            StatusCode::NOT_FOUND,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(request(method, path.clone(), &token, body)?)
            .await?;
        anyhow::ensure!(
            response.status() == expected,
            "action ceiling must hold for {method} {path}: got {}",
            response.status()
        );
    }
    server.abort();
    let automation = json!({"name":"Scope-capped renewal","action":{"kind":"RENEW","ttl_seconds":600},"trigger":{"kind":"ONCE","at":Utc::now()+chrono::Duration::minutes(5)},"delegation_expires_at":Utc::now()+chrono::Duration::hours(1),"run_budget":1,"minimum_interval_seconds":60,"grace_seconds":60});
    let mut created = None;
    for (scope, expected) in [
        ("sandbox:access automations:write", StatusCode::FORBIDDEN),
        (
            "sandbox:access automations:write instances:renew",
            StatusCode::CREATED,
        ),
    ] {
        let (app, token, server) = f
            .app_with_scope(
                300,
                CancellationToken::new(),
                crate::auth::ScopeProfile::ActionScopes,
                scope,
            )
            .await?;
        let response = app
            .oneshot(request(
                "POST",
                format!("/v1/instances/{instance}/automations"),
                &token,
                automation.clone(),
            )?)
            .await?;
        let status = response.status();
        let body: Value =
            serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
        server.abort();
        anyhow::ensure!(
            status == expected,
            "delegation must fit OAuth action ceiling: got {status}, code {:?}",
            body.get("code")
        );
        if status == StatusCode::CREATED {
            created = Some(Uuid::parse_str(
                body["resource"]["id"].as_str().context("automation ID")?,
            )?);
        }
    }
    let mut tx = f.db.owner_transaction().await?;
    let allowed: Vec<String> =
        sqlx::query_scalar("SELECT allowed_actions FROM automation_delegations WHERE tenant_id=$1")
            .bind(f.db.actor.tenant_id)
            .fetch_one(&mut *tx)
            .await?;
    anyhow::ensure!(
        allowed == ["instances:renew", "automations:write"],
        "durable authority retains only checked action ceiling"
    );
    tx.commit().await?;
    let automation = created.context("accepted automation")?;
    let (limited, limited_token, limited_server) = f
        .app_with_scope(
            300,
            CancellationToken::new(),
            crate::auth::ScopeProfile::ActionScopes,
            "sandbox:access automations:write",
        )
        .await?;
    let (full, full_token, full_server) = f
        .app_with_scope(
            300,
            CancellationToken::new(),
            crate::auth::ScopeProfile::ActionScopes,
            "sandbox:access automations:write instances:renew",
        )
        .await?;
    let change =
        |action: &str, token: &str, version: i64, key: &str| -> anyhow::Result<Request<Body>> {
            Ok(Request::builder()
                .method("POST")
                .uri(format!("/v1/automations/{automation}/actions/{action}"))
                .header("authorization", format!("Bearer {token}"))
                .header("x-tenant-id", f.db.actor.tenant_id.to_string())
                .header("content-type", "application/json")
                .header("idempotency-key", key)
                .header("if-match", format!("\"{version}\""))
                .body(Body::from("{}"))?)
        };
    // Management scopes can reduce authority without the delegated action scope.
    let response = limited
        .clone()
        .oneshot(change("pause", &limited_token, 1, "scope-pause")?)
        .await?;
    anyhow::ensure!(
        response.status() == StatusCode::OK,
        "management-only token can pause"
    );
    let response = limited
        .clone()
        .oneshot(change("resume", &limited_token, 2, "scope-resume")?)
        .await?;
    anyhow::ensure!(
        response.status() == StatusCode::FORBIDDEN,
        "resume must check all delegated action scopes before accepting or replaying"
    );
    let mut tx = f.db.owner_transaction().await?;
    sqlx::query("UPDATE grants SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND action='instances:renew'")
        .bind(f.db.actor.tenant_id).bind(f.db.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let response = full
        .clone()
        .oneshot(change("resume", &full_token, 2, "scope-resume")?)
        .await?;
    anyhow::ensure!(
        response.status() == StatusCode::NOT_FOUND,
        "resume also intersects current local action grants"
    );
    let mut tx = f.db.owner_transaction().await?;
    let state: (String, i64) =
        sqlx::query_as("SELECT status,version FROM automations WHERE tenant_id=$1 AND id=$2")
            .bind(f.db.actor.tenant_id)
            .bind(automation)
            .fetch_one(&mut *tx)
            .await?;
    anyhow::ensure!(
        state == ("PAUSED".into(), 2),
        "rejected resume leaves status and version unchanged"
    );
    sqlx::query("UPDATE grants SET revoked_at=NULL WHERE tenant_id=$1 AND principal_id=$2 AND action='instances:renew'")
        .bind(f.db.actor.tenant_id).bind(f.db.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    for _ in 0..2 {
        let response = full
            .clone()
            .oneshot(change("resume", &full_token, 2, "scope-resume")?)
            .await?;
        anyhow::ensure!(
            response.status() == StatusCode::OK,
            "full authority accepts and replays the same resume"
        );
        let receipt: Value =
            serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
        anyhow::ensure!(
            receipt["resource"]["version"] == 3 && receipt["resource"]["status"] == "ACTIVE"
        );
    }
    let response = limited
        .clone()
        .oneshot(change("resume", &limited_token, 2, "scope-resume")?)
        .await?;
    anyhow::ensure!(
        response.status() == StatusCode::FORBIDDEN,
        "a successful receipt cannot bypass a narrower replay token"
    );
    let response = limited
        .clone()
        .oneshot(change("pause", &limited_token, 3, "scope-pause-again")?)
        .await?;
    anyhow::ensure!(response.status() == StatusCode::OK);
    let response = limited
        .oneshot(change("revoke", &limited_token, 4, "scope-revoke")?)
        .await?;
    anyhow::ensure!(
        response.status() == StatusCode::OK,
        "management-only token can revoke"
    );
    limited_server.abort();
    full_server.abort();
    Ok(())
}
