#![allow(clippy::unwrap_used)]

use super::*;
use crate::test_support_db::{Fixture, api_failure, serial};
use anyhow::Context;
use axum::{Router, body::Body, http::Request, routing::get};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use tower::ServiceExt;

#[path = "event_stream_sdk_test.rs"]
mod sdk;

fn signer() -> anyhow::Result<CursorSigner> {
    CursorSigner::from_json(include_str!("../tests/fixtures/history/cursor-keys.json"))
}

fn actor() -> Actor {
    Actor {
        authorization: None,
        tenant_id: Uuid::new_v4(),
        principal_id: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
    }
}

fn query(project_id: Uuid) -> EventStreamQuery {
    EventStreamQuery {
        project_id,
        instance_id: None,
        replay: Replay::All,
    }
}

#[test]
fn stream_cursors_are_scoped_expire_and_cannot_be_history_tokens() -> anyhow::Result<()> {
    let actor = actor();
    let query = query(Uuid::new_v4());
    let position = StreamPosition {
        epoch: Uuid::new_v4(),
        cluster_epoch: Uuid::new_v4(),
        sequence: 37,
    };
    let signer = signer()?;
    let now = Utc::now();
    let token = position
        .cursor(&actor, &query, &signer, now)
        .map_err(api_failure)?;
    let mut cursor: Cursor = signer.decode_payload(&token).map_err(api_failure)?;
    validate_cursor(&cursor, &actor, &query, now).map_err(api_failure)?;
    let mut another_actor = actor.clone();
    another_actor.principal_id = Uuid::new_v4();
    assert!(validate_cursor(&cursor, &another_actor, &query, now).is_err());
    another_actor = actor.clone();
    another_actor.tenant_id = Uuid::new_v4();
    assert!(validate_cursor(&cursor, &another_actor, &query, now).is_err());
    let mut filtered = query.clone();
    filtered.instance_id = Some(Uuid::new_v4());
    assert!(validate_cursor(&cursor, &actor, &filtered, now).is_err());
    assert_eq!(
        validate_cursor(&cursor, &actor, &query, now + chrono::Duration::days(1))
            .unwrap_err()
            .status,
        StatusCode::GONE
    );
    cursor.kind = "events:read".into();
    assert!(validate_cursor(&cursor, &actor, &query, now).is_err());
    cursor.kind = "project_event_stream".into();
    cursor.sequence = -1;
    assert!(validate_cursor(&cursor, &actor, &query, now).is_err());
    assert!(
        signer
            .decode_payload::<Cursor>(&format!("{token}x"))
            .is_err()
    );
    Ok(())
}

#[test]
fn stream_cursor_future_issue_skew_is_bounded_without_expiry_or_ttl_grace() -> anyhow::Result<()> {
    let actor = actor();
    let query = query(Uuid::new_v4());
    let position = StreamPosition {
        epoch: Uuid::new_v4(),
        cluster_epoch: Uuid::new_v4(),
        sequence: 37,
    };
    let signer = signer()?;
    let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    for seconds in [1, 60] {
        let token = position
            .cursor(
                &actor,
                &query,
                &signer,
                now + chrono::Duration::seconds(seconds),
            )
            .map_err(api_failure)?;
        let cursor: Cursor = signer.decode_payload(&token).map_err(api_failure)?;
        validate_cursor(&cursor, &actor, &query, now).map_err(api_failure)?;
    }
    let token = position
        .cursor(
            &actor,
            &query,
            &signer,
            now + chrono::Duration::seconds(60) + chrono::Duration::nanoseconds(1),
        )
        .map_err(api_failure)?;
    let cursor: Cursor = signer.decode_payload(&token).map_err(api_failure)?;
    let error = validate_cursor(&cursor, &actor, &query, now).unwrap_err();
    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert_eq!(error.code, "INVALID_CURSOR");

    let token = position
        .cursor(
            &actor,
            &query,
            &signer,
            now - chrono::Duration::seconds(CURSOR_TTL),
        )
        .map_err(api_failure)?;
    let cursor: Cursor = signer.decode_payload(&token).map_err(api_failure)?;
    validate_cursor(
        &cursor,
        &actor,
        &query,
        now - chrono::Duration::nanoseconds(1),
    )
    .map_err(api_failure)?;
    let error = validate_cursor(&cursor, &actor, &query, now).unwrap_err();
    assert_eq!(error.status, StatusCode::GONE);
    assert_eq!(error.code, "EVENT_CURSOR_EXPIRED");

    let token = position
        .cursor(&actor, &query, &signer, now + chrono::Duration::seconds(60))
        .map_err(api_failure)?;
    let mut cursor: Cursor = signer.decode_payload(&token).map_err(api_failure)?;
    cursor.expires_at += chrono::Duration::nanoseconds(1);
    let error = validate_cursor(&cursor, &actor, &query, now).unwrap_err();
    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert_eq!(error.code, "INVALID_CURSOR");
    Ok(())
}

#[test]
fn connection_permits_live_until_body_drop_and_limit_each_principal_and_tenant() {
    let runtime = StreamRuntime::new(CancellationToken::new());
    let actor = actor();
    let held: Vec<_> = (0..4).map(|_| runtime.acquire(&actor).unwrap()).collect();
    assert!(runtime.acquire(&actor).is_err());
    drop(held);
    let mut held = Vec::new();
    for _ in 0..4 {
        let mut other = actor.clone();
        other.principal_id = Uuid::new_v4();
        held.extend((0..4).map(|_| runtime.acquire(&other).unwrap()));
    }
    assert!(runtime.acquire(&actor).is_err());
    drop(held);
    assert!(runtime.acquire(&actor).is_ok());
    assert_eq!(runtime.counts.lock().unwrap().total, 0);
    assert!(runtime.counts.lock().unwrap().tenants.is_empty());
    assert!(runtime.counts.lock().unwrap().principals.is_empty());
}

#[test]
fn ambiguous_resume_headers_and_unknown_queries_are_rejected() {
    let mut headers = HeaderMap::new();
    headers.insert("last-event-id", HeaderValue::from_static(""));
    assert!(last_event_id(&headers).is_err());
    headers.insert("last-event-id", HeaderValue::from_static("one"));
    headers.append("last-event-id", HeaderValue::from_static("two"));
    assert!(last_event_id(&headers).is_err());
    assert!(
        serde_json::from_value::<EventStreamQuery>(
            json!({"project_id":Uuid::new_v4(),"token":"PRIVATE"})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<EventStreamQuery>(
            json!({"project_id":Uuid::new_v4(),"replay":"silent-reset"})
        )
        .is_err()
    );
}

async fn fixture() -> anyhow::Result<Fixture> {
    let fixture = Fixture::new(10).await?;
    let mut tx = fixture.owner_transaction().await?;
    sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,'events:read')")
        .bind(fixture.actor.tenant_id).bind(fixture.request.project_id).bind(fixture.actor.principal_id)
        .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(fixture)
}

async fn insert_event(
    tx: &mut Transaction<'_, Postgres>,
    fixture: &Fixture,
    aggregate: Uuid,
    version: i64,
    offset_seconds: i64,
) -> anyhow::Result<Uuid> {
    Ok(sqlx::query_scalar("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,request_id,payload,occurred_at) VALUES($1,$2,$3,$4,'test.stream',$5,'{\"PRIVATE-MARKER\":\"never expose\"}',clock_timestamp()+$6*interval '1 second') RETURNING id")
        .bind(fixture.actor.tenant_id).bind(fixture.request.project_id).bind(aggregate).bind(version)
        .bind(Uuid::new_v4()).bind(offset_seconds as f64).fetch_one(&mut **tx).await?)
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and distinct owner/API logins"]
async fn concurrent_event_writers_cannot_publish_past_an_uncommitted_position() -> anyhow::Result<()>
{
    let _serial = serial().await;
    let fixture = Arc::new(fixture().await?);
    let query = query(fixture.request.project_id);
    let position = fixture
        .database
        .open_event_stream(&fixture.actor, &query, None, &signer()?)
        .await
        .map_err(api_failure)?;
    let mut first = fixture.owner_transaction().await?;
    let one = insert_event(&mut first, &fixture, Uuid::new_v4(), 1, 3600).await?;
    let (send, receive) = tokio::sync::oneshot::channel();
    let other = fixture.clone();
    let second = tokio::spawn(async move {
        let mut tx = other
            .database
            .begin(other.actor.tenant_id)
            .await
            .map_err(api_failure)?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await?;
        send.send(pid)
            .map_err(|_| anyhow::anyhow!("test receiver closed"))?;
        let id = insert_event(&mut tx, &other, Uuid::new_v4(), 1, -3600).await?;
        tx.commit().await?;
        Ok::<_, anyhow::Error>(id)
    });
    let pid = receive.await?;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT cardinality(pg_blocking_pids($1))>0")
                .bind(pid)
                .fetch_one(&fixture.database.pool)
                .await?;
            if blocked {
                break;
            }
            tokio::task::yield_now().await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    assert!(
        fixture
            .database
            .read_event_batch(&fixture.actor, &query, &position)
            .await
            .map_err(api_failure)?
            .is_empty()
    );
    first.commit().await?;
    let two = second.await??;
    let rows = fixture
        .database
        .read_event_batch(&fixture.actor, &query, &position)
        .await
        .map_err(api_failure)?;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].position.sequence, 1);
    assert_eq!(rows[1].position.sequence, 2);
    assert_eq!(rows[0].event.as_ref().context("first event")?.id, one);
    assert_eq!(rows[1].event.as_ref().context("second event")?.id, two);
    assert!(
        rows[0].event.as_ref().unwrap().occurred_at > rows[1].event.as_ref().unwrap().occurred_at
    );
    // Reconnection after the first delivered frame must recover the later commit.
    let cursor = rows[0]
        .position
        .cursor(&fixture.actor, &query, &signer()?, Utc::now())
        .map_err(api_failure)?;
    let resumed = fixture
        .database
        .open_event_stream(&fixture.actor, &query, Some(&cursor), &signer()?)
        .await
        .map_err(api_failure)?;
    let rest = fixture
        .database
        .read_event_batch(&fixture.actor, &query, &resumed)
        .await
        .map_err(api_failure)?;
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].event.as_ref().unwrap().id, two);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and distinct owner/API logins"]
async fn rolled_back_events_leave_no_gap_and_runtime_cannot_forge_positions() -> anyhow::Result<()>
{
    let _serial = serial().await;
    let fixture = fixture().await?;
    let query = query(fixture.request.project_id);
    let start = fixture
        .database
        .open_event_stream(&fixture.actor, &query, None, &signer()?)
        .await
        .map_err(api_failure)?;
    let mut tx = fixture.owner_transaction().await?;
    insert_event(&mut tx, &fixture, Uuid::new_v4(), 1, 0).await?;
    tx.rollback().await?;
    let mut tx = fixture.owner_transaction().await?;
    let id = insert_event(&mut tx, &fixture, Uuid::new_v4(), 1, 0).await?;
    tx.commit().await?;
    let rows = fixture
        .database
        .read_event_batch(&fixture.actor, &query, &start)
        .await
        .map_err(api_failure)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].position.sequence, 1);
    assert_eq!(rows[0].event.as_ref().unwrap().id, id);
    for statement in [
        "UPDATE event_stream_heads SET last_sequence=500",
        "UPDATE event_stream_positions SET sequence=500",
        "DELETE FROM event_stream_positions",
        "SELECT sandbox_sequence_event()",
    ] {
        let mut tx = fixture
            .database
            .begin(fixture.actor.tenant_id)
            .await
            .map_err(api_failure)?;
        let error = sqlx::query(statement)
            .execute(&mut *tx)
            .await
            .err()
            .context("privileged write was accepted")?;
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("42501")
        );
        tx.rollback().await?;
    }
    let another = self::fixture().await?;
    let mut tx = another
        .database
        .begin(another.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM event_stream_positions WHERE tenant_id=$1")
            .bind(fixture.actor.tenant_id)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(count, 0);
    tx.rollback().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and distinct owner/API logins"]
async fn filtered_replay_is_bounded_and_reauthorizes_each_batch() -> anyhow::Result<()> {
    let _serial = serial().await;
    let fixture = fixture().await?;
    let instance = fixture
        .create("stream-instance")
        .await
        .map_err(api_failure)?
        .body
        .resource;
    let mut query = query(fixture.request.project_id);
    query.instance_id = Some(instance.id);
    let position = fixture
        .database
        .open_event_stream(&fixture.actor, &query, None, &signer()?)
        .await
        .map_err(api_failure)?;
    let mut tx = fixture.owner_transaction().await?;
    for version in 1..=80 {
        insert_event(&mut tx, &fixture, Uuid::new_v4(), version, 0).await?;
    }
    let target = insert_event(&mut tx, &fixture, instance.id, 90, 0).await?;
    tx.commit().await?;
    let first = fixture
        .database
        .read_event_batch(&fixture.actor, &query, &position)
        .await
        .map_err(api_failure)?;
    assert_eq!(first.len(), BATCH_SIZE);
    assert_eq!(first.iter().filter(|e| e.event.is_some()).count(), 1);
    let position = first.back().unwrap().position.clone();
    let second = fixture
        .database
        .read_event_batch(&fixture.actor, &query, &position)
        .await
        .map_err(api_failure)?;
    assert_eq!(second.back().unwrap().event.as_ref().unwrap().id, target);
    let serialized = serde_json::to_string(second.back().unwrap().event.as_ref().unwrap())?;
    assert!(!serialized.contains("PRIVATE-MARKER"));
    let mut tx = fixture.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND action='events:read'")
        .bind(fixture.actor.tenant_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    assert_eq!(
        fixture
            .database
            .read_event_batch(&fixture.actor, &query, &position)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL and loopback JWKS"]
async fn restored_cluster_epoch_invalidates_old_cursors_and_buffered_frames() -> anyhow::Result<()>
{
    let _serial = serial().await;
    let fixture = fixture().await?;
    let query = query(fixture.request.project_id);
    let mut tx = fixture.owner_transaction().await?;
    insert_event(&mut tx, &fixture, Uuid::new_v4(), 1, 0).await?;
    tx.commit().await?;
    let start = fixture
        .database
        .open_event_stream(&fixture.actor, &query, None, &signer()?)
        .await
        .map_err(api_failure)?;
    let cursor = start
        .cursor(&fixture.actor, &query, &signer()?, Utc::now())
        .map_err(api_failure)?;
    let (app, token, server) = http_app(&fixture, 300, CancellationToken::new()).await?;
    let response = app.oneshot(http_request(&fixture, &token, None)).await?;
    let mut body = response.into_body();
    next_frame(&mut body).await?;
    let old_epoch: Uuid =
        sqlx::query_scalar("SELECT cluster_epoch FROM platform_configuration WHERE singleton")
            .fetch_one(&fixture.owner)
            .await?;
    sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton")
        .bind(Uuid::new_v4())
        .execute(&fixture.owner)
        .await?;
    let outcome = async {
        let reopened = fixture
            .database
            .open_event_stream(&fixture.actor, &query, Some(&cursor), &signer()?)
            .await;
        assert_eq!(reopened.unwrap_err().code, "EVENT_HISTORY_UNAVAILABLE");
        assert_eq!(
            fixture
                .database
                .read_event_batch(&fixture.actor, &query, &start)
                .await
                .unwrap_err()
                .code,
            "EVENT_HISTORY_UNAVAILABLE"
        );
        let frame = next_frame(&mut body)
            .await?
            .context("missing closed-stream diagnostic")?;
        assert!(frame.contains("EVENT_HISTORY_UNAVAILABLE"));
        assert!(!frame.contains("domain.event"));
        assert!(next_frame(&mut body).await?.is_none());
        let mut ahead = fixture
            .database
            .open_event_stream(&fixture.actor, &query, None, &signer()?)
            .await
            .map_err(api_failure)?;
        ahead.sequence = 2;
        let token = ahead
            .cursor(&fixture.actor, &query, &signer()?, Utc::now())
            .map_err(api_failure)?;
        assert_eq!(
            fixture
                .database
                .open_event_stream(&fixture.actor, &query, Some(&token), &signer()?)
                .await
                .unwrap_err()
                .code,
            "EVENT_CURSOR_AHEAD"
        );
        let expired = start
            .cursor(
                &fixture.actor,
                &query,
                &signer()?,
                Utc::now() - chrono::Duration::days(2),
            )
            .map_err(api_failure)?;
        assert_eq!(
            fixture
                .database
                .open_event_stream(&fixture.actor, &query, Some(&expired), &signer()?)
                .await
                .unwrap_err()
                .code,
            "EVENT_CURSOR_EXPIRED"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton")
        .bind(old_epoch)
        .execute(&fixture.owner)
        .await?;
    server.abort();
    outcome
}

async fn http_app(
    fixture: &Fixture,
    lifetime: i64,
    shutdown: CancellationToken,
) -> anyhow::Result<(Router, String, tokio::task::JoinHandle<()>)> {
    let jwk: Value = serde_json::from_str(include_str!("../tests/fixtures/auth/jwk-a.json"))?;
    let kid = jwk["kid"].as_str().context("kid")?.to_owned();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
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
    fixture.bind_client_id("stream-test").await?;
    let auth = crate::auth::JwtAuthenticator::new(crate::auth::AuthConfig {
        scope_profile: Default::default(),
        issuer: "https://issuer.example.test".into(),
        audience: "sandbox-api".into(),
        jwks_url: format!("http://{addr}/jwks"),
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
        &json!({"iss":"https://issuer.example.test","sub":fixture.actor.principal_id.to_string(),"aud":"sandbox-api","client_id":"stream-test","jti":Uuid::new_v4().to_string(),"iat":now,"exp":now+lifetime,"scope":"sandbox:access"}),
        &EncodingKey::from_rsa_der(include_bytes!("../tests/fixtures/auth/rsa-a.der")),
    )?;
    let app = crate::api::router_with_shutdown(
        Arc::new(AppState {
            database: fixture.database.clone(),
            auth,
            cursor_signer: signer()?,
            output_reader: None,
            metrics: None,
            default_ttl_seconds: 300,
            max_ttl_seconds: 86400,
        }),
        shutdown,
    );
    Ok((app, token, server))
}

fn http_request(fixture: &Fixture, token: &str, cursor: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .uri(format!(
            "/v1/events/stream?project_id={}&replay=all",
            fixture.request.project_id
        ))
        .header("authorization", format!("Bearer {token}"))
        .header("x-tenant-id", fixture.actor.tenant_id.to_string());
    if let Some(cursor) = cursor {
        request = request.header("last-event-id", cursor);
    }
    request.body(Body::empty()).unwrap()
}

async fn next_frame(body: &mut Body) -> anyhow::Result<Option<String>> {
    let Some(frame) = tokio::time::timeout(Duration::from_secs(3), body.frame()).await? else {
        return Ok(None);
    };
    let frame = frame?;
    Ok(Some(String::from_utf8(
        frame
            .into_data()
            .map_err(|_| anyhow::anyhow!("not data"))?
            .to_vec(),
    )?))
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL, loopback JWKS and HTTP body streaming"]
async fn sse_resumes_and_revocation_stops_already_buffered_events() -> anyhow::Result<()> {
    let _serial = serial().await;
    let fixture = fixture().await?;
    let mut tx = fixture.owner_transaction().await?;
    let one = insert_event(&mut tx, &fixture, Uuid::new_v4(), 1, 0).await?;
    let two = insert_event(&mut tx, &fixture, Uuid::new_v4(), 1, 0).await?;
    tx.commit().await?;
    let cancel = CancellationToken::new();
    let (app, token, server) = http_app(&fixture, 300, cancel.clone()).await?;
    let response = app
        .clone()
        .oneshot(http_request(&fixture, &token, None))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    assert_eq!(response.headers()["x-accel-buffering"], "no");
    let mut body = response.into_body();
    assert!(
        next_frame(&mut body)
            .await?
            .unwrap()
            .contains("stream.checkpoint")
    );
    let frame = next_frame(&mut body).await?.unwrap();
    assert!(frame.contains(&one.to_string()));
    assert!(!frame.contains("PRIVATE-MARKER"));
    let cursor = frame
        .lines()
        .find_map(|line| line.strip_prefix("id: "))
        .context("no SSE resume ID")?
        .to_owned();
    drop(body);
    let response = app
        .clone()
        .oneshot(http_request(&fixture, &token, Some(&cursor)))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    next_frame(&mut body).await?;
    assert!(
        next_frame(&mut body)
            .await?
            .unwrap()
            .contains(&two.to_string())
    );
    drop(body);
    let response = app.oneshot(http_request(&fixture, &token, None)).await?;
    let mut body = response.into_body();
    next_frame(&mut body).await?;
    next_frame(&mut body).await?; // second envelope is now buffered, but unsent
    let mut tx = fixture.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND action='events:read'")
        .bind(fixture.actor.tenant_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let denied = next_frame(&mut body).await?.unwrap();
    assert!(denied.contains("stream.error"));
    assert!(!denied.contains(&two.to_string()));
    assert!(next_frame(&mut body).await?.is_none());
    cancel.cancel();
    server.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL, loopback JWKS and HTTP body streaming"]
async fn sse_holds_connection_limits_closes_on_expiry_and_cancels_during_idle() -> anyhow::Result<()>
{
    let _serial = serial().await;
    let fixture = fixture().await?;
    let cancel = CancellationToken::new();
    let (app, token, server) = http_app(&fixture, 300, cancel.clone()).await?;
    let mut held = Vec::new();
    for _ in 0..4 {
        let response = app
            .clone()
            .oneshot(http_request(&fixture, &token, None))
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        held.push(response.into_body());
    }
    let denied = app
        .clone()
        .oneshot(http_request(&fixture, &token, None))
        .await?;
    assert_eq!(denied.status(), StatusCode::SERVICE_UNAVAILABLE);
    held.pop();
    let response = app.oneshot(http_request(&fixture, &token, None)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    next_frame(&mut body).await?;
    cancel.cancel();
    assert!(next_frame(&mut body).await?.is_none());
    drop(held);
    server.abort();
    let (app, token, server) = http_app(&fixture, 2, CancellationToken::new()).await?;
    let response = app.oneshot(http_request(&fixture, &token, None)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    next_frame(&mut body).await?;
    assert!(next_frame(&mut body).await?.is_none());
    server.abort();
    Ok(())
}
