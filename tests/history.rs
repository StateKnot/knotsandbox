#[allow(dead_code)]
mod support;

use anyhow::Context;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use chrono::{DateTime, Utc};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use sandbox_platform::{
    api::{AppState, router},
    auth::{AuthConfig, JwtAuthenticator},
    db::Actor,
    error::ApiError,
    history::{CursorSigner, HistoryQuery},
};
use serde_json::{Value, json};
use std::{collections::HashSet, sync::Arc};
use support::{Fixture, api_failure};
use tower::ServiceExt;
use uuid::Uuid;

fn signer() -> anyhow::Result<CursorSigner> {
    CursorSigner::from_json(include_str!("fixtures/history/cursor-keys.json"))
}
struct HistoryFixture {
    fixture: Fixture,
    instance_id: Uuid,
    query: HistoryQuery,
}
impl HistoryFixture {
    async fn new() -> anyhow::Result<Self> {
        let fixture = Fixture::new(10).await?;
        let instance = fixture
            .create("history-instance")
            .await
            .map_err(api_failure)?
            .body
            .resource;
        let mut tx = fixture.owner_transaction().await?;
        for action in ["events:read", "audit:read"] {
            sqlx::query(
                "INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4)",
            )
            .bind(fixture.actor.tenant_id)
            .bind(instance.project_id)
            .bind(fixture.actor.principal_id)
            .bind(action)
            .execute(&mut *tx)
            .await?;
        }
        let timestamp: DateTime<Utc> =
            sqlx::query_scalar("SELECT clock_timestamp()-interval '1 hour'")
                .fetch_one(&mut *tx)
                .await?;
        for version in 10..14_i64 {
            let op = Uuid::new_v4();
            sqlx::query("INSERT INTO operations(id,tenant_id,project_id,instance_id,workspace_id,kind,status,request,actor_principal_id,request_id,deadline,created_at,completed_at,error) VALUES($1,$2,$3,$4,$5,'RENEW','SUCCEEDED',$6,$7,$8,clock_timestamp()+interval '1 hour',$9,$9,$6)")
                .bind(op).bind(fixture.actor.tenant_id).bind(instance.project_id).bind(instance.id).bind(instance.workspace_id).bind(json!({"PRIVATE_MARKER":"hidden command, env, provider response"})).bind(fixture.actor.principal_id).bind(Uuid::new_v4()).bind(timestamp).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,operation_id,request_id,payload,occurred_at) VALUES($1,$2,$3,$4,'test.history',$5,$6,$7,$8)")
                .bind(fixture.actor.tenant_id).bind(instance.project_id).bind(instance.id).bind(version).bind(op).bind(Uuid::new_v4()).bind(json!({"PRIVATE_MARKER":"hidden event payload"})).bind(timestamp).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO audit_events(tenant_id,project_id,actor_principal_id,request_id,operation_id,resource_id,action,outcome,details,occurred_at) VALUES($1,$2,$3,$4,$5,$6,'test.history','SUCCEEDED',$7,$8)")
                .bind(fixture.actor.tenant_id).bind(instance.project_id).bind(fixture.actor.principal_id).bind(Uuid::new_v4()).bind(op).bind(instance.id).bind(json!({"PRIVATE_MARKER":"hidden audit details"})).bind(timestamp).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(Self {
            fixture,
            instance_id: instance.id,
            query: HistoryQuery {
                project_id: instance.project_id,
                instance_id: None,
                limit: Some(2),
                cursor: None,
            },
        })
    }
    async fn list(
        &self,
        kind: &str,
        actor: &Actor,
        query: &HistoryQuery,
    ) -> Result<Value, ApiError> {
        let signer =
            signer().map_err(|_| ApiError::invalid("Test signer configuration invalid"))?;
        let db = &self.fixture.database;
        let result = match kind {
            "operations" => serde_json::to_value(db.list_operations(actor, query, &signer).await?),
            "events" => serde_json::to_value(db.list_events(actor, query, &signer).await?),
            "audit-records" => {
                serde_json::to_value(db.list_audit_records(actor, query, &signer).await?)
            }
            _ => unreachable!(),
        };
        result.map_err(|_| ApiError::invalid("Test serialization failed"))
    }
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn project_histories_use_stable_keyset_order_and_withhold_private_payloads()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let data = HistoryFixture::new().await?;
    for kind in ["operations", "events", "audit-records"] {
        let mut query = data.query.clone();
        let mut all = Vec::new();
        let mut cutoff = None;
        loop {
            let page = data
                .list(kind, &data.fixture.actor, &query)
                .await
                .map_err(api_failure)?;
            assert!(!page.to_string().contains("PRIVATE_MARKER"));
            if let Some(old) = &cutoff {
                assert_eq!(old, &page["cutoff"]);
            } else {
                cutoff = Some(page["cutoff"].clone());
            }
            let items = page["items"].as_array().context("Page has no items")?;
            assert!(items.len() <= 2);
            all.extend(items.iter().cloned());
            if let Some(cursor) = page["next_cursor"].as_str() {
                query.cursor = Some(cursor.to_owned());
            } else {
                break;
            }
        }
        assert_eq!(all.len(), 5);
        let unique = all
            .iter()
            .map(|item| item["id"].as_str().context("Missing history id"))
            .collect::<anyhow::Result<HashSet<_>>>()?;
        assert_eq!(unique.len(), 5);
        let column = if kind == "operations" {
            "created_at"
        } else {
            "occurred_at"
        };
        for pair in all.windows(2) {
            let a: (DateTime<Utc>, Uuid) = (
                serde_json::from_value(pair[0][column].clone())?,
                serde_json::from_value(pair[0]["id"].clone())?,
            );
            let b: (DateTime<Utc>, Uuid) = (
                serde_json::from_value(pair[1][column].clone())?,
                serde_json::from_value(pair[1]["id"].clone())?,
            );
            assert!(a > b);
        }
        let filtered = HistoryQuery {
            instance_id: Some(data.instance_id),
            limit: Some(100),
            cursor: None,
            ..data.query.clone()
        };
        assert_eq!(
            data.list(kind, &data.fixture.actor, &filtered)
                .await
                .map_err(api_failure)?["items"]
                .as_array()
                .context("Missing history items")?
                .len(),
            5
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn histories_hide_cross_scope_resources_and_recheck_revocation_even_with_valid_cursors()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let data = HistoryFixture::new().await?;
    let other = HistoryFixture::new().await?;
    for kind in ["operations", "events", "audit-records"] {
        let mut query = data.query.clone();
        let page = data
            .list(kind, &data.fixture.actor, &query)
            .await
            .map_err(api_failure)?;
        query.cursor = Some(
            page["next_cursor"]
                .as_str()
                .context("Missing next cursor")?
                .to_owned(),
        );
        for inaccessible in [
            HistoryQuery {
                project_id: other.query.project_id,
                cursor: None,
                ..query.clone()
            },
            HistoryQuery {
                project_id: Uuid::new_v4(),
                cursor: None,
                ..query.clone()
            },
            HistoryQuery {
                instance_id: Some(other.instance_id),
                cursor: None,
                ..query.clone()
            },
            HistoryQuery {
                instance_id: Some(Uuid::new_v4()),
                cursor: None,
                ..query.clone()
            },
        ] {
            assert!(
                matches!(data.list(kind,&data.fixture.actor,&inaccessible).await,Err(error) if error.status==StatusCode::NOT_FOUND)
            );
        }
        for bad_limit in [0, 101, -1] {
            assert!(
                matches!(data.list(kind,&data.fixture.actor,&HistoryQuery{limit:Some(bad_limit),cursor:None,..query.clone()}).await,Err(error) if error.status==StatusCode::BAD_REQUEST)
            );
        }
        let other_kind = if kind == "operations" {
            "events"
        } else {
            "operations"
        };
        assert!(
            matches!(data.list(other_kind,&data.fixture.actor,&query).await,Err(error) if error.code=="INVALID_CURSOR")
        );
        let mut tx = data.fixture.owner_transaction().await?;
        sqlx::query(
            "UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action=$3",
        )
        .bind(data.fixture.actor.tenant_id)
        .bind(data.fixture.actor.principal_id)
        .bind(if kind == "audit-records" {
            "audit:read".to_owned()
        } else {
            format!("{kind}:read")
        })
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        assert!(
            matches!(data.list(kind,&data.fixture.actor,&query).await,Err(error) if error.status==StatusCode::NOT_FOUND)
        );
        let mut tx = data.fixture.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=true WHERE tenant_id=$1 AND principal_id=$2")
            .bind(data.fixture.actor.tenant_id)
            .bind(data.fixture.actor.principal_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    let mut tx = data.fixture.owner_transaction().await?;
    sqlx::query("UPDATE principals SET enabled=false WHERE id=$1")
        .bind(data.fixture.actor.principal_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    for kind in ["operations", "events", "audit-records"] {
        assert!(
            matches!(data.list(kind,&data.fixture.actor,&data.query).await,Err(error) if error.status==StatusCode::NOT_FOUND)
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+, both TEST_*DATABASE_URL credentials and a loopback mock JWKS listener"]
async fn signed_http_history_contract_is_paginated_redacted_and_revocable() -> anyhow::Result<()> {
    let _serial = support::serial().await;
    let data = HistoryFixture::new().await?;
    let jwk: Value = serde_json::from_str(include_str!("fixtures/auth/jwk-a.json"))?;
    let kid = jwk["kid"].as_str().context("No kid")?.to_owned();
    let keys = json!({"keys":[jwk]});
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/jwks",
                get(move || {
                    let keys = keys.clone();
                    async move { axum::Json(keys) }
                }),
            ),
        )
        .await
    });
    data.fixture.bind_client_id("history-test").await?;
    let auth = JwtAuthenticator::new(AuthConfig {
        scope_profile: Default::default(),
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
    let now = Utc::now().timestamp();
    let token = encode(
        &header,
        &json!({"iss":"https://issuer.example.test","sub":data.fixture.actor.principal_id.to_string(),"aud":"sandbox-api","client_id":"history-test","jti":Uuid::new_v4().to_string(),"iat":now,"exp":now+300,"scope":"sandbox:access"}),
        &EncodingKey::from_rsa_der(include_bytes!("fixtures/auth/rsa-a.der")),
    )?;
    let app = router(Arc::new(AppState {
        output_reader: None,
        metrics: None,
        database: data.fixture.database.clone(),
        auth,
        cursor_signer: signer()?,
        default_ttl_seconds: 300,
        max_ttl_seconds: 86400,
    }));
    for kind in ["operations", "events", "audit-records"] {
        let path = format!("/v1/{kind}?project_id={}&limit=2", data.query.project_id);
        let request = |path: &str| {
            Request::builder()
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("x-tenant-id", data.fixture.actor.tenant_id.to_string())
                .body(Body::empty())
        };
        let first = app.clone().oneshot(request(&path)?).await?;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(first.headers()["cache-control"], "no-store");
        let first: Value = serde_json::from_slice(&first.into_body().collect().await?.to_bytes())?;
        assert_eq!(
            first["items"]
                .as_array()
                .context("Missing history items")?
                .len(),
            2
        );
        assert!(!first.to_string().contains("PRIVATE_MARKER"));
        let cursor = first["next_cursor"].as_str().context("Missing cursor")?;
        let next = app
            .clone()
            .oneshot(request(&format!("{path}&cursor={cursor}"))?)
            .await?;
        assert_eq!(next.status(), StatusCode::OK);
        let bad = app
            .clone()
            .oneshot(request(&format!("{path}&cursor=malformed"))?)
            .await?;
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        assert_eq!(bad.headers()["content-type"], "application/problem+json");
    }
    let mut tx = data.fixture.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND action='audit:read'")
        .bind(data.fixture.actor.tenant_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let denied = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/audit-records?project_id={}",
                    data.query.project_id
                ))
                .header("authorization", format!("Bearer {token}"))
                .header("x-tenant-id", data.fixture.actor.tenant_id.to_string())
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(denied.status(), StatusCode::NOT_FOUND);
    server.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+ and both TEST_*DATABASE_URL credentials"]
async fn legacy_lifecycle_receipt_and_operation_detail_withhold_raw_error_fields()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let data = HistoryFixture::new().await?;
    let first = data
        .fixture
        .create("history-instance")
        .await
        .map_err(api_failure)?;
    let private = json!({"code":"KUBERNETES_UNAVAILABLE","retryable":false,"message":"PRIVATE-MARKER","nested":{"credentials":"PRIVATE-MARKER"}});
    let mut tx = data.fixture.owner_transaction().await?;
    sqlx::query("UPDATE operations SET error=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(data.fixture.actor.tenant_id)
        .bind(first.body.operation.id)
        .bind(&private)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE idempotency_keys SET response_body=jsonb_set(response_body,'{operation,error}',$3) WHERE tenant_id=$1 AND operation_id=$2").bind(data.fixture.actor.tenant_id).bind(first.body.operation.id).bind(&private).execute(&mut *tx).await?;
    tx.commit().await?;
    let current = serde_json::to_value(
        data.fixture
            .database
            .get_operation(&data.fixture.actor, first.body.operation.id)
            .await
            .map_err(api_failure)?,
    )?;
    assert_eq!(
        current["error"],
        json!({"code":"DEPENDENCY_UNAVAILABLE","retryable":true})
    );
    assert!(!current.to_string().contains("PRIVATE-MARKER"));
    let replay = serde_json::to_value(
        data.fixture
            .create("history-instance")
            .await
            .map_err(api_failure)?
            .body,
    )?;
    assert_eq!(
        replay["operation"]["error"],
        json!({"code":"DEPENDENCY_UNAVAILABLE","retryable":true})
    );
    assert!(!replay.to_string().contains("PRIVATE-MARKER"));
    Ok(())
}
