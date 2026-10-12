#[allow(dead_code)]
mod support;
use anyhow::Context;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use chrono::{DateTime, Duration, Utc};
use futures_util::future::join_all;
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use sandbox_platform::{
    api::{AppState, router},
    auth::{AuthConfig, JwtAuthenticator},
    db::Actor,
    grants::{CreateGrant, UpdateGrant},
    history::{CursorSigner, HistoryQuery},
};
use serde_json::{Value, json};
use std::sync::Arc;
use support::{Fixture, api_failure, require_pg_error};
use tokio::sync::Barrier;
use tower::ServiceExt;
use uuid::Uuid;

struct GrantFixture {
    fixture: Fixture,
    project: Uuid,
    target: Uuid,
    instance: Uuid,
}
impl GrantFixture {
    async fn new(manager_expiry: Option<DateTime<Utc>>) -> anyhow::Result<Self> {
        let fixture = Fixture::new(10).await?;
        let instance = fixture
            .create("grant-instance")
            .await
            .map_err(api_failure)?
            .body
            .resource;
        let target = Uuid::new_v4();
        let mut tx = fixture.owner_transaction().await?;
        for action in ["grants:read", "grants:write"] {
            sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action,expires_at) VALUES($1,$2,$3,$4,$5)").bind(fixture.actor.tenant_id).bind(instance.project_id).bind(fixture.actor.principal_id).bind(action).bind(manager_expiry).execute(&mut *tx).await?;
        }
        sqlx::query(
            "INSERT INTO principals(id,kind,display_name) VALUES($1,'SERVICE','Target service')",
        )
        .bind(target)
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO tenant_principals(tenant_id,principal_id,display_name) VALUES($1,$2,'Target service')").bind(fixture.actor.tenant_id).bind(target).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(Self {
            fixture,
            project: instance.project_id,
            target,
            instance: instance.id,
        })
    }
    fn request(&self, action: &str, expires_at: Option<DateTime<Utc>>) -> CreateGrant {
        CreateGrant {
            principal_id: self.target,
            action: action.into(),
            expires_at,
        }
    }
}
#[test]
fn expiry_and_patch_fields_are_explicit_and_identity_fields_cannot_be_patched() -> anyhow::Result<()>
{
    assert!(
        serde_json::from_value::<CreateGrant>(
            json!({"principal_id":Uuid::new_v4(),"action":"instances:read"})
        )
        .is_err()
    );
    assert!(serde_json::from_value::<UpdateGrant>(json!({"enabled":true})).is_err());
    assert!(
        serde_json::from_value::<UpdateGrant>(
            json!({"enabled":true,"expires_at":null,"action":"*"})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<UpdateGrant>(
            json!({"enabled":true,"expires_at":null,"principal_id":Uuid::new_v4()})
        )
        .is_err()
    );
    Ok(())
}
#[tokio::test]
#[ignore = "Requires PostgreSQL and both TEST_*DATABASE_URL credentials"]
async fn delegated_actions_and_expiry_are_bounded_by_both_manager_and_action_authority()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let ceiling = Utc::now() + Duration::hours(1);
    let data = GrantFixture::new(Some(ceiling)).await?;
    for expiry in [None, Some(ceiling + Duration::seconds(1))] {
        assert!(
            matches!(data.fixture.database.create_project_grant(&data.fixture.actor,data.project,&data.request("instances:read",expiry),"too-long").await,Err(e) if e.code=="DELEGATION_DENIED")
        );
    }
    assert!(
        matches!(data.fixture.database.create_project_grant(&data.fixture.actor,data.project,&data.request("*",Some(ceiling)),"self-elevate").await,Err(e) if e.code=="INVALID_ARGUMENT")
    );
    assert!(
        matches!(data.fixture.database.create_project_grant(&data.fixture.actor,data.project,&data.request("unimplemented:root",Some(ceiling)),"unknown").await,Err(e) if e.code=="INVALID_ARGUMENT")
    );
    let mut tx = data.fixture.owner_transaction().await?;
    let action_ceiling = ceiling - Duration::minutes(10);
    sqlx::query("UPDATE grants SET expires_at=$3 WHERE tenant_id=$1 AND principal_id=$2 AND action='instances:read'").bind(data.fixture.actor.tenant_id).bind(data.fixture.actor.principal_id).bind(action_ceiling).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(
        matches!(data.fixture.database.create_project_grant(&data.fixture.actor,data.project,&data.request("instances:read",Some(ceiling)),"action-too-long").await,Err(e) if e.code=="DELEGATION_DENIED")
    );
    assert!(
        matches!(data.fixture.database.create_project_grant(&data.fixture.actor,data.project,&data.request("instances:read",Some(Utc::now()-Duration::seconds(1))),"past").await,Err(e) if e.code=="INVALID_ARGUMENT")
    );
    let accepted = data
        .fixture
        .database
        .create_project_grant(
            &data.fixture.actor,
            data.project,
            &data.request("instances:read", Some(action_ceiling)),
            "exact-bound",
        )
        .await
        .map_err(api_failure)?;
    assert_eq!(
        accepted
            .body
            .resource
            .expires_at
            .map(|t| t.timestamp_micros()),
        Some(action_ceiling.timestamp_micros())
    );
    let mut tx = data.fixture.owner_transaction().await?;
    sqlx::query("UPDATE grants SET expires_at=$3 WHERE tenant_id=$1 AND principal_id=$2 AND action='grants:write'").bind(data.fixture.actor.tenant_id).bind(data.fixture.actor.principal_id).bind(action_ceiling-Duration::minutes(1)).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(
        matches!(data.fixture.database.create_project_grant(&data.fixture.actor,data.project,&data.request("instances:read",Some(action_ceiling)),"exact-bound").await,Err(e) if e.code=="DELEGATION_DENIED")
    );
    Ok(())
}
#[tokio::test]
#[ignore = "Requires PostgreSQL and both TEST_*DATABASE_URL credentials"]
async fn grant_mutations_are_atomic_idempotent_versioned_and_immediately_revoke_access()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let data = GrantFixture::new(None).await?;
    let barrier = Arc::new(Barrier::new(8));
    let results = join_all((0..8).map(|_| {
        let barrier = barrier.clone();
        let data = &data;
        async move {
            barrier.wait().await;
            data.fixture
                .database
                .create_project_grant(
                    &data.fixture.actor,
                    data.project,
                    &data.request("instances:read", None),
                    "same-key",
                )
                .await
        }
    }))
    .await;
    let mut values = Vec::new();
    for result in results {
        let receipt = result.map_err(api_failure)?;
        assert_eq!(receipt.status, 201);
        values.push(serde_json::to_value(receipt.body)?);
    }
    assert!(values.iter().all(|v| v == &values[0]));
    let id: Uuid = serde_json::from_value(values[0]["resource"]["id"].clone())?;
    assert!(
        matches!(data.fixture.database.create_project_grant(&data.fixture.actor,data.project,&data.request("instances:create",None),"same-key").await,Err(e) if e.code=="IDEMPOTENCY_CONFLICT")
    );
    assert!(
        matches!(data.fixture.database.create_project_grant(&data.fixture.actor,data.project,&data.request("instances:read",None),"another-key").await,Err(e) if e.code=="GRANT_ALREADY_EXISTS")
    );
    let target = Actor {
        authorization: None,
        tenant_id: data.fixture.actor.tenant_id,
        principal_id: data.target,
        request_id: Uuid::new_v4(),
    };
    assert!(
        data.fixture
            .database
            .get_instance(&target, data.instance)
            .await
            .is_ok()
    );
    let patch = UpdateGrant {
        enabled: true,
        expires_at: Some(Utc::now() + Duration::hours(1)),
    };
    let updated = data
        .fixture
        .database
        .update_project_grant(
            &data.fixture.actor,
            data.project,
            id,
            &patch,
            "change-expiry",
            1,
        )
        .await
        .map_err(api_failure)?;
    assert_eq!(updated.body.resource.version, 2);
    assert!(
        matches!(data.fixture.database.revoke_project_grant(&data.fixture.actor,data.project,id,"stale",1).await,Err(e) if e.code=="VERSION_MISMATCH")
    );
    let revoked = data
        .fixture
        .database
        .revoke_project_grant(&data.fixture.actor, data.project, id, "revoke", 2)
        .await
        .map_err(api_failure)?;
    assert_eq!(revoked.body.resource.version, 3);
    assert!(revoked.body.resource.revoked_at.is_some());
    assert!(!revoked.body.resource.enabled);
    assert!(
        matches!(data.fixture.database.get_instance(&target,data.instance).await,Err(e) if e.status==StatusCode::NOT_FOUND)
    );
    let replay = data
        .fixture
        .database
        .revoke_project_grant(&data.fixture.actor, data.project, id, "revoke", 2)
        .await
        .map_err(api_failure)?;
    assert_eq!(
        serde_json::to_value(replay.body)?,
        serde_json::to_value(revoked.body)?
    );
    let restored = data
        .fixture
        .database
        .update_project_grant(
            &data.fixture.actor,
            data.project,
            id,
            &UpdateGrant {
                enabled: true,
                expires_at: None,
            },
            "explicit-restore",
            3,
        )
        .await
        .map_err(api_failure)?;
    assert_eq!(restored.body.resource.version, 4);
    assert!(restored.body.resource.revoked_at.is_none());
    assert!(
        data.fixture
            .database
            .get_instance(&target, data.instance)
            .await
            .is_ok()
    );
    let mut tx = data.fixture.owner_transaction().await?;
    let audits:i64=sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND resource_id=$2 AND action LIKE 'grants:%'").bind(data.fixture.actor.tenant_id).bind(id).fetch_one(&mut *tx).await?;
    assert_eq!(audits, 4);
    let receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM management_receipts WHERE tenant_id=$1 AND resource_id=$2",
    )
    .bind(data.fixture.actor.tenant_id)
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(receipts, 4);
    tx.commit().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "Requires PostgreSQL and both TEST_*DATABASE_URL credentials"]
async fn tenant_membership_disable_blocks_old_authority_without_disabling_the_same_global_principal_elsewhere()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let data = GrantFixture::new(None).await?;
    let other = GrantFixture::new(None).await?;
    let accepted = data
        .fixture
        .database
        .create_project_grant(
            &data.fixture.actor,
            data.project,
            &data.request("instances:read", None),
            "before-disabled",
        )
        .await
        .map_err(api_failure)?;
    assert!(
        matches!(data.fixture.database.get_project_grant(&data.fixture.actor,other.project,accepted.body.resource.id).await,Err(e) if e.status==StatusCode::NOT_FOUND)
    );
    let mut foreign = data.request("instances:read", None);
    foreign.principal_id = other.target;
    assert!(
        matches!(data.fixture.database.create_project_grant(&data.fixture.actor,data.project,&foreign,"foreign-target").await,Err(e) if e.status==StatusCode::NOT_FOUND)
    );
    let mut tx = other.fixture.owner_transaction().await?;
    sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,'instances:read')").bind(other.fixture.actor.tenant_id).bind(other.project).bind(data.fixture.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let cross = Actor {
        authorization: None,
        tenant_id: other.fixture.actor.tenant_id,
        principal_id: data.fixture.actor.principal_id,
        request_id: Uuid::new_v4(),
    };
    assert!(
        other
            .fixture
            .database
            .get_instance(&cross, other.instance)
            .await
            .is_ok()
    );
    let mut tx = data.fixture.owner_transaction().await?;
    sqlx::query(
        "UPDATE tenant_principals SET enabled=false WHERE tenant_id=$1 AND principal_id=$2",
    )
    .bind(data.fixture.actor.tenant_id)
    .bind(data.fixture.actor.principal_id)
    .execute(&mut *tx)
    .await?;
    let globally_enabled: bool = sqlx::query_scalar("SELECT enabled FROM principals WHERE id=$1")
        .bind(data.fixture.actor.principal_id)
        .fetch_one(&mut *tx)
        .await?;
    assert!(globally_enabled);
    tx.commit().await?;
    assert!(
        matches!(data.fixture.database.get_instance(&data.fixture.actor,data.instance).await,Err(e) if e.status==StatusCode::NOT_FOUND)
    );
    assert!(
        matches!(data.fixture.database.create_project_grant(&data.fixture.actor,data.project,&data.request("instances:read",None),"before-disabled").await,Err(e) if e.status==StatusCode::NOT_FOUND)
    );
    assert!(
        other
            .fixture
            .database
            .get_instance(&cross, other.instance)
            .await
            .is_ok()
    );
    let no_context: bool = sqlx::query_scalar("SELECT sandbox_principal_enabled($1)")
        .bind(cross.principal_id)
        .fetch_one(&data.fixture.database.pool)
        .await?;
    assert!(!no_context);
    let mut tx = data
        .fixture
        .database
        .begin(data.fixture.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    require_pg_error(
        sqlx::query("UPDATE principals SET enabled=true WHERE id=$1")
            .bind(data.fixture.actor.principal_id)
            .execute(&mut *tx)
            .await,
        "42501",
    )?;
    tx.rollback().await?;
    let mut tx = data
        .fixture
        .database
        .begin(data.fixture.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    require_pg_error(
        sqlx::query("UPDATE grants SET enabled=true WHERE tenant_id=$1")
            .bind(data.fixture.actor.tenant_id)
            .execute(&mut *tx)
            .await,
        "42501",
    )?;
    tx.rollback().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "Requires PostgreSQL and a loopback JWKS listener"]
async fn signed_http_grants_require_etags_and_reject_old_jwt_after_tenant_disable()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let data = GrantFixture::new(None).await?;
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
    data.fixture.bind_client_id("grants-test").await?;
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
        &json!({"iss":"https://issuer.example.test","sub":data.fixture.actor.principal_id.to_string(),"aud":"sandbox-api","client_id":"grants-test","jti":Uuid::new_v4().to_string(),"iat":now,"exp":now+300,"scope":"sandbox:access"}),
        &EncodingKey::from_rsa_der(include_bytes!("fixtures/auth/rsa-a.der")),
    )?;
    let app = router(Arc::new(AppState {
        output_reader: None,
        metrics: None,
        database: data.fixture.database.clone(),
        auth,
        cursor_signer: CursorSigner::from_json(include_str!("fixtures/history/cursor-keys.json"))?,
        default_ttl_seconds: 300,
        max_ttl_seconds: 86400,
    }));
    let path = format!("/v1/projects/{}/grants", data.project);
    let request = |method: &str,
                   path: &str,
                   body: Value,
                   key: Option<&str>,
                   etag: Option<&str>|
     -> anyhow::Result<Request<Body>> {
        let mut r = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .header("x-tenant-id", data.fixture.actor.tenant_id.to_string())
            .header("content-type", "application/json");
        if let Some(k) = key {
            r = r.header("idempotency-key", k);
        }
        if let Some(e) = etag {
            r = r.header("if-match", e);
        }
        Ok(r.body(Body::from(serde_json::to_vec(&body)?))?)
    };
    let created = app
        .clone()
        .oneshot(request(
            "POST",
            &path,
            serde_json::to_value(data.request("instances:read", None))?,
            Some("http-grant"),
            None,
        )?)
        .await?;
    assert_eq!(created.status(), StatusCode::CREATED);
    assert_eq!(created.headers()["etag"], "\"1\"");
    let location = created.headers()["location"].to_str()?.to_owned();
    let missing = app
        .clone()
        .oneshot(request(
            "PATCH",
            &location,
            json!({"enabled":false,"expires_at":null}),
            Some("missing-etag"),
            None,
        )?)
        .await?;
    assert_eq!(missing.status(), StatusCode::PRECONDITION_REQUIRED);
    let updated = app
        .clone()
        .oneshot(request(
            "PATCH",
            &location,
            json!({"enabled":false,"expires_at":null}),
            Some("disable-grant"),
            Some("\"1\""),
        )?)
        .await?;
    assert_eq!(updated.status(), StatusCode::OK);
    assert_eq!(updated.headers()["etag"], "\"2\"");
    let list = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("{path}?limit=2"),
            Value::Null,
            None,
            None,
        )?)
        .await?;
    assert_eq!(list.status(), StatusCode::OK);
    let list: Value = serde_json::from_slice(&list.into_body().collect().await?.to_bytes())?;
    assert_eq!(list["items"].as_array().context("Missing grants")?.len(), 2);
    assert!(list["next_cursor"].is_string());
    let direct = data
        .fixture
        .database
        .list_project_grants(
            &data.fixture.actor,
            &HistoryQuery {
                project_id: data.project,
                instance_id: None,
                limit: Some(2),
                cursor: Some(
                    list["next_cursor"]
                        .as_str()
                        .context("Missing cursor")?
                        .to_owned(),
                ),
            },
            &CursorSigner::from_json(include_str!("fixtures/history/cursor-keys.json"))?,
        )
        .await
        .map_err(api_failure)?;
    assert_eq!(direct.items.len(), 2);
    // Exercise the public grant path: fixtures must not bypass the
    // supported-action check by provisioning only direct owner grants.
    let file_ceiling = Utc::now() + Duration::hours(1);
    for action in ["files:read", "files:write"] {
        let denied = app
            .clone()
            .oneshot(request(
                "POST",
                &path,
                serde_json::to_value(data.request(action, Some(file_ceiling)))?,
                Some(&format!("{action}-without-authority")),
                None,
            )?)
            .await?;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let denied: Value =
            serde_json::from_slice(&denied.into_body().collect().await?.to_bytes())?;
        assert_eq!(denied["code"], "DELEGATION_DENIED");
        let mut tx = data.fixture.owner_transaction().await?;
        sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action,expires_at) VALUES($1,$2,$3,$4,$5)")
            .bind(data.fixture.actor.tenant_id).bind(data.project)
            .bind(data.fixture.actor.principal_id).bind(action).bind(file_ceiling)
            .execute(&mut *tx).await?;
        tx.commit().await?;
        for expiry in [None, Some(file_ceiling + Duration::seconds(1))] {
            let denied = app
                .clone()
                .oneshot(request(
                    "POST",
                    &path,
                    serde_json::to_value(data.request(action, expiry))?,
                    Some(&format!("{action}-over-expiry")),
                    None,
                )?)
                .await?;
            assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        }
        let accepted = app
            .clone()
            .oneshot(request(
                "POST",
                &path,
                serde_json::to_value(data.request(action, Some(file_ceiling)))?,
                Some(&format!("{action}-bounded")),
                None,
            )?)
            .await?;
        assert_eq!(accepted.status(), StatusCode::CREATED);
        let accepted: Value =
            serde_json::from_slice(&accepted.into_body().collect().await?.to_bytes())?;
        assert_eq!(accepted["resource"]["action"], action);
        let expires: DateTime<Utc> =
            serde_json::from_value(accepted["resource"]["expires_at"].clone())?;
        assert_eq!(expires.timestamp_micros(), file_ceiling.timestamp_micros());
    }
    let mut tx = data.fixture.owner_transaction().await?;
    sqlx::query(
        "UPDATE tenant_principals SET enabled=false WHERE tenant_id=$1 AND principal_id=$2",
    )
    .bind(data.fixture.actor.tenant_id)
    .bind(data.fixture.actor.principal_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let denied = app
        .oneshot(request("GET", &path, Value::Null, None, None)?)
        .await?;
    assert_eq!(denied.status(), StatusCode::NOT_FOUND);
    server.abort();
    Ok(())
}
