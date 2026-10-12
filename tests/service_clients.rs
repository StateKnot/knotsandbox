#[allow(dead_code)]
mod support;
use anyhow::Context;
use chrono::{Duration, Utc};
use futures_util::future::join_all;
use sandbox_platform::{
    db::Actor,
    history::CursorSigner,
    service_clients::{RegisterServiceClient, UpdateServiceClient},
};
use serde_json::{Value, json};
use support::{Fixture, api_failure, require_pg_error};
use uuid::Uuid;

const ISSUER: &str = "https://identity.example.test/realms/sandbox";
async fn manager(tenant_wide: bool) -> anyhow::Result<Fixture> {
    let fixture = Fixture::new(10).await?;
    let mut tx = fixture.owner_transaction().await?;
    for action in ["service_clients:read", "service_clients:write"] {
        sqlx::query(
            "INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4)",
        )
        .bind(fixture.actor.tenant_id)
        .bind(if tenant_wide {
            None
        } else {
            Some(fixture.request.project_id)
        })
        .bind(fixture.actor.principal_id)
        .bind(action)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(fixture)
}
fn registration(subject: &str, name: &str) -> RegisterServiceClient {
    RegisterServiceClient {
        issuer: ISSUER.into(),
        subject: subject.into(),
        client_id: "registered-service".into(),
        display_name: name.into(),
    }
}
fn signer() -> anyhow::Result<CursorSigner> {
    CursorSigner::from_json(&json!({"active":{"kid":"test","key_base64":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="},"previous":[]}).to_string())
}

fn oauth_client_cases() -> Vec<(String, bool)> {
    vec![
        ("machine-client".into(), true),
        (" client with exact spaces ".into(), true),
        ("a".repeat(256), true),
        ("é".repeat(128), true),
        ("\u{feff}".into(), true),
        (String::new(), false),
        (" ".into(), false),
        ("\u{00a0}".into(), false),
        ("\u{3000}".into(), false),
        ("\u{2000}\u{202f}\u{205f}".into(), false),
        ("a".repeat(257), false),
        ("a".repeat(300), false),
        ("é".repeat(129), false),
        ("client\u{0007}".into(), false),
        ("client\u{0085}".into(), false),
    ]
}

#[test]
fn oauth_client_validation_matches_jwt_and_owner_binding_contract() -> anyhow::Result<()> {
    use sandbox_platform::{admin::ServiceIdentityBindingRequest, auth::valid_client_id};
    for (client, valid) in oauth_client_cases() {
        assert_eq!(valid_client_id(&client), valid);
        let mut request = json!({"issuer":ISSUER,"subject":"reviewed-sub","expected_client_id":null,"client_id":client,"reason":"Reviewed identity metadata"});
        assert_eq!(
            ServiceIdentityBindingRequest::parse(&serde_json::to_vec(&request)?).is_ok(),
            valid
        );
        request["expected_client_id"] = request["client_id"].clone();
        request["client_id"] = json!("valid-new-client");
        assert_eq!(
            ServiceIdentityBindingRequest::parse(&serde_json::to_vec(&request)?).is_ok(),
            valid
        );
    }
    let request = json!({"issuer":ISSUER,"subject":"reviewed-sub","client_id":"valid-new-client","reason":"Reviewed identity metadata"});
    assert!(
        ServiceIdentityBindingRequest::parse(&serde_json::to_vec(&request)?).is_err(),
        "owner CAS explicitly requires expected_client_id, including null"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL normal migrations and distinct owner/app logins"]
async fn oauth_client_registration_and_owner_sql_enforce_exact_utf8_byte_contract()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let f = manager(true).await?;
    f.bind_client_id("validation-manager").await?;
    for (index, (client, valid)) in oauth_client_cases().into_iter().enumerate() {
        let sql_valid: bool = sqlx::query_scalar("SELECT sandbox_valid_oauth_client_id($1)")
            .bind(&client)
            .fetch_one(&f.owner)
            .await?;
        assert_eq!(
            sql_valid, valid,
            "SQL and JWT identifier rules must agree for case {index}"
        );
        let mut request = registration(&Uuid::new_v4().to_string(), "Byte-bounded machine");
        request.client_id = client.clone();
        let result = f
            .database
            .register_service_client(
                &f.actor,
                &request,
                ISSUER,
                &format!("byte-registration-{index}"),
            )
            .await;
        if valid {
            assert_eq!(
                result
                    .map_err(api_failure)?
                    .body
                    .resource
                    .client_id
                    .as_deref(),
                Some(client.as_str()),
                "registration preserves exact bytes"
            );
        } else {
            assert!(matches!(result,Err(e) if e.code=="INVALID_ARGUMENT"));
            let mut tx = f
                .database
                .begin(f.actor.tenant_id)
                .await
                .map_err(api_failure)?;
            let result=sqlx::query("SELECT sandbox_mutate_service_client($1,'CREATE',$2,$3,$4,$5,'Byte-bounded machine',true,NULL::bigint)")
                .bind(f.actor.principal_id).bind(Uuid::new_v4()).bind(ISSUER).bind(&request.subject).bind(&client).execute(&mut *tx).await;
            require_pg_error(result, "P4000")?;
            tx.rollback().await?;
            let result=sqlx::query("SELECT sandbox_bind_service_identity('https://issuer.example.test',$1,'validation-manager',$2,'Reviewed invalid binding')")
                .bind(f.actor.principal_id.to_string()).bind(&client).execute(&f.owner).await;
            require_pg_error(result, "P4000")?;
            let result = sqlx::query(
                "UPDATE principal_identities SET service_client_id=$1 WHERE principal_id=$2",
            )
            .bind(&client)
            .bind(f.actor.principal_id)
            .execute(&f.owner)
            .await;
            require_pg_error(result, "23514")?;
        }
    }
    let binding: String = sqlx::query_scalar(
        "SELECT service_client_id FROM principal_identities WHERE principal_id=$1",
    )
    .bind(f.actor.principal_id)
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(
        binding, "validation-manager",
        "invalid owner writes leave the reviewed binding intact"
    );
    Ok(())
}

#[test]
fn identity_and_secret_fields_cannot_be_patched_or_submitted() -> anyhow::Result<()> {
    for request in [
        json!({"issuer":ISSUER,"subject":"service","display_name":"Service","secret":"forbidden"}),
        json!({"issuer":ISSUER,"subject":"service"}),
    ] {
        assert!(serde_json::from_value::<RegisterServiceClient>(request).is_err());
    }
    assert!(
        serde_json::from_value::<UpdateServiceClient>(
            json!({"enabled":true,"display_name":"Name","subject":"rebind"})
        )
        .is_err()
    );
    Ok(())
}
#[tokio::test]
#[ignore = "Requires PostgreSQL and both TEST_*DATABASE_URL credentials"]
async fn registration_requires_tenant_authority_and_trusted_issuer_and_never_rebinds_user_identity()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let project_only = manager(false).await?;
    let request = registration(&Uuid::new_v4().to_string(), "Machine");
    assert!(
        matches!(project_only.database.register_service_client(&project_only.actor,&request,ISSUER,"project-only").await,Err(e) if e.code=="RESOURCE_NOT_FOUND")
    );
    let fixture = manager(true).await?;
    assert!(
        matches!(fixture.database.register_service_client(&fixture.actor,&request,"https://another.example","wrong-issuer").await,Err(e) if e.code=="INVALID_ARGUMENT")
    );
    let mut tx = fixture.owner_transaction().await?;
    let user = Uuid::new_v4();
    sqlx::query("INSERT INTO principals(id,kind,display_name) VALUES($1,'USER','User identity')")
        .bind(user)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO principal_identities(principal_id,issuer,subject) VALUES($1,$2,$3)")
        .bind(user)
        .bind(ISSUER)
        .bind(&request.subject)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    assert!(
        matches!(fixture.database.register_service_client(&fixture.actor,&request,ISSUER,"user-rebind").await,Err(e) if e.code=="RESOURCE_NOT_FOUND")
    );
    let mut tx = fixture
        .database
        .begin(fixture.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    let forbidden = sqlx::query("INSERT INTO principals(kind,display_name) VALUES('SERVICE','No')")
        .execute(&mut *tx)
        .await;
    require_pg_error(forbidden, "42501")?;
    tx.rollback().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "Requires PostgreSQL and both TEST_*DATABASE_URL credentials"]
async fn concurrent_idempotency_and_cross_tenant_registration_share_identity_but_not_membership()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let fixture = manager(true).await?;
    let other = manager(true).await?;
    let subject = Uuid::new_v4().to_string();
    let request = registration(&subject, "Tenant A");
    let results = join_all((0..8).map(|_| {
        fixture
            .database
            .register_service_client(&fixture.actor, &request, ISSUER, "create")
    }))
    .await;
    let mut values = vec![];
    for result in results {
        let result = result.map_err(api_failure)?;
        assert_eq!(result.status, 201);
        values.push(serde_json::to_value(result.body)?);
    }
    assert!(values.iter().all(|v| v == &values[0]));
    let id: Uuid = serde_json::from_value(values[0]["resource"]["id"].clone())?;
    let principal: Uuid = serde_json::from_value(values[0]["resource"]["principal_id"].clone())?;
    let second = other
        .database
        .register_service_client(
            &other.actor,
            &registration(&subject, "Tenant B"),
            ISSUER,
            "create",
        )
        .await
        .map_err(api_failure)?;
    assert_eq!(second.body.resource.principal_id, principal);
    assert_ne!(second.body.resource.id, id);
    assert_eq!(second.body.resource.display_name, "Tenant B");
    assert!(
        matches!(other.database.get_service_client(&other.actor,id).await,Err(e) if e.code=="RESOURCE_NOT_FOUND")
    );
    assert!(
        matches!(fixture.database.register_service_client(&fixture.actor,&request,ISSUER,"duplicate").await,Err(e) if e.code=="SERVICE_CLIENT_ALREADY_EXISTS")
    );
    assert!(
        matches!(fixture.database.register_service_client(&fixture.actor,&registration(&subject,"Different"),ISSUER,"create").await,Err(e) if e.code=="IDEMPOTENCY_CONFLICT")
    );
    let mut tx = fixture.owner_transaction().await?;
    let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM management_receipts WHERE tenant_id=$1 AND action='service_clients:create'),(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='service_clients:create')").bind(fixture.actor.tenant_id).fetch_one(&mut *tx).await?;
    assert_eq!(counts, (1, 1));
    tx.commit().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "Requires PostgreSQL and both TEST_*DATABASE_URL credentials"]
async fn disable_is_tenant_local_replays_do_not_restore_state_and_restoration_cannot_exceed_authority()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let fixture = manager(true).await?;
    let other = manager(true).await?;
    let request = registration(&Uuid::new_v4().to_string(), "Tenant A");
    let created = fixture
        .database
        .register_service_client(&fixture.actor, &request, ISSUER, "create")
        .await
        .map_err(api_failure)?;
    let target = created.body.resource.principal_id;
    let id = created.body.resource.id;
    let elsewhere = other
        .database
        .register_service_client(&other.actor, &request, ISSUER, "create")
        .await
        .map_err(api_failure)?;
    let mut tx = fixture.owner_transaction().await?;
    for action in ["instances:read"] {
        sqlx::query(
            "INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4)",
        )
        .bind(fixture.actor.tenant_id)
        .bind(fixture.request.project_id)
        .bind(target)
        .bind(action)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    let instance = fixture
        .create("instance")
        .await
        .map_err(api_failure)?
        .body
        .resource;
    let actor = Actor {
        authorization: None,
        tenant_id: fixture.actor.tenant_id,
        principal_id: target,
        request_id: Uuid::new_v4(),
    };
    assert!(
        fixture
            .database
            .get_instance(&actor, instance.id)
            .await
            .is_ok()
    );
    let disabled = fixture
        .database
        .update_service_client(
            &fixture.actor,
            id,
            &UpdateServiceClient {
                enabled: false,
                display_name: "Disabled".into(),
            },
            "disable",
            1,
        )
        .await
        .map_err(api_failure)?;
    assert_eq!(disabled.body.resource.version, 2);
    assert!(!disabled.body.resource.enabled);
    assert!(
        fixture
            .database
            .get_instance(&actor, instance.id)
            .await
            .is_err()
    );
    assert!(
        other
            .database
            .get_service_client(&other.actor, elsewhere.body.resource.id)
            .await
            .map_err(api_failure)?
            .enabled
    );
    assert!(
        fixture
            .database
            .register_service_client(&fixture.actor, &request, ISSUER, "create")
            .await
            .map_err(api_failure)?
            .body
            .resource
            .enabled
    );
    assert!(
        !fixture
            .database
            .get_service_client(&fixture.actor, id)
            .await
            .map_err(api_failure)?
            .enabled,
        "Receipt replay is not restoration"
    );
    let restore = UpdateServiceClient {
        enabled: true,
        display_name: "Restored".into(),
    };
    assert!(
        matches!(fixture.database.update_service_client(&fixture.actor,id,&restore,"restore",2).await,Err(e) if e.code=="DELEGATION_DENIED")
    );
    let mut tx = fixture.owner_transaction().await?;
    sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action,expires_at) VALUES($1,$2,$3,'grants:write',$4)").bind(fixture.actor.tenant_id).bind(fixture.request.project_id).bind(fixture.actor.principal_id).bind(Utc::now()+Duration::hours(1)).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(
        matches!(fixture.database.update_service_client(&fixture.actor,id,&restore,"restore",2).await,Err(e) if e.code=="DELEGATION_DENIED")
    );
    let mut tx = fixture.owner_transaction().await?;
    sqlx::query("UPDATE grants SET expires_at=NULL WHERE tenant_id=$1 AND principal_id=$2 AND action='grants:write'").bind(fixture.actor.tenant_id).bind(fixture.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let restored = fixture
        .database
        .update_service_client(&fixture.actor, id, &restore, "restore", 2)
        .await
        .map_err(api_failure)?;
    assert_eq!(restored.body.resource.version, 3);
    assert!(
        fixture
            .database
            .get_instance(&actor, instance.id)
            .await
            .is_ok()
    );
    assert!(
        matches!(fixture.database.update_service_client(&fixture.actor,id,&restore,"stale",2).await,Err(e) if e.code=="VERSION_MISMATCH")
    );
    let mut tx = fixture.owner_transaction().await?;
    sqlx::query(
        "UPDATE tenant_principals SET enabled=false WHERE tenant_id=$1 AND principal_id=$2",
    )
    .bind(fixture.actor.tenant_id)
    .bind(fixture.actor.principal_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    assert!(
        fixture
            .database
            .register_service_client(&fixture.actor, &request, ISSUER, "create")
            .await
            .is_err()
    );
    assert!(
        fixture
            .database
            .update_service_client(&fixture.actor, id, &restore, "restore", 2)
            .await
            .is_err()
    );
    Ok(())
}
#[tokio::test]
#[ignore = "Requires PostgreSQL and both TEST_*DATABASE_URL credentials"]
async fn client_pages_are_signed_and_scoped_to_live_tenant_authority() -> anyhow::Result<()> {
    let _serial = support::serial().await;
    let fixture = manager(true).await?;
    let other = manager(true).await?;
    let signer = signer()?;
    for _ in 0..3 {
        let subject = Uuid::new_v4().to_string();
        fixture
            .database
            .register_service_client(
                &fixture.actor,
                &registration(&subject, "Page"),
                ISSUER,
                &subject,
            )
            .await
            .map_err(api_failure)?;
    }
    let page = fixture
        .database
        .list_service_clients(&fixture.actor, Some(1), None, &signer)
        .await
        .map_err(api_failure)?;
    assert_eq!(page.items.len(), 1);
    let cursor = page.next_cursor.context("More clients")?;
    let second = fixture
        .database
        .list_service_clients(&fixture.actor, Some(1), Some(cursor.clone()), &signer)
        .await
        .map_err(api_failure)?;
    assert_ne!(page.items[0].id, second.items[0].id);
    assert!(
        matches!(fixture.database.list_service_clients(&other.actor,Some(1),Some(cursor.clone()),&signer).await,Err(e) if e.code=="INVALID_CURSOR")
    );
    assert!(
        matches!(fixture.database.list_service_clients(&fixture.actor,Some(2),Some(cursor),&signer).await,Err(e) if e.code=="INVALID_CURSOR")
    );
    let mut tx = fixture.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='service_clients:read'").bind(fixture.actor.tenant_id).bind(fixture.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(
        fixture
            .database
            .list_service_clients(&fixture.actor, None, None, &signer)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires PostgreSQL and a loopback JWKS listener"]
async fn signed_http_service_client_registration_and_disable_obey_identity_and_etag_contracts()
-> anyhow::Result<()> {
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::get,
    };
    use http_body_util::BodyExt;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use sandbox_platform::{
        api::{AppState, router},
        auth::{AuthConfig, JwtAuthenticator},
    };
    use std::sync::Arc;
    use tower::ServiceExt;
    let _serial = support::serial().await;
    let fixture = manager(true).await?;
    let jwk: Value = serde_json::from_str(include_str!("fixtures/auth/jwk-a.json"))?;
    let kid = jwk["kid"].as_str().context("kid")?.to_owned();
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
    fixture.bind_client_id("client-admin-test").await?;
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
        &json!({"iss":"https://issuer.example.test","sub":fixture.actor.principal_id.to_string(),"aud":"sandbox-api","client_id":"client-admin-test","jti":Uuid::new_v4().to_string(),"iat":now,"exp":now+300,"scope":"sandbox:access"}),
        &EncodingKey::from_rsa_der(include_bytes!("fixtures/auth/rsa-a.der")),
    )?;
    let app = router(Arc::new(AppState {
        database: fixture.database.clone(),
        auth,
        cursor_signer: signer()?,
        output_reader: None,
        metrics: None,
        default_ttl_seconds: 300,
        max_ttl_seconds: 86400,
    }));
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
            .header("x-tenant-id", fixture.actor.tenant_id.to_string())
            .header("content-type", "application/json");
        if let Some(k) = key {
            r = r.header("idempotency-key", k);
        }
        if let Some(e) = etag {
            r = r.header("if-match", e);
        }
        Ok(r.body(Body::from(serde_json::to_vec(&body)?))?)
    };
    let body = json!({"issuer":"https://issuer.example.test","subject":Uuid::new_v4().to_string(),"display_name":"HTTP machine","client_id":"http-registered-client"});
    let wrong = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/service-clients",
            json!({"issuer":"https://untrusted.test","subject":"other","display_name":"Wrong","client_id":"http-registered-client"}),
            Some("wrong"),
            None,
        )?)
        .await?;
    assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
    for (index, client) in [
        "a".repeat(300),
        "é".repeat(129),
        "\u{00a0}".into(),
        "\u{3000}".into(),
    ]
    .into_iter()
    .enumerate()
    {
        let mut invalid = body.clone();
        invalid["client_id"] = json!(client);
        let rejected = app
            .clone()
            .oneshot(request(
                "POST",
                "/v1/service-clients",
                invalid,
                Some(&format!("invalid-client-{index}")),
                None,
            )?)
            .await?;
        assert_eq!(
            rejected.status(),
            StatusCode::BAD_REQUEST,
            "HTTP registration follows the JWT byte and whitespace contract"
        );
    }
    let mut secret = body.clone();
    secret["client_secret"] = json!("must-reject");
    let rejected = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/service-clients",
            secret,
            Some("secret"),
            None,
        )?)
        .await?;
    assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let created = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/service-clients",
            body.clone(),
            Some("create"),
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
            json!({"enabled":false,"display_name":"HTTP machine"}),
            Some("disable"),
            None,
        )?)
        .await?;
    assert_eq!(missing.status(), StatusCode::PRECONDITION_REQUIRED);
    let disabled = app
        .clone()
        .oneshot(request(
            "PATCH",
            &location,
            json!({"enabled":false,"display_name":"HTTP machine"}),
            Some("disable"),
            Some("\"1\""),
        )?)
        .await?;
    assert_eq!(disabled.status(), StatusCode::OK);
    assert_eq!(disabled.headers()["etag"], "\"2\"");
    let got = app
        .clone()
        .oneshot(request("GET", &location, Value::Null, None, None)?)
        .await?;
    assert_eq!(got.status(), StatusCode::OK);
    let got: Value = serde_json::from_slice(&got.into_body().collect().await?.to_bytes())?;
    assert_eq!(got["enabled"], false);
    assert_eq!(got["identity_enabled"], true);
    let list = app
        .clone()
        .oneshot(request(
            "GET",
            "/v1/service-clients?limit=1",
            Value::Null,
            None,
            None,
        )?)
        .await?;
    assert_eq!(list.status(), StatusCode::OK);
    let mut tx = fixture.owner_transaction().await?;
    sqlx::query(
        "UPDATE tenant_principals SET enabled=false WHERE tenant_id=$1 AND principal_id=$2",
    )
    .bind(fixture.actor.tenant_id)
    .bind(fixture.actor.principal_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let stale = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/service-clients",
            body,
            Some("create"),
            None,
        )?)
        .await?;
    assert_eq!(stale.status(), StatusCode::NOT_FOUND);
    let stale = app
        .oneshot(request("GET", &location, Value::Null, None, None)?)
        .await?;
    assert_eq!(stale.status(), StatusCode::NOT_FOUND);
    server.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real normal PostgreSQL migrations and distinct owner/app logins"]
async fn service_client_binding_rejects_other_client_and_owner_rotation_revokes_delegation()
-> anyhow::Result<()> {
    use sandbox_platform::{
        auth::VerifiedIdentity,
        automation::{AutomationAction, AutomationTrigger, CreateAutomation},
    };
    let _serial = support::serial().await;
    let f = manager(true).await?;
    f.bind_client_id("reviewed-client-a").await?;
    let identity = VerifiedIdentity {
        issuer: "https://issuer.example.test".into(),
        subject: f.actor.principal_id.to_string(),
        client_id: Some("reviewed-client-a".into()),
        scopes: vec!["sandbox:access".into()],
        scope_profile: Default::default(),
        expires_at: Utc::now().timestamp() + 300,
    };
    let actor = f
        .database
        .resolve_actor(&identity, f.actor.tenant_id, Uuid::new_v4())
        .await
        .map_err(api_failure)?;
    let mut wrong = identity.clone();
    wrong.client_id = Some("another-client-with-same-sub".into());
    assert!(
        matches!(f.database.resolve_actor(&wrong,f.actor.tenant_id,Uuid::new_v4()).await,Err(e) if e.code=="PERMISSION_DENIED")
    );
    let instance = f
        .create("client-binding-instance")
        .await
        .map_err(api_failure)?
        .body
        .resource;
    let mut tx = f.owner_transaction().await?;
    // Fixture::new already grants instances:renew; add only the management action.
    sqlx::query(
        "INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,'automations:write')",
    )
    .bind(f.actor.tenant_id)
    .bind(f.request.project_id)
    .bind(f.actor.principal_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let request = CreateAutomation {
        name: "Client-bound renewal".into(),
        action: AutomationAction::Renew { ttl_seconds: 600 },
        trigger: AutomationTrigger::Once {
            at: Utc::now() + Duration::minutes(5),
        },
        delegation_expires_at: Utc::now() + Duration::hours(1),
        run_budget: 1,
        minimum_interval_seconds: 60,
        grace_seconds: 60,
    };
    let receipt = f
        .database
        .create_automation(
            &actor,
            &identity,
            instance.id,
            &request,
            "client-delegation",
            1,
            86400,
        )
        .await
        .map_err(api_failure)?;
    let live = |id| {
        let f = &f;
        async move {
            let mut tx = f.owner_transaction().await?;
            let enabled: bool = sqlx::query_scalar("SELECT sandbox_automation_authorized($1,$2)")
                .bind(f.actor.tenant_id)
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok::<_, anyhow::Error>(enabled)
        }
    };
    assert!(live(receipt.body.resource.id).await?);
    let runtime_bind=sqlx::query("SELECT sandbox_bind_service_identity('https://issuer.example.test',$1,'reviewed-client-a','new-client','Untrusted runtime rotation')")
        .bind(&identity.subject).execute(&f.database.pool).await;
    require_pg_error(runtime_bind, "42501")?;
    f.bind_client_id("reviewed-client-b").await?;
    assert!(!live(receipt.body.resource.id).await?);
    assert!(
        f.database
            .resolve_actor(&identity, f.actor.tenant_id, Uuid::new_v4())
            .await
            .is_err()
    );
    let stale=sqlx::query("SELECT sandbox_bind_service_identity('https://issuer.example.test',$1,'reviewed-client-a','stale-change','Reviewed stale CAS')")
        .bind(&identity.subject).execute(&f.owner).await;
    require_pg_error(stale, "P4120")?;
    f.bind_client_id("reviewed-client-a").await?;
    assert!(
        !live(receipt.body.resource.id).await?,
        "binding generation prevents old delegation revival"
    );
    assert!(
        f.database
            .resolve_actor(&identity, f.actor.tenant_id, Uuid::new_v4())
            .await
            .is_ok()
    );
    let second = registration(&Uuid::new_v4().to_string(), "Registered machine");
    f.database
        .register_service_client(&f.actor, &second, ISSUER, "exact-client-register")
        .await
        .map_err(api_failure)?;
    let mut different = registration(&second.subject, "Another tenant same-sub client");
    different.client_id = "another-client".into();
    let other = manager(true).await?;
    assert!(
        matches!(other.database.register_service_client(&other.actor,&different,ISSUER,"same-sub-wrong-client").await,Err(e) if e.code=="RESOURCE_NOT_FOUND")
    );
    Ok(())
}
