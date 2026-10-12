#[allow(dead_code)]
mod support;
use anyhow::Context;
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
    history::CursorSigner,
    model::{PublicOperationError, PublicOperationErrorCode},
};
use serde_json::{Value, json};
use std::sync::Arc;
use support::{Fixture, api_failure};
use tower::ServiceExt;
use uuid::Uuid;

#[test]
fn public_operation_errors_map_only_fixed_codes_and_never_forward_arbitrary_fields()
-> anyhow::Result<()> {
    for input in [
        json!({"code":"PRIVATE-MARKER","retryable":true,"message":"PRIVATE-MARKER"}),
        json!(["PRIVATE-MARKER"]),
        json!("PRIVATE-MARKER"),
        json!(null),
        json!({"details":{"secret":"PRIVATE-MARKER"}}),
    ] {
        let error: PublicOperationError = serde_json::from_value(input)?;
        assert_eq!(error.code, PublicOperationErrorCode::OperationFailed);
        assert!(!error.retryable);
        assert!(!serde_json::to_string(&error)?.contains("PRIVATE-MARKER"));
    }
    let error: PublicOperationError = serde_json::from_value(
        json!({"code":"OUTCOME_UNKNOWN","retryable":true,"message":"PRIVATE-MARKER"}),
    )?;
    assert_eq!(error.code, PublicOperationErrorCode::OutcomeUnknown);
    assert!(!error.retryable);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires real PostgreSQL 17+, both TEST_*DATABASE_URL credentials and a loopback mock JWKS listener"]
async fn capabilities_report_only_implemented_contract_and_live_project_limits_after_explicit_authorization()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let fixture = Fixture::new(10).await?;
    let created = fixture
        .create("capability-instance")
        .await
        .map_err(api_failure)?;
    let project = created.body.resource.project_id;
    assert!(
        matches!(fixture.database.capabilities(&fixture.actor,project,300,86400).await,Err(e) if e.status==StatusCode::NOT_FOUND)
    );
    let mut tx = fixture.owner_transaction().await?;
    sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,'capabilities:read')").bind(fixture.actor.tenant_id).bind(project).bind(fixture.actor.principal_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE projects SET max_ttl_seconds=120 WHERE tenant_id=$1 AND id=$2")
        .bind(fixture.actor.tenant_id)
        .bind(project)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let caps = fixture
        .database
        .capabilities(&fixture.actor, project, 300, 86400)
        .await
        .map_err(api_failure)?;
    let caps = serde_json::to_value(caps)?;
    assert_eq!(
        caps["limits"]["ttl_seconds"],
        json!({"minimum":60,"maximum":120,"configured_default":300,"explicit_value_required":true})
    );
    assert_eq!(
        caps["flavors"].as_array().context("Missing flavors")?.len(),
        3
    );
    assert_eq!(caps["runtime_certification"], "NOT_ASSERTED");
    assert!(
        caps.as_object()
            .context("Capabilities object")?
            .contains_key("automation")
    );
    assert!(
        caps["automation"].is_null(),
        "unmounted automation routes have no usable contract"
    );
    for name in [
        "file_transfer",
        "terminal_sessions",
        "execution_output_download",
        "execution_output_streaming",
        "monitoring",
        "health_diagnostics",
        "scheduled_tasks",
        "event_automation",
        "automation_notifications",
        "backup_restore",
    ] {
        assert_eq!(caps["api_features"][name], false);
    }
    assert_eq!(caps["api_features"]["execution_acceptance"], true);
    assert_eq!(caps["api_features"]["instance_security"], true);
    assert_eq!(caps["api_features"]["control_plane_diagnoses"], true);
    // Discovery reports the implemented API, even without a diagnosis grant.
    // It must not replace authorization for the advertised mutation.
    assert!(
        matches!(fixture.database.create_diagnosis(&fixture.actor,created.body.resource.id,&sandbox_platform::diagnostics::CreateDiagnosis::default(),"capability-not-diagnosis-authority").await,Err(e) if e.status==StatusCode::NOT_FOUND)
    );
    assert!(!caps.to_string().contains("integration-storage"));
    assert!(!caps.to_string().contains("runtime_namespace"));
    let capped = fixture
        .database
        .capabilities(&fixture.actor, project, 60, 90)
        .await
        .map_err(api_failure)?;
    assert_eq!(capped.limits.ttl_seconds.maximum, 90);
    assert!(!capped.limits.ttl_seconds.explicit_value_required);
    assert!(
        matches!(fixture.database.capabilities(&fixture.actor,Uuid::new_v4(),300,86400).await,Err(e) if e.status==StatusCode::NOT_FOUND)
    );
    let other = Fixture::new(10).await?;
    let other_project = other
        .create("other-capability")
        .await
        .map_err(api_failure)?
        .body
        .resource
        .project_id;
    assert!(
        matches!(fixture.database.capabilities(&fixture.actor,other_project,300,86400).await,Err(e) if e.status==StatusCode::NOT_FOUND)
    );

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
    fixture.bind_client_id("capabilities-test").await?;
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
    let now = chrono::Utc::now().timestamp();
    let token = encode(
        &header,
        &json!({"iss":"https://issuer.example.test","sub":fixture.actor.principal_id.to_string(),"aud":"sandbox-api","client_id":"capabilities-test","jti":Uuid::new_v4().to_string(),"iat":now,"exp":now+300,"scope":"sandbox:access"}),
        &EncodingKey::from_rsa_der(include_bytes!("fixtures/auth/rsa-a.der")),
    )?;
    let app = router(Arc::new(AppState {
        output_reader: None,
        metrics: None,
        database: fixture.database.clone(),
        auth,
        cursor_signer: CursorSigner::from_json(include_str!("fixtures/history/cursor-keys.json"))?,
        default_ttl_seconds: 300,
        max_ttl_seconds: 86400,
    }));
    let path = format!("/v1/capabilities?project_id={project}");
    let request = || {
        Request::builder()
            .uri(&path)
            .header("authorization", format!("Bearer {token}"))
            .header("x-tenant-id", fixture.actor.tenant_id.to_string())
            .body(Body::empty())
    };
    let response = app.clone().oneshot(request()?).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let response: Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    assert_eq!(response, caps);
    assert_eq!(response["api_features"]["control_plane_diagnoses"], true);
    assert_eq!(response["api_features"]["health_diagnostics"], false);
    let details = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/instances/{}/details",
                    created.body.resource.id
                ))
                .header("authorization", format!("Bearer {token}"))
                .header("x-tenant-id", fixture.actor.tenant_id.to_string())
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(details.status(), StatusCode::OK);
    assert_eq!(
        details.headers()["x-instance-etag"],
        format!("\"{}\"", created.body.resource.spec_version)
    );
    assert!(!details.headers().contains_key("etag"));
    let details: Value = serde_json::from_slice(&details.into_body().collect().await?.to_bytes())?;
    assert_eq!(details["launch_readiness"]["status"], "UNVERIFIED");
    assert_eq!(details["runtime_health"]["status"], "UNKNOWN");
    assert_eq!(details["active_execution"]["state"], "REDACTED");

    let mut tx = fixture.owner_transaction().await?;
    sqlx::query(
        "UPDATE grants SET enabled=false WHERE tenant_id=$1 AND action='capabilities:read'",
    )
    .bind(fixture.actor.tenant_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let response = app.oneshot(request()?).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    server.abort();
    Ok(())
}
