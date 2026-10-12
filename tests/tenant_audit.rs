#[allow(dead_code)]
mod support;

use anyhow::{Context, ensure};
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
    auth::{AuthConfig, JwtAuthenticator, ScopeProfile, VerifiedIdentity},
    db::Actor,
    history::{CursorSigner, HistoryQuery},
    service_clients::{RegisterServiceClient, UpdateServiceClient},
    tenant_audit::{READ_ACTION, TenantAuditQuery},
};
use serde_json::{Value, json};
use std::{collections::HashSet, sync::Arc, time::Duration};
use support::{Fixture, api_failure};
use tower::ServiceExt;
use uuid::Uuid;

fn signer() -> anyhow::Result<CursorSigner> {
    CursorSigner::from_json(include_str!("fixtures/history/cursor-keys.json"))
}
fn query(limit: i64) -> TenantAuditQuery {
    TenantAuditQuery {
        limit: Some(limit),
        cursor: None,
    }
}
async fn grant(
    f: &Fixture,
    principal: Uuid,
    project: Option<Uuid>,
    action: &str,
) -> anyhow::Result<()> {
    let mut tx = f.owner_transaction().await?;
    sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4)")
        .bind(f.actor.tenant_id)
        .bind(project)
        .bind(principal)
        .bind(action)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}
async fn manager() -> anyhow::Result<Fixture> {
    let f = Fixture::new(10).await?;
    for action in [READ_ACTION, "service_clients:read", "service_clients:write"] {
        grant(&f, f.actor.principal_id, None, action).await?;
    }
    f.bind_client_id("tenant-audit-fixture").await?;
    Ok(f)
}
fn identity(f: &Fixture) -> VerifiedIdentity {
    VerifiedIdentity {
        issuer: "https://issuer.example.test".into(),
        subject: f.actor.principal_id.to_string(),
        client_id: Some("tenant-audit-fixture".into()),
        scopes: vec![READ_ACTION.into()],
        scope_profile: ScopeProfile::ActionScopes,
        expires_at: Utc::now().timestamp() + 300,
    }
}
fn http_actor(f: &Fixture) -> Actor {
    Actor {
        authorization: Some(identity(f)),
        ..f.actor.clone()
    }
}
async fn seed(f: &Fixture, count: usize) -> anyhow::Result<HashSet<Uuid>> {
    let mut tx = f.owner_transaction().await?;
    let timestamp: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()-interval '1 hour'")
        .fetch_one(&mut *tx)
        .await?;
    let mut ids = HashSet::new();
    for _ in 0..count {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO audit_events(id,tenant_id,actor_principal_id,request_id,resource_id,action,outcome,details,occurred_at) VALUES($1,$2,$3,$4,$5,'test.tenant_history','SUCCEEDED',$6,$7)")
            .bind(id).bind(f.actor.tenant_id).bind(f.actor.principal_id).bind(Uuid::new_v4()).bind(Uuid::new_v4())
            .bind(json!({"PRIVATE_TENANT_AUDIT_MARKER":"secret credential, command and external provider response"})).bind(timestamp).execute(&mut *tx).await?;
        ids.insert(id);
    }
    tx.commit().await?;
    Ok(ids)
}

#[tokio::test]
#[ignore = "requires real PostgreSQL 17+ and distinct owner/app credentials"]
async fn tenant_audit_pages_contain_real_account_changes_and_never_project_or_cross_tenant_details()
-> anyhow::Result<()> {
    let _guard = support::serial().await;
    let f = manager().await?;
    let other = manager().await?;
    seed(&other, 3).await?;
    let mut expected = seed(&f, 5).await?;
    let registered = f
        .database
        .register_service_client(
            &f.actor,
            &RegisterServiceClient {
                issuer: "https://issuer.example.test".into(),
                subject: Uuid::new_v4().to_string(),
                client_id: "audited-client".into(),
                display_name: "Audited machine".into(),
            },
            "https://issuer.example.test",
            "tenant-audit-register",
        )
        .await
        .map_err(api_failure)?
        .body
        .resource;
    let mut client = registered;
    for (index, enabled) in [false, true, false].into_iter().enumerate() {
        client = f
            .database
            .update_service_client(
                &f.actor,
                client.id,
                &UpdateServiceClient {
                    display_name: client.display_name.clone(),
                    enabled,
                },
                &format!("tenant-audit-update-{index}"),
                client.version,
            )
            .await
            .map_err(api_failure)?
            .body
            .resource;
    }
    let mut tx = f.owner_transaction().await?;
    let actual: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM audit_events WHERE tenant_id=$1 AND project_id IS NULL AND resource_id=$2",
    )
    .bind(f.actor.tenant_id)
    .bind(client.id)
    .fetch_all(&mut *tx)
    .await?;
    ensure!(
        actual.len() == 4,
        "real registration and three changes create four tenant records"
    );
    expected.extend(actual);
    let project_id = Uuid::new_v4();
    sqlx::query("INSERT INTO audit_events(id,tenant_id,project_id,request_id,action,outcome,details) VALUES($1,$2,$3,$4,'test.project_only','SUCCEEDED',$5)")
        .bind(project_id).bind(f.actor.tenant_id).bind(f.request.project_id).bind(Uuid::new_v4()).bind(json!({"PRIVATE_TENANT_AUDIT_MARKER":"project private"})).execute(&mut *tx).await?;
    tx.commit().await?;
    grant(
        &f,
        f.actor.principal_id,
        Some(f.request.project_id),
        "audit:read",
    )
    .await?;
    let project = f
        .database
        .list_audit_records(
            &f.actor,
            &HistoryQuery {
                project_id: f.request.project_id,
                instance_id: None,
                limit: Some(100),
                cursor: None,
            },
            &signer()?,
        )
        .await
        .map_err(api_failure)?;
    ensure!(
        project.items.len() == 1 && project.items[0].id == project_id,
        "project reader remains project-only"
    );
    let mut q = query(2);
    let mut seen = HashSet::new();
    let mut order = Vec::new();
    let mut cutoff = None;
    loop {
        let page = f
            .database
            .list_tenant_audit_records(&http_actor(&f), &q, &signer()?)
            .await
            .map_err(api_failure)?;
        ensure!(
            cutoff.is_none_or(|cutoff| cutoff == page.cutoff),
            "stable page cutoff"
        );
        if cutoff.is_none() {
            cutoff = Some(page.cutoff);
            let mut tx = f.owner_transaction().await?;
            sqlx::query("INSERT INTO audit_events(tenant_id,request_id,action,outcome) VALUES($1,$2,'test.after_cutoff','SUCCEEDED')")
                .bind(f.actor.tenant_id).bind(Uuid::new_v4()).execute(&mut *tx).await?;
            tx.commit().await?;
        }
        ensure!(
            !serde_json::to_string(&page)?.contains("PRIVATE_TENANT_AUDIT_MARKER"),
            "raw audit details remain private"
        );
        for record in page.items {
            ensure!(
                record.tenant_id == f.actor.tenant_id && record.project_id.is_none(),
                "exact tenant and NULL-project scope"
            );
            ensure!(
                expected.contains(&record.id) && seen.insert(record.id),
                "no cross-scope or duplicate records"
            );
            order.push((record.occurred_at, record.id));
        }
        match page.next_cursor {
            Some(cursor) => q.cursor = Some(cursor),
            None => break,
        }
    }
    ensure!(
        seen == expected && order.windows(2).all(|rows| rows[0] > rows[1]),
        "complete stable keyset traversal"
    );
    f.database.check_identity_api_schema().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL RLS and live identity/grant revocation"]
async fn tenant_audit_rechecks_every_live_authority_and_action_scope() -> anyhow::Result<()> {
    let _guard = support::serial().await;
    let f = manager().await?;
    seed(&f, 3).await?;
    let actor = http_actor(&f);
    let first = f
        .database
        .list_tenant_audit_records(&actor, &query(1), &signer()?)
        .await
        .map_err(api_failure)?;
    let q = TenantAuditQuery {
        limit: Some(1),
        cursor: first.next_cursor,
    };
    for (withdraw, restore, status) in [
        (
            "UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='tenant_audit:read'",
            "UPDATE grants SET enabled=true WHERE tenant_id=$1 AND principal_id=$2 AND action='tenant_audit:read'",
            StatusCode::NOT_FOUND,
        ),
        (
            "UPDATE grants SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND principal_id=$2 AND action='tenant_audit:read'",
            "UPDATE grants SET expires_at=NULL WHERE tenant_id=$1 AND principal_id=$2 AND action='tenant_audit:read'",
            StatusCode::NOT_FOUND,
        ),
        (
            "UPDATE grants SET enabled=false,revoked_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND action='tenant_audit:read'",
            "UPDATE grants SET enabled=true,revoked_at=NULL WHERE tenant_id=$1 AND principal_id=$2 AND action='tenant_audit:read'",
            StatusCode::NOT_FOUND,
        ),
        (
            "UPDATE tenants SET enabled=false WHERE id=$1 AND $2::uuid IS NOT NULL",
            "UPDATE tenants SET enabled=true WHERE id=$1 AND $2::uuid IS NOT NULL",
            StatusCode::NOT_FOUND,
        ),
        (
            "UPDATE tenant_principals SET enabled=false WHERE tenant_id=$1 AND principal_id=$2",
            "UPDATE tenant_principals SET enabled=true WHERE tenant_id=$1 AND principal_id=$2",
            StatusCode::NOT_FOUND,
        ),
        (
            "UPDATE principals SET enabled=false WHERE id=$2 AND $1::uuid IS NOT NULL",
            "UPDATE principals SET enabled=true WHERE id=$2 AND $1::uuid IS NOT NULL",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "UPDATE principal_identities SET enabled=false WHERE principal_id=$2 AND $1::uuid IS NOT NULL",
            "UPDATE principal_identities SET enabled=true WHERE principal_id=$2 AND $1::uuid IS NOT NULL",
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        for (sql, denied) in [(withdraw, true), (restore, false)] {
            let mut tx = f.owner_transaction().await?;
            sqlx::query(sql)
                .bind(f.actor.tenant_id)
                .bind(f.actor.principal_id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            let result = f
                .database
                .list_tenant_audit_records(&actor, &q, &signer()?)
                .await;
            if denied {
                ensure!(
                    result.is_err_and(|error| error.status == status),
                    "old valid cursor cannot preserve withdrawn authority"
                );
            } else {
                result.map_err(api_failure)?;
            }
        }
    }
    let mut invalid = actor.clone();
    invalid.authorization.as_mut().context("identity")?.scopes = vec!["audit:read".into()];
    ensure!(
        f.database
            .list_tenant_audit_records(&invalid, &q, &signer()?)
            .await
            .is_err_and(|e| e.code == "INSUFFICIENT_SCOPE"),
        "project OAuth action cannot read tenant administration"
    );
    invalid.authorization = Some(identity(&f));
    invalid
        .authorization
        .as_mut()
        .context("identity")?
        .expires_at = Utc::now().timestamp() - 1;
    ensure!(
        f.database
            .list_tenant_audit_records(&invalid, &q, &signer()?)
            .await
            .is_err_and(|e| e.status == StatusCode::UNAUTHORIZED),
        "expired token"
    );
    invalid.authorization = Some(identity(&f));
    invalid
        .authorization
        .as_mut()
        .context("identity")?
        .client_id = Some("wrong-client".into());
    ensure!(
        f.database
            .list_tenant_audit_records(&invalid, &q, &signer()?)
            .await
            .is_err_and(|e| e.status == StatusCode::UNAUTHORIZED),
        "exact service identity binding"
    );
    let project = Fixture::new(2).await?;
    grant(
        &project,
        project.actor.principal_id,
        Some(project.request.project_id),
        READ_ACTION,
    )
    .await?;
    ensure!(
        project
            .database
            .list_tenant_audit_records(&project.actor, &query(100), &signer()?)
            .await
            .is_err_and(|e| e.status == StatusCode::NOT_FOUND),
        "project product action cannot read tenant records"
    );
    let system = Uuid::new_v4();
    sqlx::query("INSERT INTO principals(id,kind,display_name) VALUES($1,'SYSTEM','Controller')")
        .bind(system)
        .execute(&f.owner)
        .await?;
    grant(&f, system, None, "*").await?;
    let system_actor = Actor {
        principal_id: system,
        authorization: None,
        ..f.actor.clone()
    };
    ensure!(
        f.database
            .list_tenant_audit_records(&system_actor, &query(100), &signer()?)
            .await
            .is_err_and(|e| e.status == StatusCode::NOT_FOUND),
        "SYSTEM exception supplies no tenant membership"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL and signed cursor scope authorization"]
async fn tenant_audit_cursors_cannot_cross_actor_tenant_action_or_limit() -> anyhow::Result<()> {
    let _guard = support::serial().await;
    let f = manager().await?;
    seed(&f, 3).await?;
    let first = f
        .database
        .list_tenant_audit_records(&f.actor, &query(1), &signer()?)
        .await
        .map_err(api_failure)?;
    let cursor = first.next_cursor.context("continuation")?;
    let q = TenantAuditQuery {
        limit: Some(1),
        cursor: Some(cursor.clone()),
    };
    let other = manager().await?;
    grant(&f, other.actor.principal_id, None, READ_ACTION).await?;
    for actor in [
        Actor {
            principal_id: other.actor.principal_id,
            ..f.actor.clone()
        },
        other.actor.clone(),
    ] {
        ensure!(
            f.database
                .list_tenant_audit_records(&actor, &q, &signer()?)
                .await
                .is_err_and(|e| e.code == "INVALID_CURSOR"),
            "cursor binds actor and tenant"
        );
    }
    for q in [
        TenantAuditQuery {
            limit: Some(2),
            cursor: Some(cursor.clone()),
        },
        TenantAuditQuery {
            limit: Some(1),
            cursor: Some(format!("{cursor}x")),
        },
        TenantAuditQuery {
            limit: Some(1),
            cursor: Some("x".repeat(2049)),
        },
    ] {
        ensure!(
            f.database
                .list_tenant_audit_records(&f.actor, &q, &signer()?)
                .await
                .is_err_and(|e| e.code == "INVALID_CURSOR"),
            "page size, signature, and size bound"
        );
    }
    for limit in [0, 101] {
        ensure!(
            f.database
                .list_tenant_audit_records(&f.actor, &query(limit), &signer()?)
                .await
                .is_err_and(|e| e.code == "INVALID_ARGUMENT"),
            "bounded page size"
        );
    }
    for index in 0..2 {
        f.database
            .register_service_client(
                &f.actor,
                &RegisterServiceClient {
                    issuer: "https://issuer.example.test".into(),
                    subject: Uuid::new_v4().to_string(),
                    client_id: "cursor-client".into(),
                    display_name: format!("Cursor client {index}"),
                },
                "https://issuer.example.test",
                &format!("cursor-register-{index}"),
            )
            .await
            .map_err(api_failure)?;
    }
    let first = f
        .database
        .list_service_clients(&f.actor, Some(1), None, &signer()?)
        .await
        .map_err(api_failure)?;
    let wrong_kind = TenantAuditQuery {
        limit: Some(1),
        cursor: first.next_cursor,
    };
    ensure!(
        f.database
            .list_tenant_audit_records(&f.actor, &wrong_kind, &signer()?)
            .await
            .is_err_and(|e| e.code == "INVALID_CURSOR"),
        "account cursor cannot read tenant audit"
    );
    ensure!(
        f.database
            .list_service_clients(&f.actor, Some(1), Some(cursor.clone()), &signer()?)
            .await
            .is_err_and(|e| e.code == "INVALID_CURSOR"),
        "tenant audit cursor cannot read accounts"
    );
    grant(
        &f,
        f.actor.principal_id,
        Some(f.request.project_id),
        "audit:read",
    )
    .await?;
    let project = HistoryQuery {
        project_id: f.request.project_id,
        instance_id: None,
        limit: Some(1),
        cursor: Some(cursor),
    };
    ensure!(
        f.database
            .list_audit_records(&f.actor, &project, &signer()?)
            .await
            .is_err_and(|e| e.code == "INVALID_CURSOR"),
        "tenant cursor cannot read project history"
    );
    Ok(())
}

async fn wait_for_blocker(f: &Fixture, pid: i32) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
            )
            .bind(pid)
            .fetch_one(&f.owner)
            .await?;
            if waiting {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    })
    .await
    .context("real tenant audit query must wait on table lock")??;
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL locks, identity revocation and grant/token expiry"]
async fn tenant_audit_rechecks_authority_after_real_database_wait() -> anyhow::Result<()> {
    let _guard = support::serial().await;
    let f = manager().await?;
    seed(&f, 3).await?;
    for case in [
        "GRANT_REVOKED",
        "IDENTITY_DISABLED",
        "TOKEN_EXPIRED",
        "GRANT_EXPIRED",
    ] {
        let mut blocker = f.owner_transaction().await?;
        sqlx::query("LOCK TABLE audit_events IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *blocker)
            .await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        let mut actor = http_actor(&f);
        let deadline = Utc::now().timestamp() + 2;
        if case == "TOKEN_EXPIRED" {
            actor.authorization.as_mut().context("identity")?.expires_at = deadline;
        }
        if case == "GRANT_EXPIRED" {
            let mut tx = f.owner_transaction().await?;
            sqlx::query("UPDATE grants SET expires_at=to_timestamp($3::bigint) WHERE tenant_id=$1 AND principal_id=$2 AND action='tenant_audit:read'").bind(f.actor.tenant_id).bind(f.actor.principal_id).bind(deadline).execute(&mut *tx).await?;
            tx.commit().await?;
        }
        let db = f.database.clone();
        let signer = signer()?;
        let job = tokio::spawn(async move {
            db.list_tenant_audit_records(&actor, &query(2), &signer)
                .await
        });
        wait_for_blocker(&f, pid).await?;
        match case {
            "GRANT_REVOKED" | "IDENTITY_DISABLED" => {
                let sql = if case == "GRANT_REVOKED" {
                    "UPDATE grants SET enabled=false,revoked_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND action='tenant_audit:read'"
                } else {
                    "UPDATE principal_identities SET enabled=false WHERE principal_id=$2 AND $1::uuid IS NOT NULL"
                };
                let mut tx = f.owner_transaction().await?;
                sqlx::query(sql)
                    .bind(f.actor.tenant_id)
                    .bind(f.actor.principal_id)
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
            }
            _ => {
                tokio::time::timeout(Duration::from_millis(2400), async {
                    loop {
                        let expired: bool = sqlx::query_scalar(
                            "SELECT clock_timestamp()>=to_timestamp($1::bigint)",
                        )
                        .bind(deadline)
                        .fetch_one(&f.owner)
                        .await?;
                        if expired {
                            return Ok::<_, anyhow::Error>(());
                        }
                        tokio::time::sleep(Duration::from_millis(15)).await;
                    }
                })
                .await
                .context("authority expiry before real lock timeout")??;
            }
        }
        blocker.commit().await?;
        let error = job
            .await?
            .err()
            .context("waiting read must deny expired/revoked authority")?;
        let status = if case.starts_with("GRANT") {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::UNAUTHORIZED
        };
        ensure!(
            error.status == status,
            "post-wait authority status for {case}: {} {}",
            error.status,
            error.code
        );
        let mut tx = f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=true,revoked_at=NULL,expires_at=NULL WHERE tenant_id=$1 AND principal_id=$2 AND action='tenant_audit:read'").bind(f.actor.tenant_id).bind(f.actor.principal_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE principal_identities SET enabled=true WHERE principal_id=$1")
            .bind(f.actor.principal_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    Ok(())
}

async fn node_sdk(origin: &str, f: &Fixture, token: &str, phase: &str) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    ensure!(
        root.join("sdk/typescript/dist/index.js").is_file(),
        "build actual TypeScript SDK before integration"
    );
    let mut child = tokio::process::Command::new("node")
        .arg(root.join("tests/fixtures/tenant-audit/sdk-http.mjs"))
        .current_dir(root)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child.stdin.take().context("private SDK stdin")?;
    stdin
        .write_all(&serde_json::to_vec(
            &json!({"baseUrl":origin,"tenantId":f.actor.tenant_id,"token":token,"phase":phase}),
        )?)
        .await?;
    stdin.shutdown().await?;
    drop(stdin);
    let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .context("bounded actual SDK timeout")??;
    ensure!(output.status.success(), "SDK_TENANT_AUDIT_HTTP_FAILED");
    ensure!(output.stdout.len() < 1024, "bounded public SDK receipt");
    let receipt: Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        receipt["phase"] == phase
            && receipt["status"] == if phase == "REVOKED" { 404 } else { 200 },
        "actual SDK receipt status"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL, built Node SDK and signed TCP JWT/JWKS HTTP"]
async fn signed_http_and_actual_node_sdk_tenant_audit_contract_is_redacted_and_revocable()
-> anyhow::Result<()> {
    let _guard = support::serial().await;
    let f = manager().await?;
    seed(&f, 3).await?;
    let jwk: Value = serde_json::from_str(include_str!("fixtures/auth/jwk-a.json"))?;
    let kid = jwk["kid"].as_str().context("jwk kid")?.to_owned();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let jwks_addr = listener.local_addr()?;
    let jwks = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/jwks",
                get(move || {
                    let jwk = jwk.clone();
                    async move { axum::Json(json!({"keys":[jwk]})) }
                }),
            ),
        )
        .await
    });
    let app = router(Arc::new(AppState {
        database: f.database.clone(),
        auth: JwtAuthenticator::new(AuthConfig {
            scope_profile: ScopeProfile::ActionScopes,
            issuer: "https://issuer.example.test".into(),
            audience: "sandbox-api".into(),
            jwks_url: format!("http://{jwks_addr}/jwks"),
            required_scopes: vec!["sandbox:access".into()],
            jwks_ttl_seconds: 300,
            clock_skew_seconds: 0,
            allow_loopback_http: true,
            max_token_lifetime_seconds: 300,
        })?,
        cursor_signer: signer()?,
        output_reader: None,
        metrics: None,
        default_ttl_seconds: 300,
        max_ttl_seconds: 86400,
    }));
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("at+jwt".into());
    header.kid = Some(kid);
    let now = Utc::now().timestamp();
    let token = encode(
        &header,
        &json!({"iss":"https://issuer.example.test","sub":f.actor.principal_id.to_string(),"aud":"sandbox-api","client_id":"tenant-audit-fixture","jti":Uuid::new_v4().to_string(),"iat":now,"exp":now+300,"scope":"sandbox:access tenant_audit:read"}),
        &EncodingKey::from_rsa_der(include_bytes!("fixtures/auth/rsa-a.der")),
    )?;
    let request = |path: &str| {
        Request::builder()
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .header("x-tenant-id", f.actor.tenant_id.to_string())
            .body(Body::empty())
    };
    let first = app
        .clone()
        .oneshot(request("/v1/tenant-audit-records?limit=1")?)
        .await?;
    ensure!(
        first.status() == StatusCode::OK && first.headers()["cache-control"] == "no-store",
        "signed route and no-store"
    );
    let first: Value = serde_json::from_slice(&first.into_body().collect().await?.to_bytes())?;
    ensure!(
        first["items"][0]["project_id"].is_null()
            && !first.to_string().contains("PRIVATE_TENANT_AUDIT_MARKER"),
        "HTTP redaction and explicit NULL scope"
    );
    let cursor = first["next_cursor"].as_str().context("HTTP continuation")?;
    for suffix in [
        "project_id=00000000-0000-0000-0000-000000000000",
        "instance_id=00000000-0000-0000-0000-000000000000",
        "action=service_clients:create",
        "limit=101",
        "cursor=malformed",
    ] {
        let response = app
            .clone()
            .oneshot(request(&format!("/v1/tenant-audit-records?{suffix}"))?)
            .await?;
        ensure!(
            response.status() == StatusCode::BAD_REQUEST
                && response.headers()["content-type"] == "application/problem+json",
            "reject unsupported query or invalid continuation"
        );
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let api = tokio::spawn({
        let app = app.clone();
        async move { axum::serve(listener, app).await }
    });
    let origin = format!("http://{addr}");
    let result=async {
        node_sdk(&origin,&f,&token,"AVAILABLE").await?;
        let mut tx=f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='tenant_audit:read'").bind(f.actor.tenant_id).bind(f.actor.principal_id).execute(&mut *tx).await?;
        tx.commit().await?;
        let denied=app.oneshot(request(&format!("/v1/tenant-audit-records?limit=1&cursor={cursor}"))?).await?;
        ensure!(denied.status()==StatusCode::NOT_FOUND,"HTTP old cursor rechecks current grant");
        node_sdk(&origin,&f,&token,"REVOKED").await?;
        Ok::<_,anyhow::Error>(())
    }.await;
    api.abort();
    jwks.abort();
    result
}
