#![allow(clippy::expect_used)]
#[allow(dead_code)]
mod support;
use anyhow::{Context, ensure};
use sandbox_platform::{
    db::Database,
    diagnostics::{CreateDiagnosis, EvidenceScope},
    engine::{Claim, OperationEngine},
};
use sqlx::Row;
use support::{Fixture, api_failure};
use uuid::Uuid;

async fn setup(limit: i64) -> anyhow::Result<(Fixture, OperationEngine)> {
    let f = Fixture::new(limit).await?;
    sqlx::raw_sql(include_str!("../scripts/sql/worker-role.sql"))
        .execute(&f.owner)
        .await?;
    let mut tx = f.owner_transaction().await?;
    for action in ["diagnoses:create", "diagnoses:read"] {
        sqlx::query(
            "INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4)",
        )
        .bind(f.actor.tenant_id)
        .bind(f.request.project_id)
        .bind(f.actor.principal_id)
        .bind(action)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    let url =
        std::env::var("TEST_WORKER_DATABASE_URL").context("TEST_WORKER_DATABASE_URL required")?;
    let parsed = url::Url::parse(&url)?;
    ensure!(
        parsed.username() == "sandbox_worker" && parsed.path().ends_with("_test"),
        "isolated worker identity required"
    );
    let db = Database::connect(&url, 4).await?;
    db.verify_runtime_role().await?;
    let engine = OperationEngine::new(db, format!("diagnosis-test-{}", Uuid::new_v4()))?;
    Ok((f, engine))
}
async fn claim(f: &Fixture, engine: &OperationEngine, op: Uuid) -> anyhow::Result<Claim> {
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET next_attempt_at=(SELECT COALESCE(min(eligible_at),clock_timestamp())-interval '1 day' FROM operation_dispatch WHERE queue_role='WORKER'),lease_until=CASE WHEN lease_until IS NOT NULL THEN (SELECT COALESCE(min(eligible_at),clock_timestamp())-interval '1 day' FROM operation_dispatch WHERE queue_role='WORKER') ELSE NULL END WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(op).execute(&mut *tx).await?;
    tx.commit().await?;
    let c = engine
        .claim()
        .await
        .map_err(api_failure)?
        .context("claim")?;
    ensure!(
        c.operation_id == op,
        "own diagnosis operation must be claimed"
    );
    Ok(c)
}

#[tokio::test]
#[ignore = "requires real PostgreSQL app/worker/owner identities"]
async fn diagnosis_concurrency_safe_mode_and_existing_activity_are_independent()
-> anyhow::Result<()> {
    let _guard = support::serial().await;
    let (f, engine) = setup(2).await?;
    let instance = f.create("create").await.map_err(api_failure)?.body.resource;
    let before = f
        .database
        .get_instance(&f.actor, instance.id)
        .await
        .map_err(api_failure)?;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..12 {
        let db = f.database.clone();
        let actor = f.actor.clone();
        tasks.spawn(async move {
            db.create_diagnosis(&actor, instance.id, &CreateDiagnosis::default(), "same")
                .await
        });
    }
    let mut id = None;
    let mut op = None;
    while let Some(r) = tasks.join_next().await {
        let accepted = r?.map_err(api_failure)?;
        ensure!(
            id.is_none_or(|id| id == accepted.body.resource.id),
            "one diagnosis"
        );
        id = Some(accepted.body.resource.id);
        op = Some(accepted.body.operation.id);
    }
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE platform_configuration SET safe_mode=true WHERE singleton")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let result = async {
        let c = claim(&f, &engine, op.context("operation")?).await?;
        engine
            .database
            .reconcile_diagnosis(&engine, &c)
            .await
            .map_err(api_failure)?;
        let report = f
            .database
            .get_diagnosis(&f.actor, id.context("diagnosis")?)
            .await
            .map_err(api_failure)?;
        ensure!(
            report.status == "COMPLETE",
            "report must complete in safe mode"
        );
        let report = report.report.context("report")?;
        ensure!(
            report.checks.iter().any(|c| c.code == "PLATFORM_SAFE_MODE"),
            "safe-mode evidence"
        );
        ensure!(
            report
                .checks
                .iter()
                .any(|c| c.evidence_scope == EvidenceScope::Executions
                    && c.code == "EVIDENCE_REDACTED"),
            "execution permission withheld"
        );
        let after = f
            .database
            .get_instance(&f.actor, instance.id)
            .await
            .map_err(api_failure)?;
        ensure!(
            before.spec_version == after.spec_version
                && before.active_operation_id == after.active_operation_id
                && before.slot_held == after.slot_held,
            "diagnosis cannot mutate instance slots or lifecycle"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    sqlx::query("UPDATE platform_configuration SET safe_mode=false WHERE singleton")
        .execute(&f.owner)
        .await?;
    result
}

#[tokio::test]
#[ignore = "requires real PostgreSQL app/worker/owner identities"]
async fn diagnosis_authorization_replay_rls_and_publication_revocation() -> anyhow::Result<()> {
    let _guard = support::serial().await;
    let (f, engine) = setup(2).await?;
    let instance = f.create("create").await.map_err(api_failure)?.body.resource;
    let d = f
        .database
        .create_diagnosis(&f.actor, instance.id, &CreateDiagnosis::default(), "key")
        .await
        .map_err(api_failure)?
        .body;
    let mismatch = f
        .database
        .create_diagnosis(
            &f.actor,
            instance.id,
            &CreateDiagnosis {
                include_operations: false,
                include_executions: true,
            },
            "key",
        )
        .await
        .err()
        .context("different body rejected")?;
    ensure!(
        mismatch.code == "IDEMPOTENCY_CONFLICT",
        "same key different options"
    );
    let other = Fixture::new(1).await?;
    ensure!(
        f.database
            .get_diagnosis(&other.actor, d.resource.id)
            .await
            .err()
            .context("cross tenant")?
            .status
            .as_u16()
            == 404,
        "cross tenant hidden"
    );
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='diagnoses:create'").bind(f.actor.tenant_id).bind(f.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    ensure!(
        f.database
            .create_diagnosis(&f.actor, instance.id, &CreateDiagnosis::default(), "key")
            .await
            .err()
            .context("replay revoked")?
            .status
            .as_u16()
            == 404,
        "replay reauthorizes"
    );
    let c = claim(&f, &engine, d.operation.id).await?;
    engine
        .database
        .reconcile_diagnosis(&engine, &c)
        .await
        .map_err(api_failure)?;
    let failed = f
        .database
        .get_diagnosis(&f.actor, d.resource.id)
        .await
        .map_err(api_failure)?;
    ensure!(
        failed.failure_code.as_deref() == Some("AUTHORITY_REVOKED") && failed.report.is_none(),
        "revoked actor cannot publish snapshot"
    );
    let mut tx = f
        .database
        .begin(f.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    ensure!(
        sqlx::query("UPDATE diagnoses SET report='{}' WHERE id=$1")
            .bind(d.resource.id)
            .execute(&mut *tx)
            .await
            .is_err(),
        "app cannot forge reports"
    );
    tx.rollback().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL app/worker/owner identities"]
async fn diagnosis_worker_reclaim_fences_stale_publication_and_redacts_later_reader()
-> anyhow::Result<()> {
    let _guard = support::serial().await;
    let (f, engine) = setup(2).await?;
    let instance = f.create("create").await.map_err(api_failure)?.body.resource;
    let d = f
        .database
        .create_diagnosis(&f.actor, instance.id, &CreateDiagnosis::default(), "key")
        .await
        .map_err(api_failure)?
        .body;
    let stale = claim(&f, &engine, d.operation.id).await?;
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(d.operation.id).execute(&mut *tx).await?;
    tx.commit().await?;
    let current = claim(&f, &engine, d.operation.id).await?;
    ensure!(current.lease_token > stale.lease_token, "reclaimed token");
    ensure!(
        engine
            .database
            .reconcile_diagnosis(&engine, &stale)
            .await
            .err()
            .context("stale")?
            .code
            == "WORKER_LEASE_LOST",
        "stale worker cannot publish"
    );
    engine
        .database
        .reconcile_diagnosis(&engine, &current)
        .await
        .map_err(api_failure)?;
    ensure!(
        engine
            .database
            .reconcile_diagnosis(&engine, &current)
            .await
            .is_err(),
        "completed report cannot commit twice"
    );
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='operations:read'").bind(f.actor.tenant_id).bind(f.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let view = f
        .database
        .get_diagnosis(&f.actor, d.resource.id)
        .await
        .map_err(api_failure)?
        .report
        .context("report")?;
    ensure!(
        view.checks
            .iter()
            .filter(|c| c.evidence_scope == EvidenceScope::Operations)
            .all(|c| c.code == "EVIDENCE_REDACTED" && c.evidence.is_empty()),
        "reports reauthorize optional evidence at read"
    );
    let mut tx = f.owner_transaction().await?;
    let events:i64=sqlx::query_scalar("SELECT count(*) FROM domain_events WHERE tenant_id=$1 AND aggregate_id=$2 AND event_type='diagnoses.completed'").bind(f.actor.tenant_id).bind(d.resource.id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    ensure!(events == 1, "one completion event");
    Ok(())
}

async fn seed(
    f: &Fixture,
    instance: Uuid,
    age_seconds: i64,
    completed: bool,
) -> anyhow::Result<(Uuid, Uuid)> {
    let mut tx = f.owner_transaction().await?;
    let row=sqlx::query("SELECT workspace_id,runtime_generation,launch_id,c.cluster_epoch FROM instances CROSS JOIN platform_configuration c WHERE tenant_id=$1 AND id=$2 AND singleton").bind(f.actor.tenant_id).bind(instance).fetch_one(&mut *tx).await?;
    let id = Uuid::new_v4();
    let op = Uuid::new_v4();
    let now: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT clock_timestamp()-make_interval(secs=>$1::double precision)")
            .bind(age_seconds as f64)
            .fetch_one(&mut *tx)
            .await?;
    let deadline = now + chrono::Duration::seconds(120);
    sandbox_platform::db::insert_operation(
        &mut tx,
        &f.actor,
        op,
        f.request.project_id,
        instance,
        row.try_get("workspace_id")?,
        "DIAGNOSE",
        &serde_json::json!({"diagnosis_id":id}),
        deadline,
    )
    .await
    .map_err(api_failure)?;
    sqlx::query("INSERT INTO diagnoses(id,tenant_id,project_id,instance_id,workspace_id,operation_id,actor_principal_id,requested_generation,requested_launch_id,cluster_epoch,ruleset_version,include_operations,include_executions,created_at,deadline,retention_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'control-plane/v1',false,false,$11,$12,$13)").bind(id).bind(f.actor.tenant_id).bind(f.request.project_id).bind(instance).bind(row.try_get::<Uuid,_>("workspace_id")?).bind(op).bind(f.actor.principal_id).bind(row.try_get::<i64,_>("runtime_generation")?).bind(row.try_get::<Uuid,_>("launch_id")?).bind(row.try_get::<Uuid,_>("cluster_epoch")?).bind(now).bind(deadline).bind(now+chrono::Duration::days(30)).execute(&mut *tx).await?;
    if completed {
        sqlx::query("UPDATE diagnoses SET status='COMPLETE',snapshot_at=$3,completed_at=$3,report=$4 WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(id).bind(now+chrono::Duration::seconds(1)).bind(serde_json::json!({"overall":"UNKNOWN","checks":[]})).execute(&mut *tx).await?;
        sqlx::query("UPDATE operations SET status='SUCCEEDED',completed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(op).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok((id, op))
}

#[tokio::test]
#[ignore = "requires real PostgreSQL app/worker/owner identities"]
async fn diagnosis_deadline_maintenance_retention_and_immutable_report() -> anyhow::Result<()> {
    let _guard = support::serial().await;
    let (f, engine) = setup(3).await?;
    let instance = f.create("create").await.map_err(api_failure)?.body.resource;
    let (expired, op) = seed(&f, instance.id, 121, false).await?;
    // Admission cleans overdue pending work without needing a running worker.
    let next = f
        .database
        .create_diagnosis(
            &f.actor,
            instance.id,
            &CreateDiagnosis::default(),
            "after-expiry",
        )
        .await
        .map_err(api_failure)?
        .body;
    let failed = f
        .database
        .get_diagnosis(&f.actor, expired)
        .await
        .map_err(api_failure)?;
    ensure!(
        failed.failure_code.as_deref() == Some("DEADLINE_EXCEEDED"),
        "deadline releases pending admission slot"
    );
    ensure!(
        f.database
            .get_operation(&f.actor, op)
            .await
            .map_err(api_failure)?
            .status
            == "FAILED",
        "operation fails atomically"
    );
    let c = claim(&f, &engine, next.operation.id).await?;
    engine
        .database
        .reconcile_diagnosis(&engine, &c)
        .await
        .map_err(api_failure)?;
    let (retained, _) = seed(&f, instance.id, 31 * 86400, true).await?;
    ensure!(
        f.database
            .get_diagnosis(&f.actor, retained)
            .await
            .map_err(api_failure)?
            .report
            .is_none(),
        "public retention applies before cleanup"
    );
    engine
        .database
        .maintain_diagnoses()
        .await
        .map_err(api_failure)?;
    let view = f
        .database
        .get_diagnosis(&f.actor, retained)
        .await
        .map_err(api_failure)?;
    ensure!(
        view.status == "EXPIRED" && view.report.is_none(),
        "payload erased, identity retained"
    );
    let mut tx = f.owner_transaction().await?;
    ensure!(
        sqlx::query(
            "UPDATE diagnoses SET status='COMPLETE',report='{}' WHERE tenant_id=$1 AND id=$2"
        )
        .bind(f.actor.tenant_id)
        .bind(retained)
        .execute(&mut *tx)
        .await
        .is_err(),
        "expired report never revived"
    );
    tx.rollback().await?;
    let mut tx = f.owner_transaction().await?;
    let force: bool = sqlx::query_scalar(
        "SELECT relforcerowsecurity FROM pg_class WHERE oid='diagnoses'::regclass",
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    ensure!(force, "FORCE RLS");
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL app/worker/owner identities"]
async fn diagnosis_concurrent_quota_and_deferred_operation_binding() -> anyhow::Result<()> {
    let _guard = support::serial().await;
    let (f, _) = setup(40).await?;
    let mut instances = Vec::new();
    for n in 0..33 {
        instances.push(
            f.create(&format!("create-{n}"))
                .await
                .map_err(api_failure)?
                .body
                .resource
                .id,
        );
    }
    let mut tasks = tokio::task::JoinSet::new();
    for instance in &instances {
        let db = f.database.clone();
        let actor = f.actor.clone();
        let id = *instance;
        tasks.spawn(async move {
            db.create_diagnosis(&actor, id, &CreateDiagnosis::default(), "quota")
                .await
        });
    }
    let (mut accepted, mut rejected) = (0, 0);
    while let Some(r) = tasks.join_next().await {
        match r? {
            Ok(_) => accepted += 1,
            Err(e) if e.code == "DIAGNOSIS_QUOTA_EXCEEDED" => rejected += 1,
            Err(e) => return Err(api_failure(e)),
        }
    }
    ensure!(
        accepted == 32 && rejected == 1,
        "concurrent admission must not oversell pending slots"
    );
    let mut tx = f.owner_transaction().await?;
    let workspace: Uuid =
        sqlx::query_scalar("SELECT workspace_id FROM instances WHERE tenant_id=$1 AND id=$2")
            .bind(f.actor.tenant_id)
            .bind(instances[0])
            .fetch_one(&mut *tx)
            .await?;
    sandbox_platform::db::insert_operation(
        &mut tx,
        &f.actor,
        Uuid::new_v4(),
        f.request.project_id,
        instances[0],
        workspace,
        "DIAGNOSE",
        &serde_json::json!({}),
        chrono::Utc::now() + chrono::Duration::seconds(120),
    )
    .await
    .map_err(api_failure)?;
    ensure!(
        tx.commit().await.is_err(),
        "orphan diagnosis operation must fail at commit"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL and real loopback HTTP/JWT signature verification"]
async fn diagnostic_http_receipt_replay_redaction_and_revocation() -> anyhow::Result<()> {
    use axum::{Json, Router, routing::get};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use sandbox_platform::{
        api::{AppState, router},
        auth::{AuthConfig, JwtAuthenticator},
        diagnostics::{Diagnosis, DiagnosisAccepted},
        history::CursorSigner,
    };
    use serde_json::{Value, json};
    use std::{sync::Arc, time::Duration};
    let _guard = support::serial().await;
    let (f, engine) = setup(2).await?;
    let instance = f.create("create").await.map_err(api_failure)?.body.resource;
    let delegated_principal = Uuid::new_v4();
    let mut tx = f.owner_transaction().await?;
    sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,'grants:write')").bind(f.actor.tenant_id).bind(f.request.project_id).bind(f.actor.principal_id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO principals(id,kind,display_name) VALUES($1,'SERVICE','Diagnostic delegate fixture')").bind(delegated_principal).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO tenant_principals(tenant_id,principal_id,display_name) VALUES($1,$2,'Diagnostic delegate fixture')").bind(f.actor.tenant_id).bind(delegated_principal).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO principal_identities(principal_id,issuer,subject,service_client_id,service_binding_generation) VALUES($1,'https://issuer.example.test',$2,'diagnosis-delegated-test',1)").bind(delegated_principal).bind(delegated_principal.to_string()).execute(&mut *tx).await?;
    tx.commit().await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let jwks_address = listener.local_addr()?;
    let jwks_server = tokio::spawn(async move {
        axum::serve(listener,Router::new().route("/jwks",get(||async {Json(json!({"keys":[serde_json::from_str::<Value>(include_str!("fixtures/auth/jwk-a.json")).expect("public test fixture")]}))}))).await
    });
    f.bind_client_id("diagnosis-http-test").await?;
    let app = router(Arc::new(AppState {
        database: f.database.clone(),
        auth: JwtAuthenticator::new(AuthConfig {
            scope_profile: Default::default(),
            issuer: "https://issuer.example.test".into(),
            audience: "sandbox-api".into(),
            jwks_url: format!("http://{jwks_address}/jwks"),
            required_scopes: vec!["sandbox:access".into()],
            jwks_ttl_seconds: 300,
            clock_skew_seconds: 0,
            allow_loopback_http: true,
            max_token_lifetime_seconds: 300,
        })?,
        cursor_signer: CursorSigner::from_json(include_str!("fixtures/history/cursor-keys.json"))?,
        output_reader: None,
        metrics: None,
        default_ttl_seconds: 300,
        max_ttl_seconds: 86400,
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let api_server = tokio::spawn(async move { axum::serve(listener, app).await });
    let result=async {
 let now=chrono::Utc::now().timestamp();let mut header=Header::new(Algorithm::RS256);header.typ=Some("at+jwt".into());header.kid=Some("key-a".into());
 let token=encode(&header,&json!({"iss":"https://issuer.example.test","sub":f.actor.principal_id.to_string(),"aud":"sandbox-api","client_id":"diagnosis-http-test","iat":now,"exp":now+300,"jti":Uuid::new_v4().to_string(),"scope":"sandbox:access"}),&EncodingKey::from_rsa_der(include_bytes!("fixtures/auth/rsa-a.der")))?;
 let client=reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(10)).build()?;
 let grant_endpoint=format!("http://{address}/v1/projects/{}/grants",f.request.project_id);
 let mut created_grant=None;
 for action in ["instances:read","diagnoses:create","diagnoses:read"] {
    let response=client.post(&grant_endpoint).bearer_auth(&token).header("x-tenant-id",f.actor.tenant_id.to_string()).header("idempotency-key",format!("grant-{action}")).json(&json!({"principal_id":delegated_principal,"action":action,"expires_at":null})).send().await?;
    ensure!(response.status()==reqwest::StatusCode::CREATED,"diagnosis action must be delegable through the real grant API");
    let receipt:Value=response.json().await?;if action=="diagnoses:create" {created_grant=Some(receipt["resource"].clone());}
 }
 let grant=created_grant.context("created diagnostic grant")?;
 let grant_id=grant["id"].as_str().context("grant id")?;
 let delegated_token=encode(&header,&json!({"iss":"https://issuer.example.test","sub":delegated_principal.to_string(),"aud":"sandbox-api","client_id":"diagnosis-delegated-test","iat":now,"exp":now+300,"jti":Uuid::new_v4().to_string(),"scope":"sandbox:access"}),&EncodingKey::from_rsa_der(include_bytes!("fixtures/auth/rsa-a.der")))?;
 let endpoint=format!("http://{address}/v1/instances/{}/diagnoses",instance.id);
 let post=|key:&str,value:Value|client.post(&endpoint).bearer_auth(&token).header("x-tenant-id",f.actor.tenant_id.to_string()).header("idempotency-key",key).json(&value);
 let response=post("diagnostic-http-key",json!({})).send().await?;
 ensure!(response.status()==reqwest::StatusCode::ACCEPTED,"HTTP POST: {}",response.status());
 ensure!(response.headers()["cache-control"]=="no-store","private response");
 let location=response.headers()["location"].to_str()?.to_owned();let content_location=response.headers()["content-location"].to_str()?.to_owned();
 let receipt:DiagnosisAccepted=response.json().await?;
 ensure!(location==format!("/v1/operations/{}",receipt.operation.id)&&content_location==format!("/v1/diagnoses/{}",receipt.resource.id),"durable report and operation URLs");
 let repeated:DiagnosisAccepted=post("diagnostic-http-key",json!({})).send().await?.json().await?;ensure!(receipt.resource.id==repeated.resource.id,"HTTP replay");
 ensure!(post("diagnostic-http-key",json!({"include_operations":false})).send().await?.status()==reqwest::StatusCode::CONFLICT,"different semantics rejected");
 let rejected=post("diagnostic-http-unknown",json!({"command":"secret-command-must-not-run"})).send().await?;
 ensure!(rejected.status()==reqwest::StatusCode::UNPROCESSABLE_ENTITY,"unknown request fields rejected");
 ensure!(!rejected.text().await?.contains("secret-command-must-not-run"),"rejected input never echoed");
 let c=claim(&f,&engine,receipt.operation.id).await?;engine.database.reconcile_diagnosis(&engine,&c).await.map_err(api_failure)?;
 let get=|tenant:Uuid|client.get(format!("http://{address}{content_location}")).bearer_auth(&token).header("x-tenant-id",tenant.to_string());
 let report:Diagnosis=get(f.actor.tenant_id).send().await?.json().await?;
 ensure!(report.status=="COMPLETE"&&report.report.context("report")?.checks.iter().any(|c|c.evidence_scope==EvidenceScope::Executions&&c.code=="EVIDENCE_REDACTED"),"HTTP completed sanitized report");
 let delegated_get=client.get(format!("http://{address}{content_location}")).bearer_auth(&delegated_token).header("x-tenant-id",f.actor.tenant_id.to_string()).send().await?;
 ensure!(delegated_get.status()==reqwest::StatusCode::OK,"delegated diagnosis read works");
 let delegated_post=||client.post(&endpoint).bearer_auth(&delegated_token).header("x-tenant-id",f.actor.tenant_id.to_string()).header("idempotency-key","delegated-diagnosis").json(&json!({}));
 let second:DiagnosisAccepted=delegated_post().send().await?.error_for_status()?.json().await?;
 let patch_grant=|version:i64,enabled:bool|client.patch(format!("{grant_endpoint}/{grant_id}")).bearer_auth(&token).header("x-tenant-id",f.actor.tenant_id.to_string()).header("idempotency-key",format!("toggle-diagnostic-{enabled}")).header("if-match",format!("\"{version}\"")).json(&json!({"enabled":enabled,"expires_at":null}));
 let disabled:Value=patch_grant(grant["version"].as_i64().context("version")?,false).send().await?.error_for_status()?.json().await?;
 ensure!(delegated_post().send().await?.status()==reqwest::StatusCode::NOT_FOUND,"grant API disable revokes replay");
 patch_grant(disabled["resource"]["version"].as_i64().context("disabled version")?,true).send().await?.error_for_status()?;
 let enabled:DiagnosisAccepted=delegated_post().send().await?.error_for_status()?.json().await?;
 ensure!(enabled.resource.id==second.resource.id,"reenabled grant replays original durable task");
 ensure!(get(Uuid::new_v4()).send().await?.status()==reqwest::StatusCode::NOT_FOUND,"cross-tenant report hidden");
 let mut tx=f.owner_transaction().await?;sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action IN('diagnoses:read','diagnoses:create')").bind(f.actor.tenant_id).bind(f.actor.principal_id).execute(&mut *tx).await?;tx.commit().await?;
 ensure!(get(f.actor.tenant_id).send().await?.status()==reqwest::StatusCode::NOT_FOUND,"GET reauthorizes");
 ensure!(post("diagnostic-http-key",json!({})).send().await?.status()==reqwest::StatusCode::NOT_FOUND,"HTTP replay reauthorizes");
 Ok::<_,anyhow::Error>(()) }.await;
    api_server.abort();
    jwks_server.abort();
    result
}

#[tokio::test]
#[ignore = "requires real PostgreSQL and bounded concurrent row-lock wait"]
async fn diagnosis_publication_head_wait_cannot_cross_task_deadline() -> anyhow::Result<()> {
    let _guard = support::serial().await;
    let (f, engine) = setup(2).await?;
    let instance = f.create("create").await.map_err(api_failure)?.body.resource;
    let (id, op) = seed(&f, instance.id, 118, false).await?;
    let c = claim(&f, &engine, op).await?;
    // Hold the actual project event-stream head. Publication must wait here after
    // computing its snapshot, then recheck the deadline before committing.
    let mut head = f.owner_transaction().await?;
    sqlx::query("SELECT last_sequence FROM event_stream_heads WHERE tenant_id=$1 AND project_id=$2 FOR UPDATE").bind(f.actor.tenant_id).bind(f.request.project_id).fetch_one(&mut *head).await?;
    let task_engine = engine.clone();
    let task_claim = c.clone();
    let task = tokio::spawn(async move {
        task_engine
            .database
            .reconcile_diagnosis(&task_engine, &task_claim)
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(2300)).await;
    head.commit().await?;
    let failed = task
        .await?
        .err()
        .context("publication must fail after deadline")?;
    ensure!(
        failed.code == "DIAGNOSIS_TARGET_CHANGED",
        "final publication fence must reject stale evidence"
    );
    engine
        .database
        .maintain_diagnoses()
        .await
        .map_err(api_failure)?;
    let view = f
        .database
        .get_diagnosis(&f.actor, id)
        .await
        .map_err(api_failure)?;
    ensure!(
        view.failure_code.as_deref() == Some("DEADLINE_EXCEEDED") && view.report.is_none(),
        "expired snapshot never becomes visible"
    );
    let mut tx = f.owner_transaction().await?;
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM domain_events WHERE tenant_id=$1 AND aggregate_id=$2 AND event_type='diagnoses.completed'").bind(f.actor.tenant_id).bind(id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    ensure!(count == 0, "completion event rolls back with report");
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; owner seeds explicit unknown execution evidence only"]
async fn diagnosis_reports_unknown_execution_without_mutating_or_exposing_revoked_evidence()
-> anyhow::Result<()> {
    let _guard = support::serial().await;
    let (f, engine) = setup(2).await?;
    let instance = f.create("create").await.map_err(api_failure)?.body.resource;
    f.seed_observed_state(instance.id, "RUNNING").await?;
    let mut tx = f.owner_transaction().await?;
    sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,'executions:read')").bind(f.actor.tenant_id).bind(f.request.project_id).bind(f.actor.principal_id).execute(&mut *tx).await?;
    let row=sqlx::query("SELECT launch_id,cluster_epoch,runtime_generation FROM instances WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(instance.id).fetch_one(&mut *tx).await?;
    let execution = Uuid::new_v4();
    let op = Uuid::new_v4();
    let deadline = chrono::Utc::now() + chrono::Duration::seconds(60);
    sandbox_platform::db::insert_operation(
        &mut tx,
        &f.actor,
        op,
        f.request.project_id,
        instance.id,
        instance.workspace_id,
        "EXECUTE",
        &serde_json::json!({"private_argument":"must-not-appear-in-report"}),
        deadline,
    )
    .await
    .map_err(api_failure)?;
    sqlx::query("INSERT INTO executions(id,tenant_id,project_id,instance_id,operation_id,runtime_generation,launch_id,pod_uid,cluster_epoch,status,deadline,timeout_seconds,termination_status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'QUEUED',$10,60,'NOT_REQUESTED')").bind(execution).bind(f.actor.tenant_id).bind(f.request.project_id).bind(instance.id).bind(op).bind(row.try_get::<i64,_>("runtime_generation")?).bind(row.try_get::<Uuid,_>("launch_id")?).bind(Uuid::new_v4()).bind(row.try_get::<Uuid,_>("cluster_epoch")?).bind(deadline).execute(&mut *tx).await?;
    sqlx::query("UPDATE executions SET status='DISPATCHING',dispatch_attempt_id=$3,dispatch_attempted_at=clock_timestamp(),dispatch_lease_token=1 WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(execution).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    sqlx::query("UPDATE executions SET status='OUTCOME_UNKNOWN',termination_status='UNKNOWN' WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(execution).execute(&mut *tx).await?;
    sqlx::query("UPDATE instances SET slot_held=true,activity_kind='EXECUTION',activity_id=$3,activity_generation=runtime_generation WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(instance.id).bind(execution).execute(&mut *tx).await?;
    tx.commit().await?;
    let d = f
        .database
        .create_diagnosis(
            &f.actor,
            instance.id,
            &CreateDiagnosis::default(),
            "diagnose-unknown",
        )
        .await
        .map_err(api_failure)?
        .body;
    let c = claim(&f, &engine, d.operation.id).await?;
    engine
        .database
        .reconcile_diagnosis(&engine, &c)
        .await
        .map_err(api_failure)?;
    let report = f
        .database
        .get_diagnosis(&f.actor, d.resource.id)
        .await
        .map_err(api_failure)?;
    let encoded = serde_json::to_string(&report)?;
    ensure!(
        !encoded.contains("must-not-appear-in-report"),
        "command payload never enters report"
    );
    let report = report.report.context("report")?;
    ensure!(
        report
            .checks
            .iter()
            .any(|c| c.code == "EXECUTION_OUTCOME_UNKNOWN_SLOT_HELD"
                && c.status == sandbox_platform::diagnostics::DiagnosticStatus::Critical),
        "unknown is critical before execution deadline"
    );
    ensure!(
        f.database
            .get_instance(&f.actor, instance.id)
            .await
            .map_err(api_failure)?
            .slot_held,
        "diagnosis does not release activity"
    );
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='executions:read'").bind(f.actor.tenant_id).bind(f.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let report = f
        .database
        .get_diagnosis(&f.actor, d.resource.id)
        .await
        .map_err(api_failure)?
        .report
        .context("redacted report")?;
    ensure!(
        report
            .checks
            .iter()
            .filter(|c| c.evidence_scope == EvidenceScope::Executions)
            .all(|c| c.code == "EVIDENCE_REDACTED" && c.evidence.is_empty()),
        "historical execution evidence redacted after revoke"
    );
    Ok(())
}
