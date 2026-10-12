//! Signed loopback HTTP drives real PostgreSQL management and real renewal.
use super::*;
use crate::{
    api::AppState,
    auth::{AuthConfig, JwtAuthenticator},
    automation::api::AutomationApiRuntime,
};
use axum::{Json, Router, http::StatusCode, routing::get};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

async fn sdk_wait(
    origin: &str,
    tenant: Uuid,
    token: &str,
    project: Uuid,
    run: &str,
    timeout_ms: u32,
) -> anyhow::Result<Value> {
    let mut child = tokio::process::Command::new("node")
        .arg("tests/fixtures/automation/sdk-http.mjs")
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let mut input = child.stdin.take().context("SDK stdin")?;
    input.write_all(&serde_json::to_vec(&json!({"baseUrl":origin,"tenantId":tenant,"token":token,"projectId":project,"runId":run,"timeoutMs":timeout_ms}))?).await?;
    input.shutdown().await?;
    drop(input);
    let result = tokio::time::timeout(std::time::Duration::from_secs(10), child.wait_with_output())
        .await??;
    ensure!(result.status.success(), "real HTTP SDK helper failed");
    Ok(serde_json::from_slice(&result.stdout)?)
}

#[test]
#[ignore = "requires dedicated PostgreSQL automation database and signed loopback HTTP"]
fn signed_microservice_http_receipts_history_and_control_actions_use_real_database()
-> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
    let _serial = test_support_db::serial().await;
    let r = Ready::new().await?;
    let jwks = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let jwks_address = jwks.local_addr()?;
    let runtime = Arc::new(AutomationApiRuntime {
        app: Arc::new(AppState {
            database: r.f.database.clone(),
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
            cursor_signer: signer(),
            output_reader: None,
            metrics: None,
            default_ttl_seconds: 300,
            max_ttl_seconds: 86400,
        }),
    });
    runtime.check_schema().await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let app = crate::api::router_with_automations(
        runtime.app.clone(),
        tokio_util::sync::CancellationToken::new(),
        None,
        None,
        Some(runtime.clone()),
    );
    let jwks_server = tokio::spawn(async move {
        axum::serve(jwks,Router::new().route("/jwks",get(||async{Json(json!({"keys":[serde_json::from_str::<Value>(include_str!("../tests/fixtures/auth/jwk-a.json")).unwrap()]}))}))).await.unwrap();
    });
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let result=async {
        let now=Utc::now().timestamp();
        let mut header=Header::new(Algorithm::RS256);header.typ=Some("at+jwt".into());header.kid=Some("key-a".into());
        let token=encode(&header,&json!({"iss":"https://issuer.example.test","sub":r.f.actor.principal_id.to_string(),"aud":"sandbox-api","client_id":"automation-http-test","jti":Uuid::new_v4().to_string(),"iat":now,"exp":now+300,"scope":"sandbox:access"}),&EncodingKey::from_rsa_der(include_bytes!("../tests/fixtures/auth/rsa-a.der")))?;
        let client=reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(std::time::Duration::from_secs(10)).build()?;
        let origin=format!("http://{address}");
        let mut tx=r.f.owner_transaction().await?;
        sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,'capabilities:read')")
            .bind(r.f.actor.tenant_id).bind(r.f.request.project_id).bind(r.f.actor.principal_id).execute(&mut *tx).await?;
        tx.commit().await?;
        let caps=client.get(format!("{origin}/v1/capabilities?project_id={}",r.f.request.project_id))
            .bearer_auth(&token).header("x-tenant-id",r.f.actor.tenant_id.to_string()).send().await?;
        ensure!(caps.status()==StatusCode::OK);
        let caps:Value=caps.json().await?;
        ensure!(caps["api_features"]["scheduled_tasks"]==true && caps["api_features"]["event_automation"]==true);
        ensure!(caps["api_features"]["automation_notifications"]==true);
        ensure!(caps["api_features"]["backup_restore"]==false && caps["runtime_certification"]=="NOT_ASSERTED");
        ensure!(caps["automation"]["schema_version"]==1);
        ensure!(caps["automation"]["supported_actions"]==json!(["START","STOP","RESTART","DELETE","RENEW","EXECUTE","BACKUP"]));
        ensure!(caps["automation"]["supported_triggers"]==json!(["ONCE","CRON_UTC","EVENT"]));
        ensure!(caps["automation"]["clock"]=="POSTGRESQL" && caps["automation"]["time_zone"]=="UTC");
        ensure!(caps["automation"]["cron"]==json!({"field_count":7,"seconds_field":"0","year_field":"*","day_of_month_and_week":"INTERSECTION"}));
        ensure!(caps["automation"]["limits"]["run_budget"]==json!({"minimum":1,"maximum":10000}));
        ensure!(caps["automation"]["limits"]["minimum_interval_seconds"]==json!({"minimum":60,"maximum":86400}));
        ensure!(caps["automation"]["limits"]["grace_seconds"]==json!({"minimum":1,"maximum":3600}));
        ensure!(caps["automation"]["limits"]["delegation_lifetime_seconds"]==json!({"exclusive_minimum":60,"maximum":31622400}));
        ensure!(caps["automation"]["limits"]["live_policies_per_project"]==100 && caps["automation"]["limits"]["live_policies_per_tenant"]==1000);
        ensure!(caps["automation"]["limits"]["name_bytes_max"]==128 && caps["automation"]["limits"]["cron_expression_bytes_max"]==128 && caps["automation"]["limits"]["event_type_bytes_max"]==128);
        ensure!(caps["automation"]["missed_run_policy"]=="AT_MOST_ONE_WITHIN_GRACE_ELSE_SKIP_SPAN");
        ensure!(caps["automation"]["skipped_runs_consume_budget"]==true && caps["automation"]["known_automated_events_retrigger"]==false);
        ensure!(caps["automation"]["outcome_unknown_policy"]=="RECONCILE_ORIGINAL_ONLY" && caps["automation"]["assurance"]=="API_CONTRACT_ONLY");
        ensure!(client.get(format!("{origin}/v1/capabilities?project_id={}",Uuid::new_v4())).bearer_auth(&token).header("x-tenant-id",r.f.actor.tenant_id.to_string()).send().await?.status()==StatusCode::NOT_FOUND);
        ensure!(client.get(format!("{origin}/v1/capabilities?project_id={}",r.f.request.project_id)).bearer_auth(&token).header("x-tenant-id",Uuid::new_v4().to_string()).send().await?.status()==StatusCode::NOT_FOUND);
        // The compatibility router has no configured automation component.
        // It advertises neither API and cannot accept an automation mutation.
        use http_body_util::BodyExt;
        use tower::ServiceExt;
        let closed=crate::api::router(runtime.app.clone());
        let closed_response=closed.clone().oneshot(axum::http::Request::builder()
            .uri(format!("/v1/capabilities?project_id={}",r.f.request.project_id))
            .header("authorization",format!("Bearer {token}"))
            .header("x-tenant-id",r.f.actor.tenant_id.to_string())
            .body(axum::body::Body::empty())?).await?;
        ensure!(closed_response.status()==StatusCode::OK);
        let closed_caps:Value=serde_json::from_slice(&closed_response.into_body().collect().await?.to_bytes())?;
        ensure!(closed_caps["api_features"]["scheduled_tasks"]==false && closed_caps["api_features"]["event_automation"]==false);
        ensure!(closed_caps["api_features"]["automation_notifications"]==false);
        ensure!(closed_caps.as_object().context("closed capabilities object")?.contains_key("automation") && closed_caps["automation"].is_null());
        let closed_response=closed.oneshot(axum::http::Request::builder().method("POST")
            .uri(format!("/v1/instances/{}/automations",r.instance.id))
            .header("authorization",format!("Bearer {token}"))
            .header("x-tenant-id",r.f.actor.tenant_id.to_string())
            .body(axum::body::Body::empty())?).await?;
        ensure!(closed_response.status()==StatusCode::NOT_FOUND);
        let mut request=r.request();request.trigger=AutomationTrigger::Once{at:Utc::now()+Duration::seconds(2)};
        let body=json!(request);
        let endpoint=format!("{origin}/v1/instances/{}/automations",r.instance.id);
        let post=|url:&str,key:&str,etag:Option<&str>,body:&Value| {
            let mut req=client.post(url).bearer_auth(&token).header("x-tenant-id",r.f.actor.tenant_id.to_string()).header("idempotency-key",key).json(body);
            if let Some(etag)=etag {req=req.header("if-match",etag);}req
        };
        let mut tx=r.f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='automations:write'").bind(r.f.actor.tenant_id).bind(r.f.actor.principal_id).execute(&mut *tx).await?;
        tx.commit().await?;
        ensure!(post(&endpoint,"capabilities-not-a-write-grant",Some("\"1\""),&body).send().await?.status()==StatusCode::NOT_FOUND);
        ensure!(client.get(format!("{origin}/v1/capabilities?project_id={}",r.f.request.project_id)).bearer_auth(&token).header("x-tenant-id",r.f.actor.tenant_id.to_string()).send().await?.json::<Value>().await?["automation"]==caps["automation"],"discovery is independent of the caller's mutation grants");
        let mut tx=r.f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=true WHERE tenant_id=$1 AND principal_id=$2 AND action='automations:write'").bind(r.f.actor.tenant_id).bind(r.f.actor.principal_id).execute(&mut *tx).await?;
        tx.commit().await?;
        // Exercise the advertised creation contract through the signed public
        // HTTP interface, without overriding runtime grants or schema guards.
        for (field, value) in [
            ("run_budget",json!(0)), ("run_budget",json!(10001)),
            ("minimum_interval_seconds",json!(59)), ("minimum_interval_seconds",json!(86401)),
            ("grace_seconds",json!(0)), ("grace_seconds",json!(3601)),
            ("name",json!("x".repeat(129))), ("name",json!("坏".repeat(43))),
            ("delegation_expires_at",json!(Utc::now()+Duration::seconds(60))),
            ("delegation_expires_at",json!(Utc::now()+Duration::days(366)+Duration::minutes(1))),
        ] {
            let mut invalid=body.clone(); invalid[field]=value;
            ensure!(post(&endpoint,&Uuid::new_v4().to_string(),Some("\"1\""),&invalid).send().await?.status()==StatusCode::BAD_REQUEST,"advertised {field} boundary must be enforced");
        }
        let mut bounded=body.clone();
        bounded["name"]=json!("x".repeat(128));
        bounded["run_budget"]=json!(10000);
        bounded["minimum_interval_seconds"]=json!(86400);
        bounded["grace_seconds"]=json!(3600);
        bounded["trigger"]=json!({"kind":"ONCE","at":Utc::now()+Duration::days(1)});
        bounded["delegation_expires_at"]=json!(Utc::now()+Duration::days(366)-Duration::minutes(1));
        let upper=post(&endpoint,"http-upper-contract",Some("\"1\""),&bounded).send().await?;
        ensure!(upper.status()==StatusCode::CREATED,"advertised upper values must be usable with current permanent grants");
        let upper:AutomationReceipt=upper.json().await?;
        ensure!(post(&format!("{origin}/v1/automations/{}/actions/revoke",upper.resource.id),"http-upper-revoke",Some("\"1\""),&json!({})).send().await?.status()==StatusCode::OK);
        ensure!(client.get(format!("{origin}/v1/automations/{}",Uuid::new_v4())).send().await?.status()==StatusCode::UNAUTHORIZED);
        ensure!(post(&endpoint,"missing-ifmatch",None,&body).send().await?.status()==StatusCode::PRECONDITION_REQUIRED);
        ensure!(post(&endpoint,"weak-ifmatch",Some("W/\"1\""),&body).send().await?.status()==StatusCode::BAD_REQUEST);
        ensure!(post(&endpoint,"stale-ifmatch",Some("\"999\""),&body).send().await?.status()==StatusCode::PRECONDITION_FAILED);
        let created=post(&endpoint,"http-create",Some("\"1\""),&body).send().await?;
        ensure!(created.status()==StatusCode::CREATED);ensure!(created.headers()["etag"]=="\"1\"");
        ensure!(created.headers()["cache-control"]=="no-store" && created.headers().get("x-request-id").is_some());
        let location=created.headers()["location"].to_str()?.to_owned();
        let receipt:AutomationReceipt=created.json().await?;
        ensure!(location==format!("/v1/automations/{}",receipt.resource.id));
        let mut changed=body.clone();changed["name"]=json!("another body");
        ensure!(post(&endpoint,"http-create",Some("\"1\""),&changed).send().await?.status()==StatusCode::CONFLICT);
        sqlx::query("SELECT pg_sleep(2.05)").execute(&r.f.owner).await?;
        let replay=post(&endpoint,"http-create",Some("\"1\""),&body).send().await?;
        ensure!(replay.status()==StatusCode::CREATED);
        ensure!(replay.json::<AutomationReceipt>().await?.resource.id==receipt.resource.id);
        let claim=r.worker.claim().await.map_err(api_failure)?.context("HTTP-created due claim")?;
        r.worker.run_claim(&claim).await.map_err(api_failure)?;
        let get=|url:String|client.get(url).bearer_auth(&token).header("x-tenant-id",r.f.actor.tenant_id.to_string());
        let listed=get(format!("{origin}/v1/automations?project_id={}&limit=1",r.f.request.project_id)).send().await?;
        ensure!(listed.status()==StatusCode::OK);
        let listed:Value=listed.json().await?;ensure!(listed["items"][0]["id"]==json!(receipt.resource.id));
        ensure!(get(format!("{origin}/v1/automations?project_id={}&cursor=invalid",r.f.request.project_id)).send().await?.status()==StatusCode::BAD_REQUEST);
        let got=get(format!("{origin}{location}")).send().await?;ensure!(got.status()==StatusCode::OK);
        let public:Value=got.json().await?;
        for field in ["action","identity_subject","identity_issuer","delegation_id","event_stream_epoch"]{ensure!(public.get(field).is_none());}
        let runs=get(format!("{origin}{location}/runs?project_id={}",r.f.request.project_id)).send().await?;
        ensure!(runs.status()==StatusCode::OK);
        let runs:Value=runs.json().await?;let run=runs["items"][0]["id"].as_str().context("run ID")?.to_owned();
        let got=get(format!("{origin}/v1/automation-runs/{run}")).send().await?;
        ensure!(got.status()==StatusCode::OK && got.headers().get("etag").is_some());
        let public:Value=got.json().await?;ensure!(public["status"]=="SUBMITTED" && public["operation_id"].is_string());
        for field in ["original_request","operation_request","request_sha256","management_key","lease_token","lease_owner","dispatch_attempt_id","produced_resource_id"]{ensure!(public.get(field).is_none());}
        ensure!(get(format!("{origin}{location}/runs?project_id={}",Uuid::new_v4())).send().await?.status()==StatusCode::NOT_FOUND);
        let waited=sdk_wait(&origin,r.f.actor.tenant_id,&token,r.f.request.project_id,&run,300).await?;
        ensure!(waited["automation"]==caps["automation"],"SDK must read the same live contract");
        ensure!(waited["kind"]=="timeout" && waited["status"]=="SUBMITTED");
        ensure!(r.count_operations(receipt.resource.id).await?==1,"SDK timeout cannot resubmit work");
        sqlx::query("UPDATE automation_claims SET eligible_at=clock_timestamp() WHERE automation_id=$1").bind(receipt.resource.id).execute(&r.f.owner).await?;
        let close=r.worker.claim().await.map_err(api_failure)?.context("renewal reconciliation claim")?;
        r.worker.run_claim(&close).await.map_err(api_failure)?;
        let waited=sdk_wait(&origin,r.f.actor.tenant_id,&token,r.f.request.project_id,&run,2000).await?;
        ensure!(waited["kind"]=="terminal" && waited["status"]=="SUCCEEDED");
        ensure!(r.count_operations(receipt.resource.id).await?==1);
        // Controls exercise a separate future rule after the renewal changed the
        // resource version, using actual strong ETags and original receipt keys.
        let instance=r.f.database.get_instance(&r.f.actor,r.instance.id).await.map_err(api_failure)?;
        let mut future=r.request();future.trigger=AutomationTrigger::Once{at:Utc::now()+Duration::hours(1)};
        let future=post(&endpoint,"future-control",Some(&format!("\"{}\"",instance.spec_version)),&json!(future)).send().await?;
        ensure!(future.status()==StatusCode::CREATED);let future:AutomationReceipt=future.json().await?;
        let control=format!("{origin}/v1/automations/{}/actions",future.resource.id);
        let paused=post(&format!("{control}/pause"),"http-pause",Some("\"1\""),&json!({})).send().await?;
        ensure!(paused.status()==StatusCode::OK);let paused:AutomationReceipt=paused.json().await?;ensure!(paused.resource.status=="PAUSED" && paused.resource.version==2);
        ensure!(post(&format!("{control}/resume"),"stale-resume",Some("\"1\""),&json!({})).send().await?.status()==StatusCode::PRECONDITION_FAILED);
        let resumed=post(&format!("{control}/resume"),"http-resume",Some("\"2\""),&json!({})).send().await?;
        ensure!(resumed.status()==StatusCode::OK && resumed.json::<AutomationReceipt>().await?.resource.version==3);
        let revoked=post(&format!("{control}/revoke"),"http-revoke",Some("\"3\""),&json!({})).send().await?;
        ensure!(revoked.status()==StatusCode::OK);let revoked:AutomationReceipt=revoked.json().await?;
        ensure!(revoked.resource.status=="REVOKED" && revoked.resource.delegation_revoked_at.is_some());
        ensure!(post(&format!("{control}/resume"),"irreversible-resume",Some("\"4\""),&json!({})).send().await?.status()==StatusCode::CONFLICT);
        // Use the real project-grant HTTP endpoints and the preserved 0036
        // delegation function with only automation actions added in formal 0039.
        let target=Uuid::new_v4();let ceiling=Utc::now()+Duration::hours(1);let action_ceiling=ceiling-Duration::minutes(10);
        let mut tx=r.f.owner_transaction().await?;
        for action in ["grants:read","grants:write"] {
            sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action,expires_at) VALUES($1,$2,$3,$4,$5)")
                .bind(r.f.actor.tenant_id).bind(r.f.request.project_id).bind(r.f.actor.principal_id).bind(action).bind(ceiling).execute(&mut *tx).await?;
        }
        sqlx::query("INSERT INTO principals(id,kind,display_name) VALUES($1,'SERVICE','Automation delegated HTTP target')").bind(target).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO principal_identities(issuer,subject,principal_id,service_client_id,service_binding_generation) VALUES('https://issuer.example.test',$1,$2,'automation-http-delegate',1)").bind(target.to_string()).bind(target).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO tenant_principals(tenant_id,principal_id,display_name) VALUES($1,$2,'Automation delegated HTTP target')").bind(r.f.actor.tenant_id).bind(target).execute(&mut *tx).await?;
        tx.commit().await?;
        let grant_endpoint=format!("{origin}/v1/projects/{}/grants",r.f.request.project_id);
        let target_token=encode(&header,&json!({"iss":"https://issuer.example.test","sub":target.to_string(),"aud":"sandbox-api","client_id":"automation-http-delegate","jti":Uuid::new_v4().to_string(),"iat":now,"exp":now+300,"scope":"sandbox:access"}),&EncodingKey::from_rsa_der(include_bytes!("../tests/fixtures/auth/rsa-a.der")))?;
        for action in ["backups:restore","restores:read"] {
            ensure!(post(&grant_endpoint,&format!("closed-{action}"),None,&json!({"principal_id":target,"action":action,"expires_at":null})).send().await?.status()==StatusCode::BAD_REQUEST,
                "formal automation must not open restore delegation");
        }
        for action in ["automations:read","automations:write"] {
            let mut tx=r.f.owner_transaction().await?;
            sqlx::query("UPDATE grants SET enabled=false,expires_at=$4 WHERE tenant_id=$1 AND principal_id=$2 AND action=$3").bind(r.f.actor.tenant_id).bind(r.f.actor.principal_id).bind(action).bind(action_ceiling).execute(&mut *tx).await?;
            tx.commit().await?;
            let grant=json!({"principal_id":target,"action":action,"expires_at":action_ceiling});
            ensure!(post(&grant_endpoint,&format!("missing-{action}"),None,&grant).send().await?.status()==StatusCode::FORBIDDEN,"missing concrete action cannot be delegated");
            let mut tx=r.f.owner_transaction().await?;
            sqlx::query("UPDATE grants SET enabled=true WHERE tenant_id=$1 AND principal_id=$2 AND action=$3").bind(r.f.actor.tenant_id).bind(r.f.actor.principal_id).bind(action).execute(&mut *tx).await?;tx.commit().await?;
            ensure!(post(&grant_endpoint,&format!("unlimited-{action}"),None,&json!({"principal_id":target,"action":action,"expires_at":null})).send().await?.status()==StatusCode::FORBIDDEN);
            ensure!(post(&grant_endpoint,&format!("over-ceiling-{action}"),None,&json!({"principal_id":target,"action":action,"expires_at":ceiling})).send().await?.status()==StatusCode::FORBIDDEN);
            let key=format!("exact-{action}");let accepted=post(&grant_endpoint,&key,None,&grant).send().await?;
            ensure!(accepted.status()==StatusCode::CREATED,"exact finite delegation must succeed");let accepted:Value=accepted.json().await?;
            let grant_id=accepted["resource"]["id"].as_str().context("delegated grant ID")?;
            if action=="automations:read" {
                ensure!(client.get(format!("{origin}{location}")).bearer_auth(&target_token).header("x-tenant-id",r.f.actor.tenant_id.to_string()).send().await?.status()==StatusCode::OK);
            }
            let revoked=client.delete(format!("{grant_endpoint}/{grant_id}")).bearer_auth(&token).header("x-tenant-id",r.f.actor.tenant_id.to_string()).header("idempotency-key",format!("revoke-{action}")).header("if-match","\"1\"").send().await?;
            ensure!(revoked.status()==StatusCode::OK);
            if action=="automations:read" {
                ensure!(client.get(format!("{origin}{location}")).bearer_auth(&target_token).header("x-tenant-id",r.f.actor.tenant_id.to_string()).send().await?.status()==StatusCode::NOT_FOUND);
            }
            let mut tx=r.f.owner_transaction().await?;
            sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='grants:write'").bind(r.f.actor.tenant_id).bind(r.f.actor.principal_id).execute(&mut *tx).await?;tx.commit().await?;
            ensure!(post(&grant_endpoint,&key,None,&grant).send().await?.status()==StatusCode::NOT_FOUND,"revoked manager cannot replay a delegation receipt");
            let mut tx=r.f.owner_transaction().await?;
            sqlx::query("UPDATE grants SET enabled=true WHERE tenant_id=$1 AND principal_id=$2 AND action='grants:write'").bind(r.f.actor.tenant_id).bind(r.f.actor.principal_id).execute(&mut *tx).await?;tx.commit().await?;
        }
        let mut tx=r.f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='automations:read'").bind(r.f.actor.tenant_id).bind(r.f.actor.principal_id).execute(&mut *tx).await?;tx.commit().await?;
        ensure!(get(format!("{origin}{location}")).send().await?.status()==StatusCode::NOT_FOUND);
        ensure!(get(format!("{origin}/v1/automation-runs/{run}")).send().await?.status()==StatusCode::NOT_FOUND);
        let mut tx=r.f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='capabilities:read'").bind(r.f.actor.tenant_id).bind(r.f.actor.principal_id).execute(&mut *tx).await?;
        tx.commit().await?;
        ensure!(get(format!("{origin}/v1/capabilities?project_id={}",r.f.request.project_id)).send().await?.status()==StatusCode::NOT_FOUND);
        Ok::<(),anyhow::Error>(())
    }.await;
    server.abort();
    jwks_server.abort();
    let _ = server.await;
    let _ = jwks_server.await;
    result
    })
}
