#[allow(dead_code)]
mod support;
use anyhow::{Context, ensure};
use chrono::{Duration, Utc};
use sandbox_platform::{
    auth::VerifiedIdentity,
    instance_security::{
        InstanceSecurity, NodeAuthorizationStatus, ObjectEvidenceStatus, OperationEvidenceState,
        PolicyDocumentStatus, PolicyProfile, SecurityFinding, UnknownStatus,
    },
};
use serde_json::{Value, json};
use support::{Fixture, api_failure};
use uuid::Uuid;

fn identity(f: &Fixture) -> VerifiedIdentity {
    VerifiedIdentity {
        scope_profile: Default::default(),
        issuer: "https://issuer.example.test".into(),
        subject: f.actor.principal_id.to_string(),
        client_id: Some("instance-security-fixture".into()),
        scopes: vec!["sandbox:access".into()],
        expires_at: Utc::now().timestamp() + 300,
    }
}
async fn policy(f: &mut Fixture, rules: Value) -> anyhow::Result<()> {
    let id = Uuid::new_v4();
    let mut tx = f.owner_transaction().await?;
    sqlx::query("INSERT INTO security_policy_versions(id,tenant_id,name,version,status,rules) VALUES($1,$2,$3,1,'APPROVED',$4)")
        .bind(id).bind(f.actor.tenant_id).bind(format!("security-{id}")).bind(rules).execute(&mut *tx).await?;
    tx.commit().await?;
    f.request.security_profile_id = id;
    Ok(())
}
async fn view(f: &Fixture, id: Uuid) -> anyhow::Result<InstanceSecurity> {
    f.database
        .get_instance_security(&f.actor, &identity(f), id)
        .await
        .map_err(api_failure)
}
async fn counts(f: &Fixture) -> anyhow::Result<(i64, i64, i64)> {
    let mut tx = f.owner_transaction().await?;
    let n=sqlx::query_as("SELECT (SELECT count(*) FROM operations WHERE tenant_id=$1),(SELECT count(*) FROM audit_events WHERE tenant_id=$1),(SELECT count(*) FROM domain_events WHERE tenant_id=$1)").bind(f.actor.tenant_id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(n)
}
#[test]
fn published_contract_deserializes_and_never_asserts_runtime_certification() -> anyhow::Result<()> {
    let report: InstanceSecurity =
        serde_json::from_str(include_str!("fixtures/security/instance-security.json"))?;
    ensure!(
        report.applied_policy.status == UnknownStatus::Unknown
            && report.runtime_isolation.status == UnknownStatus::Unknown
            && report.image_verification.status == UnknownStatus::Unknown,
        "three independent evidence gaps"
    );
    let v = serde_json::to_value(report)?;
    ensure!(
        v["runtime_certification"] == "NOT_ASSERTED"
            && v["denial_history"]["status"] == "NOT_CAPTURED",
        "no implied certification or fake event count"
    );
    ensure!(
        v == serde_json::from_str::<Value>(include_str!(
            "fixtures/security/instance-security.json"
        ))?,
        "exact JSON/typed DTO contract"
    );
    Ok(())
}
#[tokio::test]
#[ignore = "requires real PostgreSQL 17 normal migrations and distinct app/owner identities"]
async fn supported_desired_policy_historical_records_remain_unknown_and_read_only()
-> anyhow::Result<()> {
    let _guard = support::serial().await;
    let mut f = Fixture::new(2).await?;
    f.bind_client_id("instance-security-fixture").await?;
    policy(&mut f, json!({"profile":"deny-all","dns":true})).await?;
    let receipt = f.create("security-create").await.map_err(api_failure)?;
    let id = receipt.body.resource.id;
    f.seed_observed_state(id, "RUNNING").await?;
    f.seed_test_launch_certification(id, Utc::now() + Duration::hours(1))
        .await?;
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE instances SET observed_at=clock_timestamp(),ready_observed_at=clock_timestamp(),ready_generation=runtime_generation,ready_launch_id=launch_id,ready_pod_uid=pod_uid,ready_cluster_epoch=cluster_epoch WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO external_resources(tenant_id,project_id,operation_id,instance_id,workspace_id,provider,kind,provider_id,generation,owner_id,status,observed_at) SELECT tenant_id,project_id,$3,id,workspace_id,'kubernetes','CILIUM_POLICY',$4,runtime_generation,workspace_id,'ACTIVE',clock_timestamp()-interval '1 day' FROM instances WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(id).bind(receipt.body.operation.id).bind(format!("private-host-resource-{id}")).execute(&mut *tx).await?;
    tx.commit().await?;
    let before = counts(&f).await?;
    let report = view(&f, id).await?;
    ensure!(
        report.desired.security_policy.profile == Some(PolicyProfile::DenyAllWithDns),
        "supported exact profile"
    );
    ensure!(
        report.observations.policy_object.status == ObjectEvidenceStatus::Recorded,
        "historical object record"
    );
    ensure!(
        report.observations.node_authorization.status
            == NodeAuthorizationStatus::CoversComputeLease,
        "synthetic authorization covers lease"
    );
    ensure!(
        report.observations.launch_validation.matches_current_launch,
        "same-launch historical validation"
    );
    ensure!(
        report.findings.is_empty(),
        "no guard problems for this desired state"
    );
    let json = serde_json::to_value(&report)?;
    ensure!(
        json["applied_policy"]["status"] == "UNKNOWN"
            && json["runtime_isolation"]["status"] == "UNKNOWN"
            && json["image_verification"]["status"] == "UNKNOWN",
        "object and Ready never upgraded to independent applied evidence"
    );
    let text = json.to_string();
    for forbidden in [
        "private-host-resource",
        "test-account",
        "test-region",
        "test-only-certified-node",
        "test-only-disk",
        "registry.example.test",
        "csi_volume_handle",
        "provider_id",
        "receipt",
        "rules\"",
    ] {
        ensure!(
            !text.contains(forbidden),
            "host/receipt/raw rule details withheld"
        );
    }
    ensure!(
        counts(&f).await? == before,
        "GET performs no operations/audit/events writes"
    );
    let mut tx = f.owner_transaction().await?;
    sqlx::query("INSERT INTO external_resources(tenant_id,project_id,operation_id,instance_id,workspace_id,provider,kind,provider_id,generation,owner_id,status,deleted_at) SELECT tenant_id,project_id,$3,id,workspace_id,'kubernetes','CILIUM_POLICY',$4,runtime_generation,workspace_id,'DELETED',clock_timestamp() FROM instances WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(id).bind(receipt.body.operation.id).bind(format!("duplicate-{id}")).execute(&mut *tx).await?;
    tx.commit().await?;
    ensure!(
        view(&f, id).await?.observations.policy_object.status == ObjectEvidenceStatus::Unavailable,
        "ambiguous object rows never chosen as proof"
    );
    Ok(())
}
#[tokio::test]
#[ignore = "requires real PostgreSQL expanded JSON bound and immutable policy catalogs"]
async fn compressed_oversize_and_unsupported_policy_are_safe_classifications() -> anyhow::Result<()>
{
    let _guard = support::serial().await;
    let mut f = Fixture::new(3).await?;
    f.bind_client_id("instance-security-fixture").await?;
    policy(
        &mut f,
        json!({"profile":"deny-all","dns":true,"unexpected":false}),
    )
    .await?;
    let id = f
        .create("unsupported")
        .await
        .map_err(api_failure)?
        .body
        .resource
        .id;
    let r = view(&f, id).await?;
    ensure!(
        r.desired.security_policy.document_status == PolicyDocumentStatus::Available
            && r.desired.security_policy.profile.is_none()
            && r.findings
                .contains(&SecurityFinding::PolicyProfileUnsupported),
        "extra fields do not silently become supported"
    );
    policy(&mut f, json!({"payload":"x".repeat(200_000)})).await?;
    f.request.name = "oversize-security".into();
    let id = f
        .create("oversize")
        .await
        .map_err(api_failure)?
        .body
        .resource
        .id;
    let mut tx = f.owner_transaction().await?;
    let (expanded,stored):(i32,i32)=sqlx::query_as("SELECT octet_length(rules::text),pg_column_size(rules) FROM security_policy_versions WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(f.request.security_profile_id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    ensure!(
        expanded > 65536 && stored < 65536,
        "test must exercise compressed oversized JSON, not only an oversized physical row"
    );
    let r = view(&f, id).await?;
    ensure!(
        r.desired.security_policy.document_status == PolicyDocumentStatus::Unavailable
            && r.desired.security_policy.rules_sha256.is_none()
            && r.findings
                .contains(&SecurityFinding::PolicyDocumentUnavailable),
        "expanded 64 KiB database limit"
    );
    // A policy digest must retain precision beyond Rust JSON's f64 range.
    let precise = Uuid::new_v4();
    let raw = r#"{"exact":18446744073709551616.000000000000000001}"#;
    let mut tx = f.owner_transaction().await?;
    sqlx::query("INSERT INTO security_policy_versions(id,tenant_id,name,version,status,rules) VALUES($1,$2,'exact-numeric-fixture',1,'APPROVED',$3::text::jsonb)").bind(precise).bind(f.actor.tenant_id).bind(raw).execute(&mut *tx).await?;
    let exact: String = sqlx::query_scalar(
        "SELECT rules::text FROM security_policy_versions WHERE tenant_id=$1 AND id=$2",
    )
    .bind(f.actor.tenant_id)
    .bind(precise)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    ensure!(
        exact.contains("18446744073709551616.000000000000000001"),
        "PostgreSQL precision fixture"
    );
    f.request.security_profile_id = precise;
    f.request.name = "precise-security".into();
    let id = f
        .create("precise")
        .await
        .map_err(api_failure)?
        .body
        .resource
        .id;
    use sha2::{Digest, Sha256};
    ensure!(
        view(&f, id)
            .await?
            .desired
            .security_policy
            .rules_sha256
            .as_deref()
            == Some(hex::encode(Sha256::digest(exact.as_bytes())).as_str()),
        "digest uses exact expanded text without f64 conversion"
    );
    Ok(())
}
#[tokio::test]
#[ignore = "requires isolated real PostgreSQL; temporarily changes installation epoch/safe mode"]
async fn historical_epoch_catalog_revocation_and_expired_lease_do_not_assert_enforcement()
-> anyhow::Result<()> {
    let _guard = support::serial().await;
    let f = Fixture::new(2).await?;
    f.bind_client_id("instance-security-fixture").await?;
    let id = f
        .create("historical-security")
        .await
        .map_err(api_failure)?
        .body
        .resource
        .id;
    let mut tx = f.owner_transaction().await?;
    let original: Uuid =
        sqlx::query_scalar("SELECT cluster_epoch FROM platform_configuration WHERE singleton")
            .fetch_one(&mut *tx)
            .await?;
    sqlx::query("UPDATE template_versions SET status='REVOKED' WHERE tenant_id=$1 AND id=$2")
        .bind(f.actor.tenant_id)
        .bind(f.request.template_version_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE security_policy_versions SET status='REVOKED' WHERE tenant_id=$1 AND id=$2",
    )
    .bind(f.actor.tenant_id)
    .bind(f.request.security_profile_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE instances SET compute_lease_started_at=clock_timestamp()-interval '1 hour',compute_lease_expires_at=clock_timestamp()-interval '1 minute',desired_state='STOPPED' WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(id).execute(&mut *tx).await?;
    sqlx::query(
        "UPDATE platform_configuration SET cluster_epoch=$1,safe_mode=true WHERE singleton",
    )
    .bind(Uuid::new_v4())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let result = async {
        let r = view(&f, id).await?;
        for code in [
            SecurityFinding::TemplateNotApproved,
            SecurityFinding::SecurityPolicyNotApproved,
            SecurityFinding::HistoricalClusterEpoch,
            SecurityFinding::PlatformSafeMode,
            SecurityFinding::ComputeLeaseExpired,
            SecurityFinding::ComputeNoLongerDesired,
        ] {
            ensure!(r.findings.contains(&code), "current guard finding missing");
        }
        ensure!(
            !r.observations
                .launch_validation
                .matches_current_cluster_epoch,
            "historical epoch"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let mut tx = f.owner_transaction().await?;
    sqlx::query(
        "UPDATE platform_configuration SET cluster_epoch=$1,safe_mode=false WHERE singleton",
    )
    .bind(original)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    result
}
#[tokio::test]
#[ignore = "requires real PostgreSQL RLS/authority revocation"]
async fn every_live_authority_and_optional_operation_are_rechecked() -> anyhow::Result<()> {
    let _guard = support::serial().await;
    let f = Fixture::new(2).await?;
    f.bind_client_id("instance-security-fixture").await?;
    let receipt = f.create("authority-security").await.map_err(api_failure)?;
    let id = receipt.body.resource.id;
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET error=$3 WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(receipt.body.operation.id).bind(json!({"code":"IDENTITY_UNAVAILABLE","private_host":"never-return-this","message":"secret credential"})).execute(&mut *tx).await?;
    tx.commit().await?;
    let r = view(&f, id).await?;
    ensure!(
        r.active_operation.state == OperationEvidenceState::Available,
        "optional operation permitted"
    );
    let text = serde_json::to_string(&r)?;
    ensure!(
        text.contains("DEPENDENCY_UNAVAILABLE")
            && !text.contains("never-return-this")
            && !text.contains("secret credential"),
        "public operation error classifier"
    );
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='operations:read'").bind(f.actor.tenant_id).bind(f.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let r = view(&f, id).await?;
    ensure!(
        r.active_operation.state == OperationEvidenceState::Redacted
            && r.active_operation.resource.is_none(),
        "optional grant removal redacts without hiding instance"
    );
    let mut actor = f.actor.clone();
    actor.tenant_id = Uuid::new_v4();
    ensure!(
        f.database
            .get_instance_security(&actor, &identity(&f), id)
            .await
            .is_err_and(|e| e.status == axum::http::StatusCode::NOT_FOUND),
        "cross tenant hidden"
    );
    let mut invalid = identity(&f);
    invalid.expires_at = Utc::now().timestamp() - 1;
    ensure!(
        f.database
            .get_instance_security(&f.actor, &invalid, id)
            .await
            .is_err_and(|e| e.status == axum::http::StatusCode::UNAUTHORIZED),
        "token DB clock check"
    );
    let statements = [
        "UPDATE grants SET enabled=$3 WHERE tenant_id=$1 AND principal_id=$2 AND action='instances:read'",
        "UPDATE projects SET enabled=$3 WHERE tenant_id=$1 AND id=(SELECT project_id FROM grants WHERE tenant_id=$1 AND principal_id=$2 LIMIT 1)",
        "UPDATE tenants SET enabled=$3 WHERE id=$1 AND $2::uuid IS NOT NULL",
        "UPDATE tenant_principals SET enabled=$3 WHERE tenant_id=$1 AND principal_id=$2",
        "UPDATE principals SET enabled=$3 WHERE id=$2 AND $1::uuid IS NOT NULL",
        "UPDATE principal_identities SET enabled=$3 WHERE principal_id=$2 AND $1::uuid IS NOT NULL",
    ];
    for sql in statements {
        let mut tx = f.owner_transaction().await?;
        sqlx::query(sql)
            .bind(f.actor.tenant_id)
            .bind(f.actor.principal_id)
            .bind(false)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        ensure!(
            f.database
                .get_instance_security(&f.actor, &identity(&f), id)
                .await
                .is_err_and(|e| e.status == axum::http::StatusCode::NOT_FOUND),
            "withdrawn authority must hide security view"
        );
        let mut tx = f.owner_transaction().await?;
        sqlx::query(sql)
            .bind(f.actor.tenant_id)
            .bind(f.actor.principal_id)
            .bind(true)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    Ok(())
}
async fn wait_for_blocker(f: &Fixture, blocker: i32) -> anyhow::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
            )
            .bind(blocker)
            .fetch_one(&f.owner)
            .await?;
            if waiting {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .context("actual security query must block on held database table")??;
    Ok(())
}
#[tokio::test]
#[ignore = "requires real PostgreSQL row/table locks and final live authority checks"]
async fn revocation_and_token_expiry_during_real_database_wait_deny_the_report()
-> anyhow::Result<()> {
    let _guard = support::serial().await;
    let f = Fixture::new(2).await?;
    f.bind_client_id("instance-security-fixture").await?;
    let id = f
        .create("waiting-security")
        .await
        .map_err(api_failure)?
        .body
        .resource
        .id;
    for case in ["IDENTITY", "TOKEN", "GRANT"] {
        let mut blocker = f.owner_transaction().await?;
        sqlx::query("LOCK TABLE runtime_nodes IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *blocker)
            .await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        let db = f.database.clone();
        let actor = f.actor.clone();
        let mut auth = identity(&f);
        if case == "TOKEN" {
            auth.expires_at = Utc::now().timestamp() + 2;
        }
        let deadline = if case == "GRANT" {
            let mut tx = f.owner_transaction().await?;
            let deadline = Utc::now().timestamp() + 2;
            sqlx::query("UPDATE grants SET expires_at=to_timestamp($3::bigint) WHERE tenant_id=$1 AND principal_id=$2 AND action='instances:read'")
                .bind(f.actor.tenant_id).bind(f.actor.principal_id).bind(deadline).execute(&mut *tx).await?;
            tx.commit().await?;
            deadline
        } else {
            auth.expires_at
        };
        let job = tokio::spawn(async move { db.get_instance_security(&actor, &auth, id).await });
        wait_for_blocker(&f, pid).await?;
        if case == "IDENTITY" {
            let mut tx = f.owner_transaction().await?;
            sqlx::query("UPDATE principal_identities SET enabled=false WHERE principal_id=$1")
                .bind(f.actor.principal_id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        } else {
            tokio::time::timeout(std::time::Duration::from_millis(2600), async {
                loop {
                    let expired: bool =
                        sqlx::query_scalar("SELECT clock_timestamp()>=to_timestamp($1::bigint)")
                            .bind(deadline)
                            .fetch_one(&f.owner)
                            .await?;
                    if expired {
                        return Ok::<_, anyhow::Error>(());
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await
            .context("token must expire within the real lock timeout")??;
        }
        blocker.commit().await?;
        let error = job
            .await?
            .err()
            .context("read must fail after authority expiration")?;
        ensure!(
            error.status
                == if case != "TOKEN" {
                    axum::http::StatusCode::NOT_FOUND
                } else {
                    axum::http::StatusCode::UNAUTHORIZED
                },
            "post-wait mapping/token check: status={} code={}",
            error.status,
            error.code
        );
        if case == "IDENTITY" {
            let mut tx = f.owner_transaction().await?;
            sqlx::query("UPDATE principal_identities SET enabled=true WHERE principal_id=$1")
                .bind(f.actor.principal_id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }
        if case == "GRANT" {
            let mut tx = f.owner_transaction().await?;
            sqlx::query("UPDATE grants SET expires_at=NULL WHERE tenant_id=$1 AND principal_id=$2 AND action='instances:read'").bind(f.actor.tenant_id).bind(f.actor.principal_id).execute(&mut *tx).await?;
            tx.commit().await?;
        }
    }

    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL and actual loopback HTTP/JWT signature verification"]
async fn signed_http_security_etag_capability_redaction_and_withdrawal() -> anyhow::Result<()> {
    use axum::{Json, Router, routing::get};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use sandbox_platform::{
        api::{AppState, router},
        auth::{AuthConfig, JwtAuthenticator},
        history::CursorSigner,
    };
    use std::{sync::Arc, time::Duration};
    let _guard = support::serial().await;
    let f = Fixture::new(2).await?;
    f.bind_client_id("instance-security-fixture").await?;
    let created = f.create("security-http").await.map_err(api_failure)?;
    let id = created.body.resource.id;
    let mut tx = f.owner_transaction().await?;
    sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,'capabilities:read')").bind(f.actor.tenant_id).bind(f.request.project_id).bind(f.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let jwk: Value = serde_json::from_str(include_str!("fixtures/auth/jwk-a.json"))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let jwks_address = listener.local_addr()?;
    let jwks_server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/jwks",
                get(move || {
                    let jwk = jwk.clone();
                    async move { Json(json!({"keys":[jwk]})) }
                }),
            ),
        )
        .await
    });
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
        let now=Utc::now().timestamp();let mut header=Header::new(Algorithm::RS256);header.typ=Some("at+jwt".into());header.kid=Some("key-a".into());
        let token=encode(&header,&json!({"iss":"https://issuer.example.test","sub":f.actor.principal_id.to_string(),"aud":"sandbox-api","client_id":"instance-security-fixture","iat":now,"exp":now+300,"jti":Uuid::new_v4().to_string(),"scope":"sandbox:access"}),&EncodingKey::from_rsa_der(include_bytes!("fixtures/auth/rsa-a.der")))?;
        let client=reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(10)).build()?;let endpoint=format!("http://{address}/v1/instances/{id}/security");
        let get=|tenant:Uuid|client.get(&endpoint).bearer_auth(&token).header("x-tenant-id",tenant.to_string());
        let response=get(f.actor.tenant_id).send().await?;ensure!(response.status()==reqwest::StatusCode::OK,"authenticated security GET must succeed");
        ensure!(response.headers()["cache-control"]=="no-store"&&response.headers()["x-instance-etag"]==format!("\"{}\"",created.body.resource.spec_version),"private snapshot and optimistic version header");
        let r:InstanceSecurity=response.json().await?;ensure!(r.instance_id==id&&r.runtime_isolation.status==UnknownStatus::Unknown,"exact typed endpoint");
        ensure!(r.active_operation.resource.as_ref().context("active CREATE")?.error.is_none(),"null stored error must remain absent");
        let caps:Value=client.get(format!("http://{address}/v1/capabilities?project_id={}",f.request.project_id)).bearer_auth(&token).header("x-tenant-id",f.actor.tenant_id.to_string()).send().await?.error_for_status()?.json().await?;
        ensure!(caps["api_features"]["instance_security"]==true&&caps["runtime_certification"]=="NOT_ASSERTED","feature flag describes API only");
        ensure!(get(Uuid::new_v4()).send().await?.status()==reqwest::StatusCode::NOT_FOUND,"cross-tenant hidden through actual JWT HTTP");
        ensure!(client.get(&endpoint).header("x-tenant-id",f.actor.tenant_id.to_string()).send().await?.status()==reqwest::StatusCode::UNAUTHORIZED,"signature authentication mandatory");
        ensure!(client.get(format!("http://{address}/v1/instances/not-a-uuid/security")).bearer_auth(&token).header("x-tenant-id",f.actor.tenant_id.to_string()).send().await?.status()==reqwest::StatusCode::BAD_REQUEST,"invalid identifiers classified");
        let mut tx=f.owner_transaction().await?;sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='operations:read'").bind(f.actor.tenant_id).bind(f.actor.principal_id).execute(&mut *tx).await?;tx.commit().await?;
        let r:InstanceSecurity=get(f.actor.tenant_id).send().await?.error_for_status()?.json().await?;ensure!(r.active_operation.state==OperationEvidenceState::Redacted&&r.active_operation.resource.is_none(),"HTTP optional redaction");
        let mut tx=f.owner_transaction().await?;sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='instances:read'").bind(f.actor.tenant_id).bind(f.actor.principal_id).execute(&mut *tx).await?;tx.commit().await?;
        ensure!(get(f.actor.tenant_id).send().await?.status()==reqwest::StatusCode::NOT_FOUND,"HTTP live mandatory permission");Ok::<_,anyhow::Error>(())
    }.await;
    api_server.abort();
    jwks_server.abort();
    result
}

#[tokio::test]
#[ignore = "requires real PostgreSQL evidence snapshot/authorization changes during actual lock waits"]
async fn concurrent_catalog_change_conflicts_and_optional_grant_change_redacts()
-> anyhow::Result<()> {
    let _guard = support::serial().await;
    let f = Fixture::new(2).await?;
    f.bind_client_id("instance-security-fixture").await?;
    let receipt = f.create("binding-security").await.map_err(api_failure)?;
    let id = receipt.body.resource.id;
    for catalog_change in [false, true] {
        let mut blocker = f.owner_transaction().await?;
        sqlx::query("LOCK TABLE runtime_nodes IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *blocker)
            .await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        let db = f.database.clone();
        let actor = f.actor.clone();
        let auth = identity(&f);
        let job = tokio::spawn(async move { db.get_instance_security(&actor, &auth, id).await });
        wait_for_blocker(&f, pid).await?;
        let mut tx = f.owner_transaction().await?;
        if catalog_change {
            sqlx::query(
                "UPDATE template_versions SET status='REVOKED' WHERE tenant_id=$1 AND id=$2",
            )
            .bind(f.actor.tenant_id)
            .bind(f.request.template_version_id)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='operations:read'").bind(f.actor.tenant_id).bind(f.actor.principal_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE operations SET error=$3 WHERE tenant_id=$1 AND id=$2")
                .bind(f.actor.tenant_id)
                .bind(receipt.body.operation.id)
                .bind(json!({"code":"OUTCOME_UNKNOWN","private":"never-disclose-operation-change"}))
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        blocker.commit().await?;
        let result = job.await?;
        if catalog_change {
            ensure!(
                result.is_err_and(|e| e.status == axum::http::StatusCode::CONFLICT
                    && e.code == "SECURITY_TARGET_CHANGED"),
                "changed desired catalog must never mix old/new evidence"
            );
        } else {
            let report = result.map_err(api_failure)?;
            ensure!(
                report.active_operation.state == OperationEvidenceState::Redacted
                    && report.active_operation.resource.is_none(),
                "withdrawal hides even changed operation evidence without an operation-derived conflict"
            );
            ensure!(
                !serde_json::to_string(&report)?.contains("never-disclose-operation-change"),
                "withdrawn optional evidence cannot escape"
            );
        }
    }
    Ok(())
}

async fn node_sdk_security_read(
    origin: &str,
    tenant: Uuid,
    token: &str,
    instance: Uuid,
    spec_version: i64,
    phase: &str,
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    ensure!(
        root.join("sdk/typescript/dist/index.js").is_file(),
        "Build the actual TypeScript SDK before running this integration test"
    );
    let mut child = tokio::process::Command::new("node")
        .arg(root.join("tests/fixtures/security/sdk-http.mjs"))
        .current_dir(root)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("Cannot start actual Node SDK integration")?;
    let mut input = child.stdin.take().context("Private SDK input pipe")?;
    input
        .write_all(&serde_json::to_vec(&json!({
            "baseUrl":origin,"tenantId":tenant,"token":token,
            "instanceId":instance,"phase":phase,"specVersion":spec_version
        }))?)
        .await?;
    input.shutdown().await?;
    drop(input);
    let output = tokio::time::timeout(std::time::Duration::from_secs(10), child.wait_with_output())
        .await
        .context("Actual Node SDK exceeded its bounded deadline")??;
    ensure!(output.status.success(), "SDK_SECURITY_HTTP_FAILED");
    ensure!(output.stdout.len() <= 1024, "Invalid public SDK receipt");
    let receipt: Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        receipt["phase"] == phase
            && receipt["status"] == if phase == "REVOKED" { 404 } else { 200 }
            && receipt["token_provider_calls"] == 1,
        "Actual SDK public result must match the authority phase"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL, built Node SDK and signed TCP JWT/JWKS HTTP"]
async fn real_node_sdk_security_read_redaction_and_live_required_revocation() -> anyhow::Result<()>
{
    use axum::{Json, Router, routing::get};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use sandbox_platform::{
        api::{AppState, router},
        auth::{AuthConfig, JwtAuthenticator},
        history::CursorSigner,
    };
    use std::sync::Arc;
    let _guard = support::serial().await;
    let f = Fixture::new(2).await?;
    f.bind_client_id("instance-security-fixture").await?;
    let receipt = f.create("node-security-read").await.map_err(api_failure)?;
    let id = receipt.body.resource.id;
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET error=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(f.actor.tenant_id)
        .bind(receipt.body.operation.id)
        .bind(json!({"code":"IDENTITY_UNAVAILABLE","private":"never-return-sdk-private-error"}))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let before = counts(&f).await?;
    let jwk: Value = serde_json::from_str(include_str!("fixtures/auth/jwk-a.json"))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let jwks_address = listener.local_addr()?;
    let jwks_server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/jwks",
                get(move || {
                    let jwk = jwk.clone();
                    async move { Json(json!({"keys":[jwk]})) }
                }),
            ),
        )
        .await
    });
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
    let result = async {
        let now = Utc::now().timestamp();
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some("key-a".into());
        let token = encode(&header, &json!({
            "iss":"https://issuer.example.test","sub":f.actor.principal_id.to_string(),
            "aud":"sandbox-api","client_id":"instance-security-fixture",
            "iat":now,"exp":now+300,"jti":Uuid::new_v4().to_string(),"scope":"sandbox:access"
        }), &EncodingKey::from_rsa_der(include_bytes!("fixtures/auth/rsa-a.der")))?;
        let origin = format!("http://{address}");
        for phase in ["AVAILABLE", "REDACTED", "REVOKED"] {
            if phase != "AVAILABLE" {
                let action = if phase == "REDACTED" { "operations:read" } else { "instances:read" };
                let mut tx = f.owner_transaction().await?;
                sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action=$3")
                    .bind(f.actor.tenant_id).bind(f.actor.principal_id).bind(action)
                    .execute(&mut *tx).await?;
                tx.commit().await?;
            }
            node_sdk_security_read(&origin, f.actor.tenant_id, &token, id,
                receipt.body.resource.spec_version, phase).await?;
        }
        ensure!(counts(&f).await? == before, "Actual SDK GETs create no operation, audit or event");
        Ok::<_,anyhow::Error>(())
    }.await;
    api_server.abort();
    jwks_server.abort();
    result
}
