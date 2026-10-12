//! Real session identity, dedicated coordinator and immutable source facts for
//! the browser inbox acceptance. No seeded failure, notification or ACK reply.
use super::*;
use crate::{
    automation::{
        AutomationAction, AutomationTrigger, CreateAutomation, controller::AutomationController,
    },
    model::RenewRequest,
};
use sqlx::Row;

async fn save_private_facts(
    fixture: &support::Fixture,
    instance: Uuid,
    source: &Value,
    before: &Value,
) -> anyhow::Result<()> {
    let Some(directory) = std::env::var_os("SANDBOX_BROWSER_EVIDENCE_DIR") else {
        return Ok(());
    };
    let directory = PathBuf::from(directory);
    let metadata = std::fs::symlink_metadata(&directory)?;
    ensure!(
        directory.is_absolute()
            && metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && directory.canonicalize()? == directory
            && !directory
                .components()
                .any(|component| component.as_os_str() == "target"),
        "the private browser evidence directory must be canonical, owned by the runner and outside build caches"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "the browser evidence directory must not expose private business rows"
        );
    }
    let id = Uuid::parse_str(
        source["notification"]["id"]
            .as_str()
            .context("source notice identity missing")?,
    )?;
    let mut tx = fixture.owner_transaction().await?;
    let receipts: Value = sqlx::query_scalar(r#"SELECT jsonb_build_object(
      'notification',(SELECT to_jsonb(n) FROM automation_notifications n WHERE n.tenant_id=$1 AND n.id=$2),
      'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.created_at),'[]'::jsonb) FROM management_receipts r WHERE r.tenant_id=$1 AND r.action='automations:notifications:acknowledge' AND r.target_id=$2),
      'audits',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY a.occurred_at,a.id),'[]'::jsonb) FROM audit_events a WHERE a.tenant_id=$1 AND a.resource_id=$2 AND a.action='automations:notifications:acknowledge'),
      'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.occurred_at,e.id),'[]'::jsonb) FROM domain_events e WHERE e.tenant_id=$1 AND e.aggregate_id=$2 AND e.event_type='automation-notifications:acknowledged')
    )"#).bind(fixture.actor.tenant_id).bind(id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    let after = business_facts(fixture, instance).await?;
    ensure!(
        &after == before,
        "private browser evidence must retain equal full before/after business facts"
    );
    let report = serde_json::to_vec_pretty(&json!({"schema_version":1,
        "source_generation":"real verified browser session identity; normal domain creation and dedicated coordinator prepare; normal manual renewal version race; real run_claim failure",
        "source":source,"before_ack":before,"after_ack_and_replay":after,"acknowledgement":receipts,
        "business_facts_equal":true,"recorded_at":Utc::now()}))?;
    // create_new refuses an existing report or file symlink. Restrictive mode
    // applies at creation; no browser session, hash, bearer or provider secret
    // is included in this test's source/fact/receipt snapshots.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(directory.join("notification-facts.json"))?;
    std::io::Write::write_all(&mut file, &report)?;
    file.sync_all()?;
    Ok(())
}

async fn business_facts(fixture: &support::Fixture, instance: Uuid) -> anyhow::Result<Value> {
    let mut tx = fixture.owner_transaction().await?;
    let facts: Value = sqlx::query_scalar(r#"SELECT jsonb_build_object(
      'instance',to_jsonb(i),'workspace',to_jsonb(w),
      'executions',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]'::jsonb) FROM executions e WHERE e.tenant_id=i.tenant_id AND e.instance_id=i.id),
      'file_transfers',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY f.id),'[]'::jsonb) FROM file_transfers f WHERE f.tenant_id=i.tenant_id AND f.instance_id=i.id),
      'file_parts',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY p.transfer_id,p.part_index),'[]'::jsonb) FROM file_transfer_parts p JOIN file_transfers f ON(f.tenant_id,f.id)=(p.tenant_id,p.transfer_id) WHERE f.tenant_id=i.tenant_id AND f.instance_id=i.id),
      'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY o.id),'[]'::jsonb) FROM operations o WHERE o.tenant_id=i.tenant_id AND o.instance_id=i.id),
      'operation_dispatch',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY d.operation_id),'[]'::jsonb) FROM operation_dispatch d JOIN operations o ON(o.tenant_id,o.id)=(d.tenant_id,d.operation_id) WHERE o.tenant_id=i.tenant_id AND o.instance_id=i.id),
      'automations',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY a.id),'[]'::jsonb) FROM automations a WHERE a.tenant_id=i.tenant_id AND a.instance_id=i.id),
      'delegations',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY d.id),'[]'::jsonb) FROM automation_delegations d WHERE d.tenant_id=i.tenant_id AND d.instance_id=i.id),
      'runs',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.id),'[]'::jsonb) FROM automation_runs r WHERE r.tenant_id=i.tenant_id AND r.instance_id=i.id),
      'automation_claims',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY c.automation_id),'[]'::jsonb) FROM automation_claims c JOIN automations a ON(a.tenant_id,a.id)=(c.tenant_id,c.automation_id) WHERE a.tenant_id=i.tenant_id AND a.instance_id=i.id),
      'quota_accounts',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY q.id),'[]'::jsonb) FROM quota_accounts q WHERE q.tenant_id=i.tenant_id AND(q.project_id=i.project_id OR q.project_id IS NULL)),
      'quota_reservations',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY q.id),'[]'::jsonb) FROM quota_reservations q WHERE q.tenant_id=i.tenant_id AND q.project_id=i.project_id),
      'holds',(SELECT coalesce(jsonb_agg(to_jsonb(h) ORDER BY h.id),'[]'::jsonb) FROM workspace_holds h WHERE h.tenant_id=w.tenant_id AND h.workspace_id=w.id),
      'hold_releases',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.hold_id),'[]'::jsonb) FROM workspace_hold_releases r JOIN workspace_holds h ON(h.tenant_id,h.id)=(r.tenant_id,r.hold_id) WHERE h.tenant_id=w.tenant_id AND h.workspace_id=w.id)
    ) FROM instances i JOIN workspaces w ON(w.tenant_id,w.project_id,w.id)=(i.tenant_id,i.project_id,i.workspace_id) WHERE i.tenant_id=$1 AND i.id=$2"#)
        .bind(fixture.actor.tenant_id).bind(instance).fetch_one(&mut *tx).await?;
    ensure!(
        facts["instance"].is_object()
            && facts["workspace"].is_object()
            && facts["runs"].is_array()
            && facts["delegations"].is_array(),
        "the inbox comparison must contain full real business rows"
    );
    tx.commit().await?;
    Ok(facts)
}

async fn acknowledged_once(
    fixture: &support::Fixture,
    instance: Uuid,
    notice_before: &Value,
    expected_facts: &Value,
) -> anyhow::Result<()> {
    ensure!(
        &business_facts(fixture, instance).await? == expected_facts,
        "notification reads, ACK and current permission changes cannot mutate business facts or run budget"
    );
    let id = Uuid::parse_str(
        notice_before["id"]
            .as_str()
            .context("notice identity missing")?,
    )?;
    let run = Uuid::parse_str(
        notice_before["run_id"]
            .as_str()
            .context("source run identity missing")?,
    )?;
    let mut tx = fixture.owner_transaction().await?;
    let after: Value = sqlx::query_scalar(
        "SELECT to_jsonb(n) FROM automation_notifications n WHERE n.tenant_id=$1 AND n.id=$2",
    )
    .bind(fixture.actor.tenant_id)
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
        after["version"] == 2
            && after["acknowledged_at"].is_string()
            && after["acknowledged_by"] == json!(fixture.actor.principal_id),
        "the actual committed ACK advances the notification exactly once"
    );
    let mut expected_notice = notice_before.clone();
    expected_notice["version"] = json!(2);
    expected_notice["acknowledged_at"] = after["acknowledged_at"].clone();
    expected_notice["acknowledged_by"] = after["acknowledged_by"].clone();
    ensure!(
        after == expected_notice,
        "ACK preserves all immutable exception source fields"
    );
    let row = sqlx::query(r#"SELECT
      (SELECT count(*) FROM management_receipts WHERE tenant_id=$1 AND principal_id=$2 AND action='automations:notifications:acknowledge' AND target_id=$3) AS receipts,
      (SELECT bool_and(resource_id=$3 AND response_status=200) FROM management_receipts WHERE tenant_id=$1 AND principal_id=$2 AND action='automations:notifications:acknowledge' AND target_id=$3) AS receipt_valid,
      (SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND actor_principal_id=$2 AND action='automations:notifications:acknowledge' AND resource_id=$3) AS audits,
      (SELECT bool_and(outcome='SUCCEEDED' AND request_id<>$4 AND request_id<>'00000000-0000-0000-0000-000000000000'::uuid) FROM audit_events WHERE tenant_id=$1 AND actor_principal_id=$2 AND action='automations:notifications:acknowledge' AND resource_id=$3) AS audit_valid,
      (SELECT count(*) FROM domain_events WHERE tenant_id=$1 AND aggregate_id=$3 AND event_type='automation-notifications:acknowledged') AS events,
      (SELECT bool_and(aggregate_version=2 AND request_id=$4 AND operation_id IS NULL AND payload=jsonb_build_object('notification_id',$3::uuid,'run_id',$4::uuid,'acknowledged',true)) FROM domain_events WHERE tenant_id=$1 AND aggregate_id=$3 AND event_type='automation-notifications:acknowledged') AS event_valid,
      (SELECT count(*) FROM automation_notifications WHERE tenant_id=$1 AND run_id=$4) AS sources,
      (SELECT bool_and(EXISTS(SELECT 1 FROM automation_runs r WHERE r.tenant_id=e.tenant_id AND(r.id=e.request_id OR r.operation_id=e.operation_id))) FROM domain_events e WHERE e.tenant_id=$1 AND e.aggregate_id=$3 AND e.event_type='automation-notifications:acknowledged') AS excluded"#)
        .bind(fixture.actor.tenant_id).bind(fixture.actor.principal_id).bind(id).bind(run).fetch_one(&mut *tx).await?;
    ensure!(
        row.try_get::<i64, _>("receipts")? == 1
            && row.try_get::<i64, _>("audits")? == 1
            && row.try_get::<i64, _>("events")? == 1
            && row.try_get::<i64, _>("sources")? == 1
            && row.try_get::<bool, _>("receipt_valid")?
            && row.try_get::<bool, _>("audit_valid")?
            && row.try_get::<bool, _>("event_valid")?
            && row.try_get::<bool, _>("excluded")?,
        "lost reply, denied attempts and original-key replay retain one receipt/audit/causal event and cannot feed automation"
    );
    tx.commit().await?;
    Ok(())
}

pub(super) async fn browser_notifications(
    fixture: &support::Fixture,
    verified: &support::VerifiedFixtureConnections,
    browser: &Arc<BrowserRuntime>,
    instance: Uuid,
    input: &mut tokio::process::ChildStdin,
    output: &mut BufReader<tokio::process::ChildStdout>,
) -> anyhow::Result<()> {
    phase(output, "notifications_ready").await?;
    // Read only the current session's opaque routing hash in Rust, then use the
    // real BFF credential/refresh and JWT verification paths. Nothing sensitive
    // is serialized to the browser coordinator or test logs.
    let mut tx = fixture.owner_transaction().await?;
    let hashes: Vec<String> = sqlx::query_scalar("SELECT r.cookie_hash FROM browser_sessions b JOIN browser_session_routes r ON(r.tenant_id,r.id)=(b.tenant_id,b.id) WHERE b.tenant_id=$1 AND b.principal_id=$2 AND b.status='ACTIVE' AND r.scrubbed_at IS NULL")
        .bind(fixture.actor.tenant_id).bind(fixture.actor.principal_id).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    ensure!(
        hashes.len() == 1,
        "use the one actual current authenticated browser session"
    );
    let (_, credentials) = browser
        .credentials(&hashes[0])
        .await
        .map_err(support::api_failure)?;
    let identity = browser
        .app
        .auth
        .verify(&credentials.tokens.access_token)
        .await?;
    let actor = fixture
        .database
        .resolve_actor(&identity, fixture.actor.tenant_id, Uuid::new_v4())
        .await
        .map_err(support::api_failure)?;
    ensure!(
        actor.principal_id == fixture.actor.principal_id
            && identity.issuer == browser.config.oidc.settings().issuer
            && identity.client_id.as_deref()
                == Some(browser.config.oidc.settings().client_id.as_str()),
        "the notification source creator must be the exact real Keycloak browser identity"
    );
    let current = fixture
        .database
        .get_instance(&actor, instance)
        .await
        .map_err(support::api_failure)?;
    let request = CreateAutomation {
        name: "real browser inbox source".into(),
        action: AutomationAction::Renew { ttl_seconds: 7200 },
        trigger: AutomationTrigger::Once {
            at: Utc::now() + chrono::Duration::seconds(2),
        },
        delegation_expires_at: Utc::now() + chrono::Duration::hours(1),
        run_budget: 1,
        minimum_interval_seconds: 60,
        grace_seconds: 300,
    };
    let policy = fixture
        .database
        .create_automation(
            &actor,
            &identity,
            instance,
            &request,
            "real-browser-inbox-create",
            current.spec_version,
            86400,
        )
        .await
        .map_err(support::api_failure)?
        .body
        .resource;
    let runtime = verified
        .runtime("TEST_AUTOMATION_DATABASE_URL", "sandbox_automation", 4)
        .await?;
    let worker = AutomationController::new(
        runtime.database_for("sandbox_automation")?,
        format!("browser-inbox-{}", Uuid::new_v4()),
        3600,
        86400,
    )
    .map_err(support::api_failure)?;
    worker.check_schema().await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let claim = loop {
        if let Some(claim) = worker.claim().await.map_err(support::api_failure)? {
            ensure!(
                claim.tenant_id == actor.tenant_id && claim.automation_id == policy.id,
                "the normal due queue selects only this bounded source policy"
            );
            break claim;
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "actual source ONCE never became due"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    ensure!(
        worker
            .prepare_for_acceptance_test(&claim)
            .await
            .map_err(support::api_failure)?,
        "the normal dedicated coordinator commits the source run before acceptance"
    );
    let renewed = fixture
        .database
        .renew_instance(
            &actor,
            instance,
            &RenewRequest {
                expires_at: Utc::now() + chrono::Duration::hours(3),
            },
            "real-browser-inbox-manual-renew",
            current.spec_version,
            86400,
        )
        .await
        .map_err(support::api_failure)?
        .body
        .resource;
    ensure!(
        renewed.spec_version == current.spec_version + 1,
        "a normal permitted manual renewal makes the prepared request stale"
    );
    worker
        .run_claim(&claim)
        .await
        .map_err(support::api_failure)?;
    let mut tx = fixture.owner_transaction().await?;
    let source: Value = sqlx::query_scalar("SELECT jsonb_build_object('notification',to_jsonb(n),'run',to_jsonb(r),'event',to_jsonb(e)) FROM automation_notifications n JOIN automation_runs r ON(r.tenant_id,r.id)=(n.tenant_id,n.run_id) JOIN domain_events e ON(e.tenant_id,e.project_id,e.id)=(n.tenant_id,n.project_id,n.source_event_id) WHERE n.tenant_id=$1 AND n.automation_id=$2")
        .bind(actor.tenant_id).bind(policy.id).fetch_one(&mut *tx).await?;
    let notice = &source["notification"];
    ensure!(
        notice["version"] == 1
            && notice["acknowledged_at"].is_null()
            && notice["source_status"] == "FAILED"
            && source["run"]["status"] == "FAILED"
            && source["run"]["failure_code"] == "VERSION_MISMATCH"
            && source["run"]["operation_id"].is_null()
            && source["run"]["dispatch_attempt_id"].is_string()
            && source["event"]["request_id"] == notice["run_id"]
            && source["event"]["aggregate_version"] == notice["source_run_version"]
            && source["event"]["payload"]["status"] == "FAILED",
        "the source notice is transactionally derived from the real version rejection and run event"
    );
    tx.commit().await?;
    let before = business_facts(fixture, instance).await?;
    let metadata = json!({"phase":"notifications_start", "notice_id":notice["id"], "id":notice["id"],
        "run_id":notice["run_id"], "automation_id":notice["automation_id"],
        "source_status":notice["source_status"], "source_run_version":notice["source_run_version"]});
    input.write_all(format!("{metadata}\n").as_bytes()).await?;

    phase(output, "notifications_ack_lost").await?;
    acknowledged_once(fixture, instance, notice, &before).await?;
    let mut tx = fixture.owner_transaction().await?;
    let revoked = sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND project_id=$2 AND principal_id=$3 AND action='automations:write' AND enabled AND revoked_at IS NULL")
        .bind(actor.tenant_id).bind(current.project_id).bind(actor.principal_id).execute(&mut *tx).await?;
    ensure!(
        revoked.rows_affected() == 1,
        "disable precisely the real current notification write grant"
    );
    tx.commit().await?;
    input
        .write_all(b"{\"phase\":\"notification_write_revoked\"}\n")
        .await?;
    phase(output, "notifications_write_denied").await?;
    acknowledged_once(fixture, instance, notice, &before).await?;
    let mut tx = fixture.owner_transaction().await?;
    let revoked = sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND project_id=$2 AND principal_id=$3 AND action='automations:read' AND enabled AND revoked_at IS NULL")
        .bind(actor.tenant_id).bind(current.project_id).bind(actor.principal_id).execute(&mut *tx).await?;
    ensure!(
        revoked.rows_affected() == 1,
        "disable precisely the real current notification read grant"
    );
    tx.commit().await?;
    input
        .write_all(b"{\"phase\":\"notification_read_revoked\"}\n")
        .await?;
    phase(output, "notifications_read_denied").await?;
    acknowledged_once(fixture, instance, notice, &before).await?;
    let mut tx = fixture.owner_transaction().await?;
    let restored = sqlx::query("UPDATE grants SET enabled=true WHERE tenant_id=$1 AND project_id=$2 AND principal_id=$3 AND action IN('automations:read','automations:write') AND NOT enabled AND revoked_at IS NULL")
        .bind(actor.tenant_id).bind(current.project_id).bind(actor.principal_id).execute(&mut *tx).await?;
    ensure!(
        restored.rows_affected() == 2,
        "restore only the two original inbox grants before explicit replay and stop"
    );
    tx.commit().await?;
    input
        .write_all(b"{\"phase\":\"notifications_permissions_restored\"}\n")
        .await?;
    phase(output, "notifications_complete").await?;
    acknowledged_once(fixture, instance, notice, &before).await?;
    save_private_facts(fixture, instance, &source, &before).await?;
    input
        .write_all(b"{\"phase\":\"notifications_checked\"}\n")
        .await?;
    println!(
        "VERIFIED real Chrome BFF automation notifications: exact real Keycloak session identity and normally migrated dedicated coordinator; normal prepared RENEW/manual version conflict produces FAILED event+notice; actual ACK commit/lost reply/reload, UNKNOWN original key/body/ETag retained across real write/read denial, explicit replay after authority restoration; CSRF/Origin/401/stale ETag rejection; one receipt/audit/causal event, complete business rows and budget unchanged by ACK, no automation feedback, original grants restored before stop"
    );
    Ok(())
}
