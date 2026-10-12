#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::{
    tests::{Ready, automation_test_runtime},
    *,
};
use crate::{
    history::{CursorSigner, HistoryQuery},
    model::RenewRequest,
    test_support_db::{self, api_failure},
};
use anyhow::ensure;
use chrono::Duration;
use sqlx::Row;
use std::time::Duration as WallDuration;

#[test]
#[ignore = "requires dedicated formal automation Docker PostgreSQL and provisioned roles"]
fn real_exception_event_inbox_acknowledgement_and_live_revocation() -> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
        let _serial=test_support_db::serial().await;
        let r=Ready::new().await?;
        let policy=r.create(&r.request()).await?.resource;
        let claim=r.due_claim().await?;
        let prepared=r.worker.prepare(&claim).await.map_err(api_failure)?;
        ensure!(prepared.is_some());
        // A normal manual renewal invalidates the prepared resource version.
        // The real automation acceptor records its business rejection and event.
        r.f.database.renew_instance(&r.f.actor,r.instance.id,&RenewRequest {expires_at:Utc::now()+Duration::hours(3)},"inbox-manual-renew",r.instance.spec_version,86400).await.map_err(api_failure)?;
        r.worker.run_claim(&claim).await.map_err(api_failure)?;
        let signer=CursorSigner::from_json(r#"{"active":{"kid":"inbox-fixture","key_base64":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="},"previous":[]}"#)?;
        let query=HistoryQuery { project_id:policy.project_id,instance_id:Some(r.instance.id),limit:Some(1),cursor:None };
        let page=r.f.database.list_automation_notifications(&r.f.actor,&query,&signer).await.map_err(api_failure)?;
        ensure!(page.items.len()==1 && page.items[0].source_status=="FAILED");
        let n=&page.items[0];
        ensure!(n.version==1 && n.acknowledged_at.is_none());
        let mut tx=r.f.owner_transaction().await?;
        let before:serde_json::Value=sqlx::query_scalar("SELECT to_jsonb(r) FROM automation_runs r WHERE r.tenant_id=$1 AND r.id=$2").bind(r.f.actor.tenant_id).bind(n.run_id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        let ack=r.f.database.acknowledge_automation_notification(&r.f.actor,&r.identity,n.id,"inbox-ack",1).await.map_err(api_failure)?;
        ensure!(ack.status==200 && ack.body.resource.version==2 && ack.body.resource.acknowledged_by==Some(r.f.actor.principal_id));
        let replay=r.f.database.acknowledge_automation_notification(&r.f.actor,&r.identity,n.id,"inbox-ack",1).await.map_err(api_failure)?;
        ensure!(serde_json::to_value(replay.body)?==serde_json::to_value(ack.body)?);
        let conflict=r.f.database.acknowledge_automation_notification(&r.f.actor,&r.identity,n.id,"inbox-ack",2).await.err().unwrap();
        ensure!(conflict.status==axum::http::StatusCode::CONFLICT);
        let stale=r.f.database.acknowledge_automation_notification(&r.f.actor,&r.identity,n.id,"inbox-stale",1).await.err().unwrap();
        ensure!(stale.status==axum::http::StatusCode::PRECONDITION_FAILED);
        r.f.database.acknowledge_automation_notification(&r.f.actor,&r.identity,n.id,"inbox-already",2).await.map_err(api_failure)?;
        let mut tx=r.f.owner_transaction().await?;
        let after:serde_json::Value=sqlx::query_scalar("SELECT to_jsonb(r) FROM automation_runs r WHERE r.tenant_id=$1 AND r.id=$2").bind(r.f.actor.tenant_id).bind(n.run_id).fetch_one(&mut *tx).await?;
        ensure!(before==after,"ack must not mutate original run or authority");
        let row=sqlx::query("SELECT count(*) AS total,bool_and(e.request_id=$3 AND EXISTS(SELECT 1 FROM automation_runs r WHERE r.tenant_id=e.tenant_id AND(r.id=e.request_id OR r.operation_id=e.operation_id))) AS excluded FROM domain_events e WHERE e.tenant_id=$1 AND e.aggregate_id=$2 AND e.event_type='automation-notifications:acknowledged'").bind(r.f.actor.tenant_id).bind(n.id).bind(n.run_id).fetch_one(&mut *tx).await?;
        ensure!(row.try_get::<i64,_>("total")?==1 && row.try_get::<bool,_>("excluded")?,"legacy/current origin predicate excludes ACK");
        let audits:i64=sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND resource_id=$2 AND action='automations:notifications:acknowledge' AND request_id=$3").bind(r.f.actor.tenant_id).bind(n.id).bind(r.f.actor.request_id).fetch_one(&mut *tx).await?;
        ensure!(audits==1,"new key on already acknowledged notice must not duplicate audit");
        sqlx::query("UPDATE grants SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND action='automations:write'").bind(r.f.actor.tenant_id).bind(r.f.actor.principal_id).execute(&mut *tx).await?;
        tx.commit().await?;
        ensure!(r.f.database.acknowledge_automation_notification(&r.f.actor,&r.identity,n.id,"inbox-ack",1).await.is_err(),"receipt replay must not bypass live revocation");
        Ok(())
    })
}

#[test]
#[ignore = "requires dedicated formal automation Docker PostgreSQL and provisioned roles"]
fn unknown_exception_source_deduplication_and_trigger_rollback() -> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
        let _serial=test_support_db::serial().await;
        let r=Ready::new().await?;
        let policy=r.create(&r.request()).await?.resource;
        let claim=r.due_claim().await?;
        ensure!(r.worker.prepare(&claim).await.map_err(api_failure)?.is_some());
        // This fixture exercises a real persisted UNKNOWN row, not a fabricated
        // transport receipt or a claim of cloud execution/closure.
        let mut tx=r.f.owner_transaction().await?;
        let run:Uuid=sqlx::query_scalar("UPDATE automation_runs SET status='OUTCOME_UNKNOWN',failure_code='DEPENDENCY_UNAVAILABLE' WHERE tenant_id=$1 AND automation_id=$2 RETURNING id").bind(r.f.actor.tenant_id).bind(policy.id).fetch_one(&mut *tx).await?;
        let actor=crate::db::Actor {tenant_id:r.f.actor.tenant_id,principal_id:r.f.actor.principal_id,request_id:run,authorization:None};
        ledger::event(&mut tx,&actor,policy.project_id,run,"automations:run","OUTCOME_UNKNOWN").await.map_err(api_failure)?;
        let source_version:i64=sqlx::query_scalar("SELECT source_run_version FROM automation_notifications WHERE tenant_id=$1 AND run_id=$2").bind(actor.tenant_id).bind(run).fetch_one(&mut *tx).await?;
        // Existing domain events uniquely identify aggregate + version + type;
        // a later legitimate UNKNOWN reconciliation advances the run version.
        sqlx::query("UPDATE automation_runs SET status='OUTCOME_UNKNOWN' WHERE tenant_id=$1 AND id=$2").bind(actor.tenant_id).bind(run).execute(&mut *tx).await?;
        ledger::event(&mut tx,&actor,policy.project_id,run,"automations:run","OUTCOME_UNKNOWN").await.map_err(api_failure)?;
        let retained_version:i64=sqlx::query_scalar("SELECT source_run_version FROM automation_notifications WHERE tenant_id=$1 AND run_id=$2").bind(actor.tenant_id).bind(run).fetch_one(&mut *tx).await?;
        ensure!(source_version==retained_version,"first historical exception remains immutable");
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM automation_notifications WHERE tenant_id=$1 AND run_id=$2").bind(actor.tenant_id).bind(run).fetch_one(&mut *tx).await?;
        ensure!(count==1,"repeated UNKNOWN events create one source notice");
        tx.rollback().await?;
        let mut tx=r.f.owner_transaction().await?;
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM automation_notifications WHERE tenant_id=$1 AND run_id=$2").bind(actor.tenant_id).bind(run).fetch_one(&mut *tx).await?;
        ensure!(count==0,"rolled-back event cannot publish its notice");
        tx.commit().await?;
        Ok(())
    })
}

async fn persisted_unknown_notification(
    r: &Ready,
) -> anyhow::Result<notifications::AutomationNotification> {
    let policy = r.create(&r.request()).await?.resource;
    let claim = r.due_claim().await?;
    ensure!(
        r.worker
            .prepare(&claim)
            .await
            .map_err(api_failure)?
            .is_some()
    );
    let mut tx = r.f.owner_transaction().await?;
    let run: Uuid = sqlx::query_scalar("UPDATE automation_runs SET status='OUTCOME_UNKNOWN',failure_code='DEPENDENCY_UNAVAILABLE' WHERE tenant_id=$1 AND automation_id=$2 RETURNING id")
        .bind(r.f.actor.tenant_id).bind(policy.id).fetch_one(&mut *tx).await?;
    let source = crate::db::Actor {
        request_id: run,
        ..r.f.actor.clone()
    };
    ledger::event(
        &mut tx,
        &source,
        policy.project_id,
        run,
        "automations:run",
        "OUTCOME_UNKNOWN",
    )
    .await
    .map_err(api_failure)?;
    let id: Uuid = sqlx::query_scalar(
        "SELECT id FROM automation_notifications WHERE tenant_id=$1 AND run_id=$2",
    )
    .bind(source.tenant_id)
    .bind(run)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    r.f.database
        .get_automation_notification(&r.f.actor, id)
        .await
        .map_err(api_failure)
}

async fn lock_project_head(r: &Ready) -> anyhow::Result<sqlx::Transaction<'_, sqlx::Postgres>> {
    let mut tx = r.f.owner_transaction().await?;
    sqlx::query(
        "SELECT project_id FROM event_stream_heads WHERE tenant_id=$1 AND project_id=$2 FOR UPDATE",
    )
    .bind(r.f.actor.tenant_id)
    .bind(r.f.request.project_id)
    .fetch_one(&mut *tx)
    .await?;
    Ok(tx)
}

async fn wait_for_head_waiter(owner: &sqlx::PgPool, head_pid: i32) -> anyhow::Result<()> {
    tokio::time::timeout(WallDuration::from_secs(3), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database() AND a.usename='sandbox_app' AND $1=ANY(pg_blocking_pids(a.pid)))")
                .bind(head_pid).fetch_one(owner).await?;
            if waiting { return Ok::<_, anyhow::Error>(()); }
            tokio::time::sleep(WallDuration::from_millis(10)).await;
        }
    }).await??;
    Ok(())
}

#[test]
#[ignore = "requires dedicated formal automation Docker PostgreSQL and provisioned roles"]
fn acknowledgement_head_wait_rechecks_live_grant_and_token_expiry() -> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
        let _serial = test_support_db::serial().await;
        for expiry in [false, true] {
            let r = Ready::new().await?;
            let notification = persisted_unknown_notification(&r).await?;
            let mut identity = r.identity.clone();
            if expiry { identity.expires_at = (Utc::now()+Duration::seconds(2)).timestamp(); }
            let actor = crate::db::Actor { authorization: Some(identity.clone()), ..r.f.actor.clone() };
            let mut head = lock_project_head(&r).await?;
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *head).await?;
            let ack = r.f.database.acknowledge_automation_notification(&actor, &identity, notification.id, "inbox-wait-ack", 1);
            let release = async {
                wait_for_head_waiter(&r.f.owner, pid).await?;
                if expiry {
                    // Wait for the authoritative DB clock, not an estimated
                    // sleep margin, while the API is actually blocked on head.
                    sqlx::query("SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM(to_timestamp($1::double precision)-clock_timestamp())))+0.05)")
                        .bind(identity.expires_at as f64).execute(&r.f.owner).await?;
                } else {
                    let mut revoke = r.f.owner_transaction().await?;
                    sqlx::query("UPDATE grants SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND action='automations:write'")
                        .bind(actor.tenant_id).bind(actor.principal_id).execute(&mut *revoke).await?;
                    revoke.commit().await?;
                }
                head.commit().await?;
                Ok::<_, anyhow::Error>(())
            };
            let (result, released) = tokio::time::timeout(WallDuration::from_secs(6), async { tokio::join!(ack, release) }).await?;
            released?;
            let error = result.err().ok_or_else(|| anyhow::anyhow!("ACK must reject expired/revoked authority after head wait"))?;
            ensure!(error.status == if expiry { axum::http::StatusCode::UNAUTHORIZED } else { axum::http::StatusCode::NOT_FOUND });
            let mut tx = r.f.owner_transaction().await?;
            let untouched: bool = sqlx::query_scalar("SELECT version=1 AND acknowledged_at IS NULL FROM automation_notifications WHERE tenant_id=$1 AND id=$2")
                .bind(actor.tenant_id).bind(notification.id).fetch_one(&mut *tx).await?;
            let facts: i64 = sqlx::query_scalar("SELECT (SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND resource_id=$2 AND action='automations:notifications:acknowledge')+(SELECT count(*) FROM domain_events WHERE tenant_id=$1 AND aggregate_id=$2 AND event_type='automation-notifications:acknowledged')+(SELECT count(*) FROM management_receipts WHERE tenant_id=$1 AND target_id=$2 AND action='automations:notifications:acknowledge')")
                .bind(actor.tenant_id).bind(notification.id).fetch_one(&mut *tx).await?;
            ensure!(untouched && facts==0, "failed final authority recheck leaves no ACK, audit, event or receipt");
            tx.commit().await?;
        }
        Ok(())
    })
}

#[test]
#[ignore = "requires dedicated formal automation Docker PostgreSQL and provisioned roles"]
fn duplicate_unknown_source_and_ack_share_bounded_head_first_lock_order() -> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
        let _serial = test_support_db::serial().await;
        let r = Ready::new().await?;
        let notification = persisted_unknown_notification(&r).await?;
        let source = crate::db::Actor { request_id: notification.run_id, ..r.f.actor.clone() };
        let mut duplicate = lock_project_head(&r).await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *duplicate).await?;
        // Reconciliation owns the normal head before advancing its actual
        // persisted UNKNOWN version. ACK must wait without taking the notice.
        sqlx::query("UPDATE automation_runs SET status='OUTCOME_UNKNOWN' WHERE tenant_id=$1 AND id=$2")
            .bind(source.tenant_id).bind(notification.run_id).execute(&mut *duplicate).await?;
        let ack = r.f.database.acknowledge_automation_notification(&r.f.actor, &r.identity, notification.id, "inbox-concurrent-ack", 1);
        let producer = async {
            wait_for_head_waiter(&r.f.owner, pid).await?;
            // The blocked ACK must not yet own this row. NOWAIT turns a lock
            // inversion into a precise failure instead of a timing assumption.
            sqlx::query("SELECT id FROM automation_notifications WHERE tenant_id=$1 AND id=$2 FOR UPDATE NOWAIT")
                .bind(source.tenant_id).bind(notification.id).fetch_one(&mut *duplicate).await?;
            ledger::event(&mut duplicate, &source, notification.project_id, notification.run_id, "automations:run", "OUTCOME_UNKNOWN").await.map_err(api_failure)?;
            duplicate.commit().await?;
            Ok::<_, anyhow::Error>(())
        };
        let (ack, produced) = tokio::time::timeout(WallDuration::from_secs(6), async { tokio::join!(ack, producer) }).await?;
        produced?;
        let ack = ack.map_err(api_failure)?;
        ensure!(ack.body.resource.version==2);
        let mut tx = r.f.owner_transaction().await?;
        let (count, source_version): (i64, i64) = sqlx::query_as("SELECT count(*),min(source_run_version) FROM automation_notifications WHERE tenant_id=$1 AND run_id=$2")
            .bind(source.tenant_id).bind(notification.run_id).fetch_one(&mut *tx).await?;
        ensure!(count==1 && source_version==notification.source_run_version, "concurrent later event retains the original historical source");
        tx.commit().await?;
        Ok(())
    })
}

#[test]
#[ignore = "requires dedicated formal automation Docker PostgreSQL and provisioned roles"]
fn ordinary_run_events_without_exception_status_keep_existing_semantics() -> anyhow::Result<()> {
    automation_test_runtime().block_on(async {
        let _serial = test_support_db::serial().await;
        let r = Ready::new().await?;
        let mut tx = r.f.owner_transaction().await?;
        for (event_type,payload) in [
            ("automations:run.changed", serde_json::json!({})),
            ("automations:run.changed", serde_json::json!({"status":null})),
            ("automations:run.changed", serde_json::json!({"status":"SKIPPED"})),
            ("automations:run.changed", serde_json::json!({"status":"CANCELLED"})),
            ("automations:run.changed", serde_json::json!({"status":"SUCCEEDED"})),
            ("unrelated.changed", serde_json::json!({"status":"FAILED"})),
        ] {
            sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,request_id,payload) VALUES($1,$2,$3,1,$4,$5,$6)")
                .bind(r.f.actor.tenant_id).bind(r.f.request.project_id).bind(Uuid::new_v4()).bind(event_type).bind(Uuid::new_v4()).bind(payload).execute(&mut *tx).await?;
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM automation_notifications WHERE tenant_id=$1")
            .bind(r.f.actor.tenant_id).fetch_one(&mut *tx).await?;
        ensure!(count==0, "ordinary event rows are not interpreted as exception sources");
        tx.commit().await?;
        let mut tx = r.f.owner_transaction().await?;
        let forged = sqlx::query("INSERT INTO domain_events(tenant_id,project_id,aggregate_id,aggregate_version,event_type,request_id,payload) VALUES($1,$2,$3,1,'automations:run.changed',$3,'{\"status\":\"FAILED\"}')")
            .bind(r.f.actor.tenant_id).bind(r.f.request.project_id).bind(Uuid::new_v4()).execute(&mut *tx).await.err()
            .ok_or_else(|| anyhow::anyhow!("exception source must match a real persisted run"))?;
        ensure!(forged.as_database_error().is_some_and(|e|e.code().as_deref()==Some("23514")));
        tx.rollback().await?;
        Ok(())
    })
}
