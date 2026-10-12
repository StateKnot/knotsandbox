#![allow(clippy::expect_used, clippy::unwrap_used)]
#[allow(dead_code)]
mod support;
use anyhow::{Context, ensure};
use futures_util::future::join_all;
use sandbox_platform::{
    auth::VerifiedIdentity,
    engine::{Claim, OperationEngine},
    execution::DispatchIdentity,
    file_transfer::{
        CreateFileTransfer,
        path::{MAX_FILE_BYTES, RelativeFilePath},
        transport::{CompletedFileProcess, FileTerminal},
    },
    model::Instance,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use support::{Fixture, api_failure};
use tokio::sync::{Barrier, OnceCell};
use uuid::Uuid;
static SCHEMA: OnceCell<()> = OnceCell::const_new();

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and real normally migrated API/owner identities"]
async fn deferred_file_activity_checks_each_row_scope_and_restores_context_on_failure()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let left = Ready::new(16, 4096).await?;
    let right = Ready::new(16, 4096).await?;
    let left_upload = left
        .create(&upload(b"left"), "deferred-left")
        .await
        .map_err(api_failure)?;
    let right_upload = right
        .create(&upload(b"right"), "deferred-right")
        .await
        .map_err(api_failure)?;
    let unrelated_tenant = Uuid::new_v4().to_string();
    let mut connection = left.f.owner.acquire().await?;
    let original_context: String =
        sqlx::query_scalar("SELECT COALESCE(current_setting('app.tenant_id',true),'')")
            .fetch_one(&mut *connection)
            .await?;
    let mut tx = sqlx::Connection::begin(&mut *connection).await?;
    for (ready, transfer) in [(&left, &left_upload), (&right, &right_upload)] {
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(ready.f.actor.tenant_id.to_string())
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE instances SET updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2",
        )
        .bind(ready.f.actor.tenant_id)
        .bind(ready.instance.id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE file_transfers SET updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2",
        )
        .bind(ready.f.actor.tenant_id)
        .bind(transfer.body.resource.id)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
        .bind(&unrelated_tenant)
        .execute(&mut *tx)
        .await?;
    // Exercise both public trigger tables in one transaction. A caller scope
    // that sees neither tenant must not suppress either deferred row check.
    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *tx)
        .await?;
    let after_checks: (String, i64) = sqlx::query_as(
        "SELECT current_setting('app.tenant_id',true),(SELECT count(*) FROM instances)",
    )
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(after_checks, (unrelated_tenant.clone(), 0));
    tx.commit().await?;
    let after_commit: String =
        sqlx::query_scalar("SELECT COALESCE(current_setting('app.tenant_id',true),'')")
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(after_commit, original_context);
    drop(connection);

    // Intentionally invalid activity exists only inside a rolled-back owner
    // fixture transaction. It mints no process, admission or termination proof.
    // Check both directions of the unchanged invariant with unrelated caller
    // scope: a held writer needs its exact instance activity, and vice versa.
    for held_writer in [false, true] {
        let broken = Ready::new(16, 4096).await?;
        let broken_transfer = if held_writer {
            Some(
                broken
                    .create(&upload(b"broken"), "deferred-broken")
                    .await
                    .map_err(api_failure)?
                    .body
                    .resource
                    .id,
            )
        } else {
            None
        };
        let mut connection = broken.f.owner.acquire().await?;
        let original_context: String =
            sqlx::query_scalar("SELECT COALESCE(current_setting('app.tenant_id',true),'')")
                .fetch_one(&mut *connection)
                .await?;
        let mut tx = sqlx::Connection::begin(&mut *connection).await?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(broken.f.actor.tenant_id.to_string())
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE instances SET slot_held=true,activity_kind='FILE_WRITE',activity_id=$3,activity_generation=runtime_generation,idle_since=NULL WHERE tenant_id=$1 AND id=$2")
            .bind(broken.f.actor.tenant_id)
            .bind(broken.instance.id)
            .bind(Uuid::new_v4())
            .execute(&mut *tx)
            .await?;
        if let Some(transfer) = broken_transfer {
            let queued = sqlx::query("UPDATE file_transfers SET updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
                .bind(broken.f.actor.tenant_id)
                .bind(transfer)
                .execute(&mut *tx)
                .await?;
            assert_eq!(queued.rows_affected(), 1);
        }
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(right.f.actor.tenant_id.to_string())
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE file_transfers SET updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2",
        )
        .bind(right.f.actor.tenant_id)
        .bind(right_upload.body.resource.id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
            .bind(&unrelated_tenant)
            .execute(&mut *tx)
            .await?;
        sqlx::query("SAVEPOINT activity_validation")
            .execute(&mut *tx)
            .await?;
        // Flush only the intended trigger family so an instance check cannot
        // accidentally substitute for proof of the transfer NEW.instance_id path.
        let check = if held_writer {
            "SET CONSTRAINTS transfer_file_activity_match IMMEDIATE"
        } else {
            "SET CONSTRAINTS instance_file_activity_match IMMEDIATE"
        };
        let error = match sqlx::query(check).execute(&mut *tx).await {
            Err(error) => error,
            Ok(_) => anyhow::bail!("unrelated tenant context hid invalid file activity"),
        };
        let database_error = error
            .as_database_error()
            .context("file activity constraint error")?;
        assert_eq!(database_error.code().as_deref(), Some("23514"));
        assert_eq!(
            database_error.message(),
            if held_writer {
                "file writer slot requires exact activity identity"
            } else {
                "file activity requires held file slot"
            }
        );
        sqlx::query("ROLLBACK TO SAVEPOINT activity_validation")
            .execute(&mut *tx)
            .await?;
        let after_failure: (String, i64) = sqlx::query_as(
            "SELECT current_setting('app.tenant_id',true),(SELECT count(*) FROM instances)",
        )
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(after_failure, (unrelated_tenant.clone(), 0));
        tx.rollback().await?;
        let after_rollback: String =
            sqlx::query_scalar("SELECT COALESCE(current_setting('app.tenant_id',true),'')")
                .fetch_one(&mut *connection)
                .await?;
        assert_eq!(after_rollback, original_context);
    }
    Ok(())
}

async fn initialize(owner: &sqlx::PgPool) -> anyhow::Result<()> {
    SCHEMA
        .get_or_try_init(|| async {
            let migrated: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=36 AND success)",
            )
            .fetch_one(owner)
            .await?;
            ensure!(
                migrated,
                "file transfer tests require completed migration 0036"
            );
            for script in [
                include_str!("../scripts/sql/gateway-role.sql"),
                include_str!("../scripts/sql/worker-role.sql"),
                include_str!("../scripts/sql/termination-role.sql"),
            ] {
                sqlx::raw_sql(script).execute(owner).await?;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await?;
    Ok(())
}
fn checksum(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn upload(bytes: &[u8]) -> CreateFileTransfer {
    CreateFileTransfer::Upload {
        path: RelativeFilePath::new("input/data.bin".into()).unwrap(),
        byte_length: bytes.len() as u64,
        sha256: checksum(bytes),
        replace: false,
        timeout_seconds: 60,
    }
}
fn download() -> CreateFileTransfer {
    CreateFileTransfer::Download {
        path: RelativeFilePath::new("output/data.bin".into()).unwrap(),
        max_bytes: 1024,
        timeout_seconds: 60,
    }
}
struct Ready {
    f: Fixture,
    gateway: sandbox_platform::db::Database,
    instance: Instance,
    identity: DispatchIdentity,
}
impl Ready {
    async fn new(count: i64, bytes: i64) -> anyhow::Result<Self> {
        let f = Fixture::new(10).await?;
        f.bind_client_id("file-transfer-fixture").await?;
        initialize(&f.owner).await?;
        let created = f.create("file-instance").await.map_err(api_failure)?;
        f.seed_observed_state(created.body.resource.id, "RUNNING")
            .await?;
        let mut tx = f.owner_transaction().await?;
        for action in ["files:read", "files:write"] {
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
        for project in [None, Some(f.request.project_id)] {
            for (dimension, limit) in [("FILE_TRANSFERS", count), ("FILE_TRANSFER_BYTES", bytes)] {
                sqlx::query("INSERT INTO quota_accounts(tenant_id,project_id,dimension,limit_value) VALUES($1,$2,$3,$4)").bind(f.actor.tenant_id).bind(project).bind(dimension).bind(limit).execute(&mut *tx).await?;
            }
        }
        let pod = Uuid::new_v4();
        sqlx::query("UPDATE instances SET pod_uid=$3,ready_generation=runtime_generation,ready_launch_id=launch_id,ready_pod_uid=$3,ready_cluster_epoch=cluster_epoch,ready_observed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(created.body.resource.id).bind(pod).execute(&mut *tx).await?;
        let(generation,launch,epoch):(i64,Uuid,Uuid)=sqlx::query_as("SELECT runtime_generation,launch_id,cluster_epoch FROM instances WHERE tenant_id=$1 AND id=$2").bind(f.actor.tenant_id).bind(created.body.resource.id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        f.seed_test_launch_certification(
            created.body.resource.id,
            chrono::Utc::now() + chrono::Duration::days(2),
        )
        .await?;
        let instance = f
            .database
            .get_instance(&f.actor, created.body.resource.id)
            .await
            .map_err(api_failure)?;
        let gateway = sandbox_platform::db::Database::connect(
            &std::env::var("TEST_GATEWAY_DATABASE_URL")?,
            4,
        )
        .await?;
        gateway.verify_runtime_role().await?;
        Ok(Self {
            f,
            gateway,
            instance,
            identity: DispatchIdentity {
                runtime_generation: generation,
                launch_id: launch,
                pod_uid: pod,
                cluster_epoch: epoch,
            },
        })
    }
    async fn create(
        &self,
        request: &CreateFileTransfer,
        key: &str,
    ) -> Result<
        sandbox_platform::file_transfer::FileTransferMutationResult,
        sandbox_platform::error::ApiError,
    > {
        let instance = self
            .f
            .database
            .get_instance(&self.f.actor, self.instance.id)
            .await?;
        self.f
            .database
            .create_file_transfer(
                &self.f.actor,
                self.instance.id,
                request,
                key,
                instance.spec_version,
                MAX_FILE_BYTES,
            )
            .await
    }
    async fn claim(&self, operation: Uuid) -> anyhow::Result<(OperationEngine, Claim)> {
        let mut tx = self.f.owner_transaction().await?;
        sqlx::query("UPDATE operations SET status='RUNNING',lease_owner='file-integration',lease_token=1,lease_until=clock_timestamp()+interval '5 minutes' WHERE tenant_id=$1 AND id=$2").bind(self.f.actor.tenant_id).bind(operation).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok((
            OperationEngine::new(self.gateway.clone(), "file-integration".into())?,
            Claim {
                tenant_id: self.f.actor.tenant_id,
                operation_id: operation,
                lease_token: 1,
            },
        ))
    }
    async fn admit(&self, id: Uuid, attempt: Uuid, review: Uuid) -> anyhow::Result<bool> {
        let mut tx = self.f.owner_transaction().await?;
        let result = sqlx::query_scalar("SELECT sandbox_check_file_connect($1,$2,$3,$4,true)")
            .bind(self.f.actor.tenant_id)
            .bind(id)
            .bind(attempt)
            .bind(review)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(result)
    }
    async fn budget(&self, dimension: &str) -> anyhow::Result<Vec<i64>> {
        let mut tx = self.f.owner_transaction().await?;
        let result=sqlx::query_scalar("SELECT pending+allocated FROM quota_accounts WHERE tenant_id=$1 AND dimension=$2 ORDER BY id").bind(self.f.actor.tenant_id).bind(dimension).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        Ok(result)
    }
    async fn idle_is_none(&self) -> anyhow::Result<bool> {
        let mut tx = self.f.owner_transaction().await?;
        let result = sqlx::query_scalar(
            "SELECT idle_since IS NULL FROM instances WHERE tenant_id=$1 AND id=$2",
        )
        .bind(self.f.actor.tenant_id)
        .bind(self.instance.id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result)
    }
    fn identity(&self) -> VerifiedIdentity {
        VerifiedIdentity {
            scope_profile: Default::default(),
            issuer: "https://issuer.example.test".into(),
            subject: self.f.actor.principal_id.to_string(),
            client_id: Some("file-transfer-fixture".into()),
            scopes: vec![],
            expires_at: chrono::Utc::now().timestamp() + 300,
        }
    }
}
#[tokio::test]
#[ignore = "requires real isolated PostgreSQL identities"]
async fn concurrent_upload_acceptance_one_slot_and_atomic_two_scope_budget() -> anyhow::Result<()> {
    let _serial = support::serial().await;
    let r = Ready::new(16, 1024).await?;
    let barrier = Arc::new(Barrier::new(16));
    let results = join_all((0..16).map(|i| {
        let b = barrier.clone();
        let db = r.f.database.clone();
        let actor = r.f.actor.clone();
        let instance = r.instance.clone();
        async move {
            b.wait().await;
            db.create_file_transfer(
                &actor,
                instance.id,
                &upload(b"abc"),
                &format!("concurrent-{i}"),
                instance.spec_version,
                MAX_FILE_BYTES,
            )
            .await
        }
    }))
    .await;
    let accepted: Vec<_> = results.iter().filter_map(|v| v.as_ref().ok()).collect();
    assert_eq!(accepted.len(), 1);
    assert_eq!(r.budget("FILE_TRANSFERS").await?, vec![1, 1]);
    assert_eq!(r.budget("FILE_TRANSFER_BYTES").await?, vec![3, 3]);
    let resource = &accepted[0].body.resource;
    assert_eq!(resource.status, "WAITING_UPLOAD");
    assert!(resource.slot_held);
    let mut tx = r.f.owner_transaction().await?;
    let created_version: i64 = sqlx::query_scalar("SELECT aggregate_version FROM domain_events WHERE tenant_id=$1 AND aggregate_id=$2 AND event_type='files:create'")
        .bind(r.f.actor.tenant_id).bind(resource.id).fetch_one(&mut *tx).await?;
    assert_eq!(created_version, resource.version);
    tx.commit().await?;
    let current =
        r.f.database
            .get_instance(&r.f.actor, r.instance.id)
            .await
            .map_err(api_failure)?;
    assert!(current.slot_held);
    assert!(r.idle_is_none().await?);
    Ok(())
}
#[tokio::test]
#[ignore = "requires real isolated PostgreSQL identities"]
async fn idempotent_replay_is_original_receipt_with_live_auth_and_tenant_rls() -> anyhow::Result<()>
{
    let _serial = support::serial().await;
    let r = Ready::new(4, 4096).await?;
    let first = r
        .create(&upload(b"abc"), "same")
        .await
        .map_err(api_failure)?;
    let replay =
        r.f.database
            .create_file_transfer(
                &r.f.actor,
                r.instance.id,
                &upload(b"abc"),
                "same",
                r.instance.spec_version,
                MAX_FILE_BYTES,
            )
            .await
            .map_err(api_failure)?;
    assert_eq!(first.body.resource.id, replay.body.resource.id);
    assert_eq!(first.body.resource.version, replay.body.resource.version);
    let mut other = r.f.actor.clone();
    other.tenant_id = Uuid::new_v4();
    assert_eq!(
        r.f.database
            .get_file_transfer(&other, first.body.resource.id)
            .await
            .err()
            .context("tenant denied")?
            .status
            .as_u16(),
        404
    );
    let mut tx = r.f.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='files:write'").bind(r.f.actor.tenant_id).bind(r.f.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    assert_eq!(
        r.f.database
            .create_file_transfer(
                &r.f.actor,
                r.instance.id,
                &upload(b"abc"),
                "same",
                r.instance.spec_version,
                MAX_FILE_BYTES
            )
            .await
            .err()
            .context("revoked replay")?
            .status
            .as_u16(),
        404
    );
    Ok(())
}
#[tokio::test]
#[ignore = "requires real isolated PostgreSQL identities"]
async fn download_holds_no_writer_slot_and_concurrency_still_suppresses_idle() -> anyhow::Result<()>
{
    let _serial = support::serial().await;
    let r = Ready::new(2, 2048).await?;
    let a = r.create(&download(), "read-a").await.map_err(api_failure)?;
    let b = r.create(&download(), "read-b").await.map_err(api_failure)?;
    assert!(!a.body.resource.slot_held && !b.body.resource.slot_held);
    let current =
        r.f.database
            .get_instance(&r.f.actor, r.instance.id)
            .await
            .map_err(api_failure)?;
    assert!(!current.slot_held && r.idle_is_none().await?);
    let error = r
        .create(&download(), "read-c")
        .await
        .err()
        .context("quota")?;
    assert_eq!(error.code, "QUOTA_EXCEEDED");
    assert_eq!(r.budget("FILE_TRANSFERS").await?, vec![2, 2]);
    let mut tx = r.f.owner_transaction().await?;
    sqlx::query("UPDATE instances SET idle_since=clock_timestamp()-interval '1 hour' WHERE tenant_id=$1 AND id=$2").bind(r.f.actor.tenant_id).bind(r.instance.id).execute(&mut *tx).await?;
    let idle: bool =
        sqlx::query_scalar("SELECT idle_since IS NULL FROM instances WHERE tenant_id=$1 AND id=$2")
            .bind(r.f.actor.tenant_id)
            .bind(r.instance.id)
            .fetch_one(&mut *tx)
            .await?;
    assert!(idle);
    tx.rollback().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "requires real isolated PostgreSQL identities"]
async fn committed_dispatch_is_single_connect_and_unknown_keeps_all_budgets() -> anyhow::Result<()>
{
    let _serial = support::serial().await;
    let r = Ready::new(2, 2048).await?;
    let accepted = r
        .create(&download(), "dispatch")
        .await
        .map_err(api_failure)?;
    let (engine, claim) = r.claim(accepted.body.operation.id).await?;
    let first = r
        .gateway
        .begin_file_transfer_dispatch(&engine, &claim, accepted.body.resource.id, r.identity)
        .await
        .map_err(api_failure)?;
    let second = r
        .gateway
        .begin_file_transfer_dispatch(&engine, &claim, accepted.body.resource.id, r.identity)
        .await
        .err()
        .context("one dispatch")?;
    assert_eq!(second.code, "DISPATCH_ALREADY_ATTEMPTED");
    let review = Uuid::new_v4();
    assert!(
        r.admit(
            accepted.body.resource.id,
            first.request.dispatch_attempt_id,
            review
        )
        .await?
    );
    assert!(
        r.admit(
            accepted.body.resource.id,
            first.request.dispatch_attempt_id,
            review
        )
        .await?
    );
    assert!(
        !r.admit(
            accepted.body.resource.id,
            first.request.dispatch_attempt_id,
            Uuid::new_v4()
        )
        .await?
    );
    r.f.database
        .mark_file_transfer_unknown(
            r.f.actor.tenant_id,
            accepted.body.resource.id,
            first.request.dispatch_attempt_id,
        )
        .await
        .map_err(api_failure)?;
    let unknown =
        r.f.database
            .get_file_transfer(&r.f.actor, accepted.body.resource.id)
            .await
            .map_err(api_failure)?;
    assert_eq!(unknown.status, "OUTCOME_UNKNOWN");
    assert_eq!(r.budget("FILE_TRANSFERS").await?, vec![1, 1]);
    assert_eq!(r.budget("FILE_TRANSFER_BYTES").await?, vec![1024, 1024]);
    assert!(
        r.gateway
            .complete_file_transfer_process(
                &engine,
                &claim,
                unknown.id,
                first.request.dispatch_attempt_id,
                &CompletedFileProcess {
                    trusted_exit_code: 0,
                    terminal: FileTerminal::Complete {
                        byte_length: 0,
                        sha256: checksum(b"")
                    }
                }
            )
            .await
            .is_err()
    );
    Ok(())
}
#[tokio::test]
#[ignore = "requires real isolated PostgreSQL identities"]
async fn upload_part_put_is_indexed_before_cloud_and_never_resent_when_unknown()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let r = Ready::new(2, 2048).await?;
    let a = r
        .create(&upload(b"abc"), "upload-part")
        .await
        .map_err(api_failure)?;
    let intent =
        r.f.database
            .begin_file_part_upload(
                &r.f.actor,
                a.body.resource.id,
                0,
                3,
                &checksum(b"abc"),
                a.body.resource.version,
            )
            .await
            .map_err(api_failure)?;
    assert!(!intent.already_stored);
    let duplicate =
        r.f.database
            .begin_file_part_upload(
                &r.f.actor,
                a.body.resource.id,
                0,
                3,
                &checksum(b"abc"),
                a.body.resource.version,
            )
            .await
            .err()
            .context("no replay")?;
    assert_eq!(duplicate.code, "FILE_PART_PUT_OUTCOME_UNKNOWN");
    assert!(
        r.f.database
            .begin_file_part_upload(
                &r.f.actor,
                a.body.resource.id,
                0,
                3,
                &checksum(b"xyz"),
                a.body.resource.version
            )
            .await
            .is_err()
    );
    r.f.database
        .publish_file_part(&r.f.actor, &intent, &intent.receipt)
        .await
        .map_err(api_failure)?;
    let replay =
        r.f.database
            .begin_file_part_upload(
                &r.f.actor,
                a.body.resource.id,
                0,
                3,
                &checksum(b"abc"),
                a.body.resource.version,
            )
            .await
            .map_err(api_failure)?;
    assert!(replay.already_stored);
    assert_eq!(replay.put_attempt_id, intent.put_attempt_id);
    Ok(())
}
#[tokio::test]
#[ignore = "requires real isolated PostgreSQL identities"]
async fn trusted_process_completion_releases_count_only_and_all_downloads_control_idle()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let r = Ready::new(4, 4096).await?;
    let a = r
        .create(&download(), "normal-a")
        .await
        .map_err(api_failure)?;
    let b = r
        .create(&download(), "normal-b")
        .await
        .map_err(api_failure)?;
    for (which, accepted) in [a, b].into_iter().enumerate() {
        let (engine, claim) = r.claim(accepted.body.operation.id).await?;
        let prepared = r
            .gateway
            .begin_file_transfer_dispatch(&engine, &claim, accepted.body.resource.id, r.identity)
            .await
            .map_err(api_failure)?;
        assert!(
            r.admit(
                accepted.body.resource.id,
                prepared.request.dispatch_attempt_id,
                Uuid::new_v4()
            )
            .await?
        );
        r.gateway
            .complete_file_transfer_process(
                &engine,
                &claim,
                accepted.body.resource.id,
                prepared.request.dispatch_attempt_id,
                &CompletedFileProcess {
                    trusted_exit_code: 0,
                    terminal: FileTerminal::Complete {
                        byte_length: 0,
                        sha256: checksum(b""),
                    },
                },
            )
            .await
            .map_err(api_failure)?;
        assert_eq!(!r.idle_is_none().await?, which == 1);
    }
    assert_eq!(r.budget("FILE_TRANSFERS").await?, vec![0, 0]);
    assert_eq!(r.budget("FILE_TRANSFER_BYTES").await?, vec![2048, 2048]);
    Ok(())
}

#[path = "file_transfer_http_support.rs"]
mod cloud_support;
#[tokio::test]
#[ignore = "requires real PostgreSQL and local signed OSS TCP"]
async fn upload_commit_independently_reads_hash_and_replays_without_another_cloud_call()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let r = Ready::new(2, 2048).await?;
    let cloud = cloud_support::Cloud::new().await?;
    let a = r
        .create(&upload(b"abc"), "cloud-upload")
        .await
        .map_err(api_failure)?;
    let intent =
        r.f.database
            .begin_file_part_upload(
                &r.f.actor,
                a.body.resource.id,
                0,
                3,
                &checksum(b"abc"),
                a.body.resource.version,
            )
            .await
            .map_err(api_failure)?;
    let receipt = cloud
        .writer()
        .put_part(intent.receipt.identity, b"abc".to_vec())
        .await?;
    r.f.database
        .publish_file_part(&r.f.actor, &intent, &receipt)
        .await
        .map_err(api_failure)?;
    let committed =
        r.f.database
            .commit_file_upload(
                &r.f.actor,
                a.body.resource.id,
                a.body.resource.version,
                "commit",
                &cloud.reader(),
                &r.identity(),
            )
            .await
            .map_err(api_failure)?;
    assert_eq!(committed.body.resource.status, "QUEUED");
    let mut tx = r.f.owner_transaction().await?;
    let frozen_version: i64 = sqlx::query_scalar("SELECT aggregate_version FROM domain_events WHERE tenant_id=$1 AND aggregate_id=$2 AND event_type='files:content_frozen'")
        .bind(r.f.actor.tenant_id).bind(a.body.resource.id).fetch_one(&mut *tx).await?;
    assert_eq!(frozen_version, committed.body.resource.version);
    tx.commit().await?;
    assert_eq!(
        committed.body.resource.storage_writer_status,
        "ACKNOWLEDGED"
    );
    let calls = cloud.wire.methods.lock().await.len();
    let replay =
        r.f.database
            .commit_file_upload(
                &r.f.actor,
                a.body.resource.id,
                a.body.resource.version,
                "commit",
                &cloud.reader(),
                &r.identity(),
            )
            .await
            .map_err(api_failure)?;
    assert_eq!(
        replay.body.resource.version,
        committed.body.resource.version
    );
    assert_eq!(cloud.wire.methods.lock().await.len(), calls);
    assert_eq!(r.budget("FILE_TRANSFER_BYTES").await?, vec![3, 3]);
    Ok(())
}
#[tokio::test]
#[ignore = "requires real PostgreSQL and local signed OSS TCP"]
async fn upload_commit_after_external_read_rechecks_identity_mapping() -> anyhow::Result<()> {
    let _serial = support::serial().await;
    let r = Ready::new(2, 2048).await?;
    let cloud = cloud_support::Cloud::new().await?;
    let a = r
        .create(&upload(b"abc"), "revoked-cloud-upload")
        .await
        .map_err(api_failure)?;
    let intent =
        r.f.database
            .begin_file_part_upload(
                &r.f.actor,
                a.body.resource.id,
                0,
                3,
                &checksum(b"abc"),
                a.body.resource.version,
            )
            .await
            .map_err(api_failure)?;
    let receipt = cloud
        .writer()
        .put_part(intent.receipt.identity, b"abc".to_vec())
        .await?;
    r.f.database
        .publish_file_part(&r.f.actor, &intent, &receipt)
        .await
        .map_err(api_failure)?;
    *cloud.wire.revoke_on_get.lock().await = Some((r.f.owner.clone(), r.f.actor.principal_id));
    assert!(
        r.f.database
            .commit_file_upload(
                &r.f.actor,
                a.body.resource.id,
                a.body.resource.version,
                "commit",
                &cloud.reader(),
                &r.identity()
            )
            .await
            .is_err()
    );
    let mut tx = r.f.owner_transaction().await?;
    let status: String =
        sqlx::query_scalar("SELECT status FROM file_transfers WHERE tenant_id=$1 AND id=$2")
            .bind(r.f.actor.tenant_id)
            .bind(a.body.resource.id)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(status, "WAITING_UPLOAD");
    tx.commit().await?;
    assert_eq!(r.budget("FILE_TRANSFER_BYTES").await?, vec![3, 3]);
    Ok(())
}
async fn fixture_expire_content(r: &Ready, id: Uuid) -> anyhow::Result<()> {
    // Only the isolated fixture owner changes clock fields. Runtime identities
    // cannot do this; no proof/process/parts/dispatch data is fabricated here.
    let mut tx = r.f.owner_transaction().await?;
    sqlx::raw_sql("ALTER TABLE file_transfers DISABLE TRIGGER file_evidence_guard")
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE file_transfers SET created_at=clock_timestamp()-interval '25 hours',content_expires_at=clock_timestamp()-interval '1 hour' WHERE tenant_id=$1 AND id=$2").bind(r.f.actor.tenant_id).bind(id).execute(&mut *tx).await?;
    sqlx::raw_sql("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *tx)
        .await?;
    sqlx::raw_sql("ALTER TABLE file_transfers ENABLE TRIGGER file_evidence_guard")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "requires real PostgreSQL and local signed OSS TCP"]
async fn byte_cleanup_requires_acknowledged_put_and_actual_delete_head_absence()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let r = Ready::new(4, 4096).await?;
    let cloud = cloud_support::Cloud::new().await?;
    let worker =
        sandbox_platform::db::Database::connect(&std::env::var("TEST_WORKER_DATABASE_URL")?, 4)
            .await?;
    for (n, ack) in [true, false].into_iter().enumerate() {
        let a = r
            .create(&download(), &format!("cleanup-{n}"))
            .await
            .map_err(api_failure)?;
        let (engine, claim) = r.claim(a.body.operation.id).await?;
        let p = r
            .gateway
            .begin_file_transfer_dispatch(&engine, &claim, a.body.resource.id, r.identity)
            .await
            .map_err(api_failure)?;
        assert!(
            r.admit(
                a.body.resource.id,
                p.request.dispatch_attempt_id,
                Uuid::new_v4()
            )
            .await?
        );
        let intent = r
            .gateway
            .begin_download_file_part(
                &engine,
                &claim,
                a.body.resource.id,
                p.request.dispatch_attempt_id,
                0,
                b"abc",
            )
            .await
            .map_err(api_failure)?;
        // The second object exists in cloud but its returned ACK never reaches
        // the durable ledger, as with a crash after PUT and before publication.
        let receipt = cloud
            .writer()
            .put_part(intent.receipt.identity, b"abc".to_vec())
            .await?;
        if ack {
            r.gateway
                .publish_download_file_part(
                    &engine,
                    &claim,
                    a.body.resource.id,
                    p.request.dispatch_attempt_id,
                    &intent,
                    &receipt,
                )
                .await
                .map_err(api_failure)?;
        }
        let terminal = if ack {
            FileTerminal::Complete {
                byte_length: 3,
                sha256: checksum(b"abc"),
            }
        } else {
            FileTerminal::Error(
                sandbox_platform::file_transfer::protocol::FileFailureCode::IoFailed,
            )
        };
        r.gateway
            .complete_file_transfer_process(
                &engine,
                &claim,
                a.body.resource.id,
                p.request.dispatch_attempt_id,
                &CompletedFileProcess {
                    trusted_exit_code: 0,
                    terminal,
                },
            )
            .await
            .map_err(api_failure)?;
        fixture_expire_content(&r, a.body.resource.id).await?;
        let batch = worker
            .prepare_file_cleanup(r.f.actor.tenant_id, a.body.resource.id)
            .await
            .map_err(api_failure)?
            .context("cleanup batch")?;
        assert_eq!(batch.writer_outcome_unknown, !ack);
        let observed = cloud.cleaner().delete_part(&intent.receipt).await?;
        assert_eq!(
            worker
                .record_file_part_cleanup(&observed)
                .await
                .map_err(api_failure)?,
            ack
        );
        assert_eq!(
            worker
                .finish_file_cleanup(r.f.actor.tenant_id, a.body.resource.id)
                .await
                .map_err(api_failure)?,
            ack
        );
        assert_eq!(
            worker
                .finish_file_cleanup(r.f.actor.tenant_id, a.body.resource.id)
                .await
                .map_err(api_failure)?,
            ack
        );
        let mut tx = r.f.owner_transaction().await?;
        let events: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND resource_id=$2 AND action='files:content_cleaned'),(SELECT count(*) FROM domain_events WHERE tenant_id=$1 AND aggregate_id=$2 AND event_type='files:content_cleaned')")
            .bind(r.f.actor.tenant_id).bind(a.body.resource.id).fetch_one(&mut *tx).await?;
        assert_eq!(events, if ack { (1, 1) } else { (0, 0) });
        if ack {
            let matching_version: bool = sqlx::query_scalar("SELECT e.aggregate_version=f.version FROM domain_events e JOIN file_transfers f ON f.tenant_id=e.tenant_id AND f.id=e.aggregate_id WHERE e.tenant_id=$1 AND e.aggregate_id=$2 AND e.event_type='files:content_cleaned'")
                .bind(r.f.actor.tenant_id).bind(a.body.resource.id).fetch_one(&mut *tx).await?;
            assert!(matching_version);
        }
        tx.commit().await?;
    }
    assert_eq!(r.budget("FILE_TRANSFERS").await?, vec![0, 0]);
    assert_eq!(r.budget("FILE_TRANSFER_BYTES").await?, vec![1024, 1024]);
    Ok(())
}
#[tokio::test]
#[ignore = "requires real PostgreSQL event-head locking and immutable deadlines"]
async fn dispatch_after_event_head_wait_rechecks_deadline_before_committing_attempt()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let r = Ready::new(4, 4096).await?;
    let request = CreateFileTransfer::Download {
        path: RelativeFilePath::new("output/data.bin".into())?,
        max_bytes: 1024,
        timeout_seconds: 1,
    };
    let accepted = r
        .create(&request, "deadline-after-event-head")
        .await
        .map_err(api_failure)?;
    let (engine, claim) = r.claim(accepted.body.operation.id).await?;
    let mut head = r.f.owner_transaction().await?;
    sqlx::query("SELECT last_sequence FROM event_stream_heads WHERE tenant_id=$1 AND project_id=$2 FOR UPDATE")
        .bind(r.f.actor.tenant_id).bind(r.f.request.project_id).fetch_one(&mut *head).await?;
    let gateway = r.gateway.clone();
    let transfer_id = accepted.body.resource.id;
    let identity = r.identity;
    let pending = tokio::spawn(async move {
        gateway
            .begin_file_transfer_dispatch(&engine, &claim, transfer_id, identity)
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(1250)).await;
    head.commit().await?;
    let error = pending.await?.err().context("expired dispatch must fail")?;
    assert_eq!(error.code, "FILE_DISPATCH_AUTHORITY_CHANGED");
    let mut tx = r.f.owner_transaction().await?;
    let state: (String, Option<Uuid>) = sqlx::query_as(
        "SELECT status,dispatch_attempt_id FROM file_transfers WHERE tenant_id=$1 AND id=$2",
    )
    .bind(r.f.actor.tenant_id)
    .bind(transfer_id)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(state, ("QUEUED".into(), None));
    tx.commit().await?;
    assert_eq!(r.budget("FILE_TRANSFERS").await?, vec![1, 1]);
    assert_eq!(r.budget("FILE_TRANSFER_BYTES").await?, vec![1024, 1024]);
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL plus local JWT/JWKS/API/OSS TCP"]
async fn signed_microservice_api_upload_commit_and_verified_download_use_real_tcp()
-> anyhow::Result<()> {
    use axum::{Router, routing::get};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use sandbox_platform::{
        api::{AppState, router_with_components},
        auth::{AuthConfig, JwtAuthenticator},
        file_api::FileApiRuntime,
    };
    let _serial = support::serial().await;
    let r = Ready::new(4, 4096).await?;
    let mut tx = r.f.owner_transaction().await?;
    sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,'capabilities:read')")
        .bind(r.f.actor.tenant_id).bind(r.f.request.project_id).bind(r.f.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let cloud = cloud_support::Cloud::new().await?;
    let jwk: serde_json::Value = serde_json::from_str(include_str!("fixtures/auth/jwk-a.json"))?;
    let kid = jwk["kid"].as_str().context("kid")?.to_owned();
    let keys = serde_json::json!({"keys":[jwk]});
    let jwks = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let jwks_addr = jwks.local_addr()?;
    let jwks_task = tokio::spawn(async move {
        axum::serve(
            jwks,
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
    let auth = JwtAuthenticator::new(AuthConfig {
        scope_profile: Default::default(),
        issuer: "https://issuer.example.test".into(),
        audience: "sandbox-api".into(),
        jwks_url: format!("http://{jwks_addr}/jwks"),
        required_scopes: vec!["sandbox:access".into()],
        jwks_ttl_seconds: 300,
        clock_skew_seconds: 0,
        allow_loopback_http: true,
        max_token_lifetime_seconds: 300,
    })?;
    let app = Arc::new(AppState {
        output_reader: None,
        metrics: None,
        cursor_signer: sandbox_platform::history::CursorSigner::from_json(include_str!(
            "fixtures/history/cursor-keys.json"
        ))?,
        database: r.f.database.clone(),
        auth,
        default_ttl_seconds: 300,
        max_ttl_seconds: 86400,
    });
    let files = Arc::new(FileApiRuntime {
        app: app.clone(),
        writer: cloud.writer(),
        reader: cloud.reader(),
        max_file_bytes: MAX_FILE_BYTES,
    });
    files.check_schema().await?;
    let shutdown = tokio_util::sync::CancellationToken::new();
    let routes = router_with_components(app, shutdown.clone(), None, Some(files));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let api = tokio::spawn(async move { axum::serve(listener, routes).await });
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("at+jwt".into());
    header.kid = Some(kid);
    let now = chrono::Utc::now().timestamp();
    let token = encode(
        &header,
        &serde_json::json!({"iss":"https://issuer.example.test","sub":r.f.actor.principal_id.to_string(),"aud":"sandbox-api","client_id":"file-transfer-fixture","jti":Uuid::new_v4(),"iat":now,"exp":now+300,"scope":"sandbox:access"}),
        &EncodingKey::from_rsa_der(include_bytes!("fixtures/auth/rsa-a.der")),
    )?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let auth_request = |method: reqwest::Method, path: String| {
        client
            .request(method, format!("{origin}{path}"))
            .bearer_auth(&token)
            .header("x-tenant-id", r.f.actor.tenant_id.to_string())
    };
    let capabilities = auth_request(
        reqwest::Method::GET,
        format!("/v1/capabilities?project_id={}", r.f.request.project_id),
    )
    .send()
    .await?;
    assert_eq!(capabilities.status().as_u16(), 200);
    let capabilities: serde_json::Value = capabilities.json().await?;
    assert_eq!(capabilities["api_features"]["file_transfer"], true);
    assert_eq!(capabilities["runtime_certification"], "NOT_ASSERTED");
    let response = auth_request(
        reqwest::Method::POST,
        format!("/v1/instances/{}/file-transfers", r.instance.id),
    )
    .header("if-match", format!("\"{}\"", r.instance.spec_version))
    .header("idempotency-key", "api-upload")
    .json(&upload(b"abc"))
    .send()
    .await?;
    assert_eq!(response.status().as_u16(), 202);
    assert!(response.headers().get("content-location").is_some());
    let accepted: sandbox_platform::file_transfer::FileTransferAccepted = response.json().await?;
    let part_path = format!("/v1/file-transfers/{}/content/0", accepted.resource.id);
    for _ in 0..2 {
        let response = auth_request(reqwest::Method::PUT, part_path.clone())
            .header("if-match", "\"1\"")
            .header("content-type", "application/octet-stream")
            .header("content-length", "3")
            .header("x-content-sha256", checksum(b"abc"))
            .body(b"abc".to_vec())
            .send()
            .await?;
        assert_eq!(response.status().as_u16(), 200);
        let text = response.text().await?;
        assert!(!text.contains("object_key"));
    }
    assert_eq!(
        cloud
            .wire
            .methods
            .lock()
            .await
            .iter()
            .filter(|m| m.as_str() == "PUT")
            .count(),
        1
    );
    let frozen = auth_request(
        reqwest::Method::POST,
        format!("/v1/file-transfers/{}/content/commit", accepted.resource.id),
    )
    .header("if-match", "\"1\"")
    .header("idempotency-key", "api-upload-commit")
    .json(&serde_json::json!({}))
    .send()
    .await?;
    assert_eq!(frozen.status().as_u16(), 202);
    let frozen: sandbox_platform::file_transfer::FileTransferAccepted = frozen.json().await?;
    assert_eq!(frozen.resource.content_status, "FROZEN");
    let a = r
        .create(&download(), "api-download")
        .await
        .map_err(api_failure)?;
    let (engine, claim) = r.claim(a.body.operation.id).await?;
    let p = r
        .gateway
        .begin_file_transfer_dispatch(&engine, &claim, a.body.resource.id, r.identity)
        .await
        .map_err(api_failure)?;
    assert!(
        r.admit(
            a.body.resource.id,
            p.request.dispatch_attempt_id,
            Uuid::new_v4()
        )
        .await?
    );
    let intent = r
        .gateway
        .begin_download_file_part(
            &engine,
            &claim,
            a.body.resource.id,
            p.request.dispatch_attempt_id,
            0,
            b"xyz",
        )
        .await
        .map_err(api_failure)?;
    let receipt = cloud
        .writer()
        .put_part(intent.receipt.identity, b"xyz".to_vec())
        .await?;
    r.gateway
        .publish_download_file_part(
            &engine,
            &claim,
            a.body.resource.id,
            p.request.dispatch_attempt_id,
            &intent,
            &receipt,
        )
        .await
        .map_err(api_failure)?;
    r.gateway
        .complete_file_transfer_process(
            &engine,
            &claim,
            a.body.resource.id,
            p.request.dispatch_attempt_id,
            &CompletedFileProcess {
                trusted_exit_code: 0,
                terminal: FileTerminal::Complete {
                    byte_length: 3,
                    sha256: checksum(b"xyz"),
                },
            },
        )
        .await
        .map_err(api_failure)?;
    let response = auth_request(
        reqwest::Method::GET,
        format!("/v1/file-transfers/{}/content", a.body.resource.id),
    )
    .send()
    .await?;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .context("download type")?,
        "application/octet-stream"
    );
    assert_eq!(response.bytes().await?.as_ref(), b"xyz");
    let wrong = client
        .get(format!("{origin}/v1/file-transfers/{}", a.body.resource.id))
        .bearer_auth(&token)
        .header("x-tenant-id", Uuid::new_v4().to_string())
        .send()
        .await?;
    assert_eq!(wrong.status().as_u16(), 404);
    let mut tx = r.f.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND principal_id=$2 AND action='files:read'").bind(r.f.actor.tenant_id).bind(r.f.actor.principal_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let denied = auth_request(
        reqwest::Method::GET,
        format!("/v1/file-transfers/{}/content", a.body.resource.id),
    )
    .send()
    .await?;
    assert_eq!(denied.status().as_u16(), 404);
    shutdown.cancel();
    api.abort();
    jwks_task.abort();
    Ok(())
}
