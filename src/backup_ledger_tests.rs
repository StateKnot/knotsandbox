use super::*;
use crate::{
    domain::InstanceAction,
    model::StartRequest,
    termination_ledger::tests::{FixtureRuntime, cleanup_runtime},
    test_support_db::{self, VerifiedFixtureConnections, VerifiedRuntimeDatabase, api_failure},
};
use anyhow::{Context, ensure};
#[path = "backup_http_tests.rs"]
mod http_tests;
pub(crate) struct Fixture {
    pub(crate) base: FixtureRuntime,
    pub(crate) profile: Uuid,
    pub(crate) backup: OperationEngine,
}
impl Fixture {
    // Test-only composition of a normally activated immutable profile. This
    // never registers/enables a profile or supplies a production capability.
    pub(crate) async fn from_activated_profile(
        base: FixtureRuntime,
        profile: Uuid,
        backup: &VerifiedRuntimeDatabase,
    ) -> anyhow::Result<Self> {
        let mut tx = base.f.owner_transaction().await?;
        let normal: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM backup_profiles p WHERE p.id=$1 AND p.cluster_epoch=$2 AND p.enabled AND p.certified_until>clock_timestamp()+interval '6 hours' AND EXISTS(SELECT 1 FROM backup_profile_actions a WHERE a.profile_id=p.id AND a.action='REGISTER') AND EXISTS(SELECT 1 FROM backup_profile_actions a WHERE a.profile_id=p.id AND a.action='ACTIVATE'))")
            .bind(profile).bind(base.node.cluster_epoch).fetch_one(&mut *tx).await?;
        ensure!(
            normal,
            "source profile must have normal owner registration and activation"
        );
        for project in [None, Some(base.launch.project_id)] {
            for action in ["backups:create", "backups:read"] {
                sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
                    .bind(base.f.actor.tenant_id).bind(project).bind(base.f.actor.principal_id).bind(action).execute(&mut *tx).await?;
            }
            for dimension in ["BACKUP_GIB", "BACKUP_TEMP_GIB"] {
                sqlx::query("INSERT INTO quota_accounts(tenant_id,project_id,dimension,limit_value) VALUES($1,$2,$3,100)")
                    .bind(base.f.actor.tenant_id).bind(project).bind(dimension).execute(&mut *tx).await?;
            }
        }
        tx.commit().await?;
        let database = backup.database_for("sandbox_backup")?;
        database.verify_runtime_role().await?;
        Ok(Self {
            base,
            profile,
            backup: OperationEngine::new(database, format!("matched-source-{}", Uuid::new_v4()))?,
        })
    }
    pub(crate) async fn new(stopped: bool) -> anyhow::Result<Self> {
        Self::with_cloud(stopped, cloud_settings()).await
    }
    pub(super) async fn with_cloud(stopped: bool, cloud: Value) -> anyhow::Result<Self> {
        Self::with_cloud_inner(stopped, cloud, None).await
    }
    pub(crate) async fn new_with_verified_connections(
        stopped: bool,
        fixture: &VerifiedFixtureConnections,
        termination: &VerifiedRuntimeDatabase,
        backup: &VerifiedRuntimeDatabase,
    ) -> anyhow::Result<Self> {
        Self::with_cloud_inner(
            stopped,
            cloud_settings(),
            Some((fixture, termination, backup)),
        )
        .await
    }
    async fn with_cloud_inner(
        stopped: bool,
        cloud: Value,
        verified: Option<(
            &VerifiedFixtureConnections,
            &VerifiedRuntimeDatabase,
            &VerifiedRuntimeDatabase,
        )>,
    ) -> anyhow::Result<Self> {
        let base = if let Some((fixture, termination, _)) = verified {
            FixtureRuntime::new_with_verified_connections(true, fixture, termination).await?
        } else {
            FixtureRuntime::new(true).await?
        };
        base.running().await?;
        if stopped {
            let stop = base.accept(InstanceAction::Stop).await?;
            let (proof, id) = base.proof(&stop).await?;
            let (runtime, _) = cleanup_runtime(&base.launch, false);
            let cleanup = runtime.cleanup(&proof).await?.context("cleanup")?;
            base.engine
                .database
                .complete_termination(&base.engine, &stop, id, &cleanup)
                .await
                .map_err(api_failure)?;
        }
        if verified.is_none() {
            sqlx::raw_sql(include_str!("../scripts/sql/backup-role.sql"))
                .execute(&base.f.owner)
                .await?;
        }
        let mut tx = base.f.owner_transaction().await?;
        let profile = Uuid::new_v4();
        sqlx::query("INSERT INTO backup_profiles(id,cluster_epoch,enabled,certification_sha256,certified_until,image,snapshot_class,clone_storage_class,password_secret,signing_private_secret,signing_public_secret,settings) VALUES($1,$2,true,$3,clock_timestamp()+interval '1 day',$4,'snapshot-retain','backup-retain','sbx-bkey-password','sbx-bkey-signing','sbx-bkey-public',$5)")
   .bind(profile).bind(base.node.cluster_epoch).bind("a".repeat(64)).bind(format!("registry.fixture.invalid/backup@sha256:{}","b".repeat(64))).bind(cloud).execute(&mut *tx).await?;
        for project in [None, Some(base.launch.project_id)] {
            for action in ["backups:create", "backups:read"] {
                sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING").bind(base.f.actor.tenant_id).bind(project).bind(base.f.actor.principal_id).bind(action).execute(&mut *tx).await?;
            }
            for dim in ["BACKUP_GIB", "BACKUP_TEMP_GIB"] {
                sqlx::query("INSERT INTO quota_accounts(tenant_id,project_id,dimension,limit_value) VALUES($1,$2,$3,100)").bind(base.f.actor.tenant_id).bind(project).bind(dim).execute(&mut *tx).await?;
            }
        }
        tx.commit().await?;
        let db = if let Some((_, _, backup)) = verified {
            backup.database_for("sandbox_backup")?
        } else {
            let url = std::env::var("TEST_BACKUP_DATABASE_URL")
                .context("TEST_BACKUP_DATABASE_URL required")?;
            let parsed = url::Url::parse(&url)?;
            ensure!(
                parsed.username() == "sandbox_backup" && parsed.path().ends_with("_test"),
                "isolated backup test role required"
            );
            let db = Database::connect(&url, 4).await?;
            db.verify_runtime_role().await?;
            db
        };
        let backup = OperationEngine::new(db, format!("backup-test-{}", Uuid::new_v4()))?;
        Ok(Self {
            base,
            profile,
            backup,
        })
    }
    pub(super) async fn accept(&self, key: &str) -> Result<BackupMutationResult, ApiError> {
        self.base
            .f
            .database
            .create_backup(
                &self.base.f.actor,
                self.base.launch.workspace_id,
                &CreateBackup {
                    profile_id: self.profile,
                    retention_days: 31,
                },
                key,
                1,
            )
            .await
    }
    pub(super) async fn claim(&self, operation: Uuid) -> anyhow::Result<Claim> {
        let mut tx = self.base.f.owner_transaction().await?;
        sqlx::query("UPDATE operations SET next_attempt_at=(SELECT COALESCE(min(eligible_at),clock_timestamp())-interval '1 day' FROM operation_dispatch WHERE queue_role='BACKUP') WHERE tenant_id=$1 AND id=$2").bind(self.base.f.actor.tenant_id).bind(operation).execute(&mut *tx).await?;
        tx.commit().await?;
        let claim = self
            .backup
            .claim_backup()
            .await
            .map_err(api_failure)?
            .context("claim")?;
        ensure!(claim.operation_id == operation, "own operation required");
        Ok(claim)
    }
}
#[tokio::test]
#[ignore = "requires isolated PostgreSQL and component roles"]
async fn cold_backup_acceptance_is_atomic_idempotent_and_blocks_start() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = Fixture::new(true).await?;
    let (a, b) = tokio::join!(f.accept("cold-idempotency"), f.accept("cold-idempotency"));
    let a = a.map_err(api_failure)?;
    let b = b.map_err(api_failure)?;
    assert_eq!(a.body.resource.id, b.body.resource.id);
    assert_eq!(a.body.resource.status, "QUEUED");
    let mut tx = f.base.f.owner_transaction().await?;
    let(holds,reservations,pending):(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM workspace_holds WHERE tenant_id=$1 AND reference_id=$2),(SELECT count(*) FROM quota_reservations WHERE tenant_id=$1 AND operation_id=$3),(SELECT sum(pending)::bigint FROM quota_accounts WHERE tenant_id=$1 AND dimension IN('BACKUP_GIB','BACKUP_TEMP_GIB'))").bind(f.base.f.actor.tenant_id).bind(a.body.resource.id).bind(a.body.operation.id).fetch_one(&mut *tx).await?;
    assert_eq!((holds, reservations, pending), (1, 8, 80));
    tx.commit().await?;
    let instance = f
        .base
        .f
        .database
        .get_instance(&f.base.f.actor, f.base.launch.instance_id)
        .await
        .map_err(api_failure)?;
    assert!(
        f.base
            .f
            .database
            .lifecycle_action(
                &f.base.f.actor,
                instance.id,
                InstanceAction::Start,
                &StartRequest {
                    ttl_seconds: Some(300)
                },
                "start-during-backup",
                instance.spec_version,
                3600,
                7200
            )
            .await
            .is_err()
    );
    let claim = f.claim(a.body.operation.id).await?;
    let plan = f
        .backup
        .database
        .prepare_backup_storage(&f.backup, &claim)
        .await
        .map_err(api_failure)?;
    assert_eq!(plan.source.pvc_uid, f.base.launch.pvc_uid);
    assert!(plan.snapshot.is_none());
    // Unknown/partial work cannot clear a hold, even from the controller role.
    let mut tx = f
        .backup
        .database
        .begin(f.base.f.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    let release = sqlx::query(
        "INSERT INTO workspace_hold_releases(tenant_id,hold_id,reason) VALUES($1,$2,'unsafe test')",
    )
    .bind(f.base.f.actor.tenant_id)
    .bind(plan.backup.hold_id)
    .execute(&mut *tx)
    .await;
    assert!(release.is_err());
    tx.rollback().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "requires isolated PostgreSQL and component roles"]
async fn running_source_and_quota_failure_create_no_hold_or_remote_intent() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = Fixture::new(false).await?;
    assert_eq!(
        f.accept("hot-denied")
            .await
            .err()
            .context("reject hot")?
            .code,
        "BACKUP_BLOCKED"
    );
    let mut tx = f.base.f.owner_transaction().await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM workspace_holds WHERE tenant_id=$1")
        .bind(f.base.f.actor.tenant_id)
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(count, 0);
    tx.commit().await?;
    let f = Fixture::new(true).await?;
    let mut tx = f.base.f.owner_transaction().await?;
    sqlx::query(
        "UPDATE quota_accounts SET limit_value=0 WHERE tenant_id=$1 AND dimension='BACKUP_GIB'",
    )
    .bind(f.base.f.actor.tenant_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    assert!(f.accept("quota-denied").await.is_err());
    let mut tx = f.base.f.owner_transaction().await?;
    let counts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM backups WHERE tenant_id=$1),(SELECT count(*) FROM workspace_holds WHERE tenant_id=$1),(SELECT count(*) FROM operations WHERE tenant_id=$1 AND kind='BACKUP')").bind(f.base.f.actor.tenant_id).fetch_one(&mut *tx).await?;
    assert_eq!(counts, (0, 0, 0));
    tx.commit().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "requires isolated PostgreSQL and component roles"]
async fn snapshot_progress_rejects_lost_lease_and_revoked_authority() -> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = Fixture::new(true).await?;
    let accepted = f.accept("snapshot-fencing").await.map_err(api_failure)?;
    let claim = f.claim(accepted.body.operation.id).await?;
    let observation = SnapshotObservation {
        snapshot_uid: Uuid::new_v4(),
        ready: None,
    };
    f.backup
        .database
        .record_backup_snapshot(&f.backup, &claim, &observation)
        .await
        .map_err(api_failure)?;
    let mut tx = f.base.f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET lease_token=lease_token+1 WHERE tenant_id=$1 AND id=$2")
        .bind(claim.tenant_id)
        .bind(claim.operation_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let error = f
        .backup
        .database
        .record_backup_snapshot(&f.backup, &claim, &observation)
        .await
        .err()
        .context("lost lease")?;
    assert_eq!(error.code, "WORKER_LEASE_LOST");
    let mut tx = f.base.f.owner_transaction().await?;
    let status: String =
        sqlx::query_scalar("SELECT status FROM backups WHERE tenant_id=$1 AND id=$2")
            .bind(claim.tenant_id)
            .bind(accepted.body.resource.id)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(status, "SNAPSHOT_PENDING");
    tx.commit().await?;
    Ok(())
}

pub(super) fn cloud_settings() -> Value {
    use sha2::{Digest, Sha256};
    let bindings = [("password", "sbx-bkey-password", "password"), ("signing_private", "sbx-bkey-signing", "private.pem"), ("signing_public", "sbx-bkey-public", "public.pem")].into_iter().map(|(purpose,name,key)| (purpose.to_owned(),json!({"name":name,"uid":Uuid::new_v4(),"content_sha256":hex::encode(Sha256::digest(format!("test-only-backup-key-{key}")))}))).collect::<std::collections::BTreeMap<_,_>>();
    json!({"deployment":"sandbox","secret_bindings":bindings,"vault_retention_days":31,"clone_kms_key_id":"clone-key","signing_key_sha256":"a".repeat(64),"vault_endpoint":"https://oss-cn-hangzhou-internal.aliyuncs.com","key_ref":"backup/key-v1","region":"cn-hangzhou","account_id":"1234567890123456","bucket":"fixture-backup","vault_bucket":"fixture-backup-vault","kms_key_id":"repo-key","vault_kms_key_id":"vault-key","issuer":"https://issuer.fixture.invalid","oidc_provider_arn":"acs:ram::1234567890123456:oidc-provider/fixture","roles":(["backup","backup-export","restore"].into_iter().map(|role|(role.to_owned(),json!({"arn":format!("acs:ram::1234567890123456:role/sandbox-{role}"),"subject":format!("system:serviceaccount:sandbox-system:sandbox-{role}")}))).collect::<std::collections::BTreeMap<_,_>>())})
}
