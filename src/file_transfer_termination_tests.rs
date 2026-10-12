//! Real PG + authenticated mTLS with the existing controlled host/Kube fixture.
//! This verifies ledger trust boundaries; it is not real Kata/cloud acceptance.
use super::*;
use crate::execution::DispatchIdentity;
use crate::file_transfer::{
    CreateFileTransfer,
    path::{MAX_FILE_BYTES, RelativeFilePath},
};
#[tokio::test]
#[ignore = "requires isolated real PostgreSQL and local authenticated mTLS"]
async fn whole_vm_cleanup_closes_uploader_and_all_downloads_without_releasing_bytes()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let f = FixtureRuntime::new(true).await?;
    let migrated: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=36 AND success)",
    )
    .fetch_one(&f.f.owner)
    .await?;
    ensure!(
        migrated,
        "file VM closure tests require completed migration 0036"
    );
    f.running().await?;
    sqlx::raw_sql(include_str!("../scripts/sql/gateway-role.sql"))
        .execute(&f.f.owner)
        .await?;
    let mut tx = f.f.owner_transaction().await?;
    for action in ["files:read", "files:write"] {
        sqlx::query(
            "INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,$4)",
        )
        .bind(f.f.actor.tenant_id)
        .bind(f.launch.project_id)
        .bind(f.f.actor.principal_id)
        .bind(action)
        .execute(&mut *tx)
        .await?;
    }
    for project in [None, Some(f.launch.project_id)] {
        for (dimension, limit) in [
            ("FILE_TRANSFERS", 16_i64),
            ("FILE_TRANSFER_BYTES", 4096_i64),
        ] {
            sqlx::query("INSERT INTO quota_accounts(tenant_id,project_id,dimension,limit_value) VALUES($1,$2,$3,$4)").bind(f.f.actor.tenant_id).bind(project).bind(dimension).bind(limit).execute(&mut *tx).await?;
        }
    }
    sqlx::query("UPDATE instances SET ready_generation=runtime_generation,ready_launch_id=launch_id,ready_pod_uid=pod_uid,ready_cluster_epoch=cluster_epoch,ready_observed_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2").bind(f.f.actor.tenant_id).bind(f.launch.instance_id).execute(&mut *tx).await?;
    tx.commit().await?;
    let gateway = Database::connect(&std::env::var("TEST_GATEWAY_DATABASE_URL")?, 4).await?;
    let engine = OperationEngine::new(gateway.clone(), "file-vm-fixture".into())?;
    let mut ids = vec![];
    for n in 0..3 {
        let instance =
            f.f.database
                .get_instance(&f.f.actor, f.launch.instance_id)
                .await
                .map_err(api_failure)?;
        let request = if n == 0 {
            CreateFileTransfer::Upload {
                path: RelativeFilePath::new("upload.bin".into())?,
                byte_length: 3,
                sha256: hex::encode(Sha256::digest(b"abc")),
                replace: false,
                timeout_seconds: 60,
            }
        } else {
            CreateFileTransfer::Download {
                path: RelativeFilePath::new("download.bin".into())?,
                max_bytes: 1024,
                timeout_seconds: 60,
            }
        };
        let accepted =
            f.f.database
                .create_file_transfer(
                    &f.f.actor,
                    instance.id,
                    &request,
                    &format!("file-close-{n}"),
                    instance.spec_version,
                    MAX_FILE_BYTES,
                )
                .await
                .map_err(api_failure)?;
        ids.push(accepted.body.resource.id);
        if n == 2 {
            let mut tx = f.f.owner_transaction().await?;
            sqlx::query("UPDATE operations SET status='RUNNING',lease_owner='file-vm-fixture',lease_token=1,lease_until=clock_timestamp()+interval '5 minutes' WHERE tenant_id=$1 AND id=$2").bind(f.f.actor.tenant_id).bind(accepted.body.operation.id).execute(&mut *tx).await?;
            tx.commit().await?;
            let claim = Claim {
                tenant_id: f.f.actor.tenant_id,
                operation_id: accepted.body.operation.id,
                lease_token: 1,
            };
            let prepared = gateway
                .begin_file_transfer_dispatch(
                    &engine,
                    &claim,
                    accepted.body.resource.id,
                    DispatchIdentity {
                        runtime_generation: f.launch.generation,
                        launch_id: f.launch.launch_id,
                        pod_uid: f.launch.pod_uid,
                        cluster_epoch: f.node.cluster_epoch,
                    },
                )
                .await
                .map_err(api_failure)?;
            gateway
                .mark_file_transfer_unknown(
                    f.f.actor.tenant_id,
                    accepted.body.resource.id,
                    prepared.request.dispatch_attempt_id,
                )
                .await
                .map_err(api_failure)?;
        }
    }
    assert_eq!(f.pending_dimension("FILE_TRANSFERS").await?, 6);
    assert_eq!(f.pending_dimension("FILE_TRANSFER_BYTES").await?, 4102);
    let claim = f.accept(InstanceAction::Stop).await?;
    let (proof, id) = f.proof(&claim).await?;
    assert_eq!(f.pending_dimension("FILE_TRANSFERS").await?, 6);
    let (blocked, _) = cleanup_runtime(&f.launch, true);
    assert!(blocked.cleanup(&proof).await?.is_none());
    assert_eq!(f.pending_dimension("FILE_TRANSFERS").await?, 6);
    let (runtime, _) = cleanup_runtime(&f.launch, false);
    let cleanup = runtime
        .cleanup(&proof)
        .await?
        .context("independent cleanup")?;
    assert_eq!(
        f.engine
            .database
            .complete_termination(&f.engine, &claim, id, &cleanup)
            .await
            .map_err(api_failure)?,
        TerminationCompletion::Stopped
    );
    assert_eq!(f.pending_dimension("FILE_TRANSFERS").await?, 0);
    assert_eq!(f.pending_dimension("FILE_TRANSFER_BYTES").await?, 4102);
    assert_eq!(f.pending_dimension("CPU_MILLIS").await?, 0);
    for (n, transfer) in ids.iter().enumerate() {
        let got =
            f.f.database
                .get_file_transfer(&f.f.actor, *transfer)
                .await
                .map_err(api_failure)?;
        assert!(!got.slot_held);
        assert_eq!(got.process_status, "VM_TERMINATED");
        assert_eq!(
            got.status,
            if n == 2 {
                "OUTCOME_UNKNOWN"
            } else {
                "CANCELLED"
            }
        );
        let mut tx = f.f.owner_transaction().await?;
        let events: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND resource_id=$2 AND action='files:vm_terminated'),(SELECT count(*) FROM domain_events WHERE tenant_id=$1 AND aggregate_id=$2 AND event_type='files:vm_terminated')")
            .bind(f.f.actor.tenant_id).bind(transfer).fetch_one(&mut *tx).await?;
        assert_eq!(events, (1, 1));
        tx.commit().await?;
    }
    f.guard.shutdown().await?;
    Ok(())
}
