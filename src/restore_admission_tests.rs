//! Actual private admission methods against the narrow PostgreSQL role and
//! stateful Kubernetes API. No production apiserver certificate is fabricated.
use super::super::{admission::RestoreAdmissionService, ledger::JobPlan};
use crate::{
    admission::{AdmissionRequest, ControllerIdentity, ServiceIdentity},
    backup_admission::BackupAdmissionIdentities,
    backup_job::BackupJobRuntime,
    backup_manifest::NAMESPACE,
    db::Database,
    nodeguard::protocol::NodeBinding,
    termination_ledger::tests::FixtureRuntime,
    test_support_db::api_failure,
};
#[path = "restore_job_create_admission_tests.rs"]
mod job_create;

#[path = "restore_admission_commit_tests.rs"]
pub(super) mod commit;

use anyhow::{Context, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use uuid::Uuid;
fn request(value: Value, resource: &str, user: Value) -> anyhow::Result<AdmissionRequest> {
    Ok(serde_json::from_value(
        json!({"uid":Uuid::new_v4(),"resource":{"group":if resource=="jobs"{"batch"}else{""},"version":"v1","resource":resource},
        "operation":"CREATE","namespace":NAMESPACE,"name":value["metadata"]["name"],"userInfo":user,"object":value}),
    )?)
}
fn user(service: &RestoreAdmissionService) -> Value {
    json!({"username":service.identities.controller.username,"uid":service.identities.controller.uid})
}
fn job_user(service: &RestoreAdmissionService) -> Value {
    match &service.identities.job_controller {
        ControllerIdentity::ServiceAccount { username, uid } => {
            json!({"username":username,"uid":uid})
        }
        ControllerIdentity::ControlPlane { username } => {
            json!({"username":username,"uid":"","groups":["system:authenticated"]})
        }
    }
}
pub(super) async fn node_authority(
    database: &Database,
    tenant: Uuid,
    restore: Uuid,
    node: &NodeBinding,
    binding: bool,
    observation: bool,
) -> anyhow::Result<()> {
    let mut tx = database.begin(tenant).await.map_err(api_failure)?;
    let source: Uuid =
        sqlx::query_scalar("SELECT backup_id FROM restores WHERE tenant_id=$1 AND id=$2")
            .bind(tenant)
            .bind(restore)
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    for (query, expected) in [
        (
            "SELECT sandbox_restore_node_binding($1,$2,$3,$4,$5,$6)",
            binding,
        ),
        (
            "SELECT sandbox_restore_node_observation($1,$2,$3,$4,$5,$6)",
            observation,
        ),
    ] {
        let mut tx = database.begin(tenant).await.map_err(api_failure)?;
        let allowed: bool = sqlx::query_scalar(query)
            .bind(tenant)
            .bind(restore)
            .bind(node.node_uid)
            .bind(&node.node_name)
            .bind(node.boot_id)
            .bind(&node.profile_sha256)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            allowed, expected,
            "RESTORE node reader must separate new binding from historical observation"
        );
        tx.commit().await?;
        for field in [
            "tenant",
            "restore",
            "source_backup",
            "node_uid",
            "node_name",
            "boot",
            "profile",
        ] {
            let mut n = node.clone();
            let mut t = tenant;
            let mut r = restore;
            match field {
                "tenant" => t = Uuid::new_v4(),
                "restore" => r = Uuid::new_v4(),
                "source_backup" => r = source,
                "node_uid" => n.node_uid = Uuid::new_v4(),
                "node_name" => n.node_name = "unrelated-node".into(),
                "boot" => n.boot_id = Uuid::new_v4(),
                _ => n.profile_sha256 = "f".repeat(64),
            }
            let mut tx = database.begin(t).await.map_err(api_failure)?;
            let allowed: bool = sqlx::query_scalar(query)
                .bind(t)
                .bind(r)
                .bind(n.node_uid)
                .bind(n.node_name)
                .bind(n.boot_id)
                .bind(n.profile_sha256)
                .fetch_one(&mut *tx)
                .await?;
            assert!(
                !allowed,
                "changed {field} cannot adopt a RESTORE node grant"
            );
            tx.commit().await?;
        }
    }
    let mut tx = database.begin(tenant).await.map_err(api_failure)?;
    let legacy: bool = sqlx::query_scalar("SELECT sandbox_backup_node_binding($1,$2,$3,$4,$5,$6)")
        .bind(tenant)
        .bind(restore)
        .bind(node.node_uid)
        .bind(&node.node_name)
        .bind(node.boot_id)
        .bind(&node.profile_sha256)
        .fetch_one(&mut *tx)
        .await?;
    assert!(
        !legacy,
        "historical backup reader cannot authorize a RESTORE attempt"
    );
    let ordinary:bool=sqlx::query_scalar("SELECT sandbox_guarded_node_binding($1,(SELECT instance_id FROM restores WHERE tenant_id=$1 AND id=$2),$3,$4,$5,$6)")
        .bind(tenant).bind(restore).bind(node.node_uid).bind(&node.node_name).bind(node.boot_id).bind(&node.profile_sha256).fetch_one(&mut *tx).await?;
    assert!(
        !ordinary,
        "ordinary stopped target cannot borrow the RESTORE node grant"
    );
    tx.commit().await?;
    Ok(())
}
pub(super) async fn postwait_node_revocation(
    database: &Database,
    plan: &JobPlan,
    base: &FixtureRuntime,
) -> anyhow::Result<()> {
    let mut blocker = base.f.owner_transaction().await?;
    sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(plan.record.tenant_id)
        .bind(plan.record.workspace_id)
        .fetch_one(&mut *blocker)
        .await?;
    sqlx::query("UPDATE runtime_nodes SET enabled=false WHERE cluster_epoch=$1 AND node_uid=$2 AND boot_id=$3")
        .bind(base.node.cluster_epoch).bind(base.node.node_uid).bind(base.node.boot_id)
        .execute(&mut *blocker).await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    let query = async {
        let mut tx = database
            .begin(plan.record.tenant_id)
            .await
            .map_err(api_failure)?;
        let allowed: bool =
            sqlx::query_scalar("SELECT sandbox_restore_node_binding($1,$2,$3,$4,$5,$6)")
                .bind(plan.record.tenant_id)
                .bind(plan.record.id)
                .bind(base.node.node_uid)
                .bind(&base.node.node_name)
                .bind(base.node.boot_id)
                .bind(&base.node.profile_sha256)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        anyhow::Ok(allowed)
    };
    let (decision, released) = tokio::join!(query, async {
        let mut blocked = false;
        for _ in 0..30 {
            blocked=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename='sandbox_admission' AND $1=ANY(pg_blocking_pids(pid)))")
                .bind(pid).fetch_one(&base.f.owner).await?;
            if blocked {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        ensure!(
            blocked,
            "node binding must actually wait on the held restore workspace"
        );
        blocker.commit().await?;
        anyhow::Ok(())
    });
    released?;
    ensure!(
        !decision?,
        "post-wait disabled node cannot obtain a fresh restore binding"
    );
    // The already fixed historical permit remains observable for closure.
    node_authority(
        database,
        plan.record.tenant_id,
        plan.record.id,
        &base.node,
        false,
        true,
    )
    .await?;
    let mut tx = base.f.owner_transaction().await?;
    sqlx::query("UPDATE runtime_nodes SET enabled=true WHERE cluster_epoch=$1 AND node_uid=$2 AND boot_id=$3")
        .bind(base.node.cluster_epoch).bind(base.node.node_uid).bind(base.node.boot_id)
        .execute(&mut *tx).await?;
    tx.commit().await?;
    node_authority(
        database,
        plan.record.tenant_id,
        plan.record.id,
        &base.node,
        true,
        true,
    )
    .await?;
    eprintln!(
        "VERIFIED node binding actually waits on restore workspace lock and rejects committed node revocation; historical permit remains observable and fresh re-enable restores only the current exact binding"
    );
    Ok(())
}
pub(super) async fn prepare(
    database: Database,
    runtime: &BackupJobRuntime,
    plan: &JobPlan,
    base: &FixtureRuntime,
    objects: &Arc<Mutex<BTreeMap<String, Value>>>,
) -> anyhow::Result<(RestoreAdmissionService, (Uuid, Uuid))> {
    let service = RestoreAdmissionService {
        database,
        runtime: runtime.clone(),
        raw_scheduling: None,
        scheduler: ControllerIdentity::ControlPlane {
            username: "system:kube-scheduler".into(),
        },
        control_gc: ControllerIdentity::ControlPlane {
            username: "system:kube-controller-manager".into(),
        },
        identities: BackupAdmissionIdentities {
            controller: ServiceIdentity {
                username: "system:serviceaccount:sandbox-system:sandbox-backup-controller".into(),
                uid: Uuid::new_v4().to_string(),
            },
            job_controller: ControllerIdentity::ControlPlane {
                username: "system:kube-controller-manager".into(),
            },
        },
    };
    let observed = Box::pin(job_create::verify(&service, plan, &base.f.owner, objects)).await?;
    // All positive and negative CREATE bodies retain actual server preparation.
    // A stored RV is a GET fact and is removed from the CREATE review view only.
    let (prepared_config, prepared_job) = {
        let map = objects
            .lock()
            .map_err(|_| anyhow::anyhow!("prepared CREATE objects"))?;
        let mut config = map
            .get(&format!(
                "/api/v1/namespaces/{NAMESPACE}/configmaps/{}",
                crate::backup_manifest::config_name(plan.record.id)
            ))
            .cloned()
            .context("actual stored config")?;
        let mut job = map
            .get(&format!(
                "/apis/batch/v1/namespaces/{NAMESPACE}/jobs/{}",
                crate::nodeguard::protocol::backup_job_name(
                    plan.record.id,
                    crate::nodeguard::protocol::BackupStage::Restore
                )
            ))
            .cloned()
            .context("actual stored Job")?;
        config["metadata"]
            .as_object_mut()
            .context("config metadata")?
            .remove("resourceVersion");
        job["metadata"]
            .as_object_mut()
            .context("Job metadata")?
            .remove("resourceVersion");
        (config, job)
    };
    for (kind, object) in [
        ("configmaps", prepared_config),
        ("jobs", prepared_job.clone()),
    ] {
        let good = request(object, kind, user(&service))?;
        service
            .decide(&good)
            .await
            .map_err(|e| anyhow::anyhow!("create {} {}", e.code, e.message))?;
        for field in ["identity", "scope", "dry_run", "subresource", "manifest"] {
            let mut changed = good.clone();
            match field {
                "identity" => changed.user_info.uid = Uuid::new_v4().to_string(),
                "scope" => {
                    let value = changed.object.as_mut().context("object")?;
                    value["metadata"]["labels"]["sandbox.platform/backup-attempt-id"] =
                        json!(Uuid::new_v4());
                }
                "dry_run" => changed.dry_run = true,
                "subresource" => changed.sub_resource = "status".into(),
                _ => {
                    let value = changed.object.as_mut().context("object")?;
                    value["metadata"]["annotations"] = json!({"unsafe-admission":"changed"});
                }
            }
            assert!(
                service.decide(&changed).await.is_err(),
                "changed {kind} {field} must be rejected"
            );
        }
    }
    let original = objects
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture lock"))?
        .get(&format!(
            "/api/v1/namespaces/{NAMESPACE}/secrets/{}",
            plan.cloud.secret_bindings.password.name
        ))
        .cloned()
        .context("secret")?;
    let secret_path = format!(
        "/api/v1/namespaces/{NAMESPACE}/secrets/{}",
        plan.cloud.secret_bindings.password.name
    );
    {
        let mut map = objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture lock"))?;
        let value = map.get_mut(&secret_path).context("secret")?;
        value["metadata"]["uid"] = json!(Uuid::new_v4());
    }
    let good = request(prepared_job, "jobs", user(&service))?;
    assert!(
        service.decide(&good).await.is_err(),
        "same-name Secret replacement rejected"
    );
    objects
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture lock"))?
        .insert(secret_path, original);
    let mut tx = base.f.owner_transaction().await?;
    sqlx::query("UPDATE backup_profiles SET enabled=false WHERE id=$1")
        .bind(plan.record.profile_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    assert!(
        service.decide(&good).await.is_err(),
        "disabled current profile rejected"
    );
    let mut tx = base.f.owner_transaction().await?;
    sqlx::query("UPDATE backup_profiles SET enabled=true WHERE id=$1")
        .bind(plan.record.profile_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let mut tx = base.f.owner_transaction().await?;
    let class_change = sqlx::query(
        "UPDATE backup_profiles SET clone_storage_class='unreviewed-class' WHERE id=$1",
    )
    .bind(plan.record.profile_id)
    .execute(&mut *tx)
    .await
    .err()
    .context("a reviewed profile class must remain immutable")?;
    ensure!(
        class_change
            .as_database_error()
            .and_then(|e| e.code())
            .as_deref()
            == Some("23514"),
        "the actual profile guard must reject class replacement"
    );
    tx.rollback().await?;
    for query in [
        "UPDATE restores SET updated_at=clock_timestamp()",
        "INSERT INTO restore_pod_admissions(restore_id,tenant_id,job_uid,review_uid) VALUES($1,$2,$3,$4)",
    ] {
        let mut tx = service
            .database
            .begin(plan.record.tenant_id)
            .await
            .map_err(api_failure)?;
        let result = if query.starts_with("INSERT") {
            sqlx::query(query)
                .bind(plan.record.id)
                .bind(plan.record.tenant_id)
                .bind(Uuid::new_v4())
                .bind(Uuid::new_v4())
                .execute(&mut *tx)
                .await
        } else {
            sqlx::query(query).execute(&mut *tx).await
        };
        let error = result
            .err()
            .context("direct admission mutation must fail")?;
        ensure!(
            error.as_database_error().and_then(|e| e.code()).as_deref() == Some("42501"),
            "narrow admission role cannot mutate restore or admission table"
        );
        tx.rollback().await?;
    }
    postwait_profile_revocation(&service, &good, plan, base).await?;
    Box::pin(commit::alternatives(&service, plan, base)).await?;
    Box::pin(commit::initial_ack(&service, &good, plan, base)).await?;
    Box::pin(commit::final_ack(&service, &good, plan, base, false)).await?;
    Box::pin(commit::final_ack(&service, &good, plan, base, true)).await?;
    Ok((service, observed))
}

async fn postwait_profile_revocation(
    service: &RestoreAdmissionService,
    request: &AdmissionRequest,
    plan: &JobPlan,
    base: &FixtureRuntime,
) -> anyhow::Result<()> {
    let mut blocker = base.f.owner_transaction().await?;
    sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(plan.record.tenant_id)
        .bind(plan.record.workspace_id)
        .fetch_one(&mut *blocker)
        .await?;
    sqlx::query("UPDATE backup_profiles SET enabled=false WHERE id=$1")
        .bind(plan.record.profile_id)
        .execute(&mut *blocker)
        .await?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    let (decision, released) = tokio::join!(service.decide(request), async {
        let mut blocked = false;
        for _ in 0..30 {
            blocked=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename='sandbox_admission' AND $1=ANY(pg_blocking_pids(pid)))")
                    .bind(blocker_pid).fetch_one(&base.f.owner).await?;
            if blocked {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        ensure!(
            blocked,
            "actual restore admission must wait on this workspace lock after observing old profile"
        );
        blocker.commit().await?;
        anyhow::Ok(())
    });
    released?;
    let denial = decision
        .err()
        .context("current profile revocation must reject post-wait admission")?;
    ensure!(
        denial.code == 403,
        "dependency error is not proof of post-wait authorization denial"
    );
    let mut tx = base.f.owner_transaction().await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM restore_pod_admissions WHERE tenant_id=$1 AND restore_id=$2",
    )
    .bind(plan.record.tenant_id)
    .bind(plan.record.id)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(count, 0);
    sqlx::query("UPDATE backup_profiles SET enabled=true WHERE id=$1")
        .bind(plan.record.profile_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    service
        .decide(request)
        .await
        .map_err(|e| anyhow::anyhow!("fresh restore admission {} {}", e.code, e.message))?;
    eprintln!(
        "VERIFIED actual workspace lock wait: pre-observed enabled profile revoked before admission lock, final authorization denies and writes no Pod admission"
    );
    Ok(())
}
// Keep the readback verification on its own test future; the long scenario
// retains neither this JobPlan nor its query state through later trusted cleanup.
pub(super) async fn verify_recorded_objects(
    engine: &crate::engine::OperationEngine,
    claim: &crate::engine::Claim,
    base: &FixtureRuntime,
    tenant: Uuid,
    restore_id: Uuid,
    config_uid: Uuid,
    job_uid: Uuid,
) -> anyhow::Result<()> {
    {
        let bound_job = Box::pin(engine.database.prepare_restore_job(engine, claim))
            .await
            .map_err(api_failure)?;
        assert_eq!(bound_job.known_job, Some(job_uid));
        assert_eq!(bound_job.known_pod, None);
    }
    {
        let mut tx = base.f.owner_transaction().await?;
        let bindings: Vec<(String, Uuid)> = sqlx::query_as(
            "SELECT i.kind,b.uid FROM restore_resource_intents i JOIN restore_resource_bindings b ON b.tenant_id=i.tenant_id AND b.intent_id=i.id WHERE i.tenant_id=$1 AND i.restore_id=$2 AND i.kind IN ('CONFIG','JOB') ORDER BY i.kind",
        )
        .bind(tenant)
        .bind(restore_id)
        .fetch_all(&mut *tx)
        .await?;
        assert_eq!(
            bindings,
            vec![("CONFIG".into(), config_uid), ("JOB".into(), job_uid)]
        );
        tx.commit().await?;
    }
    Ok(())
}

pub(super) async fn consume(
    service: RestoreAdmissionService,
    plan: &JobPlan,
    job_uid: Uuid,
    pod_name: &str,
    objects: &Arc<Mutex<BTreeMap<String, Value>>>,
) -> anyhow::Result<Uuid> {
    let path = format!(
        "/apis/batch/v1/namespaces/{NAMESPACE}/jobs/{}",
        crate::nodeguard::protocol::backup_job_name(
            plan.record.id,
            crate::nodeguard::protocol::BackupStage::Restore
        )
    );
    let mut job = objects
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture lock"))?
        .get(&path)
        .cloned()
        .context("actual created Job")?;
    ensure!(
        job["metadata"]["uid"] == json!(job_uid),
        "Pod ownership uses actual recorded Job UID"
    );
    let mut pod = crate::backup_admission::expected_pod(&plan.context, job_uid, pod_name)
        .map_err(|e| anyhow::anyhow!(e.message))?;
    // Validating admission receives the prepared Pod, not the controller's
    // pre-strategy template. CPU/memory in the approved single-container
    // manifest are positive and unequal, hence pinned v1.36.4 QoS Burstable.
    ensure!(
        pod["spec"].get("resources").is_none()
            && pod["spec"].get("initContainers").is_none()
            && pod["spec"].get("schedulingGates").is_none()
            && pod["spec"]["containers"].as_array().map(Vec::len) == Some(1)
            && pod["spec"]["containers"][0]["resources"]["requests"]["cpu"] == json!("1")
            && pod["spec"]["containers"][0]["resources"]["limits"]["cpu"] == json!("2")
            && pod["spec"]["containers"][0]["resources"]["requests"]["memory"] == json!("1Gi")
            && pod["spec"]["containers"][0]["resources"]["limits"]["memory"] == json!("2Gi"),
        "approved Pod QoS fixture contract"
    );
    pod["metadata"]["uid"] = json!(Uuid::new_v4());
    pod["metadata"]["creationTimestamp"] = json!("2026-10-09T00:00:00Z");
    pod["metadata"]["generation"] = json!(1);
    pod["status"] = json!({"phase":"Pending","qosClass":"Burstable"});
    let good = request(pod, "pods", job_user(&service))?;
    assert!(
        service.decide(&good).await.is_err(),
        "suspended durable Job cannot create Pod"
    );
    let mut update = request(job.clone(), "jobs", user(&service))?;
    update.operation = "UPDATE".into();
    update.old_object = Some(job.clone());
    update.object.as_mut().context("object")?["spec"]["suspend"] = json!(false);
    update.object.as_mut().context("object")?["metadata"]["generation"] = json!(2);
    service
        .decide(&update)
        .await
        .map_err(|e| anyhow::anyhow!("unsuspend {} {}", e.code, e.message))?;
    job["spec"]["suspend"] = json!(false);
    job["metadata"]["generation"] = json!(2);
    job["metadata"]["resourceVersion"] = json!("102");
    objects
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture lock"))?
        .insert(path, job);
    for field in [
        "privilege",
        "job_uid",
        "controller",
        "dry_run",
        "source",
        "secret",
        "image",
    ] {
        let mut changed = good.clone();
        match field {
            "controller" => {
                changed.user_info.username = service.identities.controller.username.clone()
            }
            "dry_run" => changed.dry_run = true,
            field => {
                let value = changed.object.as_mut().context("object")?;
                match field {
                    "privilege" => {
                        value["spec"]["containers"][0]["securityContext"]["privileged"] =
                            json!(true)
                    }
                    "job_uid" => {
                        value["metadata"]["ownerReferences"][0]["uid"] = json!(Uuid::new_v4())
                    }
                    "source" => {
                        value["metadata"]["labels"]["sandbox.platform/backup-id"] =
                            json!(Uuid::new_v4())
                    }
                    "secret" => {
                        value["spec"]["volumes"][0] =
                            json!({"name":"escape","hostPath":{"path":"/"}})
                    }
                    _ => value["spec"]["containers"][0]["image"] = json!("unapproved:latest"),
                }
            }
        }
        assert!(
            service.decide(&changed).await.is_err(),
            "changed Pod {field} must reject"
        );
    }
    let mut races = tokio::task::JoinSet::new();
    for _ in 0..12 {
        let service = service.clone();
        let mut request = good.clone();
        request.uid = Uuid::new_v4().to_string();
        races.spawn(async move {
            let allowed = service.decide(&request).await.is_ok();
            (allowed, request.uid)
        });
    }
    let mut winner = None;
    while let Some(result) = races.join_next().await {
        let (allowed, uid) = result?;
        if allowed {
            ensure!(winner.is_none(), "only one distinct real review may win");
            winner = Some(uid);
        }
    }
    let winner = winner.context("one real admission must succeed")?;
    let mut retry = good;
    retry.uid = winner.clone();
    service
        .decide(&retry)
        .await
        .map_err(|e| anyhow::anyhow!("retry {} {}", e.code, e.message))?;
    eprintln!(
        "VERIFIED private RESTORE admission actual Job/config/Pod validators, current profile/Secret, strict controller/spec denial, narrow SQL privileges, 12 reviews exactly one winner and identical review retry"
    );
    Ok(Uuid::parse_str(&winner)?)
}
