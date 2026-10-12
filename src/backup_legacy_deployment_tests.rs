//! Upgrade regression: normal INSERT of already accepted immutable legacy facts,
//! followed by the actual current ledger and mTLS close/cleanup code. Kubernetes
//! and kernel observations remain explicit fixtures, not cloud certification.
use super::*;
use crate::{
    backup_manifest::{BackupManifestContext, build_backup_manifests, config_name},
    nodeguard::protocol::{
        BackupStage, LaunchBinding, LaunchPurpose, PROTOCOL_VERSION, RegisterLaunchRequest,
    },
};

/// No current acceptance/launch capability is bypassed. This test-only seeder
/// describes facts persisted by the previous release, with all SQL triggers and
/// immutable constraints enabled. It never seeds termination/cleanup evidence.
async fn historical_accepted(f: Fixture) -> anyhow::Result<Pipeline> {
    let actor = &f.base.f.actor;
    let source_launch = &f.base.launch;
    let mut tx = f.base.f.owner_transaction().await?;
    let w = sqlx::query("SELECT * FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(actor.tenant_id)
        .bind(source_launch.workspace_id)
        .fetch_one(&mut *tx)
        .await?;
    let source_permit: Uuid = sqlx::query_scalar(
        "SELECT id FROM launch_permits WHERE tenant_id=$1 AND instance_id=$2 AND launch_id=$3",
    )
    .bind(actor.tenant_id)
    .bind(source_launch.instance_id)
    .bind(source_launch.launch_id)
    .fetch_one(&mut *tx)
    .await?;
    let runtime_node: Uuid = sqlx::query_scalar(
        "SELECT runtime_node_id FROM launch_permits WHERE tenant_id=$1 AND id=$2",
    )
    .bind(actor.tenant_id)
    .bind(source_permit)
    .fetch_one(&mut *tx)
    .await?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let id = Uuid::new_v4();
    let operation = Uuid::new_v4();
    let hold = Uuid::new_v4();
    let capture = Uuid::new_v4();
    let seal = Uuid::new_v4();
    let deadline = now + Duration::hours(6);
    let job_deadline = now + Duration::minutes(30);
    let size: i64 = w.try_get("size_gib")?;
    let source = BackupSource {
        tenant_id: actor.tenant_id,
        project_id: source_launch.project_id,
        backup_id: id,
        workspace_id: source_launch.workspace_id,
        cluster_epoch: f.base.node.cluster_epoch,
        namespace: w.try_get("namespace")?,
        pvc_name: w.try_get("pvc_name")?,
        pvc_uid: source_launch.pvc_uid,
        pv_uid: source_launch.pv_uid,
        pv_name: source_launch.pv_name.clone(),
        cloud_disk: source_launch.csi_volume_handle.clone(),
        storage_class: w.try_get("storage_class")?,
        snapshot_class: "snapshot-retain".into(),
        size_bytes: u64::try_from(size)?
            .checked_mul(1024_u64.pow(3))
            .context("source size")?,
    };
    source.validate()?;
    insert_operation(&mut tx, actor, operation, source.project_id, source_launch.instance_id,
        source.workspace_id, "BACKUP", &json!({"backup_id":id,"profile_id":f.profile,"consistency":"STOPPED_CONSISTENT","retention_days":31}), deadline)
        .await.map_err(api_failure)?;
    sqlx::query("INSERT INTO workspace_holds(id,tenant_id,project_id,workspace_id,kind,reference_id,source_generation,source_pvc_uid,reason) VALUES($1,$2,$3,$4,'BACKUP',$5,$6,$7,'Legacy accepted cold backup')")
        .bind(hold).bind(actor.tenant_id).bind(source.project_id).bind(source.workspace_id).bind(id)
        .bind(source_launch.generation).bind(source.pvc_uid).execute(&mut *tx).await?;
    let b: BackupRecord = sqlx::query_as("INSERT INTO backups(id,tenant_id,project_id,workspace_id,instance_id,operation_id,profile_id,hold_id,source_permit_id,source_generation,cluster_epoch,source,capture_attempt_id,seal_attempt_id,size_gib,retention_until,deadline,created_at,updated_at,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$18,'CAPTURE_PENDING') RETURNING *")
        .bind(id).bind(actor.tenant_id).bind(source.project_id).bind(source.workspace_id).bind(source_launch.instance_id)
        .bind(operation).bind(f.profile).bind(hold).bind(source_permit).bind(source_launch.generation)
        .bind(source.cluster_epoch).bind(json!(source)).bind(capture).bind(seal).bind(size)
        .bind(now+Duration::days(31)).bind(deadline).bind(now).fetch_one(&mut *tx).await?;
    for (attempt, stage) in [(capture, "CAPTURE"), (seal, "SEAL")] {
        sqlx::query(
            "INSERT INTO backup_attempts(id,tenant_id,backup_id,stage) VALUES($1,$2,$3,$4)",
        )
        .bind(attempt)
        .bind(actor.tenant_id)
        .bind(id)
        .bind(stage)
        .execute(&mut *tx)
        .await?;
    }
    reserve_quota(
        &mut tx,
        actor,
        source.project_id,
        operation,
        id,
        capture,
        &[
            ("BACKUP_GIB", size),
            ("BACKUP_TEMP_GIB", size),
            ("CPU_MILLIS", 2000),
            ("MEMORY_MIB", 2048),
        ],
    )
    .await
    .map_err(api_failure)?;
    let cloud_value: Value = sqlx::query_scalar("SELECT settings FROM backup_profiles WHERE id=$1")
        .bind(f.profile)
        .fetch_one(&mut *tx)
        .await?;
    ensure!(
        cloud_value.get("deployment").is_none(),
        "historical settings must lack deployment"
    );
    let cloud: crate::backup_job::BackupCloudSettings = serde_json::from_value(cloud_value)?;
    cloud.validate_historical()?;
    ensure!(
        cloud.validate().is_err(),
        "legacy profile cannot validate new work"
    );
    let ready = SnapshotReady {
        snapshot_uid: Uuid::new_v4(),
        content_uid: Uuid::new_v4(),
        content_name: format!("snapcontent-{}", Uuid::new_v4()),
        cloud_snapshot: "s-legacy0001".into(),
        created_at: now - Duration::seconds(1),
        restore_size: source.size_bytes,
    };
    let volume = BoundBackupVolume {
        pvc_uid: Uuid::new_v4(),
        pv_uid: Uuid::new_v4(),
        pv_name: format!("pvc-{}", Uuid::new_v4()),
        cloud_disk: "d-legacyclone01".into(),
        size_bytes: source.size_bytes,
    };
    let delegated_content = Uuid::new_v4();
    let delegated_snapshot = Uuid::new_v4();
    let source_snapshot = serde_json::to_value(source.snapshot()?)?;
    let clone_content =
        serde_json::to_value(crate::backup_runtime::clone_content(&source, &ready)?)?;
    let clone_snapshot = serde_json::to_value(crate::backup_runtime::clone_snapshot(&source)?)?;
    let block = crate::backup_manifest::BackupBlockContext {
        backup_id: id,
        attempt_id: capture,
        storage_class: "backup-retain".into(),
        size_bytes: source.size_bytes,
        snapshot_name: Some(source.snapshot_name()),
    };
    let clone_pvc = crate::backup_runtime::scoped_block_pvc(&source, &block)?;
    for (kind, attempt, ns, name, object, uid) in [
        (
            "SOURCE_SNAPSHOT",
            None,
            source.namespace.as_str(),
            source.snapshot_name(),
            Some(source_snapshot),
            ready.snapshot_uid,
        ),
        (
            "SOURCE_CONTENT",
            None,
            "",
            ready.content_name.clone(),
            None,
            ready.content_uid,
        ),
        (
            "CLONE_CONTENT",
            Some(capture),
            "",
            source.snapshot_name(),
            Some(clone_content),
            delegated_content,
        ),
        (
            "CLONE_SNAPSHOT",
            Some(capture),
            NAMESPACE,
            source.snapshot_name(),
            Some(clone_snapshot),
            delegated_snapshot,
        ),
        (
            "CLONE_PVC",
            Some(capture),
            NAMESPACE,
            block_pvc_name(capture),
            Some(clone_pvc),
            volume.pvc_uid,
        ),
        (
            "CLONE_PV",
            Some(capture),
            "",
            volume.pv_name.clone(),
            None,
            volume.pv_uid,
        ),
    ] {
        let intent = resource_intent(
            &mut tx,
            actor.tenant_id,
            id,
            attempt,
            kind,
            ns,
            &name,
            object.as_ref(),
        )
        .await
        .map_err(api_failure)?;
        bind_resource(&mut tx, actor.tenant_id, id, intent, uid)
            .await
            .map_err(api_failure)?;
    }
    sqlx::query("INSERT INTO backup_snapshot_receipts(backup_id,tenant_id,snapshot_uid,content_uid,content_name,cloud_snapshot,data_timestamp,size_bytes) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(id).bind(actor.tenant_id).bind(ready.snapshot_uid).bind(ready.content_uid).bind(&ready.content_name)
        .bind(&ready.cloud_snapshot).bind(ready.created_at).bind(i64::try_from(source.size_bytes)?).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO backup_clone_receipts(attempt_id,tenant_id,backup_id,pvc_uid,pv_uid,pv_name,cloud_disk,size_bytes) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(capture).bind(actor.tenant_id).bind(id).bind(volume.pvc_uid).bind(volume.pv_uid)
        .bind(&volume.pv_name).bind(&volume.cloud_disk).bind(i64::try_from(volume.size_bytes)?).execute(&mut *tx).await?;
    let image = format!("registry.fixture.invalid/backup@sha256:{}", "b".repeat(64));
    let mut config = json!(cloud);
    let object = config.as_object_mut().context("cloud object")?;
    for (key, value) in [
        ("protocol", json!(1)),
        ("tenant_id", json!(actor.tenant_id)),
        ("project_id", json!(source.project_id)),
        ("backup_id", json!(id)),
        ("source_instance_id", json!(source_launch.instance_id)),
        ("source_generation", json!(source_launch.generation)),
        ("source_pvc_uid", json!(source.pvc_uid)),
        ("snapshot_content_uid", json!(ready.content_uid)),
        ("clone_pvc_uid", json!(volume.pvc_uid)),
        ("seal_attempt_id", json!(seal)),
        ("cluster_epoch", json!(source.cluster_epoch)),
        ("size_bytes", json!(source.size_bytes)),
        ("data_timestamp", json!(ready.created_at)),
        ("consistency", json!("STOPPED_CONSISTENT")),
        ("retention_until", json!(b.retention_until)),
        ("deadline", json!(job_deadline)),
        (
            "template_digest",
            json!(format!("sha256:{}", "b".repeat(64))),
        ),
        ("runtime_certification_sha256", json!("a".repeat(64))),
    ] {
        object.insert(key.into(), value);
    }
    let context = BackupManifestContext {
        tenant_id: actor.tenant_id,
        project_id: source.project_id,
        backup_id: id,
        attempt_id: capture,
        cluster_epoch: source.cluster_epoch,
        stage: BackupStage::Capture,
        image: image.clone(),
        certification_sha256: "a".repeat(64),
        deadline_seconds: 1800,
        config_json: config.to_string(),
        password_secret: cloud.secret_bindings.password.name.clone(),
        signing_private_secret: cloud.secret_bindings.signing_private.name.clone(),
        signing_public_secret: cloud.secret_bindings.signing_public.name.clone(),
        block_pvc: Some(block_pvc_name(capture)),
        expected_manifest_sha256: None,
    };
    let manifests = build_backup_manifests(&context)?;
    sqlx::query("INSERT INTO backup_job_contexts(attempt_id,tenant_id,backup_id,context,deadline) VALUES($1,$2,$3,$4,$5)")
        .bind(capture).bind(actor.tenant_id).bind(id).bind(json!(context)).bind(job_deadline).execute(&mut *tx).await?;
    let job = Uuid::new_v4();
    let cfg = Uuid::new_v4();
    let pod_id = Uuid::new_v4();
    let pod_name = format!(
        "{}-abcde",
        crate::nodeguard::protocol::backup_job_name(capture, BackupStage::Capture)
    );
    for (kind, name, object, uid) in [
        (
            "JOB",
            crate::nodeguard::protocol::backup_job_name(capture, BackupStage::Capture),
            Some(manifests.job),
            job,
        ),
        (
            "CONFIG",
            config_name(capture),
            Some(manifests.config_map),
            cfg,
        ),
        ("POD", pod_name.clone(), None, pod_id),
    ] {
        let intent = resource_intent(
            &mut tx,
            actor.tenant_id,
            id,
            Some(capture),
            kind,
            NAMESPACE,
            &name,
            object.as_ref(),
        )
        .await
        .map_err(api_failure)?;
        bind_resource(&mut tx, actor.tenant_id, id, intent, uid)
            .await
            .map_err(api_failure)?;
    }
    sqlx::query("INSERT INTO backup_pod_admissions(attempt_id,tenant_id,backup_id,review_uid,job_uid) VALUES($1,$2,$3,$4,$5)")
        .bind(capture).bind(actor.tenant_id).bind(id).bind(Uuid::new_v4()).bind(job).execute(&mut *tx).await?;
    let launch = LaunchBinding {
        purpose: LaunchPurpose::Backup {
            backup_id: id,
            attempt_id: capture,
            job_uid: job,
            stage: BackupStage::Capture,
            image_ref: image,
            source_pvc_uid: source.pvc_uid,
        },
        tenant_id: actor.tenant_id,
        project_id: source.project_id,
        instance_id: source_launch.instance_id,
        workspace_id: source.workspace_id,
        generation: source_launch.generation,
        launch_id: capture,
        pod_uid: pod_id,
        namespace: NAMESPACE.into(),
        pod_name: pod_name.clone(),
        pvc_uid: volume.pvc_uid,
        pv_uid: volume.pv_uid,
        pv_name: volume.pv_name.clone(),
        csi_volume_handle: volume.cloud_disk.clone(),
    };
    ensure!(launch.validate(), "historical launch identity invalid");
    let permit_id = Uuid::new_v4();
    sqlx::query("INSERT INTO backup_launch_permits(id,tenant_id,backup_id,attempt_id,runtime_node_id,launch,pod_uid,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(permit_id).bind(actor.tenant_id).bind(id).bind(capture).bind(runtime_node).bind(json!(launch)).bind(pod_id).bind(job_deadline).execute(&mut *tx).await?;
    sqlx::query("UPDATE workspaces SET spec_version=spec_version+1,updated_at=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(actor.tenant_id).bind(source.workspace_id).bind(now).execute(&mut *tx).await?;
    sqlx::query(
        "UPDATE operations SET next_attempt_at=next_attempt_at WHERE tenant_id=$1 AND id=$2",
    )
    .bind(actor.tenant_id)
    .bind(operation)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let claim = f.claim(operation).await?;
    // Register only the seeded saved permit, never mint a new typed observation.
    // This establishes the pre-upgrade host fact through the real mTLS protocol.
    let receipt = f
        .base
        .guard
        .client
        .register(&RegisterLaunchRequest {
            protocol: PROTOCOL_VERSION,
            permit_id,
            node: f.base.node.clone(),
            launch,
            expires_at: job_deadline,
        })
        .await?;
    f.backup
        .database
        .record_backup_registration(&f.backup, &claim, &receipt)
        .await
        .map_err(api_failure)?;
    let plan = JobPlan {
        clone_storage_class: "backup-retain".into(),
        backup: b,
        context,
        cloud,
        deadline: job_deadline,
        known_config: Some(cfg),
        known_job: Some(job),
        known_pod: Some(pod_id),
    };
    let mut pod =
        expected_pod(&plan.context, job, &pod_name).map_err(|e| anyhow::anyhow!(e.message))?;
    pod["metadata"]["uid"] = json!(pod_id);
    pod["metadata"]["resourceVersion"] = json!("1");
    pod["spec"]["nodeName"] = json!(f.base.node.node_name);
    let (objects, runtime) = runtime_objects(&plan, &volume, &f.base.node, &pod)?;
    Ok(Pipeline {
        f,
        claim,
        plan,
        volume,
        pod,
        runtime,
        objects,
    })
}

async fn accounting(p: &Pipeline) -> anyhow::Result<Value> {
    let mut tx = p.f.base.f.owner_transaction().await?;
    let value = sqlx::query_scalar("SELECT jsonb_build_object('released',EXISTS(SELECT 1 FROM workspace_hold_releases WHERE tenant_id=$1 AND hold_id=b.hold_id),'source',b.source,'reservations',(SELECT jsonb_agg(jsonb_build_object('id',q.id,'amount',r.amount,'status',r.status) ORDER BY q.id) FROM quota_reservations r JOIN quota_accounts q ON q.id=r.quota_account_id WHERE r.tenant_id=$1 AND r.operation_id=b.operation_id)) FROM backups b WHERE b.tenant_id=$1 AND b.id=$2")
        .bind(p.claim.tenant_id).bind(p.plan.backup.id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(value)
}

async fn current_job_create_is_denied(p: &Pipeline) -> anyhow::Result<()> {
    use crate::admission::{AdmissionConfig, AdmissionRequest, AdmissionService};
    let controller_uid = Uuid::new_v4();
    let config: AdmissionConfig = serde_json::from_value(json!({
        "gateway":{"username":"system:serviceaccount:sandbox-system:sandbox-gateway","uid":Uuid::new_v4()},
        "termination":{"username":"system:serviceaccount:sandbox-system:sandbox-termination","uid":Uuid::new_v4()},
        "worker":{"username":"system:serviceaccount:sandbox-system:sandbox-worker","uid":Uuid::new_v4()},
        "namespace_provisioner":{"username":"system:serviceaccount:sandbox-system:namespace-provisioner","uid":Uuid::new_v4()},
        "backup":{"controller":{"username":"system:serviceaccount:sandbox-system:sandbox-backup-controller","uid":controller_uid},"job_controller":{"kind":"control_plane","username":"system:kube-controller-manager"}},
        "scheduler":{"kind":"control_plane","username":"system:kube-scheduler"},
        "storage_controllers":[{"kind":"service_account","username":"system:serviceaccount:kube-system:csi-provisioner","uid":Uuid::new_v4()}],
        "policy_status_controllers":[{"kind":"service_account","username":"system:serviceaccount:kube-system:cilium","uid":Uuid::new_v4()}],
        "namespace_status_controllers":[{"kind":"control_plane","username":"system:kube-controller-manager"}],
        "pod_garbage_collectors":[{"kind":"control_plane","username":"system:kube-controller-manager"}],
        "storage_provisioner":"diskplugin.csi.alibabacloud.com","certification_id":"test-only-legacy-upgrade",
        "dns_namespace":"kube-system","dns_labels":{"k8s-app":"kube-dns"},"ephemeral_storage_mib":1024,"tmp_size_mib":256
    }))?;
    config.validate()?;
    let database = Database::connect(&std::env::var("TEST_ADMISSION_DATABASE_URL")?, 4).await?;
    database.verify_runtime_role().await?;
    let job = build_backup_manifests(&p.plan.context)?.job;
    let request: AdmissionRequest = serde_json::from_value(json!({
        "uid":Uuid::new_v4(),"resource":{"group":"batch","version":"v1","resource":"jobs"},
        "operation":"CREATE","namespace":NAMESPACE,"name":job["metadata"]["name"],
        "userInfo":{"username":"system:serviceaccount:sandbox-system:sandbox-backup-controller","uid":controller_uid},
        "object":job
    }))?;
    let service = AdmissionService {
        database,
        kubernetes: p.runtime.runtime().client_clone(),
        config,
    };
    let denial = service
        .decide(&request)
        .await
        .err()
        .context("legacy current CREATE must be denied")?;
    assert_eq!(denial.code, 403);
    assert_eq!(
        denial.message,
        "Current backup deployment contract required for new work"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and authenticated loopback nodeguard"]
async fn legacy_missing_deployment_closes_exact_saved_job_without_new_writer_authority()
-> anyhow::Result<()> {
    let _serial = test_support_db::serial().await;
    let mut cloud = super::super::tests::cloud_settings();
    cloud
        .as_object_mut()
        .context("settings")?
        .remove("deployment");
    let f = Box::pin(Fixture::with_cloud(true, cloud)).await?;
    // This fails before the legacy hold exists: denial is the new profile gate.
    let denial = f
        .accept("legacy-profile-new-acceptance")
        .await
        .err()
        .context("new backup must be denied")?;
    ensure!(
        denial.code == "BACKUP_BLOCKED",
        "unexpected acceptance denial"
    );
    assert_eq!(
        denial.detail,
        "Approved backup cloud configuration is invalid"
    );
    let mut tx = f.base.f.owner_transaction().await?;
    let existing: i64 = sqlx::query_scalar("SELECT count(*) FROM backups WHERE profile_id=$1")
        .bind(f.profile)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    assert_eq!(existing, 0);
    let mut p = Box::pin(historical_accepted(f)).await?;
    let baseline = accounting(&p).await?;
    assert_eq!(baseline["released"], false);
    let pod_name = p.pod["metadata"]["name"]
        .as_str()
        .context("Pod name")?
        .to_owned();
    let before_objects = p
        .objects
        .lock()
        .map_err(|_| anyhow::anyhow!("objects lock"))?
        .clone();
    current_job_create_is_denied(&p).await?;
    let job_denied =
        p.f.backup
            .database
            .prepare_backup_job(&p.f.backup, &p.claim)
            .await
            .err()
            .context("legacy current Job prepare must be denied")?;
    assert_eq!(job_denied.detail, "Backup cloud identity invalid");
    let launch_denied = p
        .runtime
        .observe_launch(&p.plan, &pod_name, Some(&p.volume))
        .await
        .err()
        .context("legacy current launch observation must be denied")?;
    assert!(
        launch_denied
            .to_string()
            .contains("reviewed backup deployment tag missing or malformed")
    );
    assert_eq!(
        *p.objects
            .lock()
            .map_err(|_| anyhow::anyhow!("objects lock"))?,
        before_objects
    );
    let mut tx = p.f.base.f.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE tenant_id=$1 AND action='backups:create'")
        .bind(p.claim.tenant_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    p.f.backup
        .database
        .close_backup_attempt(
            &p.f.backup,
            &p.claim,
            Some(&BackupJobExit {
                exit_code: 1,
                report: None,
                finished_at: Utc::now(),
            }),
        )
        .await
        .map_err(api_failure)?;
    p.plan =
        p.f.backup
            .database
            .prepare_backup_job(&p.f.backup, &p.claim)
            .await
            .map_err(api_failure)?;
    assert_eq!(p.plan.backup.status, "CAPTURE_CLOSING");
    assert!(p.plan.cloud.deployment.is_empty());
    assert_eq!(accounting(&p).await?, baseline);
    assert!(
        !p.f.backup
            .database
            .cancel_quiescent_backup(&p.f.backup, &p.claim)
            .await
            .map_err(api_failure)?
    );
    let mut tx = p.f.base.f.owner_transaction().await?;
    let proof_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM backup_termination_proofs WHERE tenant_id=$1 AND backup_id=$2",
    )
    .bind(p.claim.tenant_id)
    .bind(p.plan.backup.id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    assert_eq!(proof_count, 0);
    let challenge =
        p.f.backup
            .database
            .prepare_backup_close(&p.f.backup, &p.claim)
            .await
            .map_err(api_failure)?;
    p.runtime
        .request_close(&p.plan, &challenge.permit.request.launch)
        .await?;
    let TerminationObservation::Verified(proof) =
        p.f.base.guard.client.close(&challenge.request).await?
    else {
        anyhow::bail!("independent mTLS close must return verified evidence")
    };
    let proof_id =
        p.f.backup
            .database
            .record_backup_termination(&p.f.backup, &p.claim, &proof)
            .await
            .map_err(api_failure)?;
    assert_eq!(accounting(&p).await?, baseline);
    assert!(
        !p.f.backup
            .database
            .cancel_quiescent_backup(&p.f.backup, &p.claim)
            .await
            .map_err(api_failure)?
    );
    let path = format!("/api/v1/namespaces/{NAMESPACE}/pods/{pod_name}");
    let original = {
        let mut objects = p
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("objects lock"))?;
        let original = objects[&path].clone();
        objects.get_mut(&path).context("Pod")?["metadata"]["uid"] = json!(Uuid::new_v4());
        original
    };
    assert!(p.runtime.finish_cleanup(&p.plan, &proof).await.is_err());
    p.objects
        .lock()
        .map_err(|_| anyhow::anyhow!("objects lock"))?
        .insert(path.clone(), original);
    let media_before = {
        let objects = p
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("objects lock"))?;
        (
            objects[&format!("/api/v1/persistentvolumes/{}", p.volume.pv_name)].clone(),
            objects[&format!(
                "/api/v1/namespaces/{NAMESPACE}/persistentvolumeclaims/{}",
                block_pvc_name(p.plan.context.attempt_id)
            )]
                .clone(),
        )
    };
    let cleanup = p
        .runtime
        .finish_cleanup(&p.plan, &proof)
        .await?
        .context("exact cleanup")?;
    p.f.backup
        .database
        .record_backup_cleanup(&p.f.backup, &p.claim, proof_id, &cleanup)
        .await
        .map_err(api_failure)?;
    assert_eq!(accounting(&p).await?, baseline);
    let record =
        p.f.backup
            .database
            .backup_record(&p.f.backup, &p.claim)
            .await
            .map_err(api_failure)?;
    assert_eq!(record.status, "CAPTURE_CLOSING");
    let mut tx = p.f.base.f.owner_transaction().await?;
    let (proofs,receipts,capture_reports,vaults):(i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM backup_termination_proofs WHERE tenant_id=$1 AND backup_id=$2),(SELECT count(*) FROM backup_cleanup_receipts WHERE tenant_id=$1 AND backup_id=$2),(SELECT count(*) FROM backup_capture_reports WHERE tenant_id=$1 AND backup_id=$2),(SELECT count(*) FROM backup_vault_receipts WHERE tenant_id=$1 AND backup_id=$2)")
        .bind(p.claim.tenant_id).bind(record.id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    assert_eq!((proofs, receipts, capture_reports, vaults), (1, 1, 0, 0));
    let objects = p
        .objects
        .lock()
        .map_err(|_| anyhow::anyhow!("objects lock"))?;
    assert!(!objects.contains_key(&path));
    assert_eq!(
        (
            objects[&format!("/api/v1/persistentvolumes/{}", p.volume.pv_name)].clone(),
            objects[&format!(
                "/api/v1/namespaces/{NAMESPACE}/persistentvolumeclaims/{}",
                block_pvc_name(p.plan.context.attempt_id)
            )]
                .clone()
        ),
        media_before
    );
    Ok(())
}
