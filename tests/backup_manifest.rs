use sandbox_platform::{backup_manifest::*, nodeguard::protocol::*};
use serde_json::json;
use uuid::Uuid;

pub fn fixture(stage: BackupStage) -> BackupManifestContext {
    let tenant_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let backup_id = Uuid::new_v4();
    let attempt_id = Uuid::new_v4();
    BackupManifestContext {tenant_id,project_id,backup_id,attempt_id,cluster_epoch:Uuid::new_v4(),stage,
        image:format!("registry.example.test/sandbox/backup@sha256:{}","a".repeat(64)),certification_sha256:"b".repeat(64),deadline_seconds:3600,
        config_json:json!({"protocol":1,"tenant_id":tenant_id,"project_id":project_id,"backup_id":backup_id,"runtime_certification_sha256":"b".repeat(64)}).to_string(),
        password_secret:"backup-password-v1".into(),signing_private_secret:"backup-signing-private-v1".into(),signing_public_secret:"backup-signing-public-v1".into(),
        block_pvc:(stage!=BackupStage::Seal).then(||block_pvc_name(attempt_id)),expected_manifest_sha256:(stage==BackupStage::Restore).then(||"c".repeat(64))}
}
#[test]
fn bounded_stages_never_share_signing_key_or_mount_tenant_filesystem() -> anyhow::Result<()> {
    for stage in [
        BackupStage::Capture,
        BackupStage::Seal,
        BackupStage::Restore,
    ] {
        let c = fixture(stage);
        let m = build_backup_manifests(&c)?;
        let spec = &m.job["spec"]["template"]["spec"];
        assert_eq!(spec["runtimeClassName"], "kata-backup-qemu");
        assert_eq!(m.job["spec"]["suspend"], true);
        assert_eq!(m.job["spec"]["backoffLimit"], 0);
        assert_eq!(m.job["spec"]["podReplacementPolicy"], "Failed");
        assert_eq!(
            spec["containers"][0]["volumeDevices"].is_array(),
            stage != BackupStage::Seal
        );
        let text = serde_json::to_string(spec)?;
        assert!(!text.contains("hostPath"));
        assert_eq!(
            text.contains(&c.signing_private_secret),
            stage == BackupStage::Seal
        );
        assert_eq!(
            text.contains(&c.signing_public_secret),
            stage == BackupStage::Restore
        );
        assert_eq!(spec["automountServiceAccountToken"], false);
        assert_eq!(
            spec["containers"][0]["securityContext"]["capabilities"]["drop"],
            json!(["ALL"])
        );
    }
    Ok(())
}
#[test]
fn input_drift_rejects_missing_manifest_mutable_image_and_foreign_config() {
    let c = fixture(BackupStage::Restore);
    for changed in 0..6 {
        let mut m = c.clone();
        match changed {
            0 => m.expected_manifest_sha256 = None,
            1 => m.image = "registry.example.test/backup:latest".into(),
            2 => m.block_pvc = None,
            3 => m.password_secret = m.signing_private_secret.clone(),
            4 => m.config_json = json!({"tenant_id":Uuid::new_v4()}).to_string(),
            _ => m.deadline_seconds = 7201,
        };
        assert!(build_backup_manifests(&m).is_err(), "mutation {changed}");
    }
}
#[test]
fn legacy_journal_defaults_only_to_exact_workload_identity() -> anyhow::Result<()> {
    let workspace = Uuid::new_v4();
    let old = json!({"tenant_id":Uuid::new_v4(),"project_id":Uuid::new_v4(),"instance_id":Uuid::new_v4(),"workspace_id":workspace,"generation":1,
        "launch_id":Uuid::new_v4(),"pod_uid":Uuid::new_v4(),"namespace":"tenant-test","pod_name":format!("sbx-ws-{workspace}"),
        "pvc_uid":Uuid::new_v4(),"pv_uid":Uuid::new_v4(),"pv_name":"pvc-test","csi_volume_handle":"d-test"});
    let l: LaunchBinding = serde_json::from_value(old.clone())?;
    assert!(l.validate());
    assert_eq!(l.purpose, LaunchPurpose::Workload);
    let mut v = old.clone();
    v["pod_name"] = json!("sbx-bkp-not-a-workload");
    assert!(!serde_json::from_value::<LaunchBinding>(v)?.validate());
    let mut v = old;
    v["purpose"] = json!({"kind":"FUTURE"});
    assert!(serde_json::from_value::<LaunchBinding>(v).is_err());
    Ok(())
}
#[test]
fn backup_launch_binds_job_attempt_and_only_derived_block_volume() -> anyhow::Result<()> {
    let c = fixture(BackupStage::Capture);
    let source = Uuid::new_v4();
    let mut l = LaunchBinding {
        purpose: LaunchPurpose::Backup {
            backup_id: c.backup_id,
            attempt_id: c.attempt_id,
            job_uid: Uuid::new_v4(),
            stage: c.stage,
            image_ref: c.image,
            source_pvc_uid: source,
        },
        tenant_id: c.tenant_id,
        project_id: c.project_id,
        instance_id: Uuid::new_v4(),
        workspace_id: Uuid::new_v4(),
        generation: 1,
        launch_id: c.attempt_id,
        pod_uid: Uuid::new_v4(),
        namespace: NAMESPACE.into(),
        pod_name: format!("{}-abc12", backup_job_name(c.attempt_id, c.stage)),
        pvc_uid: Uuid::new_v4(),
        pv_uid: Uuid::new_v4(),
        pv_name: "pvc-derived".into(),
        csi_volume_handle: "d-derived".into(),
    };
    assert!(l.validate());
    let valid = l.clone();
    l.pvc_uid = source;
    assert!(!l.validate());
    l = valid.clone();
    l.launch_id = Uuid::new_v4();
    assert!(!l.validate());
    l = valid.clone();
    l.namespace = "kube-system".into();
    assert!(!l.validate());
    l = valid;
    if let LaunchPurpose::Backup { stage, .. } = &mut l.purpose {
        *stage = BackupStage::Seal;
    }
    l.pod_name = format!("{}-abc12", backup_job_name(l.launch_id, BackupStage::Seal));
    assert!(!l.validate());
    l.pvc_uid = Uuid::nil();
    l.pv_uid = Uuid::nil();
    l.pv_name.clear();
    l.csi_volume_handle.clear();
    assert!(l.validate());
    Ok(())
}

#[test]
fn rust_and_deployment_renderer_share_exact_three_stage_objects() -> anyhow::Result<()> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../deploy/backup/tests/manifest-fixture.json"))?;
    let uuid = |s: &str| -> anyhow::Result<Uuid> { Ok(Uuid::parse_str(s)?) };
    let str_field = |v: &serde_json::Value, k: &str| -> anyhow::Result<String> {
        Ok(v[k]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing {k}"))?
            .to_owned())
    };
    let job = &fixture["job"];
    let s = &fixture["settings"];
    for stage in [
        BackupStage::Capture,
        BackupStage::Seal,
        BackupStage::Restore,
    ] {
        let c = BackupManifestContext {
            tenant_id: uuid(&str_field(job, "tenant_id")?)?,
            project_id: uuid(&str_field(job, "project_id")?)?,
            backup_id: uuid(&str_field(job, "backup_id")?)?,
            attempt_id: uuid(&str_field(&fixture, "attempt_id")?)?,
            cluster_epoch: uuid(&str_field(&fixture, "cluster_epoch")?)?,
            stage,
            image: str_field(s, "image")?,
            certification_sha256: str_field(s, "certification_report_sha256")?,
            deadline_seconds: 3600,
            config_json: serde_json::to_string(job)?,
            password_secret: str_field(&s["secrets"], "password")?,
            signing_private_secret: str_field(&s["secrets"], "signing_private")?,
            signing_public_secret: str_field(&s["secrets"], "signing_public")?,
            block_pvc: if stage == BackupStage::Seal {
                None
            } else {
                Some(str_field(&fixture, "volume")?)
            },
            expected_manifest_sha256: if stage == BackupStage::Restore {
                Some(str_field(&fixture, "expected_manifest")?)
            } else {
                None
            },
        };
        let values = build_backup_manifests(&c)?;
        assert_eq!(
            values.config_map,
            fixture["objects"][stage.name()][0],
            "{} config",
            stage.name()
        );
        assert_eq!(
            values.job,
            fixture["objects"][stage.name()][1],
            "{} Job",
            stage.name()
        );
    }
    Ok(())
}
