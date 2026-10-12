use sandbox_platform::{
    admission::{AdmissionRequest, ControllerIdentity, ServiceIdentity},
    backup_admission::*,
    backup_manifest::*,
    nodeguard::protocol::{BackupStage, backup_job_name},
};
use serde_json::{Value, json};
use uuid::Uuid;
fn setup() -> (BackupAuthority, BackupAdmissionIdentities) {
    let tenant = Uuid::new_v4();
    let project = Uuid::new_v4();
    let backup = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let c=BackupManifestContext{tenant_id:tenant,project_id:project,backup_id:backup,attempt_id:attempt,cluster_epoch:Uuid::new_v4(),stage:BackupStage::Capture,
        image:format!("registry.example.test/backup@sha256:{}","a".repeat(64)),certification_sha256:"b".repeat(64),deadline_seconds:3600,
        config_json:json!({"protocol":1,"tenant_id":tenant,"project_id":project,"backup_id":backup,"runtime_certification_sha256":"b".repeat(64)}).to_string(),
        password_secret:"backup-password".into(),signing_private_secret:"backup-sign-private".into(),signing_public_secret:"backup-sign-public".into(),
        block_pvc:Some(block_pvc_name(attempt)),expected_manifest_sha256:None};
    let block = BackupBlockContext {
        backup_id: backup,
        attempt_id: attempt,
        storage_class: "sandbox-retain".into(),
        size_bytes: 20 * 1024_u64.pow(3),
        snapshot_name: Some(format!("sbx-bs-{backup}")),
    };
    let a = BackupAuthority {
        context: c,
        block: Some(block),
        hold_active: true,
        intent_active: true,
        certification_current: true,
        network_verified: true,
        job_uid: None,
        pod_uid: None,
        pvc_uid: None,
        start_allowed: true,
    };
    let identities = BackupAdmissionIdentities {
        controller: ServiceIdentity {
            username: "system:serviceaccount:sandbox-system:sandbox-backup-controller".into(),
            uid: Uuid::new_v4().to_string(),
        },
        job_controller: ControllerIdentity::ServiceAccount {
            username: "system:serviceaccount:kube-system:job-controller".into(),
            uid: Uuid::new_v4().to_string(),
        },
    };
    (a, identities)
}
fn request(
    v: Value,
    resource: &str,
    identity: &ServiceIdentity,
) -> anyhow::Result<AdmissionRequest> {
    Ok(serde_json::from_value(
        json!({"uid":Uuid::new_v4(),"resource":{"group":if resource=="jobs"{"batch"}else{""},"version":"v1","resource":resource},
        "operation":"CREATE","namespace":NAMESPACE,"name":v["metadata"]["name"],"userInfo":{"username":identity.username,"uid":identity.uid},"object":v}),
    )?)
}
// Faithful state delivered to validating admission after server metadata fill
// and Job PrepareForCreate. The original approved manifest remains unmodified.
fn apiserver_job(mut value: Value, uid: Uuid) -> Value {
    let name = value["metadata"]["name"].clone();
    value["metadata"]["uid"] = json!(uid);
    value["metadata"]["creationTimestamp"] = json!("2026-10-08T12:00:00Z");
    value["metadata"]["generation"] = json!(1);
    value["spec"]["manualSelector"] = json!(false);
    value["spec"]["selector"] = json!({"matchLabels":{"batch.kubernetes.io/controller-uid":uid}});
    for key in ["controller-uid", "batch.kubernetes.io/controller-uid"] {
        value["spec"]["template"]["metadata"]["labels"][key] = json!(uid);
    }
    for key in ["job-name", "batch.kubernetes.io/job-name"] {
        value["spec"]["template"]["metadata"]["labels"][key] = name.clone();
    }
    value
}
fn job_request(v: Value, identity: &ControllerIdentity) -> anyhow::Result<AdmissionRequest> {
    let user = match identity {
        ControllerIdentity::ServiceAccount { username, uid } => {
            json!({"username":username,"uid":uid})
        }
        ControllerIdentity::ControlPlane { username } => {
            json!({"username":username,"uid":"","groups":["system:authenticated"]})
        }
    };
    Ok(serde_json::from_value(
        json!({"uid":Uuid::new_v4(),"resource":{"group":"","version":"v1","resource":"pods"},"operation":"CREATE","namespace":NAMESPACE,"name":v["metadata"]["name"],"userInfo":user,"object":v}),
    )?)
}
#[test]
fn exact_controller_and_durable_hold_required_for_all_objects() -> anyhow::Result<()> {
    let (mut a, i) = setup();
    let m = build_backup_manifests(&a.context)?;
    let values = [
        ("jobs", apiserver_job(m.job, Uuid::new_v4())),
        ("configmaps", m.config_map),
        (
            "persistentvolumeclaims",
            build_backup_block_pvc(a.block.as_ref().ok_or_else(|| anyhow::anyhow!("block"))?)?,
        ),
    ];
    for (kind, v) in values {
        let mut r = request(v, kind, &i.controller)?;
        assert_eq!(
            validate_backup_resource(&r, &a, &i).map_err(|e| anyhow::anyhow!(e.message))?,
            BackupAdmissionPlan::Allow
        );
        r.user_info.uid = Uuid::new_v4().to_string();
        assert!(validate_backup_resource(&r, &a, &i).is_err());
        r.user_info.uid = i.controller.uid.clone();
        a.hold_active = false;
        assert!(validate_backup_resource(&r, &a, &i).is_err());
        a.hold_active = true;
        a.network_verified = false;
        assert!(validate_backup_resource(&r, &a, &i).is_err());
        a.network_verified = true;
    }
    Ok(())
}
#[test]
fn job_security_mutations_are_rejected_before_any_pod_gate() -> anyhow::Result<()> {
    let (a, i) = setup();
    let job = apiserver_job(build_backup_manifests(&a.context)?.job, Uuid::new_v4());
    let attacks = [
        ("/spec/suspend", json!(false)),
        ("/spec/backoffLimit", json!(1)),
        ("/spec/parallelism", json!(2)),
        ("/spec/template/spec/runtimeClassName", json!("runc")),
        (
            "/spec/template/spec/automountServiceAccountToken",
            json!(true),
        ),
        (
            "/spec/template/spec/containers/0/image",
            json!("registry.example.test/backup:latest"),
        ),
        (
            "/spec/template/spec/containers/0/command",
            json!(["sh", "-c", "mount /dev/sandbox-data /work"]),
        ),
        (
            "/spec/template/spec/containers/0/securityContext/capabilities/drop",
            json!([]),
        ),
        (
            "/spec/template/spec/containers/0/volumeDevices/0/devicePath",
            json!("/dev/sda"),
        ),
        ("/spec/template/spec/hostNetwork", json!(true)),
        ("/spec/template/metadata/finalizers", json!([])),
    ];
    for (path, v) in attacks {
        let mut changed = job.clone();
        *changed
            .pointer_mut(path)
            .ok_or_else(|| anyhow::anyhow!("path {path}"))? = v;
        let r = request(changed, "jobs", &i.controller)?;
        assert_eq!(
            validate_backup_resource(&r, &a, &i)
                .err()
                .map(|e| e.message),
            Some("Backup Job differs from approved template"),
            "{path} must reach exact template comparison after valid generated fields"
        );
    }
    for (extra, v) in [
        ("nodeName", json!("control-plane")),
        (
            "hostAliases",
            json!([{"ip":"100.100.100.200","hostnames":["sts.cn-hangzhou.aliyuncs.com"]}]),
        ),
        ("initContainers", json!([{"name":"extra","image":"evil"}])),
    ] {
        let mut changed = job.clone();
        changed["spec"]["template"]["spec"][extra] = v;
        assert_eq!(
            validate_backup_resource(&request(changed, "jobs", &i.controller)?, &a, &i)
                .err()
                .map(|e| e.message),
            Some("Backup Job differs from approved template"),
            "{extra} must reach exact template comparison"
        );
    }
    Ok(())
}
fn child(a: &BackupAuthority) -> anyhow::Result<Value> {
    let m = build_backup_manifests(&a.context)?;
    let uid = a.job_uid.ok_or_else(|| anyhow::anyhow!("job UID"))?;
    let name = backup_job_name(a.context.attempt_id, a.context.stage);
    let mut v = json!({"apiVersion":"v1","kind":"Pod","metadata":m.job["spec"]["template"]["metadata"],"spec":m.job["spec"]["template"]["spec"]});
    v["metadata"]["name"] = json!(format!("{name}-abc12"));
    v["metadata"]["generateName"] = json!(format!("{name}-"));
    v["metadata"]["namespace"] = json!(NAMESPACE);
    v["metadata"]["ownerReferences"] = json!([{"apiVersion":"batch/v1","kind":"Job","name":name,"uid":uid,"controller":true,"blockOwnerDeletion":true}]);
    for key in ["controller-uid", "batch.kubernetes.io/controller-uid"] {
        v["metadata"]["labels"][key] = json!(uid);
    }
    for key in ["job-name", "batch.kubernetes.io/job-name"] {
        v["metadata"]["labels"][key] = json!(name);
    }
    v["metadata"]["finalizers"] = json!([
        "sandbox.platform/termination-protection",
        "batch.kubernetes.io/job-tracking"
    ]);
    // Store metadata fill and Pod PrepareForCreate before validating admission.
    v["metadata"]["uid"] = json!(Uuid::new_v4());
    v["metadata"]["creationTimestamp"] = json!("2026-10-09T00:00:00Z");
    v["metadata"]["generation"] = json!(1);
    v["status"] = json!({"phase":"Pending","qosClass":"Burstable"});
    Ok(v)
}
#[test]
fn child_pod_requires_exact_job_owner_and_returns_mandatory_durable_gate() -> anyhow::Result<()> {
    let (mut a, i) = setup();
    a.job_uid = Some(Uuid::new_v4());
    let v = child(&a)?;
    let mut r = job_request(v.clone(), &i.job_controller)?;
    assert!(matches!(
        validate_backup_resource(&r, &a, &i),
        Ok(BackupAdmissionPlan::ConsumePodCreate { .. })
    ));
    r.dry_run = true;
    assert!(validate_backup_resource(&r, &a, &i).is_err());
    r.dry_run = false;
    a.pod_uid = Some(Uuid::new_v4());
    assert!(validate_backup_resource(&r, &a, &i).is_err());
    a.pod_uid = None;
    for (path, bad) in [
        ("/metadata/ownerReferences/0/uid", json!(Uuid::new_v4())),
        (
            "/metadata/labels/batch.kubernetes.io~1controller-uid",
            json!(Uuid::new_v4()),
        ),
        (
            "/spec/volumes/4/persistentVolumeClaim/claimName",
            json!("tenant-original"),
        ),
    ] {
        let mut changed = v.clone();
        *changed
            .pointer_mut(path)
            .ok_or_else(|| anyhow::anyhow!("path {path}"))? = bad;
        assert!(
            validate_backup_resource(&job_request(changed, &i.job_controller)?, &a, &i).is_err(),
            "{path}"
        );
    }
    Ok(())
}
#[test]
fn block_claim_rejects_filesystem_source_handle_and_unknown_snapshot() -> anyhow::Result<()> {
    let (a, i) = setup();
    let v = build_backup_block_pvc(a.block.as_ref().ok_or_else(|| anyhow::anyhow!("block"))?)?;
    for (path, bad) in [
        ("/spec/volumeMode", json!("Filesystem")),
        ("/spec/dataSource/name", json!("foreign-snapshot")),
        ("/spec/accessModes", json!(["ReadWriteMany"])),
    ] {
        let mut changed = v.clone();
        *changed
            .pointer_mut(path)
            .ok_or_else(|| anyhow::anyhow!("path"))? = bad;
        assert!(
            validate_backup_resource(
                &request(changed, "persistentvolumeclaims", &i.controller)?,
                &a,
                &i
            )
            .is_err()
        );
    }
    let mut changed = v;
    changed["spec"]["volumeName"] = json!("original-source-pv");
    assert!(
        validate_backup_resource(
            &request(changed, "persistentvolumeclaims", &i.controller)?,
            &a,
            &i
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn apiserver_priority_defaults_and_exact_kcm_principal_are_supported() -> anyhow::Result<()> {
    let (mut a, mut i) = setup();
    a.job_uid = Some(Uuid::new_v4());
    i.job_controller = ControllerIdentity::ControlPlane {
        username: "system:kube-controller-manager".into(),
    };
    let mut pod = child(&a)?;
    pod["spec"]["priority"] = json!(0);
    pod["spec"]["preemptionPolicy"] = json!("PreemptLowerPriority");
    assert!(
        validate_backup_resource(&job_request(pod.clone(), &i.job_controller)?, &a, &i).is_ok()
    );
    for (key, bad) in [
        ("priority", json!(1000)),
        ("preemptionPolicy", json!("Never")),
    ] {
        let mut drift = pod.clone();
        drift["spec"][key] = bad;
        assert!(validate_backup_resource(&job_request(drift, &i.job_controller)?, &a, &i).is_err());
    }
    let mut r = job_request(pod, &i.job_controller)?;
    r.user_info.groups.push("system:masters".into());
    assert!(validate_backup_resource(&r, &a, &i).is_err());
    Ok(())
}

#[test]
fn first_job_create_accepts_apiserver_generated_identity_without_a_recorded_job()
-> anyhow::Result<()> {
    let (a, i) = setup();
    assert!(a.job_uid.is_none());
    let mut job = build_backup_manifests(&a.context)?.job;
    let candidate_uid = Uuid::new_v4();
    let name = backup_job_name(a.context.attempt_id, a.context.stage);
    // Fixed Kubernetes v1.36.4 Store/Job strategy runs before validating
    // admission: FillObjectMetaSystemFields, PrepareForCreate/generateSelector.
    job["metadata"]["uid"] = json!(candidate_uid);
    job["metadata"]["creationTimestamp"] = json!("2026-10-08T12:00:00Z");
    job["metadata"]["generation"] = json!(1);
    job["spec"]["manualSelector"] = json!(false);
    job["spec"]["selector"] =
        json!({"matchLabels":{"batch.kubernetes.io/controller-uid":candidate_uid}});
    for key in ["controller-uid", "batch.kubernetes.io/controller-uid"] {
        job["spec"]["template"]["metadata"]["labels"][key] = json!(candidate_uid);
    }
    for key in ["job-name", "batch.kubernetes.io/job-name"] {
        job["spec"]["template"]["metadata"]["labels"][key] = json!(name);
    }
    let submitted = request(job, "jobs", &i.controller)?;
    assert_eq!(
        validate_backup_resource(&submitted, &a, &i).map_err(|e| anyhow::anyhow!(e.message))?,
        BackupAdmissionPlan::Allow,
        "first CREATE must compare generated labels to its server candidate UID, never demand a future DB binding"
    );
    assert!(
        a.job_uid.is_none(),
        "admission must not mutate durable Job authority"
    );
    Ok(())
}

#[test]
fn first_job_create_supports_all_stages_without_binding_candidate_uid() -> anyhow::Result<()> {
    for stage in [
        BackupStage::Capture,
        BackupStage::Seal,
        BackupStage::Restore,
    ] {
        let (mut a, i) = setup();
        a.context.stage = stage;
        a.context.block_pvc =
            (stage != BackupStage::Seal).then(|| block_pvc_name(a.context.attempt_id));
        a.context.expected_manifest_sha256 =
            (stage == BackupStage::Restore).then(|| "c".repeat(64));
        let mut job = apiserver_job(build_backup_manifests(&a.context)?.job, Uuid::new_v4());
        job["metadata"]["resourceVersion"] = json!("");
        job["metadata"]["creationTimestamp"] = json!("2026-10-08T23:59:59.123456789Z");
        assert_eq!(
            validate_backup_resource(&request(job, "jobs", &i.controller)?, &a, &i)
                .map_err(|e| anyhow::anyhow!(e.message))?,
            BackupAdmissionPlan::Allow,
            "{}",
            stage.name()
        );
        assert!(a.job_uid.is_none());
    }
    Ok(())
}

#[test]
fn first_job_create_requires_full_canonical_server_metadata() -> anyhow::Result<()> {
    let (a, i) = setup();
    let uid = Uuid::parse_str("8f891cc0-2cb0-4a58-a6ed-012345abcdef")?;
    let valid = apiserver_job(build_backup_manifests(&a.context)?.job, uid);
    for bad in [
        Value::Null,
        json!(Uuid::nil()),
        json!("not-a-uuid"),
        json!(uid.to_string().to_uppercase()),
        json!(uid.simple().to_string()),
        json!(1),
    ] {
        let mut changed = valid.clone();
        changed["metadata"]["uid"] = bad;
        assert_eq!(
            validate_backup_resource(&request(changed, "jobs", &i.controller)?, &a, &i)
                .err()
                .map(|e| e.message),
            Some("Job CREATE requires canonical server candidate UID")
        );
    }
    for bad in [
        Value::Null,
        json!("1"),
        json!(true),
        json!(1.0),
        json!(0),
        json!(2),
    ] {
        let mut changed = valid.clone();
        changed["metadata"]["generation"] = bad;
        assert_eq!(
            validate_backup_resource(&request(changed, "jobs", &i.controller)?, &a, &i)
                .err()
                .map(|e| e.message),
            Some("Job CREATE requires integer generation one")
        );
    }
    for bad in [
        Value::Null,
        json!(1),
        json!("2026-10-08T24:00:00Z"),
        json!("2026-10-08T23:60:00Z"),
        json!("2026-10-08T23:59:60Z"),
        json!("2026-02-29T12:00:00Z"),
        json!("2026-10-08T12:00:00+00:00"),
        json!("2026-10-08T12:00:00+08:00"),
        json!("2026-10-08T12:00:00.Z"),
        json!("2026-10-08T12:00:00.1234567890Z"),
        json!("0000-10-08T12:00:00Z"),
    ] {
        let mut changed = valid.clone();
        changed["metadata"]["creationTimestamp"] = bad;
        assert_eq!(
            validate_backup_resource(&request(changed, "jobs", &i.controller)?, &a, &i)
                .err()
                .map(|e| e.message),
            Some("Job CREATE requires valid server creation timestamp")
        );
    }
    for (key, message) in [
        ("uid", "Job CREATE requires canonical server candidate UID"),
        ("generation", "Job CREATE requires integer generation one"),
        (
            "creationTimestamp",
            "Job CREATE requires valid server creation timestamp",
        ),
    ] {
        let mut changed = valid.clone();
        changed["metadata"]
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("metadata"))?
            .remove(key);
        assert_eq!(
            validate_backup_resource(&request(changed, "jobs", &i.controller)?, &a, &i)
                .err()
                .map(|e| e.message),
            Some(message),
            "missing {key}"
        );
    }
    for bad in [Value::Null, json!(1), json!("1")] {
        let mut changed = valid.clone();
        changed["metadata"]["resourceVersion"] = bad;
        assert_eq!(
            validate_backup_resource(&request(changed, "jobs", &i.controller)?, &a, &i)
                .err()
                .map(|e| e.message),
            Some("Job CREATE resourceVersion must be empty")
        );
    }
    assert!(
        validate_backup_resource(
            &request(
                build_backup_manifests(&a.context)?.job,
                "jobs",
                &i.controller
            )?,
            &a,
            &i
        )
        .is_err(),
        "bare pre-strategy manifest must never masquerade as validating admission"
    );
    Ok(())
}

#[test]
fn first_job_create_requires_all_generated_labels_and_exact_selector() -> anyhow::Result<()> {
    let (a, i) = setup();
    let valid = apiserver_job(build_backup_manifests(&a.context)?.job, Uuid::new_v4());
    for (key, message) in [
        (
            "controller-uid",
            "Job CREATE generated controller UID label changed",
        ),
        (
            "batch.kubernetes.io/controller-uid",
            "Job CREATE generated controller UID label changed",
        ),
        ("job-name", "Job CREATE generated name label changed"),
        (
            "batch.kubernetes.io/job-name",
            "Job CREATE generated name label changed",
        ),
    ] {
        for bad in [None, Some(Value::Null), Some(json!("foreign"))] {
            let mut changed = valid.clone();
            let labels = changed["spec"]["template"]["metadata"]["labels"]
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("labels"))?;
            if let Some(bad) = bad {
                labels.insert(key.into(), bad);
            } else {
                labels.remove(key);
            }
            assert_eq!(
                validate_backup_resource(&request(changed, "jobs", &i.controller)?, &a, &i)
                    .err()
                    .map(|e| e.message),
                Some(message),
                "{key}"
            );
        }
    }
    for bad in [
        Value::Null,
        json!({"matchLabels":{"batch.kubernetes.io/controller-uid":Uuid::new_v4()}}),
        json!({"matchLabels":{"batch.kubernetes.io/controller-uid":valid["metadata"]["uid"],"extra":"true"}}),
        json!({"matchLabels":{"batch.kubernetes.io/controller-uid":valid["metadata"]["uid"]},"matchExpressions":[]}),
    ] {
        let mut changed = valid.clone();
        changed["spec"]["selector"] = bad;
        assert_eq!(
            validate_backup_resource(&request(changed, "jobs", &i.controller)?, &a, &i)
                .err()
                .map(|e| e.message),
            Some("Job CREATE generated selector changed")
        );
    }
    for bad in [Value::Null, json!(true), json!("false"), json!(0)] {
        let mut changed = valid.clone();
        changed["spec"]["manualSelector"] = bad;
        assert_eq!(
            validate_backup_resource(&request(changed, "jobs", &i.controller)?, &a, &i)
                .err()
                .map(|e| e.message),
            Some("Job CREATE manual selector must be false")
        );
    }
    for key in ["selector", "manualSelector"] {
        let mut changed = valid.clone();
        changed["spec"]
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("spec"))?
            .remove(key);
        assert!(
            validate_backup_resource(&request(changed, "jobs", &i.controller)?, &a, &i).is_err()
        );
    }
    let mut changed = valid.clone();
    changed["metadata"]["uid"] = json!(Uuid::new_v4());
    assert_eq!(
        validate_backup_resource(&request(changed, "jobs", &i.controller)?, &a, &i)
            .err()
            .map(|e| e.message),
        Some("Job CREATE generated controller UID label changed"),
        "a different coherent-looking metadata UID must not adopt the original selector"
    );
    for (key, bad) in [
        ("candidateTrusted", json!(true)),
        ("annotations", json!({"unknown":"value"})),
        ("ownerReferences", json!([])),
        ("finalizers", json!([])),
    ] {
        let mut changed = valid.clone();
        changed["metadata"][key] = bad;
        assert_eq!(
            validate_backup_resource(&request(changed, "jobs", &i.controller)?, &a, &i)
                .err()
                .map(|e| e.message),
            Some("Backup Job differs from approved template"),
            "unknown metadata {key} remains strictly compared"
        );
    }
    Ok(())
}

#[test]
fn update_requires_recorded_uid_and_never_uses_create_candidate() -> anyhow::Result<()> {
    for stage in [
        BackupStage::Capture,
        BackupStage::Seal,
        BackupStage::Restore,
    ] {
        let (mut a, i) = setup();
        a.context.stage = stage;
        a.context.block_pvc =
            (stage != BackupStage::Seal).then(|| block_pvc_name(a.context.attempt_id));
        a.context.expected_manifest_sha256 =
            (stage == BackupStage::Restore).then(|| "c".repeat(64));
        let recorded_uid = Uuid::new_v4();
        a.job_uid = Some(recorded_uid);
        let mut old = apiserver_job(build_backup_manifests(&a.context)?.job, recorded_uid);
        old["metadata"]["resourceVersion"] = json!("12");
        let mut new = old.clone();
        new["metadata"]["resourceVersion"] = json!("13");
        new["spec"]["suspend"] = json!(false);
        let mut update = request(new.clone(), "jobs", &i.controller)?;
        update.operation = "UPDATE".into();
        update.old_object = Some(old.clone());
        assert_eq!(
            validate_backup_resource(&update, &a, &i).map_err(|e| anyhow::anyhow!(e.message))?,
            BackupAdmissionPlan::Allow
        );
        a.job_uid = None;
        assert_eq!(
            validate_backup_resource(&update, &a, &i)
                .err()
                .map(|e| e.message),
            Some("Backup resource identity not recorded")
        );
        a.job_uid = Some(recorded_uid);
        let changed_uid = Uuid::new_v4();
        let mut replaced = apiserver_job(build_backup_manifests(&a.context)?.job, changed_uid);
        replaced["spec"]["suspend"] = json!(false);
        update.object = Some(replaced.clone());
        assert_eq!(
            validate_backup_resource(&update, &a, &i)
                .err()
                .map(|e| e.message),
            Some("Backup resource UID changed")
        );
        let create = request(
            apiserver_job(build_backup_manifests(&a.context)?.job, recorded_uid),
            "jobs",
            &i.controller,
        )?;
        assert_eq!(
            validate_backup_resource(&create, &a, &i)
                .err()
                .map(|e| e.message),
            Some("Job CREATE cannot reuse recorded identity or old object")
        );
        a.job_uid = None;
        let mut create = create;
        create.old_object = Some(old);
        assert_eq!(
            validate_backup_resource(&create, &a, &i)
                .err()
                .map(|e| e.message),
            Some("Job CREATE cannot reuse recorded identity or old object")
        );
    }
    Ok(())
}

// Fixed Kubernetes v1.36.4 Store metadata fill then Pod PrepareForCreate.
// This positive case must fail the original shared guard; no DB gate is consumed.
#[test]
fn pinned_apiserver_pod_create_pending_approved_qos_all_stages() -> anyhow::Result<()> {
    for stage in [
        BackupStage::Capture,
        BackupStage::Seal,
        BackupStage::Restore,
    ] {
        let (mut authority, mut identities) = setup();
        authority.context.stage = stage;
        authority.context.block_pvc =
            (stage != BackupStage::Seal).then(|| block_pvc_name(authority.context.attempt_id));
        authority.context.expected_manifest_sha256 =
            (stage == BackupStage::Restore).then(|| "c".repeat(64));
        identities.job_controller = ControllerIdentity::ControlPlane {
            username: "system:kube-controller-manager".into(),
        };
        let job_uid = Uuid::new_v4();
        authority.job_uid = Some(job_uid);
        let mut pod = child(&authority)?;
        // GetPodQOS takes the per-container branch: no Pod-level/init/ephemeral
        // resources, and positive CPU/memory requests differ from limits.
        assert!(pod["spec"].get("resources").is_none());
        assert!(pod["spec"].get("initContainers").is_none());
        assert!(pod["spec"].get("ephemeralContainers").is_none());
        assert_eq!(pod["spec"]["containers"].as_array().map(Vec::len), Some(1));
        let resources = &pod["spec"]["containers"][0]["resources"];
        assert_eq!(resources["requests"]["cpu"], json!("1"));
        assert_eq!(resources["limits"]["cpu"], json!("2"));
        assert_eq!(resources["requests"]["memory"], json!("1Gi"));
        assert_eq!(resources["limits"]["memory"], json!("2Gi"));
        pod["metadata"]["uid"] = json!(Uuid::new_v4());
        pod["metadata"]["creationTimestamp"] = json!("2026-10-09T00:00:00Z");
        pod["metadata"]["generation"] = json!(1);
        pod["status"] = json!({"phase":"Pending","qosClass":"Burstable"});
        let request = job_request(pod, &identities.job_controller)?;
        assert_eq!(
            validate_backup_resource(&request, &authority, &identities)
                .map_err(|e| anyhow::anyhow!("{}: {}", stage.name(), e.message))?,
            BackupAdmissionPlan::ConsumePodCreate {
                attempt_id: authority.context.attempt_id,
                review_uid: Uuid::parse_str(&request.uid)?,
                job_uid,
            },
            "legitimate prepared {} Pod remains subject to the durable consume gate",
            stage.name()
        );
        assert!(authority.pod_uid.is_none());
    }
    Ok(())
}

fn stage_pod_authority(stage: BackupStage) -> (BackupAuthority, BackupAdmissionIdentities) {
    let (mut a, i) = setup();
    a.context.stage = stage;
    a.context.block_pvc =
        (stage != BackupStage::Seal).then(|| block_pvc_name(a.context.attempt_id));
    a.context.expected_manifest_sha256 = (stage == BackupStage::Restore).then(|| "c".repeat(64));
    a.job_uid = Some(Uuid::new_v4());
    (a, i)
}
#[test]
fn pod_create_status_is_exact_server_initialization_for_every_stage() -> anyhow::Result<()> {
    for stage in [
        BackupStage::Capture,
        BackupStage::Seal,
        BackupStage::Restore,
    ] {
        let (a, i) = stage_pod_authority(stage);
        let pod = child(&a)?;
        for bad in [
            Value::Null,
            json!({}),
            json!("Pending"),
            json!({"phase":"Pending"}),
            json!({"qosClass":"Burstable"}),
            json!({"phase":"Running","qosClass":"Burstable"}),
            json!({"phase":"Pending","qosClass":"Guaranteed"}),
            json!({"phase":"Pending","qosClass":"BestEffort"}),
            json!({"phase":"Pending","qosClass":true}),
            json!({"phase":"Pending","qosClass":"Burstable","conditions":[]}),
            json!({"phase":"Pending","qosClass":"Burstable","podIP":"10.0.0.2"}),
            json!({"phase":"Pending","qosClass":"Burstable","containerStatuses":[]}),
        ] {
            let mut changed = pod.clone();
            changed["status"] = bad.clone();
            assert_eq!(
                validate_backup_resource(&job_request(changed, &i.job_controller)?, &a, &i)
                    .err()
                    .map(|e| e.message),
                Some("Pod CREATE status differs from approved server initialization"),
                "{} status {bad} must reach its exact initialization guard",
                stage.name()
            );
        }
        let mut missing = pod;
        missing
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("Pod object"))?
            .remove("status");
        assert_eq!(
            validate_backup_resource(&job_request(missing, &i.job_controller)?, &a, &i)
                .err()
                .map(|e| e.message),
            Some("Pod CREATE status differs from approved server initialization")
        );
        assert!(a.pod_uid.is_none());
    }
    Ok(())
}
#[test]
fn pod_create_server_metadata_cannot_replace_durable_authority() -> anyhow::Result<()> {
    for stage in [
        BackupStage::Capture,
        BackupStage::Seal,
        BackupStage::Restore,
    ] {
        let (a, i) = stage_pod_authority(stage);
        let pod = child(&a)?;
        for (field, bad, reason) in [
            (
                "uid",
                Value::Null,
                "Pod CREATE requires canonical server candidate UID",
            ),
            (
                "uid",
                json!(Uuid::nil()),
                "Pod CREATE requires canonical server candidate UID",
            ),
            (
                "uid",
                json!(Uuid::new_v4().simple().to_string()),
                "Pod CREATE requires canonical server candidate UID",
            ),
            (
                "uid",
                json!("ABCDEFAB-CDEF-4ABC-8ABC-ABCDEFABCDEF"),
                "Pod CREATE requires canonical server candidate UID",
            ),
            (
                "creationTimestamp",
                Value::Null,
                "Pod CREATE requires valid server creation timestamp",
            ),
            (
                "creationTimestamp",
                json!("2026-10-09T24:00:00Z"),
                "Pod CREATE requires valid server creation timestamp",
            ),
            (
                "creationTimestamp",
                json!("2026-10-09T23:60:00Z"),
                "Pod CREATE requires valid server creation timestamp",
            ),
            (
                "creationTimestamp",
                json!("2026-10-09T23:59:60Z"),
                "Pod CREATE requires valid server creation timestamp",
            ),
            (
                "creationTimestamp",
                json!("2026-02-30T00:00:00Z"),
                "Pod CREATE requires valid server creation timestamp",
            ),
            (
                "creationTimestamp",
                json!("2026-10-09T00:00:00+00:00"),
                "Pod CREATE requires valid server creation timestamp",
            ),
            (
                "generation",
                json!(0),
                "Pod CREATE requires integer generation one",
            ),
            (
                "generation",
                json!(2),
                "Pod CREATE requires integer generation one",
            ),
            (
                "generation",
                json!(1.0),
                "Pod CREATE requires integer generation one",
            ),
            (
                "generation",
                json!(true),
                "Pod CREATE requires integer generation one",
            ),
            (
                "resourceVersion",
                json!("1"),
                "Pod CREATE resourceVersion must be empty",
            ),
            (
                "resourceVersion",
                Value::Null,
                "Pod CREATE resourceVersion must be empty",
            ),
        ] {
            let mut changed = pod.clone();
            changed["metadata"][field] = bad;
            assert_eq!(
                validate_backup_resource(&job_request(changed, &i.job_controller)?, &a, &i)
                    .err()
                    .map(|e| e.message),
                Some(reason),
                "{} {field}",
                stage.name()
            );
        }
        let mut request = job_request(pod, &i.job_controller)?;
        let expected = BackupAdmissionPlan::ConsumePodCreate {
            attempt_id: a.context.attempt_id,
            review_uid: Uuid::parse_str(&request.uid)?,
            job_uid: a.job_uid.ok_or_else(|| anyhow::anyhow!("recorded Job"))?,
        };
        // A second canonical server candidate cannot become a durable binding;
        // this stateless decision still uses only the recorded Job/review gate.
        request
            .object
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Pod"))?["metadata"]["uid"] = json!(Uuid::new_v4());
        assert_eq!(
            validate_backup_resource(&request, &a, &i).map_err(|e| anyhow::anyhow!(e.message))?,
            expected
        );
        request.old_object = request.object.clone();
        assert_eq!(
            validate_backup_resource(&request, &a, &i)
                .err()
                .map(|e| e.message),
            Some("Pod CREATE cannot reuse an old object")
        );
        assert!(a.pod_uid.is_none());
    }
    Ok(())
}
#[test]
fn pod_create_prepared_status_never_hides_spec_or_metadata_drift() -> anyhow::Result<()> {
    for stage in [
        BackupStage::Capture,
        BackupStage::Seal,
        BackupStage::Restore,
    ] {
        let (mut a, i) = stage_pod_authority(stage);
        let pod = child(&a)?;
        for (path, bad) in [
            ("/spec/containers/0/resources/requests/cpu", json!("2")),
            ("/spec/containers/0/resources/limits/memory", json!("1Gi")),
            ("/metadata/ownerReferences/0/uid", json!(Uuid::new_v4())),
        ] {
            let mut changed = pod.clone();
            *changed
                .pointer_mut(path)
                .ok_or_else(|| anyhow::anyhow!("approved {path}"))? = bad;
            assert_eq!(
                validate_backup_resource(&job_request(changed, &i.job_controller)?, &a, &i)
                    .err()
                    .map(|e| e.message),
                Some("Backup Pod differs from controlled Job"),
                "{} {path} must reach full controlled-object comparison",
                stage.name()
            );
        }
        for (field, bad) in [
            (
                "resources",
                json!({"requests":{"cpu":"1"},"limits":{"cpu":"1"}}),
            ),
            ("initContainers", json!([{"name":"added","image":"unsafe"}])),
            ("schedulingGates", json!([{"name":"added"}])),
        ] {
            let mut changed = pod.clone();
            changed["spec"][field] = bad;
            assert_eq!(
                validate_backup_resource(&job_request(changed, &i.job_controller)?, &a, &i)
                    .err()
                    .map(|e| e.message),
                Some("Backup Pod differs from controlled Job"),
                "{} added {field}",
                stage.name()
            );
        }
        // The approved securityContext omits privileged; insert the forbidden
        // field instead of demanding an existing pointer and failing the fixture.
        let mut privileged = pod.clone();
        privileged["spec"]["containers"][0]["securityContext"]["privileged"] = json!(true);
        assert_eq!(
            validate_backup_resource(&job_request(privileged, &i.job_controller)?, &a, &i)
                .err()
                .map(|e| e.message),
            Some("Backup Pod differs from controlled Job")
        );
        let mut unknown = pod.clone();
        unknown["metadata"]["unknown"] = json!("added");
        assert_eq!(
            validate_backup_resource(&job_request(unknown, &i.job_controller)?, &a, &i)
                .err()
                .map(|e| e.message),
            Some("Backup Pod differs from controlled Job")
        );
        let request = job_request(pod, &i.job_controller)?;
        a.start_allowed = false;
        assert_eq!(
            validate_backup_resource(&request, &a, &i)
                .err()
                .map(|e| e.message),
            Some("Backup Pod creation denied")
        );
        a.start_allowed = true;
        a.job_uid = None;
        assert_eq!(
            validate_backup_resource(&request, &a, &i)
                .err()
                .map(|e| e.message),
            Some("Backup Job UID not recorded")
        );
    }
    Ok(())
}
