//! Backup-specific admission without a generic exception for sandbox-system.
//! This module does not load authority or grant admission by itself. Production
//! routing must load the current hold/intent, then consume the returned Pod gate
//! in the database before returning Allow. Until wired, existing denial remains.
use crate::{
    admission::{AdmissionRequest, ControllerIdentity, Denial, ServiceIdentity},
    backup_manifest::*,
    nodeguard::protocol::backup_job_name,
};
use serde_json::{Value, json};
use uuid::Uuid;

type Decision<T> = Result<T, Denial>;
fn require(condition: bool, message: &'static str) -> Decision<()> {
    if condition {
        Ok(())
    } else {
        Err(Denial { code: 403, message })
    }
}

#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupAdmissionIdentities {
    pub controller: ServiceIdentity,
    pub job_controller: ControllerIdentity,
}
/// All fields are loaded from durable intent plus fresh Kubernetes observations.
/// Neither a Job label nor a caller-supplied certification file is authority.
pub struct BackupAuthority {
    pub context: BackupManifestContext,
    pub block: Option<BackupBlockContext>,
    pub hold_active: bool,
    pub intent_active: bool,
    pub certification_current: bool,
    pub network_verified: bool,
    pub job_uid: Option<Uuid>,
    pub pod_uid: Option<Uuid>,
    pub pvc_uid: Option<Uuid>,
    /// Live create/start intent, template approval, authorization and lease.
    /// Bound volume/node checks belong to permit registration to support WFFC.
    pub start_allowed: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum BackupAdmissionPlan {
    Allow,
    /// Same review UID may be retried; a different review for this stage attempt
    /// must lose permanently. No second Job-created Pod may obtain a permit.
    ConsumePodCreate {
        attempt_id: Uuid,
        review_uid: Uuid,
        job_uid: Uuid,
    },
}

fn caller(request: &AdmissionRequest, identity: &ServiceIdentity) -> bool {
    identity.username == request.user_info.username
        && identity.uid == request.user_info.uid
        && identity.username.starts_with("system:serviceaccount:")
        && Uuid::parse_str(&identity.uid).is_ok_and(|u| !u.is_nil())
}
fn object(value: &Option<Value>) -> Decision<&Value> {
    value.as_ref().ok_or(Denial {
        code: 403,
        message: "Backup resource body required",
    })
}
fn metadata_identity(value: &Value, name: &str, uid: Option<Uuid>, creating: bool) -> Decision<()> {
    require(
        value.pointer("/metadata/namespace") == Some(&json!(NAMESPACE)),
        "Backup namespace changed",
    )?;
    require(
        value.pointer("/metadata/name") == Some(&json!(name)),
        "Backup resource name changed",
    )?;
    require(
        value
            .pointer("/metadata/deletionTimestamp")
            .is_none_or(Value::is_null),
        "Backup resource deleting",
    )?;
    if let Some(uid) = uid {
        require(
            value.pointer("/metadata/uid") == Some(&json!(uid)),
            "Backup resource UID changed",
        )?;
    } else {
        require(creating, "Backup resource identity not recorded")?;
    }
    Ok(())
}
fn remove_fields(v: &mut Value, fields: &[&str]) {
    if let Some(o) = v.as_object_mut() {
        for field in fields {
            o.remove(*field);
        }
    }
}
fn normalized(mut value: Value) -> Value {
    // Only API-managed metadata is omitted. Arbitrary labels, annotations,
    // ownerReferences, finalizers and every specification field remain compared.
    remove_fields(
        &mut value["metadata"],
        &[
            "uid",
            "resourceVersion",
            "creationTimestamp",
            "generation",
            "managedFields",
            "selfLink",
        ],
    );
    if value
        .get("status")
        .is_some_and(|s| s == &json!({}) || s.is_null())
    {
        remove_fields(&mut value, &["status"]);
    }
    value
}
fn strip_generated_job(value: &mut Value, job_uid: Option<Uuid>, job_name: &str) -> Decision<()> {
    let names = [
        ("batch.kubernetes.io/job-name", job_name.to_string()),
        ("job-name", job_name.to_string()),
    ];
    let labels = &mut value["spec"]["template"]["metadata"]["labels"];
    for (key, expected) in names {
        if let Some(actual) = labels.get(key) {
            require(actual == &json!(expected), "Job generated label changed")?;
            remove_fields(labels, &[key]);
        }
    }
    let uid_labels = ["controller-uid", "batch.kubernetes.io/controller-uid"];
    for key in uid_labels {
        if let Some(actual) = labels.get(key) {
            require(
                job_uid.is_some_and(|u| actual == &json!(u)),
                "Job controller UID is not recorded",
            )?;
            remove_fields(labels, &[key]);
        }
    }
    if let Some(selector) = value.pointer("/spec/selector") {
        require(
            job_uid.is_some_and(|uid| {
                selector == &json!({"matchLabels":{"batch.kubernetes.io/controller-uid":uid}})
            }),
            "Unexpected Job selector",
        )?;
        remove_fields(&mut value["spec"], &["selector"]);
    }
    if let Some(manual) = value.pointer("/spec/manualSelector") {
        require(manual == &json!(false), "Manual Job selector forbidden")?;
        remove_fields(&mut value["spec"], &["manualSelector"]);
    }
    Ok(())
}
// Only the first CREATE may use the API server's candidate UID to compare its
// generated selector and labels. It never becomes durable Job authority here.
fn create_job_candidate(value: &Value, name: &str) -> Decision<Uuid> {
    let text = value.pointer("/metadata/uid").and_then(Value::as_str);
    let uid = text
        .and_then(|s| Uuid::parse_str(s).ok())
        .filter(|u| !u.is_nil() && text == Some(u.to_string().as_str()))
        .ok_or(Denial {
            code: 403,
            message: "Job CREATE requires canonical server candidate UID",
        })?;
    require(
        value
            .pointer("/metadata/creationTimestamp")
            .and_then(Value::as_str)
            .is_some_and(job_creation_timestamp),
        "Job CREATE requires valid server creation timestamp",
    )?;
    require(
        value
            .pointer("/metadata/generation")
            .and_then(Value::as_u64)
            == Some(1),
        "Job CREATE requires integer generation one",
    )?;
    require(
        value
            .pointer("/metadata/resourceVersion")
            .is_none_or(|v| v.as_str() == Some("")),
        "Job CREATE resourceVersion must be empty",
    )?;
    for key in ["controller-uid", "batch.kubernetes.io/controller-uid"] {
        require(
            value["spec"]["template"]["metadata"]["labels"].get(key) == Some(&json!(uid)),
            "Job CREATE generated controller UID label changed",
        )?;
    }
    for key in ["job-name", "batch.kubernetes.io/job-name"] {
        require(
            value["spec"]["template"]["metadata"]["labels"].get(key) == Some(&json!(name)),
            "Job CREATE generated name label changed",
        )?;
    }
    require(
        value.pointer("/spec/selector")
            == Some(&json!({"matchLabels":{"batch.kubernetes.io/controller-uid":uid}})),
        "Job CREATE generated selector changed",
    )?;
    require(
        value.pointer("/spec/manualSelector") == Some(&json!(false)),
        "Job CREATE manual selector must be false",
    )?;
    Ok(uid)
}
fn job_creation_timestamp(value: &str) -> bool {
    // UTC RFC3339, seconds or at most nanoseconds; explicitly reject leap-second
    // and clock rollover lexemes accepted by some permissive time parsers. This
    // API bookkeeping is not a clock-freshness or authorization proof.
    let b = value.as_bytes();
    if !(20..=30).contains(&b.len())
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[b.len() - 1] != b'Z'
        || ![0..4, 5..7, 8..10, 11..13, 14..16, 17..19]
            .iter()
            .all(|r| b[r.clone()].iter().all(u8::is_ascii_digit))
        || &b[0..4] == b"0000"
        || &b[11..13] > b"23".as_slice()
        || &b[14..16] > b"59".as_slice()
        || &b[17..19] > b"59".as_slice()
    {
        return false;
    }
    if b.len() != 20
        && (b[19] != b'.' || b.len() == 21 || !b[20..b.len() - 1].iter().all(u8::is_ascii_digit))
    {
        return false;
    }
    chrono::DateTime::parse_from_rfc3339(value).is_ok()
}
// Store metadata fill precedes validating admission. This candidate UID is
// bookkeeping only: the durable gate remains keyed by the recorded Job and
// review UID, and only a later readback may bind the Pod UID.
fn validate_pod_create_metadata(value: &Value) -> Decision<()> {
    let text = value.pointer("/metadata/uid").and_then(Value::as_str);
    require(
        text.and_then(|s| Uuid::parse_str(s).ok())
            .is_some_and(|u| !u.is_nil() && text == Some(u.to_string().as_str())),
        "Pod CREATE requires canonical server candidate UID",
    )?;
    require(
        value
            .pointer("/metadata/creationTimestamp")
            .and_then(Value::as_str)
            .is_some_and(job_creation_timestamp),
        "Pod CREATE requires valid server creation timestamp",
    )?;
    require(
        value
            .pointer("/metadata/generation")
            .and_then(Value::as_u64)
            == Some(1),
        "Pod CREATE requires integer generation one",
    )?;
    require(
        value
            .pointer("/metadata/resourceVersion")
            .is_none_or(|v| v.as_str() == Some("")),
        "Pod CREATE resourceVersion must be empty",
    )
}
fn approved_pod_create_status(expected: &Value) -> Decision<Value> {
    // Pinned v1.36.4 Pod PrepareForCreate initializes Pending/GetPodQOS. All
    // approved stages have one container with positive, unequal CPU/memory
    // requests and limits. Bind that result to the approved template rather
    // than taking caller status or implementing a second quantity parser.
    // A future resource or scheduling-gate contract must be reviewed explicitly.
    let spec = &expected["spec"];
    let resources = &spec["containers"][0]["resources"];
    require(
        [
            "resources",
            "initContainers",
            "ephemeralContainers",
            "schedulingGates",
        ]
        .iter()
        .all(|field| spec.get(*field).is_none())
            && spec["containers"].as_array().map(Vec::len) == Some(1)
            && resources["requests"]["cpu"] == json!("1")
            && resources["limits"]["cpu"] == json!("2")
            && resources["requests"]["memory"] == json!("1Gi")
            && resources["limits"]["memory"] == json!("2Gi"),
        "Approved Pod CREATE QoS contract changed",
    )?;
    Ok(json!({"phase":"Pending","qosClass":"Burstable"}))
}
fn normalize_pod_spec(spec: &mut Value) -> Decision<()> {
    // Kubernetes Priority admission injects exactly these defaults. Privileged
    // priority classes or alternative preemption behavior remain mismatches.
    for (field, default) in [
        ("priority", json!(0)),
        ("preemptionPolicy", json!("PreemptLowerPriority")),
    ] {
        if spec.get(field) == Some(&default) {
            remove_fields(spec, &[field]);
        }
    }
    for field in ["hostNetwork", "hostPID", "hostIPC"] {
        if spec.get(field) == Some(&json!(false)) {
            remove_fields(spec, &[field]);
        }
    }
    if let Some(old_name) = spec.get("serviceAccount") {
        require(
            spec.get("serviceAccountName") == Some(old_name),
            "ServiceAccount alias changed",
        )?;
        remove_fields(spec, &["serviceAccount"]);
    }
    // The built-in DefaultTolerationSeconds plugin may insert precisely these.
    if let Some(tolerations) = spec.get_mut("tolerations").and_then(Value::as_array_mut) {
        tolerations.retain(|v| {
            !["node.kubernetes.io/not-ready","node.kubernetes.io/unreachable"].iter().any(|key|
            v==&json!({"key":key,"operator":"Exists","effect":"NoExecute","tolerationSeconds":300}))
        });
    }
    if let Some(containers) = spec.get_mut("containers").and_then(Value::as_array_mut) {
        for c in containers {
            for f in ["stdin", "stdinOnce", "tty"] {
                if c.get(f) == Some(&json!(false)) {
                    remove_fields(c, &[f]);
                }
            }
            if let Some(mounts) = c.get_mut("volumeMounts").and_then(Value::as_array_mut) {
                for m in mounts {
                    if m.get("readOnly") == Some(&json!(false)) {
                        remove_fields(m, &["readOnly"]);
                    }
                }
            }
        }
    }
    if let Some(volumes) = spec.get_mut("volumes").and_then(Value::as_array_mut) {
        for v in volumes {
            if let Some(pvc) = v.get_mut("persistentVolumeClaim")
                && pvc.get("readOnly") == Some(&json!(false))
            {
                remove_fields(pvc, &["readOnly"]);
            }
        }
    }
    Ok(())
}
fn same_job(actual: &Value, expected: &Value, uid: Option<Uuid>, name: &str) -> Decision<()> {
    let mut actual = normalized(actual.clone());
    let mut expected = normalized(expected.clone());
    remove_fields(&mut actual, &["status"]);
    remove_fields(&mut expected, &["status"]);
    strip_generated_job(&mut actual, uid, name)?;
    normalize_pod_spec(&mut actual["spec"]["template"]["spec"])?;
    normalize_pod_spec(&mut expected["spec"]["template"]["spec"])?;
    require(
        actual == expected,
        "Backup Job differs from approved template",
    )
}

pub fn validate_backup_resource(
    request: &AdmissionRequest,
    a: &BackupAuthority,
    identities: &BackupAdmissionIdentities,
) -> Decision<BackupAdmissionPlan> {
    require(
        request.namespace == NAMESPACE && request.sub_resource.is_empty(),
        "Backup subresource or namespace denied",
    )?;
    require(
        a.hold_active && a.intent_active && a.certification_current && a.network_verified,
        "Backup durable authority unavailable",
    )?;
    require(
        matches!(request.operation.as_str(), "CREATE" | "UPDATE"),
        "Backup deletion requires a termination and cleanup receipt",
    )?;
    let creating = request.operation == "CREATE";
    let objects = build_backup_manifests(&a.context).map_err(|_| Denial {
        code: 403,
        message: "Invalid approved backup configuration",
    })?;
    let value = object(&request.object)?;
    match (
        request.resource.group.as_str(),
        request.resource.version.as_str(),
        request.resource.resource.as_str(),
    ) {
        ("batch", "v1", "jobs") => {
            require(
                caller(request, &identities.controller),
                "Only the exact backup controller may manage Jobs",
            )?;
            let name = backup_job_name(a.context.attempt_id, a.context.stage);
            metadata_identity(value, &name, a.job_uid, creating)?;
            require(request.name == name, "Backup Job request name changed")?;
            let comparison_uid = if creating {
                require(
                    a.job_uid.is_none() && request.old_object.is_none(),
                    "Job CREATE cannot reuse recorded identity or old object",
                )?;
                Some(create_job_candidate(value, &name)?)
            } else {
                a.job_uid
            };
            let mut expected = objects.job;
            if !creating {
                let old = object(&request.old_object)?;
                require(
                    old.get("status") == value.get("status"),
                    "Backup controller may not change Job status",
                )?;
                metadata_identity(old, &name, a.job_uid, false)?;
                let mut old_expected = expected.clone();
                old_expected["spec"]["suspend"] = old["spec"]["suspend"].clone();
                require(
                    old.pointer("/spec/suspend").is_some_and(Value::is_boolean),
                    "Backup Job suspend missing",
                )?;
                same_job(old, &old_expected, a.job_uid, &name)?;
                let suspend = value
                    .pointer("/spec/suspend")
                    .and_then(Value::as_bool)
                    .ok_or(Denial {
                        code: 403,
                        message: "Backup Job suspend missing",
                    })?;
                require(
                    suspend || a.start_allowed,
                    "Backup start authority unavailable",
                )?;
                // Re-suspending a running Job causes deletion; that path requires the
                // termination controller and is not a harmless template update.
                require(
                    !suspend || old.pointer("/spec/suspend") == Some(&json!(true)),
                    "Backup resuspension requires termination",
                )?;
                expected["spec"]["suspend"] = json!(suspend);
            }
            same_job(value, &expected, comparison_uid, &name)?;
            Ok(BackupAdmissionPlan::Allow)
        }
        ("", "v1", "configmaps") => {
            require(
                caller(request, &identities.controller) && creating,
                "Backup config is create-only",
            )?;
            let name = config_name(a.context.attempt_id);
            metadata_identity(value, &name, None, true)?;
            require(
                request.name == name && normalized(value.clone()) == normalized(objects.config_map),
                "Backup config changed",
            )?;
            Ok(BackupAdmissionPlan::Allow)
        }
        ("", "v1", "persistentvolumeclaims") => {
            require(
                caller(request, &identities.controller) && creating,
                "Backup volumes are create-only through this path",
            )?;
            let block = a.block.as_ref().ok_or(Denial {
                code: 403,
                message: "Backup block intent missing",
            })?;
            require(
                match a.context.stage {
                    crate::nodeguard::protocol::BackupStage::Capture => {
                        block.snapshot_name.is_some()
                    }
                    crate::nodeguard::protocol::BackupStage::Restore => {
                        block.snapshot_name.is_none()
                    }
                    crate::nodeguard::protocol::BackupStage::Seal => false,
                },
                "Backup block source does not match stage",
            )?;
            require(
                block.backup_id == a.context.backup_id && block.attempt_id == a.context.attempt_id,
                "Backup block intent changed",
            )?;
            require(
                a.context.block_pvc.as_deref() == Some(block_pvc_name(block.attempt_id).as_str()),
                "Backup claim differs from Job",
            )?;
            let expected = build_backup_block_pvc(block).map_err(|_| Denial {
                code: 403,
                message: "Invalid backup block intent",
            })?;
            let name = block_pvc_name(block.attempt_id);
            metadata_identity(value, &name, a.pvc_uid, true)?;
            let mut actual = normalized(value.clone());
            if let Some(reference) = actual.pointer("/spec/dataSourceRef") {
                require(
                    actual.pointer("/spec/dataSource") == Some(reference),
                    "Backup datasource alias changed",
                )?;
                remove_fields(&mut actual["spec"], &["dataSourceRef"]);
            }
            require(
                request.name == name && actual == normalized(expected),
                "Backup volume differs from exact block intent",
            )?;
            Ok(BackupAdmissionPlan::Allow)
        }
        ("", "v1", "pods") => {
            require(
                creating
                    && identities.job_controller.matches(&request.user_info)
                    && a.start_allowed,
                "Backup Pod creation denied",
            )?;
            require(a.pod_uid.is_none(), "Backup attempt already has a Pod")?;
            let job_uid = a.job_uid.ok_or(Denial {
                code: 403,
                message: "Backup Job UID not recorded",
            })?;
            let name = backup_job_name(a.context.attempt_id, a.context.stage);
            let prefix = format!("{name}-");
            require(
                request.name.strip_prefix(&prefix).is_some_and(|s| {
                    s.len() == 5
                        && s.bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                }),
                "Unexpected generated backup Pod name",
            )?;
            require(
                request.old_object.is_none(),
                "Pod CREATE cannot reuse an old object",
            )?;
            metadata_identity(value, &request.name, None, true)?;
            validate_pod_create_metadata(value)?;
            let mut expected = expected_pod(&a.context, job_uid, &request.name)?;
            expected["status"] = approved_pod_create_status(&expected)?;
            require(
                value.get("status") == expected.get("status"),
                "Pod CREATE status differs from approved server initialization",
            )?;
            let mut actual = normalized(value.clone());
            normalize_pod_spec(&mut actual["spec"])?;
            normalize_pod_spec(&mut expected["spec"])?;
            require(
                actual == normalized(expected),
                "Backup Pod differs from controlled Job",
            )?;
            let review_uid = Uuid::parse_str(&request.uid).map_err(|_| Denial {
                code: 403,
                message: "Invalid admission review UID",
            })?;
            require(
                !review_uid.is_nil() && !request.dry_run,
                "Backup Pod gate requires a real admission request",
            )?;
            Ok(BackupAdmissionPlan::ConsumePodCreate {
                attempt_id: a.context.attempt_id,
                review_uid,
                job_uid,
            })
        }
        _ => Err(Denial {
            code: 403,
            message: "Backup resource or operation is not implemented; denied",
        }),
    }
}

pub(crate) fn expected_pod(
    c: &BackupManifestContext,
    job_uid: Uuid,
    pod_name: &str,
) -> Decision<Value> {
    let objects = build_backup_manifests(c).map_err(|_| Denial {
        code: 403,
        message: "Invalid approved backup configuration",
    })?;
    let name = backup_job_name(c.attempt_id, c.stage);
    let prefix = format!("{name}-");
    require(
        pod_name.strip_prefix(&prefix).is_some_and(|s| {
            s.len() == 5
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        }),
        "Unexpected backup Pod name",
    )?;
    let mut expected = json!({"apiVersion":"v1","kind":"Pod","metadata":objects.job["spec"]["template"]["metadata"],"spec":objects.job["spec"]["template"]["spec"]});
    expected["metadata"]["name"] = json!(pod_name);
    expected["metadata"]["namespace"] = json!(NAMESPACE);
    expected["metadata"]["generateName"] = json!(prefix);
    expected["metadata"]["ownerReferences"] = json!([{"apiVersion":"batch/v1","kind":"Job","name":name,"uid":job_uid,"controller":true,"blockOwnerDeletion":true}]);
    for k in ["controller-uid", "batch.kubernetes.io/controller-uid"] {
        expected["metadata"]["labels"][k] = json!(job_uid);
    }
    for k in ["job-name", "batch.kubernetes.io/job-name"] {
        expected["metadata"]["labels"][k] = json!(name);
    }
    expected["metadata"]["finalizers"]
        .as_array_mut()
        .ok_or(Denial {
            code: 403,
            message: "Protection finalizer missing",
        })?
        .push(json!("batch.kubernetes.io/job-tracking"));
    Ok(expected)
}
pub(crate) fn verify_job_object(
    value: &Value,
    c: &BackupManifestContext,
    uid: Uuid,
) -> Decision<()> {
    metadata_identity(
        value,
        &backup_job_name(c.attempt_id, c.stage),
        Some(uid),
        false,
    )?;
    let mut actual = value.clone();
    remove_fields(&mut actual, &["status"]);
    let mut expected = build_backup_manifests(c)
        .map_err(|_| Denial {
            code: 403,
            message: "Invalid approved configuration",
        })?
        .job;
    require(
        actual
            .pointer("/spec/suspend")
            .is_some_and(Value::is_boolean),
        "Backup Job suspend required",
    )?;
    expected["spec"]["suspend"] = actual["spec"]["suspend"].clone();
    same_job(
        &actual,
        &expected,
        Some(uid),
        &backup_job_name(c.attempt_id, c.stage),
    )
}
pub(crate) fn verify_pod_object(
    value: &Value,
    c: &BackupManifestContext,
    job_uid: Uuid,
    pod_uid: Uuid,
) -> Decision<()> {
    let name = value
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .ok_or(Denial {
            code: 403,
            message: "Backup Pod name required",
        })?;
    metadata_identity(value, name, Some(pod_uid), false)?;
    let mut actual = normalized(value.clone());
    remove_fields(&mut actual, &["status"]);
    // Node assignment is independently checked against the enrolled node before Run.
    remove_fields(&mut actual["spec"], &["nodeName"]);
    let mut expected = expected_pod(c, job_uid, name)?;
    normalize_pod_spec(&mut actual["spec"])?;
    normalize_pod_spec(&mut expected["spec"])?;
    require(
        actual == normalized(expected),
        "Observed backup Pod differs from approved Job",
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod job_observation_tests {
    use super::*;
    use crate::nodeguard::protocol::BackupStage;

    #[test]
    fn all_stages_observe_only_recorded_job_uid_even_for_coherent_replacement() {
        for stage in [
            BackupStage::Capture,
            BackupStage::Seal,
            BackupStage::Restore,
        ] {
            let tenant = Uuid::new_v4();
            let project = Uuid::new_v4();
            let backup = Uuid::new_v4();
            let attempt = Uuid::new_v4();
            let context = BackupManifestContext {
                tenant_id: tenant,
                project_id: project,
                backup_id: backup,
                attempt_id: attempt,
                cluster_epoch: Uuid::new_v4(),
                stage,
                image: format!("registry.example.test/backup@sha256:{}", "a".repeat(64)),
                certification_sha256: "b".repeat(64),
                deadline_seconds: 3600,
                config_json: json!({"protocol":1,"tenant_id":tenant,"project_id":project,
                    "backup_id":backup,"runtime_certification_sha256":"b".repeat(64)})
                .to_string(),
                password_secret: "backup-password".into(),
                signing_private_secret: "backup-sign-private".into(),
                signing_public_secret: "backup-sign-public".into(),
                block_pvc: (stage != BackupStage::Seal).then(|| block_pvc_name(attempt)),
                expected_manifest_sha256: (stage == BackupStage::Restore).then(|| "c".repeat(64)),
            };
            let recorded_uid = Uuid::new_v4();
            let name = backup_job_name(attempt, stage);
            let expected = build_backup_manifests(&context).unwrap().job;
            for (uid, permitted) in [(recorded_uid, true), (Uuid::new_v4(), false)] {
                // Observed object fixture: all generated labels and selector are
                // coherent even in the rejected replacement, not just metadata.
                let mut observed = expected.clone();
                observed["metadata"]["uid"] = json!(uid);
                observed["metadata"]["resourceVersion"] = json!("12");
                observed["metadata"]["creationTimestamp"] = json!("2026-10-08T12:00:00Z");
                observed["metadata"]["generation"] = json!(1);
                observed["spec"]["manualSelector"] = json!(false);
                observed["spec"]["selector"] =
                    json!({"matchLabels":{"batch.kubernetes.io/controller-uid":uid}});
                for key in ["controller-uid", "batch.kubernetes.io/controller-uid"] {
                    observed["spec"]["template"]["metadata"]["labels"][key] = json!(uid);
                }
                for key in ["job-name", "batch.kubernetes.io/job-name"] {
                    observed["spec"]["template"]["metadata"]["labels"][key] = json!(name);
                }
                let result = verify_job_object(&observed, &context, recorded_uid);
                if permitted {
                    assert!(result.is_ok(), "{} recorded observation", stage.name());
                } else {
                    assert_eq!(
                        result.err().map(|e| e.message),
                        Some("Backup resource UID changed"),
                        "{} coherent replacement must not self-authorize",
                        stage.name()
                    );
                }
            }
        }
    }

    #[test]
    fn all_stages_pod_readback_requires_recorded_uid_after_prepared_create() {
        for stage in [
            BackupStage::Capture,
            BackupStage::Seal,
            BackupStage::Restore,
        ] {
            let tenant = Uuid::new_v4();
            let project = Uuid::new_v4();
            let backup = Uuid::new_v4();
            let attempt = Uuid::new_v4();
            let context = BackupManifestContext {
                tenant_id: tenant,
                project_id: project,
                backup_id: backup,
                attempt_id: attempt,
                cluster_epoch: Uuid::new_v4(),
                stage,
                image: format!("registry.example.test/backup@sha256:{}", "a".repeat(64)),
                certification_sha256: "b".repeat(64),
                deadline_seconds: 3600,
                config_json: json!({"protocol":1,"tenant_id":tenant,"project_id":project,
                    "backup_id":backup,"runtime_certification_sha256":"b".repeat(64)})
                .to_string(),
                password_secret: "backup-password".into(),
                signing_private_secret: "backup-sign-private".into(),
                signing_public_secret: "backup-sign-public".into(),
                block_pvc: (stage != BackupStage::Seal).then(|| block_pvc_name(attempt)),
                expected_manifest_sha256: (stage == BackupStage::Restore).then(|| "c".repeat(64)),
            };

            let job_uid = Uuid::new_v4();
            let pod_uid = Uuid::new_v4();
            let name = format!("{}-abc12", backup_job_name(attempt, stage));
            for phase in ["Pending", "Running"] {
                let mut observed = expected_pod(&context, job_uid, &name).unwrap();
                observed["metadata"]["uid"] = json!(pod_uid);
                observed["metadata"]["resourceVersion"] = json!("12");
                observed["metadata"]["creationTimestamp"] = json!("2026-10-09T00:00:00Z");
                observed["metadata"]["generation"] = json!(1);
                observed["status"] = json!({"phase":phase,"qosClass":"Burstable"});
                assert!(verify_pod_object(&observed, &context, job_uid, pod_uid).is_ok());
                observed["metadata"]["uid"] = json!(Uuid::new_v4());
                assert_eq!(
                    verify_pod_object(&observed, &context, job_uid, pod_uid)
                        .err()
                        .map(|e| e.message),
                    Some("Backup resource UID changed"),
                    "{} coherent replacement cannot become durable authority",
                    stage.name()
                );
                observed["metadata"]["uid"] = json!(pod_uid);
                observed["spec"]["containers"][0]["securityContext"]["privileged"] = json!(true);
                assert_eq!(
                    verify_pod_object(&observed, &context, job_uid, pod_uid)
                        .err()
                        .map(|e| e.message),
                    Some("Observed backup Pod differs from approved Job")
                );
            }
        }
    }
}
