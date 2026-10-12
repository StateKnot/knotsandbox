//! Historical control objects only. A DELETE never declares the restore VM
//! dead, and this path never publishes a volume or settles storage accounting.
use super::*;
use crate::{
    backup_admission::verify_pod_object,
    nodeguard::protocol::{LaunchPurpose, PROTOCOL_VERSION, RegisterLaunchRequest},
    runtime_manifest::TERMINATION_FINALIZER,
};
use k8s_openapi::api::core::v1::Pod;
use kube::{
    api::ListParams,
    core::{ApiResource, DynamicObject},
};

const JOB_TRACKING: &str = "batch.kubernetes.io/job-tracking";

struct ControlAuthority {
    pin: Value,
    context: BackupManifestContext,
    permit: RegisterLaunchRequest,
    job: Uuid,
    closed: bool,
    cleaned: bool,
}
fn text<'a>(value: &'a Value, path: &str) -> Decision<&'a str> {
    value.pointer(path).and_then(Value::as_str).ok_or(Denial {
        code: 403,
        message: "Historical restore control identity missing",
    })
}
fn finalizers(value: &Value) -> Decision<Vec<Value>> {
    let Some(values) = value.pointer("/metadata/finalizers") else {
        return Ok(Vec::new());
    };
    let values = values.as_array().ok_or(Denial {
        code: 403,
        message: "Historical control finalizers malformed",
    })?;
    checked(
        values.len() <= 32
            && values
                .iter()
                .all(|v| v.as_str().is_some_and(|s| !s.is_empty()))
            && values
                .iter()
                .enumerate()
                .all(|(n, v)| !values[..n].contains(v)),
        "Historical control finalizers are duplicated or malformed",
    )?;
    Ok(values.clone())
}
fn comparable(mut value: Value) -> Value {
    if let Some(meta) = value.get_mut("metadata").and_then(Value::as_object_mut) {
        for field in ["managedFields", "selfLink"] {
            meta.remove(field);
        }
        if meta
            .get("finalizers")
            .is_some_and(|v| v.as_array().is_some_and(Vec::is_empty))
        {
            meta.remove("finalizers");
        }
    }
    value
}
fn lifecycle_view(value: &Value) -> Decision<Value> {
    let mut value = value.clone();
    let deleting = value
        .pointer("/metadata/deletionTimestamp")
        .is_some_and(|v| !v.is_null());
    let finals = finalizers(&value)?;
    checked(
        finals.is_empty() || (deleting && finals == [json!("foregroundDeletion")]),
        "Historical Job/config has an unknown finalizer",
    )?;
    checked(
        value
            .pointer("/metadata/deletionGracePeriodSeconds")
            .is_none_or(|v| v.is_null() || (deleting && v.as_i64().is_some_and(|v| v >= 0))),
        "Historical control deletion lifecycle malformed",
    )?;
    let metadata = value["metadata"].as_object_mut().ok_or(Denial {
        code: 403,
        message: "Historical control metadata missing",
    })?;
    for field in [
        "deletionTimestamp",
        "deletionGracePeriodSeconds",
        "finalizers",
    ] {
        metadata.remove(field);
    }
    Ok(value)
}
fn protected_pod(value: &Value, a: &ControlAuthority) -> Decision<()> {
    let finals = finalizers(value)?;
    checked(
        finals
            .iter()
            .all(|v| v == TERMINATION_FINALIZER || v == JOB_TRACKING)
            && (a.closed || finals.iter().any(|v| v == TERMINATION_FINALIZER)),
        "Unprotected restore Pod lacks exact permanent host closure",
    )?;
    checked(
        text(value, "/spec/nodeName")? == a.permit.node.node_name,
        "Historical restore Pod has changed its assigned node",
    )?;
    let mut view = value.clone();
    let metadata = view["metadata"].as_object_mut().ok_or(Denial {
        code: 403,
        message: "Historical restore Pod metadata missing",
    })?;
    metadata.remove("deletionTimestamp");
    metadata.remove("deletionGracePeriodSeconds");
    metadata.insert(
        "finalizers".into(),
        json!([TERMINATION_FINALIZER, JOB_TRACKING]),
    );
    verify_pod_object(&view, &a.context, a.job, a.permit.launch.pod_uid)
}
fn validate_object(value: &Value, a: &ControlAuthority, kind: &str) -> Decision<()> {
    match kind {
        "POD" => protected_pod(value, a),
        "JOB" => verify_job_object(&lifecycle_view(value)?, &a.context, a.job),
        "CONFIG" => {
            let mut value = lifecycle_view(value)?;
            let expected = crate::backup_manifest::build_backup_manifests(&a.context)
                .map_err(dependency)?
                .config_map;
            let metadata = value["metadata"].as_object_mut().ok_or(Denial {
                code: 403,
                message: "Historical restore config metadata missing",
            })?;
            for field in [
                "uid",
                "resourceVersion",
                "creationTimestamp",
                "generation",
                "managedFields",
                "selfLink",
            ] {
                metadata.remove(field);
            }
            checked(
                value == expected,
                "Historical restore config differs from its immutable intent",
            )
        }
        _ => checked(false, "Unsupported historical restore control kind"),
    }
}
fn delete_options(r: &AdmissionRequest, live: &Value, kind: &str) -> Decision<()> {
    let options = r.options.as_ref().ok_or(Denial {
        code: 403,
        message: "Historical control deletion requires exact preconditions",
    })?;
    checked(
        options.as_object().is_some_and(|fields| {
            fields.keys().all(|field| {
                matches!(
                    field.as_str(),
                    "apiVersion"
                        | "kind"
                        | "preconditions"
                        | "dryRun"
                        | "gracePeriodSeconds"
                        | "propagationPolicy"
                )
            })
        }) && options.get("apiVersion").is_none_or(|v| v == "v1")
            && options.get("kind").is_none_or(|v| v == "DeleteOptions")
            && options
                .get("dryRun")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
            && options
                .get("preconditions")
                .and_then(Value::as_object)
                .is_some_and(|fields| fields.len() == 2)
            && options.pointer("/preconditions/uid") == live.pointer("/metadata/uid")
            && options.pointer("/preconditions/resourceVersion")
                == live.pointer("/metadata/resourceVersion")
            && r.object.as_ref().is_none_or(Value::is_null)
            && if kind == "POD" {
                options.get("gracePeriodSeconds") == Some(&json!(30))
                    && options.get("propagationPolicy").is_none()
            } else {
                options.get("gracePeriodSeconds").is_none()
                    && options.get("propagationPolicy") == Some(&json!("Foreground"))
            },
        "Historical control DELETE must preserve exact UID/version and ordinary deletion semantics",
    )
}
fn source_config(
    source: &Value,
    config_json: &str,
    tenant: Uuid,
    project: Uuid,
    backup: Uuid,
) -> Decision<()> {
    let identity: crate::backup_object::BackupIdentity = serde_json::from_value(source.clone())
        .map_err(|_| Denial {
            code: 403,
            message: "Historical source identity malformed",
        })?;
    let config: Value = serde_json::from_str(config_json).map_err(|_| Denial {
        code: 403,
        message: "Historical source configuration malformed",
    })?;
    checked(
        identity.protocol == 1
            && identity.tenant_id == tenant
            && identity.project_id == project
            && identity.backup_id == backup
            && [
                identity.tenant_id,
                identity.project_id,
                identity.backup_id,
                identity.source_instance_id,
                identity.source_pvc_uid,
                identity.snapshot_content_uid,
                identity.clone_pvc_uid,
                identity.seal_attempt_id,
                identity.cluster_epoch,
            ]
            .iter()
            .all(|v| !v.is_nil())
            && source.as_object().is_some_and(|fields| {
                fields
                    .iter()
                    .all(|(key, value)| config.get(key) == Some(value))
            }),
        "Historical configuration differs from complete immutable source identity",
    )
}
fn reviewed_identities(service: &RestoreAdmissionService) -> Decision<()> {
    let controller = &service.identities.controller;
    let reviewed_controller = |identity: &crate::admission::ControllerIdentity| {
        identity.valid()
            && match identity {
                crate::admission::ControllerIdentity::ControlPlane { username } => {
                    username == "system:kube-controller-manager"
                }
                crate::admission::ControllerIdentity::ServiceAccount { .. } => true,
            }
    };
    checked(
        controller.username == "system:serviceaccount:sandbox-system:sandbox-backup-controller"
            && Uuid::parse_str(&controller.uid).is_ok_and(|u| !u.is_nil())
            && reviewed_controller(&service.identities.job_controller)
            && reviewed_controller(&service.control_gc)
            && match &service.control_gc {
                crate::admission::ControllerIdentity::ServiceAccount { username, uid } => {
                    username != &controller.username && uid != &controller.uid
                }
                crate::admission::ControllerIdentity::ControlPlane { .. } => true,
            }
            && match &service.identities.job_controller {
                crate::admission::ControllerIdentity::ServiceAccount { username, uid } => {
                    username != &controller.username && uid != &controller.uid
                }
                crate::admission::ControllerIdentity::ControlPlane { .. } => true,
            },
        "Separate exact reviewed restore and Job/GC controller configuration required",
    )
}
impl RestoreAdmissionService {
    async fn control_authority(
        &self,
        r: &AdmissionRequest,
        tenant: Uuid,
        restore: Uuid,
        uid: Uuid,
        kind: &str,
    ) -> Decision<ControlAuthority> {
        let mut tx = self.database.begin(tenant).await.map_err(dependency)?;
        let pin: Option<Value> =
            sqlx::query_scalar("SELECT sandbox_restore_control_cleanup($1,$2,$3,$4,$5)")
                .bind(tenant)
                .bind(restore)
                .bind(kind)
                .bind(&r.name)
                .bind(uid)
                .fetch_one(&mut *tx)
                .await
                .map_err(dependency)?;
        let pin = pin.filter(Value::is_object).ok_or(Denial {
            code: 403,
            message: "Historical isolated restore control authority missing",
        })?;
        let context: BackupManifestContext =
            serde_json::from_value(pin["context"].clone()).map_err(dependency)?;
        let permit: RegisterLaunchRequest =
            serde_json::from_value(pin["permit"].clone()).map_err(dependency)?;
        source_config(
            &pin["source_identity"],
            &context.config_json,
            tenant,
            context.project_id,
            context.backup_id,
        )?;
        let job = selector(&pin, "/job_uid")?;
        let manifests =
            crate::backup_manifest::build_backup_manifests(&context).map_err(dependency)?;
        checked(
            pin.pointer("/bindings/JOB/expected") == Some(&manifests.job)
                && pin.pointer("/bindings/CONFIG/expected") == Some(&manifests.config_map),
            "Historical control immutable intents differ from recorded context",
        )?;
        checked(
            permit.protocol == PROTOCOL_VERSION
                && permit.launch.validate()
                && permit.node.validate()
                && permit.permit_id == selector(&pin, "/permit_id")?
                && permit.launch.tenant_id == tenant
                && permit.launch.launch_id == restore
                && permit.launch.namespace == NAMESPACE
                && context.tenant_id == tenant
                && context.attempt_id == restore
                && context.stage == BackupStage::Restore
                && permit.node.cluster_epoch == context.cluster_epoch
                && permit.launch.purpose
                    == LaunchPurpose::Backup {
                        backup_id: context.backup_id,
                        attempt_id: restore,
                        job_uid: job,
                        stage: BackupStage::Restore,
                        image_ref: context.image.clone(),
                        source_pvc_uid: selector(&pin, "/source_pvc_uid")?,
                    }
                && context.expected_manifest_sha256.as_deref()
                    == Some(text(&pin, "/source_manifest_sha256")?),
            "Historical restore control purpose or source changed",
        )?;
        let result = ControlAuthority {
            closed: pin.get("proof").is_some_and(Value::is_object),
            cleaned: pin.get("cleanup").is_some_and(Value::is_object),
            pin,
            context,
            permit,
            job,
        };
        tx.commit().await.map_err(dependency)?;
        Ok(result)
    }
    async fn closed_pods_absent(&self, a: &ControlAuthority) -> Decision<()> {
        let pods = Api::<Pod>::namespaced(self.runtime.runtime().client_clone(), NAMESPACE);
        checked(
            pods.get_opt(&a.permit.launch.pod_name)
                .await
                .map_err(dependency)?
                .is_none(),
            "Closed restore Pod is still present",
        )?;
        let page = pods
            .list(
                &ListParams::default()
                    .labels(&format!("batch.kubernetes.io/controller-uid={}", a.job))
                    .limit(2),
            )
            .await
            .map_err(dependency)?;
        checked(
            page.items.is_empty() && page.metadata.continue_.as_deref().is_none_or(str::is_empty),
            "Restore Job still owns a Pod or the inventory is incomplete",
        )
    }
    async fn job_status_authority(
        &self,
        r: &AdmissionRequest,
        tenant: Uuid,
        restore: Uuid,
        uid: Uuid,
    ) -> Decision<Value> {
        let mut tx = self.database.begin(tenant).await.map_err(dependency)?;
        let pin: Option<Value> =
            sqlx::query_scalar("SELECT sandbox_restore_job_status($1,$2,$3,$4)")
                .bind(tenant)
                .bind(restore)
                .bind(&r.name)
                .bind(uid)
                .fetch_one(&mut *tx)
                .await
                .map_err(dependency)?;
        let pin = pin.filter(Value::is_object).ok_or(Denial {
            code: 403,
            message: "Recorded restore Job status identity missing",
        })?;
        tx.commit().await.map_err(dependency)?;
        Ok(pin)
    }
    async fn decide_job_status(&self, r: &AdmissionRequest) -> Decision<()> {
        reviewed_identities(self)?;
        checked(
            r.namespace == NAMESPACE
                && r.resource.group == "batch"
                && r.resource.version == "v1"
                && r.resource.resource == "jobs"
                && r.sub_resource == "status"
                && r.operation == "UPDATE"
                && !r.dry_run
                && crate::backup_manifest::valid_name(&r.name)
                && Uuid::parse_str(&r.uid).is_ok_and(|u| !u.is_nil())
                && r.options.as_ref().is_none_or(|options| {
                    options
                        .get("dryRun")
                        .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
                })
                && self.identities.job_controller.valid()
                && self.identities.job_controller.matches(&r.user_info),
            "Only the exact reviewed Job controller may update recorded restore status",
        )?;
        let old = r.old_object.as_ref().ok_or(Denial {
            code: 403,
            message: "Recorded Job oldObject required",
        })?;
        let after = r.object.as_ref().ok_or(Denial {
            code: 403,
            message: "Recorded Job status body required",
        })?;
        let tenant = selector(old, "/metadata/labels/sandbox.platform~1tenant-id")?;
        let restore = selector(old, "/metadata/labels/sandbox.platform~1backup-attempt-id")?;
        let uid = selector(old, "/metadata/uid")?;
        let started = Instant::now();
        let pin = self.job_status_authority(r, tenant, restore, uid).await?;
        checked(
            started.elapsed() <= Duration::from_secs(10),
            "Job status first COMMIT acknowledgement expired",
        )?;
        let context: BackupManifestContext =
            serde_json::from_value(pin["context"].clone()).map_err(dependency)?;
        source_config(
            &pin["source_identity"],
            &context.config_json,
            tenant,
            context.project_id,
            context.backup_id,
        )?;
        checked(
            context.stage == BackupStage::Restore
                && context.tenant_id == tenant
                && context.attempt_id == restore
                && context.expected_manifest_sha256.as_deref()
                    == Some(text(&pin, "/source_manifest_sha256")?),
            "Job status immutable source context changed",
        )?;
        let manifests =
            crate::backup_manifest::build_backup_manifests(&context).map_err(dependency)?;
        checked(
            pin.pointer("/job/expected") == Some(&manifests.job),
            "Job status immutable intent differs from recorded context",
        )?;
        let api = Api::<Job>::namespaced(self.runtime.runtime().client_clone(), NAMESPACE);
        let live = serde_json::to_value(api.get(&r.name).await.map_err(dependency)?)
            .map_err(dependency)?;
        checked(
            comparable(old.clone()) == comparable(live.clone())
                && selector(&live, "/metadata/uid")? == uid
                && !text(&live, "/metadata/resourceVersion")?.is_empty(),
            "Job status oldObject differs from actual stored identity",
        )?;
        verify_job_object(&lifecycle_view(&live)?, &context, uid)?;
        verify_job_object(&lifecycle_view(after)?, &context, uid)?;
        let mut expected = live.clone();
        if let Some(status) = after.get("status") {
            expected["status"] = status.clone();
        } else if let Some(fields) = expected.as_object_mut() {
            fields.remove("status");
        }
        checked(
            comparable(expected) == comparable(after.clone()),
            "Job status update changed metadata or workload specification",
        )?;
        let current = self.job_status_authority(r, tenant, restore, uid).await?;
        checked(
            current == pin && started.elapsed() <= Duration::from_secs(10),
            "Job status identity or observation expired after final COMMIT acknowledgement",
        )
    }
    pub(crate) async fn decide_control(&self, r: &AdmissionRequest) -> Decision<()> {
        reviewed_identities(self)?;
        if r.resource.resource == "jobs" && r.sub_resource == "status" {
            return self.decide_job_status(r).await;
        }
        // Existing historical assigned-node status has its own exact node/boot
        // observation and never delegates a status write to the cleanup caller.
        if r.resource.resource == "pods" && r.sub_resource == "status" {
            return self.decide_node(r).await;
        }
        checked(
            r.namespace == NAMESPACE
                && crate::backup_manifest::valid_name(&r.name)
                && !r.dry_run
                && r.options.as_ref().is_none_or(|options| {
                    options
                        .get("dryRun")
                        .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
                })
                && r.resource.version == "v1"
                && Uuid::parse_str(&r.uid).is_ok_and(|u| !u.is_nil())
                && matches!(r.operation.as_str(), "UPDATE" | "DELETE"),
            "Unsupported historical restore control operation",
        )?;
        let kind = match (r.resource.group.as_str(), r.resource.resource.as_str()) {
            ("batch", "jobs") => "JOB",
            ("", "configmaps") => "CONFIG",
            ("", "pods") => "POD",
            _ => return checked(false, "Unknown historical restore control kind"),
        };
        let controller = self
            .identities
            .controller
            .username
            .starts_with("system:serviceaccount:")
            && self.identities.controller.username.split(':').count() == 4
            && self
                .identities
                .controller
                .username
                .split(':')
                .skip(2)
                .all(|part| !part.is_empty() && crate::backup_manifest::valid_name(part))
            && Uuid::parse_str(&self.identities.controller.uid).is_ok_and(|u| !u.is_nil())
            && r.user_info.username == self.identities.controller.username
            && r.user_info.uid == self.identities.controller.uid;
        let job_controller = self.identities.job_controller.valid()
            && self.identities.job_controller.matches(&r.user_info);
        let gc = self.control_gc.valid() && self.control_gc.matches(&r.user_info);
        checked(
            if r.operation == "DELETE" {
                r.sub_resource.is_empty() && controller
            } else if matches!(kind, "JOB" | "CONFIG") {
                r.sub_resource.is_empty() && gc
            } else {
                kind == "POD" && r.sub_resource.is_empty() && (controller || job_controller)
            },
            "Only exact reviewed restore controllers may close historical controls",
        )?;
        let old = r.old_object.as_ref().ok_or(Denial {
            code: 403,
            message: "Stored historical restore control required",
        })?;
        let tenant = selector(old, "/metadata/labels/sandbox.platform~1tenant-id")?;
        let restore = selector(old, "/metadata/labels/sandbox.platform~1backup-attempt-id")?;
        let uid = selector(old, "/metadata/uid")?;
        checked(
            text(old, "/metadata/name")? == r.name
                && text(old, "/metadata/namespace")? == NAMESPACE,
            "Historical restore control request identity changed",
        )?;
        // Permanent proof/receipt identify the already-closed writer. Their old
        // recordedAt is not re-stamped here. This *new* observation has one total
        // monotonic budget covering first SQL I/O, all GET/LIST and final ACK.
        let started = Instant::now();
        let a = self
            .control_authority(r, tenant, restore, uid, kind)
            .await?;
        checked(
            started.elapsed() <= Duration::from_secs(10),
            "Historical restore first COMMIT acknowledgement expired",
        )?;
        let resource = ApiResource {
            group: r.resource.group.clone(),
            version: "v1".into(),
            api_version: if kind == "JOB" {
                "batch/v1".into()
            } else {
                "v1".into()
            },
            kind: match kind {
                "JOB" => "Job",
                "CONFIG" => "ConfigMap",
                _ => "Pod",
            }
            .into(),
            plural: r.resource.resource.clone(),
        };
        let api: Api<DynamicObject> =
            Api::namespaced_with(self.runtime.runtime().client_clone(), NAMESPACE, &resource);
        let live = serde_json::to_value(api.get(&r.name).await.map_err(dependency)?)
            .map_err(dependency)?;
        checked(
            comparable(old.clone()) == comparable(live.clone())
                && selector(&live, "/metadata/uid")? == uid
                && !text(&live, "/metadata/resourceVersion")?.is_empty(),
            "Historical control oldObject differs from the actual stored object",
        )?;
        validate_object(&live, &a, kind)?;
        if r.operation == "DELETE" {
            delete_options(r, &live, kind)?;
            if kind != "POD" {
                checked(
                    a.closed && a.cleaned,
                    "Job/config removal requires exact independent writer and volume cleanup",
                )?;
                self.closed_pods_absent(&a).await?;
            }
        } else {
            let after = r.object.as_ref().ok_or(Denial {
                code: 403,
                message: "Updated historical restore control required",
            })?;
            validate_object(after, &a, kind)?;
            let mut expected = live.clone();
            if matches!(kind, "JOB" | "CONFIG") {
                checked(
                    gc && a.closed
                        && a.cleaned
                        && live
                            .pointer("/metadata/deletionTimestamp")
                            .is_some_and(|v| !v.is_null())
                        && finalizers(&live)? == [json!("foregroundDeletion")]
                        && finalizers(after)?.is_empty(),
                    "Only the reviewed GC may remove sole foreground protection after permanent closure",
                )?;
                self.closed_pods_absent(&a).await?;
                expected["metadata"]["finalizers"] = json!([]);
            } else {
                let before = finalizers(&live)?;
                let remove = if controller {
                    TERMINATION_FINALIZER
                } else {
                    JOB_TRACKING
                };
                let retained: Vec<Value> = before
                    .iter()
                    .filter(|v| v.as_str() != Some(remove))
                    .cloned()
                    .collect();
                checked(
                    before.len() == retained.len() + 1 && finalizers(after)? == retained,
                    "Only the caller's exact existing finalizer may be removed",
                )?;
                if controller {
                    checked(
                        a.closed
                            && live
                                .pointer("/metadata/deletionTimestamp")
                                .is_some_and(|v| !v.is_null()),
                        "Termination protection removal requires permanent trusted closure and deletion intent",
                    )?;
                }
                expected["metadata"]["finalizers"] = json!(retained);
            }
            checked(
                comparable(expected) == comparable(after.clone()),
                "Historical control update changed unrelated metadata, specification or status",
            )?;
        }
        let current = self
            .control_authority(r, tenant, restore, uid, kind)
            .await?;
        checked(
            current.pin == a.pin && started.elapsed() <= Duration::from_secs(10),
            "Historical control identity or observation expired after final COMMIT acknowledgement",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_original_source_config_is_pinned_without_replacing_historical_epoch()
    -> anyhow::Result<()> {
        let tenant = Uuid::new_v4();
        let project = Uuid::new_v4();
        let backup = Uuid::new_v4();
        let source = json!({"protocol":1,"tenant_id":tenant,"project_id":project,"backup_id":backup,
            "source_instance_id":Uuid::new_v4(),"source_generation":1,"source_pvc_uid":Uuid::new_v4(),
            "snapshot_content_uid":Uuid::new_v4(),"clone_pvc_uid":Uuid::new_v4(),"seal_attempt_id":Uuid::new_v4(),
            "cluster_epoch":Uuid::new_v4(),"size_bytes":20_u64*1024*1024*1024,"data_timestamp":"2026-10-08T00:00:00Z",
            "consistency":"STOPPED_CONSISTENT","retention_until":"2026-11-08T00:00:00Z","key_ref":"public/fixture",
            "region":"cn-hangzhou","account_id":"1234567890123456","bucket":"public-fixture-source",
            "vault_bucket":"public-fixture-vault","kms_key_id":"source-key","vault_kms_key_id":"vault-key","template_digest":format!("sha256:{}","a".repeat(64))});
        let mut config = source.clone();
        config["issuer"] = json!("https://issuer.example.test");
        assert!(source_config(&source, &config.to_string(), tenant, project, backup).is_ok());
        config["source_pvc_uid"] = json!(Uuid::new_v4());
        assert!(source_config(&source, &config.to_string(), tenant, project, backup).is_err());
        config = source.clone();
        config["cluster_epoch"] = json!(Uuid::new_v4());
        assert!(source_config(&source, &config.to_string(), tenant, project, backup).is_err());
        Ok(())
    }

    #[test]
    fn historical_delete_rejects_force_orphan_and_changed_identity() -> anyhow::Result<()> {
        let old = json!({"metadata":{"name":"closed-restore","namespace":NAMESPACE,"uid":Uuid::new_v4(),"resourceVersion":"17"}});
        let mut r: AdmissionRequest = serde_json::from_value(
            json!({"uid":Uuid::new_v4(),"operation":"DELETE",
            "resource":{"group":"","version":"v1","resource":"pods"},"namespace":NAMESPACE,"name":"closed-restore",
            "userInfo":{"username":"system:serviceaccount:sandbox-system:reviewed-controller","uid":Uuid::new_v4()},
            "object":null,"oldObject":old,"options":{"gracePeriodSeconds":30,"preconditions":{"uid":old["metadata"]["uid"],"resourceVersion":"17"}}}),
        )?;
        delete_options(&r, &old, "POD")
            .map_err(|e| anyhow::anyhow!("normal UID-conditioned DELETE denied {}", e.code))?;
        for (field, value) in [
            ("gracePeriodSeconds", json!(0)),
            ("propagationPolicy", json!("Orphan")),
            ("orphanDependents", json!(true)),
            (
                "ignoreStoreReadErrorWithClusterBreakingPotential",
                json!(true),
            ),
            ("dryRun", json!(["All"])),
        ] {
            let mut bad = r.clone();
            if let Some(options) = bad.options.as_mut() {
                options[field] = value;
            }
            assert!(delete_options(&bad, &old, "POD").is_err());
        }
        if let Some(options) = r.options.as_mut() {
            options["preconditions"]["uid"] = json!(Uuid::new_v4());
        }
        assert!(delete_options(&r, &old, "POD").is_err());
        Ok(())
    }

    #[test]
    fn foreground_job_lifecycle_does_not_remove_unknown_protection() {
        let live = json!({"metadata":{"deletionTimestamp":"2026-10-08T00:00:00Z","finalizers":["foregroundDeletion"],"uid":Uuid::new_v4()},"spec":{"suspend":false}});
        assert!(lifecycle_view(&live).is_ok());
        let mut fresh = live.clone();
        if let Some(meta) = fresh["metadata"].as_object_mut() {
            meta.remove("deletionTimestamp");
        }
        assert!(lifecycle_view(&fresh).is_err());
        let mut protected = live;
        protected["metadata"]["finalizers"] =
            json!(["foregroundDeletion", "other.example/protection"]);
        assert!(lifecycle_view(&protected).is_err());
    }
}
