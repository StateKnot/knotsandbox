//! Fresh scheduler binding and historical assigned-node status are separate
//! authorities. Neither admission response is a host write permit.
use super::*;
use crate::{
    admission::ControllerIdentity,
    backup_admission::verify_pod_object,
    nodeguard::protocol::{LaunchPurpose, NodeBinding, PROTOCOL_VERSION, RegisterLaunchRequest},
};
use k8s_openapi::api::core::v1::{Node, Pod};

struct Historical {
    context: BackupManifestContext,
    permit: RegisterLaunchRequest,
    proof: bool,
    pin: Value,
}
fn text<'a>(v: &'a Value, path: &str) -> Decision<&'a str> {
    v.pointer(path).and_then(Value::as_str).ok_or(Denial {
        code: 403,
        message: "Restore node resource identity missing",
    })
}
fn protected_pod(
    value: &Value,
    context: &BackupManifestContext,
    job: Uuid,
    pod: Uuid,
    proof: bool,
) -> Decision<()> {
    let finals = match value.pointer("/metadata/finalizers") {
        None => &[][..],
        Some(value) => value.as_array().map(Vec::as_slice).ok_or(Denial {
            code: 403,
            message: "Restore Pod protection shape invalid",
        })?,
    };
    let termination = crate::runtime_manifest::TERMINATION_FINALIZER;
    checked(
        finals.iter().all(|f| {
            f.as_str().is_some_and(|s| {
                matches!(
                    s,
                    "sandbox.platform/termination-protection" | "batch.kubernetes.io/job-tracking"
                )
            })
        }) && (proof || finals.iter().any(|f| f.as_str() == Some(termination))),
        "Restore Pod lacks exact trusted termination protection",
    )?;
    let mut view = value.clone();
    let metadata = view["metadata"].as_object_mut().ok_or(Denial {
        code: 403,
        message: "Restore Pod metadata missing",
    })?;
    metadata.remove("deletionTimestamp");
    metadata.remove("deletionGracePeriodSeconds");
    metadata.insert(
        "finalizers".into(),
        json!([termination, "batch.kubernetes.io/job-tracking"]),
    );
    verify_pod_object(&view, context, job, pod)
}
fn same_status_identity(a: &Value, b: &Value) -> Decision<()> {
    checked(
        a.get("spec") == b.get("spec")
            && [
                "name",
                "namespace",
                "uid",
                "labels",
                "annotations",
                "ownerReferences",
                "finalizers",
                "deletionTimestamp",
                "deletionGracePeriodSeconds",
            ]
            .iter()
            .all(|field| a["metadata"].get(*field) == b["metadata"].get(*field)),
        "Restore status changed immutable specification or protected metadata",
    )
}
impl RestoreAdmissionService {
    async fn historical(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant: Uuid,
        restore: Uuid,
    ) -> Decision<Historical> {
        let row=sqlx::query("SELECT r.cluster_epoch,r.backup_id,r.source_project_id,r.source_manifest_sha256,r.source_identity,c.context,p.request,p.id AS permit_id,(SELECT EXISTS(SELECT 1 FROM restore_termination_proofs proof WHERE proof.tenant_id=p.tenant_id AND proof.restore_id=p.restore_id AND proof.permit_id=p.id AND proof.runtime_node_id=p.runtime_node_id)) AS proved FROM restores r JOIN restore_job_contexts c ON c.tenant_id=r.tenant_id AND c.restore_id=r.id JOIN restore_launch_permits p ON p.tenant_id=r.tenant_id AND p.restore_id=r.id WHERE r.tenant_id=$1 AND r.id=$2 AND r.status IN('RESTORE_PENDING','RESTORE_RUNNING','RESTORE_CLOSING')")
            .bind(tenant).bind(restore).fetch_optional(&mut **tx).await.map_err(|e|dependency(e))?.ok_or(Denial{code:403,message:"Fixed restore historical permit missing"})?;
        let context_value: Value = row.try_get("context").map_err(|e| dependency(e))?;
        let request_value: Value = row.try_get("request").map_err(|e| dependency(e))?;
        let context: BackupManifestContext =
            serde_json::from_value(context_value.clone()).map_err(|e| dependency(e))?;
        let permit: RegisterLaunchRequest =
            serde_json::from_value(request_value.clone()).map_err(|e| dependency(e))?;
        let epoch: Uuid = row.try_get("cluster_epoch").map_err(|e| dependency(e))?;
        let source: Value = row.try_get("source_identity").map_err(|e| dependency(e))?;
        let job = match &permit.launch.purpose {
            LaunchPurpose::Backup {
                backup_id,
                attempt_id,
                job_uid,
                stage,
                image_ref,
                source_pvc_uid,
            } => {
                checked(
                    *backup_id
                        == row
                            .try_get::<Uuid, _>("backup_id")
                            .map_err(|e| dependency(e))?
                        && *attempt_id == restore
                        && *stage == BackupStage::Restore
                        && image_ref == &context.image
                        && Some(source_pvc_uid.to_string().as_str())
                            == source.get("source_pvc_uid").and_then(Value::as_str),
                    "Historical restore purpose changed",
                )?;
                *job_uid
            }
            _ => {
                return Err(Denial {
                    code: 403,
                    message: "Historical restore purpose missing",
                });
            }
        };
        let exact:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM restore_resource_intents i JOIN restore_resource_bindings b ON b.tenant_id=i.tenant_id AND b.intent_id=i.id WHERE i.tenant_id=$1 AND i.restore_id=$2 AND i.kind='POD' AND i.name=$3 AND i.namespace=$4 AND b.uid=$5) AND EXISTS(SELECT 1 FROM restore_pod_admissions WHERE tenant_id=$1 AND restore_id=$2 AND job_uid=$6)")
            .bind(tenant).bind(restore).bind(&permit.launch.pod_name).bind(&permit.launch.namespace).bind(permit.launch.pod_uid).bind(job).fetch_one(&mut **tx).await.map_err(|e|dependency(e))?;
        checked(
            exact
                && permit.protocol == PROTOCOL_VERSION
                && permit.permit_id
                    == row
                        .try_get::<Uuid, _>("permit_id")
                        .map_err(|e| dependency(e))?
                && permit.launch.validate()
                && permit.node.validate()
                && permit.launch.launch_id == restore
                && permit.launch.tenant_id == tenant
                && permit.launch.namespace == NAMESPACE
                && permit.node.cluster_epoch == epoch
                && context.cluster_epoch == epoch
                && context.stage == BackupStage::Restore
                && context.tenant_id == tenant
                && context.attempt_id == restore
                && context.backup_id
                    == row
                        .try_get::<Uuid, _>("backup_id")
                        .map_err(|e| dependency(e))?
                && context.project_id
                    == row
                        .try_get::<Uuid, _>("source_project_id")
                        .map_err(|e| dependency(e))?
                && context.expected_manifest_sha256.as_deref()
                    == Some(
                        row.try_get::<String, _>("source_manifest_sha256")
                            .map_err(|e| dependency(e))?
                            .as_str(),
                    ),
            "Historical restore identity differs from immutable source and Pod",
        )?;
        Ok(Historical {
            context,
            permit,
            proof: row.try_get("proved").map_err(|e| dependency(e))?,
            pin: json!({"context":context_value,"permit":request_value,"source":source}),
        })
    }
    pub(super) async fn decide_node(&self, r: &AdmissionRequest) -> Decision<()> {
        let binding = r.sub_resource == "binding";
        checked(
            r.namespace == NAMESPACE
                && crate::backup_manifest::valid_name(&r.name)
                && r.resource.group.is_empty()
                && r.resource.version == "v1"
                && r.resource.resource == "pods"
                && !r.dry_run
                && r.options.as_ref().is_none_or(|v| {
                    v.get("dryRun")
                        .is_none_or(|a| a.as_array().is_some_and(Vec::is_empty))
                })
                && ((binding && r.operation == "CREATE" && r.old_object.is_none())
                    || (!binding && r.sub_resource == "status" && r.operation == "UPDATE")),
            "Unsupported restore node admission operation",
        )?;
        if binding {
            checked(
                self.scheduler.valid()
                    && self.scheduler.matches(&r.user_info)
                    && match &self.scheduler {
                        ControllerIdentity::ControlPlane { username } => {
                            username == "system:kube-scheduler"
                        }
                        ControllerIdentity::ServiceAccount { username, uid } => {
                            username != &self.identities.controller.username
                                && uid != &self.identities.controller.uid
                        }
                    },
                "Exact reviewed restore scheduler identity required",
            )?;
        }
        let started = Instant::now();
        let client = self.runtime.runtime().client_clone();
        let pod = Api::<Pod>::namespaced(client.clone(), NAMESPACE)
            .get(&r.name)
            .await
            .map_err(|e| dependency(e))?;
        let live = serde_json::to_value(&pod).map_err(|e| dependency(e))?;
        let tenant = selector(&live, "/metadata/labels/sandbox.platform~1tenant-id")?;
        let restore = selector(
            &live,
            "/metadata/labels/sandbox.platform~1backup-attempt-id",
        )?;
        let pod_uid = selector(&live, "/metadata/uid")?;
        checked(
            text(&live, "/metadata/name")? == r.name
                && text(&live, "/metadata/namespace")? == NAMESPACE,
            "Restore live Pod request scope changed",
        )?;
        if binding {
            Box::pin(self.fresh_binding(r, live, tenant, restore, pod_uid, started)).await
        } else {
            Box::pin(self.historical_status(r, live, tenant, restore, pod_uid, started)).await
        }
    }
    async fn fresh_binding(
        &self,
        r: &AdmissionRequest,
        live: Value,
        tenant: Uuid,
        restore: Uuid,
        pod_uid: Uuid,
        started: Instant,
    ) -> Decision<()> {
        let value = r.object.as_ref().ok_or(Denial {
            code: 403,
            message: "Restore Binding object missing",
        })?;
        checked(
            value.get("apiVersion") == Some(&json!("v1"))
                && value.get("kind") == Some(&json!("Binding"))
                && text(value, "/metadata/name")? == r.name
                && text(value, "/metadata/namespace")? == NAMESPACE
                && selector(value, "/metadata/uid")? == pod_uid
                && text(value, "/target/kind")? == "Node"
                && value.pointer("/target/namespace").is_none_or(|v| v == "")
                && value
                    .pointer("/target/apiVersion")
                    .is_none_or(|v| v == "v1")
                && value.as_object().is_some_and(|m| {
                    m.keys().all(|k| {
                        matches!(k.as_str(), "apiVersion" | "kind" | "metadata" | "target")
                    })
                })
                && value["target"].as_object().is_some_and(|m| {
                    m.keys().all(|k| {
                        matches!(
                            k.as_str(),
                            "name" | "kind" | "uid" | "namespace" | "apiVersion"
                        )
                    })
                })
                && value["metadata"].as_object().is_some_and(|m| {
                    // Kubernetes BindingREST can merge annotations/labels
                    // into the Pod. A Binding may carry only identity.
                    m.keys().all(|k| {
                        matches!(
                            k.as_str(),
                            "name"
                                | "namespace"
                                | "uid"
                                | "resourceVersion"
                                | "creationTimestamp"
                                | "managedFields"
                        )
                    })
                })
                && value
                    .pointer("/metadata/creationTimestamp")
                    .is_none_or(Value::is_null)
                && value
                    .pointer("/metadata/managedFields")
                    .is_none_or(|v| v.is_null() || v.as_array().is_some_and(|a| a.len() <= 32))
                && value
                    .pointer("/metadata/resourceVersion")
                    .is_none_or(|v| Some(v) == live.pointer("/metadata/resourceVersion"))
                && live
                    .pointer("/metadata/deletionTimestamp")
                    .is_none_or(Value::is_null)
                && live
                    .pointer("/spec/nodeName")
                    .is_none_or(|v| v.is_null() || v == ""),
            "Restore Binding or live Pod identity changed",
        )?;
        let mut tx = self
            .database
            .begin(tenant)
            .await
            .map_err(|e| dependency(e))?;
        let a = self.load(&mut tx, tenant, restore).await?;
        tx.commit().await.map_err(|e| dependency(e))?;
        checked(
            Instant::now() < a.valid_until && started.elapsed() <= Duration::from_secs(10),
            "Restore binding authority expired after initial COMMIT acknowledgement",
        )?;
        let job = a.bindings.get("JOB").copied().ok_or(Denial {
            code: 403,
            message: "Restore Job binding missing",
        })?;
        checked(
            a.bindings.get("POD") == Some(&pod_uid),
            "Restore scheduling requires recorded exact Pod UID",
        )?;
        verify_pod_object(&live, &a.context, job, pod_uid)?;
        Box::pin(self.observe(&a, r)).await?;
        let name = text(value, "/target/name")?;
        checked(
            name.len() <= 253 && name.split('.').all(crate::backup_manifest::valid_name),
            "Restore target Node DNS identity invalid",
        )?;
        let node = Api::<Node>::all(self.runtime.runtime().client_clone())
            .get(name)
            .await
            .map_err(|e| dependency(e))?;
        let n =
            crate::backup_host::node_binding(&node, a.record.cluster_epoch).map_err(observation)?;
        checked(
            n.node_name == name
                && value
                    .pointer("/target/uid")
                    .is_none_or(|v| v.as_str() == Some(n.node_uid.to_string().as_str())),
            "Restore target Node UID/name changed",
        )?;
        // Re-read the Pod after all remote security/node observations.
        let again = serde_json::to_value(
            Api::<Pod>::namespaced(self.runtime.runtime().client_clone(), NAMESPACE)
                .get(&r.name)
                .await
                .map_err(|e| dependency(e))?,
        )
        .map_err(|e| dependency(e))?;
        checked(
            again == live,
            "Restore Pod changed during scheduling observation",
        )?;
        let mut tx = self
            .database
            .begin(tenant)
            .await
            .map_err(|e| dependency(e))?;
        let allowed: bool =
            sqlx::query_scalar("SELECT sandbox_restore_node_binding($1,$2,$3,$4,$5,$6)")
                .bind(tenant)
                .bind(restore)
                .bind(n.node_uid)
                .bind(&n.node_name)
                .bind(n.boot_id)
                .bind(&n.profile_sha256)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| dependency(e))?;
        checked(
            allowed && started.elapsed() <= Duration::from_secs(10),
            "Restore binding authority or remote observation expired after waiting",
        )?;
        let current = self.load(&mut tx, tenant, restore).await?;
        checked(
            a.pin == current.pin,
            "Restore scheduling identity changed while waiting",
        )?;
        if let Some(request) = sqlx::query_scalar::<_, Value>(
            "SELECT request FROM restore_launch_permits WHERE tenant_id=$1 AND restore_id=$2",
        )
        .bind(tenant)
        .bind(restore)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| dependency(e))?
        {
            let fixed: RegisterLaunchRequest =
                serde_json::from_value(request).map_err(|e| dependency(e))?;
            checked(
                fixed.node == n
                    && fixed.launch.pod_uid == pod_uid
                    && fixed.launch.pod_name == r.name
                    && fixed.launch.namespace == NAMESPACE,
                "Restore Binding differs from its existing immutable host permit",
            )?;
        }
        tx.commit().await.map_err(|e| dependency(e))?;
        checked(
            Instant::now() < a.valid_until
                && Instant::now() < current.valid_until
                && started.elapsed() <= Duration::from_secs(10),
            "Restore binding authority expired after final COMMIT acknowledgement",
        )?;
        Ok(())
    }
    async fn historical_status(
        &self,
        r: &AdmissionRequest,
        live: Value,
        tenant: Uuid,
        restore: Uuid,
        pod_uid: Uuid,
        started: Instant,
    ) -> Decision<()> {
        let mut tx = self
            .database
            .begin(tenant)
            .await
            .map_err(|e| dependency(e))?;
        let a = self.historical(&mut tx, tenant, restore).await?;
        tx.commit().await.map_err(|e| dependency(e))?;
        let before = r.old_object.as_ref().ok_or(Denial {
            code: 403,
            message: "Old restore status Pod required",
        })?;
        let after = r.object.as_ref().ok_or(Denial {
            code: 403,
            message: "New restore status Pod required",
        })?;
        let assigned = text(&live, "/spec/nodeName")?;
        checked(
            a.permit.launch.pod_uid == pod_uid
                && a.permit.launch.pod_name == r.name
                && a.permit.launch.namespace == NAMESPACE
                && a.permit.node.node_name == assigned
                && r.user_info.username == format!("system:node:{assigned}")
                && r.user_info.groups.iter().any(|g| g == "system:nodes"),
            "Only the exact historical assigned node may update restore status",
        )?;
        let job = match a.permit.launch.purpose {
            LaunchPurpose::Backup { job_uid, .. } => job_uid,
            _ => {
                return Err(Denial {
                    code: 403,
                    message: "Restore status Job purpose missing",
                });
            }
        };
        for v in [&live, before, after] {
            protected_pod(v, &a.context, job, pod_uid, a.proof)?;
            same_status_identity(&live, v)?;
        }
        let node = Api::<Node>::all(self.runtime.runtime().client_clone())
            .get(assigned)
            .await
            .map_err(|e| dependency(e))?;
        let n = NodeBinding {
            cluster_epoch: a.permit.node.cluster_epoch,
            node_uid: node
                .metadata
                .uid
                .as_deref()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or(Denial {
                    code: 403,
                    message: "Restore historical Node UID missing",
                })?,
            node_name: node.metadata.name.clone().ok_or(Denial {
                code: 403,
                message: "Restore historical Node name missing",
            })?,
            boot_id: node
                .status
                .as_ref()
                .and_then(|s| s.node_info.as_ref())
                .and_then(|i| Uuid::parse_str(&i.boot_id).ok())
                .ok_or(Denial {
                    code: 403,
                    message: "Restore historical Node boot missing",
                })?,
            profile_sha256: node
                .metadata
                .annotations
                .as_ref()
                .and_then(|m| m.get("sandbox.platform/runtime-profile-sha256"))
                .cloned()
                .ok_or(Denial {
                    code: 403,
                    message: "Restore historical Node profile missing",
                })?,
        };
        checked(
            n == a.permit.node && n.validate(),
            "Restore historical Node was replaced or rebooted",
        )?;
        let mut tx = self
            .database
            .begin(tenant)
            .await
            .map_err(|e| dependency(e))?;
        let locked: bool = sqlx::query_scalar("SELECT sandbox_lock_restore_observation($1,$2)")
            .bind(tenant)
            .bind(restore)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| dependency(e))?;
        checked(locked, "Restore historical observation no longer active")?;
        let current = self.historical(&mut tx, tenant, restore).await?;
        checked(
            a.pin == current.pin,
            "Restore historical identity changed while waiting",
        )?;
        for v in [&live, before, after] {
            protected_pod(v, &current.context, job, pod_uid, current.proof)?;
        }
        let allowed: bool =
            sqlx::query_scalar("SELECT sandbox_restore_node_observation($1,$2,$3,$4,$5,$6)")
                .bind(tenant)
                .bind(restore)
                .bind(n.node_uid)
                .bind(&n.node_name)
                .bind(n.boot_id)
                .bind(&n.profile_sha256)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| dependency(e))?;
        checked(
            allowed && started.elapsed() <= Duration::from_secs(10),
            "Restore historical observation identity or freshness expired after waiting",
        )?;
        tx.commit().await.map_err(|e| dependency(e))?;
        checked(
            started.elapsed() <= Duration::from_secs(10),
            "Restore historical observation expired after final COMMIT acknowledgement",
        )?;
        Ok(())
    }
}
