//! Exact Job status, scheduler binding, node status and finalizer transitions.
use super::*;
use crate::{
    backup_admission::{verify_job_object, verify_pod_object},
    backup_manifest::{BackupManifestContext, NAMESPACE},
    nodeguard::protocol::NodeBinding,
};
impl AdmissionService {
    pub(super) async fn backup_job_update(
        &self,
        r: &AdmissionRequest,
        b: &sqlx::postgres::PgRow,
        c: &BackupManifestContext,
        current: &Value,
        bindings: &BTreeMap<String, Uuid>,
        admitted: bool,
    ) -> Decision {
        let ids = self
            .config
            .backup
            .as_ref()
            .ok_or(Denial::policy("Backup disabled"))?;
        let job = *bindings
            .get("JOB")
            .ok_or(Denial::policy("Known Job UID required"))?;
        let old = r.old_object.as_ref();
        if r.resource.resource == "jobs" {
            checked(
                r.operation == "UPDATE"
                    && r.sub_resource == "status"
                    && ids.job_controller.matches(&r.user_info),
                "Only Job controller may update Job status",
            )?;
            let before = old.ok_or(Denial::policy("Old Job required"))?;
            verify_job_object(current, c, job)?;
            verify_job_object(before, c, job)?;
            same_metadata(before, current)?;
            return checked(
                before.get("spec") == current.get("spec"),
                "Job status changed specification",
            );
        }
        checked(
            r.resource.group.is_empty()
                && r.resource.version == "v1"
                && r.resource.resource == "pods"
                && r.namespace == NAMESPACE
                && admitted,
            "Backup Pod requires consumed admission",
        )?;
        let pod = Uuid::parse_str(uid(current)?).map_err(|_| Denial::policy("Invalid Pod UID"))?;
        checked(
            bindings.get("POD").is_none_or(|v| *v == pod),
            "Backup Pod UID changed",
        )?;
        verify_managed_pod(current, c, job, pod)?;
        // Once protection has gone, status/GC can continue only with immutable
        // exact historical evidence; absence of the finalizer is never proof.
        let removed_before = old.is_some_and(|v| {
            finalizers(v)
                .is_ok_and(|f| !f.contains(&crate::runtime_manifest::TERMINATION_FINALIZER))
        });
        if !finalizers(current)?.contains(&crate::runtime_manifest::TERMINATION_FINALIZER)
            && (r.sub_resource == "status" || removed_before)
        {
            let mut tx = self
                .database
                .begin(c.tenant_id)
                .await
                .map_err(|_| Denial::dependency())?;
            let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM backup_termination_proofs p JOIN backup_launch_permits l ON l.tenant_id=p.tenant_id AND l.id=p.permit_id WHERE p.tenant_id=$1 AND p.backup_id=$2 AND p.attempt_id=$3 AND l.pod_uid=$4 AND l.launch->'purpose'->>'job_uid'=$5)")
                .bind(c.tenant_id).bind(c.backup_id).bind(c.attempt_id).bind(pod).bind(job.to_string()).fetch_one(&mut *tx).await.map_err(|_|Denial::dependency())?;
            tx.commit().await.map_err(|_| Denial::dependency())?;
            checked(
                exists,
                "Unprotected backup Pod lacks exact termination evidence",
            )?;
        }
        if r.sub_resource == "binding" {
            checked(
                r.operation == "CREATE"
                    && self.config.scheduler.matches(&r.user_info)
                    && current
                        .pointer("/spec/nodeName")
                        .is_none_or(|v| v.is_null() || v == ""),
                "Only scheduler may bind a fresh backup Pod",
            )?;
            let binding = object(r)?;
            let target =
                string(binding, "/target/name").ok_or(Denial::policy("Node target required"))?;
            checked(
                string(binding, "/target/kind") == Some("Node")
                    && string(binding, "/metadata/name") == Some(r.name.as_str())
                    && string(binding, "/metadata/namespace") == Some(NAMESPACE)
                    && string(binding, "/metadata/uid").is_none_or(|u| u == pod.to_string()),
                "Backup binding identity changed",
            )?;
            return self.backup_node(c, target, true).await;
        }
        let closing = b
            .try_get::<String, _>("status")
            .map_err(|_| Denial::dependency())?
            .ends_with("CLOSING");
        if r.operation == "DELETE" {
            checked(
                ids.controller.matches(&r.user_info)
                    && closing
                    && bindings.get("POD") == Some(&pod)
                    && r.sub_resource.is_empty(),
                "Backup Pod deletion requires recorded closing intent",
            )?;
            let options = r
                .options
                .as_ref()
                .ok_or(Denial::policy("Delete preconditions required"))?;
            return checked(
                string(options, "/preconditions/uid") == Some(uid(current)?)
                    && string(options, "/preconditions/resourceVersion")
                        == string(current, "/metadata/resourceVersion")
                    && options.get("gracePeriodSeconds") == Some(&json!(30)),
                "Backup deletion requires exact UID/resourceVersion and ordinary grace",
            );
        }
        checked(r.operation == "UPDATE", "Unsupported backup Pod transition")?;
        let before = old.ok_or(Denial::policy("Old Pod required"))?;
        verify_managed_pod(before, c, job, pod)?;
        checked(
            before.get("spec") == current.get("spec") && uid(before)? == uid(current)?,
            "Backup Pod specification is immutable",
        )?;
        if r.sub_resource == "status" {
            same_metadata(before, current)?;
            if self.config.scheduler.matches(&r.user_info) {
                return scheduler_status(before, current);
            }
            let assigned = string(before, "/spec/nodeName")
                .ok_or(Denial::policy("Assigned backup node required"))?;
            checked(
                r.user_info.username == format!("system:node:{assigned}")
                    && r.user_info.groups.iter().any(|g| g == "system:nodes"),
                "Only authenticated assigned node may update backup status",
            )?;
            return self.backup_node(c, assigned, false).await;
        }
        checked(
            r.sub_resource.is_empty() && before.get("status") == current.get("status"),
            "Backup metadata update changed status",
        )?;
        let old_final = finalizers(before)?;
        let new_final = finalizers(current)?;
        let termination = crate::runtime_manifest::TERMINATION_FINALIZER;
        if old_final.contains(&termination) && !new_final.contains(&termination) {
            checked(
                ids.controller.matches(&r.user_info)
                    && closing
                    && before
                        .pointer("/metadata/deletionTimestamp")
                        .is_some_and(|v| !v.is_null())
                    && before.pointer("/metadata/deletionTimestamp")
                        == current.pointer("/metadata/deletionTimestamp"),
                "Backup protection removal requires closing controller",
            )?;
            let mut tx = self
                .database
                .begin(c.tenant_id)
                .await
                .map_err(|_| Denial::dependency())?;
            let proof:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM backup_termination_proofs p JOIN backup_launch_permits l ON l.tenant_id=p.tenant_id AND l.id=p.permit_id WHERE p.tenant_id=$1 AND p.backup_id=$2 AND p.attempt_id=$3 AND l.pod_uid=$4 AND l.launch->'purpose'->>'job_uid'=$5 AND p.recorded_at>clock_timestamp()-interval '30 seconds' AND p.observed_at>clock_timestamp()-interval '30 seconds' AND l.launch->>'pod_name'=$6)")
            .bind(c.tenant_id).bind(c.backup_id).bind(c.attempt_id).bind(pod).bind(job.to_string()).bind(&r.name).fetch_one(&mut *tx).await.map_err(|_|Denial::dependency())?;
            tx.commit().await.map_err(|_| Denial::dependency())?;
            checked(proof, "Fresh exact backup host termination proof required")?;
            checked(
                new_final
                    == old_final
                        .iter()
                        .copied()
                        .filter(|v| *v != termination)
                        .collect::<Vec<_>>(),
                "Only termination protection may be removed",
            )?;
        } else if ids.job_controller.matches(&r.user_info) {
            checked(
                new_final
                    == old_final
                        .iter()
                        .copied()
                        .filter(|v| *v != "batch.kubernetes.io/job-tracking")
                        .collect::<Vec<_>>(),
                "Job controller may remove only Job tracking",
            )?;
        } else {
            checked(
                ids.controller.matches(&r.user_info) && old_final == new_final,
                "Unauthorized backup metadata mutation",
            )?;
        }
        let mut comparable = current.clone();
        comparable["metadata"]["finalizers"] = before["metadata"]["finalizers"].clone();
        same_metadata(before, &comparable)
    }
    async fn backup_node(&self, c: &BackupManifestContext, name: &str, start: bool) -> Decision {
        let node = Api::<Node>::all(self.kubernetes.clone())
            .get(name)
            .await
            .map_err(|_| Denial::dependency())?;
        let binding = NodeBinding {
            cluster_epoch: c.cluster_epoch,
            node_uid: node
                .metadata
                .uid
                .as_deref()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or(Denial::policy("Node UID required"))?,
            node_name: name.into(),
            boot_id: node
                .status
                .as_ref()
                .and_then(|s| s.node_info.as_ref())
                .and_then(|s| Uuid::parse_str(&s.boot_id).ok())
                .ok_or(Denial::policy("Node boot ID required"))?,
            profile_sha256: node
                .metadata
                .annotations
                .as_ref()
                .and_then(|a| a.get("sandbox.platform/runtime-profile-sha256"))
                .cloned()
                .ok_or(Denial::policy("Node profile required"))?,
        };
        checked(binding.validate(), "Node identity invalid")?;
        if start {
            let taints = node
                .spec
                .as_ref()
                .and_then(|s| s.taints.as_ref())
                .map(Vec::as_slice)
                .unwrap_or_default();
            checked(
                node.metadata.deletion_timestamp.is_none()
                    && node
                        .spec
                        .as_ref()
                        .is_some_and(|s| s.unschedulable != Some(true))
                    && node
                        .metadata
                        .labels
                        .as_ref()
                        .and_then(|l| l.get("sandbox.platform/worker-pool"))
                        .is_some_and(|v| v == "kata")
                    && node
                        .status
                        .as_ref()
                        .and_then(|s| s.conditions.as_ref())
                        .is_some_and(|cs| {
                            cs.iter().any(|x| x.type_ == "Ready" && x.status == "True")
                        })
                    && taints.iter().any(|t| {
                        t.key == "sandbox.platform/untrusted"
                            && t.value.as_deref() == Some("true")
                            && t.effect == "NoSchedule"
                    })
                    && taints.iter().all(|t| {
                        !matches!(t.effect.as_str(), "NoSchedule" | "NoExecute")
                            || (t.key == "sandbox.platform/untrusted"
                                && t.value.as_deref() == Some("true")
                                && t.effect == "NoSchedule")
                    }),
                "Backup target is not a schedulable dedicated Kata node",
            )?;
        }
        let mut tx = self
            .database
            .begin(c.tenant_id)
            .await
            .map_err(|_| Denial::dependency())?;
        let allowed: bool = sqlx::query_scalar(if start {
            "SELECT sandbox_backup_node_binding($1,$2,$3,$4,$5,$6)"
        } else {
            "SELECT sandbox_backup_node_observation($1,$2,$3,$4,$5,$6)"
        })
        .bind(c.tenant_id)
        .bind(c.attempt_id)
        .bind(binding.node_uid)
        .bind(name)
        .bind(binding.boot_id)
        .bind(&binding.profile_sha256)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| Denial::dependency())?;
        tx.commit().await.map_err(|_| Denial::dependency())?;
        checked(
            allowed,
            "Backup node is outside exact registered launch authority",
        )
    }
}
fn finalizers(v: &Value) -> Result<Vec<&str>, Denial> {
    let Some(v) = v.pointer("/metadata/finalizers") else {
        return Ok(Vec::new());
    };
    v.as_array()
        .ok_or(Denial::policy("Finalizers must be array"))?
        .iter()
        .map(|v| v.as_str().ok_or(Denial::policy("Invalid finalizer")))
        .collect()
}
fn verify_managed_pod(v: &Value, c: &BackupManifestContext, job: Uuid, pod: Uuid) -> Decision {
    let finals = finalizers(v)?;
    checked(
        finals.iter().all(|v| {
            matches!(
                *v,
                "sandbox.platform/termination-protection" | "batch.kubernetes.io/job-tracking"
            )
        }),
        "Unknown backup Pod finalizer",
    )?;
    let mut view = v.clone();
    let m = view
        .get_mut("metadata")
        .and_then(Value::as_object_mut)
        .ok_or(Denial::policy("Pod metadata required"))?;
    m.remove("deletionTimestamp");
    m.remove("deletionGracePeriodSeconds");
    m.insert(
        "finalizers".into(),
        json!([
            crate::runtime_manifest::TERMINATION_FINALIZER,
            "batch.kubernetes.io/job-tracking"
        ]),
    );
    verify_pod_object(&view, c, job, pod)
}
