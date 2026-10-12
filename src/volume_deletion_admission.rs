//! Private extension of authenticated apiserver admission. Service-account
//! labels never authorize deletion; the immutable cloud-absence ledger does.
use super::*;

impl AdmissionService {
    async fn volume_cleanup_receipt(
        &self,
        tenant: Uuid,
        project: Uuid,
        namespace: &str,
        current: &Value,
        pv: bool,
        lease: bool,
    ) -> Result<bool, Denial> {
        let (pvc_name, pvc_uid, pv_name, pv_uid, handle) = if pv {
            (
                string(current, "/spec/claimRef/name"),
                string(current, "/spec/claimRef/uid"),
                string(current, "/metadata/name"),
                Some(uid(current)?),
                string(current, "/spec/csi/volumeHandle"),
            )
        } else {
            (
                string(current, "/metadata/name"),
                Some(uid(current)?),
                string(current, "/spec/volumeName"),
                None,
                None,
            )
        };
        let pvc_uid = pvc_uid
            .and_then(|v| Uuid::parse_str(v).ok())
            .ok_or(Denial::policy("Exact PVC UID required"))?;
        let pv_uid = pv_uid
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|_| Denial::policy("Exact PV UID required"))?;
        let mut tx = self
            .database
            .begin(tenant)
            .await
            .map_err(|_| Denial::dependency())?;
        let allowed: bool = sqlx::query_scalar(
            "SELECT sandbox_workspace_cleanup_authorized($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(tenant)
        .bind(project)
        .bind(namespace)
        .bind(pvc_name)
        .bind(pvc_uid)
        .bind(pv_name)
        .bind(pv_uid)
        .bind(handle)
        .bind(lease)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| Denial::dependency())?;
        tx.commit().await.map_err(|_| Denial::dependency())?;
        Ok(allowed)
    }
    pub(super) async fn deleted_workspace_pvc(
        &self,
        request: &AdmissionRequest,
        tenant: Uuid,
        project: Uuid,
    ) -> Result<bool, Denial> {
        let current = object(request)?;
        // DELETE always needs this workflow. For updates, intercept only a
        // deleting PVC; ordinary binding/status keeps the existing policy.
        if request.operation != "DELETE"
            && current
                .pointer("/metadata/deletionTimestamp")
                .is_none_or(Value::is_null)
        {
            return Ok(false);
        }
        let deleter = self
            .config
            .volume_deleter
            .as_ref()
            .is_some_and(|id| id.matches(&request.user_info));
        let storage = self
            .config
            .storage_controllers
            .iter()
            .any(|id| id.matches(&request.user_info));
        checked(
            !request.dry_run
                && request.sub_resource.is_empty()
                && ((request.operation == "DELETE" && deleter)
                    || (request.operation == "UPDATE" && storage)),
            "Only the exact volume deleter or storage finalizer controller may clean a deleted workspace",
        )?;
        checked(
            self.volume_cleanup_receipt(
                tenant,
                project,
                &request.namespace,
                current,
                false,
                request.operation == "DELETE",
            )
            .await?,
            "Cloud disk absence and the exact accepted deletion are required",
        )?;
        if request.operation == "UPDATE" {
            cleanup_metadata_update(request, current, &["kubernetes.io/pvc-protection"])?;
        }
        Ok(true)
    }
    pub(super) async fn persistent_volume(&self, request: &AdmissionRequest) -> Decision {
        checked(
            request.resource.group.is_empty()
                && request.resource.version == "v1"
                && matches!(request.operation.as_str(), "UPDATE" | "DELETE")
                && (request.sub_resource.is_empty() || request.sub_resource == "status"),
            "Unsupported PV mutation",
        )?;
        let current = object(request)?;
        let stored = request
            .old_object
            .as_ref()
            .ok_or(Denial::policy("Stored PV required"))?;
        if string(stored, "/spec/csi/driver") != Some(self.config.storage_provisioner.as_str()) {
            return Ok(());
        }
        let namespace = string(stored, "/spec/claimRef/namespace")
            .ok_or(Denial::policy("PV claim namespace required"))?;
        let ns = Api::<Namespace>::all(self.kubernetes.clone())
            .get(namespace)
            .await
            .map_err(|_| Denial::dependency())?;
        let ns = serde_json::to_value(ns).map_err(|_| Denial::dependency())?;
        if string(&ns, "/metadata/labels/sandbox.platform~1managed") != Some("true") {
            return Ok(());
        }
        checked(
            string(
                &ns,
                "/metadata/annotations/sandbox.platform~1certification-id",
            ) == Some(self.config.certification_id.as_str()),
            "Namespace certification changed",
        )?;
        let (tenant, project) = scope(&ns)?;
        self.project(tenant, project, namespace).await?;
        checked(
            uid(current)? == uid(stored)?
                && string(current, "/metadata/name") == Some(request.name.as_str())
                && string(current, "/spec/claimRef/namespace") == Some(namespace),
            "PV identity or namespace changed",
        )?;
        checked(
            string(current, "/spec/persistentVolumeReclaimPolicy") == Some("Retain")
                && string(current, "/spec/csi/driver")
                    == Some(self.config.storage_provisioner.as_str()),
            "Workspace PV must remain on its reviewed Retain CSI path",
        )?;
        if request.operation == "DELETE" {
            checked(
                !request.dry_run
                    && request.sub_resource.is_empty()
                    && self
                        .config
                        .volume_deleter
                        .as_ref()
                        .is_some_and(|id| id.matches(&request.user_info)),
                "Only the exact volume deleter may delete a workspace PV",
            )?;
            return checked(
                self.volume_cleanup_receipt(tenant, project, namespace, current, true, true)
                    .await?,
                "PV deletion requires exact physical disk absence evidence",
            );
        }
        checked(
            self.config
                .storage_controllers
                .iter()
                .any(|id| id.matches(&request.user_info)),
            "Only registered storage controllers may update workspace PV metadata/status",
        )?;
        checked(
            current.get("spec") == stored.get("spec"),
            "Workspace PV disk, claim and Retain policy are immutable",
        )?;
        if current
            .pointer("/metadata/deletionTimestamp")
            .is_some_and(|v| !v.is_null())
        {
            checked(
                self.volume_cleanup_receipt(tenant, project, namespace, current, true, false)
                    .await?,
                "Finalizer cleanup requires physical disk absence",
            )?;
            cleanup_metadata_update(
                request,
                current,
                &[
                    "kubernetes.io/pv-protection",
                    "external-provisioner.volume.kubernetes.io/finalizer",
                ],
            )?;
        } else {
            checked(
                labels(current) == labels(stored)
                    && current.pointer("/metadata/ownerReferences")
                        == stored.pointer("/metadata/ownerReferences"),
                "PV ownership metadata is immutable",
            )?;
            // Native protection/provisioner controllers may reconcile their own
            // finalizers. DELETE remains independently gated on cloud evidence.
            let finals = current
                .pointer("/metadata/finalizers")
                .and_then(Value::as_array);
            checked(
                finals.is_none_or(|v| {
                    v.iter().all(|f| {
                        matches!(
                            f.as_str(),
                            Some(
                                "kubernetes.io/pv-protection"
                                    | "external-provisioner.volume.kubernetes.io/finalizer"
                            )
                        )
                    })
                }),
                "Unknown workspace PV finalizer",
            )?;
        }
        Ok(())
    }
}
fn cleanup_metadata_update(
    request: &AdmissionRequest,
    current: &Value,
    allowed: &[&str],
) -> Decision {
    let old = request
        .old_object
        .as_ref()
        .ok_or(Denial::policy("Stored volume required"))?;
    checked(
        uid(old)? == uid(current)?
            && old.get("spec") == current.get("spec")
            && labels(old) == labels(current)
            && annotations(old) == annotations(current)
            && old.pointer("/metadata/ownerReferences")
                == current.pointer("/metadata/ownerReferences"),
        "Volume cleanup cannot change binding or ownership",
    )?;
    let before = old
        .pointer("/metadata/finalizers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let after = current
        .pointer("/metadata/finalizers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    checked(
        after.iter().all(|v| before.contains(v))
            && before
                .iter()
                .filter(|v| !after.contains(v))
                .all(|v| v.as_str().is_some_and(|f| allowed.contains(&f))),
        "Cleanup may remove only its registered storage protection finalizers",
    )
}
