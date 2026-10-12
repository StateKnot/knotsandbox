//! Private routing from the authenticated apiserver. Until an exact persisted
//! intent exists no backup-labeled resource receives a namespace exemption.
use super::*;
use crate::{
    backup_admission::{BackupAdmissionPlan, BackupAuthority, validate_backup_resource},
    backup_job::{BackupCloudSettings, BackupJobRuntime},
    backup_manifest::{BACKUP_LABEL, NAMESPACE},
    runtime::KubernetesRuntime,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
impl AdmissionService {
    /// This gate is independent of profile enablement: old backups retain their
    /// keys. Reserved names are protected from their very first creation, before
    /// a profile exists, so a pre-registration delayed DELETE cannot win later.
    pub(super) async fn backup_key_secret(&self, r: &AdmissionRequest) -> Option<Decision> {
        if !r.resource.group.is_empty()
            || r.resource.resource != "secrets"
            || r.namespace != NAMESPACE
        {
            return None;
        }
        let historical = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM backup_profiles WHERE password_secret=$1 OR signing_private_secret=$1 OR signing_public_secret=$1)"
        ).bind(&r.name).fetch_one(&self.database.pool).await;
        let historical = match historical {
            Ok(value) => value,
            Err(_) => return Some(Err(Denial::dependency())),
        };
        if !historical && !r.name.starts_with("sbx-bkey-") {
            return None;
        }
        Some((|| {
            checked(
                !historical && r.operation == "CREATE" && r.sub_resource.is_empty(),
                "Backup key identities are permanent; rotate with a new reserved name",
            )?;
            checked(
                !r.user_info.username.starts_with("system:")
                    && r.user_info
                        .groups
                        .iter()
                        .any(|g| g == "sandbox:backup-key-installers"),
                "Backup key creation requires the dedicated installation identity",
            )?;
            let value = object(r)?;
            checked(
                crate::backup_manifest::valid_name(&r.name)
                    && r.name.len() > 9
                    && string(value, "/metadata/name") == Some(r.name.as_str())
                    && string(value, "/metadata/namespace") == Some(NAMESPACE)
                    && value.pointer("/metadata/generateName").is_none()
                    && value.pointer("/metadata/deletionTimestamp").is_none()
                    && ["/metadata/ownerReferences", "/metadata/finalizers"]
                        .iter()
                        .all(|key| {
                            value
                                .pointer(key)
                                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
                        })
                    && value.get("immutable") == Some(&Value::Bool(true))
                    && value.get("type").and_then(Value::as_str) == Some("Opaque")
                    && value.get("stringData").is_none(),
                "Immutable unowned backup key required",
            )?;
            let data = value
                .get("data")
                .and_then(Value::as_object)
                .ok_or(Denial::policy("Backup key data required"))?;
            checked(
                data.len() == 1
                    && data.iter().all(|(key, value)| {
                        ["password", "private.pem", "public.pem"].contains(&key.as_str())
                            && value.as_str().is_some_and(|text| {
                                text.len() <= 5464
                                    && STANDARD
                                        .decode(text)
                                        .is_ok_and(|bytes| !bytes.is_empty() && bytes.len() <= 4096)
                            })
                    }),
                "Backup key requires exactly one bounded approved entry",
            )
        })())
    }
    pub(super) async fn backup_resource(&self, r: &AdmissionRequest) -> Option<Decision> {
        // Ordinary resource paths retain their previous policy. A forged backup label
        // only opts into this stricter gate; it does not opt out of managed admission.
        let obj = r.object.as_ref().or(r.old_object.as_ref());
        let labeled = obj
            .and_then(|o| o.pointer("/metadata/labels"))
            .and_then(|l| l.get(BACKUP_LABEL))
            .and_then(Value::as_str)
            .is_some();
        let reserved = r.name.starts_with("sbx-bs-")
            || r.name.starts_with("sbx-bkp-")
            || r.name.starts_with("sbx-bcfg-")
            || r.name.starts_with("sbx-bvol-")
            || r.name.starts_with("sbx-capture-");
        // CSI-created content/PV may not carry labels; follow only their exact ref.
        let derived = obj.is_some_and(|o| {
            o.pointer("/spec/volumeSnapshotRef/name")
                .and_then(Value::as_str)
                .is_some_and(|s| s.starts_with("sbx-bs-"))
                || ["/spec/volumes", "/spec/template/spec/volumes"]
                    .iter()
                    .any(|p| {
                        o.pointer(p).and_then(Value::as_array).is_some_and(|vs| {
                            vs.iter().any(|v| {
                                string(v, "/persistentVolumeClaim/claimName")
                                    .is_some_and(|n| n.starts_with("sbx-bvol-"))
                            })
                        })
                    })
                || o.pointer("/spec/claimRef/name")
                    .and_then(Value::as_str)
                    .is_some_and(|s| s.starts_with("sbx-bvol-"))
        });
        if !(labeled || reserved || derived) {
            return None;
        }
        Some(self.backup_decide(r).await)
    }
    async fn backup_decide(&self, r: &AdmissionRequest) -> Decision {
        let ids = self
            .config
            .backup
            .as_ref()
            .ok_or(Denial::policy("Backup admission is disabled"))?;
        checked(
            r.operation != "CONNECT" && !r.dry_run,
            "Backup CONNECT/dry-run denied",
        )?;
        let mut current = if r.resource.resource == "pods" && r.sub_resource == "binding" {
            checked(r.namespace == NAMESPACE, "Backup binding namespace changed")?;
            serde_json::to_value(
                Api::<Pod>::namespaced(self.kubernetes.clone(), NAMESPACE)
                    .get(&r.name)
                    .await
                    .map_err(|_| Denial::dependency())?,
            )
            .map_err(|_| Denial::dependency())?
        } else {
            object(r)?.clone()
        };
        let namespace = r.namespace.as_str();
        // Resolve missing CSI metadata through a fresh referenced namespaced object.
        let label_source = if current
            .pointer("/metadata/labels/sandbox.platform~1tenant-id")
            .is_some()
        {
            current.clone()
        } else if let (Some(ns), Some(name)) = (
            string(&current, "/spec/volumeSnapshotRef/namespace"),
            string(&current, "/spec/volumeSnapshotRef/name"),
        ) {
            let ar = ApiResource::from_gvk(&GroupVersionKind::gvk(
                "snapshot.storage.k8s.io",
                "v1",
                "VolumeSnapshot",
            ));
            serde_json::to_value(
                Api::<DynamicObject>::namespaced_with(self.kubernetes.clone(), ns, &ar)
                    .get(name)
                    .await
                    .map_err(|_| Denial::dependency())?,
            )
            .map_err(|_| Denial::dependency())?
        } else if let (Some(ns), Some(name)) = (
            string(&current, "/spec/claimRef/namespace"),
            string(&current, "/spec/claimRef/name"),
        ) {
            serde_json::to_value(
                Api::<PersistentVolumeClaim>::namespaced(self.kubernetes.clone(), ns)
                    .get(name)
                    .await
                    .map_err(|_| Denial::dependency())?,
            )
            .map_err(|_| Denial::dependency())?
        } else {
            return Err(Denial::policy(
                "Backup resource lacks an authoritative scope selector",
            ));
        };
        let tenant = string(
            &label_source,
            "/metadata/labels/sandbox.platform~1tenant-id",
        )
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or(Denial::policy("Backup tenant selector required"))?;
        let backup = string(
            &label_source,
            "/metadata/labels/sandbox.platform~1backup-id",
        )
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or(Denial::policy("Backup identity selector required"))?;
        let mut tx = self
            .database
            .begin(tenant)
            .await
            .map_err(|_| Denial::dependency())?;
        let row=sqlx::query("SELECT b.*,bp.settings,bp.snapshot_class,bp.clone_storage_class,bp.certification_sha256,bp.certified_until,bp.enabled AS profile_enabled,c.cluster_epoch AS current_epoch FROM backups b JOIN backup_profiles bp ON bp.id=b.profile_id CROSS JOIN platform_configuration c WHERE b.tenant_id=$1 AND b.id=$2")
   .bind(tenant).bind(backup).fetch_optional(&mut *tx).await.map_err(|_|Denial::dependency())?.ok_or(Denial::policy("Backup intent missing"))?;
        let cloud: BackupCloudSettings =
            serde_json::from_value(row.try_get("settings").map_err(|_| Denial::dependency())?)
                .map_err(|_| Denial::policy("Invalid backup profile"))?;
        if r.operation == "CREATE" {
            cloud.validate().map_err(|_| {
                Denial::policy("Current backup deployment contract required for new work")
            })?;
        }
        let active: bool = sqlx::query_scalar("SELECT sandbox_backup_authorized($1,$2,$3)")
            .bind(tenant)
            .bind(backup)
            .bind(ids.controller.username == r.user_info.username)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| Denial::dependency())?;
        if r.resource.resource == "configmaps" && r.name.starts_with("sbx-capture-") {
            checked(
                r.operation == "CREATE"
                    && r.sub_resource.is_empty()
                    && ids.controller.matches(&r.user_info)
                    && active,
                "Only active backup controller may hand off capture result",
            )?;
            let wanted:Option<Value>=sqlx::query_scalar("SELECT expected_object FROM backup_resource_intents WHERE tenant_id=$1 AND backup_id=$2 AND kind='CAPTURE_REPORT' AND namespace=$3 AND name=$4 AND NOT EXISTS(SELECT 1 FROM backup_resource_bindings rb WHERE rb.tenant_id=$1 AND rb.intent_id=backup_resource_intents.id)")
                .bind(tenant).bind(backup).bind(namespace).bind(&r.name).fetch_optional(&mut *tx).await.map_err(|_|Denial::dependency())?.flatten();
            let mut wanted = wanted.ok_or(Denial::policy(
                "Capture handoff intent missing or already bound",
            ))?;
            normalize_created(&mut current);
            normalize_created(&mut wanted);
            tx.commit().await.map_err(|_| Denial::dependency())?;
            return checked(
                current == wanted,
                "Capture result differs from durable intent",
            );
        }
        // Storage intents exist before CSI mutates anything and before Job config can
        // include a bound clone UID. They have a separate strict manifest path.
        let kind = r.resource.resource.as_str();
        if matches!(
            kind,
            "volumesnapshots"
                | "volumesnapshotcontents"
                | "persistentvolumeclaims"
                | "persistentvolumes"
        ) {
            let rows=sqlx::query("SELECT i.kind,i.expected_object,b.uid FROM backup_resource_intents i LEFT JOIN backup_resource_bindings b ON b.tenant_id=i.tenant_id AND b.intent_id=i.id WHERE i.tenant_id=$1 AND i.backup_id=$2 AND i.namespace=$3 AND i.name=$4")
    .bind(tenant).bind(backup).bind(namespace).bind(&r.name).fetch_all(&mut *tx).await.map_err(|_|Denial::dependency())?;
            tx.commit().await.map_err(|_| Denial::dependency())?;
            BackupJobRuntime::new(KubernetesRuntime::from_client(self.kubernetes.clone()))
                .verify_network(&cloud)
                .await
                .map_err(|_| Denial::policy("Backup network boundary drift"))?;
            checked(active, "Backup creation authority unavailable")?;
            let clone_class: String = row
                .try_get("clone_storage_class")
                .map_err(|_| Denial::dependency())?;
            BackupJobRuntime::new(KubernetesRuntime::from_client(self.kubernetes.clone()))
                .verify_clone_storage(&clone_class, &cloud)
                .await
                .map_err(|_| Denial::policy("Clone storage encryption or retention drift"))?;
            if matches!(kind, "volumesnapshots" | "volumesnapshotcontents") {
                let class_name: String = row
                    .try_get("snapshot_class")
                    .map_err(|_| Denial::dependency())?;
                let class = crate::backup_runtime::dyn_api(
                    &KubernetesRuntime::from_client(self.kubernetes.clone()),
                    "VolumeSnapshotClass",
                    None,
                )
                .get(&class_name)
                .await
                .map_err(|_| Denial::dependency())?;
                crate::backup_runtime::validate_snapshot_class(
                    &serde_json::to_value(class).map_err(|_| Denial::dependency())?,
                    &cloud.deployment,
                )
                .map_err(|_| Denial::policy("Snapshot deployment tag or retention drift"))?;
            }
            if r.operation == "CREATE"
                && ids.controller.username == r.user_info.username
                && ids.controller.uid == r.user_info.uid
            {
                checked(
                    r.sub_resource.is_empty() && rows.len() == 1,
                    "Exact storage intent required",
                )?;
                let expected: Option<Value> = rows[0]
                    .try_get("expected_object")
                    .map_err(|_| Denial::dependency())?;
                let expected = expected.ok_or(Denial::policy(
                    "Generated storage object cannot be caller-created",
                ))?;
                checked(
                    rows[0]
                        .try_get::<Option<Uuid>, _>("uid")
                        .map_err(|_| Denial::dependency())?
                        .is_none(),
                    "Known storage object cannot be recreated",
                )?;
                normalize_created(&mut current);
                let mut expected = expected;
                normalize_created(&mut expected);
                return checked(current == expected, "Backup storage intent drift");
            }
            // CSI status/binding paths are intentionally kept closed until their exact
            // generated-resource validators below have proved immutable claim/handle.
            let reference = self.backup_storage_reference(&current).await?;
            return self.backup_csi_update(r, &row, &reference, &rows).await;
        }
        let attempt = string(
            &current,
            "/metadata/labels/sandbox.platform~1backup-attempt-id",
        )
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or(Denial::policy("Backup attempt selector required"))?;
        let context:Value=sqlx::query_scalar("SELECT context FROM backup_job_contexts WHERE tenant_id=$1 AND backup_id=$2 AND attempt_id=$3").bind(tenant).bind(backup).bind(attempt).fetch_optional(&mut *tx).await.map_err(|_|Denial::dependency())?.ok_or(Denial::policy("Persisted Job context required"))?;
        let context: crate::backup_manifest::BackupManifestContext =
            serde_json::from_value(context).map_err(|_| Denial::dependency())?;
        let mut bindings = BTreeMap::new();
        for b in sqlx::query("SELECT i.kind,b.uid FROM backup_resource_intents i JOIN backup_resource_bindings b ON b.tenant_id=i.tenant_id AND b.intent_id=i.id WHERE i.tenant_id=$1 AND i.backup_id=$2 AND i.attempt_id=$3").bind(tenant).bind(backup).bind(attempt).fetch_all(&mut *tx).await.map_err(|_|Denial::dependency())?{
   bindings.insert(b.try_get::<String,_>("kind").map_err(|_|Denial::dependency())?,b.try_get::<Uuid,_>("uid").map_err(|_|Denial::dependency())?);
  }
        let admitted:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM backup_pod_admissions WHERE tenant_id=$1 AND backup_id=$2 AND attempt_id=$3 AND job_uid=$4)")
            .bind(tenant).bind(backup).bind(attempt).bind(bindings.get("JOB").copied()).fetch_one(&mut *tx).await.map_err(|_|Denial::dependency())?;
        tx.commit().await.map_err(|_| Denial::dependency())?;
        if r.sub_resource == "binding"
            || r.operation == "DELETE"
            || (r.operation == "UPDATE"
                && (r.resource.resource == "pods" || r.sub_resource == "status"))
        {
            return self
                .backup_job_update(r, &row, &context, &current, &bindings, admitted)
                .await;
        }
        BackupJobRuntime::new(KubernetesRuntime::from_client(self.kubernetes.clone()))
            .verify_network(&cloud)
            .await
            .map_err(|_| Denial::policy("Backup network boundary drift"))?;
        BackupJobRuntime::new(KubernetesRuntime::from_client(self.kubernetes.clone()))
            .verify_profile_secrets(&cloud)
            .await
            .map_err(|_| Denial::policy("Backup Secret identity drift"))?;
        let authority = BackupAuthority {
            context,
            block: None,
            hold_active: active,
            intent_active: active,
            certification_current: active,
            network_verified: true,
            job_uid: bindings.get("JOB").copied(),
            pod_uid: bindings.get("POD").copied(),
            pvc_uid: bindings.get("CLONE_PVC").copied(),
            start_allowed: active,
        };
        let plan = validate_backup_resource(r, &authority, ids)?;
        match plan {
            BackupAdmissionPlan::Allow => Ok(()),
            BackupAdmissionPlan::ConsumePodCreate {
                attempt_id,
                review_uid,
                job_uid,
            } => {
                let mut tx = self
                    .database
                    .begin(tenant)
                    .await
                    .map_err(|_| Denial::dependency())?;
                let allowed: bool =
                    sqlx::query_scalar("SELECT sandbox_admit_backup_pod($1,$2,$3,$4)")
                        .bind(tenant)
                        .bind(attempt_id)
                        .bind(review_uid)
                        .bind(job_uid)
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(|_| Denial::dependency())?;
                tx.commit().await.map_err(|_| Denial::dependency())?;
                checked(
                    allowed,
                    "Backup Pod attempt has no remaining one-shot admission",
                )
            }
        }
    }
    async fn backup_storage_reference(&self, value: &Value) -> Result<Value, Denial> {
        if let (Some(ns), Some(name)) = (
            string(value, "/spec/volumeSnapshotRef/namespace"),
            string(value, "/spec/volumeSnapshotRef/name"),
        ) {
            let ar = ApiResource::from_gvk(&GroupVersionKind::gvk(
                "snapshot.storage.k8s.io",
                "v1",
                "VolumeSnapshot",
            ));
            serde_json::to_value(
                Api::<DynamicObject>::namespaced_with(self.kubernetes.clone(), ns, &ar)
                    .get(name)
                    .await
                    .map_err(|_| Denial::dependency())?,
            )
            .map_err(|_| Denial::dependency())
        } else if let (Some(ns), Some(name)) = (
            string(value, "/spec/claimRef/namespace"),
            string(value, "/spec/claimRef/name"),
        ) {
            serde_json::to_value(
                Api::<PersistentVolumeClaim>::namespaced(self.kubernetes.clone(), ns)
                    .get(name)
                    .await
                    .map_err(|_| Denial::dependency())?,
            )
            .map_err(|_| Denial::dependency())
        } else {
            Ok(value.clone())
        }
    }
    async fn backup_csi_update(
        &self,
        r: &AdmissionRequest,
        b: &sqlx::postgres::PgRow,
        reference: &Value,
        intents: &[sqlx::postgres::PgRow],
    ) -> Decision {
        let storage = self
            .config
            .storage_controllers
            .iter()
            .any(|i| i.matches(&r.user_info));
        let scheduler = self.config.scheduler.matches(&r.user_info);
        checked(
            (storage || scheduler)
                && matches!(r.operation.as_str(), "CREATE" | "UPDATE")
                && (r.sub_resource.is_empty() || r.sub_resource == "status"),
            "Only reviewed CSI/binding controllers may change backup storage",
        )?;
        let value = object(r)?;
        let old = r.old_object.as_ref();
        let source: crate::backup_runtime::BackupSource =
            serde_json::from_value(b.try_get("source").map_err(|_| Denial::dependency())?)
                .map_err(|_| Denial::dependency())?;
        let kind = r.resource.resource.as_str();
        checked(
            !scheduler || kind == "persistentvolumeclaims",
            "Scheduler may only select the backup claim node",
        )?;
        if r.operation == "UPDATE" {
            let stored = old.ok_or(Denial::policy("Stored storage identity required"))?;
            checked(
                uid(value)? == uid(stored)?
                    && string(value, "/metadata/name") == Some(r.name.as_str())
                    && string(value, "/metadata/namespace")
                        == string(stored, "/metadata/namespace"),
                "Storage identity changed",
            )?;
            checked(
                value
                    .pointer("/metadata/deletionTimestamp")
                    .is_none_or(Value::is_null),
                "Backup storage deletion requires separate physical cleanup",
            )?;
            for intent in intents {
                if let Some(known) = intent
                    .try_get::<Option<Uuid>, _>("uid")
                    .map_err(|_| Denial::dependency())?
                {
                    checked(
                        uid(value)? == known.to_string(),
                        "Stored backup UID was replaced",
                    )?;
                }
            }
        }
        let tenant: Uuid = b.try_get("tenant_id").map_err(|_| Denial::dependency())?;
        let backup: Uuid = b.try_get("id").map_err(|_| Denial::dependency())?;
        checked(
            string(reference, "/metadata/labels/sandbox.platform~1tenant-id")
                == Some(tenant.to_string().as_str())
                && string(reference, "/metadata/labels/sandbox.platform~1backup-id")
                    == Some(backup.to_string().as_str()),
            "Fresh CSI reference changed backup ownership",
        )?;
        let driver = Some(&json!("diskplugin.csi.alibabacloud.com"));
        match kind {
            "volumesnapshotcontents" => {
                checked(storage, "Snapshot controller identity required")?;
                let spec = value
                    .get("spec")
                    .ok_or(Denial::policy("Snapshot specification required"))?;
                let ref_uid = string(reference, "/metadata/uid")
                    .ok_or(Denial::policy("Source snapshot UID required"))?;
                checked(
                    spec.get("driver") == driver
                        && spec.get("deletionPolicy") == Some(&json!("Retain"))
                        && spec.get("sourceVolumeMode") == Some(&json!("Filesystem")),
                    "Snapshot mode/driver/retention changed",
                )?;
                let reference_name = string(reference, "/metadata/name")
                    .ok_or(Denial::policy("Snapshot name required"))?;
                let reference_namespace = string(reference, "/metadata/namespace")
                    .ok_or(Denial::policy("Snapshot namespace required"))?;
                checked(
                    string(value, "/spec/volumeSnapshotRef/name") == Some(reference_name)
                        && string(value, "/spec/volumeSnapshotRef/namespace")
                            == Some(reference_namespace),
                    "Snapshot reference changed",
                )?;
                if r.operation == "CREATE" {
                    checked(
                        reference_namespace == source.namespace
                            && reference_name == source.snapshot_name()
                            && r.name == format!("snapcontent-{ref_uid}")
                            && string(value, "/spec/volumeSnapshotRef/uid") == Some(ref_uid)
                            && spec.get("source")
                                == Some(&json!({"volumeHandle":source.cloud_disk}))
                            && spec.get("volumeSnapshotClassName")
                                == Some(&json!(source.snapshot_class)),
                        "Generated source snapshot content differs from frozen source",
                    )?;
                } else {
                    let mut before = old
                        .and_then(|v| v.get("spec"))
                        .cloned()
                        .ok_or(Denial::policy("Previous snapshot spec required"))?;
                    let mut after = spec.clone();
                    // Only fill the pre-provisioned snapshot UID once. Never switch it.
                    for v in [&mut before, &mut after] {
                        if let Some(m) = v
                            .get_mut("volumeSnapshotRef")
                            .and_then(Value::as_object_mut)
                        {
                            for key in ["uid", "resourceVersion", "kind", "apiVersion"] {
                                m.remove(key);
                            }
                        }
                    }
                    checked(
                        before == after
                            && string(value, "/spec/volumeSnapshotRef/uid") == Some(ref_uid),
                        "Snapshot content binding/source changed",
                    )?;
                    if reference_namespace == NAMESPACE {
                        checked(value.pointer("/metadata/annotations/snapshot.storage.kubernetes.io~1allow-volume-mode-change")==Some(&json!("true")),"Conversion approval changed")?;
                    }
                }
            }
            "volumesnapshots" => {
                checked(
                    storage
                        && r.operation == "UPDATE"
                        && old.and_then(|v| v.get("spec")) == value.get("spec"),
                    "Snapshot spec is immutable",
                )?;
                checked(protection_preserved(value), "Snapshot protection removed")?;
            }
            "persistentvolumeclaims" => {
                checked(
                    value
                        .pointer("/metadata/annotations")
                        .and_then(Value::as_object)
                        .is_none_or(|m| {
                            m.keys().all(|k| {
                                matches!(
                                    k.as_str(),
                                    "pv.kubernetes.io/bind-completed"
                                        | "pv.kubernetes.io/bound-by-controller"
                                        | "volume.kubernetes.io/selected-node"
                                        | "volume.kubernetes.io/storage-provisioner"
                                        | "volume.beta.kubernetes.io/storage-provisioner"
                                )
                            })
                        }),
                    "Unapproved PVC cloud or provisioner override",
                )?;
                checked(
                    r.operation == "UPDATE" && intents.len() == 1,
                    "Block claim requires existing exact intent",
                )?;
                let expected: Option<Value> = intents[0]
                    .try_get("expected_object")
                    .map_err(|_| Denial::dependency())?;
                let expected =
                    expected.ok_or(Denial::policy("Expected block specification missing"))?;
                let mut actual = value
                    .get("spec")
                    .cloned()
                    .ok_or(Denial::policy("Claim spec missing"))?;
                if let Some(m) = actual.as_object_mut() {
                    m.remove("volumeName");
                    if let Some(alias) = m.remove("dataSourceRef") {
                        checked(
                            m.get("dataSource") == Some(&alias),
                            "Claim datasource alias changed",
                        )?;
                    }
                }
                normalize_capacity(&mut actual);
                let mut wanted = expected["spec"].clone();
                normalize_capacity(&mut wanted);
                checked(actual == wanted, "Backup block/source/capacity changed")?;
                if let Some(previous) = old.and_then(|v| v.pointer("/spec/volumeName")) {
                    checked(
                        value.pointer("/spec/volumeName") == Some(previous),
                        "Bound backup volume changed",
                    )?;
                }
                if scheduler {
                    checked(
                        value.get("spec") == old.and_then(|v| v.get("spec")),
                        "Scheduler may not rewrite backup claim spec",
                    )?;
                }
            }
            "persistentvolumes" => {
                checked(
                    storage && r.sub_resource.is_empty() || storage && r.sub_resource == "status",
                    "CSI volume identity required",
                )?;
                let pvc_uid = string(reference, "/metadata/uid")
                    .ok_or(Denial::policy("Block claim UID missing"))?;
                let name = string(reference, "/metadata/name")
                    .ok_or(Denial::policy("Block claim name missing"))?;
                let class: String = b
                    .try_get("clone_storage_class")
                    .map_err(|_| Denial::dependency())?;
                let handle = string(value, "/spec/csi/volumeHandle")
                    .ok_or(Denial::policy("Cloud clone handle required"))?;
                checked(
                    handle != source.cloud_disk
                        && handle.strip_prefix("d-").is_some_and(|s| {
                            !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric())
                        })
                        && value.pointer("/spec/csi/driver") == driver
                        && value.pointer("/spec/volumeMode") == Some(&json!("Block"))
                        && value.pointer("/spec/persistentVolumeReclaimPolicy")
                            == Some(&json!("Retain"))
                        && value.pointer("/spec/storageClassName") == Some(&json!(class))
                        && value.pointer("/spec/accessModes") == Some(&json!(["ReadWriteOnce"]))
                        && string(value, "/spec/claimRef/namespace") == Some(NAMESPACE)
                        && string(value, "/spec/claimRef/name") == Some(name)
                        && string(value, "/spec/claimRef/uid") == Some(pvc_uid),
                    "Derived PV may not reuse source, change mode, claim or retention",
                )?;
                let size = value
                    .pointer("/spec/capacity/storage")
                    .and_then(Value::as_str)
                    .and_then(quantity);
                checked(
                    size == Some(source.size_bytes),
                    "Derived PV capacity changed",
                )?;
                if let Some(old) = old {
                    checked(
                        old.get("spec") == value.get("spec"),
                        "Derived PV spec is immutable",
                    )?;
                }
            }
            _ => return Err(Denial::policy("Unsupported backup storage resource")),
        }
        Ok(())
    }
}
fn normalize_created(v: &mut Value) {
    if let Some(m) = v.get_mut("metadata").and_then(Value::as_object_mut) {
        for key in [
            "uid",
            "resourceVersion",
            "creationTimestamp",
            "managedFields",
            "generation",
        ] {
            m.remove(key);
        }
    }
    if v.get("status")
        .is_some_and(|v| v.is_null() || v == &json!({}))
    {
        v.as_object_mut().map(|m| m.remove("status"));
    }
    if let Some(reference) = v.pointer("/spec/dataSourceRef").cloned()
        && v.pointer("/spec/dataSource") == Some(&reference)
        && let Some(o) = v.get_mut("spec").and_then(Value::as_object_mut)
    {
        o.remove("dataSourceRef");
    }
}

fn protection_preserved(v: &Value) -> bool {
    v.pointer("/metadata/finalizers")
        .and_then(Value::as_array)
        .is_some_and(|f| f.iter().any(|x| x == "sandbox.platform/backup-protection"))
}
fn quantity(s: &str) -> Option<u64> {
    for (suffix, factor) in [
        ("Ti", 1024_u64.pow(4)),
        ("Gi", 1024_u64.pow(3)),
        ("Mi", 1024_u64.pow(2)),
        ("Ki", 1024),
    ] {
        if let Some(n) = s.strip_suffix(suffix) {
            return n.parse::<u64>().ok()?.checked_mul(factor);
        }
    }
    s.parse().ok()
}
fn normalize_capacity(v: &mut Value) {
    if let Some(n) = v
        .pointer("/resources/requests/storage")
        .and_then(Value::as_str)
        .and_then(quantity)
    {
        v["resources"]["requests"]["storage"] = json!(n.to_string());
    }
}
