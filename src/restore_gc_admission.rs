//! Private exact-UID temporary metadata cleanup. Source/target volumes and new
//! storage/writer authority never enter this path; no production router exposes it.
use crate::{
    admission::{AdmissionRequest, Denial, ServiceIdentity},
    db::Database,
};
use kube::{
    Api, Client,
    core::{ApiResource, DynamicObject},
};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use uuid::Uuid;

const PROTECTION: &str = "sandbox.platform/backup-protection";
type Decision<T> = Result<T, Denial>;
fn require(ok: bool) -> Decision<()> {
    if ok {
        Ok(())
    } else {
        Err(Denial {
            code: 403,
            message: "Exact closed restore temporary resource cleanup authority required",
        })
    }
}
fn unavailable(_: impl std::fmt::Debug) -> Denial {
    Denial {
        code: 503,
        message: "Restore cleanup observation unavailable",
    }
}
fn text<'a>(v: &'a Value, p: &str) -> Option<&'a str> {
    v.pointer(p).and_then(Value::as_str)
}
fn id(v: &Value, p: &str) -> Decision<Uuid> {
    let value = text(v, p)
        .and_then(|s| Uuid::parse_str(s).ok())
        .filter(|u| !u.is_nil());
    require(value.is_some())?;
    value.ok_or(Denial {
        code: 403,
        message: "Immutable cleanup UID required",
    })
}
#[derive(Clone)]
pub(super) struct RestoreGcAdmissionService {
    pub database: Database,
    pub client: Client,
    pub controller: ServiceIdentity,
}
impl RestoreGcAdmissionService {
    async fn authority(
        &self,
        tenant: Uuid,
        restore: Uuid,
        r: &AdmissionRequest,
        uid: Uuid,
    ) -> Decision<(Value, Instant)> {
        let reading = Instant::now();
        let mut tx = self.database.begin(tenant).await.map_err(unavailable)?;
        let pin: Option<Value> =
            sqlx::query_scalar("SELECT sandbox_restore_gc_metadata($1,$2,$3,$4,$5)")
                .bind(tenant)
                .bind(restore)
                .bind(&r.namespace)
                .bind(&r.name)
                .bind(uid)
                .fetch_one(&mut *tx)
                .await
                .map_err(unavailable)?;
        let envelope = pin.ok_or(Denial {
            code: 403,
            message: "Current cleanup claim unavailable",
        })?;
        let pin = envelope
            .get("pin")
            .filter(|v| v.is_object())
            .cloned()
            .ok_or(Denial {
                code: 403,
                message: "Cleanup authority pin required",
            })?;
        let budget = envelope
            .get("valid_for_us")
            .and_then(Value::as_u64)
            .filter(|v| *v > 0)
            .ok_or(Denial {
                code: 403,
                message: "Cleanup authority already expired",
            })?;
        let valid_until = reading
            .checked_add(Duration::from_micros(budget))
            .ok_or(Denial {
                code: 403,
                message: "Invalid cleanup authority horizon",
            })?;
        tx.commit().await.map_err(unavailable)?;
        require(Instant::now() < valid_until)?;
        Ok((pin, valid_until))
    }
    pub async fn decide(&self, r: &AdmissionRequest) -> Decision<()> {
        require(
            self.controller.username == "system:serviceaccount:sandbox-system:sandbox-restore-gc"
                && Uuid::parse_str(&self.controller.uid).is_ok_and(|u| !u.is_nil())
                && r.user_info.username == self.controller.username
                && r.user_info.uid == self.controller.uid
                && !r.dry_run
                && r.sub_resource.is_empty()
                && r.resource.version == "v1"
                && Uuid::parse_str(&r.uid).is_ok_and(|u| !u.is_nil())
                && matches!(r.operation.as_str(), "UPDATE" | "DELETE"),
        )?;
        let (kind, cluster) = match (r.resource.group.as_str(), r.resource.resource.as_str()) {
            ("", "persistentvolumeclaims") => ("PersistentVolumeClaim", false),
            ("", "persistentvolumes") => ("PersistentVolume", true),
            ("snapshot.storage.k8s.io", "volumesnapshots") => ("VolumeSnapshot", false),
            ("snapshot.storage.k8s.io", "volumesnapshotcontents") => {
                ("VolumeSnapshotContent", true)
            }
            _ => return require(false),
        };
        require(cluster == r.namespace.is_empty())?;
        let old = r.old_object.as_ref().ok_or(Denial {
            code: 403,
            message: "Stored cleanup object required",
        })?;
        let uid = id(old, "/metadata/uid")?;
        require(
            text(old, "/metadata/name") == Some(r.name.as_str())
                && (cluster || text(old, "/metadata/namespace") == Some(r.namespace.as_str())),
        )?;
        // Includes routing/initial authority, every HTTP read and the final
        // SQL lock/commit in the conservative monotonic decision window.
        let observed = Instant::now();
        let scope: Vec<(Uuid, Uuid)> =
            sqlx::query_as("SELECT * FROM sandbox_resolve_restore_gc_resource($1,$2,$3,$4,$5)")
                .bind(&r.resource.group)
                .bind(&r.resource.resource)
                .bind(&r.namespace)
                .bind(&r.name)
                .bind(uid)
                .fetch_all(&self.database.pool)
                .await
                .map_err(unavailable)?;
        require(scope.len() == 1)?;
        let (tenant, restore) = scope[0];
        let (pin, first_until) = self.authority(tenant, restore, r, uid).await?;
        let resource = ApiResource {
            group: r.resource.group.clone(),
            version: "v1".into(),
            api_version: if r.resource.group.is_empty() {
                "v1".into()
            } else {
                format!("{}/v1", r.resource.group)
            },
            kind: kind.into(),
            plural: r.resource.resource.clone(),
        };
        let api: Api<DynamicObject> = if cluster {
            Api::all_with(self.client.clone(), &resource)
        } else {
            Api::namespaced_with(self.client.clone(), &r.namespace, &resource)
        };
        let actual = api.get(&r.name).await.map_err(unavailable)?;
        let actual = serde_json::to_value(actual).map_err(unavailable)?;
        // API-managed metadata omitted by typed decoding is normalized on both
        // sides. Every spec/status/label/annotation/owner/finalizer is retained.
        require(
            comparable(actual.clone()) == comparable(old.clone())
                && id(&actual, "/metadata/uid")? == uid,
        )?;
        validate_binding(&actual, &pin)?;
        let rv = text(&actual, "/metadata/resourceVersion")
            .filter(|s| !s.is_empty())
            .ok_or(Denial {
                code: 403,
                message: "Cleanup resourceVersion required",
            })?;
        let before = finalizers(&actual)?;
        if r.operation == "UPDATE" {
            let after = r.object.as_ref().ok_or(Denial {
                code: 403,
                message: "Updated cleanup object required",
            })?;
            let retained: Vec<Value> = before
                .iter()
                .filter(|v| v.as_str() != Some(PROTECTION))
                .cloned()
                .collect();
            require(
                before
                    .iter()
                    .filter(|v| v.as_str() == Some(PROTECTION))
                    .count()
                    == 1
                    && finalizers(after)? == retained
                    && text(after, "/metadata/resourceVersion") == Some(rv),
            )?;
            let mut expected = actual;
            expected["metadata"]["finalizers"] = json!(retained);
            require(comparable(expected) == comparable(after.clone()))?;
        } else {
            let options = r.options.as_ref().ok_or(Denial {
                code: 403,
                message: "UID and version conditioned deletion required",
            })?;
            require(
                options.as_object().is_some_and(|fields| {
                    fields.keys().all(|key| {
                        matches!(
                            key.as_str(),
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
                        .get("gracePeriodSeconds")
                        .is_none_or(|v| v == &json!(0))
                    && options
                        .get("preconditions")
                        .and_then(Value::as_object)
                        .is_some_and(|fields| fields.len() == 2)
                    && !before.iter().any(|v| v.as_str() == Some(PROTECTION))
                    && text(options, "/preconditions/uid") == Some(uid.to_string().as_str())
                    && text(options, "/preconditions/resourceVersion") == Some(rv)
                    && options
                        .get("dryRun")
                        .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
                    && options.get("orphanDependents").is_none()
                    && options
                        .get("propagationPolicy")
                        .is_none_or(|v| v == "Background")
                    && r.object.as_ref().is_none_or(Value::is_null),
            )?;
        }
        // Includes every SQL lock wait in the monotonic observation window.
        let (latest, latest_until) = self.authority(tenant, restore, r, uid).await?;
        let decided = Instant::now();
        require(
            latest == pin
                && decided < first_until
                && decided < latest_until
                && observed.elapsed() <= Duration::from_secs(10),
        )
    }
}
fn comparable(mut v: Value) -> Value {
    if let Some(meta) = v.get_mut("metadata").and_then(Value::as_object_mut) {
        for field in ["managedFields", "selfLink"] {
            meta.remove(field);
        }
    }
    v
}
fn finalizers(v: &Value) -> Decision<Vec<Value>> {
    let Some(value) = v.pointer("/metadata/finalizers") else {
        return Ok(Vec::new());
    };
    let values = value.as_array().ok_or(Denial {
        code: 403,
        message: "Malformed cleanup finalizers",
    })?;
    require(values.iter().all(Value::is_string))?;
    Ok(values.clone())
}
fn validate_binding(v: &Value, p: &Value) -> Decision<()> {
    require(id(v, "/metadata/uid")? == id(p, "/uid")?)?;
    let raw = &p["raw"];
    let snap = &p["snapshot"];
    let delivery = &p["delivery"];
    let expected = &p["expected"];
    let driver = Some(&json!("diskplugin.csi.alibabacloud.com"));
    match p["kind"].as_str() {
        Some("BLOCK_PVC") => {
            let mut spec = v["spec"].clone();
            require(spec["volumeName"] == raw["pv_name"])?;
            if let Some(fields) = spec.as_object_mut() {
                fields.remove("volumeName");
                if let Some(alias) = fields.remove("dataSourceRef") {
                    require(fields.get("dataSource") == Some(&alias))?;
                }
            }
            require(spec == expected["spec"] && id(v, "/metadata/uid")? == id(raw, "/pvc_uid")?)?;
        }
        Some("BLOCK_PV") => {
            require(
                id(v, "/metadata/uid")? == id(raw, "/pv_uid")?
                    && v.pointer("/spec/csi/driver") == driver
                    && v.pointer("/spec/csi/volumeHandle") == Some(&raw["cloud_disk"])
                    && v.pointer("/spec/persistentVolumeReclaimPolicy") == Some(&json!("Retain"))
                    && v.pointer("/spec/volumeMode") == Some(&json!("Block"))
                    && v.pointer("/spec/claimRef/uid") == Some(&raw["pvc_uid"])
                    && v.pointer("/spec/claimRef/namespace") == Some(&json!("sandbox-system"))
                    && v.pointer("/spec/claimRef/name") == p.pointer("/raw_claim/metadata/name")
                    && v.pointer("/spec/storageClassName")
                        == p.pointer("/raw_claim/spec/storageClassName")
                    && v.pointer("/spec/accessModes") == p.pointer("/raw_claim/spec/accessModes")
                    && v.pointer("/spec/claimRef/kind") == Some(&json!("PersistentVolumeClaim"))
                    && v.pointer("/spec/capacity/storage")
                        == p.pointer("/raw_claim/spec/resources/requests/storage"),
            )?;
        }
        Some("RESTORED_SNAPSHOT") | Some("DELIVERY_SNAPSHOT") => {
            require(v.get("spec") == expected.get("spec"))?;
            let receipt = if p["kind"] == "RESTORED_SNAPSHOT" {
                snap
            } else {
                delivery
            };
            require(id(v, "/metadata/uid")? == id(receipt, "/snapshot_uid")?)?;
            let name = if p["kind"] == "RESTORED_SNAPSHOT" {
                &snap["content_name"]
            } else {
                &delivery["snapshot_name"]
            };
            require(v.pointer("/status/boundVolumeSnapshotContentName") == Some(name))?;
        }
        Some("RESTORED_CONTENT") | Some("DELIVERY_CONTENT") => {
            let dynamic = p["kind"] == "RESTORED_CONTENT";
            let receipt = if dynamic { snap } else { delivery };
            require(id(v, "/metadata/uid")? == id(receipt, "/content_uid")?)?;
            let (source, snapshot_uid, snapshot_name, namespace) = if dynamic {
                (
                    &raw["cloud_disk"],
                    &snap["snapshot_uid"],
                    json!(format!(
                        "sbx-rraw-{}",
                        text(p, "/restore_id").unwrap_or_default()
                    )),
                    json!("sandbox-system"),
                )
            } else {
                (
                    &snap["cloud_snapshot"],
                    &delivery["snapshot_uid"],
                    delivery["snapshot_name"].clone(),
                    delivery["namespace"].clone(),
                )
            };
            require(
                v.pointer("/spec/driver") == driver
                    && v.pointer("/spec/deletionPolicy") == Some(&json!("Retain"))
                    && v.pointer("/spec/sourceVolumeMode") == Some(&json!("Block"))
                    && v.pointer("/spec/source")
                        == Some(&if dynamic {
                            json!({"volumeHandle":source})
                        } else {
                            json!({"snapshotHandle":source})
                        })
                    && v.pointer("/spec/volumeSnapshotRef/uid") == Some(snapshot_uid)
                    && v.pointer("/spec/volumeSnapshotRef/name") == Some(&snapshot_name)
                    && v.pointer("/spec/volumeSnapshotRef/namespace") == Some(&namespace)
                    && (!dynamic
                        || v.pointer("/status/snapshotHandle") == Some(&snap["cloud_snapshot"])),
            )?;
        }
        _ => return require(false),
    }
    Ok(())
}
