//! Actual HTTP Kubernetes transport, real PostgreSQL admission role and signed
//! cloud protocol fixture. This is not live CSI/Kata/provider certification.
use super::super::{
    gc::{GcClaim, RestoreGcController},
    gc_admission::RestoreGcAdmissionService,
};
use crate::{
    admission::{AdmissionRequest, ServiceIdentity},
    cloud_fencing::restore_gc::tests::Fixture as Cloud,
    db::Database,
    termination_ledger::tests::FixtureRuntime,
    test_support_db::api_failure,
};
use anyhow::{Context, ensure};
use axum::{
    Router,
    body::Body,
    http::{Method, Request, Response, StatusCode},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use uuid::Uuid;

#[derive(Clone)]
struct HttpState {
    objects: Arc<Mutex<BTreeMap<String, Value>>>,
    service: RestoreGcAdmissionService,
    blocked: Arc<AtomicBool>,
    pause: Arc<AtomicBool>,
    seen: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    delay: Arc<AtomicU64>,
    updates: Arc<AtomicUsize>,
    deletes: Arc<AtomicUsize>,
    updated_paths: Arc<Mutex<BTreeMap<String, Value>>>,
    deleted_paths: Arc<Mutex<BTreeMap<String, Value>>>,
}
#[path = "restore_gc_commit_tests.rs"]
mod commit;

struct HttpFixture {
    state: HttpState,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn get(objects: &Arc<Mutex<BTreeMap<String, Value>>>, path: &str) -> anyhow::Result<Value> {
    objects
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture state poisoned"))?
        .get(path)
        .cloned()
        .context("fixture object missing")
}
fn request(
    old: Value,
    controller: &ServiceIdentity,
    delete: bool,
) -> anyhow::Result<AdmissionRequest> {
    let kind = old["kind"].as_str().context("resource kind")?;
    let plural = match kind {
        "PersistentVolumeClaim" => "persistentvolumeclaims",
        "PersistentVolume" => "persistentvolumes",
        "VolumeSnapshot" => "volumesnapshots",
        "VolumeSnapshotContent" => "volumesnapshotcontents",
        _ => anyhow::bail!("unsupported fixture kind"),
    };
    let mut after = old.clone();
    after["metadata"]["finalizers"] = json!(
        old.pointer("/metadata/finalizers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|v| v.as_str() != Some("sandbox.platform/backup-protection"))
            .cloned()
            .collect::<Vec<_>>()
    );
    Ok(serde_json::from_value(
        json!({"uid":Uuid::new_v4(),"operation":if delete{"DELETE"}else{"UPDATE"},"resource":{"group":if kind.starts_with("VolumeSnapshot"){"snapshot.storage.k8s.io"}else{""},"version":"v1","resource":plural},"name":old["metadata"]["name"],"namespace":old["metadata"].get("namespace").cloned().unwrap_or(json!("")),"userInfo":{"username":controller.username,"uid":controller.uid},"object":if delete{Value::Null}else{after},"oldObject":old,"options":if delete{json!({"preconditions":{"uid":old["metadata"]["uid"],"resourceVersion":old["metadata"]["resourceVersion"]}})}else{Value::Null}}),
    )?)
}
async fn http(state: HttpState, r: Request<Body>) -> Response<Body> {
    let path = r.uri().path().to_owned();
    let method = r.method().clone();
    let bytes = axum::body::to_bytes(r.into_body(), 131072)
        .await
        .unwrap_or_default();
    let payload: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let old = state
        .objects
        .lock()
        .ok()
        .and_then(|m| m.get(&path).cloned());
    let (status, value) = if method == Method::GET {
        if let Some(v) = old {
            if state.pause.swap(false, Ordering::SeqCst) {
                state.seen.notify_one();
                state.release.notified().await;
            }
            tokio::time::sleep(Duration::from_millis(state.delay.swap(0, Ordering::SeqCst))).await;
            (StatusCode::OK, v)
        } else if path.ends_with("/pods") || path.ends_with("/volumeattachments") {
            (
                StatusCode::OK,
                json!({"apiVersion":if path.ends_with("/pods"){"v1"}else{"storage.k8s.io/v1"},"kind":if path.ends_with("/pods"){"PodList"}else{"VolumeAttachmentList"},"items":[],"metadata":{}}),
            )
        } else {
            (
                StatusCode::NOT_FOUND,
                json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}),
            )
        }
    } else if let Some(old) = old {
        if state.blocked.load(Ordering::SeqCst) {
            (
                StatusCode::FORBIDDEN,
                json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Forbidden","code":403}),
            )
        } else {
            let prepared = request(
                old.clone(),
                &state.service.controller,
                method == Method::DELETE,
            );
            let decision = match prepared {
                Ok(mut review) => {
                    if method == Method::PATCH {
                        if let Some(after) = review.object.as_mut() {
                            after["metadata"]["finalizers"] =
                                payload["metadata"]["finalizers"].clone();
                        }
                        if payload.pointer("/metadata/uid") != old.pointer("/metadata/uid")
                            || payload.pointer("/metadata/resourceVersion")
                                != old.pointer("/metadata/resourceVersion")
                        {
                            Err(crate::admission::Denial {
                                code: 409,
                                message: "fixture CAS mismatch",
                            })
                        } else {
                            state.service.decide(&review).await
                        }
                    } else if method == Method::DELETE {
                        review.options = Some(payload.clone());
                        state.service.decide(&review).await
                    } else {
                        Err(crate::admission::Denial {
                            code: 403,
                            message: "unsupported fixture mutation",
                        })
                    }
                }
                Err(_) => Err(crate::admission::Denial {
                    code: 403,
                    message: "fixture review malformed",
                }),
            };
            if let Err(error) = decision {
                (
                    StatusCode::from_u16(error.code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                    json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Forbidden","code":error.code,"message":error.message}),
                )
            } else {
                let mut objects = state
                    .objects
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if objects.get(&path) != Some(&old) {
                    (
                        StatusCode::CONFLICT,
                        json!({"apiVersion":"v1","kind":"Status","status":"Failure","code":409}),
                    )
                } else if method == Method::PATCH {
                    let mut next = old;
                    next["metadata"]["finalizers"] = payload["metadata"]["finalizers"].clone();
                    next["metadata"]["resourceVersion"] = json!("2");
                    state
                        .updated_paths
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(path.clone(), next["metadata"]["uid"].clone());
                    objects.insert(path, next.clone());
                    state.updates.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::OK, next)
                } else if old
                    .pointer("/metadata/finalizers")
                    .and_then(Value::as_array)
                    .is_some_and(|v| !v.is_empty())
                {
                    let mut retained = old;
                    retained["metadata"]["deletionTimestamp"] = json!(chrono::Utc::now());
                    objects.insert(path, retained.clone());
                    (StatusCode::ACCEPTED, retained)
                } else {
                    state
                        .deleted_paths
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(path.clone(), old["metadata"]["uid"].clone());
                    objects.remove(&path);
                    state.deletes.fetch_add(1, Ordering::SeqCst);
                    (
                        StatusCode::OK,
                        json!({"apiVersion":"v1","kind":"Status","status":"Success"}),
                    )
                }
            }
        }
    } else {
        (
            StatusCode::NOT_FOUND,
            json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}),
        )
    };
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(value.to_string()))
        .unwrap_or_default()
}
#[track_caller]
fn denied<'a>(
    service: &'a RestoreGcAdmissionService,
    r: &'a AdmissionRequest,
) -> impl std::future::Future<Output = anyhow::Result<()>> + 'a {
    let caller = std::panic::Location::caller();
    async move {
        let error = service.decide(r).await.err().with_context(|| {
            format!(
                "security policy must deny this request at {}:{}",
                caller.file(),
                caller.line()
            )
        })?;
        ensure!(
            error.code == 403,
            "denial must be policy, not a dependency timeout: {}",
            error.message
        );
        Ok(())
    }
}

async fn reclaim(
    controller: &RestoreGcController,
    tenant: Uuid,
    restore: Uuid,
    worker: &str,
) -> anyhow::Result<GcClaim> {
    tokio::time::sleep(Duration::from_millis(1100)).await;
    controller
        .claim(tenant, restore, worker)
        .await
        .map_err(api_failure)?
        .context("new GC claim")
}
pub(super) async fn run(
    base: &FixtureRuntime,
    restore: Uuid,
    objects: &Arc<Mutex<BTreeMap<String, Value>>>,
    mut controller: RestoreGcController,
    cloud: &Cloud,
    paths: &[String],
) -> anyhow::Result<()> {
    sqlx::raw_sql(include_str!(
        "../tests/fixtures/restore/0038_restore_gc_admission.sql"
    ))
    .execute(&base.f.owner)
    .await?;
    sqlx::raw_sql(include_str!("../scripts/sql/restore-gc-admission-role.sql"))
        .execute(&base.f.owner)
        .await?;
    let database = Database::connect(&std::env::var("TEST_ADMISSION_DATABASE_URL")?, 4).await?;
    let role: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&database.pool)
        .await?;
    assert_eq!(role, "sandbox_admission");
    assert!(
        crate::workspace_restore::verify_component_schema(&database.pool)
            .await
            .is_err(),
        "private draft is not an installed production migration"
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let client = kube::Client::try_from(kube::Config::new(
        format!("http://{}", listener.local_addr()?).parse()?,
    ))?;
    let service = RestoreGcAdmissionService {
        database,
        client: client.clone(),
        controller: ServiceIdentity {
            username: "system:serviceaccount:sandbox-system:sandbox-restore-gc".into(),
            uid: Uuid::new_v4().to_string(),
        },
    };
    let state = HttpState {
        objects: objects.clone(),
        service: service.clone(),
        blocked: Arc::new(AtomicBool::new(true)),
        pause: Arc::new(AtomicBool::new(false)),
        seen: Arc::new(tokio::sync::Notify::new()),
        release: Arc::new(tokio::sync::Notify::new()),
        delay: Arc::new(AtomicU64::new(0)),
        updates: Arc::new(AtomicUsize::new(0)),
        deletes: Arc::new(AtomicUsize::new(0)),
        updated_paths: Arc::new(Mutex::new(BTreeMap::new())),
        deleted_paths: Arc::new(Mutex::new(BTreeMap::new())),
    };
    let serving = state.clone();
    let app = Router::new().fallback(move |r: Request<Body>| http(serving.clone(), r));
    let fixture = HttpFixture {
        state,
        task: tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        }),
    };
    controller.client = client;
    let tenant = base.f.actor.tenant_id;
    let protected_path = paths
        .iter()
        .find(|p| p.contains("/volumesnapshots/"))
        .context("protected temporary snapshot path")?;
    let old = get(objects, protected_path)?;
    let good = request(old.clone(), &service.controller, false)?;
    // No tenant was set on this connection: exact routing must work without
    // bypassing FORCE RLS on any payload/evidence table.
    let scope: Vec<(Uuid, Uuid)> =
        sqlx::query_as("SELECT * FROM sandbox_resolve_restore_gc_resource($1,$2,$3,$4,$5)")
            .bind(&good.resource.group)
            .bind(&good.resource.resource)
            .bind(&good.namespace)
            .bind(&good.name)
            .bind(Uuid::parse_str(
                old["metadata"]["uid"].as_str().context("bound UID")?,
            )?)
            .fetch_all(&service.database.pool)
            .await?;
    assert_eq!(scope, vec![(tenant, restore)]);
    for (namespace, name, uid) in [
        (good.namespace.clone(), good.name.clone(), Uuid::new_v4()),
        (
            "foreign-scope".into(),
            good.name.clone(),
            Uuid::parse_str(old["metadata"]["uid"].as_str().context("bound UID")?)?,
        ),
        (
            good.namespace.clone(),
            "different-resource".into(),
            Uuid::parse_str(old["metadata"]["uid"].as_str().context("bound UID")?)?,
        ),
    ] {
        let scope: Vec<(Uuid, Uuid)> =
            sqlx::query_as("SELECT * FROM sandbox_resolve_restore_gc_resource($1,$2,$3,$4,$5)")
                .bind(&good.resource.group)
                .bind(&good.resource.resource)
                .bind(namespace)
                .bind(name)
                .bind(uid)
                .fetch_all(&service.database.pool)
                .await?;
        assert!(scope.is_empty());
    }
    let mut claim = controller
        .claim(tenant, restore, "gc-admission-first")
        .await
        .map_err(api_failure)?
        .context("first GC claim")?;
    denied(&service, &good).await?;
    assert!(
        !Box::pin(controller.reconcile(&claim))
            .await
            .map_err(api_failure)?
    );
    cloud.raw_absent();
    claim = reclaim(&controller, tenant, restore, "gc-admission-snapshot").await?;
    assert!(
        !Box::pin(controller.reconcile(&claim))
            .await
            .map_err(api_failure)?
    );
    denied(&service, &good).await?;
    let mut tx = base.f.owner_transaction().await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM restore_gc_cloud_absences WHERE tenant_id=$1 AND restore_id=$2",
    )
    .bind(tenant)
    .bind(restore)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(count, 1);
    tx.commit().await?;
    cloud.snapshot_absent();
    claim = reclaim(&controller, tenant, restore, "gc-admission-metadata").await?;
    assert!(
        Box::pin(controller.reconcile_resources(&claim))
            .await
            .is_err(),
        "fixture intentionally retains metadata until private admission tests finish"
    );
    let mut tx = base.f.owner_transaction().await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM restore_gc_cloud_absences WHERE tenant_id=$1 AND restore_id=$2",
    )
    .bind(tenant)
    .bind(restore)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(count, 2);
    let workspace: Uuid =
        sqlx::query_scalar("SELECT workspace_id FROM restores WHERE tenant_id=$1 AND id=$2")
            .bind(tenant)
            .bind(restore)
            .fetch_one(&mut *tx)
            .await?;
    // Historical cleanup remains safe after the launching profile is disabled.
    sqlx::query("UPDATE backup_profiles SET enabled=false WHERE id=(SELECT profile_id FROM restores WHERE tenant_id=$1 AND id=$2)").bind(tenant).bind(restore).execute(&mut *tx).await?;
    tx.commit().await?;
    service
        .decide(&good)
        .await
        .map_err(|e| anyhow::anyhow!("valid cleanup denied {} {}", e.code, e.message))?;
    for sql in [
        "SELECT * FROM restore_gc_reviews",
        "SELECT * FROM restore_gc_resource_routes",
        "INSERT INTO restore_gc_resource_routes(uid) VALUES(gen_random_uuid())",
        "UPDATE restore_gc_resource_routes SET uid=gen_random_uuid()",
        "INSERT INTO restore_gc_cloud_absences(restore_id) VALUES(gen_random_uuid())",
        "UPDATE restore_resource_bindings SET uid=gen_random_uuid()",
    ] {
        let mut tx = service.database.begin(tenant).await.map_err(api_failure)?;
        let error = sqlx::query(sql)
            .execute(&mut *tx)
            .await
            .err()
            .context("narrow role must reject evidence writes/reads")?;
        ensure!(
            error.as_database_error().and_then(|e| e.code()).as_deref() == Some("42501"),
            "permission denial required"
        );
        tx.rollback().await?;
    }
    let mut foreign = service
        .database
        .begin(Uuid::new_v4())
        .await
        .map_err(api_failure)?;
    let pin: Option<Value> =
        sqlx::query_scalar("SELECT sandbox_restore_gc_metadata($1,$2,$3,$4,$5)")
            .bind(tenant)
            .bind(restore)
            .bind(&good.namespace)
            .bind(&good.name)
            .bind(Uuid::parse_str(
                old["metadata"]["uid"].as_str().context("uid")?,
            )?)
            .fetch_one(&mut *foreign)
            .await?;
    assert!(pin.is_none());
    foreign.commit().await?;
    for field in [
        "uid",
        "controller",
        "dry_run",
        "namespace",
        "operation",
        "spec",
        "finalizers",
    ] {
        let mut altered = good.clone();
        match field {
            "uid" => {
                altered.old_object.as_mut().context("old")?["metadata"]["uid"] =
                    json!(Uuid::new_v4())
            }
            "controller" => altered.user_info.uid = Uuid::new_v4().to_string(),
            "dry_run" => altered.dry_run = true,
            "namespace" => altered.namespace = "foreign-tenant".into(),
            "operation" => altered.operation = "CREATE".into(),
            "spec" => {
                altered.object.as_mut().context("new")?["spec"]["volumeMode"] = json!("Filesystem")
            }
            _ => {
                altered.object.as_mut().context("new")?["metadata"]["finalizers"] =
                    json!(["unreviewed/finalizer"])
            }
        };
        denied(&service, &altered).await?;
    }
    let pv_path = paths
        .iter()
        .find(|p| p.starts_with("/api/v1/persistentvolumes/"))
        .context("raw PV path")?;
    let original_pv = get(objects, pv_path)?;
    let target: String = {
        let mut tx = base.f.owner_transaction().await?;
        let disk = sqlx::query_scalar(
            "SELECT cloud_disk FROM restore_delivery_receipts WHERE tenant_id=$1 AND restore_id=$2",
        )
        .bind(tenant)
        .bind(restore)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        disk
    };
    let mut drift = original_pv.clone();
    drift["spec"]["csi"]["volumeHandle"] = json!(target);
    objects
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture lock"))?
        .insert(pv_path.clone(), drift.clone());
    denied(&service, &request(drift, &service.controller, false)?).await?;
    objects
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture lock"))?
        .insert(pv_path.clone(), original_pv);
    for path in paths {
        let value = get(objects, path)?;
        // Raw PVC/PV normally have no platform protection; exact deletion is
        // then a legitimate positive case. The negative below must actually
        // contain the protection it is asserting cannot be bypassed.
        let mut protected = value.clone();
        protected["metadata"]["finalizers"] = json!(["sandbox.platform/backup-protection"]);
        objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture lock"))?
            .insert(path.clone(), protected.clone());
        assert_eq!(
            get(objects, path)?["metadata"]["finalizers"],
            json!(["sandbox.platform/backup-protection"])
        );
        denied(&service, &request(protected, &service.controller, true)?).await?;
        let mut unprotected = value.clone();
        unprotected["metadata"]["finalizers"] = json!([]);
        objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture lock"))?
            .insert(path.clone(), unprotected.clone());
        let valid_delete = request(unprotected, &service.controller, true)?;
        service
            .decide(&valid_delete)
            .await
            .map_err(|e| anyhow::anyhow!("exact DELETE denied {} {}", e.code, e.message))?;
        for invalid_field in ["uid", "resourceVersion", "unsafe", "propagation", "grace"] {
            let mut invalid = valid_delete.clone();
            let options = invalid.options.as_mut().context("delete options")?;
            match invalid_field {
                "uid" => options["preconditions"]["uid"] = json!(Uuid::new_v4()),
                "resourceVersion" => options["preconditions"]["resourceVersion"] = json!("stale"),
                "unsafe" => {
                    options["ignoreStoreReadErrorWithClusterBreakingPotential"] = json!(true)
                }
                "propagation" => options["propagationPolicy"] = json!("Orphan"),
                _ => options["gracePeriodSeconds"] = json!(60),
            }
            denied(&service, &invalid).await?;
        }
        objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture lock"))?
            .insert(path.clone(), value.clone());
        let mut modified = value.clone();
        modified["metadata"]["uid"] = json!(Uuid::new_v4());
        objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture lock"))?
            .insert(path.clone(), modified);
        denied(
            &service,
            &request(value.clone(), &service.controller, false)?,
        )
        .await?;
        objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture lock"))?
            .insert(path.clone(), value.clone());
        let mut csi = value.clone();
        csi["metadata"]["finalizers"] = json!([
            "sandbox.platform/backup-protection",
            "snapshot.storage.kubernetes.io/test-csi-finalizer"
        ]);
        objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture lock"))?
            .insert(path.clone(), csi.clone());
        let valid = request(csi.clone(), &service.controller, false)?;
        service
            .decide(&valid)
            .await
            .map_err(|e| anyhow::anyhow!("preserve CSI finalizer {} {}", e.code, e.message))?;
        let mut invalid = valid;
        invalid.object.as_mut().context("new")?["metadata"]["finalizers"] = json!([]);
        denied(&service, &invalid).await?;
        objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture lock"))?
            .insert(path.clone(), value);
    }
    let snapshot = objects
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture lock"))?
        .clone();
    let mut forbidden = 0;
    for (path, value) in snapshot {
        if !paths.contains(&path)
            && matches!(
                value["kind"].as_str(),
                Some(
                    "PersistentVolumeClaim"
                        | "PersistentVolume"
                        | "VolumeSnapshot"
                        | "VolumeSnapshotContent"
                )
            )
        {
            denied(&service, &request(value, &service.controller, false)?).await?;
            forbidden += 1;
        }
    }
    ensure!(
        forbidden >= 2,
        "source/target fixture objects must be checked"
    );
    let epoch: Uuid =
        sqlx::query_scalar("SELECT cluster_epoch FROM platform_configuration WHERE singleton")
            .fetch_one(&base.f.owner)
            .await?;
    sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton")
        .bind(Uuid::new_v4())
        .execute(&base.f.owner)
        .await?;
    let stale_epoch = service.decide(&good).await;
    sqlx::query("UPDATE platform_configuration SET cluster_epoch=$1 WHERE singleton")
        .bind(epoch)
        .execute(&base.f.owner)
        .await?;
    ensure!(
        stale_epoch.err().is_some_and(|e| e.code == 403),
        "current epoch mismatch must deny exact UID cleanup"
    );
    Box::pin(commit::run(
        &fixture, &service, &good, base, tenant, restore,
    ))
    .await?;
    controller
        .claim(tenant, restore, "gc-admission-after-commit-expiry")
        .await
        .map_err(api_failure)?
        .context("renew commit-expired claim")?;
    wait_expiry(&fixture, &service, &good, base, tenant, restore, workspace).await?;
    claim = controller
        .claim(tenant, restore, "gc-admission-renewed")
        .await
        .map_err(api_failure)?
        .context("renew expired claim")?;
    freshness(&fixture, &service, &good, base, tenant, workspace).await?;
    Box::pin(complete_metadata_cleanup(
        &controller,
        &claim,
        &fixture,
        base,
        paths,
    ))
    .await?;
    eprintln!(
        "VERIFIED actual HTTP six exact-UID GC metadata UPDATE/DELETE, both real signed-protocol absences, revoked profile cleanup, source/target exclusion, CSI finalizer retention, least privilege, cross-tenant denial, actual workspace-wait lease expiry and final monotonic observation window"
    );
    Ok(())
}

async fn complete_metadata_cleanup(
    controller: &RestoreGcController,
    claim: &GcClaim,
    fixture: &HttpFixture,
    base: &FixtureRuntime,
    paths: &[String],
) -> anyhow::Result<()> {
    let mut tx = base.f.owner_transaction().await?;
    let bindings: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT i.kind,b.uid FROM restore_resource_intents i JOIN restore_resource_bindings b ON b.tenant_id=i.tenant_id AND b.intent_id=i.id WHERE i.tenant_id=$1 AND i.restore_id=$2 AND i.kind IN('BLOCK_PVC','BLOCK_PV','RESTORED_SNAPSHOT','RESTORED_CONTENT','DELIVERY_SNAPSHOT','DELIVERY_CONTENT')",
    )
    .bind(base.f.actor.tenant_id)
    .bind(claim.restore_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let kinds: BTreeMap<Uuid, String> = bindings.into_iter().map(|(k, u)| (u, k)).collect();
    ensure!(
        kinds.len() == 6 && paths.len() == 6,
        "six exact bindings required"
    );
    let (expected_updates, expected_deletes, retained) = {
        let objects = fixture
            .state
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("fixture lock"))?;
        let mut updates = BTreeMap::new();
        let mut deletes = BTreeMap::new();
        let mut protected_kinds = Vec::new();
        for path in paths {
            let object = objects
                .get(path)
                .context("temporary resource before cleanup")?;
            let uid = object["metadata"]["uid"].clone();
            let id = Uuid::parse_str(uid.as_str().context("temporary resource UID")?)?;
            let kind = kinds
                .get(&id)
                .context("resource must match immutable binding")?;
            deletes.insert(path.clone(), uid.clone());
            if object
                .pointer("/metadata/finalizers")
                .and_then(Value::as_array)
                .is_some_and(|v| {
                    v.iter()
                        .any(|f| f.as_str() == Some("sandbox.platform/backup-protection"))
                })
            {
                updates.insert(path.clone(), uid);
                protected_kinds.push(kind.as_str());
            }
        }
        protected_kinds.sort_unstable();
        ensure!(
            protected_kinds == ["DELIVERY_CONTENT", "DELIVERY_SNAPSHOT", "RESTORED_SNAPSHOT"],
            "exact three manifest protections must be exercised"
        );
        let retained: BTreeMap<_, _> = objects
            .iter()
            .filter(|(path, _)| !paths.contains(path))
            .map(|(p, v)| (p.clone(), v.clone()))
            .collect();
        ensure!(
            !retained.is_empty(),
            "source and target fixture resources must remain"
        );
        (updates, deletes, retained)
    };
    fixture.state.blocked.store(false, Ordering::SeqCst);
    ensure!(
        Box::pin(controller.reconcile(claim))
            .await
            .map_err(api_failure)?,
        "six metadata cleanup must finish"
    );
    ensure!(
        fixture.state.updates.load(Ordering::SeqCst) == 3
            && fixture.state.deletes.load(Ordering::SeqCst) == 6,
        "exact three PATCH and six DELETE required"
    );
    ensure!(
        *fixture
            .state
            .updated_paths
            .lock()
            .map_err(|_| anyhow::anyhow!("updated paths lock"))?
            == expected_updates,
        "PATCH must match exact protected paths and UIDs"
    );
    ensure!(
        *fixture
            .state
            .deleted_paths
            .lock()
            .map_err(|_| anyhow::anyhow!("deleted paths lock"))?
            == expected_deletes,
        "DELETE must match exact six paths and UIDs"
    );
    let remaining = fixture
        .state
        .objects
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture lock"))?;
    ensure!(
        *remaining == retained,
        "source/target and all other fixture objects must remain unchanged"
    );
    for uid in expected_deletes.values() {
        ensure!(
            !remaining
                .values()
                .any(|v| v.pointer("/metadata/uid") == Some(uid)),
            "each temporary UID must be absent, including renamed objects"
        );
    }
    Ok(())
}

async fn wait_expiry(
    f: &HttpFixture,
    service: &RestoreGcAdmissionService,
    r: &AdmissionRequest,
    base: &FixtureRuntime,
    tenant: Uuid,
    restore: Uuid,
    workspace: Uuid,
) -> anyhow::Result<()> {
    f.state.pause.store(true, Ordering::SeqCst);
    let (copy, review) = (service.clone(), r.clone());
    let task = tokio::spawn(async move { copy.decide(&review).await });
    tokio::time::timeout(Duration::from_secs(2), f.state.seen.notified()).await?;
    let mut tx = base.f.owner_transaction().await?;
    sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(tenant)
        .bind(workspace)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("UPDATE restore_gc_runs SET lease_until=clock_timestamp()+interval '2 seconds' WHERE tenant_id=$1 AND restore_id=$2").bind(tenant).bind(restore).execute(&mut *tx).await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await?;
    f.state.release.notify_one();
    actual_wait(base, pid).await?;
    tokio::time::sleep(Duration::from_millis(2100)).await;
    tx.commit().await?;
    let result = tokio::time::timeout(Duration::from_secs(2), task).await??;
    ensure!(
        result.err().is_some_and(|e| e.code == 403),
        "lease expiry after real workspace lock must deny policy"
    );
    Ok(())
}
async fn freshness(
    f: &HttpFixture,
    service: &RestoreGcAdmissionService,
    r: &AdmissionRequest,
    base: &FixtureRuntime,
    tenant: Uuid,
    workspace: Uuid,
) -> anyhow::Result<()> {
    f.state.pause.store(true, Ordering::SeqCst);
    f.state.delay.store(9000, Ordering::SeqCst);
    let (copy, review) = (service.clone(), r.clone());
    let task = tokio::spawn(async move { copy.decide(&review).await });
    tokio::time::timeout(Duration::from_secs(2), f.state.seen.notified()).await?;
    f.state.release.notify_one();
    tokio::time::sleep(Duration::from_millis(8600)).await;
    let mut tx = base.f.owner_transaction().await?;
    sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(tenant)
        .bind(workspace)
        .fetch_one(&mut *tx)
        .await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await?;
    actual_wait(base, pid).await?;
    tokio::time::sleep(Duration::from_millis(1250)).await;
    tx.commit().await?;
    let result = tokio::time::timeout(Duration::from_secs(2), task).await??;
    ensure!(
        result.err().is_some_and(|e| e.code == 403),
        "latest SQL reader cannot return stale >10s HTTP observation"
    );
    Ok(())
}
async fn actual_wait(base: &FixtureRuntime, pid: i32) -> anyhow::Result<()> {
    for _ in 0..15 {
        let waited:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename='sandbox_admission' AND $1=ANY(pg_blocking_pids(pid)))").bind(pid).fetch_one(&base.f.owner).await?;
        if waited {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("admission must actually wait on this workspace lock")
}
