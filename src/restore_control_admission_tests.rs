//! Real PG admission and real HTTP mutations. Kubernetes storage/controller
//! mechanics below are an explicit stateful stand-in, never cluster certification.
use super::super::{admission::RestoreAdmissionService, ledger::JobPlan};
use crate::{
    admission::{AdmissionRequest, ControllerIdentity},
    backup_job::BackupJobRuntime,
    backup_manifest::NAMESPACE,
    runtime::KubernetesRuntime,
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
    sync::{Arc, Mutex},
};
use uuid::Uuid;

#[derive(Clone)]
struct State {
    service: RestoreAdmissionService,
    objects: Arc<Mutex<BTreeMap<String, Value>>>,
    mutations: Arc<Mutex<Vec<(String, String, Uuid)>>>,
}
pub(super) struct Fixture {
    service: RestoreAdmissionService,
    state: State,
    base: String,
    media_at_start: BTreeMap<String, Value>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn caller(r: &mut AdmissionRequest, identity: &ControllerIdentity) {
    match identity {
        ControllerIdentity::ServiceAccount { username, uid } => {
            r.user_info.username = username.clone();
            r.user_info.uid = uid.clone();
            r.user_info.groups = vec!["system:authenticated".into()];
        }
        ControllerIdentity::ControlPlane { username } => {
            r.user_info.username = username.clone();
            r.user_info.uid.clear();
            r.user_info.groups = vec!["system:authenticated".into()];
        }
    }
}
fn media(map: &BTreeMap<String, Value>) -> BTreeMap<String, Value> {
    map.iter()
        .filter(|(_, v)| {
            matches!(
                v.get("kind").and_then(Value::as_str),
                Some(
                    "PersistentVolume"
                        | "PersistentVolumeClaim"
                        | "VolumeSnapshot"
                        | "VolumeSnapshotContent"
                        | "VolumeAttachment"
                )
            )
        })
        .map(|(path, value)| (path.clone(), value.clone()))
        .collect()
}
fn review(
    old: Value,
    service: &RestoreAdmissionService,
    operation: &str,
    after: Value,
) -> anyhow::Result<AdmissionRequest> {
    let kind = old["kind"].as_str().context("control kind")?;
    let plural = match kind {
        "Job" => "jobs",
        "ConfigMap" => "configmaps",
        "Pod" => "pods",
        _ => anyhow::bail!("non-control kind"),
    };
    Ok(serde_json::from_value(
        json!({"uid":Uuid::new_v4(),"operation":operation,
      "resource":{"group":if kind=="Job"{"batch"}else{""},"version":"v1","resource":plural},
      "name":old["metadata"]["name"],"namespace":NAMESPACE,
      "userInfo":{"username":service.identities.controller.username,"uid":service.identities.controller.uid},
      "object":after,"oldObject":old}),
    )?)
}
fn deleting(v: &Value) -> bool {
    v.pointer("/metadata/deletionTimestamp")
        .is_some_and(|v| !v.is_null())
}
async fn http(state: State, r: Request<Body>) -> Response<Body> {
    let raw_path = r.uri().path().to_owned();
    let path = raw_path
        .strip_suffix("/status")
        .unwrap_or(&raw_path)
        .to_owned();
    let query = r.uri().query().unwrap_or_default().to_owned();
    let method = r.method().clone();
    // This is fixture routing to explicitly reviewed simulated controllers;
    // production caller identity continues to come only from the apiserver.
    let identity = r
        .headers()
        .get("x-fixture-controller")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("backup")
        .to_owned();
    let body = axum::body::to_bytes(r.into_body(), 131072).await;
    let payload = body
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    let old = state
        .objects
        .lock()
        .ok()
        .and_then(|m| m.get(&path).cloned());
    let mut status = StatusCode::OK;
    let value = if method == Method::GET {
        if path.ends_with("/pods") {
            let selector = url::form_urlencoded::parse(query.as_bytes())
                .find(|(k, _)| k == "labelSelector")
                .map(|(_, v)| v.into_owned());
            let wanted = selector
                .as_deref()
                .and_then(|s| s.strip_prefix("batch.kubernetes.io/controller-uid="));
            let map = state
                .objects
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let items: Vec<_> = map
                .values()
                .filter(|v| {
                    v.get("kind") == Some(&json!("Pod"))
                        && wanted.is_some_and(|uid| {
                            v.pointer("/metadata/labels/batch.kubernetes.io~1controller-uid")
                                .and_then(Value::as_str)
                                == Some(uid)
                        })
                })
                .cloned()
                .collect();
            json!({"apiVersion":"v1","kind":"PodList","metadata":{},"items":items})
        } else if let Some(old) = old {
            old
        } else {
            status = StatusCode::NOT_FOUND;
            json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404})
        }
    } else if let (Some(old), Some(payload)) = (old, payload) {
        let operation = if method == Method::DELETE {
            "DELETE"
        } else {
            "UPDATE"
        };
        let mut after = old.clone();
        if raw_path.ends_with("/status") {
            after["status"] = payload["status"].clone();
        } else if method == Method::PATCH {
            after["metadata"]["finalizers"] = payload["metadata"]["finalizers"].clone();
        }
        let prepared = review(
            old.clone(),
            &state.service,
            operation,
            if method == Method::DELETE {
                Value::Null
            } else {
                after.clone()
            },
        );
        let decision = match prepared {
            Ok(mut review) => {
                if method == Method::DELETE {
                    review.options = Some(payload.clone());
                }
                if raw_path.ends_with("/status") {
                    review.sub_resource = "status".into();
                }
                if identity == "job" {
                    caller(&mut review, &state.service.identities.job_controller);
                } else if identity == "gc" {
                    caller(&mut review, &state.service.control_gc);
                }
                let cas = method != Method::PATCH
                    || (payload.pointer("/metadata/uid") == old.pointer("/metadata/uid")
                        && payload.pointer("/metadata/resourceVersion")
                            == old.pointer("/metadata/resourceVersion"));
                if !cas {
                    Err(crate::admission::Denial {
                        code: 409,
                        message: "fixture CAS mismatch",
                    })
                } else if matches!(method, Method::DELETE | Method::PATCH) {
                    Box::pin(state.service.decide(&review)).await
                } else {
                    Err(crate::admission::Denial {
                        code: 403,
                        message: "fixture unsupported mutation",
                    })
                }
            }
            Err(_) => Err(crate::admission::Denial {
                code: 403,
                message: "fixture malformed review",
            }),
        };
        match decision {
            Err(e) => {
                status = StatusCode::from_u16(e.code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Forbidden","code":e.code})
            }
            Ok(()) => {
                let mut map = state
                    .objects
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if map.get(&path) != Some(&old) {
                    status = StatusCode::CONFLICT;
                    json!({"apiVersion":"v1","kind":"Status","status":"Failure","code":409})
                } else {
                    if let Some(uid) = old
                        .pointer("/metadata/uid")
                        .and_then(Value::as_str)
                        .and_then(|s| Uuid::parse_str(s).ok())
                    {
                        state
                            .mutations
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push((method.to_string(), path.clone(), uid));
                    }
                    let mut next = if method == Method::DELETE {
                        old.clone()
                    } else {
                        after
                    };
                    if method == Method::DELETE {
                        next["metadata"]["deletionTimestamp"] = json!("2026-10-08T00:00:00Z");
                        if old.get("kind") == Some(&json!("Pod")) {
                            next["metadata"]["deletionGracePeriodSeconds"] = json!(30);
                        } else {
                            next["metadata"]["finalizers"] = json!(["foregroundDeletion"]);
                        }
                    }
                    let rv = old
                        .pointer("/metadata/resourceVersion")
                        .and_then(Value::as_str)
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(0)
                        + 1;
                    next["metadata"]["resourceVersion"] = json!(rv.to_string());
                    let empty = next
                        .pointer("/metadata/finalizers")
                        .and_then(Value::as_array)
                        .is_some_and(Vec::is_empty);
                    if deleting(&next) && empty {
                        map.remove(&path);
                    } else {
                        map.insert(path, next.clone());
                    }
                    if method == Method::DELETE {
                        json!({"apiVersion":"v1","kind":"Status","status":"Success"})
                    } else {
                        next
                    }
                }
            }
        }
    } else {
        status = StatusCode::NOT_FOUND;
        json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404})
    };
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(value.to_string()))
        .unwrap_or_default()
}
impl Fixture {
    pub(super) async fn new(
        mut service: RestoreAdmissionService,
        objects: Arc<Mutex<BTreeMap<String, Value>>>,
    ) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        service.runtime = BackupJobRuntime::new(KubernetesRuntime::from_client(
            kube::Client::try_from(kube::Config::new(base.parse()?))?,
        ));
        let media_at_start = media(
            &*objects
                .lock()
                .map_err(|_| anyhow::anyhow!("fixture media"))?,
        );
        let state = State {
            service: service.clone(),
            objects,
            mutations: Arc::new(Mutex::new(Vec::new())),
        };
        let callback = state.clone();
        let app = Router::new().fallback(move |r: Request<Body>| http(callback.clone(), r));
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self {
            service,
            state,
            base,
            media_at_start,
            task,
        })
    }
    pub(super) fn runtime(&self) -> &BackupJobRuntime {
        &self.service.runtime
    }
    fn object(&self, path: &str) -> anyhow::Result<Value> {
        self.state
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("control state poisoned"))?
            .get(path)
            .cloned()
            .context("control object missing")
    }
    fn put(&self, path: &str, value: Value) -> anyhow::Result<()> {
        self.state
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("control state poisoned"))?
            .insert(path.into(), value);
        Ok(())
    }
    fn control_path(&self, plural: &str) -> anyhow::Result<String> {
        self.state
            .objects
            .lock()
            .map_err(|_| anyhow::anyhow!("control state poisoned"))?
            .keys()
            .find(|p| p.contains(&format!("/{plural}/")))
            .cloned()
            .context("control path")
    }
    async fn allow(&self, r: &AdmissionRequest, why: &str) -> anyhow::Result<()> {
        Box::pin(self.service.decide(r))
            .await
            .map_err(|e| anyhow::anyhow!("{why}: {} {}", e.code, e.message))
    }
    async fn deny(&self, r: &AdmissionRequest, why: &str) -> anyhow::Result<()> {
        ensure!(
            Box::pin(self.service.decide(r))
                .await
                .err()
                .is_some_and(|e| e.code == 403),
            "{why} must return 403"
        );
        Ok(())
    }
    pub(super) async fn job_status(&self, bound: bool) -> anyhow::Result<()> {
        let path = self.control_path("jobs")?;
        let old = self.object(&path)?;
        let mut after = old.clone();
        after["status"] = json!({"active":1});
        let mut r = review(old.clone(), &self.service, "UPDATE", after)?;
        r.sub_resource = "status".into();
        caller(&mut r, &self.service.identities.job_controller);
        if !bound {
            self.deny(&r, "unbound Job status").await?;
            return Ok(());
        }
        self.allow(&r, "recorded Job-only status without requiring permit")
            .await?;
        for field in ["spec", "scope", "controller", "options"] {
            let mut bad = r.clone();
            match field {
                "spec" => {
                    bad.object.as_mut().context("status body")?["spec"]["suspend"] =
                        json!(!old["spec"]["suspend"].as_bool().context("suspend")?)
                }
                "scope" => {
                    bad.old_object.as_mut().context("old Job")?["metadata"]["labels"]["sandbox.platform/tenant-id"] =
                        json!(Uuid::new_v4())
                }
                "controller" => bad.user_info.username = "system:kube-scheduler".into(),
                _ => bad.options = Some(json!({"dryRun":["All"]})),
            };
            self.deny(&bad, field).await?;
        }
        let mut misconfigured = self.service.clone();
        misconfigured.identities.job_controller = ControllerIdentity::ControlPlane {
            username: "system:kube-scheduler".into(),
        };
        ensure!(
            Box::pin(misconfigured.decide(&r)).await.is_err(),
            "scheduler configured as Jobcontroller must fail"
        );
        let mut sa = self.service.clone();
        sa.identities.job_controller = ControllerIdentity::ServiceAccount {
            username: "system:serviceaccount:sandbox-system:reviewed-job-controller".into(),
            uid: Uuid::new_v4().to_string(),
        };
        caller(&mut r, &sa.identities.job_controller);
        Box::pin(sa.decide(&r))
            .await
            .map_err(|e| anyhow::anyhow!("exact SA Job status denied {}", e.code))?;
        r.user_info.uid = Uuid::new_v4().to_string();
        ensure!(
            Box::pin(sa.decide(&r)).await.is_err(),
            "replacement SA UID cannot update status"
        );
        Ok(())
    }
    pub(super) async fn no_permit(&self, pod: &Value) -> anyhow::Result<()> {
        let mut r = review(pod.clone(), &self.service, "DELETE", Value::Null)?;
        r.options = Some(
            json!({"gracePeriodSeconds":30,"preconditions":{"uid":pod["metadata"]["uid"],"resourceVersion":pod["metadata"]["resourceVersion"]}}),
        );
        self.deny(&r, "NoPermit Pod DELETE").await
    }
    pub(super) async fn final_ack(
        &self,
        pod: &Value,
        base: &crate::termination_ledger::tests::FixtureRuntime,
    ) -> anyhow::Result<()> {
        let mut r = review(pod.clone(), &self.service, "DELETE", Value::Null)?;
        r.options = Some(
            json!({"gracePeriodSeconds":30,"preconditions":{"uid":pod["metadata"]["uid"],"resourceVersion":pod["metadata"]["resourceVersion"]}}),
        );
        Box::pin(super::admission::commit::historical_final_ack(
            &self.service,
            &r,
            base,
        ))
        .await
    }
    pub(super) async fn protected_delete(&self, pod: &Value) -> anyhow::Result<()> {
        let mut r = review(pod.clone(), &self.service, "DELETE", Value::Null)?;
        r.options = Some(
            json!({"gracePeriodSeconds":30,"preconditions":{"uid":pod["metadata"]["uid"],"resourceVersion":pod["metadata"]["resourceVersion"]}}),
        );
        self.allow(
            &r,
            "protected historical Pod DELETE after permission revocation",
        )
        .await?;
        for (field, value) in [
            ("gracePeriodSeconds", json!(0)),
            ("propagationPolicy", json!("Orphan")),
            (
                "ignoreStoreReadErrorWithClusterBreakingPotential",
                json!(true),
            ),
        ] {
            let mut bad = r.clone();
            bad.options.as_mut().context("delete options")?[field] = value;
            self.deny(&bad, field).await?;
        }
        let mut after = pod.clone();
        after["metadata"]["finalizers"] = json!(["batch.kubernetes.io/job-tracking"]);
        let r = review(pod.clone(), &self.service, "UPDATE", after)?;
        self.deny(&r, "own protection removal before independent proof")
            .await?;
        for plural in ["jobs", "configmaps"] {
            let old = self.object(&self.control_path(plural)?)?;
            let mut r = review(old.clone(), &self.service, "DELETE", Value::Null)?;
            r.options = Some(
                json!({"propagationPolicy":"Foreground","preconditions":{"uid":old["metadata"]["uid"],"resourceVersion":old["metadata"]["resourceVersion"]}}),
            );
            self.deny(
                &r,
                "Job/config DELETE without independent proof and cleanup",
            )
            .await?;
        }
        Ok(())
    }
    pub(super) async fn finalizer_after_proof(&self, pod_path: &str) -> anyhow::Result<()> {
        let before = self.object(pod_path)?;
        let mut after = before.clone();
        after["metadata"]["finalizers"] = json!(["batch.kubernetes.io/job-tracking"]);
        let r = review(before, &self.service, "UPDATE", after)?;
        self.allow(&r, "real exact proof own finalizer").await?;
        for path in [
            "/spec/containers/0/image",
            "/metadata/ownerReferences/0/uid",
            "/metadata/labels/sandbox.platform~1tenant-id",
        ] {
            let mut bad = r.clone();
            *bad.object
                .as_mut()
                .and_then(|v| v.pointer_mut(path))
                .context("negative field")? = json!(Uuid::new_v4());
            self.deny(&bad, path).await?;
        }
        let mut both = r.clone();
        both.object.as_mut().context("Pod")?["metadata"]["finalizers"] = json!([]);
        self.deny(&both, "cannot remove Job protection too").await?;
        Ok(())
    }
    async fn patch_finalizers(&self, path: &str, identity: &str) -> anyhow::Result<()> {
        let old = self.object(path)?;
        let answer=reqwest::Client::new().patch(format!("{}{path}",self.base)).header("x-fixture-controller",identity)
            .json(&json!({"metadata":{"uid":old["metadata"]["uid"],"resourceVersion":old["metadata"]["resourceVersion"],"finalizers":[]}})).send().await?;
        ensure!(
            answer.status().is_success(),
            "actual {identity} PATCH failed {}",
            answer.status()
        );
        ensure!(
            reqwest::Client::new()
                .get(format!("{}{path}", self.base))
                .send()
                .await?
                .status()
                == StatusCode::NOT_FOUND,
            "API object storage must report actual404 after last finalizer"
        );
        Ok(())
    }
    pub(super) async fn job_tracking(&self, pod_path: &str) -> anyhow::Result<()> {
        let old = self.object(pod_path)?;
        ensure!(
            old["metadata"]["finalizers"] == json!(["batch.kubernetes.io/job-tracking"]),
            "own finalizer must be removed by real runtime PATCH first"
        );
        self.patch_finalizers(pod_path, "job").await
    }
    pub(super) async fn artifacts_before_delivery(&self, plan: &JobPlan) -> anyhow::Result<()> {
        let mut tx = self
            .service
            .database
            .begin(plan.record.tenant_id)
            .await
            .map_err(crate::test_support_db::api_failure)?;
        let no_delivery:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM restore_delivery_receipts WHERE tenant_id=$1 AND restore_id=$2)").bind(plan.record.tenant_id).bind(plan.record.id).fetch_one(&mut *tx).await?;
        ensure!(
            no_delivery,
            "historical cleanup fixture must precede successful delivery"
        );
        tx.commit().await?;
        for plural in ["jobs", "configmaps"] {
            let path = self.control_path(plural)?;
            let old = self.object(&path)?;
            let mut r = review(old.clone(), &self.service, "DELETE", Value::Null)?;
            r.options = Some(
                json!({"propagationPolicy":"Foreground","preconditions":{"uid":old["metadata"]["uid"],"resourceVersion":old["metadata"]["resourceVersion"]}}),
            );
            self.allow(&r, "closed pre-delivery DELETE").await?;
            let mut replacement = old.clone();
            replacement["metadata"]["uid"] = json!(Uuid::new_v4());
            self.put(&path, replacement)?;
            self.deny(&r, "same-name object replacement").await?;
            self.put(&path, old)?;
            r.user_info.uid = Uuid::new_v4().to_string();
            self.deny(&r, "same-name controller replacement").await?;
        }
        Ok(())
    }
    pub(super) async fn foreground_gc(&self, plural: &str) -> anyhow::Result<()> {
        let path = self.control_path(plural)?;
        let old = self.object(&path)?;
        ensure!(
            deleting(&old) && old["metadata"]["finalizers"] == json!(["foregroundDeletion"]),
            "Foreground retry must retain exact terminating object"
        );
        let mut after = old.clone();
        after["metadata"]["finalizers"] = json!([]);
        let mut r = review(old.clone(), &self.service, "UPDATE", after)?;
        caller(&mut r, &self.service.control_gc);
        self.allow(&r, "reviewed foreground GC PATCH").await?;
        for field in ["status", "spec", "unknown", "duplicate", "controller"] {
            let mut bad = r.clone();
            match field {
                "status" => bad.object.as_mut().context("body")?["status"] = json!({"unsafe":true}),
                "spec" => {
                    bad.object.as_mut().context("body")?["metadata"]["labels"]["changed"] =
                        json!(true)
                }
                "unknown" | "duplicate" => {
                    let mut value = old.clone();
                    value["metadata"]["finalizers"] = if field == "unknown" {
                        json!(["foregroundDeletion", "other.example/protect"])
                    } else {
                        json!(["foregroundDeletion", "foregroundDeletion"])
                    };
                    self.put(&path, value.clone())?;
                    bad.old_object = Some(value);
                }
                _ => bad.user_info.username = "system:kube-scheduler".into(),
            };
            self.deny(&bad, field).await?;
            self.put(&path, old.clone())?;
        }
        let mut badconfig = self.service.clone();
        badconfig.control_gc = ControllerIdentity::ControlPlane {
            username: "system:kube-scheduler".into(),
        };
        ensure!(
            Box::pin(badconfig.decide(&r)).await.is_err(),
            "scheduler configured as control GC must fail"
        );
        let mut aliased = self.service.clone();
        aliased.control_gc = ControllerIdentity::ServiceAccount {
            username: aliased.identities.controller.username.clone(),
            uid: aliased.identities.controller.uid.clone(),
        };
        ensure!(
            Box::pin(aliased.decide(&r)).await.is_err(),
            "GC configured as backup controller must fail"
        );
        let mut sa = self.service.clone();
        sa.control_gc = ControllerIdentity::ServiceAccount {
            username: "system:serviceaccount:sandbox-system:reviewed-control-gc".into(),
            uid: Uuid::new_v4().to_string(),
        };
        let mut sa_review = r.clone();
        caller(&mut sa_review, &sa.control_gc);
        Box::pin(sa.decide(&sa_review))
            .await
            .map_err(|e| anyhow::anyhow!("reviewed exact GC SA denied {}", e.code))?;
        sa_review.user_info.uid = Uuid::new_v4().to_string();
        ensure!(
            Box::pin(sa.decide(&sa_review)).await.is_err(),
            "replacement GC SA UID must deny"
        );
        self.patch_finalizers(&path, "gc").await
    }
    pub(super) async fn finish_artifacts(
        &self,
        plan: &super::super::completion::RestoreArtifactPlan,
    ) -> anyhow::Result<super::super::completion::VerifiedRestoreArtifacts> {
        for plural in ["jobs", "configmaps"] {
            ensure!(
                self.runtime()
                    .finish_restore_artifacts(plan)
                    .await?
                    .is_none(),
                "Foreground DELETE must retain protected object"
            );
            ensure!(
                self.runtime()
                    .finish_restore_artifacts(plan)
                    .await?
                    .is_none(),
                "Foreground retry must validate retained terminating object"
            );
            Box::pin(self.foreground_gc(plural)).await?;
        }
        self.runtime()
            .finish_restore_artifacts(plan)
            .await?
            .context("actual Job/config absence")
    }
    pub(super) fn assert_mutations(
        &self,
        pod: Uuid,
        job: Uuid,
        config: Uuid,
    ) -> anyhow::Result<()> {
        let mutations = self
            .state
            .mutations
            .lock()
            .map_err(|_| anyhow::anyhow!("mutation log"))?;
        for (uid, plural, patches) in [
            (pod, "pods", 2),
            (job, "jobs", 1),
            (config, "configmaps", 1),
        ] {
            let found: Vec<_> = mutations
                .iter()
                .filter(|(_, path, id)| id == &uid && path.contains(&format!("/{plural}/")))
                .collect();
            ensure!(
                found
                    .iter()
                    .filter(|(method, _, _)| method == "DELETE")
                    .count()
                    == 1,
                "one exact DELETE {plural}"
            );
            ensure!(
                found
                    .iter()
                    .filter(|(method, _, _)| method == "PATCH")
                    .count()
                    == patches,
                "exact own/GC PATCH {plural}"
            );
        }
        ensure!(
            mutations.len() == 7,
            "no source/target media mutation via control admission"
        );
        ensure!(
            media(
                &*self
                    .state
                    .objects
                    .lock()
                    .map_err(|_| anyhow::anyhow!("media state"))?
            ) == self.media_at_start,
            "all actual PVC/PV/snapshot/attachment objects must remain unchanged"
        );
        Ok(())
    }
}
