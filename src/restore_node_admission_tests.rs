//! Loopback HTTP Kubernetes observations plus the actual narrow PostgreSQL role.
use super::super::{admission::RestoreAdmissionService, ledger::JobPlan};
use crate::{
    admission::{AdmissionRequest, ControllerIdentity},
    backup_job::BackupJobRuntime,
    backup_manifest::NAMESPACE,
    runtime::KubernetesRuntime,
    termination_ledger::tests::FixtureRuntime,
};
use anyhow::{Context, ensure};
use axum::{
    Router,
    body::Body,
    http::{Request, Response, StatusCode},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use uuid::Uuid;
pub(super) struct Fixture {
    service: RestoreAdmissionService,
    engine: crate::engine::OperationEngine,
    claim: crate::engine::Claim,
    objects: Arc<Mutex<BTreeMap<String, Value>>>,
    delay: Arc<AtomicU64>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    pub(super) async fn new(
        mut service: RestoreAdmissionService,
        objects: Arc<Mutex<BTreeMap<String, Value>>>,
        engine: &crate::engine::OperationEngine,
        claim: &crate::engine::Claim,
    ) -> anyhow::Result<Self> {
        let delay = Arc::new(AtomicU64::new(0));
        let map = objects.clone();
        let latency = delay.clone();
        let app=Router::new().fallback(move |r:Request<Body>| {
            let map=map.clone();let latency=latency.clone();
            async move {
                if r.uri().path().starts_with("/api/v1/nodes/") {tokio::time::sleep(Duration::from_millis(latency.swap(0,Ordering::SeqCst))).await;}
                let value=map.lock().ok().and_then(|m|m.get(r.uri().path()).cloned());
                let (status,value)=match value {Some(v)=>(StatusCode::OK,v),None=>(StatusCode::NOT_FOUND,json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}))};
                Response::builder().status(status).header("content-type","application/json").body(Body::from(value.to_string())).unwrap_or_default()
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let config = kube::Config::new(format!("http://{}", listener.local_addr()?).parse()?);
        let client = kube::Client::try_from(config)?;
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        service.runtime = BackupJobRuntime::new(KubernetesRuntime::from_client(client));
        service.scheduler = ControllerIdentity::ServiceAccount {
            username: "system:serviceaccount:kube-system:reviewed-scheduler".into(),
            uid: Uuid::new_v4().to_string(),
        };
        Ok(Self {
            service,
            engine: engine.clone(),
            claim: claim.clone(),
            objects,
            delay,
            task,
        })
    }
    pub(super) async fn heartbeat(&self) -> anyhow::Result<()> {
        ensure!(
            self.engine
                .heartbeat(&self.claim)
                .await
                .map_err(crate::test_support_db::api_failure)?,
            "actual controller heartbeat cannot resurrect an expired or superseded claim"
        );
        Ok(())
    }
    fn get(&self, path: &str) -> anyhow::Result<Value> {
        self.objects
            .lock()
            .map_err(|_| anyhow::anyhow!("HTTP fixture map poisoned"))?
            .get(path)
            .cloned()
            .context("HTTP fixture object missing")
    }
    fn put(&self, path: &str, value: Value) -> anyhow::Result<()> {
        self.objects
            .lock()
            .map_err(|_| anyhow::anyhow!("HTTP fixture map poisoned"))?
            .insert(path.into(), value);
        Ok(())
    }
    fn pod_path(name: &str) -> String {
        format!("/api/v1/namespaces/{NAMESPACE}/pods/{name}")
    }
    fn bind(
        &self,
        pod: &Value,
        node: &crate::nodeguard::protocol::NodeBinding,
    ) -> anyhow::Result<AdmissionRequest> {
        let (username, uid) = match &self.service.scheduler {
            ControllerIdentity::ServiceAccount { username, uid } => (username, uid),
            _ => anyhow::bail!("fixture scheduler SA required"),
        };
        Ok(serde_json::from_value(
            json!({"uid":Uuid::new_v4(),"resource":{"group":"","version":"v1","resource":"pods"},"operation":"CREATE","subResource":"binding","namespace":NAMESPACE,"name":pod["metadata"]["name"],"userInfo":{"username":username,"uid":uid},"object":{"apiVersion":"v1","kind":"Binding","metadata":{"name":pod["metadata"]["name"],"namespace":NAMESPACE,"uid":pod["metadata"]["uid"]},"target":{"kind":"Node","apiVersion":"v1","name":node.node_name,"uid":node.node_uid}},"options":{"apiVersion":"meta.k8s.io/v1","kind":"CreateOptions"}}),
        )?)
    }
    fn status_request(
        pod: &Value,
        node: &crate::nodeguard::protocol::NodeBinding,
    ) -> anyhow::Result<AdmissionRequest> {
        // API admission and GET both serialize native Pod types. In particular
        // Kubernetes Time emits seconds, unlike fixture Utc nanoseconds.
        let pod = serde_json::to_value(serde_json::from_value::<k8s_openapi::api::core::v1::Pod>(
            pod.clone(),
        )?)?;
        let mut after = pod.clone();
        after["status"] = json!({"phase":"Succeeded"});
        Ok(serde_json::from_value(
            json!({"uid":Uuid::new_v4(),"resource":{"group":"","version":"v1","resource":"pods"},"operation":"UPDATE","subResource":"status","namespace":NAMESPACE,"name":pod["metadata"]["name"],"userInfo":{"username":format!("system:node:{}",node.node_name),"groups":["system:nodes","system:authenticated"]},"oldObject":pod,"object":after,"options":{"apiVersion":"meta.k8s.io/v1","kind":"UpdateOptions"}}),
        )?)
    }
    async fn allow(&self, r: &AdmissionRequest) -> anyhow::Result<()> {
        Box::pin(self.service.decide(r))
            .await
            .map_err(|e| anyhow::anyhow!("node admission positive {} {}", e.code, e.message))
    }
    async fn deny(&self, r: &AdmissionRequest) -> anyhow::Result<()> {
        let d = Box::pin(self.service.decide(r))
            .await
            .err()
            .context("node admission must reject")?;
        ensure!(
            d.code == 403,
            "dependency failure does not prove identity denial"
        );
        Ok(())
    }
    pub(super) async fn binding(
        &self,
        plan: &JobPlan,
        base: &FixtureRuntime,
        name: &str,
    ) -> anyhow::Result<()> {
        self.heartbeat().await?;
        let path = Self::pod_path(name);
        let original = self.get(&path)?;
        let mut unassigned = original.clone();
        unassigned["spec"]
            .as_object_mut()
            .context("Pod spec")?
            .remove("nodeName");
        self.put(&path, unassigned.clone())?;
        let request = self.bind(&unassigned, &base.node)?;
        self.allow(&request).await?;
        for grant in [false, true] {
            self.heartbeat().await?;
            Box::pin(super::admission::commit::final_ack(
                &self.service,
                &request,
                plan,
                base,
                grant,
            ))
            .await?;
        }
        self.heartbeat().await?;
        let mut default_binder = request.clone();
        let value = default_binder.object.as_mut().context("Binding")?;
        value["target"]
            .as_object_mut()
            .context("target")?
            .remove("uid");
        value["target"]
            .as_object_mut()
            .context("target")?
            .remove("apiVersion");
        value["metadata"]["creationTimestamp"] = Value::Null;
        value["metadata"]["managedFields"] = json!([{"manager":"kube-scheduler","operation":"Update","apiVersion":"v1","fieldsType":"FieldsV1","fieldsV1":{}}]);
        self.allow(&default_binder).await?;
        // Status cannot use only a consumed admission, before the fixed permit exists.
        self.put(&path, original.clone())?;
        self.deny(&Self::status_request(&original, &base.node)?)
            .await?;
        self.put(&path, unassigned.clone())?;
        for field in [
            "scheduler_uid",
            "scheduler_name",
            "uid_missing",
            "uid_changed",
            "target_namespace",
            "target_uid",
            "target_kind",
            "dry_run",
            "old",
            "spec",
            "binding_annotation",
            "binding_label",
        ] {
            self.heartbeat().await?;
            let mut r = request.clone();
            match field {
                "scheduler_uid" => r.user_info.uid = Uuid::new_v4().to_string(),
                "scheduler_name" => r.user_info.username = "system:kube-controller-manager".into(),
                "dry_run" => r.dry_run = true,
                "old" => r.old_object = Some(unassigned.clone()),
                "uid_missing" => {
                    r.object.as_mut().context("Binding")?["metadata"]
                        .as_object_mut()
                        .context("metadata")?
                        .remove("uid");
                }
                "uid_changed" => {
                    r.object.as_mut().context("Binding")?["metadata"]["uid"] = json!(Uuid::new_v4())
                }
                "target_namespace" => {
                    r.object.as_mut().context("Binding")?["target"]["namespace"] = json!("foreign")
                }
                "target_uid" => {
                    r.object.as_mut().context("Binding")?["target"]["uid"] = json!(Uuid::new_v4())
                }
                "target_kind" => {
                    r.object.as_mut().context("Binding")?["target"]["kind"] = json!("Pod")
                }
                "binding_annotation" => {
                    r.object.as_mut().context("Binding")?["metadata"]["annotations"] =
                        json!({"unsafe":"injected"});
                }
                "binding_label" => {
                    r.object.as_mut().context("Binding")?["metadata"]["labels"] =
                        json!({"sandbox.platform/tenant-id":Uuid::new_v4()});
                }
                _ => r.object.as_mut().context("Binding")?["spec"] = json!({"unsafe":"changed"}),
            }
            self.deny(&r).await?;
        }
        for field in ["uid", "assigned", "deleting", "image", "owner"] {
            self.heartbeat().await?;
            let mut changed = unassigned.clone();
            match field {
                "uid" => changed["metadata"]["uid"] = json!(Uuid::new_v4()),
                "assigned" => changed["spec"]["nodeName"] = json!(&base.node.node_name),
                "deleting" => changed["metadata"]["deletionTimestamp"] = json!(chrono::Utc::now()),
                "image" => changed["spec"]["containers"][0]["image"] = json!("unsafe/image:latest"),
                _ => changed["metadata"]["ownerReferences"][0]["uid"] = json!(Uuid::new_v4()),
            };
            self.put(&path, changed)?;
            self.deny(&request).await?;
        }
        self.put(&path, unassigned.clone())?;
        let node_path = format!("/api/v1/nodes/{}", base.node.node_name);
        let node = self.get(&node_path)?;
        for field in ["uid", "boot", "profile", "ready", "pool", "taint"] {
            self.heartbeat().await?;
            let mut changed = node.clone();
            match field {
                "uid" => changed["metadata"]["uid"] = json!(Uuid::new_v4()),
                "boot" => changed["status"]["nodeInfo"]["bootID"] = json!(Uuid::new_v4()),
                "profile" => {
                    changed["metadata"]["annotations"]["sandbox.platform/runtime-profile-sha256"] =
                        json!("f".repeat(64))
                }
                "ready" => changed["status"]["conditions"][0]["status"] = json!("False"),
                "pool" => {
                    changed["metadata"]["labels"]["sandbox.platform/worker-pool"] = json!("shared")
                }
                _ => changed["spec"]["taints"]
                    .as_array_mut()
                    .context("taints")?
                    .push(json!({"key":"other","effect":"NoSchedule"})),
            };
            self.put(&node_path, changed)?;
            self.deny(&request).await?;
        }
        self.put(&node_path, node)?;
        for field in ["node", "profile", "cancel", "lease"] {
            self.heartbeat().await?;
            Box::pin(self.postwait(plan, base, &request, field)).await?;
        }
        self.heartbeat().await?;
        Box::pin(self.late_node_lock(plan, base, &request)).await?;
        self.heartbeat().await?;
        self.allow(&request).await?;
        self.put(&path, original)?;
        eprintln!(
            "VERIFIED actual loopback HTTP scheduler Binding, exact Pod/Node UID/spec/boot/taint identity, no-permit status denial, four actual workspace-wait revocations and final node-lock monotonic freshness denial"
        );
        Ok(())
    }
    async fn wait_pid(base: &FixtureRuntime, pid: i32) -> anyhow::Result<()> {
        for _ in 0..30 {
            let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename='sandbox_admission' AND $1=ANY(pg_blocking_pids(pid)))").bind(pid).fetch_one(&base.f.owner).await?;
            if blocked {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        anyhow::bail!("actual narrow admission transaction must wait on this owner lock")
    }
    async fn postwait(
        &self,
        plan: &JobPlan,
        base: &FixtureRuntime,
        r: &AdmissionRequest,
        field: &str,
    ) -> anyhow::Result<()> {
        let mut blocker = base.f.owner_transaction().await?;
        sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(plan.record.tenant_id)
            .bind(plan.record.workspace_id)
            .fetch_one(&mut *blocker)
            .await?;
        let until: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT lease_until FROM operations WHERE tenant_id=$1 AND id=$2")
                .bind(plan.record.tenant_id)
                .bind(plan.record.operation_id)
                .fetch_one(&mut *blocker)
                .await?;
        match field {
            "node" => {
                sqlx::query(
                    "UPDATE runtime_nodes SET enabled=false WHERE node_uid=$1 AND boot_id=$2",
                )
                .bind(base.node.node_uid)
                .bind(base.node.boot_id)
                .execute(&mut *blocker)
                .await?;
            }
            "profile" => {
                sqlx::query("UPDATE backup_profiles SET enabled=false WHERE id=$1")
                    .bind(plan.record.profile_id)
                    .execute(&mut *blocker)
                    .await?;
            }
            "cancel" => {
                sqlx::query(
                    "UPDATE operations SET cancel_requested=true WHERE tenant_id=$1 AND id=$2",
                )
                .bind(plan.record.tenant_id)
                .bind(plan.record.operation_id)
                .execute(&mut *blocker)
                .await?;
            }
            _ => {
                sqlx::query("UPDATE operations SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND id=$2").bind(plan.record.tenant_id).bind(plan.record.operation_id).execute(&mut *blocker).await?;
            }
        }
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        let (result, released) = tokio::join!(Box::pin(self.service.decide(r)), async {
            Self::wait_pid(base, pid).await?;
            blocker.commit().await?;
            anyhow::Ok(())
        });
        released?;
        ensure!(
            result.err().context("postwait must deny")?.code == 403,
            "SQL timeout is not post-wait denial"
        );
        let mut tx = base.f.owner_transaction().await?;
        sqlx::query("UPDATE runtime_nodes SET enabled=true WHERE node_uid=$1 AND boot_id=$2")
            .bind(base.node.node_uid)
            .bind(base.node.boot_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE backup_profiles SET enabled=true WHERE id=$1")
            .bind(plan.record.profile_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE operations SET cancel_requested=false,lease_until=$3 WHERE tenant_id=$1 AND id=$2").bind(plan.record.tenant_id).bind(plan.record.operation_id).bind(until).execute(&mut *tx).await?;
        tx.commit().await?;
        self.allow(r).await?;
        Ok(())
    }
    async fn late_node_lock(
        &self,
        _plan: &JobPlan,
        base: &FixtureRuntime,
        r: &AdmissionRequest,
    ) -> anyhow::Result<()> {
        let mut blocker = base.f.owner_transaction().await?;
        sqlx::query("SELECT id FROM runtime_nodes WHERE node_uid=$1 AND boot_id=$2 FOR UPDATE")
            .bind(base.node.node_uid)
            .bind(base.node.boot_id)
            .fetch_one(&mut *blocker)
            .await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        self.delay.store(9000, Ordering::SeqCst);
        let (result, released) = tokio::join!(Box::pin(self.service.decide(r)), async {
            // The delayed real HTTP GET occurs before the SQL node lock. Only
            // hold the SQL wait for two seconds, below production lock_timeout.
            tokio::time::sleep(Duration::from_secs(9)).await;
            Self::wait_pid(base, pid).await?;
            tokio::time::sleep(Duration::from_secs(2)).await;
            blocker.commit().await?;
            anyhow::Ok(())
        });
        released?;
        let d = result
            .err()
            .context("late node lock must expire monotonic observation")?;
        ensure!(
            d.code == 403 && d.message.contains("expired after waiting"),
            "timeout or dependency error is not final freshness rejection"
        );
        Ok(())
    }
    pub(super) async fn status(&self, base: &FixtureRuntime, name: &str) -> anyhow::Result<()> {
        let path = Self::pod_path(name);
        let original = self.get(&path)?;
        let r = Self::status_request(&original, &base.node)?;
        self.allow(&r).await?;
        for field in [
            "node_user",
            "node_group",
            "uid",
            "spec",
            "namespace",
            "name",
            "labels",
            "owner",
            "finalizer",
            "deletion",
        ] {
            let mut bad = r.clone();
            match field {
                "node_user" => bad.user_info.username = "system:node:other".into(),
                "node_group" => bad.user_info.groups.clear(),
                "uid" => {
                    bad.object.as_mut().context("new Pod")?["metadata"]["uid"] =
                        json!(Uuid::new_v4())
                }
                "spec" => {
                    bad.object.as_mut().context("new Pod")?["spec"]["containers"][0]["image"] =
                        json!("unsafe:latest")
                }
                "namespace" => {
                    bad.object.as_mut().context("new Pod")?["metadata"]["namespace"] =
                        json!("foreign")
                }
                "name" => {
                    bad.object.as_mut().context("new Pod")?["metadata"]["name"] = json!("foreign")
                }
                "labels" => {
                    bad.object.as_mut().context("new Pod")?["metadata"]["labels"]["sandbox.platform/tenant-id"] =
                        json!(Uuid::new_v4())
                }
                "owner" => {
                    bad.object.as_mut().context("new Pod")?["metadata"]["ownerReferences"][0]["uid"] =
                        json!(Uuid::new_v4())
                }
                "finalizer" => {
                    bad.object.as_mut().context("new Pod")?["metadata"]["finalizers"] = json!([])
                }
                _ => {
                    bad.object.as_mut().context("new Pod")?["metadata"]["deletionTimestamp"] =
                        json!(chrono::Utc::now())
                }
            };
            self.deny(&bad).await?;
        }
        let node_path = format!("/api/v1/nodes/{}", base.node.node_name);
        let node = self.get(&node_path)?;
        let mut changed = node.clone();
        changed["status"]["nodeInfo"]["bootID"] = json!(Uuid::new_v4());
        self.put(&node_path, changed)?;
        self.deny(&r).await?;
        self.put(&node_path, node)?;
        let mut changed = original.clone();
        changed["metadata"]["uid"] = json!(Uuid::new_v4());
        self.put(&path, changed.clone())?;
        self.deny(&Self::status_request(&changed, &base.node)?)
            .await?;
        self.put(&path, original)?;
        Ok(())
    }
    pub(super) async fn revoked_status(
        &self,
        plan: &JobPlan,
        base: &FixtureRuntime,
        name: &str,
    ) -> anyhow::Result<()> {
        let mut tx = base.f.owner_transaction().await?;
        let until: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT lease_until FROM operations WHERE tenant_id=$1 AND id=$2")
                .bind(plan.record.tenant_id)
                .bind(plan.record.operation_id)
                .fetch_one(&mut *tx)
                .await?;
        sqlx::query("UPDATE backup_profiles SET enabled=false WHERE id=$1")
            .bind(plan.record.profile_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE runtime_nodes SET enabled=false WHERE node_uid=$1 AND boot_id=$2")
            .bind(base.node.node_uid)
            .bind(base.node.boot_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE operations SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND id=$2").bind(plan.record.tenant_id).bind(plan.record.operation_id).execute(&mut *tx).await?;
        tx.commit().await?;
        self.status(base, name).await?;
        let path = Self::pod_path(name);
        let original = self.get(&path)?;
        let mut deleting = original.clone();
        deleting["metadata"]["deletionTimestamp"] = json!(chrono::Utc::now());
        deleting["metadata"]["deletionGracePeriodSeconds"] = json!(30);
        self.put(&path, deleting.clone())?;
        self.allow(&Self::status_request(&deleting, &base.node)?)
            .await?;
        deleting["metadata"]["finalizers"] = json!(["batch.kubernetes.io/job-tracking"]);
        self.put(&path, deleting.clone())?;
        self.deny(&Self::status_request(&deleting, &base.node)?)
            .await?;
        deleting["metadata"]
            .as_object_mut()
            .context("metadata")?
            .remove("finalizers");
        self.put(&path, deleting.clone())?;
        self.deny(&Self::status_request(&deleting, &base.node)?)
            .await?;
        self.put(&path, original)?;
        let mut tx = base.f.owner_transaction().await?;
        sqlx::query("UPDATE backup_profiles SET enabled=true WHERE id=$1")
            .bind(plan.record.profile_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE runtime_nodes SET enabled=true WHERE node_uid=$1 AND boot_id=$2")
            .bind(base.node.node_uid)
            .bind(base.node.boot_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE operations SET lease_until=$3 WHERE tenant_id=$1 AND id=$2")
            .bind(plan.record.tenant_id)
            .bind(plan.record.operation_id)
            .bind(until)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        eprintln!(
            "VERIFIED actual HTTP historical assigned-node status after grant/profile/node revocation and expired lease in RESTORE_CLOSING, deleting protected Pod allowed, missing exact termination proof denied"
        );
        Ok(())
    }
    pub(super) async fn proven_status(
        &self,
        base: &FixtureRuntime,
        name: &str,
    ) -> anyhow::Result<()> {
        let path = Self::pod_path(name);
        let original = self.get(&path)?;
        let mut removed = original.clone();
        removed["metadata"]
            .as_object_mut()
            .context("metadata")?
            .remove("finalizers");
        self.put(&path, removed.clone())?;
        self.allow(&Self::status_request(&removed, &base.node)?)
            .await?;
        self.put(&path, original)?;
        eprintln!(
            "VERIFIED late assigned-node status with Kubernetes omitted finalizers only after exact permit's actual trusted mTLS termination proof"
        );
        Ok(())
    }
}
