//! Bounded live-object inventory, independent of operation completion. Permanent
//! birth/closure and UID receipts survive a scan that saw no Pod; a delayed Pod
//! is still recognized later. This collector never touches PVCs or PVs.
use anyhow::{Context, ensure};
use k8s_openapi::api::core::v1::Pod;
use kube::{
    Api, Client,
    api::{DeleteParams, ListParams, Patch, PatchParams, Preconditions},
};
use serde_json::{Value, json};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    db::Database,
    runtime_manifest::{
        RuntimeManifestConfig, RuntimeManifestContext, TERMINATION_FINALIZER, build_manifests,
        validate_existing_pod,
    },
};

#[derive(FromRow)]
struct ClosedContext {
    tenant_id: Uuid,
    project_id: Uuid,
    instance_id: Uuid,
    workspace_id: Uuid,
    launch_id: Uuid,
    cluster_epoch: Uuid,
    generation: i64,
    namespace: String,
    storage_class: String,
    image_ref: String,
    image_digest: String,
    security_policy_rules: Value,
    cpu_millis: i64,
    memory_mib: i64,
    workspace_size_gib: i64,
    closure_id: Uuid,
    #[sqlx(skip)]
    restore_snapshot: Option<String>,
}
impl ClosedContext {
    fn context(&self) -> RuntimeManifestContext {
        RuntimeManifestContext {
            tenant_id: self.tenant_id,
            project_id: self.project_id,
            instance_id: self.instance_id,
            workspace_id: self.workspace_id,
            launch_id: self.launch_id,
            cluster_epoch: self.cluster_epoch,
            generation: self.generation,
            namespace: self.namespace.clone(),
            storage_class: self.storage_class.clone(),
            workspace_snapshot: self.restore_snapshot.clone(),
            image_ref: self.image_ref.clone(),
            image_digest: self.image_digest.clone(),
            template_approved: true,
            security_policy_approved: true,
            security_policy_rules: self.security_policy_rules.clone(),
            cpu_millis: self.cpu_millis,
            memory_mib: self.memory_mib,
            workspace_size_gib: self.workspace_size_gib,
        }
    }
}
#[derive(Clone)]
pub struct NeverAuthorizedGc {
    pub(crate) database: Database,
    pub(crate) client: Client,
    pub(crate) manifests: RuntimeManifestConfig,
}
impl NeverAuthorizedGc {
    /// One API-server inventory page. Labels select candidates, but grant no
    /// authority: each candidate requires exact immutable DB identity and spec.
    pub async fn page(&self, continuation: Option<&str>) -> anyhow::Result<Option<String>> {
        let api: Api<Pod> = Api::all(self.client.clone());
        let mut params = ListParams::default()
            .labels("app.kubernetes.io/managed-by=sandbox-platform")
            .limit(100);
        if let Some(token) = continuation {
            params = params.continue_token(token);
        }
        let page = api.list(&params).await?;
        for pod in page.items {
            match tokio::time::timeout(std::time::Duration::from_secs(10), self.collect(&pod)).await
            {
                Ok(Ok(_)) => {}
                _ => tracing::warn!(
                    reason = "NEVER_AUTHORIZED_POD_GC_BLOCKED",
                    "closed launch Pod cleanup requires retry"
                ),
            }
        }
        Ok(page.metadata.continue_.filter(|v| !v.is_empty()))
    }
    pub(crate) async fn collect(&self, pod: &Pod) -> anyhow::Result<bool> {
        let Some(labels) = pod.metadata.labels.as_ref() else {
            return Ok(false);
        };
        let selected = |key: &str| {
            labels
                .get(&format!("sandbox.platform/{key}"))
                .and_then(|s| Uuid::parse_str(s).ok())
        };
        let (Some(tenant), Some(instance)) = (selected("tenant-id"), selected("instance-id"))
        else {
            return Ok(false);
        };
        let mut tx = self
            .database
            .begin(tenant)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e.code))?;
        let mut scope:Option<ClosedContext>=sqlx::query_as("SELECT i.tenant_id,i.project_id,i.id AS instance_id,i.workspace_id,i.launch_id,i.cluster_epoch,i.runtime_generation AS generation,i.namespace,w.storage_class,t.image_ref,t.image_digest,p.rules AS security_policy_rules,i.cpu_millis,i.memory_mib,w.size_gib AS workspace_size_gib,i.never_authorized_closure_id AS closure_id FROM instances i JOIN workspaces w ON w.tenant_id=i.tenant_id AND w.id=i.workspace_id JOIN template_versions t ON t.tenant_id=i.tenant_id AND t.id=i.template_version_id JOIN security_policy_versions p ON p.tenant_id=i.tenant_id AND p.id=i.security_policy_version_id WHERE i.tenant_id=$1 AND i.id=$2 AND i.observed_state='DELETED' AND i.desired_state='DELETED' AND sandbox_never_authorized(i.tenant_id,i.id,i.workspace_id,i.runtime_generation,i.launch_id,i.cluster_epoch,i.never_authorized_closure_id)")
            .bind(tenant).bind(instance).fetch_optional(&mut *tx).await?;
        if let Some(ref mut value) = scope {
            let mut context = value.context();
            crate::workspace_restore::apply(&mut tx, &mut context)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e.code))?;
            value.restore_snapshot = context.workspace_snapshot;
        }
        tx.commit().await?;
        let Some(scope) = scope else { return Ok(false) };
        let expected = build_manifests(&scope.context(), &self.manifests)?;
        let name = expected
            .pod
            .metadata
            .name
            .as_deref()
            .context("controlled Pod name missing")?;
        ensure!(
            pod.metadata.name.as_deref() == Some(name)
                && pod.metadata.namespace.as_deref() == Some(scope.namespace.as_str()),
            "candidate scope mismatch"
        );
        let api: Api<Pod> = Api::namespaced(self.client.clone(), &scope.namespace);
        let Some(current) = api.get_opt(name).await? else {
            return Ok(false);
        };
        let uid = current.metadata.uid.as_deref().context("Pod UID missing")?;
        ensure!(
            current.metadata.uid == pod.metadata.uid,
            "inventory Pod replaced"
        );
        let id = Uuid::parse_str(uid)?;
        let rv = current
            .metadata
            .resource_version
            .as_deref()
            .context("resourceVersion missing")?;
        let mut checked = current.clone();
        checked.metadata.deletion_timestamp = None;
        // A closed generation cannot ever run, even after the protective
        // finalizer has already been removed by a previous successful pass.
        checked.metadata.finalizers = Some(vec![TERMINATION_FINALIZER.into()]);
        ensure!(
            current
                .metadata
                .finalizers
                .as_ref()
                .is_none_or(|v| v.iter().all(|x| x == TERMINATION_FINALIZER)),
            "foreign finalizer requires operator review"
        );
        validate_existing_pod(&checked, &expected.pod, Some(uid))?;
        let mut tx = self
            .database
            .begin(tenant)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e.code))?;
        sqlx::query("SELECT id FROM workspaces WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(tenant)
            .bind(scope.workspace_id)
            .fetch_one(&mut *tx)
            .await?;
        let valid: bool =
            sqlx::query_scalar("SELECT sandbox_never_authorized($1,$2,$3,$4,$5,$6,$7)")
                .bind(tenant)
                .bind(instance)
                .bind(scope.workspace_id)
                .bind(scope.generation)
                .bind(scope.launch_id)
                .bind(scope.cluster_epoch)
                .bind(scope.closure_id)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(valid, "closure epoch changed");
        sqlx::query("INSERT INTO never_authorized_pod_observations(tenant_id,closure_id,pod_uid,resource_version) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,closure_id,pod_uid) DO NOTHING").bind(tenant).bind(scope.closure_id).bind(id).bind(rv).execute(&mut *tx).await?;
        tx.commit().await?;
        if current.metadata.deletion_timestamp.is_none() {
            api.delete(
                name,
                &DeleteParams {
                    grace_period_seconds: Some(30),
                    preconditions: Some(Preconditions {
                        uid: Some(uid.into()),
                        resource_version: Some(rv.into()),
                    }),
                    ..Default::default()
                },
            )
            .await?;
            return Ok(true);
        }
        if current
            .metadata
            .finalizers
            .as_ref()
            .is_some_and(|v| v.iter().any(|x| x == TERMINATION_FINALIZER))
        {
            api.patch(
                name,
                &PatchParams::default(),
                &Patch::Merge(json!({"metadata":{"uid":uid,"resourceVersion":rv,"finalizers":[]}})),
            )
            .await?;
        }
        Ok(true)
    }
}
