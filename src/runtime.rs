//! Kubernetes I/O for a single, controlled Kata backend. Successful HTTP calls
//! are observations, not proof of Cilium enforcement or VM termination.

use std::time::Duration;

use chrono::{DateTime, Utc};
use k8s_openapi::api::{
    core::v1::{Namespace, PersistentVolumeClaim, Pod},
    networking::v1::NetworkPolicy,
};
use kube::{
    Api, Client, Config,
    api::{DeleteParams, PostParams, Preconditions},
    core::{ApiResource, DynamicObject, GroupVersionKind},
};
use thiserror::Error;
use uuid::Uuid;

use crate::runtime_manifest::{
    ManifestError, RuntimeManifests, validate_existing_pod, validate_existing_policy,
    validate_existing_pvc,
};

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("Kubernetes connection configuration is not secure")]
    InsecureConfiguration,
    #[error("Kata RuntimeClass is missing or has an unexpected handler")]
    InvalidRuntimeClass,
    #[error(
        "namespace does not reference the required deployment certification and tenant binding"
    )]
    UncertifiedNamespace,
    #[error("Kubernetes API request failed (HTTP {0:?})")]
    Kubernetes(Option<u16>),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("Kubernetes object has no stable name, namespace, or UID")]
    MissingIdentity,
}

impl From<kube::Error> for RuntimeError {
    fn from(error: kube::Error) -> Self {
        let code = if let kube::Error::Api(response) = error {
            Some(response.code)
        } else {
            None
        };
        // API error bodies may include workload arguments or admission details.
        Self::Kubernetes(code)
    }
}

#[derive(Clone)]
pub struct KubernetesRuntime {
    client: Client,
}

/// A capability minted only by the complete, repeated API readback below.
/// This carries facts forward without letting requested manifests or JSON
/// manufacture evidence. It is deliberately neither Clone nor Deserialize.
pub(crate) struct VerifiedPodResources {
    pod_uid: Uuid,
    pod_resource_version: String,
    node_name: Option<String>,
    quantities: crate::runtime_resource_contract::PodResourceObservation,
    class: crate::runtime_class_guard::ManagedRuntimeClass,
    observed_at: DateTime<Utc>,
}

impl VerifiedPodResources {
    pub(crate) fn pod_uid(&self) -> Uuid {
        self.pod_uid
    }
    pub(crate) fn pod_resource_version(&self) -> &str {
        &self.pod_resource_version
    }
    pub(crate) fn node_name(&self) -> Option<&str> {
        self.node_name.as_deref()
    }
    pub(crate) fn quantities(&self) -> &crate::runtime_resource_contract::PodResourceObservation {
        &self.quantities
    }
    pub(crate) fn class(&self) -> &crate::runtime_class_guard::ManagedRuntimeClass {
        &self.class
    }
    pub(crate) fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

pub(crate) struct VerifiedPodReadback {
    pub(crate) pod: Pod,
    pub(crate) resources: VerifiedPodResources,
}

impl KubernetesRuntime {
    pub(crate) fn client_clone(&self) -> Client {
        self.client.clone()
    }

    /// Inject an already configured client; production callers use `connect`.
    pub fn from_client(client: Client) -> Self {
        Self { client }
    }

    /// This binding references independently reviewed deployment evidence. It
    /// does not certify CNI enforcement, Kata isolation or admission by itself.
    pub async fn verify_namespace(
        &self,
        context: &crate::runtime_manifest::RuntimeManifestContext,
        certification_id: &str,
    ) -> Result<(), RuntimeError> {
        let api: Api<Namespace> = Api::all(self.client.clone());
        let ns = api.get(&context.namespace).await?;
        let labels = ns.metadata.labels.as_ref();
        if labels
            .and_then(|l| l.get("sandbox.platform/managed"))
            .map(String::as_str)
            != Some("true")
        {
            return Err(RuntimeError::UncertifiedNamespace);
        }
        for (key, value) in [
            ("sandbox.platform/tenant-id", context.tenant_id.to_string()),
            (
                "sandbox.platform/project-id",
                context.project_id.to_string(),
            ),
            (
                "sandbox.platform/cluster-epoch",
                context.cluster_epoch.to_string(),
            ),
        ] {
            if labels.and_then(|l| l.get(key)) != Some(&value) {
                return Err(RuntimeError::UncertifiedNamespace);
            }
        }
        if certification_id.is_empty()
            || ns.metadata.deletion_timestamp.is_some()
            || ns
                .metadata
                .annotations
                .as_ref()
                .and_then(|a| a.get("sandbox.platform/certification-id"))
                .map(String::as_str)
                != Some(certification_id)
        {
            return Err(RuntimeError::UncertifiedNamespace);
        }
        let policies: Api<NetworkPolicy> = Api::namespaced(self.client.clone(), &context.namespace);
        let baseline = policies.get("sandbox-default-deny").await?;
        if baseline.metadata.deletion_timestamp.is_some()
            || !baseline.spec.as_ref().is_some_and(|spec| {
                spec.pod_selector == Some(Default::default())
                    && spec.ingress.as_ref().is_none_or(Vec::is_empty)
                    && spec.egress.as_ref().is_none_or(Vec::is_empty)
                    && spec.policy_types.as_deref()
                        == Some(&["Ingress".to_owned(), "Egress".to_owned()])
            })
        {
            return Err(RuntimeError::UncertifiedNamespace);
        }
        Ok(())
    }

    /// Read-only discovery for a pending stop; absence is never proof of death.
    pub async fn find_stop_target(&self, expected: &Pod) -> Result<Option<Pod>, RuntimeError> {
        let (namespace, name) = identity(&expected.metadata)?;
        let api: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
        let pod = api.get_opt(name).await?;
        if let Some(pod) = &pod {
            let mut live = pod.clone();
            live.metadata.deletion_timestamp = None;
            validate_existing_pod(&live, expected, None)?;
        }
        Ok(pod)
    }

    pub async fn connect() -> Result<Self, RuntimeError> {
        let mut config = Config::infer()
            .await
            .map_err(|_| RuntimeError::InsecureConfiguration)?;
        if config.accept_invalid_certs || config.cluster_url.scheme_str() != Some("https") {
            return Err(RuntimeError::InsecureConfiguration);
        }
        // Non-idempotent exec must never be retried by kube's default 429/503/504
        // middleware. Resource reconciliation already owns explicit retries.
        config.default_retry = false;
        config.connect_timeout = Some(Duration::from_secs(3));
        config.read_timeout = Some(Duration::from_secs(10));
        let client = Client::try_from(config)?;
        Ok(Self { client })
    }

    pub async fn verify_runtime_class(&self) -> Result<(), RuntimeError> {
        crate::runtime_class_guard::read(self.client.clone()).await?;
        Ok(())
    }

    pub async fn ensure_network_policy(
        &self,
        expected: &DynamicObject,
        known_uid: Option<&str>,
    ) -> Result<DynamicObject, RuntimeError> {
        let (namespace, name) = identity(&expected.metadata)?;
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            "cilium.io",
            "v2",
            "CiliumNetworkPolicy",
        ));
        let api: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), namespace, &resource);
        let policy = match api.get_opt(name).await? {
            Some(policy) => policy,
            None if known_uid.is_some() => {
                return Err(ManifestError::OwnershipMismatch(
                    "recorded network policy disappeared",
                )
                .into());
            }
            None => match api.create(&PostParams::default(), expected).await {
                Ok(policy) => policy,
                Err(kube::Error::Api(e)) if e.code == 409 => api.get(name).await?,
                Err(e) => return Err(e.into()),
            },
        };
        validate_existing_policy(&policy, expected, known_uid)?;
        Ok(policy)
    }

    pub async fn ensure_workspace(
        &self,
        expected: &PersistentVolumeClaim,
        known_uid: Option<&str>,
    ) -> Result<PersistentVolumeClaim, RuntimeError> {
        let (namespace, name) = identity(&expected.metadata)?;
        let api: Api<PersistentVolumeClaim> = Api::namespaced(self.client.clone(), namespace);
        let pvc = match api.get_opt(name).await? {
            Some(pvc) => pvc,
            None if known_uid.is_some() => {
                return Err(ManifestError::OwnershipMismatch("recorded PVC disappeared").into());
            }
            None => match api.create(&PostParams::default(), expected).await {
                Ok(pvc) => pvc,
                Err(kube::Error::Api(e)) if e.code == 409 => api.get(name).await?,
                Err(e) => return Err(e.into()),
            },
        };
        validate_existing_pvc(&pvc, expected, known_uid)?;
        Ok(pvc)
    }

    /// A previously recorded UID is never recreated under the same launch: if
    /// it disappeared unexpectedly, reconciliation must quarantine the instance.
    pub async fn ensure_pod(
        &self,
        manifests: &RuntimeManifests,
        known_uid: Option<&str>,
    ) -> Result<Pod, RuntimeError> {
        // Typed Kubernetes readback state is large. Keep it on this module's
        // heap so every lifecycle caller does not inline it into its own future.
        Box::pin(self.ensure_pod_inner(manifests, known_uid)).await
    }

    async fn ensure_pod_inner(
        &self,
        manifests: &RuntimeManifests,
        known_uid: Option<&str>,
    ) -> Result<Pod, RuntimeError> {
        let expected = &manifests.pod;
        crate::runtime_resource_contract::validate_provision_resources(expected, expected)
            .map_err(|_| ManifestError::SpecificationDrift("runtime resource quantities"))?;
        let class = crate::runtime_class_guard::read(self.client.clone()).await?;
        let (namespace, name) = identity(&expected.metadata)?;
        let api: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
        let pod = match api.get_opt(name).await? {
            Some(pod) => pod,
            None if known_uid.is_some() => {
                return Err(ManifestError::OwnershipMismatch("recorded Pod disappeared").into());
            }
            None => match api.create(&PostParams::default(), expected).await {
                Ok(created) => {
                    // A successful create response is not the independent
                    // actual-object readback. Never adopt a same-name UID.
                    validate_existing_pod(&created, expected, None)?;
                    validate_pod_resource_version(&created)?;
                    let created_resources =
                        crate::runtime_resource_contract::observe_pod_resources(
                            &created,
                            expected,
                            class.overhead(),
                        )
                        .map_err(|_| {
                            ManifestError::SpecificationDrift("runtime resource quantities")
                        })?;
                    let created_uid = pod_uid(&created)?;
                    let readback = api.get(name).await?;
                    validate_existing_pod(&readback, expected, Some(created_uid))?;
                    let readback_resources =
                        crate::runtime_resource_contract::observe_pod_resources(
                            &readback,
                            expected,
                            class.overhead(),
                        )
                        .map_err(|_| {
                            ManifestError::SpecificationDrift("runtime resource quantities")
                        })?;
                    if created_resources != readback_resources
                        || !consistent_node_placement(&created, &readback, true)
                    {
                        return Err(
                            ManifestError::SpecificationDrift("Pod readback conflict").into()
                        );
                    }
                    readback
                }
                Err(kube::Error::Api(e)) if e.code == 409 => api.get(name).await?,
                Err(e) => return Err(e.into()),
            },
        };
        Ok(self
            .recheck_pod(expected, known_uid, pod, class, true)
            .await?
            .pod)
    }

    /// Fresh read-only validation used by trusted launch and execution readers.
    /// It does not commit a historical observation or authorize CRI/cleanup.
    pub(crate) async fn read_pod(
        &self,
        expected: &Pod,
        known_uid: &str,
    ) -> Result<VerifiedPodReadback, RuntimeError> {
        // Scheduled launch and exec readers share the same bounded interface.
        Box::pin(self.read_pod_inner(expected, known_uid)).await
    }

    async fn read_pod_inner(
        &self,
        expected: &Pod,
        known_uid: &str,
    ) -> Result<VerifiedPodReadback, RuntimeError> {
        let class = crate::runtime_class_guard::read(self.client.clone()).await?;
        let (namespace, name) = identity(&expected.metadata)?;
        let api: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
        let pod = api.get(name).await?;
        self.recheck_pod(expected, Some(known_uid), pod, class, false)
            .await
    }

    async fn recheck_pod(
        &self,
        expected: &Pod,
        known_uid: Option<&str>,
        pod: Pod,
        class: crate::runtime_class_guard::ManagedRuntimeClass,
        allow_initial_scheduling: bool,
    ) -> Result<VerifiedPodReadback, RuntimeError> {
        validate_existing_pod(&pod, expected, known_uid)?;
        validate_pod_resource_version(&pod)?;
        let resources = crate::runtime_resource_contract::observe_pod_resources(
            &pod,
            expected,
            class.overhead(),
        )
        .map_err(|_| ManifestError::SpecificationDrift("runtime resource quantities"))?;
        let after = crate::runtime_class_guard::read(self.client.clone()).await?;
        if !class.same_configuration(&after) {
            return Err(RuntimeError::InvalidRuntimeClass);
        }
        let (namespace, name) = identity(&expected.metadata)?;
        let api: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
        let current = api.get(name).await?;
        validate_existing_pod(&current, expected, Some(pod_uid(&pod)?))?;
        validate_pod_resource_version(&current)?;
        let current_resources = crate::runtime_resource_contract::observe_pod_resources(
            &current,
            expected,
            after.overhead(),
        )
        .map_err(|_| ManifestError::SpecificationDrift("runtime resource quantities"))?;
        // Status and opaque RV may legitimately advance between GETs. During
        // provisioning, an unassigned Pod may acquire its first node. Once a
        // node exists it stays pinned; trusted scheduled reads require exact
        // placement even when the initial source is still unassigned.
        if resources != current_resources
            || !consistent_node_placement(&pod, &current, allow_initial_scheduling)
        {
            return Err(ManifestError::SpecificationDrift("Pod readback conflict").into());
        }
        let pod_uid = Uuid::parse_str(pod_uid(&current)?)
            .ok()
            .filter(|id| !id.is_nil())
            .ok_or(RuntimeError::MissingIdentity)?;
        let evidence = VerifiedPodResources {
            pod_uid,
            pod_resource_version: current
                .metadata
                .resource_version
                .clone()
                .ok_or(RuntimeError::MissingIdentity)?,
            node_name: current.spec.as_ref().and_then(|s| s.node_name.clone()),
            quantities: current_resources,
            class: after,
            observed_at: Utc::now(),
        };
        Ok(VerifiedPodReadback {
            pod: current,
            resources: evidence,
        })
    }

    /// Requests termination with UID+resourceVersion preconditions. It never
    /// force-deletes, removes the finalizer, or reports that the VM is dead.
    pub async fn request_stop(
        &self,
        expected: &Pod,
        known_uid: &str,
    ) -> Result<Option<Pod>, RuntimeError> {
        let (namespace, name) = identity(&expected.metadata)?;
        let api: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
        let Some(pod) = api.get_opt(name).await? else {
            return Ok(None);
        };
        let mut for_validation = pod.clone();
        for_validation.metadata.deletion_timestamp = None;
        validate_existing_pod(&for_validation, expected, Some(known_uid))?;
        if pod.metadata.deletion_timestamp.is_none() {
            let resource_version = pod
                .metadata
                .resource_version
                .as_ref()
                .filter(|v| !v.is_empty())
                .ok_or(RuntimeError::MissingIdentity)?;
            let params = DeleteParams {
                grace_period_seconds: Some(30),
                preconditions: Some(Preconditions {
                    uid: Some(known_uid.to_owned()),
                    resource_version: Some(resource_version.clone()),
                }),
                ..DeleteParams::default()
            };
            api.delete(name, &params).await?;
        }
        Ok(Some(pod))
    }
}

fn consistent_node_placement(before: &Pod, after: &Pod, allow_initial_scheduling: bool) -> bool {
    let previous = before
        .spec
        .as_ref()
        .and_then(|spec| spec.node_name.as_deref());
    let current = after
        .spec
        .as_ref()
        .and_then(|spec| spec.node_name.as_deref());
    previous == current
        || (allow_initial_scheduling
            && previous.is_none()
            && current.is_some_and(|node| !node.is_empty()))
}

fn pod_uid(pod: &Pod) -> Result<&str, RuntimeError> {
    pod.metadata
        .uid
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or(RuntimeError::MissingIdentity)
}

fn validate_pod_resource_version(pod: &Pod) -> Result<(), RuntimeError> {
    if pod
        .metadata
        .resource_version
        .as_deref()
        .is_some_and(|value| {
            !value.is_empty()
                && value.len() <= 256
                && value.is_ascii()
                && !value
                    .bytes()
                    .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        })
    {
        Ok(())
    } else {
        Err(RuntimeError::MissingIdentity)
    }
}

fn identity(
    metadata: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta,
) -> Result<(&str, &str), RuntimeError> {
    match (metadata.namespace.as_deref(), metadata.name.as_deref()) {
        (Some(namespace), Some(name)) if !namespace.is_empty() && !name.is_empty() => {
            Ok((namespace, name))
        }
        _ => Err(RuntimeError::MissingIdentity),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, Response},
    };
    use kube::client::Body as KubeBody;
    use std::{
        convert::Infallible,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    #[tokio::test]
    async fn verified_readback_carries_final_api_identifiers_and_actual_quantities()
    -> anyhow::Result<()> {
        use crate::runtime_manifest::{
            RuntimeManifestConfig, RuntimeManifestContext, build_manifests,
        };
        use serde_json::json;
        let context = RuntimeManifestContext {
            tenant_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            instance_id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            launch_id: Uuid::new_v4(),
            cluster_epoch: Uuid::new_v4(),
            generation: 1,
            namespace: "resource-readback-test".into(),
            storage_class: "encrypted-rwo".into(),
            workspace_snapshot: None,
            image_ref: "registry.example.test/runtime".into(),
            image_digest: format!("sha256:{}", "a".repeat(64)),
            template_approved: true,
            security_policy_approved: true,
            security_policy_rules: json!({"profile":"deny-all","dns":true}),
            cpu_millis: 1000,
            memory_mib: 2048,
            workspace_size_gib: 20,
        };
        let config = RuntimeManifestConfig {
            runtime_class_name: "kata-qemu".into(),
            dns_namespace: "kube-system".into(),
            dns_labels: [("k8s-app".into(), "kube-dns".into())].into(),
            ephemeral_storage_mib: 1024,
            tmp_size_mib: 256,
        };
        let manifests = build_manifests(&context, &config)?;
        let pod_uid = Uuid::new_v4();
        let mut actual = serde_json::to_value(&manifests.pod)?;
        actual["metadata"]["uid"] = json!(pod_uid);
        actual["spec"]["nodeName"] = json!("kata-resource-node");
        actual["spec"]["overhead"] = json!({"cpu":"0.250","memory":"512M"});
        let reads = Arc::new(AtomicUsize::new(0));
        let class_reads = Arc::new(AtomicUsize::new(0));
        let seen = reads.clone();
        let seen_class = class_reads.clone();
        let service = tower::service_fn(move |request: Request<KubeBody>| {
            assert_eq!(request.method(), axum::http::Method::GET);
            let value = if request.uri().path().contains("/pods/") {
                let index = seen.fetch_add(1, Ordering::SeqCst) + 1;
                let mut pod = actual.clone();
                pod["metadata"]["resourceVersion"] = json!(format!("pod-opaque-{index}"));
                pod["status"] =
                    json!({"phase":"Pending","message":format!("metadata-only-{index}")});
                pod
            } else {
                let mut object = crate::test_support_db::runtime_class_guard::object(
                    request.uri().path(),
                    Some(&json!({"cpu":"250m","memory":"512M"})),
                )
                .unwrap_or_else(|| panic!("unexpected readback fixture path"));
                if request.uri().path().contains("/runtimeclasses/") {
                    let index = seen_class.fetch_add(1, Ordering::SeqCst) + 1;
                    object["metadata"]["resourceVersion"] = json!(format!("class-opaque-{index}"));
                }
                object
            };
            async move {
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(Body::from(value.to_string()))
                        .unwrap_or_else(|_| Response::new(Body::empty())),
                )
            }
        });
        let runtime = KubernetesRuntime::from_client(Client::new(service, "test"));
        let started = Utc::now();
        let readback = runtime
            .read_pod(&manifests.pod, &pod_uid.to_string())
            .await?;
        assert_eq!(reads.load(Ordering::SeqCst), 2);
        assert_eq!(class_reads.load(Ordering::SeqCst), 2);
        assert_eq!(readback.resources.pod_uid(), pod_uid);
        assert_eq!(readback.resources.pod_resource_version(), "pod-opaque-2");
        assert_eq!(readback.resources.node_name(), Some("kata-resource-node"));
        assert_eq!(
            readback.resources.class().resource_version(),
            "class-opaque-2"
        );
        assert_eq!(readback.resources.class().config_sha256().len(), 64);
        assert!(readback.resources.observed_at() >= started);
        assert!(readback.resources.observed_at() <= Utc::now());
        let q = readback.resources.quantities();
        assert_eq!(q.workload_cpu_millis(), 1000);
        assert_eq!(q.workload_memory_bytes(), 2_147_483_648);
        assert_eq!(q.workload_ephemeral_bytes(), 1_073_741_824);
        assert_eq!(q.overhead_cpu_millis(), 250);
        assert_eq!(q.overhead_memory_bytes(), 512_000_000);
        assert_eq!(q.class_overhead_cpu_millis(), 250);
        assert_eq!(q.class_overhead_memory_bytes(), 512_000_000);
        assert_eq!(q.effective_cpu_millis(), 1250);
        assert_eq!(q.effective_memory_bytes(), 2_659_483_648);
        Ok(())
    }

    fn runtime_class_response(overhead: serde_json::Value) -> KubernetesRuntime {
        let class = serde_json::json!({
            "apiVersion":"node.k8s.io/v1", "kind":"RuntimeClass",
            "metadata":{"name":"kata-qemu","uid":"00000000-0000-4000-8000-000000000101","resourceVersion":"class-fixture-rv"}, "handler":"kata-qemu",
            "scheduling":{"nodeSelector":{"sandbox.platform/worker-pool":"kata"}},
            "overhead":overhead
        });
        let service = tower::service_fn(move |request: Request<KubeBody>| {
            let body = if request.uri().path() == "/apis/node.k8s.io/v1/runtimeclasses/kata-qemu" {
                class.to_string()
            } else {
                crate::test_support_db::runtime_class_guard::object(request.uri().path(), None)
                    .unwrap_or_else(|| panic!("unexpected class fixture request"))
                    .to_string()
            };
            async move {
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap_or_else(|_| Response::new(Body::empty())),
                )
            }
        });
        KubernetesRuntime::from_client(Client::new(service, "test"))
    }

    #[tokio::test]
    async fn readback_interface_keeps_large_kubernetes_state_off_caller_futures() {
        let runtime = runtime_class_response(serde_json::Value::Null);
        let manifests = RuntimeManifests {
            pod: Pod::default(),
            pvc: PersistentVolumeClaim::default(),
            network_policy: DynamicObject::new(
                "size-probe",
                &ApiResource::from_gvk(&GroupVersionKind::gvk(
                    "cilium.io",
                    "v2",
                    "CiliumNetworkPolicy",
                )),
            ),
        };
        let guard = crate::runtime_class_guard::read(runtime.client_clone());
        let verify = runtime.verify_runtime_class();
        let ensure = runtime.ensure_pod(&manifests, None);
        let read = runtime.read_pod(&manifests.pod, "size-probe-uid");
        for (name, bytes) in [
            ("guard.read", std::mem::size_of_val(&guard)),
            ("verify_runtime_class", std::mem::size_of_val(&verify)),
            ("ensure_pod", std::mem::size_of_val(&ensure)),
            ("read_pod", std::mem::size_of_val(&read)),
        ] {
            eprintln!("{name} inline future bytes: {bytes}");
            assert!(
                bytes <= 256,
                "{name} leaked large readback state into callers: {bytes}"
            );
        }
        let class = crate::runtime_class_guard::read(runtime.client_clone())
            .await
            .unwrap_or_else(|error| panic!("size fixture was invalid: {error}"));
        let recheck = runtime.recheck_pod(&manifests.pod, None, Pod::default(), class, true);
        let bytes = std::mem::size_of_val(&recheck);
        eprintln!("recheck_pod internal future bytes: {bytes}");
        assert!(
            bytes <= 32 * 1024,
            "internal readback future exceeded its heap budget: {bytes}"
        );
    }

    #[tokio::test]
    async fn runtime_class_accepts_the_documented_quantity_subset_and_absent_overhead() {
        for overhead in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!({"podFixed":{}}),
            serde_json::json!({"podFixed":{"cpu":"250m","memory":"160Mi"}}),
            serde_json::json!({"podFixed":{"cpu":"0.25","memory":"512M"}}),
            serde_json::json!({"podFixed":{"cpu":"0.001","memory":"1Ki"}}),
            serde_json::json!({"podFixed":{"cpu":"0","memory":"0"}}),
            serde_json::json!({"podFixed":{"cpu":"1.000","memory":"1G"}}),
            serde_json::json!({"podFixed":{"cpu":"1","memory":"1000k"}}),
            serde_json::json!({"podFixed":{"memory":"1T"}}),
            serde_json::json!({"podFixed":{"memory":"1Ti"}}),
            serde_json::json!({"podFixed":{"cpu":"9223372036854775807m","memory":"9223372036854775807"}}),
        ] {
            assert!(
                runtime_class_response(overhead.clone())
                    .verify_runtime_class()
                    .await
                    .is_ok(),
                "supported configuration was refused: {overhead}"
            );
        }
    }

    #[tokio::test]
    async fn runtime_class_rejects_unsupported_precision_units_keys_and_overflow() {
        for values in [
            serde_json::json!({"cpu":"0.0001"}),
            serde_json::json!({"cpu":"1000.0m"}),
            serde_json::json!({"cpu":"1e0"}),
            serde_json::json!({"cpu":"+1"}),
            serde_json::json!({"cpu":"1 "}),
            serde_json::json!({"cpu":"NaN"}),
            serde_json::json!({"cpu":"1\u{a0}"}),
            serde_json::json!({"cpu":"9223372036854775808m"}),
            serde_json::json!({"cpu":"18446744073709551615"}),
            serde_json::json!({"cpu":"9".repeat(65)}),
            serde_json::json!({"cpu":"9".repeat(64)}),
            serde_json::json!({"memory":"-1"}),
            serde_json::json!({"memory":"1.5Gi"}),
            serde_json::json!({"memory":"1m"}),
            serde_json::json!({"memory":"1E"}),
            serde_json::json!({"memory":"9223372036854775808"}),
            serde_json::json!({"memory":"16777216Ti"}),
            serde_json::json!({"memory":""}),
            serde_json::json!({"nvidia.com/gpu":"1"}),
            serde_json::json!({"ephemeral-storage":"1Gi"}),
            serde_json::json!({"hugepages-2Mi":"2Mi"}),
        ] {
            let overhead = serde_json::json!({"podFixed":values});
            assert!(
                matches!(
                    runtime_class_response(overhead)
                        .verify_runtime_class()
                        .await,
                    Err(RuntimeError::InvalidRuntimeClass)
                ),
                "invalid resources were accepted: {values}"
            );
        }
    }

    #[tokio::test]
    async fn runtime_class_rejects_negative_cpu_overhead_from_the_api() -> anyhow::Result<()> {
        let class = serde_json::json!({
            "apiVersion":"node.k8s.io/v1", "kind":"RuntimeClass",
            "metadata":{"name":"kata-qemu","uid":"00000000-0000-4000-8000-000000000101","resourceVersion":"class-fixture-rv"}, "handler":"kata-qemu",
            "scheduling":{"nodeSelector":{"sandbox.platform/worker-pool":"kata"}},
            "overhead":{"podFixed":{"cpu":"-250m","memory":"160Mi"}}
        });
        let service = tower::service_fn(move |request: Request<KubeBody>| {
            let body = if request.uri().path() == "/apis/node.k8s.io/v1/runtimeclasses/kata-qemu" {
                class.to_string()
            } else {
                crate::test_support_db::runtime_class_guard::object(request.uri().path(), None)
                    .unwrap_or_else(|| panic!("unexpected class fixture request"))
                    .to_string()
            };
            async move {
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap_or_else(|_| Response::new(Body::empty())),
                )
            }
        });
        let runtime = KubernetesRuntime::from_client(Client::new(service, "test"));
        assert!(matches!(
            runtime.verify_runtime_class().await,
            Err(RuntimeError::InvalidRuntimeClass)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn a_missing_recorded_volume_is_never_recreated() -> anyhow::Result<()> {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let service = tower::service_fn(move |request: Request<KubeBody>| {
            captured
                .lock()
                .map(|mut rows| rows.push(request.method().clone()))
                .ok();
            async {
                Ok::<_,Infallible>(Response::builder().status(404).header("content-type","application/json").body(Body::from(r#"{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404,"message":"missing"}"#)).unwrap_or_else(|_|Response::new(Body::empty())))
            }
        });
        let runtime = KubernetesRuntime {
            client: Client::new(service, "test"),
        };
        let pvc = PersistentVolumeClaim {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("ws-test".into()),
                namespace: Some("test".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(matches!(
            runtime.ensure_workspace(&pvc, Some("known-uid")).await,
            Err(RuntimeError::Manifest(ManifestError::OwnershipMismatch(
                "recorded PVC disappeared"
            )))
        ));
        assert_eq!(
            *requests
                .lock()
                .map_err(|_| anyhow::anyhow!("test lock poisoned"))?,
            vec![axum::http::Method::GET]
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_unknown_stop_target_does_not_force_delete_or_claim_termination()
    -> anyhow::Result<()> {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let service = tower::service_fn(move |request: Request<KubeBody>| {
            captured
                .lock()
                .map(|mut rows| rows.push(request.method().clone()))
                .ok();
            async {
                Ok::<_,Infallible>(Response::builder().status(404).header("content-type","application/json").body(Body::from(r#"{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404,"message":"missing"}"#)).unwrap_or_else(|_|Response::new(Body::empty())))
            }
        });
        let runtime = KubernetesRuntime {
            client: Client::new(service, "test"),
        };
        let pod = Pod {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("sbx-ws-test".into()),
                namespace: Some("test".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        // None is deliberately an unknown observation, not a termination proof.
        assert!(runtime.request_stop(&pod, "known-uid").await?.is_none());
        assert_eq!(
            *requests
                .lock()
                .map_err(|_| anyhow::anyhow!("test lock poisoned"))?,
            vec![axum::http::Method::GET]
        );
        Ok(())
    }
}
