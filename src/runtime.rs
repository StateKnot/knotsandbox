//! Kubernetes I/O for a single, controlled Kata backend. Successful HTTP calls
//! are observations, not proof of Cilium enforcement or VM termination.

use std::time::Duration;

use k8s_openapi::api::{
    core::v1::{Namespace, PersistentVolumeClaim, Pod},
    networking::v1::NetworkPolicy,
    node::v1::RuntimeClass,
};
use kube::{
    Api, Client, Config,
    api::{DeleteParams, PostParams, Preconditions},
    core::{ApiResource, DynamicObject, GroupVersionKind},
};
use thiserror::Error;

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
        let api: Api<RuntimeClass> = Api::all(self.client.clone());
        let class = api
            .get_opt("kata-qemu")
            .await?
            .ok_or(RuntimeError::InvalidRuntimeClass)?;
        if class.metadata.deletion_timestamp.is_some()
            || class.handler != "kata-qemu"
            || class
                .scheduling
                .as_ref()
                .and_then(|s| s.node_selector.as_ref())
                .and_then(|s| s.get("sandbox.platform/worker-pool"))
                .map(String::as_str)
                != Some("kata")
        {
            return Err(RuntimeError::InvalidRuntimeClass);
        }
        crate::runtime_resource_contract::validate_overhead(
            class
                .overhead
                .as_ref()
                .and_then(|overhead| overhead.pod_fixed.as_ref()),
        )
        .map_err(|_| RuntimeError::InvalidRuntimeClass)?;
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
        let expected = &manifests.pod;
        crate::runtime_resource_contract::validate_provision_resources(expected, expected)
            .map_err(|_| ManifestError::SpecificationDrift("runtime resource quantities"))?;
        let (namespace, name) = identity(&expected.metadata)?;
        let api: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
        let pod = match api.get_opt(name).await? {
            Some(pod) => pod,
            None if known_uid.is_some() => {
                return Err(ManifestError::OwnershipMismatch("recorded Pod disappeared").into());
            }
            None => match api.create(&PostParams::default(), expected).await {
                Ok(pod) => pod,
                Err(kube::Error::Api(e)) if e.code == 409 => api.get(name).await?,
                Err(e) => return Err(e.into()),
            },
        };
        validate_existing_pod(&pod, expected, known_uid)?;
        crate::runtime_resource_contract::validate_provision_resources(&pod, expected)
            .map_err(|_| ManifestError::SpecificationDrift("runtime resource quantities"))?;
        Ok(pod)
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
        sync::{Arc, Mutex},
    };

    fn runtime_class_response(overhead: serde_json::Value) -> KubernetesRuntime {
        let class = serde_json::json!({
            "apiVersion":"node.k8s.io/v1", "kind":"RuntimeClass",
            "metadata":{"name":"kata-qemu"}, "handler":"kata-qemu",
            "scheduling":{"nodeSelector":{"sandbox.platform/worker-pool":"kata"}},
            "overhead":overhead
        });
        let service = tower::service_fn(move |request: Request<KubeBody>| {
            assert_eq!(
                request.uri().path(),
                "/apis/node.k8s.io/v1/runtimeclasses/kata-qemu"
            );
            let body = class.to_string();
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
            "metadata":{"name":"kata-qemu"}, "handler":"kata-qemu",
            "scheduling":{"nodeSelector":{"sandbox.platform/worker-pool":"kata"}},
            "overhead":{"podFixed":{"cpu":"-250m","memory":"160Mi"}}
        });
        let service = tower::service_fn(move |request: Request<KubeBody>| {
            assert_eq!(
                request.uri().path(),
                "/apis/node.k8s.io/v1/runtimeclasses/kata-qemu"
            );
            let body = class.to_string();
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
