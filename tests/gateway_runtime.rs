//! Synthetic Kubernetes transport verifies client decisions, not Kata isolation.
#[path = "support/runtime_class_guard.rs"]
mod runtime_class_guard;
use axum::{
    body::Body,
    http::{Method, Request, Response},
};
use kube::{Client, client::Body as KubeBody};
use sandbox_platform::{
    gateway_runtime::{GatewayRuntime, KnownRuntimeResources},
    runtime::KubernetesRuntime,
    runtime_manifest::{
        RuntimeManifestConfig, RuntimeManifestContext, build_manifests, container_name,
        network_policy_name, pod_name, pvc_name,
    },
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

type ObservedRequests = Arc<Mutex<Vec<(Method, String)>>>;

struct Fixture {
    context: RuntimeManifestContext,
    config: RuntimeManifestConfig,
    known: KnownRuntimeResources,
    objects: BTreeMap<String, Value>,
}
impl Fixture {
    fn new() -> anyhow::Result<Self> {
        let context = RuntimeManifestContext {
            tenant_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            instance_id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            launch_id: Uuid::new_v4(),
            cluster_epoch: Uuid::new_v4(),
            generation: 7,
            namespace: "runtime-project".into(),
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
            dns_labels: BTreeMap::from([("k8s-app".into(), "kube-dns".into())]),
            ephemeral_storage_mib: 1024,
            tmp_size_mib: 256,
        };
        let known = KnownRuntimeResources {
            pod_uid: Uuid::new_v4(),
            pvc_uid: Uuid::new_v4().to_string(),
            policy_uid: Uuid::new_v4().to_string(),
        };
        let manifests = build_manifests(&context, &config)?;
        let mut pod = serde_json::to_value(manifests.pod)?;
        pod["metadata"]["uid"] = json!(known.pod_uid);
        pod["metadata"]["resourceVersion"] = json!("pod-fixture-rv");
        pod["spec"]["nodeName"] = json!("kata-node");
        pod["status"] = json!({"phase":"Running","conditions":[{"type":"Ready","status":"True"}],"containerStatuses":[{"name":container_name(context.launch_id),"ready":true,"restartCount":0,"image":"registry.example.test/runtime","imageID":"runtime-image","state":{"running":{}}}]});
        let mut pvc = serde_json::to_value(manifests.pvc)?;
        pvc["metadata"]["uid"] = json!(known.pvc_uid);
        pvc["spec"]["volumeName"] = json!("workspace-volume");
        pvc["status"] = json!({"phase":"Bound"});
        let mut policy = serde_json::to_value(manifests.network_policy)?;
        policy["metadata"]["uid"] = json!(known.policy_uid);
        let mut objects = BTreeMap::from([
            (
                "class".into(),
                runtime_class_guard::object("/apis/node.k8s.io/v1/runtimeclasses/kata-qemu", None)
                    .ok_or_else(|| anyhow::anyhow!("class fixture"))?,
            ),
            (
                "namespace".into(),
                json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":context.namespace,"labels":{"sandbox.platform/managed":"true","sandbox.platform/tenant-id":context.tenant_id,"sandbox.platform/project-id":context.project_id,"sandbox.platform/cluster-epoch":context.cluster_epoch},"annotations":{"sandbox.platform/certification-id":"test-only-certification"}}}),
            ),
            (
                "baseline".into(),
                json!({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"sandbox-default-deny","namespace":context.namespace},"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"]}}),
            ),
            (
                "node".into(),
                json!({"apiVersion":"v1","kind":"Node","metadata":{"name":"kata-node","uid":Uuid::new_v4(),"labels":{"sandbox.platform/worker-pool":"kata"}},"spec":{"taints":[{"key":"sandbox.platform/untrusted","value":"true","effect":"NoSchedule"}]},"status":{"conditions":[{"type":"Ready","status":"True"}]}}),
            ),
            (
                "volume".into(),
                json!({"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":"workspace-volume","uid":Uuid::new_v4()},"spec":{"accessModes":["ReadWriteOnce"],"volumeMode":"Filesystem","storageClassName":context.storage_class,"csi":{"driver":"diskplugin.csi.alibabacloud.com","volumeHandle":"fixture-only-volume"},"claimRef":{"kind":"PersistentVolumeClaim","name":pvc_name(context.workspace_id),"namespace":context.namespace,"uid":known.pvc_uid}},"status":{"phase":"Bound"}}),
            ),
        ]);
        for (key, path) in [
            (
                "guard-policy",
                "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/sandbox-kata-runtimeclass-v1",
            ),
            (
                "guard-binding",
                "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/sandbox-kata-runtimeclass-v1",
            ),
        ] {
            objects.insert(
                key.into(),
                runtime_class_guard::object(path, None)
                    .ok_or_else(|| anyhow::anyhow!("guard fixture"))?,
            );
        }
        objects.insert("pod".into(), pod);
        objects.insert("pvc".into(), pvc);
        objects.insert("policy".into(), policy);
        Ok(Self {
            context,
            config,
            known,
            objects,
        })
    }
    fn runtime(&self) -> (GatewayRuntime, ObservedRequests) {
        self.runtime_with_node_change(None)
    }

    fn runtime_with_node_change(
        &self,
        second_node: Option<&'static str>,
    ) -> (GatewayRuntime, ObservedRequests) {
        let c = &self.context;
        let paths: BTreeMap<String, String> = [
            (
                "class",
                "/apis/node.k8s.io/v1/runtimeclasses/kata-qemu".into(),
            ),
            ("guard-policy", "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/sandbox-kata-runtimeclass-v1".into()),
            ("guard-binding", "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/sandbox-kata-runtimeclass-v1".into()),
            ("namespace", format!("/api/v1/namespaces/{}", c.namespace)),
            (
                "baseline",
                format!(
                    "/apis/networking.k8s.io/v1/namespaces/{}/networkpolicies/sandbox-default-deny",
                    c.namespace
                ),
            ),
            (
                "pod",
                format!(
                    "/api/v1/namespaces/{}/pods/{}",
                    c.namespace,
                    pod_name(c.workspace_id)
                ),
            ),
            (
                "pvc",
                format!(
                    "/api/v1/namespaces/{}/persistentvolumeclaims/{}",
                    c.namespace,
                    pvc_name(c.workspace_id)
                ),
            ),
            (
                "policy",
                format!(
                    "/apis/cilium.io/v2/namespaces/{}/ciliumnetworkpolicies/{}",
                    c.namespace,
                    network_policy_name(c.workspace_id)
                ),
            ),
            ("node", "/api/v1/nodes/kata-node".into()),
            (
                "volume",
                "/api/v1/persistentvolumes/workspace-volume".into(),
            ),
        ]
        .into_iter()
        .map(|(k, v)| (v, k.into()))
        .collect();
        let objects = self.objects.clone();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_clone = seen.clone();
        let pod_reads = Arc::new(Mutex::new(0));
        let service = tower::service_fn(move |req: Request<KubeBody>| {
            let method = req.method().clone();
            let path = req.uri().path().to_string();
            if let Ok(mut seen) = seen_clone.lock() {
                seen.push((method.clone(), path.clone()));
            }
            let body = paths.get(&path).and_then(|key| objects.get(key));
            let (status, mut data) = if method == Method::GET
                && let Some(body) = body
            {
                (200, body.clone())
            } else {
                (
                    404,
                    json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","message":"synthetic missing resource","code":404}),
                )
            };
            if method == Method::GET && path.contains("/pods/") {
                let mut reads = pod_reads
                    .lock()
                    .unwrap_or_else(|_| panic!("pod fixture lock"));
                *reads += 1;
                if *reads > 1
                    && let Some(node) = second_node
                {
                    data["spec"]["nodeName"] = json!(node);
                }
            }
            async move {
                let mut response = Response::new(Body::from(data.to_string()));
                *response.status_mut() = axum::http::StatusCode::from_u16(status)
                    .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
                response.headers_mut().insert(
                    "content-type",
                    axum::http::HeaderValue::from_static("application/json"),
                );
                Ok::<_, Infallible>(response)
            }
        });
        (
            GatewayRuntime::new(
                KubernetesRuntime::from_client(Client::new(service, "default")),
                self.config.clone(),
                "test-only-certification".into(),
            ),
            seen,
        )
    }
}

#[tokio::test]
async fn scheduled_verifier_pins_placement_across_resource_reads() -> anyhow::Result<()> {
    for initially_unassigned in [false, true] {
        let mut f = Fixture::new()?;
        if initially_unassigned {
            f.objects
                .get_mut("pod")
                .ok_or_else(|| anyhow::anyhow!("Pod fixture"))?["spec"]
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("Pod spec fixture"))?
                .remove("nodeName");
        }
        let (runtime, _) = f.runtime_with_node_change(Some("other-node"));
        assert!(
            runtime.verify(&f.context, &f.known).await.is_err(),
            "scheduled observation accepted a placement transition"
        );
    }
    Ok(())
}

#[tokio::test]
async fn verifies_current_runtime_with_fresh_gets_only() -> anyhow::Result<()> {
    let f = Fixture::new()?;
    let (runtime, seen) = f.runtime();
    for _ in 0..2 {
        let verified = runtime.verify(&f.context, &f.known).await?;
        assert_eq!(verified.identity.launch_id, f.context.launch_id);
        assert_eq!(verified.identity.runtime_generation, 7);
        assert_eq!(verified.identity.pod_uid, f.known.pod_uid);
        assert_eq!(verified.identity.cluster_epoch, f.context.cluster_epoch);
        assert_eq!(verified.namespace, f.context.namespace);
        assert_eq!(verified.pod_name, pod_name(f.context.workspace_id));
        assert_eq!(verified.container, container_name(f.context.launch_id));
    }
    let seen = seen
        .lock()
        .map_err(|_| anyhow::anyhow!("test request lock"))?;
    for path in [
        "/apis/node.k8s.io/v1/runtimeclasses/kata-qemu".to_owned(),
        format!(
            "/api/v1/namespaces/{}/pods/{}",
            f.context.namespace,
            pod_name(f.context.workspace_id)
        ),
    ] {
        assert_eq!(
            seen.iter()
                .filter(|(_, observed)| observed == &path)
                .count(),
            4,
            "each verify must read both before and after: {path}"
        );
    }
    assert!(
        seen.len() >= 28,
        "both calls must freshly observe all resources and guards"
    );
    assert!(seen.iter().all(|(m, _)| *m == Method::GET));
    Ok(())
}

#[tokio::test]
async fn rejects_replacement_drift_stale_readiness_and_fenced_nodes() -> anyhow::Result<()> {
    let attacks = [
        ("class", "/handler", json!("runc")),
        ("class", "/metadata/resourceVersion", json!("")),
        ("pod", "/metadata/resourceVersion", json!("")),
        ("pod", "/spec/overhead", json!({"cpu":"0.0001"})),
        (
            "pod",
            "/spec/overhead",
            json!({"cpu":"250m","memory":"160Mi"}),
        ),
        ("guard-binding", "/spec/validationActions", json!(["Warn"])),
        (
            "namespace",
            "/metadata/annotations/sandbox.platform~1certification-id",
            json!("other-cluster"),
        ),
        (
            "namespace",
            "/metadata/labels/sandbox.platform~1project-id",
            json!(Uuid::new_v4()),
        ),
        (
            "namespace",
            "/metadata/labels/sandbox.platform~1cluster-epoch",
            json!(Uuid::new_v4()),
        ),
        (
            "baseline",
            "/spec/podSelector",
            json!({"matchLabels":{"unrelated":"true"}}),
        ),
        (
            "baseline",
            "/spec",
            json!({"podSelector":{},"policyTypes":["Ingress","Egress"],"egress":[{}]}),
        ),
        ("policy", "/metadata/uid", json!(Uuid::new_v4())),
        ("policy", "/spec/egress", json!([{"toEntities":["world"]}])),
        ("pvc", "/metadata/uid", json!(Uuid::new_v4())),
        ("pvc", "/status/phase", json!("Pending")),
        ("volume", "/spec/claimRef/uid", json!(Uuid::new_v4())),
        ("volume", "/spec/claimRef/namespace", json!("other-project")),
        (
            "volume",
            "/spec/storageClassName",
            json!("unreviewed-class"),
        ),
        ("volume", "/spec/csi/volumeHandle", json!("")),
        ("pod", "/metadata/uid", json!(Uuid::new_v4())),
        (
            "pod",
            "/metadata/labels/sandbox.platform~1launch-id",
            json!(Uuid::new_v4()),
        ),
        (
            "pod",
            "/metadata/labels/sandbox.platform~1generation",
            json!("6"),
        ),
        ("pod", "/metadata/finalizers", json!([])),
        ("pod", "/spec/hostPID", json!(true)),
        ("pod", "/status/conditions/0/status", json!("False")),
        (
            "pod",
            "/status/containerStatuses/0/name",
            json!("workload-old-launch"),
        ),
        (
            "pod",
            "/status/containerStatuses/0/state",
            json!({"terminated":{"exitCode":0}}),
        ),
        (
            "node",
            "/metadata/labels/sandbox.platform~1worker-pool",
            json!("platform"),
        ),
        ("node", "/status/conditions/0/status", json!("Unknown")),
        (
            "node",
            "/spec",
            json!({"unschedulable":true,"taints":[{"key":"sandbox.platform/untrusted","value":"true","effect":"NoSchedule"}]}),
        ),
        ("node", "/spec/taints", json!([])),
        (
            "node",
            "/spec/taints",
            json!([{"key":"sandbox.platform/untrusted","value":"true","effect":"NoSchedule"},{"key":"node.kubernetes.io/out-of-service","effect":"NoExecute"}]),
        ),
    ];
    for (object, pointer, value) in attacks {
        let mut f = Fixture::new()?;
        let target = f
            .objects
            .get_mut(object)
            .ok_or_else(|| anyhow::anyhow!("fixture object missing {object}"))?;
        if object == "pod" && pointer == "/spec/overhead" {
            // The valid baseline has no overhead. These attacks add a new
            // field, while the other cases replace an existing JSON pointer.
            target["spec"]
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("fixture Pod spec missing"))?
                .insert("overhead".into(), value);
        } else {
            *target
                .pointer_mut(pointer)
                .ok_or_else(|| anyhow::anyhow!("fixture path missing {object}{pointer}"))? = value;
        }
        let (runtime, seen) = f.runtime();
        assert!(
            runtime.verify(&f.context, &f.known).await.is_err(),
            "accepted {object}{pointer}"
        );
        assert!(
            seen.lock()
                .map_err(|_| anyhow::anyhow!("test lock"))?
                .iter()
                .all(|(m, _)| *m == Method::GET)
        );
    }
    for object in [
        "class",
        "namespace",
        "baseline",
        "policy",
        "pvc",
        "volume",
        "pod",
        "node",
    ] {
        let mut f = Fixture::new()?;
        f.objects.remove(object);
        assert!(
            f.runtime().0.verify(&f.context, &f.known).await.is_err(),
            "missing {object} accepted"
        );
    }
    for object in [
        "class",
        "namespace",
        "baseline",
        "policy",
        "pvc",
        "volume",
        "pod",
        "node",
    ] {
        let mut f = Fixture::new()?;
        f.objects
            .get_mut(object)
            .ok_or_else(|| anyhow::anyhow!("test object"))?["metadata"]["deletionTimestamp"] =
            json!("2026-10-03T00:00:00Z");
        assert!(
            f.runtime().0.verify(&f.context, &f.known).await.is_err(),
            "terminating {object} accepted"
        );
    }
    Ok(())
}
