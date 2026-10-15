#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "support/runtime_class_guard.rs"]
mod runtime_class_guard;
use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Pod};
use sandbox_platform::runtime_manifest::{
    ManifestError, RuntimeManifestConfig, RuntimeManifestContext, TERMINATION_FINALIZER,
    build_manifests, container_name, pod_name, pvc_name, validate_existing_pod,
    validate_existing_policy, validate_existing_pvc,
};
use serde_json::{Value, json};
use uuid::Uuid;

#[tokio::test]
async fn all_flavors_preserve_equal_requests_and_limits_and_supported_ephemeral_storage()
-> anyhow::Result<()> {
    use axum::{
        body::Body,
        http::{Request, Response},
    };
    use kube::{Client, client::Body as KubeBody};
    use sandbox_platform::runtime::KubernetesRuntime;
    use std::convert::Infallible;

    for (cpu_millis, memory_mib, cpu_quantity, memory_quantity) in [
        (1000, 2048, "1", "2Gi"),
        (2000, 4096, "2", "4Gi"),
        (4000, 8192, "4", "8Gi"),
    ] {
        for (ephemeral_mib, ephemeral_quantity) in [(128, "128Mi"), (1024, "1Gi"), (32768, "32Gi")]
        {
            let mut context = context();
            context.cpu_millis = cpu_millis;
            context.memory_mib = memory_mib;
            let mut config = config();
            config.ephemeral_storage_mib = ephemeral_mib;
            config.tmp_size_mib = 64;
            let manifests = build_manifests(&context, &config)?;
            let mut observed = serde_json::to_value(observed_pod(&manifests.pod))?;
            let resources = json!({"cpu":cpu_quantity,"memory":memory_quantity,"ephemeral-storage":ephemeral_quantity});
            assert_eq!(
                observed["spec"]["containers"][0]["resources"],
                json!({"requests":resources,"limits":resources})
            );
            observed["spec"]["overhead"] = json!({"cpu":"0.250","memory":"512M"});
            let known_uid = observed["metadata"]["uid"].as_str().unwrap().to_owned();
            let service = tower::service_fn(move |request: Request<KubeBody>| {
                assert_eq!(request.method(), axum::http::Method::GET);
                let body = runtime_class_guard::object(
                    request.uri().path(),
                    Some(&observed["spec"]["overhead"]),
                )
                .unwrap_or_else(|| observed.clone())
                .to_string();
                async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(Body::from(body))
                            .unwrap(),
                    )
                }
            });
            let runtime = KubernetesRuntime::from_client(Client::new(service, "test"));
            let accepted = runtime.ensure_pod(&manifests, Some(&known_uid)).await?;
            assert_eq!(
                accepted.spec.unwrap().containers[0].resources,
                manifests.pod.spec.unwrap().containers[0].resources
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn invalid_provision_requests_are_rejected_before_any_kubernetes_request()
-> anyhow::Result<()> {
    use axum::{
        body::Body,
        http::{Request, Response},
    };
    use kube::{Client, client::Body as KubeBody};
    use sandbox_platform::runtime::KubernetesRuntime;
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    for case in [
        "negative",
        "precision",
        "overflow",
        "zero_memory",
        "unequal",
        "missing_requests",
        "missing_ephemeral",
        "gpu",
        "hugepages",
        "claims",
        "pod_claims",
        "pod_resources",
        "sidecar",
        "init",
        "ephemeral_container",
        "unsupported_ephemeral_unit",
    ] {
        let mut manifests = build_manifests(&context(), &config())?;
        let mut value = serde_json::to_value(&manifests.pod)?;
        match case {
            "negative" => {
                value["spec"]["containers"][0]["resources"]["requests"]["cpu"] = json!("-1")
            }
            "precision" => {
                value["spec"]["containers"][0]["resources"]["requests"]["cpu"] = json!("0.0001")
            }
            "overflow" => {
                value["spec"]["containers"][0]["resources"]["requests"]["memory"] =
                    json!("9223372036854775808")
            }
            "zero_memory" => {
                value["spec"]["containers"][0]["resources"]["requests"]["memory"] = json!("0")
            }
            "unequal" => value["spec"]["containers"][0]["resources"]["limits"]["cpu"] = json!("2"),
            "missing_requests" => {
                value["spec"]["containers"][0]["resources"]
                    .as_object_mut()
                    .unwrap()
                    .remove("requests");
            }
            "missing_ephemeral" => {
                value["spec"]["containers"][0]["resources"]["requests"]
                    .as_object_mut()
                    .unwrap()
                    .remove("ephemeral-storage");
            }
            "gpu" => {
                value["spec"]["containers"][0]["resources"]["requests"]["nvidia.com/gpu"] =
                    json!("1")
            }
            "hugepages" => {
                value["spec"]["containers"][0]["resources"]["limits"]["hugepages-2Mi"] =
                    json!("2Mi")
            }
            "claims" => {
                value["spec"]["containers"][0]["resources"]["claims"] = json!([{"name":"device"}])
            }
            "pod_claims" => {
                value["spec"]["resourceClaims"] =
                    json!([{"name":"device","resourceClaimName":"foreign"}])
            }
            "pod_resources" => {
                value["spec"]["resources"] = value["spec"]["containers"][0]["resources"].clone()
            }
            "sidecar" => {
                let extra = value["spec"]["containers"][0].clone();
                value["spec"]["containers"]
                    .as_array_mut()
                    .unwrap()
                    .push(extra);
            }
            "init" => {
                value["spec"]["initContainers"] = json!([value["spec"]["containers"][0].clone()])
            }
            "ephemeral_container" => {
                value["spec"]["ephemeralContainers"] = json!([{"name":"debug"}])
            }
            "unsupported_ephemeral_unit" => {
                value["spec"]["containers"][0]["resources"]["requests"]["ephemeral-storage"] =
                    json!("1.5Gi")
            }
            _ => unreachable!(),
        }
        manifests.pod = serde_json::from_value(value)?;
        let requests = Arc::new(AtomicUsize::new(0));
        let captured = requests.clone();
        let service = tower::service_fn(move |_: Request<KubeBody>| {
            captured.fetch_add(1, Ordering::SeqCst);
            async {
                Ok::<_, Infallible>(Response::builder().status(500).body(Body::empty()).unwrap())
            }
        });
        let runtime = KubernetesRuntime::from_client(Client::new(service, "test"));
        assert!(
            runtime.ensure_pod(&manifests, None).await.is_err(),
            "invalid provision request: {case}"
        );
        assert_eq!(
            requests.load(Ordering::SeqCst),
            0,
            "Kubernetes was contacted for {case}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_created_pod_with_unsupported_overhead_is_not_returned_as_a_valid_launch()
-> anyhow::Result<()> {
    use axum::{
        body::Body,
        http::{Method, Request, Response},
    };
    use kube::{Client, client::Body as KubeBody};
    use sandbox_platform::runtime::KubernetesRuntime;
    use std::{
        convert::Infallible,
        sync::{Arc, Mutex},
    };

    let manifests = build_manifests(&context(), &config())?;
    let mut created = serde_json::to_value(observed_pod(&manifests.pod))?;
    created["spec"]["overhead"] = json!({"cpu":"0.0001"});
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = requests.clone();
    let service = tower::service_fn(move |request: Request<KubeBody>| {
        let (status, body) = if let Some(value) =
            runtime_class_guard::object(request.uri().path(), None)
        {
            (200, value.to_string())
        } else {
            captured.lock().unwrap().push(request.method().clone());
            match *request.method() {
                Method::GET if captured.lock().unwrap().len() == 1 => (404, json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404,"message":"fixture absent"}).to_string()),
                Method::GET => (200, created.to_string()),
                Method::POST => (201, created.to_string()),
                _ => panic!("unexpected Kubernetes mutation"),
            }
        };
        async move {
            Ok::<_, Infallible>(
                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
        }
    });
    let runtime = KubernetesRuntime::from_client(Client::new(service, "test"));
    assert!(runtime.ensure_pod(&manifests, None).await.is_err());
    assert_eq!(*requests.lock().unwrap(), [Method::GET, Method::POST]);
    Ok(())
}

#[tokio::test]
async fn provisioning_rejects_request_plus_overhead_integer_overflow() -> anyhow::Result<()> {
    use axum::{
        body::Body,
        http::{Request, Response},
    };
    use kube::{Client, client::Body as KubeBody};
    use sandbox_platform::runtime::KubernetesRuntime;
    use std::convert::Infallible;

    for overhead in [
        json!({"memory":"9223372036854775807"}),
        json!({"cpu":"9223372036854775807m"}),
    ] {
        let manifests = build_manifests(&context(), &config())?;
        let mut observed = serde_json::to_value(observed_pod(&manifests.pod))?;
        observed["spec"]["overhead"] = overhead;
        let known_uid = observed["metadata"]["uid"].as_str().unwrap().to_owned();
        let service = tower::service_fn(move |request: Request<KubeBody>| {
            let body = runtime_class_guard::object(
                request.uri().path(),
                Some(&observed["spec"]["overhead"]),
            )
            .unwrap_or_else(|| observed.clone())
            .to_string();
            async move {
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
            }
        });
        let runtime = KubernetesRuntime::from_client(Client::new(service, "test"));
        assert!(
            runtime
                .ensure_pod(&manifests, Some(&known_uid))
                .await
                .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn provisioning_keeps_the_full_pod_comparison_strict_for_quantity_aliases()
-> anyhow::Result<()> {
    use axum::{
        body::Body,
        http::{Request, Response},
    };
    use kube::{Client, client::Body as KubeBody};
    use sandbox_platform::runtime::KubernetesRuntime;
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    let manifests = build_manifests(&context(), &config())?;
    let mut observed = serde_json::to_value(observed_pod(&manifests.pod))?;
    for field in ["requests", "limits"] {
        observed["spec"]["containers"][0]["resources"][field]["cpu"] = json!("1000m");
        observed["spec"]["containers"][0]["resources"][field]["memory"] = json!("2048Mi");
    }
    let known_uid = observed["metadata"]["uid"].as_str().unwrap().to_owned();
    let requests = Arc::new(AtomicUsize::new(0));
    let captured = requests.clone();
    let service = tower::service_fn(move |request: Request<KubeBody>| {
        let body = if let Some(value) = runtime_class_guard::object(request.uri().path(), None) {
            value.to_string()
        } else {
            captured.fetch_add(1, Ordering::SeqCst);
            observed.to_string()
        };
        async move {
            Ok::<_, Infallible>(
                Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
        }
    });
    let runtime = KubernetesRuntime::from_client(Client::new(service, "test"));
    assert!(
        runtime
            .ensure_pod(&manifests, Some(&known_uid))
            .await
            .is_err()
    );
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn provisioning_rejects_bad_overhead_but_safety_stop_still_targets_the_old_uid()
-> anyhow::Result<()> {
    use axum::{
        body::Body,
        http::{Method, Request, Response},
    };
    use kube::{Client, client::Body as KubeBody};
    use sandbox_platform::runtime::KubernetesRuntime;
    use std::{
        convert::Infallible,
        sync::{Arc, Mutex},
    };

    let manifests = build_manifests(&context(), &config())?;
    let mut observed = serde_json::to_value(observed_pod(&manifests.pod))?;
    observed["metadata"]["resourceVersion"] = json!("fixture-version");
    observed["spec"]["overhead"] = json!({"cpu":"-250m","memory":"160Mi"});
    let known_uid = observed["metadata"]["uid"].as_str().unwrap().to_owned();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = requests.clone();
    let service = tower::service_fn(move |request: Request<KubeBody>| {
        let body = if let Some(value) = runtime_class_guard::object(request.uri().path(), None) {
            value.to_string()
        } else {
            captured.lock().unwrap().push(request.method().clone());
            observed.to_string()
        };
        async move {
            Ok::<_, Infallible>(
                Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
        }
    });
    let runtime = KubernetesRuntime::from_client(Client::new(service, "test"));
    assert!(
        runtime
            .ensure_pod(&manifests, Some(&known_uid))
            .await
            .is_err()
    );
    assert!(runtime.find_stop_target(&manifests.pod).await?.is_some());
    assert!(
        runtime
            .request_stop(&manifests.pod, &known_uid)
            .await?
            .is_some()
    );
    assert_eq!(
        *requests.lock().unwrap(),
        [Method::GET, Method::GET, Method::GET, Method::DELETE]
    );
    Ok(())
}

#[test]
fn maximum_workspace_keeps_the_kubernetes_canonical_tib_quantity() {
    let mut ctx = context();
    ctx.workspace_size_gib = 1024;
    ctx.workspace_snapshot = Some(format!("sbx-rs-{}", Uuid::new_v4()));
    let expected = build_manifests(&ctx, &config()).unwrap().pvc;
    let mut canonical = serde_json::to_value(&expected).unwrap();
    assert_eq!(canonical["spec"]["resources"]["requests"]["storage"], "1Ti");
    let uid = Uuid::new_v4().to_string();
    canonical["metadata"]["uid"] = json!(uid);
    canonical["spec"]["volumeName"] = json!("delivered-tib-pv");
    canonical["spec"]["dataSourceRef"] = canonical["spec"]["dataSource"].clone();
    let received: PersistentVolumeClaim = serde_json::from_value(canonical).unwrap();
    validate_existing_pvc(&received, &expected, Some(&uid)).unwrap();
}

#[test]
fn restored_workspace_datasource_stays_fixed_across_launches_and_aliases() {
    let mut ctx = context();
    let snapshot = format!("sbx-rs-{}", Uuid::new_v4());
    ctx.workspace_snapshot = Some(snapshot.clone());
    let expected = build_manifests(&ctx, &config()).unwrap().pvc;
    let mut observed = serde_json::to_value(&expected).unwrap();
    let uid = Uuid::new_v4().to_string();
    observed["metadata"]["uid"] = json!(uid);
    observed["spec"]["volumeName"] = json!("bound-restored-volume");
    observed["spec"]["dataSourceRef"] = observed["spec"]["dataSource"].clone();
    let pvc: PersistentVolumeClaim = serde_json::from_value(observed.clone()).unwrap();
    assert!(validate_existing_pvc(&pvc, &expected, Some(&uid)).is_ok());
    ctx.generation += 1;
    ctx.launch_id = Uuid::new_v4();
    assert_eq!(build_manifests(&ctx, &config()).unwrap().pvc, expected);
    for (field, wrong) in [
        ("name", json!(format!("sbx-rs-{}", Uuid::new_v4()))),
        ("namespace", json!("foreign-project")),
        ("kind", json!("PersistentVolumeClaim")),
    ] {
        let mut changed = observed.clone();
        changed["spec"]["dataSourceRef"][field] = wrong;
        let changed: PersistentVolumeClaim = serde_json::from_value(changed).unwrap();
        assert!(validate_existing_pvc(&changed, &expected, Some(&uid)).is_err());
    }
    let mut empty = ctx;
    empty.workspace_snapshot = None;
    assert!(
        validate_existing_pvc(
            &pvc,
            &build_manifests(&empty, &config()).unwrap().pvc,
            Some(&uid)
        )
        .is_err()
    );
}

#[test]
fn restore_datasource_rejects_unmanaged_names_and_noncanonical_uuids() {
    for invalid in [
        "arbitrary-snapshot".to_owned(),
        format!("sbx-rs-{}", Uuid::nil()),
        format!("sbx-rs-{}", Uuid::new_v4().simple()),
        "../foreign/snapshot".to_owned(),
    ] {
        let mut ctx = context();
        ctx.workspace_snapshot = Some(invalid);
        assert!(matches!(
            build_manifests(&ctx, &config()),
            Err(ManifestError::InvalidConfiguration(_))
        ));
    }
}

fn context() -> RuntimeManifestContext {
    RuntimeManifestContext {
        tenant_id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        instance_id: Uuid::new_v4(),
        workspace_id: Uuid::new_v4(),
        launch_id: Uuid::new_v4(),
        cluster_epoch: Uuid::new_v4(),
        generation: 1,
        namespace: "sandbox-project-one".to_owned(),
        storage_class: "encrypted-rwo".to_owned(),
        workspace_snapshot: None,
        image_ref: "registry.example.test/sandbox/python".to_owned(),
        image_digest: format!("sha256:{}", "a".repeat(64)),
        template_approved: true,
        security_policy_approved: true,
        security_policy_rules: json!({"profile":"deny-all","dns":true}),
        cpu_millis: 1000,
        memory_mib: 2048,
        workspace_size_gib: 20,
    }
}

fn config() -> RuntimeManifestConfig {
    RuntimeManifestConfig {
        runtime_class_name: "kata-qemu".to_owned(),
        dns_namespace: "kube-system".to_owned(),
        dns_labels: BTreeMap::from([("k8s-app".to_owned(), "kube-dns".to_owned())]),
        ephemeral_storage_mib: 1024,
        tmp_size_mib: 256,
    }
}

fn observed_pod(pod: &Pod) -> Pod {
    let mut existing = pod.clone();
    existing.metadata.uid = Some(Uuid::new_v4().to_string());
    existing.metadata.resource_version = Some("pod-fixture-rv".into());
    existing
}

#[tokio::test]
async fn actual_pod_readback_rejects_resource_identity_and_guard_races() -> anyhow::Result<()> {
    use axum::{
        body::Body,
        http::{Request, Response},
    };
    use kube::{Client, client::Body as KubeBody};
    use sandbox_platform::runtime::KubernetesRuntime;
    use std::{
        convert::Infallible,
        sync::{Arc, Mutex},
    };

    for case in [
        "stable",
        "status_rv_only",
        "initial_scheduling",
        "class_uid",
        "class_overhead",
        "class_scheduling",
        "policy_uid",
        "binding_uid",
        "pod_uid",
        "pod_overhead",
        "pod_resources",
        "pod_node",
        "pod_spec",
        "pod_invalid_rv",
        "pod_missing_rv",
        "pod_large_rv",
        "pod_missing_overhead",
        "pod_mismatched_overhead",
    ] {
        let manifests = build_manifests(&context(), &config())?;
        let mut pod = serde_json::to_value(observed_pod(&manifests.pod))?;
        pod["spec"]["nodeName"] = json!("kata-node");
        if case == "initial_scheduling" {
            pod["spec"].as_object_mut().unwrap().remove("nodeName");
        }
        // The actual Pod source may use a different supported quantity spelling
        // for overhead, which is compared numerically to the separate Class.
        pod["spec"]["overhead"] = json!({"cpu":"0.25","memory":"167772160"});
        if case == "pod_missing_overhead" {
            pod["spec"].as_object_mut().unwrap().remove("overhead");
        } else if case == "pod_mismatched_overhead" {
            pod["spec"]["overhead"]["cpu"] = json!("251m");
        }
        let known_uid = pod["metadata"]["uid"].as_str().unwrap().to_owned();
        let calls = Arc::new(Mutex::new(BTreeMap::<String, usize>::new()));
        let seen = calls.clone();
        let service = tower::service_fn(move |request: Request<KubeBody>| {
            assert_eq!(request.method(), axum::http::Method::GET);
            let path = request.uri().path();
            let count = {
                let mut calls = calls.lock().unwrap();
                let count = calls.entry(path.to_owned()).or_default();
                *count += 1;
                *count
            };
            let mut value =
                runtime_class_guard::object(path, Some(&json!({"cpu":"250m","memory":"160Mi"})))
                    .unwrap_or_else(|| pod.clone());
            if count > 1 {
                match (value["kind"].as_str(), case) {
                    (Some("RuntimeClass"), "class_uid")
                    | (Some("ValidatingAdmissionPolicy"), "policy_uid")
                    | (Some("ValidatingAdmissionPolicyBinding"), "binding_uid")
                    | (Some("Pod"), "pod_uid") => value["metadata"]["uid"] = json!(Uuid::new_v4()),
                    (Some("RuntimeClass"), "class_overhead") => {
                        value["overhead"]["podFixed"]["cpu"] = json!("251m")
                    }
                    (Some("RuntimeClass"), "class_scheduling") => {
                        value["scheduling"]["nodeSelector"]["another-selector"] = json!("changed")
                    }
                    (Some("Pod"), "pod_overhead") => {
                        value["spec"]["overhead"]["cpu"] = json!("251m")
                    }
                    (Some("Pod"), "pod_resources") => {
                        value["spec"]["containers"][0]["resources"]["limits"]["cpu"] = json!("2")
                    }
                    (Some("Pod"), "pod_node") => value["spec"]["nodeName"] = json!("other-node"),
                    (Some("Pod"), "initial_scheduling") => {
                        value["spec"]["nodeName"] = json!("kata-node")
                    }
                    (Some("Pod"), "pod_spec") => value["spec"]["hostPID"] = json!(true),
                    (Some("Pod"), "pod_invalid_rv") => {
                        value["metadata"]["resourceVersion"] = json!("contains space")
                    }
                    (Some("Pod"), "pod_missing_rv") => {
                        value["metadata"]
                            .as_object_mut()
                            .unwrap()
                            .remove("resourceVersion");
                    }
                    (Some("Pod"), "pod_large_rv") => {
                        value["metadata"]["resourceVersion"] = json!("x".repeat(257))
                    }
                    (_, "status_rv_only") => {
                        value["metadata"]["resourceVersion"] = json!("opaque:revision-2");
                        if value["kind"] == "Pod" {
                            value["status"] = json!({"phase":"Running"});
                        }
                    }
                    _ => {}
                }
            }
            std::future::ready(Ok::<_, Infallible>(
                Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(Body::from(value.to_string()))
                    .unwrap(),
            ))
        });
        let runtime = KubernetesRuntime::from_client(Client::new(service, "test"));
        let result = runtime.ensure_pod(&manifests, Some(&known_uid)).await;
        assert_eq!(
            result.is_ok(),
            matches!(case, "stable" | "status_rv_only" | "initial_scheduling"),
            "case {case}: {result:?}"
        );
        if matches!(case, "stable" | "status_rv_only" | "initial_scheduling") {
            let calls = seen.lock().unwrap();
            assert_eq!(
                calls
                    .iter()
                    .find(|(path, _)| path.contains("/pods/"))
                    .map(|(_, n)| *n),
                Some(2)
            );
            assert_eq!(calls["/apis/node.k8s.io/v1/runtimeclasses/kata-qemu"], 2);
        }
    }
    Ok(())
}

#[tokio::test]
async fn created_pod_requires_an_independent_exact_uid_get() -> anyhow::Result<()> {
    use axum::{
        body::Body,
        http::{Method, Request, Response},
    };
    use kube::{Client, client::Body as KubeBody};
    use sandbox_platform::runtime::KubernetesRuntime;
    use std::{
        convert::Infallible,
        sync::{Arc, Mutex},
    };

    for case in ["stable", "replaced", "first_scheduling"] {
        let manifests = build_manifests(&context(), &config())?;
        let pod = serde_json::to_value(observed_pod(&manifests.pod))?;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = calls.clone();
        let service = tower::service_fn(move |request: Request<KubeBody>| {
            let (status, value) = if let Some(value) =
                runtime_class_guard::object(request.uri().path(), None)
            {
                (200, value)
            } else {
                let mut calls = calls.lock().unwrap();
                calls.push(request.method().clone());
                if calls.len() == 1 {
                    (
                        404,
                        json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404,"message":"absent"}),
                    )
                } else if request.method() == Method::POST {
                    (201, pod.clone())
                } else {
                    let mut readback = pod.clone();
                    if case == "replaced" {
                        readback["metadata"]["uid"] = json!(Uuid::new_v4());
                    } else if case == "first_scheduling" {
                        readback["spec"]["nodeName"] = json!("kata-node");
                    }
                    (200, readback)
                }
            };
            std::future::ready(Ok::<_, Infallible>(
                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(Body::from(value.to_string()))
                    .unwrap(),
            ))
        });
        let runtime = KubernetesRuntime::from_client(Client::new(service, "test"));
        let result = runtime.ensure_pod(&manifests, None).await;
        assert_eq!(
            result.is_ok(),
            case != "replaced",
            "case={case}: {result:?}"
        );
        let calls = seen.lock().unwrap();
        assert_eq!(&calls[..3], [Method::GET, Method::POST, Method::GET]);
        assert_eq!(calls.len(), if case == "replaced" { 3 } else { 4 });
    }
    Ok(())
}

fn mutate_pod(pod: &Pod, mutate: impl FnOnce(&mut Value)) -> Pod {
    let mut value = serde_json::to_value(observed_pod(pod)).unwrap();
    mutate(&mut value);
    serde_json::from_value(value).unwrap()
}

#[test]
fn generated_workload_has_a_fixed_safe_entrypoint_and_no_host_access() {
    let ctx = context();
    let manifests = build_manifests(&ctx, &config()).unwrap();
    let pod = serde_json::to_value(&manifests.pod).unwrap();
    let spec = &pod["spec"];
    assert_eq!(pod["metadata"]["name"], pod_name(ctx.workspace_id));
    assert_eq!(spec["runtimeClassName"], "kata-qemu");
    assert!(spec.get("nodeName").is_none());
    assert_eq!(spec["hostNetwork"], false);
    assert_eq!(spec["hostPID"], false);
    assert_eq!(spec["hostIPC"], false);
    assert_eq!(spec["automountServiceAccountToken"], false);
    assert_eq!(spec["enableServiceLinks"], false);
    assert_eq!(spec["restartPolicy"], "Never");
    assert_eq!(spec["containers"].as_array().unwrap().len(), 1);
    let workload = &spec["containers"][0];
    assert_eq!(workload["name"], container_name(ctx.launch_id));
    assert_eq!(
        workload["command"],
        json!(["/usr/local/bin/sandbox-runner", "idle"])
    );
    assert_eq!(
        workload["readinessProbe"]["exec"]["command"],
        json!(["/usr/local/bin/sandbox-runner", "health"])
    );
    assert_eq!(workload["securityContext"]["readOnlyRootFilesystem"], true);
    assert_eq!(
        workload["securityContext"]["allowPrivilegeEscalation"],
        false
    );
    assert_eq!(
        workload["securityContext"]["capabilities"]["drop"],
        json!(["ALL"])
    );
    assert_eq!(
        workload["resources"]["limits"],
        workload["resources"]["requests"]
    );
    assert_eq!(workload["resources"]["limits"]["cpu"], "1");
    assert_eq!(workload["resources"]["limits"]["memory"], "2Gi");
    assert_eq!(
        spec["volumes"][0]["persistentVolumeClaim"]["claimName"],
        pvc_name(ctx.workspace_id)
    );
    assert_eq!(
        pod["metadata"]["finalizers"],
        json!([TERMINATION_FINALIZER])
    );
    assert!(manifests.pvc.metadata.owner_references.is_none());
}

#[test]
fn only_approved_digest_pinned_images_and_exact_supported_policy_are_accepted() {
    let ctx = context();
    for image in [
        "python:latest",
        "https://registry.example.test/python",
        "registry.example.test/python@sha256:deadbeef",
        "registry.example.test/bad name",
    ] {
        let changed = RuntimeManifestContext {
            image_ref: image.to_owned(),
            ..ctx.clone()
        };
        assert!(matches!(
            build_manifests(&changed, &config()),
            Err(ManifestError::InvalidImage)
        ));
    }
    let changed = RuntimeManifestContext {
        image_digest: "sha256:abcd".to_owned(),
        ..ctx.clone()
    };
    assert!(matches!(
        build_manifests(&changed, &config()),
        Err(ManifestError::InvalidImage)
    ));
    let changed = RuntimeManifestContext {
        template_approved: false,
        ..ctx.clone()
    };
    assert!(matches!(
        build_manifests(&changed, &config()),
        Err(ManifestError::ApprovalRequired)
    ));
    let changed = RuntimeManifestContext {
        security_policy_rules: json!({"profile":"allow-all","dns":true}),
        ..ctx
    };
    assert!(matches!(
        build_manifests(&changed, &config()),
        Err(ManifestError::InvalidConfiguration(_))
    ));
}

#[test]
fn configuration_cannot_fall_back_to_runc_or_an_unbounded_dns_selector() {
    let ctx = context();
    for runtime in ["runc", "", "kata-unverified"] {
        let changed = RuntimeManifestConfig {
            runtime_class_name: runtime.to_owned(),
            ..config()
        };
        assert!(build_manifests(&ctx, &changed).is_err());
    }
    let changed = RuntimeManifestConfig {
        dns_labels: BTreeMap::new(),
        ..config()
    };
    assert!(build_manifests(&ctx, &changed).is_err());
    let changed = RuntimeManifestConfig {
        tmp_size_mib: 1024,
        ..config()
    };
    assert!(build_manifests(&ctx, &changed).is_err());
    let changed = RuntimeManifestContext {
        namespace: "../../default".to_owned(),
        ..ctx
    };
    assert!(build_manifests(&changed, &config()).is_err());
}

#[test]
fn adoption_requires_all_identity_labels_and_the_recorded_uid() {
    let ctx = context();
    let expected = build_manifests(&ctx, &config()).unwrap().pod;
    let existing = observed_pod(&expected);
    assert_eq!(
        validate_existing_pod(&existing, &expected, existing.metadata.uid.as_deref()),
        Ok(())
    );
    assert!(matches!(
        validate_existing_pod(&existing, &expected, Some("different-uid")),
        Err(ManifestError::OwnershipMismatch("UID"))
    ));
    assert!(validate_existing_pod(&expected, &expected, None).is_err());
    for key in [
        "tenant-id",
        "project-id",
        "instance-id",
        "workspace-id",
        "launch-id",
        "cluster-epoch",
        "generation",
    ] {
        let mut changed = existing.clone();
        changed
            .metadata
            .labels
            .as_mut()
            .unwrap()
            .remove(&format!("sandbox.platform/{key}"));
        assert!(matches!(
            validate_existing_pod(&changed, &expected, None),
            Err(ManifestError::OwnershipMismatch(_))
        ));
    }
    let mut changed = existing;
    changed.metadata.finalizers = None;
    assert!(matches!(
        validate_existing_pod(&changed, &expected, None),
        Err(ManifestError::SpecificationDrift(_))
    ));
}

#[test]
fn runtime_privilege_network_and_volume_drift_is_rejected() {
    let expected = build_manifests(&context(), &config()).unwrap().pod;
    let changes: Vec<fn(&mut Value)> = vec![
        |pod| pod["spec"]["hostNetwork"] = json!(true),
        |pod| pod["spec"]["runtimeClassName"] = json!("runc"),
        |pod| pod["spec"]["automountServiceAccountToken"] = json!(true),
        |pod| pod["spec"]["containers"][0]["securityContext"]["privileged"] = json!(true),
        |pod| {
            pod["spec"]["containers"][0]["securityContext"]["allowPrivilegeEscalation"] =
                json!(true)
        },
        |pod| pod["spec"]["containers"][0]["resources"]["limits"]["nvidia.com/gpu"] = json!("1"),
        |pod| pod["spec"]["containers"][0]["command"] = json!(["/workspace/bootstrap.sh"]),
        |pod| pod["spec"]["volumes"][0] = json!({"name":"workspace","hostPath":{"path":"/"}}),
        |pod| pod["spec"]["initContainers"] = json!([{"name":"injected","image":"busybox"}]),
        |pod| {
            pod["spec"]["containers"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name":"sidecar","image":"busybox"}))
        },
        |pod| {
            pod["metadata"]["annotations"] =
                json!({"io.katacontainers.config.hypervisor.disable_block_device_use":"true"})
        },
        |pod| pod["metadata"]["annotations"] = json!({"k8s.v1.cni.cncf.io/networks":"host-bypass"}),
    ];
    for change in changes {
        let existing = mutate_pod(&expected, change);
        assert!(validate_existing_pod(&existing, &expected, None).is_err());
    }
}

#[test]
fn documented_api_defaults_are_accepted_but_dangerous_omissions_are_not() {
    let expected = build_manifests(&context(), &config()).unwrap().pod;
    let existing = mutate_pod(&expected, |pod| {
        let spec = pod["spec"].as_object_mut().unwrap();
        for field in ["hostNetwork", "hostPID", "hostIPC"] {
            spec.remove(field);
        }
        spec.insert("serviceAccount".to_owned(), json!("sandbox-workload"));
        spec.insert("nodeName".to_owned(), json!("certified-kata-worker-one"));
        spec.insert("priority".to_owned(), json!(0));
        spec.insert(
            "overhead".to_owned(),
            json!({"cpu":"250m","memory":"160Mi"}),
        );
        let container = spec["containers"][0].as_object_mut().unwrap();
        container.remove("stdin");
        container.remove("tty");
        for mount in container["volumeMounts"].as_array_mut().unwrap() {
            mount.as_object_mut().unwrap().remove("readOnly");
        }
        spec["volumes"][0]["persistentVolumeClaim"]
            .as_object_mut()
            .unwrap()
            .remove("readOnly");
    });
    assert_eq!(validate_existing_pod(&existing, &expected, None), Ok(()));
    let missing_token_guard = mutate_pod(&expected, |pod| {
        pod["spec"]
            .as_object_mut()
            .unwrap()
            .remove("automountServiceAccountToken");
    });
    assert!(validate_existing_pod(&missing_token_guard, &expected, None).is_err());
    let missing_escalation_guard = mutate_pod(&expected, |pod| {
        pod["spec"]["containers"][0]["securityContext"]
            .as_object_mut()
            .unwrap()
            .remove("allowPrivilegeEscalation");
    });
    assert!(validate_existing_pod(&missing_escalation_guard, &expected, None).is_err());
}

#[test]
fn workspace_and_network_boundary_survive_launch_rotation() {
    let ctx = context();
    let first = build_manifests(&ctx, &config()).unwrap();
    let next_ctx = RuntimeManifestContext {
        launch_id: Uuid::new_v4(),
        cluster_epoch: Uuid::new_v4(),
        generation: 2,
        ..ctx
    };
    let next = build_manifests(&next_ctx, &config()).unwrap();
    assert_eq!(first.pvc, next.pvc);
    assert_eq!(
        serde_json::to_value(&first.network_policy).unwrap(),
        serde_json::to_value(&next.network_policy).unwrap()
    );
    assert_ne!(first.pod.spec, next.pod.spec);
    assert_eq!(first.pod.metadata.name, next.pod.metadata.name);
    assert!(matches!(
        validate_existing_pod(&observed_pod(&first.pod), &next.pod, None),
        Err(ManifestError::OwnershipMismatch(_))
    ));
}

#[test]
fn bound_volume_must_keep_its_owner_storage_class_and_size() {
    let expected = build_manifests(&context(), &config()).unwrap().pvc;
    let mut value = serde_json::to_value(&expected).unwrap();
    value["metadata"]["uid"] = json!(Uuid::new_v4().to_string());
    value["spec"]["volumeName"] = json!("pvc-server-assigned-identity");
    let existing: PersistentVolumeClaim = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(validate_existing_pvc(&existing, &expected, None), Ok(()));
    value["spec"]["storageClassName"] = json!("unencrypted-fast-disk");
    let changed = serde_json::from_value(value).unwrap();
    assert!(validate_existing_pvc(&changed, &expected, None).is_err());
}

#[test]
fn network_policy_allows_only_exact_dns_endpoints_and_no_ingress() {
    let expected = build_manifests(&context(), &config())
        .unwrap()
        .network_policy;
    let spec = &expected.data["spec"];
    assert_eq!(spec["ingress"], json!([]));
    assert_eq!(
        spec["enableDefaultDeny"],
        json!({"ingress":true,"egress":true})
    );
    assert_eq!(spec["egress"].as_array().unwrap().len(), 1);
    assert_eq!(
        spec["egress"][0]["toEndpoints"][0]["matchLabels"],
        json!({"k8s:io.kubernetes.pod.namespace":"kube-system","k8s:k8s-app":"kube-dns"})
    );
    let mut existing = expected.clone();
    existing.metadata.uid = Some(Uuid::new_v4().to_string());
    existing.data["status"] = json!({"nodes":{}});
    assert_eq!(validate_existing_policy(&existing, &expected, None), Ok(()));
    existing.data["spec"]["egress"] = json!([{"toEntities":["world"]}]);
    assert!(validate_existing_policy(&existing, &expected, None).is_err());
}

#[test]
fn network_policy_rejects_additive_specs_even_when_approved_spec_is_unchanged() {
    let expected = build_manifests(&context(), &config())
        .unwrap()
        .network_policy;
    let uid = Uuid::new_v4().to_string();
    // Cilium's pinned CRD accepts spec OR specs (not an exclusive choice).
    // Extra rules union with the approved DNS-only policy, so checking spec
    // alone would authorize this unrestricted world egress.
    for extra in [
        json!([{
            "endpointSelector": expected.data["spec"]["endpointSelector"],
            "egress": [{"toEntities": ["world"]}]
        }]),
        json!([]),
        serde_json::Value::Null,
    ] {
        let mut existing = expected.clone();
        existing.metadata.uid = Some(uid.clone());
        existing.data["status"] = json!({"nodes":{}});
        existing.data["specs"] = extra;
        assert_eq!(existing.data["spec"], expected.data["spec"]);
        assert!(validate_existing_policy(&existing, &expected, Some(&uid)).is_err());
    }
}
