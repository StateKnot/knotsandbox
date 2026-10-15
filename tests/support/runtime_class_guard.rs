//! Reviewed Kubernetes transport responses, not live admission certification.
#![allow(
    dead_code,
    reason = "shared helper used by independent integration crates"
)]
use serde_json::{Value, json};

pub fn object(path: &str, overhead: Option<&Value>) -> Option<Value> {
    let contract: Value =
        serde_json::from_str(include_str!("../../deploy/runtime-class-guard/guard.json")).ok()?;
    let (mut value, uid) = match path {
        "/apis/node.k8s.io/v1/runtimeclasses/kata-qemu" => (
            json!({"apiVersion":"node.k8s.io/v1","kind":"RuntimeClass",
                "metadata":{"name":"kata-qemu"},"handler":"kata-qemu",
                "scheduling":{"nodeSelector":{"sandbox.platform/worker-pool":"kata"}}}),
            "00000000-0000-4000-8000-000000000101",
        ),
        "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/sandbox-kata-runtimeclass-v1" => {
            (
                contract["policy"].clone(),
                "00000000-0000-4000-8000-000000000102",
            )
        }
        "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/sandbox-kata-runtimeclass-v1" => {
            (
                contract["binding"].clone(),
                "00000000-0000-4000-8000-000000000103",
            )
        }
        _ => return None,
    };
    value["metadata"]["uid"] = json!(uid);
    value["metadata"]["resourceVersion"] = json!("fixture-opaque-rv");
    value["metadata"]["generation"] = json!(1);
    if value["kind"] == "RuntimeClass" {
        if let Some(overhead) = overhead {
            value["overhead"] = json!({"podFixed":overhead});
        }
    } else if value["kind"] == "ValidatingAdmissionPolicy" {
        value["status"] = json!({"observedGeneration":1,"typeChecking":{"expressionWarnings":[]}});
    }
    Some(value)
}

pub fn objects(overhead: Option<&Value>) -> std::collections::BTreeMap<String, Value> {
    [
        "/apis/node.k8s.io/v1/runtimeclasses/kata-qemu",
        "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/sandbox-kata-runtimeclass-v1",
        "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/sandbox-kata-runtimeclass-v1",
    ]
    .into_iter()
    .filter_map(|path| object(path, overhead).map(|value| (path.to_owned(), value)))
    .collect()
}
