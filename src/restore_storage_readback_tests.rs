//! The initial adoption boundary is checked before typed ObjectMeta can erase
//! fields. These tests confer no admission, ledger or vendor CSI certification.
#![allow(clippy::expect_used)]
use super::*;
use axum::{
    Router,
    body::Body,
    http::{Method, Request as HttpRequest, Response, StatusCode},
};
use std::sync::{Arc, Mutex};

fn expected() -> Value {
    json!({
        "apiVersion":"v1","kind":"PersistentVolumeClaim",
        "metadata":{"name":"sbx-bvol-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "namespace":NAMESPACE,
            "labels":{"sandbox.platform/restore-id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "app.kubernetes.io/managed-by":"sandbox-backup"}},
        "spec":{"accessModes":["ReadWriteOnce"],"volumeMode":"Block",
            "storageClassName":"sandbox-restore-raw","resources":{"requests":{"storage":"20Gi"}}}
    })
}
fn stored() -> Value {
    let mut body = expected();
    body["metadata"]["uid"] = json!("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    body["metadata"]["resourceVersion"] = json!("opaque-rv:123");
    body["metadata"]["creationTimestamp"] = json!("2026-10-08T10:00:00Z");
    body["metadata"]["finalizers"] = json!(["kubernetes.io/pvc-protection"]);
    body["status"] = json!({"phase":"Pending"});
    body
}
#[test]
fn initial_pending_readback_accepts_only_non_authorizing_bookkeeping() -> Result<(), RuntimeError> {
    let expected = expected();
    let mut actual = stored();
    validate_initial_pending_raw_pvc(&actual, &expected)?;
    actual["metadata"]["generation"] = json!(1);
    actual["metadata"]["managedFields"] = json!([{
        "manager":"sandbox-backup","operation":"Update","apiVersion":"v1",
        "time":"2026-10-08T10:00:00Z","fieldsType":"FieldsV1",
        "fieldsV1":{"f:spec":{"f:volumeMode":{}}}
    }]);
    actual["metadata"]["annotations"] = json!({});
    actual["metadata"]["ownerReferences"] = json!([]);
    validate_initial_pending_raw_pvc(&actual, &expected)?;
    for finalizers in [json!([]), json!(["kubernetes.io/pvc-protection"])] {
        actual["metadata"]["finalizers"] = finalizers;
        validate_initial_pending_raw_pvc(&actual, &expected)?;
    }
    actual["metadata"]
        .as_object_mut()
        .ok_or(RuntimeError::MissingIdentity)?
        .remove("finalizers");
    validate_initial_pending_raw_pvc(&actual, &expected)?;
    assert_eq!(
        expected,
        self::expected(),
        "validation cannot rewrite frozen intent"
    );
    Ok(())
}
#[test]
fn initial_pending_readback_rejects_all_behavioral_metadata_and_spec_drift() {
    let changes = [
        (
            "/metadata/annotations",
            json!({"volume.kubernetes.io/selected-node":"platform-node"}),
        ),
        (
            "/metadata/annotations",
            json!({"pv.kubernetes.io/bind-completed":"yes"}),
        ),
        (
            "/metadata/annotations",
            json!({"external.example/behavior":"yes"}),
        ),
        (
            "/metadata/finalizers",
            json!(["external.example/finalizer"]),
        ),
        (
            "/metadata/finalizers",
            json!(["kubernetes.io/pvc-protection", "external.example/finalizer"]),
        ),
        (
            "/metadata/finalizers",
            json!([
                "kubernetes.io/pvc-protection",
                "kubernetes.io/pvc-protection"
            ]),
        ),
        ("/metadata/finalizers", Value::Null),
        (
            "/metadata/ownerReferences",
            json!([{"uid":"cccccccc-cccc-4ccc-8ccc-cccccccccccc"}]),
        ),
        (
            "/metadata/uid",
            json!("BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB"),
        ),
        ("/metadata/uid", json!(Uuid::nil())),
        ("/metadata/uid", Value::Null),
        ("/metadata/resourceVersion", json!("")),
        ("/metadata/resourceVersion", json!("white space")),
        ("/metadata/resourceVersion", json!("x".repeat(129))),
        ("/metadata/resourceVersion", json!(1)),
        ("/metadata/creationTimestamp", json!("not-a-timestamp")),
        ("/metadata/generation", json!(-1)),
        ("/metadata/managedFields", json!([true])),
        ("/metadata/annotations", Value::Null),
        ("/metadata/ownerReferences", Value::Null),
        (
            "/metadata/labels",
            json!({"sandbox.platform/restore-id":"wrong"}),
        ),
        ("/status", json!({"phase":"Bound"})),
        ("/status", json!({"phase":"Pending","conditions":[]})),
        ("/status", json!({})),
        ("/status", Value::Null),
        ("/spec/volumeMode", json!("Filesystem")),
        ("/spec/storageClassName", json!("foreign")),
        ("/spec/resources/requests/storage", json!("30Gi")),
    ];
    let expected = expected();
    for (path, value) in changes {
        let mut actual = stored();
        // Add generation/managedFields before editing optional entries.
        actual["metadata"]["generation"] = json!(1);
        actual["metadata"]["managedFields"] = json!([]);
        actual["metadata"]["annotations"] = json!({});
        actual["metadata"]["ownerReferences"] = json!([]);
        *actual
            .pointer_mut(path)
            .expect("fixed existing fixture path") = value;
        assert!(
            validate_initial_pending_raw_pvc(&actual, &expected).is_err(),
            "accepted {path}"
        );
    }
    for (parent, key, value) in [
        ("/metadata", "unknown", json!({"behavior":true})),
        (
            "/metadata",
            "deletionTimestamp",
            json!("2026-10-08T10:00:01Z"),
        ),
        ("/metadata", "generateName", json!("sbx-")),
        ("/metadata/labels", "external.example/trust", json!("yes")),
        (
            "/spec",
            "volumeName",
            json!("disk-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
        ),
        (
            "/spec",
            "dataSource",
            json!({"kind":"PersistentVolumeClaim","name":"source"}),
        ),
        (
            "/spec",
            "dataSourceRef",
            json!({"kind":"PersistentVolumeClaim","name":"source"}),
        ),
        ("/spec", "volumeAttributesClassName", json!("external")),
        ("/spec", "unknown", json!(true)),
        ("", "unknown", json!(true)),
    ] {
        let mut actual = stored();
        actual
            .pointer_mut(parent)
            .and_then(Value::as_object_mut)
            .expect("fixed object fixture path")
            .insert(key.into(), value);
        assert!(
            validate_initial_pending_raw_pvc(&actual, &expected).is_err(),
            "accepted {parent}/{key}"
        );
    }
    for key in ["uid", "resourceVersion", "creationTimestamp"] {
        let mut actual = stored();
        actual["metadata"]
            .as_object_mut()
            .expect("fixed fixture metadata")
            .remove(key);
        assert!(
            validate_initial_pending_raw_pvc(&actual, &expected).is_err(),
            "accepted missing {key}"
        );
    }
}

#[tokio::test]
async fn fixed_pvc_get_retains_unknown_json_and_preserves_api_error_classification()
-> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let observed = Arc::new(Mutex::new(Vec::new()));
    let requests = observed.clone();
    let app = Router::new().fallback(move |request: HttpRequest<Body>| {
        let requests = requests.clone();
        async move {
            let path = request.uri().path().to_owned();
            requests
                .lock()
                .expect("fixture state")
                .push((request.method().clone(), path.clone()));
            let (code, body) = if path.ends_with("/missing") {
                (
                    StatusCode::NOT_FOUND,
                    json!({"apiVersion":"v1","kind":"Status", "status":"Failure",
                    "reason":"NotFound","message":"fixture missing","code":404}),
                )
            } else if path.ends_with("/unavailable") {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    json!({"apiVersion":"v1","kind":"Status", "status":"Failure",
                    "reason":"ServiceUnavailable","message":"fixture unavailable","code":503}),
                )
            } else {
                let mut body = stored();
                body["metadata"]["unknown"] = json!({"behavior":true});
                (StatusCode::OK, body)
            };
            let mut response = Response::new(Body::from(body.to_string()));
            *response.status_mut() = code;
            response.headers_mut().insert(
                "content-type",
                axum::http::HeaderValue::from_static("application/json"),
            );
            response
        }
    });
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = stopped.await;
            })
            .await
    });
    let result = async {
        let mut config = kube::Config::new(format!("http://{address}").parse()?);
        // This unit fixture isolates final API-error classification and three
        // exact GETs. The PG Raw-parent acceptance keeps the default retry
        // policy and separately exercises POST 503 -> retry 409 -> actual GETs.
        config.default_retry = false;
        let client = kube::Client::try_from(config)?;
        let runtime = BackupJobRuntime::new(crate::runtime::KubernetesRuntime::from_client(client));
        let name = expected()["metadata"]["name"]
            .as_str()
            .expect("fixed fixture name")
            .to_owned();
        let (raw, typed) = runtime
            .read_restore_raw_pvc(&name)
            .await?
            .ok_or(RuntimeError::MissingIdentity)?;
        assert_eq!(
            raw.pointer("/metadata/unknown"),
            Some(&json!({"behavior":true}))
        );
        assert_eq!(
            typed.metadata.uid.as_deref(),
            Some("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
        );
        assert!(validate_initial_pending_raw_pvc(&raw, &expected()).is_err());
        assert!(runtime.read_restore_raw_pvc("missing").await?.is_none());
        assert!(matches!(
            runtime.read_restore_raw_pvc("unavailable").await,
            Err(RuntimeError::Kubernetes(Some(503)))
        ));
        let actual = observed.lock().expect("fixture state").clone();
        assert_eq!(
            actual,
            [name.as_str(), "missing", "unavailable"].map(|name| {
                (
                    Method::GET,
                    format!("/api/v1/namespaces/{NAMESPACE}/persistentvolumeclaims/{name}"),
                )
            })
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let _ = stop.send(());
    let joined = tokio::time::timeout(std::time::Duration::from_secs(3), task).await;
    result?;
    joined???;
    Ok(())
}
