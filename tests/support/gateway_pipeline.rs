//! Real PG + real local HTTP/WebSocket transport + native OSS signed-request
//! mock. This verifies the gateway composition, not cloud or VM certification.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::{Dispatched, support};
use anyhow::{Context, ensure};
use axum::{
    Router,
    body::Body,
    extract::{
        FromRequestParts, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{Request, Response, StatusCode},
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use futures_util::SinkExt;
use opendal::{Buffer, HttpBody, HttpTransport, HttpTransporter};
use sandbox_platform::{
    gateway::Gateway,
    output_store::{OssOutputConfig, OssOutputReader, OssOutputStore},
    runtime::KubernetesRuntime,
    runtime_manifest::{
        RuntimeManifestConfig, RuntimeManifestContext, build_manifests, container_name,
        network_policy_name, pod_name, pvc_name,
    },
};
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Clone, Copy)]
enum Scenario {
    Normal,
    Truncated,
    Disconnected,
    OutputFailure,
}
#[derive(Clone)]
struct KubeServer {
    owner: PgPool,
    tenant: Uuid,
    execution: Uuid,
    container: String,
    objects: Arc<BTreeMap<String, Value>>,
    connects: Arc<AtomicUsize>,
    scenario: Scenario,
}
async fn kube_request(
    State(state): State<KubeServer>,
    request: Request<Body>,
) -> axum::response::Response {
    if request.uri().path().ends_with("/exec") {
        let pairs: Vec<_> =
            url::form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes())
                .into_owned()
                .collect();
        let commands: Vec<_> = pairs
            .iter()
            .filter(|(k, _)| k == "command")
            .map(|(_, v)| v.as_str())
            .collect();
        let get = |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };
        if commands.len() != 6
            || commands[0] != "/usr/local/bin/sandbox-runner"
            || commands[1] != "exec"
            || commands[2] != "--execution-id"
            || commands[3] != state.execution.to_string()
            || commands[4] != "--dispatch-attempt-id"
            || get("container") != Some(&state.container)
            || get("stdin") != Some("true")
            || get("stdout") != Some("true")
            || get("stderr") != Some("true")
            || get("tty") == Some("true")
        {
            return StatusCode::FORBIDDEN.into_response();
        }
        let Ok(attempt) = Uuid::parse_str(commands[5]) else {
            return StatusCode::FORBIDDEN.into_response();
        };
        let admitted: bool =
            sqlx::query_scalar("SELECT sandbox_admit_execution_connect($1,$2,$3,$4)")
                .bind(state.tenant)
                .bind(state.execution)
                .bind(attempt)
                .bind(Uuid::new_v4())
                .fetch_one(&state.owner)
                .await
                .unwrap_or(false);
        if !admitted {
            return StatusCode::FORBIDDEN.into_response();
        }
        state.connects.fetch_add(1, Ordering::SeqCst);
        let (mut parts, _) = request.into_parts();
        let Ok(upgrade) = WebSocketUpgrade::from_request_parts(&mut parts, &()).await else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        return upgrade
            .protocols(["v5.channel.k8s.io"])
            .on_upgrade(move |socket| guest(socket, state))
            .into_response();
    }
    if let Some(object) = state.objects.get(request.uri().path()) {
        return axum::Json(object).into_response();
    }
    StatusCode::NOT_FOUND.into_response()
}
async fn guest(mut socket: WebSocket, state: KubeServer) {
    let mut input = Vec::new();
    while let Some(Ok(Message::Binary(data))) = socket.recv().await {
        if data.as_ref() == [255, 0] {
            break;
        }
        assert_eq!(data.first(), Some(&0));
        input.extend_from_slice(&data[1..]);
        assert!(input.len() <= 65536);
    }
    let request: Value = serde_json::from_slice(&input).unwrap();
    assert_eq!(request["execution_id"], json!(state.execution));
    assert_eq!(request["argv"], json!(["/usr/bin/true"]));
    let limit = request["output_limit_bytes"].as_u64().unwrap() as usize;
    let observed = b"hello";
    let output = &observed[..observed.len().min(limit)];
    let truncated = output.len() < observed.len();
    let mut frames = vec![
        json!({"protocol_version":1,"execution_id":state.execution,"sequence":0,"type":"started","pid":42}),
    ];
    if !output.is_empty() {
        frames.push(json!({"protocol_version":1,"execution_id":state.execution,"sequence":1,"type":"output","stream":"stdout","data":STANDARD.encode(output)}));
    }
    for frame in &frames {
        let mut data = vec![1];
        data.extend(serde_json::to_vec(frame).unwrap());
        data.push(b'\n');
        if socket.send(Message::Binary(data.into())).await.is_err() {
            return;
        }
    }
    if matches!(state.scenario, Scenario::Disconnected) {
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let _ = socket.close().await;
        return;
    }
    let terminal = json!({"protocol_version":1,"execution_id":state.execution,"sequence":frames.len(),"type":"exited","exit_code":0,"signal":null,"timed_out":false,"cancelled":false,"output_complete":!truncated,"output_truncated":truncated,"bytes_observed":observed.len(),"bytes_emitted":output.len(),"termination_confirmed":false});
    let mut data = vec![1];
    data.extend(serde_json::to_vec(&terminal).unwrap());
    data.push(b'\n');
    if socket.send(Message::Binary(data.into())).await.is_err() {
        return;
    }
    let mut status = vec![3];
    status.extend_from_slice(br#"{"status":"Success"}"#);
    let _ = socket.send(Message::Binary(status.into())).await;
    let _ = socket.close().await;
}

#[derive(Clone, Default)]
struct OutputMock {
    objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    fail: bool,
    revoke: Option<(PgPool, Uuid, Uuid)>,
}
impl HttpTransport for OutputMock {
    async fn fetch(&self, req: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
        assert!(req.headers().contains_key("authorization"));
        assert!(req.headers().contains_key("x-oss-security-token"));
        if req.method() != "PUT" {
            if let Some((owner, tenant, principal)) = &self.revoke {
                let mut tx = owner.begin().await.unwrap();
                sqlx::query("SELECT set_config('app.tenant_id',$1,true)")
                    .bind(tenant.to_string())
                    .execute(&mut *tx)
                    .await
                    .unwrap();
                sqlx::query("UPDATE grants SET enabled=false,revoked_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND action='executions:output:read' AND revoked_at IS NULL").bind(tenant).bind(principal).execute(&mut *tx).await.unwrap();
                tx.commit().await.unwrap();
            }
            let objects = self.objects.lock().await;
            let bytes = objects.get(req.uri().path()).unwrap();
            let head = req.method() == "HEAD";
            assert!(head || req.method() == "GET");
            let body = if head { Vec::new() } else { bytes.clone() };
            let body_size = body.len() as u64;
            let mut response = Response::builder()
                .status(if head { 200 } else { 206 })
                .header("content-length", bytes.len())
                .header("etag", "\"fixture-etag\"")
                .header("last-modified", "Sat, 03 Oct 2026 00:00:00 GMT");
            if !head {
                response = response.header(
                    "content-range",
                    format!("bytes 0-{}/{}", bytes.len() - 1, bytes.len()),
                );
            }
            return Ok(response
                .body(HttpBody::new(
                    futures_util::stream::iter([Ok(Buffer::from(body))]),
                    Some(body_size),
                ))
                .unwrap());
        }
        assert_eq!(req.headers().get("x-oss-forbid-overwrite").unwrap(), "true");
        if self.fail {
            return Err(opendal::Error::new(
                opendal::ErrorKind::Unexpected,
                "test output failure",
            ));
        }
        let mut objects = self.objects.lock().await;
        ensure_unique(&objects, req.uri().path());
        objects.insert(req.uri().path().to_owned(), req.body().to_vec());
        Ok(Response::builder()
            .status(200)
            .header("content-length", "0")
            .body(HttpBody::new(futures_util::stream::empty(), Some(0)))
            .unwrap())
    }
}
fn ensure_unique(objects: &BTreeMap<String, Vec<u8>>, key: &str) {
    assert!(
        !objects.contains_key(key),
        "gateway must not duplicate published object writes"
    );
}

async fn prepared_runtime(
    d: &Dispatched,
) -> anyhow::Result<(
    RuntimeManifestContext,
    RuntimeManifestConfig,
    BTreeMap<String, Value>,
)> {
    let mut tx = d.f.owner_transaction().await?;
    let r=sqlx::query("SELECT i.*,w.storage_class,w.size_gib,t.image_ref,t.image_digest,p.rules FROM instances i JOIN workspaces w ON w.tenant_id=i.tenant_id AND w.id=i.workspace_id JOIN template_versions t ON t.tenant_id=i.tenant_id AND t.id=i.template_version_id JOIN security_policy_versions p ON p.tenant_id=i.tenant_id AND p.id=i.security_policy_version_id WHERE i.tenant_id=$1 AND i.id=$2").bind(d.f.actor.tenant_id).bind(d.instance).fetch_one(&mut *tx).await?;
    let c = RuntimeManifestContext {
        tenant_id: d.f.actor.tenant_id,
        project_id: r.try_get("project_id")?,
        instance_id: d.instance,
        workspace_id: r.try_get("workspace_id")?,
        generation: r.try_get("runtime_generation")?,
        launch_id: r.try_get("launch_id")?,
        cluster_epoch: r.try_get("cluster_epoch")?,
        namespace: r.try_get("namespace")?,
        storage_class: r.try_get("storage_class")?,
        workspace_snapshot: None,
        image_ref: r.try_get("image_ref")?,
        image_digest: r.try_get("image_digest")?,
        template_approved: true,
        security_policy_approved: true,
        security_policy_rules: r.try_get("rules")?,
        cpu_millis: r.try_get("cpu_millis")?,
        memory_mib: r.try_get("memory_mib")?,
        workspace_size_gib: r.try_get("size_gib")?,
    };
    let pod: Uuid = r.try_get("pod_uid")?;
    let pvc = Uuid::new_v4();
    let policy = Uuid::new_v4();
    for (kind, uid, generation, owner) in [
        ("POD", pod, c.generation, c.instance_id),
        ("PVC", pvc, 1, c.workspace_id),
        ("CILIUM_POLICY", policy, 1, c.instance_id),
    ] {
        sqlx::query("INSERT INTO external_resources(tenant_id,project_id,operation_id,instance_id,workspace_id,provider,kind,provider_id,generation,owner_id,status,observed_at) VALUES($1,$2,$3,$4,$5,'kubernetes',$6,$7,$8,$9,'ACTIVE',clock_timestamp())")
            .bind(c.tenant_id).bind(c.project_id).bind(d.claim.operation_id).bind(c.instance_id).bind(c.workspace_id).bind(kind).bind(uid.to_string()).bind(generation).bind(owner).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    let config = RuntimeManifestConfig {
        runtime_class_name: "kata-qemu".into(),
        dns_namespace: "kube-system".into(),
        dns_labels: [("k8s-app".into(), "kube-dns".into())].into(),
        ephemeral_storage_mib: 1024,
        tmp_size_mib: 256,
    };
    let manifests = build_manifests(&c, &config)?;
    let mut pod_object = serde_json::to_value(manifests.pod)?;
    pod_object["metadata"]["uid"] = json!(pod);
    pod_object["metadata"]["resourceVersion"] = json!("pod-fixture-rv");
    pod_object["spec"]["nodeName"] = json!("kata-node");
    pod_object["status"] = json!({"phase":"Running","conditions":[{"type":"Ready","status":"True"}],"containerStatuses":[{"name":container_name(c.launch_id),"ready":true,"restartCount":0,"image":"fixture-image","imageID":"fixture-id","state":{"running":{}}}]});
    let mut pvc_object = serde_json::to_value(manifests.pvc)?;
    pvc_object["metadata"]["uid"] = json!(pvc);
    pvc_object["spec"]["volumeName"] = json!("workspace-volume");
    pvc_object["status"] = json!({"phase":"Bound"});
    let mut policy_object = serde_json::to_value(manifests.network_policy)?;
    policy_object["metadata"]["uid"] = json!(policy);
    let mut objects = BTreeMap::from([
        (
            format!("/api/v1/namespaces/{}", c.namespace),
            json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":c.namespace,"labels":{"sandbox.platform/managed":"true","sandbox.platform/tenant-id":c.tenant_id,"sandbox.platform/project-id":c.project_id,"sandbox.platform/cluster-epoch":c.cluster_epoch},"annotations":{"sandbox.platform/certification-id":"test-certification"}}}),
        ),
        (
            format!(
                "/apis/networking.k8s.io/v1/namespaces/{}/networkpolicies/sandbox-default-deny",
                c.namespace
            ),
            json!({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"sandbox-default-deny","namespace":c.namespace},"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"]}}),
        ),
        (
            "/api/v1/nodes/kata-node".into(),
            json!({"apiVersion":"v1","kind":"Node","metadata":{"name":"kata-node","uid":Uuid::new_v4(),"labels":{"sandbox.platform/worker-pool":"kata"}},"spec":{"taints":[{"key":"sandbox.platform/untrusted","value":"true","effect":"NoSchedule"}]},"status":{"conditions":[{"type":"Ready","status":"True"}]}}),
        ),
        (
            "/api/v1/persistentvolumes/workspace-volume".into(),
            json!({"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":"workspace-volume","uid":Uuid::new_v4()},"spec":{"accessModes":["ReadWriteOnce"],"volumeMode":"Filesystem","storageClassName":c.storage_class,"csi":{"driver":"fixture-csi-driver","volumeHandle":"fixture-volume"},"claimRef":{"kind":"PersistentVolumeClaim","name":pvc_name(c.workspace_id),"namespace":c.namespace,"uid":pvc}},"status":{"phase":"Bound"}}),
        ),
        (
            format!(
                "/api/v1/namespaces/{}/pods/{}",
                c.namespace,
                pod_name(c.workspace_id)
            ),
            pod_object,
        ),
        (
            format!(
                "/api/v1/namespaces/{}/persistentvolumeclaims/{}",
                c.namespace,
                pvc_name(c.workspace_id)
            ),
            pvc_object,
        ),
        (
            format!(
                "/apis/cilium.io/v2/namespaces/{}/ciliumnetworkpolicies/{}",
                c.namespace,
                network_policy_name(c.workspace_id)
            ),
            policy_object,
        ),
    ]);
    objects.extend(support::runtime_class_guard::objects(None));
    Ok((c, config, objects))
}

async fn scenario(scenario: Scenario, limit: u64) -> anyhow::Result<()> {
    let d = Dispatched::setup(false, limit).await?;
    let (context, config, objects) = prepared_runtime(&d).await?;
    let connects = Arc::new(AtomicUsize::new(0));
    let state = KubeServer {
        owner: d.f.owner.clone(),
        tenant: d.f.actor.tenant_id,
        execution: d.execution,
        container: container_name(context.launch_id),
        objects: Arc::new(objects),
        connects: connects.clone(),
        scenario,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(kube_request).with_state(state),
        )
        .await
    });
    let mut kube_config = kube::Config::new(format!("http://{address}").parse()?);
    kube_config.default_retry = false;
    let runtime = KubernetesRuntime::from_client(kube::Client::try_from(kube_config)?);
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("sts.json");
    tokio::fs::write(&path,serde_json::to_vec(&json!({"access_key_id":"TEST_ONLY_AK","access_key_secret":"TEST_ONLY_SECRET","security_token":"TEST_ONLY_TOKEN","expires_at":Utc::now()+chrono::Duration::minutes(10)}))?).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await?;
    }
    let output_mock = OutputMock {
        fail: matches!(scenario, Scenario::OutputFailure),
        ..Default::default()
    };
    let output_config = OssOutputConfig {
        endpoint: "https://oss-cn-hangzhou-internal.aliyuncs.com".into(),
        bucket: "sandbox-output".into(),
        kms_key_id: "test-key".into(),
        sts_credentials_file: path,
    };
    let output = OssOutputStore::from_transport(
        output_config.clone(),
        HttpTransporter::new(output_mock.clone()),
    )?;
    let gateway = Gateway::new(
        d.engine.database.clone(),
        runtime,
        output,
        "gateway-ledger-test".into(),
        "test-certification".into(),
        1,
        config,
    )?;
    tokio::time::timeout(
        Duration::from_secs(15),
        gateway.run_claim(d.claim.clone(), CancellationToken::new()),
    )
    .await?;
    ensure!(
        connects.load(Ordering::SeqCst) == 1,
        "exactly one CONNECT request should reach the test server"
    );
    let mut tx = d.f.owner_transaction().await?;
    let row=sqlx::query("SELECT status,slot_held,output_status,output_manifest,termination_status,cancel_operation_id,dispatch_attempt_id FROM executions WHERE tenant_id=$1 AND id=$2").bind(d.f.actor.tenant_id).bind(d.execution).fetch_one(&mut *tx).await?;
    let status: String = row.try_get("status")?;
    let held: bool = row.try_get("slot_held")?;
    let output_status: String = row.try_get("output_status")?;
    let termination: String = row.try_get("termination_status")?;
    let unknown = matches!(scenario, Scenario::Disconnected | Scenario::OutputFailure);
    if unknown {
        assert_eq!(
            (status.as_str(), held, termination.as_str()),
            ("OUTCOME_UNKNOWN", true, "PENDING")
        );
        assert!(
            row.try_get::<Option<Uuid>, _>("cancel_operation_id")?
                .is_some()
        );
        assert_eq!(
            output_status,
            if matches!(scenario, Scenario::Disconnected) {
                "PARTIAL"
            } else {
                "LOST"
            }
        );
    } else {
        assert_eq!(
            (status.as_str(), held, termination.as_str()),
            ("SUCCEEDED", false, "NOT_REQUESTED")
        );
        assert_eq!(
            output_status,
            if matches!(scenario, Scenario::Truncated) {
                "TRUNCATED"
            } else {
                "COMPLETE"
            }
        );
        let reference: Value = row
            .try_get::<Option<Value>, _>("output_manifest")?
            .context("persisted manifest")?;
        let objects = output_mock.objects.lock().await;
        let key = format!(
            "/{}",
            reference["object_key"].as_str().context("manifest key")?
        );
        let body = objects
            .get(&key)
            .context("manifest object must exist before DB result")?;
        let manifest: Value = serde_json::from_slice(body)?;
        let segments = manifest["segments"]
            .as_array()
            .context("manifest segments")?;
        assert_eq!(segments.len(), usize::from(limit > 0));
        for segment in segments {
            let object_key = format!(
                "/tenants/{}/executions/{}/attempts/{}/segments/{}-{}.ndjson",
                d.f.actor.tenant_id,
                d.execution,
                manifest["dispatch_attempt_id"]
                    .as_str()
                    .context("attempt")?,
                segment["sequence"],
                segment["sha256"].as_str().context("sha")?
            );
            assert!(
                objects.contains_key(&object_key),
                "indexed segment object must exist"
            );
        }
    }
    let quota:i64=sqlx::query_scalar("SELECT sum(pending+allocated)::bigint FROM quota_accounts WHERE tenant_id=$1 AND dimension='EXECUTIONS'").bind(d.f.actor.tenant_id).fetch_one(&mut *tx).await?;
    assert_eq!(quota, if unknown { 2 } else { 0 });
    tx.commit().await?;
    let reader = OssOutputReader::from_transport(
        output_config.clone(),
        HttpTransporter::new(output_mock.clone()),
    )?;
    let page =
        d.f.database
            .execution_output(&d.f.actor, d.execution, -1, 2, &reader)
            .await
            .map_err(support::api_failure)?;
    assert_eq!(page.output_status, output_status);
    assert!(!page.has_more);
    assert_eq!(page.manifest_verified, !unknown);
    let expected_segments = usize::from(limit > 0 && !matches!(scenario, Scenario::OutputFailure));
    assert_eq!(page.segments.len(), expected_segments);
    for segment in &page.segments {
        for frame in &segment.frames {
            assert_eq!(frame.offset, 0);
            assert_eq!(
                STANDARD.decode(&frame.data)?,
                b"hello"[..5.min(limit as usize)]
            );
        }
    }
    if !unknown {
        assert_eq!(
            page.final_segment_sequence,
            if expected_segments > 0 {
                Some(0)
            } else {
                Some(-1)
            }
        );
    }
    let mut other = d.f.actor.clone();
    other.tenant_id = Uuid::new_v4();
    assert_eq!(
        d.f.database
            .execution_output(&other, d.execution, -1, 1, &reader)
            .await
            .err()
            .context("foreign tenant read must fail")?
            .code,
        "RESOURCE_NOT_FOUND"
    );
    assert!(
        d.f.database
            .execution_output(&d.f.actor, d.execution, -2, 1, &reader)
            .await
            .is_err()
    );
    if matches!(scenario, Scenario::Normal) {
        let empty =
            d.f.database
                .execution_output(&d.f.actor, d.execution, 0, 1, &reader)
                .await
                .map_err(support::api_failure)?;
        assert!(empty.segments.is_empty() && empty.manifest_verified && !empty.has_more);
        let mut tx = d.f.owner_transaction().await?;
        let old_manifest: Value = sqlx::query_scalar(
            "SELECT output_manifest FROM executions WHERE tenant_id=$1 AND id=$2",
        )
        .bind(d.f.actor.tenant_id)
        .bind(d.execution)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("UPDATE executions SET output_manifest=NULL WHERE tenant_id=$1 AND id=$2")
            .bind(d.f.actor.tenant_id)
            .bind(d.execution)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        assert_eq!(
            d.f.database
                .execution_output(&d.f.actor, d.execution, -1, 1, &reader)
                .await
                .err()
                .context("missing final manifest cannot imply complete")?
                .code,
            "OUTPUT_INTEGRITY_FAILED"
        );
        let mut tx = d.f.owner_transaction().await?;
        sqlx::query("UPDATE executions SET output_manifest=$3 WHERE tenant_id=$1 AND id=$2")
            .bind(d.f.actor.tenant_id)
            .bind(d.execution)
            .bind(old_manifest)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        // Same-size object tampering is caught by SHA rather than trusted metadata.
        let segment_key = {
            output_mock
                .objects
                .lock()
                .await
                .keys()
                .find(|key| key.contains("/segments/"))
                .cloned()
                .context("segment")?
        };
        let original = {
            let mut objects = output_mock.objects.lock().await;
            let body = objects.get_mut(&segment_key).context("segment")?;
            let original = body.clone();
            body[0] ^= 1;
            original
        };
        assert_eq!(
            d.f.database
                .execution_output(&d.f.actor, d.execution, -1, 1, &reader)
                .await
                .err()
                .context("corrupt output must fail")?
                .code,
            "OUTPUT_INTEGRITY_FAILED"
        );
        output_mock
            .objects
            .lock()
            .await
            .insert(segment_key, original);
        let revoking = OssOutputReader::from_transport(
            output_config,
            HttpTransporter::new(OutputMock {
                objects: output_mock.objects.clone(),
                fail: false,
                revoke: Some((
                    d.f.owner.clone(),
                    d.f.actor.tenant_id,
                    d.f.actor.principal_id,
                )),
            }),
        )?;
        assert_eq!(
            d.f.database
                .execution_output(&d.f.actor, d.execution, -1, 1, &revoking)
                .await
                .err()
                .context("revocation during storage I/O must prevent return")?
                .code,
            "RESOURCE_NOT_FOUND"
        );
    }
    // Reusing the old claim after completion or safety cancellation must never
    // send a second request, even though the caller retries the controller.
    gateway.run_claim(d.claim, CancellationToken::new()).await;
    assert_eq!(connects.load(Ordering::SeqCst), 1);
    server.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable PostgreSQL and local HTTP/WebSocket listener"]
async fn full_gateway_persists_native_oss_before_normal_or_truncated_completion()
-> anyhow::Result<()> {
    let _scope = support::serial().await;
    scenario(Scenario::Normal, 1024).await?;
    scenario(Scenario::Truncated, 1).await?;
    scenario(Scenario::Truncated, 0).await?;
    Ok(())
}
#[tokio::test]
#[ignore = "Requires disposable PostgreSQL and local HTTP/WebSocket listener"]
async fn full_gateway_disconnect_or_output_failure_requests_stop_without_replay()
-> anyhow::Result<()> {
    let _scope = support::serial().await;
    scenario(Scenario::Disconnected, 1024).await?;
    scenario(Scenario::OutputFailure, 1024).await?;
    Ok(())
}
