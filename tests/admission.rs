//! Policy samples plus real mTLS HTTP transport; cluster isolation is tested at G1.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[allow(dead_code)]
mod support;

use std::{convert::Infallible, sync::Arc, time::Duration};

use axum::{
    body::Body,
    http::{Request, Response},
};
use kube::{Client, client::Body as KubeBody};
use sandbox_platform::{
    admission::{
        AdmissionConfig, AdmissionRequest, AdmissionService, ControllerIdentity, WorkloadAuthority,
        execution_connect_identity, router, validate_workload,
    },
    db::Database,
    domain::InstanceAction,
    runtime_manifest::{RuntimeManifestContext, build_manifests},
    tls::{admission_mutual_tls, serve_admission},
};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use support::{Fixture, api_failure};
use uuid::Uuid;

fn config() -> AdmissionConfig {
    serde_json::from_value(json!({
        "gateway":{"username":"system:serviceaccount:sandbox-system:sandbox-gateway","uid":Uuid::new_v4()},
        "termination":{"username":"system:serviceaccount:sandbox-system:sandbox-termination","uid":Uuid::new_v4()},
        "worker":{"username":"system:serviceaccount:sandbox-system:sandbox-worker","uid":Uuid::new_v4()},
        "namespace_provisioner":{"username":"system:serviceaccount:sandbox-system:namespace-provisioner","uid":Uuid::new_v4()},
        "scheduler":{"kind":"control_plane","username":"system:kube-scheduler"},
        "storage_controllers":[{"kind":"service_account","username":"system:serviceaccount:kube-system:csi-provisioner","uid":Uuid::new_v4()}],
        "policy_status_controllers":[{"kind":"service_account","username":"system:serviceaccount:kube-system:cilium","uid":Uuid::new_v4()}],
        "namespace_status_controllers":[{"kind":"control_plane","username":"system:kube-controller-manager"}],
        "pod_garbage_collectors":[{"kind":"control_plane","username":"system:kube-controller-manager"}],
        "storage_provisioner":"diskplugin.csi.alibabacloud.com", "certification_id":"test-evidence-reference",
        "dns_namespace":"kube-system","dns_labels":{"k8s-app":"kube-dns"},"ephemeral_storage_mib":1024,"tmp_size_mib":256
    })).unwrap()
}
fn authority() -> WorkloadAuthority {
    WorkloadAuthority {
        context: RuntimeManifestContext {
            tenant_id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            instance_id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            launch_id: Uuid::new_v4(),
            cluster_epoch: Uuid::new_v4(),
            generation: 1,
            namespace: "sandbox-test-project".into(),
            storage_class: "encrypted-rwo".into(),
            workspace_snapshot: None,
            image_ref: "registry.example.test/sandbox/python".into(),
            image_digest: format!("sha256:{}", "a".repeat(64)),
            template_approved: true,
            security_policy_approved: true,
            security_policy_rules: json!({"profile":"deny-all","dns":true}),
            cpu_millis: 1000,
            memory_mib: 2048,
            workspace_size_gib: 20,
        },
        create_allowed: true,
        stop_allowed: false,
        termination_finalizer_allowed: false,
        termination_proven: false,
        pod_uid: None,
        pvc_uid: None,
        policy_uid: None,
        node_binding_valid: false,
        volume_binding_valid: false,
    }
}
fn manifest(a: &WorkloadAuthority, c: &AdmissionConfig, resource: &str) -> Value {
    let m = build_manifests(&a.context, &c.runtime()).unwrap();
    let mut value = match resource {
        "pods" => serde_json::to_value(m.pod),
        "persistentvolumeclaims" => serde_json::to_value(m.pvc),
        _ => serde_json::to_value(m.network_policy),
    }
    .unwrap();
    // apiserver assigns the UID before validating admission, not the submitter.
    value["metadata"]["uid"] = json!(Uuid::new_v4());
    value["metadata"]["resourceVersion"] = json!("17");
    value
}
fn request(c: &AdmissionConfig, resource: &str, object: Value) -> AdmissionRequest {
    serde_json::from_value(json!({"uid":Uuid::new_v4(),"resource":{"group":if resource=="ciliumnetworkpolicies"{"cilium.io"}else{""},"version":if resource=="ciliumnetworkpolicies"{"v2"}else{"v1"},"resource":resource},"operation":"CREATE","namespace":object["metadata"]["namespace"],"name":object["metadata"]["name"],"userInfo":{"username":c.worker.username,"uid":c.worker.uid},"object":object})).unwrap()
}
fn updated(mut r: AdmissionRequest) -> AdmissionRequest {
    r.operation = "UPDATE".into();
    r.old_object = r.object.clone();
    r
}
fn controller(r: &mut AdmissionRequest, identity: &ControllerIdentity) {
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
fn denied(r: &AdmissionRequest, a: &WorkloadAuthority, c: &AdmissionConfig) {
    assert!(
        validate_workload(r, a, c).is_err(),
        "malicious sample unexpectedly admitted"
    );
}

#[test]
fn legal_pod_pvc_and_deny_all_dns_policy_are_admitted() {
    let a = authority();
    let c = config();
    c.validate().unwrap();
    for resource in ["pods", "persistentvolumeclaims", "ciliumnetworkpolicies"] {
        validate_workload(&request(&c, resource, manifest(&a, &c, resource)), &a, &c).unwrap();
    }
}
#[test]
fn copied_labels_never_grant_worker_identity_or_current_lease() {
    let mut a = authority();
    let c = config();
    let good = request(&c, "pods", manifest(&a, &c, "pods"));
    for (username, uid) in [
        ("oidc:attacker", c.worker.uid.as_str()),
        (c.worker.username.as_str(), "recreated-sa-uid"),
        (
            "system:serviceaccount:sandbox-system:sandbox-api",
            c.worker.uid.as_str(),
        ),
    ] {
        let mut r = good.clone();
        r.user_info.username = username.into();
        r.user_info.uid = uid.into();
        denied(&r, &a, &c);
    }
    a.create_allowed = false;
    denied(&good, &a, &c);
    a.create_allowed = true;
    a.pod_uid = Some(Uuid::new_v4().to_string());
    denied(&good, &a, &c);
}
#[test]
fn pod_attack_matrix_blocks_isolation_escape_writer_injection_and_identity_forgery() {
    let a = authority();
    let c = config();
    let original = manifest(&a, &c, "pods");
    let attacks: Vec<(&str, Value)> = vec![
        ("/spec/runtimeClassName", json!("runc")),
        ("/spec/nodeName", json!("untrusted-node")),
        ("/spec/hostNetwork", json!(true)),
        ("/spec/hostPID", json!(true)),
        ("/spec/hostIPC", json!(true)),
        ("/spec/automountServiceAccountToken", json!(true)),
        ("/spec/serviceAccountName", json!("default")),
        ("/spec/schedulerName", json!("attacker")),
        ("/spec/containers/0/securityContext/privileged", json!(true)),
        (
            "/spec/containers/0/securityContext/readOnlyRootFilesystem",
            json!(false),
        ),
        ("/spec/containers/0/image", json!("attacker:latest")),
        (
            "/spec/volumes/0",
            json!({"name":"workspace","hostPath":{"path":"/"}}),
        ),
        (
            "/metadata/annotations",
            json!({"io.katacontainers.config.hypervisor.kernel_params":"init=/bin/sh"}),
        ),
        ("/metadata/finalizers", json!([])),
        (
            "/metadata/labels/sandbox.platform~1tenant-id",
            json!(Uuid::new_v4()),
        ),
        (
            "/metadata/labels/unsafe-policy-selector",
            json!("allow-world"),
        ),
        ("/metadata/name", json!("extra-workspace-writer")),
        (
            "/spec/ephemeralContainers",
            json!([{"name":"debug","image":"attacker"}]),
        ),
        (
            "/spec/initContainers",
            json!([{"name":"init","image":"attacker"}]),
        ),
        ("/kind", json!("Deployment")),
    ];
    for (pointer, value) in attacks {
        let mut object = original.clone();
        set_pointer(&mut object, pointer, value);
        let r = request(&c, "pods", object);
        denied(&r, &a, &c);
    }
    let mut object = original.clone();
    object["spec"]["containers"]
        .as_array_mut()
        .unwrap()
        .push(original["spec"]["containers"][0].clone());
    denied(&request(&c, "pods", object), &a, &c);
    let mut r = request(&c, "pods", original);
    r.sub_resource = "ephemeralcontainers".into();
    denied(&r, &a, &c);
}
fn set_pointer(object: &mut Value, pointer: &str, value: Value) {
    let (parent, key) = pointer.rsplit_once('/').unwrap();
    let parent = object.pointer_mut(parent).unwrap();
    let key = key.replace("~1", "/").replace("~0", "~");
    if let Some(fields) = parent.as_object_mut() {
        fields.insert(key, value);
    } else {
        parent[key.parse::<usize>().unwrap()] = value;
    }
}
#[test]
fn pod_stop_requires_exact_preconditions_and_never_removes_finalizer() {
    let mut a = authority();
    let c = config();
    let good = manifest(&a, &c, "pods");
    let mut r = updated(request(&c, "pods", good.clone()));
    a.pod_uid = good["metadata"]["uid"].as_str().map(str::to_owned);
    a.stop_allowed = true;
    r.operation = "DELETE".into();
    r.object = None;
    r.options = Some(
        json!({"preconditions":{"uid":good["metadata"]["uid"],"resourceVersion":"17"},"gracePeriodSeconds":30}),
    );
    validate_workload(&r, &a, &c).unwrap();
    for option in [
        json!({}),
        json!({"preconditions":{"uid":"fake","resourceVersion":"17"},"gracePeriodSeconds":30}),
        json!({"preconditions":{"uid":good["metadata"]["uid"],"resourceVersion":"17"},"gracePeriodSeconds":0}),
    ] {
        let mut bad = r.clone();
        bad.options = Some(option);
        denied(&bad, &a, &c);
    }
    let mut update = updated(request(&c, "pods", good));
    update.object.as_mut().unwrap()["metadata"]["finalizers"] = json!([]);
    denied(&update, &a, &c);
    a.stop_allowed = false;
    denied(&r, &a, &c);
}
#[test]
fn finalizer_requires_dedicated_identity_and_fresh_exact_proof() {
    let mut a = authority();
    let c = config();
    let mut pod = manifest(&a, &c, "pods");
    pod["metadata"]["deletionTimestamp"] = json!("2026-10-03T00:00:00Z");
    pod["spec"]["nodeName"] = json!("kata-node-1");
    a.pod_uid = pod["metadata"]["uid"].as_str().map(str::to_owned);
    a.stop_allowed = true;
    a.termination_proven = true;
    a.termination_finalizer_allowed = true;
    let mut r = updated(request(&c, "pods", pod));
    r.object.as_mut().unwrap()["metadata"]["finalizers"] = json!([]);
    // Even a worker holding valid evidence cannot release the VM's protection.
    denied(&r, &a, &c);
    r.user_info.username = c.termination.username.clone();
    r.user_info.uid = c.termination.uid.clone();
    validate_workload(&r, &a, &c).unwrap();
    let mut wrong_identity = r.clone();
    wrong_identity.user_info.uid = Uuid::new_v4().to_string();
    denied(&wrong_identity, &a, &c);
    for pointer in [
        "/metadata/deletionTimestamp",
        "/metadata/finalizers",
        "/spec/hostNetwork",
        "/status",
    ] {
        let mut bad = r.clone();
        let value = match pointer {
            "/metadata/finalizers" => json!(["other/finalizer"]),
            "/spec/hostNetwork" => json!(true),
            "/status" => json!({"phase":"Succeeded"}),
            _ => Value::Null,
        };
        set_pointer(bad.object.as_mut().unwrap(), pointer, value);
        denied(&bad, &a, &c);
    }
    a.termination_finalizer_allowed = false;
    denied(&r, &a, &c);
    // After the finalizer was lawfully removed, lease expiry cannot strand GC.
    let unprotected = r.object.clone();
    r.old_object = unprotected;
    r.sub_resource = "status".into();
    r.user_info.username = "system:node:kata-node-1".into();
    r.user_info.uid.clear();
    r.user_info.groups = vec!["system:nodes".into(), "system:authenticated".into()];
    a.stop_allowed = false;
    a.node_binding_valid = true;
    r.object.as_mut().unwrap()["status"] = json!({"phase":"Succeeded"});
    validate_workload(&r, &a, &c).unwrap();
    controller(&mut r, &c.pod_garbage_collectors[0]);
    r.object.as_mut().unwrap()["status"] = json!({"phase":"Failed","conditions":[{"type":"DisruptionTarget","status":"True","reason":"DeletionByPodGC"}]});
    validate_workload(&r, &a, &c).unwrap();
    let mut forged_ready = r.clone();
    forged_ready.object.as_mut().unwrap()["status"]["conditions"] =
        json!([{"type":"Ready","status":"True"}]);
    denied(&forged_ready, &a, &c);
    r.sub_resource.clear();
    r.operation = "DELETE".into();
    r.object = None;
    controller(&mut r, &c.pod_garbage_collectors[0]);
    // The pinned upstream PodGC sends NewDeleteOptions(0), without preconditions.
    r.options = Some(json!({"gracePeriodSeconds":0}));
    validate_workload(&r, &a, &c).unwrap();
    a.termination_proven = false;
    denied(&r, &a, &c);
    let mut invalid = c.clone();
    invalid.termination = invalid.worker.clone();
    assert!(invalid.validate().is_err());
}
#[test]
fn status_cannot_change_pod_spec_and_scheduler_cannot_invent_readiness() {
    let mut a = authority();
    let c = config();
    let mut pod = manifest(&a, &c, "pods");
    pod["spec"]["nodeName"] = json!("kata-node-1");
    let mut r = updated(request(&c, "pods", pod));
    r.sub_resource = "status".into();
    r.user_info.username = "system:node:kata-node-1".into();
    r.user_info.uid.clear();
    r.user_info.groups = vec!["system:nodes".into(), "system:authenticated".into()];
    r.object.as_mut().unwrap()["status"] = json!({"phase":"Running"});
    a.node_binding_valid = true;
    validate_workload(&r, &a, &c).unwrap();
    r.user_info.username = "system:node:kata-node-2".into();
    denied(&r, &a, &c);
    controller(&mut r, &c.scheduler);
    denied(&r, &a, &c);
    r.object.as_mut().unwrap()["status"] =
        json!({"conditions":[{"type":"PodScheduled","status":"False","reason":"Unschedulable"}]});
    validate_workload(&r, &a, &c).unwrap();
    r.user_info.groups.push("system:masters".into());
    denied(&r, &a, &c);
    controller(&mut r, &c.scheduler);
    r.object.as_mut().unwrap()["spec"]["nodeName"] = json!("forged");
    denied(&r, &a, &c);
}
#[test]
fn pvc_binding_requires_controller_and_verified_pv_claim_uid() {
    let mut a = authority();
    let c = config();
    let mut r = updated(request(
        &c,
        "persistentvolumeclaims",
        manifest(&a, &c, "persistentvolumeclaims"),
    ));
    r.object.as_mut().unwrap()["spec"]["volumeName"] = json!("pv-1");
    controller(&mut r, &c.storage_controllers[0]);
    denied(&r, &a, &c);
    a.volume_binding_valid = true;
    validate_workload(&r, &a, &c).unwrap();
    r.user_info.uid = "forged-sa".into();
    denied(&r, &a, &c);
    controller(&mut r, &c.storage_controllers[0]);
    r.object.as_mut().unwrap()["metadata"]["annotations"] = json!({"unsafe.volume/mount":"host"});
    denied(&r, &a, &c);
    r.object.as_mut().unwrap()["metadata"]["annotations"] =
        json!({"volume.kubernetes.io/selected-node":"kata-node-1"});
    denied(&r, &a, &c);
    a.node_binding_valid = true;
    validate_workload(&r, &a, &c).unwrap();
    r.old_object = r.object.clone();
    r.object.as_mut().unwrap()["spec"]["volumeName"] = json!("another-pv");
    denied(&r, &a, &c);
}
#[test]
fn scheduler_can_select_a_ready_kata_node_without_becoming_a_storage_controller() {
    let mut a = authority();
    let c = config();
    let mut r = updated(request(
        &c,
        "persistentvolumeclaims",
        manifest(&a, &c, "persistentvolumeclaims"),
    ));
    controller(&mut r, &c.scheduler);
    r.object.as_mut().unwrap()["metadata"]["annotations"] =
        json!({"volume.kubernetes.io/selected-node":"kata-node-1"});
    denied(&r, &a, &c);
    a.node_binding_valid = true;
    validate_workload(&r, &a, &c).unwrap();
    a.create_allowed = false;
    denied(&r, &a, &c);
    a.create_allowed = true;
    r.object.as_mut().unwrap()["metadata"]["annotations"]["volume.kubernetes.io/storage-provisioner"] =
        json!(c.storage_provisioner);
    denied(&r, &a, &c);
    r.object.as_mut().unwrap()["metadata"]["annotations"]
        .as_object_mut()
        .unwrap()
        .remove("volume.kubernetes.io/storage-provisioner");
    r.object.as_mut().unwrap()["spec"]["volumeName"] = json!("pv-forged");
    a.volume_binding_valid = true;
    denied(&r, &a, &c);
}

#[test]
fn network_allow_world_uid_rebinding_and_policy_removal_are_denied() {
    let a = authority();
    let c = config();
    let good = manifest(&a, &c, "ciliumnetworkpolicies");
    let mut r = request(&c, "ciliumnetworkpolicies", good.clone());
    r.object.as_mut().unwrap()["spec"]["egress"] = json!([{}]);
    denied(&r, &a, &c);
    r = updated(request(&c, "ciliumnetworkpolicies", good));
    r.object.as_mut().unwrap()["metadata"]["uid"] = json!(Uuid::new_v4());
    denied(&r, &a, &c);
    r.operation = "DELETE".into();
    denied(&r, &a, &c);
}

fn mock_client(namespace: Option<Value>) -> Client {
    let service = tower::service_fn(move |_req: Request<KubeBody>| {
        let body = namespace.clone();
        async move {
            let response = match body {
                Some(value) => Response::builder()
                    .status(200)
                    .body(Body::from(serde_json::to_vec(&value).unwrap()))
                    .unwrap(),
                None => Response::builder()
                    .status(503)
                    .body(Body::from("dependency deliberately unavailable"))
                    .unwrap(),
            };
            Ok::<_, Infallible>(response)
        }
    });
    Client::new(service, "default")
}
fn disconnected_service(c: AdmissionConfig) -> Arc<AdmissionService> {
    Arc::new(AdmissionService {
        database: Database {
            pool: PgPoolOptions::new()
                .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused_test")
                .unwrap(),
        },
        kubernetes: mock_client(None),
        config: c,
    })
}
#[tokio::test]
async fn mtls_real_http_requires_dedicated_client_ca_and_echoes_admission_uid() -> anyhow::Result<()>
{
    let tls = admission_mutual_tls(
        include_bytes!("fixtures/admission/server.pem"),
        include_bytes!("fixtures/admission/server.key"),
        include_bytes!("fixtures/admission/apiserver-ca.pem"),
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let cancel = tokio_util::sync::CancellationToken::new();
    let app = router(disconnected_service(config()));
    let task = tokio::spawn(serve_admission(listener, tls, app, cancel.clone()));
    let outcome=async {
        let build=|identity:Option<(&[u8],&[u8])>|->anyhow::Result<reqwest::Client> {
            let mut builder=reqwest::Client::builder().no_proxy().http2_prior_knowledge().timeout(Duration::from_secs(3)).add_root_certificate(reqwest::Certificate::from_pem(include_bytes!("fixtures/admission/server-ca.pem"))?);
            if let Some((cert,key))=identity {let pem=[cert,key].concat();builder=builder.identity(reqwest::Identity::from_pem(&pem)?);}
            Ok(builder.build()?)
        };
        let url=format!("https://127.0.0.1:{}/validate",addr.port());
        let review=json!({"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"must-echo-this","resource":{"group":"","version":"v1","resource":"namespaces"},"operation":"CREATE","name":"ordinary-unmanaged-namespace","userInfo":{"username":"normal-user"},"object":{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"ordinary-unmanaged-namespace","uid":Uuid::new_v4()}}}});
        let client=build(Some((include_bytes!("fixtures/admission/apiserver.pem"),include_bytes!("fixtures/admission/apiserver.key"))))?;
        let response=client.post(&url).json(&review).send().await?;assert_eq!(response.version(),reqwest::Version::HTTP_2);assert!(response.status().is_success());let value:Value=response.json().await?;assert_eq!(value["response"]["uid"],"must-echo-this");assert_eq!(value["response"]["allowed"],true);
        assert!(build(None)?.post(&url).json(&review).send().await.is_err());
        assert!(build(Some((include_bytes!("fixtures/admission/outsider.pem"),include_bytes!("fixtures/admission/outsider.key"))))?.post(&url).json(&review).send().await.is_err());
        let mut attack=review.clone();attack["request"]["object"]["metadata"]["labels"]=json!({"sandbox.platform/managed":"true"});let value:Value=client.post(&url).json(&attack).send().await?.json().await?;assert_eq!(value["response"]["allowed"],false);
        let mut bad=review.clone();bad["apiVersion"]=json!("admission.k8s.io/v1beta1");assert_eq!(client.post(&url).json(&bad).send().await?.status(),400);
        // Authenticated apiserver still receives a denial when trusted state is unavailable.
        let a=authority();let c=config();let pod=manifest(&a,&c,"pods");let fail=json!({"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"dependency-failure","resource":{"group":"","version":"v1","resource":"pods"},"operation":"CREATE","namespace":a.context.namespace,"name":pod["metadata"]["name"],"userInfo":{"username":c.worker.username,"uid":c.worker.uid},"object":pod}});
        let value:Value=client.post(&url).json(&fail).send().await?.json().await?;assert_eq!(value["response"]["allowed"],false);assert_eq!(value["response"]["status"]["code"],503);
        Ok::<(),anyhow::Error>(())
    }.await;
    cancel.cancel();
    task.await??;
    outcome
}

#[tokio::test]
#[ignore = "requires explicit disposable PostgreSQL and dedicated admission role"]
async fn real_readonly_role_authorizes_from_sql_and_rejects_expired_revoked_or_stopped_launch()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let url = std::env::var("TEST_ADMISSION_DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("TEST_ADMISSION_DATABASE_URL is required"))?;
    let expected = url::Url::parse(
        &std::env::var("TEST_DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("TEST_DATABASE_URL is required"))?,
    )?;
    let actual = url::Url::parse(&url)?;
    anyhow::ensure!(
        actual.host_str() == expected.host_str()
            && actual.port_or_known_default() == expected.port_or_known_default()
            && actual.path() == expected.path()
            && actual.username() == "sandbox_admission"
            && actual.path().ends_with("_test"),
        "dedicated admission identity must target the same disposable test database"
    );
    let mut f = Fixture::new(5).await?;
    let policy = Uuid::new_v4();
    let mut tx = f.owner_transaction().await?;
    sqlx::query("INSERT INTO security_policy_versions(id,tenant_id,name,version,status,rules) VALUES($1,$2,'admission-deny-all',1,'APPROVED',$3)").bind(policy).bind(f.actor.tenant_id).bind(json!({"profile":"deny-all","dns":true})).execute(&mut *tx).await?;
    tx.commit().await?;
    f.request.security_profile_id = policy;
    sqlx::raw_sql(include_str!("../scripts/sql/admission-role.sql"))
        .execute(&f.owner)
        .await?;
    let db = Database::connect(&url, 4).await?;
    db.verify_runtime_role().await?;
    assert!(
        sqlx::query("UPDATE platform_configuration SET safe_mode=false")
            .execute(&db.pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("SELECT sandbox_claim_operation('unauthorized-admission')")
            .execute(&db.pool)
            .await
            .is_err()
    );
    let created = f
        .create("admission-real-launch")
        .await
        .map_err(api_failure)?;
    let instance = f
        .database
        .get_instance(&f.actor, created.body.resource.id)
        .await
        .map_err(api_failure)?;
    let mut tx = f.owner_transaction().await?;
    let (namespace,epoch,launch,workspace,generation):(String,Uuid,Uuid,Uuid,i64)=sqlx::query_as("SELECT namespace,cluster_epoch,launch_id,workspace_id,runtime_generation FROM instances WHERE id=$1").bind(instance.id).fetch_one(&mut *tx).await?;
    let (image,digest,rules):(String,String,Value)=sqlx::query_as("SELECT t.image_ref,t.image_digest,p.rules FROM template_versions t CROSS JOIN security_policy_versions p WHERE t.id=$1 AND p.id=$2").bind(f.request.template_version_id).bind(f.request.security_profile_id).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    let c = config();
    let mut a = authority();
    a.context.tenant_id = f.actor.tenant_id;
    a.context.project_id = instance.project_id;
    a.context.instance_id = instance.id;
    a.context.workspace_id = workspace;
    a.context.launch_id = launch;
    a.context.cluster_epoch = epoch;
    a.context.generation = generation;
    a.context.namespace = namespace.clone();
    a.context.storage_class = "integration-storage".into();
    a.context.image_ref = image;
    a.context.image_digest = digest;
    a.context.security_policy_rules = rules;
    a.context.cpu_millis = instance.cpu_millis;
    a.context.memory_mib = instance.memory_mib;
    a.context.workspace_size_gib = f.request.workspace.size_gib;
    let ns = json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":namespace,"uid":Uuid::new_v4(),"labels":{"sandbox.platform/managed":"true","sandbox.platform/tenant-id":f.actor.tenant_id,"sandbox.platform/project-id":instance.project_id,"sandbox.platform/cluster-epoch":epoch},"annotations":{"sandbox.platform/certification-id":c.certification_id}}});
    let service = AdmissionService {
        database: db,
        kubernetes: mock_client(Some(ns)),
        config: c.clone(),
    };
    let r = request(&c, "pods", manifest(&a, &c, "pods"));
    let decision = service.decide(&r).await;
    assert!(
        decision.is_ok(),
        "expected authorized launch, got {decision:?}"
    );
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE instances SET compute_lease_started_at=clock_timestamp()-interval '60 seconds',compute_lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1").bind(instance.id).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(service.decide(&r).await.is_err());
    let mut tx = f.owner_transaction().await?;
    sqlx::query(
        "UPDATE instances SET compute_lease_started_at=$2,compute_lease_expires_at=$3 WHERE id=$1",
    )
    .bind(instance.id)
    .bind(instance.compute_lease_started_at)
    .bind(instance.compute_lease_expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let mut forged = r.clone();
    forged.object.as_mut().unwrap()["metadata"]["labels"]["sandbox.platform/tenant-id"] =
        json!(Uuid::new_v4());
    assert!(service.decide(&forged).await.is_err());
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE principal_id=$1")
        .bind(f.actor.principal_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    assert!(service.decide(&r).await.is_err());
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE grants SET enabled=true WHERE principal_id=$1")
        .bind(f.actor.principal_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let mut tx = f.owner_transaction().await?;
    sqlx::query("INSERT INTO external_resources(tenant_id,project_id,operation_id,instance_id,workspace_id,provider,kind,provider_id,generation,owner_id,status,deleted_at) VALUES($1,$2,$3,$4,$5,'kubernetes','PVC',$6,1,$5,'DELETED',clock_timestamp())")
        .bind(f.actor.tenant_id).bind(instance.project_id).bind(created.body.operation.id).bind(instance.id).bind(workspace).bind(Uuid::new_v4().to_string()).execute(&mut *tx).await?;
    tx.commit().await?;
    let recreated_pvc = request(
        &c,
        "persistentvolumeclaims",
        manifest(&a, &c, "persistentvolumeclaims"),
    );
    assert!(
        service.decide(&recreated_pvc).await.is_err(),
        "historical DELETED ledger cannot authorize a new empty workspace"
    );
    f.database
        .lifecycle_action(
            &f.actor,
            instance.id,
            InstanceAction::Stop,
            &sandbox_platform::model::StartRequest { ttl_seconds: None },
            "admission-stop",
            instance.spec_version,
            300,
            86400,
        )
        .await
        .map_err(api_failure)?;
    assert!(service.decide(&r).await.is_err());
    let pod = r.object.as_ref().unwrap();
    let pod_uid = Uuid::parse_str(pod["metadata"]["uid"].as_str().unwrap())?;
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE instances SET pod_uid=$2 WHERE id=$1")
        .bind(instance.id)
        .bind(pod_uid)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE grants SET enabled=false WHERE principal_id=$1")
        .bind(f.actor.principal_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE template_versions SET status='REVOKED' WHERE id=$1")
        .bind(f.request.template_version_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let mut stop = updated(r.clone());
    stop.operation = "DELETE".into();
    stop.object = None;
    stop.old_object.as_mut().unwrap()["spec"]["nodeName"] =
        json!("unavailable-node-must-not-block-stop");
    stop.options = Some(
        json!({"preconditions":{"uid":pod_uid,"resourceVersion":"17"},"gracePeriodSeconds":30}),
    );
    let decision = service.decide(&stop).await;
    assert!(
        decision.is_ok(),
        "accepted cleanup must survive grant/template revocation: {decision:?}"
    );
    // The independent termination controller can request normal deletion, but
    // cannot remove protection until the trusted ledger contains an exact proof.
    stop.user_info.username = c.termination.username.clone();
    stop.user_info.uid = c.termination.uid.clone();
    service
        .decide(&stop)
        .await
        .map_err(|e| anyhow::anyhow!("termination DELETE: {e:?}"))?;
    let mut deleting = stop.old_object.clone().unwrap();
    deleting["metadata"]["deletionTimestamp"] = json!("2026-10-03T00:00:00Z");
    let mut remove = updated(request(&c, "pods", deleting));
    remove.user_info = stop.user_info.clone();
    remove.object.as_mut().unwrap()["metadata"]["finalizers"] = json!([]);
    assert!(service.decide(&remove).await.is_err());
    let mut tx = f.owner_transaction().await?;
    let stop_id: Uuid = sqlx::query_scalar("SELECT active_operation_id FROM instances WHERE id=$1")
        .bind(instance.id)
        .fetch_one(&mut *tx)
        .await?;
    let lease: i64 = sqlx::query_scalar("UPDATE operations SET status='RUNNING',lease_owner='admission-proof-test',lease_until=clock_timestamp()+interval '1 minute',lease_token=lease_token+1 WHERE id=$1 RETURNING lease_token").bind(stop_id).fetch_one(&mut *tx).await?;
    let node = Uuid::new_v4();
    let permit = Uuid::new_v4();
    let challenge = Uuid::new_v4();
    sqlx::query("INSERT INTO runtime_nodes(id,cluster_epoch,node_uid,node_name,cloud_provider,cloud_account_id,region,cloud_instance_id,private_ip,profile_sha256,boot_id,enabled) VALUES($1,$2,$3,'unavailable-node-must-not-block-stop','alicloud','admission-test','test-region',$4,'10.0.0.11',$5,$6,true)")
        .bind(node).bind(epoch).bind(Uuid::new_v4()).bind(format!("test-{node}")).bind("a".repeat(64)).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO launch_permits(id,tenant_id,project_id,instance_id,workspace_id,operation_id,runtime_node_id,cluster_epoch,generation,launch_id,pod_uid,namespace,pod_name,pvc_uid,pv_uid,pv_name,csi_volume_handle,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'test-pv','test-disk',clock_timestamp()+interval '1 minute')")
        .bind(permit).bind(f.actor.tenant_id).bind(instance.project_id).bind(instance.id).bind(workspace).bind(created.body.operation.id).bind(node).bind(epoch).bind(generation).bind(launch).bind(pod_uid).bind(&namespace).bind(format!("sbx-ws-{workspace}")).bind(Uuid::new_v4()).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO termination_challenges(id,tenant_id,project_id,permit_id,operation_id,lease_token,reason,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,'STOP',clock_timestamp()-interval '1 second',clock_timestamp()+interval '20 seconds')")
        .bind(challenge).bind(f.actor.tenant_id).bind(instance.project_id).bind(permit).bind(stop_id).bind(lease).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO local_termination_proofs(tenant_id,project_id,challenge_id,permit_id,instance_id,workspace_id,generation,launch_id,pod_uid,cluster_epoch,runtime_node_id,journal_revision,evidence,evidence_sha256,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1,'{}',$12,clock_timestamp())")
        .bind(f.actor.tenant_id).bind(instance.project_id).bind(challenge).bind(permit).bind(instance.id).bind(workspace).bind(generation).bind(launch).bind(pod_uid).bind(epoch).bind(node).bind("b".repeat(64)).execute(&mut *tx).await?;
    tx.commit().await?;
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE runtime_nodes SET enabled=false WHERE id=$1")
        .bind(node)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let decision = service.decide(&remove).await;
    assert!(
        decision.is_ok(),
        "fresh exact trusted proof must permit finalizer removal even after node disablement: {decision:?}"
    );
    let mut wrong = remove.clone();
    wrong.old_object.as_mut().unwrap()["spec"]["nodeName"] = json!("other-node");
    wrong.object.as_mut().unwrap()["spec"]["nodeName"] = json!("other-node");
    assert!(service.decide(&wrong).await.is_err());
    wrong = remove.clone();
    wrong.user_info.username = c.worker.username.clone();
    wrong.user_info.uid = c.worker.uid.clone();
    assert!(service.decide(&wrong).await.is_err());
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET lease_token=lease_token+1 WHERE id=$1")
        .bind(stop_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    assert!(
        service.decide(&remove).await.is_err(),
        "old challenge cannot authorize a new lease owner"
    );
    let expired_challenge = Uuid::new_v4();
    let mut tx = f.owner_transaction().await?;
    sqlx::query("INSERT INTO termination_challenges(id,tenant_id,project_id,permit_id,operation_id,lease_token,reason,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,'STOP',clock_timestamp()-interval '20 seconds',clock_timestamp()-interval '10 seconds')")
        .bind(expired_challenge).bind(f.actor.tenant_id).bind(instance.project_id).bind(permit).bind(stop_id).bind(lease+1).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO local_termination_proofs(tenant_id,project_id,challenge_id,permit_id,instance_id,workspace_id,generation,launch_id,pod_uid,cluster_epoch,runtime_node_id,journal_revision,evidence,evidence_sha256,observed_at,recorded_at) SELECT tenant_id,project_id,$2,permit_id,instance_id,workspace_id,generation,launch_id,pod_uid,cluster_epoch,runtime_node_id,journal_revision,evidence,evidence_sha256,clock_timestamp()-interval '15 seconds',clock_timestamp()-interval '15 seconds' FROM local_termination_proofs WHERE challenge_id=$1")
        .bind(challenge).bind(expired_challenge).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(
        service.decide(&remove).await.is_err(),
        "a proof for the current lease still requires an unexpired challenge"
    );
    let mut gc = stop.clone();
    gc.old_object = remove.object;
    controller(&mut gc, &c.pod_garbage_collectors[0]);
    let mut gc_status = gc.clone();
    gc_status.operation = "UPDATE".into();
    gc_status.sub_resource = "status".into();
    gc_status.object = gc_status.old_object.clone();
    gc_status.object.as_mut().unwrap()["status"] = json!({"phase":"Failed","conditions":[{"type":"DisruptionTarget","status":"True","reason":"DeletionByPodGC"}]});
    let decision = service.decide(&gc_status).await;
    assert!(
        decision.is_ok(),
        "proof allows GC status even when the old Node no longer exists: {decision:?}"
    );
    gc.options = Some(json!({"gracePeriodSeconds":0}));
    let decision = service.decide(&gc).await;
    assert!(
        decision.is_ok(),
        "historical exact proof must survive lease turnover for GC: {decision:?}"
    );
    assert!(
        sqlx::query("UPDATE local_termination_proofs SET journal_revision=2")
            .execute(&service.database.pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("SELECT evidence FROM local_termination_proofs")
            .execute(&service.database.pool)
            .await
            .is_err(),
        "admission does not read raw host evidence"
    );
    // Seed the ledger's post-termination RESTART phase; the admission path must
    // classify it as new compute and recheck BOTH live privileges.
    let restart_id = Uuid::new_v4();
    let next_launch = Uuid::new_v4();
    let next_generation = generation + 1;
    let mut tx = f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET status='CANCELLED',completed_at=clock_timestamp(),lease_owner=NULL,lease_until=NULL WHERE id=$1").bind(stop_id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO operations(id,tenant_id,project_id,instance_id,workspace_id,kind,request,actor_principal_id,request_id,deadline,restart_generation) VALUES($1,$2,$3,$4,$5,'RESTART','{}',$6,$7,clock_timestamp()+interval '1 minute',$8)")
        .bind(restart_id).bind(f.actor.tenant_id).bind(instance.project_id).bind(instance.id).bind(workspace).bind(f.actor.principal_id).bind(Uuid::new_v4()).bind(next_generation).execute(&mut *tx).await?;
    sqlx::query("UPDATE instances SET desired_state='RUNNING',stop_reason=NULL,stop_accepted_at=NULL,pod_uid=NULL,runtime_generation=$2,launch_id=$3,active_operation_id=$4,slot_held=false,activity_id=NULL,activity_kind=NULL,activity_generation=NULL WHERE id=$1")
        .bind(instance.id).bind(next_generation).bind(next_launch).bind(restart_id).execute(&mut *tx).await?;
    // Revocation is intentionally irreversible. Use a newly approved immutable
    // version with the same image for this separately seeded admission scenario.
    let replacement_template = Uuid::new_v4();
    sqlx::query("INSERT INTO template_versions(id,tenant_id,name,version,image_ref,image_digest,runner_version,status) SELECT $2,tenant_id,name,version+1,image_ref,image_digest,runner_version,'APPROVED' FROM template_versions WHERE id=$1")
        .bind(f.request.template_version_id).bind(replacement_template).execute(&mut *tx).await?;
    sqlx::query("UPDATE instances SET template_version_id=$2 WHERE id=$1")
        .bind(instance.id)
        .bind(replacement_template)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE grants SET enabled=true WHERE principal_id=$1")
        .bind(f.actor.principal_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    a.context.generation = next_generation;
    a.context.launch_id = next_launch;
    let restart = request(&c, "pods", manifest(&a, &c, "pods"));
    let decision = service.decide(&restart).await;
    assert!(
        decision.is_ok(),
        "new RESTART generation must be permitted with both scopes: {decision:?}"
    );
    let mut deleting_restart = updated(restart.clone());
    deleting_restart.operation = "DELETE".into();
    deleting_restart.object = None;
    deleting_restart.options = Some(
        json!({"preconditions":{"uid":restart.object.as_ref().unwrap()["metadata"]["uid"],"resourceVersion":"17"},"gracePeriodSeconds":30}),
    );
    assert!(
        service.decide(&deleting_restart).await.is_err(),
        "new restart generation is not a stop phase"
    );
    for scope in ["instances:restart", "instances:hard_stop"] {
        let mut tx = f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=false WHERE principal_id=$1 AND action=$2")
            .bind(f.actor.principal_id)
            .bind(scope)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        assert!(
            service.decide(&restart).await.is_err(),
            "restart must recheck {scope}"
        );
        let mut tx = f.owner_transaction().await?;
        sqlx::query("UPDATE grants SET enabled=true WHERE principal_id=$1 AND action=$2")
            .bind(f.actor.principal_id)
            .bind(scope)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM instances")
        .fetch_one(&service.database.pool)
        .await?;
    assert_eq!(count, 0, "admission role must not bypass tenant RLS");
    service.database.pool.close().await;
    Ok(())
}

fn exec_request(
    config: &AdmissionConfig,
    context: &RuntimeManifestContext,
    execution: Uuid,
    attempt: Uuid,
) -> AdmissionRequest {
    serde_json::from_value(json!({"uid":Uuid::new_v4(),"resource":{"group":"","version":"v1","resource":"pods"},"subResource":"exec","operation":"CONNECT","namespace":context.namespace,"name":format!("sbx-ws-{}",context.workspace_id),"userInfo":{"username":config.gateway.username,"uid":config.gateway.uid},"object":{"apiVersion":"v1","kind":"PodExecOptions","container":format!("workload-{}",context.launch_id),"command":["/usr/local/bin/sandbox-runner","exec","--execution-id",execution,"--dispatch-attempt-id",attempt],"stdin":true,"stdout":true,"stderr":true,"tty":false}})).unwrap()
}
#[test]
fn execution_connect_rejects_shell_tty_wrong_identity_and_dry_run() {
    let c = config();
    let a = authority();
    let execution = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let request = exec_request(&c, &a.context, execution, attempt);
    assert_eq!(
        execution_connect_identity(&request, &c).unwrap(),
        (execution, attempt)
    );
    for pointer in ["/stdin", "/stdout", "/stderr"] {
        let mut bad = request.clone();
        set_pointer(bad.object.as_mut().unwrap(), pointer, json!(false));
        assert!(execution_connect_identity(&bad, &c).is_err());
    }
    let mut bad = request.clone();
    bad.object.as_mut().unwrap()["tty"] = json!(true);
    assert!(execution_connect_identity(&bad, &c).is_err());
    let mut bad = request.clone();
    bad.object.as_mut().unwrap()["command"] = json!(["sh", "-c", "arbitrary code"]);
    assert!(execution_connect_identity(&bad, &c).is_err());
    let mut bad = request.clone();
    bad.object.as_mut().unwrap()["command"][3] = json!(Uuid::nil());
    assert!(execution_connect_identity(&bad, &c).is_err());
    let mut bad = request.clone();
    bad.user_info.uid = Uuid::new_v4().to_string();
    assert!(execution_connect_identity(&bad, &c).is_err());
    let mut bad = request.clone();
    bad.user_info.username = c.worker.username.clone();
    bad.user_info.uid = c.worker.uid.clone();
    assert!(execution_connect_identity(&bad, &c).is_err());
    let mut bad = request.clone();
    bad.dry_run = true;
    assert!(execution_connect_identity(&bad, &c).is_err());
    for subresource in ["attach", "portforward"] {
        let mut bad = request.clone();
        bad.sub_resource = subresource.into();
        assert!(execution_connect_identity(&bad, &c).is_err());
    }
}

#[test]
fn file_connection_has_a_distinct_single_use_protocol_identity() {
    use sandbox_platform::admission::file_transfer_connect_identity;
    let c = config();
    let a = authority();
    let transfer = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let mut request = exec_request(&c, &a.context, transfer, attempt);
    request.object.as_mut().unwrap()["command"][1] = json!("file-transfer");
    request.object.as_mut().unwrap()["command"][2] = json!("--transfer-id");
    assert_eq!(
        file_transfer_connect_identity(&request, &c).unwrap(),
        (transfer, attempt)
    );
    assert!(execution_connect_identity(&request, &c).is_err());
    let mut mismatched = request.clone();
    mismatched.object.as_mut().unwrap()["command"][2] = json!("--execution-id");
    assert!(file_transfer_connect_identity(&mismatched, &c).is_err());
    let mut tty = request.clone();
    tty.object.as_mut().unwrap()["tty"] = json!(true);
    assert!(file_transfer_connect_identity(&tty, &c).is_err());
    let mut unauthorized = request.clone();
    unauthorized.user_info.uid = c.worker.uid.clone();
    assert!(file_transfer_connect_identity(&unauthorized, &c).is_err());
    let mut dry = request.clone();
    dry.dry_run = true;
    assert!(file_transfer_connect_identity(&dry, &c).is_err());
    let mut nil = request;
    nil.object.as_mut().unwrap()["command"][3] = json!(Uuid::nil());
    assert!(file_transfer_connect_identity(&nil, &c).is_err());
}

struct ExecutionConnectFixture {
    f: Fixture,
    service: Arc<AdmissionService>,
    request: AdmissionRequest,
    execution: Uuid,
    attempt: Uuid,
    operation: Uuid,
}
impl ExecutionConnectFixture {
    async fn new() -> anyhow::Result<Self> {
        Self::with_certification(chrono::Utc::now() + chrono::Duration::days(2)).await
    }
    async fn with_certification(
        certified_until: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<Self> {
        let mut f = Fixture::new(5).await?;
        let admission_url = std::env::var("TEST_ADMISSION_DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("TEST_ADMISSION_DATABASE_URL is required"))?;
        let gateway_url = std::env::var("TEST_GATEWAY_DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("TEST_GATEWAY_DATABASE_URL is required"))?;
        let expected = url::Url::parse(&std::env::var("TEST_DATABASE_URL")?)?;
        for (value, user) in [
            (&admission_url, "sandbox_admission"),
            (&gateway_url, "sandbox_gateway"),
        ] {
            let target = url::Url::parse(value)?;
            anyhow::ensure!(
                target.username() == user
                    && target.host_str() == expected.host_str()
                    && target.port_or_known_default() == expected.port_or_known_default()
                    && target.path() == expected.path()
                    && target.path().ends_with("_test"),
                "CONNECT tests require dedicated roles on the same disposable database"
            );
        }
        sqlx::raw_sql(include_str!("../scripts/sql/admission-role.sql"))
            .execute(&f.owner)
            .await?;
        sqlx::raw_sql(include_str!("../scripts/sql/gateway-role.sql"))
            .execute(&f.owner)
            .await?;
        let policy = Uuid::new_v4();
        let mut tx = f.owner_transaction().await?;
        sqlx::query("INSERT INTO security_policy_versions(id,tenant_id,name,version,status,rules) VALUES($1,$2,'connect-deny-all',1,'APPROVED',$3)").bind(policy).bind(f.actor.tenant_id).bind(json!({"profile":"deny-all","dns":true})).execute(&mut *tx).await?;
        tx.commit().await?;
        f.request.security_profile_id = policy;
        let created = f.create("connect-runtime").await.map_err(api_failure)?;
        let instance = created.body.resource;
        f.seed_observed_state(instance.id, "RUNNING").await?;
        let mut tx = f.owner_transaction().await?;
        sqlx::query("INSERT INTO grants(tenant_id,project_id,principal_id,action) VALUES($1,$2,$3,'executions:create')").bind(f.actor.tenant_id).bind(instance.project_id).bind(f.actor.principal_id).execute(&mut *tx).await?;
        for project in [None, Some(instance.project_id)] {
            sqlx::query("INSERT INTO quota_accounts(tenant_id,project_id,dimension,limit_value) VALUES($1,$2,'EXECUTIONS',5)").bind(f.actor.tenant_id).bind(project).execute(&mut *tx).await?;
        }
        let pod_uid = Uuid::new_v4();
        let pvc_uid = Uuid::new_v4();
        let policy_uid = Uuid::new_v4();
        // Owner-seeded prerequisites model a verified runtime. Actual Kubernetes
        // transport below is controlled test data, never cloud evidence.
        sqlx::query("UPDATE instances SET pod_uid=$2,ready_generation=runtime_generation,ready_launch_id=launch_id,ready_pod_uid=$2,ready_cluster_epoch=cluster_epoch,ready_observed_at=clock_timestamp() WHERE id=$1").bind(instance.id).bind(pod_uid).execute(&mut *tx).await?;
        let (namespace,epoch,launch,generation):(String,Uuid,Uuid,i64)=sqlx::query_as("SELECT namespace,cluster_epoch,launch_id,runtime_generation FROM instances WHERE id=$1").bind(instance.id).fetch_one(&mut *tx).await?;
        for (kind, uid, owner) in [
            ("POD", pod_uid, instance.id),
            ("PVC", pvc_uid, instance.workspace_id),
            ("CILIUM_POLICY", policy_uid, instance.id),
        ] {
            sqlx::query("INSERT INTO external_resources(tenant_id,project_id,operation_id,instance_id,workspace_id,provider,kind,provider_id,generation,owner_id,status) VALUES($1,$2,$3,$4,$5,'kubernetes',$6,$7,1,$8,'ACTIVE')").bind(f.actor.tenant_id).bind(instance.project_id).bind(created.body.operation.id).bind(instance.id).bind(instance.workspace_id).bind(kind).bind(uid.to_string()).bind(owner).execute(&mut *tx).await?;
        }
        let (image, digest): (String, String) =
            sqlx::query_as("SELECT image_ref,image_digest FROM template_versions WHERE id=$1")
                .bind(f.request.template_version_id)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        f.seed_test_launch_certification(instance.id, certified_until)
            .await?;
        let command: sandbox_platform::model::CreateExecution = serde_json::from_value(
            json!({"argv":["/usr/bin/true"],"public_env":{},"cwd":"/workspace","timeout_seconds":60,"on_timeout":"HARD_STOP_INSTANCE","output_limit_bytes":1024,"client_reference":null}),
        )?;
        let accepted = f
            .database
            .create_execution(
                &f.actor,
                instance.id,
                &command,
                "connect-execution",
                instance.spec_version,
            )
            .await
            .map_err(api_failure)?;
        let execution = accepted.body.resource.id;
        let operation = accepted.body.operation.id;
        let mut tx = f.owner_transaction().await?;
        sqlx::query("UPDATE operations SET status='RUNNING',lease_owner='admission-test-gateway',lease_token=7,lease_until=clock_timestamp()+interval '30 seconds' WHERE id=$1").bind(operation).execute(&mut *tx).await?;
        tx.commit().await?;
        let gateway = Database::connect(&gateway_url, 4).await?;
        gateway.verify_runtime_role().await?;
        let engine = sandbox_platform::engine::OperationEngine::new(
            gateway.clone(),
            "admission-test-gateway".into(),
        )?;
        let prepared = gateway
            .begin_execution_dispatch(
                &engine,
                &sandbox_platform::engine::Claim {
                    tenant_id: f.actor.tenant_id,
                    operation_id: operation,
                    lease_token: 7,
                },
                execution,
                sandbox_platform::execution::DispatchIdentity {
                    runtime_generation: generation,
                    launch_id: launch,
                    pod_uid,
                    cluster_epoch: epoch,
                },
            )
            .await
            .map_err(api_failure)?;
        gateway.pool.close().await;
        let c = config();
        let mut a = authority();
        a.context.tenant_id = f.actor.tenant_id;
        a.context.project_id = instance.project_id;
        a.context.instance_id = instance.id;
        a.context.workspace_id = instance.workspace_id;
        a.context.launch_id = launch;
        a.context.cluster_epoch = epoch;
        a.context.generation = generation;
        a.context.namespace = namespace.clone();
        a.context.storage_class = "integration-storage".into();
        a.context.image_ref = image;
        a.context.image_digest = digest;
        a.context.cpu_millis = instance.cpu_millis;
        a.context.memory_mib = instance.memory_mib;
        a.context.workspace_size_gib = f.request.workspace.size_gib;
        let mut pod = manifest(&a, &c, "pods");
        pod["metadata"]["uid"] = json!(pod_uid);
        pod["spec"]["nodeName"] = json!("kata-ready");
        pod["status"] = json!({"phase":"Running","conditions":[{"type":"Ready","status":"True"}],"containerStatuses":[{"name":format!("workload-{launch}"),"ready":true,"restartCount":0,"image":"test","imageID":"test","state":{"running":{}}}]});
        let mut pvc = manifest(&a, &c, "persistentvolumeclaims");
        pvc["metadata"]["uid"] = json!(pvc_uid);
        pvc["status"] = json!({"phase":"Bound"});
        let mut policy = manifest(&a, &c, "ciliumnetworkpolicies");
        policy["metadata"]["uid"] = json!(policy_uid);
        let namespace_value = json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":namespace,"uid":Uuid::new_v4(),"labels":{"sandbox.platform/managed":"true","sandbox.platform/tenant-id":f.actor.tenant_id,"sandbox.platform/project-id":instance.project_id,"sandbox.platform/cluster-epoch":epoch},"annotations":{"sandbox.platform/certification-id":c.certification_id}}});
        let objects = std::collections::BTreeMap::from([
            (format!("/api/v1/namespaces/{namespace}"), namespace_value),
            (
                format!(
                    "/api/v1/namespaces/{namespace}/pods/{}",
                    pod["metadata"]["name"].as_str().unwrap()
                ),
                pod,
            ),
            (
                format!(
                    "/api/v1/namespaces/{namespace}/persistentvolumeclaims/{}",
                    pvc["metadata"]["name"].as_str().unwrap()
                ),
                pvc,
            ),
            (
                format!(
                    "/apis/cilium.io/v2/namespaces/{namespace}/ciliumnetworkpolicies/{}",
                    policy["metadata"]["name"].as_str().unwrap()
                ),
                policy,
            ),
            (
                "/api/v1/nodes/kata-ready".into(),
                json!({"apiVersion":"v1","kind":"Node","metadata":{"name":"kata-ready","uid":Uuid::new_v4(),"labels":{"sandbox.platform/worker-pool":"kata"}},"status":{"conditions":[{"type":"Ready","status":"True"}]}}),
            ),
        ]);
        let service_fn = tower::service_fn(move |request: Request<KubeBody>| {
            let found = objects.get(request.uri().path()).cloned();
            async move {
                Ok::<_,Infallible>(Response::builder().status(if found.is_some(){200}else{404}).body(Body::from(serde_json::to_vec(&found.unwrap_or(json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}))).unwrap())).unwrap())
            }
        });
        let database = Database::connect(&admission_url, 8).await?;
        database.verify_runtime_role().await?;
        let request = exec_request(&c, &a.context, execution, prepared.dispatch_attempt_id);
        Ok(Self {
            f,
            service: Arc::new(AdmissionService {
                database,
                kubernetes: Client::new(service_fn, "default"),
                config: c,
            }),
            request,
            execution,
            attempt: prepared.dispatch_attempt_id,
            operation,
        })
    }
    async fn admitted(&self, review: Uuid) -> anyhow::Result<bool> {
        Ok(
            sqlx::query_scalar("SELECT sandbox_admit_execution_connect($1,$2,$3,$4)")
                .bind(self.f.actor.tenant_id)
                .bind(self.execution)
                .bind(self.attempt)
                .bind(review)
                .fetch_one(&self.service.database.pool)
                .await?,
        )
    }
}

#[tokio::test]
#[ignore = "requires real PostgreSQL and separate admission/gateway roles"]
async fn connect_consumption_is_durable_exact_once_and_cannot_be_used_by_other_roles()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let fixture = ExecutionConnectFixture::new().await?;
    let mut bad = fixture.request.clone();
    bad.dry_run = true;
    assert!(fixture.service.decide(&bad).await.is_err());
    bad = fixture.request.clone();
    bad.object.as_mut().unwrap()["container"] = json!("wrong-launch");
    assert!(fixture.service.decide(&bad).await.is_err());
    let mut tx = fixture.f.owner_transaction().await?;
    let unused:bool=sqlx::query_scalar("SELECT exec_admission_uid IS NULL AND exec_admitted_at IS NULL FROM executions WHERE id=$1").bind(fixture.execution).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    assert!(
        unused,
        "dry-run and wrong-container rejection must not consume admission"
    );
    let allowed = fixture.service.decide(&fixture.request).await;
    assert!(
        allowed.is_ok(),
        "current trusted CONNECT should be admitted: {allowed:?}"
    );
    assert!(
        fixture.service.decide(&fixture.request).await.is_ok(),
        "same server-assigned review UID may retry"
    );
    let mut second = fixture.request.clone();
    second.uid = Uuid::new_v4().to_string();
    assert!(fixture.service.decide(&second).await.is_err());
    let denied = sqlx::query("SELECT sandbox_admit_execution_connect($1,$2,$3,$4)")
        .bind(fixture.f.actor.tenant_id)
        .bind(fixture.execution)
        .bind(fixture.attempt)
        .bind(Uuid::new_v4())
        .execute(&fixture.f.database.pool)
        .await;
    assert!(
        denied.is_err(),
        "public API must not call admission's definer function"
    );
    let mut tx = fixture
        .service
        .database
        .begin(fixture.f.actor.tenant_id)
        .await
        .map_err(api_failure)?;
    assert!(
        sqlx::query(
            "UPDATE executions SET exec_admission_uid=NULL,exec_admitted_at=NULL WHERE id=$1"
        )
        .bind(fixture.execution)
        .execute(&mut *tx)
        .await
        .is_err()
    );
    tx.rollback().await?;
    let mut tx = fixture.f.owner_transaction().await?;
    sqlx::query(
        "UPDATE grants SET enabled=false WHERE principal_id=$1 AND action='instances:hard_stop'",
    )
    .bind(fixture.f.actor.principal_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    assert!(
        !fixture
            .admitted(Uuid::parse_str(&fixture.request.uid)?)
            .await?,
        "even same-review replay must recheck revocation"
    );
    let other = ExecutionConnectFixture::new().await?;
    let mut jobs = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let pool = other.service.database.pool.clone();
        let tenant = other.f.actor.tenant_id;
        let execution = other.execution;
        let attempt = other.attempt;
        jobs.spawn(async move {
            let uid = Uuid::new_v4();
            let admitted: bool =
                sqlx::query_scalar("SELECT sandbox_admit_execution_connect($1,$2,$3,$4)")
                    .bind(tenant)
                    .bind(execution)
                    .bind(attempt)
                    .bind(uid)
                    .fetch_one(&pool)
                    .await?;
            Ok::<_, sqlx::Error>((uid, admitted))
        });
    }
    let mut winners = Vec::new();
    while let Some(result) = jobs.join_next().await {
        let (uid, admitted) = result??;
        if admitted {
            winners.push(uid);
        }
    }
    assert_eq!(
        winners.len(),
        1,
        "distinct concurrent API requests must consume only once"
    );
    assert!(other.admitted(winners[0]).await?);
    let current: Option<String> =
        sqlx::query_scalar("SELECT nullif(current_setting('app.tenant_id',true),'')")
            .fetch_one(&other.service.database.pool)
            .await?;
    assert!(
        current.is_none(),
        "definer must restore pooled tenant context"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL and separate admission/gateway roles"]
async fn stale_gateway_lease_and_wrong_current_launch_cannot_consume_connect() -> anyhow::Result<()>
{
    let _serial = support::serial().await;
    let fixture = ExecutionConnectFixture::new().await?;
    let review = Uuid::new_v4();
    let mut tx = fixture.f.owner_transaction().await?;
    sqlx::query("UPDATE operations SET lease_token=lease_token+1 WHERE id=$1")
        .bind(fixture.operation)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    assert!(
        !fixture.admitted(review).await?,
        "a replacement claim cannot authorize an old attempt"
    );
    let other = ExecutionConnectFixture::new().await?;
    let mut tx = other.f.owner_transaction().await?;
    sqlx::query(
        "UPDATE instances SET pod_uid=$2 WHERE id=(SELECT instance_id FROM executions WHERE id=$1)",
    )
    .bind(other.execution)
    .bind(Uuid::new_v4())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    assert!(
        !other.admitted(Uuid::new_v4()).await?,
        "execution must match the current Pod UID"
    );
    let empty: Option<Uuid> = sqlx::query_scalar(
        "SELECT exec_admission_uid FROM executions WHERE tenant_id=$1 AND id=$2",
    )
    .bind(other.f.actor.tenant_id)
    .bind(other.execution)
    .fetch_one(&mut *other.f.owner_transaction().await?)
    .await?;
    assert!(empty.is_none());
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL and separate admission/gateway roles"]
async fn connect_requires_current_certification_covering_the_whole_lease() -> anyhow::Result<()> {
    let _serial = support::serial().await;
    for horizon in [
        chrono::Utc::now() - chrono::Duration::days(1),
        chrono::Utc::now() + chrono::Duration::seconds(30),
    ] {
        let fixture = ExecutionConnectFixture::with_certification(horizon).await?;
        let review = Uuid::parse_str(&fixture.request.uid)?;
        assert!(
            !fixture.admitted(review).await?,
            "old Ready cannot authorize work with an expired or too-short review"
        );
        let mut tx = fixture.f.owner_transaction().await?;
        let unused: bool =
            sqlx::query_scalar("SELECT exec_admission_uid IS NULL FROM executions WHERE id=$1")
                .bind(fixture.execution)
                .fetch_one(&mut *tx)
                .await?;
        assert!(unused);
        let node:Uuid=sqlx::query_scalar("SELECT p.runtime_node_id FROM launch_permits p JOIN executions e ON e.tenant_id=p.tenant_id AND e.instance_id=p.instance_id WHERE e.id=$1").bind(fixture.execution).fetch_one(&mut *tx).await?;
        support::seed_test_node_certification(
            &mut tx,
            node,
            chrono::Utc::now() + chrono::Duration::days(2),
        )
        .await?;
        tx.commit().await?;
        assert!(
            fixture.admitted(review).await?,
            "append-only operator renewal restores authorization without rewriting the launch"
        );
    }
    Ok(())
}
