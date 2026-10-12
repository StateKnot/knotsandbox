#![allow(clippy::unwrap_used)]
use super::*;
use serde_json::{Value, json};

fn inputs() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let node = crate::termination_client::test_support::node();
    let a = json!({"protocol":1,"node":node,"cloud_account_id":"1234567890123456","region":"cn-hangzhou","cloud_instance_id":"i-testnode","private_ip":"10.0.0.8","guard_port":9444,"certification_id":"cert-test-enrollment"});
    let terraform = json!({"deployment_identity":{"sensitive":false,"type":"object","value":{"cloud_account_id":"1234567890123456","region":"cn-hangzhou","deployment":"test-deploy","environment":"preproduction"}},"node_inventory":{"sensitive":false,"type":"object","value":{node.node_name.clone():{"id":"i-testnode","private_ip":"10.0.0.8","role":"kata","zone":"cn-hangzhou-h"}}}});
    let checks: BTreeMap<_, _> = CERTIFICATION_CHECKS
        .iter()
        .map(|key| {
            (
                *key,
                json!({"status":"PASS","evidence_sha256":"d".repeat(64)}),
            )
        })
        .collect();
    let versions = digest(include_bytes!("../deploy/cluster/versions.lock.json"));
    let report = json!({"protocol":1,"certification_id":"cert-test-enrollment","cluster_epoch":node.cluster_epoch,"versions_lock_sha256":versions,"nodeguard_binary_sha256":"b".repeat(64),"reviewed_at":Utc::now()-chrono::Duration::minutes(1),"expires_at":Utc::now()+chrono::Duration::days(1),"nodes":[{"node":node,"cloud_instance_id":"i-testnode","private_ip":"10.0.0.8"}],"checks":checks});
    let report = serde_json::to_vec(&report).unwrap();
    let settings = json!({"deployment":"test-deploy","region":"cn-hangzhou","oidc_provider_arn":"acs:ram::1234567890123456:oidc-provider/test-deploy-kubernetes","cluster_epoch":node.cluster_epoch,"certification_id":"cert-test-enrollment","certification_report_sha256":digest(&report),"nodeguard_binary_sha256":"b".repeat(64),"versions_lock_sha256":versions});
    (
        serde_json::to_vec(&a).unwrap(),
        serde_json::to_vec(&terraform).unwrap(),
        serde_json::to_vec(&settings).unwrap(),
        report,
    )
}
fn encode(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn plan(inputs: &(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)) -> anyhow::Result<EnrollmentPlan> {
    EnrollmentPlan::parse(&inputs.0, &inputs.1, &inputs.2, &inputs.3, Utc::now())
}

#[test]
fn exact_reviewed_inventory_is_required_and_report_hash_is_not_a_boolean_override() {
    let source = inputs();
    assert!(plan(&source).is_ok());
    for (field, value) in [
        ("private_ip", json!("8.8.8.8")),
        ("guard_port", json!(443)),
        ("cloud_account_id", json!("9999999999999999")),
        ("cloud_instance_id", json!("i-other")),
        ("certification_id", json!("other-cert")),
    ] {
        let mut i = source.clone();
        let mut a: Value = serde_json::from_slice(&i.0).unwrap();
        a[field] = value;
        i.0 = encode(&a);
        assert!(plan(&i).is_err(), "{field}");
    }
    let mut i = source.clone();
    let mut r: Value = serde_json::from_slice(&i.3).unwrap();
    r["checks"]["workspace_single_writer"]["status"] = json!("PENDING");
    i.3 = encode(&r);
    assert!(plan(&i).is_err());
    // Changing both mutually-consistent cloud fields must still fail the
    // independent account anchor retained in the reviewed OIDC provider ARN.
    let mut other_account = source.clone();
    let mut a: Value = serde_json::from_slice(&other_account.0).unwrap();
    let mut tf: Value = serde_json::from_slice(&other_account.1).unwrap();
    a["cloud_account_id"] = json!("9999999999999999");
    tf["deployment_identity"]["value"]["cloud_account_id"] = a["cloud_account_id"].clone();
    other_account.0 = encode(&a);
    other_account.1 = encode(&tf);
    assert!(plan(&other_account).is_err());
    // Re-pinning cannot make a failed check acceptable.
    let mut s: Value = serde_json::from_slice(&i.2).unwrap();
    s["certification_report_sha256"] = json!(digest(&i.3));
    i.2 = encode(&s);
    assert!(plan(&i).is_err());
    assert!(
        EnrollmentPlan::parse(
            &vec![b' '; MAX_ENROLLMENT_BYTES + 1],
            &source.1,
            &source.2,
            &source.3,
            Utc::now()
        )
        .is_err()
    );
}

#[test]
fn duplicate_nodes_expired_review_and_epoch_or_profile_changes_are_rejected() {
    for change in [
        "duplicate",
        "expired",
        "future",
        "profile",
        "epoch",
        "version",
    ] {
        let mut i = inputs();
        let mut r: Value = serde_json::from_slice(&i.3).unwrap();
        match change {
            "duplicate" => {
                let n = r["nodes"][0].clone();
                r["nodes"].as_array_mut().unwrap().push(n);
            }
            "expired" => r["expires_at"] = json!(Utc::now() - chrono::Duration::seconds(1)),
            "future" => r["reviewed_at"] = json!(Utc::now() + chrono::Duration::hours(1)),
            "profile" => r["nodes"][0]["node"]["profile_sha256"] = json!("e".repeat(64)),
            "epoch" => r["cluster_epoch"] = json!(Uuid::new_v4()),
            "version" => r["versions_lock_sha256"] = json!("f".repeat(64)),
            _ => unreachable!(),
        }
        i.3 = encode(&r);
        let mut s: Value = serde_json::from_slice(&i.2).unwrap();
        s["certification_report_sha256"] = json!(digest(&i.3));
        i.2 = encode(&s);
        assert!(plan(&i).is_err(), "{change}");
    }
}

fn live_node(a: &EnrollmentArtifact) -> Node {
    serde_json::from_value(json!({"apiVersion":"v1","kind":"Node","metadata":{"name":a.node.node_name,"uid":a.node.node_uid,"resourceVersion":"77","labels":{"sandbox.platform/worker-pool":"kata"},"annotations":{"sandbox.platform/runtime-profile-sha256":a.node.profile_sha256}},"spec":{"taints":[{"key":"sandbox.platform/untrusted","value":"true","effect":"NoSchedule"},{"key":"sandbox.platform/unverified","value":"true","effect":"NoSchedule"}]},"status":{"nodeInfo":{"architecture":"amd64","operatingSystem":"linux","bootID":a.node.boot_id,"containerRuntimeVersion":"containerd://2.3.5","kernelVersion":"test","kubeProxyVersion":"","kubeletVersion":"v1.36.4","machineID":"test","osImage":"test","systemUUID":"test"},"addresses":[{"type":"InternalIP","address":a.private_ip}],"conditions":[{"type":"Ready","status":"True"}]}})).unwrap()
}
#[test]
fn live_node_requires_quarantine_boot_profile_private_ip_and_stable_uid() {
    let p = plan(&inputs()).unwrap();
    let valid = live_node(&p.artifact);
    assert!(validate_live_node(&valid, &p.artifact, false).is_ok());
    let mut serving = valid.clone();
    serving
        .spec
        .as_mut()
        .unwrap()
        .taints
        .as_mut()
        .unwrap()
        .retain(|taint| taint.key != "sandbox.platform/unverified");
    assert!(validate_live_node(&serving, &p.artifact, false).is_err());
    assert!(validate_live_node(&serving, &p.artifact, true).is_ok());
    for key in ["uid", "boot", "profile", "address", "quarantine", "ready"] {
        let mut n = valid.clone();
        match key {
            "uid" => n.metadata.uid = Some(Uuid::new_v4().to_string()),
            "boot" => {
                n.status
                    .as_mut()
                    .unwrap()
                    .node_info
                    .as_mut()
                    .unwrap()
                    .boot_id = Uuid::new_v4().to_string()
            }
            "profile" => {
                n.metadata.annotations.as_mut().unwrap().insert(
                    "sandbox.platform/runtime-profile-sha256".into(),
                    "e".repeat(64),
                );
            }
            "address" => n.status.as_mut().unwrap().addresses = None,
            "quarantine" => n.spec.as_mut().unwrap().taints = None,
            "ready" => n.status.as_mut().unwrap().conditions = None,
            _ => unreachable!(),
        }
        assert!(validate_live_node(&n, &p.artifact, false).is_err(), "{key}");
    }
}

fn fixture_runtime(node: Node, replacement: Option<Node>) -> KubernetesRuntime {
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    let count = Arc::new(AtomicUsize::new(0));
    let service = tower::service_fn(move |request: axum::http::Request<kube::client::Body>| {
        let call = count.fetch_add(1, Ordering::SeqCst);
        let node = if call > 0 {
            replacement.clone().unwrap_or_else(|| node.clone())
        } else {
            node.clone()
        };
        async move {
            assert_eq!(request.method(), "GET");
            assert_eq!(
                request.uri().path(),
                format!("/api/v1/nodes/{}", node.metadata.name.as_deref().unwrap())
            );
            Ok::<_, Infallible>(
                axum::http::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&node).unwrap()))
                    .unwrap(),
            )
        }
    });
    KubernetesRuntime::from_client(kube::Client::new(service, "default"))
}

#[tokio::test]
async fn enrollment_uses_actual_mtls_and_rechecks_node_after_authenticated_host_response()
-> anyhow::Result<()> {
    let p = plan(&inputs())?;
    let guard =
        crate::termination_client::test_support::FixtureGuard::start(p.artifact.node.clone())
            .await?;
    let node = live_node(&p.artifact);
    let runtime = fixture_runtime(node.clone(), None);
    let observed = observe_node(&runtime, &guard.client, &p.artifact, false).await?;
    assert_eq!(observed.resource_version, "77");
    let mut rebooted = node.clone();
    rebooted
        .status
        .as_mut()
        .unwrap()
        .node_info
        .as_mut()
        .unwrap()
        .boot_id = Uuid::new_v4().to_string();
    assert!(
        observe_node(
            &fixture_runtime(node, Some(rebooted)),
            &guard.client,
            &p.artifact,
            false
        )
        .await
        .is_err()
    );
    guard.shutdown().await?;
    Ok(())
}

use crate::test_support_db as support;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and real local mTLS socket"]
async fn real_owner_enrollment_is_atomic_idempotent_append_only_and_cannot_reactivate_or_replace()
-> anyhow::Result<()> {
    let _serial = support::serial().await;
    let f = support::Fixture::new(10).await?;
    let epoch: Uuid =
        sqlx::query_scalar("SELECT cluster_epoch FROM platform_configuration WHERE singleton")
            .fetch_one(&f.owner)
            .await?;
    let mut bytes = inputs();
    let mut artifact: Value = serde_json::from_slice(&bytes.0)?;
    artifact["node"]["cluster_epoch"] = json!(epoch);
    artifact["cloud_instance_id"] = json!(format!("i-enroll{}", Uuid::new_v4().simple()));
    bytes.0 = encode(&artifact);
    let mut report: Value = serde_json::from_slice(&bytes.3)?;
    report["cluster_epoch"] = json!(epoch);
    report["nodes"][0]["node"] = artifact["node"].clone();
    report["nodes"][0]["cloud_instance_id"] = artifact["cloud_instance_id"].clone();
    bytes.3 = encode(&report);
    let mut settings: Value = serde_json::from_slice(&bytes.2)?;
    settings["cluster_epoch"] = json!(epoch);
    settings["certification_report_sha256"] = json!(digest(&bytes.3));
    bytes.2 = encode(&settings);
    let mut terraform: Value = serde_json::from_slice(&bytes.1)?;
    let name = artifact["node"]["node_name"].as_str().unwrap().to_owned();
    terraform["node_inventory"]["value"][&name]["id"] = artifact["cloud_instance_id"].clone();
    bytes.1 = encode(&terraform);
    let p = plan(&bytes)?;
    // Earlier suites register synthetic identities using the public fixture SAN.
    // Quarantine those test-only rows without mutating immutable evidence.
    sqlx::query("UPDATE runtime_nodes SET enabled=false WHERE cluster_epoch=$1 AND (node_uid=$2 OR node_name=$3 OR private_ip='10.0.0.8')")
        .bind(epoch).bind(p.artifact.node.node_uid).bind(&p.artifact.node.node_name).execute(&f.owner).await?;
    let owner = Database {
        pool: f.owner.clone(),
    };
    let guard =
        crate::termination_client::test_support::FixtureGuard::start(p.artifact.node.clone())
            .await?;
    let runtime = fixture_runtime(live_node(&p.artifact), None);
    let credentials = crate::termination_client::test_support::credentials();
    assert!(
        enroll_node(&f.database, &runtime, &credentials, &p)
            .await
            .unwrap_err()
            .to_string()
            .contains("owner")
    );
    let observe = || observe_node(&runtime, &guard.client, &p.artifact, false);
    // The test-only loopback client does real mutual TLS; no public constructor
    // can turn arbitrary serialized identity data into a LiveEnrollment.
    let first = commit_enrollment(&owner, &p, observe().await?).await?;
    assert!(first.changed && first.enabled);
    let replay = commit_enrollment(&owner, &p, observe().await?).await?;
    assert!(!replay.changed && first.enrollment_id == replay.enrollment_id);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM runtime_node_enrollments WHERE runtime_node_id=$1",
    )
    .bind(first.runtime_node_id)
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(count, 1);
    for query in [
        "UPDATE runtime_node_enrollments SET receipt='{}' WHERE id=$1",
        "DELETE FROM runtime_node_enrollments WHERE id=$1",
    ] {
        assert!(
            sqlx::query(query)
                .bind(first.enrollment_id)
                .execute(&f.owner)
                .await
                .is_err()
        );
    }
    assert!(
        sqlx::query("SELECT * FROM runtime_node_enrollments")
            .fetch_all(&f.database.pool)
            .await
            .is_err()
    );
    let stale = LiveEnrollment {
        resource_version: "77".into(),
        observed_at: Utc::now() - chrono::Duration::seconds(11),
    };
    assert!(commit_enrollment(&owner, &p, stale).await.is_err());
    let mut changed = plan(&bytes)?;
    changed.settings_sha256 = "0".repeat(64);
    assert!(
        commit_enrollment(&owner, &changed, observe().await?)
            .await
            .is_err()
    );
    let mut renewed_bytes = bytes.clone();
    let mut review: Value = serde_json::from_slice(&renewed_bytes.3)?;
    review["reviewed_at"] = json!(Utc::now() - chrono::Duration::seconds(1));
    review["expires_at"] = json!(Utc::now() + chrono::Duration::days(2));
    renewed_bytes.3 = encode(&review);
    let mut settings: Value = serde_json::from_slice(&renewed_bytes.2)?;
    settings["certification_report_sha256"] = json!(digest(&renewed_bytes.3));
    renewed_bytes.2 = encode(&settings);
    let renewal = plan(&renewed_bytes)?;
    assert!(
        commit_enrollment(&owner, &renewal, observe().await?)
            .await
            .is_err()
    );
    let renewal = renewal.renewing_certification();
    let renewed = commit_enrollment(&owner, &renewal, observe().await?).await?;
    assert!(
        renewed.changed
            && renewed.runtime_node_id == first.runtime_node_id
            && renewed.enrollment_id != first.enrollment_id
    );
    assert!(
        !commit_enrollment(&owner, &renewal, observe().await?)
            .await?
            .changed
    );
    assert!(
        commit_enrollment(
            &owner,
            &plan(&bytes)?.renewing_certification(),
            observe().await?
        )
        .await
        .is_err()
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM runtime_node_enrollments WHERE runtime_node_id=$1",
    )
    .bind(first.runtime_node_id)
    .fetch_one(&f.owner)
    .await?;
    assert_eq!(count, 2);
    // A different boot cannot replace an enabled node, even with fresh evidence.
    let mut changed = plan(&bytes)?;
    changed.artifact.node.boot_id = Uuid::new_v4();
    let changed_guard =
        crate::termination_client::test_support::FixtureGuard::start(changed.artifact.node.clone())
            .await?;
    let changed_runtime = fixture_runtime(live_node(&changed.artifact), None);
    let new_boot = observe_node(
        &changed_runtime,
        &changed_guard.client,
        &changed.artifact,
        false,
    )
    .await?;
    assert!(commit_enrollment(&owner, &changed, new_boot).await.is_err());

    sqlx::query("UPDATE runtime_nodes SET enabled=false WHERE id=$1")
        .bind(first.runtime_node_id)
        .execute(&f.owner)
        .await?;
    assert!(
        commit_enrollment(&owner, &p, observe().await?)
            .await
            .unwrap_err()
            .to_string()
            .contains("reactivated")
    );
    let retired_boot = observe_node(
        &changed_runtime,
        &changed_guard.client,
        &changed.artifact,
        false,
    )
    .await?;
    assert!(
        commit_enrollment(&owner, &changed, retired_boot)
            .await
            .unwrap_err()
            .to_string()
            .contains("historical cloud instance")
    );
    changed_guard.shutdown().await?;
    guard.shutdown().await?;
    Ok(())
}
