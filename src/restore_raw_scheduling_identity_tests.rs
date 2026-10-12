//! PRIVATE observed identity drift. This child changes only the stateful
//! loopback apiserver's returned objects, preserving their metadata UID.
//! Enrollment, topology receipts, source facts and authorization are not seeded
//! or rewritten. It runs before the terminal ordinary claim replacement.
use super::*;

#[derive(Clone, Copy, Debug)]
enum Drift {
    Boot,
    Profile,
    Ready,
    Address,
    Zone,
    CsiOwner,
    CsiInstance,
    CsiKeys,
}
impl Drift {
    fn csi(self) -> bool {
        matches!(self, Self::CsiOwner | Self::CsiInstance | Self::CsiKeys)
    }
    fn denial(self) -> &'static str {
        match self {
            Self::Boot | Self::Profile => {
                "Live Node differs from registered boot or runtime profile"
            }
            Self::Ready => {
                "Observed restore security or resource identity differs from durable authority"
            }
            Self::Address => "Node OS or exact private address differs",
            Self::Zone => "Live Node topology differs from installation receipt",
            Self::CsiOwner => "CSINode must have the exact sole registered Node owner",
            Self::CsiInstance | Self::CsiKeys => {
                "CSI registration identity or exact topology keys differ"
            }
        }
    }
    fn change(self, original: &Value) -> anyhow::Result<Value> {
        let mut changed = original.clone();
        match self {
            Self::Boot => {
                let value = changed
                    .pointer_mut("/status/nodeInfo/bootID")
                    .context("actual observed boot field")?;
                *value = json!(Uuid::new_v4());
            }
            Self::Profile => {
                let value = changed
                    .pointer_mut("/metadata/annotations/sandbox.platform~1runtime-profile-sha256")
                    .context("actual observed runtime profile field")?;
                *value = json!(if *value == json!("f".repeat(64)) {
                    "e".repeat(64)
                } else {
                    "f".repeat(64)
                });
            }
            Self::Ready => {
                ensure!(
                    changed.pointer("/status/conditions/0/type") == Some(&json!("Ready"))
                        && changed.pointer("/status/conditions/0/status") == Some(&json!("True")),
                    "known first Ready condition is initially True"
                );
                changed["status"]["conditions"][0]["status"] = json!("False");
            }
            Self::Address => {
                ensure!(
                    changed.pointer("/status/addresses/0/type") == Some(&json!("InternalIP")),
                    "known first address is the registered private address"
                );
                let value = changed
                    .pointer_mut("/status/addresses/0/address")
                    .context("actual observed private address")?;
                *value = json!(if *value == json!("10.0.0.253") {
                    "10.0.0.252"
                } else {
                    "10.0.0.253"
                });
            }
            Self::Zone => {
                let value = changed
                    .pointer_mut("/metadata/labels/topology.kubernetes.io~1zone")
                    .context("actual observed zone label")?;
                *value = json!(if *value == json!("cn-hangzhou-c") {
                    "cn-hangzhou-b"
                } else {
                    "cn-hangzhou-c"
                });
            }
            Self::CsiOwner => {
                let value = changed
                    .pointer_mut("/metadata/ownerReferences/0/uid")
                    .context("actual observed sole CSI Node owner")?;
                *value = json!(Uuid::new_v4());
            }
            Self::CsiInstance => {
                ensure!(
                    changed.pointer("/spec/drivers/0/name") == Some(&json!(DRIVER)),
                    "known first CSI driver is the reviewed disk driver"
                );
                let value = changed
                    .pointer_mut("/spec/drivers/0/nodeID")
                    .context("actual observed CSI instance")?;
                *value = json!("i-differentSelectedObservation");
            }
            Self::CsiKeys => {
                ensure!(
                    changed.pointer("/spec/drivers/0/name") == Some(&json!(DRIVER)),
                    "known first CSI driver is the reviewed disk driver"
                );
                let keys = changed
                    .pointer_mut("/spec/drivers/0/topologyKeys")
                    .and_then(Value::as_array_mut)
                    .context("actual observed CSI topology keys")?;
                ensure!(
                    keys.len() == 4,
                    "installation has the exact four CSI topology keys"
                );
                keys.pop()
                    .context("remove one actual reviewed topology key")?;
            }
        }
        ensure!(
            changed != *original && changed["metadata"]["uid"] == original["metadata"]["uid"],
            "observed drift changes a protected field and preserves object UID"
        );
        Ok(changed)
    }
}

fn replace(case: &SelectedCase<'_>, path: &str, value: &Value) -> anyhow::Result<()> {
    let mut objects = case
        .w
        .objects
        .lock()
        .map_err(|_| anyhow::anyhow!("identity observation objects"))?;
    let target = objects
        .get_mut(path)
        .context("registered observation exists")?;
    *target = value.clone();
    Ok(())
}

// Heartbeat legitimately updates the ordinary operation lease. All durable
// source/hold/quota facts are already compared by SelectedCase::put; this adds
// the current platform and registered node identities without comparing mutable
// heartbeat timestamps or rewinding a principal revision changed by v8.
async fn platform_facts(case: &SelectedCase<'_>) -> anyhow::Result<Value> {
    let mut tx = case.source.f.base.f.owner_transaction().await?;
    let value = sqlx::query_scalar(
        "SELECT jsonb_build_object('configuration',(SELECT to_jsonb(c) FROM platform_configuration c WHERE singleton),'tenant',(SELECT to_jsonb(t) FROM tenants t WHERE t.id=$1),'principal',(SELECT to_jsonb(p) FROM operations o JOIN principals p ON p.id=o.actor_principal_id WHERE o.tenant_id=$1 AND o.id=$2),'projects',COALESCE((SELECT jsonb_agg(to_jsonb(p) ORDER BY p.id) FROM projects p WHERE p.tenant_id=$1),'[]'::jsonb),'grants',COALESCE((SELECT jsonb_agg(to_jsonb(g) ORDER BY g.id) FROM grants g WHERE g.tenant_id=$1),'[]'::jsonb),'template',(SELECT to_jsonb(t) FROM instances i JOIN template_versions t ON t.tenant_id=i.tenant_id AND t.id=i.template_version_id WHERE i.tenant_id=$1 AND i.id=$5),'security',(SELECT to_jsonb(s) FROM instances i JOIN security_policy_versions s ON s.tenant_id=i.tenant_id AND s.id=i.security_policy_version_id WHERE i.tenant_id=$1 AND i.id=$5),'profile',(SELECT to_jsonb(p) FROM backup_profiles p WHERE p.id=$3),'restore_certification',(SELECT to_jsonb(c) FROM restore_profile_certifications c WHERE c.profile_id=$3 AND c.cluster_epoch=$4),'nodes',COALESCE((SELECT jsonb_agg(to_jsonb(n) ORDER BY n.id) FROM runtime_nodes n WHERE n.cluster_epoch=$4),'[]'::jsonb),'enrollments',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY e.id) FROM runtime_node_enrollments e WHERE e.cluster_epoch=$4),'[]'::jsonb),'topology',COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY t.id) FROM restore_node_topology_receipts t WHERE t.restore_profile_id=$3),'[]'::jsonb))",
    )
    .bind(case.t)
    .bind(case.job.record.operation_id)
    .bind(case.job.record.profile_id)
    .bind(case.job.record.cluster_epoch)
    .bind(case.job.record.instance_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(value)
}

fn target_counts(
    case: &SelectedCase<'_>,
    node_path: &str,
    csi_path: &str,
    drift: Drift,
    second: bool,
) -> anyhow::Result<()> {
    let expected = match (drift.csi(), second) {
        (false, false) => (1, 0),
        (true, false) => (1, 1),
        (false, true) => (2, 1),
        (true, true) => (2, 2),
    };
    ensure!(
        case.w.reads(node_path)? == expected.0 && case.w.reads(csi_path)? == expected.1,
        "observed {drift:?} hits only the required Node/CSI GET round"
    );
    for path in [
        case.pvc_path.to_owned(),
        format!(
            "/api/v1/namespaces/{NAMESPACE}/configmaps/{}",
            config_name(case.r)
        ),
        format!(
            "/apis/batch/v1/namespaces/{NAMESPACE}/jobs/{}",
            backup_job_name(case.r, BackupStage::Restore)
        ),
        case.pod_path.to_owned(),
        format!("/api/v1/namespaces/{NAMESPACE}/pods"),
    ] {
        ensure!(
            case.w.reads(&path)? == if second { 2 } else { 1 },
            "observed identity drift reaches the exact workload read round"
        );
    }
    let state = case
        .w
        .shared
        .lock()
        .map_err(|_| anyhow::anyhow!("identity denial state"))?;
    ensure!(
        state.decision_messages == vec![(403, drift.denial())] && state.violations.is_empty(),
        "target-specific production403, not an earlier protocol error or timeout"
    );
    drop(state);
    let expected_cloud = if second {
        vec![
            "AssumeRoleWithOIDC",
            "GetCallerIdentity",
            "DescribeInstances",
        ]
    } else {
        vec![]
    };
    ensure!(
        case.cloud.actions()? == expected_cloud,
        "first identity drift invokes no cloud, second follows exactly one fresh observation"
    );
    Ok(())
}

struct Resume(Arc<ReadPause>);
impl Drop for Resume {
    fn drop(&mut self) {
        self.0.resume.notify_one();
    }
}
async fn trial(
    case: &SelectedCase<'_>,
    node_path: &str,
    csi_path: &str,
    drift: Drift,
    second: bool,
) -> anyhow::Result<()> {
    case.configure(0, Fault::None)?;
    let path = if drift.csi() { csi_path } else { node_path };
    let original = case.w.get(path)?;
    let changed = drift.change(&original)?;
    let body = case.changed(|_| {})?;
    let decision = if second {
        let pause = Arc::new(ReadPause {
            path: path.to_owned(),
            hit: 2,
            arrived: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
        });
        case.w
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("identity read barrier"))?
            .read_pause = Some(pause.clone());
        // Both futures finish through join; no detached owner task or database
        // mutation is created. Resume also runs on a bounded barrier failure.
        let (decision, mutation) =
            tokio::join!(case.put("select", body, StatusCode::FORBIDDEN), async {
                let _resume = Resume(pause.clone());
                tokio::time::timeout(Duration::from_secs(3), pause.arrived.notified())
                    .await
                    .context("actual second identity GET did not arrive")?;
                ensure!(
                    case.w.reads(path)? == 2
                        && case.cloud.actions()?
                            == vec![
                                "AssumeRoleWithOIDC",
                                "GetCallerIdentity",
                                "DescribeInstances"
                            ],
                    "second identity mutation occurs only at actual arrival after signed cloud"
                );
                replace(case, path, &changed)
            });
        case.w
            .shared
            .lock()
            .map_err(|_| anyhow::anyhow!("identity barrier release"))?
            .read_pause = None;
        decision.and(mutation)
    } else {
        replace(case, path, &changed)?;
        case.put("select", body, StatusCode::FORBIDDEN).await
    };
    // Restore the entire actual server row even if the business assertion failed.
    replace(case, path, &original)?;
    ensure!(
        case.w.get(path)? == original,
        "observed server row restored exactly"
    );
    decision?;
    target_counts(case, node_path, csi_path, drift, second)
}

pub(super) async fn run(case: &SelectedCase<'_>, node_name: &str) -> anyhow::Result<()> {
    let node_path = format!("/api/v1/nodes/{node_name}");
    let csi_path = format!("/apis/storage.k8s.io/v1/csinodes/{node_name}");
    let original_node = case.w.get(&node_path)?;
    let original_csi = case.w.get(&csi_path)?;
    ensure!(
        original_node["metadata"]["name"] == json!(node_name)
            && original_csi["metadata"]["name"] == json!(node_name)
            && original_node["metadata"]["uid"].as_str().is_some()
            && original_csi["metadata"]["uid"].as_str().is_some(),
        "sameUID trials start from registered actual HTTP objects"
    );
    let before = platform_facts(case).await?;
    for field in [
        "configuration",
        "tenant",
        "principal",
        "profile",
        "template",
        "security",
        "restore_certification",
    ] {
        ensure!(
            before[field].is_object(),
            "actual scoped platform {field} row exists"
        );
    }
    ensure!(
        before["tenant"]["id"] == json!(case.t)
            && before["profile"]["id"] == json!(case.job.record.profile_id)
            && before["restore_certification"]["profile_id"] == json!(case.job.record.profile_id)
            && before["restore_certification"]["cluster_epoch"]
                == json!(case.job.record.cluster_epoch)
            && before["configuration"]["cluster_epoch"] == json!(case.job.record.cluster_epoch),
        "whole scoped platform rows match the current recorded restore tuple"
    );
    for field in ["projects", "grants", "nodes", "enrollments", "topology"] {
        ensure!(
            before[field]
                .as_array()
                .is_some_and(|rows| !rows.is_empty()),
            "actual registered {field} rows exist before comparison"
        );
    }
    for drift in [
        Drift::Boot,
        Drift::Profile,
        Drift::Ready,
        Drift::Address,
        Drift::Zone,
        Drift::CsiOwner,
        Drift::CsiInstance,
        Drift::CsiKeys,
    ] {
        Box::pin(trial(case, &node_path, &csi_path, drift, false)).await?;
        ensure!(
            platform_facts(case).await? == before,
            "first sameUID observation leaves platform identity facts unchanged"
        );
    }
    for drift in [Drift::Boot, Drift::CsiOwner] {
        Box::pin(trial(case, &node_path, &csi_path, drift, true)).await?;
        ensure!(
            platform_facts(case).await? == before,
            "second sameUID observation leaves platform identity facts unchanged"
        );
    }
    ensure!(
        case.w.get(&node_path)? == original_node && case.w.get(&csi_path)? == original_csi,
        "all actual Node/CSI observation rows restored without identity or receipt changes"
    );
    eprintln!(
        "VERIFIED private sameUID first Node boot/profile/Ready/IP/topology and CSI owner/nodeID/topology keys, actual second Node/CSI barriers; precise403/GET/cloud stages and unchanged platform facts; not a real apiserver/CSI/cloud certification"
    );
    Ok(())
}
