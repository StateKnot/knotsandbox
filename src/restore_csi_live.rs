//! Read-only CSI runtime TEMPLATE observations under the existing bound attempt.
//! This child of raw_bound_collector can consume its actual private owned state;
//! API objects/installed expectations never produce a vendor Gate or permission.
use super::{
    BackupRawBoundTemplateAttempt, blocked, denial, dependency, vendor_report_error,
    vendor_unavailable,
};
use crate::{
    engine::{Claim, OperationEngine},
    error::ApiError,
    nodeguard::protocol::NodeBinding,
    restore::{
        csi_pod_projection::{CsiPodProjectionInput, project_csi_pod},
        vendor_profile::{
            RestoreVendorReport, VendorActiveImageExpectation, VendorWorkloadExpectation,
        },
    },
};
use axum::{body::HttpBody, http::StatusCode};
use k8s_openapi::api::{
    apps::v1::{ControllerRevision, DaemonSet, Deployment, ReplicaSet},
    core::v1::{Node, Pod, ServiceAccount},
    scheduling::v1::PriorityClass,
    storage::v1::CSINode,
};
use kube::{
    Api, Client,
    api::{GetParams, ListParams},
    client::Body,
    core::Request,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::poll_fn,
    pin::Pin,
    time::Instant,
};

use uuid::Uuid;

const NS: &str = "kube-system";
const LIMIT: usize = 1024 * 1024;
const ZONE: &str = "topology.kubernetes.io/zone";

struct Expected<'a> {
    controller: &'a VendorWorkloadExpectation,
    node_plugin: &'a VendorWorkloadExpectation,
    images: &'a [VendorActiveImageExpectation],
    zones: &'a [String],
    selected: &'a NodeBinding,
    selected_zone: &'a str,
}
struct Snapshot {
    objects: BTreeMap<String, Value>,
    selected_node: Value,
    selected_csi: Value,
}
fn same_snapshot(before: &Snapshot, after: &Snapshot) -> Result<(), ApiError> {
    require(before.objects == after.objects)
}
fn current(deadline: Instant) -> Result<(), ApiError> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(blocked())
    }
}
fn name(v: &Value, path: &str) -> Result<String, ApiError> {
    let s = v
        .pointer(path)
        .and_then(Value::as_str)
        .ok_or_else(blocked)?;
    if s.is_empty()
        || s.len() > 253
        || !s.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && part
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    {
        return Err(blocked());
    }
    Ok(s.to_owned())
}
fn uid(value: &Value) -> Result<Uuid, ApiError> {
    let text = value
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .ok_or_else(blocked)?;
    let uid = Uuid::parse_str(text).map_err(|_| blocked())?;
    require(!uid.is_nil() && uid.to_string() == text)?;
    Ok(uid)
}
fn require(ok: bool) -> Result<(), ApiError> {
    if ok { Ok(()) } else { Err(blocked()) }
}
fn digest(v: &Value) -> Result<String, ApiError> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(v).map_err(|_| blocked())?,
    )))
}
/// One MiB bound is enforced while frames arrive, before Value deserialization.
/// Raw duplicate/unknown JSON survives the authenticated client and is rejected
/// by the fixed parser/projector; no typed K8s roundtrip can erase fields.
async fn request(
    client: &Client,
    request: axum::http::Request<Vec<u8>>,
    deadline: Instant,
) -> Result<Value, ApiError> {
    current(deadline)?;
    let value = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
        let response = client
            .send(request.map(Body::from))
            .await
            .map_err(|_| dependency())?;
        if response.status() == StatusCode::NOT_FOUND {
            return Err(blocked());
        }
        if !response.status().is_success() {
            return Err(dependency());
        }
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
            let frame = frame.map_err(|_| dependency())?;
            let data = frame.into_data().map_err(|_| blocked())?;
            require(
                bytes
                    .len()
                    .checked_add(data.len())
                    .is_some_and(|n| n <= LIMIT),
            )?;
            bytes.extend_from_slice(&data);
        }
        CsiPodProjectionInput::decode_api_object(&bytes).map_err(|_| blocked())
    })
    .await
    .map_err(|_| blocked())??;
    current(deadline)?;
    Ok(value)
}
async fn get(
    client: &Client,
    url: &str,
    object_name: &str,
    deadline: Instant,
) -> Result<Value, ApiError> {
    request(
        client,
        Request::new(url)
            .get(object_name, &GetParams::default())
            .map_err(|_| dependency())?,
        deadline,
    )
    .await
}
async fn list(
    client: &Client,
    url: &str,
    params: ListParams,
    deadline: Instant,
) -> Result<Value, ApiError> {
    request(
        client,
        Request::new(url).list(&params).map_err(|_| dependency())?,
        deadline,
    )
    .await
}
fn list_items(v: &Value, count: usize) -> Result<Vec<Value>, ApiError> {
    let object = v.as_object().ok_or_else(blocked)?;
    require(
        object.len() == 4
            && ["apiVersion", "kind", "metadata", "items"]
                .iter()
                .all(|k| object.contains_key(*k)),
    )?;
    require(v["apiVersion"] == "v1" && v["kind"] == "PodList")?;
    let meta = v["metadata"].as_object().ok_or_else(blocked)?;
    require(meta.keys().all(|k| {
        matches!(
            k.as_str(),
            "resourceVersion" | "continue" | "remainingItemCount"
        )
    }))?;
    require(
        meta.get("resourceVersion")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty() && s.len() <= 256),
    )?;
    require(meta.get("continue").is_none_or(|x| x == ""))?;
    require(
        meta.get("remainingItemCount")
            .is_none_or(|x| x.as_u64() == Some(0)),
    )?;
    let items = v["items"].as_array().ok_or_else(blocked)?;
    require(items.len() == count)?;
    Ok(items.clone())
}
fn workload(value: &Value, expected: &VendorWorkloadExpectation) -> Result<(), ApiError> {
    require(
        value["apiVersion"] == "apps/v1"
            && value["kind"] == expected.kind
            && value["metadata"]["name"] == expected.name
            && value["metadata"]["namespace"] == expected.namespace
            && value["metadata"]["uid"] == expected.uid.to_string()
            && digest(value.get("spec").ok_or_else(blocked)?)? == expected.spec_sha256,
    )
}
struct PodObjects<'a> {
    workload: &'a Value,
    account: &'a Value,
    owner: &'a Value,
    priority: &'a Value,
    node: &'a Value,
    pod: &'a Value,
}
fn carrier(
    expected: &Expected<'_>,
    controller: bool,
    objects: PodObjects<'_>,
) -> Result<(), ApiError> {
    let PodObjects {
        workload,
        account,
        owner,
        priority,
        node,
        pod,
    } = objects;
    let w = if controller {
        expected.controller
    } else {
        expected.node_plugin
    };
    let images: Vec<&VendorActiveImageExpectation> = expected
        .images
        .iter()
        .filter(|i| i.workload_name == w.name)
        .collect();
    let input = CsiPodProjectionInput::from_value(json!({
        "protocol":1,"purpose":if controller { "CONTROLLER" } else { "NODE_PLUGIN" },
        "workload_expectation":w,"active_images":images,"workload":workload,"service_account":account,
        "owner":owner,"priority_class":priority,"node":node,
        "placement":{"zone_ids":expected.zones,"selected_node":if controller { Value::Null } else { json!(expected.selected) },
            "selected_zone":if controller { Value::Null } else { json!(expected.selected_zone) }},"pod":pod
    })).map_err(|_| blocked())?;
    let projection = project_csi_pod(&input).map_err(|_| blocked())?;
    require(
        projection.pod_uid().to_string() == pod["metadata"]["uid"]
            && digest(&pod["spec"])? == projection.spec_sha256(),
    )
}
fn insert(
    objects: &mut BTreeMap<String, Value>,
    key: String,
    value: &Value,
) -> Result<(), ApiError> {
    if let Some(prior) = objects.insert(key, value.clone()) {
        require(prior == *value)?;
    }
    Ok(())
}
/// Exact bounded read path. Dynamic names are locators only: the fixed projector
/// validates every full owner/template/placement chain. Lists cannot authorize.
async fn round(client: &Client, e: &Expected<'_>, deadline: Instant) -> Result<Snapshot, ApiError> {
    current(deadline)?;
    let deployments = Api::<Deployment>::namespaced(client.clone(), NS);
    let daemonsets = Api::<DaemonSet>::namespaced(client.clone(), NS);
    let pods = Api::<Pod>::namespaced(client.clone(), NS);
    let replicasets = Api::<ReplicaSet>::namespaced(client.clone(), NS);
    let revisions = Api::<ControllerRevision>::namespaced(client.clone(), NS);
    let accounts = Api::<ServiceAccount>::namespaced(client.clone(), NS);
    let priorities = Api::<PriorityClass>::all(client.clone());
    let nodes = Api::<Node>::all(client.clone());
    let csis = Api::<CSINode>::all(client.clone());
    let deployment = get(
        client,
        deployments.resource_url(),
        &e.controller.name,
        deadline,
    )
    .await?;
    workload(&deployment, e.controller)?;
    let daemonset = get(
        client,
        daemonsets.resource_url(),
        &e.node_plugin.name,
        deadline,
    )
    .await?;
    workload(&daemonset, e.node_plugin)?;
    let controller_account = get(
        client,
        accounts.resource_url(),
        &e.controller.service_account_name,
        deadline,
    )
    .await?;
    let node_account = get(
        client,
        accounts.resource_url(),
        &e.node_plugin.service_account_name,
        deadline,
    )
    .await?;
    let controller_priority = get(
        client,
        priorities.resource_url(),
        "system-cluster-critical",
        deadline,
    )
    .await?;
    let node_priority = get(
        client,
        priorities.resource_url(),
        "system-node-critical",
        deadline,
    )
    .await?;
    let controller_list = list(
        client,
        pods.resource_url(),
        ListParams::default().labels("app=csi-provisioner").limit(4),
        deadline,
    )
    .await?;
    let mut controllers = list_items(&controller_list, 3)?;
    controllers.sort_by(|a, b| {
        a["metadata"]["name"]
            .as_str()
            .cmp(&b["metadata"]["name"].as_str())
    });
    let first = controllers.first().ok_or_else(blocked)?;
    let references = first["metadata"]["ownerReferences"]
        .as_array()
        .ok_or_else(blocked)?;
    require(references.len() == 1 && references[0]["kind"] == "ReplicaSet")?;
    let rs_name = name(&references[0], "/name")?;
    let rs = get(client, replicasets.resource_url(), &rs_name, deadline).await?;
    let mut objects = BTreeMap::new();
    for (key, value) in [
        (
            format!("{}/{}", deployments.resource_url(), e.controller.name),
            &deployment,
        ),
        (
            format!("{}/{}", daemonsets.resource_url(), e.node_plugin.name),
            &daemonset,
        ),
        (
            format!(
                "{}/{}",
                accounts.resource_url(),
                e.controller.service_account_name
            ),
            &controller_account,
        ),
        (
            format!(
                "{}/{}",
                accounts.resource_url(),
                e.node_plugin.service_account_name
            ),
            &node_account,
        ),
        (
            format!("{}/system-cluster-critical", priorities.resource_url()),
            &controller_priority,
        ),
        (
            format!("{}/system-node-critical", priorities.resource_url()),
            &node_priority,
        ),
        ("controller-list".into(), &controller_list),
        (format!("{}/{rs_name}", replicasets.resource_url()), &rs),
    ] {
        insert(&mut objects, key, value)?;
    }
    let mut seen_zones = BTreeSet::new();
    let mut seen_nodes = BTreeSet::new();
    let mut seen_pods = BTreeSet::new();
    let mut pod_uids = BTreeSet::new();
    let mut node_uids = BTreeSet::new();
    for listed in controllers {
        let pod_name = name(&listed, "/metadata/name")?;
        require(seen_pods.insert(pod_name.clone()))?;
        let pod = get(client, pods.resource_url(), &pod_name, deadline).await?;
        require(pod == listed && pod_uids.insert(uid(&pod)?))?;
        let node_name = name(&pod, "/spec/nodeName")?;
        require(seen_nodes.insert(node_name.clone()))?;
        let node = get(client, nodes.resource_url(), &node_name, deadline).await?;
        require(node_uids.insert(uid(&node)?))?;
        let zone = node["metadata"]["labels"][ZONE]
            .as_str()
            .ok_or_else(blocked)?;
        require(seen_zones.insert(zone.to_owned()))?;
        carrier(
            e,
            true,
            PodObjects {
                workload: &deployment,
                account: &controller_account,
                owner: &rs,
                priority: &controller_priority,
                node: &node,
                pod: &pod,
            },
        )?;
        insert(
            &mut objects,
            format!("{}/{pod_name}", pods.resource_url()),
            &pod,
        )?;
        insert(
            &mut objects,
            format!("{}/{node_name}", nodes.resource_url()),
            &node,
        )?;
    }
    require(seen_zones.iter().eq(e.zones.iter()))?;
    let node_list = list(
        client,
        pods.resource_url(),
        ListParams::default()
            .labels("app=csi-plugin")
            .fields(&format!("spec.nodeName={}", e.selected.node_name))
            .limit(2),
        deadline,
    )
    .await?;
    let listed = list_items(&node_list, 1)?.pop().ok_or_else(blocked)?;
    let pod_name = name(&listed, "/metadata/name")?;
    let pod = get(client, pods.resource_url(), &pod_name, deadline).await?;
    require(
        pod == listed
            && pod["spec"]["nodeName"] == e.selected.node_name
            && pod_uids.insert(uid(&pod)?),
    )?;
    let hash = pod["metadata"]["labels"]["controller-revision-hash"]
        .as_str()
        .ok_or_else(blocked)?;
    require(
        !hash.is_empty()
            && hash.len() <= 10
            && hash
                .bytes()
                .all(|b| b"bcdfghjklmnpqrstvwxz2456789".contains(&b)),
    )?;
    let cr_name = format!("csi-plugin-{hash}");
    let revision = get(client, revisions.resource_url(), &cr_name, deadline).await?;
    let selected_node = get(
        client,
        nodes.resource_url(),
        &e.selected.node_name,
        deadline,
    )
    .await?;
    let selected_csi = get(client, csis.resource_url(), &e.selected.node_name, deadline).await?;
    carrier(
        e,
        false,
        PodObjects {
            workload: &daemonset,
            account: &node_account,
            owner: &revision,
            priority: &node_priority,
            node: &selected_node,
            pod: &pod,
        },
    )?;
    for (key, value) in [
        ("selected-plugin-list".into(), &node_list),
        (format!("{}/{pod_name}", pods.resource_url()), &pod),
        (format!("{}/{cr_name}", revisions.resource_url()), &revision),
        (
            format!("{}/{}", nodes.resource_url(), e.selected.node_name),
            &selected_node,
        ),
        (
            format!("{}/{}", csis.resource_url(), e.selected.node_name),
            &selected_csi,
        ),
    ] {
        insert(&mut objects, key, value)?;
    }
    current(deadline)?;
    Ok(Snapshot {
        objects,
        selected_node,
        selected_csi,
    })
}
impl BackupRawBoundTemplateAttempt {
    /// Actual owned normal caller. This preserves every existing held/cloud
    /// horizon and keeps the new post-CSI full14 token for the original handoff.
    pub(crate) async fn observe_csi_and_refuse(
        mut self,
        engine: &OperationEngine,
        claim: &Claim,
    ) -> Result<(), ApiError> {
        self.current(engine, claim)?;
        let scope = self
            .observed
            .current
            .backup_disk_scope(&self.attempt, engine, claim)
            .map_err(denial)?;
        let report: &RestoreVendorReport = self
            .vendor_report
            .as_deref()
            .ok_or_else(vendor_unavailable)?;
        report.compare_scope(&scope).map_err(vendor_report_error)?;
        let deadline = self.handoff_deadline(engine, claim)?.min(scope.deadline());
        let e = Expected {
            controller: report.controller(),
            node_plugin: report.node_plugin(),
            images: report.active_images(),
            zones: &scope
                .collection()
                .storage
                .storage_contract
                .mapping
                .topology
                .zone_ids,
            selected: &scope.facts().node,
            selected_zone: &scope.facts().zone_id,
        };
        let client = self.csi_client.clone();
        let observed = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            let one = Box::pin(round(&client, &e, deadline)).await?;
            self.current(engine, claim)?;
            self.observed
                .current
                .validate_collection_node(&self.attempt, &one.selected_node, &one.selected_csi)
                .map_err(denial)?;
            let two = Box::pin(round(&client, &e, deadline)).await?;
            self.current(engine, claim)?;
            self.observed
                .current
                .validate_collection_node(&self.attempt, &two.selected_node, &two.selected_csi)
                .map_err(denial)?;
            same_snapshot(&one, &two)?;
            current(deadline)?;
            let final_read = engine
                .database
                .finish_restore_bound_collection(engine, claim, &self.observed.current)
                .await?;
            current(deadline)?;
            final_read
                .backup_current(&self.attempt, engine, claim)
                .map_err(denial)?;
            let final_scope = final_read
                .backup_disk_scope(&self.attempt, engine, claim)
                .map_err(denial)?;
            report
                .compare_scope(&final_scope)
                .map_err(vendor_report_error)?;
            current(deadline.min(final_scope.deadline()))?;
            Ok::<_, ApiError>(final_read)
        })
        .await
        .map_err(|_| blocked())??;
        current(deadline)?;
        // Do not merely check then drop the shorter new SQL horizon. Store it in
        // the actual owned observation consumed by the existing same-TX method.
        self.observed.current = observed;
        self.current(engine, claim)?;
        Box::pin(self.refuse_unverified_publication(engine, claim)).await
    }
}
#[cfg(test)]
#[path = "restore_csi_live_tests.rs"]
mod tests;
