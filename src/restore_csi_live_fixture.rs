//! Fixed synthetic CSI HTTP object fixtures only. No scope/proof/Gate producer.
//! Selected objects are copies of the normal fixture's actually enrolled Node
//! and CSINode, never replacements for the sealed collector validation.
use crate::{
    nodeguard::protocol::NodeBinding,
    restore::vendor_profile::{VendorActiveImageExpectation, VendorWorkloadExpectation},
};
use anyhow::{Context, Result as TestResult, ensure};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use uuid::Uuid;
type Objects = BTreeMap<String, Value>;
const ZONE: &str = "topology.kubernetes.io/zone";
pub(crate) struct Input {
    pub(crate) objects: Objects,
    pub(crate) controller: VendorWorkloadExpectation,
    pub(crate) node_plugin: VendorWorkloadExpectation,
    pub(crate) images: Vec<VendorActiveImageExpectation>,
    pub(crate) zones: Vec<String>,
    pub(crate) selected: NodeBinding,
    pub(crate) selected_zone: String,
}
pub(crate) fn fixture() -> TestResult<Input> {
    let raw: Value = serde_json::from_slice(include_bytes!(
        "../tests/fixtures/restore/csi-pod-projection.synthetic.json"
    ))?;
    let c = raw.get(0).context("controller fixture")?;
    let n = raw.get(1).context("node fixture")?;
    let mut objects = BTreeMap::new();
    for carrier in [c, n] {
        let kind = carrier["workload"]["kind"]
            .as_str()
            .context("workload kind")?;
        let plural = if kind == "Deployment" {
            "deployments"
        } else {
            "daemonsets"
        };
        let wn = carrier["workload"]["metadata"]["name"]
            .as_str()
            .context("workload name")?;
        objects.insert(
            format!("/apis/apps/v1/namespaces/kube-system/{plural}/{wn}"),
            carrier["workload"].clone(),
        );
        let sa = carrier["service_account"]["metadata"]["name"]
            .as_str()
            .context("account name")?;
        objects.insert(
            format!("/api/v1/namespaces/kube-system/serviceaccounts/{sa}"),
            carrier["service_account"].clone(),
        );
        let pc = carrier["priority_class"]["metadata"]["name"]
            .as_str()
            .context("priority name")?;
        objects.insert(
            format!("/apis/scheduling.k8s.io/v1/priorityclasses/{pc}"),
            carrier["priority_class"].clone(),
        );
        let plural = if kind == "Deployment" {
            "replicasets"
        } else {
            "controllerrevisions"
        };
        let owner = carrier["owner"]["metadata"]["name"]
            .as_str()
            .context("owner name")?;
        objects.insert(
            format!("/apis/apps/v1/namespaces/kube-system/{plural}/{owner}"),
            carrier["owner"].clone(),
        );
    }
    let zones: Vec<String> = serde_json::from_value(c["placement"]["zone_ids"].clone())?;
    let mut controller_pods = Vec::new();
    for (index, suffix) in ["jklmn", "pqrst", "vwxzz"].iter().enumerate() {
        let mut pod = c["pod"].clone();
        let prefix = pod["metadata"]["generateName"]
            .as_str()
            .context("generated name")?;
        pod["metadata"]["name"] = json!(format!("{prefix}{suffix}"));
        pod["metadata"]["uid"] = json!(Uuid::new_v4());
        let node_name = format!("platform-node-{}", index + 1);
        pod["spec"]["nodeName"] = json!(node_name);
        let mut node = c["node"].clone();
        node["metadata"]["name"] = json!(node_name);
        node["metadata"]["uid"] = json!(Uuid::new_v4());
        node["metadata"]["labels"][ZONE] = json!(zones[index]);
        node["status"]["nodeInfo"]["bootID"] = json!(Uuid::new_v4());
        objects.insert(format!("/api/v1/nodes/{node_name}"), node);
        let pn = pod["metadata"]["name"].as_str().context("pod name")?;
        objects.insert(
            format!("/api/v1/namespaces/kube-system/pods/{pn}"),
            pod.clone(),
        );
        controller_pods.push(pod);
    }
    objects.insert("controller-list".into(),json!({"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"1"},"items":controller_pods}));
    let pod_name = n["pod"]["metadata"]["name"]
        .as_str()
        .context("node pod name")?;
    objects.insert(
        format!("/api/v1/namespaces/kube-system/pods/{pod_name}"),
        n["pod"].clone(),
    );
    objects.insert("selected-plugin-list".into(),json!({"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"1"},"items":[n["pod"].clone()]}));
    objects.insert("/api/v1/nodes/kata-node-1".into(), n["node"].clone());
    objects.insert("/apis/storage.k8s.io/v1/csinodes/kata-node-1".into(),json!({"apiVersion":"storage.k8s.io/v1","kind":"CSINode","metadata":{"name":"kata-node-1","uid":Uuid::new_v4(),"resourceVersion":"1"},"drivers":[]}));
    let mut images: Vec<VendorActiveImageExpectation> =
        serde_json::from_value(c["active_images"].clone())?;
    images.extend(serde_json::from_value::<Vec<VendorActiveImageExpectation>>(
        n["active_images"].clone(),
    )?);
    Ok(Input {
        objects,
        controller: serde_json::from_value(c["workload_expectation"].clone())?,
        node_plugin: serde_json::from_value(n["workload_expectation"].clone())?,
        images,
        zones,
        selected: serde_json::from_value(n["placement"]["selected_node"].clone())?,
        selected_zone: n["placement"]["selected_zone"]
            .as_str()
            .context("selected zone")?
            .into(),
    })
}

/// Ordinary test observations; all authority remains in the subsequent normal
/// Source14/current-claim collector. No production client or proof is built.
pub(crate) fn for_actual_node(
    mut input: Input,
    node: &Value,
    csi: &Value,
    binding: &NodeBinding,
    zone: &str,
    zones: &[String],
) -> TestResult<Input> {
    ensure!(
        zones.len() == 3
            && zones.windows(2).all(|w| w[0] < w[1])
            && zones.iter().any(|z| z == zone),
        "actual sealed sorted three-zone comparison facts"
    );
    ensure!(
        node["metadata"]["name"] == binding.node_name
            && node["metadata"]["uid"] == json!(binding.node_uid)
            && node["status"]["nodeInfo"]["bootID"] == json!(binding.boot_id)
            && node["metadata"]["annotations"]["sandbox.platform/runtime-profile-sha256"]
                == binding.profile_sha256
            && node["metadata"]["labels"][ZONE] == zone
            && csi["metadata"]["name"] == binding.node_name,
        "fixture observations correspond to actually enrolled bound Node"
    );
    ensure!(
        (1..=3).all(|i| binding.node_name != format!("platform-node-{i}")),
        "fixture platform Nodes are separate from actual enrolled kata Node"
    );
    let old_node = format!("/api/v1/nodes/{}", input.selected.node_name);
    let old_csi = format!(
        "/apis/storage.k8s.io/v1/csinodes/{}",
        input.selected.node_name
    );
    input.objects.remove(&old_node);
    input.objects.remove(&old_csi);
    input
        .objects
        .insert(format!("/api/v1/nodes/{}", binding.node_name), node.clone());
    input.objects.insert(
        format!("/apis/storage.k8s.io/v1/csinodes/{}", binding.node_name),
        csi.clone(),
    );
    for (i, zone) in zones.iter().enumerate() {
        let name = format!("platform-node-{}", i + 1);
        input
            .objects
            .get_mut(&format!("/api/v1/nodes/{name}"))
            .context("synthetic controller placement Node")?["metadata"]["labels"][ZONE] =
            json!(zone);
    }
    let pod_name = input.objects["selected-plugin-list"]["items"][0]["metadata"]["name"]
        .as_str()
        .context("plugin actual synthetic name")?
        .to_owned();
    let path = format!("/api/v1/namespaces/kube-system/pods/{pod_name}");
    let pod = input
        .objects
        .get_mut(&path)
        .context("selected plugin object")?;
    pod["spec"]["nodeName"] = json!(binding.node_name);
    *pod.pointer_mut("/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/0/matchFields/0/values").context("fixed daemon actual-node affinity")?=json!([binding.node_name]);
    let adapted_pod = input
        .objects
        .get(&path)
        .context("adapted plugin Pod")?
        .clone();
    input
        .objects
        .get_mut("selected-plugin-list")
        .context("plugin list")?["items"] = json!([adapted_pod]);
    input.zones = zones.to_vec();
    input.selected = binding.clone();
    input.selected_zone = zone.to_owned();
    Ok(input)
}
