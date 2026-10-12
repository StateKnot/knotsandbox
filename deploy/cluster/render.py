#!/usr/bin/env python3
"""Render the locked upstream CSI chart and apply narrowly scoped structural changes."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import subprocess
import sys

import jsonschema
import yaml

from cluster import DEFAULT_CACHE, ROOT, LOCK, require, load_installation, publish_rendered


def csi_values(settings):
    return {
        "controller": {"replicas": 3, "nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [{"matchExpressions": [{"key": "sandbox.platform/node-pool", "operator": "In", "values": ["platform"]}]}]}}},
        "csi": {name: {"enabled": name == "disk", "controller": {"enabled": name == "disk"}} for name in ["disk", "nas", "oss", "local", "bmcpfs"]},
        "defaultStorageClass": {"enabled": False}, "defaultVolumeSnapshotClass": {"enabled": False},
        "deploy": {"ack": False, "ecs": True, "ramToken": "", "accessKey": {"enabled": False}, "network": "vpc", "clusterID": settings["deployment"], "regionID": settings["region"]},
        "images": {"registry": "registry.cn-hangzhou.aliyuncs.com", "registryVPC": "registry.cn-hangzhou.aliyuncs.com", "controller": {"tag": "v1.37.2"}, "plugin": {"tag": "v1.37.2"}, "pluginInit": {"tag": "v1.37.2-init"}},
        "nodePools": {"default": {"pluginname": "csi-plugin", "nodeSelectorTerms": [{"matchExpressions": [{"key": "sandbox.platform/node-pool", "operator": "In", "values": ["kata", "platform"]}]}]}},
        "logging": {"format": "json"},
    }


def post_render(documents, outputs, settings, images):
    objects = copy.deepcopy(documents)
    renamed = {"alicloud-csi-provisioner": "sandbox-csi-controller", "alicloud-csi-node": "sandbox-csi-node"}
    workloads = set()
    for obj in objects:
        kind = obj["kind"]
        if kind == "ServiceAccount":
            require(obj["metadata"]["name"] in renamed, "unexpected upstream CSI service account")
            obj["metadata"]["name"] = renamed[obj["metadata"]["name"]]
        if kind in ["ClusterRoleBinding", "RoleBinding"]:
            for subject in obj.get("subjects", []):
                if subject["kind"] == "ServiceAccount":
                    require(subject["name"] in renamed, "unknown CSI RBAC principal")
                    subject["name"] = renamed[subject["name"]]
        if kind in ["ClusterRole", "Role"]:
            # Upstream chart covers NAS/OSS/CPFS and grants credential Secret
            # creation. This deployment has only disk, OIDC and ordinary snapshots.
            rules = []
            for rule in obj["rules"]:
                if any(group in ["groupsnapshot.storage.k8s.io", "storage.alibabacloud.com"] for group in rule["apiGroups"]):
                    continue
                if "secrets" in rule["resources"] or "endpoints" in rule["resources"] or "services" in rule["resources"]:
                    continue
                if kind == "ClusterRole" and obj["metadata"]["name"] == "alicloud-csi-node":
                    if "nodes" in rule["resources"]:
                        rule["verbs"] = ["get", "list", "watch", "patch"]
                    elif "events" not in rule["resources"]:
                        rule["verbs"] = [verb for verb in rule["verbs"] if verb in ["get", "list", "watch"]]
                        if not rule["verbs"]:
                            continue
                rules.append(rule)
            obj["rules"] = rules
        if kind not in ["Deployment", "DaemonSet"]:
            continue
        name = obj["metadata"]["name"]
        require(name in ["csi-provisioner", "csi-plugin"], "unexpected upstream CSI workload")
        workloads.add(name)
        spec = obj["spec"]["template"]["spec"]
        role = "csi-controller" if kind == "Deployment" else "csi-node"
        identity = outputs["workload_roles"][role]
        require(spec["serviceAccountName"] in renamed, "unexpected CSI workload service account")
        spec["serviceAccountName"] = renamed[spec["serviceAccountName"]]
        # Kubernetes API token still required by upstream sidecars. This separate
        # audience-bound projected token is mounted ONLY in the cloud driver.
        spec.setdefault("volumes", []).append({"name": "cloud-identity", "projected": {"defaultMode": 0o400, "sources": [{"serviceAccountToken": {"audience": identity["audience"], "expirationSeconds": 600, "path": "token"}}]}})
        if kind == "Deployment":
            spec["nodeSelector"] = {"sandbox.platform/node-pool": "platform"}
            spec["topologySpreadConstraints"] = [{"maxSkew": 1, "topologyKey": "topology.kubernetes.io/zone", "whenUnsatisfiable": "DoNotSchedule", "labelSelector": obj["spec"]["selector"]["matchLabels"] and {"matchLabels": obj["spec"]["selector"]["matchLabels"]}}]
            # Projected token mode 0400 is owned by fsGroup for non-root driver.
            spec.setdefault("securityContext", {})["fsGroup"] = 65532
            spec["volumes"][-1]["projected"]["defaultMode"] = 0o440
        else:
            spec.pop("nodeSelector", None)
            spec.setdefault("affinity", {})["nodeAffinity"] = {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [{"matchExpressions": [{"key": "sandbox.platform/node-pool", "operator": "In", "values": ["kata", "platform"]}]}]}}
            # Explicitly allow installation on quarantined nodes; no arbitrary toleration.
            spec["tolerations"] = [{"key": f"sandbox.platform/{key}", "operator": "Equal", "value": "true", "effect": "NoSchedule"} for key in ["untrusted", "unverified"]]
        drivers = []
        for container in spec.get("containers", []) + spec.get("initContainers", []):
            original = container["image"]
            require(original in images, f"unlocked upstream image: {original}")
            container["image"] = images[original]
            require("@sha256:" in container["image"], "image digest missing")
            cloud_driver = "/acs/csi-plugin:" in original
            env = container.setdefault("env", [])
            require(not any(e["name"] in ["ACCESS_KEY_ID", "ACCESS_KEY_SECRET", "ALIBABA_CLOUD_ACCESS_KEY_ID", "ALIBABA_CLOUD_ACCESS_KEY_SECRET"] for e in env), "upstream injected long-lived credentials")
            if cloud_driver and container in spec.get("containers", []):
                drivers.append(container["name"])
                env.extend([{"name": key, "value": value} for key, value in {
                    "ALIBABA_CLOUD_ROLE_ARN": identity["arn"], "ALIBABA_CLOUD_OIDC_PROVIDER_ARN": settings["oidc_provider_arn"],
                    "ALIBABA_CLOUD_OIDC_TOKEN_FILE": "/var/run/sandbox-cloud/token", "ALIBABA_CLOUD_ROLE_SESSION_NAME": role,
                    "ALIBABA_CLOUD_CLI_PROFILE_DISABLED": "true", "ALIBABA_CLOUD_ECS_METADATA_DISABLED": "true",
                    "ALIBABA_CLOUD_REGION_ID": settings["region"],
                }.items()])
                container.setdefault("volumeMounts", []).append({"name": "cloud-identity", "mountPath": "/var/run/sandbox-cloud", "readOnly": True})
        require(len(drivers) == 1, f"expected exactly one cloud driver per CSI workload, got {drivers}")
    require(workloads == {"csi-provisioner", "csi-plugin"}, "upstream workload shape changed")
    objects += [
        {"apiVersion": "storage.k8s.io/v1", "kind": "StorageClass", "metadata": {"name": "sandbox-workspace"}, "provisioner": "diskplugin.csi.alibabacloud.com", "reclaimPolicy": "Retain", "volumeBindingMode": "WaitForFirstConsumer", "allowVolumeExpansion": True, "parameters": {"type": "cloud_essd", "fsType": "ext4", "encrypted": "true", "kmsKeyId": outputs["workspace_kms_key_id"], "diskTags/Deployment": settings["deployment"]}},
        {"apiVersion": "snapshot.storage.k8s.io/v1", "kind": "VolumeSnapshotClass", "metadata": {"name": "sandbox-workspace"}, "driver": "diskplugin.csi.alibabacloud.com", "deletionPolicy": "Retain", "parameters": {"snapshotTags/Deployment": settings["deployment"]}},
    ]
    return objects


def policies(outputs, settings):
    namespace_selectors = [{"matchLabels": {"k8s:io.kubernetes.pod.namespace": namespace}} for namespace in ["kube-system", "sandbox-system"]]
    entities = ["host", "remote-node", "kube-apiserver"]
    node_cidrs = [node["private_ip"] + "/32" for node in outputs["node_inventory"].values()]
    host_allow = settings["enterprise_cidrs"] + node_cidrs
    trusted_out = settings["trusted_egress_cidrs"] + node_cidrs + [settings["service_cidr"], "100.100.100.200/32"]
    # Dedicated component policies are additive in Cilium. Exclude their labeled
    # endpoints from this bootstrap allow; a narrow CNP cannot subtract it.
    # No tenant endpoint, reserved:init or all-cluster selector gets a blanket allow.
    return [
        {"apiVersion": "cilium.io/v2", "kind": "CiliumClusterwideNetworkPolicy", "metadata": {"name": "sandbox-trusted-bootstrap"}, "spec": {"endpointSelector": {"matchExpressions": [{"key": "k8s:io.kubernetes.pod.namespace", "operator": "In", "values": ["kube-system", "sandbox-system"]}, {"key": "k8s:sandbox.platform/backup-id", "operator": "DoesNotExist"}, {"key": "k8s:sandbox.platform/network-policy", "operator": "DoesNotExist"}]}, "ingress": [{"fromEndpoints": namespace_selectors}, {"fromEntities": entities}], "egress": [{"toEndpoints": namespace_selectors}, {"toEntities": entities}, {"toCIDR": trusted_out}]}},
        {"apiVersion": "cilium.io/v2", "kind": "CiliumClusterwideNetworkPolicy", "metadata": {"name": "sandbox-host-bootstrap"}, "spec": {"nodeSelector": {"matchExpressions": [{"key": "sandbox.platform/node-pool", "operator": "In", "values": ["control", "platform", "kata"]}]}, "ingress": [{"fromCIDR": host_allow}, {"fromEndpoints": namespace_selectors}], "egress": [{"toCIDR": trusted_out}, {"toEndpoints": namespace_selectors}]}},
    ]


def validate_schema(documents, cache):
    swagger = json.loads((cache / "kubernetes-schema.json").read_text())
    def kubernetes_types(value):
        # OpenAPI 2 encodes this Kubernetes union as format=int-or-string;
        # generic JSON Schema validators otherwise reject legal integer PDBs.
        if isinstance(value, dict):
            if value.get("format") == "int-or-string" or value.get("x-kubernetes-int-or-string") is True:
                value["type"] = ["integer", "string"]
            for child in value.values():
                kubernetes_types(child)
        elif isinstance(value, list):
            for child in value:
                kubernetes_types(child)
    kubernetes_types(swagger)
    definitions = swagger["definitions"]
    native = {}
    for name, definition in definitions.items():
        for gvk in definition.get("x-kubernetes-group-version-kind", []):
            api = (gvk["group"] + "/" if gvk["group"] else "") + gvk["version"]
            native[(api, gvk["kind"])] = name
    custom = {}
    for obj in documents:
        if obj["kind"] == "CustomResourceDefinition":
            for version in obj["spec"]["versions"]:
                definition = copy.deepcopy(version["schema"]["openAPIV3Schema"])
                kubernetes_types(definition)
                custom[(obj["spec"]["group"] + "/" + version["name"], obj["spec"]["names"]["kind"])] = definition
    for obj in documents:
        key = (obj["apiVersion"], obj["kind"])
        if key in native:
            schema = {"$ref": "#/definitions/" + native[key], "definitions": definitions}
        else:
            require(key in custom, f"no official schema for {key}")
            schema = custom[key]
        jsonschema.Draft4Validator(schema).validate(obj)


def render(deployment, cache, *, expected=None):
    import tempfile
    snapshot = load_installation(deployment, expected=expected)
    settings, outputs = snapshot["settings"], snapshot["outputs"]
    values = yaml.safe_dump(csi_values(settings)).encode()
    chart = cache / "csi/deploy/charts/alibaba-cloud-csi-driver"
    chart_metadata = yaml.safe_load((chart / "Chart.yaml").read_text())
    require(chart_metadata["version"] == LOCK["versions"]["csi_chart"], "upstream CSI chart version drift")
    with tempfile.TemporaryDirectory(prefix=".render-", dir=deployment) as temporary:
        values_path = Path(temporary) / "csi-values.yaml"
        values_path.write_bytes(values)
        rendered = subprocess.check_output([str(cache / "helm"), "template", "sandbox-csi", str(chart), "--namespace", "kube-system", "--kube-version", LOCK["versions"]["kubernetes"], "--include-crds", "-f", str(values_path)], text=True, timeout=120)
    documents = [o for o in yaml.safe_load_all(rendered) if o]
    result = post_render(documents, outputs, settings, LOCK["csi_images"])
    validate_schema(result, cache)
    policy_objects = policies(outputs, settings)
    policy_crd = yaml.safe_load((cache / "cilium-policy-crd.yaml").read_text())
    validate_schema([policy_crd] + policy_objects, cache)
    crds = [o for o in result if o["kind"] == "CustomResourceDefinition"]
    ordinary = [o for o in result if o["kind"] != "CustomResourceDefinition"]
    resources = {"csi-values.yaml": values}
    resources.update({name: yaml.safe_dump_all(objects, sort_keys=False).encode()
                      for name, objects in [("csi-crds.yaml", crds), ("csi.yaml", ordinary), ("trusted-policies.yaml", policy_objects)]})
    publish_rendered(deployment, snapshot, resources)
    print(f"validated {len(result)} CSI resources against Kubernetes {LOCK['versions']['kubernetes']} and upstream CRD schemas")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    args = parser.parse_args()
    try:
        render(args.deployment.resolve(), args.cache.resolve())
    except (ValueError, KeyError) as error:
        sys.exit(f"render: {error}")
