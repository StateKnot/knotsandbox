#!/usr/bin/env python3
"""Render the dedicated automation worker. No cloud apply or secret material."""
import argparse
import ipaddress
import json
import pathlib
import re

APP = "sandbox-automation"
FIELDS = {"namespace", "image", "database_secret", "database_secret_key", "database_ca_config_map", "database_cidrs", "replicas", "default_ttl_seconds", "max_ttl_seconds", "db_max_connections"}
DNS = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
IMAGE = re.compile(r"[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}\Z")

def validate(value):
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError("automation config must contain exactly the documented non-secret fields")
    for field in ["namespace", "database_secret", "database_secret_key", "database_ca_config_map"]:
        if not isinstance(value[field], str) or not DNS.fullmatch(value[field]):
            raise ValueError("invalid automation resource name")
    if not isinstance(value["image"], str) or not IMAGE.fullmatch(value["image"]):
        raise ValueError("automation image must be immutable by SHA-256 digest")
    for field, low, high in [("replicas", 2, 8), ("db_max_connections", 4, 16), ("default_ttl_seconds", 60, 604800), ("max_ttl_seconds", 60, 604800)]:
        if type(value[field]) is not int or not low <= value[field] <= high:
            raise ValueError("invalid bounded automation worker setting")
    if value["default_ttl_seconds"] > value["max_ttl_seconds"]:
        raise ValueError("default TTL exceeds maximum")
    cidrs = value["database_cidrs"]
    if not isinstance(cidrs, list) or not 1 <= len(cidrs) <= 4 or not all(isinstance(c, str) for c in cidrs) or len(set(cidrs)) != len(cidrs):
        raise ValueError("database egress must name one to four unique private subnets")
    private = [ipaddress.ip_network(c) for c in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]]
    for cidr in cidrs:
        if not isinstance(cidr, str):
            raise ValueError("database CIDRs must be strings")
        network = ipaddress.ip_network(cidr, strict=True)
        if network.version != 4 or network.prefixlen < 24 or not any(network.subnet_of(parent) for parent in private):
            raise ValueError("database egress requires narrow RFC1918 subnets, never world or metadata")
    return value


def render(config):
    c = validate(config)
    labels = {"app.kubernetes.io/name": APP,
              "sandbox.platform/network-policy": "automation-v1"}
    def metadata(name):
        return {"name": name, "namespace": c["namespace"], "labels": labels}
    security = {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001, "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}
    container = {
        "name": APP, "image": c["image"], "imagePullPolicy": "IfNotPresent", "command": ["/usr/local/bin/sandbox-automation"],
        "securityContext": security, "ports": [{"name": "health", "containerPort": 8091}],
        "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "1", "memory": "512Mi"}},
        "env": [{"name": "SANDBOX_AUTOMATION_DATABASE_URL", "valueFrom": {"secretKeyRef": {"name": c["database_secret"], "key": c["database_secret_key"], "optional": False}}}]
               + [{"name": "SANDBOX_AUTOMATION_" + name, "value": str(c[key])} for name, key in [("DB_MAX_CONNECTIONS", "db_max_connections"), ("DEFAULT_TTL_SECONDS", "default_ttl_seconds"), ("MAX_TTL_SECONDS", "max_ttl_seconds")]]
               + [{"name": "SANDBOX_PROCESS_POD_UID", "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.uid"}}}],
        "volumeMounts": [{"name": "database-ca", "mountPath": "/etc/sandbox-automation-db-ca", "readOnly": True}],
        "startupProbe": {"httpGet": {"path": "/health/ready", "port": "health"}, "periodSeconds": 5, "timeoutSeconds": 3, "failureThreshold": 24},
        "readinessProbe": {"httpGet": {"path": "/health/ready", "port": "health"}, "periodSeconds": 5, "timeoutSeconds": 3, "failureThreshold": 3},
        "livenessProbe": {"httpGet": {"path": "/health/live", "port": "health"}, "periodSeconds": 10, "timeoutSeconds": 2, "failureThreshold": 3},
    }
    deployment = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": metadata(APP), "spec": {
        "replicas": c["replicas"], "revisionHistoryLimit": 3, "progressDeadlineSeconds": 300, "selector": {"matchLabels": labels},
        "strategy": {"type": "RollingUpdate", "rollingUpdate": {"maxUnavailable": 0, "maxSurge": 1}},
        "template": {"metadata": {"labels": labels}, "spec": {
            "serviceAccountName": APP, "automountServiceAccountToken": False, "terminationGracePeriodSeconds": 60,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001, "seccompProfile": {"type": "RuntimeDefault"}},
            "nodeSelector": {"sandbox.platform/node-pool": "platform", "kubernetes.io/arch": "amd64"},
            "topologySpreadConstraints": [{"maxSkew": 1, "minDomains": 2, "topologyKey": "topology.kubernetes.io/zone", "whenUnsatisfiable": "DoNotSchedule", "labelSelector": {"matchLabels": labels}}],
            "containers": [container], "volumes": [{"name": "database-ca", "configMap": {"name": c["database_ca_config_map"], "optional": False, "items": [{"key": "ca.crt", "path": "ca.crt"}]}}],
        }},
    }}
    policy = {"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy", "metadata": metadata(APP), "spec": {
        "endpointSelector": {"matchLabels": labels},
        "ingress": [{"fromEntities": ["host"], "toPorts": [{"ports": [{"port": "8091", "protocol": "TCP"}]}]}],
        "egress": [
            {"toEndpoints": [{"matchLabels": {"k8s:io.kubernetes.pod.namespace": "kube-system", "k8s:k8s-app": "kube-dns"}}], "toPorts": [{"ports": [{"port": "53", "protocol": "UDP"}, {"port": "53", "protocol": "TCP"}]}]},
            {"toCIDR": c["database_cidrs"], "toPorts": [{"ports": [{"port": "5432", "protocol": "TCP"}]}]},
        ],
    }}
    return {"apiVersion": "v1", "kind": "List", "items": [
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": metadata(APP), "automountServiceAccountToken": False},
        policy, deployment,
        {"apiVersion": "policy/v1", "kind": "PodDisruptionBudget", "metadata": metadata(APP), "spec": {"minAvailable": 1, "selector": {"matchLabels": labels}}},
    ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=pathlib.Path)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.config.stat().st_size > 65536:
        raise ValueError("configuration too large")
    value = render(json.loads(args.config.read_text()))
    args.out.write_text(json.dumps(value, indent=2) + "\n")

if __name__ == "__main__":
    main()
