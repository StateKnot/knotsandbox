#!/usr/bin/env python3
"""Check automation manifests against the shared, locked official schemas.

Schema validation alone does not establish live Cilium enforcement or authorize
deployment. Cluster activation also requires the shared policy-boundary check.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "deploy/cluster"))
from render import validate_schema
from cluster import load_installation, require
sys.path.insert(0, str(ROOT / "deploy/automation"))
from automation import render


def check_deployment(documents, deployment):
    """Compose the actual worker and reviewed inventory, beyond object schemas."""
    installation = load_installation(deployment)
    from cluster import inventory
    hosts = inventory(installation["outputs"], installation["settings"])["all"]["hosts"]
    pod = next(obj for obj in documents if obj["kind"] == "Deployment")["spec"]["template"]["spec"]
    require(pod["nodeSelector"]["sandbox.platform/node-pool"] == "platform" and not pod.get("tolerations"),
            "automation must use the trusted platform pool without control or Kata tolerations")
    eligible = [host for host in hosts.values()
                if host["node_labels"]["sandbox.platform/node-pool"] == "platform"
                and not any(taint.endswith(":NoSchedule") or taint.endswith(":NoExecute") for taint in host["node_taints"])]
    require(len(eligible) == 3 and len({host["node_labels"]["topology.kubernetes.io/zone"] for host in eligible}) == 3,
            "automation requires three schedulable trusted platform fault domains")
    return installation["binding"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path,
                        default=ROOT / "deploy/automation/tests/manifest-fixture.json")
    parser.add_argument("--artifacts-dir", type=Path,
                        default=ROOT / ".local/cluster-artifacts")
    parser.add_argument("--deployment", type=Path,
                        help="reviewed cluster deployment for actual pool/taint composition; required for production acceptance")
    args = parser.parse_args()
    cluster_lock = json.loads((ROOT / "deploy/cluster/versions.lock.json").read_text())
    identity_lock = json.loads((ROOT / "deploy/identity/versions.lock.json").read_text())
    swagger = args.artifacts_dir / "kubernetes-schema.json"
    cnp = ROOT / "deploy/identity" / identity_lock["cnp_schema"]["path"]
    if hashlib.sha256(swagger.read_bytes()).hexdigest() != cluster_lock["artifacts"]["kubernetes-schema"]["sha256"]:
        raise ValueError("locked official Kubernetes schema checksum mismatch")
    if hashlib.sha256(cnp.read_bytes()).hexdigest() != identity_lock["cnp_schema"]["sha256"]:
        raise ValueError("locked official Cilium CNP schema checksum mismatch")
    if args.config.stat().st_size > 65536:
        raise ValueError("automation configuration too large")
    documents = [yaml.safe_load(cnp.read_text())] + render(json.loads(args.config.read_text()))["items"]
    validate_schema(documents, args.artifacts_dir)
    if args.deployment:
        binding = check_deployment(documents, args.deployment)
        print(f"PASS automation official schemas and reviewed platform scheduling composition; installation={binding}; no cloud enforcement asserted")
    else:
        print("PASS automation schema only; production scheduling composition requires --deployment; no cloud enforcement asserted")


if __name__ == "__main__":
    main()
