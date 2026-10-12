#!/usr/bin/env python3
"""Pinned cluster bootstrap. No cloud credentials, shell interpolation or implicit SSH."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

import yaml

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent.parent
LOCK = json.loads((ROOT / "versions.lock.json").read_text())
DEFAULT_CACHE = REPO / ".local/cluster-artifacts"
INSTALLATION_FILE = "installation.json"
INPUT_FILES = {"inventory.yaml", "inputs.json", "inventory.sha256"}
RENDERED_FILES = {"csi-values.yaml", "csi-crds.yaml", "csi.yaml", "trusted-policies.yaml"}
TERRAFORM_OUTPUTS = {"vpc_id", "deployment_identity", "subnets", "node_inventory", "private_entrances",
                     "database", "object_storage", "workload_roles", "workload_oidc_provider_arn", "workspace_kms_key_id"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def installation_bytes(deployment, name):
    """Read one bounded private regular file, without following a file symlink."""
    path = deployment / name
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise ValueError(f"installation file missing or unsafe: {name}") from error
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077,
                f"installation file must be a private regular file: {name}")
        require(info.st_size <= 16 * 1024 * 1024, f"installation file too large: {name}")
        data = stream.read(16 * 1024 * 1024 + 1)
        require(len(data) <= 16 * 1024 * 1024, f"installation file grew beyond limit: {name}")
        return data


def atomic_private(path, data):
    descriptor, name = tempfile.mkstemp(prefix=".installation-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def load_installation(deployment, *, expected=None, require_rendered=False):
    """Verify the whole installation contract before rendering or host access.

    A checksum is drift evidence, not a signature or operator authorization.
    Business validation and deterministic inventory binding remain mandatory
    even when somebody updates a local checksum alongside a file.
    """
    deployment = Path(deployment)
    require(deployment.is_dir() and not deployment.is_symlink(), "installation directory missing or unsafe")
    manifest_raw = installation_bytes(deployment, INSTALLATION_FILE)
    manifest = json.loads(manifest_raw)
    require(isinstance(manifest, dict) and set(manifest) == {"protocol", "artifact_lock_sha256", "files"}
            and manifest["protocol"] == 1, "unsupported installation snapshot")
    require(manifest["artifact_lock_sha256"] == hashlib.sha256(canonical(LOCK)).hexdigest(),
            "installation artifact lock differs; generate a reviewed new revision")
    files = manifest["files"]
    require(isinstance(files, dict) and set(files) in (INPUT_FILES, INPUT_FILES | RENDERED_FILES),
            "installation snapshot has incomplete or unknown files")
    require(not require_rendered or RENDERED_FILES <= set(files), "installation resources have not been rendered and reviewed")
    captured = {}
    for name, checksum in files.items():
        require(isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum), "invalid installation checksum")
        captured[name] = installation_bytes(deployment, name)
        require(hashlib.sha256(captured[name]).hexdigest() == checksum,
                f"installation file changed after review: {name}")
    if not RENDERED_FILES <= set(files):
        require(not any((deployment / name).exists() or (deployment / name).is_symlink() for name in RENDERED_FILES),
                "installation contains unbound rendered resources; generate a reviewed new revision")
    inputs = json.loads(captured["inputs.json"])
    require(isinstance(inputs, dict) and set(inputs) == {"outputs", "settings"}, "invalid installation inputs")
    require(isinstance(inputs["outputs"], dict) and isinstance(inputs["settings"], dict), "invalid installation input objects")
    tf = {key: {"value": value, "sensitive": False} for key, value in inputs["outputs"].items()}
    outputs = validate(tf, inputs["settings"])
    require(yaml.safe_load(captured["inventory.yaml"]) == inventory(outputs, inputs["settings"]),
            "installation inventory does not match validated inputs and artifact lock")
    require(captured["inventory.sha256"].decode().strip() == files["inventory.yaml"],
            "installation inventory checksum differs")
    if RENDERED_FILES <= set(files):
        # Deterministic security artifacts must retain their input contract,
        # even if a local operator rewrites their checksum alongside a file.
        from render import csi_values, policies
        require(yaml.safe_load(captured["csi-values.yaml"]) == csi_values(inputs["settings"]),
                "installation CSI values do not match validated inputs")
        require(list(yaml.safe_load_all(captured["trusted-policies.yaml"])) == policies(outputs, inputs["settings"]),
                "installation policies do not match validated inputs")
    baseline = {name: files[name] for name in sorted(INPUT_FILES)}
    binding = hashlib.sha256(canonical({"files": baseline, "artifact_lock_sha256": manifest["artifact_lock_sha256"]})).hexdigest()
    require(expected is None or expected == binding, "installation changed during execution")
    return {"outputs": outputs, "settings": inputs["settings"], "binding": binding,
            "manifest": manifest, "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest()}


def publish_rendered(deployment, snapshot, resources):
    require(set(resources) == RENDERED_FILES, "incomplete installation rendering")
    current = load_installation(deployment, expected=snapshot["binding"])
    require(current["manifest_sha256"] == snapshot["manifest_sha256"], "installation rendering changed during execution")
    manifest = current["manifest"]
    # Publish only after all chart/business/schema checks have succeeded. The
    # snapshot is written last; an interrupted publication fails closed.
    for name, data in resources.items():
        atomic_private(deployment / name, data)
        manifest["files"][name] = hashlib.sha256(data).hexdigest()
    atomic_private(deployment / INSTALLATION_FILE, json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n")
    load_installation(deployment, expected=snapshot["binding"], require_rendered=True)


def fetch(name, cache):
    artifact = LOCK["artifacts"][name]
    target = cache / artifact["filename"]
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.exists():
        require(digest(target) == artifact["sha256"], f"cached artifact checksum mismatch: {name}")
        return target
    temporary = target.with_suffix(target.suffix + ".partial")
    try:
        with urllib.request.urlopen(artifact["url"], timeout=120) as response, temporary.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
        require(digest(temporary) == artifact["sha256"], f"download checksum mismatch: {name}")
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)
    return target


def extract_source(archive, destination):
    # Only regular files/directories are accepted. Never follow archive links.
    require(not destination.is_symlink(), "source cache must not be a symlink")
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:gz") as package:
        for item in package:
            parts = Path(item.name).parts[1:]
            require(not Path(item.name).is_absolute() and ".." not in parts, "unsafe archive path")
            if not parts or item.isdir():
                continue
            # Upstream Kubespray carries compatibility links to plugins. They
            # are unused: ansible() sets explicit verified plugin directories.
            if item.issym():
                resolved = posixpath.normpath(posixpath.join(str(Path(*parts).parent), item.linkname))
                require(not Path(item.linkname).is_absolute() and not resolved.startswith("../"), "unsafe archive symlink")
                continue
            require(item.isfile(), f"unsupported source archive entry: {item.name}")
            target = destination.joinpath(*parts)
            require(not target.is_symlink(), "symlink in extraction destination")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(package.extractfile(item).read())
            target.chmod(0o755 if item.mode & 0o111 else 0o644)


def prepare(cache, include_kata=False):
    for name in ["kubespray", "csi", "cilium"]:
        archive = fetch(name, cache)
        destination = cache / name
        # Re-extract on each preparation: local edits must not masquerade as upstream.
        extract_source(archive, destination)
    for name in ["kubernetes-schema", "kata-versions", "cilium-policy-crd"]:
        fetch(name, cache)
    system = platform.system().lower()
    architecture = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    name = f"helm-{system}-{architecture}"
    require(name in LOCK["artifacts"], "unsupported installer platform")
    with tarfile.open(fetch(name, cache), "r:gz") as package:
        data = package.extractfile(f"{system}-{architecture}/helm").read()
    (cache / "helm").write_bytes(data)
    (cache / "helm").chmod(0o755)
    if include_kata:
        fetch("kata-go", cache)


def bootstrap_playbook(cache):
    """Preserve upstream tasks; insert policies before its CNI role can start."""
    source = cache / "kubespray/playbooks/cluster.yml"
    plays = yaml.safe_load(source.read_text())
    anchors = [i for i, play in enumerate(plays) if play.get("name") == "Invoke kubeadm and install a CNI"]
    require(len(anchors) == 1, "upstream CNI installation boundary changed")
    for play in plays:
        if "import_playbook" in play:
            play["import_playbook"] = str((source.parent / play["import_playbook"]).resolve())
    plays.insert(anchors[0], {"name": "Establish fail-closed network policy before CNI starts", "ansible.builtin.import_playbook": str(ROOT / "early-policies.yaml")})
    target = cache / "bootstrap.yml"
    target.write_text(yaml.safe_dump(plays, sort_keys=False))
    return target


def network(value):
    result = ipaddress.ip_network(value, strict=True)
    ranges = [ipaddress.ip_network(cidr) for cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]]
    require(result.version == 4 and any(result.subnet_of(cidr) for cidr in ranges), "expected RFC1918 IPv4 network")
    return result


def validate(tf, settings):
    require(tf.get("node_inventory", {}).get("sensitive") is False, "expected terraform output -json, not plan/state")
    require(all(isinstance(value, dict) and value.get("sensitive") is False and "value" in value for value in tf.values()),
            "installation snapshot accepts only non-sensitive terraform outputs")
    require(set(tf) <= TERRAFORM_OUTPUTS, "unknown terraform installation output")
    outputs = {k: v["value"] for k, v in tf.items()}
    nodes = outputs["node_inventory"]
    required = ["deployment", "region", "host_image_id", "host_kernel", "host_image_evidence_sha256", "network_evidence_sha256", "mtu", "pod_cidr", "service_cidr", "enterprise_cidrs", "ntp_servers", "api_dns_name", "oidc_provider_arn", "ssh_known_hosts_file", "download_proxy", "trusted_egress_cidrs", "backup_recipient_certificate"]
    require(set(settings) == set(required), "missing or unknown installation settings")
    require(re.fullmatch(r"[a-z][a-z0-9-]{3,19}", settings["deployment"]), "invalid deployment name")
    require(re.fullmatch(r"[a-z]{2}-[a-z0-9-]+", settings["region"]), "invalid region")
    require(re.fullmatch(r"[a-zA-Z0-9_.-]+", settings["host_image_id"]), "fixed host image ID required")
    require(re.fullmatch(r"[0-9][a-zA-Z0-9_.+-]+", settings["host_kernel"]), "exact reviewed host kernel required")
    for field in ["host_image_evidence_sha256", "network_evidence_sha256"]:
        require(re.fullmatch(r"[0-9a-f]{64}", settings[field]) and len(set(settings[field])) > 1, f"real evidence digest required: {field}")
    require(type(settings["mtu"]) is int and 1280 <= settings["mtu"] <= 1450, "certified conservative Kata/VXLAN MTU required (1280..1450)")
    require(re.fullmatch(r"[a-z0-9][a-z0-9.-]+[a-z0-9]", settings["api_dns_name"]), "API TLS DNS name required")
    require(re.fullmatch(r"acs:ram::[0-9]{16}:oidc-provider/[a-zA-Z0-9_-]+", settings["oidc_provider_arn"]), "exact workload OIDC provider ARN required")
    # Proxy may be empty for a private mirrored environment. Never embed proxy credentials.
    require(not settings["download_proxy"] or re.fullmatch(r"https?://[a-zA-Z0-9.-]+:[0-9]+", settings["download_proxy"]), "proxy must be an explicit credential-free URL")
    known_hosts = Path(settings["ssh_known_hosts_file"])
    require(known_hosts.is_absolute() and re.fullmatch(r"/[a-zA-Z0-9_./-]+", str(known_hosts)), "absolute preverified SSH known_hosts path without shell metacharacters required")
    require(settings["ntp_servers"], "trusted NTP servers required")
    for address in settings["ntp_servers"]:
        require(ipaddress.ip_address(address).is_private, "private NTP server required")
    routed = [network(settings["pod_cidr"]), network(settings["service_cidr"])]
    require(not routed[0].overlaps(routed[1]), "Pod and Service CIDRs overlap")
    outside = [network(n) for n in settings["enterprise_cidrs"]]
    outside += [network(s["cidr"]) for s in outputs["subnets"].values()]
    require(all(not a.overlaps(b) for a in routed for b in outside), "Pod/Service CIDR overlaps enterprise or VPC subnet")
    require(settings["trusted_egress_cidrs"], "explicit trusted platform egress required")
    for cidr in settings["trusted_egress_cidrs"]:
        destination = ipaddress.ip_network(cidr)
        require(destination.version == 4 and destination.prefixlen > 0, "unbounded or non-IPv4 egress is forbidden")
    ips, ids = set(), set()
    role_zones = {r: [] for r in ["control", "platform", "kata"]}
    for name, node in nodes.items():
        require(re.fullmatch(r"[a-z][a-z0-9-]+", name), "invalid hostname")
        require(node["role"] in role_zones and node["zone"].startswith(settings["region"]), "invalid node role or zone")
        address = ipaddress.ip_address(node["private_ip"])
        require(address.version == 4 and address.is_private and address not in ips, "invalid or duplicate private node IP")
        require(re.fullmatch(r"i-[a-zA-Z0-9]+", node["id"]) and node["id"] not in ids, "invalid or duplicate ECS instance ID")
        require(any(address in network(s["cidr"]) for s in outputs["subnets"].values() if node["zone"] == s["zone"]), "node outside declared zone subnets")
        ips.add(address)
        ids.add(node["id"])
        role_zones[node["role"]].append(node["zone"])
    require(len(role_zones["control"]) == 3 and len(role_zones["platform"]) == 3, "exactly three control and platform nodes required")
    require(all(len(set(v)) == 3 for v in role_zones.values()), "each pool must cover the same three AZs")
    require(len({tuple(sorted(set(v))) for v in role_zones.values()}) == 1, "pool fault domains differ")
    for role, sa in [("csi-controller", "sandbox-csi-controller"), ("csi-node", "sandbox-csi-node")]:
        identity = outputs["workload_roles"][role]
        account = settings["oidc_provider_arn"].split(":")[3]
        require(identity["arn"] == f"acs:ram::{account}:role/{settings['deployment']}-{role}", "CSI role belongs to another environment or account")
        require(identity["subject"] == f"system:serviceaccount:kube-system:{sa}", "unexpected CSI workload identity")
        require(identity["issuer"].startswith("https://") and identity["audience"] and "*" not in identity["audience"], "invalid workload issuer/audience")
    controller, node = [outputs["workload_roles"][role] for role in ["csi-controller", "csi-node"]]
    require((controller["issuer"], controller["audience"]) == (node["issuer"], node["audience"]), "CSI OIDC trust differs across roles")
    endpoint = outputs["private_entrances"]["kubernetes"]
    require(endpoint["port"] == 6443 and any(ipaddress.ip_address(endpoint["address"]) in network(s["cidr"]) for s in outputs["subnets"].values()), "Kubernetes LB is not in the declared private network")
    return outputs


def inventory(outputs, settings):
    hosts = {}
    pools = {r: {"hosts": {}} for r in ["control", "platform", "kata"]}
    for name, node in sorted(outputs["node_inventory"].items()):
        labels = {"sandbox.platform/node-pool": node["role"], "topology.kubernetes.io/region": settings["region"], "topology.kubernetes.io/zone": node["zone"]}
        taints = ["node-role.kubernetes.io/control-plane:NoSchedule"] if node["role"] == "control" else []
        if node["role"] == "kata":
            labels["sandbox.platform/worker-pool"] = "kata"
            taints += ["sandbox.platform/untrusted=true:NoSchedule", "sandbox.platform/unverified=true:NoSchedule"]
        hosts[name] = {"ansible_host": node["private_ip"], "ip": node["private_ip"], "access_ip": node["private_ip"], "ecs_instance_id": node["id"], "node_labels": labels, "node_taints": taints}
        pools[node["role"]]["hosts"][name] = {}
    endpoint = outputs["private_entrances"]["kubernetes"]
    values = {
        "ansible_user": "platform-admin", "ansible_become": True,
        "ansible_ssh_common_args": f"-o StrictHostKeyChecking=yes -o UserKnownHostsFile={settings['ssh_known_hosts_file']}",
        "kube_version": LOCK["versions"]["kubernetes"], "etcd_version": LOCK["versions"]["etcd"],
        "containerd_version": LOCK["versions"]["containerd"], "runc_version": LOCK["versions"]["runc"],
        "container_manager": "containerd", "containerd_use_systemd_cgroup": True, "kubelet_cgroup_driver": "systemd",
        "kubelet_fail_cgroup_v1": True, "kata_containers_enabled": False, "containerd_additional_runtimes": [],
        "kube_network_plugin": "cilium", "cilium_version": LOCK["versions"]["cilium"],
        "cilium_tunnel_mode": "vxlan", "cilium_mtu": settings["mtu"], "cilium_kube_proxy_replacement": False,
        "kube_proxy_remove": False, "kube_proxy_mode": "iptables", "cilium_enable_host_firewall": True,
        "cilium_enable_hubble": False, "cilium_enable_bpf_masquerade": False,
        "cilium_install_extra_flags": "--chart-directory /etc/kubernetes/sandbox-bootstrap/cilium-chart",
        "cilium_extra_values": {"policyEnforcementMode": "always", "nodeSelectorLabels": True, "clustermesh": {"policyDefaultLocalCluster": True}, "socketLB": {"hostNamespaceOnly": True}, "healthChecking": False, "endpointHealthChecking": {"enabled": False}, "extraConfig": {"enable-lockdown-endpoint-on-policy-overflow": "true"}},
        "kube_pods_subnet": settings["pod_cidr"], "kube_service_addresses": settings["service_cidr"],
        "enable_nodelocaldns": False, "dns_mode": "coredns", "dns_autoscaler_enabled": False,
        "loadbalancer_apiserver": {"address": endpoint["address"], "port": endpoint["port"]}, "loadbalancer_apiserver_localhost": False,
        "apiserver_loadbalancer_domain_name": settings["api_dns_name"], "supplementary_addresses_in_ssl_keys": [settings["api_dns_name"], endpoint["address"]],
        "kube_encrypt_secret_data": True, "kube_encryption_algorithm": "secretbox", "kube_apiserver_enable_admission_plugins": ["NodeRestriction"],
        "kube_kubeadm_controller_extra_args": {"disable-force-detach-on-timeout": "true"},
        "kube_kubeadm_apiserver_extra_args": {
            "service-account-issuer": outputs["workload_roles"]["csi-controller"]["issuer"],
            "service-account-jwks-uri": outputs["workload_roles"]["csi-controller"]["issuer"].rstrip("/") + "/openid/v1/jwks",
            "service-account-max-token-expiration": "3600s",
            "service-account-extend-token-expiration": "false",
        },
        "ntp_enabled": True, "ntp_servers": settings["ntp_servers"],
        "download_run_once": False, "helm_enabled": True, "helm_version": LOCK["versions"]["helm"],
        "kubeconfig_localhost": True, "kubectl_localhost": False,
        "sandbox_installation": {"settings": settings, "outputs": outputs, "artifact_lock": LOCK},
    }
    if settings["download_proxy"]:
        values.update({"http_proxy": settings["download_proxy"], "https_proxy": settings["download_proxy"]})
    children = {**pools, "kube_control_plane": {"children": {"control": {}}}, "etcd": {"children": {"control": {}}}, "kube_node": {"children": {"platform": {}, "kata": {}}}, "k8s_cluster": {"children": {"kube_control_plane": {}, "kube_node": {}}}}
    return {"all": {"hosts": hosts, "vars": values, "children": children}}


def generate(tf_path, settings_path, destination):
    tf, settings = json.loads(tf_path.read_text()), json.loads(settings_path.read_text())
    outputs = validate(tf, settings)
    require(not destination.is_symlink(), "installation directory must not be a symlink")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(not any(destination.iterdir()), "refuse to overwrite an existing deployment inventory; generate a reviewed new revision")
    (destination / "inventory.yaml").write_text(yaml.safe_dump(inventory(outputs, settings), sort_keys=False))
    (destination / "inputs.json").write_text(json.dumps({"outputs": outputs, "settings": settings}, indent=2) + "\n")
    (destination / "inventory.sha256").write_text(digest(destination / "inventory.yaml") + "\n")
    for path in destination.iterdir():
        if path.is_file():
            path.chmod(0o600)
    manifest = {"protocol": 1, "artifact_lock_sha256": hashlib.sha256(canonical(LOCK)).hexdigest(),
                "files": {name: digest(destination / name) for name in sorted(INPUT_FILES)}}
    atomic_private(destination / INSTALLATION_FILE, json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n")
    load_installation(destination)
    return outputs, settings


def run(command, *, cwd=None, env=None):
    subprocess.run([str(arg) for arg in command], cwd=cwd, env=env, check=True)


def ansible(cache, deployment, playbook, extra=(), *, installation=None, require_rendered=False):
    source = cache / "kubespray"
    env = os.environ.copy()
    env.update({"ANSIBLE_CONFIG": str(source / "ansible.cfg"), "ANSIBLE_ROLES_PATH": str(source / "roles"), "ANSIBLE_LIBRARY": str(source / "plugins/modules"), "ANSIBLE_FILTER_PLUGINS": str(source / "plugins/filter"), "ANSIBLE_ACTION_PLUGINS": str(source / "plugins/action"), "ANSIBLE_LOCAL_TEMP": str(cache / "ansible-tmp"), "ANSIBLE_HOME": str(cache / "ansible-home"), "ANSIBLE_HOST_KEY_CHECKING": "True", "ANSIBLE_SSH_ARGS": "-o ControlMaster=auto -o ControlPersist=60s -o ConnectionAttempts=3", "ANSIBLE_CACHE_PLUGIN_CONNECTION": str(deployment / "facts")})
    if installation is None:
        # The guarded nodeguard installer owns its separate inventory contract.
        run([sys.executable, "-m", "ansible.cli.playbook", "-i", deployment / "inventory.yaml", playbook, *extra], cwd=source, env=env)
        return
    current = load_installation(deployment, expected=installation["binding"], require_rendered=require_rendered)
    with tempfile.TemporaryDirectory(prefix="sandbox-installation-") as temporary:
        frozen = Path(temporary)
        for name in set(current["manifest"]["files"]) | {INSTALLATION_FILE}:
            atomic_private(frozen / name, installation_bytes(deployment, name))
        load_installation(frozen, expected=installation["binding"], require_rendered=require_rendered)
        latest = load_installation(deployment, expected=installation["binding"], require_rendered=require_rendered)
        require(latest["manifest_sha256"] == current["manifest_sha256"], "installation changed before host access")
        # Inventory and playbook copy/apply sources share this private snapshot.
        # Later edits to the reviewed directory cannot alter an active command.
        frozen_vars = ["-e", json.dumps({"sandbox_deployment_dir": str(frozen), "sandbox_artifact_cache": str(cache),
                                        "artifacts_dir": str(deployment / "artifacts"), "credentials_dir": str(deployment / "credentials"),
                                        "sandbox_receipts_dir": str(deployment)})]
        run([sys.executable, "-m", "ansible.cli.playbook", "-i", frozen / "inventory.yaml", playbook, *extra, *frozen_vars], cwd=source, env=env)
        load_installation(deployment, expected=installation["binding"], require_rendered=require_rendered)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--include-kata", action="store_true")
    gen = commands.add_parser("generate")
    gen.add_argument("--terraform-output", type=Path, required=True)
    gen.add_argument("--settings", type=Path, required=True)
    gen.add_argument("--out", type=Path, required=True)
    for name in ["check", "install-control-plane", "install-addons", "upgrade", "backup-etcd", "restore-etcd", "enable-sandboxes"]:
        sub = commands.add_parser(name)
        sub.add_argument("--deployment", type=Path, required=True)
        if name not in ["check", "enable-sandboxes"]:
            sub.add_argument("--execute", action="store_true", help="explicitly permits contacting the configured hosts")
        if name == "restore-etcd":
            sub.add_argument("--recovery-vars", type=Path, required=True)
        if name == "install-addons":
            sub.add_argument("--identity-config", type=Path, required=True)
            sub.add_argument("--cluster-epoch", required=True)
    args = parser.parse_args()
    cache = args.cache.resolve()
    if args.command == "prepare":
        prepare(cache, args.include_kata)
        return
    if args.command == "generate":
        generate(args.terraform_output, args.settings, args.out)
        return
    deployment = args.deployment.resolve()
    snapshot = load_installation(deployment)
    if args.command == "enable-sandboxes":
        raise ValueError("use deploy/nodeguard for installed host gate and enrollment verification; cloud-fencing release capability remains unavailable, so leave quarantine and RuntimeClass absent")
    if args.command == "check":
        from render import render
        render(deployment, cache, expected=snapshot["binding"])
        for play in [bootstrap_playbook(cache), cache / "kubespray/upgrade-cluster.yml", ROOT / "preflight.yaml", ROOT / "kata-files.yaml", ROOT / "addons.yaml", ROOT / "backup-etcd.yaml", ROOT / "restore-etcd.yaml"]:
            ansible(cache, deployment, play, ["--syntax-check"], installation=snapshot, require_rendered=True)
        return
    require(not (deployment / "nodeguard-plan.json").exists() or args.command in ["backup-etcd", "restore-etcd"], "guarded nodeguard configuration owns this deployment; bootstrap install/upgrade would bypass the CRI gate")
    require(args.execute, "live host operations require explicit --execute; check is offline")
    require(Path(snapshot["settings"]["ssh_known_hosts_file"]).is_file(), "preverified SSH host keys missing")
    if args.command in ["install-control-plane", "upgrade"]:
        from render import render
        render(deployment, cache, expected=snapshot["binding"])
        execution_vars = ["-e", json.dumps({"sandbox_deployment_dir": str(deployment), "sandbox_artifact_cache": str(cache)})]
        require((cache / LOCK["artifacts"]["kata-go"]["filename"]).is_file(), "run prepare --include-kata before live installation")
        require(digest(cache / LOCK["artifacts"]["kata-go"]["filename"]) == LOCK["artifacts"]["kata-go"]["sha256"], "Kata cache mismatch")
        ansible(cache, deployment, ROOT / "preflight.yaml", installation=snapshot, require_rendered=True)
        if args.command == "upgrade":
            ansible(cache, deployment, ROOT / "backup-etcd.yaml", installation=snapshot, require_rendered=True)
            ansible(cache, deployment, ROOT / "early-policies.yaml", execution_vars, installation=snapshot, require_rendered=True)
        ansible(cache, deployment, bootstrap_playbook(cache) if args.command == "install-control-plane" else cache / "kubespray/upgrade-cluster.yml", execution_vars, installation=snapshot, require_rendered=True)
        ansible(cache, deployment, ROOT / "kata-files.yaml", ["-e", json.dumps({"sandbox_artifact_cache": str(cache)})], installation=snapshot, require_rendered=True)
        print("Control plane/CNI ready for public workload identity publication; CSI addons require install-addons live acceptance.")
    elif args.command == "install-addons":
        import importlib.util
        import time
        from render import render
        identity_spec = importlib.util.spec_from_file_location("sandbox_workload_identity", ROOT.parent / "workload-identity/identity.py")
        identity = importlib.util.module_from_spec(identity_spec)
        identity_spec.loader.exec_module(identity)
        settings = identity.config(args.identity_config)
        load_installation(deployment, expected=snapshot["binding"])
        try:
            receipt = identity.accept_addons(settings, deployment, args.cluster_epoch)
        except Exception:
            raise ValueError("workload identity live acceptance failed; addons were not installed") from None
        # Authority is the preceding live call, never an externally supplied JSON
        # success file. Keep this public receipt only for deployment audit.
        require(receipt["issued_at"] <= time.time() < receipt["expires_at"], "workload identity acceptance expired")
        identity.atomic_json(deployment / ("workload-identity-receipt-" + str(time.time_ns()) + ".json"), receipt)
        render(deployment, cache, expected=snapshot["binding"])
        require(receipt["issued_at"] <= time.time() < receipt["expires_at"], "workload identity acceptance expired before addons")
        ansible(cache, deployment, ROOT / "addons.yaml", ["-e", json.dumps({"sandbox_deployment_dir": str(deployment)})], installation=snapshot, require_rendered=True)
        try:
            actual = identity.verify_installed_csi(settings)
        except Exception:
            raise ValueError("installed CSI workload identity verification failed; keep runtime quarantined") from None
        identity.atomic_json(deployment / ("workload-identity-csi-" + str(time.time_ns()) + ".json"), {"acceptance": receipt, "actual_csi_pods": actual})
    elif args.command == "backup-etcd":
        ansible(cache, deployment, ROOT / "backup-etcd.yaml", installation=snapshot)
    else:
        require(args.recovery_vars.is_file(), "explicit recovery variables missing")
        ansible(cache, deployment, ROOT / "restore-etcd.yaml", ["-e", "@" + str(args.recovery_vars.resolve())], installation=snapshot)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError) as error:
        sys.exit(f"cluster: {error}")
