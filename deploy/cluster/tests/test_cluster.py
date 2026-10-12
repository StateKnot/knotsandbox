import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cluster import DEFAULT_CACHE, LOCK, INPUT_FILES, INSTALLATION_FILE, ansible, bootstrap_playbook, digest, generate, inventory, load_installation, validate
from render import csi_values, policies, post_render, render, validate_schema
import yaml


def fixture():
    nodes, subnets = {}, {}
    for index, role in enumerate(["control", "platform", "kata"]):
        for zone in range(3):
            name = f"{role}-{zone}"
            az = "cn-hangzhou-" + chr(104 + zone)
            cidr = f"10.80.{index * 16 + zone}.0/24"
            nodes[name] = {"id": f"i-test{index}{zone}", "private_ip": cidr.replace("0/24", "10"), "role": role, "zone": az}
            subnets[name] = {"id": f"vsw-test{index}{zone}", "zone": az, "cidr": cidr}
    settings = {"deployment": "sbx-test", "region": "cn-hangzhou", "host_image_id": "m-testonly", "host_kernel": "6.8.0-999-test", "host_image_evidence_sha256": hashlib.sha256(b"test-only-image").hexdigest(), "network_evidence_sha256": hashlib.sha256(b"test-only-network").hexdigest(), "mtu": 1400, "pod_cidr": "10.120.0.0/16", "service_cidr": "10.121.0.0/20", "enterprise_cidrs": ["10.1.0.0/16"], "ntp_servers": ["10.1.1.1"], "api_dns_name": "kube.test.invalid", "oidc_provider_arn": "acs:ram::1234567890123456:oidc-provider/sbx-test-kubernetes", "ssh_known_hosts_file": "/tmp/only-test-known-hosts", "download_proxy": "http://10.1.1.2:3128", "trusted_egress_cidrs": ["10.1.0.0/16", "100.100.100.200/32"], "backup_recipient_certificate": "/tmp/only-test-recipient.pem"}
    outputs = {"node_inventory": nodes, "subnets": subnets, "private_entrances": {"kubernetes": {"address": "10.80.16.100", "port": 6443}}, "workspace_kms_key_id": "test-kms-key", "workload_roles": {role: {"arn": f"acs:ram::1234567890123456:role/sbx-test-{role}", "subject": f"system:serviceaccount:kube-system:sandbox-{role}", "issuer": "https://issuer.test.invalid", "audience": "sandbox-cloud"} for role in ["csi-controller", "csi-node"]}}
    return {k: {"value": v, "sensitive": False} for k, v in outputs.items()}, settings


class InventoryTest(unittest.TestCase):
    def test_trusted_namespace_allow_does_not_select_backup_pods(self):
        tf, settings = fixture()
        baseline = next(p for p in policies(validate(tf, settings), settings)
                        if p['metadata']['name'] == 'sandbox-trusted-bootstrap')
        expressions = baseline['spec']['endpointSelector']['matchExpressions']
        self.assertIn({'key': 'k8s:sandbox.platform/backup-id', 'operator': 'DoesNotExist'}, expressions)
        # Namespace membership alone must no longer grant a backup VM control-plane/metadata access.
        labels = {'k8s:io.kubernetes.pod.namespace': 'sandbox-system', 'k8s:sandbox.platform/backup-id': 'fixture'}
        def matches(values):
            return all((e['operator'] == 'In' and values.get(e['key']) in e['values'])
                       or (e['operator'] == 'DoesNotExist' and e['key'] not in values) for e in expressions)
        self.assertFalse(matches(labels))
        # A dedicated component policy cannot be widened by the bootstrap
        # namespace allow: exercise the actual selector for each private role.
        for component in ('api-v1', 'automation-v1', 'console-v1'):
            self.assertFalse(matches({'k8s:io.kubernetes.pod.namespace': 'sandbox-system',
                                      'k8s:sandbox.platform/network-policy': component}))
        self.assertTrue(matches({'k8s:io.kubernetes.pod.namespace': 'sandbox-system'}))

    def test_kata_config_disables_reuse_and_annotation_escape(self):
        spec = importlib.util.spec_from_file_location("kata_config", ROOT / "configure-kata.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        import tomllib
        text = '[hypervisor.qemu]\npath="/opt/kata/bin/qemu-system-x86_64"\nenable_annotations=[".*"]\nenable_debug=true\n[runtime]\nsandbox_cgroup_only=false\ndisable_new_netns=true\n[factory]\nenable_template=true\nvm_cache_number=10\n'
        actual = tomllib.loads(module.harden(text))
        self.assertEqual(actual["hypervisor"]["qemu"]["enable_annotations"], [])
        self.assertFalse(actual["factory"]["enable_template"])
        self.assertEqual(actual["factory"]["vm_cache_number"], 0)
        self.assertTrue(actual["runtime"]["sandbox_cgroup_only"])
        self.assertFalse(actual["runtime"]["disable_new_netns"])
        self.assertEqual(actual["hypervisor"]["qemu"]["path"], "/opt/kata/bin/qemu-system-x86_64")
        with self.assertRaises(ValueError):
            module.harden('[hypervisor.dragonball]\npath="wrong-runtime"\n')

    def test_three_pools_quarantined_without_runtime(self):
        tf, settings = fixture()
        inv = inventory(validate(tf, settings), settings)["all"]
        self.assertEqual(len(inv["hosts"]), 9)
        self.assertFalse(inv["vars"]["kata_containers_enabled"])
        self.assertEqual(inv["vars"]["containerd_additional_runtimes"], [])
        self.assertEqual(inv["vars"]["cilium_extra_values"]["policyEnforcementMode"], "always")
        self.assertEqual(inv["vars"]["kube_kubeadm_controller_extra_args"]["disable-force-detach-on-timeout"], "true")
        oidc = inv["vars"]["kube_kubeadm_apiserver_extra_args"]
        self.assertEqual(oidc["service-account-jwks-uri"], oidc["service-account-issuer"].rstrip("/") + "/openid/v1/jwks")
        self.assertEqual(oidc["service-account-max-token-expiration"], "3600s")
        self.assertEqual(oidc["service-account-extend-token-expiration"], "false")
        for name in inv["children"]["kata"]["hosts"]:
            self.assertIn("sandbox.platform/unverified=true:NoSchedule", inv["hosts"][name]["node_taints"])

    def test_reject_attack_and_broken_topology_inputs(self):
        mutations = [
            lambda t, s: s.update(pod_cidr=s["service_cidr"]),
            lambda t, s: s.update(pod_cidr="10.80.0.0/16"),
            lambda t, s: s.update(mtu=1500),
            lambda t, s: s.update(host_image_evidence_sha256="0" * 64),
            lambda t, s: s.update(ssh_known_hosts_file="/tmp/keys -oProxyCommand=malicious"),
            lambda t, s: s.update(download_proxy="http://user:secret@proxy.invalid:80"),
            lambda t, s: s.update(trusted_egress_cidrs=["0.0.0.0/0"]),
            lambda t, s: s.update(database_password="not-an-installation-field"),
            lambda t, s: t["workspace_kms_key_id"].update(sensitive=True),
            lambda t, s: t.update(database_password={"sensitive": False, "value": "not-an-installation-output"}),
            lambda t, s: t["node_inventory"]["value"]["kata-2"].update(zone="cn-hangzhou-h"),
            lambda t, s: t["node_inventory"]["value"]["kata-0"].update(private_ip="8.8.8.8"),
            lambda t, s: t["node_inventory"]["value"]["kata-0"].update(id="i-test00"),
            lambda t, s: t["workload_roles"]["value"]["csi-node"].update(subject="system:serviceaccount:default:attacker"),
            lambda t, s: t["workload_roles"]["value"]["csi-node"].update(audience="*"),
        ]
        for mutation in mutations:
            tf, settings = fixture()
            mutation(tf, settings)
            with self.subTest(mutation=mutation), self.assertRaises((ValueError, KeyError)):
                validate(tf, settings)

    def test_generate_refuses_overwrite_and_sandbox_activation(self):
        tf, settings = fixture()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "tf.json").write_text(json.dumps(tf))
            (base / "settings.json").write_text(json.dumps(settings))
            generate(base / "tf.json", base / "settings.json", base / "deployment")
            with self.assertRaises(ValueError):
                generate(base / "tf.json", base / "settings.json", base / "deployment")
            result = subprocess.run([sys.executable, str(ROOT / "cluster.py"), "enable-sandboxes", "--deployment", str(base / "deployment")], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("nodeguard", result.stderr)


class RealUpstreamRenderingTest(unittest.TestCase):
    def generated(self, base):
        tf, settings = fixture()
        (base / "tf.json").write_text(json.dumps(tf))
        (base / "settings.json").write_text(json.dumps(settings))
        generate(base / "tf.json", base / "settings.json", base / "deployment")
        return base / "deployment"

    def test_changed_inputs_fail_before_helm_and_leave_policies_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            deployment = self.generated(Path(directory))
            render(deployment, DEFAULT_CACHE)
            policy = (deployment / "trusted-policies.yaml").read_bytes()
            inputs = json.loads((deployment / "inputs.json").read_text())
            inputs["settings"]["trusted_egress_cidrs"] = ["0.0.0.0/0"]
            (deployment / "inputs.json").write_text(json.dumps(inputs))
            with patch("render.subprocess.check_output", side_effect=AssertionError("unvalidated inputs reached Helm")) as helm:
                with self.assertRaisesRegex(ValueError, "installation|inputs"):
                    render(deployment, DEFAULT_CACHE)
                helm.assert_not_called()
            self.assertEqual((deployment / "trusted-policies.yaml").read_bytes(), policy)

    def test_changed_derived_policy_is_rejected_instead_of_silently_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            deployment = self.generated(Path(directory))
            render(deployment, DEFAULT_CACHE)
            with (deployment / "trusted-policies.yaml").open("a") as stream:
                stream.write("\n# unreviewed drift\n")
            with self.assertRaisesRegex(ValueError, "installation|trusted-policies"):
                render(deployment, DEFAULT_CACHE)

    def test_direct_renderer_rejects_unbound_inputs_without_inventory_snapshot(self):
        tf, settings = fixture()
        with tempfile.TemporaryDirectory() as directory:
            deployment = Path(directory)
            (deployment / "inputs.json").write_text(json.dumps({"outputs": validate(tf, settings), "settings": settings}))
            with self.assertRaises((ValueError, FileNotFoundError)):
                render(deployment, DEFAULT_CACHE)

    def test_rewritten_checksums_do_not_bypass_business_validation_or_inventory_binding(self):
        for invalid in (True, False):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as directory:
                deployment = self.generated(Path(directory))
                inputs = json.loads((deployment / "inputs.json").read_text())
                inputs["settings"]["trusted_egress_cidrs"] = ["0.0.0.0/0" if invalid else "10.2.0.0/16"]
                (deployment / "inputs.json").write_text(json.dumps(inputs))
                manifest = json.loads((deployment / INSTALLATION_FILE).read_text())
                manifest["files"]["inputs.json"] = digest(deployment / "inputs.json")
                (deployment / INSTALLATION_FILE).write_text(json.dumps(manifest))
                with self.assertRaisesRegex(ValueError, "unbounded|does not match"):
                    load_installation(deployment)

    def test_every_cluster_execution_entry_rejects_input_drift_before_host_access(self):
        for command in ("check", "install-control-plane", "install-addons", "upgrade", "backup-etcd", "restore-etcd", "enable-sandboxes"):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as directory:
                deployment = self.generated(Path(directory))
                with (deployment / "inputs.json").open("a") as stream:
                    stream.write("\n")
                arguments = [sys.executable, str(ROOT / "cluster.py"), command, "--deployment", str(deployment)]
                if command not in ("check", "enable-sandboxes"):
                    arguments.append("--execute")
                if command == "install-addons":
                    arguments += ["--identity-config", str(Path(directory) / "missing.json"), "--cluster-epoch", "test-only"]
                if command == "restore-etcd":
                    arguments += ["--recovery-vars", str(Path(directory) / "missing.json")]
                result = subprocess.run(arguments, capture_output=True, text=True, timeout=15)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("installation file changed after review: inputs.json", result.stderr)

    def test_manifest_cannot_omit_existing_derived_resource(self):
        with tempfile.TemporaryDirectory() as directory:
            deployment = self.generated(Path(directory))
            render(deployment, DEFAULT_CACHE)
            manifest = json.loads((deployment / INSTALLATION_FILE).read_text())
            manifest["files"] = {name: manifest["files"][name] for name in INPUT_FILES}
            (deployment / INSTALLATION_FILE).write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "unbound rendered resources"):
                load_installation(deployment)

    def test_resealed_world_policy_cannot_diverge_from_validated_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            deployment = self.generated(Path(directory))
            render(deployment, DEFAULT_CACHE)
            path = deployment / "trusted-policies.yaml"
            resources = list(yaml.safe_load_all(path.read_text()))
            resources[0]["spec"]["egress"][-1]["toCIDR"] = ["0.0.0.0/0"]
            path.write_text(yaml.safe_dump_all(resources))
            manifest = json.loads((deployment / INSTALLATION_FILE).read_text())
            manifest["files"]["trusted-policies.yaml"] = digest(path)
            (deployment / INSTALLATION_FILE).write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "policies do not match"):
                load_installation(deployment, require_rendered=True)

    def test_symlinked_inputs_and_partial_resource_publication_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            deployment = self.generated(Path(directory))
            original = deployment / "inputs.json"
            outside = Path(directory) / "external.json"
            original.rename(outside)
            original.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "unsafe: inputs.json"):
                load_installation(deployment)
            original.unlink(); outside.rename(original)
            (deployment / "csi.yaml").write_text("partial render")
            with self.assertRaisesRegex(ValueError, "unbound rendered resources"):
                load_installation(deployment)

    def test_host_command_consumes_private_frozen_inventory_and_policy_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            deployment = self.generated(Path(directory))
            render(deployment, DEFAULT_CACHE)
            snapshot = load_installation(deployment, require_rendered=True)
            policy = (deployment / "trusted-policies.yaml").read_bytes()
            def execute(command, **kwargs):
                frozen_inventory = Path(command[command.index("-i") + 1])
                variables = json.loads(command[-1])
                frozen = Path(variables["sandbox_deployment_dir"])
                self.assertNotEqual(frozen, deployment)
                self.assertEqual(frozen_inventory.parent, frozen)
                self.assertEqual(Path(variables["artifacts_dir"]), deployment / "artifacts")
                self.assertEqual(Path(variables["credentials_dir"]), deployment / "credentials")
                self.assertEqual(Path(variables["sandbox_receipts_dir"]), deployment)
                with (deployment / "trusted-policies.yaml").open("a") as stream:
                    stream.write("\n# changed during host command\n")
                self.assertEqual((frozen / "trusted-policies.yaml").read_bytes(), policy)
                load_installation(frozen, expected=snapshot["binding"], require_rendered=True)
            with patch("cluster.run", side_effect=execute) as process:
                with self.assertRaisesRegex(ValueError, "trusted-policies.yaml"):
                    ansible(DEFAULT_CACHE, deployment, ROOT / "addons.yaml", installation=snapshot, require_rendered=True)
                process.assert_called_once()

    def test_locked_cilium_node_selectors_without_cidr_reinterpretation(self):
        tf, settings = fixture()
        from cluster import inventory
        values = inventory(validate(tf, settings), settings)["all"]["vars"]["cilium_extra_values"]
        self.assertTrue(values["nodeSelectorLabels"])
        self.assertTrue(values["clustermesh"]["policyDefaultLocalCluster"])
        self.assertNotIn("policyCIDRMatchMode", values)
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "values.yaml"
            file.write_text(yaml.safe_dump(values))
            raw = subprocess.check_output([str(DEFAULT_CACHE / "helm"), "template", "cilium", str(DEFAULT_CACHE / "cilium"), "--namespace", "kube-system", "-f", str(file)], text=True)
            config = next(v["data"] for v in yaml.safe_load_all(raw) if v and v["kind"] == "ConfigMap" and v["metadata"]["name"] == "cilium-config")
            self.assertEqual(config["enable-node-selector-labels"], "true")
            self.assertEqual(config["policy-default-local-cluster"], "true")

    def test_locked_chart_structural_transform_and_official_schema(self):
        tf, settings = fixture()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            deployment = self.generated(base)
            render(deployment, DEFAULT_CACHE)
            docs = list(yaml.safe_load_all((deployment / "csi.yaml").read_text()))
            workloads = [d for d in docs if d["kind"] in ["Deployment", "DaemonSet"]]
            self.assertEqual(len(workloads), 2)
            for work in workloads:
                pod = work["spec"]["template"]["spec"]
                self.assertTrue(pod["serviceAccountName"].startswith("sandbox-csi-"))
                if work["kind"] == "DaemonSet":
                    self.assertNotIn("nodeSelector", pod)
                    self.assertEqual(pod["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"], [{"matchExpressions": [{"key": "sandbox.platform/node-pool", "operator": "In", "values": ["kata", "platform"]}]}])
                for container in pod["containers"] + pod.get("initContainers", []):
                    self.assertIn("@sha256:", container["image"])
                    identity_mount = [v for v in container.get("volumeMounts", []) if v["name"] == "cloud-identity"]
                    if identity_mount:
                        self.assertIn("/acs/csi-plugin@", container["image"])
            self.assertFalse(any(d["kind"] == "RuntimeClass" for d in docs))
            for role in [d for d in docs if d["kind"] in ["Role", "ClusterRole"]]:
                self.assertFalse(any("secrets" in rule["resources"] for rule in role["rules"]))
            sc = next(d for d in docs if d["kind"] == "StorageClass")
            self.assertEqual(sc["reclaimPolicy"], "Retain")
            self.assertEqual(sc["parameters"]["diskTags/Deployment"], settings["deployment"])
            self.assertEqual(sc["volumeBindingMode"], "WaitForFirstConsumer")
            broken = copy.deepcopy(next(w for w in workloads if w["kind"] == "Deployment"))
            broken["spec"]["replicas"] = "invalid-integer"
            with self.assertRaises(Exception):
                validate_schema([broken], DEFAULT_CACHE)

    def test_upstream_installation_policy_order(self):
        plays = yaml.safe_load(bootstrap_playbook(DEFAULT_CACHE).read_text())
        cni = next(i for i, p in enumerate(plays) if p.get("name") == "Invoke kubeadm and install a CNI")
        self.assertTrue(plays[cni - 1]["ansible.builtin.import_playbook"].endswith("early-policies.yaml"))

    def test_unknown_upstream_image_and_principal_fail_closed(self):
        tf, settings = fixture()
        obj = {"kind": "ServiceAccount", "metadata": {"name": "unknown"}}
        with self.assertRaises(ValueError):
            post_render([obj], validate(tf, settings), settings, LOCK["csi_images"])
        deployment = {"kind": "Deployment", "metadata": {"name": "csi-provisioner"}, "spec": {"selector": {"matchLabels": {"app": "csi-provisioner"}}, "template": {"spec": {"serviceAccountName": "alicloud-csi-provisioner", "containers": [{"name": "injected", "image": "attacker.invalid/root:latest"}]}}}}
        with self.assertRaisesRegex(ValueError, "unlocked upstream image"):
            post_render([deployment], validate(tf, settings), settings, LOCK["csi_images"])


if __name__ == "__main__":
    unittest.main()
