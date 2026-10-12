import copy
import importlib.util
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "cluster/tests"))
from test_cluster import fixture, inventory, validate

spec = importlib.util.spec_from_file_location("automation_deploy", pathlib.Path(__file__).parents[1] / "automation.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class ProductionIsolation(unittest.TestCase):
    def config(self):
        return {"namespace": "sandbox-system", "image": "registry.example.test/platform@sha256:" + "a" * 64, "database_secret": "automation-database", "database_secret_key": "url", "database_ca_config_map": "database-ca", "database_cidrs": ["10.20.1.0/24", "10.20.2.0/24"], "replicas": 2, "default_ttl_seconds": 3600, "max_ttl_seconds": 86400, "db_max_connections": 4}
    def test_renderer_has_no_secret_material_and_no_guest_or_cloud_privileges(self):
        config = self.config()
        manifest = module.render(config)
        items = {i["kind"]: i for i in manifest["items"]}
        pod = items["Deployment"]["spec"]["template"]["spec"]
        pod_labels = items["Deployment"]["spec"]["template"]["metadata"]["labels"]
        self.assertEqual(pod_labels["sandbox.platform/network-policy"], "automation-v1")
        self.assertEqual(items["CiliumNetworkPolicy"]["spec"]["endpointSelector"]["matchLabels"], pod_labels)
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertEqual(pod["nodeSelector"]["sandbox.platform/node-pool"], "platform")
        self.assertEqual(pod["topologySpreadConstraints"][0]["minDomains"], 2)
        container = pod["containers"][0]
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        self.assertEqual(container["env"][0]["valueFrom"]["secretKeyRef"]["name"], "automation-database")
        self.assertNotIn("value", container["env"][0])
        self.assertEqual(items["CiliumNetworkPolicy"]["spec"]["egress"][1]["toCIDR"], config["database_cidrs"])
        self.assertEqual(items["PodDisruptionBudget"]["spec"]["minAvailable"], 1)
        self.assertNotIn("RoleBinding", items)

    def test_actual_inventory_has_three_schedulable_platform_zones(self):
        tf, settings = fixture()
        hosts = inventory(validate(tf, settings), settings)["all"]["hosts"]
        pod = next(item for item in module.render(self.config())["items"]
                   if item["kind"] == "Deployment")["spec"]["template"]["spec"]
        selected = [host for host in hosts.values()
                    if host["node_labels"]["sandbox.platform/node-pool"]
                    == pod["nodeSelector"]["sandbox.platform/node-pool"]]
        eligible = [host for host in selected if not any(
            taint.endswith(":NoSchedule") or taint.endswith(":NoExecute")
            for taint in host["node_taints"])]
        self.assertEqual(len(eligible), 3)
        self.assertEqual(len({host["node_labels"]["topology.kubernetes.io/zone"]
                              for host in eligible}), 3)
        self.assertTrue(all(host["node_labels"]["sandbox.platform/node-pool"]
                            == "platform" for host in eligible))
        self.assertNotIn("tolerations", pod)
    def test_worker_command_and_process_identity_use_exact_downward_api(self):
        items={item['kind']:item for item in module.render(self.config())['items']}
        pod=items['Deployment']['spec']['template']['spec'];container=pod['containers'][0]
        self.assertEqual(container['command'],['/usr/local/bin/sandbox-automation'])
        names=[entry['name'] for entry in container['env']]
        self.assertEqual(len(names),len(set(names)))
        identity=next(entry for entry in container['env'] if entry['name']=='SANDBOX_PROCESS_POD_UID')
        self.assertEqual(identity,{'name':'SANDBOX_PROCESS_POD_UID','valueFrom':{'fieldRef':{'apiVersion':'v1','fieldPath':'metadata.uid'}}})
        self.assertNotIn('envFrom',container)
        self.assertEqual(container['volumeMounts'],[{'name':'database-ca','mountPath':'/etc/sandbox-automation-db-ca','readOnly':True}])
        self.assertFalse(pod['automountServiceAccountToken'])
        self.assertEqual(container['readinessProbe']['httpGet'],{'path':'/health/ready','port':'health'})
        self.assertEqual(container['livenessProbe']['httpGet'],{'path':'/health/live','port':'health'})

    def test_no_inline_secrets_world_metadata_or_broad_egress(self):
        for cidr in ["0.0.0.0/0", "169.254.169.254/32", "10.0.0.0/8", "::/0", "192.0.2.0/24", "10.20.1.1/24"]:
            value = self.config(); value["database_cidrs"] = [cidr]
            with self.assertRaises(ValueError): module.render(value)
        value = self.config(); value["database_url"] = "TEST_ONLY"
        with self.assertRaises(ValueError): module.render(value)
    def test_immutable_image_and_bounded_ha_pool(self):
        for key, bad in [("image", "registry.example.test/platform:latest"), ("replicas", 1), ("db_max_connections", 128), ("default_ttl_seconds", 86401)]:
            value = copy.deepcopy(self.config()); value[key] = bad
            with self.assertRaises(ValueError): module.render(value)

if __name__ == "__main__": unittest.main()
