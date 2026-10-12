import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from uuid import UUID
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


renderer = module('volume_renderer', ROOT / 'render.py')
sys.path.insert(0, str(ROOT))
preparer = module('volume_preparer', ROOT / 'prepare.py')
gate = module('volume_policy_gate', REPO / 'deploy/policy_boundary.py')


def fixture(replicas=2):
    # Invented cloud identity, image digest, registration and public CA only.
    # This fixture is not a cloud certification or a deployment input.
    return {'schema_version': 1, 'image': 'registry.example.test/service@sha256:' + 'a' * 64,
        'replicas': replicas, 'platform_nodes': [
            {'hostname': 'platform-' + str(i), 'zone': 'cn-hangzhou-' + zone}
            for i, zone in enumerate('hijhijhij', 1)],
        'database': {'secret': {'name': 'volume-db-revision1', 'key': 'url'},
            'host': 'postgres.example.test', 'port': 5432,
            'ca_pem': (REPO / 'tests/fixtures/admission/server-ca.pem').read_text()},
        'configuration': {'cloud': {'account_id': '1234567890123456', 'region': 'cn-hangzhou',
            'role_arn': 'acs:ram::1234567890123456:role/sbx-test-volume-deleter', 'role_id': '123456',
            'oidc_provider_arn': 'acs:ram::1234567890123456:oidc-provider/sbx-test-kubernetes',
            'oidc_issuer': 'https://oidc.example.test/cluster', 'oidc_audience': 'sts.aliyuncs.com',
            'oidc_subject': 'system:serviceaccount:sandbox-system:sandbox-volume-deleter',
            'oidc_token_file': '/var/run/sandbox-cloud/token', 'deployment': 'sbx-test',
            'requests_per_second': 2, 'max_in_flight': 2},
            'storage': {'storage_class': 'sandbox-workspace', 'kms_key_id': 'test-workspace-kms',
                'zones': ['cn-hangzhou-h', 'cn-hangzhou-i', 'cn-hangzhou-j'], 'deployment': 'sbx-test',
                'certification_id': 'PUBLIC_TEST_ONLY_NOT_CERTIFIED'}, 'concurrency': 2},
        'projects': [{'tenant_id': str(UUID(int=1)), 'project_id': str(UUID(int=i)), 'namespace': 'sbx-project-' + str(i)}
            for i in [2, 3]], 'db_max_connections': 10}


def prepare_fixture():
    value = fixture()
    config, cloud = value['configuration'], value['configuration']['cloud']
    settings = {key: value[key] for key in ['schema_version', 'image', 'replicas', 'projects', 'db_max_connections']}
    settings['database'] = {key: value['database'][key] for key in ['secret', 'ca_pem']}
    settings.update({key: cloud[key] for key in ['requests_per_second', 'max_in_flight']})
    settings.update({key: config['storage'][key] for key in ['storage_class', 'certification_id']})
    settings['concurrency'] = config['concurrency']
    outputs = {'vpc_id': 'vpc-test', 'subnets': {}, 'private_entrances': {}, 'object_storage': {},
        'deployment_identity': {'deployment': cloud['deployment'], 'region': cloud['region'],
            'cloud_account_id': cloud['account_id'], 'environment': 'test'},
        'database': {'id': 'rds-test', 'endpoint': value['database']['host'], 'port': 5432,
            'engine': 'PostgreSQL', 'major_version': 17},
        'node_inventory': {node['hostname']: {'id': 'i-test-' + str(i), 'private_ip': '10.80.1.' + str(i + 10),
            'role': 'platform', 'zone': node['zone']} for i, node in enumerate(value['platform_nodes'], 1)},
        'workload_roles': {'volume-deleter': {'arn': cloud['role_arn'], 'role_id': cloud['role_id'],
            'subject': cloud['oidc_subject'], 'issuer': cloud['oidc_issuer'], 'audience': cloud['oidc_audience']}},
        'workspace_kms_key_id': config['storage']['kms_key_id'], 'workload_oidc_provider_arn': cloud['oidc_provider_arn']}
    return settings, outputs


def resource(value, kind):
    return next(item for item in value['items'] if item['kind'] == kind)


class VolumeInstaller(unittest.TestCase):
    def test_role_uses_actual_storage_class_exact_namespaces_and_no_writes_outside_cleanup(self):
        value = fixture(); value['configuration']['storage']['storage_class'] = 'reviewed-workspace'
        objects = renderer.identities(value)['items']
        self.assertNotIn('Deployment', [o['kind'] for o in objects])
        self.assertEqual(len(objects), 7)
        rules = next(o for o in objects if o['kind'] == 'ClusterRole')['rules']
        self.assertEqual(rules, [
            {'apiGroups': [''], 'resources': ['namespaces'],
                'resourceNames': ['sbx-project-2', 'sbx-project-3'], 'verbs': ['get']},
            {'apiGroups': [''], 'resources': ['persistentvolumes'], 'verbs': ['get', 'delete']},
            {'apiGroups': ['storage.k8s.io'], 'resources': ['storageclasses'], 'resourceNames': ['reviewed-workspace'], 'verbs': ['get']},
            {'apiGroups': ['storage.k8s.io'], 'resources': ['volumeattachments'], 'verbs': ['list']}])
        for binding in [o for o in objects if o['kind'].endswith('Binding')]:
            self.assertEqual(binding['subjects'], [{'kind': 'ServiceAccount', 'name': renderer.NAME, 'namespace': renderer.NS}])
        roles = [o for o in objects if o['kind'] == 'Role']
        self.assertEqual({r['metadata']['namespace'] for r in roles}, {'sbx-project-2', 'sbx-project-3'})
        for role in roles:
            self.assertEqual(role['rules'], [
                {'apiGroups': [''], 'resources': ['persistentvolumeclaims'], 'verbs': ['get', 'delete']},
                {'apiGroups': [''], 'resources': ['pods'], 'verbs': ['list']}])
        text = json.dumps(objects)
        for forbidden in ['patch', 'update', 'create', 'pods/exec', 'secrets', '*']:
            self.assertNotIn(forbidden, text)

    def test_real_controller_cli_file_paths_dedicated_projected_tokens_and_nonroot_permissions(self):
        value = fixture(); objects = renderer.workload(value)
        pod = resource(objects, 'Deployment')['spec']['template']['spec']; controller = pod['containers'][0]
        self.assertFalse(pod['automountServiceAccountToken'])
        self.assertEqual(pod['serviceAccountName'], renderer.NAME)
        self.assertEqual(pod['securityContext']['runAsUser'], 10001)
        self.assertEqual(pod['securityContext']['runAsGroup'], 10001)
        self.assertEqual(pod['securityContext']['fsGroup'], 10001)
        self.assertEqual(controller['command'], ['/usr/local/bin/sandboxd'])
        self.assertEqual(controller['args'], ['--role', 'volume-deleter'])
        env = {v['name']: v.get('value', v.get('valueFrom')) for v in controller['env']}
        self.assertEqual(env['SANDBOX_PROCESS_POD_UID'], {'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.uid'}})
        self.assertEqual(sum(v['name'] == 'SANDBOX_PROCESS_POD_UID' for v in controller['env']), 1)
        self.assertEqual(env['SANDBOX_DATABASE_URL'], {'secretKeyRef': value['database']['secret']})
        self.assertEqual(env['SANDBOX_VOLUME_DELETION_CONFIG_FILE'], renderer.CONFIG)
        self.assertEqual(env['SANDBOX_ALLOW_LOOPBACK_HTTP'], 'false')
        cloud = next(v for v in pod['volumes'] if v['name'] == 'cloud-identity')['projected']
        self.assertEqual(cloud['sources'], [{'serviceAccountToken': {'path': 'token', 'audience': 'sts.aliyuncs.com', 'expirationSeconds': 600}}])
        kube = next(v for v in pod['volumes'] if v['name'] == 'kube-api')['projected']['sources'][0]['serviceAccountToken']
        self.assertNotIn('audience', kube); self.assertEqual(kube['expirationSeconds'], 3600)
        self.assertTrue(all(m['readOnly'] for m in controller['volumeMounts']))
        self.assertEqual(controller['securityContext'], {'readOnlyRootFilesystem': True,
            'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}})
        for volume in pod['volumes']:
            self.assertEqual(volume.get('configMap', volume.get('projected'))['defaultMode'], 0o440)
        for forbidden in ['Service', 'Secret', 'Job']:
            self.assertNotIn(forbidden, [o['kind'] for o in objects['items']])
        for forbidden in ['hostNetwork', 'hostPath', 'privileged', '/bin/sh', 'tcpSocket', 'httpGet', 'nodeguard']:
            self.assertNotIn(forbidden, json.dumps(objects))
        configmap = next(o for o in objects['items'] if o['kind'] == 'ConfigMap' and 'config.json' in o['data'])
        self.assertTrue(configmap['immutable'])
        self.assertEqual(json.loads(configmap['data']['config.json']), value['configuration'])

    def test_narrow_regional_cloud_dns_database_api_policy_no_public_ingress_or_issuer_fetch(self):
        policy = resource(renderer.workload(fixture()), 'CiliumNetworkPolicy')['spec']
        self.assertEqual(policy['enableDefaultDeny'], {'ingress': True, 'egress': True})
        self.assertEqual(policy['ingress'], [])
        names = {item['matchName'] for rule in policy['egress'] for item in rule.get('toFQDNs', [])}
        self.assertEqual(names, {'postgres.example.test', 'sts.cn-hangzhou.aliyuncs.com', 'ecs.cn-hangzhou.aliyuncs.com'})
        dns = policy['egress'][0]['toPorts'][0]['rules']['dns']
        self.assertEqual({v['matchName'] for v in dns}, names)
        self.assertEqual(policy['egress'][-1], {'toEntities': ['kube-apiserver'],
            'toPorts': [{'ports': [{'port': '443', 'protocol': 'TCP'}, {'port': '6443', 'protocol': 'TCP'}]}]})
        text = json.dumps(policy)
        for forbidden in ['world', 'remote-node', '100.100.100.200', '0.0.0.0/0', 'toCIDR', 'matchPattern', '*', 'oidc.example.test']:
            self.assertNotIn(forbidden, text)

    def test_balanced_rolling_surge_ha_for_all_supported_sizes(self):
        for replicas in range(2, 9):
            objects = renderer.workload(fixture(replicas))
            d = resource(objects, 'Deployment')['spec']; pod = d['template']['spec']
            self.assertEqual(d['strategy']['rollingUpdate'], {'maxUnavailable': 0, 'maxSurge': 1})
            self.assertEqual(pod['topologySpreadConstraints'][0]['minDomains'], 3)
            self.assertEqual(pod['nodeSelector'], {'sandbox.platform/node-pool': 'platform'})
            self.assertEqual(resource(objects, 'PodDisruptionBudget')['spec']['minAvailable'], replicas - 1)
        for nodes in [fixture()['platform_nodes'][:2], fixture()['platform_nodes'][:3]]:
            value = fixture(3); value['platform_nodes'] = nodes
            with self.assertRaises(ValueError): renderer.workload(value)
        value = fixture(8); value['platform_nodes'][-1]['zone'] = 'cn-hangzhou-h'
        with self.assertRaisesRegex(ValueError, 'SURGE_CAPACITY'): renderer.workload(value)

    def test_configuration_and_ca_changes_have_immutable_rollout_names(self):
        value = fixture(); before = renderer.workload(value)
        value['configuration']['concurrency'] = 3
        after = renderer.workload(value)
        names = lambda data: {o['metadata']['name'] for o in data['items'] if o['kind'] == 'ConfigMap'}
        self.assertNotEqual(names(before), names(after))
        old = resource(before, 'Deployment')['spec']['template']['metadata']['annotations']
        new = resource(after, 'Deployment')['spec']['template']['metadata']['annotations']
        self.assertNotEqual(old, new)
        value['database']['ca_pem'] = (REPO / 'tests/fixtures/admission/outsider-ca.pem').read_text()
        self.assertNotEqual(names(after), names(renderer.workload(value)))

    def test_production_bootstrap_overlap_gate_rejects_added_broad_allow(self):
        sys.path.insert(0, str(REPO / 'deploy/cluster'))
        cluster = module('volume_cluster', REPO / 'deploy/cluster/cluster.py')
        manifests = module('volume_cluster_renderer', REPO / 'deploy/cluster/render.py')
        with patch.dict(sys.modules, {'render': manifests, 'cluster': cluster}):
            tests = module('volume_cluster_fixture', REPO / 'deploy/cluster/tests/test_cluster.py')
        tf, settings = tests.fixture()
        bootstrap = manifests.policies(cluster.validate(tf, settings), settings)
        objects = renderer.workload(fixture()); policy = resource(objects, 'CiliumNetworkPolicy')
        labels = resource(objects, 'Deployment')['spec']['template']['metadata']['labels']
        identity = {'k8s:' + key: value for key, value in labels.items()} | {
            'k8s:io.kubernetes.pod.namespace': renderer.NS,
            'k8s:io.cilium.k8s.policy.serviceaccount': renderer.NAME,
            'k8s:io.cilium.k8s.policy.cluster': 'default'}
        def check(extra):
            return gate.analyze(policy, renderer.NS, {'kubernetes.io/metadata.name': renderer.NS}, labels, renderer.NAME,
                [{'kind': 'List', 'items': [policy] + extra}], endpoint_labels=identity)
        self.assertEqual(check(bootstrap)['configuration_overlap'], 'PASS')
        self.assertEqual(check(bootstrap)['runtime_enforcement'], 'NOT_VERIFIED')
        for extra in [[{'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
                'metadata': {'name': 'wide', 'namespace': renderer.NS}, 'spec': {'podSelector': {}, 'egress': [{}]}}],
                [{'apiVersion': 'cilium.io/v2', 'kind': 'CiliumClusterwideNetworkPolicy', 'metadata': {'name': 'wide'},
                  'spec': {'endpointSelector': {}, 'ingress': [{}]}}]]:
            with self.assertRaises(gate.BoundaryError): check(bootstrap + extra)

    def test_source_binding_uses_real_output_keys_and_rejects_cross_account_role_provider_and_host_overrides(self):
        settings, outputs = prepare_fixture()
        self.assertEqual(preparer.prepare(settings, outputs), fixture())
        wrapped = {key: {'value': value, 'sensitive': False, 'type': 'public-fixture'} for key, value in outputs.items()}
        self.assertEqual(preparer.prepare(settings, wrapped), fixture())
        mutations = [lambda s, o: o['deployment_identity'].update(cloud_account_id='9999999999999999'),
            lambda s, o: o['workload_roles']['volume-deleter'].update(arn='acs:ram::1234567890123456:role/sbx-test-fencing'),
            lambda s, o: o['workload_roles']['volume-deleter'].update(subject='system:serviceaccount:sandbox-system:sandbox-worker'),
            lambda s, o: o.update(workload_oidc_provider_arn='acs:ram::1234567890123456:oidc-provider/another-kubernetes'),
            lambda s, o: s['database'].update(host='overridden.example.test'),
            lambda s, o: o['database'].update(engine='MySQL'), lambda s, o: o['database'].update(major_version=16),
            lambda s, o: o['node_inventory']['platform-2'].update(id=o['node_inventory']['platform-1']['id']),
            lambda s, o: s.update(configuration={}), lambda s, o: s.update(role_id='guessed')]
        for mutation in mutations:
            settings, outputs = prepare_fixture(); mutation(settings, outputs)
            with self.assertRaises((ValueError, KeyError)): preparer.prepare(settings, outputs)
        wrapped['workload_roles']['sensitive'] = True
        with self.assertRaises(ValueError): preparer.prepare(prepare_fixture()[0], wrapped)

    def test_strict_bounds_wrong_identities_unregistered_control_scopes_and_private_keys_rejected(self):
        mutations = [lambda v: v.update(replicas=True), lambda v: v.update(replicas=1), lambda v: v.update(replicas=9),
            lambda v: v.update(image='service:latest'), lambda v: v.update(schema_version=True), lambda v: v.update(extra={}),
            lambda v: v['configuration']['cloud'].update(role_arn='acs:ram::1234567890123456:role/admin'),
            lambda v: v['configuration']['cloud'].update(oidc_token_file='/tmp/token'),
            lambda v: v['configuration']['cloud'].update(oidc_audience='*'),
            lambda v: v['configuration']['cloud'].update(oidc_issuer='https://oidc.sandbox-system.svc/cluster'),
            lambda v: v['configuration']['cloud'].update(oidc_issuer='https://oidc.example.test/../cluster'),
            lambda v: v['configuration']['cloud'].update(access_key='private'),
            lambda v: v['configuration']['cloud'].update(max_in_flight=True),
            lambda v: v['configuration'].update(concurrency=17), lambda v: v.update(db_max_connections=3),
            lambda v: v['configuration']['storage'].update(deployment='other'),
            lambda v: v['configuration']['storage'].update(zones=['cn-beijing-a', 'cn-beijing-b', 'cn-beijing-c']),
            lambda v: v['database'].update(host='127.0.0.1'), lambda v: v['database'].update(port=True),
            lambda v: v['database'].update(ca_pem=(REPO / 'tests/fixtures/admission/apiserver.key').read_text()),
            lambda v: v['database']['secret'].update(value='private'), lambda v: v['projects'][0].update(namespace='kube-system'),
            lambda v: v['projects'][0].update(namespace='sandbox-system'), lambda v: v['projects'][0].update(tenant_id=str(UUID(int=0))),
            lambda v: v['projects'][0].update(project_id=v['projects'][1]['project_id']),
            lambda v: v['projects'][0].update(namespace=v['projects'][1]['namespace'])]
        for mutation in mutations:
            value = fixture(); mutation(value)
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError): renderer.workload(value)

    def test_real_prepare_and_render_cli_strict_json_create_only_and_activation_separation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            for raw in ['{"x":1,"x":2}', '{"x":NaN}', '{"x":1e999}', 'x' * 262145]:
                (path / 'bad.json').write_text(raw)
                with self.assertRaises(ValueError): renderer.load(path / 'bad.json')
            settings, outputs = prepare_fixture()
            for filename, value in [('settings.json', settings), ('outputs.json', outputs)]:
                (path / filename).write_text(json.dumps(value))
            prepare = [sys.executable, str(ROOT / 'prepare.py'), '--settings', str(path / 'settings.json'),
                '--terraform-output', str(path / 'outputs.json'), '--output', str(path / 'input.json')]
            result = subprocess.run(prepare, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            render = [sys.executable, str(ROOT / 'render.py'), '--input', str(path / 'input.json'),
                '--identity-out', str(path / 'identity.json'), '--workload-out', str(path / 'workload.json')]
            result = subprocess.run(render, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(json.loads((path / 'identity.json').read_text()), renderer.identities(fixture()))
            self.assertEqual(json.loads((path / 'workload.json').read_text()), renderer.workload(fixture()))
            before = (path / 'workload.json').read_bytes()
            result = subprocess.run(render, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0); self.assertEqual((path / 'workload.json').read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
