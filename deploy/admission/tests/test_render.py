import base64
import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


renderer = module('admission_renderer', ROOT / 'render.py')
gate = module('admission_policy_gate', REPO / 'deploy/policy_boundary.py')


def fixture(replicas=3):
    # PUBLIC test CAs and invented digest/inventory; never deploy this fixture.
    ca = lambda name: (REPO / 'tests/fixtures/admission' / name).read_text()
    return {'schema_version': 1, 'image': 'registry.example.test/service@sha256:' + 'a' * 64,
        'replicas': replicas, 'platform_nodes': [
            {'hostname': 'platform-' + str(index), 'zone': 'cn-hangzhou-' + zone}
            for index, zone in enumerate('hijhijhij', 1)],
        'config': {'name': 'admission-reviewed-revision1', 'key': 'config.json', 'sha256': 'b' * 64},
        'database': {'secret': {'name': 'admission-db-revision1', 'key': 'url'},
            'host': 'postgres.example.test', 'port': 5432, 'ca_pem': ca('server-ca.pem')},
        'server_tls': {'secret_name': 'admission-tls-revision1', 'certificate_key': 'tls.crt',
            'private_key_key': 'tls.key', 'server_ca_pem': ca('server-ca.pem')},
        'apiserver_client_ca_pem': ca('apiserver-ca.pem')}


def resource(values, kind):
    return next(item for item in values['items'] if item['kind'] == kind)


def identity(labels):
    return {'k8s:' + key: value for key, value in labels.items()} | {
        'k8s:io.kubernetes.pod.namespace': renderer.NS,
        'k8s:io.cilium.k8s.policy.serviceaccount': renderer.NAME,
        'k8s:io.cilium.k8s.policy.cluster': 'default'}


class AdmissionRenderer(unittest.TestCase):
    def test_real_cli_paths_projected_identity_private_permissions_and_local_probes(self):
        values = renderer.render(fixture())
        pod = resource(values, 'Deployment')['spec']['template']['spec']
        container = pod['containers'][0]
        self.assertEqual(pod['serviceAccountName'], renderer.NAME)
        self.assertFalse(pod['automountServiceAccountToken'])
        self.assertEqual(pod['dnsConfig'], {'options': [{'name': 'ndots', 'value': '1'}]})
        self.assertEqual(pod['securityContext']['runAsUser'], 10001)
        self.assertEqual(pod['securityContext']['runAsGroup'], 10001)
        self.assertEqual(pod['securityContext']['fsGroup'], 10001)
        self.assertEqual(container['args'], ['--config', '/etc/sandbox-admission/config.json',
            '--tls-certificate', '/etc/sandbox-admission-tls/tls.crt', '--tls-key', '/etc/sandbox-admission-tls/tls.key',
            '--apiserver-client-ca', '/etc/sandbox-admission-client-ca/ca.crt'])
        self.assertEqual(container['env'], [{'name': 'SANDBOX_ADMISSION_DATABASE_URL',
            'valueFrom': {'secretKeyRef': fixture()['database']['secret']}},
            {'name': 'SANDBOX_PROCESS_POD_UID', 'valueFrom': {'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.uid'}}}])
        for probe in ['startupProbe', 'readinessProbe', 'livenessProbe']:
            self.assertEqual(container[probe]['exec']['command'], ['/usr/local/bin/sandbox-admission', '--probe-local'])
            self.assertEqual(container[probe]['timeoutSeconds'], 2)
            self.assertNotIn('tcpSocket', container[probe]); self.assertNotIn('httpGet', container[probe])
        for volume in pod['volumes']:
            source = volume.get('configMap', volume.get('secret', volume.get('projected')))
            self.assertEqual(source['defaultMode'], 0o440)
        token = next(v for v in pod['volumes'] if v['name'] == 'kube-api')['projected']['sources'][0]
        self.assertEqual(token, {'serviceAccountToken': {'path': 'token', 'expirationSeconds': 3600}})
        self.assertTrue(all(m['readOnly'] for m in container['volumeMounts']))
        self.assertEqual(container['securityContext'], {'readOnlyRootFilesystem': True,
            'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}})
        self.assertNotIn('initContainers', pod)
        self.assertNotIn('Secret', [v['kind'] for v in values['items']])
        text = json.dumps(values)
        for forbidden in ['sts.aliyuncs.com', '100.100.100.200', 'cloud-identity', 'hostNetwork', 'hostPath', 'privileged', '/bin/sh']:
            self.assertNotIn(forbidden, text)

    def test_exact_get_only_rbac_service_san_and_separate_last_webhook(self):
        value = fixture(); values = renderer.render(value)
        role = resource(values, 'ClusterRole')
        self.assertEqual(role['rules'], [
            {'apiGroups': [''], 'resources': ['namespaces', 'nodes', 'pods', 'persistentvolumes', 'persistentvolumeclaims'], 'verbs': ['get']},
            {'apiGroups': ['cilium.io'], 'resources': ['ciliumnetworkpolicies'], 'verbs': ['get']}])
        self.assertEqual(resource(values, 'ClusterRoleBinding')['subjects'],
            [{'kind': 'ServiceAccount', 'name': renderer.NAME, 'namespace': renderer.NS}])
        self.assertEqual(resource(values, 'Service')['spec']['ports'],
            [{'name': 'https', 'port': 443, 'targetPort': 'webhook', 'protocol': 'TCP'}])
        self.assertEqual(renderer.SERVER_NAMES, ['sandbox-admission.sandbox-system.svc', 'sandbox-admission.sandbox-system.svc.cluster.local'])
        self.assertNotIn('ValidatingWebhookConfiguration', [v['kind'] for v in values['items']])
        hook = renderer.webhook(value)['webhooks'][0]
        self.assertEqual(hook['failurePolicy'], 'Fail'); self.assertEqual(hook['timeoutSeconds'], 5)
        self.assertEqual(hook['admissionReviewVersions'], ['v1']); self.assertEqual(hook['sideEffects'], 'NoneOnDryRun')
        self.assertEqual(hook['clientConfig']['service'],
            {'namespace': renderer.NS, 'name': renderer.NAME, 'path': '/validate', 'port': 443})
        self.assertEqual(base64.b64decode(hook['clientConfig']['caBundle']).decode(), value['server_tls']['server_ca_pem'])
        self.assertNotIn('namespaceSelector', hook); self.assertNotIn('objectSelector', hook)
        self.assertIn('pods/exec', hook['rules'][0]['resources'])

    def test_three_az_bound_nodes_surge_and_pdb_for_all_supported_sizes(self):
        for replicas in range(2, 9):
            values = renderer.render(fixture(replicas))
            deployment = resource(values, 'Deployment')['spec']; pod = deployment['template']['spec']
            self.assertEqual(pod['nodeSelector'], {'sandbox.platform/node-pool': 'platform'})
            self.assertEqual(pod['topologySpreadConstraints'][0]['minDomains'], 3)
            self.assertTrue(all(s['whenUnsatisfiable'] == 'DoNotSchedule' for s in pod['topologySpreadConstraints']))
            affinity = pod['affinity']['nodeAffinity']['requiredDuringSchedulingIgnoredDuringExecution']['nodeSelectorTerms'][0]
            self.assertEqual(len(affinity['matchExpressions'][0]['values']), 9)
            self.assertEqual(pod['affinity']['podAntiAffinity']['requiredDuringSchedulingIgnoredDuringExecution'][0]['topologyKey'], 'kubernetes.io/hostname')
            self.assertEqual(deployment['strategy']['rollingUpdate'], {'maxUnavailable': 0, 'maxSurge': 1})
            self.assertEqual(resource(values, 'PodDisruptionBudget')['spec']['minAvailable'], replicas - 1)

    def test_immutable_public_trust_and_config_digest_rollout(self):
        value = fixture(); first = renderer.render(value)
        trust = resource(first, 'ConfigMap'); self.assertTrue(trust['immutable'])
        self.assertEqual(set(trust['data']), {'db-ca.pem', 'apiserver-client-ca.pem'})
        value['database']['ca_pem'] = (REPO / 'tests/fixtures/admission/outsider-ca.pem').read_text()
        second = renderer.render(value)
        self.assertNotEqual(trust['metadata']['name'], resource(second, 'ConfigMap')['metadata']['name'])
        value['config']['sha256'] = 'c' * 64
        self.assertEqual(resource(renderer.render(value), 'Deployment')['spec']['template']['metadata']['annotations']['sandbox.platform/config-sha256'], 'c' * 64)

    def test_network_is_exact_apiserver_dns_external_database_only(self):
        policy = resource(renderer.render(fixture()), 'CiliumNetworkPolicy')['spec']
        self.assertEqual(policy['endpointSelector']['matchLabels']['k8s:sandbox.platform/network-policy'], 'admission-v1')
        self.assertEqual(policy['enableDefaultDeny'], {'ingress': True, 'egress': True})
        self.assertEqual(policy['ingress'], [{'fromEntities': ['kube-apiserver'],
            'toPorts': [{'ports': [{'port': '8443', 'protocol': 'TCP'}]}]}])
        self.assertEqual(policy['egress'][0]['toPorts'][0]['rules']['dns'], [{'matchName': 'postgres.example.test'}])
        self.assertEqual(policy['egress'][1]['toFQDNs'], [{'matchName': 'postgres.example.test'}])
        self.assertEqual(policy['egress'][2], {'toEntities': ['kube-apiserver'],
            'toPorts': [{'ports': [{'port': '443', 'protocol': 'TCP'}, {'port': '6443', 'protocol': 'TCP'}]}]})
        text = json.dumps(policy)
        for forbidden in ['world', 'cluster"', 'host"', 'remote-node', 'toCIDR', 'matchPattern', '*']:
            self.assertNotIn(forbidden, text)

    def test_production_bootstrap_overlap_gate_and_additive_negative_cases(self):
        sys.path.insert(0, str(REPO / 'deploy/cluster'))
        cluster = module('admission_cluster', REPO / 'deploy/cluster/cluster.py')
        manifests = module('admission_cluster_renderer', REPO / 'deploy/cluster/render.py')
        tests = module('admission_cluster_fixture', REPO / 'deploy/cluster/tests/test_cluster.py')
        tf, settings = tests.fixture()
        actual_bootstrap = manifests.policies(cluster.validate(tf, settings), settings)
        values = renderer.render(fixture()); policy = resource(values, 'CiliumNetworkPolicy')
        labels = resource(values, 'Deployment')['spec']['template']['metadata']['labels']
        def check(extra):
            return gate.analyze(policy, renderer.NS, {'kubernetes.io/metadata.name': renderer.NS}, labels, renderer.NAME,
                [{'kind': 'List', 'items': [policy] + extra}], endpoint_labels=identity(labels))
        self.assertEqual(check(actual_bootstrap)['configuration_overlap'], 'PASS')
        self.assertEqual(check(actual_bootstrap)['runtime_enforcement'], 'NOT_VERIFIED')
        old = copy.deepcopy(actual_bootstrap)
        old[0]['spec']['endpointSelector']['matchExpressions'] = [rule for rule in old[0]['spec']['endpointSelector']['matchExpressions']
            if rule['key'] != 'k8s:sandbox.platform/network-policy']
        extras = [old, [{'kind': 'NetworkPolicy', 'metadata': {'name': 'broad', 'namespace': renderer.NS},
            'spec': {'podSelector': {}, 'egress': [{}]}}], [{'kind': 'CiliumClusterwideNetworkPolicy', 'metadata': {'name': 'broad'},
            'specs': [{'endpointSelector': {}, 'ingress': [{}]}]}]]
        for extra in extras:
            with self.assertRaises(gate.BoundaryError):
                check(extra)

    def test_unknown_fields_types_mutable_images_invalid_refs_and_wide_dependencies_rejected(self):
        mutations = [lambda v: v.update(cloud_role='admin'), lambda v: v.update(replicas=True), lambda v: v.update(replicas=1),
            lambda v: v.update(replicas=9), lambda v: v.update(schema_version=True), lambda v: v.update(image='service:latest'),
            lambda v: v['database'].update(port=True), lambda v: v['database'].update(port=443),
            lambda v: v['database'].update(host='127.0.0.1'), lambda v: v['database'].update(host='postgres.database.svc'),
            lambda v: v['database'].update(host='postgres.svc.cluster.local'), lambda v: v['database'].update(host='*.example.test'),
            lambda v: v['database'].update(host='Postgres.example.test'), lambda v: v['database']['secret'].update(value='private'),
            lambda v: v['config'].update(key='../config'), lambda v: v['config'].update(name='kube-root-ca.crt'),
            lambda v: v['config'].update(sha256='b' * 63), lambda v: v['server_tls'].update(private_key_key='tls.crt'),
            lambda v: v['server_tls'].update(secret_name=v['database']['secret']['name']),
            lambda v: v.update(platform_nodes=v['platform_nodes'][:2]),
            lambda v: v.update(platform_nodes=[{'hostname': 'one', 'zone': 'cn-hangzhou-h'}] * 9),
            lambda v: v.update(platform_nodes=[{'hostname': str(i), 'zone': 'cn-hangzhou-h'} for i in range(9)]),
            lambda v: v['platform_nodes'][0].update(hostname='a' * 64),
            lambda v: v['platform_nodes'][0].update(zone='cn-' + 'a' * 64),
            lambda v: v['platform_nodes'][0].update(role='kata')]
        for mutation in mutations:
            value = fixture(); mutation(value)
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError):
                    renderer.render(value)

    def test_reviewed_inventory_insufficient_balanced_surge_rejected(self):
        value = fixture(8)
        value['platform_nodes'][-1]['zone'] = 'cn-hangzhou-h'
        with self.assertRaisesRegex(ValueError, 'SURGE_CAPACITY'):
            renderer.render(value)
        value = fixture(3); value['platform_nodes'] = value['platform_nodes'][:3]
        with self.assertRaisesRegex(ValueError, 'SURGE_CAPACITY'):
            renderer.render(value)

    def test_client_ca_is_dedicated_real_signing_key_not_leaf_or_private_key(self):
        for field, contents in [('apiserver_client_ca_pem', fixture()['server_tls']['server_ca_pem']),
            ('apiserver_client_ca_pem', (REPO / 'tests/fixtures/admission/apiserver.pem').read_text()),
            ('apiserver_client_ca_pem', (REPO / 'tests/fixtures/admission/apiserver.key').read_text()),
            ('apiserver_client_ca_pem', fixture()['apiserver_client_ca_pem'] * 2),
            ('apiserver_client_ca_pem', 'invalid'), ('apiserver_client_ca_pem', 'x' * 65537)]:
            value = fixture(); value[field] = contents
            with self.assertRaises(ValueError):
                renderer.render(value)
        value = fixture(); value['database']['ca_pem'] = value['apiserver_client_ca_pem']
        with self.assertRaisesRegex(ValueError, 'DEDICATED_APISERVER'):
            renderer.render(value)
        with patch.object(renderer, 'datetime') as clock:
            for year in [1900, 2040]:
                clock.now.return_value = datetime(year, 1, 1, tzinfo=timezone.utc)
                with self.assertRaises(ValueError):
                    renderer.render(fixture())

    def test_bounded_strict_json_and_real_cli_output_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'settings.json'
            for raw in ['{"replicas":2,"replicas":3}', '{"replicas":NaN}', '{"replicas":Infinity}', '{"replicas":1e999}', 'x' * 262145]:
                source.write_text(raw)
                with self.assertRaises(ValueError):
                    renderer.load(source)
            source.write_text(json.dumps(fixture()))
            output = Path(directory) / 'workload.json'; activation = Path(directory) / 'webhook.json'
            argv = [sys.executable, str(ROOT / 'render.py'), '--input', str(source), '--out', str(output), '--webhook-out', str(activation)]
            result = subprocess.run(argv, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(json.loads(output.read_text()), renderer.render(fixture()))
            self.assertEqual(json.loads(activation.read_text()), renderer.webhook(fixture()))
            before = output.read_bytes()
            result = subprocess.run(argv, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0); self.assertEqual(output.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
