import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
sys.path.insert(0, str(ROOT))


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


renderer = module('termination_renderer', ROOT / 'render.py')
preparer = module('termination_preparer', ROOT / 'prepare.py')
gate = module('termination_policy_gate', REPO / 'deploy/policy_boundary.py')
NOW = datetime.now(timezone.utc).replace(microsecond=0)


def raw(value):
    return renderer.canonical(value).encode()


def prepare_fixture(replicas=3):
    # PUBLIC invented cloud/node/identity observations, digest and CA only.
    # Never install this fixture or treat it as runtime/cloud certification.
    ca = (REPO / 'tests/fixtures/admission/server-ca.pem').read_text()
    settings = {'schema_version': 1, 'image': 'registry.example.test/service@sha256:' + 'a' * 64, 'replicas': replicas,
        'database': {'secret': {'name': 'termination-db-revision1', 'key': 'url'}, 'ca_pem': ca},
        'nodeguard': {'identity_secret': {'name': 'termination-mtls-revision1', 'key': 'identity.pem'}, 'server_ca_pem': ca},
        'certification_id': 'PUBLIC_TEST_ONLY_NOT_CERTIFIED', 'concurrency': 2, 'db_max_connections': 10,
        'projects': [{'tenant_id': str(UUID(int=1)), 'project_id': str(UUID(int=i)), 'namespace': 'sbx-project-' + str(i)} for i in [2, 3]]}
    terraform = {'vpc_id': 'vpc-test', 'subnets': {}, 'private_entrances': {}, 'object_storage': {},
        'workload_roles': {}, 'workspace_kms_key_id': 'PUBLIC_TEST_ONLY', 'workload_oidc_provider_arn': 'PUBLIC_TEST_ONLY_UNUSED',
        'deployment_identity': {'deployment': 'sbx-test', 'region': 'cn-hangzhou', 'cloud_account_id': '1234567890123456', 'environment': 'test'},
        'database': {'id': 'rds-test', 'endpoint': 'postgres.example.test', 'port': 5432, 'engine': 'PostgreSQL', 'major_version': 17},
        'node_inventory': {}}
    receipts, kubernetes, remotes = [], [], []
    for index, zone in enumerate('hijhijhij', 1):
        terraform['node_inventory']['platform-' + str(index)] = {'id': 'i-platform' + str(index),
            'private_ip': '10.80.1.' + str(index + 10), 'role': 'platform', 'zone': 'cn-hangzhou-' + zone}
    for index, zone in enumerate('hij', 1):
        node = {'cluster_epoch': str(UUID(int=700)), 'node_uid': str(UUID(int=100 + index)),
            'node_name': 'kata-' + str(index), 'boot_id': str(UUID(int=200 + index)), 'profile_sha256': 'd' * 64}
        terraform['node_inventory'][node['node_name']] = {'id': 'i-kata' + str(index),
            'private_ip': '10.80.2.' + str(index + 10), 'role': 'kata', 'zone': 'cn-hangzhou-' + zone}
        receipts.append({'protocol': 1, 'enrollment_id': str(UUID(int=300 + index)), 'runtime_node_id': str(UUID(int=400 + index)),
            'node': node, 'cloud_account_id': '1234567890123456', 'region': 'cn-hangzhou', 'cloud_instance_id': 'i-kata' + str(index),
            'private_ip': '10.80.2.' + str(index + 10), 'guard_port': 9444, 'certification_id': settings['certification_id'],
            'certification_report_sha256': 'e' * 64, 'artifact_sha256': 'f' * 64, 'terraform_output_sha256': '',
            'registered_at': (NOW - timedelta(minutes=5)).isoformat(), 'changed': True, 'enabled': True})
    for hostname, node in terraform['node_inventory'].items():
        receipt = next((r for r in receipts if r['node']['node_name'] == hostname), None)
        uid = receipt['node']['node_uid'] if receipt else str(UUID(int=1000 + len(kubernetes)))
        boot = receipt['node']['boot_id'] if receipt else str(UUID(int=2000 + len(kubernetes)))
        kubernetes.append({'apiVersion': 'v1', 'kind': 'Node', 'metadata': {'name': hostname, 'uid': uid,
            'resourceVersion': '7', 'labels': {'kubernetes.io/hostname': hostname, 'sandbox.platform/node-pool': node['role'],
                'topology.kubernetes.io/zone': node['zone']},
            'annotations': {'sandbox.platform/runtime-profile-sha256': 'd' * 64} if receipt else {}},
            'spec': {'unschedulable': False}, 'status': {'nodeInfo': {'bootID': boot},
                'addresses': [{'type': 'InternalIP', 'address': node['private_ip']}], 'conditions': [{'type': 'Ready', 'status': 'True'}]}})
    for source, node in terraform['node_inventory'].items():
        if node['role'] != 'platform':
            continue
        for receipt in receipts:
            hostname = receipt['node']['node_name']
            remotes.append({'source_node': source, 'node_name': hostname, 'private_ip': receipt['private_ip'], 'identity_id': 0x02000001 + len(remotes),
                'labels': {'reserved:remote-node': '', 'node:kubernetes.io/hostname': hostname,
                    'node:sandbox.platform/node-pool': 'kata', 'node:topology.kubernetes.io/zone': terraform['node_inventory'][hostname]['zone'],
                    'k8s:io.cilium.k8s.policy.cluster': 'default'}})
    digest = hashlib.sha256(raw(terraform)).hexdigest()
    for receipt in receipts:
        receipt['terraform_output_sha256'] = digest
    observation = {'observed_at': NOW.isoformat(), 'cilium_config': {'apiVersion': 'v1', 'kind': 'ConfigMap',
        'metadata': {'name': 'cilium-config', 'namespace': 'kube-system', 'resourceVersion': '9'},
        'data': {'enable-policy': 'always', 'enable-node-selector-labels': 'true', 'policy-default-local-cluster': 'true', 'cluster-name': 'default'}},
        'nodes': {'apiVersion': 'v1', 'kind': 'NodeList', 'items': kubernetes}, 'remote_identities': remotes}
    return settings, terraform, receipts, observation


def prepared(parts):
    settings, terraform, receipts, observation = parts
    return preparer.prepare(settings, terraform, receipts, observation,
        terraform_raw=raw(terraform), enrollments_raw=raw(receipts), observation_raw=raw(observation))


def fixture(replicas=3):
    return prepared(prepare_fixture(replicas))


def resource(value, kind):
    return next(item for item in value['items'] if item['kind'] == kind)


class TerminationInstaller(unittest.TestCase):
    def test_exact_existing_rbac_narrow_namespaces_nodes_and_proof_bounded_patch(self):
        value = fixture(); objects = renderer.identities(value)
        self.assertEqual(len(objects['items']), 7)
        self.assertNotIn('Deployment', [r['kind'] for r in objects['items']])
        rules = resource(objects, 'ClusterRole')['rules']
        self.assertEqual(rules, [
            {'apiGroups': [''], 'resources': ['pods'], 'verbs': ['list']},
            {'apiGroups': [''], 'resources': ['namespaces'], 'resourceNames': ['sbx-project-2', 'sbx-project-3'], 'verbs': ['get']},
            {'apiGroups': [''], 'resources': ['nodes'], 'resourceNames': ['kata-1', 'kata-2', 'kata-3'], 'verbs': ['get']},
            {'apiGroups': [''], 'resources': ['persistentvolumes'], 'verbs': ['get']},
            {'apiGroups': ['admissionregistration.k8s.io'], 'resources': ['validatingadmissionpolicies', 'validatingadmissionpolicybindings'], 'resourceNames': ['sandbox-kata-runtimeclass-v1'], 'verbs': ['get']},
            {'apiGroups': ['node.k8s.io'], 'resources': ['runtimeclasses'], 'resourceNames': ['kata-qemu'], 'verbs': ['get']},
            {'apiGroups': ['storage.k8s.io'], 'resources': ['volumeattachments'], 'verbs': ['list']}])
        for role in [r for r in objects['items'] if r['kind'] == 'Role']:
            self.assertIn(role['metadata']['namespace'], ['sbx-project-2', 'sbx-project-3'])
            self.assertEqual(role['rules'], [
                {'apiGroups': [''], 'resources': ['pods'], 'verbs': ['get', 'delete', 'patch']},
                {'apiGroups': [''], 'resources': ['persistentvolumeclaims'], 'verbs': ['get']},
                {'apiGroups': ['networking.k8s.io'], 'resources': ['networkpolicies'], 'resourceNames': ['sandbox-default-deny'], 'verbs': ['get']},
                {'apiGroups': ['cilium.io'], 'resources': ['ciliumnetworkpolicies'], 'verbs': ['get']}])
        for binding in [r for r in objects['items'] if r['kind'].endswith('Binding')]:
            self.assertEqual(binding['subjects'], [{'kind': 'ServiceAccount', 'name': renderer.NAME, 'namespace': renderer.NS}])
        for bad in ['secrets', 'impersonate', 'pods/exec', 'update', 'create', 'persistentvolumes/delete', '*']:
            self.assertNotIn(bad, json.dumps(objects))

    def test_actual_rust_cli_paths_secret_refs_nonroot_and_no_cloud_identity(self):
        value = fixture(); values = renderer.workload(value)
        pod = resource(values, 'Deployment')['spec']['template']['spec']; controller = pod['containers'][0]
        self.assertEqual(controller['command'], ['/usr/local/bin/sandboxd']); self.assertEqual(controller['args'], ['--role', 'termination'])
        env = {v['name']: v.get('value', v.get('valueFrom')) for v in controller['env']}
        self.assertEqual(env['SANDBOX_PROCESS_POD_UID'], {'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.uid'}})
        self.assertEqual(sum(v['name'] == 'SANDBOX_PROCESS_POD_UID' for v in controller['env']), 1)
        self.assertEqual(env, {'SANDBOX_DATABASE_URL': {'secretKeyRef': value['database']['secret']},
            'SANDBOX_PROCESS_POD_UID': {'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.uid'}},
            'SANDBOX_DB_MAX_CONNECTIONS': '10', 'SANDBOX_TERMINATION_CONCURRENCY': '2',
            'SANDBOX_NODEGUARD_SERVER_CA_FILE': renderer.TRUST + '/nodeguard-server-ca.pem',
            'SANDBOX_NODEGUARD_CLIENT_IDENTITY_FILE': renderer.IDENTITY,
            'SANDBOX_DEPLOYMENT_CERTIFICATION_ID': value['certification_id'], 'SANDBOX_DNS_NAMESPACE': 'kube-system',
            'SANDBOX_DNS_LABEL': 'k8s-app=kube-dns', 'SANDBOX_ALLOW_LOOPBACK_HTTP': 'false'})
        self.assertFalse(pod['automountServiceAccountToken']); self.assertEqual(pod['serviceAccountName'], renderer.NAME)
        self.assertEqual(pod['securityContext']['runAsUser'], 10001); self.assertEqual(pod['securityContext']['runAsGroup'], 10001)
        self.assertEqual(pod['securityContext']['fsGroup'], 10001); self.assertEqual(pod['terminationGracePeriodSeconds'], 50)
        for volume in pod['volumes']:
            source = volume.get('configMap', volume.get('secret', volume.get('projected')))
            self.assertEqual(source['defaultMode'], 0o440)
        self.assertTrue(all(m['readOnly'] for m in controller['volumeMounts']))
        self.assertEqual(next(v for v in pod['volumes'] if v['name'] == 'kube-api')['projected']['sources'][0],
            {'serviceAccountToken': {'path': 'token', 'expirationSeconds': 3600}})
        self.assertNotIn('initContainers', pod); self.assertNotIn('ports', controller)
        self.assertFalse(any(k.endswith('Probe') for k in controller))
        self.assertNotIn('Secret', [r['kind'] for r in values['items']]); self.assertNotIn('Service', [r['kind'] for r in values['items']])
        for forbidden in ['sts.aliyuncs.com', 'role_arn', 'cloud-identity', '100.100.100.200', 'hostNetwork', 'hostPath', '/bin/sh']:
            self.assertNotIn(forbidden, json.dumps(values))

    def test_exact_to_nodes_source_and_scope_no_cidr_or_broad_host_rule(self):
        value = fixture(); policy = resource(renderer.workload(value), 'CiliumNetworkPolicy')['spec']
        self.assertEqual(policy['ingress'], [])
        self.assertEqual(policy['enableDefaultDeny'], {'ingress': True, 'egress': True})
        rule = policy['egress'][-1]
        self.assertEqual(rule['toPorts'], [{'ports': [{'port': '9444', 'protocol': 'TCP'}]}])
        self.assertEqual(rule['toNodes'], [{'matchLabels': {'node:kubernetes.io/hostname': 'kata-' + str(i),
            'node:sandbox.platform/node-pool': 'kata', 'node:topology.kubernetes.io/zone': 'cn-hangzhou-' + zone,
            'k8s:io.cilium.k8s.policy.cluster': 'default'}} for i, zone in enumerate('hij', 1)])
        self.assertEqual(policy['egress'][0]['toPorts'][0]['rules']['dns'], [{'matchName': 'postgres.example.test'}])
        self.assertEqual(policy['egress'][1]['toFQDNs'], [{'matchName': 'postgres.example.test'}])
        self.assertEqual(policy['egress'][2]['toEntities'], ['kube-apiserver'])
        for bad in ['world', 'remote-node', 'host"', 'toCIDR', 'matchPattern', '9445', '*']:
            self.assertNotIn(bad, json.dumps(policy))

    def test_three_az_balanced_ha_surge_fixed_platform_inventory_and_pdb(self):
        for replicas in range(2, 9):
            values = renderer.workload(fixture(replicas)); deployment = resource(values, 'Deployment')['spec']
            pod = deployment['template']['spec']
            self.assertEqual(pod['nodeSelector'], {'sandbox.platform/node-pool': 'platform'})
            self.assertEqual(pod['topologySpreadConstraints'][0]['minDomains'], 3)
            self.assertEqual(pod['affinity']['podAntiAffinity']['requiredDuringSchedulingIgnoredDuringExecution'][0]['topologyKey'], 'kubernetes.io/hostname')
            self.assertEqual(deployment['strategy']['rollingUpdate'], {'maxUnavailable': 0, 'maxSurge': 1})
            self.assertEqual(resource(values, 'PodDisruptionBudget')['spec']['minAvailable'], replicas - 1)
        value = fixture(8); value['platform_nodes'][-1]['zone'] = 'cn-hangzhou-h'
        with self.assertRaisesRegex(ValueError, 'SURGE_CAPACITY'):
            renderer.workload(value)

    def test_current_terraform_receipts_readbacks_are_bound_not_mere_config_flags(self):
        value = fixture(); settings, tf, receipts, observed = prepare_fixture()
        self.assertEqual(value['database']['host'], tf['database']['endpoint'])
        self.assertEqual(value['network_evidence']['terraform_output_sha256'], hashlib.sha256(raw(tf)).hexdigest())
        self.assertEqual(value['network_evidence']['enrollments_sha256'], hashlib.sha256(raw(receipts)).hexdigest())
        self.assertEqual(value['network_evidence']['observation_sha256'], hashlib.sha256(raw(observed)).hexdigest())
        self.assertEqual(value['runtime_nodes'][0]['node'], receipts[0]['node'])
        wrapped = {key: {'value': val, 'sensitive': False, 'type': 'PUBLIC_TEST_TYPE'} for key, val in tf.items()}
        for receipt in receipts:
            receipt['terraform_output_sha256'] = hashlib.sha256(raw(wrapped)).hexdigest()
        value = prepared((settings, wrapped, receipts, observed))
        self.assertEqual(len(value['runtime_nodes']), 3)

    def test_wrong_enrollment_uid_boot_profile_ip_account_epoch_and_certificate_ref_rejected(self):
        mutations = [lambda x: x[2][0].update(enabled=False), lambda x: x[2][0].update(guard_port=443),
            lambda x: x[2][0].update(cloud_account_id='9999999999999999'), lambda x: x[2][0].update(region='cn-beijing'),
            lambda x: x[2][0].update(certification_id='OTHER'), lambda x: x[2][0].update(terraform_output_sha256='0' * 64),
            lambda x: x[2][0].update(private_ip='8.8.8.8'), lambda x: x[2][0]['node'].update(boot_id=str(UUID(int=999))),
            lambda x: x[2][0]['node'].update(node_uid=str(UUID(int=999))), lambda x: x[2][0]['node'].update(profile_sha256='0' * 64),
            lambda x: x[2][0]['node'].update(cluster_epoch=str(UUID(int=999))), lambda x: x[2].pop(),
            lambda x: x[2].append(copy.deepcopy(x[2][0])), lambda x: x[2][0].update(private_key='NOT_ACCEPTED')]
        for mutate in mutations:
            parts = prepare_fixture(); mutate(parts)
            with self.assertRaises((ValueError, TypeError, KeyError)):
                prepared(parts)

    def test_current_cilium_flags_filtered_wrong_source_cluster_and_missing_platform_identity_rejected(self):
        mutations = [lambda x: x[3]['cilium_config']['data'].update({'enable-policy': 'default'}),
            lambda x: x[3]['cilium_config']['data'].update({'enable-node-selector-labels': 'false'}),
            lambda x: x[3]['cilium_config']['data'].update({'policy-default-local-cluster': 'false'}),
            lambda x: x[3]['cilium_config']['data'].pop('cluster-name'), lambda x: x[3]['remote_identities'].pop(),
            lambda x: x[3]['remote_identities'][0]['labels'].pop('node:sandbox.platform/node-pool'),
            lambda x: x[3]['remote_identities'][0]['labels'].update({'node:sandbox.platform/node-pool': 'platform'}),
            lambda x: x[3]['remote_identities'][0]['labels'].update({'k8s:io.cilium.k8s.policy.cluster': 'foreign'}),
            lambda x: x[3]['remote_identities'][0]['labels'].update({'reserved:host': ''}),
            lambda x: x[3]['remote_identities'][0].update(private_ip='10.80.2.99'),
            lambda x: x[3]['remote_identities'][0].update(source_node='control-1'),
            lambda x: x[3]['remote_identities'][0].update(identity_id=True),
            lambda x: x[3]['remote_identities'][0]['labels'].update({'k8s:kubernetes.io/hostname': x[3]['remote_identities'][0]['labels'].pop('node:kubernetes.io/hostname')})]
        for mutate in mutations:
            parts = prepare_fixture(); mutate(parts)
            with self.assertRaises((ValueError, TypeError, KeyError)):
                prepared(parts)

    def test_remote_identity_requires_remote_node_scope_and_nonzero_allocator(self):
        for identity in (0x00000100, 0x01000001, 0x02000000, 0xffffffff):
            with self.subTest(identity=identity):
                parts = prepare_fixture()
                parts[3]['remote_identities'][0]['identity_id'] = identity
                with self.assertRaisesRegex(ValueError, 'REMOTE_IPCACHE_IDENTITY_BINDING'):
                    prepared(parts)
        for identity in (0x02000001, 0x02ffffff):
            with self.subTest(identity=identity):
                parts = prepare_fixture()
                parts[3]['remote_identities'][0]['identity_id'] = identity
                prepared(parts)

    def test_readback_age_immutable_ids_ready_node_zones_and_tls_overrides_rejected(self):
        mutations = [lambda x: x[3].update(observed_at=(NOW - timedelta(minutes=6)).isoformat()),
            lambda x: x[3].update(observed_at=(NOW + timedelta(minutes=1)).isoformat()),
            lambda x: x[3]['nodes']['items'][0]['metadata']['labels'].update({'sandbox.platform/node-pool': 'kata'}),
            lambda x: x[3]['nodes']['items'][0]['spec'].update(unschedulable=True),
            lambda x: x[3]['nodes']['items'][0]['spec'].update(taints=[{'key': 'dedicated', 'effect': 'NoSchedule'}]),
            lambda x: x[3]['nodes']['items'][0]['spec'].update(taints=[{'key': 'failed', 'effect': 'NoExecute'}]),
            lambda x: x[3]['nodes']['items'][0]['metadata'].update(deletionTimestamp=NOW.isoformat()),
            lambda x: x[3]['nodes']['items'][0]['metadata'].pop('resourceVersion'),
            lambda x: x[3]['nodes']['items'][0]['status']['conditions'][0].update(status='False'),
            lambda x: x[3]['nodes']['items'][0]['status']['addresses'][0].update(address='10.80.1.200'),
            lambda x: x[0]['database'].update(host='wrong.example.test'), lambda x: x[1]['database'].update(port=443),
            lambda x: x[1]['node_inventory']['kata-1'].update(private_ip='8.8.8.8'),
            lambda x: x[0].update(cloud_role='admin')]
        for mutate in mutations:
            parts = prepare_fixture(); mutate(parts)
            with self.assertRaises((ValueError, TypeError, KeyError)):
                prepared(parts)
        value = fixture(); value['network_evidence']['expires_at'] = (NOW - timedelta(seconds=1)).isoformat()
        with self.assertRaises(ValueError):
            renderer.workload(value)

    def test_cordoned_not_ready_runtime_nodes_keep_exact_control_routes(self):
        parts = prepare_fixture()
        for node in parts[3]['nodes']['items']:
            if node['metadata']['labels']['sandbox.platform/node-pool'] == 'kata':
                node['spec'].update(unschedulable=True, taints=[{'key': 'failed', 'effect': 'NoExecute'}])
                node['status']['conditions'][0]['status'] = 'False'
        value = prepared(parts)
        policy = resource(renderer.workload(value), 'CiliumNetworkPolicy')['spec']
        self.assertEqual(len(policy['egress'][-1]['toNodes']), 3)
        self.assertEqual({n['matchLabels']['node:kubernetes.io/hostname'] for n in policy['egress'][-1]['toNodes']},
            {'kata-1', 'kata-2', 'kata-3'})

    def test_unknown_settings_secrets_unregistered_namespaces_and_unsafe_nodes_rejected(self):
        mutations = [lambda v: v.update(replicas=True), lambda v: v.update(replicas=1), lambda v: v.update(replicas=9),
            lambda v: v.update(image='service:latest'), lambda v: v.update(concurrency=0), lambda v: v.update(db_max_connections=5),
            lambda v: v.update(ram_role='admin'), lambda v: v['database'].update(host='127.0.0.1'),
            lambda v: v['database'].update(host='postgres.svc.cluster.local'), lambda v: v['nodeguard'].update(identity='PRIVATE'),
            lambda v: v['nodeguard']['identity_secret'].update(name=v['database']['secret']['name']),
            lambda v: v['projects'][0].update(namespace='sandbox-system'), lambda v: v['projects'][0].update(namespace='kube-system'),
            lambda v: v['projects'][0].update(project_id=str(UUID(int=0))), lambda v: v['projects'].append(copy.deepcopy(v['projects'][0])),
            lambda v: v['runtime_nodes'][0].update(private_ip='127.0.0.1'), lambda v: v['runtime_nodes'][0].update(guard_port=True),
            lambda v: v['runtime_nodes'][0]['node'].update(node_uid='UPPERCASE'),
            lambda v: v['network_evidence']['cilium_config'].update({'policy-default-local-cluster': 'false'})]
        for mutate in mutations:
            value = fixture(); mutate(value)
            with self.assertRaises((ValueError, TypeError, KeyError)):
                renderer.workload(value)

    def test_real_shared_overlap_gate_current_bootstrap_and_extra_policy_negatives(self):
        sys.path.insert(0, str(REPO / 'deploy/cluster'))
        cluster = module('termination_cluster', REPO / 'deploy/cluster/cluster.py')
        manifests = module('termination_cluster_renderer', REPO / 'deploy/cluster/render.py')
        with patch.dict(sys.modules, {'render': manifests}):
            samples = module('termination_cluster_fixture', REPO / 'deploy/cluster/tests/test_cluster.py')
        tf, settings = samples.fixture()
        bootstrap = manifests.policies(cluster.validate(tf, settings), settings)
        objects = renderer.workload(fixture()); policy = resource(objects, 'CiliumNetworkPolicy')
        labels = resource(objects, 'Deployment')['spec']['template']['metadata']['labels']
        identity = {'k8s:' + k: v for k, v in labels.items()} | {'k8s:io.kubernetes.pod.namespace': renderer.NS,
            'k8s:io.cilium.k8s.policy.serviceaccount': renderer.NAME, 'k8s:io.cilium.k8s.policy.cluster': 'default'}
        def check(extra):
            return gate.analyze(policy, renderer.NS, {'kubernetes.io/metadata.name': renderer.NS}, labels, renderer.NAME,
                [{'kind': 'List', 'items': [policy] + extra}], endpoint_labels=identity)
        self.assertEqual(check(bootstrap)['configuration_overlap'], 'PASS')
        self.assertEqual(check(bootstrap)['runtime_enforcement'], 'NOT_VERIFIED')
        bad = copy.deepcopy(bootstrap); bad[0]['spec']['endpointSelector']['matchExpressions'].pop()
        for extra in [bad, [{'kind': 'NetworkPolicy', 'metadata': {'name': 'broad', 'namespace': renderer.NS},
            'spec': {'podSelector': {}, 'egress': [{}]}}], [{'kind': 'CiliumClusterwideNetworkPolicy', 'metadata': {'name': 'broad'},
            'specs': [{'endpointSelector': {}, 'egress': [{}]}]}]]:
            with self.assertRaises(gate.BoundaryError):
                check(extra)

    def test_nonblocking_opened_fd_json_rejects_fifo_link_writable_and_special_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / 'input.json'; path.write_text('{}')
            self.assertEqual(renderer.load(path), {})
            for mode in [0o666, 0o620, 0o664, 0o1644]:
                path.chmod(mode)
                with self.assertRaises(ValueError):
                    renderer.load(path)
            path.chmod(0o600); link = root / 'linked.json'; link.symlink_to(path)
            with self.assertRaises(OSError):
                renderer.load(link)
            fifo = root / 'input.pipe'; os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                renderer.load(fifo)
            with self.assertRaises(ValueError):
                renderer.load(root)
            for contents in ['{"a":1,"a":2}', '{"a":NaN}', '{"a":1e999}', 'x' * 262145]:
                path.write_text(contents)
                with self.assertRaises(ValueError):
                    renderer.load(path)

    def test_real_prepare_and_render_cli_are_create_only_public_outputs(self):
        parts = prepare_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [root / (key + '.json') for key in ['settings', 'terraform', 'receipts', 'observed']]
            for path, value in zip(paths, parts):
                path.write_bytes(raw(value))
            prepared_path = root / 'prepared.json'
            command = [sys.executable, str(ROOT / 'prepare.py'), '--settings', str(paths[0]), '--terraform-output', str(paths[1]),
                '--enrollments', str(paths[2]), '--cluster-observation', str(paths[3]), '--output', str(prepared_path)]
            result = subprocess.run(command, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(json.loads(prepared_path.read_text()), prepared(parts))
            identity, workload = root / 'identity.json', root / 'workload.json'
            command = [sys.executable, str(ROOT / 'render.py'), '--input', str(prepared_path), '--identity-out', str(identity), '--workload-out', str(workload)]
            result = subprocess.run(command, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(json.loads(identity.read_text()), renderer.identities(prepared(parts)))
            self.assertEqual(json.loads(workload.read_text()), renderer.workload(prepared(parts)))
            before = workload.read_bytes()
            result = subprocess.run(command, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0); self.assertEqual(workload.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
