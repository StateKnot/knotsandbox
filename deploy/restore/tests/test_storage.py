import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
import uuid

HERE = Path(__file__).resolve()
ROOT = HERE.parents[1]
REPO = next(path for path in HERE.parents if (path / 'Cargo.toml').is_file())
sys.path.insert(0, str(ROOT))
import storage


def fixture():
    path = ROOT.parents[1] / 'tests/fixtures/restore/storage-canonical.json'
    fixed = storage.decode(path.read_bytes())
    config = fixed['config']
    nodes, subnets = {}, {}
    for role_index, role in enumerate(('control', 'platform', 'kata')):
        for zone_index, zone in enumerate(fixed['contract']['mapping']['topology']['zone_ids']):
            key = f'{role}-{zone_index}'
            octet = role_index * 16 + zone_index
            nodes[key] = {'id': f'i-test{role_index}{zone_index}', 'private_ip': f'10.80.{octet}.10', 'role': role, 'zone': zone}
            subnets[key] = {'id': f'vsw-test{role_index}{zone_index}', 'zone': zone, 'cidr': f'10.80.{octet}.0/24'}
    values = {'deployment_identity': {'cloud_account_id': config['account_id'], 'region': config['region'],
              'deployment': config['deployment'], 'environment': 'preproduction'},
              'workspace_kms_key_id': config['workspace_kms_key_id'], 'node_inventory': nodes, 'subnets': subnets}
    terraform = {k: {'value': v, 'sensitive': False} for k, v in values.items()}
    return config, terraform, fixed


class FakeKubernetes:
    context = 'disposable-test-not-production'
    def __init__(self):
        c, _, fixed = fixture()
        self.objects, self.creates, self.gets = {}, [], []
        for purpose, value in fixed['specs'].items():
            identity = fixed['contract']['mapping'][purpose]
            resource = 'volumesnapshotclass' if purpose == 'snapshot' else 'storageclass'
            self.objects[(resource, identity['name'])] = {**value, 'metadata': {'name': identity['name'], 'uid': identity['uid']}}
    def get(self, resource, name, optional=False):
        self.gets.append((resource, name))
        value = self.objects.get((resource, name))
        storage.require(optional or value is not None, 'FAKE_CLASS_NOT_FOUND')
        return copy.deepcopy(value)
    def create(self, body):
        self.creates.append(copy.deepcopy(body))
        value = copy.deepcopy(body)
        value['metadata']['uid'] = str(uuid.uuid4())
        self.objects[('storageclass', value['metadata']['name'])] = value


class StorageContractTests(unittest.TestCase):
    def test_fixed_rust_python_bytes_and_hashes(self):
        config, terraform, fixed = fixture()
        raw = (ROOT.parents[1] / 'tests/fixtures/restore/storage-canonical.json').read_bytes()
        self.assertEqual(raw, storage.canonical(fixed))
        zones = storage.infrastructure(config, terraform)
        self.assertFalse(fixed['production_activation'])
        for purpose in storage.PURPOSES:
            spec = storage.class_spec(config, zones, purpose)
            self.assertEqual(storage.canonical(spec), storage.canonical(fixed['specs'][purpose]))
            self.assertEqual(hashlib.sha256(storage.canonical(spec)).hexdigest(), fixed['hashes'][purpose])
        self.assertEqual(storage.snapshot_spec(config), fixed['specs']['snapshot'])
        self.assertEqual(hashlib.sha256(storage.canonical(storage.snapshot_spec(config))).hexdigest(), fixed['hashes']['snapshot'])

    def test_renderer_only_two_fixed_classes(self):
        c, t, _ = fixture()
        result = storage.render(c, t)
        self.assertEqual(len(result['items']), 2)
        raw, delivery = result['items']
        self.assertEqual(raw['volumeBindingMode'], 'WaitForFirstConsumer')
        self.assertEqual(delivery['volumeBindingMode'], 'Immediate')
        self.assertFalse(raw['allowVolumeExpansion']); self.assertFalse(delivery['allowVolumeExpansion'])
        self.assertEqual(len(raw['parameters']), 4); self.assertEqual(len(delivery['parameters']), 5)
        self.assertNotIn('fsType', raw['parameters']); self.assertEqual(delivery['parameters']['fsType'], 'ext4')
        self.assertEqual(raw['allowedTopologies'], delivery['allowedTopologies'])
        self.assertEqual(len(raw['allowedTopologies'][0]['matchLabelExpressions'][0]['values']), 3)

    def test_config_rejects_coercion_unknown_and_purpose_alias(self):
        original, t, _ = fixture()
        for key, value in [('protocol', True), ('protocol', 1.0), ('account_id', 1234567890123456),
                           ('deployment', 'Bad-Tag'), ('region', 'outside'), ('workspace_kms_key_id', ''),
                           ('restore_raw_storage_class', original['normal_storage_class']),
                           ('restore_delivery_storage_class', original['restore_raw_storage_class']), ('snapshot_class', 'BadName')]:
            c = copy.deepcopy(original); c[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): storage.render(c, t)
        with self.assertRaises(ValueError): storage.render(original | {'approved': True}, t)
        with self.assertRaises(ValueError): storage.decode(b'{"protocol":1,"protocol":1}')
        with self.assertRaises(ValueError): storage.decode(b'{"n":NaN}')

    def test_terraform_wrappers_must_be_actual_nonsecret_outputs(self):
        c, original, _ = fixture()
        for key in original:
            for value in (True, 0, 1, None, 'false'):
                t = copy.deepcopy(original); t[key]['sensitive'] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError): storage.render(c, t)
        with self.assertRaises(ValueError): storage.render(c, {k: v['value'] for k, v in original.items()})
        t = copy.deepcopy(original); t['node_inventory']['secret_override'] = {}
        with self.assertRaises(ValueError): storage.render(c, t)

    def test_infrastructure_key_account_deployment_and_fault_domains(self):
        c, original, _ = fixture()
        for key in ('cloud_account_id', 'region', 'deployment', 'environment'):
            t = copy.deepcopy(original); t['deployment_identity']['value'][key] = 'foreign'
            with self.subTest(key=key), self.assertRaises(ValueError): storage.render(c, t)
        t = copy.deepcopy(original); t['workspace_kms_key_id']['value'] = 'vault-key'
        with self.assertRaises(ValueError): storage.render(c, t)
        mutations = [lambda t: t['node_inventory']['value']['kata-0'].update(zone='cn-beijing-a'),
                     lambda t: t['node_inventory']['value']['kata-0'].update(role='foreign'),
                     lambda t: t['node_inventory']['value']['kata-0'].update(private_ip='10.81.1.10'),
                     lambda t: t['node_inventory']['value']['kata-0'].update(zone='cn-hangzhou-i'),
                     lambda t: t['node_inventory']['value']['kata-0'].update(extra='ignored'),
                     lambda t: t['subnets']['value']['kata-0'].update(cidr='0.0.0.0/0'),
                     lambda t: t['subnets']['value']['kata-0'].update(zone='cn-hangzhou-z'),
                     lambda t: t['subnets']['value']['kata-0'].update(extra='ignored')]
        for change in mutations:
            t = copy.deepcopy(original); change(t)
            with self.assertRaises(ValueError): storage.render(c, t)

    def test_purpose_drift_refuses_install_before_any_create(self):
        c, t, _ = fixture()
        raw_key = ('storageclass', c['restore_raw_storage_class'])
        delivery_key = ('storageclass', c['restore_delivery_storage_class'])
        cases = [lambda v: v.update(volumeBindingMode='WaitForFirstConsumer'),
                 lambda v: v['parameters'].update(kmsKeyId='foreign-key'),
                 lambda v: v['parameters'].update(**{'diskTags/Deployment': 'foreign'}),
                 lambda v: v['parameters'].pop('fsType'),
                 lambda v: v['parameters'].update(zoneId='cn-hangzhou-h'),
                 lambda v: v['parameters'].update(**{'csi.storage.k8s.io/provisioner-secret-name': 'secret'}),
                 lambda v: v.update(allowVolumeExpansion=0),
                 lambda v: v.update(mountOptions=['discard']),
                 lambda v: v['allowedTopologies'].append(copy.deepcopy(v['allowedTopologies'][0])),
                 lambda v: v['metadata'].update(annotations={'storageclass.kubernetes.io/is-default-class': 'false'}),
                 lambda v: v['metadata'].update(deletionTimestamp='2026-10-08T00:00:00Z'),
                 lambda v: v['metadata'].update(namespace='sandbox-system'),
                 lambda v: v['metadata'].update(ownerReferences=[{}]),
                 lambda v: v.update(unknownBehavior=True)]
        for change in cases:
            kube = FakeKubernetes(); del kube.objects[raw_key]; change(kube.objects[delivery_key])
            with self.assertRaises(ValueError): storage.probe(c, t, kube, install=True, lock_path=REPO/'deploy/cluster/versions.lock.json')
            self.assertGreater(len(kube.gets), 0)
            self.assertEqual(kube.creates, [])

    def test_install_no_patch_and_probe_never_certifies_or_enables(self):
        c, t, _ = fixture(); kube = FakeKubernetes()
        for key in ('restore_raw_storage_class', 'restore_delivery_storage_class'):
            del kube.objects[('storageclass', c[key])]
        report = storage.probe(c, t, kube, install=True, lock_path=REPO/'deploy/cluster/versions.lock.json')
        self.assertEqual(len(kube.creates), 2)
        self.assertEqual([v['metadata']['name'] for v in kube.creates], [c['restore_raw_storage_class'], c['restore_delivery_storage_class']])
        self.assertFalse(report['production_activation']); self.assertEqual(report['csi_restore_certification'], 'NOT_VERIFIED')
        self.assertEqual(report['result'], 'CANDIDATE_STORAGE_MAPPING')
        self.assertNotIn('profile_id', report); self.assertNotIn('report_sha256', report)
        for purpose in ('raw', 'delivery'):
            identity = report['mapping'][purpose]
            self.assertEqual(identity['uid'], kube.objects[('storageclass', identity['name'])]['metadata']['uid'])
        again = storage.probe(c, t, kube, install=True, lock_path=REPO/'deploy/cluster/versions.lock.json')
        self.assertEqual(len(kube.creates), 2); self.assertEqual(again['mapping'], report['mapping'])

    def test_probe_rejects_missing_nil_and_changed_observed_uid(self):
        c, t, _ = fixture()
        kube = FakeKubernetes(); key = ('storageclass', c['restore_raw_storage_class']); del kube.objects[key]
        with self.assertRaises(ValueError): storage.probe(c, t, kube, lock_path=REPO/'deploy/cluster/versions.lock.json')
        kube = FakeKubernetes(); kube.objects[key]['metadata']['uid'] = str(uuid.UUID(int=0))
        with self.assertRaises(ValueError): storage.probe(c, t, kube, lock_path=REPO/'deploy/cluster/versions.lock.json')
        kube = FakeKubernetes(); original_get = kube.get
        def replacement(resource, name, optional=False):
            v = original_get(resource, name, optional)
            if len(kube.gets) > 4 and name == c['restore_raw_storage_class']:
                v['metadata']['uid'] = str(uuid.uuid4())
            return v
        kube.get = replacement
        with self.assertRaises(ValueError): storage.probe(c, t, kube, lock_path=REPO/'deploy/cluster/versions.lock.json')

    def test_explicit_context_and_bounded_kubectl_contract(self):
        for context in (None, '', '-flag', 'context\nsecret', 'x'*254):
            with self.assertRaises(ValueError): storage.Kubernetes(context)
        self.assertEqual(storage.Kubernetes('prod-cluster').context, 'prod-cluster')


if __name__ == '__main__':
    unittest.main()
