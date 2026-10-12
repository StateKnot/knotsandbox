"""Fault tests for the whole gate; responses are explicit Kubernetes fixtures.

This tests input consistency, not a running Cilium dataplane or cluster install.
"""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_policy_boundary import endpoint, inventory, pod, policy
from test_policy_snapshot import config

DEPLOY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DEPLOY))
spec = importlib.util.spec_from_file_location('whole_policy_gate', DEPLOY / 'policy_boundary.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class PolicyObservation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='sandbox-policy-observation-')
        self.directory = Path(self.temporary.name)
        self.source = self.directory / 'private.kubeconfig'
        self.source.write_text(json.dumps(config()))
        self.source.chmod(0o600)
        self.manifest = self.directory / 'reviewed.json'
        current_pod = pod()
        current_pod['status'] = {'conditions': [{'type': 'Ready', 'status': 'True'}]}
        self.documents = {
            'namespace': {'metadata': {'name': 'sandbox-system', 'uid': 'ns-current', 'resourceVersion': '3',
                                      'labels': {'kubernetes.io/metadata.name': 'sandbox-system'}}},
            'configmap': {'metadata': {'uid': 'config-current', 'resourceVersion': '4'},
                          'data': {'enable-policy': 'always', 'cluster-name': 'default'}},
            'pods': inventory(current_pod), 'ciliumendpoints.cilium.io': inventory(endpoint()),
            'ciliumnetworkpolicies.cilium.io': inventory(policy()),
            'ciliumclusterwidenetworkpolicies.cilium.io': inventory(),
            'networkpolicies.networking.k8s.io': inventory(),
            'customnetworkpolicies.example.test': inventory(),
        }
        deployment = {'kind': 'Deployment', 'spec': {'replicas': 1, 'template': {
            'metadata': {'labels': current_pod['metadata']['labels']},
            'spec': {'serviceAccountName': 'sandbox-api'}}}}
        self.manifest.write_text(json.dumps(inventory(policy(), deployment)))
        self.output = self.directory / 'new-report.json'
        self.counts = {}
        self.paths = []
        self.change = None
        self.resources = sorted(['ciliumendpoints.cilium.io', 'ciliumnetworkpolicies.cilium.io',
            'ciliumclusterwidenetworkpolicies.cilium.io', 'networkpolicies.networking.k8s.io',
            'customnetworkpolicies.example.test'])

    def tearDown(self):
        self.temporary.cleanup()

    def read(self, command, limit, timeout):
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 8)
        path = Path(command[command.index('--kubeconfig') + 1])
        self.assertNotEqual(path, self.source)
        self.paths.append(path)
        frozen = json.loads(path.read_text())
        self.assertEqual(frozen['current-context'], 'production-review')
        self.assertEqual(set(frozen['users'][0]['user']), {'token'})
        self.assertNotIn('config', command)
        if 'api-resources' in command:
            key = 'discovery'
            value = list(self.resources)
        else:
            key = command[command.index('get') + 1]
            value = copy.deepcopy(self.documents.get(key, inventory()))
        self.counts[key] = self.counts.get(key, 0) + 1
        if self.change:
            value = self.change(key, value, self.counts[key])
        return ('\n'.join(value) + '\n').encode() if key == 'discovery' else json.dumps(value).encode()

    def run_gate(self):
        argv = ['policy_boundary.py', '--manifest', str(self.manifest), '--kubeconfig', str(self.source),
                '--context', 'production-review', '--out', str(self.output)]
        with patch.object(sys, 'argv', argv), patch.object(gate, 'bounded_command', side_effect=self.read):
            gate.main()

    def test_whole_observation_uses_frozen_credentials_and_only_reports_configuration(self):
        def replace_source(key, value, count):
            if key == 'discovery' and count == 1:
                dangerous = config()
                dangerous['users'][0]['user'] = {'exec': {'command': '/must-never-execute'}}
                replacement = self.directory / 'replacement'
                replacement.write_text(json.dumps(dangerous))
                replacement.chmod(0o600)
                replacement.replace(self.source)
            return value
        self.change = replace_source
        self.run_gate()
        report = json.loads(self.output.read_text())
        self.assertEqual(report['configuration_overlap'], 'PASS')
        self.assertEqual(report['runtime_enforcement'], 'NOT_VERIFIED')
        self.assertEqual(report['endpoint_identities'][0]['pod_uid'], 'pod-current')
        self.assertEqual(report['endpoint_identities'][0]['endpoint_uid'], 'cep-current')
        self.assertNotIn('PUBLIC_TEST_ONLY', self.output.read_text())
        self.assertTrue(all(count == 2 for count in self.counts.values()))
        self.assertTrue(self.paths and all(not path.exists() for path in self.paths))

    def test_any_selection_input_change_blocks_report(self):
        for changed in self.documents.keys() | {'discovery'}:
            with self.subTest(resource=changed):
                self.counts.clear()
                def mutate(key, value, count):
                    if key == changed and count == 2:
                        if key == 'discovery':
                            value.append('newnetworkpolicies.example.test')
                        elif key in ('namespace', 'configmap'):
                            value['metadata']['resourceVersion'] = 'changed'
                        else:
                            if value['items']:
                                value['items'][0].setdefault('metadata', {})['resourceVersion'] = 'changed'
                            else:
                                value['items'].append({'kind': 'ChangedResource', 'metadata': {
                                    'name': 'new', 'namespace': 'sandbox-system', 'uid': 'new-current'}})
                    return value
                self.change = mutate
                with self.assertRaises(gate.BoundaryError):
                    self.run_gate()
                self.assertFalse(self.output.exists())
                self.assertTrue(all(not path.exists() for path in self.paths))

    def test_collection_observation_version_change_is_recorded_without_false_drift(self):
        def observe_later(key, value, count):
            if count == 2 and key not in ('discovery', 'namespace', 'configmap'):
                value['metadata']['resourceVersion'] = 'later-etcd-observation'
            return value
        self.change = observe_later
        self.run_gate()
        report = json.loads(self.output.read_text())
        self.assertEqual(report['configuration_overlap'], 'PASS')
        versions = report['collection_resource_versions']
        self.assertNotEqual(versions['initial']['pods'], versions['final']['pods'])

    def test_new_unknown_allow_inventory_and_filtered_identity_fail_closed(self):
        for changed in ('customnetworkpolicies.example.test', 'ciliumendpoints.cilium.io'):
            self.counts.clear()
            def mutate(key, value, count):
                if key == changed:
                    if key == 'customnetworkpolicies.example.test':
                        value['items'] = [{'kind': 'UnknownPolicy'}]
                    else:
                        value['items'][0]['status']['identity']['labels'] = [label for label in
                            value['items'][0]['status']['identity']['labels'] if not
                            label.startswith('k8s:sandbox.platform/network-policy=')]
                return value
            self.change = mutate
            with self.assertRaises(gate.BoundaryError):
                self.run_gate()
            self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
