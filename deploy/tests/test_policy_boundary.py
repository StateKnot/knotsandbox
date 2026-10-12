import copy
import importlib.util
from pathlib import Path
import sys
import os
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('policy_boundary', ROOT / 'policy_boundary.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def policy():
    return {'apiVersion': 'cilium.io/v2', 'kind': 'CiliumNetworkPolicy',
            'metadata': {'name': 'api', 'namespace': 'sandbox-system', 'uid': 'fixture-uid', 'resourceVersion': '7'},
            'spec': {'endpointSelector': {'matchLabels': {'sandbox.platform/network-policy': 'api-v1'}},
                     'ingress': [{'fromEntities': ['host'], 'toPorts': [{'ports': [{'port': '8443', 'protocol': 'TCP'}]}]}],
                     'egress': [{'toCIDR': ['10.1.2.3/32'], 'toPorts': [{'ports': [{'port': '5432', 'protocol': 'TCP'}]}]}]}}


def inventory(*resources):
    return {'kind': 'List', 'items': list(resources), 'metadata': {'resourceVersion': 'fixture'}}


def pod():
    return {'metadata': {'name': 'api-1', 'namespace': 'sandbox-system', 'uid': 'pod-current',
                         'labels': {'sandbox.platform/network-policy': 'api-v1'}},
            'spec': {'serviceAccountName': 'sandbox-api'}}


def endpoint():
    return {'apiVersion': 'cilium.io/v2', 'kind': 'CiliumEndpoint',
            'metadata': {'name': 'api-1', 'namespace': 'sandbox-system', 'uid': 'cep-current',
                         'resourceVersion': '9', 'ownerReferences': [
                             {'apiVersion': 'v1', 'kind': 'Pod', 'name': 'api-1', 'uid': 'pod-current'}]},
            'status': {'state': 'ready', 'identity': {'id': 3728, 'labels': [
                'k8s:sandbox.platform/network-policy=api-v1',
                'k8s:io.kubernetes.pod.namespace=sandbox-system',
                'k8s:io.cilium.k8s.policy.serviceaccount=sandbox-api',
                'k8s:io.cilium.k8s.policy.cluster=default',
                'k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=sandbox-system']},
                'policy': {direction: {'enforcing': True, 'state': 'enforcing'}
                           for direction in ('ingress', 'egress')}}}


def identity():
    return gate.endpoint_identity(endpoint(), pod(), {'kubernetes.io/metadata.name': 'sandbox-system'}, 'default')


def check(*extra):
    expected = policy()
    return gate.analyze(expected, 'sandbox-system', {'kubernetes.io/metadata.name': 'sandbox-system'},
                        {'sandbox.platform/network-policy': 'api-v1'}, 'sandbox-api',
                        [inventory(expected, *extra)], endpoint_labels=identity())


class PolicyBoundary(unittest.TestCase):
    def test_current_bootstrap_cannot_widen_component_policy(self):
        sys.path.insert(0, str(ROOT / 'cluster/tests'))
        from test_cluster import fixture
        from render import policies
        from cluster import validate
        tf, settings = fixture()
        result = check(*policies(validate(tf, settings), settings))
        self.assertEqual(result['configuration_overlap'], 'PASS')
        self.assertEqual(result['runtime_enforcement'], 'NOT_VERIFIED')
        self.assertEqual(len(result['selected_policies']), 1)

    def test_old_bootstrap_and_multirule_clusterwide_allow_rejected(self):
        broad = {'kind': 'CiliumClusterwideNetworkPolicy', 'metadata': {'name': 'bootstrap'},
                 'spec': {'endpointSelector': {}, 'egress': [{'toCIDR': ['100.100.100.200/32']}]}}
        with self.assertRaises(gate.BoundaryError):
            check(broad)
        broad['specs'] = [broad.pop('spec'), {'endpointSelector': {'matchLabels': {'unrelated': 'pod'}}}]
        with self.assertRaises(gate.BoundaryError):
            check(broad)

    def test_service_account_and_namespace_label_sources_are_effective(self):
        for key, value in [('any:io.cilium.k8s.policy.serviceaccount', 'sandbox-api'),
                           ('k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name', 'sandbox-system')]:
            additional = {'kind': 'CiliumClusterwideNetworkPolicy', 'metadata': {'name': 'additional'},
                          'spec': {'endpointSelector': {'matchLabels': {key: value}}, 'egress': [{}]}}
            with self.assertRaises(gate.BoundaryError):
                check(additional)

    def test_namespace_scoping_and_default_deny_do_not_add_allows(self):
        elsewhere = copy.deepcopy(policy())
        elsewhere['metadata'].update(namespace='other', name='other')
        deny = {'kind': 'NetworkPolicy', 'metadata': {'name': 'default-deny', 'namespace': 'sandbox-system'},
                'spec': {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress'], 'ingress': [], 'egress': []}}
        self.assertEqual(check(elsewhere, deny)['configuration_overlap'], 'PASS')
        deny['spec']['egress'] = [{}]
        with self.assertRaises(gate.BoundaryError):
            check(deny)

    def test_changed_review_missing_live_and_unknown_engine_rejected(self):
        changed = copy.deepcopy(policy())
        changed['spec']['egress'] = [{'toEntities': ['world']}]
        labels = {'sandbox.platform/network-policy': 'api-v1'}
        for resources in [inventory(changed), inventory(), inventory(policy(), {'kind': 'AdminNetworkPolicy'})]:
            with self.assertRaises(gate.BoundaryError):
                gate.analyze(policy(), 'sandbox-system', {}, labels, 'sandbox-api', [resources], endpoint_labels=identity())

    def test_filtered_boundary_label_cannot_be_inferred_from_pod(self):
        actual = endpoint()
        actual['status']['identity']['labels'] = [v for v in actual['status']['identity']['labels']
                                                 if not v.startswith('k8s:sandbox.platform/network-policy=')]
        with self.assertRaises(gate.BoundaryError):
            gate.endpoint_identity(actual, pod(), {'kubernetes.io/metadata.name': 'sandbox-system'}, 'default')
        with self.assertRaises(TypeError):
            gate.analyze(policy(), 'sandbox-system', {}, pod()['metadata']['labels'], 'sandbox-api', [inventory(policy())])

    def test_endpoint_uid_enforcement_and_actual_identity_are_required(self):
        cases = []
        stale = endpoint(); stale['metadata']['ownerReferences'][0]['uid'] = 'previous-pod'; cases.append(stale)
        for direction in ('ingress', 'egress'):
            disabled = endpoint(); disabled['status']['policy'][direction]['enforcing'] = False; cases.append(disabled)
            missing = endpoint(); del missing['status']['policy'][direction]; cases.append(missing)
        for state in ('regenerating', 'waiting-for-identity', 'disconnecting'):
            actual = endpoint(); actual['status']['state'] = state; cases.append(actual)
        for label in ('reserved:init', 'container:tenant=other',
                      'k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=other',
                      'k8s:sandbox.platform/network-policy=api-v1'):
            actual = endpoint(); actual['status']['identity']['labels'].append(label); cases.append(actual)
        for actual in cases:
            with self.subTest(actual=cases.index(actual)), self.assertRaises(gate.BoundaryError):
                gate.endpoint_identity(actual, pod(), {'kubernetes.io/metadata.name': 'sandbox-system'}, 'default')

    def test_source_any_matches_actual_labels_without_inventing_reserved_labels(self):
        self.assertTrue(gate.matches({'matchLabels': {'any:role': 'worker'}}, {'reserved:role': 'worker'}, True))
        self.assertFalse(gate.matches({'matchExpressions': [{'key': 'reserved:host', 'operator': 'Exists'}]}, identity(), True))

    def test_expression_missing_notin_and_unknown_source_fail_closed(self):
        labels = {'k8s:sandbox.platform/network-policy': 'api-v1'}
        self.assertTrue(gate.matches({'matchExpressions': [{'key': 'absent', 'operator': 'NotIn', 'values': ['x']}]}, labels, True))
        self.assertFalse(gate.matches({'matchExpressions': [{'key': 'absent', 'operator': 'Exists'}]}, labels, True))
        for expression in [{'key': 'container:role', 'operator': 'Exists'},
                           {'key': 'role', 'operator': 'Gt', 'values': ['1']},
                           {'key': 'role', 'operator': 'Exists', 'values': ['x']}]:
            with self.assertRaises(gate.BoundaryError):
                gate.matches({'matchExpressions': [expression]}, labels, True)

    def test_truncated_inventory_and_duplicate_json_are_never_proof(self):
        for value in [{'items': [policy()], 'metadata': {'continue': 'more'}}, {'items': [policy()] * 513}]:
            with self.assertRaises(gate.BoundaryError):
                gate.items(value)
        with self.assertRaises(gate.BoundaryError):
            gate.strict_json(b'{"items":[],"items":[]}')
        with self.assertRaises(gate.BoundaryError):
            gate.strict_json(b'{"number": NaN}')

    def test_manifest_fifo_symlink_and_oversize_fail_before_unbounded_read(self):
        with tempfile.TemporaryDirectory(prefix='sandbox-reviewed-manifest-') as temporary:
            directory = Path(temporary)
            regular = directory / 'manifest.json'
            regular.write_bytes(b'{"items":[]}')
            self.assertEqual(gate.manifest_bytes(regular), b'{"items":[]}')
            link = directory / 'link'
            link.symlink_to(regular)
            with self.assertRaises(OSError):
                gate.manifest_bytes(link)
            fifo = directory / 'fifo'
            os.mkfifo(fifo)
            start = time.monotonic()
            with self.assertRaises(gate.BoundaryError):
                gate.manifest_bytes(fifo)
            self.assertLess(time.monotonic() - start, 1)
            with regular.open('wb') as target:
                target.truncate(8*1024*1024 + 1)
            with self.assertRaises(gate.BoundaryError):
                gate.manifest_bytes(regular)

    def test_command_deadline_and_output_bound_without_private_error_echo(self):
        start = time.monotonic()
        with self.assertRaises(gate.BoundaryError):
            gate.bounded_command([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=.1)
        self.assertLess(time.monotonic() - start, 2)
        with self.assertRaises(gate.BoundaryError) as failure:
            gate.bounded_command([sys.executable, '-c', 'print("private-fixture" * 10000)'], limit=1024)
        self.assertNotIn('private-fixture', str(failure.exception))


if __name__ == '__main__':
    unittest.main()
