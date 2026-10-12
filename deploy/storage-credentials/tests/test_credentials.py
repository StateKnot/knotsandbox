import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('storage_credentials', Path(__file__).parents[1] / 'credentials.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def inputs():
    return {'deployment': 'sandbox-test', 'account_id': '1234567890123456', 'region': 'cn-hangzhou',
        'workload_roles': {purpose: {'arn': 'acs:ram::1234567890123456:role/sandbox-test-' + purpose,
            'role_id': '1234567890123457', 'subject': 'system:serviceaccount:sandbox-system:sandbox-' + component,
            'issuer': 'https://issuer.test', 'audience': 'sts.aliyuncs.com'}
            for component, purposes in module.SCOPES.items() for purpose in purposes}}


def deployment(component):
    return {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'namespace': 'sandbox-system', 'name': 'sandbox-' + component},
        'spec': {'replicas': 2, 'selector': {'matchLabels': {'app': component}}, 'template': {'metadata': {'labels': {'app': component}},
            'spec': {'serviceAccountName': 'sandbox-' + component, 'automountServiceAccountToken': False,
                'nodeSelector': {'sandbox.platform/node-pool': 'platform'},
                'securityContext': {'runAsUser': 10001, 'runAsGroup': 10001, 'fsGroup': 10001, 'runAsNonRoot': True, 'seccompProfile': {'type': 'RuntimeDefault'}},
                'containers': [{'name': component, 'image': 'registry.test/sandbox-service@sha256:' + 'a' * 64,
                    'securityContext': {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}}}]}}}}


class Composition(unittest.TestCase):
    def test_exact_scopes_private_volumes_and_startup_order(self):
        for component, purposes in module.SCOPES.items():
            original = deployment(component)
            config, result = module.compose(original, inputs(), component)
            self.assertEqual(original, deployment(component))
            self.assertTrue(config['immutable'])
            pod = result['spec']['template']['spec']
            self.assertEqual(len(pod['initContainers']), len(purposes))
            for helper in pod['initContainers']:
                self.assertEqual(helper['restartPolicy'], 'Always')
                self.assertEqual(helper['startupProbe']['exec']['command'][-1], '--check')
                self.assertEqual(helper['readinessProbe']['failureThreshold'], 1)
                writable = [m for m in helper['volumeMounts'] if not m.get('readOnly')]
                self.assertEqual(len(writable), 1)
            application_mounts = pod['containers'][0]['volumeMounts']
            self.assertTrue(all(m['readOnly'] for m in application_mounts))
            self.assertFalse(any('oidc' in m['name'] for m in application_mounts))
            self.assertEqual(len(config['data']), len(purposes))

    def test_mutable_images_guest_identities_and_existing_mounts_rejected(self):
        for change in range(6):
            obj = deployment('api')
            pod = obj['spec']['template']['spec']
            if change == 0: obj['metadata']['namespace'] = 'tenant'
            if change == 1: pod['serviceAccountName'] = 'sandbox-workload'
            if change == 2: pod['automountServiceAccountToken'] = True
            if change == 3: pod['containers'][0]['image'] = 'registry.test/service:latest'
            if change == 4: pod['containers'][0]['volumeMounts'] = [{'name': 'foreign', 'mountPath': '/run/sandbox-cloud/file-reader'}]
            if change == 5: pod['securityContext']['runAsUser'] = 0
            with self.assertRaises(ValueError): module.compose(obj, inputs(), 'api')

    def test_role_account_and_workload_bindings_cannot_be_retargeted(self):
        for field, value in [('arn', 'acs:ram::0000000000000000:role/operator'), ('subject', 'system:serviceaccount:sandbox-system:other'),
                              ('audience', 'kubernetes'), ('issuer', 'https://user:password@issuer.test'), ('role_id', 'malformed')]:
            value_inputs = copy.deepcopy(inputs())
            value_inputs['workload_roles']['file-reader'][field] = value
            with self.assertRaises(ValueError): module.compose(deployment('api'), value_inputs, 'api')
        with self.assertRaises(ValueError): module.configuration(inputs(), 'worker', 'file-reader')

    def test_config_revision_changes_with_role_rotation_and_refuses_double_composition(self):
        first = module.compose(deployment('api'), inputs(), 'api')
        changed = inputs(); changed['workload_roles']['file-reader']['role_id'] = '9876543210123456'
        second = module.compose(deployment('api'), changed, 'api')
        self.assertNotEqual(first[0]['metadata']['name'], second[0]['metadata']['name'])
        with self.assertRaises(ValueError): module.compose(first[1], inputs(), 'api')


if __name__ == '__main__': unittest.main()
