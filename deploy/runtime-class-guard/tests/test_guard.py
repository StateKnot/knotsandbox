import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('runtime_guard_contract', HERE / 'guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def observed(key):
    value = json.loads((HERE / 'guard.json').read_text())[key]
    value['metadata'].update(uid='00000000-0000-4000-8000-000000000001', resourceVersion='opaque:v1', generation=1)
    if key == 'policy':
        value['status'] = {'observedGeneration': 1, 'typeChecking': {'expressionWarnings': []}}
    return value


class RuntimeClassGuard(unittest.TestCase):
    def test_exact_guard_rejects_audit_selectors_missing_rules_or_compile_warnings(self):
        for key, mutation in [
            ('binding', lambda v: v['spec'].update(validationActions=['Audit'])),
            ('binding', lambda v: v['spec']['matchResources'].update(objectSelector={'matchLabels': {'skip': 'true'}})),
            ('policy', lambda v: v['spec'].update(failurePolicy='Ignore')),
            ('policy', lambda v: v['spec']['validations'].pop()),
            ('policy', lambda v: v['metadata'].update(generation=2)),
            ('policy', lambda v: v['status']['typeChecking'].update(expressionWarnings=[{'warning': 'untyped'}])),
        ]:
            expected = json.loads((HERE / 'guard.json').read_text())[key]
            value = observed(key)
            mutation(value)
            with self.assertRaises(guard.Rejected):
                guard.validate_guard(value, expected)

    def test_opaque_resource_version_is_not_parsed_as_integer(self):
        value = observed('policy')
        expected = json.loads((HERE / 'guard.json').read_text())['policy']
        self.assertEqual(guard.validate_guard(value, expected), value['metadata']['uid'])
        for invalid in ['', 'bad version', 'x' * 257]:
            changed = copy.deepcopy(value)
            changed['metadata']['resourceVersion'] = invalid
            with self.assertRaises(guard.Rejected):
                guard.validate_guard(changed, expected)

    def test_install_refuses_existing_drift_without_applying_or_replacing(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'config'
            config.write_text('test path only; no transport')
            instance = guard.Guard(config, 'explicit', '00000000-0000-4000-8000-000000000001')
            value = observed('policy')
            value['spec']['validations'][0]['expression'] = 'true'
            with patch.object(instance, 'cluster'), patch.object(instance, 'get', return_value=value), patch.object(instance, 'run') as run:
                with self.assertRaises(guard.Rejected):
                    instance.install()
                run.assert_not_called()

    def test_minimal_observers_have_only_fixed_name_get(self):
        rbac = json.loads((HERE / 'read-rbac.json').read_text())['items']
        self.assertEqual(rbac[0]['rules'], [{'apiGroups': ['admissionregistration.k8s.io'],
            'resources': ['validatingadmissionpolicies', 'validatingadmissionpolicybindings'],
            'resourceNames': [guard.NAME], 'verbs': ['get']}])
        self.assertEqual({s['name'] for s in rbac[1]['subjects']}, {'sandbox-worker', 'sandbox-gateway', 'sandbox-termination'})
        self.assertTrue(all(s['namespace'] == 'sandbox-system' for s in rbac[1]['subjects']))

    def test_compiled_public_contract_and_fixture_are_present_in_docker_context(self):
        # Missing either file breaks real Docker compilation (including the
        # production SQLite acceptance target that compiles tests/support).
        ignore = (ROOT / '.dockerignore').read_text().splitlines()
        self.assertIn('!deploy/runtime-class-guard/', ignore)
        self.assertIn('!deploy/runtime-class-guard/guard.json', ignore)
        self.assertIn('!tests/support/runtime_class_guard.rs', ignore)


if __name__ == '__main__':
    unittest.main()
