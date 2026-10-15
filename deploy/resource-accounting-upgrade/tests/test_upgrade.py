import copy
import importlib.util
import json
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('resource_upgrade', HERE / 'upgrade.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def plan():
    return {'schema_version': 1, 'namespace': 'sandbox-system',
            'cluster_uid': '00000000-0000-0000-0000-000000000001',
            'writers': {'sandbox-worker': {'containers': {'worker': 'registry.example.test/service@sha256:' + 'a' * 64}, 'init_containers': {}}},
            'workloads': [{'kind': 'Deployment', 'name': 'sandbox-worker', 'service_account': 'sandbox-worker', 'replicas': 2}],
            'sandboxd': '/opt/sandbox/bin/sandboxd', 'sandboxd_sha256': 'b' * 64, 'database_name': 'sandbox'}


class UpgradeContract(unittest.TestCase):
    def test_plan_rejects_floating_images_and_unreviewed_partial_writer_inventory(self):
        for mutation in [lambda v: v['writers']['sandbox-worker']['containers'].update(worker='registry.example.test/service:latest'),
                         lambda v: v['workloads'].clear(),
                         lambda v: v['writers'].update({'other': copy.deepcopy(v['writers']['sandbox-worker'])}),
                         lambda v: v['writers'].update({'default': v['writers'].pop('sandbox-worker')}),
                         lambda v: v.update(schema_version=True)]:
            value = plan()
            mutation(value)
            with self.assertRaises(gate.Rejected):
                gate.validate(value)

    def test_duplicate_keys_are_rejected_before_any_operation(self):
        with self.assertRaises(gate.Rejected):
            gate.strict_json('{"namespace":"safe","namespace":"other"}')

    def test_database_targets_require_verify_full_and_preserve_database_and_ca_binding(self):
        raw = 'postgres://sandbox_app:PUBLIC_TEST_ONLY@127.0.0.1:5432/sandbox?sslmode=verify-full&sslrootcert=/public-ca.pem'
        target, role = gate.database_target(raw, 'sandbox')
        self.assertEqual(role, 'sandbox_app')
        self.assertEqual(target, ('127.0.0.1', 5432, '/sandbox', '/public-ca.pem'))
        self.assertEqual(gate.database_target(raw.replace('sandbox_app:', 'sandbox%5fapp:'), 'sandbox')[1], role)
        for value in [raw.replace('verify-full', 'require'), raw + '&sslmode=disable', raw.replace('/sandbox?', '/other?'), raw + '\n']:
            with self.assertRaises(gate.Rejected):
                gate.database_target(value, 'sandbox')

    def test_maintenance_is_server_enforced_and_ephemeral_containers_not_an_escape(self):
        approved, binding = gate.manifests(plan())
        closed = gate.manifests(plan(), True)[0]
        self.assertEqual(binding['spec']['validationActions'], ['Deny'])
        self.assertEqual(approved['spec']['failurePolicy'], 'Fail')
        self.assertEqual(approved['spec']['matchConstraints']['resourceRules'][0]['resources'], ['pods', 'pods/ephemeralcontainers'])
        self.assertEqual(closed['spec']['validations'], [{'expression': 'false', 'message': gate.CLOSED}])
        self.assertIn('ephemeralContainers.size() == 0', approved['spec']['validations'][0]['expression'])

    def test_manifest_is_bound_to_namespace_plan_and_each_container_name(self):
        value = plan()
        policy = gate.manifests(value)[0]
        self.assertIn('request.namespace == "sandbox-system"', str(policy['spec']['matchConditions']))
        self.assertIn('c.name in', policy['spec']['validations'][0]['expression'])
        before = policy['metadata']['annotations']['sandbox.platform/upgrade-plan-sha256']
        value['writers']['sandbox-worker']['containers']['worker'] = 'registry.example.test/service@sha256:' + 'c' * 64
        self.assertNotEqual(before, gate.manifests(value)[0]['metadata']['annotations']['sandbox.platform/upgrade-plan-sha256'])

    def test_preflight_requires_fixed_regular_sandboxd_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            value = plan()
            executable = Path(directory).resolve() / 'sandboxd'
            executable.write_bytes(b'not executed')
            executable.chmod(0o700)
            value['sandboxd'] = str(executable)
            value['sandboxd_sha256'] = gate.sha(executable.read_bytes())
            instance = gate.Gate(value, '/unused', 'unused', Path(directory) / 'evidence')
            self.assertEqual(instance.executable(), str(executable))
            executable.write_bytes(b'replaced')
            with self.assertRaises(gate.Rejected):
                instance.executable()

    def test_actual_admission_drift_cannot_hide_behind_matching_plan_annotation(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = gate.Gate(plan(), '/unused', 'unused', Path(directory) / 'evidence')
            documents = gate.manifests(plan())
            documents[0]['spec']['validations'][0]['expression'] = 'true'
            with patch.object(instance, 'get', side_effect=documents):
                with self.assertRaises(gate.Rejected):
                    instance.installed(False)

    def test_failure_after_fence_does_not_resume_old_writers(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = gate.Gate(plan(), '/unused', 'unused', Path(directory) / 'evidence')
            calls = []
            def fail():
                instance.maintenance = True
                raise gate.Rejected('ACTUAL_MIGRATION_FAILED')
            with patch.object(instance, 'identity'), patch.object(instance, 'acquire_operation_lock'), patch.object(instance, 'kubectl', return_value=type('R', (), {'stdout': b''})()), \
                    patch.object(instance, 'install', side_effect=lambda closed=False: calls.append(('install', closed))), \
                    patch.object(instance, 'verify'), patch.object(instance, 'maintain', side_effect=fail), \
                    patch.object(instance, 'scale', side_effect=lambda resume: calls.append(('scale', resume))):
                with self.assertRaises(gate.Rejected):
                    instance.run('maintain')
            self.assertEqual(instance.record['status'], 'FAIL')
            self.assertTrue(instance.record['maintenance_left_closed'])
            self.assertEqual(calls[-2:], [('install', True), ('scale', False)])
            self.assertNotIn(('scale', True), calls)

    def test_operation_lock_is_atomic_create_only_and_deleted_with_exact_uid(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = gate.Gate(plan(), '/unused', 'unused', Path(directory) / 'evidence')
            documents = []
            actual = {}
            def kube(args, value=None):
                documents.append((args, value))
                if args[0] == 'create':
                    actual.update(copy.deepcopy(value))
                    actual['metadata']['uid'] = '00000000-0000-0000-0000-000000000009'
                    return type('R', (), {'stdout': json.dumps(actual).encode()})()
                return type('R', (), {'stdout': b''})()
            with patch.object(instance, 'kubectl', side_effect=kube), patch.object(instance, 'get', return_value=actual):
                instance.acquire_operation_lock()
                self.assertNotIn('ttl', str(documents[0]).lower())
                self.assertEqual(documents[0][0], ['create', '-f', '-', '-o', 'json'])
                instance.release_operation_lock()
            self.assertEqual(documents[-1][0][:2], ['delete', '--raw'])
            self.assertEqual(documents[-1][1]['preconditions'], {'uid': '00000000-0000-0000-0000-000000000009'})
            self.assertIsNone(instance.operation_lock)

    def test_second_operation_cannot_modify_policy_when_create_lock_conflicts(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = gate.Gate(plan(), '/unused', 'unused', Path(directory) / 'evidence')
            with patch.object(instance, 'identity'), patch.object(instance, 'kubectl', side_effect=gate.Rejected('COMMAND_FAILED')) as kube, \
                    patch.object(instance, 'install') as install, patch.object(instance, 'maintain') as maintain:
                with self.assertRaisesRegex(gate.Rejected, 'UPGRADE_OPERATION_LOCK_NOT_ACQUIRED'):
                    instance.run('maintain')
            self.assertEqual(kube.call_args.args[0][0], 'create')
            install.assert_not_called()
            maintain.assert_not_called()
            self.assertEqual(instance.record['status'], 'FAIL')

    def test_failed_unclosed_execution_preserves_lock_for_operator_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = gate.Gate(plan(), '/unused', 'unused', Path(directory) / 'evidence')
            def acquire():
                instance.operation_lock = {'name': 'owned', 'uid': 'old', 'operation': 'original'}
            with patch.object(instance, 'identity'), patch.object(instance, 'acquire_operation_lock', side_effect=acquire), \
                    patch.object(instance, 'kubectl', side_effect=gate.Rejected('COMMAND_FAILED')), \
                    patch.object(instance, 'release_operation_lock') as release:
                with self.assertRaises(gate.Rejected):
                    instance.run('maintain')
            release.assert_not_called()
            self.assertTrue(instance.record['operation_lock_requires_operator_recovery'])

    def test_lock_release_cannot_delete_a_same_name_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = gate.Gate(plan(), '/unused', 'unused', Path(directory) / 'evidence')
            instance.operation_lock = {'name': 'owned', 'uid': 'old', 'operation': 'original'}
            with patch.object(instance, 'get', return_value={'metadata': {'uid': 'replacement'}}), \
                    patch.object(instance, 'kubectl') as kube:
                with self.assertRaisesRegex(gate.Rejected, 'UPGRADE_OPERATION_LOCK_OWNER_CHANGED'):
                    instance.release_operation_lock()
            kube.assert_not_called()

    def test_admission_cache_convergence_never_skips_required_actual_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = gate.Gate(plan(), '/unused', 'unused', Path(directory) / 'evidence')
            with patch.object(instance, 'kubectl', side_effect=[gate.Rejected('EXPECTED_ACTUAL_ADMISSION_DENIAL_MISSING'), 'actual denied']) as kube, \
                    patch.object(gate.time, 'sleep'):
                actual = instance.admission_probe(['create', '--dry-run=server', '-f', '-'], {}, expected=1, marker=gate.CLOSED)
            self.assertEqual(actual, 'actual denied')
            self.assertEqual(kube.call_count, 2)
            with self.assertRaisesRegex(gate.Rejected, 'ADMISSION_RETRY_REQUIRES_SERVER_DRY_RUN'):
                instance.admission_probe(['create', '-f', '-'], {})

    def test_lost_delete_ack_after_rollout_is_completed_cleanup_failure_without_unlocked_refence(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = gate.Gate(plan(), '/unused', 'unused', Path(directory) / 'evidence')
            def acquire():
                instance.operation_lock = {'name': 'owned', 'uid': 'old', 'operation': 'original'}
            def maintained():
                instance.maintenance = True
            with patch.object(instance, 'identity'), patch.object(instance, 'acquire_operation_lock', side_effect=acquire), \
                    patch.object(instance, 'kubectl', return_value=type('R', (), {'stdout': b''})()), \
                    patch.object(instance, 'install') as install, patch.object(instance, 'verify'), \
                    patch.object(instance, 'maintain', side_effect=maintained), patch.object(instance, 'scale') as scale, \
                    patch.object(instance, 'release_operation_lock', side_effect=subprocess.TimeoutExpired('kubectl DELETE', 30)):
                with self.assertRaises(gate.CompletedWithCleanupFailure):
                    instance.run('maintain')
            self.assertEqual(instance.record['status'], 'COMPLETED_WITH_CLEANUP_FAILURE')
            self.assertEqual(instance.record['completed_action'], 'maintain')
            self.assertFalse(instance.record['operation_lock_released'])
            self.assertTrue(instance.record['operation_lock_requires_operator_recovery'])
            install.assert_called_once_with(False)
            scale.assert_not_called()

    def test_receipt_write_failure_at_each_completed_finalization_boundary_stays_completed(self):
        for failure in ('probe_cleanup', 'delete_ack', 'last_receipt'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                instance = gate.Gate(plan(), '/unused', 'unused', Path(directory) / 'evidence')
                def acquire():
                    instance.operation_lock = {'name': 'owned', 'uid': 'old', 'operation': 'original'}
                def release():
                    if failure == 'delete_ack':
                        raise gate.Rejected('COMMAND_FAILED')
                    instance.operation_lock = None
                def clean():
                    if failure == 'probe_cleanup':
                        raise gate.Rejected('COMMAND_FAILED')
                with patch.object(instance, 'identity'), patch.object(instance, 'acquire_operation_lock', side_effect=acquire), \
                        patch.object(instance, 'kubectl', return_value=type('R', (), {'stdout': b''})()), \
                        patch.object(instance, 'install') as install, patch.object(instance, 'verify'), \
                        patch.object(instance, 'maintain'), patch.object(instance, 'scale') as scale, \
                        patch.object(instance, 'clean_probes', side_effect=clean), \
                        patch.object(instance, 'release_operation_lock', side_effect=release), \
                        patch.object(instance, 'save', side_effect=OSError('public disk full fixture')):
                    with self.assertRaises(gate.CompletedWithCleanupFailure):
                        instance.run('maintain')
                self.assertEqual(instance.record['status'], 'COMPLETED_WITH_CLEANUP_FAILURE')
                self.assertEqual(instance.record['completed_action'], 'maintain')
                install.assert_called_once_with(False)
                scale.assert_not_called()


if __name__ == '__main__':
    unittest.main()
