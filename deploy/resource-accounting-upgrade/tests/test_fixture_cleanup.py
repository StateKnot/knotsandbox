import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('resource_upgrade_fixture_cleanup', ROOT / 'scripts/test-resource-upgrade-admission.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class FixtureCleanup(unittest.TestCase):
    def test_lost_run_ack_recovers_only_exact_owned_container_and_confirms_absence(self):
        name = 'sandbox-resource-admission-public-test'
        identifier = 'a' * 64
        actual = {'Id': identifier, 'Name': '/' + name,
                  'Config': {'Labels': {fixture.module.OWNER: name}}}
        responses = [SimpleNamespace(returncode=0, stdout=json.dumps(actual).encode(), stderr=b'')]
        responses += [SimpleNamespace(returncode=0, stdout=b'', stderr=b'') for _ in range(4)]
        with tempfile.TemporaryDirectory() as directory, patch.object(fixture.subprocess, 'run', side_effect=responses) as run:
            result = fixture.cleanup_control_plane(['docker'], {}, name, None, Path(directory))
        self.assertEqual(result['status'], 'CONFIRMED')
        self.assertTrue(result['recovered_after_unacknowledged_create'])
        self.assertEqual(run.call_args_list[2].args[0], ['docker', 'stop', '--time', '10', identifier])
        self.assertEqual(run.call_args_list[3].args[0], ['docker', 'rm', identifier])

    def test_unavailable_daemon_never_claims_cleanup_confirmed(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(fixture.subprocess, 'run', side_effect=subprocess.TimeoutExpired('docker inspect', 15)):
            result = fixture.cleanup_control_plane(['docker'], {}, 'sandbox-resource-admission-public-test', None, Path(directory))
        self.assertEqual(result['status'], 'UNCONFIRMED')

    def test_mismatching_label_is_never_stopped_or_removed(self):
        name = 'sandbox-resource-admission-public-test'
        actual = {'Id': 'a' * 64, 'Name': '/' + name, 'Config': {'Labels': {fixture.module.OWNER: 'another-owner'}}}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(fixture.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=json.dumps(actual).encode(), stderr=b'')) as run:
            result = fixture.cleanup_control_plane(['docker'], {}, name, None, Path(directory))
        self.assertEqual(result['status'], 'UNCONFIRMED')
        self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
