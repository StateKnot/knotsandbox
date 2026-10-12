import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fixture_cleanup import fixture_directory
from observability import LOCK


class FixtureCleanupTest(unittest.TestCase):
    def test_default_owner_cleanup_runs_after_body_for_only_own_fixed_stores(self):
        for prefix, stores in [('sandbox-metrics-check-', ('wal', 'wal-samples')),
                               ('sandbox-prometheus-pipeline-', ('receiver', 'agent-a', 'agent-b'))]:
            with self.subTest(prefix=prefix):
                body_complete = False
                calls = []
                def run(command, **options):
                    self.assertTrue(body_complete)
                    calls.append((command, options))
                    return subprocess.CompletedProcess(command, 0, b'', b'')
                with patch('fixture_cleanup.subprocess.run', side_effect=run):
                    with fixture_directory(prefix, stores) as root:
                        for name in stores:
                            (root / name).mkdir(mode=0o777)
                        body_complete = True
                self.assertFalse(root.exists())
                self.assertEqual(len(calls), len(stores))
                for (command, options), name in zip(calls, stores):
                    self.assertEqual(command, ['docker', 'run', '--rm', '--pull=never', '--network=none',
                                              '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                                              '--mount', f'type=bind,src={root / name},dst=/prometheus',
                                              '--entrypoint=/bin/rm', LOCK['prometheus_image'],
                                              '-rf', '/prometheus/wal', '/prometheus/chunks_head'])
                    self.assertEqual(options['timeout'], 30)
                    self.assertFalse(options['check'])
                    self.assertFalse(any(arg.startswith('--user') or arg.startswith('--cap-add') for arg in command))

    def test_cleanup_failure_preserves_primary_error_and_retains_bounded_diagnostic(self):
        primary = ValueError('ORIGINAL_PROTOCOL_FAILURE')
        diagnostic = io.StringIO()
        failed = subprocess.CompletedProcess([], 1, b'', b'owner cleanup denied ' + b'x' * 20000)
        with patch('fixture_cleanup.subprocess.run', return_value=failed), contextlib.redirect_stderr(diagnostic):
            with self.assertRaises(ValueError) as caught:
                with fixture_directory('sandbox-metrics-check-', ('wal', 'wal-samples')) as root:
                    (root / 'wal').mkdir()
                    (root / 'wal-samples').mkdir()
                    raise primary
        self.assertIs(caught.exception, primary)
        self.assertIn('FIXTURE_CLEANUP_FAILED', diagnostic.getvalue())
        self.assertIn('owner cleanup denied', diagnostic.getvalue())
        self.assertLess(len(diagnostic.getvalue()), 8300)

    def test_cleanup_failure_after_success_fails_instead_of_printing_pass(self):
        failed = subprocess.CompletedProcess([], 1, b'', b'owner cleanup denied')
        with patch('fixture_cleanup.subprocess.run', return_value=failed), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(ValueError, '^FIXTURE_CLEANUP_FAILED$'):
                with fixture_directory('sandbox-metrics-check-', ('wal', 'wal-samples')) as root:
                    (root / 'wal').mkdir()

    def test_unknown_profile_and_symlink_store_cannot_mount_external_directory(self):
        with self.assertRaisesRegex(ValueError, '^FIXTURE_CLEANUP_PROFILE$'):
            with fixture_directory('foreign-', ('wal',)):
                self.fail('An unapproved profile must never enter its body')
        with tempfile.TemporaryDirectory() as external:
            sentinel = Path(external) / 'sentinel'
            sentinel.write_text('unrelated fixture must remain')
            with patch('fixture_cleanup.subprocess.run') as run, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaisesRegex(ValueError, '^FIXTURE_CLEANUP_FAILED$'):
                    with fixture_directory('sandbox-metrics-check-', ('wal', 'wal-samples')) as root:
                        (root / 'wal').symlink_to(external, target_is_directory=True)
            run.assert_not_called()
            self.assertEqual(sentinel.read_text(), 'unrelated fixture must remain')


if __name__ == '__main__':
    unittest.main()
