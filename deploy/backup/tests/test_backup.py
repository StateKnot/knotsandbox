import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup


class Contracts(unittest.TestCase):
    def test_clean_environment_does_not_forward_credentials_or_proxy(self):
        os.environ['AWS_ACCESS_KEY_ID'] = 'must-not-inherit'
        os.environ['RCLONE_CONFIG_EVIL_TYPE'] = 's3'
        os.environ['HTTPS_PROXY'] = 'http://must-not-use.invalid'
        env = backup.environment()
        self.assertEqual(env['AWS_EC2_METADATA_DISABLED'], 'true')
        self.assertNotIn('AWS_ACCESS_KEY_ID', env)
        self.assertNotIn('RCLONE_CONFIG_EVIL_TYPE', env)
        self.assertNotIn('HTTPS_PROXY', env)

    def test_duplicate_keys_nonfinite_and_short_hash_rejected(self):
        for value in ('{"x":1,"x":2}', '{"x":NaN}'):
            with self.assertRaises(ValueError):
                backup.decode(value)
        self.assertFalse(backup.sha('a' * 63))
        self.assertTrue(backup.sha('0' * 64))

    def test_bound_output_and_hung_child_are_killed(self):
        with self.assertRaisesRegex(ValueError, 'COMMAND_OUTPUT_LIMIT'):
            backup.run([sys.executable, '-c', 'import os;os.write(1,b"x"*10000)'], time.time() + 5, maximum=1024)
        start = time.monotonic()
        with self.assertRaisesRegex(ValueError, 'COMMAND_DEADLINE'):
            backup.run([sys.executable, '-c', 'import time;time.sleep(30)'], time.time() + 0.2)
        self.assertLess(time.monotonic() - start, 3)

    def test_hour_of_progress_does_not_accumulate_or_drop_the_final_summary(self):
        repository = backup.Repository('unused', 'unused', 'unused', time.time() + 10)
        def call(*args, sink=None):
            if args[0] == 'backup':
                for _ in range(7200):
                    sink(b'{"message_type":"status","percent_done":0.5}\n')
                sink(b'{"message_type":"summary","snapshot_id":"' + b'a' * 64 + b'"}\n')
            return b''
        repository.call = call
        self.assertEqual(repository.capture(['fixed-reader']), 'a' * 64)
        def invalid(*args, sink=None):
            if args[0] == 'backup':
                sink(b'x' * 65537)
            return b''
        repository.call = invalid
        with self.assertRaisesRegex(ValueError, 'RESTIC_FRAME_LIMIT'):
            repository.capture(['fixed-reader'])

    def test_secret_symlink_and_mode_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'secret'
            path.write_bytes(b'test')
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'SECRET_FILE_MODE'):
                backup.read(path, secret=True)
            path.chmod(0o600)
            self.assertEqual(backup.read(path, secret=True), b'test')
            link = Path(tmp) / 'link'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                backup.read(link)

    def test_manifest_cannot_select_another_tenant_or_repository(self):
        import datetime as dt
        now = dt.datetime.now(dt.timezone.utc)
        c = {'tenant_id': 'tenant', 'backup_id': 'backup', 'size_bytes': 512, 'deadline': (now + dt.timedelta(hours=1)).isoformat(),
             'data_timestamp': (now - dt.timedelta(minutes=1)).isoformat(), 'retention_until': (now + dt.timedelta(days=31)).isoformat()}
        inventory = {'format':'restic-object-inventory-v1','object_count':5,'total_bytes':512,'shards':[{'key':'inventory/000000.json','size_bytes':1024,'sha256':'c'*64,'object_count':5}]}
        value = backup.manifest(c, 'a' * 64, {'size_bytes': 512, 'sha256': 'b' * 64}, inventory)
        backup.validate_manifest(value, {**c, 'deadline': 'fresh'})
        with self.assertRaisesRegex(ValueError, 'MANIFEST_IDENTITY'):
            backup.validate_manifest(value, {**c, 'tenant_id': 'other'})
        value['repository_prefix'] = 'other/repo'
        with self.assertRaisesRegex(ValueError, 'MANIFEST_REPOSITORY'):
            backup.validate_manifest(value, c)


if __name__ == '__main__':
    unittest.main()
