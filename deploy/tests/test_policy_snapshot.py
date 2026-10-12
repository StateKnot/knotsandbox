import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('policy_snapshot', ROOT / 'deploy/policy_snapshot.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def encoded(path):
    return base64.b64encode(path.read_bytes()).decode()


def config():
    return {'apiVersion': 'v1', 'kind': 'Config', 'preferences': {}, 'current-context': 'unselected',
            'clusters': [{'name': 'production', 'cluster': {'server': 'https://api.example.test:6443',
                'certificate-authority-data': encoded(ROOT / 'tests/fixtures/admission/apiserver-ca.pem')}}],
            'contexts': [{'name': 'production-review', 'context': {'cluster': 'production', 'user': 'reviewer'}},
                         {'name': 'unselected', 'context': {'cluster': 'production', 'user': 'reviewer'}}],
            'users': [{'name': 'reviewer', 'user': {'token': 'PUBLIC_TEST_ONLY'}}]}


class PolicySnapshot(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='policy-snapshot-fixture-')
        self.directory = Path(self.temporary.name)
        self.source = self.directory / 'private.kubeconfig'
        self.write(config())

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, value, raw=False):
        if self.source.exists():
            self.source.chmod(0o600)
        self.source.write_bytes(value if raw else json.dumps(value).encode())
        self.source.chmod(0o600)

    def rejects(self, value, raw=False):
        self.write(value, raw)
        with self.assertRaises(module.SnapshotError) as failure:
            with module.snapshot(self.source, 'production-review'):
                self.fail('unsafe kubeconfig was accepted')
        self.assertNotIn('PUBLIC_TEST_ONLY', str(failure.exception))

    def test_private_snapshot_pins_explicit_context_and_survives_source_replacement(self):
        with module.snapshot(self.source, 'production-review') as pinned:
            directory = pinned.config_path.parent
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(pinned.config_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(pinned.cache_dir.stat().st_mode), 0o700)
            self.assertEqual(pinned.config_path.stat().st_uid, os.geteuid())
            selected = json.loads(pinned.config_path.read_text())
            self.assertEqual(selected['current-context'], 'production-review')
            self.assertEqual(len(selected['contexts']), 1)
            dangerous = config()
            dangerous['users'][0]['user'] = {'exec': {'command': '/must-never-execute'}}
            replacement = self.directory / 'replacement'
            replacement.write_text(json.dumps(dangerous))
            replacement.chmod(0o600)
            replacement.replace(self.source)
            # A real subprocess receives only the pinned path. No original
            # config path, authentication plugin or credential is in argv.
            process = subprocess.run([sys.executable, '-c',
                'import json,sys; c=json.load(open(sys.argv[1])); '
                'assert c["current-context"]=="production-review"; '
                'assert set(c["users"][0]["user"])=={"token"}',
                str(pinned.config_path)], capture_output=True, timeout=2)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(process.stdout, b'')
        self.assertFalse(directory.exists())

    def test_inline_client_certificate_pair_and_yaml_are_supported(self):
        value = config()
        value['users'][0]['user'] = {
            'client-certificate-data': encoded(ROOT / 'tests/fixtures/admission/apiserver.pem'),
            'client-key-data': encoded(ROOT / 'tests/fixtures/admission/apiserver.key')}
        self.write(yaml.safe_dump(value).encode(), raw=True)
        with module.snapshot(self.source, 'production-review') as pinned:
            self.assertEqual(set(json.loads(pinned.config_path.read_text())['users'][0]['user']),
                             {'client-certificate-data', 'client-key-data'})
            self.assertEqual(set(p.name for p in pinned.config_path.parent.iterdir()),
                             {'kubeconfig.json', 'discovery'})
        value['users'][0]['user']['client-key-data'] = encoded(ROOT / 'tests/fixtures/admission/outsider.key')
        self.rejects(value)

    def test_private_modes_remain_exact_with_restrictive_caller_umask(self):
        previous = os.umask(0o777)
        try:
            with module.snapshot(self.source, 'production-review') as pinned:
                self.assertEqual(stat.S_IMODE(pinned.config_path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(pinned.cache_dir.stat().st_mode), 0o700)
        finally:
            os.umask(previous)

    def test_duplicate_fields_names_aliases_merge_and_unknown_tags_fail_closed(self):
        self.rejects(self.source.read_bytes().replace(b'"kind": "Config"',
            b'"kind": "Config", "kind": "Config"'), raw=True)
        self.rejects(b'apiVersion: v1\nkind: Config\nkind: Config\ntoken: PUBLIC_TEST_ONLY\n', raw=True)
        for raw in [b'apiVersion: v1\nkind: &shape Config\ncopy: *shape\n',
                    b'apiVersion: v1\nkind: &shape Config\n',
                    b'apiVersion: v1\nkind: Config\npreferences: {<<: {x: y}}\n',
                    b'!!python/object/apply:os.system [echo PUBLIC_TEST_ONLY]\n',
                    b'apiVersion: v1\nkind: Config\npreferences: {1: true}\n']:
            self.rejects(raw, raw=True)
        for field in ['clusters', 'contexts', 'users']:
            value = config()
            value[field].append(copy.deepcopy(value[field][0]))
            self.rejects(value)

    def test_plugins_path_credentials_impersonation_proxy_and_tls_overrides_rejected(self):
        users = [{'exec': {'command': '/must-never-execute'}}, {'auth-provider': {'name': 'oidc'}},
                 {'tokenFile': '/private/token'}, {'token': 'PUBLIC_TEST_ONLY', 'as': 'cluster-admin'},
                 {'username': 'PUBLIC_TEST_ONLY', 'password': 'PUBLIC_TEST_ONLY'},
                 {'client-certificate': '/cert.pem', 'client-key': '/key.pem'},
                 {'token': 'PUBLIC_TEST_ONLY', 'client-certificate-data': 'abcd', 'client-key-data': 'abcd'}]
        for user in users:
            value = config()
            value['users'][0]['user'] = user
            self.rejects(value)
        for addition in [{'certificate-authority': '/ca.pem'}, {'insecure-skip-tls-verify': False},
                         {'proxy-url': 'https://proxy.example.test'}, {'tls-server-name': 'other.example.test'}]:
            value = config()
            value['clusters'][0]['cluster'].update(addition)
            self.rejects(value)
        for server in ['http://api.example.test', 'https://user:PUBLIC_TEST_ONLY@api.example.test',
                       'https://api.example.test?token=PUBLIC_TEST_ONLY', 'https://api.example.test/#x',
                       'https://api.example.test:99999', 'https://api.example.test/prefix',
                       'https://api.example.test\n']:
            value = config()
            value['clusters'][0]['cluster']['server'] = server
            self.rejects(value)
        for credential in ['', 'not-base64', 'AA==', base64.b64encode(b'PUBLIC_TEST_ONLY').decode()]:
            value = config()
            value['clusters'][0]['cluster']['certificate-authority-data'] = credential
            self.rejects(value)

    def test_real_file_type_permissions_symlink_size_and_cleanup_on_error(self):
        for mode in [0o640, 0o644, 0o660, 0o4600, 0o700]:
            self.source.chmod(mode)
            # Some non-root macOS filesystems remove setuid during chmod;
            # exercise the special-bit negative when the kernel retains it.
            if mode == 0o4600 and stat.S_IMODE(self.source.stat().st_mode) != mode:
                continue
            with self.assertRaises(module.SnapshotError):
                with module.snapshot(self.source, 'production-review'):
                    self.fail('broad file mode was accepted')
        self.source.chmod(0o400)
        with module.snapshot(self.source, 'production-review'):
            pass
        link = self.directory / 'link'
        link.symlink_to(self.source)
        with self.assertRaises(module.SnapshotError):
            with module.snapshot(link, 'production-review'):
                self.fail('symlink was accepted')
        fifo = self.directory / 'fifo'
        os.mkfifo(fifo, mode=0o600)
        start = time.monotonic()
        with self.assertRaises(module.SnapshotError):
            with module.snapshot(fifo, 'production-review'):
                self.fail('FIFO was accepted')
        self.assertLess(time.monotonic() - start, 1)
        self.rejects(b'x' * (module.LIMIT + 1), raw=True)
        self.write(config())
        with self.assertRaisesRegex(RuntimeError, 'caller failure'):
            with module.snapshot(self.source, 'production-review') as pinned:
                directory = pinned.config_path.parent
                raise RuntimeError('caller failure')
        self.assertFalse(directory.exists())

    def test_explicit_context_and_finite_shared_deadline(self):
        for context in ['', '../production-review', 'missing']:
            with self.assertRaises(module.SnapshotError):
                with module.snapshot(self.source, context):
                    self.fail('invalid context was accepted')
        for seconds in [0, -1, 46, float('nan'), float('inf'), True]:
            with self.assertRaises(module.SnapshotError):
                with module.snapshot(self.source, 'production-review', seconds=seconds):
                    self.fail('invalid total deadline was accepted')
        with module.snapshot(self.source, 'production-review', seconds=.12) as pinned:
            self.assertLessEqual(pinned.remaining_timeout(), .12)
            self.assertLessEqual(pinned.remaining_timeout(maximum=.03), .03)
            time.sleep(.13)
            with self.assertRaises(module.SnapshotError):
                pinned.remaining_timeout()

    def test_complete_discovery_is_bounded_and_requires_all_supported_policy_apis(self):
        supported = sorted(module.SUPPORTED_POLICIES)
        with module.snapshot(self.source, 'production-review') as pinned:
            self.assertEqual(pinned.check_discovery(supported), ())
            unknown = 'globalnetworkpolicies.crd.projectcalico.org'
            self.assertEqual(pinned.check_discovery([*supported, unknown]), (unknown,))
            for resources in [supported[:-1], [*supported, supported[0]],
                              [*supported, '--unsafe'], [*supported, 'bad/name'],
                              [*supported, *[f'customnetworkpolicies{i}.example.test' for i in range(17)]],
                              [*supported, *[f'custom{i}.example.test' for i in range(254)]]]:
                with self.assertRaises(module.SnapshotError):
                    pinned.check_discovery(resources)


if __name__ == '__main__':
    unittest.main()
