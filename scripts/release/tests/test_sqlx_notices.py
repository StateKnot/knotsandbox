"""Offline release/installation contracts, not GitHub or Sigstore certification."""
import contextlib
import copy
import io
import json
from pathlib import Path
import runpy
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import BINARIES, COMPONENTS, HISTORICAL_BINARIES, ROOT, SQLX_POSTGRES_NOTICES, NATIVE_PROTOCOL_NOTICES, load, release_file_names, sha
from download_previous import download
from sqlx_notices import create, validate, MAX_BYTES
from native_protocol_notices import create as create_native_notices
from test_release import COMMIT, FIXTURE_TIME, REPO, TAG, fixture, rewrite
from test_sqlite_build import native_trust_fixture
from verify import verify_candidate


class SqlxNoticesReleaseTest(unittest.TestCase):
    def setUp(self):
        self.trust = native_trust_fixture()
        self.trust.start()
        self.addCleanup(self.trust.stop)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        fixture(self.directory)

    def verify(self, **kwargs):
        return verify_candidate(self.directory, REPO, TAG, COMMIT, FIXTURE_TIME, **kwargs)

    def test_current_v4_contains_full_reviewed_sqlx_notices(self):
        self.assertEqual(self.verify()['version'], 4)
        value = load(self.directory / SQLX_POSTGRES_NOTICES)
        validate(value)
        for name, text in value['licenses'].items():
            self.assertEqual(text.encode(), (ROOT.parent.parent / 'vendor/sqlx-postgres' / name).read_bytes())

    def test_v4_cannot_omit_sqlx_notices_from_signed_inventory(self):
        manifest = load(self.directory / 'release-manifest.json')
        manifest['files'].pop(SQLX_POSTGRES_NOTICES)
        rewrite(self.directory / 'release-manifest.json', manifest)
        with self.assertRaisesRegex(ValueError, 'RELEASE_FILE_COVERAGE'):
            self.verify()

    def test_v4_cannot_omit_the_sqlx_notices_asset(self):
        (self.directory / SQLX_POSTGRES_NOTICES).unlink()
        with self.assertRaisesRegex(ValueError, 'ARTIFACT_MISSING'):
            self.verify()

    def test_v4_detects_sqlx_notices_byte_tampering(self):
        with (self.directory / SQLX_POSTGRES_NOTICES).open('ab') as output:
            output.write(b' ')
        with self.assertRaisesRegex(ValueError, 'RELEASE_FILE_HASH'):
            self.verify()

    def test_rehashed_truncated_license_still_fails_the_content_contract(self):
        path = self.directory / SQLX_POSTGRES_NOTICES
        value = load(path)
        value['licenses']['LICENSE-MIT'] = value['licenses']['LICENSE-MIT'][:-1]
        rewrite(path, value)
        manifest = load(self.directory / 'release-manifest.json')
        manifest['files'][SQLX_POSTGRES_NOTICES] = {'sha256': sha(path), 'size': path.stat().st_size}
        rewrite(self.directory / 'release-manifest.json', manifest)
        with self.assertRaisesRegex(ValueError, 'SQLX_NOTICES_LICENSE_BYTES'):
            self.verify()

    def test_v1_v2_remain_historical_only(self):
        original = load(self.directory / 'release-manifest.json')
        original_gate = load(self.directory / 'scan-gate.json')
        for version in (1, 2):
            with self.subTest(version=version):
                manifest = copy.deepcopy(original)
                manifest['version'] = version
                names = release_file_names(legacy=version == 1, version=version)
                manifest['files'] = {name: value for name, value in manifest['files'].items() if name in names}
                gate = copy.deepcopy(original_gate)
                if version == 1:
                    gate['reports'].pop('native-components')
                rewrite(self.directory / 'scan-gate.json', gate)
                manifest['files']['scan-gate.json'] = {'sha256': sha(self.directory / 'scan-gate.json'),
                                                      'size': (self.directory / 'scan-gate.json').stat().st_size}
                rewrite(self.directory / 'release-manifest.json', manifest)
                self.assertEqual(self.verify(historical=True)['version'], version)
                with self.assertRaisesRegex(ValueError, 'RELEASE_IDENTITY'):
                    self.verify()

    def test_v3_is_also_valid_as_authenticated_previous_history(self):
        manifest = load(self.directory / 'release-manifest.json')
        manifest['version'] = 3
        manifest['files'].pop(NATIVE_PROTOCOL_NOTICES)
        rewrite(self.directory / 'release-manifest.json', manifest)
        self.assertEqual(self.verify(historical=True)['version'], 3)
        with self.assertRaisesRegex(ValueError, 'RELEASE_IDENTITY'):
            self.verify()

    def test_producer_refuses_unreviewed_vendor_license_bytes(self):
        source = self.directory / 'source'
        source.mkdir()
        (source / 'scripts').mkdir()
        (source / 'vendor').mkdir()
        upstream = ROOT.parent.parent
        shutil.copytree(upstream / 'vendor/sqlx-postgres', source / 'vendor/sqlx-postgres')
        shutil.copyfile(upstream / 'scripts/verify-sqlx-postgres-patch.py',
                        source / 'scripts/verify-sqlx-postgres-patch.py')
        for name in ('Cargo.toml', 'Cargo.lock', '.dockerignore'):
            shutil.copyfile(upstream / name, source / name)
        (source / 'vendor/sqlx-postgres/LICENSE-MIT').write_text('truncated license')
        with self.assertRaisesRegex(RuntimeError, 'SQLX_PATCH_FILE_DIGEST'):
            create(source)


class SqlxNoticesDownloadTest(unittest.TestCase):
    def candidate(self, version, binaries=BINARIES):
        names = release_file_names(legacy=version == 1, version=version,
                                   binary_names=binaries, historical=True)
        manifest = {'version': version, 'binaries': list(binaries),
                    'files': {name: {'sha256': 'a' * 64, 'size': 1} for name in names}}
        return manifest

    def download(self, directory, manifest, *, extra=()):
        metadata = {'release-manifest.json', 'release-manifest.sigstore.json', 'provenance.json'}
        sizes = {name: data['size'] for name, data in manifest['files'].items()}
        sizes.update({name: 1 for name in metadata | set(extra)})
        release = {'draft': False, 'tag_name': TAG,
                   'assets': [{'name': name, 'size': size} for name, size in sizes.items()]}
        calls = []
        def execute(args, **kwargs):
            calls.append(list(args))
            if args[0] == 'gh' and 'release-manifest.json' in args:
                rewrite(directory / 'release-manifest.json', manifest)
        with patch('download_previous.github', return_value=release), \
             patch('download_previous.tool', return_value='gh'), \
             patch('download_previous.cosign_arguments', return_value=['cosign']), \
             patch('download_previous.run', side_effect=execute):
            download(directory, Path('/tools'), REPO, TAG, COMMIT)
        return calls

    def test_v1_v2_v3_v4_authenticated_metadata_controls_exact_download_whitelist(self):
        for version in (1, 2, 3, 4):
            for binaries in (HISTORICAL_BINARIES, BINARIES):
                with self.subTest(version=version, count=len(binaries)), tempfile.TemporaryDirectory() as temporary:
                    manifest = self.candidate(version, binaries)
                    calls = self.download(Path(temporary) / 'download', manifest, extra=('unselected-file',))
                    self.assertEqual(calls[1], ['cosign'])
                    self.assertNotIn(SQLX_POSTGRES_NOTICES, calls[0])
                    self.assertEqual(set(calls[2][calls[2].index('--pattern') + 1::2]), set(manifest['files']))
                    self.assertEqual(SQLX_POSTGRES_NOTICES in calls[2], version >= 3)
                    self.assertEqual(NATIVE_PROTOCOL_NOTICES in calls[2], version == 4)
                    self.assertNotIn('unselected-file', calls[2])

    def test_v3_manifest_cannot_drop_notices_from_download_inventory(self):
        manifest = self.candidate(3)
        manifest['files'].pop(SQLX_POSTGRES_NOTICES)
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(ValueError, 'PREVIOUS_RELEASE_FILE_COVERAGE'):
            self.download(Path(temporary) / 'download', manifest)

    def test_downloader_rejects_oversized_notices_before_bulk_fetch(self):
        manifest = self.candidate(3)
        manifest['files'][SQLX_POSTGRES_NOTICES]['size'] = MAX_BYTES + 1
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(ValueError, 'PREVIOUS_RELEASE_NOTICES_LIMIT'):
            self.download(Path(temporary) / 'download', manifest)

    def test_downloader_rejects_manifest_expansion_outside_the_whitelist(self):
        manifest = self.candidate(3)
        manifest['files']['unreviewed-file'] = {'sha256': 'a' * 64, 'size': 1}
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(ValueError, 'PREVIOUS_RELEASE_FILE_COVERAGE'):
            self.download(Path(temporary) / 'download', manifest)


class SqlxNoticesInstallationTest(unittest.TestCase):
    def install(self, base, *, tamper=False, version=4):
        source = base / 'candidate'
        source.mkdir()
        names = (*BINARIES, *(name + '.oci.tar' for name in COMPONENTS), SQLX_POSTGRES_NOTICES, NATIVE_PROTOCOL_NOTICES)
        for name in names:
            if name == SQLX_POSTGRES_NOTICES:
                payload = json.dumps(create(ROOT.parent.parent)).encode()
            elif name == NATIVE_PROTOCOL_NOTICES:
                payload = json.dumps(create_native_notices(ROOT.parent.parent)).encode()
            else:
                payload = b'PUBLIC INSTALLATION FIXTURE'
            (source / name).write_bytes(payload)
        manifest = {'version': version, 'files': {name: {'sha256': sha(source / name),
                                                'size': (source / name).stat().st_size} for name in names}}
        rewrite(source / 'release-manifest.json', manifest)
        destination = base / 'installed'
        def verified(args, **kwargs):
            # Only cryptographic verification is stubbed. The real installer
            # copies, hashes, sets modes and atomically publishes actual files.
            self.assertEqual(Path(args[1]), ROOT / 'verify.py')
            output = Path(args[args.index('--output') + 1])
            rewrite(output, {'manifest_sha256': sha(source / 'release-manifest.json')})
            if tamper:
                (source / (SQLX_POSTGRES_NOTICES if tamper is True else tamper)).write_bytes(b'TAMPER')
        argv = ['install.py', '--directory', str(source), '--tools', '/tools',
                '--repository', REPO, '--tag', TAG, '--commit', COMMIT,
                '--destination', str(destination)]
        with patch('sys.argv', argv), patch('common.run', side_effect=verified), contextlib.redirect_stdout(io.StringIO()):
            runpy.run_path(str(ROOT / 'install.py'), run_name='__main__')
        return source, destination, names

    def test_real_file_installation_preserves_verified_notices_and_execution_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, destination, names = self.install(Path(temporary))
            self.assertEqual({p.name for p in destination.iterdir()}, set(names) | {'deployment-lock.json'})
            self.assertEqual((destination / SQLX_POSTGRES_NOTICES).read_bytes(),
                             (source / SQLX_POSTGRES_NOTICES).read_bytes())
            self.assertEqual((destination / SQLX_POSTGRES_NOTICES).stat().st_mode & 0o777, 0o444)
            self.assertEqual((destination / NATIVE_PROTOCOL_NOTICES).read_bytes(),
                             (source / NATIVE_PROTOCOL_NOTICES).read_bytes())
            self.assertEqual((destination / NATIVE_PROTOCOL_NOTICES).stat().st_mode & 0o777, 0o444)
            self.assertEqual({p.name for p in destination.iterdir() if p.stat().st_mode & 0o111}, set(BINARIES))

    def test_notice_changed_after_verification_never_publishes_an_installation(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            with self.assertRaisesRegex(ValueError, 'ARTIFACT_CHANGED_AFTER_VERIFICATION'):
                self.install(base, tamper=True)
            self.assertFalse((base / 'installed').exists())

    def test_native_notice_changed_after_verification_never_publishes_an_installation(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            with self.assertRaisesRegex(ValueError, 'ARTIFACT_CHANGED_AFTER_VERIFICATION'):
                self.install(base, tamper=NATIVE_PROTOCOL_NOTICES)
            self.assertFalse((base / 'installed').exists())

    def test_installer_requires_current_v4_even_after_a_verification_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            with self.assertRaisesRegex(ValueError, 'CURRENT_RELEASE_SCHEMA_REQUIRED'):
                self.install(base, version=3)
            self.assertFalse((base / 'installed').exists())


if __name__ == '__main__':
    unittest.main()
