"""Offline distribution contracts; no real signature or image build claims."""
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from build import create_manifest
from common import (BINARIES, NATIVE_PROTOCOL_NOTICES, SQLX_POSTGRES_NOTICES,
                    ROOT, load, release_file_names, sha)
from console_assets import verify_previous
from download_previous import download
from native_protocol_notices import create, validate, FIXED, LICENSES, MAX_BYTES, VENDORS
from test_release import COMMIT, FIXTURE_TIME, REPO, TAG, fixture, rewrite
from test_sqlite_build import native_trust_fixture
from verify import verify_candidate


class NativeProtocolNoticesReleaseTest(unittest.TestCase):
    def setUp(self):
        trust = native_trust_fixture()
        trust.start()
        self.addCleanup(trust.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        fixture(self.directory)

    def verify(self, **kwargs):
        return verify_candidate(self.directory, REPO, TAG, COMMIT, FIXTURE_TIME, **kwargs)

    def rehash(self, value):
        path = self.directory / NATIVE_PROTOCOL_NOTICES
        rewrite(path, value)
        manifest_path = self.directory / 'release-manifest.json'
        manifest = load(manifest_path)
        manifest['files'][NATIVE_PROTOCOL_NOTICES] = {'sha256': sha(path), 'size': path.stat().st_size}
        rewrite(manifest_path, manifest)

    def test_current_v4_delivers_complete_fixed_provenance_and_license_texts(self):
        self.assertEqual(self.verify()['version'], 4)
        self.assertEqual(self.verify(historical=True)['version'], 4)
        value = load(self.directory / NATIVE_PROTOCOL_NOTICES, MAX_BYTES)
        validate(value)
        self.assertEqual(value['protocols'], FIXED['protocols'])
        self.assertLessEqual((self.directory / NATIVE_PROTOCOL_NOTICES).stat().st_size, MAX_BYTES)
        for name, relative in VENDORS.items():
            self.assertEqual(value['licenses'][name].encode(),
                             (ROOT.parent.parent / relative / 'LICENSE').read_bytes())

    def test_v4_cannot_drop_native_notices_from_inventory(self):
        manifest_path = self.directory / 'release-manifest.json'
        manifest = load(manifest_path)
        manifest['files'].pop(NATIVE_PROTOCOL_NOTICES)
        rewrite(manifest_path, manifest)
        with self.assertRaisesRegex(ValueError, 'RELEASE_FILE_COVERAGE'):
            self.verify()

    def test_v4_requires_the_real_notice_asset_in_both_producer_and_verifier(self):
        (self.directory / NATIVE_PROTOCOL_NOTICES).unlink()
        with self.assertRaisesRegex(ValueError, 'ARTIFACT_MISSING'):
            self.verify()
        with self.assertRaisesRegex(ValueError, 'ARTIFACT_MISSING'):
            create_manifest(self.directory, REPO, TAG, COMMIT, '42',
                            {'first_release': True, 'previous': None})

    def test_notice_byte_tampering_fails_the_signed_inventory(self):
        with (self.directory / NATIVE_PROTOCOL_NOTICES).open('ab') as output:
            output.write(b' ')
        with self.assertRaisesRegex(ValueError, 'RELEASE_FILE_HASH'):
            self.verify()

    def test_rehash_cannot_authorize_truncated_license_or_changed_provenance(self):
        original = load(self.directory / NATIVE_PROTOCOL_NOTICES)
        for name in LICENSES:
            with self.subTest(license=name):
                value = copy.deepcopy(original)
                value['licenses'][name] = value['licenses'][name][:-1]
                self.rehash(value)
                with self.assertRaisesRegex(ValueError, 'NATIVE_PROTOCOL_NOTICES_LICENSE_BYTES'):
                    self.verify()
        for mutate in (
            lambda value: value['protocols'].pop('containerd'),
            lambda value: value['protocols']['containerd'].update(version='v2.3.6'),
            lambda value: value['protocols']['containerd']['inputs_sha256'].update(
                {'api/types/descriptor.proto': 'a' * 64}),
            lambda value: value.update(schema_version=True),
        ):
            value = copy.deepcopy(original)
            mutate(value)
            self.rehash(value)
            with self.assertRaisesRegex(ValueError, 'NATIVE_PROTOCOL_NOTICES_PROVENANCE'):
                self.verify()

    def test_rehashed_oversize_notice_is_rejected_with_original_limit(self):
        path = self.directory / NATIVE_PROTOCOL_NOTICES
        path.write_bytes(path.read_bytes() + b' ' * MAX_BYTES)
        manifest_path = self.directory / 'release-manifest.json'
        manifest = load(manifest_path)
        manifest['files'][NATIVE_PROTOCOL_NOTICES] = {'sha256': sha(path), 'size': path.stat().st_size}
        rewrite(manifest_path, manifest)
        with self.assertRaisesRegex(ValueError, 'JSON_LIMIT'):
            self.verify()

    def test_previous_v3_keeps_sqlx_only_and_requires_authentication(self):
        manifest_path = self.directory / 'release-manifest.json'
        manifest = load(manifest_path)
        manifest['version'] = 3
        manifest['files'].pop(NATIVE_PROTOCOL_NOTICES)
        (self.directory / NATIVE_PROTOCOL_NOTICES).unlink()
        rewrite(manifest_path, manifest)
        self.assertIn(SQLX_POSTGRES_NOTICES, manifest['files'])
        with self.assertRaisesRegex(ValueError, 'RELEASE_IDENTITY'):
            self.verify()
        # Only signature orchestration is mocked. All previous v3 file hashes,
        # OCI, native, scanner and SQLx notice checks still run normally.
        with patch('verify.cosign_arguments', return_value=['pinned-cosign']), \
             patch('console_assets.run') as crypto, patch('verify.verify_statement'):
            previous = verify_previous(self.directory, Path('/tools'), REPO, TAG, COMMIT)
        crypto.assert_called_once_with(['pinned-cosign'], timeout=60)
        self.assertEqual(previous['version'], 3)
        self.assertFalse((self.directory / 'deployment-lock.json').exists())
        with patch('verify.cosign_arguments', return_value=['pinned-cosign']), \
             patch('console_assets.run', side_effect=ValueError('SIGNATURE_REJECTED')), \
             patch('verify.verify_candidate') as candidate, \
             self.assertRaisesRegex(ValueError, 'SIGNATURE_REJECTED'):
            verify_previous(self.directory, Path('/tools'), REPO, TAG, COMMIT)
        candidate.assert_not_called()

    def test_producer_authenticates_every_protocol_input_and_license(self):
        source = self.directory / 'source'
        for relative in VENDORS.values():
            shutil.copytree(ROOT.parent.parent / relative, source / relative)
        expected = create(source)
        for name, relative in VENDORS.items():
            for filename in (*FIXED['protocols'][name]['inputs_sha256'], 'LICENSE'):
                with self.subTest(protocol=name, file=filename):
                    path = source / relative / filename
                    original = path.read_bytes()
                    path.write_bytes(original + b'TAMPER')
                    with self.assertRaisesRegex(ValueError, 'NATIVE_PROTOCOL_(SOURCE|LICENSE)_HASH'):
                        create(source)
                    path.write_bytes(original)
        self.assertEqual(create(source), expected)
        # Historical content validation must not depend on a current checkout.
        shutil.rmtree(source)
        self.assertEqual(validate(expected), expected)


class NativeProtocolNoticesDownloadTest(unittest.TestCase):
    def download(self, manifest, error=None):
        names = {'release-manifest.json', 'release-manifest.sigstore.json', 'provenance.json'}
        sizes = {name: item['size'] for name, item in manifest['files'].items()}
        sizes.update({name: 1 for name in names})
        release = {'draft': False, 'tag_name': TAG,
                   'assets': [{'name': name, 'size': size} for name, size in sizes.items()]}
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / 'previous'
            def execute(args, **kwargs):
                calls.append(list(args))
                if args[0] == 'gh' and 'release-manifest.json' in args:
                    rewrite(destination / 'release-manifest.json', manifest)
            with patch('download_previous.github', return_value=release), \
                 patch('download_previous.tool', return_value='gh'), \
                 patch('download_previous.cosign_arguments', return_value=['cosign']), \
                 patch('download_previous.run', side_effect=execute):
                if error:
                    with self.assertRaisesRegex(ValueError, error):
                        download(destination, Path('/tools'), REPO, TAG, COMMIT)
                else:
                    download(destination, Path('/tools'), REPO, TAG, COMMIT)
        return calls

    def candidate(self):
        return {'version': 4, 'binaries': list(BINARIES),
                'files': {name: {'sha256': 'a' * 64, 'size': 1}
                          for name in release_file_names(version=4)}}

    def test_v4_authenticates_metadata_then_fetches_both_notices(self):
        calls = self.download(self.candidate())
        self.assertNotIn(NATIVE_PROTOCOL_NOTICES, calls[0])
        self.assertEqual(calls[1], ['cosign'])
        self.assertIn(SQLX_POSTGRES_NOTICES, calls[2])
        self.assertIn(NATIVE_PROTOCOL_NOTICES, calls[2])

    def test_v4_missing_notice_or_size_above_limit_never_bulk_fetches(self):
        manifest = self.candidate()
        manifest['files'].pop(NATIVE_PROTOCOL_NOTICES)
        calls = self.download(manifest, 'PREVIOUS_RELEASE_FILE_COVERAGE')
        self.assertEqual(len(calls), 2)
        manifest = self.candidate()
        manifest['files'][NATIVE_PROTOCOL_NOTICES]['size'] = MAX_BYTES + 1
        calls = self.download(manifest, 'PREVIOUS_RELEASE_NATIVE_NOTICES_LIMIT')
        self.assertEqual(len(calls), 2)
        manifest = self.candidate()
        manifest['files'][SQLX_POSTGRES_NOTICES]['size'] = MAX_BYTES + 1
        calls = self.download(manifest, 'PREVIOUS_RELEASE_NOTICES_LIMIT')
        self.assertEqual(len(calls), 2)

    def test_versioned_inventory_does_not_reinterpret_v3_or_accept_legacy_mismatch(self):
        v3 = release_file_names(version=3)
        self.assertIn(SQLX_POSTGRES_NOTICES, v3)
        self.assertNotIn(NATIVE_PROTOCOL_NOTICES, v3)
        self.assertEqual(release_file_names(), v3 | {NATIVE_PROTOCOL_NOTICES})
        for legacy, version in ((True, 4), (False, 1), (True, 3), (False, True)):
            with self.assertRaisesRegex(ValueError, 'RELEASE_VERSION'):
                release_file_names(legacy=legacy, version=version)


if __name__ == '__main__':
    unittest.main()
