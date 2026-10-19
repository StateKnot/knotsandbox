"""Exact decoder notices across real offline producers and release consumers."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from build import create_manifest
from common import (BINARIES, OCI_PAYLOAD_NOTICES, NATIVE_PROTOCOL_NOTICES, ROOT,
                    dump, load, release_file_names, sha)
from console_assets import verify_previous
from oci_payload_notices import (create, validate, validate_distribution, FIXED,
                                 MAX_BYTES, MAX_LOCK_BYTES)
from test_release import COMMIT, FIXTURE_TIME, REPO, TAG, blob, fixture, rewrite
from test_sqlite_build import native_trust_fixture
import test_native_protocol_notices
import test_sqlx_notices
from verify import verify_candidate


class OciPayloadNoticesTest(unittest.TestCase):
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

    def rehash(self, name, value):
        path = self.directory / name
        rewrite(path, value)
        manifest_path = self.directory / 'release-manifest.json'
        manifest = load(manifest_path)
        manifest['files'][name] = {'sha256': sha(path), 'size': path.stat().st_size}
        rewrite(manifest_path, manifest)

    def test_real_cli_producer_preserves_all_five_original_mit_files_and_lock(self):
        source = ROOT.parent.parent
        output = self.directory / 'producer.json'
        subprocess.run([sys.executable, '-B', str(ROOT / 'oci_payload_notices.py'),
                        '--source', str(source), '--output', str(output)],
                       check=True, timeout=30, capture_output=True)
        value = load(output)
        validate(value, (source / 'Cargo.lock').read_bytes())
        self.assertEqual(value['cargo_lock_sha256'], sha(source / 'Cargo.lock'))
        self.assertEqual({name: record['version'] for name, record in value['crates'].items()},
                         {'flate2': '1.1.10', 'crc32fast': '1.5.2', 'miniz_oxide': '0.9.1',
                          'adler2': '2.0.1', 'simd-adler32': '0.3.10'})
        for name, record in value['crates'].items():
            body = (source / 'licenses/oci-payload' / (name + '-' + record['version'] + '-MIT.txt')).read_bytes()
            self.assertEqual(value['licenses'][name].encode(), body)
            self.assertIn(b'Permission is hereby granted', body)
            self.assertEqual(hashlib.sha256(body).hexdigest(), record['license_sha256'])
        self.assertLess(output.stat().st_size, MAX_BYTES)

    def test_producer_rejects_modified_or_missing_license_bytes(self):
        source = self.directory / 'source'
        shutil.copytree(ROOT.parent.parent / 'licenses/oci-payload', source / 'licenses/oci-payload')
        shutil.copyfile(ROOT.parent.parent / 'Cargo.lock', source / 'Cargo.lock')
        expected = create(source)
        for name, record in FIXED['crates'].items():
            path = source / 'licenses/oci-payload' / (name + '-' + record['version'] + '-MIT.txt')
            original = path.read_bytes()
            for contents in (original[:-1], original + b'TAMPER'):
                path.write_bytes(contents)
                with self.subTest(crate=name), self.assertRaisesRegex(ValueError, 'OCI_PAYLOAD_LICENSE_HASH'):
                    create(source)
            path.unlink()
            with self.assertRaisesRegex(ValueError, 'ARTIFACT_MISSING'):
                create(source)
            path.write_bytes(original)
        self.assertEqual(create(source), expected)
        shutil.rmtree(source)
        self.assertEqual(validate(expected, (ROOT.parent.parent / 'Cargo.lock').read_bytes()), expected)

    def test_current_v5_and_authenticated_history_require_exact_notice_inventory(self):
        self.assertEqual(self.verify()['version'], 5)
        self.assertEqual(self.verify(historical=True)['version'], 5)
        self.assertEqual(release_file_names(), release_file_names(version=4) | {OCI_PAYLOAD_NOTICES})
        manifest_path = self.directory / 'release-manifest.json'
        manifest = load(manifest_path)
        manifest['files'].pop(OCI_PAYLOAD_NOTICES)
        rewrite(manifest_path, manifest)
        with self.assertRaisesRegex(ValueError, 'RELEASE_FILE_COVERAGE'):
            self.verify()

    def test_v4_native_schema2_history_keeps_original_inventory_and_cannot_install_as_current(self):
        path = self.directory / 'release-manifest.json'
        manifest = load(path)
        manifest['version'] = 4
        manifest['files'].pop(OCI_PAYLOAD_NOTICES)
        rewrite(path, manifest)
        self.assertEqual(set(manifest['files']), release_file_names(version=4))
        with self.assertRaisesRegex(ValueError, 'RELEASE_IDENTITY'):
            self.verify()
        with patch('verify.cosign_arguments', return_value=['pinned-cosign']), \
             patch('console_assets.run') as crypto, patch('verify.verify_statement'):
            previous = verify_previous(self.directory, Path('/tools'), REPO, TAG, COMMIT)
        self.assertEqual(previous['version'], 4)
        crypto.assert_called_once_with(['pinned-cosign'], timeout=60)
        self.assertFalse((self.directory / 'deployment-lock.json').exists())

    def test_missing_asset_is_rejected_by_both_current_producer_and_verifier(self):
        (self.directory / OCI_PAYLOAD_NOTICES).unlink()
        with self.assertRaisesRegex(ValueError, 'ARTIFACT_MISSING'):
            self.verify()
        with self.assertRaisesRegex(ValueError, 'ARTIFACT_MISSING'):
            create_manifest(self.directory, REPO, TAG, COMMIT, '42', {'first_release': True, 'previous': None})

    def test_rehash_cannot_authorize_truncated_body_or_changed_fixed_provenance(self):
        original = load(self.directory / OCI_PAYLOAD_NOTICES)
        mutations = [lambda value: value['licenses'].pop('adler2'),
                     lambda value: value.update(schema_version=True),
                     lambda value: value['crates'].pop('simd-adler32')]
        for name in FIXED['crates']:
            mutations.extend([
                lambda value, name=name: value['licenses'].__setitem__(name, value['licenses'][name][:-1]),
                lambda value, name=name: value['crates'][name].update(version='0.0.0'),
                lambda value, name=name: value['crates'][name].update(selected_license='Apache-2.0'),
                lambda value, name=name: value['crates'][name].update(crate_archive_sha256='a' * 64),
            ])
        for mutate in mutations:
            value = copy.deepcopy(original)
            mutate(value)
            self.rehash(OCI_PAYLOAD_NOTICES, value)
            with self.subTest(value=value.get('schema_version')), \
                 self.assertRaisesRegex(ValueError, 'OCI_PAYLOAD_NOTICES_(PROVENANCE|LICENSES|LICENSE_BYTES)'):
                self.verify()

    def test_lock_origin_version_checksum_duplicate_or_missing_crate_rejects_even_after_rehash(self):
        original = (self.directory / 'Cargo.lock').read_bytes()
        notices = load(self.directory / OCI_PAYLOAD_NOTICES)
        for name, record in FIXED['crates'].items():
            package = ('[[package]]\nname="' + name + '"\nversion="' + record['version']
                       + '"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="'
                       + record['crate_archive_sha256'] + '"\n').encode()
            self.assertIn(package, original)
            mutations = (original.replace(package, b''), original + package,
                         original.replace(package, package.replace(record['version'].encode(), b'0.0.0')),
                         original.replace(package, package.replace(b'registry+', b'untrusted+')),
                         original.replace(package, package.replace(record['crate_archive_sha256'].encode(), b'a' * 64)))
            for changed in mutations:
                value = copy.deepcopy(notices)
                value['cargo_lock_sha256'] = hashlib.sha256(changed).hexdigest()
                with self.subTest(crate=name), self.assertRaisesRegex(ValueError, 'OCI_PAYLOAD_NOTICES_LOCK_COVERAGE'):
                    validate(value, changed)
        with self.assertRaisesRegex(ValueError, 'OCI_PAYLOAD_NOTICES_LOCK_HASH'):
            validate(notices, original + b'\n')
        with self.assertRaisesRegex(ValueError, 'OCI_PAYLOAD_NOTICES_LOCK_LIMIT'):
            validate(notices, b' ' * (MAX_LOCK_BYTES + 1))

    def test_signed_inventory_tamper_and_notice_size_bound(self):
        path = self.directory / OCI_PAYLOAD_NOTICES
        original = path.read_bytes()
        path.write_bytes(original + b' ')
        with self.assertRaisesRegex(ValueError, 'RELEASE_FILE_HASH'):
            self.verify()
        path.write_bytes(original + b' ' * MAX_BYTES)
        manifest_path = self.directory / 'release-manifest.json'
        manifest = load(manifest_path)
        manifest['files'][OCI_PAYLOAD_NOTICES] = {'sha256': sha(path), 'size': path.stat().st_size}
        rewrite(manifest_path, manifest)
        with self.assertRaisesRegex(ValueError, 'JSON_LIMIT'):
            self.verify()

    def test_admitted_oversized_lock_is_read_with_a_cap_before_parse_in_every_current_consumer(self):
        # The release inventory admits this file under its general 8 GiB cap.
        # Rehash both the notice binding and inventory so only the actual
        # bounded lock reader can reject it, before TOML or native processing.
        path = self.directory / 'Cargo.lock'
        path.write_bytes(b' ' * (MAX_LOCK_BYTES + 1))
        notice = load(self.directory / OCI_PAYLOAD_NOTICES)
        notice['cargo_lock_sha256'] = sha(path)
        self.rehash(OCI_PAYLOAD_NOTICES, notice)
        manifest_path = self.directory / 'release-manifest.json'
        manifest = load(manifest_path)
        manifest['files']['Cargo.lock'] = {'sha256': sha(path), 'size': path.stat().st_size}
        rewrite(manifest_path, manifest)
        original_fdopen = os.fdopen
        reads = []
        class CappedReadEvidence:
            def __init__(self, descriptor, mode):
                self.source = original_fdopen(descriptor, mode)
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.source.close()
            def fileno(self):
                return self.source.fileno()
            def read(self, size=-1):
                reads.append(size)
                if not 0 <= size <= MAX_LOCK_BYTES + 1:
                    raise AssertionError('unbounded lock read')
                return self.source.read(size)
        consumers = [lambda: create(self.directory),
                     lambda: create_manifest(self.directory, REPO, TAG, COMMIT, '42',
                                             {'first_release': True, 'previous': None}),
                     lambda: self.verify(), lambda: self.verify(historical=True)]
        for index, consume in enumerate(consumers):
            reads.clear()
            with self.subTest(consumer=index), \
                 patch.object(Path, 'read_bytes', side_effect=AssertionError('whole-file read')) as whole, \
                 patch('oci_payload_notices.os.fdopen', side_effect=CappedReadEvidence), \
                 patch('oci_payload_notices.tomllib.loads') as parser, \
                 self.assertRaisesRegex(ValueError, 'OCI_PAYLOAD_NOTICES_LOCK_LIMIT'):
                consume()
            self.assertEqual(reads, [MAX_LOCK_BYTES + 1])
            whole.assert_not_called()
            parser.assert_not_called()

    def test_runtime_license_omission_is_rejected_after_all_image_and_inventory_hashes_are_updated(self):
        component = 'runner'
        image = self.directory / component
        initial_index = load(image / 'index.json')
        initial = load(image / 'blobs/sha256' / initial_index['manifests'][0]['digest'][7:])
        with tarfile.open(image / 'blobs/sha256' / initial['layers'][0]['digest'][7:]) as archive:
            files = {entry.name: archive.extractfile(entry).read() for entry in archive if entry.isfile()}
        files.pop('usr/share/sandbox-platform/licenses/oci-payload/adler2-2.0.1-MIT.txt')
        body = io.BytesIO()
        with tarfile.open(fileobj=body, mode='w') as archive:
            for name, data in files.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                entry.mode = 0o555
                archive.addfile(entry, io.BytesIO(data))
        data = body.getvalue()
        digest = hashlib.sha256(data).hexdigest()
        (image / 'blobs/sha256' / digest).write_bytes(data)
        index = load(image / 'index.json')
        manifest = load(image / 'blobs/sha256' / index['manifests'][0]['digest'][7:])
        manifest['layers'] = [{'mediaType': 'application/vnd.oci.image.layer.v1.tar',
                               'digest': 'sha256:' + digest, 'size': len(data)}]
        descriptor = blob(image, manifest, 'application/vnd.oci.image.manifest.v1+json')
        rewrite(image / 'index.json', {'schemaVersion': 2, 'manifests': [descriptor]})
        archive_path = self.directory / (component + '.oci.tar')
        with tarfile.open(archive_path, 'w') as archive:
            for path in sorted(image.rglob('*')):
                archive.add(path, arcname=str(path.relative_to(image)), recursive=False)
        release_path = self.directory / 'release-manifest.json'
        release = load(release_path)
        release['images'][component]['digest'] = descriptor['digest']
        release['files'][archive_path.name] = {'sha256': sha(archive_path), 'size': archive_path.stat().st_size}
        rewrite(release_path, release)
        with self.assertRaisesRegex(ValueError, 'OCI_PAYLOAD_DISTRIBUTION'):
            self.verify()

    def test_installer_preserves_full_notice_and_refuses_postverification_tamper_and_v4(self):
        installer = test_sqlx_notices.SqlxNoticesInstallationTest()
        with tempfile.TemporaryDirectory() as temporary:
            source, destination, _ = installer.install(Path(temporary))
            self.assertEqual((destination / OCI_PAYLOAD_NOTICES).read_bytes(), (source / OCI_PAYLOAD_NOTICES).read_bytes())
            self.assertEqual((destination / OCI_PAYLOAD_NOTICES).stat().st_mode & 0o777, 0o444)
        for settings, error in (({'tamper': OCI_PAYLOAD_NOTICES}, 'ARTIFACT_CHANGED_AFTER_VERIFICATION'),
                                ({'version': 4}, 'CURRENT_RELEASE_SCHEMA_REQUIRED')):
            with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(ValueError, error):
                installer.install(Path(temporary), **settings)

    def test_v5_download_authenticates_before_notice_fetch_and_enforces_its_limit(self):
        downloader = test_native_protocol_notices.NativeProtocolNoticesDownloadTest()
        manifest = {'version': 5, 'binaries': list(BINARIES),
                    'files': {name: {'sha256': 'a' * 64, 'size': 1} for name in release_file_names()}}
        calls = downloader.download(manifest)
        self.assertNotIn(OCI_PAYLOAD_NOTICES, calls[0])
        self.assertEqual(calls[1], ['cosign'])
        self.assertIn(OCI_PAYLOAD_NOTICES, calls[2])
        manifest['files'][OCI_PAYLOAD_NOTICES]['size'] = MAX_BYTES + 1
        self.assertEqual(len(downloader.download(manifest, 'PREVIOUS_RELEASE_OCI_NOTICES_LIMIT')), 2)
        manifest['files'].pop(OCI_PAYLOAD_NOTICES)
        self.assertEqual(len(downloader.download(manifest, 'PREVIOUS_RELEASE_FILE_COVERAGE')), 2)

    def test_v5_downloader_rejects_oversized_lock_before_bulk_fetch_without_reinterpreting_v4(self):
        downloader = test_native_protocol_notices.NativeProtocolNoticesDownloadTest()
        manifest = {'version': 5, 'binaries': list(BINARIES),
                    'files': {name: {'sha256': 'a' * 64, 'size': 1} for name in release_file_names()}}
        manifest['files']['Cargo.lock']['size'] = MAX_LOCK_BYTES + 1
        self.assertEqual(len(downloader.download(manifest, 'PREVIOUS_RELEASE_OCI_LOCK_LIMIT')), 2)
        manifest['version'] = 4
        manifest['files'].pop(OCI_PAYLOAD_NOTICES)
        self.assertEqual(len(downloader.download(manifest)), 3)


if __name__ == '__main__':
    unittest.main()
