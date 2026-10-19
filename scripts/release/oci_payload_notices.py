"""Complete selected MIT notices for the fixed OCI payload decoding crates."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tarfile
import tomllib

from common import dump, image_digest, load, require, safe_child

MAX_BYTES = 64 * 1024
MAX_LOCK_BYTES = 4 * 1024 * 1024
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
FIXED = {
    'schema_version': 1,
    'crates': {
        'flate2': {
            'version': '1.1.10', 'license_expression': 'MIT OR Apache-2.0',
            'selected_license': 'MIT', 'license_source_file': 'LICENSE-MIT',
            'source': 'https://static.crates.io/crates/flate2/flate2-1.1.10.crate',
            'crate_archive_sha256': '6e634e2e0ebac1ee034020da1ca582e17ffe4e0f5e985823721e168928136dcb',
            'license_sha256': '025436edff4cfcdde17a5811fdea78892d8482efd1abdec5a17872d07a4f2112',
        },
        'crc32fast': {
            'version': '1.5.2', 'license_expression': 'MIT OR Apache-2.0',
            'selected_license': 'MIT', 'license_source_file': 'LICENSE-MIT',
            'source': 'https://static.crates.io/crates/crc32fast/crc32fast-1.5.2.crate',
            'crate_archive_sha256': '01a7799fd6b852db0e61728dde9a204c423b44d689dbd432522543614b490e78',
            'license_sha256': '61d383b05b87d78f94d2937e2580cce47226d17823c0430fbcad09596537efcf',
        },
        'miniz_oxide': {
            'version': '0.9.1', 'license_expression': 'MIT OR Zlib OR Apache-2.0',
            'selected_license': 'MIT', 'license_source_file': 'LICENSE-MIT.md',
            'source': 'https://static.crates.io/crates/miniz_oxide/miniz_oxide-0.9.1.crate',
            'crate_archive_sha256': 'b63fbc4a50860e98e7b2aa7804ded1db5cbc3aff9193adaff57a6931bf7c4b4c',
            'license_sha256': '799e9ca9d179295ef372f25d3769cdda7d25bb2668add6a6a1e22d1e4c678b8d',
        },
        'adler2': {
            'version': '2.0.1', 'license_expression': '0BSD OR MIT OR Apache-2.0',
            'selected_license': 'MIT', 'license_source_file': 'LICENSE-MIT',
            'source': 'https://static.crates.io/crates/adler2/adler2-2.0.1.crate',
            'crate_archive_sha256': '320119579fcad9c21884f5c4861d16174d0e06250625266f50fe6898340abefa',
            'license_sha256': '23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3',
        },
        'simd-adler32': {
            'version': '0.3.10', 'license_expression': 'MIT',
            'selected_license': 'MIT', 'license_source_file': 'LICENSE.md',
            'source': 'https://static.crates.io/crates/simd-adler32/simd-adler32-0.3.10.crate',
            'crate_archive_sha256': '3a219298ac11a56ea9a6d2120044824d6f01aeb034955e7af7bc16858527deea',
            'license_sha256': '42a35170233e83e18856792e748de4c1ce4a63b2afce9a370c89ef3fe23f9f2d',
        },
    },
}


def validate(value, cargo_lock):
    # Independent of checkout/registry availability: authenticated release
    # consumers still verify the exact reviewed provenance and complete text.
    require(isinstance(value, dict) and set(value) == set(FIXED) | {'licenses', 'cargo_lock_sha256'}
            and type(value.get('schema_version')) is int
            and all(value.get(key) == expected for key, expected in FIXED.items()),
            'OCI_PAYLOAD_NOTICES_PROVENANCE')
    require(isinstance(cargo_lock, bytes) and len(cargo_lock) <= MAX_LOCK_BYTES,
            'OCI_PAYLOAD_NOTICES_LOCK_LIMIT')
    require(value['cargo_lock_sha256'] == hashlib.sha256(cargo_lock).hexdigest(),
            'OCI_PAYLOAD_NOTICES_LOCK_HASH')
    packages = tomllib.loads(cargo_lock.decode('utf8')).get('package', [])
    require(isinstance(packages, list), 'OCI_PAYLOAD_NOTICES_LOCK_COVERAGE')
    for name, record in FIXED['crates'].items():
        matches = [package for package in packages if package.get('name') == name]
        require(len(matches) == 1 and all(matches[0].get(key) == expected for key, expected in {
            'version': record['version'], 'source': REGISTRY,
            'checksum': record['crate_archive_sha256'],
        }.items()), 'OCI_PAYLOAD_NOTICES_LOCK_COVERAGE')
    licenses = value['licenses']
    require(isinstance(licenses, dict) and set(licenses) == set(FIXED['crates']),
            'OCI_PAYLOAD_NOTICES_LICENSES')
    for name, record in FIXED['crates'].items():
        text = licenses[name]
        require(isinstance(text, str) and len(text.encode('utf8')) <= MAX_BYTES
                and hashlib.sha256(text.encode('utf8')).hexdigest() == record['license_sha256'],
                'OCI_PAYLOAD_NOTICES_LICENSE_BYTES')
    require(len(json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode('utf8')) <= MAX_BYTES,
            'OCI_PAYLOAD_NOTICES_LIMIT')
    return value


def _bounded_file(path, limit, code):
    # The read itself is bounded. A size check before an unbounded read would
    # still permit allocation after file growth/replacement. Nonblocking open
    # and the opened object's type also reject a swapped FIFO or symlink.
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as source:
            require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), 'ARTIFACT_MISSING')
            data = source.read(limit + 1)
    except OSError:
        raise ValueError('ARTIFACT_MISSING') from None
    require(len(data) <= limit, code)
    return data


def read_cargo_lock(directory):
    return _bounded_file(safe_child(directory, 'Cargo.lock'), MAX_LOCK_BYTES,
                         'OCI_PAYLOAD_NOTICES_LOCK_LIMIT')


def create(source):
    source = Path(source)
    cargo_lock = read_cargo_lock(source)
    value = copy.deepcopy(FIXED)
    value['cargo_lock_sha256'] = hashlib.sha256(cargo_lock).hexdigest()
    value['licenses'] = {}
    for name, record in FIXED['crates'].items():
        path = safe_child(source / 'licenses/oci-payload', name + '-' + record['version'] + '-MIT.txt')
        data = _bounded_file(path, MAX_BYTES, 'OCI_PAYLOAD_LICENSE_HASH')
        require(hashlib.sha256(data).hexdigest() == record['license_sha256'], 'OCI_PAYLOAD_LICENSE_HASH')
        value['licenses'][name] = data.decode('utf8')
    return validate(value, cargo_lock)


def validate_distribution(files, prefix, value):
    expected = {prefix + '/oci-payload-notices.json':
                (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('utf8')}
    expected.update({prefix + '/oci-payload/' + name + '-' + record['version'] + '-MIT.txt':
                     value['licenses'][name].encode('utf8')
                     for name, record in FIXED['crates'].items()})
    require(all(files.get(name) == data for name, data in expected.items()),
            'OCI_PAYLOAD_DISTRIBUTION')


def validate_image(directory, component, value):
    """Read the six fixed notice files from authenticated runtime OCI layers."""
    require(component in ('service', 'runner'), 'OCI_PAYLOAD_IMAGE_COMPONENT')
    image_digest(directory, component)
    index = load(directory / 'index.json')
    manifest = load(directory / 'blobs/sha256' / index['manifests'][0]['digest'][7:])
    prefix = 'usr/share/sandbox-platform/licenses'
    selected = {prefix + '/oci-payload-notices.json'} | {
        prefix + '/oci-payload/' + name + '-' + record['version'] + '-MIT.txt'
        for name, record in FIXED['crates'].items()}
    files, count, total = {}, 0, 0
    for layer in manifest['layers']:
        require(layer['mediaType'] in ('application/vnd.oci.image.layer.v1.tar',
                                      'application/vnd.oci.image.layer.v1.tar+gzip'),
                'OCI_PAYLOAD_IMAGE_LAYER_FORMAT')
        with tarfile.open(directory / 'blobs/sha256' / layer['digest'][7:], 'r|*') as archive:
            seen = set()
            for member in archive:
                name = member.name.removeprefix('./').rstrip('/')
                if name in ('', '.') and member.isdir():
                    continue
                require(name and not name.startswith('/') and all(part not in ('', '.', '..')
                        for part in name.split('/')) and name not in seen, 'OCI_PAYLOAD_IMAGE_PATH')
                seen.add(name)
                count += 1
                total += member.size
                require(count <= 200000 and 0 <= member.size <= 1024**3 and total <= 2 * 1024**3,
                        'OCI_PAYLOAD_IMAGE_LAYER_BOUND')
                base = name.rsplit('/', 1)[-1]
                if base.startswith('.wh.'):
                    parent = name.rsplit('/', 1)[0] if '/' in name else ''
                    affected = parent if base == '.wh..wh..opq' else (parent + '/' if parent else '') + base[4:]
                    require(affected and not any(path == affected or path.startswith(affected + '/')
                                                for path in selected), 'OCI_PAYLOAD_IMAGE_WHITEOUT')
                if any(path.startswith(name + '/') for path in selected):
                    require(member.isdir(), 'OCI_PAYLOAD_IMAGE_ANCESTOR_LINK')
                if name not in selected:
                    continue
                require(member.isfile() and member.uid == 0 and not member.mode & 0o022
                        and member.size <= MAX_BYTES, 'OCI_PAYLOAD_IMAGE_FILE')
                stream = archive.extractfile(member)
                require(stream is not None, 'OCI_PAYLOAD_IMAGE_READ')
                data = stream.read(member.size + 1)
                require(len(data) == member.size, 'OCI_PAYLOAD_IMAGE_FILE_SIZE')
                files[name] = data
    validate_distribution(files, prefix, value)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    dump(args.output, create(args.source))
