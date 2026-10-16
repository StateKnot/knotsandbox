"""Complete notices for the fixed containerd and Google protobuf inputs."""
import argparse
import copy
import hashlib
import json
from pathlib import Path

from common import dump, require, safe_child, sha

MAX_BYTES = 64 * 1024
FIXED = {
    'schema_version': 1,
    'protocols': {
        'containerd': {
            'version': 'v2.3.5',
            'source': 'https://github.com/containerd/containerd/tree/v2.3.5',
            'copyright': 'Copyright The containerd Authors.',
            'license': 'Apache-2.0',
            'inputs_sha256': {
                'api/services/images/v1/images.proto': 'f7943198b308917555040e524251f06d9262b917f856a771159253c51635b056',
                'api/services/content/v1/content.proto': '70aadb447ff3157da276afecc355a5a58ef2e322eb7530d5c2868734d626eea8',
                'api/types/descriptor.proto': 'f98bec409b5e535e2a8d81dacc549180e1dadb31bd6ac46f7aedc6ab0020e447',
            },
            'derived_messages': [
                'src/nodeguard/generated/containerd.services.images.v1.rs',
                'src/nodeguard/generated/containerd.services.content.v1.rs',
                'src/nodeguard/generated/containerd.types.rs',
            ],
        },
        'protobuf-well-known': {
            'version': 'protoc-bin-vendored-3.2.0',
            'source': 'https://crates.io/crates/protoc-bin-vendored/3.2.0',
            'copyright': 'Copyright 2008 Google Inc. All rights reserved.',
            'license': 'BSD-3-Clause',
            'inputs_sha256': {
                'include/google/protobuf/empty.proto': 'ecef3d54cc9e079673b9816c67bac770f7f3bf6dada2d4596ba69d71daa971e6',
                'include/google/protobuf/field_mask.proto': '17b0f342cc3a262e317d56884f3f575afbfac512ad0579349cc7450e41f26891',
                'include/google/protobuf/timestamp.proto': '14052c6042c1dd2d0b50245f2812eaab6eaf82db0b6e8ce483eae527f73b6ee8',
            },
            'derived_messages': ['src/nodeguard/generated/google.protobuf.rs'],
        },
    },
}
VENDORS = {
    'containerd': 'vendor/containerd/v2.3.5',
    'protobuf-well-known': 'vendor/protobuf/protoc-bin-vendored-3.2.0',
}
LICENSES = {
    'containerd': '4bbe3b885e8cd1907ab4cf9a41e862e74e24b5422297a4f2fe524e6a30ada2b4',
    'protobuf-well-known': '87a95acbb870e296243a71b67631984702e6e55e9057deaf01018f0bad4ca4e0',
}


def validate(value):
    # Validation is source-independent so an authenticated historical v4 can
    # still be verified after checkout inputs evolve. No text omission or
    # replacement is authorized by merely recomputing the release file hash.
    require(isinstance(value, dict) and set(value) == set(FIXED) | {'licenses'}
            and type(value.get('schema_version')) is int
            and all(value.get(key) == expected for key, expected in FIXED.items()),
            'NATIVE_PROTOCOL_NOTICES_PROVENANCE')
    licenses = value['licenses']
    require(isinstance(licenses, dict) and set(licenses) == set(LICENSES),
            'NATIVE_PROTOCOL_NOTICES_LICENSES')
    for name, digest in LICENSES.items():
        text = licenses[name]
        require(isinstance(text, str) and len(text.encode('utf8')) <= MAX_BYTES
                and hashlib.sha256(text.encode('utf8')).hexdigest() == digest,
                'NATIVE_PROTOCOL_NOTICES_LICENSE_BYTES')
    require(len(json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode('utf8')) <= MAX_BYTES,
            'NATIVE_PROTOCOL_NOTICES_LIMIT')
    return value


def create(source):
    value = copy.deepcopy(FIXED)
    value['licenses'] = {}
    for name, relative in VENDORS.items():
        vendor = Path(source) / relative
        for filename, digest in FIXED['protocols'][name]['inputs_sha256'].items():
            path = vendor / filename
            require(sha(safe_child(path.parent, path.name)) == digest,
                    'NATIVE_PROTOCOL_SOURCE_HASH')
        license_path = safe_child(vendor, 'LICENSE')
        require(sha(license_path) == LICENSES[name], 'NATIVE_PROTOCOL_LICENSE_HASH')
        value['licenses'][name] = license_path.read_bytes().decode('utf8')
    return validate(value)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    dump(args.output, create(args.source))
