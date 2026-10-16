#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
python3 - <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
proto=Path('vendor/cri/v0.36.4/api.proto')
assert hashlib.sha256(proto.read_bytes()).hexdigest() == '6d130c2651d335bfc755d25efc63072a1cd1eba3591ead6422dc0a27f20167f3'
generated=Path('src/nodeguard/generated/runtime.v1.rs')
before=generated.read_bytes()
subprocess.run(['cargo','run','--locked','--offline','--manifest-path','tools/cri-codegen/Cargo.toml'],check=True)
assert generated.read_bytes() == before, 'generated CRI differs from the committed input; inspect and commit the regenerated file'
native = Path('vendor/containerd/v2.3.5')
for name, digest in {
    'api/services/images/v1/images.proto': 'f7943198b308917555040e524251f06d9262b917f856a771159253c51635b056',
    'api/services/content/v1/content.proto': '70aadb447ff3157da276afecc355a5a58ef2e322eb7530d5c2868734d626eea8',
    'api/types/descriptor.proto': 'f98bec409b5e535e2a8d81dacc549180e1dadb31bd6ac46f7aedc6ab0020e447',
    'api/services/snapshots/v1/snapshots.proto': '6e23ec19b971e1088f3984b7a07ee4238d6ad56b85173750c38b0c911803bc23',
    'api/types/mount.proto': 'c7a31fa848f002cead05a23adfdd9e29a459cd01ae573b7b61b060b3056754d7',
    'LICENSE': '4bbe3b885e8cd1907ab4cf9a41e862e74e24b5422297a4f2fe524e6a30ada2b4',
}.items():
    assert hashlib.sha256((native / name).read_bytes()).hexdigest() == digest, name
well_known = Path('vendor/protobuf/protoc-bin-vendored-3.2.0')
known_inputs = {
    'include/google/protobuf/empty.proto': 'ecef3d54cc9e079673b9816c67bac770f7f3bf6dada2d4596ba69d71daa971e6',
    'include/google/protobuf/field_mask.proto': '17b0f342cc3a262e317d56884f3f575afbfac512ad0579349cc7450e41f26891',
    'include/google/protobuf/timestamp.proto': '14052c6042c1dd2d0b50245f2812eaab6eaf82db0b6e8ce483eae527f73b6ee8',
    'LICENSE': '87a95acbb870e296243a71b67631984702e6e55e9057deaf01018f0bad4ca4e0',
}
assert json.loads((well_known / 'sources.sha256.json').read_text()) == known_inputs
for name, digest in known_inputs.items():
    assert hashlib.sha256((well_known / name).read_bytes()).hexdigest() == digest, name
paths = [Path('src/nodeguard/generated') / name for name in (
    'containerd.services.images.v1.rs', 'containerd.services.content.v1.rs',
    'containerd.types.rs', 'google.protobuf.rs',
    'containerd.services.snapshots.v1.rs',
)]
before_native = {path: path.read_bytes() for path in paths}
subprocess.run(['cargo','run','--locked','--offline','--manifest-path','tools/cri-codegen/Cargo.toml', '--', '--containerd'],check=True)
assert all(path.read_bytes() == original for path, original in before_native.items()), 'generated native metadata protocol differs from the committed inputs'
PY
