#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
python3 - <<'PY'
import hashlib
from pathlib import Path
import subprocess
proto=Path('vendor/cri/v0.36.4/api.proto')
assert hashlib.sha256(proto.read_bytes()).hexdigest() == '6d130c2651d335bfc755d25efc63072a1cd1eba3591ead6422dc0a27f20167f3'
generated=Path('src/nodeguard/generated/runtime.v1.rs')
before=generated.read_bytes()
subprocess.run(['cargo','run','--locked','--offline','--manifest-path','tools/cri-codegen/Cargo.toml'],check=True)
assert generated.read_bytes() == before, 'generated CRI differs from the committed input; inspect and commit the regenerated file'
PY
