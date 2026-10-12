#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
cluster_python="${CLUSTER_PYTHON:-python3}"
"$cluster_python" -c 'import sys; assert sys.version_info >= (3, 12), "Python 3.12+ required"'
"$cluster_python" deploy/cluster/cluster.py prepare
"$cluster_python" -m unittest discover -s deploy/cluster/tests -v
cluster_check_dir="$(mktemp -d "${TMPDIR:-/tmp}/sandbox-cluster-check.XXXXXX")"
trap 'rm -rf "$cluster_check_dir"' EXIT
"$cluster_python" - "$cluster_check_dir" <<'PY'
import json, pathlib, sys
sys.path.insert(0, 'deploy/cluster/tests')
from test_cluster import fixture
from cluster import generate
path = pathlib.Path(sys.argv[1])
tf, settings = fixture()
(path / 'terraform.json').write_text(json.dumps(tf))
(path / 'settings.json').write_text(json.dumps(settings))
generate(path / 'terraform.json', path / 'settings.json', path / 'deployment')
PY
"$cluster_python" deploy/cluster/cluster.py check --deployment "$cluster_check_dir/deployment"
