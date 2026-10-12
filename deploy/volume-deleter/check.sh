#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
"${CLUSTER_PYTHON:-python3}" - <<'PY'
import pathlib, sys, yaml
sys.path.insert(0, 'deploy/cluster')
from render import validate_schema
objects=[]
for name in ['rbac.yaml', 'workload.yaml']:
    objects.extend(o for o in yaml.safe_load_all((pathlib.Path('deploy/volume-deleter') / name).read_text()) if o)
validate_schema(objects, pathlib.Path('.local/cluster-artifacts'))
assert len(objects)==7
print('Validated 7 volume-controller resources against the locked Kubernetes schema; no cluster contacted.')
PY
"${CLUSTER_PYTHON:-python3}" -m unittest discover -s deploy/volume-deleter/tests -v
"${CLUSTER_PYTHON:-python3}" deploy/volume-deleter/schema_check.py
