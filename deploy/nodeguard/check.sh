#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
nodeguard_python="${CLUSTER_PYTHON:-python3}"
"$nodeguard_python" -m unittest discover -s deploy/nodeguard/tests -v
"$nodeguard_python" - <<'PY'
import sys
import tempfile
sys.path.insert(0, 'deploy/nodeguard/tests')
from test_nodeguard import NodeguardPlanTests
import nodeguard
import cluster
with tempfile.TemporaryDirectory(prefix='sandbox-nodeguard-check-') as temporary:
    path, settings = NodeguardPlanTests().create(temporary)
    # Deliberately synthetic plan for offline Ansible syntax validation. The
    # production CLI has no skip-file or skip-certificate-validation option.
    nodeguard.plan(path/'bootstrap',path/'guard.json',path/'guarded',check_files=False)
    playbook = nodeguard.playbook(cluster.DEFAULT_CACHE,path/'guarded')
    cluster.ansible(cluster.DEFAULT_CACHE,path/'guarded',playbook,['--syntax-check'])
PY
"$nodeguard_python" deploy/nodeguard/tests/check_containerd_template.py
