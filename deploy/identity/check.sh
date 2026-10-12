#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
identity_python="${IDENTITY_PYTHON:-python3}"
"$identity_python" -m unittest discover -s deploy/identity/tests -v
"$identity_python" deploy/identity/schema_check.py --cache "${CLUSTER_ARTIFACT_CACHE:-.local/cluster-artifacts}"
