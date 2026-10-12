#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
termination_python="${CLUSTER_PYTHON:-$PWD/.local/cluster-venv/bin/python}"
"$termination_python" -m unittest discover -s deploy/termination/tests -v
"$termination_python" deploy/termination/schema_check.py
"$termination_python" -m py_compile deploy/termination/render.py deploy/termination/prepare.py deploy/termination/schema_check.py deploy/termination/tests/test_render.py deploy/termination/tests/config_fixture.py
