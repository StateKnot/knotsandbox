#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
observability_python="${OBSERVABILITY_PYTHON:-python3}"
"$observability_python" -c 'import sys; assert sys.version_info >= (3,12)'
"$observability_python" -m unittest discover -s deploy/observability/tests -v
"$observability_python" deploy/observability/schema_check.py
"$observability_python" deploy/observability/check_image.py
"$observability_python" deploy/observability/check_rules.py
"$observability_python" deploy/observability/check_pipeline.py
