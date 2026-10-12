#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${IDENTITY_PROXY_IMAGE:?Set the exact locally built image reference or reviewed registry digest}"
identity_python="${IDENTITY_PYTHON:-python3}"
identity_image_test="$(mktemp -d "${TMPDIR:-/tmp}/sandbox-proxy-image.XXXXXX")"
trap 'rm -rf "$identity_image_test"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=login.example.com \
  -addext 'subjectAltName=DNS:login.example.com,DNS:identity-admin.internal.example.com' \
  -keyout "$identity_image_test/key.pem" -out "$identity_image_test/backend-ca.pem" >/dev/null 2>&1
cat "$identity_image_test/backend-ca.pem" "$identity_image_test/key.pem" > "$identity_image_test/frontend.pem"
"$identity_python" - "$identity_image_test" <<'PY'
from pathlib import Path
import json,sys
sys.path.insert(0,'deploy/identity')
from proxy import configuration
s=json.load(open('deploy/identity/settings.example.json'))
(Path(sys.argv[1])/'haproxy.cfg').write_text(configuration(s))
PY
# These are disposable public test keys, not production credential files.
chmod 755 "$identity_image_test"
chmod 644 "$identity_image_test"/*
docker run --rm --pull=never --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --network=none --user=10001:10001 \
  --mount "type=bind,src=$identity_image_test,dst=/run/identity-tls,readonly" \
  "$IDENTITY_PROXY_IMAGE" -c -f /run/identity-tls/haproxy.cfg
docker run --rm --pull=never --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --network=none --user=10001:10001 "$IDENTITY_PROXY_IMAGE" -v
