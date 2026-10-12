#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
identity_python="${IDENTITY_PYTHON:-python3}"
identity_test_dir="$(mktemp -d "${TMPDIR:-/tmp}/sandbox-identity-live.XXXXXX")"
identity_test_container="sandbox-identity-test-$(openssl rand -hex 6)"
cleanup_identity() {
  docker rm -f "$identity_test_container" >/dev/null 2>&1 || true
  rm -rf "$identity_test_dir"
}
trap cleanup_identity EXIT
umask 077
openssl rand -hex 32 > "$identity_test_dir/password"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
  -addext 'subjectAltName=DNS:localhost' -keyout "$identity_test_dir/tls.key" \
  -out "$identity_test_dir/tls.crt" >/dev/null 2>&1
"$identity_python" - "$identity_test_dir" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]); password=(p/'password').read_text().strip()
(p/'password').write_text(password)
(p/'container.env').write_text('KC_BOOTSTRAP_ADMIN_USERNAME=isolated-test-bootstrap\nKC_BOOTSTRAP_ADMIN_PASSWORD='+password+'\n')
PY
# Test-only self-signed key, readable by the image UID inside a private mounted directory.
chmod 755 "$identity_test_dir"
chmod 644 "$identity_test_dir/tls.crt" "$identity_test_dir/tls.key"
identity_image="$("$identity_python" -c 'import json; print(json.load(open("deploy/identity/versions.lock.json"))["keycloak_image"])')"
identity_hostname=https://localhost:58443
identity_admin_hostname=https://localhost:58443
if [[ "${IDENTITY_ADMIN_CHAIN:-false}" == true ]]; then
  : "${HAPROXY_BIN:?Set an absolute path to the reviewed HAProxy 3.2.25 binary}"
  identity_hostname=https://localhost:58445
  identity_admin_hostname=https://localhost:58446
fi
docker run --pull=never --rm -d --name "$identity_test_container" \
  --env-file "$identity_test_dir/container.env" \
  -p 127.0.0.1:58443:8443 \
  --mount "type=bind,src=$identity_test_dir/tls.crt,dst=/tmp/identity-test.crt,readonly" \
  --mount "type=bind,src=$identity_test_dir/tls.key,dst=/tmp/identity-test.key,readonly" \
  "$identity_image" start-dev --http-enabled=false \
  --https-certificate-file=/tmp/identity-test.crt --https-certificate-key-file=/tmp/identity-test.key \
  --hostname="$identity_hostname" --hostname-admin="$identity_admin_hostname" >/dev/null
if [[ "${IDENTITY_ADMIN_CHAIN:-false}" == true ]]; then
  "$identity_python" deploy/identity/tests/live_admin.py "$identity_test_dir" "$HAPROXY_BIN"
else
  "$identity_python" deploy/identity/tests/live_realm.py "$identity_test_dir"
fi
