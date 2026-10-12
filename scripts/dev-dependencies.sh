#!/usr/bin/env bash
# Manage loopback-only development dependencies. Credentials never go to stdout.
set -euo pipefail
umask 077

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dev_dir="$repo_dir/.local"
env_file="$dev_dir/dev.env"

init_environment() {
  mkdir -p "$dev_dir"
  chmod 700 "$dev_dir"
  if [[ -e "$env_file" ]]; then
    [[ -f "$env_file" && ! -L "$env_file" ]] || {
      printf '%s\n' 'Refusing a non-regular development environment file.' >&2
      exit 1
    }
    chmod 600 "$env_file"
    ensure_role_environment
    return
  fi
  python3 - "$env_file" <<'PY'
import os
import secrets
import sys

passwords = {key: secrets.token_hex(32) for key in (
    "SANDBOX_POSTGRES_ADMIN_PASSWORD", "SANDBOX_DB_PASSWORD", "SANDBOX_MIGRATION_DB_PASSWORD",
    "SANDBOX_KEYCLOAK_DB_PASSWORD", "SANDBOX_KEYCLOAK_ADMIN_PASSWORD",
    "SANDBOX_MACHINE_CLIENT_SECRET",
)}
values = {
    **passwords,
    "SANDBOX_PG_PORT": "55432",
    "SANDBOX_KEYCLOAK_PORT": "58080",
    "DATABASE_URL": f"postgres://sandbox_app:{passwords['SANDBOX_DB_PASSWORD']}@127.0.0.1:55432/sandbox_dev",
    "SANDBOX_DATABASE_URL": f"postgres://sandbox_app:{passwords['SANDBOX_DB_PASSWORD']}@127.0.0.1:55432/sandbox_dev",
    "MIGRATION_DATABASE_URL": f"postgres://sandbox_owner:{passwords['SANDBOX_MIGRATION_DB_PASSWORD']}@127.0.0.1:55432/sandbox_dev",
    "TEST_MIGRATION_DATABASE_URL": f"postgres://sandbox_owner:{passwords['SANDBOX_MIGRATION_DB_PASSWORD']}@127.0.0.1:55432/sandbox_test",
    "TEST_DATABASE_URL": f"postgres://sandbox_app:{passwords['SANDBOX_DB_PASSWORD']}@127.0.0.1:55432/sandbox_test",
    "SANDBOX_OIDC_ISSUER": "http://127.0.0.1:58080/realms/sandbox-dev",
    "SANDBOX_OIDC_JWKS_URL": "http://127.0.0.1:58080/realms/sandbox-dev/protocol/openid-connect/certs",
    "SANDBOX_OIDC_AUDIENCE": "sandbox-api",
    "SANDBOX_ALLOW_LOOPBACK_HTTP": "true",
    "SANDBOX_MACHINE_CLIENT_ID": "sandbox-dev-service",
}
# Exclusive creation prevents concurrent bootstrap processes from rotating credentials.
try:
    fd = os.open(sys.argv[1], os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
except FileExistsError:
    raise SystemExit(0)
with os.fdopen(fd, "w") as output:
    output.write("# Generated local development credentials only. Never deploy this file.\n")
    for key, value in values.items():
        output.write(f"{key}={value}\n")
PY
  ensure_role_environment
}

# Extend an existing development environment without rotating any credential.
ensure_role_environment() {
  python3 - "$env_file" <<'PY'
import fcntl
import base64
import json
import os
import re
import secrets
import sys
with open(sys.argv[1], 'r+', encoding='utf-8') as env:
    fcntl.flock(env, fcntl.LOCK_EX)
    values = dict(line.strip().split('=', 1) for line in env if line.strip() and not line.startswith('#'))
    port = values.get('SANDBOX_PG_PORT', '55432')
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise SystemExit('Invalid local PostgreSQL port.')
    additions = {}
    for role in ('WORKER', 'ADMISSION', 'GATEWAY', 'TERMINATION', 'FENCING', 'VOLUME_DELETER', 'BACKUP', 'RESTORE_GC'):
        key = f'SANDBOX_{role}_DB_PASSWORD'
        password = values.get(key)
        if password is None:
            password = secrets.token_hex(32)
            additions[key] = password
        if not re.fullmatch(r'[0-9a-f]{64}', password):
            raise SystemExit('Unexpected development role credential format; no values changed.')
        for url_key, database in ((f'SANDBOX_{role}_DATABASE_URL', 'sandbox_dev'), (f'TEST_{role}_DATABASE_URL', 'sandbox_test')):
            if url_key not in values:
                additions[url_key] = f'postgres://sandbox_{role.lower()}:{password}@127.0.0.1:{port}/{database}'
    if 'SANDBOX_CURSOR_SIGNING_KEY_FILE' not in values:
        key_file = os.path.join(os.path.dirname(os.path.abspath(sys.argv[1])), 'cursor-signing-keys.json')
        try:
            key_fd = os.open(key_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            # Preserve a key created by a previous interrupted initialization.
            if not os.path.isfile(key_file) or os.path.islink(key_file):
                raise SystemExit('Refusing an unsafe development cursor key file.')
        else:
            with os.fdopen(key_fd, 'w') as target:
                json.dump({'active': {'kid': 'development-1', 'key_base64': base64.b64encode(secrets.token_bytes(32)).decode()}, 'previous': []}, target)
                target.flush()
                os.fsync(target.fileno())
        additions['SANDBOX_CURSOR_SIGNING_KEY_FILE'] = key_file
    env.seek(0, os.SEEK_END)
    for key, value in additions.items():
        env.write(f'{key}={value}\n')
    env.flush()
    os.fsync(env.fileno())
PY
}

provision_roles() {
  python3 "$repo_dir/scripts/dev-database-roles.py" "$repo_dir" "$env_file"
}

compose() {
  docker compose --project-directory "$repo_dir" --env-file "$env_file" \
    --file "$repo_dir/compose.yaml" "$@"
}

issue_token() {
  python3 - "$env_file" "$dev_dir/machine-token.json" <<'PY'
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

with open(sys.argv[1], encoding="utf-8") as source:
    values = dict(line.strip().split("=", 1) for line in source
                  if line.strip() and not line.startswith("#"))
issuer = values["SANDBOX_OIDC_ISSUER"]
parsed = urllib.parse.urlsplit(issuer)
if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.username or parsed.password:
    raise SystemExit("This helper only sends credentials to the loopback development issuer.")
body = urllib.parse.urlencode({
    "grant_type": "client_credentials",
    "client_id": values["SANDBOX_MACHINE_CLIENT_ID"],
    "client_secret": values["SANDBOX_MACHINE_CLIENT_SECRET"],
    "scope": "sandbox:access",
}).encode()
request = urllib.request.Request(issuer + "/protocol/openid-connect/token", data=body)
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        token_response = json.load(response)
except (urllib.error.HTTPError, urllib.error.URLError) as error:
    # Do not include a token response, credential, or request body in errors.
    raise SystemExit(f"Development token request failed: {type(error).__name__}") from None
token = token_response["access_token"]
parts = token.split(".")
if len(parts) != 3:
    raise SystemExit("Identity provider did not return a JWT access token.")
claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
audiences = claims.get("aud", [])
if isinstance(audiences, str):
    audiences = [audiences]
if not (claims.get("iss") == issuer and "sandbox-api" in audiences
        and "sandbox:access" in claims.get("scope", "").split()
        and claims.get("typ") == "Bearer" and claims.get("sub")
        and claims.get("azp") == values["SANDBOX_MACHINE_CLIENT_ID"]
        and 0 < claims.get("exp", 0) - claims.get("iat", 0) <= 300):
    raise SystemExit("Development token does not match the application's access-token contract.")
# This checks issuer output shape, not signature authenticity; the API performs JWT verification.
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as output:
    json.dump(token_response, output)
os.chmod(sys.argv[2], 0o600)
print("Development access token saved to .local/machine-token.json (not printed).")
PY
}

case "${1:-up}" in
  init)
    init_environment
    printf '%s\n' 'Development credentials ready in .local/dev.env (mode 0600).'
    ;;
  up)
    init_environment
    compose up --detach --wait --wait-timeout 300
    provision_roles
    printf '%s\n' 'Development PostgreSQL and Keycloak are healthy; ports are loopback-only.'
    ;;
  down|status)
    [[ -f "$env_file" ]] || { printf '%s\n' 'Run this script with init first.' >&2; exit 1; }
    if [[ "$1" == down ]]; then compose down; else compose ps; fi
    ;;
  token)
    [[ -f "$env_file" ]] || { printf '%s\n' 'Run this script with up first.' >&2; exit 1; }
    issue_token
    ;;
  roles)
    init_environment
    provision_roles
    ;;
  *)
    printf '%s\n' 'Usage: scripts/dev-dependencies.sh [init|up|down|status|token|roles]' >&2
    exit 2
    ;;
esac
