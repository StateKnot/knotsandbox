#!/usr/bin/env python3
"""Provision only this Compose project's local component logins.

Existing role passwords are never changed; role security flags are checked.
Credentials travel to psql over stdin, never shell interpolation or argv.
"""
from pathlib import Path
import re
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        raise SystemExit('Use scripts/dev-dependencies.sh roles.')
    root = Path(sys.argv[1]).resolve()
    env_path = Path(sys.argv[2]).resolve()
    if env_path != root / '.local/dev.env' or not (root / 'compose.yaml').is_file():
        raise SystemExit('Only the project-local development environment is supported.')
    values = dict(line.strip().split('=', 1) for line in env_path.read_text().splitlines()
                  if line.strip() and not line.startswith('#'))
    commands = ['BEGIN;']
    for role in ('worker', 'admission', 'gateway', 'termination', 'fencing', 'volume_deleter', 'backup', 'restore_gc'):
        password = values.get(f'SANDBOX_{role.upper()}_DB_PASSWORD', '')
        if not re.fullmatch('[0-9a-f]{64}', password):
            raise SystemExit('Missing or invalid generated development role credential.')
        # Both identifiers come from the fixed tuple above; only hex enters a literal.
        commands.extend([
            f"SELECT format('CREATE ROLE sandbox_{role} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD %L', '{password}') WHERE NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='sandbox_{role}')\\gexec",
            f"DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='sandbox_{role}' AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR NOT rolcanlogin)) OR EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member WHERE r.rolname='sandbox_{role}') THEN RAISE EXCEPTION 'Unsafe existing development service role'; END IF; END $$;",
            f'GRANT CONNECT ON DATABASE sandbox_dev TO sandbox_{role};',
            f'GRANT CONNECT ON DATABASE sandbox_test TO sandbox_{role};',
        ])
    commands.append('COMMIT;')
    result = subprocess.run([
        'docker', 'compose', '--project-directory', str(root), '--env-file', str(env_path),
        '--file', str(root / 'compose.yaml'), 'exec', '-T', 'postgres', 'psql',
        '--username', 'sandbox_dev_admin', '--dbname', 'postgres', '--quiet', '--set', 'ON_ERROR_STOP=1',
    ], input='\n'.join(commands) + '\n', text=True, capture_output=True)
    if result.returncode:
        # psql may print a failed SQL line containing the password: do not echo it.
        raise SystemExit('Local service role provisioning failed; no credentials or SQL were printed. Check the project Compose PostgreSQL health and role ownership.')
    print('Local component logins verified. Existing passwords preserved; schema grants are applied by migrations/tests.')


if __name__ == '__main__':
    main()
