"""Owned, normally migrated PostgreSQL for the native node-image HTTP chain.

The caller runs the real Rust fixture; this module never replays schema SQL.
Only the returned child environment contains credentials. Receipts are public.
"""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
import urllib.parse
import uuid

ROOT = Path(__file__).resolve().parents[1]
IDENTITY_KEYS = ("SANDBOX_OIDC_ISSUER", "SANDBOX_OIDC_JWKS_URL",
                 "SANDBOX_MACHINE_CLIENT_ID", "SANDBOX_MACHINE_CLIENT_SECRET")


def _identity(path):
    if path is None and all(os.environ.get(key) for key in IDENTITY_KEYS):
        values = {key: os.environ[key] for key in IDENTITY_KEYS}
    else:
        path = Path(path) if path is not None else ROOT / ".local/dev.env"
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os.getuid() or info.st_size > 65536):
                raise RuntimeError("identity input must be an owned private bounded regular file")
            raw = source.read(65537)
        if len(raw) > 65536:
            raise RuntimeError("identity input exceeds its fixed bound")
        values = {}
        for line in raw.decode("utf-8").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            key, separator, value = line.partition("=")
            if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
                raise RuntimeError("identity input requires simple key=value assignments")
            if key in IDENTITY_KEYS:
                if key in values:
                    raise RuntimeError("identity input contains a duplicate selected assignment")
                values[key] = value
    if (set(values) != set(IDENTITY_KEYS) or sum(len(value.encode("utf-8")) for value in values.values()) > 65536
            or any(not value or value != value.strip() or value[:1] in "\"'"
                   or any(ord(c) < 32 or ord(c) == 127 for c in value)
                   for value in values.values())):
        raise RuntimeError("four nonempty literal identity assignments are required")
    return values


@contextmanager
def owned_postgres(evidence_dir: Path, identity_env_file: Path | None = None):
    """Yield ``(child_environment, mutable_public_receipt)``; always verify cleanup."""
    spec = importlib.util.spec_from_file_location("node_image_chain_fixture", ROOT / "scripts/test-automation.py")
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    evidence = Path(evidence_dir).resolve() / "postgres"
    fixture.private_directory(evidence)
    receipt = {"postgresImage": None, "ownedContainerName": None, "schemaLedger": None,
               "migrationLedgerMatchesSources": False, "cleanupConfirmed": False, "diagnostics": []}
    docker = environment = container = command = owner_env = None
    yielded = False
    owner = uuid.uuid4().hex
    name = "sandbox-node-image-chain-" + owner
    receipt.update(ownedContainerName=name, fixtureOwner=owner)

    def invoke(arguments, *, env=None, text=None, timeout=30):
        try:
            return fixture.invoke(arguments, env=env, text=text, timeout=timeout)
        except Exception:
            raise RuntimeError("node-image-chain fixture subprocess failed; output withheld") from None

    try:
        identity = _identity(identity_env_file)
        expected = [{"version": int(path.name.split("_", 1)[0]), "success": True,
                     "sha384": hashlib.sha384(path.read_bytes()).hexdigest()}
                    for path in sorted((ROOT / "migrations").glob("*.sql"))]
        if [entry["version"] for entry in expected] != [*range(1, 38), *range(39, 49)]:
            raise RuntimeError("chain fixture requires exact formal migrations 1..37+39..48")
        image = fixture.approved_image()
        receipt["postgresImage"] = image
        docker, environment = fixture.local_docker()
        tls, ca = fixture.fixture_tls(evidence)
        admin = "sandbox_node_image_fixture_admin"
        start_env = dict(environment, POSTGRES_PASSWORD=secrets.token_hex(32))
        created = invoke([
            *docker, "run", "--detach", "--name", name,
            "--label", "com.sandbox.fixture=node-image-chain", "--label", "com.sandbox.fixture.owner=" + owner,
            "--publish", "127.0.0.1::5432", "--memory", "1g", "--cpus", "2", "--pids-limit", "256",
            "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,size=1g",
            "--tmpfs", "/sandbox-tls:rw,noexec,nosuid,size=1m",
            "--mount", "type=bind,src=" + str(tls) + ",dst=/fixture-tls,readonly",
            "--env", "POSTGRES_PASSWORD", "--env", "POSTGRES_USER=" + admin,
            "--env", "POSTGRES_DB=postgres", image, "bash", "-ceu",
            "cp /fixture-tls/server.crt /fixture-tls/server.key /sandbox-tls/; "
            "chown postgres:postgres /sandbox-tls/server.*; chmod 0600 /sandbox-tls/server.key; "
            "exec docker-entrypoint.sh postgres -c ssl=on "
            "-c ssl_cert_file=/sandbox-tls/server.crt -c ssl_key_file=/sandbox-tls/server.key",
        ], env=start_env, timeout=60)
        if not re.fullmatch(r"[0-9a-f]{64}", created):
            raise RuntimeError("unexpected owned PostgreSQL container identity")
        container = created
        receipt["ownedContainerId"] = container
        binding = re.fullmatch(r"127\.0\.0\.1:([0-9]+)", invoke([*docker, "port", container, "5432/tcp"], env=environment))
        if binding is None or not 1 <= int(binding[1]) <= 65535:
            raise RuntimeError("owned PostgreSQL must publish only an IPv4 loopback port")
        psql_env = dict(start_env, PGHOST="127.0.0.1", PGPORT="5432", PGUSER=admin,
                        PGPASSWORD=start_env["POSTGRES_PASSWORD"], PGDATABASE="postgres")
        command = [*docker, "exec", "-i"]
        for key in ("PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE"):
            command += ["--env", key]
        command += [container, "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"]
        deadline = time.monotonic() + 60
        while True:
            try:
                invoke(command, env=psql_env, text="SELECT 1;", timeout=5)
                break
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("owned PostgreSQL exceeded its existing startup window") from None
                time.sleep(0.2)
        if (len(fixture.ROLES) != 10 or len(set(fixture.ROLES.values())) != 10
                or any(not re.fullmatch(r"sandbox_[a-z_]+", role) for role in fixture.ROLES.values())):
            raise RuntimeError("exactly ten ordinary fixture roles are required")
        passwords = {role: secrets.token_hex(32) for role in fixture.ROLES.values()}
        database = "sandbox_node_images_" + uuid.uuid4().hex + "_test"
        sql = ["SET password_encryption='scram-sha-256';"]
        for role, password in passwords.items():
            sql.append("CREATE ROLE " + role + " LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS "
                       "NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '" + password + "';")
        sql += ["CREATE DATABASE " + database + " OWNER sandbox_owner;",
                "REVOKE CONNECT ON DATABASE " + database + " FROM PUBLIC;",
                "GRANT CONNECT ON DATABASE " + database + " TO " + ",".join(passwords) + ";"]
        invoke(command, env=psql_env, text="\n".join(sql), timeout=60)
        owner_env = dict(psql_env, PGDATABASE=database, PGUSER="sandbox_owner", PGPASSWORD=passwords["sandbox_owner"])
        child_env = {key: value for key, value in os.environ.items()
                     if not key.startswith(("SANDBOX_", "TEST_", "PG"))
                     and key not in {"RUST_MIN_STACK", "DATABASE_URL", "MIGRATION_DATABASE_URL"}}
        child_env.update(identity)
        query = urllib.parse.urlencode({"sslmode": "verify-full", "sslrootcert": str(ca)})
        for key, role in fixture.ROLES.items():
            child_env[key] = ("postgresql://" + role + ":" + passwords[role] + "@127.0.0.1:"
                              + binding[1] + "/" + database + "?" + query)
        yielded = True
        yield child_env, receipt
    except Exception:
        if yielded:
            raise
        raise RuntimeError("node-image-chain PostgreSQL fixture setup failed; diagnostics are redacted") from None
    finally:
        primary_error = sys.exc_info()[0] is not None
        if command is not None and owner_env is not None:
            try:
                exists = invoke(command, env=owner_env, text="SELECT to_regclass('public._sqlx_migrations') IS NOT NULL;")
                if exists != "t":
                    raise RuntimeError("normal SQLx ledger was not installed")
                ledger = json.loads(invoke(command, env=owner_env, text=(
                    "SELECT coalesce(jsonb_agg(jsonb_build_object('version',version,'success',success,"
                    "'sha384',encode(substring(checksum FOR 49),'hex')) ORDER BY version),'[]'::jsonb) "
                    "FROM (SELECT version,success,checksum FROM _sqlx_migrations ORDER BY version LIMIT 48) bounded;")))
                receipt["schemaLedger"] = ledger
                receipt["migrationLedgerMatchesSources"] = ledger == expected
                if ledger != expected:
                    receipt["diagnostics"].append("NORMAL_MIGRATION_LEDGER_MISMATCH")
            except Exception:
                receipt["diagnostics"].append("NORMAL_MIGRATION_LEDGER_UNAVAILABLE")
        if docker is not None:
            try:
                ids = invoke([*docker, "ps", "-aq", "--no-trunc", "--filter", "name=^/" + name + "$"], env=environment)
                if ids:
                    if not re.fullmatch(r"[0-9a-f]{64}", ids) or (container is not None and ids != container):
                        raise RuntimeError("owned fixture name no longer matches its exact identity")
                    inspected = json.loads(invoke([*docker, "inspect", "--format", "{{json .}}", ids], env=environment))
                    labels = inspected.get("Config", {}).get("Labels", {})
                    if (inspected.get("Id") != ids or inspected.get("Name") != "/" + name
                            or labels.get("com.sandbox.fixture") != "node-image-chain"
                            or labels.get("com.sandbox.fixture.owner") != owner):
                        raise RuntimeError("owned fixture labels no longer match")
                    invoke([*docker, "rm", "--force", ids], env=environment)
                absent = not invoke([*docker, "ps", "-aq", "--no-trunc", "--filter", "name=^/" + name + "$"], env=environment)
                if container is not None:
                    absent = absent and not invoke([*docker, "ps", "-aq", "--no-trunc", "--filter", "id=" + container], env=environment)
                receipt["cleanupConfirmed"] = absent
            except Exception:
                receipt["diagnostics"].append("OWNED_POSTGRES_CLEANUP_UNCONFIRMED")
        try:
            fixture.private_json(evidence / "fixture-diagnostic.json", receipt)
        except Exception:
            receipt["diagnostics"].append("FIXTURE_DIAGNOSTIC_WRITE_FAILED")
            if not primary_error:
                raise RuntimeError("node-image-chain fixture could not preserve its diagnostic") from None
        if not primary_error and (not receipt["migrationLedgerMatchesSources"] or not receipt["cleanupConfirmed"]):
            raise RuntimeError("node-image-chain fixture ledger or cleanup failed; see fixture-diagnostic.json")
