#!/usr/bin/env python3
"""Run real automation acceptance in a fresh, loopback-only PostgreSQL server.

No existing database/role can be selected. Passwords stay in memory and child
environments/stdin; schema SQL and secret-bearing subprocess output are never
printed. This runner does not modify production startup or SQLx migration gates.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import time
import urllib.parse
import uuid

ROOT = Path(__file__).resolve().parents[1]
DATABASE = "sandbox_automation_pipeline_test"
PROCESS_DATABASE = "sandbox_automation_process_test"
ROLES = {
    "TEST_MIGRATION_DATABASE_URL": "sandbox_owner",
    "TEST_DATABASE_URL": "sandbox_app",
    "TEST_WORKER_DATABASE_URL": "sandbox_worker",
    "TEST_ADMISSION_DATABASE_URL": "sandbox_admission",
    "TEST_GATEWAY_DATABASE_URL": "sandbox_gateway",
    "TEST_TERMINATION_DATABASE_URL": "sandbox_termination",
    "TEST_FENCING_DATABASE_URL": "sandbox_fencing",
    "TEST_VOLUME_DELETER_DATABASE_URL": "sandbox_volume_deleter",
    "TEST_BACKUP_DATABASE_URL": "sandbox_backup",
    "TEST_AUTOMATION_DATABASE_URL": "sandbox_automation",
}


def approved_image():
    matches = re.findall(
        r"^\s+image: (postgres:17\.\d+-bookworm@sha256:[0-9a-f]{64})\s*$",
        (ROOT / "compose.yaml").read_text(), re.MULTILINE,
    )
    if len(matches) != 1:
        raise RuntimeError("one checksum-locked PostgreSQL 17 image is required")
    return matches[0]


def local_docker():
    """Resolve once before mutation; a daemon-side loopback port is not local."""
    host = os.environ.get("DOCKER_HOST")
    if not host:
        host = json.loads(invoke(["docker", "context", "inspect", "--format",
                                  "{{json .Endpoints.docker.Host}}"], timeout=30))
    parsed = urllib.parse.urlsplit(host)
    if (parsed.scheme != "unix" or parsed.netloc or not parsed.path.startswith("/")
            or parsed.query or parsed.fragment or len(host) > 1024
            or any(ord(c) < 32 for c in host)
            or any(part in (".", "..") for part in parsed.path.split("/"))):
        raise RuntimeError("acceptance requires a local absolute Unix Docker socket")
    environment = {k: v for k, v in os.environ.items()
                   if k not in {"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"}}
    return ["docker", "--host", host], environment


def invoke(command, *, env=None, text=None, timeout=120):
    result = subprocess.run(
        command, cwd=ROOT, env=env, input=text, text=True,
        capture_output=True, timeout=timeout, check=False,
    )
    if result.returncode:
        # psql can echo a password-bearing CREATE ROLE statement on an error.
        # Docker/npm output can also include operator credential configuration.
        raise RuntimeError("fixture subprocess failed; diagnostic output withheld")
    return result.stdout.strip()


def private_directory(path):
    path.mkdir(parents=True, exist_ok=False, mode=0o700)
    os.chmod(path, 0o700)


def private_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as target:
        json.dump(value, target, indent=2)
        target.write("\n")


def fingerprints(binary, process_binary, migration_binary):
    paths = sorted((ROOT / "migrations").glob("*.sql"))
    paths += sorted((ROOT / "src").glob("automation*.rs"))
    paths += [ROOT / name for name in (
        "Cargo.toml", "Cargo.lock", "src/db.rs", "src/workspace_restore.rs",
        "src/lifecycle.rs", "src/execution.rs", "src/backup_ledger.rs",
        "tests/support/mod.rs", "src/termination_ledger_tests.rs",
        "src/backup_ledger_tests.rs", "tests/fixtures/restore/0038_restores.sql",
        "src/lib.rs", "src/api.rs", "src/bin/sandboxd.rs", "src/capabilities.rs",
        "src/database_process_identity.rs", "src/service_lifecycle.rs",
        "src/bin/sandbox-automation.rs", "Dockerfile",
        "scripts/release/common.py", "scripts/release/native.py",
        "scripts/sql/automation-role.sql",
        "tests/automation_process.rs",
        "tests/automation_process/faults.rs", "scripts/sql/roles.sql",
        "tests/automation_process/acceptance_faults.rs",
        "tests/fixtures/automation/sdk-http.mjs",
        "tests/fixtures/automation/notifications-http.mjs", "scripts/test-automation.py",
    )]
    paths += sorted((ROOT / "scripts/sql").glob("*-role.sql"))
    paths += sorted((ROOT / "sdk/typescript/dist").glob("*.js"))
    records = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
               for p in paths}
    if binary:
        records["test_binary"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    records["process_test_binary"] = hashlib.sha256(process_binary.read_bytes()).hexdigest()
    records["migration_binary"] = hashlib.sha256(migration_binary.read_bytes()).hexdigest()
    records["worker_binary"] = hashlib.sha256(
        migration_binary.with_name("sandbox-automation").read_bytes()).hexdigest()
    return records


def artifacts(args):
    requested = [args.test_binary, args.process_test_binary, args.migration_binary]
    if not any(requested):
        output = invoke(["cargo", "test", "--locked", "--lib", "--test",
                         "automation_process", "--no-run", "--message-format=json"], timeout=1200)
        messages = [json.loads(line) for line in output.splitlines()]
        requested = []
        for name, test in [("sandbox_platform", True), ("automation_process", True),
                           ("sandboxd", False)]:
            paths = [m["executable"] for m in messages
                     if m.get("reason") == "compiler-artifact"
                     and m.get("target", {}).get("name") == name
                     and m.get("profile", {}).get("test") is test and m.get("executable")]
            if len(paths) != 1:
                raise RuntimeError("one ordinary executable per acceptance target is required")
            requested.append(Path(paths[0]))
    if not all(requested):
        raise RuntimeError("provide all three built artifacts or let Cargo build all three")
    paths = tuple(path.resolve() for path in requested)
    patterns = [r"sandbox_platform-[0-9a-f]+", r"automation_process-[0-9a-f]+", r"sandboxd"]
    for path, pattern in zip(paths, patterns):
        if not path.is_file() or not os.access(path, os.X_OK) or not re.fullmatch(pattern, path.name):
            raise RuntimeError("ordinary Cargo acceptance executable required")
    if (paths[0].parent != paths[1].parent or paths[0].parent.name != "deps"
            or paths[2].parent != paths[0].parent.parent):
        raise RuntimeError("all artifacts must share one ordinary Cargo target layout")
    worker = paths[2].with_name("sandbox-automation")
    if worker.is_symlink() or not worker.is_file() or not os.access(worker, os.X_OK):
        raise RuntimeError("the same Cargo build must provide its regular worker executable")
    return paths


def fixture_tls(evidence):
    """Disposable test CA/leaf; no production key or trust-store changes."""
    directory = evidence / "tls"
    private_directory(directory)
    ca = directory / "ca.crt"
    key = directory / "server.key"
    cert = directory / "server.crt"
    invoke(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=sandbox-automation-disposable-ca", "-keyout", str(directory / "ca.key"),
            "-out", str(ca)])
    invoke(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj",
            "/CN=127.0.0.1", "-keyout", str(key), "-out", str(directory / "server.csr")])
    extensions = directory / "leaf.ext"
    extensions.write_text("subjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\n"
                          "keyUsage=critical,digitalSignature,keyEncipherment\n"
                          "extendedKeyUsage=serverAuth\n")
    invoke(["openssl", "x509", "-req", "-days", "1", "-in", str(directory / "server.csr"),
            "-CA", str(ca), "-CAkey", str(directory / "ca.key"),
            "-CAserial", str(directory / "ca.srl"), "-CAcreateserial",
            "-extfile", str(extensions), "-out", str(cert)])
    for path in directory.iterdir():
        path.chmod(0o600)
    return directory, ca


def run(args):
    image = approved_image()
    docker, docker_environment = local_docker()
    # Build once, before starting PostgreSQL. CI may pass its just-built ordinary
    # test binary to avoid another Cargo build-directory lock during execution.
    node = invoke(["node", "--version"])
    if not re.fullmatch(r"v\d+\.\d+\.\d+", node) or int(node[1:].split(".")[0]) < 22:
        raise RuntimeError("Node.js 22 or newer is required")
    if not args.skip_sdk_prepare:
        invoke(["npm", "--prefix", "sdk/typescript", "ci", "--ignore-scripts"], timeout=300)
        invoke(["npm", "--prefix", "sdk/typescript", "run", "build"], timeout=120)
    if not (ROOT / "sdk/typescript/dist/index.js").is_file():
        raise RuntimeError("the tracked TypeScript SDK must be built")
    binary, process_binary, migration_binary = artifacts(args)
    evidence = args.evidence_dir.resolve()
    private_directory(evidence)
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    digest = fingerprints(binary, process_binary, migration_binary)
    local_image = subprocess.run([*docker, "image", "inspect", image], cwd=ROOT, env=docker_environment,
                                 capture_output=True, check=False, timeout=30)
    if local_image.returncode:
        invoke([*docker, "pull", image], env=docker_environment, timeout=300)
    tls_directory, rootcert = fixture_tls(evidence)
    env = dict(docker_environment)
    env["POSTGRES_PASSWORD"] = secrets.token_hex(32)
    admin = "sandbox_fixture_admin"
    name = "sandbox-automation-fixture-" + uuid.uuid4().hex
    container = None
    test_process = None
    result_code = 1
    cleanup_confirmed = False
    stage = "container_start"
    ledger = None
    process_ledger = None
    process_migrated = False
    failed_stage = None
    port = None
    try:
        container = invoke([
            *docker, "run", "--detach", "--name", name,
            "--label", "com.sandbox.fixture=automation",
            "--publish", "127.0.0.1::5432", "--memory", "1g", "--cpus", "2",
            "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,size=1g",
            "--tmpfs", "/sandbox-tls:rw,noexec,nosuid,size=1m",
            "--mount", "type=bind,src=" + str(tls_directory) + ",dst=/fixture-tls,readonly",
            "--env", "POSTGRES_PASSWORD", "--env", "POSTGRES_USER=" + admin,
            "--env", "POSTGRES_DB=postgres", image, "bash", "-ceu",
            "cp /fixture-tls/server.crt /fixture-tls/server.key /sandbox-tls/; "
            "chown postgres:postgres /sandbox-tls/server.*; chmod 0600 /sandbox-tls/server.key; "
            "exec docker-entrypoint.sh postgres -c ssl=on "
            "-c ssl_cert_file=/sandbox-tls/server.crt -c ssl_key_file=/sandbox-tls/server.key",
        ], env=env)
        if not re.fullmatch(r"[0-9a-f]{64}", container):
            raise RuntimeError("unexpected created fixture identity")
        port_result = invoke([*docker, "port", container, "5432/tcp"], env=docker_environment)
        binding = re.fullmatch(r"127\.0\.0\.1:(\d+)", port_result)
        if not binding or not 1 <= int(binding[1]) <= 65535:
            raise RuntimeError("fixture PostgreSQL must bind only loopback")
        port = int(binding[1])
        psql_env = dict(env, PGHOST="127.0.0.1", PGPORT="5432", PGUSER=admin,
                        PGPASSWORD=env["POSTGRES_PASSWORD"], PGDATABASE="postgres")
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
                    raise RuntimeError("fresh fixture PostgreSQL did not become ready") from None
                time.sleep(0.2)
        passwords = {role: secrets.token_hex(32) for role in ROLES.values()}
        names = ",".join("'" + role + "'" for role in ROLES.values())
        sql = [
            "DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN(" + names +
            ")) OR EXISTS(SELECT 1 FROM pg_database WHERE datname IN('" + DATABASE +
            "','" + PROCESS_DATABASE + "')) THEN RAISE EXCEPTION 'fresh fixture server required'; END IF; END $$;",
            "SET password_encryption='scram-sha-256';",
        ]
        for role, password in passwords.items():
            sql.append("CREATE ROLE " + role +
                       " LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD '" +
                       password + "';")
        for database in (DATABASE, PROCESS_DATABASE):
            sql += ["CREATE DATABASE " + database + " OWNER sandbox_owner;",
                    "REVOKE CONNECT ON DATABASE " + database + " FROM PUBLIC;",
                    "GRANT CONNECT ON DATABASE " + database + " TO " + ",".join(ROLES.values()) + ";"]
        invoke(command, env=psql_env, text="\n".join(sql), timeout=60)
        # Never reuse inherited component connections from another local suite.
        test_env = {k: v for k, v in os.environ.items()
                    if not (k.startswith("TEST_") and k.endswith("DATABASE_URL"))}
        for key, role in ROLES.items():
            test_env[key] = "postgresql://" + role + ":" + urllib.parse.quote(passwords[role]) + \
                "@127.0.0.1:" + str(port) + "/" + DATABASE
        test_env.update(CARGO_INCREMENTAL="0", RUST_BACKTRACE="0", AUTOMATION_TEST_FORMAL="39")
        tls_query = urllib.parse.urlencode({"sslmode": "verify-full", "sslrootcert": str(rootcert)})
        migration_env = {k: v for k, v in test_env.items() if not k.startswith("SANDBOX_")}
        migration_env["SANDBOX_DATABASE_URL"] = test_env["TEST_MIGRATION_DATABASE_URL"] + "?" + tls_query
        stage = "normal_migration"
        invoke([str(migration_binary), "--role", "migrate"], env=migration_env, timeout=120)
        test_env["TEST_AUTOMATION_TLS_ROOTCERT"] = str(rootcert)
        test_env["TEST_AUTOMATION_WORKER_BINARY"] = str(migration_binary.with_name("sandbox-automation"))
        test_command = [str(binary), "automation::tests::", "--ignored", "--test-threads=1"]
        fd = os.open(evidence / "acceptance.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        stage = "formal_acceptance"
        with os.fdopen(fd, "w") as log:
            test_process = subprocess.Popen(test_command, cwd=ROOT, env=test_env,
                                            stdout=log, stderr=subprocess.STDOUT,
                                            start_new_session=True)
            result_code = test_process.wait(timeout=600)
        if result_code == 0:
            output = (evidence / "acceptance.log").read_text()
            if not re.search(r"test result: ok\. 18 passed; 0 failed; 0 ignored;", output):
                result_code = 1
        for namespace, count, filename in (
                ("automation::notification_tests::", 5, "notifications.log"),
                ("automation::notification_http_tests::", 1, "notifications-http.log")):
            if result_code:
                break
            stage = namespace.removesuffix("::")
            fd = os.open(evidence / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as log:
                test_process = subprocess.Popen(
                    [str(binary), namespace, "--ignored", "--test-threads=1"],
                    cwd=ROOT, env=test_env, stdout=log, stderr=subprocess.STDOUT,
                    start_new_session=True)
                result_code = test_process.wait(timeout=180)
            output = (evidence / filename).read_text()
            if not re.search(r"test result: ok\. " + str(count)
                             + r" passed; 0 failed; 0 ignored;", output):
                result_code = 1
        if result_code == 0:
            stage = "worker_process_migration"
            # Process trials own an empty database: never delete an earlier
            # business case's queue or rewrite leases to manufacture handoff.
            process_env = dict(test_env)
            for key in ROLES:
                process_env[key] = test_env[key].removesuffix("/" + DATABASE) + "/" + PROCESS_DATABASE
            process_migration_env = dict(migration_env)
            process_migration_env["SANDBOX_DATABASE_URL"] = process_env["TEST_MIGRATION_DATABASE_URL"] + "?" + tls_query
            invoke([str(migration_binary), "--role", "migrate"], env=process_migration_env, timeout=120)
            process_migrated = True
            process_psql_env = dict(psql_env, PGDATABASE=PROCESS_DATABASE,
                                    PGUSER="sandbox_owner", PGPASSWORD=passwords["sandbox_owner"])
            role_sql = [(ROOT / "scripts/sql/roles.sql").read_text()]
            role_sql += [(ROOT / ("scripts/sql/" + name + "-role.sql")).read_text()
                         for name in ("worker", "admission", "gateway", "termination", "fencing",
                                      "volume-deleter", "backup", "automation")]
            role_sql.append("INSERT INTO platform_configuration(singleton,cluster_epoch,safe_mode) VALUES(true,'" + str(uuid.uuid4()) + "',false);")
            invoke(command, env=process_psql_env, text="\n".join(role_sql), timeout=60)
            stage = "worker_process"
            fd = os.open(evidence / "process.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as log:
                test_process = subprocess.Popen([str(process_binary), "--ignored", "--test-threads=1",
                                                "--nocapture"], cwd=ROOT, env=process_env, stdout=log,
                                                stderr=subprocess.STDOUT, start_new_session=True)
                # The process matrix includes three independent natural
                # 30-second lease/eligibility recoveries. Per-trial deadlines
                # and production SQL timeouts remain unchanged.
                result_code = test_process.wait(timeout=240)
            output = (evidence / "process.log").read_text()
            if not re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", output):
                result_code = 1
        failed_stage = stage if result_code else None
        stage = "final_ledger"
        expected_ledger = [{"version": int(path.name.split("_", 1)[0]), "success": True,
                            "checksum": hashlib.sha384(path.read_bytes()).hexdigest()}
                           for path in sorted((ROOT / "migrations").glob("*.sql"))]
        if [row["version"] for row in expected_ledger] != list(range(1, 38)) + [39, 40, 41, 42, 43]:
            raise RuntimeError("formal automation requires the complete real migration ledger without 0038")
        for database in (DATABASE, PROCESS_DATABASE) if process_migrated else (DATABASE,):
            psql_env["PGDATABASE"] = database
            actual = json.loads(invoke(command, env=psql_env, text="SELECT jsonb_agg(jsonb_build_object('version',version,'success',success,'checksum',encode(checksum,'hex')) ORDER BY version) FROM _sqlx_migrations;"))
            if database == DATABASE:
                ledger = actual
            else:
                process_ledger = actual
            if actual != expected_ledger:
                raise RuntimeError("automation database must match every real migration checksum without 0038")
        if result_code == 0 and process_ledger is None:
            raise RuntimeError("successful acceptance requires the separately migrated process database")
        if fingerprints(binary, process_binary, migration_binary) != digest:
            result_code = 1
            raise RuntimeError("automation inputs changed during acceptance")
        stage = "completed" if result_code == 0 else "acceptance_failed"
    except BaseException:
        # A setup/ledger exception after an earlier successful child must not
        # leave a green receipt. Cleanup still runs before the exception returns.
        result_code = 1
        failed_stage = failed_stage or stage
        raise
    finally:
        cleanup_errors = []
        process_cleanup_confirmed = test_process is None
        if test_process and test_process.poll() is None:
            try:
                try:
                    os.killpg(test_process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    test_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(test_process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    test_process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                cleanup_errors.append("OWNED_TEST_PROCESS_CLEANUP_UNCONFIRMED")
        if test_process:
            process_cleanup_confirmed = test_process.poll() is not None
        if container and re.fullmatch(r"[0-9a-f]{64}", container):
            removed_ok = False
            try:
                removed = subprocess.run([*docker, "rm", "--force", "--volumes", container],
                                         cwd=ROOT, env=docker_environment,
                                         capture_output=True, check=False, timeout=45)
                removed_ok = removed.returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                cleanup_errors.append("OWNED_CONTAINER_REMOVE_UNCONFIRMED")
            try:
                remaining = subprocess.run([*docker, "ps", "--all", "--no-trunc", "--filter",
                                            "id=" + container, "--format", "{{.ID}}"],
                                           cwd=ROOT, env=docker_environment,
                                           capture_output=True, check=False, timeout=15)
                cleanup_confirmed = removed_ok and remaining.returncode == 0 and not remaining.stdout.strip()
            except (OSError, subprocess.TimeoutExpired):
                cleanup_errors.append("OWNED_CONTAINER_ABSENCE_UNCONFIRMED")
        if not cleanup_confirmed or not process_cleanup_confirmed:
            result_code = 1
        private_json(evidence / "evidence.json", {
            "environment": "DISPOSABLE_LOOPBACK_FIXTURE_NOT_CLOUD_CERTIFICATION",
            "started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "postgres_image": image, "container_id": container, "loopback_port": port,
            "exit_code": result_code, "formal_migration_ledger": ledger,
            "process_formal_migration_ledger": process_ledger,
            "databases": {"business": DATABASE, "process": PROCESS_DATABASE},
            "last_stage": stage, "owned_container_cleanup_confirmed": cleanup_confirmed,
            "failed_stage": failed_stage,
            "owned_test_process_cleanup_confirmed": process_cleanup_confirmed,
            "cleanup_errors": cleanup_errors,
            "private_drafts": [], "formal_component": 39, "unpublished_version": 38,
            "normal_migration_command": "sandboxd --role migrate",
            "process_database_tls": "verify-full; disposable test CA and IP SAN",
            "required_test_counts": {"automation_business": 18,
                                     "notification_postgres": 5,
                                     "notification_signed_http_sdk": 1,
                                     "automation_worker_process": 1},
            "source_sha256": digest,
        })
    print("isolated automation acceptance exit " + str(result_code) + "; evidence: " + str(evidence))
    return result_code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-binary", type=Path)
    parser.add_argument("--process-test-binary", type=Path)
    parser.add_argument("--migration-binary", type=Path)
    parser.add_argument("--skip-sdk-prepare", action="store_true",
                        help="use the already built tracked SDK, usually after the CI SDK step")
    parser.add_argument("--evidence-dir", type=Path,
                        default=ROOT / ".local/automation-evidence" / uuid.uuid4().hex)
    args = parser.parse_args()
    def stop(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        return run(args)
    except KeyboardInterrupt:
        print("isolated automation fixture interrupted; owned child/container cleanup requested", file=sys.stderr)
        return 130
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired):
        print("isolated automation fixture failed; secret-bearing subprocess output withheld", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
