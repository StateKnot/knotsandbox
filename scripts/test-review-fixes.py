#!/usr/bin/env python3
"""Required review regressions on a disposable loopback TLS PostgreSQL server.

Consumes ordinary Cargo --message-format=json build output. Each interface suite
owns a fresh normally migrated database; the exact historical upgrade case
installs its own version-41 schema in an empty owned database before upgrading.
Bootstrap shares its explicit database initialization prerequisite. No existing
database can be selected.
Credentials stay in child environments/stdin. Reuses the automation fixture's
locked image, local Docker selection, TLS generation and redacted subprocesses.
"""
import argparse
import hashlib
import importlib.util
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

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("automation_fixture", ROOT / "scripts/test-automation.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
HISTORICAL_UPGRADE_SUITE = (
    "automation_upgrade", "automation_upgrade",
    "upgrade_from_v41_preserves_historical_automation_and_rejects_invalid_source_events",
    "upgrade_from_v41_preserves_historical_automation_and_rejects_invalid_source_events",
)
HISTORICAL_UPGRADE_MARKER = "AUTO_UPGRADE_V41_CURRENT_FACTS_OLD_MIGRATOR_REFUSAL_VERIFIED"
HISTORICAL_STATE_MARKER = "AUTO_UPGRADE_NONEMPTY_HISTORY_SCHEMA42_ACK_CURRENT_REPLAY_REVOKE_VERIFIED"
HISTORICAL_PROGRESSION_MARKER = "AUTO_UPGRADE_UNKNOWN_FAILED_DISTINCT_SOURCES_ACK_REPLAY_ISOLATION_VERIFIED"
SUITES = [
    ("resource_accounting", "resource_accounting", "", "accepted_create_freezes_launch_request_and_scoped_pending_receipts_once"),
    ("resource_accounting_http", "resource_accounting_http", "", "signed_resource_http_and_node_sdk_preserve_decimal_quantities_and_revocation"),
    ("pod_observation", "sandbox_platform", "launch_resource_observation_tests::", "actual_lost_commit_ack_replays_original_registration_and_observation_id"),
    ("pod_observation_http", "sandbox_platform", "resource_accounting::tests::", "signed_pages_pin_first_page_absence_across_an_earlier_insert_later_commit_and_recheck_revocation"),
    ("db_cancellation", "sandbox_platform", "db::cancellation_tests::", "cancelled_begin_returns_runtime_tls_connection_idle_and_autocommit_safe"),
    ("bff_pg", "sandbox_platform", "bff::tests::", "browser_fixture_tagged_pools_drain_before_ordinary_database_drop"),
    ("service_clients", "service_clients", "", "service_client_binding_rejects_other_client_and_owner_rotation_revokes_delegation"),
    ("tenant_audit", "tenant_audit", "", "signed_http_and_actual_node_sdk_tenant_audit_contract_is_redacted_and_revocable"),
    HISTORICAL_UPGRADE_SUITE,
    ("timers", "timers", "", "blocked_first_hundred_cannot_starve_later_expiry_and_replicas_accept_one_stop"),
    ("timer_worker", "worker", "", "supervised_timer_skips_hundred_locked_workspaces_and_accepts_later_expiry"),
    ("worker_process", "worker_process", "", ""),
    ("worker_dispatch", "worker_dispatch", "", "worker_fills_capacity_and_recovers_missing_hints_future_work_and_listener_loss"),
    ("worker_continuation", "worker_continuation", "", "continuous_lost_commit_ack_stops_old_batch_and_recovers_same_uid"),
    ("output_identity", "sandbox_platform", "output_page_rechecks_identity_and_expiry_after_storage_io", ""),
    ("action_scope", "sandbox_platform", "action_scope_ceiling_blocks_mutations_streams_and_delegation", ""),
    ("bootstrap_prerequisite", "database", "forced_rls_isolates_rows_and_transaction_context_does_not_leak", ""),
    ("bootstrap", "bootstrap", "", ""),
    ("grants", "grants", "", ""),
    ("capabilities", "capabilities", "", "capabilities_report_only_implemented_contract_and_live_project_limits_after_explicit_authorization"),
    ("executions", "executions", "", ""),
    ("file_transfers", "file_transfers", "", ""),
]
# A broader local acceptance caller may supply exact expected counts. The
# standalone review matrix retains its established selection and resources.
EXPECTED_COUNTS = {"resource_accounting": 9, "resource_accounting_http": 3, "pod_observation": 8, "pod_observation_http": 1, "db_cancellation": 1, "bff_pg": 4, "automation_upgrade": 1, "worker_dispatch": 3, "worker_continuation": 6}


def public_fingerprints():
    names = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT).split(b"\0")
    result = {}
    for name in sorted(set(names) - {b""}):
        relative = Path(name.decode())
        if relative.is_absolute() or ".." in relative.parts or relative.parts[0] in (".git", ".local"):
            raise RuntimeError("public source path invalid")
        path = ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("public source must be a regular file")
        result[str(relative)] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "mode": path.stat().st_mode & 0o777}
    return result


def artifacts(path):
    candidates = {}
    for line in path.read_text().splitlines():
        message = json.loads(line)
        if message.get("reason") != "compiler-artifact" or not message.get("executable"):
            continue
        key = (message["target"]["name"], message["profile"]["test"])
        raw = Path(message["executable"])
        if raw.is_symlink() or any(parent.is_symlink() for parent in raw.parents):
            raise RuntimeError("Cargo artifact symlink forbidden")
        candidates.setdefault(key, set()).add(raw.resolve())
    selected = {}
    for name, test in [(name, True) for name in {suite[1] for suite in SUITES}] + [("sandboxd", False)]:
        paths = candidates.get((name, test), set())
        if len(paths) != 1:
            raise RuntimeError("exact ordinary Cargo artifact missing: " + name)
        path = paths.pop()
        pattern = name.replace("_", "[_-]") + (r"-[0-9a-f]+" if test else "")
        if not path.is_file() or path.is_symlink() or not os.access(path, os.X_OK) or not re.fullmatch(pattern, path.name):
            raise RuntimeError("ordinary executable required")
        selected[name] = path
    target = selected["sandboxd"].parent
    if any(path.parent != target / "deps" for name, path in selected.items() if name != "sandboxd"):
        raise RuntimeError("all artifacts must share one Cargo target layout")
    return selected


def sdk_fingerprints():
    directory = ROOT / "sdk/typescript/dist"
    if not directory.is_dir() or directory.is_symlink():
        raise RuntimeError("build the actual TypeScript SDK before interface acceptance")
    result = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise RuntimeError("SDK artifact must be a regular file or directory")
        if path.is_file():
            result[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    if any("sdk/typescript/dist/" + name not in result for name in ("index.js", "transport.js", "schema.d.ts")):
        raise RuntimeError("actual generated SDK artifacts missing")
    return result


def run(args):
    binaries = artifacts(args.artifacts)
    sources = public_fingerprints()
    binary_hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()}
    sdk_hashes = sdk_fingerprints()
    evidence = args.evidence_dir.resolve()
    fixture.private_directory(evidence)
    fixture.private_json(evidence / "source.json", sources)
    tls_directory, rootcert = fixture.fixture_tls(evidence)
    docker, docker_env = fixture.local_docker()
    image = fixture.approved_image()
    admin = "sandbox_review_fixture_admin"
    environment = dict(docker_env, POSTGRES_PASSWORD=secrets.token_hex(32))
    container = None
    container_name = "sandbox-review-" + uuid.uuid4().hex
    child = None
    suites = []
    cleanup = False
    result_code = 1
    memory_gib = getattr(args, "fixture_memory_gib", 1)
    if memory_gib not in (1, 2):
        raise RuntimeError("fixture memory must be one or two GiB")
    try:
        container = fixture.invoke([
            *docker, "run", "--detach", "--name", container_name,
            "--label", "com.sandbox.fixture=review-regression", "--publish", "127.0.0.1::5432",
            "--memory", str(memory_gib) + "g", "--cpus", "2", "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,size=1g",
            "--tmpfs", "/sandbox-tls:rw,noexec,nosuid,size=1m",
            "--mount", "type=bind,src=" + str(tls_directory) + ",dst=/fixture-tls,readonly",
            "--env", "POSTGRES_PASSWORD", "--env", "POSTGRES_USER=" + admin, "--env", "POSTGRES_DB=postgres",
            image, "bash", "-ceu", "cp /fixture-tls/server.crt /fixture-tls/server.key /sandbox-tls/; "
            "chown postgres:postgres /sandbox-tls/server.*; chmod 0600 /sandbox-tls/server.key; "
            "exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/sandbox-tls/server.crt -c ssl_key_file=/sandbox-tls/server.key",
        ], env=environment)
        if not re.fullmatch(r"[0-9a-f]{64}", container):
            raise RuntimeError("unexpected owned container identity")
        binding = re.fullmatch(r"127\.0\.0\.1:(\d+)", fixture.invoke([*docker, "port", container, "5432/tcp"], env=docker_env))
        if not binding:
            raise RuntimeError("disposable database must be loopback only")
        port = int(binding[1])
        psql_env = dict(environment, PGHOST="127.0.0.1", PGPORT="5432", PGUSER=admin, PGPASSWORD=environment["POSTGRES_PASSWORD"], PGDATABASE="postgres")
        psql = [*docker, "exec", "-i"]
        for key in ("PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE"):
            psql += ["--env", key]
        psql += [container, "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"]
        deadline = time.monotonic() + 60
        while True:
            try:
                fixture.invoke(psql, env=psql_env, text="SELECT 1;", timeout=5)
                break
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("fresh database readiness failed") from None
                time.sleep(0.2)
        passwords = {role: secrets.token_hex(32) for role in fixture.ROLES.values()}
        sql = ["SET password_encryption='scram-sha-256';"]
        for role, password in passwords.items():
            sql.append("CREATE ROLE " + role + " LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD '" + password + "';")
        fixture.invoke(psql, env=psql_env, text="\n".join(sql))
        expected = [{"version": int(path.name.split("_", 1)[0]), "success": True, "checksum": hashlib.sha384(path.read_bytes()).hexdigest()} for path in sorted((ROOT / "migrations").glob("*.sql"))]
        if [row["version"] for row in expected] != list(range(1, 38)) + [39, 40, 41, 42, 43, 44, 45, 46]:
            raise RuntimeError("review requires real formal migrations 1..37+39..46, never 38")
        for index, (name, target, filter_name, required) in enumerate(SUITES, 1):
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,39}", name):
                raise RuntimeError("interface suite name invalid")
            historical_upgrade = name == "automation_upgrade" or target == "automation_upgrade"
            if historical_upgrade and (name, target, filter_name, required) != HISTORICAL_UPGRADE_SUITE:
                raise RuntimeError("historical upgrade requires its exact mandatory interface case")
            database = "sandbox_worker_process_" + str(time.time_ns()) + "_test" if name == "worker_process" else "sandbox_review_" + ("bootstrap" if name == "bootstrap_prerequisite" else name) + "_test"
            if len(database) > 63:
                raise RuntimeError("interface database identifier exceeds PostgreSQL bound")
            print(json.dumps({"suite": name, "stage": "PREPARING", "index": index, "total": len(SUITES)}), flush=True)
            if name == "bootstrap":
                if not suites or suites[-1].get("suite") != "bootstrap_prerequisite" or suites[-1].get("status") != "PASS" or suites[-1].get("database") != database:
                    raise RuntimeError("bootstrap requires its successful fresh database initialization prerequisite")
            else:
                fixture.invoke(psql, env=psql_env, text="CREATE DATABASE " + database + " OWNER sandbox_owner; REVOKE CONNECT ON DATABASE " + database + " FROM PUBLIC; GRANT CONNECT ON DATABASE " + database + " TO " + ",".join(passwords) + ";")
            test_env = {key: value for key, value in os.environ.items() if not key.startswith(("TEST_", "SANDBOX_"))}
            tls_query = urllib.parse.urlencode({"sslmode": "verify-full", "sslrootcert": str(rootcert)})
            for key, role in fixture.ROLES.items():
                test_env[key] = "postgresql://" + role + ":" + passwords[role] + "@127.0.0.1:" + str(port) + "/" + database + "?" + tls_query
            test_env["TEST_OWNER_DATABASE_URL"] = test_env["TEST_MIGRATION_DATABASE_URL"]
            test_env["TEST_AUTOMATION_TLS_ROOTCERT"] = str(rootcert)
            if name == "pod_observation":
                # Only the historical cutover case creates and drops its own
                # random database on this newly owned loopback TLS server.
                test_env["TEST_POSTGRES_ADMIN_USER"] = admin
                test_env["SANDBOX_POSTGRES_ADMIN_PASSWORD"] = environment["POSTGRES_PASSWORD"]
            if name == "bff_pg":
                # Only this fixture creates its own additional random test
                # databases. Do not expose admin authority to interface suites.
                test_env["TEST_POSTGRES_ADMIN_DATABASE_URL"] = "postgresql://" + admin + ":" + environment["POSTGRES_PASSWORD"] + "@127.0.0.1:" + str(port) + "/postgres?" + tls_query
            if historical_upgrade:
                # This one case exercises the real historical installation and
                # upgrade. A current sandboxd migration here would silently
                # turn it into a fresh-schema test. Verify the database created
                # by this fixture still has no user relations before dispatch.
                relation_count = fixture.invoke(psql, env=dict(psql_env, PGDATABASE=database), text="SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname !~ '^pg_toast' AND n.nspname !~ '^pg_temp';")
                if relation_count != "0":
                    raise RuntimeError("historical upgrade requires a new empty owned database")
                schema_preparation = {"mode": "TEST_INSTALLS_V41_THEN_CURRENT", "pre_run_user_relation_count": 0}
            else:
                migration_env = dict(test_env, SANDBOX_DATABASE_URL=test_env["TEST_MIGRATION_DATABASE_URL"])
                fixture.invoke([str(binaries["sandboxd"]), "--role", "migrate"], env=migration_env, timeout=120)
                schema_preparation = {"mode": "SANDBOXD_CURRENT_MIGRATIONS"}
            listing = fixture.invoke([str(binaries[target]), "--list", "--ignored"], env=test_env)
            names = [line.removesuffix(": test") for line in listing.splitlines() if line.endswith(": test")]
            namespace = filter_name.endswith("::")
            if namespace:
                chosen = [test for test in names if test.startswith(filter_name)]
                # libtest uses substring filtering. Refuse a namespace whose
                # substring also matches an unrelated module before execution.
                if chosen != [test for test in names if filter_name in test]:
                    raise RuntimeError("namespace is not an exact interface boundary: " + name)
            else:
                chosen = [test for test in names if test.endswith("::" + filter_name) or test == filter_name] if filter_name else names
            if not chosen or filter_name and not namespace and len(chosen) != 1 or required and not any(test.endswith(required) for test in chosen):
                raise RuntimeError("required interface regression missing: " + name)
            if name in EXPECTED_COUNTS and len(chosen) != EXPECTED_COUNTS[name]:
                raise RuntimeError("interface acceptance scope changed: " + name)
            if historical_upgrade and chosen != [HISTORICAL_UPGRADE_SUITE[2]]:
                raise RuntimeError("historical upgrade must execute exactly its one mandatory case")
            command = [str(binaries[target]), "--ignored", "--test-threads=1", "--nocapture"]
            if namespace:
                command += [filter_name]
            elif filter_name:
                command += ["--exact", chosen[0]]
            log_path = evidence / (name + ".log")
            entry = {"suite": name, "database": database, "tests": chosen, "status": "STARTED", "schema_preparation": schema_preparation}
            suites.append(entry)
            print(json.dumps({"suite": name, "stage": "STARTED", "tests": len(chosen)}), flush=True)
            with log_path.open("x") as log:
                log_path.chmod(0o600)
                child = subprocess.Popen(command, cwd=ROOT, env=test_env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                code = child.wait(timeout=240)
            output = log_path.read_text()
            entry.update(exit_code=code, log_sha256=hashlib.sha256(log_path.read_bytes()).hexdigest())
            if code or not re.search(r"test result: ok\. " + str(len(chosen)) + r" passed; 0 failed; 0 ignored;", output):
                entry["status"] = "FAIL"
                raise RuntimeError("interface regression failed: " + name)
            if name == "worker_process" and "WORKER_PROCESS_ACTUAL_ACL_TIMER_TRANSIENT_DRAIN_VERIFIED" not in output:
                raise RuntimeError("worker process matrix completion marker missing")
            if name == "timer_worker" and "WORKER_TIMER_HUNDRED_LOCKS_LATER_STOP_WITHOUT_DEADLINE_CHANGE_VERIFIED" not in output:
                raise RuntimeError("worker fairness completion marker missing")
            if name == "db_cancellation" and "DB_BEGIN_CANCEL_RUNTIME_TLS_POOL_CLEAN_VERIFIED" not in output:
                raise RuntimeError("database cancellation completion marker missing")
            if historical_upgrade:
                if HISTORICAL_UPGRADE_MARKER not in output:
                    raise RuntimeError("historical upgrade completion marker missing")
                if HISTORICAL_STATE_MARKER not in output:
                    raise RuntimeError("nonempty historical state and current acknowledgement completion marker missing")
                if HISTORICAL_PROGRESSION_MARKER not in output:
                    raise RuntimeError("post-upgrade dual-status notification progression completion marker missing")
                entry["historical_upgrade_completion_marker"] = HISTORICAL_UPGRADE_MARKER
                entry["historical_state_completion_marker"] = HISTORICAL_STATE_MARKER
                entry["historical_progression_completion_marker"] = HISTORICAL_PROGRESSION_MARKER
            # Confirm this harness released every owned process before the
            # next suite replaces our process-group cleanup handle.
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise RuntimeError("interface regression left owned processes running: " + name)
            ledger_env = dict(psql_env, PGDATABASE=database)
            actual = json.loads(fixture.invoke(psql, env=ledger_env, text="SELECT jsonb_agg(jsonb_build_object('version',version,'success',success,'checksum',encode(checksum,'hex')) ORDER BY version) FROM _sqlx_migrations;"))
            if actual != expected:
                raise RuntimeError("suite's formal migration checksums differ")
            entry.update(status="PASS", formal_migration_ledger=actual)
            if getattr(args, "drop_completed_databases", False) and name != "bootstrap_prerequisite":
                # Only the random, verified owned container is addressed by
                # this private admin pipe. Reclaim this run's new database
                # after its tests and migration evidence are fully captured.
                fixture.invoke(psql, env=psql_env, text="DROP DATABASE " + database + ";")
                entry["owned_database_disposal_confirmed"] = True
                if name == "bootstrap":
                    suites[-2]["owned_database_disposal_confirmed"] = True
            print(json.dumps({"suite": name, "stage": "PASS", "tests": len(chosen)}), flush=True)
        if public_fingerprints() != sources or {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()} != binary_hashes or sdk_fingerprints() != sdk_hashes:
            raise RuntimeError("source or artifacts changed during acceptance")
        result_code = 0
    finally:
        cleanup_errors = []
        if child and child.poll() is None:
            try:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                cleanup_errors.append("OWNED_TEST_PROCESS_CLEANUP_UNCONFIRMED")
        group_absent = child is None
        if child:
            # A failed harness can leave a worker in its owned session after
            # the harness PID has exited. Reap only that known process group.
            for requested_signal in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(child.pid, 0)
                except ProcessLookupError:
                    group_absent = True
                    break
                except PermissionError:
                    cleanup_errors.append("OWNED_PROCESS_GROUP_CHECK_UNCONFIRMED")
                    break
                try:
                    os.killpg(child.pid, requested_signal)
                except ProcessLookupError:
                    group_absent = True
                    break
                except PermissionError:
                    cleanup_errors.append("OWNED_PROCESS_GROUP_CLEANUP_UNCONFIRMED")
                    break
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    try:
                        os.killpg(child.pid, 0)
                    except ProcessLookupError:
                        group_absent = True
                        break
                    except PermissionError:
                        break
                    time.sleep(0.1)
                if group_absent:
                    break
        # Docker run can time out after daemon-side creation. The preselected
        # random name plus our exact label identifies only this fixture; never
        # remove a container merely because it shares a caller-provided name.
        try:
            inspected = subprocess.run([*docker, "inspect", "--format", "{{json .}}", container_name], env=docker_env, capture_output=True, text=True, timeout=15)
            if inspected.returncode == 0:
                owned = json.loads(inspected.stdout)
                identifier = owned.get("Id", "")
                matches = (owned.get("Name") == "/" + container_name
                           and owned.get("Config", {}).get("Labels", {}).get("com.sandbox.fixture") == "review-regression"
                           and re.fullmatch(r"[0-9a-f]{64}", identifier)
                           and (container is None or identifier == container))
                if not matches:
                    cleanup_errors.append("FIXTURE_OWNERSHIP_MISMATCH")
                else:
                    removed = subprocess.run([*docker, "rm", "--force", "--volumes", identifier], env=docker_env, capture_output=True, timeout=45)
                    absent = subprocess.run([*docker, "ps", "--all", "--no-trunc", "--filter", "id=" + identifier, "--format", "{{.ID}}"], env=docker_env, capture_output=True, timeout=15)
                    cleanup = removed.returncode == 0 and absent.returncode == 0 and not absent.stdout.strip()
            else:
                # Distinguish confirmed absence from an unavailable daemon.
                absent = subprocess.run([*docker, "ps", "--all", "--no-trunc", "--filter", "name=^/" + container_name + "$", "--format", "{{.ID}}"], env=docker_env, capture_output=True, timeout=15)
                cleanup = absent.returncode == 0 and not absent.stdout.strip()
        except (OSError, ValueError, subprocess.TimeoutExpired):
            cleanup_errors.append("OWNED_CONTAINER_CLEANUP_UNCONFIRMED")
        process_clean = (child is None or child.poll() is not None) and group_absent
        try:
            source_unchanged = public_fingerprints() == sources
            binaries_unchanged = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()} == binary_hashes
            sdk_unchanged = sdk_fingerprints() == sdk_hashes
        except (OSError, RuntimeError, subprocess.SubprocessError):
            source_unchanged = binaries_unchanged = sdk_unchanged = False
            cleanup_errors.append("FINAL_INPUT_VERIFICATION_UNCONFIRMED")
        if not cleanup or not process_clean or cleanup_errors or not source_unchanged or not binaries_unchanged or not sdk_unchanged:
            result_code = 1
        fixture.private_json(evidence / "record.json", {"environment": "DISPOSABLE_LOOPBACK_TLS_NOT_CLOUD_CERTIFICATION", "exit_code": result_code, "suites": suites, "owned_container_name": container_name, "owned_container_cleanup_confirmed": cleanup, "owned_test_process_cleanup_confirmed": process_clean, "cleanup_errors": cleanup_errors, "source_unchanged": source_unchanged, "artifacts_unchanged": binaries_unchanged, "sdk_artifacts_unchanged": sdk_unchanged, "sdk_artifact_sha256": sdk_hashes, "binary_sha256": binary_hashes, "source_sha256": hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest()})
    print(json.dumps({"record": str(evidence / "record.json"), "exit_code": result_code}))
    return result_code


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    def stop(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        raise SystemExit(run(args))
    except (RuntimeError, OSError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print("review acceptance failed: " + str(error) if isinstance(error, RuntimeError) else "review fixture failed; raw environment/provider output withheld", file=sys.stderr)
        raise SystemExit(1)
