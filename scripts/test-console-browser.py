#!/usr/bin/env python3
"""Actual Chrome/OIDC/BFF/API acceptance in a fresh local database.

Use a disposable TLS PostgreSQL server with independent runtime roles. Reuse
only the local development Keycloak through a temporary realm, without changing
its original configuration. Credentials enter only child environments/pipes.
This verifies the local product flow, not cloud/PKI/HA.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
import uuid
import shutil
from urllib.parse import urlencode

sys.dont_write_bytecode = True

TEST = "bff::live_tests::real_keycloak_chrome_console_bff_and_api_enforce_live_revocation"
MANUAL_TEST = "bff::live_tests::real_keycloak_console_manual_demo"
MARKER = b"VERIFIED real Chrome BFF automations:"
NOTIFICATION_MARKER = b"VERIFIED real Chrome BFF automation notifications:"
MANUAL_MARKER = b"DEMO_STOPPED_NOT_ACCEPTANCE realm_cleanup_confirmed"
SCREENSHOTS = [
    ("01-instance-details.png", "instance_details", "真实登录后的实例详情；创建仍在排队，未运行 VM。"),
    ("02-accounts-management.png", "accounts_management", "真实服务身份、项目授权变更及原键重放完成。"),
    ("03-diagnosis-complete.png", "diagnosis_complete", "正常 worker 完成控制面诊断；读权限恢复后显式刷新报告。"),
    ("04-events-replayed.png", "events_replayed", "按原断点重连，真实受理事件与完成事件均可见。"),
    ("05-automation-revoked.png", "automation_revoked", "未来 ONCE 策略创建、重放、暂停、恢复及撤销；零运行。"),
    ("06-notification-acknowledged.png", "notification_acknowledged", "真实 FAILED 通知已阅；丢失回执与读写撤权后原键重放完成。"),
    ("07-instance-current-before-stop.png", "instance_current_before_stop", "正常续期产生新版本，停止前重新读取当前实例及 ETag。"),
    ("08-stop-accepted.png", "stop_accepted", "真实停止 API 返回 202，只证明操作已受理。"),
    ("09-permission-revoked-login.png", "permission_revoked_login", "当前授权撤销、租户成员禁用后返回登录；旧数据已清除。"),
]


def ordinary_artifacts(root, args, fixture, env):
    # Always ask Cargo to validate the captured working source. A supplied JSON
    # file can cross-check artifacts, but cannot certify stale executables as a
    # build of today's source. Reused Cargo cache makes this normally a no-op.
    raw = fixture.invoke(["cargo", "build", "--locked", "--offline", "--bin", "sandboxd",
                          "--message-format=json"], env=env, timeout=1200)
    raw += "\n" + fixture.invoke(["cargo", "test", "--locked", "--offline", "--lib",
                                  "--no-run", "--message-format=json"], env=env, timeout=1200)
    rows = [json.loads(line) for line in raw.splitlines() if line]
    result = {}
    for name, test in (("sandbox_platform", True), ("sandboxd", False)):
        paths = {Path(row["executable"]).absolute() for row in rows
                 if row.get("reason") == "compiler-artifact" and row.get("executable")
                 and row["target"]["name"] == name and row["profile"]["test"] is test}
        if len(paths) != 1:
            raise RuntimeError("one ordinary Cargo artifact per target is required")
        path = paths.pop()
        pattern = r"sandbox_platform-[0-9a-f]+" if test else r"sandboxd"
        if not path.is_file() or path.is_symlink() or not os.access(path, os.X_OK) or not re.fullmatch(pattern, path.name):
            raise RuntimeError("ordinary Cargo executable required")
        if path.resolve() != path:
            raise RuntimeError("Cargo artifact ancestors must be regular directories")
        result[name] = path
    if result["sandbox_platform"].parent != result["sandboxd"].parent / "deps":
        raise RuntimeError("artifacts must share one ordinary Cargo target layout")
    if args.artifacts:
        supplied = [json.loads(line) for line in args.artifacts.read_text().splitlines() if line]
        for name, test in (("sandbox_platform", True), ("sandboxd", False)):
            paths = {Path(row["executable"]).absolute() for row in supplied
                     if row.get("reason") == "compiler-artifact" and row.get("executable")
                     and row["target"]["name"] == name and row["profile"]["test"] is test}
            if paths != {result[name]}:
                raise RuntimeError("supplied artifacts must match the current Cargo build")
    return result


def stop_child(child):
    if child is None:
        return True
    try:
        os.killpg(child.pid, 0)
    except ProcessLookupError:
        return True
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=5)
    # A parent can exit before an owned browser/driver; check the whole group.
    try:
        os.killpg(child.pid, 0)
    except ProcessLookupError:
        return True
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.1)
    return False


def request_demo_stop(evidence):
    path = evidence / "demo-stop"
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        if not path.is_file() or path.is_symlink():
            raise RuntimeError("Manual demo stop signal must be a regular file") from None
    else:
        os.close(fd)


def wait_manual_demo(child, evidence, seconds, record, record_path, helper):
    deadline = time.monotonic() + seconds + 120
    announced = False
    ready_path = evidence / "demo-ready.json"
    while child.poll() is None:
        if not announced and ready_path.exists():
            payload, mode = helper.regular_read(ready_path, private=True)
            ready = json.loads(payload)
            helper.require(mode == 0o600 and ready.get("status") == "READY_NOT_ACCEPTANCE"
                           and re.fullmatch(r"https://127\.0\.0\.1:\d+", ready.get("origin", ""))
                           and ready.get("runtime_vm_running") is False
                           and ready.get("cloud_certified") is False,
                           "Manual demo readiness must identify its real local scope")
            record["status"] = "READY_NOT_ACCEPTANCE"
            record["demo_ready"] = {"path": str(ready_path),
                                    "sha256": hashlib.sha256(payload).hexdigest(),
                                    "origin": ready["origin"], "expires_at": ready["expires_at"]}
            helper.write_record(record_path, record)
            print(json.dumps({"status": record["status"], "origin": ready["origin"],
                              "expires_at": ready["expires_at"], "evidence": str(evidence)}), flush=True)
            announced = True
        if time.monotonic() >= deadline:
            request_demo_stop(evidence)
            raise subprocess.TimeoutExpired(MANUAL_TEST, seconds + 120)
        time.sleep(0.25)
    helper.require(announced, "Manual demo exited before publishing readiness")
    return child.wait(timeout=5)


def stop_manual_child(child, evidence):
    # Give Rust its normal path through service shutdown and fresh-token realm
    # deletion before signalling/killing the owned process group as fallback.
    request_demo_stop(evidence)
    if child is not None and child.poll() is None:
        try:
            child.wait(timeout=45)
        except subprocess.TimeoutExpired:
            pass
    return stop_child(child)


def remove_fixture(docker, docker_env, name, fixture):
    inspected = subprocess.run([*docker, "inspect", "--format", "{{json .}}", name],
                               env=docker_env, capture_output=True, text=True, timeout=15)
    if inspected.returncode:
        absent = subprocess.run([*docker, "ps", "--all", "--filter", "name=^/" + name + "$",
                                 "--format", "{{.ID}}"], env=docker_env,
                                capture_output=True, text=True, timeout=15)
        return absent.returncode == 0 and not absent.stdout.strip()
    owned = json.loads(inspected.stdout)
    identifier = owned.get("Id", "")
    if (not re.fullmatch(r"[0-9a-f]{64}", identifier) or owned.get("Name") != "/" + name
            or owned.get("Config", {}).get("Labels", {}).get("com.sandbox.fixture") != "console-notifications"):
        raise RuntimeError("created fixture ownership cannot be confirmed")
    fixture.invoke([*docker, "rm", "--force", "--volumes", identifier], env=docker_env, timeout=45)
    absent = subprocess.run([*docker, "ps", "--all", "--no-trunc", "--filter", "id=" + identifier,
                             "--format", "{{.ID}}"], env=docker_env, capture_output=True,
                            text=True, timeout=15)
    return absent.returncode == 0 and not absent.stdout.strip()


def console_artifacts(root, helper):
    directory = root / "console/dist"
    helper.require(directory.is_dir() and directory.resolve() == directory,
                   "Current console build directory must be regular")
    rows = []
    for path in sorted(directory.rglob("*")):
        helper.require(not path.is_symlink(), "Console build cannot contain symlinks")
        if path.is_file():
            payload, mode = helper.regular_read(path)
            rows.append({"path": str(path.relative_to(directory)), "mode": mode,
                         "sha256": hashlib.sha256(payload).hexdigest()})
        else:
            helper.require(path.is_dir(), "Console build contains a special file")
    helper.require(any(row["path"] == "index.html" for row in rows),
                   "Console build must contain its real index")
    return rows


def private_png(path, helper):
    # PNGs may exceed the shared 1 MiB private-JSON bound. Retain its fixed-FD,
    # ownership, mode and mutation checks with a separate 32 MiB image ceiling.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        helper.require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                       and stat.S_IMODE(before.st_mode) == 0o600
                       and 33 <= before.st_size <= 32 * 1024**2,
                       "Screenshot must be a bounded current-user-owned 0600 PNG")
        chunks, total = [], 0
        while chunk := os.read(descriptor, 1024**2):
            total += len(chunk)
            helper.require(total <= 32 * 1024**2, "Screenshot exceeds its image size bound")
            chunks.append(chunk)
        after, named = os.fstat(descriptor), path.lstat()
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_mode", "st_uid")
        helper.require(tuple(getattr(before, field) for field in fields)
                       == tuple(getattr(after, field) for field in fields)
                       == tuple(getattr(named, field) for field in fields),
                       "Screenshot changed during its fixed-FD read")
        payload = b"".join(chunks)
        helper.require(payload.startswith(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
                       and payload[-12:-4] == b"\x00\x00\x00\x00IEND"
                       and 0 < int.from_bytes(payload[16:20], "big") <= 32768
                       and 0 < int.from_bytes(payload[20:24], "big") <= 100000,
                       "Screenshot must have a complete bounded PNG envelope")
        return payload
    finally:
        os.close(descriptor)


def screenshot_evidence(evidence, helper):
    directory = evidence / "browser-screenshots"
    metadata = directory.lstat()
    helper.require(stat.S_ISDIR(metadata.st_mode) and directory.resolve() == directory
                   and metadata.st_uid == os.getuid() and stat.S_IMODE(metadata.st_mode) == 0o700,
                   "Screenshot evidence requires a canonical current-user-owned 0700 directory")
    expected_names = {name for name, _checkpoint, _caption in SCREENSHOTS} | {"manifest.json"}
    helper.require({path.name for path in directory.iterdir()} == expected_names,
                   "Exactly the nine advertised screenshots and manifest are required")
    manifest_path = directory / "manifest.json"
    raw, mode = helper.regular_read(manifest_path, private=True)
    manifest = json.loads(raw)
    helper.require(mode == 0o600 and isinstance(manifest, dict)
                   and set(manifest) == {"version", "status", "real_flow", "manual_interaction",
                                         "cloud_certified", "vm_running_demonstrated", "scope", "files"}
                   and type(manifest.get("version")) is int and manifest["version"] == 1
                   and manifest.get("status") == "CAPTURED_CHECKPOINTS_NOT_MANUAL_INTERACTION"
                   and manifest.get("real_flow") == "Chrome/compiled console/Keycloak/BFF/API/PostgreSQL"
                   and manifest.get("manual_interaction") is False
                   and manifest.get("cloud_certified") is False
                   and manifest.get("vm_running_demonstrated") is False
                   and manifest.get("scope") == "Private screenshots of actual automated browser checks; the passing test, source/artifact binding and backend facts remain independent required evidence."
                   and isinstance(manifest.get("files"), list)
                   and len(manifest["files"]) == len(SCREENSHOTS),
                   "Screenshot manifest must preserve the actual local automated-check scope")
    images = []
    for row, (name, checkpoint, caption) in zip(manifest["files"], SCREENSHOTS):
        helper.require(isinstance(row, dict)
                       and set(row) == {"file", "checkpoint", "caption", "mode", "bytes", "sha256"}
                       and (row.get("file"), row.get("checkpoint"), row.get("caption"))
                       == (name, checkpoint, caption) and row.get("mode") == "0600"
                       and type(row.get("bytes")) is int,
                       "Screenshot manifest must match the fixed checkpoint order and captions")
        payload = private_png(directory / name, helper)
        digest = hashlib.sha256(payload).hexdigest()
        helper.require(row["bytes"] == len(payload) and row.get("sha256") == digest,
                       "Screenshot bytes/SHA256 must match independently read PNG evidence")
        images.append({"path": "browser-screenshots/" + name, "sha256": digest,
                       "name": caption, "checkpoint": checkpoint,
                       "mode": 0o600, "bytes": len(payload)})
    return {"validated": True, "manifest_path": "browser-screenshots/manifest.json",
            "manifest_sha256": hashlib.sha256(raw).hexdigest(), "count": len(images),
            "manual_interaction": False, "cloud_certified": False,
            "vm_running_demonstrated": False, "images": images}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True, type=Path)
    parser.add_argument("--chrome", type=Path)
    parser.add_argument("--identity-python", required=True, type=Path)
    parser.add_argument("--artifacts", type=Path,
                        help="JSON lines from the current ordinary Cargo build")
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--manual-demo", action="store_true",
                        help="Keep a real local console available; never produces an acceptance PASS")
    parser.add_argument("--demo-seconds", type=int, default=1800,
                        help="Explicit manual demo lifetime, 1800..7200 seconds")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "lifecycle_snapshot", root / "scripts/test-service-lifecycle.py"
    )
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    fixture_spec = importlib.util.spec_from_file_location(
        "automation_fixture", root / "scripts/test-automation.py"
    )
    fixture = importlib.util.module_from_spec(fixture_spec)
    fixture_spec.loader.exec_module(fixture)
    helper.require(not any(os.environ.get(key) for key in
                   ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUST_MIN_STACK", "RUST_TEST_THREADS")),
                   "Compiler/stack/test-thread overrides are not accepted")
    helper.require(args.manual_demo or args.chrome is not None,
                   "Automated browser acceptance requires --chrome")
    helper.require(not args.manual_demo or 1800 <= args.demo_seconds <= 7200,
                   "Manual demo lifetime must be 1800..7200 seconds")
    executables = (args.node, args.identity_python)
    if args.chrome is not None:
        executables += (args.chrome,)
    for executable in executables:
        helper.require(executable.is_absolute() and executable.is_file()
                       and os.access(executable, os.X_OK), "Absolute installed executable required")
    helper.require(shutil.disk_usage(root).free >= 50 * 1024**3,
                   "Less than 50 GB free: assess task-owned rebuildable caches before acceptance")
    host = helper.local_docker_host(os.environ.get("RESTORE_TEST_DOCKER_HOST"))
    docker = ["docker"]
    config = os.environ.get("RESTORE_TEST_DOCKER_CONFIG")
    if config:
        helper.require(Path(config).is_absolute(), "Docker configuration must be absolute")
        docker += ["--config", config]
    docker += ["--host", host]
    docker_env = {key: value for key, value in os.environ.items()
                  if key not in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS",
                                 "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")}
    nonce = uuid.uuid4().hex
    evidence_group = "console-manual-demo" if args.manual_demo else "console-notifications"
    evidence = args.evidence_dir or root / ".local/evidence" / evidence_group / nonce
    evidence = evidence.absolute()
    fixture.private_directory(evidence)
    helper.require(evidence.resolve() == evidence
                   and not any(part == "target" for part in evidence.parts),
                   "Evidence must be canonical and outside build caches")
    snapshot = evidence / "source"
    rows, source_sha = helper.capture(root, snapshot)
    helper.write_record(evidence / "source-manifest.json", {
        "source_sha256": source_sha, "files": rows,
        "git_head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=root,
                                   capture_output=True, text=True, check=True).stdout.strip(),
    })
    record = {
        "status": "PREPARED_NOT_EXECUTED", "source_sha256": source_sha,
        "snapshot": str(snapshot), "execution_root": str(root),
        "snapshot_is_evidence_copy": True, "checks": [],
        "scope": "Actual local Chrome/Keycloak/cookie-BFF/API/TLS PostgreSQL: original account/diagnosis/event/future-automation/stop/revocation matrix plus real coordinator FAILED source, lost ACK reply, current read/write revocation and original-key replay. Source create/manual RENEW use normal domain entries with the actual BFF-verified identity. No cloud/PKI/HA certification.",
    }
    if args.manual_demo:
        record.update({"acceptance": False, "demo_seconds": args.demo_seconds,
                       "scope": "Interactive real local Keycloak/BFF/API/TLS PostgreSQL control-plane demo. Normal diagnosis work only; queued compute creation is not a running VM. No cloud, PKI, HA, metrics or backup certification, and no automated acceptance PASS."})
    else:
        record["screenshots_required"] = True
    record_path = evidence / "record.json"
    helper.write_record(record_path, record)
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("SANDBOX_", "TEST_"))}
    env["PATH"] = str(args.node.parent) + os.pathsep + env["PATH"]
    env.update({
        "CARGO_INCREMENTAL": "0", "CARGO_TARGET_DIR": os.environ.get("CARGO_TARGET_DIR", str(root / "target")),
        "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
        "SANDBOX_OIDC_ISSUER": "http://127.0.0.1:58073/realms/sandbox-dev",
        "SANDBOX_TEST_NODE": str(args.node),
        "SANDBOX_TEST_SOURCE_ROOT": str(root), "IDENTITY_PYTHON": str(args.identity_python),
        "SANDBOX_BROWSER_EVIDENCE_DIR": str(evidence),
    })
    if args.chrome is not None:
        env["SANDBOX_TEST_CHROME"] = str(args.chrome)
    if args.manual_demo:
        env["SANDBOX_MANUAL_DEMO_SECONDS"] = str(args.demo_seconds)
    name = "sandbox-console-notifications-" + nonce
    database = "sandbox_console_notifications_test"
    child = None
    stage = "build"
    startup_attempted = False
    record["status"] = "RUNNING_NOT_ACCEPTANCE" if args.manual_demo else "RUNNING"
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        artifacts = ordinary_artifacts(root, args, fixture, env)
        artifact_hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest()
                           for name, path in artifacts.items()}
        record["artifacts"] = {name: {"path": str(path), "sha256": artifact_hashes[name]}
                               for name, path in artifacts.items()}
        record["current_source_validated_by_cargo"] = True
        stage = "identity_credential"
        # Read only the fixed local development administrator credential. The
        # Rust test creates and removes its own realm; the original is retained.
        secret = fixture.invoke([*docker, "exec", "sandbox-platform-dev-keycloak-1",
                                 "printenv", "KC_BOOTSTRAP_ADMIN_PASSWORD"], env=docker_env, timeout=30)
        helper.require(re.fullmatch(r"[0-9a-f]{64}", secret) is not None,
                       "Local-only identity credential format rejected")
        env["SANDBOX_KEYCLOAK_ADMIN_PASSWORD"] = secret
        image = fixture.approved_image()
        fixture.invoke([*docker, "image", "inspect", image], env=docker_env, timeout=30)
        tls_directory, rootcert = fixture.fixture_tls(evidence)
        admin = "sandbox_console_admin_" + nonce[:16]
        fixture_env = dict(docker_env, POSTGRES_PASSWORD=secrets.token_hex(32))
        stage = "container_start"
        startup_attempted = True
        container = fixture.invoke([
            *docker, "run", "--detach", "--name", name,
            "--label", "com.sandbox.fixture=console-notifications",
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
        ], env=fixture_env)
        helper.require(re.fullmatch(r"[0-9a-f]{64}", container) is not None,
                       "Unexpected disposable fixture identity")
        binding = re.fullmatch(r"127\.0\.0\.1:(\d+)", fixture.invoke(
            [*docker, "port", container, "5432/tcp"], env=docker_env, timeout=15))
        helper.require(binding is not None and 1 <= int(binding[1]) <= 65535,
                       "Fixture must bind only loopback")
        port = int(binding[1])
        record.update({"database": database, "container": container, "local_port": port})
        helper.write_record(record_path, record)
        psql_env = dict(fixture_env, PGHOST="127.0.0.1", PGPORT="5432", PGUSER=admin,
                        PGPASSWORD=fixture_env["POSTGRES_PASSWORD"], PGDATABASE="postgres")
        command = [*docker, "exec", "-i"]
        for key in ("PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE"):
            command += ["--env", key]
        command += [container, "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"]
        deadline = time.monotonic() + 60
        stage = "container_ready"
        while True:
            try:
                helper.require(fixture.invoke(command, env=psql_env, text="SELECT 1;", timeout=5) == "1",
                               "Unexpected fixture readiness reply")
                break
            except (RuntimeError, helper.Rejected, subprocess.TimeoutExpired):
                if time.monotonic() >= deadline:
                    raise RuntimeError("Disposable PostgreSQL did not become ready") from None
                time.sleep(0.2)
        stage = "fresh_roles"
        passwords = {role: secrets.token_hex(32) for role in fixture.ROLES.values()}
        sql = ["SET password_encryption='scram-sha-256';"]
        for role, password in passwords.items():
            sql.append("CREATE ROLE " + role +
                       " LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD '" +
                       password + "';")
        sql += ["CREATE DATABASE " + database + " OWNER sandbox_owner;",
                "REVOKE CONNECT ON DATABASE " + database + " FROM PUBLIC;",
                "GRANT CONNECT ON DATABASE " + database + " TO " + ",".join(fixture.ROLES.values()) + ";"]
        fixture.invoke(command, env=psql_env, text="\n".join(sql), timeout=60)
        tls_query = urlencode({"sslmode": "verify-full", "sslrootcert": str(rootcert)})
        for key, role in fixture.ROLES.items():
            env[key] = "postgresql://" + role + ":" + passwords[role] + "@127.0.0.1:" + str(port) + "/" + database + "?" + tls_query
        stage = "normal_migration"
        migration_env = {key: value for key, value in env.items() if not key.startswith("SANDBOX_")}
        migration_env["SANDBOX_DATABASE_URL"] = env["TEST_MIGRATION_DATABASE_URL"]
        fixture.invoke([str(artifacts["sandboxd"]), "--role", "migrate"], env=migration_env, timeout=120)
        selected_test = MANUAL_TEST if args.manual_demo else TEST
        run_name = "manual-demo" if args.manual_demo else "browser"
        checks = [
            ("console-build", ["npm", "run", "build"], root / "console", 120),
            (run_name, [str(artifacts["sandbox_platform"]), selected_test, "--ignored", "--exact",
                        "--nocapture", "--test-threads=1"], root,
             args.demo_seconds + 120 if args.manual_demo else 360),
        ]
        for check_name, check_command, cwd, timeout in checks:
            stage = check_name
            path = evidence / (check_name + ".log")
            start = time.monotonic()
            with path.open("xb") as log:
                os.chmod(path, 0o600)
                child = subprocess.Popen(check_command, cwd=cwd, env=env, stdout=log,
                                         stderr=subprocess.STDOUT, start_new_session=True)
                if check_name == "manual-demo":
                    try:
                        exit_code = wait_manual_demo(child, evidence, args.demo_seconds,
                                                     record, record_path, helper)
                    except KeyboardInterrupt:
                        # A requested stop is part of the manual session, not
                        # an automated test result. Rust must remove its realm.
                        signal.signal(signal.SIGTERM, signal.SIG_IGN)
                        signal.signal(signal.SIGINT, signal.SIG_IGN)
                        record["demo_stop_reason"] = "LOCAL_SIGNAL"
                        request_demo_stop(evidence)
                        exit_code = child.wait(timeout=45)
                else:
                    exit_code = child.wait(timeout=timeout)
            output = path.read_bytes()
            row = {"name": check_name, "exit_code": exit_code,
                   "seconds": round(time.monotonic() - start, 3), "log": str(path),
                   "log_sha256": hashlib.sha256(output).hexdigest()}
            if check_name == "browser":
                summaries = re.findall(rb"test result: ok\. (\d+) passed; 0 failed; 0 ignored;", output)
                row["exact_one_test"] = summaries == [b"1"]
                row["automation_marker"] = output.count(MARKER) == 1
                row["notification_marker"] = output.count(NOTIFICATION_MARKER) == 1
            if check_name == "manual-demo":
                summaries = re.findall(rb"test result: ok\. (\d+) passed; 0 failed; 0 ignored;", output)
                row["exact_one_test"] = summaries == [b"1"]
                row["demo_stopped_marker"] = output.count(MANUAL_MARKER) == 1
                row["acceptance"] = False
            helper.require(stop_child(child), "Owned child group cleanup unconfirmed")
            child = None
            record["checks"].append(row)
            helper.write_record(record_path, record)
            print(json.dumps(row), flush=True)
            helper.require(exit_code == 0 and row.get("exact_one_test", True)
                           and row.get("automation_marker", True) and row.get("notification_marker", True)
                           and row.get("demo_stopped_marker", True),
                           "Actual browser acceptance failed")
            if check_name == "console-build":
                record["console_artifacts"] = console_artifacts(root, helper)
                helper.write_record(record_path, record)
        stage = "final_ledger"
        psql_env["PGDATABASE"] = database
        ledger = json.loads(fixture.invoke(command, env=psql_env, text="SELECT jsonb_agg(jsonb_build_object('version',version,'success',success,'checksum',encode(checksum,'hex')) ORDER BY version) FROM _sqlx_migrations;"))
        expected = [{"version": int(path.name.split("_", 1)[0]), "success": True,
                     "checksum": hashlib.sha384(path.read_bytes()).hexdigest()}
                    for path in sorted((root / "migrations").glob("*.sql"))]
        helper.require([row["version"] for row in expected] == list(range(1, 38)) + [39, 40, 41, 42, 43]
                       and ledger == expected, "Normal ledger checksums must match without unused 0038")
        record["migration_ledger"] = ledger
        stage = "source_binding"
        helper.recheck(root, rows)
        record["public_source_unchanged"] = True
        helper.require({name: hashlib.sha256(path.read_bytes()).hexdigest()
                        for name, path in artifacts.items()} == artifact_hashes,
                       "Ordinary artifacts changed during acceptance")
        record["artifacts_unchanged"] = True
        helper.require(console_artifacts(root, helper) == record["console_artifacts"],
                       "Compiled console artifacts changed during actual Chrome acceptance")
        record["console_artifacts_unchanged"] = True
        if args.manual_demo:
            helper.require(not (evidence / "demo-login.json").exists()
                           and not (evidence / "demo-login.json").is_symlink(),
                           "Manual demo must remove its private login credential")
            record["status"] = "DEMO_STOPPED_NOT_ACCEPTANCE"
        else:
            facts_path = evidence / "notification-facts.json"
            facts_bytes, facts_mode = helper.regular_read(facts_path, private=True)
            facts = json.loads(facts_bytes)
            helper.require(facts_mode == 0o600 and facts.get("business_facts_equal") is True
                           and facts.get("before_ack") == facts.get("after_ack_and_replay"),
                           "Private notification facts must prove unchanged full business rows")
            record["notification_facts"] = {"path": str(facts_path),
                                            "sha256": hashlib.sha256(facts_bytes).hexdigest(),
                                            "business_facts_equal": True}
            stage = "screenshot_evidence"
            record["screenshot_evidence"] = screenshot_evidence(evidence, helper)
            record["status"] = "PASS"
        stage = "completed"
    except BaseException:
        record["status"] = "FAIL"
        record["failed_stage"] = stage
        # Credential-bearing setup output remains private/suppressed. Actual
        # browser/assertion diagnostics are available in the owned test log.
    finally:
        cleanup_errors = []
        try:
            if args.manual_demo:
                record["owned_process_cleanup_confirmed"] = stop_manual_child(child, evidence)
            else:
                record["owned_process_cleanup_confirmed"] = stop_child(child)
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            record["owned_process_cleanup_confirmed"] = False
        if not record["owned_process_cleanup_confirmed"]:
            cleanup_errors.append("OWNED_PROCESS_CLEANUP_UNCONFIRMED")
        try:
            record["fixture_cleanup_confirmed"] = not startup_attempted or remove_fixture(docker, docker_env, name, fixture)
        except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired):
            record["fixture_cleanup_confirmed"] = False
        if not record["fixture_cleanup_confirmed"]:
            cleanup_errors.append("OWNED_FIXTURE_CLEANUP_UNCONFIRMED")
        record["cleanup_errors"] = cleanup_errors
        if cleanup_errors:
            record["status"] = "FAIL"
        helper.write_record(record_path, record)
    print(json.dumps({"record": str(record_path), "status": record["status"],
                      "source_sha256": source_sha}), flush=True)
    return 0 if record["status"] in ("PASS", "DEMO_STOPPED_NOT_ACCEPTANCE") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        raise SystemExit("Local console acceptance failed; private command/environment output suppressed") from None
