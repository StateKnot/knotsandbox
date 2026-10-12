#!/usr/bin/env python3
"""Real component pool or sandboxd process drain; local private inputs, no DROP.

Run from the repository after root integrates/reviews the lifecycle helper and
this test. This driver never applies an unreviewed overlay or creates logins.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from urllib.parse import urlsplit, urlunsplit, unquote

URL_ROLES = {
    "TEST_DATABASE_URL": "sandbox_app",
    "TEST_MIGRATION_DATABASE_URL": "sandbox_owner",
    "TEST_WORKER_DATABASE_URL": "sandbox_worker",
    "TEST_GATEWAY_DATABASE_URL": "sandbox_gateway",
    "TEST_ADMISSION_DATABASE_URL": "sandbox_admission",
    "TEST_TERMINATION_DATABASE_URL": "sandbox_termination",
    "TEST_FENCING_DATABASE_URL": "sandbox_fencing",
    "TEST_VOLUME_DELETER_DATABASE_URL": "sandbox_volume_deleter",
    "TEST_BACKUP_DATABASE_URL": "sandbox_backup",
}
TEST = "actual_component_shutdown_drains_real_pg_leases_and_joins_paired_parents"
MATRIX_MARKER = "lifecycle actual 8 authenticated normal-ledger roles / 32 physical drain trials completed"
PROCESS_TEST = "sandboxd_startup_error_and_sigterm_finish_database_drain"
PROCESS_MARKER = "lifecycle actual sandboxd postconnect startup error and API SIGTERM / physical backend absence completed"
BFF_MARKER = "lifecycle actual BFF ready, in-flight SQL SIGTERM, SQL error continuation and owned bind failure / four process trials completed"
SUMMARY = "test result: ok. 1 passed; 0 failed; 0 ignored;"
MAX_BYTES = 1024 * 1024


class Rejected(Exception):
    """Fixed nonsecret protocol failure only."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Rejected(message)


def regular_read(path: Path, *, private: bool = False) -> tuple[bytes, int]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), "Input is not a regular file")
        if private:
            require(before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o600,
                    "Private environment must be owned by this user with exact mode 0600")
            require(0 < before.st_size <= MAX_BYTES, "Private environment size invalid")
        chunks = []
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            require(not private or total <= MAX_BYTES, "Private environment exceeded size bound")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        named = path.lstat()
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_mode)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode)
                and (named.st_dev, named.st_ino) == (after.st_dev, after.st_ino),
                "Input changed during fixed-FD read")
        return b"".join(chunks), stat.S_IMODE(after.st_mode)
    finally:
        os.close(descriptor)


def private_urls(path: Path) -> dict[str, str]:
    require(not path.parent.is_symlink(), "Private environment directory cannot be a symlink")
    raw, _ = regular_read(path, private=True)
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise Rejected("Private environment must be UTF-8") from None
    values = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        require("=" in line, "Private environment requires literal KEY=value lines")
        key, value = line.split("=", 1)
        require(re.fullmatch(r"[A-Z][A-Z0-9_]*", key) is not None and key not in values,
                "Private environment key invalid or duplicated")
        # No shell sourcing/expansion/quotes; URLs are parsed as literal values.
        require(not any(c in value for c in "\x00\r\n"), "Private environment value invalid")
        values[key] = value
    endpoint = None
    urls = {}
    for key, expected in URL_ROLES.items():
        value = values.get(key, "")
        try:
            parsed = urlsplit(value)
            host = parsed.hostname or ""
            address = ipaddress.ip_address(host)
            port = parsed.port or 5432
            user = unquote(parsed.username or "")
            password = parsed.password
        except (ValueError, TypeError):
            raise Rejected("Component URL syntax or literal loopback host invalid") from None
        require(parsed.scheme in ("postgres", "postgresql") and address.is_loopback
                and user == expected and password is not None and bool(password)
                and not parsed.query and not parsed.fragment
                and re.fullmatch(r"/[A-Za-z0-9_]+_test", parsed.path) is not None,
                "Component URL role, database, credentials, or query invalid")
        current = (address, port, parsed.path)
        if endpoint is None:
            endpoint = current
        require(current == endpoint, "Component URLs must share one literal loopback endpoint/database")
        urls[key] = value
    return urls


def git_files(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root, capture_output=True, check=True,
    )
    files = sorted(set(name.decode("utf-8") for name in result.stdout.split(b"\0") if name))
    require(bool(files), "Public Git source list is empty")
    for name in files:
        relative = Path(name)
        require(not relative.is_absolute() and ".." not in relative.parts
                and relative.parts[0] not in (".git", ".local")
                and not any(part == ".env" or part.startswith(".env.")
                            and part != ".env.example" for part in relative.parts),
                "Public source path is unsafe/private")
    require("tests/service_lifecycle.rs" in files and "src/service_lifecycle.rs" in files
            and "tests/service_lifecycle_process.rs" in files,
            "Root must integrate reviewed lifecycle helper and test before this runner")
    return files


def digest(rows: list[dict]) -> str:
    aggregate = hashlib.sha256()
    for row in rows:
        aggregate.update(row["path"].encode() + b"\0")
        aggregate.update(row["mode"].to_bytes(4, "big"))
        aggregate.update(bytes.fromhex(row["sha256"]))
    return aggregate.hexdigest()


def capture(root: Path, snapshot: Path) -> tuple[list[dict], str]:
    names = git_files(root)
    rows = []
    snapshot.mkdir(mode=0o700)
    for name in names:
        source = root / name
        payload, mode = regular_read(source)
        public_test_keys = {
            "tests/fixtures/auth/rsa-a.der", "tests/fixtures/auth/rsa-b.der",
            "tests/fixtures/nodeguard/client.key", "tests/fixtures/nodeguard/server.key",
        }
        require(mode in (0o644, 0o755) or mode == 0o600 and name in public_test_keys,
                "Public source mode is not the regular/executable or fixed public-test-key contract")
        # Reject ancestor symlinks as well as the final opened file.
        require(not any(parent.is_symlink() for parent in source.parents if parent != root.parent),
                "Public source ancestor is a symlink")
        target = snapshot / name
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(payload)
                stream.flush()
            os.fchmod(descriptor, mode)
        finally:
            os.close(descriptor)
        checksum = hashlib.sha256(payload).hexdigest()
        recheck, final_mode = regular_read(source)
        stored, stored_mode = regular_read(target)
        require(hashlib.sha256(recheck).hexdigest() == checksum and final_mode == mode
                and hashlib.sha256(stored).hexdigest() == checksum and stored_mode == mode,
                "Public source bytes/mode changed while capturing")
        rows.append({"path": name, "sha256": checksum, "mode": mode})
    actual = sorted(str(path.relative_to(snapshot)) for path in snapshot.rglob("*") if path.is_file())
    require(actual == names, "Snapshot has missing or extra files")
    require(git_files(root) == names, "Public source inventory changed while capturing")
    return rows, digest(rows)


def recheck(root: Path, rows: list[dict]) -> None:
    require(git_files(root) == [row["path"] for row in rows], "Public source inventory changed during actual run")
    for row in rows:
        data, mode = regular_read(root / row["path"])
        require(hashlib.sha256(data).hexdigest() == row["sha256"] and mode == row["mode"],
                "Public source changed during actual run")


def classify_output(exit_code: int, log_bytes: bytes, *, test: str = TEST,
                    marker: str = MATRIX_MARKER) -> tuple[bool, bool, bool]:
    lines = log_bytes.decode("utf-8", errors="replace").splitlines()
    summary_present = any(line.startswith(SUMMARY) for line in lines)
    marker_present = marker in lines or f"test {test} ... {marker}" in lines
    return exit_code == 0 and summary_present and marker_present, summary_present, marker_present


def write_record(path: Path, record: dict) -> None:
    path.write_text(json.dumps(record, indent=2) + "\n")
    os.chmod(path, 0o600)


def local_docker_host(host: str | None) -> str:
    require(bool(host) and host.startswith("unix://") and Path(host[7:]).is_absolute(),
            "An explicit RESTORE_TEST_DOCKER_HOST local absolute Unix socket is required")
    return host


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--suite", choices=("roles", "process"), default="roles")
    args = parser.parse_args()
    if args.suite == "roles":
        test, target, marker = TEST, "service_lifecycle", MATRIX_MARKER
        scope = "8 authenticated component roles / 32 actual borrowed-backend drain trials"
    else:
        test, target, marker = PROCESS_TEST, "service_lifecycle_process", PROCESS_MARKER
        scope = "actual sandboxd postconnect startup error and API SIGTERM plus four BFF process trials: ready SIGTERM, in-flight SQL SIGTERM, SQL error continuation and owned bind error; fresh transaction backend absence; explicit local HTTP/OIDC fixtures, not deployed cloud/PKI/runtime/capacity"
    root = args.root.resolve(strict=True)
    expected_env = root / ".local/restore-test.env"
    env_path = args.env_file or expected_env
    require(env_path.absolute() == expected_env, "Only the explicit project .local/restore-test.env is accepted")
    require(not any(os.environ.get(key) for key in
                    ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUST_MIN_STACK", "RUST_TEST_THREADS")),
            "No compiler, stack, or test-thread override is allowed")
    urls = private_urls(env_path)
    nonce = str(time.time_ns())
    database = "sandbox_service_lifecycle_" + nonce + "_test"
    evidence = root / ".local/evidence/service-lifecycle" / nonce
    evidence.mkdir(parents=True, mode=0o700)
    os.chmod(evidence, 0o700)
    snapshot = evidence / "source"
    rows, source_sha = capture(root, snapshot)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                          capture_output=True, text=True).stdout.strip()
    require(re.fullmatch(r"[0-9a-f]{40}", head) is not None, "Git commit identity invalid")
    write_record(evidence / "source-manifest.json", {"git_head": head, "source_sha256": source_sha, "files": rows})
    record = {"test": test, "database": database, "source_sha256": source_sha,
              "source_manifest": str(evidence / "source-manifest.json"),
              "snapshot": str(snapshot), "status": "PREPARED_NOT_EXECUTED",
              "suite": args.suite, "scope": scope}
    write_record(evidence / "record.json", record)
    docker = ["docker"]
    config = os.environ.get("RESTORE_TEST_DOCKER_CONFIG")
    host = local_docker_host(os.environ.get("RESTORE_TEST_DOCKER_HOST"))
    if config:
        require(Path(config).is_absolute(), "Docker configuration path must be absolute")
        docker += ["--config", config]
    docker += ["--host", host]
    docker_env = {key: value for key, value in os.environ.items()
                  if key not in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS",
                                 "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")}
    container = os.environ.get("RESTORE_TEST_PG_CONTAINER", "sandbox-platform-dev-postgres-1")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", container) is not None,
            "Local PostgreSQL container identity invalid")
    # Only fixed role names and generated database identifier enter SQL. Existing
    # LOGIN passwords/memberships are not read or changed. No DROP is performed.
    sql = (f'CREATE DATABASE "{database}" OWNER sandbox_owner;\n'
           f'REVOKE ALL ON DATABASE "{database}" FROM PUBLIC;\n'
           f'GRANT CONNECT ON DATABASE "{database}" TO '
           + ",".join(URL_ROLES.values()) + ";\n")
    created = subprocess.run(docker + ["exec", "-i", container, "psql", "-X",
                             "-v", "ON_ERROR_STOP=1", "-U", "sandbox_dev_admin", "-d", "postgres"],
                             input=sql, text=True, capture_output=True, timeout=30, env=docker_env)
    if created.returncode:
        record["status"] = "DATABASE_PREPARATION_FAILED"
        write_record(evidence / "record.json", record)
        raise Rejected("Fresh local database preparation failed; provider/SQL output suppressed")
    record["status"] = "DATABASE_CREATED_NO_DROP"
    write_record(evidence / "record.json", record)
    child_env = {key: value for key, value in os.environ.items()
                 if not key.startswith("SANDBOX_")}
    for key, raw in urls.items():
        parsed = urlsplit(raw)
        child_env[key] = urlunsplit((parsed.scheme, parsed.netloc, "/" + database, "", ""))
    child_env["CARGO_INCREMENTAL"] = "0"
    child_env["CARGO_TARGET_DIR"] = str(root / "target")
    command = ["cargo", "test", "--locked", "--offline", "--test", target, test,
               "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"]
    log_path = evidence / "actual.log"
    with log_path.open("xb") as log:
        os.chmod(log_path, 0o600)
        log.write((json.dumps({"test": test, "database": database, "source_sha256": source_sha,
                               "scope": record["scope"]}) + "\n").encode())
        log.flush()
        result = subprocess.run(command, cwd=snapshot, env=child_env,
                                stdout=log, stderr=subprocess.STDOUT)
    log_bytes = log_path.read_bytes()
    passed, summary_present, marker_present = classify_output(
        result.returncode, log_bytes, test=test, marker=marker)
    bff_marker_present = None
    if args.suite == "process":
        bff_passed, _, bff_marker_present = classify_output(
            result.returncode, log_bytes, test=test, marker=BFF_MARKER)
        passed = passed and bff_passed
    status = "PASS" if passed else ("EXACT_TEST_OR_MATRIX_MARKER_MISSING"
             if result.returncode == 0 else "FAIL")
    record.update({"exit_code": result.returncode, "status": status,
                   "exact_one_test_summary_present": summary_present,
                   "completion_marker_present": marker_present,
                   "log": str(log_path), "log_sha256": hashlib.sha256(log_bytes).hexdigest()})
    if args.suite == "roles":
        record["complete_eight_role_matrix_marker_present"] = marker_present
    else:
        record["complete_four_bff_trials_marker_present"] = bff_marker_present
    try:
        recheck(root, rows)
        record["public_source_after_equals_before"] = True
    except Rejected:
        record["public_source_after_equals_before"] = False
        record["status"] = "SOURCE_CHANGED_NOT_CERTIFIED"
        write_record(evidence / "record.json", record)
        raise
    write_record(evidence / "record.json", record)
    print(json.dumps({"record": str(evidence / "record.json"), "status": record["status"],
                      "source_sha256": source_sha, "exit_code": result.returncode}))
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Rejected as error:
        raise SystemExit(str(error)) from None
    except (OSError, UnicodeError, subprocess.SubprocessError):
        raise SystemExit("Local lifecycle runner failed; raw command/environment output suppressed") from None
