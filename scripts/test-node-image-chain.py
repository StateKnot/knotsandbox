#!/usr/bin/env python3
"""One owned native CRI/mTLS/dual-Agent/receiver/operator chain; no cloud certification."""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from node_image_chain_native import CONTRACT, owned_native
from node_image_chain_postgres import owned_postgres
from node_image_chain_prometheus import owned_pipeline

CASE = "native_chain::native_image_pipeline_to_operator_and_admin_is_revocable"
READY = "OPERATOR_IMAGE_CHAIN_READY "
COMPLETE = "OPERATOR_IMAGE_CHAIN_COMPLETE"
MAX_LOG = 8 * 1024 * 1024


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_FIXTURE_JSON_KEY")
        result[key] = value
    return result


def regular(path, limit):
    path = CONTRACT.regular(path)
    info = path.stat()
    require(info.st_uid == os.getuid() and info.st_size <= limit, "OWNED_BOUNDED_INPUT_REQUIRED")
    return path


def private_json(path, value, bound=64 * 1024):
    """Publish a complete private file without replacing an existing receipt."""
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    require(len(data) <= bound, "PRIVATE_JSON_BOUND")
    temporary = path.parent / (".pending-" + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, path, follow_symlinks=False)
    finally:
        temporary.unlink(missing_ok=True)


def read_private(path, bound):
    regular(path, bound)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_uid == os.getuid() and info.st_size <= bound, "PRIVATE_IPC_FILE_REQUIRED")
        data = source.read(bound + 1)
    require(len(data) <= bound, "PRIVATE_IPC_BODY_BOUND")
    return json.loads(data, object_pairs_hook=unique)


def disk_state():
    result = subprocess.run(["df", "-Pk", str(ROOT)], capture_output=True, text=True, timeout=10)
    require(result.returncode == 0 and len(result.stdout.splitlines()) >= 2, "ACTUAL_DF_FAILED")
    available = int(result.stdout.splitlines()[-1].split()[3]) * 1024
    return {"available_bytes": available, "df": result.stdout.strip()}


def source_state():
    sources = CONTRACT.source_fingerprints()
    # The pipeline generator and its locked public inputs are executable inputs
    # even though they are outside the original native compiler-input tree.
    for path in sorted((ROOT / "deploy/observability").rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            path = CONTRACT.regular(path)
            sources[str(path.relative_to(ROOT))] = {"sha256": CONTRACT.digest(path), "mode": path.stat().st_mode & 0o777}
    return sources


def retained_caches(binaries, native_artifacts):
    roots = {binaries["operator_access"].parent.parent.parent}
    native_artifacts = regular(native_artifacts, 32 * 1024 * 1024)
    for line in native_artifacts.read_text().splitlines():
        if not line.strip():
            continue
        item = json.loads(line, object_pairs_hook=unique)
        if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("kind") == ["lib"] and item.get("profile", {}).get("test") is True and item.get("executable"):
            roots.add(regular(item["executable"], 512 * 1024 * 1024).parent.parent.parent)
    result = []
    for root in sorted(roots):
        measured = subprocess.run(["du", "-sk", str(root)], capture_output=True, text=True, timeout=30)
        require(measured.returncode == 0, "RETAINED_CACHE_MEASUREMENT_FAILED")
        size = int(measured.stdout.split()[0]) * 1024
        result.append({"path": str(root), "measured_bytes": size, "cargo_cachedir_tag_present": (root / "CACHEDIR.TAG").is_file(),
                       "purpose": "Exact prebuilt native or host test/CLI artifacts remain in use; no compiler or copied target directory.",
                       "over_20gib_assessment": "Active verification artifacts are retained; no new compilation cache is created and no active target is removed." if size > 20 * 1024**3 else None})
    return result


def operator_artifacts(path, environment):
    path = regular(path, 32 * 1024 * 1024)
    messages = [json.loads(line, object_pairs_hook=unique) for line in path.read_text().splitlines() if line.strip()]
    metadata = subprocess.run(["cargo", "metadata", "--locked", "--offline", "--no-deps", "--format-version=1"],
                              cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30)
    require(metadata.returncode == 0, "ORDINARY_CARGO_METADATA_REQUIRED")
    metadata = json.loads(metadata.stdout)
    require(metadata["workspace_root"] == str(ROOT), "OPERATOR_WORKSPACE_MISMATCH")
    manifest = str(ROOT / "Cargo.toml")
    packages = [package for package in metadata["packages"] if package["name"] == "sandbox-platform" and package["manifest_path"] == manifest]
    require(len(packages) == 1, "UNIQUE_OPERATOR_PACKAGE_REQUIRED")
    package = packages[0]
    selected = {}
    for name, kind, tested, source in [("operator_access", ["test"], True, ROOT / "tests/operator_access.rs"),
                                       ("sandbox-admin", ["bin"], False, ROOT / "src/bin/sandbox-admin.rs")]:
        require(sum(target["name"] == name and target["kind"] == kind and target["src_path"] == str(source)
                    for target in package["targets"]) == 1, "EXACT_OPERATOR_TARGET_REQUIRED")
        candidates = [item for item in messages if item.get("reason") == "compiler-artifact" and item.get("executable")
                      and item.get("target", {}).get("name") == name and item.get("target", {}).get("kind") == kind
                      and item.get("profile", {}).get("test") is tested]
        require(len(candidates) == 1, "UNIQUE_OPERATOR_EXECUTABLE_REQUIRED_" + name)
        item = candidates[0]
        require(item.get("package_id") == package["id"] and item.get("manifest_path") == manifest
                and item["target"]["src_path"] == str(source), "EXACT_OPERATOR_COMPILER_ARTIFACT_REQUIRED")
        binary = regular(item["executable"], 512 * 1024 * 1024)
        info = binary.stat()
        require(info.st_mode & 0o111 and not info.st_mode & 0o022, "ORDINARY_OPERATOR_BINARY_MODE_REQUIRED")
        selected[name] = binary
    test, cli = selected["operator_access"], selected["sandbox-admin"]
    require(test.parent.name == "deps" and test.parent.parent.name == "debug"
            and re.fullmatch(r"operator_access-[0-9a-f]{16}", test.name)
            and cli == test.parent.parent / "sandbox-admin", "SAME_OPERATOR_TEST_AND_COMPILED_CLI_TARGET_REQUIRED")
    listing = subprocess.run([str(test), "--list", "--ignored", "--exact", CASE], cwd=ROOT,
                             env=environment, capture_output=True, text=True, timeout=10)
    require(listing.returncode == 0 and listing.stdout.splitlines().count(CASE + ": test") == 1,
            "EXACT_NATIVE_OPERATOR_IGNORED_CASE_REQUIRED")
    return selected


def generate_pki(work):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    pki, chain = work / "pki", work / "chain"
    pki.mkdir(mode=0o700)
    chain.mkdir(mode=0o700)
    identity = {"epoch": str(uuid.uuid4()), "node_uid": str(uuid.uuid4())}
    now = dt.datetime.now(dt.timezone.utc)

    def issue(name, *, issuer=None, issuer_key=None, sans=None, client=False):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PUBLIC native chain " + name)])
        ca = issuer is None
        builder = (x509.CertificateBuilder().subject_name(subject)
                   .issuer_name(subject if ca else issuer.subject).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
                   .not_valid_after(now + dt.timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                       key_encipherment=not ca, data_encipherment=False, key_agreement=False,
                       key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), critical=True))
        if not ca:
            builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        if sans is not None:
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        return builder.sign(issuer_key or key, hashes.SHA256()), key

    server_ca, server_ca_key = issue("server root")
    scraper_ca, scraper_ca_key = issue("scraper root")
    server, server_key = issue("server", issuer=server_ca, issuer_key=server_ca_key, sans=[
        x509.DNSName("receiver"), x509.DNSName("native-chain"),
        x509.DNSName(identity["node_uid"] + ".nodeguard.sandbox.internal"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    client, client_key = issue("scraper", issuer=scraper_ca, issuer_key=scraper_ca_key, client=True)
    for filename, value in [("server-root.crt", server_ca), ("server.crt", server),
                            ("scraper-root.crt", scraper_ca), ("client.crt", client)]:
        path = pki / filename
        path.write_bytes(value.public_bytes(serialization.Encoding.PEM))
        path.chmod(0o600)
    for filename, value in [("server.key", server_key), ("client.key", client_key)]:
        path = pki / filename
        path.write_bytes(value.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
        path.chmod(0o600)
    private_json(chain / "identity.json", identity, 1024)
    for source, destination in [("server.crt", "server.pem"), ("server.key", "server.key"),
                                ("scraper-root.crt", "scraper-ca.pem"), ("server-root.crt", "server-ca.pem")]:
        path = chain / destination
        path.write_bytes((pki / source).read_bytes())
        path.chmod(0o600)
    return identity


class Operator:
    def __init__(self, binary, environment, work, deadline, receipt):
        self.work, self.deadline, self.receipt = work, deadline, receipt
        self.sequence = 0
        self.log = work / "operator-service.log"
        self.stream = self.log.open("xb")
        self.log.chmod(0o600)
        try:
            self.process = subprocess.Popen([str(binary), "--exact", CASE, "--ignored", "--nocapture", "--test-threads=1"],
                cwd=ROOT, env=environment, stdout=self.stream, stderr=subprocess.STDOUT,
                start_new_session=True)
        except BaseException:
            self.stream.close()
            raise
        receipt["operator_command"] = {"case": CASE, "log": self.log.name}

    def output(self):
        require(self.log.stat().st_size <= MAX_LOG, "OPERATOR_STDOUT_BOUND")
        return self.log.read_text(errors="replace")

    def wait(self, check):
        while time.monotonic() < self.deadline:
            self.output()
            value = check()
            if value is not None:
                return value
            require(self.process.poll() is None, "OPERATOR_PROCESS_EXITED_BEFORE_PHASE")
            time.sleep(0.02)
        raise RuntimeError("ORIGINAL_NATIVE_CHAIN_MAIN_BUDGET_EXPIRED")

    def ready(self):
        def check():
            rows = [line.split(READY, 1)[1] for line in self.output().splitlines(keepends=True) if READY in line and line.endswith("\n")]
            require(len(rows) <= 1, "UNIQUE_OPERATOR_READY_REQUIRED")
            if not rows:
                return None
            result = json.loads(rows[0], object_pairs_hook=unique)
            require(set(result) == {"runtime_node_id", "api_endpoint", "grant_id"}, "FIXED_OPERATOR_READY_FIELDS")
            for key in ("runtime_node_id", "grant_id"):
                require(str(uuid.UUID(result[key])) == result[key] and uuid.UUID(result[key]).int, "NON_NIL_OPERATOR_READY_UUID")
            require(re.fullmatch(r"https://127\.0\.0\.1:[0-9]+", result["api_endpoint"]), "OPERATOR_HTTPS_LOOPBACK_ONLY")
            return result
        self.receipt["operator_ready"] = self.wait(check)

    def request(self, pipeline, action):
        require(self.sequence < 8, "AT_MOST_EIGHT_OPERATOR_PHASES")
        self.sequence += 1
        private_json(pipeline.control / f"request-{self.sequence}.json", {"sequence": self.sequence, "action": action}, 512)
        response = pipeline.control / f"response-{self.sequence}.json"
        result = self.wait(lambda: read_private(response, 64 * 1024) if response.exists() else None)
        require(result.get("sequence") == self.sequence and result.get("action") == action, "MATCHED_OPERATOR_PHASE_RECEIPT")
        self.receipt.setdefault("operator_phases", []).append(result)
        if action == "REVOKE_INFLIGHT":
            require(result.get("errorCode") == "PERMISSION_DENIED" and "status" not in result, "REVOKED_OPERATOR_MUST_RETURN_NO_OLD_DATA")
        elif action == "STOP":
            require(result == {"sequence": self.sequence, "action": action, "status": None}, "EXACT_OPERATOR_STOP_RECEIPT")
        else:
            require("errorCode" not in result and isinstance(result.get("status"), dict) and isinstance(result.get("cli_status"), dict),
                    "HTTPS_AND_REAL_ADMIN_RECEIPTS_REQUIRED")
        return result

    def complete(self):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "ORIGINAL_NATIVE_CHAIN_MAIN_BUDGET_EXPIRED")
        require(self.process.wait(timeout=remaining) == 0, "OPERATOR_EXACT_CASE_FAILED")
        output = self.output()
        summaries = re.findall(r"(?m)^test result: (.+)$", output)
        require(len(summaries) == 1 and re.fullmatch(r"ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s", summaries[0]),
                "EXACT_ONE_OPERATOR_CASE_MUST_PASS")
        require(output.count(READY) == 1 and output.splitlines().count(COMPLETE) == 1, "OPERATOR_CHAIN_COMPLETE_REQUIRED")
        self.receipt["operator_completed"] = True

    def close(self, pipeline):
        errors = []
        if self.process.poll() is None:
            if self.sequence < 8:
                try:
                    private_json(pipeline.control / f"request-{self.sequence + 1}.json", {"sequence": self.sequence + 1, "action": "STOP"}, 512)
                except Exception as error:
                    errors.append(type(error).__name__ + ":" + str(error))
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process.wait(timeout=2)
                self.receipt["operator_forced_retirement"] = True
        self.stream.close()
        self.receipt.update(operator_exit_code=self.process.returncode, operator_retired=self.process.poll() is not None,
                            operator_log_sha256=CONTRACT.digest(self.log), operator_cleanup_errors=errors)
        require(not errors, "OPERATOR_CLEANUP_IPC_FAILURE")


def run(args, evidence, receipt):
    require(os.geteuid() != 0, "ORDINARY_CALLER_REQUIRED")
    require(not os.environ.get("RUST_MIN_STACK"), "THREAD_STACK_OVERRIDE_FORBIDDEN")
    require(Path.cwd().resolve() == ROOT, "REPOSITORY_WORKING_DIRECTORY_REQUIRED")
    before_sources = source_state()
    receipt["source_before"] = before_sources
    receipt["disk_before"] = disk_state()
    require(receipt["disk_before"]["available_bytes"] >= 2 * 1024**3, "BOUNDED_FIXTURE_DISK_HEADROOM_REQUIRED")
    if receipt["disk_before"]["available_bytes"] < 50 * 1024**3:
        receipt["below_50gb_assessment"] = "No compilation or target copy; only bounded exact artifacts and an owned COPY-only runtime image. Owned image/data are removed; active build caches and unrelated volumes are retained."
    automation = CONTRACT.module("native_chain_main_automation", ROOT / "scripts/test-automation.py")
    docker, environment = automation.local_docker()
    binaries = operator_artifacts(args.operator_artifacts, environment)
    before_binaries = {name: CONTRACT.fingerprint(path) for name, path in binaries.items()}
    receipt["operator_binaries_before"] = before_binaries
    receipt["retained_caches"] = retained_caches(binaries, args.native_artifacts)
    receipt["operator_artifacts_sha256"] = CONTRACT.digest(args.operator_artifacts)
    work = evidence / "work"
    work.mkdir(mode=0o700)
    receipt["public_fixture_identity"] = generate_pki(work)
    try:
        with owned_postgres(evidence, args.identity_env_file) as (child_env, pg_receipt):
            receipt["postgres"] = pg_receipt
            with owned_native(args, work, docker, environment, receipt.setdefault("native", {})) as native:
                deadline = native.started_at + 160
                with owned_pipeline(native, work, docker, environment, receipt.setdefault("pipeline", {})) as pipeline:
                    operator = None
                    try:
                        pipeline.wait_state("FRESH", deadline)
                        fixture_path = work / "operator-fixture.json"
                        private_json(fixture_path, {"backend": pipeline.backend, "node": native.node,
                            "expected_compressed_logical_bytes": native.expected_compressed_logical_bytes,
                            "control_directory": str(pipeline.control.resolve())}, 16 * 1024)
                        require("RUST_MIN_STACK" not in child_env, "CHILD_THREAD_STACK_OVERRIDE_FORBIDDEN")
                        child_env["SANDBOX_NATIVE_OPERATOR_FIXTURE"] = str(fixture_path.resolve())
                        operator = Operator(binaries["operator_access"], child_env, work, deadline, receipt)
                        operator.ready()
                        operator.request(pipeline, "FRESH")
                        native.pause_runtime()
                        pipeline.wait_state("RPC_FAILURE", deadline)
                        operator.request(pipeline, "UNKNOWN")
                        native.resume_runtime()
                        pipeline.wait_state("FRESH", deadline)
                        operator.request(pipeline, "FRESH")
                        native.pause_transport()
                        pipeline.wait_state("TRANSPORT_FAILURE", deadline)
                        operator.request(pipeline, "UNKNOWN")
                        native.resume_transport()
                        pipeline.wait_state("FRESH", deadline)
                        operator.request(pipeline, "FRESH")
                        pipeline.hold.set()
                        operator.request(pipeline, "REVOKE_INFLIGHT")
                        operator.request(pipeline, "REGRANT_FRESH")
                        operator.request(pipeline, "STOP")
                        operator.complete()
                        require(not pipeline.proxy_errors, "REAL_QUERY_PROXY_FAILURE_RECORDED")
                        receipt["native_main_seconds"] = round(time.monotonic() - native.started_at, 3)
                    finally:
                        cleanup_errors = []
                        for action in (native.resume_transport, native.resume_runtime):
                            try:
                                action()
                            except Exception as error:
                                cleanup_errors.append(type(error).__name__ + ":" + str(error))
                        try:
                            release = pipeline.control / "query-release"
                            if not release.exists():
                                fd = os.open(release, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                                os.close(fd)
                        except Exception as error:
                            cleanup_errors.append(type(error).__name__ + ":" + str(error))
                        if operator is not None:
                            try:
                                operator.close(pipeline)
                            except Exception as error:
                                cleanup_errors.append(type(error).__name__ + ":" + str(error))
                        receipt["main_cleanup_errors"] = cleanup_errors
                        require(not cleanup_errors, "MAIN_OWNED_CLEANUP_FAILED")
    finally:
        after_sources = source_state()
        receipt["source_after_sha256"] = hashlib.sha256(json.dumps(after_sources, sort_keys=True).encode()).hexdigest()
        receipt["source_unchanged"] = after_sources == before_sources
        receipt["operator_binaries_after"] = {name: CONTRACT.fingerprint(path) for name, path in binaries.items()}
        receipt["operator_binaries_unchanged"] = receipt["operator_binaries_after"] == before_binaries
        receipt["operator_artifacts_unchanged"] = CONTRACT.digest(args.operator_artifacts) == receipt["operator_artifacts_sha256"]
        receipt["disk_after"] = disk_state()
        receipt["actual_available_change_bytes"] = receipt["disk_after"]["available_bytes"] - receipt["disk_before"]["available_bytes"]
        require(receipt["source_unchanged"] and receipt["operator_binaries_unchanged"] and receipt["operator_artifacts_unchanged"], "EXACT_CHAIN_INPUTS_CHANGED")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-artifacts", type=Path, required=True)
    parser.add_argument("--operator-artifacts", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--containerd-archive", type=Path)
    parser.add_argument("--containerd-checksum", type=Path)
    parser.add_argument("--identity-env-file", type=Path)
    args = parser.parse_args()
    require(bool(args.containerd_archive) == bool(args.containerd_checksum), "ARCHIVE_AND_CHECKSUM_TOGETHER_REQUIRED")
    evidence = args.evidence_dir.absolute()
    require(".." not in evidence.parts, "EVIDENCE_PARENT_TRAVERSAL_FORBIDDEN")
    for ancestor in evidence.parents:
        if ancestor.exists():
            require(not ancestor.is_symlink(), "EVIDENCE_SYMLINK_ANCESTOR_FORBIDDEN")
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    evidence = evidence.resolve(strict=True)
    receipt = {"status": "FAIL", "scope": "same native CRI to mTLS to dual Agent remote-write to receiver to installation API and admin",
               "started_at": dt.datetime.now(dt.timezone.utc).isoformat(), "cloud_kata_gpu_certified": False}
    try:
        run(args, evidence, receipt)
        receipt["status"] = "PASS"
    except BaseException as error:
        receipt["failure"] = {"type": type(error).__name__, "message": str(error),
                              "chain": [{"type": type(item).__name__, "message": str(item)} for item in exception_chain(error)]}
    finally:
        receipt["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        diagnostic = evidence / "postgres/fixture-diagnostic.json"
        if "postgres" not in receipt and diagnostic.is_file():
            receipt["postgres"] = read_private(diagnostic, 256 * 1024)
        private_json(evidence / "record.json", receipt, 2 * 1024 * 1024)
    print(json.dumps({"status": receipt["status"], "evidence": str(evidence), "failure": receipt.get("failure")}, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


def exception_chain(error):
    seen = {id(error)}
    while error.__cause__ is not None or error.__context__ is not None:
        error = error.__cause__ or error.__context__
        if id(error) in seen:
            return
        seen.add(id(error))
        yield error


if __name__ == "__main__":
    raise SystemExit(main())
