#!/usr/bin/env python3
"""Exact ordinary Linux Cargo test in an owned, resource-limited local container.

Only the compiled test binary is mounted. No host PID namespace, writable
cgroup mount, daemon socket, source, credentials or existing volume is exposed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
CASE = "nodeguard::host::linux::kernel_tests::actual_kernel_cgroup_capacity_uses_trusted_full_hierarchy"
MARKER = "NODEGUARD_TRUSTED_CAPACITY_REAL_KERNEL_VERIFIED"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def run(args):
    host = module("host_acceptance", ROOT / "scripts/test-nodeguard-host-observation.py")
    fixture = module("automation_fixture", ROOT / "scripts/test-automation.py")
    host.require(sys.platform == "linux" and os.geteuid() != 0, "ORDINARY_LINUX_CALLER_REQUIRED")
    host.require(Path.cwd().resolve() == ROOT, "REPOSITORY_WORKING_DIRECTORY_REQUIRED")
    artifacts = host.absolute_regular(args.artifacts.absolute())
    host.require(artifacts.stat().st_size <= 32 * 1024 * 1024, "CARGO_MESSAGES_TOO_LARGE")
    messages = [json.loads(line) for line in artifacts.read_text().splitlines() if line.strip()]
    metadata = subprocess.run(["cargo", "metadata", "--locked", "--offline", "--no-deps", "--format-version=1"], cwd=ROOT, capture_output=True, text=True, timeout=30)
    host.require(metadata.returncode == 0, "ORDINARY_CARGO_METADATA_FAILED")
    binary, target = host.select_artifact(messages, json.loads(metadata.stdout))
    before = hashlib.sha256(binary.read_bytes()).hexdigest()
    listing = subprocess.run([str(binary), "--list", "--ignored", "--exact", CASE], capture_output=True, text=True, timeout=30)
    host.require(listing.returncode == 0 and listing.stdout.splitlines().count(CASE + ": test") == 1, "EXACT_CAPACITY_TEST_REQUIRED")
    image = re.search(r"^ARG RUNTIME_IMAGE=(debian:trixie-slim@sha256:[0-9a-f]{64})$", (ROOT / "Dockerfile").read_text(), re.MULTILINE)
    host.require(image is not None, "PINNED_RUNTIME_IMAGE_REQUIRED")
    docker, environment = fixture.local_docker()
    requested_evidence = args.evidence_dir.absolute()
    host.require(not any(path.is_symlink() for path in (requested_evidence, *requested_evidence.parents)), "EVIDENCE_SYMLINK_FORBIDDEN")
    evidence = requested_evidence.resolve()
    host.require(evidence != target and target not in evidence.parents, "EVIDENCE_MUST_BE_OUTSIDE_CARGO_CACHE")
    fixture.private_directory(evidence)
    name = "sandbox-capacity-" + uuid.uuid4().hex
    label = "com.sandbox.fixture=nodeguard-capacity"
    create_attempted = False
    identity = None
    cleanup = False
    passed = False
    code = None
    primary_failure = None
    cleanup_failures = []
    try:
        # create gives ownership before a possibly interrupted start/attach.
        create_attempted = True
        identity = fixture.invoke([*docker, "create", "--name", name, "--label", label,
            "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--cgroupns", "host", "--cpus", "0.75", "--memory", "268435456", "--memory-swap", "268435456", "--pids-limit", "64",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--mount", "type=bind,src=" + str(binary) + ",dst=/capacity-test,readonly",
            "--entrypoint", "/capacity-test", image.group(1), "--exact", CASE, "--ignored", "--test-threads=1", "--nocapture"], env=environment, timeout=120)
        host.require(re.fullmatch(r"[0-9a-f]{64}", identity) is not None, "OWNED_CONTAINER_ID_REQUIRED")
        inspection = json.loads(fixture.invoke([*docker, "inspect", name], env=environment))[0]
        host.require(inspection["Id"] == identity and inspection["Config"]["Labels"].get("com.sandbox.fixture") == "nodeguard-capacity", "OWNED_CONTAINER_MISMATCH")
        settings = inspection["HostConfig"]
        host.require(settings["NanoCpus"] == 750000000 and settings["Memory"] == 268435456 and settings["CgroupnsMode"] == "host" and settings["ReadonlyRootfs"] and not settings["Privileged"] and settings["PidMode"] != "host", "RESOURCE_BOUND_OR_ISOLATION_CHANGED")
        result = subprocess.run([*docker, "start", "--attach", name], env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
        log = evidence / "capacity.log"
        with log.open("xb") as stream:
            os.chmod(log, 0o600)
            stream.write(result.stdout)
        code = result.returncode
        text = result.stdout.decode("utf-8", errors="replace")
        host.require(code == 0 and re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", text) is not None and text.count(MARKER) == 1, "EXACT_REAL_CAPACITY_TEST_FAILED")
        host.require(hashlib.sha256(binary.read_bytes()).hexdigest() == before, "CARGO_ARTIFACT_CHANGED")
        passed = True
    except Exception:
        primary_failure = "CAPACITY_ACCEPTANCE_FAILED"
    finally:
        if create_attempted:
            try:
                inspected = subprocess.run([*docker, "inspect", name], env=environment, capture_output=True, timeout=30)
                if inspected.returncode == 0:
                    inspection = json.loads(inspected.stdout)[0]
                    actual_id = inspection["Id"]
                    host.require(re.fullmatch(r"[0-9a-f]{64}", actual_id) is not None and (identity is None or identity == actual_id) and inspection["Name"] == "/" + name and inspection["Config"]["Labels"].get("com.sandbox.fixture") == "nodeguard-capacity" and inspection["Config"]["Image"] == image.group(1), "OWNED_CONTAINER_MISMATCH")
                    # Recover ownership by exact random name, label and image
                    # when create succeeded but the client lost its receipt.
                    fixture.invoke([*docker, "rm", "--force", actual_id], env=environment)
                    gone = subprocess.run([*docker, "inspect", actual_id], env=environment, capture_output=True, timeout=30)
                    cleanup = gone.returncode != 0 and b"No such" in gone.stderr
                elif identity is not None and b"No such" in inspected.stderr:
                    cleanup = True
                else:
                    # A timed-out creation with no ID is not proof that a late
                    # create cannot exist. Preserve the name for investigation.
                    cleanup_failures.append("OWNED_CREATION_OR_ABSENCE_UNCONFIRMED")
            except Exception:
                cleanup_failures.append("OWNED_CONTAINER_CLEANUP_UNCONFIRMED")
        fixture.private_json(evidence / "record.json", {"status": "PASS" if passed and cleanup and not cleanup_failures else "FAIL", "case": CASE, "exit_code": code, "primary_failure": primary_failure, "cleanup_failures": cleanup_failures, "owned_container_name": name, "binary_sha256": before, "image": image.group(1), "cpu_cores": 0.75, "memory_bytes": 268435456, "owned_container_cleanup_confirmed": cleanup, "certification": "REAL_CGROUP_KERNEL_NOT_KATA_OR_CLOUD"})
    host.require(passed and cleanup, "CAPACITY_ACCEPTANCE_OR_CLEANUP_FAILED")
    print("PASS exact real kernel capacity, owned container retired; no Kata/cloud certification")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    try:
        run(parser.parse_args())
    except Exception:
        print("Nodeguard capacity acceptance failed; private evidence retained", file=sys.stderr)
        raise SystemExit(1) from None
