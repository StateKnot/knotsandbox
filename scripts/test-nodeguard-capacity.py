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
CORE_FIELD_MARKER = "NODEGUARD_KERNEL_CORE_SCHED_FIELD_PRESENT"
KERNEL_FAILURE_STAGES = (
    "KERNEL_EXECUTABLE_CANONICALIZE", "KERNEL_EXECUTABLE_DIGEST", "KERNEL_PROCESS_SPAWN",
    "KERNEL_PROC_IDENTITY", "KERNEL_PIDFD_PIN", "KERNEL_CGROUP_READ", "KERNEL_CGROUP_PARSE",
    "KERNEL_CGROUP_RELATIVE", "KERNEL_CGROUP_PATH", "KERNEL_CGROUP_OPEN", "KERNEL_CGROUP_METADATA",
    "KERNEL_CPU_STAT_READ", "KERNEL_MEMORY_CURRENT_READ", "KERNEL_IO_STAT_READ",
    "KERNEL_PIDS_CURRENT_READ", "KERNEL_COUNTER_PARSE", "KERNEL_BOOT_ID_READ", "KERNEL_BOOT_ID_PARSE",
    "KERNEL_METRICS_SAMPLE", "KERNEL_BASE_COUNTER_ASSERT", "KERNEL_CPU_CAPACITY_ASSERT",
    "KERNEL_MEMORY_CAPACITY_ASSERT", "KERNEL_CHANGED_INODE_REJECT_ASSERT", "KERNEL_PROCESS_KILL",
    "KERNEL_PROCESS_WAIT", "KERNEL_EXITED_PID_REJECT_ASSERT",
)
CHECK_FAILURE_CODES = {
    "OWNED_CONTAINER_ID_REQUIRED", "OWNED_CONTAINER_MISMATCH", "RESOURCE_BOUND_OR_ISOLATION_CHANGED",
    "EXACT_REAL_CAPACITY_TEST_FAILED", "KERNEL_CORE_SCHED_MARKER_REQUIRED", "CARGO_ARTIFACT_CHANGED",
}


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
    primary_failure_stage = None
    kernel_failure_stage = None
    kernel_core_sched_field_present = None
    cleanup_failures = []
    cleanup_failure_stage = None
    cleanup_failure_code = None
    stage = "CREATE_OWNED_CONTAINER"
    try:
        # create gives ownership before a possibly interrupted start/attach.
        create_attempted = True
        identity = fixture.invoke([*docker, "create", "--name", name, "--label", label,
            "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--cgroupns", "host", "--cpus", "0.75", "--memory", "268435456", "--memory-swap", "268435456", "--pids-limit", "64",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--mount", "type=bind,src=" + str(binary) + ",dst=/capacity-test,readonly",
            "--entrypoint", "/capacity-test", image.group(1), "--exact", CASE, "--ignored", "--test-threads=1", "--nocapture"], env=environment, timeout=120)
        stage = "VERIFY_OWNED_CONTAINER"
        host.require(re.fullmatch(r"[0-9a-f]{64}", identity) is not None, "OWNED_CONTAINER_ID_REQUIRED")
        inspection = json.loads(fixture.invoke([*docker, "inspect", name], env=environment))[0]
        host.require(inspection["Id"] == identity and inspection["Config"]["Labels"].get("com.sandbox.fixture") == "nodeguard-capacity", "OWNED_CONTAINER_MISMATCH")
        settings = inspection["HostConfig"]
        host.require(settings["NanoCpus"] == 750000000 and settings["Memory"] == 268435456 and settings["CgroupnsMode"] == "host" and settings["ReadonlyRootfs"] and not settings["Privileged"] and settings["PidMode"] != "host", "RESOURCE_BOUND_OR_ISOLATION_CHANGED")
        stage = "RUN_EXACT_CAPACITY_TEST"
        result = subprocess.run([*docker, "start", "--attach", name], env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
        stage = "WRITE_CAPACITY_LOG"
        log = evidence / "capacity.log"
        with log.open("xb") as stream:
            os.chmod(log, 0o600)
            stream.write(result.stdout)
        code = result.returncode
        text = result.stdout.decode("utf-8", errors="replace")
        # Capture only known test-stage constants and a boolean from the real
        # kernel file. Never place a path, counter body or provider error in the
        # portable JSON receipt; detailed test output stays in the private log.
        kernel_failure_stage = next((name for name in KERNEL_FAILURE_STAGES
            if re.search(r"\b" + re.escape(name) + r"\b", text)), None)
        presence = re.findall(r"\b" + CORE_FIELD_MARKER + r"=(true|false)\b", text)
        if len(presence) == 1:
            kernel_core_sched_field_present = presence[0] == "true"
        stage = "VERIFY_EXACT_CAPACITY_RESULT"
        host.require(code == 0 and re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", text) is not None and text.count(MARKER) == 1, "EXACT_REAL_CAPACITY_TEST_FAILED")
        host.require(len(presence) == 1, "KERNEL_CORE_SCHED_MARKER_REQUIRED")
        stage = "VERIFY_CARGO_ARTIFACT_UNCHANGED"
        host.require(hashlib.sha256(binary.read_bytes()).hexdigest() == before, "CARGO_ARTIFACT_CHANGED")
        passed = True
    except Exception as exc:
        primary_failure_stage = stage
        if isinstance(exc, host.CheckError):
            check_code = getattr(exc, "code", None) or str(exc)
            primary_failure = check_code if check_code in CHECK_FAILURE_CODES else "CAPACITY_CHECK_FAILED"
        elif isinstance(exc, subprocess.TimeoutExpired):
            primary_failure = "CAPACITY_SUBPROCESS_TIMEOUT"
        else:
            primary_failure = "CAPACITY_ACCEPTANCE_FAILED"
    finally:
        if create_attempted:
            cleanup_stage = "INSPECT_OWNED_CONTAINER"
            try:
                inspected = subprocess.run([*docker, "inspect", name], env=environment, capture_output=True, timeout=30)
                if inspected.returncode == 0:
                    inspection = json.loads(inspected.stdout)[0]
                    actual_id = inspection["Id"]
                    host.require(re.fullmatch(r"[0-9a-f]{64}", actual_id) is not None and (identity is None or identity == actual_id) and inspection["Name"] == "/" + name and inspection["Config"]["Labels"].get("com.sandbox.fixture") == "nodeguard-capacity" and inspection["Config"]["Image"] == image.group(1), "OWNED_CONTAINER_MISMATCH")
                    # Recover ownership by exact random name, label and image
                    # when create succeeded but the client lost its receipt.
                    cleanup_stage = "REMOVE_OWNED_CONTAINER"
                    fixture.invoke([*docker, "rm", "--force", actual_id], env=environment)
                    cleanup_stage = "VERIFY_OWNED_CONTAINER_ABSENCE"
                    gone = subprocess.run([*docker, "inspect", actual_id], env=environment, capture_output=True, timeout=30)
                    cleanup = gone.returncode != 0 and b"no such" in gone.stderr.lower()
                    if not cleanup:
                        cleanup_failures.append("OWNED_CONTAINER_ABSENCE_UNCONFIRMED")
                        cleanup_failure_stage = cleanup_stage
                elif identity is not None and b"no such" in inspected.stderr.lower():
                    cleanup = True
                else:
                    # A timed-out creation with no ID is not proof that a late
                    # create cannot exist. Preserve the name for investigation.
                    cleanup_failures.append("OWNED_CREATION_OR_ABSENCE_UNCONFIRMED")
                    cleanup_failure_stage = cleanup_stage
            except Exception as exc:
                cleanup_failures.append("OWNED_CONTAINER_CLEANUP_UNCONFIRMED")
                cleanup_failure_stage = cleanup_stage
                if isinstance(exc, host.CheckError):
                    check_code = getattr(exc, "code", None) or str(exc)
                    cleanup_failure_code = check_code if check_code in CHECK_FAILURE_CODES else "CAPACITY_CLEANUP_CHECK_FAILED"
                elif isinstance(exc, subprocess.TimeoutExpired):
                    cleanup_failure_code = "CAPACITY_CLEANUP_SUBPROCESS_TIMEOUT"
                else:
                    cleanup_failure_code = "CAPACITY_CLEANUP_FAILED"
        fixture.private_json(evidence / "record.json", {"status": "PASS" if passed and cleanup and not cleanup_failures else "FAIL", "case": CASE, "exit_code": code, "primary_failure": primary_failure, "primary_failure_stage": primary_failure_stage, "kernel_failure_stage": kernel_failure_stage, "kernel_core_sched_field_present": kernel_core_sched_field_present, "cleanup_failures": cleanup_failures, "cleanup_failure_stage": cleanup_failure_stage, "cleanup_failure_code": cleanup_failure_code, "owned_container_name": name, "binary_sha256": before, "image": image.group(1), "cpu_cores": 0.75, "memory_bytes": 268435456, "owned_container_cleanup_confirmed": cleanup, "certification": "REAL_CGROUP_KERNEL_NOT_KATA_OR_CLOUD"})
    host.require(passed and cleanup and not cleanup_failures, "CAPACITY_ACCEPTANCE_OR_CLEANUP_FAILED")
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
