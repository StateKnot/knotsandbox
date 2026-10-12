#!/usr/bin/env python3
"""Mandatory Linux host-observation acceptance on an ordinary Cargo lib artifact.

The caller compiles as its normal UID. Only the exact already compiled test and
the root/PID1 namespace prerequisites use noninteractive sudo; Cargo never does.
This owns an empty temporary journal fixture, not a real sandbox or cloud node.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
CASE = "nodeguard::server::linux::tests::never_started_control_route_persists_death_and_refreshes_mount_observation"
MARKER = "NODEGUARD_HOST_DEATH_AND_FRESH_MOUNT_OBSERVATION_VERIFIED"


class CheckError(RuntimeError):
    pass


def require(condition, code):
    if not condition:
        raise CheckError(code)


def absolute_regular(path, directory=False):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "ABSOLUTE_PATH_REQUIRED")
    require(not path.is_symlink() and not any(parent.is_symlink() for parent in path.parents), "SYMLINK_FORBIDDEN")
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), "REGULAR_PATH_REQUIRED")
    return path


def fingerprint(path):
    path = absolute_regular(path)
    with path.open("rb") as stream:
        info = os.fstat(stream.fileno())
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"sha256": digest, "size": info.st_size, "device": info.st_dev,
            "inode": info.st_ino, "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid,
            "mtime_ns": info.st_mtime_ns}


def select_artifact(messages, metadata, root=ROOT, owner=None):
    root = absolute_regular(root, directory=True)
    manifest = absolute_regular(root / "Cargo.toml")
    source = absolute_regular(root / "src/lib.rs")
    require(metadata.get("workspace_root") == str(root), "CARGO_WORKSPACE_MISMATCH")
    packages = [package for package in metadata.get("packages", [])
                if package.get("name") == "sandbox-platform" and package.get("manifest_path") == str(manifest)]
    require(len(packages) == 1, "UNIQUE_ROOT_PACKAGE_REQUIRED")
    package = packages[0]
    libs = [target for target in package.get("targets", [])
            if target.get("kind") == ["lib"] and target.get("name") == "sandbox_platform"
            and target.get("src_path") == str(source)]
    require(len(libs) == 1, "UNIQUE_ROOT_LIB_REQUIRED")
    target_directory = absolute_regular(metadata["target_directory"], directory=True)
    candidates = []
    for message in messages:
        require(isinstance(message, dict), "CARGO_MESSAGE_INVALID")
        if message.get("reason") != "compiler-artifact" or not message.get("executable"):
            continue
        target, profile = message.get("target", {}), message.get("profile", {})
        if message.get("package_id") != package.get("id") and target.get("name") != "sandbox_platform":
            continue
        require(message.get("package_id") == package["id"] and message.get("manifest_path") == str(manifest), "CARGO_PACKAGE_MISMATCH")
        require(target.get("kind") == ["lib"] and target.get("name") == "sandbox_platform"
                and target.get("src_path") == str(source) and profile.get("test") is True, "CARGO_LIB_TEST_REQUIRED")
        binary = absolute_regular(message["executable"])
        require(binary.parent == target_directory / "debug/deps"
                and re.fullmatch(r"sandbox_platform-[0-9a-f]{16}", binary.name), "CARGO_TARGET_LAYOUT_MISMATCH")
        info = binary.stat()
        require(info.st_uid == (os.geteuid() if owner is None else owner) and info.st_mode & 0o111
                and not info.st_mode & 0o022, "ORDINARY_CALLER_BINARY_REQUIRED")
        with binary.open("rb") as stream:
            header = stream.read(64)
        machine = {"x86_64": 62, "aarch64": 183, "arm64": 183}.get(platform.machine())
        require(machine is not None and len(header) == 64 and header[:7] == b"\x7fELF\x02\x01\x01"
                and int.from_bytes(header[18:20], "little") == machine, "NATIVE_LINUX_ELF_REQUIRED")
        candidates.append(binary)
    require(len(candidates) == 1, "UNIQUE_LIB_TEST_ARTIFACT_REQUIRED")
    return candidates[0], target_directory


def successful(result, code):
    require(result.returncode == 0, code)
    return result.stdout


def inventory(output):
    require(output.splitlines().count(CASE + ": test") == 1, "EXACT_IGNORED_CASE_REQUIRED")


def completed(output):
    summaries = re.findall(r"^test result: (.+)$", output, re.MULTILINE)
    require(len(summaries) == 1 and re.fullmatch(
        r"ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s", summaries[0]),
        "EXACT_ONE_HOST_TEST_MUST_PASS")
    require(output.count(MARKER) == 1, "HOST_COMPLETION_MARKER_REQUIRED")


def trusted_system_program(path):
    path = absolute_regular(path)
    info = path.stat()
    require(info.st_uid == 0 and not info.st_mode & 0o022 and info.st_mode & 0o111, "ROOT_OWNED_SYSTEM_PROGRAM_REQUIRED")
    return str(path)


def run(args):
    require(sys.platform == "linux", "LINUX_REQUIRED")
    require(os.geteuid() != 0, "ORDINARY_CALLER_REQUIRED")
    require(Path.cwd().resolve() == ROOT, "REPOSITORY_WORKING_DIRECTORY_REQUIRED")
    artifacts = absolute_regular(args.artifacts.absolute())
    require(artifacts.stat().st_size <= 32 * 1024 * 1024, "CARGO_MESSAGES_TOO_LARGE")
    messages = [json.loads(line) for line in artifacts.read_text().splitlines() if line.strip()]
    metadata_result = subprocess.run(["cargo", "metadata", "--locked", "--offline", "--no-deps", "--format-version=1"],
                                     cwd=ROOT, capture_output=True, text=True, timeout=30)
    metadata = json.loads(successful(metadata_result, "ORDINARY_CARGO_METADATA_FAILED"))
    binary, target_directory = select_artifact(messages, metadata, ROOT)
    evidence = args.evidence_dir.absolute()
    require(".." not in evidence.parts and not evidence.is_symlink()
            and not any(parent.is_symlink() for parent in evidence.parents), "EVIDENCE_PATH_INVALID")
    require(evidence != target_directory and target_directory not in evidence.parents, "EVIDENCE_OUTSIDE_TARGET_REQUIRED")
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    record = {"protocol": 1, "case": CASE, "scope": "owned empty-journal Linux host observation fixture",
              "caller_uid": os.geteuid(), "status": "FAILED", "completed_at": None,
              "binary": str(binary), "artifacts_sha256": fingerprint(artifacts)["sha256"],
              "binary_before": fingerprint(binary), "sudo_cargo_or_target_write": False}
    with (evidence / "host-test.log").open("x") as log:
        def call(stage, command, timeout=30):
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
            log.write(json.dumps({"stage": stage, "command": command, "exit_code": result.returncode,
                                  "stdout": result.stdout, "stderr": result.stderr}) + "\n")
            log.flush()
            return result

        try:
            sudo = trusted_system_program("/usr/bin/sudo")
            uid = trusted_system_program("/usr/bin/id")
            namespace_stat = trusted_system_program("/usr/bin/stat")
            require(successful(call("privileged_uid", [sudo, "-n", "--", uid, "-u"]), "PRIVILEGED_UID_CHECK_FAILED").strip() == "0", "ROOT_UID_REQUIRED")
            values = successful(call("initial_mount_namespace", [sudo, "-n", "--", namespace_stat, "-L", "-c", "%d:%i",
                                                                 "/proc/self/ns/mnt", "/proc/1/ns/mnt"]), "PID1_NAMESPACE_UNREADABLE").splitlines()
            require(len(values) == 2 and all(re.fullmatch(r"[0-9]+:[1-9][0-9]*", value) for value in values)
                    and values[0] == values[1], "PID1_INITIAL_MOUNT_NAMESPACE_REQUIRED")
            record["namespace_device"], record["namespace_inode"] = values[0].split(":")
            inventory(successful(call("exact_ignored_inventory", [str(binary), "--list", "--ignored"]), "HOST_TEST_INVENTORY_FAILED"))
            require(fingerprint(binary) == record["binary_before"], "BINARY_CHANGED_BEFORE_EXECUTION")
            output = successful(call("privileged_exact_host_test", [sudo, "-n", "--", str(binary), CASE, "--exact", "--ignored", "--nocapture", "--test-threads=1"], timeout=60), "HOST_TEST_FAILED")
            completed(output)
            record.update(status="PASS", passed=1, failed=0, ignored=0, completion_marker=MARKER)
        except BaseException as exc:
            record["failure"] = type(exc).__name__ + ": " + str(exc)
            raise
        finally:
            primary_failure = record.get("failure")
            try:
                record["binary_after"] = fingerprint(binary)
                record["binary_unchanged"] = record["binary_after"] == record["binary_before"]
            except (CheckError, OSError) as exc:
                record["binary_after"] = None
                record["binary_unchanged"] = False
                record["post_execution_binary_error"] = type(exc).__name__ + ": " + str(exc)
            if not record["binary_unchanged"]:
                record["status"] = "FAILED"
                record.setdefault("failure", "BINARY_CHANGED_DURING_HOST_GATE")
                record.setdefault("post_execution_binary_error", "BINARY_FINGERPRINT_CHANGED")
            record["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            (evidence / "record.json").write_text(json.dumps(record, indent=2) + "\n")
            if not record["binary_unchanged"] and primary_failure is None:
                raise CheckError("BINARY_CHANGED_DURING_HOST_GATE")
    print("Mandatory Nodeguard host observation: 1 passed, 0 failed, 0 ignored")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        run(args)
    except (CheckError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        print("NODEGUARD_HOST_GATE_FAILED: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
