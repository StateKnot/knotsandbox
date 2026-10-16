#!/usr/bin/env python3
"""Inspect existing native image metadata with the exact production admin CLI.

The existing image-observation runner owns containerd, resource bounds, pinned
inputs, no-unpack postconditions and cleanup. Only an independently identified
ordinary Cargo admin ELF and generated public OCI metadata extend its fixture.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import sys

sys.dont_write_bytecode = True
SOURCE = Path(__file__).with_name("test-nodeguard-image-observation.py")
SPEC = importlib.util.spec_from_file_location("native_metadata_fixture", SOURCE)
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)
FIXTURE.CASE = "nodeguard::native_image_metadata::cli_tests::native_metadata_readback_and_admin_cli_remain_metadata_only"
FIXTURE.MARKER = "NODEGUARD_NATIVE_METADATA_CLI_VERIFIED"
FIXTURE.ACCEPTANCE_SCOPE = "LOCAL_NATIVE_CONTAINERD_METADATA_READBACK_AND_ADMIN_CLI_ONLY_NOT_APPROVAL_PULL_LAYER_VERIFICATION_UNPACK_PREPARATION_GPU_OR_CLOUD"
FIXTURE.SUCCESS_MESSAGE = "PASS native metadata readback and exact admin CLI; owned daemon retired; images remain unpacked=false; no image preparation certification"
EXTRA_FILES = ("rootfs/fixture/sandbox-admin",)
PUBLIC_ENV_MARKER = "PUBLIC_ENV_MARKER=DO_NOT_ECHO_NATIVE_METADATA_ENV"
STATE = {}

SELECT_ARTIFACT = FIXTURE.select_artifact
PREPARE_FILES = FIXTURE.prepare_files
CONTEXT_MANIFEST = FIXTURE.context_manifest
CONTAINER_COMMAND = FIXTURE.container_command
VERIFY_CONTAINER = FIXTURE.verify_container
ACCEPT = FIXTURE.accept


def select_admin_artifact(messages, metadata, arch):
    """Accept the normal root-package build binary, never a test or sibling ELF."""
    root = FIXTURE.ROOT
    FIXTURE.require(metadata.get("workspace_root") == str(root), "CARGO_WORKSPACE_MISMATCH")
    manifest, source = str(root / "Cargo.toml"), str(root / "src/bin/sandbox-admin.rs")
    packages = [p for p in metadata.get("packages", []) if p.get("name") == "sandbox-platform" and p.get("manifest_path") == manifest]
    FIXTURE.require(len(packages) == 1, "UNIQUE_ROOT_PACKAGE_REQUIRED")
    package = packages[0]
    targets = [t for t in package.get("targets", []) if t.get("kind") == ["bin"] and t.get("name") == "sandbox-admin" and t.get("src_path") == source]
    FIXTURE.require(len(targets) == 1, "UNIQUE_ROOT_ADMIN_BIN_REQUIRED")
    target = FIXTURE.regular(metadata["target_directory"], directory=True)
    selected = []
    for message in messages:
        FIXTURE.require(isinstance(message, dict), "CARGO_MESSAGE_INVALID")
        if message.get("reason") != "compiler-artifact" or not message.get("executable"):
            continue
        item = message.get("target", {})
        if message.get("package_id") != package.get("id") and item.get("name") != "sandbox-admin":
            continue
        # Other binaries from the same ordinary build are not admin candidates.
        if item.get("name") != "sandbox-admin":
            continue
        # An all-targets Cargo receipt can also contain the admin's libtest
        # executable. Select only the ordinary binary; test-only still fails
        # the final unique ordinary-artifact requirement.
        if message.get("profile", {}).get("test") is not False:
            continue
        FIXTURE.require(message.get("package_id") == package["id"] and message.get("manifest_path") == manifest, "CARGO_ADMIN_PACKAGE_MISMATCH")
        FIXTURE.require(item.get("kind") == ["bin"] and item.get("src_path") == source and message.get("profile", {}).get("test") is False, "CARGO_ORDINARY_ADMIN_BUILD_REQUIRED")
        binary = FIXTURE.regular(message["executable"])
        info = binary.stat()
        FIXTURE.require(binary == target / "debug/sandbox-admin", "CARGO_ADMIN_TARGET_LAYOUT_MISMATCH")
        FIXTURE.require(info.st_uid == os.geteuid() and info.st_mode & 0o111 and not info.st_mode & 0o022 and info.st_size <= 512 * 1024 * 1024, "ORDINARY_CALLER_ADMIN_BINARY_REQUIRED")
        with binary.open("rb") as stream:
            header = stream.read(64)
        FIXTURE.require(len(header) == 64 and header[:7] == b"\x7fELF\x02\x01\x01" and int.from_bytes(header[18:20], "little") == {"amd64": 62, "arm64": 183}[arch], "DOCKER_NATIVE_LINUX_ADMIN_ELF_REQUIRED")
        selected.append(binary)
    FIXTURE.require(len(selected) == 1, "UNIQUE_ADMIN_BUILD_ARTIFACT_REQUIRED")
    return selected[0]


def select_artifact(messages, metadata, arch):
    binary, target = SELECT_ARTIFACT(messages, metadata, arch)
    artifacts = FIXTURE.regular(STATE["admin_artifacts"])
    FIXTURE.require(artifacts.stat().st_size <= 32 * 1024 * 1024, "ADMIN_CARGO_MESSAGES_TOO_LARGE")
    admin = select_admin_artifact([json.loads(line) for line in artifacts.read_text().splitlines() if line.strip()], metadata, arch)
    STATE.update(admin=admin, admin_before=FIXTURE.fingerprint(admin), admin_artifacts_sha256=FIXTURE.digest(artifacts))
    return binary, target


def metadata_fixture(path, arch):
    def blob(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    def descriptor(data, media):
        return {"mediaType": media, "digest": "sha256:" + FIXTURE.hashlib.sha256(data).hexdigest(), "size": len(data)}

    layer = FIXTURE.tar_bytes({"public-native-metadata.txt": b"Public metadata fixture; never unpack or execute.\n"})
    layer_info = descriptor(layer, "application/vnd.oci.image.layer.v1.tar")
    config = blob({"architecture": arch, "os": "linux", "config": {"Env": [PUBLIC_ENV_MARKER]}, "rootfs": {"type": "layers", "diff_ids": [layer_info["digest"]]}})
    config_info = descriptor(config, "application/vnd.oci.image.config.v1+json")
    manifest = blob({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": config_info, "layers": [layer_info]})
    manifest_info = descriptor(manifest, "application/vnd.oci.image.manifest.v1+json")
    index = blob({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [{**manifest_info, "platform": {"os": "linux", "architecture": arch}}]})
    index_info = descriptor(index, "application/vnd.oci.image.index.v1+json")
    reference = "fixture.invalid/native-metadata-index@" + index_info["digest"]
    manifest_reference = "fixture.invalid/native-metadata-manifest@" + manifest_info["digest"]
    outer = blob({"schemaVersion": 2, "manifests": [
        {**index_info, "annotations": {"org.opencontainers.image.ref.name": reference}},
        {**manifest_info, "platform": {"os": "linux", "architecture": arch}, "annotations": {"org.opencontainers.image.ref.name": manifest_reference}},
    ]})
    files = {"oci-layout": blob({"imageLayoutVersion": "1.0.0"}), "index.json": outer}
    for data, info in [(layer, layer_info), (config, config_info), (manifest, manifest_info), (index, index_info)]:
        files["blobs/sha256/" + info["digest"][7:]] = data
    path.write_bytes(FIXTURE.tar_bytes(files))
    path.chmod(0o444)
    return {"reference": reference, "index": index_info, "manifest_reference": manifest_reference, "manifest": manifest_info,
            "config": config_info, "layers": [layer_info], "archive_sha256": FIXTURE.digest(path),
            "expected_compressed_logical_bytes": len(index) + len(manifest) + len(config) + len(layer), "unpack_requested": False}


def prepare_files(stage, archive, binary, arch):
    PREPARE_FILES(stage, archive, binary, arch)
    # The base fixture freezes its public tree; temporarily restore only this
    # exact task-owned directory to install the additionally verified ELF.
    fixture = stage / "fixture"
    fixture.chmod(0o755)
    try:
        admin = STATE["admin"]
        shutil.copyfile(admin, fixture / "sandbox-admin")
        (fixture / "sandbox-admin").chmod(0o555)
        FIXTURE.require(FIXTURE.digest(admin) == FIXTURE.digest(fixture / "sandbox-admin"), "COPIED_ADMIN_ARTIFACT_CHANGED")
        (fixture / "image.tar").unlink()
        image = metadata_fixture(fixture / "image.tar", arch)
    finally:
        fixture.chmod(0o555)
    STATE["environment"] = {
        "SANDBOX_NATIVE_METADATA_REFERENCE": image["reference"],
        "SANDBOX_NATIVE_METADATA_EXPECTED_DIGEST": image["index"]["digest"],
        "SANDBOX_NATIVE_METADATA_PLATFORM": "linux/" + arch,
        "SANDBOX_NATIVE_METADATA_MANIFEST_REFERENCE": image["manifest_reference"],
        "SANDBOX_NATIVE_METADATA_MANIFEST_DIGEST": image["manifest"]["digest"],
    }
    return image


def context_manifest(context):
    return CONTEXT_MANIFEST(context, extra_files=EXTRA_FILES)


def container_command(docker, name, arch, image):
    command = CONTAINER_COMMAND(docker, name, arch, image)
    position = command.index("--entrypoint")
    environment = [item for key, value in sorted(STATE["environment"].items()) for item in ("--env", key + "=" + value)]
    return [*command[:position], *environment, *command[position:]]


def verify_container(value, identity, name, image):
    VERIFY_CONTAINER(value, identity, name, image)
    actual = value["Config"].get("Env", [])
    expected = STATE["environment"]
    FIXTURE.require(all(actual.count(key + "=" + value) == 1 for key, value in expected.items()) and
                    all(item.partition("=")[0] in expected for item in actual if item.startswith("SANDBOX_NATIVE_METADATA_")),
                    "EXACT_GENERATED_METADATA_FIXTURE_ENVIRONMENT_REQUIRED")


def accept(args, evidence, record):
    STATE.clear()
    STATE["admin_artifacts"] = args.admin_artifacts
    try:
        ACCEPT(args, evidence, record)
    finally:
        try:
            record["admin_binary_sha256"] = STATE["admin_before"]["sha256"]
            record["admin_artifacts_sha256"] = STATE["admin_artifacts_sha256"]
            record["admin_binary_unchanged"] = FIXTURE.fingerprint(STATE["admin"]) == STATE["admin_before"]
            record["admin_artifacts_unchanged"] = FIXTURE.digest(FIXTURE.regular(args.admin_artifacts)) == STATE["admin_artifacts_sha256"]
            record["generated_public_environment"] = STATE.get("environment")
            if not record["admin_binary_unchanged"] or not record["admin_artifacts_unchanged"]:
                record["status"] = "FAIL"
                if record.get("failure_code") is None:
                    record["failure_code"] = "ADMIN_INPUT_IDENTITY_CHANGED"
                    record["failure_stage"] = "FINAL_ADMIN_INPUT_BINDING"
        except Exception:
            record["status"] = "FAIL"
            record["admin_input_verification_failure"] = "ADMIN_INPUT_IDENTITY_UNCONFIRMED"
            if record.get("failure_code") is None:
                record["failure_code"] = "ADMIN_INPUT_IDENTITY_UNCONFIRMED"
                record["failure_stage"] = "FINAL_ADMIN_INPUT_BINDING"
        if record["status"] != "PASS":
            for field in ("passed", "failed", "ignored"):
                record.pop(field, None)


FIXTURE.select_artifact = select_artifact
FIXTURE.prepare_files = prepare_files
FIXTURE.context_manifest = context_manifest
FIXTURE.container_command = container_command
FIXTURE.verify_container = verify_container
FIXTURE.accept = accept


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--admin-artifacts", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--containerd-archive", type=Path)
    parser.add_argument("--containerd-checksum", type=Path)

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        FIXTURE.run(parser.parse_args())
    except BaseException as error:
        suffix = "private evidence retained" if getattr(error, "evidence_saved", False) else "no completed evidence record was saved; a private evidence destination could not be safely created or written"
        print("Native metadata acceptance failed; " + suffix, file=sys.stderr)
        raise SystemExit(1) from None
