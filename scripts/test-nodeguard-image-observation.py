#!/usr/bin/env python3
"""Exact native image-observation acceptance against an owned containerd.

Cargo runs as the ordinary caller. macOS may orchestrate a Linux ELF built at
the same absolute workspace/target paths; it never executes that ELF itself.
Only verified containerd binaries, the exact ELF and generated public fixture
files enter a minimal FROM/COPY fixture image. No source, credentials, host
socket, existing volume, Pod, VM, image unpack or registry access is involved.
"""
import argparse
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import urllib.parse
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
CASE = "nodeguard::metrics_server::image_tests::native_containerd_inventory_status_is_scraper_only_without_vms"
MARKER = "NODEGUARD_NATIVE_IMAGE_OBSERVATION_SCRAPER_ONLY_VERIFIED"
ACCEPTANCE_SCOPE = "LOCAL_NATIVE_CONTAINERD_CRI_AND_MTLS_ONLY_NOT_KATA_GPU_CLOUD_OR_COMPLETE_CACHE_BYTES"
SUCCESS_MESSAGE = "PASS exact native containerd image observation; owned daemon retired; no Kata/cloud certification"
VERSION = "2.3.5"
RELEASE = "https://github.com/containerd/containerd/releases/tag/v2.3.5"
DOWNLOAD = "https://github.com/containerd/containerd/releases/download/v2.3.5/"
# Independently reviewed official release asset digests AND SHA256SUM assets.
# Updating a downloaded checksum to match a new archive is never sufficient.
PINS = {
    "amd64": {"archive_bytes": 34581187,
              "archive_sha256": "2f0a095a71e3262d0d91ff0e50e2e4ae73c3866c4d1ff6a15f341097fba3dd44",
              "checksum_sha256": "7767073303284a260acb6d5d5f00e93eded99e25c19ad8e5c6f22d270f15b879"},
    "arm64": {"archive_bytes": 31297063,
              "archive_sha256": "06f46cbc073872c5ad1fbc922a53543e9a26b798d62ff106d44639dcb9947942",
              "checksum_sha256": "08dc01d4f91ffd54a79b956d099ce4c4288a25b1d4f7fb20d6cd2a3002ed96ab"},
}
CONFIG = '''version = 3
root = "/var/lib/containerd"
state = "/run/containerd"
[grpc]
  address = "/run/containerd/containerd.sock"
[plugins."io.containerd.cri.v1.images"]
  snapshotter = "overlayfs"
'''
MEMORY = 768 * 1024 * 1024
TMPFS = {"/var/lib/containerd": "rw,nosuid,nodev,noexec,mode=0755,size=134217728",
         "/run": "rw,nosuid,nodev,noexec,mode=0755,size=16777216",
         "/tmp": "rw,nosuid,nodev,noexec,mode=1777,size=67108864"}
MAX_LOG = 8 * 1024 * 1024
LOG_CONFIG = {"Type": "local", "Config": {"max-size": "1m", "max-file": "1", "compress": "false"}}


class CheckError(RuntimeError):
    pass


def require(value, code):
    if not value:
        raise CheckError(code)


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(65536):
            result.update(block)
    return result.hexdigest()


def fingerprint(path):
    path = regular(path)
    info = path.stat()
    return {"sha256": digest(path), "device": info.st_dev, "inode": info.st_ino,
            "size": info.st_size, "mode": info.st_mode & 0o777, "uid": info.st_uid,
            "mtime_ns": info.st_mtime_ns}


def regular(path, directory=False):
    path = Path(path).absolute()
    require(".." not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)), "SYMLINK_OR_PARENT_PATH_FORBIDDEN")
    require(path.is_dir() if directory else path.is_file(), "REGULAR_PATH_REQUIRED")
    return path


def select_artifact(messages, metadata, arch):
    """The ordinary Cargo identity contract, with Linux ELF bound to Docker."""
    require(metadata.get("workspace_root") == str(ROOT), "CARGO_WORKSPACE_MISMATCH")
    manifest, source = str(ROOT / "Cargo.toml"), str(ROOT / "src/lib.rs")
    packages = [p for p in metadata.get("packages", []) if p.get("name") == "sandbox-platform" and p.get("manifest_path") == manifest]
    require(len(packages) == 1, "UNIQUE_ROOT_PACKAGE_REQUIRED")
    package = packages[0]
    libs = [t for t in package.get("targets", []) if t.get("kind") == ["lib"] and t.get("name") == "sandbox_platform" and t.get("src_path") == source]
    require(len(libs) == 1, "UNIQUE_ROOT_LIB_REQUIRED")
    target = regular(metadata["target_directory"], directory=True)
    selected = []
    for message in messages:
        require(isinstance(message, dict), "CARGO_MESSAGE_INVALID")
        if message.get("reason") != "compiler-artifact" or not message.get("executable"):
            continue
        item = message.get("target", {})
        if message.get("package_id") != package.get("id") and item.get("name") != "sandbox_platform":
            continue
        require(message.get("package_id") == package["id"] and message.get("manifest_path") == manifest, "CARGO_PACKAGE_MISMATCH")
        require(item.get("kind") == ["lib"] and item.get("name") == "sandbox_platform" and item.get("src_path") == source and message.get("profile", {}).get("test") is True, "CARGO_LIB_TEST_REQUIRED")
        binary = regular(message["executable"])
        info = binary.stat()
        require(binary.parent == target / "debug/deps" and re.fullmatch(r"sandbox_platform-[0-9a-f]{16}", binary.name), "CARGO_TARGET_LAYOUT_MISMATCH")
        require(info.st_uid == os.geteuid() and info.st_mode & 0o111 and not info.st_mode & 0o022 and info.st_size <= 512 * 1024 * 1024, "ORDINARY_CALLER_BINARY_REQUIRED")
        with binary.open("rb") as stream:
            header = stream.read(64)
        require(len(header) == 64 and header[:7] == b"\x7fELF\x02\x01\x01" and int.from_bytes(header[18:20], "little") == {"amd64": 62, "arm64": 183}[arch], "DOCKER_NATIVE_LINUX_ELF_REQUIRED")
        selected.append(binary)
    require(len(selected) == 1, "UNIQUE_LIB_TEST_ARTIFACT_REQUIRED")
    return selected[0], target


def source_fingerprints():
    # Works in a source-only validation copy without .git. Generated caches and
    # private evidence are outside these explicit compiler/fixture input trees.
    paths = [ROOT / name for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "build.rs", "Dockerfile", ".dockerignore")]
    for name in ("src", "migrations", "vendor", "tests", "scripts"):
        paths.extend(p for p in (ROOT / name).rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc")
    return {str(p.relative_to(ROOT)): {"sha256": digest(regular(p)), "mode": p.stat().st_mode & 0o777} for p in sorted(paths)}


def download(url, destination, size, sha256):
    with urllib.request.urlopen(url, timeout=60) as response, destination.open("xb") as stream:
        final = urllib.parse.urlsplit(response.url)
        require(final.scheme == "https" and final.hostname in ("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"), "OFFICIAL_DOWNLOAD_REDIRECT_REQUIRED")
        total = 0
        while block := response.read(65536):
            total += len(block)
            require(total <= size, "DOWNLOAD_BOUND_EXCEEDED")
            stream.write(block)
    require(total == size and digest(destination) == sha256, "PINNED_DOWNLOAD_DIGEST_MISMATCH")


def verified_archive(args, arch, work):
    pin = PINS[arch]
    name = "containerd-" + VERSION + "-linux-" + arch + ".tar.gz"
    require(bool(args.containerd_archive) == bool(args.containerd_checksum), "ARCHIVE_AND_INDEPENDENT_CHECKSUM_REQUIRED")
    if args.containerd_archive:
        archive, checksum = regular(args.containerd_archive), regular(args.containerd_checksum)
    else:
        archive, checksum = work / name, work / (name + ".sha256sum")
        download(DOWNLOAD + name, archive, pin["archive_bytes"], pin["archive_sha256"])
        download(DOWNLOAD + name + ".sha256sum", checksum, 102, pin["checksum_sha256"])
    require(archive.stat().st_size == pin["archive_bytes"] and digest(archive) == pin["archive_sha256"], "CONTAINERD_ARCHIVE_PIN_MISMATCH")
    require(checksum.stat().st_size == 102 and digest(checksum) == pin["checksum_sha256"], "CONTAINERD_CHECKSUM_ASSET_PIN_MISMATCH")
    require(checksum.read_text().split() == [pin["archive_sha256"], name], "INDEPENDENT_CHECKSUM_CONTENT_MISMATCH")
    return archive, {"version": VERSION, "architecture": arch, "release_url": RELEASE, "archive_url": DOWNLOAD + name, "checksum_url": DOWNLOAD + name + ".sha256sum", **pin}


def tar_bytes(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(files.items()):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.mtime = len(data), 0o444, 0
            archive.addfile(entry, io.BytesIO(data))
    return output.getvalue()


def image_fixture(path, arch):
    def blob(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    def descriptor(data, media):
        return {"mediaType": media, "digest": "sha256:" + hashlib.sha256(data).hexdigest(), "size": len(data)}
    layer = tar_bytes({"fixture.txt": b"public native image observation fixture; never unpack or execute\n"})
    layer_info = descriptor(layer, "application/vnd.oci.image.layer.v1.tar")
    config = blob({"architecture": arch, "os": "linux", "rootfs": {"type": "layers", "diff_ids": [layer_info["digest"]]}})
    config_info = descriptor(config, "application/vnd.oci.image.config.v1+json")
    manifest = blob({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": config_info, "layers": [layer_info]})
    manifest_info = descriptor(manifest, "application/vnd.oci.image.manifest.v1+json")
    reference = "fixture.invalid/nodeguard-native:fixture"
    index = blob({"schemaVersion": 2, "manifests": [{**manifest_info, "platform": {"os": "linux", "architecture": arch}, "annotations": {"org.opencontainers.image.ref.name": reference}}]})
    files = {"oci-layout": blob({"imageLayoutVersion": "1.0.0"}), "index.json": index}
    for data, info in [(layer, layer_info), (config, config_info), (manifest, manifest_info)]:
        files["blobs/sha256/" + info["digest"][7:]] = data
    path.write_bytes(tar_bytes(files))
    return {"reference": reference, "manifest": manifest_info, "config": config_info, "layers": [layer_info], "expected_compressed_logical_bytes": len(manifest) + len(config) + len(layer), "archive_sha256": digest(path), "unpack_requested": False}


def prepare_files(stage, archive, binary, arch):
    for name in ("usr/local/bin", "etc/containerd", "etc/cni/net.d", "opt/cni/bin", "opt/containerd", "fixture/profile-files"):
        (stage / name).mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:gz") as source:
        for name in ("containerd", "ctr"):
            members = [m for m in source.getmembers() if m.name == "bin/" + name]
            require(len(members) == 1 and members[0].isfile() and 0 < members[0].size <= 128 * 1024 * 1024, "CONTAINERD_REGULAR_BINARIES_REQUIRED")
            with source.extractfile(members[0]) as origin, (stage / "usr/local/bin" / name).open("xb") as output:
                shutil.copyfileobj(origin, output)
            (stage / "usr/local/bin" / name).chmod(0o555)
    (stage / "etc/containerd/config.toml").write_text(CONFIG)
    profile = {"protocol": 1, "runtime_handler": "kata-qemu", "containerd_version": VERSION,
               "image_observation": {"snapshotter": "overlayfs", "image_filesystem": "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs"}}
    for key in ("qemu", "virtiofs", "shim", "kata_configuration", "kubelet_configuration", "kubelet_environment"):
        path = stage / "fixture/profile-files" / key
        path.write_text("Public pinned " + key + " fixture only; no Kata/kubelet executable or certification.\n")
        profile[key] = {"path": "/fixture/profile-files/" + key, "sha256": digest(path)}
    profile["containerd_configuration"] = {"path": "/etc/containerd/config.toml", "sha256": digest(stage / "etc/containerd/config.toml")}
    (stage / "fixture/host-profile.json").write_text(json.dumps(profile, sort_keys=True) + "\n")
    image = image_fixture(stage / "fixture/image.tar", arch)
    shutil.copyfile(binary, stage / "fixture/lib-test")
    require(digest(binary) == digest(stage / "fixture/lib-test"), "COPIED_TEST_ARTIFACT_CHANGED")
    for path in stage.rglob("*"):
        if path.is_dir():
            path.chmod(0o555 if path == stage / "fixture" or stage / "fixture" in path.parents else 0o755)
        else:
            path.chmod(0o555 if path.name in ("lib-test", "containerd", "ctr") else 0o444)
    stage.chmod(0o755)
    return image


def exact_result(output):
    summaries = re.findall(r"(?m)^test result: (.+)$", output)
    require(len(summaries) == 1 and re.fullmatch(r"ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s", summaries[0]), "EXACT_ONE_NATIVE_TEST_MUST_PASS")
    require(output.count(MARKER) == 1, "UNIQUE_NATIVE_COMPLETION_MARKER_REQUIRED")


def fixture_dockerfile(base):
    require(re.fullmatch(r"debian:trixie-slim@sha256:[0-9a-f]{64}", base), "PINNED_TRIXIE_RUNTIME_IMAGE_REQUIRED")
    # Docker rejects `docker cp` into a --read-only container even before
    # start. Populate immutable image layers, then create the read-only runtime.
    return "FROM " + base + "\nCOPY rootfs/ /\n"


def context_manifest(context):
    allowed = {"Dockerfile", "rootfs/usr/local/bin/containerd", "rootfs/usr/local/bin/ctr",
               "rootfs/etc/containerd/config.toml", "rootfs/fixture/host-profile.json",
               "rootfs/fixture/image.tar", "rootfs/fixture/lib-test"}
    allowed.update("rootfs/fixture/profile-files/" + name for name in ("qemu", "virtiofs", "shim", "kata_configuration", "kubelet_configuration", "kubelet_environment"))
    actual = {str(path.relative_to(context)) for path in context.rglob("*") if path.is_file()}
    require(actual == allowed, "EXACT_PUBLIC_IMAGE_BUILD_CONTEXT_REQUIRED")
    return {name: {"sha256": digest(regular(context / name)), "size": (context / name).stat().st_size, "mode": (context / name).stat().st_mode & 0o777} for name in sorted(actual)}


def container_command(docker, name, arch, image):
    command = [*docker, "create", "--name", name, "--label", "com.sandbox.fixture=nodeguard-image-observation", "--platform", "linux/" + arch, "--user", "0:0", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--cgroupns", "private", "--cpus", "1", "--memory", str(MEMORY), "--memory-swap", str(MEMORY), "--pids-limit", "128", "--ulimit", "nofile=1024:1024", "--log-driver", "local", "--log-opt", "max-size=1m", "--log-opt", "max-file=1", "--log-opt", "compress=false"]
    for destination, options in TMPFS.items():
        command += ["--tmpfs", destination + ":" + options]
    return [*command, "--entrypoint", "/usr/local/bin/containerd", image["tag"], "--config", "/etc/containerd/config.toml"]


def verify_image(value, image):
    labels = value.get("Config", {}).get("Labels", {})
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", value.get("Id", "")) and image["tag"] in (value.get("RepoTags") or []) and labels.get("com.sandbox.fixture") == "nodeguard-image-observation" and labels.get("com.sandbox.owner") == image["owner"] and (image["id"] is None or image["id"] == value["Id"]), "OWNED_FIXTURE_IMAGE_MISMATCH")


def verify_owner(value, identity, name, image):
    require(value["Id"] == identity and value["Name"] == "/" + name and value["Config"]["Image"] == image["tag"] and value.get("Image") == image["id"] and value["Config"]["Labels"].get("com.sandbox.fixture") == "nodeguard-image-observation" and value["Config"]["Labels"].get("com.sandbox.owner") == image["owner"], "OWNED_CONTAINER_MISMATCH")


def verify_container(value, identity, name, image):
    verify_owner(value, identity, name, image)
    h = value["HostConfig"]
    require(not value.get("Mounts") and not h.get("Binds") and not h.get("Privileged") and not h.get("CapAdd") and h.get("CapDrop") == ["ALL"] and h.get("NetworkMode") == "none" and h.get("ReadonlyRootfs") is True and h.get("PidMode", "") == "" and h.get("CgroupnsMode") == "private" and h.get("Memory") == MEMORY and h.get("MemorySwap") == MEMORY and h.get("NanoCpus") == 1000000000 and h.get("PidsLimit") == 128 and h.get("Tmpfs") == TMPFS and "no-new-privileges:true" in h.get("SecurityOpt", []), "RESOURCE_OR_ISOLATION_BOUND_CHANGED")
    require(value["Config"].get("User") == "0:0" and any(item.get("Name") == "nofile" and item.get("Soft") == 1024 and item.get("Hard") == 1024 for item in h.get("Ulimits", [])), "ACTUAL_UID_OR_FD_BOUND_CHANGED")
    require(h.get("LogConfig") == LOG_CONFIG, "EXACT_BOUNDED_LOCAL_LOG_OPTIONS_REQUIRED")


def accept(args, evidence, record):
    record["failure_stage"] = "PREFLIGHT_CALLER"
    require(sys.platform in ("linux", "darwin") and os.geteuid() != 0, "ORDINARY_LOCAL_CALLER_REQUIRED")
    require(Path.cwd().resolve() == ROOT, "REPOSITORY_WORKING_DIRECTORY_REQUIRED")
    record["failure_stage"] = "PREFLIGHT_DOCKER_ENDPOINT"
    fixture = module("image_automation_fixture", ROOT / "scripts/test-automation.py")
    docker, environment = fixture.local_docker()
    record["failure_stage"] = "PREFLIGHT_CARGO_METADATA"
    artifacts = regular(args.artifacts)
    require(artifacts.stat().st_size <= 32 * 1024 * 1024, "CARGO_MESSAGES_TOO_LARGE")
    metadata = subprocess.run(["cargo", "metadata", "--locked", "--offline", "--no-deps", "--format-version=1"], cwd=ROOT, capture_output=True, text=True, timeout=30)
    require(metadata.returncode == 0, "ORDINARY_CARGO_METADATA_FAILED")
    record["failure_stage"] = "PREFLIGHT_DOCKER_ARCHITECTURE"
    engine = json.loads(fixture.invoke([*docker, "version", "--format", "{{json .Server}}"], env=environment, timeout=30))
    arch = engine.get("Arch")
    require(engine.get("Os") == "linux" and arch in PINS, "NATIVE_AMD64_OR_ARM64_DOCKER_REQUIRED")
    record["failure_stage"] = "PREFLIGHT_CARGO_ELF_IDENTITY"
    binary, target = select_artifact([json.loads(line) for line in artifacts.read_text().splitlines() if line.strip()], json.loads(metadata.stdout), arch)
    require(evidence != target and target not in evidence.parents, "PRIVATE_EVIDENCE_OUTSIDE_TARGET_REQUIRED")
    record["failure_stage"] = "PREFLIGHT_SOURCE_AND_RUNTIME_IMAGE"
    sources, binary_before = source_fingerprints(), fingerprint(binary)
    before = binary_before["sha256"]
    base = re.findall(r"^ARG RUNTIME_IMAGE=(debian:trixie-slim@sha256:[0-9a-f]{64})$", (ROOT / "Dockerfile").read_text(), re.MULTILINE)
    require(len(base) == 1, "PINNED_TRIXIE_RUNTIME_IMAGE_REQUIRED")
    base = base[0]
    record.update(architecture="linux/" + arch, runtime_image=base, binary_sha256=before, artifacts_sha256=digest(artifacts), containerd=None, fixture=None, failure_stage=None, owned_container_cleanup_confirmed=False, owned_image_cleanup_confirmed=False, source_unchanged=False, binary_unchanged=False)
    record["container_log_policy"] = LOG_CONFIG
    owner = uuid.uuid4().hex
    name, identity, create_attempted, image_build_attempted, stage = "sandbox-image-observation-" + owner, None, False, False, "PREPARE"
    image = {"tag": "sandbox-image-observation-fixture:" + owner, "id": None, "owner": owner}
    record["owned_container_name"] = name
    record["owned_fixture_image"] = image
    record["input_installation"] = {"mode": "LITERAL_PINNED_FROM_COPY_IMAGE_BEFORE_READ_ONLY_RUNTIME", "avoided_failure": "DOCKER_CP_TO_READ_ONLY_STOPPED_CONTAINER_REJECTED", "runtime_root_read_only": True, "source_or_credentials_in_context": False, "shared_build_cache_pruned": False}

    def call(label, command, timeout=30, check=True):
        log = evidence / (str(len(record["commands"]) + 1).zfill(2) + "-" + label + ".log")
        started = time.monotonic()
        with log.open("xb") as output:
            log.chmod(0o600)
            def output_bound():
                _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
                bound = MAX_LOG if hard == resource.RLIM_INFINITY else min(MAX_LOG, hard)
                resource.setrlimit(resource.RLIMIT_FSIZE, (bound, bound))
            child = subprocess.Popen(command, cwd=ROOT, env=environment, stdout=output, stderr=subprocess.STDOUT, start_new_session=True, preexec_fn=output_bound)
            failure = None
            try:
                while child.poll() is None:
                    if time.monotonic() - started > timeout:
                        failure = "SUBPROCESS_TIMEOUT"
                        break
                    if log.stat().st_size > MAX_LOG:
                        failure = "SUBPROCESS_OUTPUT_BOUND"
                        break
                    time.sleep(0.05)
            finally:
                if child.poll() is None:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                child.wait()
        if log.stat().st_size > MAX_LOG:
            with log.open("r+b") as output:
                output.truncate(MAX_LOG)
            failure = failure or "SUBPROCESS_OUTPUT_BOUND"
        record["commands"].append({"stage": label, "exit_code": child.returncode, "seconds": round(time.monotonic() - started, 3), "log": log.name, "log_sha256": digest(log), "failure": failure})
        require(failure is None, failure)
        require(not check or child.returncode == 0, "OWNED_SUBPROCESS_FAILED")
        return child.returncode, log.read_text(errors="replace")

    def ctr(*command, label, check=True):
        return call(label, [*docker, "exec", identity, "/usr/local/bin/ctr", "--address", "/run/containerd/containerd.sock", "--namespace", "k8s.io", *command], check=check)

    try:
        _, disk = call("disk-before", ["df", "-Pk", str(ROOT)])
        free = int(disk.splitlines()[-1].split()[3]) * 1024
        require(free >= 2 * 1024**3, "BOUNDED_FIXTURE_DISK_HEADROOM_REQUIRED")
        record["disk_available_before_bytes"] = free
        record["below_50gb_assessment"] = "No compile or existing cache copy; <=512MiB ELF, two <=128MiB verified binaries and <=64MiB archive in owned staging, plus a COPY-only image. Exact owned image/tag is removed; shared BuildKit cache is not pruned. No existing task output is selected for deletion." if free < 50 * 1024**3 else None
        with tempfile.TemporaryDirectory(prefix="sandbox-image-observation-") as temporary:
            work = Path(temporary).resolve()
            stage = "VERIFY_OFFICIAL_CONTAINERD"
            archive, record["containerd"] = verified_archive(args, arch, work)
            context = work / "context"
            files = context / "rootfs"
            record["fixture"] = prepare_files(files, archive, binary, arch)
            (context / "Dockerfile").write_text(fixture_dockerfile(base))
            (context / "Dockerfile").chmod(0o444)
            record["fixture_build_context"] = context_manifest(context)
            stage = "BUILD_OWNED_PUBLIC_COPY_IMAGE"
            image_build_attempted = True
            call("build-owned-copy-image", [*docker, "build", "--pull", "--network=none", "--platform", "linux/" + arch, "--label", "com.sandbox.fixture=nodeguard-image-observation", "--label", "com.sandbox.owner=" + owner, "--tag", image["tag"], "--file", str(context / "Dockerfile"), str(context)], timeout=180)
            require(context_manifest(context) == record["fixture_build_context"], "PUBLIC_BUILD_CONTEXT_CHANGED")
            _, built = call("inspect-owned-copy-image", [*docker, "image", "inspect", image["tag"]])
            image_value = json.loads(built)[0]
            verify_image(image_value, image)
            require(image_value.get("Os") == "linux" and image_value.get("Architecture") == arch, "OWNED_IMAGE_NATIVE_ARCH_REQUIRED")
            image["id"] = image_value["Id"]
            stage = "CREATE_OWNED_CONTAINER"
            create_attempted = True
            _, created = call("create", container_command(docker, name, arch, image), timeout=120)
            identity = created.strip()
            require(re.fullmatch(r"[0-9a-f]{64}", identity), "OWNED_CONTAINER_ID_REQUIRED")
            _, inspected = call("inspect-created", [*docker, "inspect", identity])
            verify_container(json.loads(inspected)[0], identity, name, image)
            stage = "START_EXACT_CONTAINERD"
            call("start", [*docker, "start", identity])
            _, libc = call("trixie-sysroot", [*docker, "exec", identity, "getconf", "GNU_LIBC_VERSION"])
            require(libc.strip() == "glibc 2.41", "REVIEWED_TRIXIE_SYSROOT_REQUIRED")
            record["glibc"] = libc.strip()
            _, copied_digest = call("verify-image-test-elf", [*docker, "exec", identity, "sha256sum", "/fixture/lib-test"])
            require(copied_digest.split() == [before, "/fixture/lib-test"], "IMAGE_TEST_ARTIFACT_DIGEST_MISMATCH")
            ready = time.monotonic() + 15
            while True:
                code, plugins = ctr("plugins", "list", label="plugins", check=False)
                if code == 0 and all(re.search(r"(?m)^" + re.escape(kind) + r"\s+" + item + r"\s+.*\sok\s*$", plugins) for kind, item in [("io.containerd.cri.v1", "images"), ("io.containerd.snapshotter.v1", "overlayfs")]):
                    break
                require(time.monotonic() < ready, "EXACT_CRI_AND_OVERLAYFS_PLUGINS_NOT_READY")
                time.sleep(0.2)
            _, version = ctr("version", label="native-containerd-version")
            require(len(re.findall(r"(?m)^\s*Version:\s+v?2\.3\.5\s*$", version)) == 2, "EXACT_CONTAINERD_CLIENT_AND_SERVER_REQUIRED")
            stage = "CHECK_EXACT_IGNORED_CASE"
            _, listing = call("test-inventory", [*docker, "exec", identity, "/fixture/lib-test", "--list", "--ignored", "--exact", CASE])
            require(listing.splitlines().count(CASE + ": test") == 1, "EXACT_IGNORED_CASE_REQUIRED")
            stage = "IMPORT_OWN_OCI_WITHOUT_UNPACK"
            _, empty = ctr("images", "list", "--quiet", label="empty-inventory")
            require(not empty.strip(), "EMPTY_OWNED_RUNTIME_REQUIRED")
            ctr("images", "import", "--no-unpack", "/fixture/image.tar", label="import-no-unpack")
            stage = "RUN_EXACT_NATIVE_CASE"
            _, output = call("native-case", [*docker, "exec", "--env", "SANDBOX_NATIVE_IMAGE_PROFILE=/fixture/host-profile.json", "--env", "SANDBOX_NATIVE_IMAGE_LOGICAL_BYTES=" + str(record["fixture"]["expected_compressed_logical_bytes"]), identity, "/fixture/lib-test", "--exact", CASE, "--ignored", "--test-threads=1", "--nocapture"], timeout=45)
            exact_result(output)
            stage = "VERIFY_NO_UNPACK_OR_RUNTIME_OBJECTS"
            _, images = ctr("images", "check", label="images-not-unpacked")
            rows = images.splitlines()[1:]
            require(rows and all(row.rstrip().endswith(" false") for row in rows), "IMAGE_MUST_REMAIN_NOT_UNPACKED")
            for kind in ("snapshots", "containers", "tasks"):
                _, objects = ctr(kind, "list", label=kind + "-absent")
                require(len(objects.strip().splitlines()) <= 1, "NO_SNAPSHOT_CONTAINER_OR_TASK_REQUIRED")
            _, inspected = call("inspect-after-case", [*docker, "inspect", identity])
            verify_container(json.loads(inspected)[0], identity, name, image)
            require(json.loads(inspected)[0]["State"]["Running"] is True and not json.loads(inspected)[0]["State"].get("OOMKilled"), "OWNED_DAEMON_MUST_REMAIN_HEALTHY")
            record["native_case_passed"] = True
    except BaseException as error:
        record["failure_stage"] = stage
        record["failure_code"] = str(error) if isinstance(error, CheckError) else "INTERRUPTED" if isinstance(error, KeyboardInterrupt) else "NATIVE_ACCEPTANCE_FAILED"
    finally:
        if create_attempted:
            try:
                code, inspected = call("cleanup-inspect", [*docker, "inspect", name], check=False)
                if code == 0:
                    value = json.loads(inspected)[0]
                    actual = value["Id"]
                    require(re.fullmatch(r"[0-9a-f]{64}", actual) and (identity is None or identity == actual), "OWNED_CONTAINER_ID_REQUIRED")
                    # Resource/isolation drift remains a failed gate but does
                    # not erase ownership or prevent retiring this exact task.
                    verify_owner(value, actual, name, image)
                    try:
                        call("daemon-private-log", [*docker, "logs", "--tail", "400", actual], check=False)
                    except Exception:
                        record["daemon_log_capture_failure"] = "PRIVATE_LOG_CAPTURE_UNCONFIRMED"
                    if value["State"]["Running"]:
                        try:
                            call("stop-owned-daemon", [*docker, "stop", "--time", "5", actual], timeout=15, check=False)
                        except Exception:
                            record["graceful_stop_failure"] = "FORCED_OWNED_RETIREMENT_REQUIRED"
                    call("remove-owned-container", [*docker, "rm", "--force", actual])
                    _, left = call("verify-owned-absence", [*docker, "container", "ls", "--all", "--no-trunc", "--filter", "id=" + actual, "--format", "{{.ID}}"])
                    record["owned_container_cleanup_confirmed"] = not left.strip()
                elif identity is not None:
                    _, left = call("verify-known-owned-absence", [*docker, "container", "ls", "--all", "--no-trunc", "--filter", "id=" + identity, "--format", "{{.ID}}"])
                    record["owned_container_cleanup_confirmed"] = not left.strip()
                # A lost create ACK with no ID and no observed object cannot
                # prove that a daemon-side late create will never materialize.
            except BaseException:
                record["cleanup_failure"] = "OWNED_DAEMON_RETIREMENT_UNCONFIRMED"
        else:
            record["owned_container_cleanup_confirmed"] = True
        if image_build_attempted:
            try:
                code, inspected = call("cleanup-image-inspect", [*docker, "image", "inspect", image["tag"]], check=False)
                if code == 0:
                    value = json.loads(inspected)[0]
                    verify_image(value, image)
                    image["id"] = value["Id"]
                    # No force/prune: retain the image if another exact owned
                    # process still references it or retirement is uncertain.
                    require(record["owned_container_cleanup_confirmed"], "CONTAINER_RETIREMENT_BEFORE_IMAGE_REMOVAL_REQUIRED")
                    call("remove-owned-image", [*docker, "image", "rm", image["tag"]])
                if image["id"] is not None:
                    _, left = call("verify-owned-image-absence", [*docker, "image", "ls", "--all", "--no-trunc", "--filter", "label=com.sandbox.owner=" + owner, "--format", "{{.ID}}"])
                    record["owned_image_cleanup_confirmed"] = not left.strip()
                # A timed-out build without an observed image cannot prove a
                # future daemon-side export/tag absent; retain UNKNOWN/failure.
            except BaseException:
                record["image_cleanup_failure"] = "OWNED_IMAGE_RETIREMENT_UNCONFIRMED"
        else:
            record["owned_image_cleanup_confirmed"] = True
        try:
            record["source_unchanged"] = source_fingerprints() == sources
            record["binary_unchanged"] = fingerprint(binary) == binary_before
            record["artifacts_unchanged"] = digest(artifacts) == record["artifacts_sha256"]
            record["source_sha256"] = hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest()
        except Exception:
            record["input_verification_failure"] = "FINAL_INPUT_IDENTITY_UNCONFIRMED"
        if record.get("native_case_passed") and record["failure_code"] is None and record["owned_container_cleanup_confirmed"] and record["owned_image_cleanup_confirmed"] and record["source_unchanged"] and record["binary_unchanged"] and record.get("artifacts_unchanged"):
            record["status"] = "PASS"
            record.update(passed=1, failed=0, ignored=0)
        record["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()


def run(args):
    # Create only a new private, non-symlink destination before any provider,
    # Cargo or ELF preflight. All subsequent failures receive a truthful receipt.
    evidence = args.evidence_dir.absolute()
    require(".." not in evidence.parts and not any(p.is_symlink() for p in (evidence, *evidence.parents)), "PRIVATE_EVIDENCE_PATH_REQUIRED")
    known_targets = [ROOT / "target"]
    if os.environ.get("CARGO_TARGET_DIR"):
        known_targets.append(Path(os.environ["CARGO_TARGET_DIR"]).absolute())
    require(not any(evidence == target or target in evidence.parents for target in known_targets), "PRIVATE_EVIDENCE_OUTSIDE_TARGET_REQUIRED")
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    evidence.chmod(0o700)
    record = {"status": "FAIL", "case": CASE, "commands": [], "failure_stage": "PREFLIGHT", "failure_code": None,
              "owned_container_cleanup_confirmed": True, "owned_image_cleanup_confirmed": True,
              "source_unchanged": None, "binary_unchanged": None, "artifacts_unchanged": None,
              "scope": ACCEPTANCE_SCOPE}
    try:
        accept(args, evidence, record)
    except BaseException as error:
        record["status"] = "FAIL"
        for field in ("passed", "failed", "ignored"):
            record.pop(field, None)
        record["failure_code"] = str(error) if isinstance(error, CheckError) else "INTERRUPTED" if isinstance(error, KeyboardInterrupt) else "NATIVE_PREFLIGHT_FAILED"
    finally:
        record["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        descriptor = os.open(evidence / "record.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as output:
            json.dump(record, output, indent=2)
            output.write("\n")
    if record["status"] != "PASS":
        error = CheckError("NATIVE_IMAGE_ACCEPTANCE_OR_CLEANUP_FAILED")
        error.evidence_saved = True
        raise error
    print(SUCCESS_MESSAGE)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--containerd-archive", type=Path)
    parser.add_argument("--containerd-checksum", type=Path)
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        run(parser.parse_args())
    except BaseException as error:
        suffix = "private evidence retained" if getattr(error, "evidence_saved", False) else "no completed evidence record was saved; a private evidence destination could not be safely created or written"
        print("Native image observation acceptance failed; " + suffix, file=sys.stderr)
        raise SystemExit(1) from None
