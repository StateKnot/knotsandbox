"""Gate rejection contracts; these tests never start Docker or a daemon."""
import argparse
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("image_gate", Path(__file__).resolve().parents[1] / "test-nodeguard-image-observation.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ImageGateBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    def artifact(self):
        (self.root / "src").mkdir()
        (self.root / "Cargo.toml").write_text("[package]\nname='sandbox-platform'\n")
        (self.root / "src/lib.rs").write_text("// ELF selection fixture, never executed\n")
        target = self.root / "target"
        (target / "debug/deps").mkdir(parents=True)
        binary = target / "debug/deps/sandbox_platform-0123456789abcdef"
        header = bytearray(64)
        header[:7], header[18:20] = b"\x7fELF\x02\x01\x01", (183).to_bytes(2, "little")
        binary.write_bytes(header)
        binary.chmod(0o755)
        item = {"name": "sandbox_platform", "kind": ["lib"], "src_path": str(self.root / "src/lib.rs")}
        package = {"name": "sandbox-platform", "id": "ordinary-cargo-package", "manifest_path": str(self.root / "Cargo.toml"), "targets": [item]}
        metadata = {"workspace_root": str(self.root), "target_directory": str(target), "packages": [package]}
        message = {"reason": "compiler-artifact", "package_id": package["id"], "manifest_path": package["manifest_path"], "target": item, "profile": {"test": True}, "executable": str(binary)}
        return binary, target, metadata, message

    def test_cargo_identity_elf_machine_and_permissions_cannot_be_substituted(self):
        binary, target, metadata, message = self.artifact()
        with patch.object(gate, "ROOT", self.root):
            self.assertEqual(gate.select_artifact([message], metadata, "arm64"), (binary, target))
            for changed in ("package", "manifest", "profile", "source", "kind", "duplicate", "engine-arch", "writable", "macho"):
                with self.subTest(changed=changed):
                    value = copy.deepcopy(message)
                    original = binary.read_bytes()
                    arch, messages = "arm64", [value]
                    if changed == "package": value["package_id"] = "another-package"
                    elif changed == "manifest": value["manifest_path"] = "/elsewhere/Cargo.toml"
                    elif changed == "profile": value["profile"]["test"] = 1
                    elif changed == "source": value["target"]["src_path"] = "/elsewhere/src/lib.rs"
                    elif changed == "kind": value["target"]["kind"] = ["bin"]
                    elif changed == "duplicate": messages.append(copy.deepcopy(value))
                    elif changed == "engine-arch": arch = "amd64"
                    elif changed == "writable": binary.chmod(0o777)
                    else: binary.write_bytes(b"\xcf\xfa\xed\xfe" + bytes(60))
                    try:
                        with self.assertRaises(gate.CheckError):
                            gate.select_artifact(messages, metadata, arch)
                    finally:
                        binary.write_bytes(original)
                        binary.chmod(0o755)

    def test_oci_expected_size_comes_from_exact_digest_closed_contents(self):
        for arch in ("amd64", "arm64"):
            path = self.root / (arch + ".tar")
            receipt = gate.image_fixture(path, arch)
            with tarfile.open(path) as archive:
                index = json.load(archive.extractfile("index.json"))
                self.assertEqual(index["manifests"][0]["platform"], {"os": "linux", "architecture": arch})
                total = 0
                for descriptor in [receipt["manifest"], receipt["config"], *receipt["layers"]]:
                    data = archive.extractfile("blobs/sha256/" + descriptor["digest"][7:]).read()
                    self.assertEqual(len(data), descriptor["size"])
                    self.assertEqual(hashlib.sha256(data).hexdigest(), descriptor["digest"][7:])
                    total += len(data)
                self.assertEqual(total, receipt["expected_compressed_logical_bytes"])
                self.assertGreater(total, 0)
                self.assertFalse(receipt["unpack_requested"])
                config = json.load(archive.extractfile("blobs/sha256/" + receipt["config"]["digest"][7:]))
                self.assertEqual(config["rootfs"]["diff_ids"], [receipt["layers"][0]["digest"]])

    def test_matching_downloaded_checksums_do_not_replace_reviewed_archive_pin(self):
        archive = self.root / "archive"
        checksum = self.root / "checksum"
        archive.write_bytes(b"small controlled archive input")
        name = "containerd-2.3.5-linux-arm64.tar.gz"
        checksum.write_text(gate.digest(archive) + "  " + name + "\n")
        args = argparse.Namespace(containerd_archive=archive, containerd_checksum=checksum)
        pin = {"archive_bytes": archive.stat().st_size, "archive_sha256": gate.digest(archive), "checksum_sha256": gate.digest(checksum)}
        with patch.dict(gate.PINS, {"arm64": pin}):
            self.assertEqual(gate.verified_archive(args, "arm64", self.root)[0], archive)
            archive.write_bytes(b"changed controlled archive!")
            checksum.write_text(gate.digest(archive) + "  " + name + "\n")
            with self.assertRaisesRegex(gate.CheckError, "CONTAINERD_ARCHIVE_PIN_MISMATCH"):
                gate.verified_archive(args, "arm64", self.root)

    def test_zero_skip_missing_marker_duplicate_marker_or_multiple_summaries_fail(self):
        good = gate.MARKER + "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 400 filtered out; finished in 0.02s\n"
        gate.exact_result(good)
        for output in (good.replace("1 passed", "0 passed"), good.replace("0 ignored", "1 ignored"), good.replace(gate.MARKER, ""), good + gate.MARKER, good + good):
            with self.assertRaises(gate.CheckError):
                gate.exact_result(output)

    def test_owner_scope_privileges_mounts_and_resource_bounds_are_verified(self):
        image = {"tag": "sandbox-image-observation-fixture:" + "a" * 32, "owner": "a" * 32, "id": "sha256:" + "c" * 64}
        identity, name = "b" * 64, "owned-name"
        value = {"Id": identity, "Name": "/" + name, "Image": image["id"], "Config": {"Image": image["tag"], "User": "0:0", "Labels": {"com.sandbox.fixture": "nodeguard-image-observation", "com.sandbox.owner": image["owner"]}}, "Mounts": [],
                 "HostConfig": {"Binds": None, "Privileged": False, "CapAdd": None, "CapDrop": ["ALL"], "NetworkMode": "none", "ReadonlyRootfs": True, "PidMode": "", "CgroupnsMode": "private", "Memory": gate.MEMORY, "MemorySwap": gate.MEMORY, "NanoCpus": 1000000000, "PidsLimit": 128, "Tmpfs": gate.TMPFS, "SecurityOpt": ["no-new-privileges:true"], "Ulimits": [{"Name": "nofile", "Soft": 1024, "Hard": 1024}], "LogConfig": gate.LOG_CONFIG}}
        gate.verify_container(value, identity, name, image)
        for key, replacement in [("Privileged", True), ("CapAdd", ["SYS_ADMIN"]), ("NetworkMode", "host"), ("PidMode", "host"), ("CgroupnsMode", "host"), ("Memory", 0), ("MemorySwap", -1), ("PidsLimit", 0), ("Tmpfs", {}), ("Ulimits", []), ("LogConfig", {"Type": "local", "Config": {"max-size": "1m", "max-file": "1", "compress": "true"}})]:
            with self.subTest(key=key):
                changed = copy.deepcopy(value)
                changed["HostConfig"][key] = replacement
                # Failure of a runtime bound must not prevent cleaning up the
                # exact already-owned container; only identity gates deletion.
                gate.verify_owner(changed, identity, name, image)
                with self.assertRaises(gate.CheckError):
                    gate.verify_container(changed, identity, name, image)
        for field, replacement in [("Mounts", [{"Type": "bind", "Source": "/private/source"}]), ("Name", "/another-container")]:
            changed = copy.deepcopy(value)
            changed[field] = replacement
            with self.assertRaises(gate.CheckError):
                gate.verify_container(changed, identity, name, image)

    def test_copy_only_image_populates_public_inputs_before_read_only_create(self):
        base = "debian:trixie-slim@sha256:" + "a" * 64
        self.assertEqual(gate.fixture_dockerfile(base), "FROM " + base + "\nCOPY rootfs/ /\n")
        for invalid in ("debian:trixie-slim", base + "\nRUN true", "debian:bookworm@sha256:" + "a" * 64):
            with self.assertRaises(gate.CheckError):
                gate.fixture_dockerfile(invalid)
        binary = self.root / "lib-test"
        binary.write_bytes(b"public non-executed ELF placeholder")
        archive = self.root / "containerd.tar.gz"
        with tarfile.open(archive, "w:gz") as target:
            for name in ("containerd", "ctr"):
                content = ("public " + name + " placeholder").encode()
                item = tarfile.TarInfo("bin/" + name)
                item.size = len(content)
                target.addfile(item, io.BytesIO(content))
        context = self.root / "context"
        gate.prepare_files(context / "rootfs", archive, binary, "arm64")
        (context / "Dockerfile").write_text(gate.fixture_dockerfile(base))
        manifest = gate.context_manifest(context)
        self.assertEqual(len(manifest), 13)
        self.assertEqual(manifest["rootfs/fixture/lib-test"]["sha256"], gate.digest(binary))
        self.assertEqual((context / "rootfs/fixture").stat().st_mode & 0o777, 0o555)
        self.assertEqual((context / "rootfs/etc/containerd").stat().st_mode & 0o777, 0o755)
        profile = json.loads((context / "rootfs/fixture/host-profile.json").read_text())
        self.assertEqual(profile["containerd_configuration"]["sha256"], gate.digest(context / "rootfs/etc/containerd/config.toml"))
        (context / ".env").write_text("UNEXPECTED_CONTEXT_INPUT=must-reject\n")
        with self.assertRaisesRegex(gate.CheckError, "EXACT_PUBLIC_IMAGE_BUILD_CONTEXT_REQUIRED"):
            gate.context_manifest(context)
        image = {"tag": "owned-fixture:random"}
        command = gate.container_command(["docker"], "owned-name", "arm64", image)
        self.assertEqual(command[:2], ["docker", "create"])
        self.assertIn("--read-only", command)
        self.assertNotIn("cp", command)
        self.assertNotIn("--mount", command)
        self.assertEqual(command[command.index("--log-driver") + 1], "local")
        self.assertEqual([command[i + 1] for i, value in enumerate(command) if value == "--log-opt"], ["max-size=1m", "max-file=1", "compress=false"])
        for path in ("/run", "/var/lib/containerd"):
            self.assertIn("mode=0755", gate.TMPFS[path])
        # Immutable profile/config/ELF paths must never be hidden by tmpfs.
        for input_path in ("/fixture/lib-test", "/fixture/host-profile.json", "/etc/containerd/config.toml", "/usr/local/bin/containerd"):
            self.assertFalse(any(input_path == p or input_path.startswith(p + "/") for p in gate.TMPFS))

    def test_cleanup_image_ownership_rejects_retagging_and_other_owners(self):
        image = {"tag": "owned-fixture:random", "owner": "a" * 32, "id": "sha256:" + "b" * 64}
        value = {"Id": image["id"], "RepoTags": [image["tag"]], "Config": {"Labels": {"com.sandbox.fixture": "nodeguard-image-observation", "com.sandbox.owner": image["owner"]}}}
        gate.verify_image(value, image)
        for changed in ("id", "tag", "owner"):
            item = copy.deepcopy(value)
            if changed == "id": item["Id"] = "sha256:" + "c" * 64
            elif changed == "tag": item["RepoTags"] = ["another:tag"]
            else: item["Config"]["Labels"]["com.sandbox.owner"] = "d" * 32
            with self.assertRaisesRegex(gate.CheckError, "OWNED_FIXTURE_IMAGE_MISMATCH"):
                gate.verify_image(item, image)

    def test_docker_preflight_failure_keeps_only_fixed_private_failure_receipt(self):
        evidence = self.root / "evidence"
        args = argparse.Namespace(artifacts=self.root / "not-read", evidence_dir=evidence)
        helper = SimpleNamespace(local_docker=lambda: (_ for _ in ()).throw(RuntimeError("PROVIDER_SECRET_MUST_NOT_BE_SAVED")))
        with patch.object(gate, "ROOT", self.root), patch.object(gate.Path, "cwd", return_value=self.root), patch.object(gate, "module", return_value=helper):
            with self.assertRaises(gate.CheckError) as caught:
                gate.run(args)
        self.assertTrue(caught.exception.evidence_saved)
        data = json.loads((evidence / "record.json").read_text())
        self.assertEqual(data["status"], "FAIL")
        self.assertEqual(data["failure_stage"], "PREFLIGHT_DOCKER_ENDPOINT")
        self.assertEqual(data["failure_code"], "NATIVE_PREFLIGHT_FAILED")
        self.assertNotIn("PROVIDER_SECRET", json.dumps(data))
        self.assertEqual((evidence / "record.json").stat().st_mode & 0o777, 0o600)
        self.assertTrue(data["owned_container_cleanup_confirmed"])

    def test_real_wrong_elf_preflight_rejection_keeps_failure_receipt(self):
        binary, target, metadata, message = self.artifact()
        artifacts = self.root / "artifacts.jsonl"
        artifacts.write_text(json.dumps(message) + "\n")
        evidence = self.root / "evidence"
        args = argparse.Namespace(artifacts=artifacts, evidence_dir=evidence)
        helper = SimpleNamespace(local_docker=lambda: (["docker"], {}), invoke=lambda *args, **kwargs: '{"Os":"linux","Arch":"amd64"}')
        result = subprocess.CompletedProcess(["cargo"], 0, json.dumps(metadata), "")
        with patch.object(gate, "ROOT", self.root), patch.object(gate.Path, "cwd", return_value=self.root), patch.object(gate, "module", return_value=helper), patch.object(gate.subprocess, "run", return_value=result):
            with self.assertRaises(gate.CheckError) as caught:
                gate.run(args)
        self.assertTrue(caught.exception.evidence_saved)
        data = json.loads((evidence / "record.json").read_text())
        self.assertEqual(data["failure_stage"], "PREFLIGHT_CARGO_ELF_IDENTITY")
        self.assertEqual(data["failure_code"], "DOCKER_NATIVE_LINUX_ELF_REQUIRED")
        self.assertEqual(data["status"], "FAIL")
        self.assertIsNone(data["binary_unchanged"])

    def test_unsafe_evidence_path_never_claims_a_saved_receipt(self):
        destination = self.root / "real-directory"
        destination.mkdir()
        alias = self.root / "evidence-alias"
        alias.symlink_to(destination, target_is_directory=True)
        args = argparse.Namespace(artifacts=self.root / "not-read", evidence_dir=alias)
        with patch.object(gate, "module") as helper:
            with self.assertRaises(gate.CheckError) as caught:
                gate.run(args)
        self.assertFalse(getattr(caught.exception, "evidence_saved", False))
        self.assertFalse((destination / "record.json").exists())
        helper.assert_not_called()

    def test_late_interruption_cannot_preserve_a_previously_set_pass(self):
        evidence = self.root / "evidence"
        args = argparse.Namespace(artifacts=self.root / "not-read", evidence_dir=evidence)
        def interrupted(_args, _evidence, record):
            record.update(status="PASS", passed=1, failed=0, ignored=0)
            raise KeyboardInterrupt
        with patch.object(gate, "accept", side_effect=interrupted):
            with self.assertRaises(gate.CheckError) as caught:
                gate.run(args)
        self.assertTrue(caught.exception.evidence_saved)
        data = json.loads((evidence / "record.json").read_text())
        self.assertEqual(data["status"], "FAIL")
        self.assertEqual(data["failure_code"], "INTERRUPTED")
        self.assertFalse(any(field in data for field in ("passed", "failed", "ignored")))


if __name__ == "__main__":
    unittest.main()
