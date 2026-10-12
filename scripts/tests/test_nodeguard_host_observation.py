import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("host_gate", Path(__file__).resolve().parents[1] / "test-nodeguard-host-observation.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class HostGateContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir="/private/tmp" if os.path.isdir("/private/tmp") else None)
        self.root = Path(self.temporary.name) / "project"
        (self.root / "src").mkdir(parents=True)
        (self.root / "Cargo.toml").write_text("[package]\nname = 'sandbox-platform'\n")
        (self.root / "src/lib.rs").write_text("// public parser fixture; no actual executable acceptance\n")
        self.target = self.root / "target"
        (self.target / "debug/deps").mkdir(parents=True)
        self.binary = self.target / "debug/deps/sandbox_platform-0123456789abcdef"
        header = bytearray(64)
        header[:7] = b"\x7fELF\x02\x01\x01"
        machine = 62 if platform.machine() == "x86_64" else 183
        header[18:20] = machine.to_bytes(2, "little")
        self.binary.write_bytes(header)
        self.binary.chmod(0o755)
        target = {"name": "sandbox_platform", "kind": ["lib"], "src_path": str(self.root / "src/lib.rs")}
        self.metadata = {"workspace_root": str(self.root), "target_directory": str(self.target),
                         "packages": [{"name": "sandbox-platform", "manifest_path": str(self.root / "Cargo.toml"),
                                       "id": "path+file://" + str(self.root) + "#sandbox-platform@0.1.0", "targets": [target]}]}
        self.message = {"reason": "compiler-artifact", "package_id": self.metadata["packages"][0]["id"],
                        "manifest_path": str(self.root / "Cargo.toml"), "target": target,
                        "profile": {"test": True}, "executable": str(self.binary)}

    def tearDown(self):
        self.temporary.cleanup()

    def select(self, messages=None, metadata=None):
        return gate.select_artifact(messages if messages is not None else [self.message],
                                    metadata if metadata is not None else self.metadata, self.root)

    def test_exact_root_lib_artifact_is_selected_and_duplicate_output_rejected(self):
        self.assertEqual(self.select(), (self.binary, self.target))
        with self.assertRaisesRegex(gate.CheckError, "UNIQUE_LIB_TEST_ARTIFACT_REQUIRED"):
            self.select([self.message, copy.deepcopy(self.message)])

    def test_forged_profile_package_manifest_and_source_cannot_select_a_program(self):
        for change in ("profile-false", "profile-number", "package", "manifest", "source", "kind"):
            with self.subTest(change=change):
                value = copy.deepcopy(self.message)
                if change == "profile-false": value["profile"]["test"] = False
                elif change == "profile-number": value["profile"]["test"] = 1
                elif change == "package": value["package_id"] = "unrelated"
                elif change == "manifest": value["manifest_path"] = "/elsewhere/Cargo.toml"
                elif change == "source": value["target"]["src_path"] = "/elsewhere/src/lib.rs"
                else: value["target"]["kind"] = ["bin"]
                with self.assertRaises(gate.CheckError): self.select([value])

    def test_real_symlink_parent_and_outside_target_paths_are_rejected(self):
        outside = self.root / self.binary.name
        outside.write_bytes(self.binary.read_bytes())
        outside.chmod(0o755)
        value = copy.deepcopy(self.message)
        value["executable"] = str(outside)
        with self.assertRaisesRegex(gate.CheckError, "CARGO_TARGET_LAYOUT_MISMATCH"): self.select([value])
        alias = self.root / "target-alias"
        alias.symlink_to(self.target, target_is_directory=True)
        metadata = copy.deepcopy(self.metadata)
        metadata["target_directory"] = str(alias)
        with self.assertRaisesRegex(gate.CheckError, "SYMLINK_FORBIDDEN"): self.select(metadata=metadata)
        self.binary.unlink()
        self.binary.symlink_to(outside)
        with self.assertRaisesRegex(gate.CheckError, "SYMLINK_FORBIDDEN"): self.select()

    def test_case_inventory_requires_one_ignored_exact_case(self):
        gate.inventory(gate.CASE + ": test\n1 test, 0 benchmarks\n")
        for output in ("0 tests, 0 benchmarks\n", "unrelated: test\n", (gate.CASE + ": test\n") * 2):
            with self.assertRaisesRegex(gate.CheckError, "EXACT_IGNORED_CASE_REQUIRED"): gate.inventory(output)

    def test_zero_tests_ignored_tests_missing_or_duplicate_completion_are_not_acceptance(self):
        good = gate.MARKER + "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 401 filtered out; finished in 0.02s\n"
        gate.completed(good)
        for output in (good.replace("1 passed", "0 passed"), good.replace("0 ignored", "1 ignored"),
                       good.replace(gate.MARKER, ""), gate.MARKER + "\n" + good,
                       good + good, good.replace("0 failed", "1 failed")):
            with self.assertRaises(gate.CheckError): gate.completed(output)

    def run_entry(self, results, after_case=None):
        artifacts = self.root / "artifacts.jsonl"
        artifacts.write_text(json.dumps(self.message) + "\n")
        evidence = self.root / "evidence"
        args = argparse.Namespace(artifacts=artifacts, evidence_dir=evidence)
        caller_uid = os.geteuid() or 1001
        if os.geteuid() == 0:
            os.chown(self.binary, caller_uid, caller_uid)
        results = [subprocess.CompletedProcess(["cargo"], 0, json.dumps(self.metadata), ""), *results]
        pending = iter(results)
        def execute(command, **kwargs):
            result = next(pending)
            if after_case is not None and command[-1] == "--test-threads=1":
                after_case()
            return result
        with patch.object(gate, "ROOT", self.root), patch.object(gate.sys, "platform", "linux"), \
             patch.object(gate.os, "geteuid", return_value=caller_uid), \
             patch.object(gate.Path, "cwd", return_value=self.root), \
             patch.object(gate, "trusted_system_program", side_effect=str), \
             patch.object(gate.subprocess, "run", side_effect=execute) as process:
            try:
                gate.run(args)
            finally:
                self.commands = [call.args[0] for call in process.call_args_list]

    def failed_receipt(self):
        receipt = json.loads((self.root / "evidence/record.json").read_text())
        self.assertEqual(receipt["status"], "FAILED")
        self.assertTrue(receipt["binary_unchanged"])
        self.assertNotIn("passed", receipt)
        return receipt

    def test_sudo_permission_failure_stops_before_test_and_retains_failed_receipt(self):
        with self.assertRaisesRegex(gate.CheckError, "PRIVILEGED_UID_CHECK_FAILED"):
            self.run_entry([subprocess.CompletedProcess(["sudo"], 1, "", "sudo: a password is required")])
        self.assertEqual(len(self.commands), 2)
        self.assertEqual(self.commands[0][0], "cargo")
        self.assertEqual(self.commands[1], ["/usr/bin/sudo", "-n", "--", "/usr/bin/id", "-u"])
        self.failed_receipt()

    def test_same_inode_on_different_namespace_devices_retains_failed_receipt(self):
        with self.assertRaisesRegex(gate.CheckError, "PID1_INITIAL_MOUNT_NAMESPACE_REQUIRED"):
            self.run_entry([subprocess.CompletedProcess(["sudo"], 0, "0\n", ""),
                            subprocess.CompletedProcess(["stat"], 0, "4:900\n5:900\n", "")])
        self.assertEqual(len(self.commands), 3)
        self.failed_receipt()

    def test_exit_zero_and_one_pass_without_marker_still_retains_failed_receipt(self):
        output = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 401 filtered out; finished in 0.02s\n"
        with self.assertRaisesRegex(gate.CheckError, "HOST_COMPLETION_MARKER_REQUIRED"):
            self.run_entry([subprocess.CompletedProcess(["sudo"], 0, "0\n", ""),
                            subprocess.CompletedProcess(["stat"], 0, "4:900\n4:900\n", ""),
                            subprocess.CompletedProcess(["inventory"], 0, gate.CASE + ": test\n", ""),
                            subprocess.CompletedProcess(["case"], 0, output, "")])
        self.assertEqual(self.commands[-1], ["/usr/bin/sudo", "-n", "--", str(self.binary), gate.CASE,
                                           "--exact", "--ignored", "--nocapture", "--test-threads=1"])
        self.failed_receipt()

    def test_unreadable_after_execution_binary_retains_failed_receipt(self):
        output = gate.MARKER + "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 401 filtered out; finished in 0.02s\n"
        with self.assertRaisesRegex(gate.CheckError, "BINARY_CHANGED_DURING_HOST_GATE"):
            self.run_entry([subprocess.CompletedProcess(["sudo"], 0, "0\n", ""),
                            subprocess.CompletedProcess(["stat"], 0, "4:900\n4:900\n", ""),
                            subprocess.CompletedProcess(["inventory"], 0, gate.CASE + ": test\n", ""),
                            subprocess.CompletedProcess(["case"], 0, output, "")],
                           after_case=self.binary.unlink)
        receipt = json.loads((self.root / "evidence/record.json").read_text())
        self.assertEqual(receipt["status"], "FAILED")
        self.assertIsNone(receipt["binary_after"])
        self.assertFalse(receipt["binary_unchanged"])
        self.assertIn("FileNotFoundError", receipt["post_execution_binary_error"])

    def test_case_failure_is_preserved_when_binary_also_disappears(self):
        with self.assertRaisesRegex(gate.CheckError, "HOST_TEST_FAILED"):
            self.run_entry([subprocess.CompletedProcess(["sudo"], 0, "0\n", ""),
                            subprocess.CompletedProcess(["stat"], 0, "4:900\n4:900\n", ""),
                            subprocess.CompletedProcess(["inventory"], 0, gate.CASE + ": test\n", ""),
                            subprocess.CompletedProcess(["case"], 101, "", "fixture rejected")],
                           after_case=self.binary.unlink)
        receipt = json.loads((self.root / "evidence/record.json").read_text())
        self.assertEqual(receipt["status"], "FAILED")
        self.assertIn("HOST_TEST_FAILED", receipt["failure"])
        self.assertIn("FileNotFoundError", receipt["post_execution_binary_error"])
        self.assertFalse(receipt["binary_unchanged"])

    def test_root_caller_cannot_execute_cargo_or_use_the_gate(self):
        args = argparse.Namespace(artifacts=self.root / "missing", evidence_dir=self.root / "missing-evidence")
        with patch.object(gate.sys, "platform", "linux"), patch.object(gate.os, "geteuid", return_value=0), \
             patch.object(gate.subprocess, "run") as process:
            with self.assertRaisesRegex(gate.CheckError, "ORDINARY_CALLER_REQUIRED"): gate.run(args)
        process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
