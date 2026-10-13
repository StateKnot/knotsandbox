"""Safe derived CI verdicts; original process output is never an artifact field."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "automation_diagnostics", Path(__file__).resolve().parents[1] / "test-automation.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class AutomationDiagnosticsTest(unittest.TestCase):
    def diagnostic(self, text, group="worker_process", code=0, timed_out=False):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "process.log"
            path.write_bytes(text.encode())
            result = runner.test_diagnostic(path, group, code, timed_out=timed_out)
            self.assertEqual(result["logSha256"], hashlib.sha256(text.encode()).hexdigest())
            self.assertEqual(result["logBytes"], len(text.encode()))
            return result

    def process(self, summary, *, name=None):
        return "running 1 test\ntest " + (name or runner.PROCESS_TEST) + " ... ok\n" + summary + "\n"

    def test_exact_process_pass_and_known_markers_are_closed_values(self):
        text = self.process("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;")
        text += "AUTOMATION_PROCESS_STEP CHECK START\n"
        text += "AUTOMATION_PROCESS_STEP UNKNOWN SECRET_BODY\n"
        result = self.diagnostic(text)
        self.assertEqual(result["testVerdict"], "EXACT_PASS")
        self.assertEqual(result["fixedMarkers"], ["AUTOMATION_PROCESS_STEP CHECK START"])
        self.assertNotIn("SECRET_BODY", json.dumps(result))

    def test_failure_class_and_source_location_do_not_copy_dynamic_error_text(self):
        secret = "postgresql://PRIVATE_LOGIN:PRIVATE_PASSWORD@private.example/SECRET_BODY"
        text = self.process("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;")
        text += "Error: Process test requires formal 1..37+39..44 and no invented migration38\n" + secret
        result = self.diagnostic(text, code=101)
        self.assertEqual(result["testVerdict"], "EXACT_FAILURE")
        self.assertEqual(result["classification"], "FORMAL_SCHEMA_MISMATCH")
        assertion = result["assertions"][0]
        self.assertEqual(assertion["sourceFile"], "tests/automation_process.rs")
        self.assertIsInstance(assertion["sourceLine"], int)
        serialized = json.dumps(result)
        for value in (secret, "PRIVATE_PASSWORD", "PRIVATE_LOGIN", "SECRET_BODY"):
            self.assertNotIn(value, serialized)

    def test_old_formal_contract_failure_remains_diagnosable_without_rewriting_log(self):
        text = self.process("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;")
        text += "Error: Process test requires formal 1..37+39..43 and no invented migration38\n"
        self.assertEqual(self.diagnostic(text, code=101)["classification"], "FORMAL_SCHEMA_MISMATCH")

    def test_zero_wrong_test_ignored_failed_exit_and_duplicate_summaries_never_pass(self):
        good = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"
        cases = ((self.process("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;"), 0),
                 (self.process(good, name="another_test"), 0),
                 (self.process("test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out;"), 0),
                 (self.process(good), 101), (self.process(good) + good + "\n", 0))
        for text, code in cases:
            with self.subTest(text=text, code=code):
                self.assertNotEqual(self.diagnostic(text, code=code)["testVerdict"], "EXACT_PASS")

    def test_timeout_overrides_a_partial_pass_and_unknown_errors_stay_fixed(self):
        text = self.process("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;")
        self.assertEqual(self.diagnostic(text, timed_out=True)["testVerdict"], "TEST_TIMEOUT")
        result = self.diagnostic("SECRET_URI SECRET_PASSWORD SECRET_BODY", code=101)
        self.assertEqual(result["classification"], "NO_EXACT_TEST_VERDICT")
        self.assertEqual(result["assertions"], [])
        self.assertNotIn("SECRET_", json.dumps(result))

    def test_all_formal_groups_require_their_exact_declared_selection_and_count(self):
        for group, (_, count, selector) in runner.TEST_GROUPS.items():
            if group == "worker_process":
                continue
            text = "running " + str(count) + " tests\n"
            text += "".join("test " + selector + "test_" + str(i) + " ... ok\n" for i in range(count))
            text += "test result: ok. " + str(count) + " passed; 0 failed; 0 ignored; 0 measured; 99 filtered out;\n"
            with self.subTest(group=group):
                self.assertEqual(self.diagnostic(text, group)["testVerdict"], "EXACT_PASS")
                self.assertNotEqual(self.diagnostic(text.replace(selector, "foreign::"), group)["testVerdict"], "EXACT_PASS")

    def test_large_log_is_hashed_completely_without_exposing_or_accepting_output(self):
        text = "SECRET_PASSWORD" * 90000
        result = self.diagnostic(text)
        self.assertEqual(result["testVerdict"], "DIAGNOSTIC_LOG_BOUND")
        self.assertEqual(result["assertions"], [])
        self.assertNotIn("SECRET_PASSWORD", json.dumps(result))

    def test_overlong_summary_number_cannot_break_failure_receipt(self):
        text = self.process("test result: ok. " + "1" * 4301
                            + " passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;")
        self.assertEqual(self.diagnostic(text)["testVerdict"], "NO_EXACT_TEST_VERDICT")

    def test_non_ascii_summary_digits_cannot_claim_an_exact_pass(self):
        text = self.process("test result: ok. \u0661 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;")
        self.assertEqual(self.diagnostic(text)["testVerdict"], "NO_EXACT_TEST_VERDICT")


if __name__ == "__main__":
    unittest.main()
