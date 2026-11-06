import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from contextlib import redirect_stderr
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location(
    "console_browser", Path(__file__).resolve().parents[1] / "test-console-browser.py"
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class LocalIdentityContract(unittest.TestCase):
    def setUp(self):
        self.docker = ["docker", "--host", "unix:///var/run/docker.sock"]
        self.environment = {"PATH": "/usr/bin"}

    def issuer(self, binding):
        self.fixture = SimpleNamespace(invoke=Mock(return_value=binding))
        return runner.local_keycloak_issuer(self.docker, self.environment, self.fixture)

    def test_current_ci_default_and_existing_local_mapping_both_drive_the_issuer(self):
        for port in (58080, 58073, 32769):
            with self.subTest(port=port):
                self.assertEqual(self.issuer(f"127.0.0.1:{port}"),
                                 f"http://127.0.0.1:{port}/realms/sandbox-dev")
                self.fixture.invoke.assert_called_once_with(
                    [*self.docker, "port", "sandbox-platform-dev-keycloak-1", "8080/tcp"],
                    env=self.environment, timeout=15,
                )

    def test_public_ipv6_ambiguous_missing_and_invalid_ports_are_rejected(self):
        for binding in ("0.0.0.0:58080", "[::]:58080", "localhost:58080", "",
                        "127.0.0.1:58080\n127.0.0.1:58073", "127.0.0.1:0",
                        "127.0.0.1:65536", "127.0.0.1:-1", "127.0.0.1:58080/path"):
            with self.subTest(binding=binding), self.assertRaisesRegex(
                RuntimeError, "one literal-loopback Keycloak port"
            ):
                self.issuer(binding)

    def test_unavailable_fixed_container_fails_without_a_fallback_endpoint(self):
        fixture = SimpleNamespace(invoke=Mock(side_effect=RuntimeError("Docker unavailable")))
        with self.assertRaisesRegex(RuntimeError, "Docker unavailable"):
            runner.local_keycloak_issuer(self.docker, self.environment, fixture)


class DiskPreflight(unittest.TestCase):
    hosted = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
    gib = 1024**3

    def invoke(self, path, free, environment, *flags):
        argv = ["test-console-browser.py", "--node", sys.executable,
                "--chrome", sys.executable, "--identity-python", sys.executable,
                "--evidence-dir", str(path), *flags]
        with (patch.object(sys, "argv", argv), patch.object(sys, "platform", "linux"),
              patch.dict(os.environ, {"RESTORE_TEST_DOCKER_HOST": "unix:///var/run/docker.sock",
                                      **environment}, clear=True),
              patch.object(runner.shutil, "disk_usage", return_value=SimpleNamespace(free=free)),
              redirect_stderr(io.StringIO())):
            return runner.main()

    def test_local_budget_still_applies_with_ci_environment_alone(self):
        with tempfile.TemporaryDirectory() as parent:
            path = Path(parent).resolve() / "receipt"
            self.assertEqual(self.invoke(path, 49 * self.gib, self.hosted), 1)
            receipt = json.loads((path / "record.json").read_text())
            self.assertEqual(receipt["failed_stage"], "disk_preflight")
            self.assertEqual(receipt["disk_preflight"]["required_bytes"], 50 * self.gib)
            self.assertFalse((path / "source").exists())

    def test_hosted_budget_reports_failure_below_its_boundary(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent).resolve()
            path = root / "below"
            self.assertEqual(self.invoke(path, 4 * self.gib - 1, self.hosted, "--github-hosted-ci"), 1)
            receipt = json.loads((path / "record.json").read_text())
            self.assertEqual(receipt["disk_preflight"]["required_bytes"], 4 * self.gib)

    def test_invalid_docker_configuration_keeps_evidence_path_available(self):
        with tempfile.TemporaryDirectory() as parent:
            path = Path(parent).resolve() / "receipt"
            with self.assertRaisesRegex(Exception, "Docker configuration must be absolute"):
                self.invoke(path, 80 * self.gib, {"RESTORE_TEST_DOCKER_CONFIG": "relative"})
            self.assertFalse(path.exists())

    def test_ci_option_rejects_self_hosted_and_manual_demo(self):
        with tempfile.TemporaryDirectory() as parent:
            path = Path(parent).resolve() / "receipt"
            for env, flags in (({**self.hosted, "RUNNER_ENVIRONMENT": "self-hosted"}, ()),
                               (self.hosted, ("--manual-demo",))):
                with self.subTest(env=env, flags=flags), self.assertRaises(SystemExit) as error:
                    self.invoke(path, 80 * self.gib, env, "--github-hosted-ci", *flags)
                self.assertEqual(error.exception.code, 2)
                self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
