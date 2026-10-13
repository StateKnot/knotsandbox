import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

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


if __name__ == "__main__":
    unittest.main()
