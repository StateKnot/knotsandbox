"""SBOM coverage for the reviewed path backport, not scanner certification."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gate import validate_sboms


class PathDependencySbomTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def candidate(self, packages, artifacts):
        lines = []
        for package in packages:
            lines.append('[[package]]')
            lines.extend(key + '=' + json.dumps(value) for key, value in package.items())
        (self.directory / 'Cargo.lock').write_text('\n'.join(lines) + '\n')
        for name in ('service', 'runner', 'rust-binaries'):
            (self.directory / (name + '.syft.json')).write_text(json.dumps({
                'artifacts': [{'name': item[0], 'version': item[1], 'type': 'rust-crate'}
                              for item in artifacts]}))
        for name in ('console-npm-locks', 'console-security.lock'):
            (self.directory / (name + '.json')).write_text('{}')
        (self.directory / 'console.syft.json').write_text('{"artifacts":[]}')

    def validate(self, **kwargs):
        # This suite exercises the real public SBOM gate's Rust contract. Console
        # and native contracts have independent full-fixture regression suites.
        with patch('gate.validate_inventory', return_value=set()), \
             patch('gate.validate_console_lock', return_value={}), \
             patch('gate.validate_console_inventory'), patch('gate.validate_native'):
            validate_sboms(self.directory, **kwargs)

    def packages(self):
        return [{'name': 'sandbox-platform', 'version': '0.1.0'},
                {'name': 'sqlx-core', 'version': '0.8.6',
                 'source': 'registry+https://github.com/rust-lang/crates.io-index'},
                {'name': 'sqlx-postgres', 'version': '0.8.6'}]

    def test_reviewed_path_package_remains_required_in_every_rust_sbom(self):
        artifacts = [('sqlx-core', '0.8.6'), ('sqlx-postgres', '0.8.6')]
        for scope in ('service', 'runner', 'rust-binaries'):
            with self.subTest(scope=scope):
                self.candidate(self.packages(), artifacts)
                (self.directory / (scope + '.syft.json')).write_text(json.dumps({
                    'artifacts': [{'name': 'sqlx-core', 'version': '0.8.6', 'type': 'rust-crate'}]}))
                with self.assertRaisesRegex(ValueError, 'CARGO_DEPENDENCIES_MISSING_FROM_SBOM'):
                    self.validate()

    def test_reviewed_path_and_root_package_are_distinguished(self):
        self.candidate(self.packages(), [('sqlx-core', '0.8.6'), ('sqlx-postgres', '0.8.6')])
        self.validate()

    def test_unknown_path_package_is_rejected_even_if_scanner_lists_it(self):
        packages = self.packages() + [{'name': 'other-override', 'version': '1.0.0'}]
        self.candidate(packages, [(p['name'], p['version']) for p in packages])
        with self.assertRaisesRegex(ValueError, 'CARGO_UNREVIEWED_PATH_DEPENDENCY'):
            self.validate()

    def test_different_backport_version_is_rejected(self):
        packages = self.packages()
        packages[-1]['version'] = '0.8.7'
        self.candidate(packages, [(p['name'], p['version']) for p in packages])
        with self.assertRaisesRegex(ValueError, 'CARGO_UNREVIEWED_PATH_DEPENDENCY'):
            self.validate()

    def test_path_package_cannot_claim_an_upstream_registry_checksum(self):
        packages = self.packages()
        packages[-1]['checksum'] = 'a' * 64
        self.candidate(packages, [(p['name'], p['version']) for p in packages])
        with self.assertRaisesRegex(ValueError, 'CARGO_UNREVIEWED_PATH_DEPENDENCY'):
            self.validate()

    def test_duplicate_path_package_is_rejected(self):
        packages = self.packages() + [{'name': 'sqlx-postgres', 'version': '0.8.6'}]
        self.candidate(packages, [(p['name'], p['version']) for p in packages])
        with self.assertRaisesRegex(ValueError, 'CARGO_PATH_DEPENDENCY_AMBIGUOUS'):
            self.validate()

    def test_mixed_registry_and_path_sqlx_versions_are_rejected(self):
        packages = self.packages() + [{'name': 'sqlx-postgres', 'version': '0.8.5',
                                     'source': 'registry+https://github.com/rust-lang/crates.io-index'}]
        self.candidate(packages, [(p['name'], p['version']) for p in packages])
        with self.assertRaisesRegex(ValueError, 'CARGO_PATH_DEPENDENCY_AMBIGUOUS'):
            self.validate()

    def test_git_dependency_is_also_required(self):
        packages = self.packages() + [{'name': 'git-dependency', 'version': '1.0.0',
                                     'source': 'git+https://example.invalid/crate#' + 'a' * 40}]
        self.candidate(packages, [('sqlx-core', '0.8.6'), ('sqlx-postgres', '0.8.6')])
        with self.assertRaisesRegex(ValueError, 'CARGO_DEPENDENCIES_MISSING_FROM_SBOM'):
            self.validate()

    def test_unknown_source_scheme_is_rejected(self):
        packages = self.packages()
        packages[-1]['source'] = 'file:///unreviewed/source'
        self.candidate(packages, [(p['name'], p['version']) for p in packages])
        with self.assertRaisesRegex(ValueError, 'CARGO_UNREVIEWED_DEPENDENCY_SOURCE'):
            self.validate()

    def test_historical_registry_package_keeps_existing_coverage_contract(self):
        packages = self.packages()
        packages[-1]['source'] = 'registry+https://github.com/rust-lang/crates.io-index'
        packages[-1]['checksum'] = 'b' * 64
        self.candidate(packages, [('sqlx-core', '0.8.6'), ('sqlx-postgres', '0.8.6')])
        self.validate(legacy=True, historical=True)


if __name__ == '__main__':
    unittest.main()
