"""Exercise the source boundary with real tampering, without compiling Rust."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("sqlx_patch", ROOT / "scripts/verify-sqlx-postgres-patch.py")
patch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch)


class SourceBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ("Cargo.toml", "Cargo.lock", ".dockerignore"):
            shutil.copy2(ROOT / name, self.root / name)
        self.vendor = self.root / "vendor/sqlx-postgres"
        shutil.copytree(ROOT / "vendor/sqlx-postgres", self.vendor)

    def rejected(self):
        with self.assertRaises(RuntimeError):
            patch.verify(self.root)

    def test_exact_sources_and_override_are_accepted(self):
        self.assertEqual(patch.verify(self.root), 118)

    def test_changed_source_and_rewritten_manifest_cannot_hide_tampering(self):
        path = self.vendor / "src/lib.rs"
        path.write_bytes(path.read_bytes() + b"\n// modified\n")
        record = json.loads((self.vendor / "upstream.lock.json").read_text())
        record["files"]["src/lib.rs"] = hashlib.sha256(path.read_bytes()).hexdigest()
        (self.vendor / "upstream.lock.json").write_text(json.dumps(record))
        self.rejected()

    def test_extra_source_is_rejected(self):
        (self.vendor / "src/extra.rs").write_text("// extra\n")
        self.rejected()

    def test_symlink_to_external_source_is_rejected(self):
        path = self.vendor / "src/lib.rs"
        path.unlink()
        path.symlink_to(ROOT / "vendor/sqlx-postgres/src/lib.rs")
        self.rejected()

    def test_missing_copyright_notice_is_rejected(self):
        (self.vendor / "LICENSE-MIT").unlink()
        self.rejected()

    def test_unapproved_dependency_override_is_rejected(self):
        path = self.root / "Cargo.toml"
        path.write_text(path.read_text().replace("[patch.crates-io]", '[patch.crates-io]\nother = { path = "vendor/other" }'))
        self.rejected()

    def test_false_registry_provenance_is_rejected(self):
        path = self.root / "Cargo.lock"
        path.write_text(path.read_text().replace('name = "sqlx-postgres"\n', 'name = "sqlx-postgres"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'))
        self.rejected()

    def test_docker_context_cannot_omit_patch(self):
        path = self.root / ".dockerignore"
        path.write_text(path.read_text().replace("!vendor/sqlx-postgres/**", ""))
        self.rejected()

    def test_wrong_archive_and_additional_provenance_fields_are_rejected(self):
        path = self.vendor / "upstream.lock.json"
        record = json.loads(path.read_text())
        record["crate_archive_sha256"] = "0" * 64
        path.write_text(json.dumps(record))
        self.rejected()
        record["crate_archive_sha256"] = patch.ARCHIVE
        record["unapproved_source"] = "other"
        path.write_text(json.dumps(record))
        self.rejected()

    def test_transaction_fix_cannot_change_beyond_reviewed_operations(self):
        path = self.vendor / "src/transaction.rs"
        path.write_bytes(path.read_bytes().replace(b"transaction_depth += 1", b"transaction_depth += 2"))
        self.rejected()


if __name__ == "__main__":
    unittest.main()
