#!/usr/bin/env python3
"""Verify the exact published SQLx crate and its reviewed BEGIN backport."""
import hashlib
import json
from pathlib import Path
import re
import stat

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = "db58fcd5a53cf07c184b154801ff91347e4c30d17a3562a635ff028ad5deda46"
ORIGINAL_FILES = "aeea9118184da797b4a9c51297a257ecd5625c6dac21fc95e46d4245da9d15c3"
PATCHED_TRANSACTION = "a18b72fb6cdf60c1d7e23ffbef2a5ae5cb1956242dfe48bef2202a231795f438"
COMMIT = "https://github.com/transact-rs/sqlx/commit/f1e94ec34dd5f11ad6488a3a8ac7988439a3f757"


def require(value, code):
    if not value:
        raise RuntimeError(code)


def verify(root=ROOT):
    directory = root / "vendor/sqlx-postgres"
    require(not any(p.is_symlink() for p in (root, root / "vendor", directory)), "SQLX_PATCH_SYMLINK")
    record = json.loads((directory / "upstream.lock.json").read_text())
    require(set(record) == {"schema_version", "crate", "version", "crate_archive_sha256", "files",
                            "patch_upstream", "modified_files", "source", "patch_reason"}, "SQLX_PATCH_RECORD_FIELDS")
    require(record["schema_version"] == 1 and record["crate"] == "sqlx-postgres"
            and record["version"] == "0.8.6" and record["crate_archive_sha256"] == ARCHIVE
            and record["patch_upstream"] == COMMIT
            and record["source"] == "https://static.crates.io/crates/sqlx-postgres/sqlx-postgres-0.8.6.crate",
            "SQLX_PATCH_PROVENANCE")
    original = record["files"]
    require(len(original) == 116 and hashlib.sha256(json.dumps(original, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest() == ORIGINAL_FILES, "SQLX_PATCH_ORIGINAL_INVENTORY")
    require(record["modified_files"] == {"src/transaction.rs": PATCHED_TRANSACTION}, "SQLX_PATCH_SCOPE")
    expected = set(original) | {"upstream.lock.json", "KNOTSANDBOX-PATCH.md"}
    actual = set()
    for path in directory.rglob("*"):
        require(not path.is_symlink(), "SQLX_PATCH_SYMLINK")
        if path.is_dir():
            continue
        mode = path.stat().st_mode
        require(stat.S_ISREG(mode) and stat.S_IMODE(mode) == 0o644, "SQLX_PATCH_FILE_MODE")
        relative = path.relative_to(directory).as_posix()
        actual.add(relative)
        if relative in original:
            digest = record["modified_files"].get(relative, original[relative])
            require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, "SQLX_PATCH_FILE_DIGEST")
    require(actual == expected, "SQLX_PATCH_FILE_INVENTORY")
    # These are deliberately exact contracts, not a general TOML parser.
    manifest = (root / "Cargo.toml").read_text()
    sections = re.findall(r"(?ms)^\[patch\.crates-io\]\s*\n(.*?)(?=^\[|\Z)", manifest)
    require(len(sections) == 1, "SQLX_PATCH_CARGO_SECTION")
    entries = [line.strip() for line in sections[0].splitlines() if line.strip() and not line.lstrip().startswith("#")]
    require(entries == ['sqlx-postgres = { path = "vendor/sqlx-postgres" }'], "SQLX_PATCH_CARGO_OVERRIDE")
    packages = (root / "Cargo.lock").read_text().split("[[package]]")
    postgres = [p for p in packages if re.search(r'^name = "sqlx-postgres"$', p, re.M)]
    require(len(postgres) == 1 and re.search(r'^version = "0\.8\.6"$', postgres[0], re.M)
            and not re.search(r'^(source|checksum) = ', postgres[0], re.M), "SQLX_PATCH_LOCK_ENTRY")
    dockerignore = (root / ".dockerignore").read_text().splitlines()
    require(all(line in dockerignore for line in ("!vendor/", "!vendor/sqlx-postgres/",
                                                 "!vendor/sqlx-postgres/**")), "SQLX_PATCH_DOCKER_CONTEXT")
    return len(actual)


if __name__ == "__main__":
    print("SQLX_POSTGRES_BEGIN_BACKPORT_VERIFIED files=" + str(verify()))
