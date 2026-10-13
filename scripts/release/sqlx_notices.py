"""Public SQLx license notices for the fixed, reviewed source backport."""
import hashlib
import importlib.util
from common import load, require, safe_child

MAX_BYTES = 64 * 1024
FIXED = {
    'schema_version': 1, 'crate': 'sqlx-postgres', 'version': '0.8.6',
    'source': 'https://static.crates.io/crates/sqlx-postgres/sqlx-postgres-0.8.6.crate',
    'crate_archive_sha256': 'db58fcd5a53cf07c184b154801ff91347e4c30d17a3562a635ff028ad5deda46',
    'patch_upstream': 'https://github.com/transact-rs/sqlx/commit/f1e94ec34dd5f11ad6488a3a8ac7988439a3f757',
    'patch_reason': 'Cancellation during the BEGIN round trip must queue rollback before pool reuse.',
    'patched_transaction_sha256': 'a18b72fb6cdf60c1d7e23ffbef2a5ae5cb1956242dfe48bef2202a231795f438',
}
LICENSES = {
    'LICENSE-MIT': '44b1600a26039a75b28e1ce154a5dd163b16549f50e34fa577d9efe9c1bae179',
    'LICENSE-APACHE': '9be39331309bc958aab10457c1a8459c038ae95662f26dfcf6c9088e2b3d653f',
}


def validate(value):
    require(isinstance(value, dict) and set(value) == set(FIXED) | {'licenses'}
            and type(value.get('schema_version')) is int
            and all(value.get(key) == expected for key, expected in FIXED.items()),
            'SQLX_NOTICES_PROVENANCE')
    licenses = value['licenses']
    require(isinstance(licenses, dict) and set(licenses) == set(LICENSES), 'SQLX_NOTICES_LICENSES')
    for name, digest in LICENSES.items():
        text = licenses[name]
        require(isinstance(text, str) and len(text.encode('utf8')) <= MAX_BYTES
                and hashlib.sha256(text.encode('utf8')).hexdigest() == digest,
                'SQLX_NOTICES_LICENSE_BYTES')
    return value


def create(source):
    # The producer validates the exact 116 upstream files and sole code change,
    # not merely a caller-provided copyright document or version string.
    helper = safe_child(source / 'scripts', 'verify-sqlx-postgres-patch.py')
    spec = importlib.util.spec_from_file_location('reviewed_sqlx_backport', helper)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    verifier.verify(source)
    vendor = source / 'vendor/sqlx-postgres'
    record = load(safe_child(vendor, 'upstream.lock.json'), MAX_BYTES)
    value = {key: record[key] for key in FIXED if key != 'patched_transaction_sha256'}
    value['patched_transaction_sha256'] = record['modified_files']['src/transaction.rs']
    value['licenses'] = {name: safe_child(vendor, name).read_bytes().decode('utf8') for name in LICENSES}
    validate(value)
    verifier.verify(source)
    return value
