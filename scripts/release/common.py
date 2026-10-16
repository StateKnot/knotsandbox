"""Small shared validation helpers. No network or publication side effects."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent
REPOSITORY = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z')
TAG = re.compile(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?\Z')
SHA = re.compile(r'[a-f0-9]{40}\Z')
DIGEST = re.compile(r'sha256:[a-f0-9]{64}\Z')
COMPONENTS = ('service', 'runner', 'identity-proxy', 'console')
LEGACY_SCAN_NAMES = (*COMPONENTS, 'rust-binaries', 'builder', 'console-builder', 'proxy-source')
SCAN_NAMES = (*LEGACY_SCAN_NAMES, 'native-components')
BOM_CDX = {'proxy-source', 'native-components'}
SQLX_POSTGRES_NOTICES = 'sqlx-postgres-notices.json'
NATIVE_PROTOCOL_NOTICES = 'native-protocol-notices.json'

def release_file_names(*, legacy=False, binary_names=None, historical=False, version=None):
    version = (1 if legacy else 4) if version is None else version
    require(type(version) is int and version in (1, 2, 3, 4) and legacy == (version == 1),
            'RELEASE_VERSION')
    binaries = release_binaries(BINARIES if binary_names is None else binary_names, historical=historical)
    result = {'console-npm-locks.json','Cargo.lock','tools.lock.json','debian-security.lock.json','console-security.lock.json','risk-exceptions.json','scan-gate.json','database.json',*binaries}
    if not legacy:
        result.update({'native-security.lock.json','native-inputs.tar','native-provenance.json'})
    if version >= 3:
        result.add(SQLX_POSTGRES_NOTICES)
    if version == 4:
        result.add(NATIVE_PROTOCOL_NOTICES)
    for name in LEGACY_SCAN_NAMES if legacy else SCAN_NAMES:
        result.add(name+'.grype.json')
        result.add(name+('.cdx.json' if name in BOM_CDX else '.syft.json'))
        if name!='proxy-source': result.add(name+'.spdx.json')
    result.update(name+'.oci.tar' for name in COMPONENTS)
    return result

BINARIES = ('sandboxd', 'sandbox-admin', 'sandbox-admission', 'sandbox-runner', 'sandbox-nodeguard', 'sandbox-backup-worm', 'sandbox-credentials', 'sandbox-automation')
HISTORICAL_BINARIES = ('sandboxd', 'sandbox-admin', 'sandbox-admission', 'sandbox-runner', 'sandbox-nodeguard', 'sandbox-backup-worm', 'sandbox-credentials')

def release_binaries(names, *, historical=False):
    # The authenticated manifest chooses a complete known generation. Current
    # installation never accepts a worker omission or guesses from file presence.
    require(isinstance(names, (list, tuple)) and
            tuple(names) in ((HISTORICAL_BINARIES, BINARIES) if historical else (BINARIES,)),
            'RELEASE_BINARY_COVERAGE')
    return tuple(names)


def require(condition, code):
    if not condition:
        raise ValueError(code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def load(path, limit=64 * 1024 * 1024):
    with open(path, 'rb') as source:
        data = source.read(limit + 1)
    require(len(data) <= limit, 'JSON_LIMIT')
    return json.loads(data, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('JSON_CONSTANT')))


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def dump(path, value):
    with open(path, 'x', encoding='utf8') as output:
        json.dump(value, output, sort_keys=True, separators=(',', ':'))
        output.write('\n')


def timevalue(value):
    result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(result.tzinfo is not None, 'TIMEZONE_REQUIRED')
    return result


def now():
    return dt.datetime.now(dt.timezone.utc)


def run(args, **kwargs):
    # argv never contains tokens; registry credentials use stdin or controlled env.
    subprocess.run([str(v) for v in args], check=True, timeout=kwargs.pop('timeout', 300), **kwargs)


def tool(directory, name):
    lock = load(ROOT / 'tools.lock.json')
    record = load(Path(directory) / 'installed.json')
    require(record['lock_sha256'] == sha(ROOT / 'tools.lock.json'), 'TOOL_LOCK_CHANGED')
    require(name in record['binaries'] and any(name in v['members'].values() for v in lock['tools'].values()), 'UNKNOWN_TOOL')
    path = Path(directory) / name
    require(path.is_file() and not path.is_symlink() and sha(path) == record['binaries'][name], 'TOOL_HASH_CHANGED')
    return path.resolve()


def subject(repository, tag, commit):
    require(REPOSITORY.fullmatch(repository) and TAG.fullmatch(tag) and SHA.fullmatch(commit), 'INVALID_RELEASE_IDENTITY')
    return 'https://github.com/' + repository + '/.github/workflows/release.yml@refs/tags/' + tag


def safe_child(directory, name):
    require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,180}', name), 'ARTIFACT_NAME')
    path = Path(directory) / name
    require(path.is_file() and not path.is_symlink(), 'ARTIFACT_MISSING')
    return path


def image_digest(directory, component=None):
    """Verify a single Linux AMD64 OCI image and every referenced blob."""
    directory = Path(directory)
    require(load(directory / 'oci-layout') == {'imageLayoutVersion': '1.0.0'}, 'OCI_LAYOUT')
    index = load(directory / 'index.json')
    require(index.get('schemaVersion') == 2 and len(index.get('manifests', [])) == 1, 'OCI_INDEX')
    def blob(descriptor):
        digest = descriptor['digest']
        require(DIGEST.fullmatch(digest) and type(descriptor['size']) is int and descriptor['size'] > 0, 'OCI_DESCRIPTOR')
        path = directory / 'blobs' / 'sha256' / digest[7:]
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == descriptor['size'] and sha(path) == digest[7:], 'OCI_BLOB_CORRUPT')
        return path
    descriptor = index['manifests'][0]
    require(descriptor['mediaType'] == 'application/vnd.oci.image.manifest.v1+json', 'OCI_IMAGE_REQUIRED')
    manifest = load(blob(descriptor))
    require(manifest['schemaVersion'] == 2, 'OCI_MANIFEST')
    config = load(blob(manifest['config']))
    require(config['os'] == 'linux' and config['architecture'] == 'amd64', 'OCI_PLATFORM')
    allowed = ('101:101',) if component == 'console' else ('1000:1000', '10001:10001')
    require(config.get('config', {}).get('User') in allowed, 'OCI_NONROOT')
    for layer in manifest['layers']:
        blob(layer)
    return descriptor['digest']
