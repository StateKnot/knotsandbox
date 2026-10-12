#!/usr/bin/env python3
"""Offline verification. Only a verified signed release emits deployment-lock.json."""
import argparse
import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
from security_packages import validate_lock
from console_security import validate_lock as validate_console_lock
from common import BINARIES, COMPONENTS, SCAN_NAMES, LEGACY_SCAN_NAMES, release_file_names, release_binaries, ROOT, DIGEST, dump, image_digest, load, now, require, run, safe_child, sha, subject, timevalue, tool, unique
from gate import evaluate, validate_database, validate_sboms
from console_assets import image_files, inventory, asset_manifest, validate_chain
from native import validate as validate_native, validate_runtime


def extract_oci(archive_path, directory, component=None):
    total = 0
    names = set()
    with tarfile.open(archive_path, 'r:') as archive:
        for member in archive:
            name = member.name
            require(name not in names and not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')), 'OCI_ARCHIVE_PATH')
            names.add(name)
            require(member.isdir() or member.isfile(), 'OCI_ARCHIVE_LINK_OR_SPECIAL')
            total += member.size
            require(total <= 8 * 1024**3 and len(names) <= 100000, 'OCI_ARCHIVE_LIMIT')
            target = directory / name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as output, archive.extractfile(member) as source:
                    shutil.copyfileobj(source, output)
    return image_digest(directory, component)


def verify_candidate(directory, repository, tag, commit, current=None, *, historical=False):
    """Structural/hash/scanner checks only. This does NOT authenticate a release."""
    current = current or now()
    manifest = load(safe_child(directory, 'release-manifest.json'), 1024 * 1024)
    expected = subject(repository, tag, commit)
    require(manifest.get('version') in ((1,2) if historical else (2,)) and manifest.get('repository') == repository and manifest.get('tag') == tag and manifest.get('commit') == commit, 'RELEASE_IDENTITY')
    legacy = manifest['version'] == 1
    require(manifest.get('platform') == 'linux/amd64' and manifest.get('workflow') == '.github/workflows/release.yml' and manifest.get('workflow_identity') == expected, 'RELEASE_WORKFLOW')
    require(re.fullmatch(r'[1-9][0-9]{0,30}', manifest.get('run_id', '')), 'RUN_ID')
    created = timevalue(manifest['created_at'])
    require(created <= current + dt.timedelta(minutes=5), 'RELEASE_FROM_FUTURE')
    require(set(manifest['images']) == set(COMPONENTS), 'RELEASE_COMPONENTS')
    binaries = release_binaries(manifest['binaries'], historical=historical)
    validate_chain(manifest.get('console_assets', {}), repository, tag, commit)
    if manifest['console_assets']['previous']:
        require(timevalue(manifest['console_assets']['previous']['created_at']) <= created, 'PREVIOUS_RELEASE_FROM_FUTURE')
    required = release_file_names(legacy=legacy, binary_names=binaries, historical=historical)
    scan_names = LEGACY_SCAN_NAMES if legacy else SCAN_NAMES
    require(set(manifest['files']) == required, 'RELEASE_FILE_COVERAGE')
    for name, metadata in manifest['files'].items():
        path = safe_child(directory, name)
        require(set(metadata) == {'sha256', 'size'} and type(metadata['size']) is int and 0 < metadata['size'] <= 8 * 1024**3, 'RELEASE_FILE_METADATA')
        require(path.stat().st_size == metadata['size'] and sha(path) == metadata['sha256'], 'RELEASE_FILE_HASH')
    # Historical checks are only used by verify_previous after current pinned
    # Cosign authenticates the exact external identity. They never emit an
    # installation lock or claim current vulnerability safety. This is not a
    # CLI option: new/installed releases must use today's reviewed policy.
    if not historical:
        for name, code in [('tools.lock.json', 'UNREVIEWED_TOOL_LOCK'), ('debian-security.lock.json', 'UNREVIEWED_SECURITY_LOCK'), ('console-security.lock.json', 'UNREVIEWED_CONSOLE_SECURITY_LOCK')]:
            require(sha(safe_child(directory, name)) == sha(ROOT / name), code)
    if historical:
        require(current == created, 'HISTORICAL_RELEASE_TIME_REQUIRED')
    validate_lock(load(safe_child(directory, 'debian-security.lock.json')), current)
    validate_console_lock(load(safe_child(directory, 'console-security.lock.json')), current)
    native = None
    if legacy:
        # Only verify_previous may inspect authenticated legacy artifacts for
        # retained console assets; this never certifies their current safety.
        for name in binaries:
            with safe_child(directory, name).open('rb') as binary: header = binary.read(64)
            require(header[:7] == b'\x7fELF\x02\x01\x01' and header[18:20] == b'\x3e\x00', 'BINARY_PLATFORM')
    else:
        native = validate_native(directory,historical=historical,binary_names=binaries)
    for name, descriptor in manifest['images'].items():
        require(descriptor['archive'] == name + '.oci.tar' and DIGEST.fullmatch(descriptor['digest']), 'RELEASE_IMAGE')
        with tempfile.TemporaryDirectory(prefix='verify-oci-') as temporary:
            require(extract_oci(safe_child(directory, descriptor['archive']), Path(temporary), name) == descriptor['digest'], 'RELEASE_IMAGE_HASH')
            if name == 'console':
                files = image_files(Path(temporary)); asset_manifest(files)
                require(inventory(files) == load(safe_child(directory, 'console-npm-locks.json')), 'CONSOLE_IMAGE_INVENTORY_MISMATCH')
            elif native is not None and name in ('service','runner'):
                validate_runtime(Path(temporary),name,native,historical=historical,binary_names=binaries)
    validate_sboms(directory, current, legacy=legacy, historical=historical, binary_names=binaries)
    gate = load(safe_child(directory, 'scan-gate.json'))
    evaluated = timevalue(gate['evaluated_at'])
    require(created - dt.timedelta(hours=1) <= evaluated <= created, 'SCAN_TIMESTAMP')
    # Freshness is checked at release time. Installation authenticity does not
    # claim current CVE safety; operators must rescan for newly published CVEs.
    validate_database(load(safe_child(directory, 'database.json')), evaluated)
    require(gate['version'] == 1 and gate['blocked'] == [] and set(gate['reports']) == set(scan_names), 'SCAN_GATE')
    require(gate['policy_sha256'] == sha(safe_child(directory, 'risk-exceptions.json')), 'SCAN_POLICY_HASH')
    require(all(gate['reports'][name] == sha(safe_child(directory, name + '.grype.json')) for name in scan_names), 'SCAN_REPORT_HASH')
    reports = {name: load(safe_child(directory, name + '.grype.json')) for name in scan_names}
    versions = load(safe_child(directory, 'tools.lock.json'))['tools'] if historical else load(ROOT / 'tools.lock.json')['tools']
    require(not evaluate(reports, load(safe_child(directory, 'risk-exceptions.json')), versions, current,
                         legacy=legacy, database_at=evaluated,
                         database_status=load(safe_child(directory, 'database.json'))), 'UNREVIEWED_VULNERABILITIES')
    return manifest


def verify_statement(directory, manifest):
    bundle = load(safe_child(directory, 'release-manifest.sigstore.json'), 4 * 1024 * 1024)
    envelope = bundle['dsseEnvelope']
    require(envelope['payloadType'] == 'application/vnd.in-toto+json', 'ATTESTATION_PAYLOAD_TYPE')
    statement = json.loads(base64.b64decode(envelope['payload'], validate=True), object_pairs_hook=unique)
    require(statement['_type'] == 'https://in-toto.io/Statement/v1' and statement['predicateType'] == 'https://slsa.dev/provenance/v1', 'ATTESTATION_TYPE')
    subjects = statement['subject']
    require(len(subjects) == 1 and subjects[0]['digest'] == {'sha256': sha(directory / 'release-manifest.json')}, 'ATTESTATION_SUBJECT')
    predicate = statement['predicate']
    require(predicate == load(safe_child(directory, 'provenance.json')), 'PROVENANCE_FILE_MISMATCH')
    definition = predicate['buildDefinition']
    repo, tag, commit = (manifest[k] for k in ('repository', 'tag', 'commit'))
    require(definition['buildType'] == 'https://github.com/' + repo + '/.github/workflows/release.yml', 'PROVENANCE_BUILD_TYPE')
    require(definition['externalParameters'] == {'repository': repo, 'tag': tag, 'commit': commit, 'platform': 'linux/amd64', 'console_assets': manifest['console_assets']}, 'PROVENANCE_PARAMETERS')
    require(definition['resolvedDependencies'] == [{'uri': 'git+https://github.com/' + repo + '@refs/tags/' + tag, 'digest': {'gitCommit': commit}}], 'PROVENANCE_SOURCE')
    require(predicate['runDetails']['builder']['id'] == manifest['workflow_identity'] and predicate['runDetails']['metadata']['invocationId'] == 'https://github.com/' + repo + '/actions/runs/' + manifest['run_id'], 'PROVENANCE_BUILDER')


def cosign_arguments(directory, tools, repository, tag, commit):
    require(sha(ROOT / 'trusted-root.json') == load(ROOT / 'tools.lock.json')['trust_root']['sha256'], 'TRUST_ROOT_HASH')
    return [tool(tools, 'cosign'), 'verify-blob-attestation', '--bundle', safe_child(directory, 'release-manifest.sigstore.json'),
        '--trusted-root', ROOT / 'trusted-root.json', '--type', 'slsaprovenance1',
        '--certificate-identity', subject(repository, tag, commit), '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com',
        '--certificate-github-workflow-sha', commit, '--certificate-github-workflow-ref', 'refs/tags/' + tag,
        '--certificate-github-workflow-repository', repository, '--certificate-github-workflow-trigger', 'workflow_dispatch',
        safe_child(directory, 'release-manifest.json')]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), 'OUTPUT_ALREADY_EXISTS')
    subject(args.repository, args.tag, args.commit)
    # Authenticate before interpreting candidate metadata. Bundle + locally
    # pinned roots supply all material; no transparency/SCT bypass flags exist.
    run(cosign_arguments(args.directory, args.tools, args.repository, args.tag, args.commit), timeout=60, stdout=subprocess.DEVNULL)
    manifest = verify_candidate(args.directory, args.repository, args.tag, args.commit)
    verify_statement(args.directory, manifest)
    prefix = 'ghcr.io/' + args.repository.lower()
    dump(args.output, {'version': 1, 'repository': args.repository, 'tag': args.tag, 'commit': args.commit,
        'manifest_sha256': sha(args.directory / 'release-manifest.json'), 'verified_at': now().isoformat(),
        'images': {name: prefix + '/' + name + '@' + value['digest'] for name, value in manifest['images'].items()},
        'binaries': {name: manifest['files'][name] for name in BINARIES}})
    print('Verified release; deployment lock written.')


if __name__ == '__main__':
    main()
