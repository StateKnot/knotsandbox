#!/usr/bin/env python3
"""Fail closed on scanner failures, stale databases and unreviewed serious findings."""
import argparse
import datetime as dt
import tomllib
from pathlib import Path
import re
from urllib.parse import parse_qsl, urlsplit
from common import SCAN_NAMES, LEGACY_SCAN_NAMES, dump, load, now, require, sha, timevalue
from native import validate as validate_native
from console_assets import validate_inventory
from console_security import validate_lock as validate_console_lock, validate_inventory as validate_console_inventory

SEVERITIES = {'Negligible', 'Low', 'Medium', 'High', 'Critical', 'Unknown'}
BLOCKING = {'High', 'Critical', 'Unknown'}
EXCEPTION_FIELDS = {'artifact', 'vulnerability', 'package', 'version', 'purl', 'severity', 'approved_at', 'expires_at', 'owner', 'ticket', 'reason'}

# Exact effective configuration emitted by locked Grype 0.120.0. Empty user
# ignore rules alone do not disable its built-in kernel-header ignore rules.
SCANNER_CONFIGURATION = {
    'output': ['json'], 'file': '', 'pretty': False, 'distro': '',
    'add-cpes-if-none': False, 'output-template-file': '',
    'check-for-app-update': False, 'only-fixed': False, 'only-notfixed': False,
    'ignore-wontfix': '', 'platform': '',
    'search': {'scope': 'squashed', 'unindexed-archives': False, 'indexed-archives': True},
    'ignore': [], 'exclude': [],
    'externalSources': {'enable': False, 'maven': {'searchUpstreamBySha1': True,
        'baseUrl': 'https://search.maven.org/solrsearch/select', 'rateLimit': 300000000}},
    'match': {
        'java': {'using-cpes': False}, 'jvm': {'using-cpes': True},
        'dotnet': {'using-cpes': False}, 'golang': {'using-cpes': False,
            'always-use-cpe-for-stdlib': False, 'allow-main-module-pseudo-version-comparison': False},
        'javascript': {'using-cpes': False}, 'python': {'using-cpes': False},
        'ruby': {'using-cpes': False}, 'rust': {'using-cpes': False},
        'hex': {'using-cpes': False}, 'stock': {'using-cpes': True},
        'dpkg': {'using-cpes': False, 'missing-epoch-strategy': 'zero', 'use-cpes-for-eol': False},
        'rpm': {'using-cpes': False, 'missing-epoch-strategy': 'auto', 'use-cpes-for-eol': False}},
    'fail-on-severity': '', 'registry': {'insecure-skip-tls-verify': False,
        'insecure-use-http': False, 'ca-cert': ''},
    'show-suppressed': False, 'include-matcher-suppressions': False,
    'by-cve': False, 'SortBy': {'sort-by': 'risk'}, 'name': '',
    'default-image-pull-source': '', 'from': None, 'vex-documents': [], 'vex-add': [],
    'match-upstream-kernel-headers': True,
    'fix-channel': {'redhat-eus': {'apply': 'auto', 'versions': '>= 8.0'},
        'ubuntu-esm': {'apply': 'auto', 'versions': ''}},
    'timestamp': True, 'alerts': {'enable-eol-distro-warnings': True},
    'db': {'cache-dir': None, 'update-url': 'https://grype.anchore.io/databases',
        'ca-cert': '', 'auto-update': False, 'validate-by-hash-on-start': True,
        'validate-age': True, 'max-allowed-built-age': 86400000000000,
        'require-update-check': False, 'update-available-timeout': 30000000000,
        'update-download-timeout': 300000000000, 'max-update-check-frequency': 7200000000000},
    'exp': {}, 'dev': {'db': {'debug': False}}}


def exact_json(actual, expected):
    """JSON booleans must not equal integer 0/1 in a security contract."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(exact_json(actual[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(exact_json(a, e) for a, e in zip(actual, expected))
    return actual == expected


def database_identity(status, current):
    require(isinstance(status, dict) and set(status) == {'schemaVersion', 'from', 'built', 'path', 'valid'}
            and status['valid'] is True and status['schemaVersion'] == 'v6.1.10'
            and all(isinstance(status[key], str) and 0 < len(status[key]) <= 4096 for key in ('from', 'built', 'path')),
            'SCANNER_DATABASE_FORMAT')
    source = urlsplit(status['from'])
    try:
        query = parse_qsl(source.query, strict_parsing=True)
    except ValueError:
        raise ValueError('SCANNER_DATABASE_SOURCE') from None
    require(source.scheme == 'https' and source.netloc == 'grype.anchore.io' and not source.fragment
            and re.fullmatch(r'/databases/v6/vulnerability-db_v6\.1\.10_[0-9TZ:\-]+_[0-9]+\.tar\.zst', source.path)
            and len(query) == 1 and query[0][0] == 'checksum'
            and re.fullmatch(r'sha256:[0-9a-f]{64}', query[0][1]), 'SCANNER_DATABASE_SOURCE')
    require(Path(status['path']).is_absolute() and '..' not in Path(status['path']).parts, 'SCANNER_DATABASE_PATH')
    validate_database(status, current)
    return tuple(status[key] for key in ('schemaVersion', 'from', 'built'))


def validate_scanner(descriptor, current):
    configuration = descriptor.get('configuration')
    require(isinstance(configuration, dict) and isinstance(configuration.get('db'), dict), 'SCANNER_CONFIGURATION')
    cache = configuration['db'].get('cache-dir')
    require(isinstance(cache, str) and 0 < len(cache) <= 4096 and Path(cache).is_absolute()
            and '..' not in Path(cache).parts, 'SCANNER_DATABASE_CACHE_PATH')
    expected = {**SCANNER_CONFIGURATION, 'db': {**SCANNER_CONFIGURATION['db'], 'cache-dir': cache}}
    require(exact_json(configuration, expected), 'SCANNER_CONFIGURATION')
    database = descriptor.get('db')
    require(isinstance(database, dict) and isinstance(database.get('status'), dict), 'SCANNER_DATABASE_FORMAT')
    status = database['status']
    identity = database_identity(status, current)
    require(status['path'] == str(Path(cache) / '6/vulnerability.db'), 'SCANNER_DATABASE_PATH')
    return identity


def exceptions(policy, current):
    require(set(policy) == {'version', 'exceptions'} and policy['version'] == 1 and isinstance(policy['exceptions'], list), 'RISK_POLICY_FORMAT')
    result = {}
    for risk in policy['exceptions']:
        require(set(risk) == EXCEPTION_FIELDS and all(isinstance(v, str) and 0 < len(v) <= 2000 for v in risk.values()), 'RISK_EXCEPTION_FORMAT')
        require(risk['artifact'] in set(SCAN_NAMES), 'RISK_ARTIFACT')
        require(risk['severity'] in BLOCKING and '*' not in risk['purl'] and risk['purl'].startswith('pkg:'), 'RISK_SCOPE')
        require(risk['ticket'].startswith('https://') and len(risk['reason']) >= 20, 'RISK_REVIEW_REQUIRED')
        approved, expires = timevalue(risk['approved_at']), timevalue(risk['expires_at'])
        require(approved <= current < expires and dt.timedelta(0) < expires - approved <= dt.timedelta(days=30), 'RISK_REVIEW_EXPIRED')
        key = tuple(risk[k] for k in ('artifact', 'vulnerability', 'package', 'version', 'purl', 'severity'))
        require(key not in result, 'RISK_DUPLICATE')
        result[key] = risk
    return result


def evaluate(reports, policy, versions, current=None, *, legacy=False, database_at=None, database_status=None):
    current = current or now()
    database_at = database_at or current
    identity = database_identity(database_status, database_at) if database_status is not None else None
    approved = exceptions(policy, current)
    used, blocked = set(), []
    require(set(reports) == set(LEGACY_SCAN_NAMES if legacy else SCAN_NAMES), 'SCAN_COVERAGE')
    for artifact, report in reports.items():
        require(isinstance(report.get('matches'), list), 'SCAN_REPORT_FORMAT')
        descriptor = report.get('descriptor', {})
        require(descriptor.get('name') == 'grype' and descriptor.get('version') == versions['grype']['version'], 'SCAN_TOOL_VERSION')
        require(not report.get('ignoredMatches') and not report.get('alertsByPackage'), 'SCANNER_IGNORES_OR_EOL_ALERTS')
        report_identity = validate_scanner(descriptor, database_at)
        if identity is None:
            identity = report_identity
        require(identity == report_identity, 'SCANNER_DATABASE_MISMATCH')
        for finding in report['matches']:
            vuln, package = finding['vulnerability'], finding['artifact']
            severity = vuln['severity']
            require(severity in SEVERITIES, 'SCAN_SEVERITY')
            if severity in BLOCKING:
                key = (artifact, vuln['id'], package['name'], package['version'], package.get('purl', ''), severity)
                if key in approved:
                    used.add(key)
                else:
                    blocked.append({'artifact': artifact, 'id': vuln['id'], 'package': package['name'], 'version': package['version'], 'severity': severity})
    require(set(approved) == used, 'RISK_UNUSED_EXCEPTION')
    return blocked


def validate_database(status, current=None):
    current = current or now()
    require(status.get('valid') is True and not status.get('error'), 'SCANNER_DATABASE_INVALID')
    built = timevalue(status['built'])
    require(dt.timedelta(0) <= current - built <= dt.timedelta(hours=24), 'SCANNER_DATABASE_STALE')


def validate_sboms(directory, current=None, *, legacy=False, historical=False, binary_names=None):
    """Image defaults exclude declared Cargo.lock: require every locked crate."""
    with (directory / 'Cargo.lock').open('rb') as source:
        packages = tomllib.load(source)['package']
    expected = {(p['name'], p['version']) for p in packages if p.get('source', '').startswith('registry+')}
    require(expected, 'CARGO_DEPENDENCY_INVENTORY_EMPTY')
    for name in ('service', 'runner', 'rust-binaries'):
        sbom = load(directory / (name + '.syft.json'))
        actual = {(p['name'], p['version']) for p in sbom['artifacts'] if p.get('type') == 'rust-crate'}
        require(expected <= actual, 'CARGO_DEPENDENCIES_MISSING_FROM_SBOM')
    npm = validate_inventory(load(directory / 'console-npm-locks.json'))
    console = load(directory / 'console.syft.json')
    actual = {(p['name'], p['version']) for p in console['artifacts'] if p.get('type') == 'npm'}
    require(npm <= actual, 'NPM_DEPENDENCIES_MISSING_FROM_SBOM')
    validate_console_inventory(validate_console_lock(load(directory / 'console-security.lock.json'), current), console['artifacts'])
    if not legacy:
        validate_native(directory,historical=historical,binary_names=binary_names)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    from common import ROOT
    directory = args.directory
    database_status = load(directory / 'database.json')
    validate_database(database_status)
    validate_sboms(directory)
    reports = {name: load(directory / (name + '.grype.json')) for name in SCAN_NAMES}
    blocked = evaluate(reports, load(directory / 'risk-exceptions.json'), load(ROOT / 'tools.lock.json')['tools'], database_status=database_status)
    dump(directory / 'scan-gate.json', {'version': 1, 'evaluated_at': now().isoformat(), 'blocked': blocked,
         'reports': {name: sha(directory / (name + '.grype.json')) for name in reports}, 'policy_sha256': sha(directory / 'risk-exceptions.json')})
    require(not blocked, 'UNREVIEWED_VULNERABILITIES')
