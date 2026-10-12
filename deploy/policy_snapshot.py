"""Pin direct Kubernetes credentials before any kubectl invocation.

The snapshot is a private, bounded observation input, not cluster certification.
No credential, parser source line, or authentication error is returned in errors.
"""
import base64
from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import re
import ssl
import stat
import tempfile
import time
from urllib.parse import urlsplit

import yaml


LIMIT = 1024 * 1024
SUPPORTED_POLICIES = frozenset({'ciliumnetworkpolicies.cilium.io',
    'ciliumclusterwidenetworkpolicies.cilium.io', 'networkpolicies.networking.k8s.io'})


class SnapshotError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise SnapshotError(message)


class _Loader(yaml.SafeLoader):
    pass


def _mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        require(key_node.tag != 'tag:yaml.org,2002:merge', 'kubeconfig merge keys are forbidden')
        key = loader.construct_object(key_node, deep=True)
        require(isinstance(key, str) and key not in result, 'invalid or duplicate kubeconfig field')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _parse(raw):
    try:
        text = raw.decode('utf-8')
        require(not any(isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken))
                        for token in yaml.scan(text)), 'kubeconfig aliases and anchors are forbidden')
        return yaml.load(text, Loader=_Loader)
    except (UnicodeError, yaml.YAMLError, RecursionError):
        raise SnapshotError('invalid kubeconfig syntax') from None


def _read(path):
    require(path.is_absolute(), 'absolute private kubeconfig required')
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, 'rb') as source:
            before = os.fstat(source.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid in (0, os.geteuid())
                    and stat.S_IMODE(before.st_mode) in (0o400, 0o600)
                    and 0 < before.st_size <= LIMIT, 'private kubeconfig type, owner, mode or size rejected')
            raw = source.read(LIMIT + 1)
            after = os.fstat(source.fileno())
            require(len(raw) <= LIMIT and (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    == (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'kubeconfig changed during read')
            return raw
    except OSError:
        raise SnapshotError('private kubeconfig read failed') from None


def _entries(values, field):
    require(isinstance(values, list) and 0 < len(values) <= 128, 'bounded kubeconfig entries required')
    result = {}
    for entry in values:
        require(isinstance(entry, dict) and set(entry) == {'name', field}, 'unsupported kubeconfig entry')
        name = entry['name']
        require(isinstance(name, str) and 0 < len(name) <= 256
                and all(32 < ord(c) < 127 for c in name) and name not in result,
                'invalid or duplicate kubeconfig entry name')
        require(isinstance(entry[field], dict), 'invalid kubeconfig entry body')
        result[name] = entry[field]
    return result


def _inline(value, limit):
    require(isinstance(value, str) and 0 < len(value) <= 2 * limit, 'bounded inline credential required')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError):
        raise SnapshotError('invalid inline credential encoding') from None
    require(0 < len(raw) <= limit and base64.b64encode(raw).decode() == value,
            'noncanonical or oversized inline credential')
    return raw


def _cluster(cluster):
    require(set(cluster) == {'server', 'certificate-authority-data'},
            'only direct HTTPS and inline CA are permitted')
    server = cluster['server']
    require(isinstance(server, str) and 0 < len(server) <= 2048
            and all(32 < ord(c) < 127 for c in server), 'invalid Kubernetes server URL')
    try:
        url = urlsplit(server)
        require(url.scheme == 'https' and url.hostname and not url.username and not url.password
                and not url.query and not url.fragment and url.path in ('', '/')
                and (url.port is None or 1 <= url.port <= 65535), 'direct verified Kubernetes HTTPS required')
        ca = _inline(cluster['certificate-authority-data'], 65536)
        require(1 <= ca.count(b'-----BEGIN CERTIFICATE-----') <= 16 and b'PRIVATE' not in ca,
                'bounded public CA PEM required')
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=ca.decode('ascii'))
    except (ValueError, UnicodeError, ssl.SSLError):
        raise SnapshotError('invalid direct Kubernetes server or CA') from None


def _user(user):
    require(set(user) in ({'token'}, {'client-certificate-data', 'client-key-data'}),
            'only direct inline token or client certificate credentials are permitted')
    if 'token' in user:
        token = user['token']
        require(isinstance(token, str) and 0 < len(token) <= 16384
                and all(32 < ord(c) < 127 for c in token), 'bounded direct token required')
    else:
        certificate = _inline(user['client-certificate-data'], 98304)
        key = _inline(user['client-key-data'], 16384)
        require(1 <= certificate.count(b'-----BEGIN CERTIFICATE-----') <= 8
                and b'PRIVATE' not in certificate, 'bounded client certificate PEM required')
        require(any(key.startswith(header) for header in (b'-----BEGIN PRIVATE KEY-----',
                b'-----BEGIN RSA PRIVATE KEY-----', b'-----BEGIN EC PRIVATE KEY-----'))
                and b'ENCRYPTED' not in key, 'unencrypted inline client key required')


def _select(config, context):
    require(isinstance(config, dict) and set(config) <= {'apiVersion', 'kind', 'clusters',
            'contexts', 'users', 'current-context', 'preferences'}
            and config.get('apiVersion') == 'v1' and config.get('kind') == 'Config'
            and config.get('preferences', {}) == {}, 'unsupported kubeconfig shape')
    clusters = _entries(config.get('clusters'), 'cluster')
    users = _entries(config.get('users'), 'user')
    contexts = _entries(config.get('contexts'), 'context')
    # Reject latent plugins, path credentials and proxy/TLS overrides as well.
    for cluster in clusters.values():
        _cluster(cluster)
    for user in users.values():
        _user(user)
    for item in contexts.values():
        require({'cluster', 'user'} <= set(item) <= {'cluster', 'user', 'namespace'}
                and isinstance(item['cluster'], str) and item['cluster'] in clusters
                and isinstance(item['user'], str) and item['user'] in users,
                'invalid direct kubeconfig context')
        if 'namespace' in item:
            require(isinstance(item['namespace'], str) and re.fullmatch(
                r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', item['namespace']), 'invalid context namespace')
    require(context in contexts, 'explicit kubeconfig context missing')
    selected = contexts[context]
    return {'apiVersion': 'v1', 'kind': 'Config', 'preferences': {}, 'current-context': context,
            'contexts': [{'name': context, 'context': selected}],
            'clusters': [{'name': selected['cluster'], 'cluster': clusters[selected['cluster']]}],
            'users': [{'name': selected['user'], 'user': users[selected['user']]}]}


def _private_write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as target:
        os.fchmod(target.fileno(), 0o600)
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())


def _check_client_pair(config, directory):
    user = config['users'][0]['user']
    if 'token' in user:
        return
    cert_path, key_path = directory / 'client.pem', directory / 'client.key'
    try:
        _private_write(cert_path, _inline(user['client-certificate-data'], 98304))
        _private_write(key_path, _inline(user['client-key-data'], 16384))
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_cert_chain(cert_path, key_path, password=lambda: '')
    except (OSError, ValueError, ssl.SSLError):
        raise SnapshotError('invalid inline client certificate and key pair') from None
    finally:
        cert_path.unlink(missing_ok=True)
        key_path.unlink(missing_ok=True)


class Snapshot:
    def __init__(self, config_path, cache_dir, context, deadline):
        self.config_path, self.cache_dir, self.context = config_path, cache_dir, context
        self._deadline = deadline

    def remaining_timeout(self, maximum=8):
        require(type(maximum) in (int, float) and math.isfinite(maximum) and maximum > 0,
                'invalid command deadline')
        remaining = self._deadline - time.monotonic()
        require(remaining > 0, 'policy observation exceeded its total deadline')
        return min(8, maximum, remaining)

    def check_discovery(self, resources):
        self.remaining_timeout()
        require(isinstance(resources, (list, tuple)) and 0 < len(resources) <= 256,
                'API discovery exceeds reviewed resource bound')
        require(all(isinstance(value, str) and len(value) <= 256 and re.fullmatch(
                r'[a-z][a-z0-9-]*(?:\.[a-z0-9.-]+)?', value) for value in resources)
                and len(set(resources)) == len(resources), 'invalid or duplicate API discovery resource')
        require(SUPPORTED_POLICIES <= set(resources), 'required policy APIs missing')
        unknown = tuple(sorted(value for value in resources
                               if 'networkpolic' in value and value not in SUPPORTED_POLICIES))
        require(len(unknown) <= 16, 'unknown policy discovery exceeds reviewed bound')
        return unknown


@contextmanager
def snapshot(kubeconfig_path, context, seconds=45):
    """Never invoke kubectl on the original file; use config_path for every read."""
    require(type(seconds) in (int, float) and math.isfinite(seconds) and 0 < seconds <= 45,
            'policy observation deadline must be at most 45 seconds')
    require(isinstance(context, str) and re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', context),
            'invalid explicit kubeconfig context')
    deadline = time.monotonic() + seconds
    selected = _select(_parse(_read(Path(kubeconfig_path))), context)
    with tempfile.TemporaryDirectory(prefix='sandbox-policy-snapshot-') as temporary:
        directory = Path(temporary)
        os.chmod(directory, 0o700)
        cache = directory / 'discovery'
        cache.mkdir(mode=0o700)
        cache.chmod(0o700)
        _check_client_pair(selected, directory)
        path = directory / 'kubeconfig.json'
        _private_write(path, json.dumps(selected, sort_keys=True, separators=(',', ':')).encode())
        pinned = Snapshot(path, cache, context, deadline)
        pinned.remaining_timeout()
        yield pinned
