#!/usr/bin/env python3
"""Public Kubernetes discovery export, atomic static publication and STS acceptance.

Uses only public API responses for export. No command reads a signing private key.
Cloud/DNS provisioning and signing-key changes are deliberately separate operations.
"""
import argparse
import asyncio
import base64
import datetime as dt
import fcntl
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import signal
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from jsonschema import Draft202012Validator, FormatChecker

HERE = Path(__file__).resolve().parent
LIMIT = 1024 * 1024
DISCOVERY = '/.well-known/openid-configuration'
JWKS = '/openid/v1/jwks'
TOKEN_PATH = '/var/run/sandbox-cloud/token'
REMOTE_COMMAND = '/opt/sandbox-workload-identity/bin/python /opt/sandbox-workload-identity/identity.py receive --config /etc/sandbox-workload-identity.json --root /srv/workload-identity'
PROBE_IMAGE = 'debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251'


class Rejected(Exception):
    """Only fixed application codes cross the command-line error boundary."""


def require(condition, code):
    if not condition:
        raise Rejected(code)


def pairs(values):
    result = {}
    for key, value in values:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def decode(data):
    require(len(data) <= LIMIT, 'INPUT_LIMIT')
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Rejected('INVALID_JSON')))
    except (ValueError, UnicodeError):
        raise Rejected('INVALID_JSON') from None


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def read_json(path):
    with open(path, 'rb') as source:
        return decode(source.read(LIMIT + 1))


def config(path):
    result = read_json(path)
    validator = Draft202012Validator(read_json(HERE / 'config.schema.json'), format_checker=FormatChecker())
    require(not list(validator.iter_errors(result)), 'CONFIG_SCHEMA')
    host = urllib.parse.urlsplit(result['issuer']).hostname
    require(host and '.' in host and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', s) for s in host.split('.')), 'ISSUER_HOST')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise Rejected('ISSUER_REQUIRES_DNS')
    require(result['oidc_provider_arn'].split(':')[3] == result['account_id'], 'ACCOUNT_BINDING')
    require(all(r['arn'].split(':')[3] == result['account_id'] for r in result['roles'].values()), 'ACCOUNT_BINDING')
    require(len({r['subject'] for r in result['roles'].values()}) == len(result['roles']), 'ROLE_SUBJECT_DUPLICATE')
    require(len({o['https_ip'] for o in result['origins']}) == len(result['origins']), 'ORIGIN_DUPLICATE')
    require(len({o['ssh_host'] for o in result['origins']}) == len(result['origins']), 'ORIGIN_DUPLICATE')
    require(set(result['control_plane_nodes']) == set(result['control_plane_contexts']), 'CONTROL_PLANE_CONFIG')
    require(len({n['private_ip'] for n in result['control_plane_nodes'].values()}) == len(result['control_plane_contexts']), 'CONTROL_PLANE_CONFIG')
    require(uuid.UUID(result['cluster_epoch']).int != 0, 'CLUSTER_EPOCH')
    return result


def b64(value):
    require(isinstance(value, str) and 0 < len(value) <= 16384 and re.fullmatch(r'[A-Za-z0-9_-]+', value), 'BASE64URL')
    try:
        raw = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
    except ValueError:
        raise Rejected('BASE64URL') from None
    require(base64.urlsafe_b64encode(raw).rstrip(b'=').decode() == value, 'BASE64URL')
    return raw


def public_keys(value):
    require(isinstance(value, dict) and set(value) == {'keys'}, 'JWKS_SHAPE')
    require(isinstance(value['keys'], list) and 1 <= len(value['keys']) <= 32, 'JWKS_KEY_COUNT')
    result = {}
    for key in value['keys']:
        require(isinstance(key, dict) and set(key) == {'kty', 'use', 'alg', 'kid', 'n', 'e'}, 'PUBLIC_KEYS_ONLY')
        require(key['kty'] == 'RSA' and key['alg'] == 'RS256' and key['use'] == 'sig', 'KEY_ALGORITHM')
        require(isinstance(key['kid'], str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', key['kid']), 'KEY_ID')
        require(key['kid'] not in result, 'DUPLICATE_KID')
        modulus, exponent = int.from_bytes(b64(key['n'])), int.from_bytes(b64(key['e']))
        require(2048 <= modulus.bit_length() <= 8192 and modulus % 2 == 1 and exponent == 65537, 'RSA_KEY_STRENGTH')
        rsa.RSAPublicNumbers(exponent, modulus).public_key()
        result[key['kid']] = key
    return result


def discovery(value, settings):
    required = {'issuer', 'jwks_uri', 'response_types_supported', 'subject_types_supported', 'id_token_signing_alg_values_supported'}
    require(isinstance(value, dict) and set(value) == required, 'DISCOVERY_SHAPE')
    require(value['issuer'] == settings['issuer'] and value['jwks_uri'] == settings['issuer'] + JWKS, 'DISCOVERY_BINDING')
    require(value['id_token_signing_alg_values_supported'] == ['RS256'], 'DISCOVERY_ALGORITHM')
    require(value['response_types_supported'] == ['id_token'] and value['subject_types_supported'] == ['public'], 'DISCOVERY_PROFILE')
    return value


def run(command, data=None, timeout=30, limit=LIMIT):
    # Token-bearing stdout never touches disk. Bound output while reading, not
    # after communicate(), so a broken container cannot exhaust controller RAM.
    async def execute():
        process = await asyncio.create_subprocess_exec(*command, stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, start_new_session=True)
        async def read(stream):
            result = bytearray()
            while chunk := await stream.read(16384):
                result.extend(chunk)
                require(len(result) <= limit, 'COMMAND_OUTPUT_LIMIT')
            return bytes(result)
        async def write():
            if data:
                process.stdin.write(data)
                await process.stdin.drain()
            process.stdin.close()
        try:
            output, _, _, status = await asyncio.wait_for(asyncio.gather(
                read(process.stdout), read(process.stderr), write(), process.wait()), timeout)
            require(status == 0, 'COMMAND_FAILED')
            return output
        finally:
            if process.returncode is None:
                os.killpg(process.pid, signal.SIGKILL)
                await process.wait()
    return asyncio.run(execute())


def kubectl(context, *arguments):
    return run(['kubectl', '--context', context, '--request-timeout=15s', *arguments])


def issuer_flags(settings):
    return {'service-account-issuer': settings['issuer'], 'service-account-jwks-uri': settings['issuer'] + JWKS,
            'service-account-max-token-expiration': str(settings['max_token_lifetime_seconds']) + 's',
            'service-account-extend-token-expiration': 'false'}


def control_plane_evidence(settings, context):
    expected = settings['control_plane_nodes'][context]
    node = decode(kubectl(context, 'get', 'node', expected['name'], '-o', 'json'))
    require(node['metadata']['name'] == expected['name'] and not node['metadata'].get('deletionTimestamp'), 'CONTROL_PLANE_NODE')
    require(any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in node['status']['conditions']), 'CONTROL_PLANE_NOT_READY')
    require(any(a.get('type') == 'InternalIP' and a.get('address') == expected['private_ip'] for a in node['status']['addresses']), 'CONTROL_PLANE_IP')
    pods = decode(kubectl(context, '-n', 'kube-system', 'get', 'pods', '--field-selector=spec.nodeName=' + expected['name'], '-l', 'component=kube-apiserver', '-o', 'json'))['items']
    require(len(pods) == 1, 'APISERVER_POD_COUNT')
    pod = pods[0]
    require(pod['spec']['nodeName'] == expected['name'] and pod['metadata'].get('annotations', {}).get('kubernetes.io/config.mirror') and not pod['metadata'].get('deletionTimestamp') and pod['status'].get('phase') == 'Running', 'APISERVER_MIRROR_POD')
    containers = [c for c in pod['spec']['containers'] if c['name'] == 'kube-apiserver']
    require(len(containers) == 1 and any(c.get('name') == 'kube-apiserver' and c.get('ready') for c in pod['status']['containerStatuses']), 'APISERVER_NOT_READY')
    arguments = containers[0].get('command', []) + containers[0].get('args', [])
    actual = {}
    for argument in arguments:
        if argument.startswith('--service-account-'):
            flag, separator, value = argument[2:].partition('=')
            if flag in issuer_flags(settings):
                require(separator and flag not in actual, 'APISERVER_FLAG_DUPLICATE')
                actual[flag] = value
    require(actual == issuer_flags(settings), 'APISERVER_ISSUER_CONTRACT')
    return {**expected, 'node_uid': node['metadata']['uid'], 'apiserver_pod_uid': pod['metadata']['uid'], 'flags': actual}


def export(settings):
    snapshots, servers, evidence = [], set(), []
    for context in settings['control_plane_contexts']:
        server = kubectl(context, 'config', 'view', '--minify', '-o', 'jsonpath={.clusters[0].cluster.server}').decode().strip()
        insecure = kubectl(context, 'config', 'view', '--minify', '-o', 'jsonpath={.clusters[0].cluster.insecure-skip-tls-verify}').decode().strip()
        require(insecure in ('', 'false'), 'KUBE_TLS_REQUIRED')
        parsed = urllib.parse.urlsplit(server)
        require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.query and not parsed.fragment and parsed.path in ('', '/'), 'KUBE_ENDPOINT')
        require(parsed.hostname == settings['control_plane_nodes'][context]['private_ip'] and parsed.port == 6443, 'CONTROL_PLANE_ENDPOINT_BINDING')
        require(server not in servers, 'CONTROL_PLANE_ENDPOINT_DUPLICATE')
        servers.add(server)
        disc = discovery(decode(kubectl(context, 'get', '--raw=' + DISCOVERY)), settings)
        keys = public_keys(decode(kubectl(context, 'get', '--raw=' + JWKS)))
        snapshots.append({'discovery': disc, 'jwks': {'keys': [keys[k] for k in sorted(keys)]}})
        evidence.append(control_plane_evidence(settings, context))
    require(all(s == snapshots[0] for s in snapshots), 'CONTROL_PLANES_DISAGREE')
    return {'version': 1, 'issuer': settings['issuer'], 'exported_at': int(time.time()),
            'deployment': settings['deployment'], 'cluster_epoch': settings['cluster_epoch'],
            'config_sha256': hashlib.sha256(canonical(settings)).hexdigest(), 'control_planes': evidence, **snapshots[0]}


def validate_bundle(bundle, settings, now):
    require(isinstance(bundle, dict) and set(bundle) == {'version', 'issuer', 'exported_at', 'deployment', 'cluster_epoch', 'config_sha256', 'control_planes', 'discovery', 'jwks'}, 'BUNDLE_SHAPE')
    require(bundle['version'] == 1 and bundle['issuer'] == settings['issuer'], 'BUNDLE_IDENTITY')
    require(type(bundle['exported_at']) is int and 0 <= now - bundle['exported_at'] <= 300, 'STALE_EXPORT')
    require(bundle['deployment'] == settings['deployment'] and bundle['cluster_epoch'] == settings['cluster_epoch'] and bundle['config_sha256'] == hashlib.sha256(canonical(settings)).hexdigest(), 'BUNDLE_CONFIG_BINDING')
    require(isinstance(bundle['control_planes'], list) and len(bundle['control_planes']) == len(settings['control_plane_contexts']), 'CONTROL_PLANE_COUNT')
    for context, evidence in zip(settings['control_plane_contexts'], bundle['control_planes'], strict=True):
        expected = settings['control_plane_nodes'][context]
        require(isinstance(evidence, dict) and set(evidence) == set(expected) | {'node_uid', 'apiserver_pod_uid', 'flags'}, 'CONTROL_PLANE_EVIDENCE')
        require(all(evidence[k] == v for k, v in expected.items()) and evidence['flags'] == issuer_flags(settings), 'CONTROL_PLANE_EVIDENCE')
        require(all(isinstance(evidence[k], str) and 0 < len(evidence[k]) <= 128 for k in ('node_uid', 'apiserver_pod_uid')), 'CONTROL_PLANE_EVIDENCE')
    discovery(bundle['discovery'], settings)
    return public_keys(bundle['jwks'])


def merge_release(bundle, settings, previous=None, retire=(), now=None):
    now = int(time.time()) if now is None else now
    current = validate_bundle(bundle, settings, now)
    missing = {}
    if previous:
        require(previous['issuer'] == settings['issuer'], 'PREVIOUS_ISSUER')
        for kid, key in public_keys(previous['jwks']).items():
            if kid in current:
                require(current[kid] == key, 'KID_REBOUND')
            else:
                missing[kid] = previous['missing_since'].get(kid, now)
                current[kid] = key
    # Lowering current settings cannot shorten validity of tokens already issued.
    # Retain at least this profile's maximum supported TTL, skew and cache window.
    hold = max(3600 + 60 + 300, settings['max_token_lifetime_seconds'] + settings['clock_skew_seconds'] + settings['cache_seconds'])
    for kid in retire:
        require(kid in missing and now - missing[kid] >= hold, 'KEY_RETIREMENT_TOO_EARLY')
        del current[kid]
        del missing[kid]
    require(current and len(current) <= 32, 'JWKS_KEY_COUNT')
    return {'version': 1, 'issuer': settings['issuer'], 'published_at': now,
            'source_exported_at': bundle['exported_at'], 'missing_since': missing,
            'discovery': bundle['discovery'], 'jwks': {'keys': [current[k] for k in sorted(current)]}}


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path, value):
    # Local output is public-only but use exclusive mode to avoid following an
    # unexpected target symlink or overwriting another reviewed export.
    with open(path, 'xb') as output:
        output.write(canonical(value))
        output.flush()
        os.fsync(output.fileno())


def receive(settings, root, request, now=None):
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), 'PUBLISH_ROOT')
    require(root.stat().st_uid == os.geteuid() and root.stat().st_mode & 0o022 == 0, 'PUBLISH_ROOT_OWNER')
    require(isinstance(request, dict) and set(request) == {'bundle', 'retire_kids'}, 'PUBLISH_REQUEST')
    require(isinstance(request['retire_kids'], list) and len(request['retire_kids']) <= 32 and all(isinstance(k, str) for k in request['retire_kids']), 'RETIRE_REQUEST')
    with open(root / '.publish.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        current = root / 'current'
        require(not current.is_symlink() or current.resolve().parent == root.resolve(), 'PUBLISH_CURRENT')
        previous = read_json(current / 'manifest.json') if current.is_symlink() else None
        require(not current.exists() or current.is_symlink(), 'PUBLISH_CURRENT')
        merged = merge_release(request['bundle'], settings, previous, request['retire_kids'], now)
        release = Path(tempfile.mkdtemp(prefix='release-', dir=root))
        os.chmod(release, 0o755)
        atomic_json(release / 'discovery.json', merged['discovery'])
        atomic_json(release / 'jwks.json', merged['jwks'])
        atomic_json(release / 'manifest.json', merged)
        for path in release.iterdir():
            os.chmod(path, 0o644)
        fsync_dir(release)
        pointer = root / ('current-' + uuid.uuid4().hex)
        pointer.symlink_to(release.name, target_is_directory=True)
        os.replace(pointer, current)
        fsync_dir(root)
        return {'published': True, 'jwks_sha256': hashlib.sha256(canonical(merged['jwks'])).hexdigest(), 'kids': list(public_keys(merged['jwks']))}


class OriginConnection(http.client.HTTPSConnection):
    def __init__(self, host, origin=None):
        super().__init__(host, timeout=10, context=ssl.create_default_context())
        self.origin = origin or host

    def connect(self):
        sock = socket.create_connection((self.origin, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


def https_json(host, path, origin=None, headers=None, method='GET'):
    connection = OriginConnection(host, origin)
    try:
        connection.request(method, path, headers=headers or {'Accept': 'application/json'}, body=b'' if method == 'POST' else None)
        response = connection.getresponse()
        require(response.status == 200, 'HTTP_FAILED')  # No redirects or retries.
        require(response.getheader('Content-Type', '').split(';')[0].strip() == 'application/json', 'HTTP_CONTENT_TYPE')
        return decode(response.read(LIMIT + 1))
    finally:
        connection.close()


def public_metadata(settings, origin=None):
    host = urllib.parse.urlsplit(settings['issuer']).hostname
    disc = discovery(https_json(host, DISCOVERY, origin), settings)
    keys = public_keys(https_json(host, JWKS, origin))
    return disc, keys


def tls_fingerprint(settings, origin=None):
    host = urllib.parse.urlsplit(settings['issuer']).hostname
    chain = run(['openssl', 's_client', '-connect', (origin or host) + ':443', '-servername', host,
                 '-verify_hostname', host, '-verify_return_error', '-showcerts'], data=b'', timeout=15)
    certificates = re.findall(b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', chain, re.S)
    require(certificates, 'TLS_CERTIFICATE_CHAIN')
    return validate_certificate_chain(certificates, settings['ca_sha1_fingerprints'])


def validate_certificate_chain(pems, expected_fingerprints):
    certificates = [x509.load_pem_x509_certificate(pem) for pem in pems]
    require(2 <= len(certificates) <= 8, 'TLS_CERTIFICATE_CHAIN')
    # OpenSSL above verifies trust, hostname and validity. Also reject an
    # unrelated CA appended after a valid chain. Alibaba's documented thumbprint
    # contract is the final certificate SERVED, which can be an intermediate
    # when fullchain omits the root; it must match an explicitly reviewed pin.
    for child, parent in zip(certificates, certificates[1:]):
        require(parent.extensions.get_extension_for_class(x509.BasicConstraints).value.ca, 'TLS_CHAIN_CA')
        child.verify_directly_issued_by(parent)
    fingerprint = certificates[-1].fingerprint(hashes.SHA1()).hex()
    require(fingerprint in expected_fingerprints, 'TLS_CA_FINGERPRINT')
    return fingerprint


def verify_public(settings, expected=None):
    snapshots = []
    for origin in [None] + [o['https_ip'] for o in settings['origins']]:
        tls_fingerprint(settings, origin)
        disc, keys = public_metadata(settings, origin)
        snapshots.append((disc, keys))
        if expected:
            for kid, key in expected.items():
                require(keys.get(kid) == key, 'PUBLISHED_KEY_MISSING')
    require(all(s == snapshots[0] for s in snapshots), 'PUBLIC_ORIGINS_DISAGREE')
    return snapshots[0][1]


def bind_deployment(settings, deployment, epoch):
    # Controller-only dependency; publication origins do not need cluster tools.
    sys.path.insert(0, str(HERE.parent / 'cluster'))
    from cluster import load_installation
    try:
        installation = load_installation(Path(deployment))
    except (ValueError, KeyError, OSError):
        raise Rejected('INSTALLATION_SNAPSHOT_CHANGED') from None
    inputs = {key: installation[key] for key in ('outputs', 'settings')}
    inventory_hash = installation['manifest']['files']['inventory.yaml']
    require(settings['cluster_epoch'] == epoch and uuid.UUID(epoch).int != 0, 'CLUSTER_EPOCH')
    require(settings['deployment'] == inputs['settings']['deployment'] and settings['region'] == inputs['settings']['region'], 'DEPLOYMENT_BINDING')
    require(settings['oidc_provider_arn'] == inputs['settings']['oidc_provider_arn'], 'PROVIDER_BINDING')
    expected = {name: {'name': name, 'private_ip': node['private_ip'], 'instance_id': node['id']}
                for name, node in inputs['outputs']['node_inventory'].items() if node['role'] == 'control'}
    actual = {node['name']: node for node in settings['control_plane_nodes'].values()}
    require(actual == expected, 'TERRAFORM_CONTROL_PLANE_BINDING')
    for role_name, role in settings['roles'].items():
        upstream = inputs['outputs']['workload_roles'][role_name]
        require(all(upstream.get(k) == role[k] for k in ('arn', 'role_id', 'subject')) and upstream['issuer'] == settings['issuer'] and upstream['audience'] == settings['audience'], 'TERRAFORM_ROLE_BINDING')
    return inventory_hash


def probe_manifest(settings, role_name, name):
    _, _, namespace, sa = settings['roles'][role_name]['subject'].split(':')
    return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': namespace, 'labels': {'sandbox.platform/purpose': 'workload-identity-acceptance'}},
            'spec': {'serviceAccountName': sa, 'automountServiceAccountToken': False, 'restartPolicy': 'Never', 'activeDeadlineSeconds': 300,
                     'nodeSelector': {'sandbox.platform/node-pool': 'platform'},
                     'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'runAsGroup': 65532, 'fsGroup': 65532, 'seccompProfile': {'type': 'RuntimeDefault'}},
                     'containers': [{'name': 'identity-probe', 'image': PROBE_IMAGE, 'command': ['/usr/bin/sleep', '300'],
                                     'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}},
                                     'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'}, 'limits': {'cpu': '100m', 'memory': '32Mi'}},
                                     'volumeMounts': [{'name': 'cloud', 'mountPath': '/var/run/sandbox-cloud', 'readOnly': True}]}],
                     'volumes': [{'name': 'cloud', 'projected': {'defaultMode': 0o440, 'sources': [{'serviceAccountToken': {'audience': settings['audience'], 'expirationSeconds': 600, 'path': 'token'}}]}}]}}


def accept_addons(settings, deployment, epoch):
    """Live gate, never accepts a caller-provided success receipt. Creates only
    temporary nonprivileged probes using the exact future CSI identities."""
    inventory_hash = bind_deployment(settings, deployment, epoch)
    bundle = export(settings)  # Actual mirror-Pod flags and all three node UIDs.
    keys = verify_public(settings, public_keys(bundle['jwks']))
    context = settings['control_plane_contexts'][0]
    results = {}
    for role_name in ('csi-controller', 'csi-node'):
        require(role_name in settings['roles'], 'CSI_ROLES_REQUIRED')
        _, _, namespace, sa_name = settings['roles'][role_name]['subject'].split(':')
        require(namespace == 'kube-system', 'CSI_NAMESPACE')
        existing = kubectl(context, '-n', namespace, 'get', 'serviceaccount', sa_name, '--ignore-not-found', '-o', 'json')
        if not existing.strip():
            run(['kubectl', '--context', context, '--request-timeout=15s', 'create', '-f', '-'],
                canonical({'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': {'namespace': namespace, 'name': sa_name}}))
        name = 'identity-probe-' + uuid.uuid4().hex[:16]
        pod = None
        try:
            created = decode(run(['kubectl', '--context', context, '--request-timeout=15s', 'create', '-f', '-', '-o', 'json'], canonical(probe_manifest(settings, role_name, name))))
            pod = created
            run(['kubectl', '--context', context, '--request-timeout=130s', '-n', namespace, 'wait', '--for=condition=Ready', 'pod/' + name, '--timeout=120s'], timeout=135)
            role, live_pod, sa, token = pod_token(settings, role_name, context, namespace, name, 'identity-probe')
            require(live_pod['metadata']['uid'] == created['metadata']['uid'], 'PROBE_REPLACED')
            result = verify_token(token, settings, keys, role['subject'], live_pod, sa)
            result['sts'] = exchange(settings, role, token)
            results[role_name] = result
        finally:
            if pod:
                # Explicit UID precondition prevents deleting a replacement Pod.
                path = '/api/v1/namespaces/' + namespace + '/pods/' + name
                run(['kubectl', '--context', context, '--request-timeout=15s', 'delete', '--raw', path, '-f', '-'],
                    canonical({'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': pod['metadata']['uid']}, 'gracePeriodSeconds': 0}))
    # Re-observe after probe cleanup; a concurrent issuer/key/flag change cannot
    # inherit a receipt created against the previous control-plane revision.
    final = export(settings)
    require(final['control_planes'] == bundle['control_planes'] and final['jwks'] == bundle['jwks'], 'CONTROL_PLANE_CHANGED_DURING_ACCEPTANCE')
    verify_public(settings, public_keys(final['jwks']))
    now = int(time.time())
    return {'kind': 'workload-identity-acceptance/v1', 'deployment': settings['deployment'], 'cluster_epoch': epoch,
            'inventory_sha256': inventory_hash, 'config_sha256': hashlib.sha256(canonical(settings)).hexdigest(),
            'issued_at': now, 'expires_at': now + 300, 'jwks_sha256': hashlib.sha256(canonical(final['jwks'])).hexdigest(),
            'control_planes': final['control_planes'], 'roles': results}


def verify_installed_csi(settings):
    keys = verify_public(settings, public_keys(export(settings)['jwks']))
    context = settings['control_plane_contexts'][0]
    results = []
    for kind, name, role_name in [('deployment', 'csi-provisioner', 'csi-controller'), ('daemonset', 'csi-plugin', 'csi-node')]:
        workload = decode(kubectl(context, '-n', 'kube-system', 'get', kind, name, '-o', 'json'))
        status = workload.get('status', {})
        require(status.get('observedGeneration') == workload['metadata']['generation'], 'CSI_WORKLOAD_NOT_READY')
        desired = workload['spec'].get('replicas', 1) if kind == 'deployment' else status.get('desiredNumberScheduled', 0)
        ready = status.get('readyReplicas', 0) if kind == 'deployment' else status.get('numberReady', 0)
        require(desired > 0 and ready == desired, 'CSI_WORKLOAD_NOT_READY')
        selector = ','.join(k + '=' + v for k, v in sorted(workload['spec']['selector']['matchLabels'].items()))
        pods = decode(kubectl(context, '-n', 'kube-system', 'get', 'pods', '-l', selector, '-o', 'json'))['items']
        require(pods and len(pods) <= 1000, 'CSI_POD_COUNT')
        observed = 0
        for pod in pods:
            if pod['metadata'].get('deletionTimestamp'):
                continue
            drivers = [c for c in pod['spec']['containers'] if any(v.get('mountPath') == '/var/run/sandbox-cloud' for v in c.get('volumeMounts', []))]
            require(len(drivers) == 1, 'CSI_CLOUD_DRIVER')
            environment = {v['name']: v.get('value') for v in drivers[0].get('env', [])}
            role = settings['roles'][role_name]
            require(environment.get('ALIBABA_CLOUD_ROLE_ARN') == role['arn'] and environment.get('ALIBABA_CLOUD_OIDC_PROVIDER_ARN') == settings['oidc_provider_arn'] and environment.get('ALIBABA_CLOUD_ECS_METADATA_DISABLED') == 'true', 'CSI_IDENTITY_ENVIRONMENT')
            require(not any(k in environment for k in ('ACCESS_KEY_ID', 'ACCESS_KEY_SECRET', 'ALIBABA_CLOUD_ACCESS_KEY_ID', 'ALIBABA_CLOUD_ACCESS_KEY_SECRET')), 'CSI_PERMANENT_CREDENTIAL')
            role, actual, sa, token = pod_token(settings, role_name, context, 'kube-system', pod['metadata']['name'], drivers[0]['name'])
            result = verify_token(token, settings, keys, role['subject'], actual, sa)
            result['sts'] = exchange(settings, role, token)
            results.append(result)
            observed += 1
        require(observed >= desired, 'CSI_POD_COUNT')
    require(results, 'CSI_POD_COUNT')
    return results


def verify_token(token, settings, keys, subject, pod, service_account, now=None):
    now = int(time.time()) if now is None else now
    require(isinstance(token, bytes) and len(token) <= 20000, 'TOKEN_LIMIT')
    try:
        parts = token.strip().decode('ascii').split('.')
    except UnicodeError:
        raise Rejected('TOKEN_FORMAT') from None
    require(len(parts) == 3, 'TOKEN_FORMAT')
    header, claims = decode(b64(parts[0])), decode(b64(parts[1]))
    require(isinstance(header, dict) and set(header) <= {'alg', 'kid', 'typ'} and header.get('alg') == 'RS256' and header.get('typ', 'JWT') == 'JWT', 'TOKEN_HEADER')
    require(header.get('kid') in keys, 'TOKEN_KID')
    key = keys[header['kid']]
    public = rsa.RSAPublicNumbers(int.from_bytes(b64(key['e'])), int.from_bytes(b64(key['n']))).public_key()
    try:
        public.verify(b64(parts[2]), (parts[0] + '.' + parts[1]).encode(), padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise Rejected('TOKEN_SIGNATURE') from None
    require(isinstance(claims, dict) and claims.get('iss') == settings['issuer'] and claims.get('aud') == [settings['audience']] and claims.get('sub') == subject, 'TOKEN_CLAIMS')
    require(all(type(claims.get(k)) is int for k in ('iat', 'nbf', 'exp')), 'TOKEN_TIME')
    skew = settings['clock_skew_seconds']
    require(claims['iat'] <= now + skew and claims['nbf'] <= now + skew and claims['exp'] > now + 60 and 0 < claims['exp'] - claims['iat'] <= settings['max_token_lifetime_seconds'], 'TOKEN_TIME')
    bound = claims.get('kubernetes.io', {})
    require(bound.get('namespace') == pod['metadata']['namespace'] and bound.get('pod') == {'name': pod['metadata']['name'], 'uid': pod['metadata']['uid']} and bound.get('serviceaccount') == {'name': service_account['metadata']['name'], 'uid': service_account['metadata']['uid']}, 'TOKEN_OBJECT_BINDING')
    return {'subject': subject, 'kid': header['kid'], 'expires_at': claims['exp'], 'pod_uid': pod['metadata']['uid']}


def pod_token(settings, role_name, context, namespace, name, container):
    require(role_name in settings['roles'] and context in settings['control_plane_contexts'], 'PROBE_SCOPE')
    require(all(re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}', s) for s in (namespace, name, container)), 'POD_NAME')
    role = settings['roles'][role_name]
    subject_parts = role['subject'].split(':')
    require(namespace == subject_parts[2], 'PROBE_NAMESPACE')
    pod = decode(kubectl(context, '-n', namespace, 'get', 'pod', name, '-o', 'json'))
    sa = decode(kubectl(context, '-n', namespace, 'get', 'serviceaccount', subject_parts[3], '-o', 'json'))
    require(not pod['metadata'].get('deletionTimestamp') and pod['spec']['serviceAccountName'] == subject_parts[3], 'POD_SERVICE_ACCOUNT')
    require(pod['metadata']['name'] == name and pod['metadata']['namespace'] == namespace and sa['metadata']['name'] == subject_parts[3] and sa['metadata']['namespace'] == namespace and not sa['metadata'].get('deletionTimestamp'), 'POD_OBJECT_IDENTITY')
    target = [c for c in pod['spec']['containers'] if c['name'] == container]
    require(len(target) == 1, 'POD_CONTAINER')
    all_mounts = [m for m in target[0].get('volumeMounts', []) if m.get('mountPath', '').startswith('/var/run/sandbox-cloud')]
    mount = [m for m in all_mounts if m.get('mountPath') == '/var/run/sandbox-cloud' and m.get('readOnly') and not m.get('subPath') and not m.get('subPathExpr')]
    require(len(all_mounts) == 1, 'POD_TOKEN_MOUNT')
    require(len(mount) == 1, 'POD_TOKEN_MOUNT')
    volume = [v for v in pod['spec']['volumes'] if v['name'] == mount[0]['name']]
    require(len(volume) == 1, 'POD_TOKEN_VOLUME')
    sources = volume[0].get('projected', {}).get('sources', [])
    require(len(sources) == 1 and set(sources[0]) == {'serviceAccountToken'}, 'POD_TOKEN_PROJECTION')
    projection = sources[0]['serviceAccountToken']
    require(projection.get('audience') == settings['audience'] and projection.get('path') == 'token' and 600 <= projection.get('expirationSeconds', 0) <= settings['max_token_lifetime_seconds'], 'POD_TOKEN_PROJECTION')
    token = kubectl(context, '-n', namespace, 'exec', name, '-c', container, '--', 'cat', TOKEN_PATH).strip()
    current_pod = decode(kubectl(context, '-n', namespace, 'get', 'pod', name, '-o', 'json'))
    current_sa = decode(kubectl(context, '-n', namespace, 'get', 'serviceaccount', subject_parts[3], '-o', 'json'))
    require(current_pod['metadata']['uid'] == pod['metadata']['uid'] and current_sa['metadata']['uid'] == sa['metadata']['uid'] and not current_pod['metadata'].get('deletionTimestamp') and not current_sa['metadata'].get('deletionTimestamp'), 'POD_OBJECT_CHANGED')
    return role, pod, sa, token


def request_id(value):
    result = value.get('RequestId')
    require(isinstance(result, str) and 0 < len(result) <= 256 and not any(ord(c) < 32 for c in result), 'PROVIDER_REQUEST_ID')
    return result


def timestamp(value):
    return int(dt.datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp())


def rpc_signature(headers, secret, query=''):
    signed = ';'.join(sorted(headers))
    canonical_headers = ''.join(k + ':' + headers[k].strip() + '\n' for k in sorted(headers))
    canonical_request = 'POST\n/\n' + query + '\n' + canonical_headers + '\n' + signed + '\n' + hashlib.sha256(b'').hexdigest()
    string_to_sign = 'ACS3-HMAC-SHA256\n' + hashlib.sha256(canonical_request.encode()).hexdigest()
    return signed, hmac.new(secret.encode(), string_to_sign.encode(), hashlib.sha256).hexdigest()


def exchange(settings, role, token):
    host = 'sts.' + settings['region'] + '.aliyuncs.com'
    session = 'acceptance-' + uuid.uuid4().hex
    query = urllib.parse.urlencode({'Action': 'AssumeRoleWithOIDC', 'Version': '2015-04-01', 'Format': 'JSON',
            'RoleArn': role['arn'], 'OIDCProviderArn': settings['oidc_provider_arn'], 'RoleSessionName': session,
            'DurationSeconds': '900', 'OIDCToken': token.decode('ascii')}, quote_via=urllib.parse.quote)
    assumed = https_json(host, '/?' + query, method='POST')
    first_id = request_id(assumed)
    expected_arn = role['arn'] + '/' + session
    info, credentials = assumed.get('OIDCTokenInfo', {}), assumed.get('Credentials', {})
    require(assumed.get('AssumedRoleUser', {}).get('Arn') == expected_arn, 'STS_ROLE_BINDING')
    require(info.get('Issuer') == settings['issuer'] and info.get('Subject') == role['subject'] and info.get('ClientIds') == settings['audience'] and info.get('VerificationInfo') == 'Success', 'STS_OIDC_BINDING')
    require(timestamp(info['ExpirationTime']) > time.time() and timestamp(info['IssuanceTime']) <= time.time() + 30, 'STS_OIDC_TIME')
    expiration = timestamp(credentials['Expiration'])
    require(time.time() + 120 < expiration <= time.time() + 930, 'STS_EXPIRATION')
    require(credentials['AccessKeyId'].startswith('STS.') and credentials['AccessKeySecret'] and credentials['SecurityToken'], 'STS_CREDENTIAL_SHAPE')
    date = dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    headers = {'host': host, 'x-acs-action': 'GetCallerIdentity', 'x-acs-version': '2015-04-01',
               'x-acs-date': date, 'x-acs-signature-nonce': str(uuid.uuid4()), 'x-acs-content-sha256': hashlib.sha256(b'').hexdigest(),
               'x-acs-security-token': credentials['SecurityToken']}
    signed, signature = rpc_signature(headers, credentials['AccessKeySecret'])
    headers['Authorization'] = f'ACS3-HMAC-SHA256 Credential={credentials["AccessKeyId"]},SignedHeaders={signed},Signature={signature}'
    headers['Accept'] = 'application/json'
    identity = https_json(host, '/', headers=headers, method='POST')
    require(identity.get('AccountId') == settings['account_id'] and identity.get('Arn') == expected_arn and identity.get('RoleId') == role['role_id'] and identity.get('IdentityType') == 'AssumedRoleUser', 'STS_CALLER_BINDING')
    return {'sts_request_id': first_id, 'identity_request_id': request_id(identity), 'role_id': role['role_id'], 'expires_at': expiration}


def publish(settings, bundle, retire):
    validate_bundle(bundle, settings, int(time.time()))
    # Verify DNS/SNI/CA against every origin before changing either one. Empty
    # origins need only a valid TLS virtual host during initial publication.
    for origin in [None] + [o['https_ip'] for o in settings['origins']]:
        tls_fingerprint(settings, origin)
    request = canonical({'bundle': bundle, 'retire_kids': retire})
    for origin in settings['origins']:
        command = ['ssh', '-F', '/dev/null', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                   '-o', 'UserKnownHostsFile=' + settings['ssh_known_hosts_file'], '-o', 'ForwardAgent=no',
                   '-o', 'ClearAllForwardings=yes', '-o', 'ConnectTimeout=10', '-o', 'PasswordAuthentication=no',
                   '-o', 'KbdInteractiveAuthentication=no', 'oidc-publisher@' + origin['ssh_host'], REMOTE_COMMAND]
        result = decode(run(command, request, timeout=45))
        require(result.get('published') is True, 'PUBLISH_FAILED')
    return verify_public(settings, public_keys(bundle['jwks']))


def nginx(settings):
    host = urllib.parse.urlsplit(settings['issuer']).hostname
    return f'''# Dedicated public origin; install the certificate with the existing PKI process.
# This tool never reads or installs the TLS private key.
server {{
    listen 443 ssl default_server;
    server_name _;
    ssl_reject_handshake on;
}}
server {{
    listen 443 ssl;
    server_name {host};
    ssl_certificate /etc/sandbox-workload-identity/tls/fullchain.pem;
    ssl_certificate_key /etc/sandbox-workload-identity/tls/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    server_tokens off;
    autoindex off;
    access_log off;
    add_header Cache-Control "public, max-age={settings['cache_seconds']}, must-revalidate" always;
    add_header X-Content-Type-Options nosniff always;
    location = {DISCOVERY} {{
        limit_except GET {{ deny all; }}
        default_type application/json;
        alias /srv/workload-identity/current/discovery.json;
    }}
    location = {JWKS} {{
        limit_except GET {{ deny all; }}
        default_type application/json;
        alias /srv/workload-identity/current/jwks.json;
    }}
    location / {{ return 404; }}
}}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['export', 'receive', 'publish', 'verify-public', 'verify-pod', 'render-nginx'])
    parser.add_argument('--config', required=True)
    parser.add_argument('--output')
    parser.add_argument('--bundle')
    parser.add_argument('--root')
    parser.add_argument('--deployment')
    parser.add_argument('--cluster-epoch')
    parser.add_argument('--retire-kid', action='append', default=[])
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--exchange', action='store_true')
    for field in ('role', 'context', 'namespace', 'pod', 'container'):
        parser.add_argument('--' + field)
    args = parser.parse_args()
    settings = config(args.config)
    if args.command == 'export':
        require(args.output and args.deployment and args.cluster_epoch, 'EXPORT_ARGUMENTS')
        bind_deployment(settings, args.deployment, args.cluster_epoch)
        atomic_json(args.output, export(settings))
        result = {'exported': True}
    elif args.command == 'receive':
        require(args.root, 'ROOT_REQUIRED')
        result = receive(settings, args.root, decode(sys.stdin.buffer.read(LIMIT + 1)))
    elif args.command == 'publish':
        require(args.bundle, 'BUNDLE_REQUIRED')
        bundle = read_json(args.bundle)
        validate_bundle(bundle, settings, int(time.time()))
        result = {'apply_required': True, 'origins': len(settings['origins'])}
        if args.apply:
            result = {'published_and_https_verified': True, 'kids': list(publish(settings, bundle, args.retire_kid))}
    elif args.command == 'verify-public':
        result = {'public_endpoints_verified': True, 'kids': list(verify_public(settings))}
    elif args.command == 'verify-pod':
        require(all((args.role, args.context, args.namespace, args.pod, args.container)), 'POD_ARGUMENTS')
        keys = verify_public(settings)
        role, pod, sa, token = pod_token(settings, args.role, args.context, args.namespace, args.pod, args.container)
        result = verify_token(token, settings, keys, role['subject'], pod, sa)
        if args.exchange:
            result['sts'] = exchange(settings, role, token)
        result['sts_exchanged'] = args.exchange
    else:
        require(args.output, 'OUTPUT_REQUIRED')
        with open(args.output, 'x') as output:
            output.write(nginx(settings))
        result = {'nginx_rendered': True}
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as failure:
        print('workload identity: ' + (str(failure) if isinstance(failure, Rejected) else 'VALIDATION_OR_IO_FAILED'), file=sys.stderr)
        sys.exit(1)
