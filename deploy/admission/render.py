#!/usr/bin/env python3
"""Offline admission installer: public trust and references only; never applies."""
import argparse
import base64
from collections import Counter
import copy
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
import yaml

ROOT = Path(__file__).resolve().parent
NS = 'sandbox-system'
NAME = 'sandbox-admission'
LABELS = {'app.kubernetes.io/name': NAME, 'sandbox.platform/network-policy': 'admission-v1'}
SERVER_NAMES = [NAME + '.' + NS + '.svc', NAME + '.' + NS + '.svc.cluster.local']
DB_CA = '/etc/sandbox-admission-db-ca/ca.crt'


def require(condition, category):
    if not condition:
        raise ValueError(category)


def fields(value, expected, category):
    require(isinstance(value, dict) and set(value) == set(expected), category)
    return value


def name(value):
    require(isinstance(value, str) and re.fullmatch(r'[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?', value), 'RESOURCE_NAME')
    return value


def key(value):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', value)
            and value not in ('.', '..'), 'REFERENCE_KEY')
    return value


def fqdn(value):
    require(isinstance(value, str) and 3 <= len(value) <= 253 and '.' in value
            and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                    for part in value.split('.')), 'CANONICAL_FQDN')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError('EXTERNAL_DB_FQDN_REQUIRED')
    require(not value.endswith(('.svc', '.cluster.local', '.localhost', '.local'))
            and value != 'localhost', 'EXTERNAL_DB_FQDN_REQUIRED')
    return value


def ca_keys(value):
    require(isinstance(value, str) and 0 < len(value.encode()) <= 65536, 'PUBLIC_CA_BOUND')
    blocks = re.findall(r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----', value)
    require(1 <= len(blocks) <= 16 and not re.sub(
        r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----', '', value).strip(), 'PUBLIC_CA_PEM')
    try:
        certificates = [x509.load_pem_x509_certificate(block.encode()) for block in blocks]
        now = datetime.now(timezone.utc)
        for cert in certificates:
            require(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                    and cert.not_valid_before_utc <= now < cert.not_valid_after_utc, 'VALID_CA_REQUIRED')
            try:
                require(cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign, 'CA_SIGNING_USAGE')
            except x509.ExtensionNotFound:
                pass
        require(len({cert.fingerprint(hashes.SHA256()) for cert in certificates}) == len(certificates), 'DUPLICATE_CA')
        return {cert.public_key().public_bytes(serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo) for cert in certificates}
    except (ValueError, x509.ExtensionNotFound):
        raise ValueError('PUBLIC_VALID_CA_REQUIRED') from None


def reference(value):
    fields(value, ['name', 'key'], 'REFERENCE_FIELDS')
    name(value['name']); key(value['key'])


def validate(value):
    fields(value, ['schema_version', 'image', 'replicas', 'platform_nodes', 'config', 'database',
                   'server_tls', 'apiserver_client_ca_pem'], 'ADMISSION_INPUT_FIELDS')
    require(type(value['schema_version']) is int and value['schema_version'] == 1, 'SCHEMA_VERSION')
    require(isinstance(value['image'], str) and re.fullmatch(
        r'[a-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9/_-]+@sha256:[a-f0-9]{64}', value['image']), 'IMMUTABLE_REVIEWED_IMAGE')
    require(type(value['replicas']) is int and 2 <= value['replicas'] <= 8, 'HA_REPLICAS_2_TO_8')
    nodes = value['platform_nodes']
    require(isinstance(nodes, list) and 3 <= len(nodes) <= 32, 'BOUNDED_PLATFORM_INVENTORY')
    for node in nodes:
        fields(node, ['hostname', 'zone'], 'PLATFORM_NODE_FIELDS')
        require(isinstance(node['hostname'], str) and len(node['hostname']) <= 63
                and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                        for part in node['hostname'].split('.')), 'PLATFORM_HOSTNAME')
        require(isinstance(node['zone'], str) and len(node['zone']) <= 63
                and re.fullmatch(r'[a-z]{2}-[a-z0-9-]+[a-z]', node['zone']), 'PLATFORM_ZONE')
    capacities = Counter(node['zone'] for node in nodes)
    require(len(capacities) == 3 and len({node['hostname'] for node in nodes}) == len(nodes), 'THREE_AZ_UNIQUE_PLATFORM_HOSTS')
    target = value['replicas'] + 1
    base = target // 3
    require(all(count >= base for count in capacities.values())
            and sum(min(count, base + 1) for count in capacities.values()) >= target, 'THREE_AZ_SURGE_CAPACITY')
    config = fields(value['config'], ['name', 'key', 'sha256'], 'CONFIG_REFERENCE_FIELDS')
    name(config['name']); key(config['key'])
    require(isinstance(config['sha256'], str) and re.fullmatch(r'[a-f0-9]{64}', config['sha256']), 'REVIEWED_CONFIG_DIGEST')
    database = fields(value['database'], ['secret', 'host', 'port', 'ca_pem'], 'DATABASE_FIELDS')
    reference(database['secret']); fqdn(database['host'])
    require(type(database['port']) is int and database['port'] == 5432, 'POSTGRES_5432')
    database_keys = ca_keys(database['ca_pem'])
    tls = fields(value['server_tls'], ['secret_name', 'certificate_key', 'private_key_key', 'server_ca_pem'], 'SERVER_TLS_FIELDS')
    name(tls['secret_name']); key(tls['certificate_key']); key(tls['private_key_key'])
    require(tls['certificate_key'] != tls['private_key_key'], 'DISTINCT_TLS_KEYS')
    require(tls['secret_name'] != database['secret']['name'], 'INDEPENDENT_DATABASE_TLS_SECRETS')
    server_keys = ca_keys(tls['server_ca_pem'])
    client_keys = ca_keys(value['apiserver_client_ca_pem'])
    require(client_keys.isdisjoint(server_keys | database_keys), 'DEDICATED_APISERVER_CLIENT_SIGNING_KEYS')
    trust = trust_name(value)
    require(config['name'] not in {trust, 'kube-root-ca.crt'}, 'INDEPENDENT_CONFIG_TRUST_BOUNDARIES')
    return copy.deepcopy(value)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def trust_name(value):
    return NAME + '-trust-' + hashlib.sha256(canonical({
        'db-ca': value['database']['ca_pem'], 'client-ca': value['apiserver_client_ca_pem']}).encode()).hexdigest()[:16]


def render(inputs):
    value = validate(inputs)
    trust = trust_name(value)
    metadata = lambda resource: {'name': resource, 'namespace': NS}
    port = lambda number: {'port': str(number), 'protocol': 'TCP'}
    pod = {'serviceAccountName': NAME, 'automountServiceAccountToken': False,
        'terminationGracePeriodSeconds': 20,
        'dnsPolicy': 'ClusterFirst', 'dnsConfig': {'options': [{'name': 'ndots', 'value': '1'}]},
        'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001, 'runAsGroup': 10001,
            'fsGroup': 10001, 'fsGroupChangePolicy': 'OnRootMismatch', 'seccompProfile': {'type': 'RuntimeDefault'}},
        'nodeSelector': {'sandbox.platform/node-pool': 'platform'},
        'affinity': {'nodeAffinity': {'requiredDuringSchedulingIgnoredDuringExecution': {'nodeSelectorTerms': [
            {'matchExpressions': [{'key': 'kubernetes.io/hostname', 'operator': 'In',
                                   'values': sorted(node['hostname'] for node in value['platform_nodes'])},
                {'key': 'topology.kubernetes.io/zone', 'operator': 'In',
                 'values': sorted({node['zone'] for node in value['platform_nodes']})}]}]}},
            'podAntiAffinity': {'requiredDuringSchedulingIgnoredDuringExecution': [
                {'topologyKey': 'kubernetes.io/hostname', 'labelSelector': {'matchLabels': LABELS}}]}},
        'topologySpreadConstraints': [{'maxSkew': 1, 'topologyKey': topology, 'whenUnsatisfiable': 'DoNotSchedule',
            'labelSelector': {'matchLabels': LABELS}, **({'minDomains': 3} if topology.endswith('/zone') else {})}
            for topology in ['topology.kubernetes.io/zone', 'kubernetes.io/hostname']],
        'volumes': [
            {'name': 'config', 'configMap': {'name': value['config']['name'], 'defaultMode': 0o440,
                'items': [{'key': value['config']['key'], 'path': 'config.json'}]}},
            {'name': 'server-tls', 'secret': {'secretName': value['server_tls']['secret_name'], 'defaultMode': 0o440,
                'items': [{'key': value['server_tls']['certificate_key'], 'path': 'tls.crt'},
                          {'key': value['server_tls']['private_key_key'], 'path': 'tls.key'}]}},
            {'name': 'client-ca', 'configMap': {'name': trust, 'defaultMode': 0o440,
                'items': [{'key': 'apiserver-client-ca.pem', 'path': 'ca.crt'}]}},
            {'name': 'db-ca', 'configMap': {'name': trust, 'defaultMode': 0o440,
                'items': [{'key': 'db-ca.pem', 'path': 'ca.crt'}]}},
            {'name': 'kube-api', 'projected': {'defaultMode': 0o440, 'sources': [
                {'serviceAccountToken': {'path': 'token', 'expirationSeconds': 3600}},
                {'configMap': {'name': 'kube-root-ca.crt', 'items': [{'key': 'ca.crt', 'path': 'ca.crt'}]}},
                {'downwardAPI': {'items': [{'path': 'namespace', 'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.namespace'}}]}}]}}]}
    container = {'name': 'admission', 'image': value['image'], 'imagePullPolicy': 'IfNotPresent',
        'command': ['/usr/local/bin/sandbox-admission'],
        'args': ['--config', '/etc/sandbox-admission/config.json', '--tls-certificate', '/etc/sandbox-admission-tls/tls.crt',
                 '--tls-key', '/etc/sandbox-admission-tls/tls.key', '--apiserver-client-ca', '/etc/sandbox-admission-client-ca/ca.crt'],
        'env': [{'name': 'SANDBOX_ADMISSION_DATABASE_URL', 'valueFrom': {'secretKeyRef': value['database']['secret']}}, {'name': 'SANDBOX_PROCESS_POD_UID', 'valueFrom': {'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.uid'}}}],
        'ports': [{'name': 'webhook', 'containerPort': 8443, 'protocol': 'TCP'}],
        'securityContext': {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}},
        'resources': {'requests': {'cpu': '250m', 'memory': '256Mi'}, 'limits': {'cpu': '1', 'memory': '512Mi'}},
        'volumeMounts': [{'name': name_, 'mountPath': path, 'readOnly': True} for name_, path in [
            ('config', '/etc/sandbox-admission'), ('server-tls', '/etc/sandbox-admission-tls'),
            ('client-ca', '/etc/sandbox-admission-client-ca'), ('db-ca', '/etc/sandbox-admission-db-ca'),
            ('kube-api', '/var/run/secrets/kubernetes.io/serviceaccount')]]}
    local = {'exec': {'command': ['/usr/local/bin/sandbox-admission', '--probe-local']}, 'timeoutSeconds': 2}
    container['startupProbe'] = dict(copy.deepcopy(local), periodSeconds=2, failureThreshold=30)
    container['readinessProbe'] = dict(copy.deepcopy(local), periodSeconds=5, failureThreshold=2)
    container['livenessProbe'] = dict(copy.deepcopy(local), periodSeconds=10, failureThreshold=3)
    pod['containers'] = [container]
    resources = [
        {'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': metadata(NAME), 'automountServiceAccountToken': False},
        {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRole', 'metadata': {'name': NAME + '-read-state'},
            'rules': [{'apiGroups': [''], 'resources': ['namespaces', 'nodes', 'pods', 'persistentvolumes', 'persistentvolumeclaims'], 'verbs': ['get']},
                      {'apiGroups': ['cilium.io'], 'resources': ['ciliumnetworkpolicies'], 'verbs': ['get']}]},
        {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRoleBinding', 'metadata': {'name': NAME + '-read-state'},
            'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': NAME + '-read-state'},
            'subjects': [{'kind': 'ServiceAccount', 'name': NAME, 'namespace': NS}]},
        {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': metadata(trust), 'immutable': True,
            'data': {'db-ca.pem': value['database']['ca_pem'], 'apiserver-client-ca.pem': value['apiserver_client_ca_pem']}},
        {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': metadata(NAME),
            'spec': {'replicas': value['replicas'], 'revisionHistoryLimit': 3, 'progressDeadlineSeconds': 180,
                'minReadySeconds': 10, 'strategy': {'type': 'RollingUpdate', 'rollingUpdate': {'maxUnavailable': 0, 'maxSurge': 1}},
                'selector': {'matchLabels': LABELS}, 'template': {'metadata': {'labels': LABELS,
                    'annotations': {'sandbox.platform/config-sha256': value['config']['sha256'],
                        'sandbox.platform/server-ca-sha256': hashlib.sha256(value['server_tls']['server_ca_pem'].encode()).hexdigest()}}, 'spec': pod}}},
        {'apiVersion': 'v1', 'kind': 'Service', 'metadata': metadata(NAME),
            'spec': {'type': 'ClusterIP', 'selector': LABELS, 'ports': [{'name': 'https', 'port': 443, 'targetPort': 'webhook', 'protocol': 'TCP'}]}},
        {'apiVersion': 'policy/v1', 'kind': 'PodDisruptionBudget', 'metadata': metadata(NAME),
            'spec': {'minAvailable': value['replicas'] - 1, 'selector': {'matchLabels': LABELS}}},
        {'apiVersion': 'cilium.io/v2', 'kind': 'CiliumNetworkPolicy', 'metadata': metadata(NAME),
            'spec': {'endpointSelector': {'matchLabels': {'k8s:' + k: v for k, v in LABELS.items()}},
                'enableDefaultDeny': {'ingress': True, 'egress': True},
                'ingress': [{'fromEntities': ['kube-apiserver'], 'toPorts': [{'ports': [port(8443)]}]}],
                'egress': [
                    {'toEndpoints': [{'matchLabels': {'k8s:io.kubernetes.pod.namespace': 'kube-system', 'k8s:k8s-app': 'kube-dns'}}],
                        'toPorts': [{'ports': [{'port': '53', 'protocol': 'ANY'}], 'rules': {'dns': [{'matchName': value['database']['host']}]}}]},
                    {'toFQDNs': [{'matchName': value['database']['host']}], 'toPorts': [{'ports': [port(5432)]}]},
                    {'toEntities': ['kube-apiserver'], 'toPorts': [{'ports': [port(443), port(6443)]}]}]}}]
    return {'apiVersion': 'v1', 'kind': 'List', 'items': resources}


def webhook(inputs):
    value = validate(inputs)
    # Reuse the reviewed global Fail/rule contract; the activation object is
    # deliberately separate from the initial identity/workload manifest.
    result = yaml.safe_load((ROOT / 'webhook.yaml').read_text())
    result['webhooks'][0]['clientConfig']['caBundle'] = base64.b64encode(value['server_tls']['server_ca_pem'].encode()).decode()
    return result


def load(path):
    with path.open('rb') as source:
        raw = source.read(262145)
    require(len(raw) <= 262144, 'INPUT_256_KIB_BOUND')
    def unique(pairs):
        value = {}
        for field, item in pairs:
            require(field not in value, 'DUPLICATE_JSON_FIELD')
            value[field] = item
        return value
    def reject_constant(_):
        raise ValueError('NONFINITE_JSON_VALUE')
    def finite_float(text):
        result = float(text)
        require(math.isfinite(result), 'NONFINITE_JSON_VALUE')
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant, parse_float=finite_float)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        raise ValueError('INVALID_INPUT_JSON') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--webhook-out', type=Path, required=True, help='Separate activation object; install LAST')
    args = parser.parse_args()
    require(len({args.input.resolve(), args.out.resolve(), args.webhook_out.resolve()}) == 3, 'DISTINCT_INPUT_OUTPUT_PATHS')
    value = load(args.input)
    documents = [render(value), webhook(value)]
    require(not args.out.exists() and not args.webhook_out.exists(), 'OUTPUT_ALREADY_EXISTS')
    for path, document in zip([args.out, args.webhook_out], documents):
        with path.open('x') as output:
            output.write(json.dumps(document, indent=2, allow_nan=False) + '\n')
    print('Rendered public admission workload and separate LAST activation object; no secrets, apply or certification.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError):
        raise SystemExit('Admission rendering rejected; inspect reviewed inputs without logging private data.') from None
