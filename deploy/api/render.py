#!/usr/bin/env python3
"""Offline production API renderer; creates no secrets and applies no resources."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import ssl
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
NS = 'sandbox-system'
NAME = 'sandbox-api'
PRIVATE = '/run/api-private/private/'
TLS_NAME = NAME + '.' + NS + '.svc.cluster.local'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fields(value, expected, message):
    require(isinstance(value, dict) and set(value) == set(expected), message)
    return value


def name(value):
    require(isinstance(value, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,61}[a-z0-9]|[a-z]', value), 'RESOURCE_NAME')
    return value


def fqdn(value):
    require(isinstance(value, str) and len(value) <= 253 and '.' in value
            and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in value.split('.')),
            'CANONICAL_FQDN')
    # This baseline uses toFQDNs for dependencies outside the Pod network.
    # Cluster endpoints require exact identities; a service DNS allow rule
    # cannot substitute for that policy merely because the URL parses.
    require(not value.endswith(('.svc', '.cluster.local')), 'DEPENDENCY_REQUIRES_EXTERNAL_FQDN')
    return value


def https(value, origin=False):
    require(isinstance(value, str) and len(value) <= 2048, 'HTTPS_URL')
    url = urlsplit(value)
    require(url.scheme == 'https' and url.hostname and url.port in (None, 443)
            and not url.username and not url.password and not url.query and not url.fragment
            and '%' not in url.path and not any(ord(c) < 32 for c in value), 'FIXED_HTTPS_URL')
    fqdn(url.hostname)
    if origin:
        require(value == 'https://' + url.hostname, 'CANONICAL_HTTPS_ORIGIN')
    return url.hostname


def ca(value):
    require(isinstance(value, str) and 0 < len(value.encode()) <= 65536
            and 1 <= value.count('-----BEGIN CERTIFICATE-----') <= 16 and 'PRIVATE' not in value, 'PUBLIC_CA_PEM')
    try:
        ssl.create_default_context(cadata=value)
    except (ssl.SSLError, ValueError):
        raise ValueError('PUBLIC_CA_PEM') from None
    return value


def secret(value):
    fields(value, ['name', 'key'], 'SECRET_REFERENCE_FIELDS')
    name(value['name'])
    require(isinstance(value['key'], str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', value['key']), 'SECRET_KEY_NAME')
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def validate(value):
    fields(value, ['schema_version', 'deployment', 'namespace', 'service_name', 'image', 'replicas', 'zones',
                   'tls', 'cursor_secret', 'database', 'oidc', 'browser', 'metrics', 'files', 'output', 'storage',
                   'callers', 'default_ttl_seconds', 'max_ttl_seconds', 'db_max_connections'], 'API_INPUT_FIELDS')
    require(type(value['schema_version']) is int and value['schema_version'] == 1, 'SCHEMA_VERSION')
    require(value['namespace'] == NS and value['service_name'] == NAME, 'EXACT_API_NAMESPACE_SERVICE')
    name(value['deployment'])
    require(isinstance(value['image'], str) and re.fullmatch(r'[a-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9/_-]+@sha256:[a-f0-9]{64}', value['image']), 'IMMUTABLE_SERVICE_IMAGE')
    require(type(value['replicas']) is int and 2 <= value['replicas'] <= 8, 'HA_REPLICAS_2_TO_8')
    zones = value['zones']
    require(isinstance(zones, list) and 2 <= len(zones) <= 8 and len(set(zones)) == len(zones)
            and all(isinstance(zone, str) and re.fullmatch(r'[a-z]{2}-[a-z0-9-]+[a-z]', zone) for zone in zones), 'REVIEWED_AVAILABILITY_ZONES')
    for key, low, high in [('default_ttl_seconds', 60, 604800), ('max_ttl_seconds', 60, 604800), ('db_max_connections', 1, 200)]:
        require(type(value[key]) is int and low <= value[key] <= high, 'BOUNDED_' + key)
    require(value['default_ttl_seconds'] <= value['max_ttl_seconds'], 'TTL_ORDER')
    fields(value['tls'], ['secret_name', 'certificate_key', 'private_key_key', 'ca_pem'], 'TLS_FIELDS')
    name(value['tls']['secret_name'])
    for key in ['certificate_key', 'private_key_key']:
        require(isinstance(value['tls'][key], str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', value['tls'][key]), 'TLS_SECRET_KEY')
    require(value['tls']['certificate_key'] != value['tls']['private_key_key'], 'DISTINCT_TLS_SECRET_KEYS')
    ca(value['tls']['ca_pem'])
    secret(value['cursor_secret'])
    fields(value['database'], ['secret', 'host', 'port', 'ca_pem'], 'DATABASE_FIELDS')
    secret(value['database']['secret']); fqdn(value['database']['host']); ca(value['database']['ca_pem'])
    require(type(value['database']['port']) is int and value['database']['port'] == 5432, 'POSTGRES_5432')
    fields(value['oidc'], ['issuer', 'audience', 'jwks_url', 'required_scope', 'scope_profile'], 'OIDC_FIELDS')
    require(value['oidc']['scope_profile'] in ('generic-access', 'action-scopes'), 'OIDC_SCOPE_PROFILE')
    https(value['oidc']['issuer']); https(value['oidc']['jwks_url'])
    for key in ['audience', 'required_scope']:
        require(isinstance(value['oidc'][key], str) and re.fullmatch(r'[A-Za-z0-9:_.-]{1,128}', value['oidc'][key]), 'OIDC_VALUE')
    references = [value['tls']['secret_name'], value['cursor_secret']['name'], value['database']['secret']['name']]
    if value['browser'] is not None:
        browser = fields(value['browser'], ['public_origin', 'authorization_url', 'token_url', 'client_id', 'scopes', 'client_secret', 'session_key_secret'], 'BROWSER_FIELDS')
        https(browser['public_origin'], True)
        for key in ['authorization_url', 'token_url']:
            require(https(browser[key]) == https(value['oidc']['issuer']), 'BROWSER_ENDPOINT_ISSUER_HOST')
        require(isinstance(browser['client_id'], str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', browser['client_id']), 'BROWSER_CLIENT_ID')
        require(isinstance(browser['scopes'], list) and 2 <= len(browser['scopes']) <= 64
                and all(isinstance(item, str) and re.fullmatch(r'[A-Za-z0-9:_.-]{1,128}', item) for item in browser['scopes'])
                and len(set(browser['scopes'])) == len(browser['scopes']) and 'openid' in browser['scopes']
                and value['oidc']['required_scope'] in browser['scopes'], 'BROWSER_SCOPES')
        for key in ['client_secret', 'session_key_secret']:
            secret(browser[key]); references.append(browser[key]['name'])
    if value['metrics'] is not None:
        metrics = fields(value['metrics'], ['endpoint', 'ca_pem', 'replicas', 'auth'], 'METRICS_FIELDS')
        https(metrics['endpoint']); ca(metrics['ca_pem'])
        require(isinstance(metrics['replicas'], list) and len(metrics['replicas']) == 2 and len(set(metrics['replicas'])) == 2
                and all(isinstance(replica, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', replica) for replica in metrics['replicas']), 'HA_METRICS_REPLICAS')
        require(isinstance(metrics['auth'], dict), 'METRICS_AUTH')
        if metrics['auth'].get('type') == 'BEARER':
            fields(metrics['auth'], ['type', 'token_secret'], 'METRICS_AUTH_FIELDS'); refs = ['token_secret']
        else:
            fields(metrics['auth'], ['type', 'username_secret', 'password_secret'], 'METRICS_AUTH_FIELDS')
            require(metrics['auth']['type'] == 'BASIC', 'METRICS_AUTH_TYPE'); refs = ['username_secret', 'password_secret']
        for key in refs:
            secret(metrics['auth'][key]); references.append(metrics['auth'][key]['name'])
    require(len(set(references)) == len(references), 'INDEPENDENT_PRIVATE_SECRET_BOUNDARIES')
    require((value['storage'] is None) == (value['files'] is None and value['output'] is None), 'STORAGE_FEATURE_COMPOSITION')
    if value['storage'] is not None:
        require(value['files'] is not None and value['output'] is not None, 'EXACT_API_THREE_STORAGE_ROLES_REQUIRED')
        fields(value['storage'], ['deployment', 'account_id', 'region', 'workload_roles'], 'STORAGE_FIELDS')
        require(value['storage']['deployment'] == value['deployment'], 'STORAGE_DEPLOYMENT_BINDING')
        require(set(value['storage']['workload_roles']) == {'file-upload', 'file-reader', 'output-reader'}, 'EXACT_STORAGE_SCOPE')
        for feature in ['files', 'output']:
            expected = ['endpoint', 'bucket', 'kms_key_id'] + (['max_file_bytes'] if feature == 'files' else [])
            item = fields(value[feature], expected, 'OSS_FIELDS')
            require(item['endpoint'] == 'https://oss-' + value['storage']['region'] + '-internal.aliyuncs.com', 'REGIONAL_PRIVATE_OSS_ENDPOINT')
            require(isinstance(item['bucket'], str) and re.fullmatch(r'[a-z0-9][a-z0-9-]{1,61}[a-z0-9]', item['bucket']), 'OSS_BUCKET')
            require(isinstance(item['kms_key_id'], str) and 1 <= len(item['kms_key_id']) <= 256 and item['kms_key_id'].isascii()
                    and all(33 <= ord(char) <= 126 for char in item['kms_key_id']), 'KMS_KEY_ID')
            if feature == 'files':
                require(type(item['max_file_bytes']) is int and 1 <= item['max_file_bytes'] <= 104857600, 'FILES_100_MIB_MAX')
        require(value['files']['bucket'] != value['output']['bucket'], 'SEPARATE_FILE_OUTPUT_BUCKETS')
        storage_module = storage_library()
        for purpose in ['file-upload', 'file-reader', 'output-reader']:
            storage_module.configuration(value['storage'], 'api', purpose)
    require(isinstance(value['callers'], list) and 1 <= len(value['callers']) <= 16, 'EXACT_MACHINE_CALLER_IDENTITIES')
    for caller in value['callers']:
        fields(caller, ['namespace', 'app_name'], 'CALLER_FIELDS'); name(caller['namespace']); name(caller['app_name'])
        require(not caller['namespace'].startswith(('sbx-', 'tenant-', 'sandbox-runtime')), 'NO_UNTRUSTED_RUNTIME_CALLER')
    return copy.deepcopy(value)


def storage_library():
    spec = importlib.util.spec_from_file_location('api_storage_composition', ROOT.parent / 'storage-credentials/credentials.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def render(inputs):
    value = validate(inputs)
    labels = {'app.kubernetes.io/name': NAME, 'sandbox.platform/network-policy': 'api-v1'}
    metadata = lambda resource: {'name': resource, 'namespace': NS}
    configs = {}
    trust = {'api-ca.pem': value['tls']['ca_pem'], 'db-ca.pem': value['database']['ca_pem']}
    private_sources = [{'secret': {'name': value['cursor_secret']['name'], 'items': [{'key': value['cursor_secret']['key'], 'path': 'cursor/keyring.json'}]}}]
    env = {'SANDBOX_LISTEN': '0.0.0.0:8443', 'SANDBOX_API_TLS_CERT_FILE': '/run/api-tls/tls.crt',
           'SANDBOX_API_TLS_KEY_FILE': '/run/api-tls/tls.key', 'SANDBOX_API_TLS_CA_FILE': '/run/api-trust/api-ca.pem',
           'SANDBOX_API_TLS_SERVER_NAME': TLS_NAME, 'SANDBOX_CURSOR_SIGNING_KEY_FILE': PRIVATE + 'cursor.json',
           'SANDBOX_OIDC_ISSUER': value['oidc']['issuer'], 'SANDBOX_OIDC_AUDIENCE': value['oidc']['audience'],
           'SANDBOX_OIDC_SCOPE_PROFILE': value['oidc']['scope_profile'], 'SANDBOX_OIDC_JWKS_URL': value['oidc']['jwks_url'], 'SANDBOX_OIDC_REQUIRED_SCOPE': value['oidc']['required_scope'],
           'SANDBOX_ALLOW_LOOPBACK_HTTP': 'false', 'SANDBOX_DB_MAX_CONNECTIONS': str(value['db_max_connections']),
           'SANDBOX_DEFAULT_TTL_SECONDS': str(value['default_ttl_seconds']), 'SANDBOX_MAX_TTL_SECONDS': str(value['max_ttl_seconds'])}
    hosts = {value['database']['host'], https(value['oidc']['issuer']), https(value['oidc']['jwks_url'])}
    dependencies = [(value['database']['host'], 5432), (https(value['oidc']['issuer']), 443), (https(value['oidc']['jwks_url']), 443)]
    if value['browser'] is not None:
        browser = value['browser']
        oidc = {key: value['oidc'][key] for key in ['issuer', 'jwks_url']}
        oidc.update({key: browser[key] for key in ['public_origin', 'authorization_url', 'token_url', 'client_id', 'scopes']})
        configs['browser.json'] = canonical({'oidc': oidc, 'client_secret_file': PRIVATE + 'browser-client-secret', 'session_key_file': PRIVATE + 'browser-session-keys.json'})
        env['SANDBOX_BROWSER_CONFIG_FILE'] = '/run/api-config/browser.json'
        for key, path in [('client_secret', 'browser/client-secret'), ('session_key_secret', 'browser/session-keys.json')]:
            ref = browser[key]; private_sources.append({'secret': {'name': ref['name'], 'items': [{'key': ref['key'], 'path': path}]}})
    metrics_type = 'none'
    if value['metrics'] is not None:
        metrics = value['metrics']; metrics_type = metrics['auth']['type'].lower()
        trust['metrics-ca.pem'] = metrics['ca_pem']
        auth = {'type': metrics['auth']['type']}
        entries = [('token_secret', 'token', 'metrics-token', 'token_file')] if metrics_type == 'bearer' else [
            ('username_secret', 'username', 'metrics-username', 'username_file'), ('password_secret', 'password', 'metrics-password', 'password_file')]
        for key, source, target, field in entries:
            ref = metrics['auth'][key]; private_sources.append({'secret': {'name': ref['name'], 'items': [{'key': ref['key'], 'path': 'metrics/' + source}]}})
            auth[field] = PRIVATE + target
        configs['metrics.json'] = canonical({'endpoint': metrics['endpoint'], 'deployment': value['deployment'], 'replicas': metrics['replicas'], 'ca_file': '/run/api-trust/metrics-ca.pem', 'auth': auth})
        env['SANDBOX_METRICS_CONFIG_FILE'] = '/run/api-config/metrics.json'
        hosts.add(https(metrics['endpoint'])); dependencies.append((https(metrics['endpoint']), 443))
    if value['storage'] is not None:
        files = dict(value['files'])
        files.update({'api_upload_sts_file': '/run/sandbox-cloud/file-upload/private/sts.json', 'read_sts_file': '/run/sandbox-cloud/file-reader/private/sts.json',
                      'gateway_sts_file': '/run/sandbox-cloud/file-gateway/private/sts.json', 'cleanup_sts_file': '/run/sandbox-cloud/file-cleaner/private/sts.json'})
        configs['files.json'] = canonical(files); env['SANDBOX_FILES_CONFIG_FILE'] = '/run/api-config/files.json'
        for key, setting in [('ENDPOINT', 'endpoint'), ('BUCKET', 'bucket'), ('KMS_KEY_ID', 'kms_key_id')]:
            env['SANDBOX_OUTPUT_OSS_' + key] = value['output'][setting]
        env['SANDBOX_OUTPUT_READ_STS_FILE'] = '/run/sandbox-cloud/output-reader/private/sts.json'
        for feature in ['files', 'output']:
            host = value[feature]['bucket'] + '.' + https(value[feature]['endpoint'])
            hosts.add(host); dependencies.append((host, 443))
        host = 'sts.' + value['storage']['region'] + '.aliyuncs.com'; hosts.add(host); dependencies.append((host, 443))
        for role in value['storage']['workload_roles'].values():
            host = https(role['issuer']); hosts.add(host); dependencies.append((host, 443))
    config_name = NAME + '-config-' + hashlib.sha256(canonical(configs).encode()).hexdigest()[:16]
    trust_name = NAME + '-trust-' + hashlib.sha256(canonical(trust).encode()).hexdigest()[:16]
    security = {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}}
    pod = {'serviceAccountName': NAME, 'automountServiceAccountToken': False, 'terminationGracePeriodSeconds': 35,
           'nodeSelector': {'sandbox.platform/node-pool': 'platform'}, 'dnsConfig': {'options': [{'name': 'ndots', 'value': '1'}]},
           'affinity': {'nodeAffinity': {'requiredDuringSchedulingIgnoredDuringExecution': {'nodeSelectorTerms': [{'matchExpressions': [{'key': 'topology.kubernetes.io/zone', 'operator': 'In', 'values': value['zones']}]}]}},
                        'podAntiAffinity': {'requiredDuringSchedulingIgnoredDuringExecution': [{'labelSelector': {'matchLabels': labels}, 'topologyKey': 'kubernetes.io/hostname'}]}},
           'topologySpreadConstraints': [{'maxSkew': 1, 'minDomains': 2, 'topologyKey': 'topology.kubernetes.io/zone', 'whenUnsatisfiable': 'DoNotSchedule', 'labelSelector': {'matchLabels': labels}}],
           'securityContext': {'runAsUser': 10001, 'runAsGroup': 10001, 'runAsNonRoot': True, 'fsGroup': 10001, 'fsGroupChangePolicy': 'OnRootMismatch', 'seccompProfile': {'type': 'RuntimeDefault'}},
           'volumes': [{'name': 'api-private-source', 'projected': {'defaultMode': 0o440, 'sources': private_sources}},
                       {'name': 'api-private', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '1Mi'}},
                       {'name': 'api-tls', 'secret': {'secretName': value['tls']['secret_name'], 'defaultMode': 0o440,
                            'items': [{'key': value['tls']['certificate_key'], 'path': 'tls.crt'}, {'key': value['tls']['private_key_key'], 'path': 'tls.key'}]}},
                       {'name': 'api-trust', 'configMap': {'name': trust_name, 'defaultMode': 0o444}},
                       {'name': 'api-config', 'configMap': {'name': config_name, 'defaultMode': 0o444}},
                       {'name': 'tmp', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '32Mi'}}],
           'initContainers': [{'name': 'api-secrets-init', 'image': value['image'], 'imagePullPolicy': 'Always',
                 'command': ['/usr/local/bin/sandboxd', 'secrets-init', '--profile', 'browser' if value['browser'] else 'bearer', '--metrics-auth', metrics_type],
                 'securityContext': security, 'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'}, 'limits': {'cpu': '100m', 'memory': '32Mi'}},
                 'volumeMounts': [{'name': 'api-private-source', 'mountPath': '/var/run/api-secret-source', 'readOnly': True}, {'name': 'api-private', 'mountPath': '/run/api-private'}]}],
           'containers': [{'name': 'api', 'image': value['image'], 'imagePullPolicy': 'Always', 'command': ['/usr/local/bin/sandboxd', '--role', 'api'],
                 'env': [{'name': key, 'value': setting} for key, setting in sorted(env.items())] + [{'name': 'SANDBOX_DATABASE_URL', 'valueFrom': {'secretKeyRef': value['database']['secret']}}, {'name': 'SANDBOX_PROCESS_POD_UID', 'valueFrom': {'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.uid'}}}],
                 'securityContext': security, 'ports': [{'name': 'https', 'containerPort': 8443}],
                 'resources': {'requests': {'cpu': '250m', 'memory': '256Mi'}, 'limits': {'cpu': '2000m', 'memory': '1Gi'}},
                 'startupProbe': {'httpGet': {'scheme': 'HTTPS', 'path': '/health/ready', 'port': 'https'}, 'periodSeconds': 3, 'timeoutSeconds': 2, 'failureThreshold': 40},
                 'readinessProbe': {'httpGet': {'scheme': 'HTTPS', 'path': '/health/ready', 'port': 'https'}, 'periodSeconds': 5, 'timeoutSeconds': 2, 'failureThreshold': 1},
                 'livenessProbe': {'httpGet': {'scheme': 'HTTPS', 'path': '/health/live', 'port': 'https'}, 'periodSeconds': 10, 'timeoutSeconds': 2, 'failureThreshold': 3},
                 'volumeMounts': [{'name': key, 'mountPath': '/run/' + key, 'readOnly': True} for key in ['api-private', 'api-tls', 'api-trust', 'api-config']] + [{'name': 'tmp', 'mountPath': '/tmp'}]}]}
    deployment = {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': metadata(NAME), 'spec': {'replicas': value['replicas'], 'revisionHistoryLimit': 3,
        'strategy': {'type': 'RollingUpdate', 'rollingUpdate': {'maxUnavailable': 0, 'maxSurge': 1}}, 'selector': {'matchLabels': labels},
        'template': {'metadata': {'labels': labels}, 'spec': pod}}}
    objects = [{'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': metadata(NAME), 'automountServiceAccountToken': False},
               {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': metadata(config_name), 'immutable': True, 'data': configs},
               {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': metadata(trust_name), 'immutable': True, 'data': trust}]
    if value['storage'] is not None:
        storage_objects = storage_library().compose(deployment, value['storage'], 'api')
        objects.extend(storage_objects[:-1]); deployment = storage_objects[-1]
    objects.extend([deployment, {'apiVersion': 'v1', 'kind': 'Service', 'metadata': metadata(NAME), 'spec': {'type': 'ClusterIP', 'selector': labels, 'ports': [{'name': 'https', 'port': 8443, 'targetPort': 'https'}]}},
                    {'apiVersion': 'policy/v1', 'kind': 'PodDisruptionBudget', 'metadata': metadata(NAME), 'spec': {'minAvailable': value['replicas'] - 1, 'selector': {'matchLabels': labels}}}])
    callers = [{'matchLabels': {'k8s:io.kubernetes.pod.namespace': NS, 'k8s:app.kubernetes.io/name': 'sandbox-console', 'k8s:sandbox.platform/network-policy': 'console-v1'}}]
    callers += [{'matchLabels': {'k8s:io.kubernetes.pod.namespace': caller['namespace'], 'k8s:app.kubernetes.io/name': caller['app_name']}} for caller in value['callers']]
    egress = [{'toEndpoints': [{'matchLabels': {'k8s:io.kubernetes.pod.namespace': 'kube-system', 'k8s:k8s-app': 'kube-dns'}}],
               'toPorts': [{'ports': [{'port': '53', 'protocol': 'ANY'}], 'rules': {'dns': [{'matchName': host} for host in sorted(hosts)]}}]}]
    for host, port in sorted(set(dependencies)):
        egress.append({'toFQDNs': [{'matchName': host}], 'toPorts': [{'ports': [{'port': str(port), 'protocol': 'TCP'}]}]})
    objects.append({'apiVersion': 'cilium.io/v2', 'kind': 'CiliumNetworkPolicy', 'metadata': metadata(NAME),
                    'spec': {'endpointSelector': {'matchLabels': {'k8s:app.kubernetes.io/name': NAME, 'k8s:sandbox.platform/network-policy': 'api-v1'}},
                             'ingress': [{'fromEndpoints': callers, 'toPorts': [{'ports': [{'port': '8443', 'protocol': 'TCP'}]}]},
                                         {'fromEntities': ['host'], 'toPorts': [{'ports': [{'port': '8443', 'protocol': 'TCP'}]}]}], 'egress': egress}})
    return {'apiVersion': 'v1', 'kind': 'List', 'items': objects}


def load(path):
    with path.open('rb') as source:
        value = source.read(262145)
    require(len(value) <= 262144, 'INPUT_256_KIB_LIMIT')
    def unique(pairs):
        result = {}
        for key, item in pairs:
            require(key not in result, 'DUPLICATE_JSON_FIELD'); result[key] = item
        return result
    return json.loads(value, object_pairs_hook=unique)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        objects = render(load(args.inputs))
        with args.output.open('xb') as out:
            out.write(canonical(objects).encode() + b'\n')
    except (ValueError, TypeError, KeyError, OSError):
        parser.exit(1, 'API_RENDER_REJECTED\n')


if __name__ == '__main__':
    main()
