#!/usr/bin/env python3
"""Reviewed production identity manifests. No cloud calls; mutation needs --execute."""
import argparse
import base64
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from urllib.parse import urlsplit

import jsonschema
import yaml
import realm

ROOT = Path(__file__).resolve().parent
LOCK = json.loads((ROOT / 'versions.lock.json').read_text())
SERVER_LABELS = {'app': 'keycloak', 'app.kubernetes.io/managed-by': 'keycloak-operator',
                 'app.kubernetes.io/component': 'server'}


def require(value, message):
    if not value:
        raise ValueError(message)


def exact(value, keys, name):
    require(isinstance(value, dict) and set(value) == set(keys), f'{name}: unexpected or missing keys')


def dns(value):
    require(isinstance(value, str) and len(value) <= 253 and
            re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', value) and '..' not in value,
            'invalid DNS name')
    return value


def url(value, origin=False):
    p = urlsplit(value)
    require(p.scheme == 'https' and p.hostname and not p.username and not p.password and
            not p.query and not p.fragment and p.port in (None, 443), 'fixed HTTPS URL required')
    dns(p.hostname)
    require(not origin or p.path == '', 'origin must not have path or trailing slash')
    require(not any(c.isspace() for c in value), 'URL whitespace rejected')
    return value


def cidrs(values, private=True):
    require(isinstance(values, list) and 1 <= len(values) <= 32, 'bounded CIDR list required')
    for value in values:
        net = ipaddress.ip_network(value, strict=True)
        require(net.version == 4 and net.prefixlen >= 16 and (net.is_private or not private),
                'explicit narrow IPv4 CIDRs required')
    return values


def validate(s):
    if s.get('mode') == 'external':
        exact(s, ['mode', 'issuer', 'jwks_url', 'audience', 'token_profile', 'allowed_algorithms',
                  'max_token_lifetime_seconds', 'clock_skew_seconds', 'required_scopes', 'scope_profile'], 'external')
        url(s['issuer']); url(s['jwks_url'])
        require(s['token_profile'] in ('rfc9068', 'keycloak'), 'unsupported access-token profile')
        require(s['allowed_algorithms'] == ['RS256'], 'API only accepts RS256')
        require(s['max_token_lifetime_seconds'] == 300 and s['clock_skew_seconds'] == 30,
                'production contract requires five minute tokens and 30 second skew')
        require(s['required_scopes'] == ['sandbox:access'], 'sandbox:access required')
        require(s['scope_profile'] in ('generic-access', 'action-scopes'), 'explicit supported action scope profile required')
    else:
        exact(s, ['mode', 'namespace', 'realm', 'audience', 'public_url', 'admin_url', 'database',
                  'smtp', 'proxy_namespace', 'proxy_labels', 'proxy_cidrs', 'admin_cidrs',
                  'monitoring_namespace', 'platform_node_selector', 'zones', 'secret_files',
                  'broker', 'apiserver_cidrs', 'proxy', 'proxy_ca_file', 'public_client_cidrs', 'proxy_backend_ca_file'], 'standalone')
        require(s['mode'] == 'standalone', 'unknown identity mode')
        for key in ('namespace', 'realm', 'proxy_namespace', 'monitoring_namespace'):
            dns(s[key]); require('.' not in s[key], 'namespace/realm must be DNS label')
        require(s['namespace'] not in ('default', 'kube-system') and s['realm'] != 'master',
                'dedicated namespace and application realm required')
        require(s['proxy_namespace'] not in ('default','kube-system',s['namespace']), 'separate trusted proxy namespace required')
        url(s['public_url'], True); url(s['admin_url'], True)
        require(s['public_url'] != s['admin_url'], 'separate private admin origin required')
        exact(s['database'], ['host', 'name', 'port'], 'database')
        dns(s['database']['host']); require(re.fullmatch(r'[a-z][a-z0-9_]{1,62}', s['database']['name']), 'invalid database identifier')
        require(s['database']['port'] == 5432 and s['database']['name'] not in ('postgres', 'sandbox_prod'),
                'dedicated PostgreSQL identity database required')
        exact(s['smtp'], ['host', 'from'], 'smtp'); dns(s['smtp']['host'])
        require(re.fullmatch(r'[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+', s['smtp']['from']), 'SMTP sender required')
        for key in ('proxy_cidrs', 'admin_cidrs', 'apiserver_cidrs'):
            cidrs(s[key])
        for key in ('proxy_labels', 'platform_node_selector'):
            require(isinstance(s[key], dict) and 0 < len(s[key]) <= 4 and
                    all(isinstance(k, str) and isinstance(v, str) and v for k, v in s[key].items()),
                    'explicit proxy and trusted platform node selectors required')
        require(s['platform_node_selector'].get('sandbox.platform/node-pool') == 'platform', 'identity must run on trusted platform nodes')
        require(len(s['zones']) == 3 and len(set(s['zones'])) == 3, 'three separate zones required')
        for zone in s['zones']: dns(zone)
        exact(s['proxy'], ['deployment','configmap','public_service','admin_service','image'], 'proxy')
        for key in ('deployment','configmap','public_service','admin_service'): dns(s['proxy'][key])
        require(s['proxy']['public_service'] != s['proxy']['admin_service'], 'separate admin Service required')
        require(re.fullmatch(r'[A-Za-z0-9./:_-]+@sha256:[a-f0-9]{64}', s['proxy']['image']), 'reviewed digest-pinned HAProxy image required')
        require(isinstance(s['public_client_cidrs'],list) and 1 <= len(s['public_client_cidrs']) <= 32, 'public client CIDRs required')
        for network in s['public_client_cidrs']: require(ipaddress.ip_network(network,strict=True).version == 4, 'IPv4 client CIDRs required')
        require(Path(s['proxy_backend_ca_file']).is_absolute(), 'explicit backend CA file required')
        require(Path(s['proxy_ca_file']).is_absolute(), 'explicit frontend CA file required')
        required_secrets = {'keycloak-db': {'username', 'password'},
            'keycloak-tls': {'tls.crt', 'tls.key'}, 'keycloak-trust': {'rds.pem'},
            'keycloak-bootstrap': {'username', 'password'}, 'keycloak-smtp': {'username', 'password'}}
        if s['broker']:
            b = s['broker']
            exact(b, ['issuer', 'authorization_url', 'token_url', 'jwks_url', 'client_id'], 'broker')
            for k in ('issuer', 'authorization_url', 'token_url', 'jwks_url'): url(b[k])
            require(re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', b['client_id']), 'invalid broker client')
            required_secrets['keycloak-broker'] = {'secret'}
        exact(s['secret_files'], required_secrets, 'secret_files')
        for name, keys in required_secrets.items():
            exact(s['secret_files'][name], keys, name)
            for path in s['secret_files'][name].values():
                require(isinstance(path, str) and Path(path).is_absolute(), 'absolute Secret file path required')
    require(isinstance(s['audience'], str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', s['audience']),
            'invalid fixed API audience')
    return s


def auth_config(s):
    issuer = s['issuer'] if s['mode'] == 'external' else s['public_url'] + '/realms/' + s['realm']
    return {'issuer': issuer, 'audience': s['audience'],
            'jwks_url': s['jwks_url'] if s['mode'] == 'external' else issuer + '/protocol/openid-connect/certs',
            'required_scopes': ['sandbox:access'],
            'scope_profile': 'ACTION_SCOPES' if s['mode'] == 'external' and s['scope_profile'] == 'action-scopes' else 'GENERIC_ACCESS',
            'jwks_ttl_seconds': 300,
            'clock_skew_seconds': 30, 'allow_loopback_http': False, 'max_token_lifetime_seconds': 300}


def verify_vendor():
    for name, expected in LOCK['files'].items():
        require(hashlib.sha256((ROOT/'vendor/26.8.0'/name).read_bytes()).hexdigest() == expected,
                f'official resource hash mismatch: {name}')


def resource(api, kind, name, namespace, spec=None, **kwargs):
    item = {'apiVersion': api, 'kind': kind, 'metadata': {'name': name}}
    if namespace: item['metadata']['namespace'] = namespace
    if spec is not None: item['spec'] = spec
    return item | kwargs


def peer(namespace, labels=None):
    p = {'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': namespace}}}
    if labels: p['podSelector'] = {'matchLabels': labels}
    return p


def render(s):
    validate(s); verify_vendor()
    result = {'auth.json': auth_config(s)}
    if s['mode'] == 'external': return result
    ns = s['namespace']
    crds = [yaml.safe_load((ROOT/'vendor/26.8.0'/n).read_text()) for n in LOCK['files'] if '-v1.yml' in n]
    operator = list(yaml.safe_load_all((ROOT/'vendor/26.8.0/kubernetes.yml').read_text()))
    for obj in operator:
        if obj['kind'] not in ('ClusterRole', 'ClusterRoleBinding'): obj['metadata']['namespace'] = ns
        for subject in obj.get('subjects', []):
            if subject['kind'] == 'ServiceAccount': subject['namespace'] = ns
        if obj['kind'] == 'Deployment':
            pod = obj['spec']['template']['spec']
            pod['nodeSelector'] = s['platform_node_selector']
            for c in pod['containers']:
                c['image'] = LOCK['operator_image']
                for env in c.get('env', []):
                    if env['name'] in ('kc.operator.keycloak.image', 'RELATED_IMAGE_KEYCLOAK'):
                        env['value'] = LOCK['keycloak_image']
    options = [('db-tls-mode', 'verify-server'), ('db-tls-trust-store-file',
        '/opt/keycloak/conf/truststores/secret-keycloak-trust/rds.pem'),
        ('proxy-trusted-addresses', ','.join(s['proxy_cidrs'])), ('health-enabled', 'true'),
        ('metrics-enabled', 'true'), ('log-console-output', 'json'), ('http-max-queued-requests', '1000'),
        ('cache-stack', 'jdbc-ping'), ('cache-embedded-mtls-enabled', 'true')]
    affinity = {'nodeAffinity': {'requiredDuringSchedulingIgnoredDuringExecution': {'nodeSelectorTerms': [
        {'matchExpressions': [{'key': k, 'operator': 'In', 'values': [v]} for k, v in s['platform_node_selector'].items()] +
         [{'key': 'topology.kubernetes.io/zone', 'operator': 'In', 'values': s['zones']}]}]}},
        'podAntiAffinity': {'requiredDuringSchedulingIgnoredDuringExecution': [
            {'labelSelector': {'matchLabels': SERVER_LABELS}, 'topologyKey': 'kubernetes.io/hostname'}]}}
    spec = {'instances': 3, 'image': LOCK['keycloak_image'], 'startOptimized': False,
        'automountServiceAccountToken': False, 'http': {'httpEnabled': False, 'tlsSecret': 'keycloak-tls'},
        'hostname': {'hostname': s['public_url'], 'admin': s['admin_url'], 'strict': True, 'backchannelDynamic': False},
        'db': {'vendor': 'postgres', 'host': s['database']['host'], 'port': 5432, 'database': s['database']['name'],
               'usernameSecret': {'name': 'keycloak-db', 'key': 'username'},
               'passwordSecret': {'name': 'keycloak-db', 'key': 'password'},
               'poolInitialSize': 20, 'poolMinSize': 20, 'poolMaxSize': 20},
        'proxy': {'headers': 'xforwarded'}, 'ingress': {'enabled': False},
        'bootstrapAdmin': {'user': {'secret': 'keycloak-bootstrap'}},
        'truststores': {'rds': {'secret': {'name': 'keycloak-trust'}}},
        'additionalOptions': [{'name': k, 'value': v} for k, v in options],
        'networkPolicy': {'enabled': False}, 'serviceMonitor': {'enabled': False},
        'resources': {'requests': {'cpu': '2', 'memory': '2Gi'}, 'limits': {'cpu': '4', 'memory': '3Gi'}},
        'scheduling': {'affinity': affinity, 'topologySpreadConstraints': [{'maxSkew': 1, 'minDomains': 3,
            'topologyKey': 'topology.kubernetes.io/zone', 'whenUnsatisfiable': 'DoNotSchedule',
            'labelSelector': {'matchLabels': SERVER_LABELS}}]},
        'import': {'scheduling': {'affinity': {'nodeAffinity': affinity['nodeAffinity']}}},
        'update': {'strategy': 'RecreateOnImageChange', 'scheduling': {'affinity': {'nodeAffinity': affinity['nodeAffinity']}}}}
    server = resource('k8s.keycloak.org/v2beta1', 'Keycloak', 'keycloak', ns, spec)
    placeholders = {key: {'secret': {'name': 'keycloak-smtp', 'key': value}}
                    for key, value in [('SMTP_USERNAME','username'), ('SMTP_PASSWORD','password')]}
    if s['broker']: placeholders['BROKER_SECRET'] = {'secret': {'name': 'keycloak-broker', 'key': 'secret'}}
    initial = resource('k8s.keycloak.org/v2beta1', 'KeycloakRealmImport', 'sandbox-initial-realm', ns,
        {'keycloakCRName': 'keycloak', 'realm': realm.build(s), 'placeholders': placeholders})
    proxy = peer(s['proxy_namespace'], s['proxy_labels'])
    operator_peer = {'podSelector': {'matchLabels': {'app.kubernetes.io/name': 'keycloak-operator'}}}
    server_peer = {'podSelector': {'matchLabels': SERVER_LABELS}}
    def port(value, protocol='TCP'): return {'port': value, 'protocol': protocol}
    policies = [resource('networking.k8s.io/v1', 'NetworkPolicy', 'identity-default-deny', ns,
                        {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress']}),
        resource('networking.k8s.io/v1', 'NetworkPolicy', 'keycloak-ingress', ns,
            {'podSelector': {'matchLabels': SERVER_LABELS}, 'policyTypes': ['Ingress'], 'ingress': [
                {'from': [proxy, operator_peer], 'ports': [port(8443)]},
                {'from': [peer(s['monitoring_namespace']), operator_peer], 'ports': [port(9000)]},
                {'from': [server_peer], 'ports': [port(7800), port(57800)]}]}),
        resource('networking.k8s.io/v1', 'NetworkPolicy', 'identity-dns', ns,
            {'podSelector': {}, 'policyTypes': ['Egress'], 'egress': [
                {'to': [peer('kube-system', {'k8s-app': 'kube-dns'})], 'ports': [port(53), port(53, 'UDP')]}]}),
        resource('networking.k8s.io/v1', 'NetworkPolicy', 'operator-egress', ns,
            {'podSelector': operator_peer['podSelector'], 'policyTypes': ['Egress'], 'egress': [
                {'to': [{'ipBlock': {'cidr': x}} for x in s['apiserver_cidrs']], 'ports': [port(443), port(6443)]},
                {'to': [server_peer], 'ports': [port(8443), port(9000)]}]}),
        # Includes import/update Jobs as they also need the identity DB. Tenant pods cannot enter this namespace.
        resource('cilium.io/v2', 'CiliumNetworkPolicy', 'identity-external-egress', ns,
            {'endpointSelector': {}, 'egress': [
                {'toEndpoints': [{'matchLabels': {'k8s:io.kubernetes.pod.namespace': 'kube-system', 'k8s:k8s-app': 'kube-dns'}}],
                 'toPorts': [{'ports': [{'port': '53', 'protocol': 'ANY'}], 'rules': {'dns': [{'matchPattern': '*'}]}}]},
                {'toFQDNs': [{'matchName': s['database']['host']}], 'toPorts': [{'ports': [{'port': '5432', 'protocol': 'TCP'}]}]},
                {'toFQDNs': [{'matchName': s['smtp']['host']}], 'toPorts': [{'ports': [{'port': '587', 'protocol': 'TCP'}]}]},
                {'toEndpoints': [{'matchLabels': {'k8s:io.kubernetes.pod.namespace': ns, 'k8s:app': 'keycloak'}}],
                 'toPorts': [{'ports': [{'port': str(x), 'protocol': 'TCP'} for x in (7800, 57800)]}]}]})]
    if s['broker']:
        policies[-1]['spec']['egress'].append({'toFQDNs': [{'matchName': h} for h in sorted({urlsplit(s['broker'][x]).hostname
            for x in ('token_url', 'jwks_url')})], 'toPorts': [{'ports': [{'port': '443', 'protocol': 'TCP'}]}]})
    pdb = resource('policy/v1', 'PodDisruptionBudget', 'keycloak', ns,
                   {'minAvailable': 2, 'selector': {'matchLabels': SERVER_LABELS}})
    result.update({'crds.json': {'apiVersion': 'v1', 'kind': 'List', 'items': crds},
        'operator.json': {'apiVersion': 'v1', 'kind': 'List', 'items': operator},
        'namespace.json': resource('v1', 'Namespace', ns, None, metadata={'name': ns, 'labels': {
            'pod-security.kubernetes.io/enforce': 'baseline', 'sandbox.platform/trust': 'identity'}}),
        'network.json': {'apiVersion': 'v1', 'kind': 'List', 'items': policies},
        'keycloak.json': {'apiVersion': 'v1', 'kind': 'List', 'items': [server, pdb]},
        'initial-realm.json': initial, 'machine-client.template.json': realm.machine_client('REPLACE_WITH_DISTINCT_SERVICE_ID')})
    for obj, file in [(server, 'keycloaks.k8s.keycloak.org-v1.yml'), (initial, 'keycloakrealmimports.k8s.keycloak.org-v1.yml')]:
        crd = yaml.safe_load((ROOT/'vendor/26.8.0'/file).read_text())
        schema = next(v for v in crd['spec']['versions'] if v['name'] == 'v2beta1')['schema']['openAPIV3Schema']
        jsonschema.Draft202012Validator(schema).validate(obj)
    from proxy_resources import objects
    result['proxy.json'] = {'apiVersion':'v1','kind':'List','items':objects(s)}
    return result


def private_file(path):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_mode & 0o077 == 0,
            'secret input must be regular non-symlink mode 0600 or 0400')
    data = path.read_bytes()
    require(0 < len(data) <= 128 * 1024, 'secret input missing or too large')
    return data


def kubectl(args, payload=None, capture=True):
    result = subprocess.run(['kubectl', '--request-timeout=30s', *args],
        input=None if payload is None else json.dumps(payload).encode(),
        stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE, check=False, timeout=180)
    # Never print stderr: admission errors may echo Secret request bodies.
    require(result.returncode == 0, 'kubectl command failed (details suppressed to protect credentials)')
    return result.stdout


def validate_secret_material(s):
    """Validate all local inputs before any cluster mutation. Secret bytes never enter artifacts."""
    material = {}
    for name, files in s['secret_files'].items():
        material[name] = {key: private_file(path) for key, path in files.items()}
    db = material['keycloak-db']
    username = db['username'].decode()
    require(re.fullmatch(r'[a-z][a-z0-9_]{1,62}', username) and username not in
            ('postgres', 'sandbox_app', 'sandbox_owner', 'sandbox_worker'), 'dedicated DB role required')
    require(len(db['password']) >= 24, 'strong independent database password required')
    bootstrap = material['keycloak-bootstrap']
    require(len(bootstrap['password']) >= 24 and re.fullmatch(r'[a-z][a-z0-9-]{3,63}', bootstrap['username'].decode())
            and bootstrap['username'].decode() not in ('admin', 'root'), 'one-time bootstrap credential required')
    def openssl(args):
        r = subprocess.run(['openssl', *args], capture_output=True, timeout=10)
        require(r.returncode == 0, 'TLS certificate/key validation failed')
        return r.stdout
    files = s['secret_files']['keycloak-tls']
    for origin in ('public_url', 'admin_url'):
        hostname = urlsplit(s[origin]).hostname
        verdict = openssl(['x509', '-in', files['tls.crt'], '-noout', '-checkhost', hostname])
        # OpenSSL 3.0 exits zero even for a hostname mismatch. Retain its own
        # SAN/wildcard matching rules, but require the exact positive verdict
        # for this origin. This checks local material, not public CA trust.
        require(verdict.strip() == f'Hostname {hostname} does match certificate'.encode(),
                'TLS certificate hostname mismatch or unrecognized verdict')
    openssl(['x509', '-in', files['tls.crt'], '-noout', '-checkend', '604800'])
    cert_public = openssl(['x509', '-in', files['tls.crt'], '-noout', '-pubkey'])
    key_public = openssl(['pkey', '-in', files['tls.key'], '-pubout'])
    require(cert_public == key_public, 'TLS key and certificate differ')
    openssl(['x509', '-in', s['secret_files']['keycloak-trust']['rds.pem'], '-noout', '-checkend', '604800'])
    return material


def apply(settings, initial=False):
    s = validate(settings)
    require(s['mode'] == 'standalone', 'external mode has no cluster install')
    generated = render(s)
    ns = s['namespace']
    material = validate_secret_material(s)
    import ssl
    from ingress import preflight, verify_namespace_roles, verify_endpoints
    ssl.create_default_context(cafile=s['proxy_ca_file'])
    private_file(s['proxy_backend_ca_file'])
    ssl.create_default_context(cafile=s['proxy_backend_ca_file'])
    from proxy_resources import install as install_proxy
    install_proxy(s,material)
    preflight(s)
    # Re-applying an initial realm is deliberately a separate operation. Operator itself never overwrites existing realms.
    kubectl(['apply', '-f', '-'], generated['namespace.json'])
    verify_namespace_roles(s, generated)
    kubectl(['apply', '--server-side', '--field-manager=sandbox-identity', '-f', '-'], generated['crds.json'])
    for name in LOCK['files']:
        if '-v1.yml' in name:
            kubectl(['wait', '--for=condition=Established', 'crd/'+name.replace('-v1.yml',''), '--timeout=120s'])
    # Fail before starting Keycloak if any required credential input is missing.
    secrets = []
    for name, files in s['secret_files'].items():
        data = material[name]
        secrets.append(resource('v1','Secret', name, ns,
            type='kubernetes.io/tls' if name == 'keycloak-tls' else 'Opaque',
            data={key: base64.b64encode(value).decode() for key, value in data.items()}))
    kubectl(['apply', '-f', '-'], generated['network.json'])
    for obj in secrets:
        # Create-only: install/upgrade never silently rotates credentials from stale disk input.
        existing = kubectl(['get','secret',obj['metadata']['name'],'-n',ns,'--ignore-not-found','-o','json'])
        if not existing: kubectl(['create','-f','-'],obj)
        else: require(json.loads(existing).get('data') == obj['data'], 'existing Secret differs; use audited explicit rotation')
    kubectl(['apply','-f','-'],generated['operator.json'])
    kubectl(['rollout','status','deployment/keycloak-operator','-n',ns,'--timeout=120s'])
    kubectl(['apply','--dry-run=server','-f','-'],generated['keycloak.json'])
    kubectl(['apply','-f','-'],generated['keycloak.json'])
    kubectl(['wait','--for=condition=Ready','keycloak/keycloak','-n',ns,'--timeout=120s'])
    if initial:
        from master import bootstrap
        bootstrap(s,material)
        kubectl(['create','-f','-'],generated['initial-realm.json'])
        kubectl(['wait','--for=condition=Done','keycloakrealmimport/sandbox-initial-realm','-n',ns,'--timeout=120s'])
        kubectl(['delete','keycloakrealmimport/sandbox-initial-realm','-n',ns])
    verify_endpoints(s)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['render', 'install'])
    parser.add_argument('--settings', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--initialize-realm', action='store_true')
    args = parser.parse_args()
    s = validate(json.loads(args.settings.read_text()))
    if args.command == 'render':
        require(args.output is not None and not args.output.exists(), 'new --output directory required')
        args.output.mkdir(mode=0o700, parents=True)
        for name, obj in render(s).items():
            (args.output/name).write_text(json.dumps(obj, indent=2)+'\n')
        if s['mode'] == 'standalone':
            from proxy import configuration
            (args.output/'haproxy.cfg').write_text(configuration(s))
        print('Rendered and verified pinned CRD schemas; no deployment or secret read performed.')
    else:
        require(args.execute, 'install requires explicit --execute')
        apply(s, args.initialize_realm)
        print('Keycloak reconciled; complete private admin/MFA, proxy, RDS failover and recovery verification before release.')


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, jsonschema.ValidationError, subprocess.TimeoutExpired) as error:
        print(f'identity: {type(error).__name__}: {error if isinstance(error, ValueError) else "validation or I/O failed"}', file=sys.stderr)
        sys.exit(1)
