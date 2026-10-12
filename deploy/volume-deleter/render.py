#!/usr/bin/env python3
"""Render an isolated volume controller; identity and activation are separate."""
import argparse
from collections import Counter
import copy
import hashlib
import importlib.util
from pathlib import Path
import re
from urllib.parse import urlsplit
from uuid import UUID

ROOT = Path(__file__).resolve().parent
NS = 'sandbox-system'
NAME = 'sandbox-volume-deleter'
LABELS = {'app.kubernetes.io/name': NAME, 'sandbox.platform/network-policy': 'volume-deleter-v1'}
DB_CA = '/etc/sandbox-db/ca.crt'
CONFIG = '/etc/sandbox-volume/config.json'

# The admission installer already owns the strict public-input/file/CA rules.
# Reuse those rules without importing its workload or activation settings.
spec = importlib.util.spec_from_file_location('volume_public_inputs', ROOT.parent / 'admission/render.py')
public = importlib.util.module_from_spec(spec)
spec.loader.exec_module(public)
require, fields, name, fqdn = public.require, public.fields, public.name, public.fqdn
canonical, load = public.canonical, public.load


def uuid(value):
    require(isinstance(value, str), 'CANONICAL_NON_NIL_UUID')
    try:
        parsed = UUID(value)
    except ValueError:
        raise ValueError('CANONICAL_NON_NIL_UUID') from None
    require(parsed.int != 0 and str(parsed) == value, 'CANONICAL_NON_NIL_UUID')
    return value


def validate(value):
    fields(value, ['schema_version', 'image', 'replicas', 'platform_nodes', 'database',
                   'configuration', 'projects', 'db_max_connections'], 'VOLUME_INPUT_FIELDS')
    require(type(value['schema_version']) is int and value['schema_version'] == 1, 'SCHEMA_VERSION')
    require(isinstance(value['image'], str) and re.fullmatch(
        r'[a-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9/_-]+@sha256:[a-f0-9]{64}', value['image']), 'IMMUTABLE_REVIEWED_IMAGE')
    require(type(value['replicas']) is int and 2 <= value['replicas'] <= 8, 'HA_REPLICAS_2_TO_8')
    nodes = value['platform_nodes']
    require(isinstance(nodes, list) and 3 <= len(nodes) <= 32, 'BOUNDED_PLATFORM_INVENTORY')
    for node in nodes:
        fields(node, ['hostname', 'zone'], 'PLATFORM_NODE_FIELDS')
        require(isinstance(node['hostname'], str) and len(node['hostname']) <= 63 and all(
            re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
            for part in node['hostname'].split('.')), 'PLATFORM_HOSTNAME')
        require(isinstance(node['zone'], str) and len(node['zone']) <= 63 and
                re.fullmatch(r'[a-z]{2}-[a-z0-9-]+[a-z]', node['zone']), 'PLATFORM_ZONE')
    capacities = Counter(node['zone'] for node in nodes)
    require(len(capacities) == 3 and len({node['hostname'] for node in nodes}) == len(nodes), 'THREE_AZ_UNIQUE_PLATFORM_HOSTS')
    target, base = value['replicas'] + 1, (value['replicas'] + 1) // 3
    require(all(count >= base for count in capacities.values()) and
            sum(min(count, base + 1) for count in capacities.values()) >= target, 'THREE_AZ_SURGE_CAPACITY')
    database = fields(value['database'], ['secret', 'host', 'port', 'ca_pem'], 'DATABASE_FIELDS')
    public.reference(database['secret']); fqdn(database['host']); public.ca_keys(database['ca_pem'])
    require(type(database['port']) is int and database['port'] == 5432, 'POSTGRES_5432')
    configuration = fields(value['configuration'], ['cloud', 'storage', 'concurrency'], 'CONTROLLER_CONFIG_FIELDS')
    cloud = fields(configuration['cloud'], ['account_id', 'region', 'role_arn', 'role_id', 'oidc_provider_arn',
        'oidc_issuer', 'oidc_audience', 'oidc_subject', 'oidc_token_file', 'deployment',
        'requests_per_second', 'max_in_flight'], 'CLOUD_IDENTITY_FIELDS')
    require(isinstance(cloud['account_id'], str) and re.fullmatch(r'[0-9]{16}', cloud['account_id']), 'CLOUD_ACCOUNT')
    require(isinstance(cloud['region'], str) and re.fullmatch(r'[a-z]{2}-[a-z][a-z0-9-]{1,24}', cloud['region']), 'CLOUD_REGION')
    name(cloud['deployment'])
    require(cloud['role_arn'] == 'acs:ram::' + cloud['account_id'] + ':role/' + cloud['deployment'] + '-volume-deleter', 'EXACT_VOLUME_ROLE')
    require(isinstance(cloud['role_id'], str) and re.fullmatch(r'[0-9]{1,32}', cloud['role_id']), 'OBSERVED_ROLE_ID')
    require(cloud['oidc_provider_arn'] == 'acs:ram::' + cloud['account_id'] + ':oidc-provider/' + cloud['deployment'] + '-kubernetes', 'EXACT_OIDC_PROVIDER')
    require(isinstance(cloud['oidc_issuer'], str) and len(cloud['oidc_issuer']) <= 2048, 'WORKLOAD_ISSUER')
    issuer = urlsplit(cloud['oidc_issuer'])
    require(issuer.scheme == 'https' and issuer.hostname and not issuer.username and not issuer.password
            and issuer.port is None and not issuer.query and not issuer.fragment
            and re.fullmatch(r'[/A-Za-z0-9_.-]*', issuer.path)
            and '..' not in issuer.path.split('/')
            and cloud['oidc_issuer'] == 'https://' + issuer.hostname + issuer.path, 'CANONICAL_WORKLOAD_ISSUER')
    fqdn(issuer.hostname)
    require(cloud['oidc_audience'] == 'sts.aliyuncs.com' and
            cloud['oidc_subject'] == 'system:serviceaccount:' + NS + ':' + NAME and
            cloud['oidc_token_file'] == '/var/run/sandbox-cloud/token', 'EXACT_PROJECTED_WORKLOAD_IDENTITY')
    for key, high in [('requests_per_second', 20), ('max_in_flight', 16)]:
        require(type(cloud[key]) is int and 1 <= cloud[key] <= high, 'BOUNDED_CLOUD_' + key)
    require(type(configuration['concurrency']) is int and 1 <= configuration['concurrency'] <= 16, 'CONTROLLER_CONCURRENCY')
    require(type(value['db_max_connections']) is int and
            configuration['concurrency'] + 2 <= value['db_max_connections'] <= 64, 'BOUNDED_DATABASE_CAPACITY')
    storage = fields(configuration['storage'], ['storage_class', 'kms_key_id', 'zones', 'deployment', 'certification_id'], 'STORAGE_PROFILE_FIELDS')
    name(storage['storage_class'])
    require(storage['deployment'] == cloud['deployment'], 'SAME_CLOUD_STORAGE_DEPLOYMENT')
    for key in ['kms_key_id', 'certification_id']:
        require(isinstance(storage[key], str) and 1 <= len(storage[key]) <= 128
                and all(33 <= ord(char) <= 126 for char in storage[key]), 'REVIEWED_STORAGE_' + key)
    require(isinstance(storage['zones'], list) and len(storage['zones']) == 3 and
            set(storage['zones']) == set(capacities) and
            all(zone.startswith(cloud['region'] + '-') for zone in storage['zones']), 'REVIEWED_SAME_REGION_STORAGE_ZONES')
    projects = value['projects']
    require(isinstance(projects, list) and 1 <= len(projects) <= 128, 'REGISTERED_PROJECT_BOUND')
    for project in projects:
        fields(project, ['tenant_id', 'project_id', 'namespace'], 'PROJECT_REGISTRATION_FIELDS')
        uuid(project['tenant_id']); uuid(project['project_id']); name(project['namespace'])
        require(project['namespace'] not in {'default', NS} and
                not project['namespace'].startswith(('kube-', 'sandbox-')), 'NO_CONTROL_NAMESPACE_ROLE')
    require(len({p['namespace'] for p in projects}) == len(projects) and
            len({p['project_id'] for p in projects}) == len(projects), 'UNIQUE_PROJECT_NAMESPACE_BINDINGS')
    return copy.deepcopy(value)


def identities(inputs):
    value = validate(inputs)
    metadata = lambda resource: {'name': resource, 'namespace': NS}
    role_name = NAME + '-observe'
    subject = [{'kind': 'ServiceAccount', 'name': NAME, 'namespace': NS}]
    objects = [
        {'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': metadata(NAME), 'automountServiceAccountToken': False},
        {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRole', 'metadata': {'name': role_name}, 'rules': [
            {'apiGroups': [''], 'resources': ['namespaces'],
                'resourceNames': sorted(project['namespace'] for project in value['projects']), 'verbs': ['get']},
            {'apiGroups': [''], 'resources': ['persistentvolumes'], 'verbs': ['get', 'delete']},
            {'apiGroups': ['storage.k8s.io'], 'resources': ['storageclasses'], 'resourceNames': [value['configuration']['storage']['storage_class']], 'verbs': ['get']},
            {'apiGroups': ['storage.k8s.io'], 'resources': ['volumeattachments'], 'verbs': ['list']}]},
        {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRoleBinding', 'metadata': {'name': role_name},
            'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': role_name}, 'subjects': subject}]
    for project in value['projects']:
        meta = {'name': NAME, 'namespace': project['namespace'], 'annotations': {
            'sandbox.platform/tenant-id': project['tenant_id'], 'sandbox.platform/project-id': project['project_id']}}
        objects += [
            {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role', 'metadata': meta, 'rules': [
                {'apiGroups': [''], 'resources': ['persistentvolumeclaims'], 'verbs': ['get', 'delete']},
                {'apiGroups': [''], 'resources': ['pods'], 'verbs': ['list']}]},
            {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding', 'metadata': copy.deepcopy(meta),
                'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': NAME}, 'subjects': copy.deepcopy(subject)}]
    return {'apiVersion': 'v1', 'kind': 'List', 'items': objects}


def workload(inputs):
    value = validate(inputs)
    cloud = value['configuration']['cloud']
    metadata = lambda resource: {'name': resource, 'namespace': NS}
    config_text = canonical(value['configuration'])
    config_hash = hashlib.sha256(config_text.encode()).hexdigest()
    config_name = NAME + '-cfg-' + config_hash[:16]
    trust_name = NAME + '-ca-' + hashlib.sha256(value['database']['ca_pem'].encode()).hexdigest()[:16]
    port = lambda number: {'port': str(number), 'protocol': 'TCP'}
    dependencies = [(value['database']['host'], 5432), ('sts.' + cloud['region'] + '.aliyuncs.com', 443),
                    ('ecs.' + cloud['region'] + '.aliyuncs.com', 443)]
    pod = {'serviceAccountName': NAME, 'automountServiceAccountToken': False, 'terminationGracePeriodSeconds': 40,
        'nodeSelector': {'sandbox.platform/node-pool': 'platform'},
        'dnsConfig': {'options': [{'name': 'ndots', 'value': '1'}]},
        'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001, 'runAsGroup': 10001,
            'fsGroup': 10001, 'fsGroupChangePolicy': 'OnRootMismatch', 'seccompProfile': {'type': 'RuntimeDefault'}},
        'affinity': {'nodeAffinity': {'requiredDuringSchedulingIgnoredDuringExecution': {'nodeSelectorTerms': [
            {'matchExpressions': [{'key': 'kubernetes.io/hostname', 'operator': 'In', 'values': sorted(n['hostname'] for n in value['platform_nodes'])},
                {'key': 'topology.kubernetes.io/zone', 'operator': 'In', 'values': sorted(value['configuration']['storage']['zones'])}]}]}},
            'podAntiAffinity': {'requiredDuringSchedulingIgnoredDuringExecution': [
                {'topologyKey': 'kubernetes.io/hostname', 'labelSelector': {'matchLabels': LABELS}}]}},
        'topologySpreadConstraints': [{'maxSkew': 1, 'minDomains': 3, 'topologyKey': 'topology.kubernetes.io/zone',
            'whenUnsatisfiable': 'DoNotSchedule', 'labelSelector': {'matchLabels': LABELS}}],
        'volumes': [
            {'name': 'config', 'configMap': {'name': config_name, 'defaultMode': 0o440}},
            {'name': 'db-ca', 'configMap': {'name': trust_name, 'defaultMode': 0o440}},
            {'name': 'cloud-identity', 'projected': {'defaultMode': 0o440, 'sources': [
                {'serviceAccountToken': {'path': 'token', 'audience': cloud['oidc_audience'], 'expirationSeconds': 600}}]}},
            {'name': 'kube-api', 'projected': {'defaultMode': 0o440, 'sources': [
                {'serviceAccountToken': {'path': 'token', 'expirationSeconds': 3600}},
                {'configMap': {'name': 'kube-root-ca.crt', 'items': [{'key': 'ca.crt', 'path': 'ca.crt'}]}},
                {'downwardAPI': {'items': [{'path': 'namespace', 'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.namespace'}}]}}]}}],
        'containers': [{'name': 'controller', 'image': value['image'], 'imagePullPolicy': 'IfNotPresent',
            'command': ['/usr/local/bin/sandboxd'], 'args': ['--role', 'volume-deleter'],
            'env': [{'name': 'SANDBOX_DATABASE_URL', 'valueFrom': {'secretKeyRef': value['database']['secret']}},
                {'name': 'SANDBOX_PROCESS_POD_UID', 'valueFrom': {'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.uid'}}},
                {'name': 'SANDBOX_DB_MAX_CONNECTIONS', 'value': str(value['db_max_connections'])},
                {'name': 'SANDBOX_VOLUME_DELETION_CONFIG_FILE', 'value': CONFIG},
                {'name': 'SANDBOX_ALLOW_LOOPBACK_HTTP', 'value': 'false'}],
            'securityContext': {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}},
            'resources': {'requests': {'cpu': '100m', 'memory': '128Mi'}, 'limits': {'cpu': '1', 'memory': '512Mi'}},
            'volumeMounts': [{'name': volume, 'mountPath': path, 'readOnly': True} for volume, path in [
                ('config', '/etc/sandbox-volume'), ('db-ca', '/etc/sandbox-db'), ('cloud-identity', '/var/run/sandbox-cloud'),
                ('kube-api', '/var/run/secrets/kubernetes.io/serviceaccount')]]}]}
    objects = [
        {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': metadata(config_name), 'immutable': True, 'data': {'config.json': config_text}},
        {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': metadata(trust_name), 'immutable': True, 'data': {'ca.crt': value['database']['ca_pem']}},
        {'apiVersion': 'cilium.io/v2', 'kind': 'CiliumNetworkPolicy', 'metadata': metadata(NAME), 'spec': {
            'endpointSelector': {'matchLabels': {'k8s:' + k: v for k, v in LABELS.items()}},
            'enableDefaultDeny': {'ingress': True, 'egress': True}, 'ingress': [],
            'egress': [{'toEndpoints': [{'matchLabels': {'k8s:io.kubernetes.pod.namespace': 'kube-system', 'k8s:k8s-app': 'kube-dns'}}],
                'toPorts': [{'ports': [{'port': '53', 'protocol': 'ANY'}], 'rules': {'dns': [{'matchName': host} for host, _ in sorted(dependencies)]}}]}]
                + [{'toFQDNs': [{'matchName': host}], 'toPorts': [{'ports': [port(number)]}]} for host, number in sorted(dependencies)]
                + [{'toEntities': ['kube-apiserver'], 'toPorts': [{'ports': [port(443), port(6443)]}]}]}},
        {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': metadata(NAME), 'spec': {
            'replicas': value['replicas'], 'revisionHistoryLimit': 3, 'progressDeadlineSeconds': 180, 'minReadySeconds': 10,
            'strategy': {'type': 'RollingUpdate', 'rollingUpdate': {'maxUnavailable': 0, 'maxSurge': 1}},
            'selector': {'matchLabels': LABELS}, 'template': {'metadata': {'labels': LABELS,
                'annotations': {'sandbox.platform/config-sha256': config_hash}}, 'spec': pod}}},
        {'apiVersion': 'policy/v1', 'kind': 'PodDisruptionBudget', 'metadata': metadata(NAME),
            'spec': {'minAvailable': value['replicas'] - 1, 'selector': {'matchLabels': LABELS}}}]
    return {'apiVersion': 'v1', 'kind': 'List', 'items': objects}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--identity-out', type=Path, required=True)
    parser.add_argument('--workload-out', type=Path, required=True)
    args = parser.parse_args()
    try:
        value = validate(load(args.input))
        require(args.identity_out.resolve() != args.workload_out.resolve(), 'SEPARATE_ACTIVATION_OUTPUTS')
        identity, activation = canonical(identities(value)), canonical(workload(value))
        # Refuse either existing revision before creating any output.
        require(not args.identity_out.exists() and not args.workload_out.exists(), 'CREATE_ONLY_OUTPUTS')
        with args.identity_out.open('x') as target:
            target.write(identity + '\n')
        with args.workload_out.open('x') as target:
            target.write(activation + '\n')
    except (ValueError, TypeError, KeyError, OSError):
        parser.exit(1, 'VOLUME_INSTALLER_REJECTED\n')


if __name__ == '__main__':
    main()
