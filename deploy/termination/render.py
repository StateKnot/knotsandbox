#!/usr/bin/env python3
"""Offline termination installer: identity/RBAC first, workload activation later."""
import argparse
from collections import Counter
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat

ROOT = Path(__file__).resolve().parent
NS = 'sandbox-system'
NAME = 'sandbox-termination'
LABELS = {'app.kubernetes.io/name': NAME, 'sandbox.platform/network-policy': 'termination-v1'}
TRUST = '/etc/sandbox-termination-trust'
IDENTITY = '/etc/sandbox-termination-identity/client.pem'


def module(name_, path):
    spec = importlib.util.spec_from_file_location(name_, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


public = module('termination_public_inputs', ROOT.parent / 'admission/render.py')
volume = module('termination_project_inputs', ROOT.parent / 'volume-deleter/render.py')
enrollment = module('termination_enrollment_contract', ROOT.parent / 'nodeguard/certification.py')
require, fields, name, fqdn = public.require, public.fields, public.name, public.fqdn
canonical, uuid = public.canonical, volume.uuid


def read_json(path, limit=262144):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid in (0, os.geteuid())
                and not before.st_mode & 0o7022 and 0 < before.st_size <= limit, 'PUBLIC_INPUT_FILE_BOUND_OWNER_MODE')
        with os.fdopen(descriptor, 'rb', closefd=False) as source:
            raw = source.read(limit + 1)
        after = os.fstat(descriptor)
        require(len(raw) <= limit and (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'PUBLIC_INPUT_CHANGED_OR_OVERSIZED')
    finally:
        os.close(descriptor)
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'DUPLICATE_JSON_FIELD')
            value[key] = item
        return value
    def constant(_):
        raise ValueError('NONFINITE_JSON_VALUE')
    def finite(text):
        value = float(text); require(math.isfinite(value), 'NONFINITE_JSON_VALUE')
        return value
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=constant, parse_float=finite), raw
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError('INVALID_PUBLIC_INPUT_JSON') from None


def load(path):
    return read_json(path)[0]


def timestamp(value):
    require(isinstance(value, str) and len(value) <= 40, 'UTC_TIMESTAMP')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(result.tzinfo is not None and result.utcoffset() == timedelta(0), 'UTC_TIMESTAMP')
    return result


def sha(value):
    require(isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value), 'SHA256')


def platform_nodes(nodes, replicas):
    require(isinstance(nodes, list) and 3 <= len(nodes) <= 32, 'BOUNDED_PLATFORM_INVENTORY')
    for node in nodes:
        fields(node, ['hostname', 'zone'], 'PLATFORM_NODE_FIELDS')
        require(isinstance(node['hostname'], str) and len(node['hostname']) <= 63 and all(
            re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in node['hostname'].split('.')), 'PLATFORM_HOSTNAME')
        require(isinstance(node['zone'], str) and len(node['zone']) <= 63 and
                re.fullmatch(r'[a-z]{2}-[a-z0-9-]+[a-z]', node['zone']), 'PLATFORM_ZONE')
    capacities = Counter(n['zone'] for n in nodes)
    require(len(capacities) == 3 and len({n['hostname'] for n in nodes}) == len(nodes), 'THREE_AZ_UNIQUE_PLATFORM_HOSTS')
    target, base = replicas + 1, (replicas + 1) // 3
    require(all(count >= base for count in capacities.values())
            and sum(min(count, base + 1) for count in capacities.values()) >= target, 'THREE_AZ_SURGE_CAPACITY')
    return capacities


def validate(value):
    fields(value, ['schema_version', 'image', 'replicas', 'platform_nodes', 'database', 'nodeguard',
                   'certification_id', 'projects', 'concurrency', 'db_max_connections', 'deployment_identity',
                   'runtime_nodes', 'network_evidence'], 'TERMINATION_INPUT_FIELDS')
    require(type(value['schema_version']) is int and value['schema_version'] == 1, 'SCHEMA_VERSION')
    require(isinstance(value['image'], str) and re.fullmatch(
        r'[a-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9/_-]+@sha256:[a-f0-9]{64}', value['image']), 'IMMUTABLE_REVIEWED_IMAGE')
    require(type(value['replicas']) is int and 2 <= value['replicas'] <= 8, 'HA_REPLICAS_2_TO_8')
    capacities = platform_nodes(value['platform_nodes'], value['replicas'])
    identity = fields(value['deployment_identity'], ['cloud_account_id', 'region', 'deployment', 'environment'], 'DEPLOYMENT_IDENTITY')
    require(isinstance(identity['cloud_account_id'], str) and re.fullmatch(r'[0-9]{16}', identity['cloud_account_id']), 'CLOUD_ACCOUNT_BINDING')
    name(identity['deployment']); name(identity['environment'])
    require(isinstance(identity['region'], str) and re.fullmatch(r'[a-z]{2}-[a-z][a-z0-9-]{1,24}', identity['region'])
            and all(zone.startswith(identity['region'] + '-') for zone in capacities), 'SAME_REGION_PLATFORM_ZONES')
    database = fields(value['database'], ['secret', 'host', 'port', 'ca_pem'], 'DATABASE_FIELDS')
    public.reference(database['secret']); fqdn(database['host']); public.ca_keys(database['ca_pem'])
    require(type(database['port']) is int and database['port'] == 5432, 'POSTGRES_5432')
    guard = fields(value['nodeguard'], ['identity_secret', 'server_ca_pem'], 'NODEGUARD_FIELDS')
    public.reference(guard['identity_secret']); public.ca_keys(guard['server_ca_pem'])
    require(database['secret']['name'] != guard['identity_secret']['name'], 'INDEPENDENT_DATABASE_NODEGUARD_SECRETS')
    require(isinstance(value['certification_id'], str) and 1 <= len(value['certification_id']) <= 128
            and all(33 <= ord(c) <= 126 for c in value['certification_id']), 'REVIEWED_CERTIFICATION_REFERENCE')
    require(type(value['concurrency']) is int and 1 <= value['concurrency'] <= 16, 'CONCURRENCY_1_TO_16')
    require(type(value['db_max_connections']) is int and value['concurrency'] + 4 <= value['db_max_connections'] <= 64, 'BOUNDED_DATABASE_CAPACITY')
    projects = value['projects']
    require(isinstance(projects, list) and 1 <= len(projects) <= 128, 'REGISTERED_PROJECT_BOUND')
    for project in projects:
        fields(project, ['tenant_id', 'project_id', 'namespace'], 'PROJECT_REGISTRATION_FIELDS')
        uuid(project['tenant_id']); uuid(project['project_id']); name(project['namespace'])
        require(project['namespace'] not in {'default', NS} and not project['namespace'].startswith(('kube-', 'sandbox-')), 'NO_CONTROL_NAMESPACE_ROLE')
    require(len({p['namespace'] for p in projects}) == len(projects) and len({p['project_id'] for p in projects}) == len(projects), 'UNIQUE_PROJECT_NAMESPACE_BINDINGS')
    nodes = value['runtime_nodes']
    require(isinstance(nodes, list) and 1 <= len(nodes) <= 32, 'REGISTERED_RUNTIME_NODE_BOUND')
    for node in nodes:
        fields(node, ['node', 'cloud_instance_id', 'private_ip', 'guard_port', 'zone', 'runtime_node_id', 'enrollment_id'], 'REGISTERED_NODE_FIELDS')
        enrollment.node_identity(node['node']); uuid(node['runtime_node_id']); uuid(node['enrollment_id'])
        require(isinstance(node['node']['node_name'], str) and len(node['node']['node_name']) <= 63, 'NODE_HOSTNAME_LABEL_BOUND')
        require(node['zone'] in capacities, 'SAME_DEPLOYMENT_NODE_ZONE')
        require(isinstance(node['cloud_instance_id'], str) and re.fullmatch(r'i-[A-Za-z0-9]+', node['cloud_instance_id']), 'OBSERVED_ECS_ID')
        address = ipaddress.ip_address(node['private_ip'])
        require(address.version == 4 and str(address) == node['private_ip'] and enrollment.private_address(node['private_ip']), 'CANONICAL_PRIVATE_NODE_IPV4')
        require(type(node['guard_port']) is int and node['guard_port'] == 9444, 'NODEGUARD_9444')
    for field in ['runtime_node_id', 'enrollment_id', 'cloud_instance_id', 'private_ip']:
        require(len({n[field] for n in nodes}) == len(nodes), 'UNIQUE_NODE_' + field)
    for field in ['node_name', 'node_uid', 'boot_id']:
        require(len({n['node'][field] for n in nodes}) == len(nodes), 'UNIQUE_NODE_' + field)
    require(len({n['node']['cluster_epoch'] for n in nodes}) == 1 and
            not {n['node']['node_name'] for n in nodes} & {n['hostname'] for n in value['platform_nodes']}, 'EXACT_DISTINCT_RUNTIME_EPOCH_POOL')
    evidence = fields(value['network_evidence'], ['observed_at', 'expires_at', 'cilium_config', 'observation_sha256',
        'terraform_output_sha256', 'enrollments_sha256'], 'CURRENT_NETWORK_EVIDENCE_FIELDS')
    observed, expires, now = timestamp(evidence['observed_at']), timestamp(evidence['expires_at']), datetime.now(timezone.utc)
    require(observed <= now < expires <= observed + timedelta(minutes=15), 'CURRENT_NETWORK_OBSERVATION_REQUIRED')
    for field in ['observation_sha256', 'terraform_output_sha256', 'enrollments_sha256']:
        sha(evidence[field])
    config = fields(evidence['cilium_config'], ['enable-policy', 'enable-node-selector-labels', 'policy-default-local-cluster', 'cluster-name'], 'EXACT_CILIUM_NODE_POLICY_CONFIG')
    require(config['enable-policy'] == 'always' and config['enable-node-selector-labels'] == 'true'
            and config['policy-default-local-cluster'] == 'true', 'CILIUM_NODE_SELECTORS_REQUIRED')
    name(config['cluster-name'])
    return copy.deepcopy(value)


def identities(inputs):
    value = validate(inputs)
    role = NAME + '-observe'
    subject = [{'kind': 'ServiceAccount', 'name': NAME, 'namespace': NS}]
    objects = [
        {'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': {'name': NAME, 'namespace': NS}, 'automountServiceAccountToken': False},
        {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRole', 'metadata': {'name': role}, 'rules': [
            {'apiGroups': [''], 'resources': ['pods'], 'verbs': ['list']},
            {'apiGroups': [''], 'resources': ['namespaces'], 'resourceNames': sorted(p['namespace'] for p in value['projects']), 'verbs': ['get']},
            {'apiGroups': [''], 'resources': ['nodes'], 'resourceNames': sorted(n['node']['node_name'] for n in value['runtime_nodes']), 'verbs': ['get']},
            {'apiGroups': [''], 'resources': ['persistentvolumes'], 'verbs': ['get']},
            {'apiGroups': ['node.k8s.io'], 'resources': ['runtimeclasses'], 'resourceNames': ['kata-qemu'], 'verbs': ['get']},
            {'apiGroups': ['storage.k8s.io'], 'resources': ['volumeattachments'], 'verbs': ['list']}]},
        {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRoleBinding', 'metadata': {'name': role},
            'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': role}, 'subjects': subject}]
    for project in value['projects']:
        meta = {'name': NAME, 'namespace': project['namespace'], 'annotations': {
            'sandbox.platform/tenant-id': project['tenant_id'], 'sandbox.platform/project-id': project['project_id']}}
        objects += [
            {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role', 'metadata': meta, 'rules': [
                {'apiGroups': [''], 'resources': ['pods'], 'verbs': ['get', 'delete', 'patch']},
                {'apiGroups': [''], 'resources': ['persistentvolumeclaims'], 'verbs': ['get']},
                {'apiGroups': ['networking.k8s.io'], 'resources': ['networkpolicies'], 'resourceNames': ['sandbox-default-deny'], 'verbs': ['get']},
                {'apiGroups': ['cilium.io'], 'resources': ['ciliumnetworkpolicies'], 'verbs': ['get']}]},
            {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding', 'metadata': copy.deepcopy(meta),
                'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': NAME}, 'subjects': copy.deepcopy(subject)}]
    return {'apiVersion': 'v1', 'kind': 'List', 'items': objects}


def workload(inputs):
    value = validate(inputs)
    labels = dict(LABELS)
    metadata = lambda resource: {'name': resource, 'namespace': NS}
    config_hash = hashlib.sha256(canonical(value).encode()).hexdigest()
    trust = NAME + '-ca-' + hashlib.sha256(canonical({'db': value['database']['ca_pem'], 'nodeguard': value['nodeguard']['server_ca_pem']}).encode()).hexdigest()[:16]
    port = lambda number: {'port': str(number), 'protocol': 'TCP'}
    env = {'SANDBOX_DB_MAX_CONNECTIONS': str(value['db_max_connections']), 'SANDBOX_TERMINATION_CONCURRENCY': str(value['concurrency']),
        'SANDBOX_NODEGUARD_SERVER_CA_FILE': TRUST + '/nodeguard-server-ca.pem', 'SANDBOX_NODEGUARD_CLIENT_IDENTITY_FILE': IDENTITY,
        'SANDBOX_DEPLOYMENT_CERTIFICATION_ID': value['certification_id'], 'SANDBOX_DNS_NAMESPACE': 'kube-system',
        'SANDBOX_DNS_LABEL': 'k8s-app=kube-dns', 'SANDBOX_ALLOW_LOOPBACK_HTTP': 'false'}
    pod = {'serviceAccountName': NAME, 'automountServiceAccountToken': False, 'terminationGracePeriodSeconds': 50,
        'nodeSelector': {'sandbox.platform/node-pool': 'platform'}, 'dnsPolicy': 'ClusterFirst', 'dnsConfig': {'options': [{'name': 'ndots', 'value': '1'}]},
        'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001, 'runAsGroup': 10001, 'fsGroup': 10001,
            'fsGroupChangePolicy': 'OnRootMismatch', 'seccompProfile': {'type': 'RuntimeDefault'}},
        'affinity': {'nodeAffinity': {'requiredDuringSchedulingIgnoredDuringExecution': {'nodeSelectorTerms': [
            {'matchExpressions': [{'key': 'kubernetes.io/hostname', 'operator': 'In', 'values': sorted(n['hostname'] for n in value['platform_nodes'])},
                {'key': 'topology.kubernetes.io/zone', 'operator': 'In', 'values': sorted({n['zone'] for n in value['platform_nodes']})}]}]}},
            'podAntiAffinity': {'requiredDuringSchedulingIgnoredDuringExecution': [{'topologyKey': 'kubernetes.io/hostname', 'labelSelector': {'matchLabels': labels}}]}},
        'topologySpreadConstraints': [{'maxSkew': 1, 'topologyKey': key, 'whenUnsatisfiable': 'DoNotSchedule',
            'labelSelector': {'matchLabels': labels}, **({'minDomains': 3} if key.endswith('/zone') else {})}
            for key in ['topology.kubernetes.io/zone', 'kubernetes.io/hostname']],
        'volumes': [
            {'name': 'trust', 'configMap': {'name': trust, 'defaultMode': 0o440}},
            {'name': 'nodeguard-identity', 'secret': {'secretName': value['nodeguard']['identity_secret']['name'], 'defaultMode': 0o440,
                'items': [{'key': value['nodeguard']['identity_secret']['key'], 'path': 'client.pem'}]}},
            {'name': 'kube-api', 'projected': {'defaultMode': 0o440, 'sources': [
                {'serviceAccountToken': {'path': 'token', 'expirationSeconds': 3600}},
                {'configMap': {'name': 'kube-root-ca.crt', 'items': [{'key': 'ca.crt', 'path': 'ca.crt'}]}},
                {'downwardAPI': {'items': [{'path': 'namespace', 'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.namespace'}}]}}]}}],
        'containers': [{'name': 'controller', 'image': value['image'], 'imagePullPolicy': 'IfNotPresent',
            'command': ['/usr/local/bin/sandboxd'], 'args': ['--role', 'termination'],
            'env': [{'name': 'SANDBOX_DATABASE_URL', 'valueFrom': {'secretKeyRef': value['database']['secret']}}, {'name': 'SANDBOX_PROCESS_POD_UID', 'valueFrom': {'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.uid'}}}]
                + [{'name': key, 'value': val} for key, val in env.items()],
            'securityContext': {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}},
            'resources': {'requests': {'cpu': '250m', 'memory': '256Mi'}, 'limits': {'cpu': '1', 'memory': '512Mi'}},
            'volumeMounts': [{'name': volume, 'mountPath': path, 'readOnly': True} for volume, path in [
                ('trust', TRUST), ('nodeguard-identity', '/etc/sandbox-termination-identity'), ('kube-api', '/var/run/secrets/kubernetes.io/serviceaccount')]]}]}
    node_selectors = [{'matchLabels': {
        'node:kubernetes.io/hostname': node['node']['node_name'], 'node:sandbox.platform/node-pool': 'kata',
        'node:topology.kubernetes.io/zone': node['zone'],
        'k8s:io.cilium.k8s.policy.cluster': value['network_evidence']['cilium_config']['cluster-name']}}
        for node in sorted(value['runtime_nodes'], key=lambda n: n['node']['node_name'])]
    objects = [
        {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': metadata(trust), 'immutable': True,
            'data': {'db-ca.pem': value['database']['ca_pem'], 'nodeguard-server-ca.pem': value['nodeguard']['server_ca_pem']}},
        {'apiVersion': 'cilium.io/v2', 'kind': 'CiliumNetworkPolicy', 'metadata': metadata(NAME), 'spec': {
            'endpointSelector': {'matchLabels': {'k8s:' + key: val for key, val in labels.items()}},
            'enableDefaultDeny': {'ingress': True, 'egress': True}, 'ingress': [], 'egress': [
                {'toEndpoints': [{'matchLabels': {'k8s:io.kubernetes.pod.namespace': 'kube-system', 'k8s:k8s-app': 'kube-dns'}}],
                    'toPorts': [{'ports': [{'port': '53', 'protocol': 'ANY'}], 'rules': {'dns': [{'matchName': value['database']['host']}]}}]},
                {'toFQDNs': [{'matchName': value['database']['host']}], 'toPorts': [{'ports': [port(5432)]}]},
                {'toEntities': ['kube-apiserver'], 'toPorts': [{'ports': [port(443), port(6443)]}]},
                {'toNodes': node_selectors, 'toPorts': [{'ports': [port(9444)]}]}]}},
        {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': metadata(NAME), 'spec': {
            'replicas': value['replicas'], 'revisionHistoryLimit': 3, 'minReadySeconds': 10, 'progressDeadlineSeconds': 180,
            'strategy': {'type': 'RollingUpdate', 'rollingUpdate': {'maxUnavailable': 0, 'maxSurge': 1}},
            'selector': {'matchLabels': labels}, 'template': {'metadata': {'labels': labels,
                'annotations': {'sandbox.platform/installer-input-sha256': config_hash,
                    'sandbox.platform/network-observation-sha256': value['network_evidence']['observation_sha256']}}, 'spec': pod}}},
        {'apiVersion': 'policy/v1', 'kind': 'PodDisruptionBudget', 'metadata': metadata(NAME),
            'spec': {'minAvailable': value['replicas'] - 1, 'selector': {'matchLabels': labels}}}]
    return {'apiVersion': 'v1', 'kind': 'List', 'items': objects}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--identity-out', type=Path, required=True)
    parser.add_argument('--workload-out', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(len({args.input.resolve(), args.identity_out.resolve(), args.workload_out.resolve()}) == 3, 'SEPARATE_CREATE_ONLY_OUTPUTS')
        value = validate(load(args.input))
        documents = [identities(value), workload(value)]
        require(not args.identity_out.exists() and not args.workload_out.exists(), 'CREATE_ONLY_OUTPUTS')
        for path, document in zip([args.identity_out, args.workload_out], documents):
            with path.open('x') as output:
                output.write(canonical(document) + '\n')
    except (ValueError, TypeError, KeyError, OSError):
        parser.exit(1, 'TERMINATION_INSTALLER_REJECTED\n')


if __name__ == '__main__':
    main()
