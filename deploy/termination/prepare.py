#!/usr/bin/env python3
"""Bind termination inputs to Terraform, enabled enrollments and current readback."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path

from render import canonical, enrollment, fields, load, name, read_json, require, sha, timestamp, uuid, validate

OUTPUTS = {'vpc_id', 'deployment_identity', 'subnets', 'node_inventory', 'private_entrances', 'database',
           'object_storage', 'workload_roles', 'workload_oidc_provider_arn', 'workspace_kms_key_id'}
SETTINGS = {'schema_version', 'image', 'replicas', 'database', 'nodeguard', 'certification_id',
            'projects', 'concurrency', 'db_max_connections'}
RECEIPT = {'protocol', 'enrollment_id', 'runtime_node_id', 'node', 'cloud_account_id', 'region',
           'cloud_instance_id', 'private_ip', 'guard_port', 'certification_id', 'certification_report_sha256',
           'artifact_sha256', 'terraform_output_sha256', 'registered_at', 'changed', 'enabled'}
CONFIG = {'enable-policy', 'enable-node-selector-labels', 'policy-default-local-cluster', 'cluster-name'}


def prepare(settings, outputs, receipts, observation, *, terraform_raw, enrollments_raw, observation_raw):
    fields(settings, SETTINGS, 'TERMINATION_SETTINGS_FIELDS')
    fields(outputs, OUTPUTS, 'TERRAFORM_OUTPUT_FIELDS')
    wrapped = [isinstance(value, dict) and 'value' in value for value in outputs.values()]
    if any(wrapped):
        require(all(wrapped), 'NO_MIXED_TERRAFORM_OUTPUT_SHAPE')
        for item in outputs.values():
            fields(item, ['value', 'sensitive', 'type'], 'PUBLIC_TERRAFORM_WRAPPER_FIELDS')
            require(item['sensitive'] is False, 'PUBLIC_TERRAFORM_OUTPUTS_REQUIRED')
        outputs = {key: value['value'] for key, value in outputs.items()}
    identity = fields(outputs['deployment_identity'], ['cloud_account_id', 'region', 'deployment', 'environment'], 'DEPLOYMENT_IDENTITY')
    database = fields(outputs['database'], ['id', 'endpoint', 'port', 'engine', 'major_version'], 'RDS_OUTPUT_FIELDS')
    require(database['engine'] == 'PostgreSQL' and type(database['major_version']) is int and database['major_version'] == 17
            and type(database['port']) is int and database['port'] == 5432, 'RDS_POSTGRES_17_IDENTITY')
    fields(settings['database'], ['secret', 'ca_pem'], 'DATABASE_SETTINGS_NO_HOST_URL_OVERRIDES')
    require(isinstance(outputs['node_inventory'], dict) and 1 <= len(outputs['node_inventory']) <= 128, 'BOUNDED_OBSERVED_NODE_INVENTORY')
    platform, kata, ids, addresses = [], {}, set(), set()
    for hostname, node in outputs['node_inventory'].items():
        fields(node, ['id', 'private_ip', 'role', 'zone'], 'TERRAFORM_NODE_FIELDS')
        require(isinstance(node['id'], str) and node['id'] not in ids and isinstance(node['private_ip'], str)
                and node['private_ip'] not in addresses and enrollment.private_address(node['private_ip']), 'UNIQUE_PRIVATE_OBSERVED_NODE_ID_IP')
        ids.add(node['id']); addresses.add(node['private_ip'])
        require(node['role'] in {'control', 'platform', 'kata'}, 'NODE_ROLE')
        if node['role'] == 'platform':
            platform.append({'hostname': hostname, 'zone': node['zone']})
        if node['role'] == 'kata':
            kata[hostname] = node
    require(isinstance(receipts, list) and 1 <= len(receipts) <= 32, 'ENABLED_ENROLLMENT_RECEIPT_BOUND')
    nodes = []
    for receipt in receipts:
        fields(receipt, RECEIPT, 'REAL_ENROLLMENT_RECEIPT_FIELDS')
        require(type(receipt['protocol']) is int and receipt['protocol'] == 1 and receipt['enabled'] is True
                and type(receipt['changed']) is bool, 'ENABLED_ENROLLMENT_REQUIRED')
        enrollment.node_identity(receipt['node'])
        node = kata.get(receipt['node']['node_name'])
        require(node is not None and receipt['cloud_instance_id'] == node['id']
                and receipt['private_ip'] == node['private_ip'], 'EXACT_TERRAFORM_KATA_ENROLLMENT')
        require(receipt['cloud_account_id'] == identity['cloud_account_id'] and receipt['region'] == identity['region']
                and receipt['certification_id'] == settings['certification_id'], 'EXACT_DEPLOYMENT_ENROLLMENT')
        require(receipt['terraform_output_sha256'] == hashlib.sha256(terraform_raw).hexdigest(), 'ENROLLMENT_TERRAFORM_BYTES_DIFFER')
        for field in ['artifact_sha256', 'certification_report_sha256']:
            sha(receipt[field])
        require(timestamp(receipt['registered_at']) <= datetime.now(timezone.utc), 'ENROLLMENT_NOT_FUTURE')
        uuid(receipt['enrollment_id']); uuid(receipt['runtime_node_id'])
        nodes.append({key: receipt[key] for key in ['node', 'cloud_instance_id', 'private_ip', 'guard_port', 'enrollment_id', 'runtime_node_id']} | {'zone': node['zone']})
    require({n['node']['node_name'] for n in nodes} == set(kata), 'ALL_DEPLOYMENT_KATA_NODES_ENROLLED')
    fields(observation, ['observed_at', 'cilium_config', 'nodes', 'remote_identities'], 'CURRENT_CLUSTER_OBSERVATION_FIELDS')
    observed, now = timestamp(observation['observed_at']), datetime.now(timezone.utc)
    require(observed <= now <= observed + timedelta(minutes=5), 'FRESH_FIVE_MINUTE_CLUSTER_READBACK')
    cilium = observation['cilium_config']
    require(isinstance(cilium, dict) and isinstance(cilium.get('metadata'), dict)
            and isinstance(cilium['metadata'].get('resourceVersion'), str) and 1 <= len(cilium['metadata']['resourceVersion']) <= 128
            and cilium.get('apiVersion') == 'v1' and cilium.get('kind') == 'ConfigMap'
            and cilium.get('metadata', {}).get('name') == 'cilium-config'
            and cilium.get('metadata', {}).get('namespace') == 'kube-system'
            and isinstance(cilium.get('data'), dict) and CONFIG <= cilium['data'].keys(), 'ACTUAL_CILIUM_CONFIGMAP_REQUIRED')
    config = {key: cilium['data'][key] for key in CONFIG}
    require(config['enable-policy'] == 'always' and config['enable-node-selector-labels'] == 'true'
            and config['policy-default-local-cluster'] == 'true', 'CILIUM_NODE_SELECTORS_REQUIRED')
    name(config['cluster-name'])
    node_list = observation['nodes']
    require(isinstance(node_list, dict) and node_list.get('apiVersion') == 'v1' and node_list.get('kind') in {'List', 'NodeList'}
            and isinstance(node_list.get('items'), list) and 1 <= len(node_list['items']) <= 128, 'ACTUAL_CURRENT_NODE_LIST')
    current = {}
    for item in node_list['items']:
        require(isinstance(item, dict) and item.get('kind') == 'Node' and item.get('apiVersion') == 'v1'
                and isinstance(item.get('metadata'), dict), 'ACTUAL_NODE_OBJECT')
        metadata = item.get('metadata', {})
        require(isinstance(metadata.get('name'), str) and metadata['name'] not in current, 'UNIQUE_OBSERVED_KUBERNETES_NODES')
        require(isinstance(metadata.get('resourceVersion'), str) and 1 <= len(metadata['resourceVersion']) <= 128, 'ACTUAL_NODE_RESOURCE_VERSION')
        uuid(metadata.get('uid')); current[metadata['name']] = item
    for hostname in [p['hostname'] for p in platform] + list(kata):
        require(hostname in current, 'OBSERVED_DEPLOYMENT_NODE_REQUIRED')
        node, terraform = current[hostname], outputs['node_inventory'][hostname]
        labels, status, spec = node['metadata'].get('labels', {}), node.get('status', {}), node.get('spec', {})
        require(isinstance(labels, dict) and isinstance(status, dict) and isinstance(spec, dict)
                and isinstance(status.get('addresses'), list) and all(isinstance(a, dict) for a in status['addresses']), 'ACTUAL_NODE_STATUS_ADDRESS_SHAPE')
        require(labels.get('kubernetes.io/hostname') == hostname and labels.get('sandbox.platform/node-pool') == terraform['role']
                and labels.get('topology.kubernetes.io/zone') == terraform['zone'], 'ACTUAL_NODE_ROLE_HOSTNAME_ZONE')
        if terraform['role'] == 'platform':
            conditions, taints = status.get('conditions', []), spec.get('taints', [])
            require(isinstance(conditions, list) and all(isinstance(c, dict) for c in conditions)
                    and isinstance(taints, list) and all(isinstance(t, dict) for t in taints), 'ACTUAL_PLATFORM_CONDITION_TAINT_SHAPE')
            require(spec.get('unschedulable') is not True and not node['metadata'].get('deletionTimestamp')
                    and any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in conditions)
                    and not any(t.get('effect') in {'NoSchedule', 'NoExecute'} for t in taints), 'CURRENT_READY_SCHEDULABLE_PLATFORM_NODE')
        # A cordoned/NotReady Kata node can still hold a live VM. Keep its exact
        # control route; only fresh runtime proofs can settle that VM's death.
        require(any(a.get('type') == 'InternalIP' and a.get('address') == terraform['private_ip']
            for a in status.get('addresses', [])), 'CURRENT_NODE_PRIVATE_IP')
    for node in nodes:
        actual = current[node['node']['node_name']]
        info, annotations = actual['status'].get('nodeInfo', {}), actual['metadata'].get('annotations', {})
        require(isinstance(info, dict) and isinstance(annotations, dict)
                and actual['metadata']['uid'] == node['node']['node_uid']
                and info.get('bootID') == node['node']['boot_id']
                and annotations.get('sandbox.platform/runtime-profile-sha256') == node['node']['profile_sha256'],
                'CURRENT_NODE_UID_BOOT_PROFILE_ENROLLMENT')
    remotes = observation['remote_identities']
    expected = {(p['hostname'], n['node']['node_name']) for p in platform for n in nodes}
    require(isinstance(remotes, list) and len(remotes) == len(expected), 'EVERY_PLATFORM_REMOTE_NODE_IDENTITY_REQUIRED')
    seen = set(); by_name = {n['node']['node_name']: n for n in nodes}
    for remote in remotes:
        fields(remote, ['source_node', 'node_name', 'private_ip', 'identity_id', 'labels'], 'REMOTE_NODE_OBSERVATION_FIELDS')
        pair = (remote['source_node'], remote['node_name'])
        require(pair in expected and pair not in seen, 'EXACT_UNIQUE_PLATFORM_TO_KATA_IDENTITY')
        seen.add(pair)
        node = by_name[remote['node_name']]
        # Cilium v1.20.2 uses scope 0x02 for allocated remote-node identities;
        # global/CIDR/unknown scopes and allocator ID zero cannot prove this bind.
        require(remote['private_ip'] == node['private_ip'] and type(remote['identity_id']) is int
                and 0x02000001 <= remote['identity_id'] <= 0x02ffffff, 'REMOTE_IPCACHE_IDENTITY_BINDING')
        labels = remote['labels']
        require(isinstance(labels, dict) and 5 <= len(labels) <= 256 and all(
            isinstance(k, str) and isinstance(v, str) and 1 <= len(k) <= 256 and len(v) <= 256 for k, v in labels.items()), 'ACTUAL_REMOTE_SECURITY_LABELS')
        required = {'reserved:remote-node': '', 'node:kubernetes.io/hostname': remote['node_name'],
            'node:sandbox.platform/node-pool': 'kata', 'node:topology.kubernetes.io/zone': node['zone'],
            'k8s:io.cilium.k8s.policy.cluster': config['cluster-name']}
        require(all(labels.get(k) == v for k, v in required.items()) and 'reserved:host' not in labels,
                'NODE_LABEL_SOURCE_CLUSTER_FILTER_OR_LOCALHOST_MISMATCH')
    value = {key: settings[key] for key in ['schema_version', 'image', 'replicas', 'nodeguard', 'certification_id',
                'projects', 'concurrency', 'db_max_connections']}
    value.update({'deployment_identity': identity, 'platform_nodes': platform, 'runtime_nodes': nodes,
        'database': dict(settings['database'], host=database['endpoint'], port=database['port']),
        'network_evidence': {'observed_at': observed.isoformat(), 'expires_at': (observed + timedelta(minutes=15)).isoformat(),
            'cilium_config': config, 'observation_sha256': hashlib.sha256(observation_raw).hexdigest(),
            'terraform_output_sha256': hashlib.sha256(terraform_raw).hexdigest(), 'enrollments_sha256': hashlib.sha256(enrollments_raw).hexdigest()}})
    return validate(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ['settings', 'terraform-output', 'enrollments', 'cluster-observation', 'output']:
        parser.add_argument('--' + option, type=Path, required=True)
    args = parser.parse_args()
    try:
        require(len({p.resolve() for p in [args.settings, args.terraform_output, args.enrollments, args.cluster_observation, args.output]}) == 5, 'DISTINCT_PREPARATION_PATHS')
        settings = load(args.settings)
        terraform, terraform_raw = read_json(args.terraform_output, 1048576)
        receipts, enrollments_raw = read_json(args.enrollments, 1048576)
        observed, observation_raw = read_json(args.cluster_observation, 1048576)
        value = prepare(settings, terraform, receipts, observed,
            terraform_raw=terraform_raw, enrollments_raw=enrollments_raw, observation_raw=observation_raw)
        output = canonical(value)
        require(len(output.encode()) <= 262144, 'PREPARED_INPUT_256_KIB_BOUND')
        with args.output.open('x') as destination:
            destination.write(output + '\n')
    except (ValueError, TypeError, KeyError, OSError):
        parser.exit(1, 'TERMINATION_PREPARE_REJECTED\n')


if __name__ == '__main__':
    main()
