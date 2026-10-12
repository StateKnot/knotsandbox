#!/usr/bin/env python3
"""Install two restore StorageClasses and observe candidate identities, without enabling restore."""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parent
DRIVER = 'diskplugin.csi.alibabacloud.com'
TOPOLOGY_KEY = 'topology.diskplugin.csi.alibabacloud.com/zone'
FIELDS = {'protocol', 'normal_storage_class', 'restore_raw_storage_class', 'restore_delivery_storage_class',
          'snapshot_class', 'workspace_kms_key_id', 'account_id', 'region', 'deployment'}
PURPOSES = ('normal', 'raw', 'delivery')
CSI_IMAGE_KEYS = {'registry.cn-hangzhou.aliyuncs.com/acs/' + value for value in (
    'csi-plugin:v1.37.2', 'csi-plugin:v1.37.2-init', 'csi-attacher:v4.12.0-aliyun',
    'csi-provisioner:v6.2.1-aliyun', 'csi-resizer:v2.1.1-aliyun', 'csi-snapshotter:v8.5.1-aliyun',
    'snapshot-controller:v8.5.1-aliyun', 'csi-node-driver-registrar:v2.17.0-aliyun')}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False, 'INVALID_JSON_NUMBER'))


def read(path, limit=1024 * 1024):
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        require(stat.S_ISREG(os.fstat(descriptor).st_mode), 'PUBLIC_INPUT_REGULAR_FILE_REQUIRED')
        with os.fdopen(descriptor, 'rb', closefd=False) as file:
            raw = file.read(limit + 1)
        require(len(raw) <= limit, 'PUBLIC_INPUT_SIZE_LIMIT')
        return decode(raw)
    finally:
        os.close(descriptor)


def name(value):
    return isinstance(value, str) and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', value)


def validate(config):
    require(type(config) is dict and set(config) == FIELDS and type(config['protocol']) is int and config['protocol'] == 1, 'STORAGE_CONFIG_FIELDS')
    classes = [config[key] for key in ('normal_storage_class', 'restore_raw_storage_class', 'restore_delivery_storage_class')]
    require(all(name(v) for v in classes) and len(set(classes)) == 3 and name(config['snapshot_class']), 'SEPARATE_STORAGE_CLASS_NAMES')
    require(isinstance(config['workspace_kms_key_id'], str) and re.fullmatch(r'[A-Za-z0-9/_:-]{1,256}', config['workspace_kms_key_id']), 'COMPUTE_KMS_ID')
    require(isinstance(config['account_id'], str) and re.fullmatch(r'[0-9]{16}', config['account_id']), 'ACCOUNT_ID')
    require(isinstance(config['region'], str) and re.fullmatch(r'cn-[a-z0-9-]{1,29}', config['region']), 'REGION')
    require(isinstance(config['deployment'], str) and re.fullmatch(r'[a-z][a-z0-9-]{3,19}', config['deployment']), 'DEPLOYMENT_TAG')
    return config


def infrastructure(config, terraform):
    validate(config)
    required = {'deployment_identity', 'workspace_kms_key_id', 'node_inventory', 'subnets'}
    require(type(terraform) is dict and required <= set(terraform), 'TERRAFORM_OUTPUT_REQUIRED')
    outputs = {}
    for key in required:
        wrapper = terraform[key]
        require(type(wrapper) is dict and {'value', 'sensitive'} <= set(wrapper)
                and set(wrapper) <= {'value', 'sensitive', 'type'}
                and type(wrapper['sensitive']) is bool and wrapper['sensitive'] is False, 'NONSECRET_TERRAFORM_WRAPPER')
        outputs[key] = wrapper['value']
    identity = outputs['deployment_identity']
    require(type(identity) is dict and set(identity) == {'cloud_account_id', 'region', 'deployment', 'environment'}
            and identity['environment'] in ('preproduction', 'production')
            and identity['cloud_account_id'] == config['account_id'] and identity['region'] == config['region']
            and identity['deployment'] == config['deployment']
            and outputs['workspace_kms_key_id'] == config['workspace_kms_key_id'], 'TERRAFORM_COMPUTE_IDENTITY')
    subnets = outputs['subnets']
    require(type(subnets) is dict and 3 <= len(subnets) <= 64, 'SUBNET_INVENTORY')
    networks, subnet_ids = [], set()
    private_ranges = [ipaddress.ip_network(c) for c in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    region = config['region']
    def zone(value):
        return isinstance(value, str) and re.fullmatch(re.escape(region) + r'-[a-z0-9-]+', value) and len(value) <= 64
    for key, subnet in subnets.items():
        require(name(key) and type(subnet) is dict and set(subnet) == {'id', 'zone', 'cidr'}
                and isinstance(subnet['id'], str) and re.fullmatch(r'vsw-[A-Za-z0-9]+', subnet['id'])
                and subnet['id'] not in subnet_ids and zone(subnet['zone']) and isinstance(subnet['cidr'], str), 'SUBNET_FIELDS')
        network = ipaddress.ip_network(subnet['cidr'], strict=True)
        require(network.version == 4 and any(network.subnet_of(p) for p in private_ranges)
                and all(not network.overlaps(n) for _, n in networks), 'SUBNET_PRIVATE_NETWORK')
        networks.append((subnet['zone'], network))
        subnet_ids.add(subnet['id'])
    nodes = outputs['node_inventory']
    require(type(nodes) is dict and 9 <= len(nodes) <= 10000, 'NODE_INVENTORY')
    pools = {role: [] for role in ('control', 'platform', 'kata')}
    ids, addresses = set(), set()
    for key, node in nodes.items():
        require(isinstance(key, str) and re.fullmatch(r'[a-z][a-z0-9-]+', key)
                and type(node) is dict and set(node) == {'id', 'private_ip', 'role', 'zone'}
                and isinstance(node['role'], str) and node['role'] in pools and zone(node['zone'])
                and isinstance(node['id'], str) and re.fullmatch(r'i-[A-Za-z0-9]+', node['id'])
                and node['id'] not in ids and isinstance(node['private_ip'], str), 'NODE_FIELDS')
        address = ipaddress.ip_address(node['private_ip'])
        require(address.version == 4 and str(address) == node['private_ip'] and address not in addresses
                and any(address in n for z, n in networks if z == node['zone']), 'NODE_SUBNET_BINDING')
        ids.add(node['id']); addresses.add(address); pools[node['role']].append(node['zone'])
    zones = sorted(set(pools['kata']))
    require(len(pools['control']) == len(pools['platform']) == 3 and len(zones) == 3
            and all(sorted(set(v)) == zones for v in pools.values())
            and set(z for z, _ in networks) == set(zones), 'EXACT_THREE_FAULT_DOMAINS')
    return zones


def class_spec(config, zones, purpose):
    require(purpose in PURPOSES, 'STORAGE_PURPOSE')
    parameters = {'type': 'cloud_essd', 'encrypted': 'true', 'kmsKeyId': config['workspace_kms_key_id'], 'diskTags/Deployment': config['deployment']}
    if purpose in ('normal', 'delivery'):
        parameters['fsType'] = 'ext4'
    return {'apiVersion': 'storage.k8s.io/v1', 'kind': 'StorageClass', 'provisioner': DRIVER,
            'reclaimPolicy': 'Retain', 'volumeBindingMode': 'Immediate' if purpose == 'delivery' else 'WaitForFirstConsumer',
            'allowVolumeExpansion': purpose == 'normal', 'parameters': parameters, 'mountOptions': [],
            'allowedTopologies': [] if purpose == 'normal' else [{'matchLabelExpressions': [{'key': TOPOLOGY_KEY, 'values': zones}]}]}


def snapshot_spec(config):
    return {'apiVersion': 'snapshot.storage.k8s.io/v1', 'kind': 'VolumeSnapshotClass', 'driver': DRIVER,
            'deletionPolicy': 'Retain', 'parameters': {'snapshotTags/Deployment': config['deployment']}}


def projection(value, expected):
    require(type(value) is dict and set(value) <= set(expected) | {'metadata'}, 'UNKNOWN_CLASS_BEHAVIOR')
    for key, wanted in expected.items():
        if key == 'mountOptions' or (key == 'allowedTopologies' and wanted == []):
            require(key not in value or value[key] == wanted, 'OPTIONAL_CLASS_LIST_DRIFT')
        else:
            # Expansion is boolean; Python's numeric equality cannot accept 0/1.
            require(key in value and type(value[key]) is type(wanted) and value[key] == wanted, 'CLASS_PURPOSE_POLICY_DRIFT')
    return expected


def metadata(value, expected_name):
    meta = value.get('metadata')
    require(type(meta) is dict and set(meta) <= {'name', 'uid', 'resourceVersion', 'creationTimestamp', 'generation', 'managedFields',
            'labels', 'annotations', 'deletionTimestamp', 'ownerReferences', 'finalizers'} and meta.get('name') == expected_name, 'CLASS_METADATA')
    actual_uid = meta.get('uid')
    require(isinstance(actual_uid, str) and str(uuid.UUID(actual_uid)) == actual_uid and uuid.UUID(actual_uid).int != 0, 'ACTUAL_CLASS_UID_REQUIRED')
    require(meta.get('deletionTimestamp') is None and all(key not in meta or meta[key] == [] for key in ('ownerReferences', 'finalizers')), 'CLASS_DELETING_OR_OWNED')
    if 'labels' in meta:
        labels = meta['labels']
        require(type(labels) is dict and len(labels) <= 128 and all(isinstance(k, str) and k.isascii() and len(k) <= 253
                and isinstance(v, str) and v.isascii() and len(v) <= 256 for k, v in labels.items()), 'CLASS_LABELS')
    if 'annotations' in meta:
        annotations = meta['annotations']
        require(type(annotations) is dict and set(annotations) <= {'kubectl.kubernetes.io/last-applied-configuration'}
                and all(isinstance(v, str) and v.isascii() and len(v) <= 65536 for v in annotations.values()), 'CLASS_BEHAVIOR_ANNOTATIONS')
    return actual_uid


def observe_class(value, expected, expected_name):
    actual_uid = metadata(value, expected_name)
    spec = projection(value, expected)
    return {'name': expected_name, 'uid': actual_uid, 'spec_sha256': hashlib.sha256(canonical(spec)).hexdigest()}


def render(config, terraform):
    zones = infrastructure(config, terraform)
    items = []
    for purpose, key in [('raw', 'restore_raw_storage_class'), ('delivery', 'restore_delivery_storage_class')]:
        spec = class_spec(config, zones, purpose)
        items.append({**spec, 'metadata': {'name': config[key], 'labels': {'app.kubernetes.io/managed-by': 'sandbox-restore-storage'}}})
    return {'apiVersion': 'v1', 'kind': 'List', 'items': items}


def version_lock(path=None):
    path = ROOT.parent / 'cluster' / 'versions.lock.json' if path is None else path
    raw = Path(path).read_bytes()
    lock = decode(raw)
    require(lock['versions']['csi_driver'] == '1.37.2' and lock['versions']['kubernetes'] == '1.36.4'
            and type(lock['csi_images']) is dict and set(lock['csi_images']) == CSI_IMAGE_KEYS
            and all(isinstance(v, str) and re.fullmatch(r'[A-Za-z0-9./:-]+@sha256:[0-9a-f]{64}', v) for v in lock['csi_images'].values()), 'FIXED_CSI_LOCK_REQUIRED')
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'kubernetes': lock['versions']['kubernetes'],
            'csi_driver': lock['versions']['csi_driver'], 'csi_images': lock['csi_images']}


class Kubernetes:
    def __init__(self, context):
        require(isinstance(context, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/@-]{0,252}', context), 'EXPLICIT_KUBERNETES_CONTEXT')
        self.context = context

    def get(self, resource, name_, optional=False):
        args = ['kubectl', '--context', self.context, '--request-timeout=20s', 'get', resource, name_, '-o', 'json']
        if optional:
            args.append('--ignore-not-found=true')
        response = subprocess.run(args, check=False, capture_output=True, timeout=25)
        require(response.returncode == 0 and len(response.stdout) <= 262144, 'KUBERNETES_CLASS_GET_FAILED')
        return decode(response.stdout) if response.stdout.strip() else None

    def create(self, body):
        # No apply/patch/update/delete and no RBAC/profile mutation path.
        response = subprocess.run(['kubectl', '--context', self.context, '--request-timeout=20s', 'create', '-f', '-', '-o', 'json'],
                                  input=canonical(body), check=False, capture_output=True, timeout=25)
        require(response.returncode == 0 and len(response.stdout) <= 262144, 'KUBERNETES_CLASS_CREATE_FAILED')


def probe(config, terraform, kubernetes, install=False, lock_path=None):
    zones = infrastructure(config, terraform)
    lock = version_lock(lock_path)
    wanted = {'normal': (config['normal_storage_class'], class_spec(config, zones, 'normal')),
              'raw': (config['restore_raw_storage_class'], class_spec(config, zones, 'raw')),
              'delivery': (config['restore_delivery_storage_class'], class_spec(config, zones, 'delivery')),
              'snapshot': (config['snapshot_class'], snapshot_spec(config))}
    observed, missing = {}, []
    # Preflight all existing objects before the first create. A partial install
    # never rewrites an existing class or rolls it back by deleting it.
    for purpose, (name_, spec) in wanted.items():
        resource = 'volumesnapshotclass' if purpose == 'snapshot' else 'storageclass'
        value = kubernetes.get(resource, name_, optional=install and purpose in ('raw', 'delivery'))
        if value is None:
            require(install and purpose in ('raw', 'delivery'), 'CLASS_NOT_INSTALLED')
            missing.append(purpose)
        else:
            observed[purpose] = observe_class(value, spec, name_)
    require(len({entry['uid'] for entry in observed.values()}) == len(observed), 'CLASS_UID_REUSED')
    for purpose in missing:
        name_, spec = wanted[purpose]
        kubernetes.create({**spec, 'metadata': {'name': name_, 'labels': {'app.kubernetes.io/managed-by': 'sandbox-restore-storage'}}})
        observed[purpose] = observe_class(kubernetes.get('storageclass', name_), spec, name_)
    require(len({observed[p]['uid'] for p in wanted}) == 4, 'CLASS_UID_REUSED')
    for purpose, (name_, spec) in wanted.items():
        resource = 'volumesnapshotclass' if purpose == 'snapshot' else 'storageclass'
        require(observe_class(kubernetes.get(resource, name_), spec, name_) == observed[purpose], 'CLASS_CHANGED_DURING_PROBE')
    mapping = {**observed, 'workspace_kms_key_id': config['workspace_kms_key_id'], 'account_id': config['account_id'],
               'region': config['region'], 'deployment': config['deployment'], 'topology': {'key': TOPOLOGY_KEY, 'zone_ids': zones}}
    return {'protocol': 1, 'result': 'CANDIDATE_STORAGE_MAPPING', 'production_activation': False,
            'csi_restore_certification': 'NOT_VERIFIED', 'context': kubernetes.context,
            'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'mapping': mapping,
            'terraform_output_sha256': hashlib.sha256(canonical(terraform)).hexdigest(), 'versions_lock': lock}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('render', 'install', 'probe'))
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--terraform-output', type=Path, required=True)
    parser.add_argument('--context')
    args = parser.parse_args()
    config, terraform = read(args.config, 16384), read(args.terraform_output)
    version_lock()
    if args.action == 'render':
        require(args.context is None, 'RENDER_DOES_NOT_USE_KUBERNETES_CONTEXT')
        result = render(config, terraform)
    else:
        result = probe(config, terraform, Kubernetes(args.context), install=args.action == 'install')
    sys.stdout.buffer.write(canonical(result) + b'\n')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired):
        # Inputs and kubectl provider errors may contain authentication material.
        print('RESTORE_STORAGE_OPERATION_REJECTED', file=sys.stderr)
        sys.exit(1)
