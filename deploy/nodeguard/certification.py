"""Strict review-evidence contract. A matching report is not an automatic certification."""
from datetime import datetime, timezone, timedelta
import hashlib
import ipaddress
import re
import uuid

CHECKS = frozenset({'kata_process_coverage', 'cri_start_fencing', 'crash_recovery_unknown',
                    'workspace_single_writer', 'csi_late_publish_unmount', 'first_packet_network_isolation',
                    'node_boot_reenrollment', 'cloud_fence_prevents_revival', 'cloud_volume_detach_safety'})
NODE_FIELDS = {'cluster_epoch', 'node_uid', 'node_name', 'boot_id', 'profile_sha256'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(parsed.tzinfo is not None, 'timezone is required')
    return parsed


def private_address(value):
    address = ipaddress.ip_address(value)
    return any(address in ipaddress.ip_network(prefix) for prefix in (['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'] if address.version == 4 else ['fc00::/7']))


def node_identity(node):
    require(set(node) == NODE_FIELDS, 'unknown or missing NodeBinding field')
    for key in ['cluster_epoch', 'node_uid', 'boot_id']:
        require(str(uuid.UUID(node[key])) == node[key] and uuid.UUID(node[key]).int != 0, 'invalid node identity UUID')
    require(re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}', node['node_name']) is not None, 'invalid node name')
    require(sha(node['profile_sha256']), 'real profile digest required')


def validate_report(report, raw, settings, now=None):
    now = now or datetime.now(timezone.utc)
    require(set(report) == {'protocol', 'certification_id', 'cluster_epoch', 'versions_lock_sha256', 'nodeguard_binary_sha256', 'reviewed_at', 'expires_at', 'nodes', 'checks'}, 'unknown or missing report field')
    require(report['protocol'] == 1 and type(report['protocol']) is int, 'unsupported report protocol')
    require(sha(settings['certification_report_sha256']) and hashlib.sha256(raw).hexdigest() == settings['certification_report_sha256'], 'report differs from independent reviewed digest')
    for key in ['cluster_epoch', 'certification_id', 'versions_lock_sha256', 'nodeguard_binary_sha256']:
        require(report[key] == settings[key], 'report scope differs: ' + key)
    require(sha(report['versions_lock_sha256']) and sha(report['nodeguard_binary_sha256']), 'invalid release digest')
    require(timestamp(report['reviewed_at']) <= now < timestamp(report['expires_at']) <= timestamp(report['reviewed_at']) + timedelta(days=30), 'certification report is future-dated, expired or exceeds 30 days')
    require(set(report['checks']) == CHECKS, 'required certification checks missing or unexpected')
    for item in report['checks'].values():
        require(set(item) == {'status', 'evidence_sha256'} and item['status'] == 'PASS' and sha(item['evidence_sha256']), 'each check needs reviewed PASS evidence')
    require(isinstance(report['nodes'], list) and 1 <= len(report['nodes']) <= 4096, 'invalid report node count')
    ids, boots, addresses = set(), set(), set()
    for item in report['nodes']:
        require(set(item) == {'node', 'cloud_instance_id', 'private_ip'}, 'invalid report node')
        node_identity(item['node'])
        require(item['node']['cluster_epoch'] == report['cluster_epoch'], 'node belongs to another epoch')
        require(re.fullmatch(r'i-[A-Za-z0-9]+', item['cloud_instance_id']) is not None, 'invalid cloud instance')
        require(private_address(item['private_ip']), 'report node address is not private')
        require(item['node']['node_uid'] not in ids and item['node']['boot_id'] not in boots and item['private_ip'] not in addresses, 'duplicate node, boot or address')
        ids.add(item['node']['node_uid']); boots.add(item['node']['boot_id']); addresses.add(item['private_ip'])
    return report


def validate_receipt(artifact, artifact_raw, receipt, terraform_raw, report, report_raw):
    require(set(artifact) == {'protocol','node','cloud_account_id','region','cloud_instance_id','private_ip','guard_port','certification_id'} and artifact['protocol'] == 1 and type(artifact['protocol']) is int, 'invalid enrollment artifact shape')
    require(artifact['guard_port'] == 9444 and re.fullmatch(r'[0-9]{16}',artifact['cloud_account_id']) is not None, 'invalid cloud account or guard port')
    fields = {'protocol', 'enrollment_id', 'runtime_node_id', 'node', 'cloud_account_id', 'region', 'cloud_instance_id', 'private_ip', 'guard_port', 'certification_id', 'certification_report_sha256', 'artifact_sha256', 'terraform_output_sha256', 'registered_at', 'changed', 'enabled'}
    require(set(receipt) == fields and receipt['protocol'] == 1 and type(receipt['protocol']) is int, 'invalid enrollment receipt shape')
    require(type(receipt['enabled']) is bool and receipt['enabled'] and type(receipt['changed']) is bool, 'receipt is not enabled enrollment')
    node_identity(artifact['node'])
    for key in ['node', 'cloud_account_id', 'region', 'cloud_instance_id', 'private_ip', 'guard_port', 'certification_id']:
        require(receipt[key] == artifact[key], 'receipt identity differs: ' + key)
    for key, data in [('artifact_sha256', artifact_raw), ('terraform_output_sha256', terraform_raw), ('certification_report_sha256', report_raw)]:
        require(receipt[key] == hashlib.sha256(data).hexdigest(), 'receipt evidence digest differs: ' + key)
    require(any(item == {'node': artifact['node'], 'cloud_instance_id': artifact['cloud_instance_id'], 'private_ip': artifact['private_ip']} for item in report['nodes']), 'node is not in certified set')
    require(receipt['certification_id'] == report['certification_id'], 'receipt certification differs')
    for key in ['enrollment_id', 'runtime_node_id']:
        require(str(uuid.UUID(receipt[key])) == receipt[key] and uuid.UUID(receipt[key]).int != 0, 'invalid receipt UUID')
    require(timestamp(receipt['registered_at']) <= datetime.now(timezone.utc), 'receipt is future-dated')
