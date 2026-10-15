#!/usr/bin/env python3
"""Render two fixed Prometheus agents and retained encrypted WALs; never applies resources."""
from __future__ import annotations
import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import urlsplit
import uuid
import yaml

ROOT = Path(__file__).resolve().parent
LOCK = json.loads((ROOT / 'versions.lock.json').read_text())
NAMESPACE = 'sandbox-observability'
APP = 'sandbox-metrics-agent'
UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
RAW_METRICS = (
    'sandbox_vm_cpu_seconds_total',
    'sandbox_vm_cpu_capacity_cores',
    'sandbox_vm_cpu_throttled_periods_total',
    'sandbox_vm_cpu_throttled_seconds_total',
    'sandbox_vm_memory_bytes',
    'sandbox_vm_memory_capacity_bytes',
    'sandbox_vm_memory_anon_bytes',
    'sandbox_vm_memory_file_bytes',
    'sandbox_vm_memory_oom_events_total',
    'sandbox_vm_memory_oom_kills_total',
    'sandbox_vm_io_read_bytes_total',
    'sandbox_vm_io_write_bytes_total',
    'sandbox_vm_tasks',
    'sandbox_vm_observation_success',
)
RAW = '|'.join(re.escape(name) for name in RAW_METRICS)
MAX_LAUNCHES_PER_TARGET = 256
NODE_SAMPLE_LIMIT = MAX_LAUNCHES_PER_TARGET * len(RAW_METRICS)
LABELS = ['__name__', 'deployment', 'cluster_epoch', 'node_uid', 'host_boot_id', 'tenant_id', 'project_id', 'instance_id', 'launch_id', 'generation', 'collector_replica', 'job', 'instance']
NODE_IMAGE_SCALARS = (
    'sandbox_node_image_inventory_observation_success',
    'sandbox_node_image_filesystem_observation_success',
    'sandbox_node_image_observed_at_seconds',
    'sandbox_node_image_inventory_count',
    'sandbox_node_image_compressed_logical_bytes',
)
NODE_IMAGE_FILESYSTEM_METRICS = (
    'sandbox_node_image_filesystem_reported_at_seconds',
    'sandbox_node_image_filesystem_used_bytes',
    'sandbox_node_image_filesystem_inodes_used',
)
NODE_IMAGE_RAW = '|'.join(NODE_IMAGE_SCALARS + NODE_IMAGE_FILESYSTEM_METRICS)
NODE_IMAGE_LABELS = ['__name__', 'deployment', 'cluster_epoch', 'node_uid', 'host_boot_id', 'profile_sha256', 'source', 'completeness', 'filesystem_id', 'collector_replica', 'job', 'instance']
NODE_IMAGE_MAX_FILESYSTEMS = 16
NODE_IMAGE_SAMPLE_LIMIT = len(NODE_IMAGE_SCALARS) + len(NODE_IMAGE_FILESYSTEM_METRICS) * NODE_IMAGE_MAX_FILESYSTEMS
# Pinned 3.13.4 agent registry. A single remote-write queue makes dropping its
# url/remote_name labels unambiguous; the WAL/corruption metrics have no labels.
SELF_METRICS = (
    'prometheus_remote_storage_samples_pending',
    'prometheus_remote_storage_samples_failed_total',
    'prometheus_remote_storage_samples_retried_total',
    'prometheus_remote_storage_queue_highest_sent_timestamp_seconds',
    'prometheus_remote_storage_shards',
    'prometheus_remote_storage_shard_capacity',
    'prometheus_tsdb_wal_storage_size_bytes',
    'prometheus_tsdb_wal_writes_failed_total',
    'prometheus_agent_corruptions_total',
)
SELF_RAW = '|'.join(SELF_METRICS)
SELF_SAMPLE_LIMIT = 64
SCRAPE_REPORT_SAMPLES = 5
WRITE_LABELS = LABELS + [label for label in NODE_IMAGE_LABELS if label not in LABELS] + ['scrape_node_uid', 'scrape_host_boot_id', 'scrape_profile_sha256']
SECRET_WRITER = 'sandbox-metrics-writer'
SECRET_SCRAPER = 'sandbox-metrics-scraper'


def require(value, code):
    if not value:
        raise ValueError(code)


def load(path, private=False):
    with Path(path).open('rb') as f:
        meta = os.fstat(f.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_size <= 1024 * 1024, 'INPUT_FILE')
        if private:
            require(stat.S_IMODE(meta.st_mode) in (0o400, 0o600), 'INPUT_PERMISSIONS')
        data = f.read(1024 * 1024 + 1)
        require(len(data) <= 1024 * 1024, 'INPUT_SIZE')
        return data


def decode(data):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'DUPLICATE_KEY')
            value[key] = item
        return value
    return json.loads(data, object_pairs_hook=unique)


def canonical_uuid(value):
    require(isinstance(value, str) and str(uuid.UUID(value)) == value and int(uuid.UUID(value)) != 0, 'UUID')
    return value


def endpoint(value):
    # Prometheus logs its remote_write URL on failures. Reject token-path URLs
    # instead of promising a redaction the upstream binary cannot guarantee.
    require(isinstance(value, str) and value.isascii() and len(value) <= 512, 'WRITER_URL')
    u = urlsplit(value)
    require(u.scheme == 'https' and u.username is None and u.password is None and not u.query and not u.fragment, 'WRITER_URL')
    require(u.path == '/api/prom_write' and u.port in (None, 3242), 'WRITER_URL_PATH')
    require(u.hostname is not None and re.fullmatch(r'ts-[a-z0-9-]+\.hitsdb\.rds\.aliyuncs\.com', u.hostname), 'WRITER_URL_HOST')
    require(u.netloc == u.hostname + (':3242' if u.port else ''), 'WRITER_URL_HOST')
    return u.hostname, u.port or 443


def validate(settings, terraform, remote_url):
    require(isinstance(settings, dict) and set(settings) == {'protocol', 'deployment', 'region', 'cluster_epoch', 'nodes', 'wal_gib'}, 'SETTINGS_FIELDS')
    require(type(settings['protocol']) is int and settings['protocol'] == 1, 'PROTOCOL')
    require(re.fullmatch(r'[a-z][a-z0-9-]{1,40}', settings['deployment'] or '') is not None, 'DEPLOYMENT')
    canonical_uuid(settings['cluster_epoch'])
    tf = {key: value['value'] for key, value in terraform.items()}
    identity = tf['deployment_identity']
    require((settings['deployment'], settings['region']) == (identity['deployment'], identity['region']), 'TERRAFORM_IDENTITY')
    require(re.fullmatch(r'[a-z]{2}-[a-z]+-[0-9]+|cn-[a-z]+', settings['region']) is not None, 'REGION')
    require(isinstance(settings['nodes'], list) and 1 <= len(settings['nodes']) <= 64, 'NODE_LIMIT')
    require(type(settings['wal_gib']) is int and 40 <= settings['wal_gib'] <= 1024, 'WAL_SIZE')
    expected = {n['private_ip']: {**n, 'name': name} for name, n in tf['node_inventory'].items() if n['role'] == 'kata'}
    platform_zones = {n['zone'] for n in tf['node_inventory'].values() if n['role'] == 'platform'}
    require(len(platform_zones) >= 2, 'PLATFORM_ZONES')
    seen_ip, seen_uid, seen_boot = set(), set(), set()
    for node in settings['nodes']:
        require(isinstance(node, dict) and set(node) in ({'name', 'node_uid', 'private_ip', 'host_boot_id'}, {'name', 'node_uid', 'private_ip', 'host_boot_id', 'image_profile_sha256'}), 'NODE_FIELDS')
        if 'image_profile_sha256' in node:
            require(isinstance(node['image_profile_sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', node['image_profile_sha256']), 'IMAGE_PROFILE_SHA256')
        require(re.fullmatch(r'[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?', node['name']) is not None, 'NODE_NAME')
        canonical_uuid(node['node_uid']); canonical_uuid(node['host_boot_id'])
        ip = ipaddress.ip_address(node['private_ip'])
        require(ip.version == 4 and any(ip in ipaddress.ip_network(net) for net in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']), 'NODE_PRIVATE_IP')
        require(str(ip) == node['private_ip'] and str(ip) in expected and expected[str(ip)]['name'] == node['name'], 'TERRAFORM_NODE')
        require(str(ip) not in seen_ip and node['node_uid'] not in seen_uid and node['host_boot_id'] not in seen_boot, 'DUPLICATE_NODE')
        seen_ip.add(str(ip)); seen_uid.add(node['node_uid']); seen_boot.add(node['host_boot_id'])
    require(seen_ip == set(expected), 'NODE_INVENTORY_INCOMPLETE')
    require(len({n['name'] for n in settings['nodes']}) == len(settings['nodes']), 'DUPLICATE_NODE')
    require(isinstance(tf['workspace_kms_key_id'], str) and re.fullmatch(r'[A-Za-z0-9-]{1,128}', tf['workspace_kms_key_id']), 'KMS_KEY')
    endpoint(remote_url)
    report = capacity(settings)
    require(report['six_hour_budget_bytes_with_checkpoint_reserve'] <= int(settings['wal_gib'] * 1024 ** 3 * 0.7), 'WAL_CAPACITY')
    return tf


def capacity(settings):
    # Fourteen bounded raw metrics per launch; the 1 KiB allowance includes churn/
    # label records. It is a conservative planning model, not a storage SLA.
    vm_samples = len(settings['nodes']) * NODE_SAMPLE_LIMIT
    # Optional image jobs reserve five scalars plus three metrics per bounded
    # filesystem; neither their sample nor body allowance is borrowed from VMs.
    image_targets = sum('image_profile_sha256' in node for node in settings['nodes'])
    image_samples = image_targets * NODE_IMAGE_SAMPLE_LIMIT
    samples = vm_samples + image_samples
    # Native scrape reports enter the WAL even when remote-write filters them.
    # Self metrics are bounded after relabeling by their own sample_limit.
    targets = len(settings['nodes']) + image_targets + 1
    reports = targets * SCRAPE_REPORT_SAMPLES
    total = samples + reports + SELF_SAMPLE_LIMIT
    budget = total * (6 * 3600 // 15) * 1024 * 2
    return {'replicas': 2, 'targets_per_replica': targets, 'max_launches_per_target': MAX_LAUNCHES_PER_TARGET,
            'max_raw_metrics_per_launch': len(RAW_METRICS), 'max_raw_samples_per_node_scrape': NODE_SAMPLE_LIMIT,
            'nodeguard_targets_per_replica': len(settings['nodes']), 'self_scrape_targets_per_replica': 1,
            'node_image_targets_per_replica': image_targets,
            'max_node_image_filesystems_per_target': NODE_IMAGE_MAX_FILESYSTEMS,
            'max_node_image_samples_per_target_scrape': NODE_IMAGE_SAMPLE_LIMIT,
            'max_vm_samples_per_scrape_per_replica': vm_samples,
            'max_node_image_samples_per_scrape_per_replica': image_samples,
            'max_raw_samples_per_scrape_per_replica': samples,
            'max_self_samples_per_scrape_per_replica': SELF_SAMPLE_LIMIT,
            'max_scrape_report_samples_per_scrape_per_replica': reports,
            'max_wal_samples_per_scrape_per_replica': total, 'max_samples_per_second_per_replica': total / 15,
            # Body planning uses the original Rust VM 2MiB upper bound and
            # self scrape; each image target reserves its own full 64KiB.
            'max_scrape_body_bytes_per_round_per_replica': (len(settings['nodes']) + 1) * 2 * 1024**2 + image_targets * 64 * 1024,
            # Of five native reports only up survives remote-write. This is a
            # planning model excluding retries/transport overhead, not a hard
            # network limit or a guaranteed compression/ingestion rate.
            'max_remote_write_samples_per_round_per_replica': samples + SELF_SAMPLE_LIMIT + targets,
            'planning_remote_write_samples_per_second_per_replica': (samples + SELF_SAMPLE_LIMIT + targets) / 15,
            'planning_remote_write_bytes_per_second_without_retries': (samples + SELF_SAMPLE_LIMIT + targets) * 1024 / 15,
            'wal_gib_per_replica': settings['wal_gib'], 'wal_gib_total': settings['wal_gib'] * 2,
            'planning_bytes_per_sample_including_churn': 1024, 'checkpoint_reserve_multiplier': 2,
            'six_hour_budget_bytes_with_checkpoint_reserve': budget, 'disk_usage_budget_fraction': 0.7,
            'retention_max_seconds': 21600, 'stale_after_seconds': 60,
            'queue_max_shards': 4, 'queue_capacity_per_shard': 10000, 'queue_max_samples_per_send': 2000,
            'memory_limit_gib_per_replica': 4, 'certified_capacity': False,
            'lossless_guarantee': False, 'requires_load_and_outage_acceptance': True}


def prometheus(settings, replica, remote_url):
    jobs = []
    for node in sorted(settings['nodes'], key=lambda n: n['node_uid']):
        relabel = [{'source_labels': ['__name__'], 'regex': RAW, 'action': 'keep'}]
        for key in ['tenant_id', 'project_id', 'instance_id', 'launch_id']:
            relabel.append({'source_labels': [key], 'regex': UUID, 'action': 'keep'})
            relabel.append({'source_labels': [key], 'regex': str(uuid.UUID(int=0)), 'action': 'drop'})
        relabel.append({'source_labels': ['generation'], 'regex': '[1-9][0-9]{0,18}', 'action': 'keep'})
        for key, expected in [('deployment', settings['deployment']), ('cluster_epoch', settings['cluster_epoch']), ('node_uid', node['node_uid']), ('host_boot_id', node['host_boot_id'])]:
            relabel.append({'source_labels': [key], 'regex': re.escape(expected), 'action': 'keep'})
        relabel += [{'target_label': 'collector_replica', 'replacement': replica, 'action': 'replace'},
                    {'action': 'labelkeep', 'regex': '|'.join(LABELS)}]
        jobs.append({'job_name': 'nodeguard-' + node['node_uid'], 'scheme': 'https', 'metrics_path': '/metrics',
                     'scrape_interval': '15s', 'scrape_timeout': '5s', 'honor_labels': False, 'honor_timestamps': False,
                     'scrape_protocols': ['PrometheusText0.0.4'], 'fallback_scrape_protocol': 'PrometheusText0.0.4',
                     'body_size_limit': '2MB', 'sample_limit': NODE_SAMPLE_LIMIT, 'label_limit': 13,
                     'label_name_length_limit': 64, 'label_value_length_limit': 128, 'target_limit': 1,
                     'follow_redirects': False, 'enable_http2': False,
                     'tls_config': {'ca_file': '/etc/scraper/ca.crt', 'cert_file': '/etc/scraper/tls.crt',
                                    'key_file': '/etc/scraper/tls.key', 'server_name': node['node_uid'] + '.nodeguard.sandbox.internal',
                                    'insecure_skip_verify': False, 'min_version': 'TLS12'},
                     'static_configs': [{'targets': [node['private_ip'] + ':9445'],
                                         'labels': {'scrape_node_uid': node['node_uid'], 'scrape_host_boot_id': node['host_boot_id']}}],
                     'metric_relabel_configs': relabel})
        if 'image_profile_sha256' in node:
            # Reuse only the reviewed transport; image observations have their
            # own path, budget and identity/label contract, independent of VMs.
            image_job = copy.deepcopy(jobs[-1])
            image_relabel = [{'source_labels': ['__name__'], 'regex': NODE_IMAGE_RAW, 'action': 'keep'},
                             {'source_labels': ['__name__', 'filesystem_id'],
                              'regex': '(' + '|'.join(NODE_IMAGE_SCALARS) + ');|(' + '|'.join(NODE_IMAGE_FILESYSTEM_METRICS) + ');[0-9a-f]{64}', 'action': 'keep'}]
            for key, expected in [('deployment', settings['deployment']), ('cluster_epoch', settings['cluster_epoch']),
                                  ('node_uid', node['node_uid']), ('host_boot_id', node['host_boot_id']),
                                  ('profile_sha256', node['image_profile_sha256']), ('source', 'RUNTIME_REPORTED'), ('completeness', 'UNKNOWN')]:
                image_relabel.append({'source_labels': [key], 'regex': re.escape(expected), 'action': 'keep'})
            image_relabel += [{'target_label': 'collector_replica', 'replacement': replica, 'action': 'replace'},
                              {'action': 'labelkeep', 'regex': '|'.join(NODE_IMAGE_LABELS)}]
            image_job.update(job_name='node-images-' + node['node_uid'], metrics_path='/metrics/node-images',
                             body_size_limit='64KiB', sample_limit=NODE_IMAGE_SAMPLE_LIMIT, label_limit=len(NODE_IMAGE_LABELS),
                             extra_scrape_metrics=False,
                             static_configs=[{'targets': [node['private_ip'] + ':9445'], 'labels': {
                                 'scrape_node_uid': node['node_uid'], 'scrape_host_boot_id': node['host_boot_id'],
                                 'scrape_profile_sha256': node['image_profile_sha256']}}], metric_relabel_configs=image_relabel)
            jobs.append(image_job)
    # Local self-scrape uses no mTLS identity and grants no additional network access.
    # URL/remote_name and all other registry labels are removed before limits/WAL.
    jobs.append({'job_name': 'sandbox-agent', 'scheme': 'http', 'metrics_path': '/metrics',
                 'scrape_interval': '15s', 'scrape_timeout': '5s', 'honor_labels': False, 'honor_timestamps': False,
                 'scrape_protocols': ['PrometheusText0.0.4'], 'fallback_scrape_protocol': 'PrometheusText0.0.4',
                 'body_size_limit': '2MB', 'sample_limit': SELF_SAMPLE_LIMIT, 'label_limit': 3,
                 'label_name_length_limit': 64, 'label_value_length_limit': 128, 'target_limit': 1,
                 'follow_redirects': False, 'enable_http2': False,
                 'static_configs': [{'targets': ['127.0.0.1:9090']}],
                 'metric_relabel_configs': [{'source_labels': ['__name__'], 'regex': SELF_RAW, 'action': 'keep'},
                                           {'action': 'labelkeep', 'regex': '__name__|job|instance'}]})
    return {'global': {'scrape_interval': '15s', 'scrape_timeout': '5s', 'external_labels': {'deployment': settings['deployment'], 'cluster_epoch': settings['cluster_epoch'], 'collector_replica': replica}},
            'scrape_configs': jobs,
            'remote_write': [{'name': 'sandbox-managed-prometheus', 'url': remote_url,
                              'remote_timeout': '15s', 'protobuf_message': 'prometheus.WriteRequest',
                              'follow_redirects': False, 'enable_http2': False,
                              'basic_auth': {'username_file': '/etc/writer/username', 'password_file': '/etc/writer/password'},
                              'tls_config': {'insecure_skip_verify': False, 'min_version': 'TLS12'},
                              'write_relabel_configs': [{'source_labels': ['__name__'], 'regex': RAW + '|' + NODE_IMAGE_RAW + '|up|' + SELF_RAW, 'action': 'keep'}, {'action': 'labelkeep', 'regex': '|'.join(WRITE_LABELS)}],
                              'queue_config': {'capacity': 10000, 'min_shards': 1, 'max_shards': 4, 'max_samples_per_send': 2000,
                                               'batch_send_deadline': '5s', 'min_backoff': '1s', 'max_backoff': '30s', 'retry_on_http_429': True, 'sample_age_limit': '0s'},
                              'metadata_config': {'send': False}}]}


def metadata(name, namespace=True):
    return {'name': name, **({'namespace': NAMESPACE} if namespace else {}), 'labels': {'app.kubernetes.io/part-of': APP}}


def resources(settings, tf, remote_url):
    host, port = endpoint(remote_url)
    result = [{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {**metadata(NAMESPACE, False), 'labels': {'pod-security.kubernetes.io/enforce': 'restricted', 'pod-security.kubernetes.io/enforce-version': 'v1.36'}}},
              {'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': metadata(APP), 'automountServiceAccountToken': False},
              {'apiVersion': 'storage.k8s.io/v1', 'kind': 'StorageClass', 'metadata': metadata('sandbox-metrics-wal', False), 'provisioner': 'diskplugin.csi.alibabacloud.com',
               'reclaimPolicy': 'Retain', 'volumeBindingMode': 'WaitForFirstConsumer', 'allowVolumeExpansion': True,
               'parameters': {'type': 'cloud_essd', 'fsType': 'ext4', 'encrypted': 'true', 'kmsKeyId': tf['workspace_kms_key_id'], 'diskTags/Deployment': settings['deployment'], 'diskTags/Purpose': 'metrics-wal'}},
              {'apiVersion': 'cilium.io/v2', 'kind': 'CiliumNetworkPolicy', 'metadata': metadata(APP), 'spec': {
                  'endpointSelector': {'matchLabels': {'app.kubernetes.io/name': APP}},
                  'ingress': [{'fromEntities': ['host'], 'toPorts': [{'ports': [{'port': '9090', 'protocol': 'TCP'}]}]}],
                  'egress': [{'toEndpoints': [{'matchLabels': {'k8s:io.kubernetes.pod.namespace': 'kube-system', 'k8s:k8s-app': 'kube-dns'}}], 'toPorts': [{'ports': [{'port': '53', 'protocol': 'UDP'}, {'port': '53', 'protocol': 'TCP'}], 'rules': {'dns': [{'matchName': host}]}}]},
                             {'toFQDNs': [{'matchName': host}], 'toPorts': [{'ports': [{'port': str(port), 'protocol': 'TCP'}]}]},
                             {'toNodes': [{'matchLabels': {'kubernetes.io/hostname': n['name'], 'sandbox.platform/node-pool': 'kata'}} for n in settings['nodes']], 'toPorts': [{'ports': [{'port': '9445', 'protocol': 'TCP'}]}]}]}}]
    result.append({'apiVersion': 'cilium.io/v2', 'kind': 'CiliumClusterwideNetworkPolicy', 'metadata': metadata(APP + '-node-ingress', False), 'spec': {
        'nodeSelector': {'matchLabels': {'sandbox.platform/node-pool': 'kata'}, 'matchExpressions': [{'key': 'kubernetes.io/hostname', 'operator': 'In', 'values': [n['name'] for n in settings['nodes']]}]},
        'ingress': [{'fromEndpoints': [{'matchLabels': {'k8s:io.kubernetes.pod.namespace': NAMESPACE, 'k8s:app.kubernetes.io/name': APP}}], 'toPorts': [{'ports': [{'port': '9445', 'protocol': 'TCP'}]}]}]}})
    common_selector = {'app.kubernetes.io/name': APP}
    for replica in ('a', 'b'):
        name = APP + '-' + replica
        labels = {**common_selector, 'sandbox.platform/collector-replica': replica}
        config = yaml.safe_dump(prometheus(settings, replica, remote_url), sort_keys=False)
        require(len(config.encode()) < 900000, 'CONFIG_SIZE')
        result.append({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': metadata(name), 'type': 'Opaque', 'stringData': {'prometheus.yml': config}})
        result.append({'apiVersion': 'v1', 'kind': 'Service', 'metadata': metadata(name), 'spec': {'clusterIP': 'None', 'selector': labels, 'ports': [{'name': 'http', 'port': 9090, 'targetPort': 'http'}]}})
        result.append({'apiVersion': 'apps/v1', 'kind': 'StatefulSet', 'metadata': metadata(name), 'spec': {
            'replicas': 1, 'serviceName': name, 'selector': {'matchLabels': labels},
            'persistentVolumeClaimRetentionPolicy': {'whenDeleted': 'Retain', 'whenScaled': 'Retain'},
            'template': {'metadata': {'labels': labels}, 'spec': {
                'serviceAccountName': APP, 'automountServiceAccountToken': False, 'terminationGracePeriodSeconds': 120, 'dnsConfig': {'options': [{'name': 'ndots', 'value': '1'}]},
                'nodeSelector': {'sandbox.platform/node-pool': 'platform', 'kubernetes.io/arch': 'amd64'},
                'affinity': {'podAntiAffinity': {'requiredDuringSchedulingIgnoredDuringExecution': [
                    {'labelSelector': {'matchLabels': common_selector}, 'topologyKey': key} for key in ('topology.kubernetes.io/zone', 'kubernetes.io/hostname')]}},
                'securityContext': {'runAsNonRoot': True, 'runAsUser': 65534, 'runAsGroup': 65534, 'fsGroup': 65534, 'fsGroupChangePolicy': 'OnRootMismatch', 'seccompProfile': {'type': 'RuntimeDefault'}},
                'containers': [{'name': 'agent', 'image': LOCK['prometheus_image'], 'imagePullPolicy': 'IfNotPresent',
                    'args': ['--agent', '--config.file=/etc/prometheus/prometheus.yml', '--config.auto-reload', '--storage.agent.path=/prometheus', '--storage.agent.wal-compression',
                             '--storage.agent.retention.min-time=5m', '--storage.agent.retention.max-time=6h', '--storage.remote.flush-deadline=60s', '--web.listen-address=0.0.0.0:9090', '--web.max-connections=32', '--log.level=warn', '--log.format=json'],
                    'ports': [{'name': 'http', 'containerPort': 9090}],
                    'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}},
                    'resources': {'requests': {'cpu': '500m', 'memory': '1Gi'}, 'limits': {'cpu': '2', 'memory': '4Gi'}},
                    'startupProbe': {'httpGet': {'path': '/-/ready', 'port': 'http'}, 'periodSeconds': 10, 'failureThreshold': 120},
                    'readinessProbe': {'httpGet': {'path': '/-/ready', 'port': 'http'}, 'periodSeconds': 10, 'failureThreshold': 3},
                    'livenessProbe': {'httpGet': {'path': '/-/healthy', 'port': 'http'}, 'periodSeconds': 20, 'failureThreshold': 3},
                    'volumeMounts': [{'name': 'wal', 'mountPath': '/prometheus'}, {'name': 'config', 'mountPath': '/etc/prometheus', 'readOnly': True}, {'name': 'writer', 'mountPath': '/etc/writer', 'readOnly': True}, {'name': 'scraper', 'mountPath': '/etc/scraper', 'readOnly': True}]}],
                'volumes': [{'name': 'config', 'secret': {'secretName': name, 'defaultMode': 0o440}}, {'name': 'writer', 'secret': {'secretName': SECRET_WRITER, 'defaultMode': 0o440}}, {'name': 'scraper', 'secret': {'secretName': SECRET_SCRAPER, 'defaultMode': 0o440}}]}},
            'volumeClaimTemplates': [{'metadata': {'name': 'wal'}, 'spec': {'accessModes': ['ReadWriteOnce'], 'storageClassName': 'sandbox-metrics-wal', 'resources': {'requests': {'storage': f"{settings['wal_gib']}Gi"}}}}]}})
    result.append({'apiVersion': 'policy/v1', 'kind': 'PodDisruptionBudget', 'metadata': metadata(APP), 'spec': {'minAvailable': 1, 'selector': {'matchLabels': common_selector}}})
    return result


def write_private(path, data):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())


def render(settings_path, terraform_path, url_path, output):
    from alerts import rules
    settings, terraform = decode(load(settings_path)), decode(load(terraform_path))
    remote = load(url_path, True).decode('ascii').strip()
    tf = validate(settings, terraform, remote)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, values in [('manifest.yaml', resources(settings, tf, remote)), ('capacity.json', capacity(settings)),
                         ('alerts.rules.yaml', [rules(settings)])]:
        data = yaml.safe_dump_all(values, sort_keys=False).encode() if name.endswith('.yaml') else json.dumps(values, indent=2).encode()
        write_private(output / name, data)
    for replica in ('a', 'b'):
        write_private(output / f'prometheus-{replica}.yaml', yaml.safe_dump(prometheus(settings, replica, remote), sort_keys=False).encode())
    print('Rendered private manifests, capacity report and backend alert rules; no cluster or cloud action performed.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--settings', type=Path, required=True)
    p.add_argument('--terraform-output', type=Path, required=True)
    p.add_argument('--remote-write-url-file', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    render(a.settings, a.terraform_output, a.remote_write_url_file, a.output)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError):
        print('OBSERVABILITY_CONFIGURATION_REJECTED', file=sys.stderr)
        sys.exit(1)
