import copy
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
import uuid
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from observability import validate, capacity, resources, prometheus, render, endpoint, LOCK, RAW, LABELS, SELF_METRICS, SELF_SAMPLE_LIMIT, SCRAPE_REPORT_SAMPLES


def relabel(labels, rules):
    """Apply the rendered fixed relabel subset to representative wire labels."""
    labels = dict(labels)
    for rule in rules:
        regex = rule.get('regex', '(.*)')
        value = rule.get('separator', ';').join(labels.get(k, '') for k in rule.get('source_labels', []))
        match = re.fullmatch(regex, value)
        action = rule['action']
        if action == 'keep' and not match or action == 'drop' and match:
            return None
        if action == 'labelkeep':
            labels = {k: v for k, v in labels.items() if re.fullmatch(regex, k)}
        elif action == 'replace' and match:
            labels[rule['target_label']] = rule['replacement']
        elif action not in ('keep', 'drop', 'replace'):
            if action != 'labelkeep':
                raise AssertionError('Unsupported rendered relabel action')
    return labels


def fixture():
    nodes = [{'name': 'kata-' + str(i), 'node_uid': str(uuid.UUID(int=i+1)), 'host_boot_id': str(uuid.UUID(int=i+11)), 'private_ip': '10.80.40.' + str(i+10)} for i in range(2)]
    settings = {'protocol': 1, 'deployment': 'sandbox-test', 'region': 'cn-hangzhou', 'cluster_epoch': str(uuid.UUID(int=30)), 'nodes': nodes, 'wal_gib': 40}
    inventory = {n['name']: {'id': 'i-test-' + str(i), 'private_ip': n['private_ip'], 'role': 'kata', 'zone': 'cn-hangzhou-h'} for i, n in enumerate(nodes)}
    inventory.update({f'platform-{i}': {'id': 'i-platform-' + str(i), 'private_ip': f'10.80.20.{i+10}', 'role': 'platform', 'zone': 'cn-hangzhou-' + chr(104+i)} for i in range(3)})
    tf = {k: {'value': v} for k,v in {'deployment_identity': {'deployment': 'sandbox-test', 'region': 'cn-hangzhou'}, 'node_inventory': inventory, 'workspace_kms_key_id': 'test-kms-key'}.items()}
    return settings, tf, 'https://ts-offline-fixture.hitsdb.rds.aliyuncs.com:3242/api/prom_write'


class ObservabilityTest(unittest.TestCase):
    def test_two_agents_use_separate_retained_persistent_encrypted_wals(self):
        s, tf, u = fixture(); outputs = validate(s, tf, u); values = resources(s, outputs, u)
        sets = [v for v in values if v['kind'] == 'StatefulSet']
        self.assertEqual(len(sets), 2)
        for v in sets:
            self.assertEqual(v['spec']['replicas'], 1)
            self.assertEqual(v['spec']['persistentVolumeClaimRetentionPolicy'], {'whenDeleted': 'Retain', 'whenScaled': 'Retain'})
            pod = v['spec']['template']['spec']
            self.assertEqual(pod['nodeSelector']['sandbox.platform/node-pool'], 'platform')
            self.assertFalse(pod['automountServiceAccountToken'])
            self.assertFalse(any('emptyDir' in x for x in pod['volumes']))
            self.assertEqual(pod['containers'][0]['image'], LOCK['prometheus_image'])
            self.assertIn('--storage.agent.retention.max-time=6h', pod['containers'][0]['args'])
            self.assertEqual(len(pod['affinity']['podAntiAffinity']['requiredDuringSchedulingIgnoredDuringExecution']), 2)
        sc = next(v for v in values if v['kind'] == 'StorageClass')
        self.assertEqual((sc['reclaimPolicy'], sc['volumeBindingMode'], sc['parameters']['encrypted']), ('Retain','WaitForFirstConsumer','true'))
        self.assertFalse(any(v['kind'] in ('Role', 'ClusterRole', 'RoleBinding', 'ClusterRoleBinding') for v in values))

    def test_exact_san_raw_metric_scope_and_separate_ha_series(self):
        s, tf, u = fixture()
        for replica in ('a', 'b'):
            p = prometheus(s, replica, u)
            self.assertEqual(p['global']['external_labels']['collector_replica'], replica)
            self.assertEqual(p['global']['external_labels']['cluster_epoch'], s['cluster_epoch'])
            self.assertNotIn('rule_files', p)
            jobs = [j for j in p['scrape_configs'] if j['job_name'].startswith('nodeguard-')]
            self.assertEqual(len(jobs), len(s['nodes']))
            for job in jobs:
                node = next(n for n in s['nodes'] if job['job_name'].endswith(n['node_uid']))
                self.assertEqual(job['tls_config']['server_name'], node['node_uid'] + '.nodeguard.sandbox.internal')
                self.assertFalse(job['tls_config']['insecure_skip_verify'])
                self.assertFalse(job['honor_timestamps'])
                self.assertFalse(job['honor_labels'])
                self.assertEqual(job['sample_limit'], 1536)
                self.assertEqual(job['label_limit'], 13)
                self.assertEqual(job['static_configs'][0]['targets'], [node['private_ip'] + ':9445'])
                self.assertEqual(job['static_configs'][0]['labels'], {'scrape_node_uid': node['node_uid'], 'scrape_host_boot_id': node['host_boot_id']})
                r = job['metric_relabel_configs']
                self.assertEqual(r[-1]['action'], 'labelkeep')
                self.assertEqual(r[-1]['regex'], '|'.join(LABELS))
                self.assertEqual(r[0]['regex'], RAW)
                self.assertEqual(r[-2]['replacement'], replica)
                for field in ['tenant_id','project_id','instance_id','launch_id','generation','cluster_epoch','node_uid','host_boot_id']:
                    self.assertTrue(any(field in x.get('source_labels', []) for x in r))
            writer = p['remote_write'][0]
            self.assertFalse(writer['follow_redirects']); self.assertFalse(writer['enable_http2'])
            self.assertEqual(writer['basic_auth'], {'username_file': '/etc/writer/username', 'password_file': '/etc/writer/password'})
            self.assertEqual(writer['queue_config']['max_shards'], 4)

    def test_native_up_survives_remote_write_without_masking_exporter_identity(self):
        s, tf, u = fixture(); p = prometheus(s, 'a', u)
        job = p['scrape_configs'][0]; node = next(n for n in s['nodes'] if job['job_name'].endswith(n['node_uid']))
        target = {'job': job['job_name'], 'instance': node['private_ip'] + ':9445', **job['static_configs'][0]['labels']}
        raw = {'__name__': 'sandbox_vm_memory_bytes', **target, 'deployment': s['deployment'], 'cluster_epoch': s['cluster_epoch'],
               'node_uid': node['node_uid'], 'host_boot_id': node['host_boot_id'], 'generation': '1', 'collector_replica': 'rogue',
               **{k: str(uuid.UUID(int=i + 101)) for i, k in enumerate(['tenant_id', 'project_id', 'instance_id', 'launch_id'])},
               'secret_label': 'PRIVATE'}
        accepted = relabel(raw, job['metric_relabel_configs'])
        self.assertEqual(set(accepted), set(LABELS))
        self.assertEqual(accepted['collector_replica'], 'a')
        # Target identity is separate: a correct scrape_* must not hide an incorrect exporter tuple.
        for key in ['node_uid', 'host_boot_id', 'cluster_epoch', 'tenant_id']:
            wrong = dict(raw); wrong[key] = str(uuid.UUID(int=999)) if key != 'tenant_id' else str(uuid.UUID(int=0))
            self.assertIsNone(relabel(wrong, job['metric_relabel_configs']))
        self.assertIsNone(relabel({**target, '__name__': 'up'}, job['metric_relabel_configs']))
        writer = p['remote_write'][0]['write_relabel_configs']
        # Prometheus generates up from target labels after metric relabeling, including failed scrapes.
        native = relabel({'__name__': 'up', **target, **p['global']['external_labels']}, writer)
        self.assertEqual(native, {'__name__': 'up', **target, **p['global']['external_labels']})
        self.assertNotIn('node_uid', native); self.assertNotIn('host_boot_id', native)
        self.assertIsNone(relabel({'__name__': 'scrape_duration_seconds', **target}, writer))
        self.assertIsNone(relabel({'__name__': 'unapproved_guest_secret', **target}, writer))

    def test_self_scrape_is_bounded_loopback_and_scrubs_registry_private_labels(self):
        s, tf, u = fixture(); p = prometheus(s, 'b', u)
        job = next(j for j in p['scrape_configs'] if j['job_name'] == 'sandbox-agent')
        self.assertEqual(job['static_configs'], [{'targets': ['127.0.0.1:9090']}])
        self.assertEqual((job['scheme'], job['metrics_path'], job['scrape_interval'], job['scrape_timeout']), ('http', '/metrics', '15s', '5s'))
        self.assertEqual((job['sample_limit'], job['label_limit'], job['body_size_limit']), (SELF_SAMPLE_LIMIT, 3, '2MB'))
        for field in ['tls_config', 'basic_auth', 'authorization']:
            self.assertNotIn(field, job)
        for field in ['honor_labels', 'honor_timestamps', 'follow_redirects', 'enable_http2']:
            self.assertFalse(job[field])
        self.assertEqual((job['label_name_length_limit'], job['label_value_length_limit'], job['target_limit']), (64, 128, 1))
        writer = p['remote_write'][0]['write_relabel_configs']
        for name in SELF_METRICS:
            labels = relabel({'__name__': name, 'job': 'sandbox-agent', 'instance': '127.0.0.1:9090',
                              'url': 'PRIVATE_REMOTE_URL', 'remote_name': 'PRIVATE_NAME', 'secret_label': 'PRIVATE'}, job['metric_relabel_configs'])
            self.assertEqual(set(labels), {'__name__', 'job', 'instance'})
            self.assertEqual(relabel({**labels, **p['global']['external_labels']}, writer), {**labels, **p['global']['external_labels']})
        for name in ['go_gc_duration_seconds', 'prometheus_http_requests_total', 'up', 'sandbox_vm_tasks']:
            self.assertIsNone(relabel({'__name__': name}, job['metric_relabel_configs']))

    def test_capacity_includes_self_scrape_and_all_native_wal_reports(self):
        s, tf, u = fixture(); p = prometheus(s, 'a', u); c = capacity(s)
        raw = len(s['nodes']) * 256 * 6
        native = len(p['scrape_configs']) * SCRAPE_REPORT_SAMPLES
        total = raw + SELF_SAMPLE_LIMIT + native
        self.assertEqual(c['max_raw_samples_per_scrape_per_replica'], raw)
        self.assertEqual(c['max_self_samples_per_scrape_per_replica'], SELF_SAMPLE_LIMIT)
        self.assertEqual(c['max_scrape_report_samples_per_scrape_per_replica'], native)
        self.assertEqual(c['max_wal_samples_per_scrape_per_replica'], total)
        self.assertEqual(c['max_samples_per_second_per_replica'], total / 15)
        self.assertEqual(c['targets_per_replica'], len(p['scrape_configs']))
        self.assertEqual(c['six_hour_budget_bytes_with_checkpoint_reserve'], total * 1440 * 1024 * 2)
        self.assertGreater(c['six_hour_budget_bytes_with_checkpoint_reserve'], raw * 1440 * 1024 * 2)
        self.assertEqual(c['disk_usage_budget_fraction'], 0.7)
        # This accepted inventory fit the old raw-only budget, but the added WAL samples do not fit.
        s['nodes'] = [{'name': 'kata-' + str(i), 'node_uid': str(uuid.UUID(int=i + 1)),
                       'host_boot_id': str(uuid.UUID(int=i + 101)), 'private_ip': '10.80.40.' + str(i + 10)} for i in range(16)]
        s['wal_gib'] = 97
        inventory = {name: n for name, n in tf['node_inventory']['value'].items() if n['role'] == 'platform'}
        inventory.update({n['name']: {'id': 'i-test-' + str(i), 'private_ip': n['private_ip'], 'role': 'kata', 'zone': 'cn-hangzhou-h'} for i, n in enumerate(s['nodes'])})
        tf['node_inventory']['value'] = inventory
        self.assertLessEqual(16 * 256 * 6 * 1440 * 1024 * 2, int(97 * 1024 ** 3 * 0.7))
        with self.assertRaisesRegex(ValueError, '^WAL_CAPACITY$'):
            validate(s, tf, u)

    def test_url_credentials_redirect_hosts_and_http_are_not_accepted(self):
        for u in ['http://ts-x.hitsdb.rds.aliyuncs.com:3242/api/prom_write', 'https://ts-x.hitsdb.rds.aliyuncs.com:3242/api/prom_write?token=secret', 'https://user:password@ts-x.hitsdb.rds.aliyuncs.com:3242/api/prom_write', 'https://cn-hangzhou.arms.aliyuncs.com/prometheus/secret/region/api/v3/write', 'https://ts-x.hitsdb.rds.aliyuncs.com.attacker.invalid/api/prom_write', 'https://127.0.0.1/api/prom_write', 'https://ts-x.hitsdb.rds.aliyuncs.com/api%2Fprom_write', 'https://ts-x.hitsdb.rds.aliyuncs.com:8443/api/prom_write', 'https://ts-x.hitsdb.rds.aliyuncs.com/api/prom_write#fragment']:
            with self.subTest(url=u), self.assertRaises(ValueError): endpoint(u)

    def test_inventory_identity_and_capacity_fail_closed(self):
        s, tf, u = fixture()
        for mutate in [lambda x: x.update(deployment='foreign'), lambda x: x.update(cluster_epoch=str(uuid.UUID(int=0))), lambda x: x.update(wal_gib=1), lambda x: x['nodes'][0].update(private_ip='127.0.0.1'), lambda x: x['nodes'][0].update(private_ip='10.80.20.10'), lambda x: x['nodes'][0].update(node_uid=x['nodes'][1]['node_uid']), lambda x: x['nodes'].pop(), lambda x: x.update(unreviewed=True)]:
            bad = copy.deepcopy(s); mutate(bad)
            with self.assertRaises(ValueError): validate(bad, tf, u)
        many = copy.deepcopy(s); many['nodes'] *= 100
        with self.assertRaises(ValueError): validate(many,tf,u)
        one_zone=copy.deepcopy(tf)
        for n in one_zone['node_inventory']['value'].values(): n['zone']='single-zone'
        with self.assertRaises(ValueError):validate(s,one_zone,u)
        self.assertFalse(capacity(s)['lossless_guarantee'])

    def test_namespace_network_does_not_inherit_trusted_bootstrap_or_guest_reachability(self):
        s, tf, u = fixture(); values=resources(s,validate(s,tf,u),u)
        cnp=next(v for v in values if v['kind']=='CiliumNetworkPolicy')
        self.assertEqual(cnp['metadata']['namespace'],'sandbox-observability')
        text=json.dumps(cnp)
        for forbidden in ['remote-node','0.0.0.0/0','world','kube-apiserver','sandbox-system']:
            self.assertNotIn(forbidden,text)
        ports=[p['port'] for r in cnp['spec']['egress'] for t in r.get('toPorts',[]) for p in t['ports']]
        self.assertEqual(set(ports),{'53','9445','3242'})
        nodes=next(r['toNodes'] for r in cnp['spec']['egress'] if 'toNodes' in r)
        self.assertEqual(nodes,[{'matchLabels':{'kubernetes.io/hostname':n['name'],'sandbox.platform/node-pool':'kata'}} for n in s['nodes']])
        host=next(v for v in values if v['kind']=='CiliumClusterwideNetworkPolicy')
        self.assertEqual(host['spec']['ingress'][0]['fromEndpoints'][0]['matchLabels']['k8s:io.kubernetes.pod.namespace'],'sandbox-observability')
        self.assertEqual(host['spec']['ingress'][0]['toPorts'][0]['ports'],[{'port':'9445','protocol':'TCP'}])

    def test_renderer_outputs_private_files_and_does_not_overwrite(self):
        s,tf,u=fixture()
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp); (p/'s').write_text(json.dumps(s));(p/'tf').write_text(json.dumps(tf));(p/'url').write_text(u);(p/'url').chmod(0o600)
            render(p/'s',p/'tf',p/'url',p/'out')
            self.assertEqual((p/'out').stat().st_mode & 0o777,0o700)
            self.assertEqual({f.name for f in (p/'out').iterdir()},
                             {'manifest.yaml', 'capacity.json', 'alerts.rules.yaml', 'prometheus-a.yaml', 'prometheus-b.yaml'})
            alerts = yaml.safe_load((p/'out'/'alerts.rules.yaml').read_text())
            self.assertEqual(alerts['groups'][0]['name'], 'sandbox-metrics-collection-' + s['cluster_epoch'])
            for f in (p/'out').iterdir():self.assertEqual(f.stat().st_mode & 0o777,0o600)
            with self.assertRaises(FileExistsError):render(p/'s',p/'tf',p/'url',p/'out')
            (p/'url').chmod(0o644)
            with self.assertRaises(ValueError):render(p/'s',p/'tf',p/'url',p/'other')


if __name__=='__main__':unittest.main()
