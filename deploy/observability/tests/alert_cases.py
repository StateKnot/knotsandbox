"""Promtool cases for real native-series rules; no VM samples or cloud writes.

The caller writes rules(settings) to rule_file and this document beside it,
then runs the already locked image's promtool test rules. Expectations below
are scenario declarations; rule expressions are not evaluated by Python.
"""
from __future__ import annotations

import json
import copy

from alerts import SELF_METRICS, rules


def cases(settings, rule_file='alerts.rules.yaml'):
    node = sorted(settings['nodes'], key=lambda item: item['node_uid'])[0]
    emitted = rules(settings)['groups'][0]['rules']
    names = sorted({rule['alert'] for rule in emitted})
    tests = []

    def series_name(metric, replica, target=None, **overrides):
        labels = {'deployment': settings['deployment'], 'cluster_epoch': settings['cluster_epoch'],
                  'collector_replica': replica, 'instance': 'fixture-' + replica,
                  'job': 'sandbox-agent' if target is None else 'nodeguard-' + target['node_uid']}
        if target:
            labels.update(scrape_node_uid=target['node_uid'], scrape_host_boot_id=target['host_boot_id'])
        labels.update(overrides)
        return metric + '{' + ','.join(key + '=' + json.dumps(value) for key, value in labels.items()) + '}'

    def build(minutes):
        values = {}
        for replica in ('a', 'b'):
            values[series_name('up', replica)] = '1+0x' + str(minutes)
            for target in settings['nodes']:
                values[series_name('up', replica, target)] = '1+0x' + str(minutes)
            for metric in SELF_METRICS:
                initial = 1 if metric == SELF_METRICS[4] else 10000 if metric == SELF_METRICS[5] else 0
                values[series_name(metric, replica)] = str(initial) + '+0x' + str(minutes)
            values[series_name(SELF_METRICS[3], replica)] = '1+60x' + str(minutes)
        return values

    def expected(name, replica=None, target=None):
        result = []
        for rule in emitted:
            if rule['alert'] != name:
                continue
            label = rule['labels']
            if label.get('collector_replica') != replica:
                continue
            if label.get('scrape_node_uid') != (target['node_uid'] if target else None):
                continue
            result.append({'exp_labels': label, 'exp_annotations': rule['annotations']})
        if len(result) != 1:
            raise ValueError('ALERT_CASE_IDENTITY')
        return name, result[0]

    def add(description, minutes, mutate=None, checks=()):
        values = build(minutes)
        if mutate:
            mutate(values, minutes)
        expected_by_name = {name: [] for name in names}
        for name, value in checks:
            expected_by_name[name].append(value)
        tests.append({'name': description, 'interval': '1m',
                      'input_series': [{'series': key, 'values': value} for key, value in values.items()],
                      'alert_rule_test': [{'eval_time': str(minutes) + 'm', 'alertname': name,
                                           'exp_alerts': expected_by_name[name]} for name in names]})

    def replace(values, minutes, metric, replica, value, target=None):
        values[series_name(metric, replica, target)] = str(value) + '+0x' + str(minutes)

    def stopped(values, minutes, metric, replica, target=None):
        values[series_name(metric, replica, target)] = ' '.join(['1'] * 5 + ['stale'] + ['_'] * (minutes - 5))

    add('healthy idle with no raw VM series', 20)
    add('single node scrape down is warning only', 5,
        lambda v, m: replace(v, m, 'up', 'a', 0, node),
        [expected('SandboxNodeguardCollectorReplicaUnavailable', 'a', node)])
    add('both node scrapes down with healthy collectors', 5,
        lambda v, m: [replace(v, m, 'up', replica, 0, node) for replica in ('a', 'b')],
        [expected('SandboxNodeguardCollectorsUnavailable', target=node)])
    add('both node scrapes absent with healthy collectors', 5,
        lambda v, m: [v.pop(series_name('up', replica, node)) for replica in ('a', 'b')],
        [expected('SandboxNodeguardCollectorsUnavailable', target=node)])
    add('stale formerly healthy node samples are not healthy', 9,
        lambda v, m: [stopped(v, m, 'up', replica, node) for replica in ('a', 'b')],
        [expected('SandboxNodeguardCollectorsUnavailable', target=node)])
    add('single collector self scrape down is warning only', 5,
        lambda v, m: replace(v, m, 'up', 'a', 0),
        [expected('SandboxMetricsCollectorReplicaUnavailable', 'a')])
    add('both collector self scrapes down are critical', 5,
        lambda v, m: [replace(v, m, 'up', replica, 0) for replica in ('a', 'b')],
        [expected('SandboxMetricsCollectorsUnavailable')])
    add('whole collector loss suppresses per-node alert flood', 9,
        lambda v, m: [v.update({key: ' '.join(['1'] * 5 + ['stale'] + ['_'] * (m - 5))}) for key in list(v)],
        [expected('SandboxMetricsCollectorsUnavailable')])

    def foreign_boot(values, minutes):
        for replica in ('a', 'b'):
            values.pop(series_name('up', replica, node))
            values[series_name('up', replica, node, scrape_host_boot_id='00000000-0000-0000-0000-000000000fff')] = '1+0x' + str(minutes)

    def foreign_epoch(values, minutes):
        original = list(values.items())
        values.clear()
        for key, value in original:
            values[key.replace(settings['cluster_epoch'], '00000000-0000-0000-0000-000000000ffe')] = value

    add('foreign boot cannot replace reviewed node health', 5, foreign_boot,
        [expected('SandboxNodeguardCollectorsUnavailable', target=node)])
    add('foreign epoch cannot replace reviewed collectors', 5, foreign_epoch,
        [expected('SandboxMetricsCollectorsUnavailable')])
    # The same target recovers; its prior for state must clear without a new
    # label identity. Check both firing and recovery in one promtool scenario.
    add('node outage fires before recovery', 6,
        lambda v, m: [replace(v, m, 'up', replica, 0, node) for replica in ('a', 'b')],
        [expected('SandboxNodeguardCollectorsUnavailable', target=node)])
    add('same node identity recovers and clears critical', 8,
        lambda v, m: [v.update({series_name('up', replica, node): '0+0x6 1 1'}) for replica in ('a', 'b')])
    fired_name, fired = expected('SandboxNodeguardCollectorsUnavailable', target=node)
    tests[-1]['alert_rule_test'] += [
        {'eval_time': '6m', 'alertname': name, 'exp_alerts': [fired] if name == fired_name else []}
        for name in names]
    add('brief both-side outage does not satisfy for', 1,
        lambda v, m: [replace(v, m, 'up', replica, 0, node) for replica in ('a', 'b')])
    add('native counter reset does not create an error increase', 7,
        lambda v, m: [v.update({series_name(metric, replica): '10 10 10 0 0 0 0 0'})
                      for replica in ('a', 'b') for metric in (SELF_METRICS[1], SELF_METRICS[2], SELF_METRICS[7], SELF_METRICS[8])])
    add('single actual failed-sample counter increase', 7,
        lambda v, m: v.update({series_name(SELF_METRICS[1], 'a'): '0 0 0 0 0 100 100 100'}),
        [expected('SandboxMetricsRemoteSamplesFailed', 'a')])
    add('both actual failed-sample counters increase', 7,
        lambda v, m: [v.update({series_name(SELF_METRICS[1], replica): '0 0 0 0 0 100 100 100'}) for replica in ('a', 'b')],
        [expected('SandboxMetricsRemoteSamplesFailed', 'a'), expected('SandboxMetricsRemoteSamplesFailed', 'b'),
         expected('SandboxMetricsRemoteSamplesFailedBothReplicas')])
    add('retry counter is not a nonexistent dropped-sample metric', 7,
        lambda v, m: v.update({series_name(SELF_METRICS[2], 'a'): '0+1x' + str(m)}),
        [expected('SandboxMetricsRemoteRetriesSustained', 'a')])
    add('pending below actual four-shard capacity is not saturation', 7,
        lambda v, m: [replace(v, m, SELF_METRICS[0], 'a', 9000), replace(v, m, SELF_METRICS[4], 'a', 4)])
    add('queue exactly eighty percent does not exceed threshold', 7,
        lambda v, m: replace(v, m, SELF_METRICS[0], 'a', 8000))
    add('single queue near actual shard capacity', 7,
        lambda v, m: replace(v, m, SELF_METRICS[0], 'a', 8001),
        [expected('SandboxMetricsQueueNearCapacity', 'a')])
    add('both queues near actual shard capacity', 7,
        lambda v, m: [replace(v, m, SELF_METRICS[0], replica, 8001) for replica in ('a', 'b')],
        [expected('SandboxMetricsQueueNearCapacity', 'a'), expected('SandboxMetricsQueueNearCapacity', 'b'),
         expected('SandboxMetricsQueueNearCapacityBothReplicas')])
    add('idle zero delivery timestamp has no lag alert', 30,
        lambda v, m: [replace(v, m, SELF_METRICS[3], replica, 0) for replica in ('a', 'b')])
    add('first pending at zero delivery is not immediate retention risk', 7,
        lambda v, m: [replace(v, m, SELF_METRICS[0], replica, 100) or replace(v, m, SELF_METRICS[3], replica, 0) for replica in ('a', 'b')])
    add('single never-confirmed delivery warns after fifteen minutes', 16,
        lambda v, m: [replace(v, m, SELF_METRICS[0], 'a', 100), replace(v, m, SELF_METRICS[3], 'a', 0)],
        [expected('SandboxMetricsDeliveryNotConfirmed', 'a')])
    add('single confirmed delivery lag warns after fifteen minutes', 21,
        lambda v, m: [replace(v, m, SELF_METRICS[0], 'a', 100), replace(v, m, SELF_METRICS[3], 'a', 1)],
        [expected('SandboxMetricsDeliveryLag', 'a')])
    add('one confirmed four-hour lag does not make healthy copy critical', 247,
        lambda v, m: [replace(v, m, SELF_METRICS[0], 'a', 100), replace(v, m, SELF_METRICS[3], 'a', 1)],
        [expected('SandboxMetricsDeliveryLag', 'a')])
    add('both confirmed delivery lags warn before six-hour retention', 247,
        lambda v, m: [replace(v, m, SELF_METRICS[0], replica, 100) or replace(v, m, SELF_METRICS[3], replica, 1) for replica in ('a', 'b')],
        [expected('SandboxMetricsDeliveryLag', 'a'), expected('SandboxMetricsDeliveryLag', 'b'),
         expected('SandboxMetricsDeliveryRetentionRisk')])
    add('pending without fresh metric is unavailable not zero', 5,
        lambda v, m: v.pop(series_name(SELF_METRICS[0], 'a')),
        [expected('SandboxMetricsAgentTelemetryIncomplete', 'a')])
    add('single actual WAL exceeds configured seventy-percent budget', 7,
        lambda v, m: replace(v, m, SELF_METRICS[6], 'a', settings['wal_gib'] * 1024 ** 3 * 8 // 10),
        [expected('SandboxMetricsWalBudgetExceeded', 'a')])
    add('single actual WAL write failure', 7,
        lambda v, m: v.update({series_name(SELF_METRICS[7], 'a'): '0 0 0 0 0 1 1 1'}),
        [expected('SandboxMetricsWalWritesFailed', 'a')])
    add('both actual WAL corruptions', 7,
        lambda v, m: [v.update({series_name(SELF_METRICS[8], replica): '0 0 0 0 0 1 1 1'}) for replica in ('a', 'b')],
        [expected('SandboxMetricsWalCorruptions', 'a'), expected('SandboxMetricsWalCorruptions', 'b'),
         expected('SandboxMetricsWalCorruptionsBothReplicas')])
    add('collector outage suppresses node replica warning flood', 5,
        lambda v, m: [replace(v, m, 'up', replica, 0) for replica in ('a', 'b')] +
                     [replace(v, m, 'up', 'a', 0, target) for target in settings['nodes']],
        [expected('SandboxMetricsCollectorsUnavailable')])
    # WAL recovery can fail before the first self-scrape. An already positive
    # startup counter must remain visible without a later observed increase.
    add('startup WAL corruption is positive at first observation', 5,
        lambda v, m: replace(v, m, SELF_METRICS[8], 'a', 1),
        [expected('SandboxMetricsWalCorruptions', 'a')])
    add('startup WAL write failure is positive at first observation', 5,
        lambda v, m: replace(v, m, SELF_METRICS[7], 'a', 1),
        [expected('SandboxMetricsWalWritesFailed', 'a')])
    add('lost remote samples are positive at first observation', 5,
        lambda v, m: replace(v, m, SELF_METRICS[1], 'a', 100),
        [expected('SandboxMetricsRemoteSamplesFailed', 'a')])
    add('new process zero clears previously positive failed-sample counter', 5,
        lambda v, m: v.update({series_name(SELF_METRICS[1], 'a'): '100 100 100 0 0 0'}))
    failed_name, failed = expected('SandboxMetricsRemoteSamplesFailed', 'a')
    tests[-1]['alert_rule_test'] += [
        {'eval_time': '2m', 'alertname': name, 'exp_alerts': [failed] if name == failed_name else []}
        for name in names]
    # Missing samples without stale markers remain in Prometheus's lookback.
    # At exactly 60s they must stop being fresh, so for:2m fires at 180s.
    add('healthy samples without stale markers expire at exactly sixty seconds', 3,
        lambda v, m: [v.update({series_name('up', replica): '1 _ _ _'}) for replica in ('a', 'b')],
        [expected('SandboxMetricsCollectorsUnavailable')])
    add('native metrics without stale markers expire at exactly sixty seconds', 3,
        lambda v, m: v.update({series_name(SELF_METRICS[0], 'a'): '0 _ _ _'}),
        [expected('SandboxMetricsAgentTelemetryIncomplete', 'a')])
    return {'rule_files': [rule_file], 'evaluation_interval': '15s', 'tests': tests}


def node_image_cases(settings, rule_file='alerts.rules.yaml'):
    """Replay optional node reports independently of the unchanged VM cases."""
    clean = copy.deepcopy(settings)
    for node in clean['nodes']:
        node.pop('image_profile_sha256', None)
    baseline = cases(clean)['tests'][0]['input_series']
    node = next(n for n in settings['nodes'] if 'image_profile_sha256' in n)
    prefix = 'sandbox_node_image_'
    names = ('SandboxNodeImageCollectorsUnavailable', 'SandboxNodeImageCollectorReplicaUnavailable',
             'SandboxNodeImageReportUnavailable', 'SandboxNodeImageReportReplicaUnavailable')
    tests = []

    def series(metric, replica, **overrides):
        labels = {'deployment': settings['deployment'], 'cluster_epoch': settings['cluster_epoch'],
                  'collector_replica': replica, 'job': 'node-images-' + node['node_uid'], 'instance': 'fixture-' + replica}
        if metric == 'up':
            labels.update(scrape_node_uid=node['node_uid'], scrape_host_boot_id=node['host_boot_id'],
                          scrape_profile_sha256=node['image_profile_sha256'])
        else:
            labels.update(node_uid=node['node_uid'], host_boot_id=node['host_boot_id'], profile_sha256=node['image_profile_sha256'],
                          source='RUNTIME_REPORTED', completeness='UNKNOWN')
        labels.update(overrides)
        return metric + '{' + ','.join(key + '=' + json.dumps(value) for key, value in labels.items()) + '}'

    def expected(name, replica=None, component='node-image-scrape'):
        identity = {'deployment': settings['deployment'], 'cluster_epoch': settings['cluster_epoch'],
                    'component': component, 'owner': 'platform', 'severity': 'warning' if replica else 'critical',
                    'scrape_node_uid': node['node_uid'], 'scrape_host_boot_id': node['host_boot_id'],
                    'scrape_profile_sha256': node['image_profile_sha256']}
        if replica:
            identity['collector_replica'] = replica
        summary = {'SandboxNodeImageCollectorsUnavailable': '该固定节点镜像端点两个采集副本均无新鲜成功抓取。',
                   'SandboxNodeImageCollectorReplicaUnavailable': '该固定节点镜像端点一个采集副本抓取失败或陈旧，另一副本仍健康。',
                   'SandboxNodeImageReportUnavailable': '该固定节点镜像组件没有新鲜成功报告；UNKNOWN 不能当作零值。',
                   'SandboxNodeImageReportReplicaUnavailable': '该固定节点镜像组件一个副本没有新鲜成功报告，另一副本仍健康。'}[name]
        return name, {'exp_labels': identity, 'exp_annotations': {'summary': summary,
                      'runbook': 'deploy/observability/README.md#监控采集链告警'}}

    def add(description, mutate=None, checks=(), minutes=5, interval_seconds=60):
        values = {row['series']: row['values'] for row in baseline}
        points = minutes * 60 // interval_seconds
        for replica in ('a', 'b'):
            values[series('up', replica)] = '1+0x' + str(points)
            for component in ('inventory', 'filesystem'):
                values[series(prefix + component + '_observation_success', replica)] = '1+0x' + str(points)
            values[series(prefix + 'observed_at_seconds', replica)] = '1+' + str(interval_seconds) + 'x' + str(points)
        if mutate:
            mutate(values, points)
        expected_by_name = {name: [] for name in names}
        for name, value in checks:
            expected_by_name[name].append(value)
        tests.append({'name': description, 'interval': str(interval_seconds) + 's',
                      'input_series': [{'series': key, 'values': value} for key, value in values.items()],
                      'alert_rule_test': [{'eval_time': str(minutes) + 'm', 'alertname': name,
                                           'exp_alerts': expected_by_name[name]} for name in names]})

    def set_value(values, minutes, metric, replica, value, **overrides):
        values[series(metric, replica, **overrides)] = str(value) + '+0x' + str(minutes)

    add('node images healthy with successful empty filesystem report')
    add('node image endpoint one-side 503 leaves VM and self healthy',
        lambda v, m: set_value(v, m, 'up', 'a', 0), [expected(names[1], 'a')])
    add('node image endpoints both 503 leave VM and self healthy',
        lambda v, m: [set_value(v, m, 'up', r, 0) for r in ('a', 'b')], [expected(names[0])])
    for component in ('inventory', 'filesystem'):
        metric = prefix + component + '_observation_success'
        label = 'node-image-' + component
        add(component + ' UNKNOWN on one replica with HTTP 200',
            lambda v, m, metric=metric: set_value(v, m, metric, 'a', 0), [expected(names[3], 'a', label)])
        add(component + ' UNKNOWN on both replicas with HTTP 200',
            lambda v, m, metric=metric: [set_value(v, m, metric, r, 0) for r in ('a', 'b')], [expected(names[2], component=label)])
        add(component + ' report success marker missing on one replica',
            lambda v, m, metric=metric: v.pop(series(metric, 'a')), [expected(names[3], 'a', label)])
    critical_reports = [expected(names[2], component='node-image-' + c) for c in ('inventory', 'filesystem')]
    add('node image endpoints absent with VM still healthy',
        lambda v, m: [v.pop(series('up', r)) for r in ('a', 'b')], [expected(names[0])])
    add('node image endpoint samples expire at exactly sixty seconds',
        lambda v, m: [v.update({series('up', r): '1 _ _ _'}) for r in ('a', 'b')], [expected(names[0])], minutes=3)
    add('brief image endpoint loss does not bypass two minute for',
        lambda v, m: [set_value(v, m, 'up', r, 0) for r in ('a', 'b')], minutes=1)
    for field in ('scrape_profile_sha256', 'scrape_host_boot_id', 'cluster_epoch'):
        def wrong_target(values, minutes, field=field):
            for replica in ('a', 'b'):
                values.pop(series('up', replica))
                value = 'b' * 64 if field == 'scrape_profile_sha256' else '00000000-0000-0000-0000-000000000fff'
                set_value(values, minutes, 'up', replica, 1, **{field: value})
        add('foreign image target ' + field + ' is not healthy', wrong_target, [expected(names[0])])
    for original, checks, description in [('0+60x5', [], 'current report'),
                                          ('-59.999+60x5', [], 'report just inside sixty seconds'),
                                          ('-60+60x5', critical_reports, 'report exactly sixty seconds old'),
                                          ('5+60x5', [], 'report exactly five seconds in future'),
                                          ('5.001+60x5', critical_reports, 'report beyond five seconds in future'),
                                          ('NaN+0x5', critical_reports, 'report NaN is not fresh')]:
        original = original.replace('+60x5', '+15x20').replace('+0x5', '+0x20')
        add(description, lambda v, m, original=original: [v.update({series(prefix + 'observed_at_seconds', r): original}) for r in ('a', 'b')], checks, interval_seconds=15)
    add('original collector time missing on both replicas',
        lambda v, m: [v.pop(series(prefix + 'observed_at_seconds', r)) for r in ('a', 'b')], critical_reports)
    add('original collector metric samples also expire at sixty seconds',
        lambda v, m: [v.update({series(prefix + 'observed_at_seconds', r): '1 _ _ _'}) for r in ('a', 'b')], critical_reports, minutes=3)
    for field in ('profile_sha256', 'host_boot_id', 'cluster_epoch', 'source', 'completeness'):
        def wrong_report(values, minutes, field=field):
            for replica in ('a', 'b'):
                for metric in (prefix + 'observed_at_seconds', prefix + 'inventory_observation_success', prefix + 'filesystem_observation_success'):
                    values.pop(series(metric, replica))
                    foreign = 'b' * 64 if field == 'profile_sha256' else 'FOREIGN' if field in ('source', 'completeness') else '00000000-0000-0000-0000-000000000fff'
                    values[series(metric, replica, **{field: foreign})] = ('1+60x' if metric.endswith('observed_at_seconds') else '1+0x') + str(minutes)
        add('foreign raw image ' + field + ' cannot authorize a report', wrong_report, critical_reports)
    for original, bad, description in [('-59.999+60x5', False, 'FS original time just inside sixty seconds'),
                                        ('-60+60x5', True, 'FS original time exactly sixty seconds old'),
                                        ('5+60x5', False, 'FS original time exactly five seconds in future'),
                                        ('5.001+60x5', True, 'FS original time beyond five seconds in future')]:
        original = original.replace('+60x5', '+15x20')
        add(description, lambda v, m, original=original: [v.update({series(prefix + 'filesystem_reported_at_seconds', r, filesystem_id='c' * 64): original}) for r in ('a', 'b')],
            [expected(names[2], component='node-image-filesystem')] if bad else [], interval_seconds=15)
    add('FS value without same identity original runtime time is missing',
        lambda v, m: [set_value(v, m, prefix + 'filesystem_used_bytes', r, 0, filesystem_id='c' * 64) for r in ('a', 'b')],
        [expected(names[2], component='node-image-filesystem')])
    add('one FS original timestamp is stale while other replica is healthy',
        lambda v, m: v.update({series(prefix + 'filesystem_reported_at_seconds', 'a', filesystem_id='c' * 64): '-60+60x5'}),
        [expected(names[3], 'a', 'node-image-filesystem')])
    add('one endpoint unavailable and remaining inventory UNKNOWN are not healthy redundancy',
        lambda v, m: [set_value(v, m, 'up', 'a', 0), set_value(v, m, prefix + 'inventory_observation_success', 'b', 0)],
        [expected(names[1], 'a'), expected(names[2], component='node-image-inventory')])
    add('whole collector outage suppresses all optional node alerts',
        lambda v, m: [v.update({key: '0+0x' + str(m)}) for key in v if key.startswith('up{')])
    add('image endpoint recovers under identical alert identity',
        lambda v, m: [v.update({series('up', r): '0+0x2 1+0x3'}) for r in ('a', 'b')], minutes=6)
    name, fired = expected(names[0])
    tests[-1]['alert_rule_test'].append({'eval_time': '2m', 'alertname': name, 'exp_alerts': [fired]})
    add('inventory UNKNOWN clears after same identity recovery',
        lambda v, m: [v.update({series(prefix + 'inventory_observation_success', r): '0+0x2 1+0x3'}) for r in ('a', 'b')], minutes=6)
    name, fired = expected(names[2], component='node-image-inventory')
    tests[-1]['alert_rule_test'].append({'eval_time': '2m', 'alertname': name, 'exp_alerts': [fired]})
    return {'rule_files': [rule_file], 'evaluation_interval': '15s', 'tests': tests}
