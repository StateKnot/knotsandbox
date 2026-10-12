"""Promtool cases for real native-series rules; no VM samples or cloud writes.

The caller writes rules(settings) to rule_file and this document beside it,
then runs the already locked image's promtool test rules. Expectations below
are scenario declarations; rule expressions are not evaluated by Python.
"""
from __future__ import annotations

import json

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
