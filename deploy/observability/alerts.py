"""Managed-backend rules for the fixed dual-agent collection contract.

The existing renderer must call validate before rules. Agents never evaluate
this file. Native self-metric names were observed in the locked 3.13.4 image.
"""
from __future__ import annotations

import json
from observability import SELF_METRICS


def rules(settings):
    """Return standard Prometheus rules from already validated settings."""
    deployment, epoch = settings['deployment'], settings['cluster_epoch']
    labels = {'deployment': deployment, 'cluster_epoch': epoch,
              'component': 'metrics-collection', 'owner': 'platform'}
    output = []

    def selector(metric, replica=None, node=None):
        values = {'deployment': deployment, 'cluster_epoch': epoch}
        if node is None:
            values['job'] = 'sandbox-agent'
        else:
            values.update(job='nodeguard-' + node['node_uid'],
                          scrape_node_uid=node['node_uid'],
                          scrape_host_boot_id=node['host_boot_id'])
        text = ','.join(key + '=' + json.dumps(value) for key, value in values.items())
        text += ',collector_replica' + ('=' + json.dumps(replica) if replica else '=~"a|b"')
        return metric + '{' + text + '}'

    def fresh(metric, replica=None, node=None):
        value = selector(metric, replica, node)
        return '(' + value + ' and (timestamp(' + value + ') > time() - 60))'

    def healthy(replica=None, node=None):
        return 'sum(' + fresh('up', replica, node) + ' == 1) > 0'

    def missing(replica=None, node=None):
        return 'sum(absent(' + fresh('up', replica, node) + ' == 1)) > 0'

    def add(name, expr, duration, severity, summary, replica=None, node=None):
        identity = dict(labels, severity=severity)
        if replica:
            identity['collector_replica'] = replica
        if node:
            identity.update(scrape_node_uid=node['node_uid'],
                            scrape_host_boot_id=node['host_boot_id'])
        output.append({'alert': name, 'expr': expr, 'for': duration,
                       'labels': identity,
                       'annotations': {'summary': summary,
                                       'runbook': 'deploy/observability/README.md#监控采集链告警'}})

    add('SandboxMetricsCollectorsUnavailable', missing(), '2m', 'critical',
        '两个采集副本均无新鲜健康样本；检查远程写入、采集进程和身份配置。')
    for replica, other in [('a', 'b'), ('b', 'a')]:
        add('SandboxMetricsCollectorReplicaUnavailable',
            '(' + missing(replica) + ') and (' + healthy(other) + ')', '2m', 'warning',
            '一个采集副本不可用，另一副本仍健康；恢复独立采集与 WAL。', replica)
    for node in sorted(settings['nodes'], key=lambda item: item['node_uid']):
        add('SandboxNodeguardCollectorsUnavailable',
            '(' + missing(node=node) + ') and (' + healthy() + ')', '2m', 'critical',
            '该固定节点两个采集副本均无新鲜成功抓取；空闲实例不是故障判据。', node=node)
        for replica, other in [('a', 'b'), ('b', 'a')]:
            add('SandboxNodeguardCollectorReplicaUnavailable',
                '(' + missing(replica, node) + ') and (' + healthy(other, node) + ') and (' + healthy() + ')',
                '2m', 'warning', '该固定节点一个采集副本抓取失败或陈旧，另一副本仍健康。',
                replica, node)

    def gauge(metric, replica):
        return 'sum(' + fresh(metric, replica) + ')'

    def increase(metric, replica):
        value = selector(metric, replica)
        return '(sum(increase(' + value + '[5m]) and ' + fresh(metric, replica) + ') > 0)'

    def queue(replica):
        pending = gauge(SELF_METRICS[0], replica)
        shards, capacity = gauge(SELF_METRICS[4], replica), gauge(SELF_METRICS[5], replica)
        return '(' + pending + ' > 0) and (' + shards + ' > 0) and (' + capacity + ' > 0) and (' + pending + ' / (' + shards + ' * ' + capacity + ') > 0.8)'

    def lag(replica, seconds):
        sent = 'max(' + fresh(SELF_METRICS[3], replica) + ')'
        return '(' + gauge(SELF_METRICS[0], replica) + ' > 0) and (' + sent + ' > 0) and (time() - ' + sent + ' > ' + str(seconds) + ')'

    def wal_size(replica):
        return '(' + gauge(SELF_METRICS[6], replica) + ' > ' + str(settings['wal_gib'] * 1024 ** 3 * 7 // 10) + ')'

    conditions = [
        ('SandboxMetricsRemoteSamplesFailed', lambda r: gauge(SELF_METRICS[1], r) + ' > 0', '1m',
         '本进程远程写入记录过不可恢复样本失败；核验数据缺口，不能假定 WAL 会补回。'),
        ('SandboxMetricsRemoteRetriesSustained', lambda r: increase(SELF_METRICS[2], r), '5m',
         '远程写入持续重试；检查网络、限流与后端状态。'),
        ('SandboxMetricsQueueNearCapacity', queue, '5m',
         '真实待发送队列超过当前 shards 与单 shard 容量的 80%。'),
        ('SandboxMetricsWalBudgetExceeded', wal_size, '5m',
         '实际 WAL 字节超过该副本配置容量的 70% 预算；核验卷剩余容量与送达。'),
        ('SandboxMetricsWalWritesFailed', lambda r: gauge(SELF_METRICS[7], r) + ' > 0', '1m',
         '本进程记录过 WAL 写入失败；检查卷、权限和可恢复性。'),
        ('SandboxMetricsWalCorruptions', lambda r: gauge(SELF_METRICS[8], r) + ' > 0', '1m',
         '本进程的 WAL 恢复报告损坏；核验数据缺口并保留故障材料。'),
    ]
    for name, condition, duration, summary in conditions:
        for replica in ('a', 'b'):
            add(name, condition(replica), duration, 'warning', summary, replica)
        # One impaired replica is a warning. Critical requires both independent
        # copies to show the same actual problem; no counter sums across copies.
        add(name + 'BothReplicas', '(' + condition('a') + ') and (' + condition('b') + ')',
            duration, 'critical', summary)
    for replica in ('a', 'b'):
        add('SandboxMetricsDeliveryLag', lag(replica, 900), '5m', 'warning',
            '有真实积压且最高已送达样本落后 15 分钟；在六小时强制截断前处理。', replica)
        add('SandboxMetricsDeliveryNotConfirmed',
            '(' + gauge(SELF_METRICS[0], replica) + ' > 0) and (max(' + fresh(SELF_METRICS[3], replica) + ') <= 0)',
            '15m', 'warning', '真实积压持续十五分钟但尚无已送达时间；不将初始零值伪称四小时延迟。', replica)
        unavailable = ' or '.join('sum(absent(' + fresh(metric, replica) + ')) > 0' for metric in SELF_METRICS)
        add('SandboxMetricsAgentTelemetryIncomplete', '(' + unavailable + ') and (' + healthy(replica) + ')',
            '2m', 'warning', '采集副本健康样本存在，但固定自身指标缺失或陈旧；核验白名单与固定镜像。', replica)
    add('SandboxMetricsDeliveryRetentionRisk', '(' + lag('a', 14400) + ') and (' + lag('b', 14400) + ')',
        '5m', 'critical', '两副本都有真实积压且已送达落后四小时；立即排查六小时强制 WAL 截断风险。')
    return {'groups': [{'name': 'sandbox-metrics-collection-' + epoch, 'interval': '15s', 'rules': output}]}
