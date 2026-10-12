#!/usr/bin/env python3
"""Render narrowly scoped backup Jobs and verify live CSI prerequisites without starting a VM."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import time

from backup import canonical, config, decode, read, require, run, sha, timestamp, uuid_text

LABEL = 'sandbox.platform/backup-id'
PURPOSE = 'sandbox.platform/purpose'
NS = 'sandbox-system'


def settings(path):
    value = decode(read(path))
    require(set(value) == {'image', 'runtime_class', 'runtime_handler', 'storage_class', 'snapshot_class',
                           'dns_namespace', 'dns_labels', 'secrets', 'certification_report_sha256'}, 'DEPLOYMENT_FIELDS')
    require(re.fullmatch(r'[a-z0-9.-]+(?::[0-9]+)?/[a-zA-Z0-9/_-]+@sha256:[0-9a-f]{64}', value['image']), 'PINNED_IMAGE')
    require(value['runtime_class'] == 'kata-backup-qemu' and value['runtime_handler'] == 'kata-qemu', 'MANAGED_KATA_REQUIRED')
    for key in ('storage_class', 'snapshot_class', 'dns_namespace'):
        require(re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,62}', value[key]), 'K8S_NAME')
    require(value['dns_namespace'] == 'kube-system' and value['dns_labels'] == {'k8s-app': 'kube-dns'}, 'DNS_IDENTITY')
    require(set(value['secrets']) == {'password', 'signing_private', 'signing_public'}, 'SECRET_FIELDS')
    require(len(set(value['secrets'].values())) == 3, 'SEPARATE_SECRETS')
    require(all(re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,62}', x) for x in value['secrets'].values()), 'SECRET_NAME')
    require(sha(value['certification_report_sha256']), 'CERTIFICATION_REFERENCE')
    return value


def obj(api, kind, name, spec=None, **extra):
    value = {'apiVersion': api, 'kind': kind, 'metadata': {'name': name, 'namespace': NS,
             'labels': {'app.kubernetes.io/managed-by': 'sandbox-backup'}}}
    if spec is not None:
        value['spec'] = spec
    value.update(extra)
    return value


def foundations(s, c):
    selector = {'matchExpressions': [{'key': LABEL, 'operator': 'Exists'}]}
    values = [obj('v1', 'ServiceAccount', 'sandbox-' + role, automountServiceAccountToken=False)
              for role in ('backup', 'backup-export', 'restore')]
    values.append(obj('networking.k8s.io/v1', 'NetworkPolicy', 'sandbox-backup-default-deny', {
        'podSelector': selector, 'policyTypes': ['Ingress', 'Egress']}))
    dns = {'k8s:io.kubernetes.pod.namespace': s['dns_namespace'], 'k8s:k8s-app': 'kube-dns'}
    hosts = [f'{bucket}.oss-{c["region"]}-internal.aliyuncs.com' for bucket in (c['bucket'], c['vault_bucket'])]
    hosts.append('sts.' + c['region'] + '.aliyuncs.com')
    values.append(obj('cilium.io/v2', 'CiliumNetworkPolicy', 'sandbox-backup-egress', {
        'endpointSelector': selector,
        'ingress': [], 'ingressDeny': [{'fromEntities': ['all']}],
        'egressDeny': [{'toCIDR': ['169.254.0.0/16', '100.100.100.200/32']}, {'toEntities': ['host', 'remote-node', 'kube-apiserver']}],
        'egress': [{'toEndpoints': [{'matchLabels': dns}], 'toPorts': [{'ports': [{'port': '53', 'protocol': 'ANY'}],
                    'rules': {'dns': [{'matchName': host} for host in hosts]}}]},
                   {'toFQDNs': [{'matchName': host} for host in hosts], 'toPorts': [{'ports': [{'port': '443', 'protocol': 'TCP'}]}]}]}))
    return values


def resources(s, c, stage, volume_name, expected_manifest=None, *, attempt_id, cluster_epoch, deadline_seconds=None):
    require(stage in ('capture', 'seal', 'restore'), 'STAGE')
    require(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', volume_name), 'PVC_NAME')
    identifier = c['backup_id']
    require(uuid_text(attempt_id) and uuid_text(cluster_epoch), 'PERSISTENT_ATTEMPT_IDENTITY')
    name = 'sbx-bkp-' + attempt_id + '-' + stage
    config_name = 'sbx-bcfg-' + attempt_id
    config_map = obj('v1', 'ConfigMap', config_name, immutable=True, data={'job.json': canonical(c).decode()})
    role = {'capture': 'backup', 'seal': 'backup-export', 'restore': 'restore'}[stage]
    volumes = [{'name': 'work', 'emptyDir': ({'sizeLimit': '1Gi'} if stage == 'seal' else {'medium': 'Memory', 'sizeLimit': '128Mi'})},
               {'name': 'config', 'configMap': {'name': config_name, 'defaultMode': 0o644}},
               {'name': 'key', 'secret': {'secretName': s['secrets']['password'], 'defaultMode': 0o400}},
               {'name': 'cloud', 'projected': {'defaultMode': 0o400, 'sources': [{'serviceAccountToken': {
                   'audience': 'sts.aliyuncs.com', 'expirationSeconds': 600, 'path': 'token'}}]}}]
    mounts = [{'name': 'work', 'mountPath': '/run/backup'},
              {'name': 'config', 'mountPath': '/run/backup-config/job.json', 'subPath': 'job.json', 'readOnly': True},
              {'name': 'key', 'mountPath': '/run/backup-key/password', 'subPath': 'password', 'readOnly': True},
              {'name': 'cloud', 'mountPath': '/var/run/sandbox-cloud', 'readOnly': True}]
    container = {'name': 'backup', 'image': s['image'], 'imagePullPolicy': 'Always',
        'command': ['/usr/local/bin/python3', '/app/backup.py', stage],
        'terminationMessagePath': '/run/backup/result.json', 'terminationMessagePolicy': 'File',
        'securityContext': {'runAsUser': 0, 'runAsGroup': 0, 'allowPrivilegeEscalation': False,
                            'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}},
        'resources': {'requests': {'cpu': '1', 'memory': '1Gi', 'ephemeral-storage': '128Mi'},
                      'limits': {'cpu': '2', 'memory': '2Gi', 'ephemeral-storage': '256Mi'}},
        'volumeMounts': mounts}
    if stage != 'seal':
        volumes.append({'name': 'data', 'persistentVolumeClaim': {'claimName': volume_name, 'readOnly': stage == 'capture'}})
        container['volumeDevices'] = [{'name': 'data', 'devicePath': '/dev/sandbox-data'}]
    if stage == 'seal':
        container['resources']['requests']['ephemeral-storage'] = '1Gi'
        container['resources']['limits']['ephemeral-storage'] = '2Gi'
        volumes += [{'name': 'source', 'configMap': {'name': 'sbx-capture-' + identifier, 'defaultMode': 0o644}},
                    {'name': 'signing', 'secret': {'secretName': s['secrets']['signing_private'], 'defaultMode': 0o400}}]
        mounts += [{'name': 'source', 'mountPath': '/run/backup-source/capture.json', 'subPath': 'capture.json', 'readOnly': True},
                   {'name': 'signing', 'mountPath': '/run/backup-signing/private.pem', 'subPath': 'private.pem', 'readOnly': True}]
    if stage == 'restore':
        require(sha(expected_manifest), 'EXPECTED_MANIFEST')
        container['env'] = [{'name': 'SANDBOX_EXPECTED_MANIFEST_SHA256', 'value': expected_manifest}]
        volumes.append({'name': 'signing', 'secret': {'secretName': s['secrets']['signing_public'], 'defaultMode': 0o400}})
        mounts.append({'name': 'signing', 'mountPath': '/run/backup-signing/public.pem', 'subPath': 'public.pem', 'readOnly': True})
    labels = {LABEL: identifier, PURPOSE: 'backup-' + stage, 'sandbox.platform/backup-attempt-id': attempt_id,
              'sandbox.platform/tenant-id': c['tenant_id'], 'sandbox.platform/project-id': c['project_id'],
              'sandbox.platform/cluster-epoch': cluster_epoch, 'app.kubernetes.io/managed-by': 'sandbox-backup'}
    config_map['metadata']['labels'] = labels
    pod = {'metadata': {'labels': labels, 'annotations': {'sandbox.platform/backup-certification': s['certification_report_sha256']},
           'finalizers': ['sandbox.platform/termination-protection']},
           'spec': {'runtimeClassName': s['runtime_class'], 'serviceAccountName': 'sandbox-' + role,
                    'automountServiceAccountToken': False, 'restartPolicy': 'Never', 'enableServiceLinks': False,
                    'hostNetwork': False, 'hostPID': False, 'hostIPC': False,
                    'dnsPolicy': 'ClusterFirst', 'schedulerName': 'default-scheduler', 'terminationGracePeriodSeconds': 30,
                    'nodeSelector': {'sandbox.platform/node-pool': 'kata'},
                    'tolerations': [{'key': 'sandbox.platform/untrusted', 'operator': 'Equal', 'value': 'true', 'effect': 'NoSchedule'}],
                    'securityContext': {'seccompProfile': {'type': 'RuntimeDefault'}},
                    'containers': [container], 'volumes': volumes}}
    # A Job controller retry must never create a second disk writer. Reconciliation starts a fresh job only after VM proof.
    seconds = max(1, int(timestamp(c['deadline']) - time.time())) if deadline_seconds is None else deadline_seconds
    require(type(seconds) is int and 1 <= seconds <= 7200, 'JOB_DEADLINE')
    job = obj('batch/v1', 'Job', name, {'suspend': True, 'backoffLimit': 0, 'parallelism': 1, 'completions': 1,
              'completionMode': 'NonIndexed', 'podReplacementPolicy': 'Failed',
              'activeDeadlineSeconds': seconds, 'template': pod})
    job['metadata']['labels'] = labels
    return [config_map, job]


def clone_plan(s, c, source_pvc, source_pv, snapshot, content, *, attempt_id):
    """Controlled cross-namespace static snapshot reference, never a tenant-selectable handle."""
    require(source_pvc['metadata']['uid'] == c['source_pvc_uid'] and source_pv['spec']['claimRef']['uid'] == c['source_pvc_uid'], 'SOURCE_BINDING')
    require(snapshot['spec']['source'] == {'persistentVolumeClaimName': source_pvc['metadata']['name']}, 'SNAPSHOT_SOURCE')
    require(snapshot['metadata']['namespace'] == source_pvc['metadata']['namespace'] and snapshot['status'].get('readyToUse') is True, 'SNAPSHOT_NAMESPACE_READY')
    require(snapshot['status']['boundVolumeSnapshotContentName'] == content['metadata']['name'], 'SNAPSHOT_CONTENT_NAME')
    require(content['spec']['volumeSnapshotRef']['uid'] == snapshot['metadata']['uid'], 'SNAPSHOT_REF_UID')
    require(content['spec']['source'] == {'volumeHandle': source_pv['spec']['csi']['volumeHandle']}, 'SNAPSHOT_SOURCE_DISK')
    require(content['spec']['driver'] == 'diskplugin.csi.alibabacloud.com' and content['status'].get('readyToUse') is True, 'SNAPSHOT_DRIVER')
    require(re.fullmatch(r's-[A-Za-z0-9]+', content['status']['snapshotHandle']), 'ALIYUN_SNAPSHOT_HANDLE')
    require(source_pvc['spec'].get('volumeMode', 'Filesystem') == 'Filesystem', 'SOURCE_FILESYSTEM')
    for value in (source_pvc, source_pv, snapshot, content):
        require(not value['metadata'].get('deletionTimestamp'), 'SOURCE_DELETING')
    require(uuid_text(attempt_id), 'PERSISTENT_ATTEMPT_IDENTITY')
    name = 'sbx-bs-' + c['backup_id']
    target = obj('snapshot.storage.k8s.io/v1', 'VolumeSnapshot', name, {'source': {'volumeSnapshotContentName': name}})
    shared = {'apiVersion': 'snapshot.storage.k8s.io/v1', 'kind': 'VolumeSnapshotContent',
              'metadata': {'name': name, 'annotations': {'snapshot.storage.kubernetes.io/allow-volume-mode-change': 'true'},
                           'labels': {LABEL: c['backup_id'], 'app.kubernetes.io/managed-by': 'sandbox-backup'}},
              'spec': {'deletionPolicy': 'Retain', 'driver': 'diskplugin.csi.alibabacloud.com', 'sourceVolumeMode': 'Filesystem',
                       'source': {'snapshotHandle': content['status']['snapshotHandle']},
                       'volumeSnapshotRef': {'name': name, 'namespace': NS}}}
    pvc = obj('v1', 'PersistentVolumeClaim', 'sbx-bvol-' + attempt_id, {
        'volumeMode': 'Block', 'accessModes': ['ReadWriteOnce'], 'storageClassName': s['storage_class'],
        'resources': {'requests': {'storage': str(c['size_bytes'])}},
        'dataSource': {'apiGroup': 'snapshot.storage.k8s.io', 'kind': 'VolumeSnapshot', 'name': name}})
    pvc['metadata']['labels'].update({LABEL: c['backup_id'], 'sandbox.platform/backup-attempt-id': attempt_id})
    return [shared, target, pvc]


def verify_storage(s, c, source_pvc, source_pv, content, clone_pvc, clone_pv, runtime):
    require(source_pvc['metadata']['uid'] == c['source_pvc_uid'], 'SOURCE_PVC_UID')
    require(source_pvc['spec'].get('volumeMode', 'Filesystem') == 'Filesystem', 'SOURCE_VOLUME_MODE')
    require(source_pv['spec']['claimRef']['uid'] == c['source_pvc_uid'], 'SOURCE_PV_UID')
    require(content['metadata']['uid'] == c['snapshot_content_uid'] and content['spec']['driver'] == 'diskplugin.csi.alibabacloud.com', 'SNAPSHOT_BINDING')
    require(content['spec'].get('sourceVolumeMode') == 'Filesystem' and content['status'].get('readyToUse') is True, 'SNAPSHOT_NOT_READY')
    require(content['metadata'].get('annotations', {}).get('snapshot.storage.kubernetes.io/allow-volume-mode-change') == 'true', 'EXPLICIT_VOLUME_MODE_CONVERSION')
    require(clone_pvc['metadata']['uid'] == c['clone_pvc_uid'] and clone_pvc['spec'].get('volumeMode') == 'Block', 'CLONE_RAW_BLOCK')
    require(clone_pvc['status'].get('phase') == 'Bound' and clone_pvc['spec']['storageClassName'] == s['storage_class'], 'CLONE_CLASS')
    require(clone_pvc['metadata']['uid'] != source_pvc['metadata']['uid'], 'ORIGINAL_VOLUME_FORBIDDEN')
    require(clone_pvc['spec'].get('dataSource') == {'apiGroup': 'snapshot.storage.k8s.io', 'kind': 'VolumeSnapshot',
                'name': content['spec']['volumeSnapshotRef']['name']}, 'CLONE_SNAPSHOT_SOURCE')
    require(clone_pvc['metadata']['namespace'] == content['spec']['volumeSnapshotRef']['namespace'], 'CLONE_SNAPSHOT_NAMESPACE')
    require(clone_pv['spec']['claimRef']['uid'] == c['clone_pvc_uid'] and clone_pv['spec'].get('volumeMode') == 'Block', 'CLONE_PV_BINDING')
    require(clone_pv['spec']['csi']['driver'] == 'diskplugin.csi.alibabacloud.com' and clone_pv['spec']['persistentVolumeReclaimPolicy'] == 'Retain', 'CLONE_DRIVER_RECLAIM')
    disk = clone_pv['spec']['csi']['volumeHandle']
    require(re.fullmatch(r'd-[A-Za-z0-9]+', disk) and disk != source_pv['spec']['csi']['volumeHandle'], 'ORIGINAL_CLOUD_DISK_FORBIDDEN')
    require(runtime['metadata']['name'] == s['runtime_class'] and runtime['handler'] == 'kata-qemu' and not runtime['metadata'].get('deletionTimestamp'), 'RUNTIME_IDENTITY')
    for value in (source_pvc, source_pv, content, clone_pvc, clone_pv):
        require(not value['metadata'].get('deletionTimestamp'), 'RESOURCE_DELETING')


def verify_restore_storage(s, pvc, pv, runtime, expected_pvc_uid, expected_pv_uid, expected_disk):
    """The expected target identity comes from the restore operation's creation ledger, not the backup manifest."""
    require(uuid_text(expected_pvc_uid) and uuid_text(expected_pv_uid) and re.fullmatch(r'd-[A-Za-z0-9]+', expected_disk), 'RESTORE_TARGET_EXPECTATION')
    require(pvc['metadata']['uid'] == expected_pvc_uid and pv['metadata']['uid'] == expected_pv_uid, 'RESTORE_TARGET_UID')
    require(pvc['metadata']['namespace'] == NS and pvc['spec'].get('volumeMode') == 'Block' and pvc['status'].get('phase') == 'Bound', 'RESTORE_TARGET_BLOCK')
    require(not pvc['spec'].get('dataSource') and not pvc['spec'].get('dataSourceRef'), 'RESTORE_REQUIRES_NEW_EMPTY_VOLUME')
    require(pvc['spec']['storageClassName'] == s['storage_class'] and pv['spec'].get('volumeMode') == 'Block', 'RESTORE_TARGET_CLASS')
    require(pv['spec']['claimRef']['uid'] == expected_pvc_uid and pv['spec']['claimRef']['namespace'] == NS
            and pv['spec']['claimRef']['name'] == pvc['metadata']['name'], 'RESTORE_PV_CLAIM')
    require(pv['spec']['persistentVolumeReclaimPolicy'] == 'Retain' and pv['spec']['csi']['driver'] == 'diskplugin.csi.alibabacloud.com'
            and pv['spec']['csi']['volumeHandle'] == expected_disk, 'RESTORE_CLOUD_DISK')
    require(runtime['metadata']['name'] == s['runtime_class'] and runtime['handler'] == 'kata-qemu', 'RESTORE_RUNTIME')
    for value in (pvc, pv, runtime):
        require(not value['metadata'].get('deletionTimestamp'), 'RESTORE_RESOURCE_DELETING')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['render', 'install-foundations', 'preflight', 'plan-clone'])
    p.add_argument('--settings', required=True)
    p.add_argument('--job', required=True)
    p.add_argument('--stage', choices=['capture', 'seal', 'restore'], default='capture')
    p.add_argument('--volume', required=True)
    p.add_argument('--expected-manifest')
    p.add_argument('--attempt-id')
    p.add_argument('--cluster-epoch')
    p.add_argument('--context')
    p.add_argument('--source-namespace')
    p.add_argument('--source-pvc')
    p.add_argument('--snapshot-content')
    p.add_argument('--snapshot')
    p.add_argument('--target-pvc-uid')
    p.add_argument('--target-pv-uid')
    p.add_argument('--target-cloud-disk')
    a = p.parse_args()
    s, c = settings(a.settings), config(a.job)
    if a.command == 'render':
        print(json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': foundations(s, c) + resources(s, c, a.stage, a.volume, a.expected_manifest, attempt_id=a.attempt_id, cluster_epoch=a.cluster_epoch)}, indent=2))
    elif a.command == 'install-foundations':
        require(a.context, 'KUBE_CONTEXT')
        env = {'PATH': '/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin', 'HOME': str(Path.home())}
        baseline = decode(run(['kubectl', '--context', a.context, '--request-timeout=15s', 'get',
            'ciliumclusterwidenetworkpolicy', 'sandbox-trusted-bootstrap', '-o', 'json'], time.time() + 20, env))
        exclusions = baseline['spec']['endpointSelector'].get('matchExpressions', [])
        require({'key': 'k8s:' + LABEL, 'operator': 'DoesNotExist'} in exclusions, 'BROAD_BOOTSTRAP_POLICY_MUST_EXCLUDE_BACKUP')
        for value in foundations(s, c):
            base = ['kubectl', '--context', a.context, '--request-timeout=15s', '-n', NS]
            existing = run(base + ['get', value['kind'], value['metadata']['name'], '--ignore-not-found', '-o', 'json'], time.time() + 20, env)
            if existing:
                current = decode(existing)
                require(current['metadata'].get('labels', {}).get('app.kubernetes.io/managed-by') == 'sandbox-backup', 'FOREIGN_OBJECT')
                require(not current['metadata'].get('deletionTimestamp'), 'OBJECT_DELETING')
                if value['kind'] == 'ServiceAccount':
                    require(current.get('automountServiceAccountToken') is False and not current.get('secrets') and not current.get('imagePullSecrets'), 'SERVICE_ACCOUNT_DRIFT')
                else:
                    require(current['spec'] == value['spec'], 'POLICY_DRIFT')
            else:
                # Private temp file avoids shell interpolation/stdin ambiguity; never server-side apply/adopt.
                import tempfile
                with tempfile.NamedTemporaryFile(mode='wb', suffix='.json') as file:
                    file.write(canonical(value))
                    file.flush()
                    run(base + ['create', '--dry-run=server', '-f', file.name], time.time() + 20, env)
                    run(base + ['create', '-f', file.name], time.time() + 20, env)
        print('Backup identities and default-deny policies installed; no Job resumed and no cloud operation invoked.')
    else:
        require(a.context, 'KUBE_CONTEXT')
        def get(kind, name, namespace=None):
            cmd = ['kubectl', '--context', a.context, '--request-timeout=15s']
            if namespace:
                cmd += ['-n', namespace]
            return decode(run(cmd + ['get', kind, name, '-o', 'json'], time.time() + 20, env={'PATH': '/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin', 'HOME': str(Path.home())}))
        if a.command == 'preflight' and a.stage == 'restore':
            target = get('pvc', a.volume, NS)
            target_pv = get('pv', target['spec']['volumeName'])
            runtime = get('runtimeclass', s['runtime_class'])
            verify_restore_storage(s, target, target_pv, runtime, a.target_pvc_uid, a.target_pv_uid, a.target_cloud_disk)
            print(json.dumps({'restore_storage_identity_checks': 'PASSED', 'job_may_start': False,
                              'required_control_plane_gates': ['RESTORE_HOLD_AND_NEW_DISK_LEDGER', 'BACKUP_LAUNCH_PERMIT']}))
            return
        require(all([a.source_namespace, a.source_pvc, a.snapshot_content]), 'PREFLIGHT_ARGUMENTS')
        source = get('pvc', a.source_pvc, a.source_namespace)
        source_pv = get('pv', source['spec']['volumeName'])
        content = get('volumesnapshotcontent', a.snapshot_content)
        if a.command == 'plan-clone':
            require(a.snapshot, 'SNAPSHOT_ARGUMENT')
            snapshot = get('volumesnapshot', a.snapshot, a.source_namespace)
            print(json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': clone_plan(s, c, source, source_pv, snapshot, content, attempt_id=a.attempt_id)}, indent=2))
            return
        clone = get('pvc', a.volume, NS)
        pv = get('pv', clone['spec']['volumeName'])
        runtime = get('runtimeclass', s['runtime_class'])
        verify_storage(s, c, source, source_pv, content, clone, pv, runtime)
        # Does not fabricate the missing live admission/CRI permit or host mount audit.
        print(json.dumps({'storage_identity_checks': 'PASSED', 'job_may_start': False,
                          'required_control_plane_gates': ['BACKUP_LAUNCH_PERMIT', 'CERTIFIED_RAW_BLOCK_HOST_TRACE']}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError):
        print('BACKUP_DEPLOYMENT_REJECTED', file=sys.stderr)
        sys.exit(1)
