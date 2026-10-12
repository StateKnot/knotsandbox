#!/usr/bin/env python3
"""Render/install the real backup controller. Does not activate a backup profile."""
import argparse
import copy
import hashlib
import json
import subprocess
from pathlib import Path
from backup import canonical, decode, read, require
from profile import name

NS = 'sandbox-system'
SA = 'sandbox-backup-controller'
FIELDS = {'protocol', 'controller_image', 'backup_image', 'database_secret', 'database_ca_secret',
          'nodeguard_server_ca_secret', 'nodeguard_client_identity_secret', 'signing_public_secret', 'password_secret', 'signing_private_secret',
          'vault', 'reader', 'concurrency', 'projects', 'job_controller', 'clone_storage_class', 'snapshot_class', 'clone_kms_key_id', 'deployment'}
KUBERNETES_CONTEXT = None
ADDITIONAL_RULES = [
    {'operations': ['CREATE', 'UPDATE', 'DELETE'], 'apiGroups': [''], 'apiVersions': ['v1'], 'resources': ['secrets'], 'scope': 'Namespaced'},
    {'operations': ['CREATE', 'UPDATE', 'DELETE'], 'apiGroups': ['batch'], 'apiVersions': ['v1'], 'resources': ['jobs', 'jobs/status'], 'scope': 'Namespaced'},
    {'operations': ['CREATE', 'UPDATE', 'DELETE'], 'apiGroups': [''], 'apiVersions': ['v1'], 'resources': ['configmaps'], 'scope': 'Namespaced'},
    {'operations': ['CREATE', 'UPDATE', 'DELETE'], 'apiGroups': ['snapshot.storage.k8s.io'], 'apiVersions': ['v1'], 'resources': ['volumesnapshots', 'volumesnapshots/status', 'volumesnapshotcontents', 'volumesnapshotcontents/status'], 'scope': '*'},
    {'operations': ['CREATE'], 'apiGroups': [''], 'apiVersions': ['v1'], 'resources': ['persistentvolumes'], 'scope': 'Cluster'},
]


def validate(c):
    import re
    require(set(c) == FIELDS and c['protocol'] == 1, 'CONTROLLER_FIELDS')
    for key in ('controller_image', 'backup_image'):
        require(re.fullmatch(r'[a-z0-9.-]+(?::[0-9]+)?/[a-zA-Z0-9/_-]+@sha256:[0-9a-f]{64}', c[key]), 'PINNED_CONTROLLER_IMAGE')
    for key in ('database_secret', 'database_ca_secret', 'nodeguard_server_ca_secret', 'nodeguard_client_identity_secret', 'signing_public_secret'):
        require(name(c[key]), 'SECRET_REFERENCE')
    for key in ('password_secret', 'signing_private_secret', 'signing_public_secret'):
        require(name(c[key]) and c[key].startswith('sbx-bkey-'), 'PROTECTED_KEY_NAME')
    require(len({c[k] for k in ('database_secret', 'database_ca_secret', 'nodeguard_server_ca_secret', 'nodeguard_client_identity_secret', 'signing_public_secret', 'password_secret', 'signing_private_secret')}) == 7, 'SEPARATE_SECRET_REFERENCES')
    require(name(c['clone_storage_class']) and name(c['snapshot_class']) and re.fullmatch(r'[A-Za-z0-9-]{1,128}', c['clone_kms_key_id']), 'STORAGE_CONFIG')
    require(re.fullmatch(r'[a-z][a-z0-9-]{3,19}', c['deployment']), 'DEPLOYMENT_TAG')
    require(c['clone_storage_class'] != 'sandbox-workspace', 'SEPARATE_CLONE_CLASS')
    require(type(c['concurrency']) is int and 1 <= c['concurrency'] <= 8, 'CONCURRENCY')
    require(type(c['projects']) is list and 1 <= len(c['projects']) <= 1000 and len(set(c['projects'])) == len(c['projects']) and all(name(n) and n not in (NS, 'default', 'kube-system') for n in c['projects']), 'PROJECT_NAMESPACES')
    require(set(c['vault']) == {'endpoint', 'bucket', 'region', 'account_id'}, 'VAULT_FIELDS')
    v = c['vault']
    require(v['endpoint'] == f'https://oss-{v["region"]}-internal.aliyuncs.com', 'INTERNAL_VAULT_ENDPOINT')
    from reader_credentials import validate as validate_reader
    validate_reader(c['reader'])
    require(all(c['reader'][key] == v[key] for key in ('region', 'account_id')) and c['reader']['vault_bucket'] == v['bucket'], 'READER_BINDING')
    identity = c['job_controller']
    require(identity == {'kind': 'control_plane', 'username': 'system:kube-controller-manager'} or
            (set(identity) == {'kind', 'username', 'uid'} and identity['kind'] == 'service_account' and identity['username'] == 'system:serviceaccount:kube-system:job-controller' and __import__('uuid').UUID(identity['uid']).int != 0), 'EXACT_JOB_CONTROLLER_IDENTITY')
    return c


def validate_infrastructure(c, terraform):
    validate(c)
    require(isinstance(terraform, dict) and terraform and all(
        isinstance(v, dict) and 'value' in v and v.get('sensitive') is False
        for v in terraform.values()), 'REVIEWED_NONSECRET_TERRAFORM_OUTPUT_REQUIRED')
    identity = terraform['deployment_identity']['value']
    require(identity['deployment'] == c['deployment']
            and identity['cloud_account_id'] == c['vault']['account_id']
            and identity['region'] == c['vault']['region'], 'TERRAFORM_DEPLOYMENT_BINDING')
    require(c['clone_kms_key_id'] == terraform['workspace_kms_key_id']['value'],
            'CSI_COMPUTE_KMS_BINDING')
    from reader_config import export
    require(c['reader'] == export(terraform), 'TERRAFORM_READER_BINDING')
    return c


def obj(api, kind, name_, namespace=NS, **fields):
    metadata = {'name': name_, 'labels': {'app.kubernetes.io/managed-by': 'sandbox-backup-controller'}}
    if namespace:
        metadata['namespace'] = namespace
    return {'apiVersion': api, 'kind': kind, 'metadata': metadata, **fields}


def role_binding(kind, role, namespace=NS, service=SA):
    return obj('rbac.authorization.k8s.io/v1', kind + 'Binding', role, namespace,
               roleRef={'apiGroup': 'rbac.authorization.k8s.io', 'kind': kind, 'name': role},
               subjects=[{'kind': 'ServiceAccount', 'name': service, 'namespace': NS}])


def resources(c):
    validate(c)
    vault = {**c['vault'], 'signing_public_key_file': '/run/backup-public/public.pem'}
    config_name = 'sandbox-backup-config-' + hashlib.sha256(canonical({'vault': vault, 'reader': c['reader']})).hexdigest()[:16]
    values = [obj('v1', 'ServiceAccount', SA, automountServiceAccountToken=False),
              obj('v1', 'ConfigMap', config_name, immutable=True,
                  data={'vault.json': canonical(vault).decode(), 'reader.json': canonical(c['reader']).decode()})]
    values += [obj('node.k8s.io/v1', 'RuntimeClass', 'kata-backup-qemu', None, handler='kata-qemu'),
               obj('storage.k8s.io/v1', 'StorageClass', c['clone_storage_class'], None,
                   provisioner='diskplugin.csi.alibabacloud.com', reclaimPolicy='Retain', volumeBindingMode='WaitForFirstConsumer', allowVolumeExpansion=False,
                   parameters={'type': 'cloud_essd', 'encrypted': 'true', 'kmsKeyId': c['clone_kms_key_id'], 'diskTags/Deployment': c['deployment']}),
               obj('snapshot.storage.k8s.io/v1', 'VolumeSnapshotClass', c['snapshot_class'], None,
                   driver='diskplugin.csi.alibabacloud.com', deletionPolicy='Retain',
                   parameters={'snapshotTags/Deployment': c['deployment']})]
    role = 'sandbox-backup-controller'
    values += [obj('rbac.authorization.k8s.io/v1', 'Role', role, rules=[
        {'apiGroups': [''], 'resources': ['pods'], 'verbs': ['get', 'list', 'patch', 'delete']},
        {'apiGroups': [''], 'resources': ['configmaps', 'persistentvolumeclaims'], 'verbs': ['get', 'create']},
        {'apiGroups': ['batch'], 'resources': ['jobs'], 'verbs': ['get', 'create', 'patch']},
        {'apiGroups': ['snapshot.storage.k8s.io'], 'resources': ['volumesnapshots'], 'verbs': ['get', 'create']},
        {'apiGroups': ['networking.k8s.io'], 'resources': ['networkpolicies'], 'verbs': ['get', 'list']},
        {'apiGroups': ['cilium.io'], 'resources': ['ciliumnetworkpolicies'], 'verbs': ['get', 'list']}]), role_binding('Role', role)]
    cluster_rules = [
        {'apiGroups':['admissionregistration.k8s.io'],'resources':['validatingwebhookconfigurations'],'resourceNames':['sandbox-runtime-protection'],'verbs':['get']},
        {'apiGroups': [''], 'resources': ['nodes', 'persistentvolumes'], 'verbs': ['get']},
        {'apiGroups': ['storage.k8s.io'], 'resources': ['volumeattachments'], 'verbs': ['list']},
        {'apiGroups': ['storage.k8s.io'], 'resources': ['storageclasses'], 'verbs': ['get']},
        {'apiGroups': ['node.k8s.io'], 'resources': ['runtimeclasses'], 'verbs': ['get']},
        {'apiGroups': ['snapshot.storage.k8s.io'], 'resources': ['volumesnapshotclasses'], 'verbs': ['get']},
        {'apiGroups': ['snapshot.storage.k8s.io'], 'resources': ['volumesnapshotcontents'], 'verbs': ['get', 'create']},
        {'apiGroups': ['cilium.io'], 'resources': ['ciliumclusterwidenetworkpolicies'], 'verbs': ['list']}]
    values += [obj('rbac.authorization.k8s.io/v1', 'ClusterRole', role, None, rules=cluster_rules), role_binding('ClusterRole', role, None)]
    # Admission reads authority and live resources; it acquires no mutation rights.
    admission_rules = [dict(rule, verbs=['get'] if 'list' not in rule['verbs'] else ['get', 'list']) for rule in cluster_rules]
    admission_rules += [
        {'apiGroups': ['batch'], 'resources': ['jobs'], 'verbs': ['get']},
        {'apiGroups': ['snapshot.storage.k8s.io'], 'resources': ['volumesnapshots'], 'verbs': ['get']},
        {'apiGroups': ['cilium.io'], 'resources': ['ciliumnetworkpolicies'], 'verbs': ['get', 'list']},
        {'apiGroups': ['networking.k8s.io'], 'resources': ['networkpolicies'], 'verbs': ['get', 'list']}]
    values += [obj('rbac.authorization.k8s.io/v1', 'ClusterRole', 'sandbox-backup-admission-read', None, rules=admission_rules), role_binding('ClusterRole', 'sandbox-backup-admission-read', None, 'sandbox-admission')]
    key_names = sorted(c[k] for k in ('password_secret', 'signing_private_secret', 'signing_public_secret'))
    values += [obj('rbac.authorization.k8s.io/v1', 'Role', 'sandbox-backup-key-read', rules=[
        {'apiGroups': [''], 'resources': ['secrets'], 'resourceNames': key_names, 'verbs': ['get']}]),
        role_binding('Role', 'sandbox-backup-key-read'),
        dict(role_binding('Role', 'sandbox-backup-key-read', service='sandbox-admission'), metadata={'name':'sandbox-backup-key-admission-read','namespace':NS,'labels':{'app.kubernetes.io/managed-by':'sandbox-backup-controller'}}),
        obj('rbac.authorization.k8s.io/v1', 'Role', 'sandbox-backup-key-install', rules=[
            {'apiGroups':[''], 'resources':['secrets'], 'verbs':['create']}]),
        obj('rbac.authorization.k8s.io/v1', 'RoleBinding', 'sandbox-backup-key-install',
            roleRef={'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':'sandbox-backup-key-install'},
            subjects=[{'kind':'Group','name':'sandbox:backup-key-installers','apiGroup':'rbac.authorization.k8s.io'}])]
    for namespace in c['projects']:
        values += [obj('rbac.authorization.k8s.io/v1', 'Role', role, namespace, rules=[
            {'apiGroups': [''], 'resources': ['persistentvolumeclaims'], 'verbs': ['get']},
            {'apiGroups': ['snapshot.storage.k8s.io'], 'resources': ['volumesnapshots'], 'verbs': ['get', 'create']}]), role_binding('Role', role, namespace)]
    secret_map = [('database-ca', c['database_ca_secret']), ('nodeguard-ca', c['nodeguard_server_ca_secret']),
                  ('nodeguard-client', c['nodeguard_client_identity_secret']), ('signing-public', c['signing_public_secret'])]
    volumes = [{'name': key, 'secret': {'secretName': secret, 'defaultMode': 0o440}} for key, secret in secret_map]
    volumes += [{'name': 'config', 'configMap': {'name': config_name, 'defaultMode': 0o440}},
                {'name': 'reader-credentials', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '16Mi'}},
                {'name': 'tmp', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '32Mi'}},
                {'name': 'reader-oidc', 'projected': {'defaultMode': 0o440, 'sources': [{'serviceAccountToken': {'path': 'token', 'audience': 'sts.aliyuncs.com', 'expirationSeconds': 600}}]}},
                {'name': 'kube-api', 'projected': {'defaultMode': 0o440, 'sources': [{'serviceAccountToken': {'path': 'token', 'expirationSeconds': 600}}, {'configMap': {'name': 'kube-root-ca.crt', 'items': [{'key': 'ca.crt', 'path': 'ca.crt'}]}}, {'downwardAPI': {'items': [{'path': 'namespace', 'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.namespace'}}]}}]}}]
    security = {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}}
    mounts = [{'name': key, 'mountPath': path, 'readOnly': True} for key, path in [('database-ca', '/run/database-ca'), ('nodeguard-ca', '/run/nodeguard-ca'), ('nodeguard-client', '/run/nodeguard-client'), ('signing-public', '/run/backup-public'), ('config', '/run/backup-config'), ('reader-credentials', '/run/backup-reader'), ('kube-api', '/var/run/secrets/kubernetes.io/serviceaccount')]]
    container = {'name': 'controller', 'image': c['controller_image'], 'imagePullPolicy': 'Always', 'command': ['/usr/local/bin/sandboxd'], 'args': ['--role', 'backup'], 'securityContext': security,
                 'env': [{'name': 'SANDBOX_DATABASE_URL', 'valueFrom': {'secretKeyRef': {'name': c['database_secret'], 'key': 'url'}}},
                         {'name': 'SANDBOX_PROCESS_POD_UID', 'valueFrom': {'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.uid'}}},
                         {'name': 'SANDBOX_BACKUP_VAULT_CONFIG_FILE', 'value': '/run/backup-config/vault.json'},
                         {'name': 'SANDBOX_BACKUP_READ_STS_FILE', 'value': '/run/backup-reader/private/credentials.json'},
                         {'name': 'SANDBOX_NODEGUARD_SERVER_CA_FILE', 'value': '/run/nodeguard-ca/ca.pem'},
                         {'name': 'SANDBOX_NODEGUARD_CLIENT_IDENTITY_FILE', 'value': '/run/nodeguard-client/identity.pem'},
                         {'name': 'SANDBOX_BACKUP_CONCURRENCY', 'value': str(c['concurrency'])}],
                 'volumeMounts': mounts + [{'name': 'tmp', 'mountPath': '/tmp'}],
                 'resources': {'requests': {'cpu': '250m', 'memory': '256Mi'}, 'limits': {'cpu': '2', 'memory': '2Gi'}}}
    sidecar = {'name': 'reader-credentials', 'image': c['backup_image'], 'imagePullPolicy': 'Always', 'command': ['/usr/local/bin/python3', '/app/reader_credentials.py'], 'args': ['--config', '/run/backup-reader-config/reader.json'], 'securityContext': security,
               'volumeMounts': [{'name': 'config', 'mountPath': '/run/backup-reader-config', 'readOnly': True}, {'name': 'reader-credentials', 'mountPath': '/run/backup-reader'}, {'name': 'reader-oidc', 'mountPath': '/var/run/backup-reader-oidc', 'readOnly': True}],
               'resources': {'requests': {'cpu': '20m', 'memory': '64Mi'}, 'limits': {'cpu': '250m', 'memory': '128Mi'}}}
    initial_credentials = copy.deepcopy(sidecar)
    initial_credentials['name'] = 'initial-reader-credentials'
    initial_credentials['args'] += ['--once']
    selector = {'app.kubernetes.io/name': SA}
    spec = {'replicas': 2, 'revisionHistoryLimit': 3, 'selector': {'matchLabels': selector}, 'strategy': {'type': 'RollingUpdate', 'rollingUpdate': {'maxUnavailable': 0, 'maxSurge': 1}},
            'template': {'metadata': {'labels': selector}, 'spec': {'serviceAccountName': SA, 'automountServiceAccountToken': False, 'nodeSelector': {'sandbox.platform/node-pool': 'platform'}, 'terminationGracePeriodSeconds': 45,
              'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001, 'runAsGroup': 10001, 'fsGroup': 10001, 'seccompProfile': {'type': 'RuntimeDefault'}},
              'topologySpreadConstraints': [{'maxSkew': 1, 'topologyKey': 'kubernetes.io/hostname', 'whenUnsatisfiable': 'ScheduleAnyway', 'labelSelector': {'matchLabels': selector}}],
              'initContainers': [initial_credentials], 'containers': [container, sidecar], 'volumes': volumes}}}
    values += [obj('apps/v1', 'Deployment', SA, spec=spec), obj('policy/v1', 'PodDisruptionBudget', SA, spec={'minAvailable': 1, 'selector': {'matchLabels': selector}})]
    return values


def hook_with_backup(hook):
    require(hook.get('kind') == 'ValidatingWebhookConfiguration' and hook['metadata']['name'] == 'sandbox-runtime-protection', 'BASE_WEBHOOK_REQUIRED')
    result = copy.deepcopy(hook)
    entries = [w for w in result['webhooks'] if w['name'] == 'runtime.sandbox.platform']
    require(len(entries) == 1, 'EXACT_WEBHOOK')
    w = entries[0]
    require(w['failurePolicy'] == 'Fail' and not w.get('namespaceSelector') and not w.get('objectSelector') and not w.get('matchConditions') and not w['clientConfig'].get('url') and w['clientConfig'].get('caBundle') and w['clientConfig'].get('service') == {'namespace': NS, 'name': 'sandbox-admission', 'path': '/validate', 'port': 443}, 'FAIL_CLOSED_WEBHOOK')
    for rule in ADDITIONAL_RULES:
        if rule not in w['rules']:
            w['rules'].append(rule)
    return result


def kubectl(args, value=None, accepted=(0,)):
    require(KUBERNETES_CONTEXT, 'EXPLICIT_KUBERNETES_CONTEXT_REQUIRED')
    result = subprocess.run(['kubectl', '--context', KUBERNETES_CONTEXT, '--request-timeout=30s', *args], input=None if value is None else canonical(value), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
    require(result.returncode in accepted, 'KUBERNETES_COMMAND_FAILED')
    return result


def get(kind, name_, namespace=None):
    return decode(kubectl(['get', kind, name_, '-o', 'json', *(['-n', namespace] if namespace else [])]).stdout)


def ensure(value):
    args = ['get', value['kind'], value['metadata']['name'], '-o', 'json', '--ignore-not-found']
    if value['metadata'].get('namespace'):
        args += ['-n', value['metadata']['namespace']]
    present = kubectl(args).stdout.strip()
    if present:
        actual = decode(present)
        require(actual.get('metadata', {}).get('labels', {}).get('app.kubernetes.io/managed-by') == 'sandbox-backup-controller', 'EXISTING_OBJECT_OWNER_DRIFT')
        # kubectl handles apiserver defaulting. Any real desired-field drift is an
        # explicit upgrade, never silently overwritten by this fresh installer.
        kubectl(['diff', '--server-side=true', '--field-manager=sandbox-backup-install', '-f', '-'], value)
    else:
        kubectl(['create', '--field-manager=sandbox-backup-install', '-f', '-'], value)


def install(c, terraform, protection_only=False):
    validate_infrastructure(c, terraform)
    values = resources(c)
    for namespace in c['projects']:
        n = get('namespace', namespace)
        require(n['metadata'].get('labels', {}).get('sandbox.platform/managed') == 'true', 'MANAGED_PROJECT_REQUIRED')
    for value in values:
        if value['kind'] not in ('Deployment', 'PodDisruptionBudget'):
            ensure(value)
    service = get('serviceaccount', SA, NS)
    # Narrow config merge preserves all existing admission identities. Updating it
    # is followed by a rollout because the webhook does not hot-reload config.
    cm = get('configmap', 'sandbox-admission-config', NS)
    current = decode(cm['data']['config.json'].encode())
    wanted = {'controller': {'username': f'system:serviceaccount:{NS}:{SA}', 'uid': service['metadata']['uid']}, 'job_controller': c['job_controller']}
    if current.get('backup') != wanted:
        require(current.get('backup') in (None, wanted), 'EXISTING_BACKUP_IDENTITY_DRIFT')
        current['backup'] = wanted
        patch = [{'op': 'test', 'path': '/metadata/resourceVersion', 'value': cm['metadata']['resourceVersion']}, {'op': 'replace', 'path': '/data/config.json', 'value': canonical(current).decode()}]
        kubectl(['patch', 'configmap', 'sandbox-admission-config', '-n', NS, '--type=json', '--patch-file=/dev/stdin'], patch)
        kubectl(['rollout', 'restart', 'deployment/sandbox-admission', '-n', NS])
    kubectl(['rollout', 'status', 'deployment/sandbox-admission', '-n', NS, '--timeout=60s'])
    old = get('validatingwebhookconfiguration', 'sandbox-runtime-protection')
    new = hook_with_backup(old)
    if new != old:
        kubectl(['replace', '-f', '-'], new)
    if protection_only:
        return {'key_protection_installed': True, 'profiles_activated': False, 'controller_started': False}
    for value in values:
        if value['kind'] in ('Deployment', 'PodDisruptionBudget'):
            ensure(value)
    kubectl(['rollout', 'status', 'deployment/' + SA, '-n', NS, '--timeout=60s'])
    return {'installed': True, 'profiles_activated': False, 'cloud_restore_certified': False}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['render', 'install-protection', 'install'])
    parser.add_argument('--config', required=True)
    parser.add_argument('--terraform-output', required=True, help='Reviewed nonsecret terraform output -json from this deployment')
    parser.add_argument('--context', help='Explicit reviewed Kubernetes context, required for install')
    args = parser.parse_args()
    KUBERNETES_CONTEXT = args.context
    if args.action != 'render':
        require(KUBERNETES_CONTEXT, 'EXPLICIT_KUBERNETES_CONTEXT_REQUIRED')
    terraform = decode(read(args.terraform_output))
    config = validate_infrastructure(decode(read(args.config)), terraform)
    print(json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': resources(config)} if args.action == 'render' else install(config, terraform, protection_only=args.action == 'install-protection'), indent=2))
