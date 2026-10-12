#!/usr/bin/env python3
"""Compose scoped storage credentials into a reviewed trusted Deployment; no apply."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re

SCOPES = {'api': ('file-upload', 'file-reader', 'output-reader'),
          'gateway': ('file-gateway', 'gateway'), 'worker': ('file-cleaner',)}
NS = 'sandbox-system'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True).encode()


def configuration(inputs, component, purpose):
    require(component in SCOPES and purpose in SCOPES[component], 'COMPONENT_SCOPE')
    require(set(inputs) == {'deployment', 'account_id', 'region', 'workload_roles'}, 'INPUT_FIELDS')
    deployment, account, region = inputs['deployment'], inputs['account_id'], inputs['region']
    require(isinstance(deployment, str) and re.fullmatch(r'[a-z0-9][a-z0-9-]{1,30}[a-z0-9]', deployment), 'DEPLOYMENT_NAME')
    require(isinstance(account, str) and re.fullmatch(r'\d{16}', account), 'ACCOUNT')
    require(isinstance(region, str) and re.fullmatch(r'[a-z]{2}-[a-z][a-z0-9-]{1,24}', region), 'REGION')
    identity = inputs['workload_roles'][purpose]
    require(set(identity) == {'arn', 'role_id', 'subject', 'issuer', 'audience'}, 'ROLE_FIELDS')
    require(identity['arn'] == f'acs:ram::{account}:role/{deployment}-{purpose}', 'ROLE_BINDING')
    require(identity['subject'] == f'system:serviceaccount:{NS}:sandbox-{component}' and identity['audience'] == 'sts.aliyuncs.com', 'OIDC_BINDING')
    require(isinstance(identity['role_id'], str) and re.fullmatch(r'\d{1,32}', identity['role_id']), 'ROLE_ID')
    from urllib.parse import urlsplit
    issuer = urlsplit(identity['issuer'])
    require(issuer.scheme == 'https' and issuer.hostname and issuer.port in (None, 443)
            and not issuer.username and not issuer.password and not issuer.query and not issuer.fragment, 'ISSUER')
    return {'deployment': deployment, 'account_id': account, 'region': region, 'purpose': purpose,
            'role_id': identity['role_id'], 'oidc_issuer': identity['issuer'],
            'oidc_token_file': '/var/run/storage-oidc/token',
            'output_file': f'/run/sandbox-cloud/{purpose}/private/sts.json'}


def compose(deployment, inputs, component):
    require(component in SCOPES, 'TRUSTED_COMPONENT_REQUIRED')
    require(deployment.get('apiVersion') == 'apps/v1' and deployment.get('kind') == 'Deployment'
            and deployment['metadata'].get('namespace') == NS
            and deployment['metadata'].get('name') == 'sandbox-' + component, 'EXACT_DEPLOYMENT')
    result = copy.deepcopy(deployment)
    pod = result['spec']['template']['spec']
    require(pod.get('serviceAccountName') == 'sandbox-' + component and pod.get('automountServiceAccountToken') is False, 'EXACT_SERVICE_ACCOUNT')
    require(not any(pod.get(k) for k in ('hostNetwork', 'hostPID', 'hostIPC')) and pod.get('nodeSelector') == {'sandbox.platform/node-pool': 'platform'}, 'TRUSTED_PLATFORM_POD')
    security = pod.get('securityContext', {})
    require(security.get('runAsUser') == 10001 and security.get('runAsGroup') == 10001
            and security.get('fsGroup') == 10001 and security.get('runAsNonRoot') is True
            and security.get('seccompProfile') == {'type': 'RuntimeDefault'}, 'POD_SECURITY')
    containers = pod['containers']
    require(len(containers) == 1 and containers[0]['name'] == component, 'ONE_PRODUCT_CONTAINER')
    application = containers[0]
    image = application['image']
    require(re.fullmatch(r'[a-z0-9.-]+(?::[0-9]+)?/[a-zA-Z0-9/_-]+@sha256:[0-9a-f]{64}', image), 'PINNED_SERVICE_IMAGE')
    require(application.get('securityContext') == {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}}, 'APPLICATION_SECURITY')
    # The installer must provide application settings and role-specific DB/Kube
    # rights separately. No token or mutable credential file enters a Secret.
    volumes = pod.setdefault('volumes', [])
    init = pod.setdefault('initContainers', [])
    require(not any(v['name'].startswith('storage-') for v in volumes)
            and not any(c['name'].startswith('storage-') for c in init), 'EXISTING_CREDENTIAL_COMPOSITION')
    mounts = application.setdefault('volumeMounts', [])
    require(not any(m['mountPath'].startswith(('/run/sandbox-cloud', '/var/run/storage-oidc')) for m in mounts), 'CREDENTIAL_MOUNT_COLLISION')
    configs = {purpose + '.json': canonical(configuration(inputs, component, purpose)).decode() for purpose in SCOPES[component]}
    digest = hashlib.sha256(canonical(configs)).hexdigest()[:16]
    name = f'sandbox-{component}-storage-{digest}'
    configmap = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': name, 'namespace': NS,
        'labels': {'app.kubernetes.io/managed-by': 'sandbox-product'}}, 'immutable': True, 'data': configs}
    volumes += [{'name': 'storage-config', 'configMap': {'name': name, 'defaultMode': 0o440}},
                {'name': 'storage-oidc', 'projected': {'defaultMode': 0o440, 'sources': [
                    {'serviceAccountToken': {'path': 'token', 'audience': 'sts.aliyuncs.com', 'expirationSeconds': 600}}]}}]
    for purpose in SCOPES[component]:
        volume = 'storage-' + purpose
        target = '/run/sandbox-cloud/' + purpose
        volumes.append({'name': volume, 'emptyDir': {'medium': 'Memory', 'sizeLimit': '1Mi'}})
        mounts.append({'name': volume, 'mountPath': target, 'readOnly': True})
        command = ['/usr/local/bin/sandbox-credentials', '--config', '/run/storage-config/' + purpose + '.json']
        init.append({'name': 'storage-' + purpose, 'restartPolicy': 'Always', 'image': image, 'imagePullPolicy': 'Always',
            'command': command, 'securityContext': copy.deepcopy(application['securityContext']),
            'volumeMounts': [{'name': 'storage-config', 'mountPath': '/run/storage-config', 'readOnly': True},
                {'name': 'storage-oidc', 'mountPath': '/var/run/storage-oidc', 'readOnly': True},
                {'name': volume, 'mountPath': target}],
            'startupProbe': {'exec': {'command': command + ['--check']}, 'periodSeconds': 5, 'timeoutSeconds': 3, 'failureThreshold': 36},
            'readinessProbe': {'exec': {'command': command + ['--check']}, 'periodSeconds': 10, 'timeoutSeconds': 3, 'failureThreshold': 1},
            'resources': {'requests': {'cpu': '20m', 'memory': '32Mi'}, 'limits': {'cpu': '250m', 'memory': '128Mi'}}})
    result['spec']['template'].setdefault('metadata', {}).setdefault('annotations', {})['sandbox.platform/storage-config-sha256'] = hashlib.sha256(canonical(configs)).hexdigest()
    return [configmap, result]


def load(path):
    value = path.read_bytes()
    require(len(value) <= 1024 * 1024, 'INPUT_TOO_LARGE')
    return json.loads(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deployment', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--component', choices=SCOPES, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    values = compose(load(args.deployment), load(args.inputs), args.component)
    # Creation only; never overwrite a reviewed revision or contact a cluster.
    with args.output.open('xb') as out:
        out.write(canonical({'apiVersion': 'v1', 'kind': 'List', 'items': values}) + b'\n')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError):
        raise SystemExit('STORAGE_CREDENTIAL_COMPOSITION_REJECTED') from None
