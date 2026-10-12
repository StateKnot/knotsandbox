#!/usr/bin/env python3
"""Read-only check for policies that widen a reviewed component's Cilium policy.

This checks Kubernetes configuration, never data-plane enforcement. A passing
report cannot activate an uncertified sandbox runtime or replace packet tests.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time


class BoundaryError(ValueError):
    pass


def require(value, message):
    if not value:
        raise BoundaryError(message)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON field')
            result[key] = value
        return result
    require(len(raw) <= 8 * 1024 * 1024, 'cluster response exceeds bound')
    def constant(_):
        raise BoundaryError('nonfinite JSON number')
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except RecursionError:
        raise BoundaryError('JSON nesting exceeds bound') from None


def manifest_bytes(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 8*1024*1024,
                'bounded regular reviewed manifest required')
        raw = source.read(8*1024*1024 + 1)
        after = os.fstat(source.fileno())
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'manifest changed during read')
        require(len(raw) <= 8*1024*1024, 'manifest exceeds bound')
        return raw


def matches(selector, labels, cilium=False):
    require(isinstance(selector, dict) and set(selector) <= {'matchLabels', 'matchExpressions'},
            'unsupported selector; overlap cannot be proved')
    def values(key):
        require(isinstance(key, str) and key, 'invalid selector key')
        if not cilium:
            return [labels[key]] if key in labels else []
        source, sep, name = key.partition(':')
        if not sep:
            source, name = 'any', key
        require(source in ('any', 'k8s', 'reserved'), 'unknown Cilium label source')
        return [v for k, v in labels.items() if
                (k.partition(':')[2] == name if source == 'any' else k == source + ':' + name)]
    fixed = selector.get('matchLabels', {})
    expressions = selector.get('matchExpressions', [])
    require(isinstance(fixed, dict) and isinstance(expressions, list) and len(expressions) <= 128,
            'malformed selector')
    for key, value in fixed.items():
        require(isinstance(value, str), 'selector value must be a string')
        if value not in values(key):
            return False
    for expression in expressions:
        require(isinstance(expression, dict) and set(expression) <= {'key', 'operator', 'values'},
                'unsupported selector expression')
        operator = expression.get('operator')
        actual = values(expression.get('key'))
        expected = expression.get('values', [])
        require(isinstance(expected, list) and all(isinstance(v, str) for v in expected),
                'invalid expression values')
        if operator in ('In', 'NotIn'):
            require(bool(expected), 'set expression requires values')
            intersects = any(v in expected for v in actual)
            if (operator == 'In' and not intersects) or (operator == 'NotIn' and intersects):
                return False
        elif operator in ('Exists', 'DoesNotExist'):
            require(not expected, 'existence expression cannot carry values')
            if (operator == 'Exists' and not actual) or (operator == 'DoesNotExist' and actual):
                return False
        else:
            raise BoundaryError('unsupported expression operator')
    return True


def items(document):
    require(isinstance(document, dict) and isinstance(document.get('items'), list),
            'complete Kubernetes List required')
    require(not document.get('metadata', {}).get('continue'), 'truncated policy inventory')
    require(not document.get('metadata', {}).get('remainingItemCount'), 'incomplete policy inventory')
    require(len(document['items']) <= 512, 'policy inventory exceeds reviewed bound')
    return document['items']


def selection_inputs(value):
    """Collection RV is an observation point, not a selected item's version."""
    if isinstance(value, dict):
        if 'items' in value:
            resources = items(value)
            def identity(resource):
                metadata = resource.get('metadata', {})
                return (resource.get('kind', ''), metadata.get('namespace', ''), metadata.get('name', ''))
            keys = [identity(resource) for resource in resources]
            require(len(keys) == len(set(keys)), 'duplicate resource in observed inventory')
            return {key: body for key, body in value.items() if key != 'metadata' and key != 'items'} | {
                'items': sorted(resources, key=identity)}
        return {key: selection_inputs(body) for key, body in value.items()}
    if isinstance(value, list):
        return [selection_inputs(body) for body in value]
    return value


def collection_versions(observation):
    lists = {'pods': observation['pods'], 'endpoints': observation['endpoints'],
             **observation['unknown_engines']}
    lists.update({f'policy_inventory_{index}': body for index, body in enumerate(observation['policies'])})
    return {key: body.get('metadata', {}).get('resourceVersion') for key, body in lists.items()}


def endpoint_identity(endpoint, pod, namespace_labels, cluster_name):
    """Read actual policy identity; Pod labels can be excluded by Cilium filters."""
    metadata = endpoint.get('metadata', {})
    wanted = pod['metadata']
    require(endpoint.get('kind') == 'CiliumEndpoint' and endpoint.get('apiVersion') == 'cilium.io/v2'
            and metadata.get('name') == wanted['name']
            and metadata.get('namespace') == wanted['namespace']
            and metadata.get('uid') and metadata.get('resourceVersion')
            and not metadata.get('deletionTimestamp'), 'current Cilium endpoint required')
    owners = metadata.get('ownerReferences', [])
    require(len(owners) == 1 and owners[0].get('kind') == 'Pod' and owners[0].get('apiVersion') == 'v1'
            and owners[0].get('name') == wanted['name'] and wanted.get('uid')
            and owners[0].get('uid') == wanted['uid'], 'endpoint does not own the current Pod UID')
    status = endpoint.get('status', {})
    require(status.get('state') == 'ready', 'Cilium endpoint is not ready')
    for direction in ('ingress', 'egress'):
        policy = status.get('policy', {}).get(direction, {})
        require(policy.get('enforcing') is True and policy.get('state') == 'enforcing',
                'endpoint does not report bidirectional enforcement')
    identity = status.get('identity', {})
    require(type(identity.get('id')) is int and 256 <= identity['id'] <= 4294967295,
            'ordinary endpoint identity required')
    raw_labels = identity.get('labels')
    require(isinstance(raw_labels, list) and 1 <= len(raw_labels) <= 512, 'bounded identity labels required')
    labels = {}
    for raw in raw_labels:
        require(isinstance(raw, str) and 1 <= len(raw) <= 1024, 'invalid identity label')
        key, _, value = raw.partition('=')
        source, separator, name = key.partition(':')
        require(separator and source == 'k8s' and name and key not in labels,
                'reserved, unknown or duplicate identity label')
        labels[key] = value
    required = {'k8s:io.kubernetes.pod.namespace': wanted['namespace'],
                'k8s:io.cilium.k8s.policy.serviceaccount': pod['spec'].get('serviceAccountName', 'default'),
                'k8s:io.cilium.k8s.policy.cluster': cluster_name,
                'k8s:sandbox.platform/network-policy': wanted.get('labels', {}).get('sandbox.platform/network-policy')}
    require(required['k8s:sandbox.platform/network-policy'] and
            all(labels.get(key) == value for key, value in required.items()),
            'actual Cilium identity differs or boundary label is filtered')
    for key, value in labels.items():
        prefix = 'k8s:io.cilium.k8s.namespace.labels.'
        if key.startswith(prefix):
            require(namespace_labels.get(key[len(prefix):]) == value, 'namespace identity label is stale')
    return labels


def analyze(expected, namespace, namespace_labels, pod_labels, service_account, inventories,
            cluster_name='default', *, endpoint_labels):
    """Compare actual selectors/specs, not policy names or desired labels alone."""
    require(expected.get('kind') == 'CiliumNetworkPolicy' and expected.get('apiVersion') == 'cilium.io/v2',
            'one reviewed namespaced Cilium policy required')
    require(expected['metadata']['namespace'] == namespace, 'reviewed namespace differs')
    require(pod_labels.get('sandbox.platform/network-policy'), 'dedicated boundary label missing')
    labels = endpoint_labels
    require(isinstance(labels, dict) and labels and all(isinstance(k, str) and isinstance(v, str)
            for k, v in labels.items()), 'actual Cilium identity required')
    require(matches(expected['spec']['endpointSelector'], labels, True), 'reviewed policy misses pod')
    require('ingress' in expected['spec'] and 'egress' in expected['spec'],
            'reviewed policy must explicitly cover both directions')
    require(expected['spec'].get('enableDefaultDeny', {'ingress': True, 'egress': True}) ==
            {'ingress': True, 'egress': True}, 'default deny is disabled')
    seen = 0
    selected = []
    for document in inventories:
        for policy in items(document):
            kind = policy.get('kind')
            metadata = policy.get('metadata', {})
            name = metadata.get('name')
            policy_namespace = metadata.get('namespace')
            if kind in ('CiliumNetworkPolicy', 'NetworkPolicy') and policy_namespace != namespace:
                continue
            if kind == 'NetworkPolicy':
                spec = policy['spec']
                if not matches(spec['podSelector'], pod_labels):
                    continue
                require(not spec.get('ingress') and not spec.get('egress'),
                        'additional Kubernetes policy allows traffic')
                require(set(spec) <= {'podSelector', 'policyTypes', 'ingress', 'egress'},
                        'unknown Kubernetes policy semantics')
                require(set(spec.get('policyTypes', ['Ingress'])) <= {'Ingress', 'Egress'},
                        'unknown Kubernetes policy direction')
                continue
            require(kind in ('CiliumNetworkPolicy', 'CiliumClusterwideNetworkPolicy'),
                    'additional policy engine requires separate review')
            require(not ('spec' in policy and 'specs' in policy), 'ambiguous Cilium rule set')
            rules = [policy['spec']] if 'spec' in policy else policy.get('specs')
            require(isinstance(rules, list) and 0 < len(rules) <= 128, 'invalid Cilium rule set')
            for rule in rules:
                if 'nodeSelector' in rule:
                    require(kind == 'CiliumClusterwideNetworkPolicy' and 'endpointSelector' not in rule,
                            'ambiguous host and endpoint policy')
                    continue
                require('endpointSelector' in rule, 'unknown Cilium policy scope')
                if not matches(rule['endpointSelector'], labels, True):
                    continue
                if kind == expected['kind'] and name == expected['metadata']['name']:
                    require(len(rules) == 1 and rule == expected['spec'], 'reviewed policy was changed')
                    seen += 1
                    selected.append({'kind': kind, 'namespace': namespace, 'name': name,
                                     'uid': metadata.get('uid'), 'resource_version': metadata.get('resourceVersion')})
                else:
                    # Even a second "narrow" allow can widen the union. A pure
                    # default-deny addition is harmless but still needs review.
                    raise BoundaryError('additional Cilium policy selects component')
    require(seen == 1, 'reviewed live policy missing or duplicated')
    return {'configuration_overlap': 'PASS', 'runtime_enforcement': 'NOT_VERIFIED',
            'reviewed_spec_sha256': hashlib.sha256(json.dumps(expected['spec'], sort_keys=True,
                separators=(',', ':')).encode()).hexdigest(), 'selected_policies': selected}


def bounded_command(command, limit=8 * 1024 * 1024, timeout=8):
    """Never echo kubectl stderr or kubeconfig/token-bearing responses."""
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    result = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while selector.get_map():
                require(time.monotonic() < deadline, 'cluster read timed out')
                for key, _ in selector.select(min(.2, max(0, deadline - time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    result.extend(chunk)
                    require(len(result) <= limit, 'cluster response exceeds bound')
        require(child.wait(timeout=max(.1, deadline-time.monotonic())) == 0,
                'cluster read failed; authorization/discovery must be complete')
        return bytes(result)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=2)
        child.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--kubeconfig', required=True, type=Path)
    parser.add_argument('--context', required=True)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    from policy_snapshot import snapshot
    raw_manifest = manifest_bytes(args.manifest)
    manifest = strict_json(raw_manifest)
    expected = [v for v in items(manifest) if v.get('kind') == 'CiliumNetworkPolicy']
    deployment = [v for v in items(manifest) if v.get('kind') == 'Deployment']
    require(len(expected) == len(deployment) == 1, 'one component deployment and policy required')
    expected = expected[0]
    desired = deployment[0]['spec']['template']
    namespace = expected['metadata']['namespace']
    require(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', namespace), 'invalid namespace')
    with snapshot(args.kubeconfig, args.context, seconds=45) as frozen:
        command = ['kubectl', '--kubeconfig', str(frozen.config_path), '--context', frozen.context,
                   '--request-timeout=5s', '--cache-dir', str(frozen.cache_dir)]
        def read(arguments, limit=8*1024*1024):
            return bounded_command(command + arguments, limit=limit,
                                   timeout=frozen.remaining_timeout(maximum=8))
        def get(resource, namespaced=False):
            return strict_json(read(['get', resource] +
                (['--namespace', namespace] if namespaced else ['--all-namespaces']) + ['-o', 'json']))
        supported = {'ciliumnetworkpolicies.cilium.io', 'ciliumclusterwidenetworkpolicies.cilium.io',
                     'networkpolicies.networking.k8s.io'}
        def observe():
            resources = read(['api-resources', '--verbs=list', '-o', 'name'], 256*1024).decode().splitlines()
            unknown = frozen.check_discovery(resources)
            require(supported | {'ciliumendpoints.cilium.io'} <= set(resources), 'required Cilium APIs missing')
            extensions = {}
            for resource in unknown:
                document = get(resource)
                require(not items(document), 'unsupported live network policy requires review')
                extensions[resource] = document
            return {'discovery': sorted(resources), 'unknown_engines': extensions,
                'namespace': strict_json(read(['get', 'namespace', namespace, '-o', 'json'])),
                'config': strict_json(read(['get', 'configmap', 'cilium-config', '-n', 'kube-system', '-o', 'json'])),
                'pods': get('pods', True), 'endpoints': get('ciliumendpoints.cilium.io', True),
                'policies': [get(resource, resource != 'ciliumclusterwidenetworkpolicies.cilium.io')
                             for resource in sorted(supported)]}
        observation = observe()
        cilium_config = observation['config']
        require(cilium_config.get('data', {}).get('enable-policy') == 'always', 'Cilium always enforcement required')
        namespace_labels = observation['namespace']['metadata'].get('labels', {})
        pod_list = items(observation['pods'])
        pods = [v for v in pod_list if all(v['metadata'].get('labels', {}).get(k) == value
            for k, value in desired['metadata']['labels'].items()) and not v['metadata'].get('deletionTimestamp')]
        require(len(pods) >= deployment[0]['spec']['replicas'], 'all desired replicas must exist before checking')
        endpoints = items(observation['endpoints'])
        results = []
        identities = []
        for pod in pods:
            require(not pod['spec'].get('hostNetwork'), 'host-network component is outside this gate')
            require(pod['spec'].get('serviceAccountName', 'default') == desired['spec']['serviceAccountName'],
                    'actual service account differs')
            require(any(v.get('type') == 'Ready' and v.get('status') == 'True'
                        for v in pod.get('status', {}).get('conditions', [])), 'component pod not ready')
            matching = [v for v in endpoints if v.get('metadata', {}).get('name') == pod['metadata']['name']]
            require(len(matching) == 1, 'one current Cilium endpoint required for each Pod')
            endpoint = matching[0]
            labels = endpoint_identity(endpoint, pod, namespace_labels,
                                       cilium_config['data'].get('cluster-name', 'default'))
            results.append(analyze(expected, namespace, namespace_labels,
                pod['metadata']['labels'], desired['spec']['serviceAccountName'], observation['policies'],
                cilium_config['data'].get('cluster-name', 'default'), endpoint_labels=labels))
            identities.append({'pod_uid': pod['metadata']['uid'], 'endpoint_uid': endpoint['metadata']['uid'],
                'endpoint_resource_version': endpoint['metadata']['resourceVersion'],
                'identity_id': endpoint['status']['identity']['id'],
                'identity_labels_sha256': hashlib.sha256(json.dumps(labels, sort_keys=True,
                    separators=(',', ':')).encode()).hexdigest()})
        # Recheck every input that affects policy selection, not just policy
        # specs. The observation remains bounded and is never an atomic or
        # future data-plane guarantee. Changing inputs require a new check.
        final_observation = observe()
        require(selection_inputs(final_observation) == selection_inputs(observation),
                'policy-selection input changed during check')
        frozen.remaining_timeout()
        report = {'configuration_overlap': 'PASS', 'runtime_enforcement': 'NOT_VERIFIED',
                  'reviewed_manifest_sha256': hashlib.sha256(raw_manifest).hexdigest(),
                  'pod_uids': [v['metadata']['uid'] for v in pods], 'endpoint_identities': identities,
                  'collection_resource_versions': {'initial': collection_versions(observation),
                                                   'final': collection_versions(final_observation)},
                  'checks': results, 'observed_unix_seconds': int(time.time())}
        descriptor = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as target:
            json.dump(report, target, indent=2)
            target.write('\n')
            target.flush()
            os.fsync(target.fileno())
        print('Live policy configuration overlap check passed; packet enforcement remains unverified.')


if __name__ == '__main__':
    try:
        main()
    except (BoundaryError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('Policy boundary check failed; no activation or secret output.')
