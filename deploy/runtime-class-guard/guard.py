#!/usr/bin/env python3
"""Install/verify the fixed ordinary RuntimeClass guard in an explicit cluster.

Create-only installation never replaces an existing policy/binding. Verification
uses real server dry runs: it cannot change a RuntimeClass or start a workload.
Cluster administrators and the API server remain trusted infrastructure.
"""
import argparse
import copy
import json
from pathlib import Path
import subprocess
import time
import uuid

HERE = Path(__file__).resolve().parent
NAME = 'sandbox-kata-runtimeclass-v1'
CLASS = 'kata-qemu'


class Rejected(ValueError):
    pass


def require(value, code):
    if not value:
        raise Rejected(code)


def strict(raw):
    require(len(raw) <= 128 * 1024, 'KUBERNETES_RESPONSE_BOUND')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def identity(value, name):
    meta = value['metadata']
    require(meta.get('name') == name and not meta.get('deletionTimestamp'), 'OBJECT_IDENTITY')
    require(uuid.UUID(meta['uid']).int != 0, 'OBJECT_UID')
    rv = meta.get('resourceVersion', '')
    require(isinstance(rv, str) and 1 <= len(rv) <= 256
            and all(33 <= ord(c) <= 126 for c in rv), 'OPAQUE_RESOURCE_VERSION')
    return meta['uid']


def validate_guard(actual, expected, ready=True):
    uid = identity(actual, NAME)
    require(actual['kind'] == expected['kind'] and actual['apiVersion'] == expected['apiVersion']
            and actual['spec'] == expected['spec'], 'GUARD_SPEC_DRIFT')
    if ready and actual['kind'] == 'ValidatingAdmissionPolicy':
        generation = actual['metadata'].get('generation')
        status = actual.get('status', {})
        require(type(generation) is int and generation > 0
                and status.get('observedGeneration') == generation
                and isinstance(status.get('typeChecking'), dict)
                and not status['typeChecking'].get('expressionWarnings'), 'GUARD_TYPE_CHECK_NOT_READY')
    return uid


class Guard:
    def __init__(self, kubeconfig, context, cluster_uid):
        require(uuid.UUID(cluster_uid).int != 0 and context and len(context) <= 256, 'EXPLICIT_CLUSTER_REQUIRED')
        require(Path(kubeconfig).is_file(), 'KUBECONFIG_REQUIRED')
        self.argv = ['kubectl', '--kubeconfig', str(Path(kubeconfig).resolve()), '--context', context,
                     '--request-timeout=10s']
        self.cluster_uid = cluster_uid
        self.contract = strict((HERE / 'guard.json').read_bytes())

    def run(self, args, value=None):
        raw = None if value is None else json.dumps(value, separators=(',', ':')).encode()
        result = subprocess.run(self.argv + args, input=raw, capture_output=True, timeout=15, check=False)
        require(len(result.stdout) + len(result.stderr) <= 256 * 1024, 'KUBERNETES_OUTPUT_BOUND')
        return result

    def get(self, kind, name):
        result = self.run(['get', kind, name, '-o', 'json', '--ignore-not-found'])
        require(result.returncode == 0, 'KUBERNETES_GET_FAILED')
        return strict(result.stdout) if result.stdout.strip() else None

    def cluster(self):
        cluster = self.get('namespace', 'kube-system')
        require(cluster is not None and identity(cluster, 'kube-system') == self.cluster_uid, 'CLUSTER_UID_MISMATCH')

    def snapshot(self):
        self.cluster()
        result = {}
        for key, expected in self.contract.items():
            value = self.get(expected['kind'], NAME)
            require(value is not None, 'GUARD_MISSING')
            result[key] = validate_guard(value, expected)
        return result

    def install(self):
        self.cluster()
        for expected in self.contract.values():
            actual = self.get(expected['kind'], NAME)
            if actual is None:
                result = self.run(['create', '-f', '-', '-o', 'json'], expected)
                # A lost ACK/racing install is resolved by exact live readback,
                # never apply/replace, and never accepting only an annotation.
                actual = self.get(expected['kind'], NAME)
                require(actual is not None, 'GUARD_CREATE_UNCONFIRMED')
            validate_guard(actual, expected, ready=False)
        deadline = time.monotonic() + 60
        while True:
            try:
                return {'guard_uids': self.snapshot(), 'class_verified': False}
            except Rejected as error:
                if str(error) != 'GUARD_TYPE_CHECK_NOT_READY' or time.monotonic() >= deadline:
                    raise
                time.sleep(0.25)

    def verify(self):
        before = self.snapshot()
        current = self.get('runtimeclass', CLASS)
        require(current is not None, 'RUNTIMECLASS_MISSING')
        class_uid = identity(current, CLASS)
        require(current['handler'] == CLASS and current.get('scheduling', {}).get('nodeSelector', {})
                .get('sandbox.platform/worker-pool') == 'kata', 'RUNTIMECLASS_BASELINE')
        positive = copy.deepcopy(current)
        positive['metadata'].setdefault('labels', {})['sandbox.platform/guard-probe'] = 'dry-run'
        ok = self.run(['replace', '--dry-run=server', '-f', '-', '-o', 'json'], positive)
        require(ok.returncode == 0, 'POSITIVE_DRY_RUN_FAILED')
        for field, value in [('overhead', {'podFixed': {'cpu': '777m'}}),
                             ('scheduling', {'nodeSelector': {'sandbox.platform/worker-pool': 'kata',
                                                              'sandbox.platform/guard-probe': 'changed'}})]:
            negative = copy.deepcopy(current)
            if negative.get(field) == value:
                value = ({'podFixed': {'cpu': '778m'}} if field == 'overhead' else
                         {'nodeSelector': {'sandbox.platform/worker-pool': 'kata',
                                           'sandbox.platform/guard-probe': 'other'}})
            negative[field] = value
            denied = self.run(['replace', '--dry-run=server', '-f', '-', '-o', 'json'], negative)
            require(denied.returncode != 0 and NAME.encode() in denied.stderr
                    and b'immutable' in denied.stderr, 'CONFIG_DRIFT_NOT_DENIED_BY_GUARD_' + field.upper())
        denied = self.run(['delete', 'runtimeclass', CLASS, '--dry-run=server'])
        require(denied.returncode != 0 and NAME.encode() in denied.stderr
                and b'deletion is forbidden' in denied.stderr, 'DELETE_NOT_DENIED_BY_GUARD')
        after = self.get('runtimeclass', CLASS)
        require(identity(after, CLASS) == class_uid
                and all(after.get(k) == current.get(k) for k in ['handler', 'overhead', 'scheduling'])
                and before == self.snapshot(), 'CONFIG_CHANGED_DURING_PROBES')
        return {'guard_uids': before, 'runtime_class_uid': class_uid,
                'class_verified': True, 'probes': 'SERVER_DRY_RUN_ONLY'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['install', 'verify'])
    parser.add_argument('--kubeconfig', type=Path, required=True)
    parser.add_argument('--context', required=True)
    parser.add_argument('--cluster-uid', required=True)
    args = parser.parse_args()
    try:
        guard = Guard(args.kubeconfig, args.context, args.cluster_uid)
        result = guard.install() if args.mode == 'install' else guard.verify()
        print(json.dumps({'status': 'PASS', 'mode': args.mode, 'cluster_uid': args.cluster_uid, **result}))
    except Rejected as error:
        raise SystemExit('RuntimeClass guard rejected: ' + str(error)) from None
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError):
        # Do not print kubeconfig/transport errors or raw admission response bodies.
        raise SystemExit('RuntimeClass guard rejected; check cluster identity, exact contract, policy readiness and operator permissions') from None


if __name__ == '__main__':
    main()
