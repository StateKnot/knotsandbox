#!/usr/bin/env python3
"""Real RuntimeClass admission/readback in an owned local Docker control plane.

Requires the already verified official fixture binary; no user Kubernetes
context, database, guest workload or existing Docker container is selected.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('runtime_fixture', ROOT / 'scripts/test-resource-upgrade-admission.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
spec = importlib.util.spec_from_file_location('runtime_guard', ROOT / 'deploy/runtime-class-guard/guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--k3s-arm64', type=Path, required=True)
    parser.add_argument('--readback-binary', type=Path, required=True)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    args = parser.parse_args()
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    binary = args.k3s_arm64.resolve()
    raw = binary.read_bytes()
    guard.require(hashlib.sha256(raw).hexdigest() == fixture.K3S and raw[:5] == b'\x7fELF\x02'
                  and int.from_bytes(raw[18:20], 'little') == 183, 'FIXED_OFFICIAL_K3S_REQUIRED')
    checker = args.readback_binary.resolve()
    guard.require(checker.is_file() and os.access(checker, os.X_OK), 'PRODUCTION_READBACK_BINARY_REQUIRED')
    sources = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in [
        Path(__file__).resolve(), ROOT / 'deploy/runtime-class-guard/guard.py', ROOT / 'deploy/runtime-class-guard/guard.json',
        ROOT / 'src/runtime_class_guard.rs', ROOT / 'src/runtime.rs', ROOT / 'src/runtime_resource_contract.rs',
        ROOT / 'examples/runtime_class_guard_check.rs', ROOT / 'scripts/test-resource-upgrade-admission.py']}
    checker_sha = hashlib.sha256(checker.read_bytes()).hexdigest()
    host = os.environ.get('DOCKER_HOST')
    guard.require(host is not None and host.startswith('unix:///') and not any(c.isspace() for c in host), 'EXPLICIT_LOCAL_DOCKER_REQUIRED')
    docker = ['docker', '--host', host]
    env = {k: v for k, v in os.environ.items() if k not in {'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY'}}
    name = 'sandbox-resource-runtimeclass-' + uuid.uuid4().hex
    container = None
    probes = []
    record = {'status': 'STARTED', 'source': sources, 'checker_sha256': checker_sha,
              'scope': 'Actual isolated local Kubernetes admission and production TLS client readback; no guest/Kata/cloud/GPU certification'}
    try:
        container = fixture.invoke(docker + ['run', '--detach', '--name', name, '--label', fixture.module.OWNER + '=' + name,
            '--privileged', '--cpus', '2', '--memory', '3g', '--pids-limit', '512', '--publish', '127.0.0.1::6443',
            '--mount', 'type=bind,src=' + str(binary) + ',dst=/k3s,readonly', '--entrypoint', '/k3s', fixture.BASE,
            'server', '--disable-agent', '--disable', 'traefik,servicelb,metrics-server,local-storage,coredns',
            '--disable-cloud-controller', '--disable-network-policy', '--flannel-backend', 'none', '--write-kubeconfig-mode', '600'], env=env).decode().strip()
        state = json.loads(fixture.invoke(docker + ['inspect', container], env=env))[0]
        binding = state['NetworkSettings']['Ports']['6443/tcp']
        guard.require(len(binding) == 1 and binding[0]['HostIp'] == '127.0.0.1', 'LOOPBACK_ONLY')
        deadline = time.monotonic() + 90
        kubeconfig = evidence / 'kubeconfig'
        while True:
            result = subprocess.run(docker + ['exec', container, 'cat', '/etc/rancher/k3s/k3s.yaml'], capture_output=True, env=env, timeout=10)
            if result.returncode == 0:
                raw = result.stdout.decode()
                guard.require(raw.count('server: https://127.0.0.1:6443') == 1, 'OWNED_KUBECONFIG')
                fixture.private(kubeconfig, raw.replace('server: https://127.0.0.1:6443', 'server: https://127.0.0.1:' + binding[0]['HostPort']).encode())
                break
            guard.require(time.monotonic() < deadline, 'CONFIG_TIMEOUT')
            time.sleep(0.25)
        kube = ['kubectl', '--kubeconfig', str(kubeconfig), '--context', 'default', '--request-timeout=5s']
        while True:
            result = subprocess.run(kube + ['get', '--raw', '/readyz'], capture_output=True, timeout=7)
            if result.returncode == 0 and result.stdout == b'ok':
                break
            guard.require(time.monotonic() < deadline, 'API_READY_TIMEOUT')
            time.sleep(0.25)
        cluster = json.loads(fixture.invoke(kube + ['get', 'namespace', 'kube-system', '-o', 'json']))['metadata']['uid']
        operator = guard.Guard(kubeconfig, 'default', cluster)
        raw_run = operator.run
        def record_probe(arguments, value=None):
            result = raw_run(arguments, value)
            if arguments[0] in ('replace', 'delete'):
                probes.append({'arguments': arguments, 'returncode': result.returncode,
                               'stdout': result.stdout.decode(errors='replace'),
                               'stderr': result.stderr.decode(errors='replace')})
            return result
        operator.run = record_probe
        record['installation'] = operator.install()
        def check(expected, category=None):
            result = subprocess.run([str(checker)], env=dict(env, KUBECONFIG=str(kubeconfig)), capture_output=True, timeout=30)
            guard.require((result.returncode == 0) == expected, 'READBACK_EXPECTATION_FAILED')
            guard.require(result.stdout.strip() == b'PASS_CURRENT_MANAGED_RUNTIMECLASS_READBACK' if expected
                          else result.stderr.strip() == category.encode(), 'READBACK_FAILURE_CATEGORY_MISMATCH')
            return result.returncode
        record['missing_class_rejected'] = check(False, 'READBACK_REJECTED_NOT_FOUND') != 0
        class_obj = {'apiVersion': 'node.k8s.io/v1', 'kind': 'RuntimeClass', 'metadata': {'name': guard.CLASS},
                     'handler': guard.CLASS, 'scheduling': {'nodeSelector': {'sandbox.platform/worker-pool': 'kata'}},
                     'overhead': {'podFixed': {'cpu': '250m', 'memory': '128Mi'}}}
        fixture.invoke(kube + ['create', '-f', '-'], data=json.dumps(class_obj).encode())
        # Informer propagation is asynchronous. The operator's bounded positive
        # and negative server probes must actually enforce the exact guard.
        deadline = time.monotonic() + 30
        while True:
            try:
                record['verification'] = operator.verify()
                break
            except guard.Rejected:
                guard.require(time.monotonic() < deadline, 'GUARD_PROPAGATION_TIMEOUT')
                time.sleep(0.25)
        record['actual_production_tls_readback'] = check(True) == 0
        # API-server admission copies the actual RuntimeClass overhead into a
        # server dry-run Pod. No guest can be scheduled or executed by this test.
        pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'resource-overhead-probe', 'namespace': 'default'},
               'spec': {'runtimeClassName': guard.CLASS, 'containers': [{'name': 'probe', 'image': fixture.BASE,
                        'resources': {'requests': {'cpu': '1', 'memory': '2Gi'}, 'limits': {'cpu': '1', 'memory': '2Gi'}}}]}}
        admitted = json.loads(fixture.invoke(kube + ['create', '--dry-run=server', '-f', '-', '-o', 'json'], data=json.dumps(pod).encode()))
        guard.require(admitted['spec']['overhead'] == class_obj['overhead']['podFixed'], 'ACTUAL_OVERHEAD_NOT_COPIED')
        record['actual_server_pod_overhead'] = admitted['spec']['overhead']
        unrelated = {'apiVersion': 'node.k8s.io/v1', 'kind': 'RuntimeClass',
                     'metadata': {'name': 'unrelated-guard-fixture'}, 'handler': 'runc'}
        fixture.invoke(kube + ['create', '-f', '-'], data=json.dumps(unrelated).encode())
        fixture.invoke(kube + ['patch', 'runtimeclass', 'unrelated-guard-fixture', '--type=merge',
                              '-p', '{"overhead":{"podFixed":{"memory":"1Mi"}}}'])
        fixture.invoke(kube + ['delete', 'runtimeclass', 'unrelated-guard-fixture'])
        record['non_target_class_unaffected'] = True
        fixture.invoke(kube + ['delete', 'validatingadmissionpolicybinding', guard.NAME])
        record['missing_binding_rejected'] = check(False, 'READBACK_REJECTED_NOT_FOUND') != 0
        drift = json.loads((ROOT / 'deploy/runtime-class-guard/guard.json').read_text())['binding']
        drift['spec']['validationActions'] = ['Audit']
        fixture.invoke(kube + ['create', '-f', '-'], data=json.dumps(drift).encode())
        record['audit_only_binding_rejected'] = check(False, 'READBACK_REJECTED_CONFIGURATION') != 0
        fixture.invoke(kube + ['delete', 'validatingadmissionpolicybinding', guard.NAME])
        fixture.invoke(kube + ['create', '-f', '-'], data=json.dumps(operator.contract['binding']).encode())
        record['restored_binding_readback'] = check(True) == 0
        fixture.invoke(kube + ['create', '-f', str(ROOT / 'deploy/runtime-class-guard/read-rbac.json')])
        permissions = []
        for account in ['sandbox-worker', 'sandbox-gateway', 'sandbox-termination']:
            for resource in ['validatingadmissionpolicies', 'validatingadmissionpolicybindings']:
                for verb, suffix, expected in [('get', '/' + guard.NAME, b'yes'), ('get', '/other-name', b'no'),
                                               ('list', '', b'no'), ('patch', '/' + guard.NAME, b'no')]:
                    result = subprocess.run(kube + ['auth', 'can-i', verb, resource + suffix,
                        '--as=system:serviceaccount:sandbox-system:' + account], capture_output=True, timeout=10)
                    guard.require(result.stdout.strip() == expected, 'RBAC_PRIVILEGE_BOUNDARY')
                    permissions.append({'account': account, 'resource': resource + suffix, 'verb': verb,
                                        'allowed': expected == b'yes'})
        record['actual_rbac_checks'] = permissions
        guard.require(sources == {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in sources}
                      and checker_sha == hashlib.sha256(checker.read_bytes()).hexdigest(), 'SOURCE_OR_BINARY_CHANGED')
        record['status'] = 'PASS'
    finally:
        fixture.private(evidence / 'probe-private.json', (json.dumps(probes, indent=2) + '\n').encode())
        if record['status'] != 'PASS':
            record['status'] = 'FAIL'
        cleanup = fixture.cleanup_control_plane(docker, env, name, container, evidence)
        record['owned_cleanup'] = cleanup
        if cleanup['status'] != 'CONFIRMED':
            record['status'] = 'FAIL'
        fixture.private(evidence / 'record.json', (json.dumps(record, indent=2) + '\n').encode())
        guard.require(cleanup['status'] == 'CONFIRMED', 'OWNED_CLEANUP_UNCONFIRMED')
    print('PASS actual RuntimeClass guard/admission/production TLS readback; owned cleanup confirmed')


if __name__ == '__main__':
    main()
