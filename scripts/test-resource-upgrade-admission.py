#!/usr/bin/env python3
"""Actual Kubernetes admission in a new disposable local Docker control plane.

This never selects a user Kubernetes context or database. K3s runs without an
agent; approved/old images are admission inputs and no guest process is started.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / 'deploy/resource-accounting-upgrade'
spec = importlib.util.spec_from_file_location('resource_upgrade_actual', HERE / 'upgrade.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
BASE = 'alpine@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507'
K3S = 'c920706346d5ad4e5cd3c7bf1bb09ce71ebe07fec829e513e40f1caf98aed8bb'


def invoke(args, *, data=None, env=None, timeout=30):
    result = subprocess.run(args, input=data, capture_output=True, env=env, timeout=timeout, check=False)
    module.require(result.returncode == 0 and len(result.stdout) <= 8 * 1024 * 1024, 'ACTUAL_FIXTURE_COMMAND_FAILED')
    return result.stdout


def private(path, raw):
    with path.open('xb') as output:
        path.chmod(0o600)
        output.write(raw)


def cleanup_control_plane(docker, env, name, container, evidence):
    """Recover a daemon-created container even if `docker run` lost its ACK."""
    receipt = {'status': 'UNCONFIRMED', 'errors': []}
    try:
        module.require(re.fullmatch(r'sandbox-resource-[a-z0-9-]+', name), 'OWNED_CONTAINER_NAME_REQUIRED')
        inspected = subprocess.run(docker + ['inspect', '--format', '{{json .}}', name],
                                   capture_output=True, env=env, timeout=15, check=False)
        if inspected.returncode == 0:
            actual = module.strict_json(inspected.stdout.decode())
            owned = actual['Id']
            module.require(re.fullmatch('[a-f0-9]{64}', owned) and actual['Name'] == '/' + name
                           and actual['Config'].get('Labels', {}).get(module.OWNER) == name
                           and (container is None or container == owned), 'OWNED_CLEANUP_IDENTITY')
            receipt.update(container_id=owned, recovered_after_unacknowledged_create=container is None)
            logs = subprocess.run(docker + ['logs', owned], capture_output=True, env=env, timeout=15, check=False)
            private(evidence / 'k3s-private.log', logs.stdout + logs.stderr)
            stopped = subprocess.run(docker + ['stop', '--time', '10', owned], capture_output=True, env=env, timeout=20, check=False)
            removed = subprocess.run(docker + ['rm', owned], capture_output=True, env=env, timeout=15, check=False)
            if stopped.returncode or removed.returncode:
                receipt['errors'].append('OWNED_STOP_OR_REMOVE_NOT_ACKNOWLEDGED')
        absent = subprocess.run(docker + ['ps', '-aq', '--filter', 'name=^/' + name + '$'],
                                capture_output=True, env=env, timeout=15, check=False)
        if absent.returncode == 0 and not absent.stdout.strip():
            receipt['status'] = 'CONFIRMED'
        else:
            receipt['errors'].append('OWNED_CONTAINER_ABSENCE_UNCONFIRMED')
    except (module.Rejected, ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        receipt['errors'].append('OWNED_CONTAINER_CLEANUP_UNCONFIRMED')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--k3s-arm64', type=Path, required=True)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    args = parser.parse_args()
    source = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in [HERE / 'upgrade.py', Path(__file__).resolve()]}
    binary = args.k3s_arm64.resolve()
    data = binary.read_bytes()
    module.require(not binary.is_symlink() and hashlib.sha256(data).hexdigest() == K3S
                   and data[:5] == b'\x7fELF\x02' and int.from_bytes(data[18:20], 'little') == 183,
                   'OFFICIAL_FIXED_K3S_ARM64_BINARY_REQUIRED')
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(parents=True, mode=0o700, exist_ok=False)
    docker_env = {k: v for k, v in os.environ.items()
                  if k not in {'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'}}
    host = os.environ.get('DOCKER_HOST')
    if not host:
        host = json.loads(invoke(['docker', 'context', 'inspect', '--format', '{{json .Endpoints.docker.Host}}']).decode())
    module.require(isinstance(host, str) and re.fullmatch(r'unix:///[^\x00-\x20]+', host)
                   and all(v not in ('.', '..') for v in host[7:].split('/')), 'LOCAL_DOCKER_UNIX_SOCKET_REQUIRED')
    docker = ['docker', '--host', host]
    image = json.loads(invoke(docker + ['image', 'inspect', BASE], env=docker_env).decode())
    module.require(len(image) == 1 and image[0]['Architecture'] == 'arm64' and image[0]['Os'] == 'linux', 'LOCAL_FIXED_ARM64_BASE_REQUIRED')
    name = 'sandbox-resource-admission-' + uuid.uuid4().hex
    record = {'status': 'STARTED', 'source': source, 'k3s_sha256': K3S, 'base_image': BASE,
              'scope': 'Actual isolated local Kubernetes v1.36.4 API admission; no guest/DB migration/cloud/Kata/GPU certification',
              'database_migration_executed': False, 'guest_started': False}
    container = None
    gate = None
    try:
        # Real daemon-side creation with the client acknowledgement discarded.
        # The cleanup helper receives None, just as after a run CLI timeout.
        ack_name = name + '-ack-loss'
        try:
            invoke(docker + ['run', '--detach', '--name', ack_name, '--label', module.OWNER + '=' + ack_name,
                             '--network', 'none', '--entrypoint', '/bin/sleep', BASE, '3600'], env=docker_env)
        finally:
            ack_evidence = evidence / 'unacknowledged-create'
            ack_evidence.mkdir(mode=0o700)
            recovered = cleanup_control_plane(docker, docker_env, ack_name, None, ack_evidence)
            record['actual_unacknowledged_create_cleanup'] = recovered
            module.require(recovered['status'] == 'CONFIRMED', 'UNACKNOWLEDGED_CREATE_CLEANUP_UNCONFIRMED')
        container = invoke(docker + ['run', '--detach', '--name', name, '--label', module.OWNER + '=' + name,
            '--privileged', '--cpus', '2', '--memory', '3g', '--pids-limit', '512',
            '--publish', '127.0.0.1::6443', '--mount', 'type=bind,src=' + str(binary) + ',dst=/k3s,readonly',
            '--entrypoint', '/k3s', BASE, 'server', '--disable-agent', '--disable', 'traefik,servicelb,metrics-server,local-storage,coredns',
            '--disable-cloud-controller', '--disable-network-policy', '--flannel-backend', 'none', '--write-kubeconfig-mode', '600'], env=docker_env).decode().strip()
        state = json.loads(invoke(docker + ['inspect', container], env=docker_env))[0]
        module.require(state['Name'] == '/' + name and state['Config']['Labels'].get(module.OWNER) == name, 'OWNED_CONTAINER_IDENTITY')
        bindings = state['NetworkSettings']['Ports']['6443/tcp']
        module.require(len(bindings) == 1 and bindings[0]['HostIp'] == '127.0.0.1', 'LOOPBACK_CONTROL_PLANE_ONLY')
        port = bindings[0]['HostPort']
        deadline = time.monotonic() + 90
        kubeconfig = evidence / 'kubeconfig'
        while True:
            result = subprocess.run(docker + ['exec', container, 'cat', '/etc/rancher/k3s/k3s.yaml'],
                                    capture_output=True, env=docker_env, timeout=10, check=False)
            if result.returncode == 0:
                raw = result.stdout.decode()
                module.require(raw.count('server: https://127.0.0.1:6443') == 1, 'OWNED_K3S_KUBECONFIG')
                private(kubeconfig, raw.replace('server: https://127.0.0.1:6443', 'server: https://127.0.0.1:' + port).encode())
                break
            module.require(time.monotonic() < deadline, 'K3S_CONFIG_TIMEOUT')
            time.sleep(0.25)
        kubectl = ['kubectl', '--kubeconfig', str(kubeconfig), '--context', 'default', '--request-timeout=5s']
        while True:
            result = subprocess.run(kubectl + ['get', '--raw', '/readyz'], capture_output=True, timeout=7, check=False)
            if result.returncode == 0 and result.stdout == b'ok':
                break
            module.require(time.monotonic() < deadline, 'K3S_API_READY_TIMEOUT')
            time.sleep(0.25)
        namespace = 'resource-upgrade-' + uuid.uuid4().hex[:16]
        invoke(kubectl + ['create', 'namespace', namespace])
        for account in ['sandbox-worker', 'sandbox-backup-controller']:
            invoke(kubectl + ['create', 'serviceaccount', account, '-n', namespace])
        cluster = json.loads(invoke(kubectl + ['get', 'namespace', 'kube-system', '-o', 'json']))['metadata']['uid']
        service = 'registry.example.test/service@sha256:' + 'a' * 64
        sidecar = 'registry.example.test/sidecar@sha256:' + 'b' * 64
        plan = {'schema_version': 1, 'namespace': namespace, 'cluster_uid': cluster,
                'writers': {'sandbox-worker': {'containers': {'worker': service, 'credentials': sidecar}, 'init_containers': {'secrets-init': service}},
                            'sandbox-backup-controller': {'containers': {'backup': service}, 'init_containers': {}}},
                'workloads': [{'kind': 'Deployment', 'name': 'worker', 'service_account': 'sandbox-worker', 'replicas': 1},
                              {'kind': 'StatefulSet', 'name': 'backup', 'service_account': 'sandbox-backup-controller', 'replicas': 1}],
                'sandboxd': '/not-executed/sandboxd', 'sandboxd_sha256': 'c' * 64, 'database_name': 'not_selected'}
        gate = module.Gate(plan, kubeconfig, 'default', evidence / 'gate')
        before = gate.probe('sandbox-worker')
        before['spec']['containers'][0]['image'] = 'registry.example.test/old@sha256:' + '0' * 64
        gate.kubectl(['create', '--dry-run=server', '-f', '-'], before)
        record['red_uninstalled_old_image_accepted'] = True
        gate.run('install')
        record['approved_actual_admission_matrix'] = gate.record
        # Exercise the production create-only lock against the real API, then
        # invoke a second complete maintain action. It must fail before policy
        # installation, workload mutation, or database credential use.
        holder = module.Gate(plan, kubeconfig, 'default', evidence / 'operation-lock-holder')
        contender = module.Gate(plan, kubeconfig, 'default', evidence / 'operation-lock-contender')
        holder.identity()
        holder.acquire_operation_lock()
        owned_uid = holder.operation_lock['uid']
        try:
            try:
                contender.run('maintain')
            except module.Rejected as error:
                module.require(str(error) == 'UPGRADE_OPERATION_LOCK_NOT_ACQUIRED', 'UNEXPECTED_SECOND_MAINTAIN_FAILURE')
            else:
                raise module.Rejected('SECOND_MAINTAIN_MUST_NOT_ACQUIRE_EXISTING_LOCK')
            module.require(holder.get('configmaps', holder.operation_lock['name'])['metadata']['uid'] == owned_uid
                           and not contender.maintenance
                           and not any(v['stage'] == 'ADMISSION_INSTALLED' for v in contender.record['stages']),
                           'SECOND_MAINTAIN_CHANGED_OWNED_OPERATION')
            holder.record['status'] = 'PASS'
        finally:
            holder.release_operation_lock()
            holder.save()
        record['actual_second_maintain_rejected'] = {'status': 'VERIFIED', 'holder_uid': owned_uid,
                                                     'owner_uid_precondition_release_confirmed': True,
                                                     'contender_status': contender.record['status']}
        # An omitted protected product identity is denied rather than silently
        # falling outside the allowlist; another namespace remains unaffected.
        invoke(kubectl + ['create', 'serviceaccount', 'sandbox-api', '-n', namespace])
        omitted = gate.probe('sandbox-worker')
        omitted['spec']['serviceAccountName'] = 'sandbox-api'
        gate.kubectl(['create', '--dry-run=server', '-f', '-'], omitted, expected=1, marker=module.DENIED)
        other = namespace + '-other'
        invoke(kubectl + ['create', 'namespace', other])
        invoke(kubectl + ['create', 'serviceaccount', 'sandbox-worker', '-n', other])
        outside = gate.probe('sandbox-worker')
        outside['metadata']['namespace'] = other
        outside['spec']['containers'][0]['image'] = 'registry.example.test/old@sha256:' + '0' * 64
        gate.kubectl(['create', '--dry-run=server', '-f', '-'], outside)
        record['actual_unconfigured_writer_denied_and_other_namespace_unaffected'] = True
        # Real controller objects let the production maintenance path actually
        # scale both kinds to zero, then encounter a deliberately absent DB
        # credential. This must leave the server-enforced CLOSED fence in place.
        for w in plan['workloads']:
            probe = gate.probe(w['service_account'])
            pod_spec = probe['spec']
            pod_spec['restartPolicy'] = 'Always'
            pod_spec['terminationGracePeriodSeconds'] = 0
            labels = {'app': w['name']}
            workload = {'apiVersion': 'apps/v1', 'kind': w['kind'], 'metadata': {'name': w['name'], 'namespace': namespace},
                        'spec': {'replicas': 1, 'selector': {'matchLabels': labels}, 'template': {'metadata': {'labels': labels}, 'spec': pod_spec}}}
            if w['kind'] == 'StatefulSet':
                workload['spec']['serviceName'] = 'not-used'
            gate.kubectl(['create', '-f', '-'], workload)
        failed = module.Gate(plan, kubeconfig, 'default', evidence / 'failure-fence')
        saved = {k: os.environ.pop(k) for k in list(os.environ) if k.startswith('SANDBOX_UPGRADE_')}
        try:
            try:
                failed.run('maintain')
            except module.Rejected as error:
                module.require(str(error) == 'DEDICATED_VERIFIED_TLS_OBSERVER_REQUIRED', 'UNEXPECTED_MAINTENANCE_FAILURE')
            else:
                raise module.Rejected('MISSING_DB_CREDENTIAL_MUST_NOT_COMPLETE_MAINTENANCE')
        finally:
            os.environ.update(saved)
        failed.verify(closed=True)
        for w in plan['workloads']:
            actual = failed.get(w['kind'].lower(), w['name'])
            module.require(actual['spec']['replicas'] == 0, 'FAILED_MAINTENANCE_RESUMED_WRITER')
        pods = failed.get('pods')['items']
        module.require(not [p for p in pods if p['spec'].get('serviceAccountName') in plan['writers']], 'FAILED_MAINTENANCE_LEFT_WRITER_POD')
        record['actual_failure_fence'] = {'status': 'VERIFIED', 'maintenance_left_closed': failed.record.get('maintenance_left_closed'),
                                          'writer_replicas': 0, 'writer_pods': 0, 'migration_not_reached': True}
        module.require(failed.record['status'] == 'FAIL' and failed.record.get('maintenance_left_closed') is True, 'FAILURE_RECEIPT_REQUIRED')
        module.require(source == {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in source}, 'SOURCE_CHANGED_DURING_ACCEPTANCE')
        record['status'] = 'PASS'
    finally:
        if record['status'] != 'PASS':
            record['status'] = 'FAIL'
        cleanup = cleanup_control_plane(docker, docker_env, name, container, evidence)
        record['owned_control_plane_cleanup'] = cleanup
        record['owned_control_plane_cleanup_confirmed'] = True if cleanup['status'] == 'CONFIRMED' else 'UNCONFIRMED'
        if cleanup['status'] != 'CONFIRMED':
            record['status'] = 'FAIL'
        private(evidence / 'record.json', (json.dumps(record, indent=2) + '\n').encode())
    module.require(record['status'] == 'PASS', 'ACTUAL_CONTROL_PLANE_ACCEPTANCE_OR_CLEANUP_FAILED')
    print('PASS actual isolated Kubernetes admission and failed-maintenance CLOSED fence; no DB migration or cloud certification')


if __name__ == '__main__':
    main()
