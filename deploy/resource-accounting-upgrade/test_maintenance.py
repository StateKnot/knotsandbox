#!/usr/bin/env python3
"""Real maintenance orchestration against an explicitly owned disposable fixture.

The PostgreSQL fixture must first be installed by the ordinary Cargo example
resource_accounting_upgrade_fixture. This does not select a production database.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from urllib.parse import parse_qs, urlsplit
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('maintenance_upgrade', HERE / 'upgrade.py')
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)
spec = importlib.util.spec_from_file_location('maintenance_local_fixture', ROOT / 'scripts/test-resource-upgrade-admission.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--k3s-arm64', type=Path, required=True)
    parser.add_argument('--k3s-airgap-arm64', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--sandboxd', type=Path, required=True)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    parser.add_argument('--agent-smoke-only', action='store_true', help='Only prove the actual disposable node/process fixture; never run or certify migration')
    args = parser.parse_args()
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = {str(p.relative_to(ROOT)): upgrade.sha(p.read_bytes()) for p in [HERE / 'upgrade.py', Path(__file__).resolve(), ROOT / 'scripts/test-resource-upgrade-admission.py']}
    descriptor = upgrade.strict_json(args.fixture.read_text())
    required = ['SANDBOX_UPGRADE_OBSERVER_DATABASE_URL', 'SANDBOX_UPGRADE_MIGRATION_DATABASE_URL', 'SANDBOX_UPGRADE_PREFLIGHT_DATABASE_URL']
    for name in required:
        url = urlsplit(descriptor[name])
        upgrade.require(url.hostname == '127.0.0.1' and url.path.endswith('_test') and url.port
                        and parse_qs(url.query).get('sslmode') == ['verify-full'], 'ONLY_OWNED_LOOPBACK_TLS_TEST_DATABASE')
    db_name = urlsplit(descriptor[required[0]]).path[1:]
    upgrade.require(all(urlsplit(descriptor[k]).path[1:] == db_name for k in required), 'FIXTURE_DATABASE_MISMATCH')
    binary = args.k3s_arm64.resolve()
    data = binary.read_bytes()
    upgrade.require(upgrade.sha(data) == fixture.K3S and data[:5] == b'\x7fELF\x02' and int.from_bytes(data[18:20], 'little') == 183, 'FIXED_OFFICIAL_K3S_BINARY')
    airgap = args.k3s_airgap_arm64.resolve()
    upgrade.require(airgap.is_file() and upgrade.sha(airgap.read_bytes()) == '5b66fde4e29681c09980d64bc77544769210abf8dcbd19dc210427ed12e0e8f8', 'FIXED_OFFICIAL_K3S_AIRGAP')
    sandboxd = args.sandboxd.resolve()
    upgrade.require(sandboxd.name == 'sandboxd' and sandboxd.is_file() and os.access(sandboxd, os.X_OK), 'ORDINARY_SANDBOXD_REQUIRED')
    sandboxd_sha = upgrade.sha(sandboxd.read_bytes())
    host = os.environ.get('DOCKER_HOST')
    if not host:
        host = json.loads(fixture.invoke(['docker', 'context', 'inspect', '--format', '{{json .Endpoints.docker.Host}}']).decode())
    upgrade.require(isinstance(host, str) and re.fullmatch(r'unix:///[^\x00-\x20]+', host), 'LOCAL_DOCKER_SOCKET_REQUIRED')
    docker = ['docker', '--host', host]
    docker_env = {k: v for k, v in os.environ.items() if k not in {'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'}}
    pg_id = descriptor['fixture_container_id']
    upgrade.require(re.fullmatch('[a-f0-9]{64}', pg_id), 'EXACT_OWNED_PG_CONTAINER_ID')
    postgres = json.loads(fixture.invoke(docker + ['inspect', pg_id], env=docker_env))[0]
    upgrade.require(postgres['Id'] == pg_id and postgres['Name'].startswith('/sandbox-resource-'), 'OWNED_RESOURCE_FIXTURE_CONTAINER')
    name = 'sandbox-resource-maintenance-' + uuid.uuid4().hex
    record = {'status': 'STARTED', 'source': source, 'sandboxd_sha256': sandboxd_sha,
              'scope': 'Actual local Kubernetes v1.36.4/fixture Alpine processes and TLS PostgreSQL normal SQLx44→45 migration/preflight; no production service OCI/Kata/cloud/GPU certification',
              'postgres_fixture_container_id': pg_id, 'k3s_sha256': fixture.K3S}
    container = None
    try:
        # --flannel-backend=none plus hostNetwork test Pods avoids downloading
        # a CNI image. The real agent/kubelet executes the imported fixed image.
        container = fixture.invoke(docker + ['run', '--detach', '--name', name, '--label', upgrade.OWNER + '=' + name,
            '--privileged', '--cpus', '2', '--memory', '3g', '--pids-limit', '1024', '--publish', '127.0.0.1::6443',
            '--mount', 'type=bind,src=' + str(binary) + ',dst=/k3s,readonly', '--entrypoint', '/k3s', fixture.BASE,
            'server', '--node-name', name, '--snapshotter', 'native', '--disable', 'traefik,servicelb,metrics-server,local-storage,coredns',
            '--disable-cloud-controller', '--disable-network-policy', '--flannel-backend', 'none', '--write-kubeconfig-mode', '600'], env=docker_env).decode().strip()
        state = json.loads(fixture.invoke(docker + ['inspect', container], env=docker_env))[0]
        bindings = state['NetworkSettings']['Ports']['6443/tcp']
        upgrade.require(len(bindings) == 1 and bindings[0]['HostIp'] == '127.0.0.1', 'ONLY_LOOPBACK_API')
        deadline = time.monotonic() + 120
        kubeconfig = evidence / 'kubeconfig'
        while True:
            p = subprocess.run(docker + ['exec', container, 'cat', '/etc/rancher/k3s/k3s.yaml'], capture_output=True, env=docker_env, timeout=10, check=False)
            if p.returncode == 0:
                raw = p.stdout.decode()
                upgrade.require(raw.count('server: https://127.0.0.1:6443') == 1, 'OWNED_KUBECONFIG')
                fixture.private(kubeconfig, raw.replace('server: https://127.0.0.1:6443', 'server: https://127.0.0.1:' + bindings[0]['HostPort']).encode())
                break
            upgrade.require(time.monotonic() < deadline, 'K3S_CONFIG_TIMEOUT')
            time.sleep(0.25)
        kube = ['kubectl', '--kubeconfig', str(kubeconfig), '--context', 'default', '--request-timeout=5s']
        while True:
            p = subprocess.run(kube + ['get', '--raw', '/readyz'], capture_output=True, timeout=7, check=False)
            if p.returncode == 0 and p.stdout == b'ok':
                break
            upgrade.require(time.monotonic() < deadline, 'K3S_READY_TIMEOUT')
            time.sleep(0.25)
        # Import the already-present approved image into this container's own
        # containerd store. No shared Docker image or volume is removed.
        archive = evidence / 'alpine.tar'
        with archive.open('xb') as output:
            archive.chmod(0o600)
            p = subprocess.run(docker + ['save', '--platform', 'linux/arm64', fixture.BASE], stdout=output, stderr=subprocess.PIPE, env=docker_env, timeout=30)
        upgrade.require(p.returncode == 0, 'LOCAL_IMAGE_ARCHIVE_FAILED')
        fixture.invoke(docker + ['cp', str(archive), container + ':/tmp/alpine.tar'], env=docker_env)
        ctr = docker + ['exec', container, '/k3s', 'ctr', '--namespace', 'k8s.io']
        def import_images(arguments, receipt):
            try:
                imported = subprocess.run(ctr + ['images', 'import', '--local', '--platform', 'linux/arm64', '--snapshotter', 'native'] + arguments,
                                          capture_output=True, env=docker_env, timeout=60, check=False)
            except subprocess.TimeoutExpired as error:
                fixture.private(evidence / receipt, (error.stdout or b'') + (error.stderr or b'') + b'\nIMAGE_IMPORT_TIMEOUT\n')
                raise
            fixture.private(evidence / receipt, imported.stdout + imported.stderr)
            upgrade.require(imported.returncode == 0, 'OWNED_CONTAINERD_IMAGE_IMPORT_FAILED')
        # A digest-only Docker archive has no RepoTags. --digests creates an
        # explicit content-addressed image record rather than silently dropping
        # the imported untagged manifest from the image inventory.
        # A fully qualified base name is also required by CRI checkpoint-image
        # lookup; an auto-generated bare import-* name is normalized to a
        # different docker.io/library/* name by the runtime.
        import_images(['--base-name', 'registry.example.test/fixture-alpine', '--digests', '/tmp/alpine.tar'], 'alpine-import-private.log')
        images = fixture.invoke(ctr + ['images', 'ls', '-q'], env=docker_env).decode().splitlines()
        upgrade.require(images, 'NO_IMPORTED_IMAGE')
        inventory = fixture.invoke(ctr + ['images', 'ls'], env=docker_env).decode().splitlines()
        row = next(line.split() for line in inventory[1:] if line.split()[0] == images[0])
        upgrade.require(re.fullmatch(r'sha256:[0-9a-f]{64}', row[2]), 'ACTUAL_IMPORTED_MANIFEST_DIGEST')
        image = 'registry.example.test/fixture-alpine@' + row[2]
        if images[0] != image:
            fixture.invoke(ctr + ['images', 'tag', images[0], image], env=docker_env)
        record.update(imported_alpine_manifest_digest=row[2], alpine_docker_archive_sha256=upgrade.sha(archive.read_bytes()))
        # ctr's local OCI importer consumes an uncompressed tar stream. Verify
        # the original official gzip above, then decompress without rewriting
        # any manifest or layer content.
        expanded_airgap = evidence / 'airgap.tar'
        with gzip.open(airgap, 'rb') as source_archive, expanded_airgap.open('xb') as output:
            expanded_airgap.chmod(0o600)
            shutil.copyfileobj(source_archive, output)
        fixture.invoke(docker + ['cp', str(expanded_airgap), container + ':/tmp/airgap.tar'], env=docker_env)
        # Import official content without unpacking disabled add-ons. Kubelet
        # unpacks the required official pause image with the native snapshotter.
        import_images(['--no-unpack', '/tmp/airgap.tar'], 'airgap-import-private.log')
        namespace = 'resource-maintenance-' + uuid.uuid4().hex[:12]
        fixture.invoke(kube + ['create', 'namespace', namespace])
        fixture.invoke(kube + ['create', 'serviceaccount', 'sandbox-worker', '-n', namespace])
        cluster = json.loads(fixture.invoke(kube + ['get', 'namespace', 'kube-system', '-o', 'json']))['metadata']['uid']
        plan = {'schema_version': 1, 'namespace': namespace, 'cluster_uid': cluster,
                'writers': {'sandbox-worker': {'containers': {'worker': image}, 'init_containers': {}}},
                'workloads': [{'kind': 'Deployment', 'name': 'worker', 'service_account': 'sandbox-worker', 'replicas': 1}],
                'sandboxd': str(sandboxd), 'sandboxd_sha256': sandboxd_sha, 'database_name': db_name}
        # The fixture's controller process is explicitly Alpine sleep; rollout
        # proves actual orchestration, not an unbuilt production service image.
        pod = {'serviceAccountName': 'sandbox-worker', 'automountServiceAccountToken': False, 'hostNetwork': True, 'nodeName': name,
               'terminationGracePeriodSeconds': 1, 'containers': [{'name': 'worker', 'image': image, 'imagePullPolicy': 'Never',
                 'command': ['/bin/sh', '-c', 'exec sleep 3600'], 'securityContext': {'runAsUser': 10001, 'runAsNonRoot': True},
                 'resources': {'requests': {'cpu': '1m', 'memory': '4Mi'}, 'limits': {'cpu': '100m', 'memory': '16Mi'}}}]}
        workload = {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': 'worker', 'namespace': namespace},
                    'spec': {'replicas': 1, 'selector': {'matchLabels': {'app': 'worker'}}, 'template': {'metadata': {'labels': {'app': 'worker'}}, 'spec': pod}}}
        fixture.invoke(kube + ['create', '-f', '-'], data=upgrade.canonical(workload).encode())
        fixture.invoke(kube + ['rollout', 'status', 'deployment/worker', '-n', namespace, '--timeout=120s'], timeout=130)
        before = json.loads(fixture.invoke(kube + ['get', 'pods', '-n', namespace, '-o', 'json']))['items']
        upgrade.require(len(before) == 1 and before[0]['status']['containerStatuses'][0]['ready'] is True, 'ACTUAL_PREUPGRADE_PROCESS_NOT_READY')
        record['actual_preupgrade_pod_uid'] = before[0]['metadata']['uid']
        if args.agent_smoke_only:
            upgrade.require(source == {p: upgrade.sha((ROOT / p).read_bytes()) for p in source}, 'SOURCE_CHANGED')
            record.update(status='PASS_AGENT_FIXTURE_ONLY', database_migration_executed=False,
                          sandboxd_executed=False, scope='Actual disposable K3s agent/node and imported fixed Alpine process readiness only')
            return
        gate = upgrade.Gate(plan, kubeconfig, 'default', evidence / 'gate')
        saved = {k: os.environ.get(k) for k in required}
        os.environ.update({k: descriptor[k] for k in required})
        try:
            gate.run('maintain')
        finally:
            for k, value in saved.items():
                if value is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = value
        after = json.loads(fixture.invoke(kube + ['get', 'pods', '-n', namespace, '-o', 'json']))['items']
        upgrade.require(len(after) == 1 and after[0]['status']['containerStatuses'][0]['ready'] is True
                        and after[0]['metadata']['uid'] != record['actual_preupgrade_pod_uid'], 'ACTUAL_NEW_PROCESS_ROLLOUT_NOT_VERIFIED')
        record['actual_postupgrade_pod_uid'] = after[0]['metadata']['uid']
        record['gate'] = gate.record
        upgrade.require(source == {p: upgrade.sha((ROOT / p).read_bytes()) for p in source}
                        and upgrade.sha(sandboxd.read_bytes()) == sandboxd_sha, 'SOURCE_OR_BINARY_CHANGED')
        record['status'] = 'PASS'
    finally:
        if record['status'] not in ('PASS', 'PASS_AGENT_FIXTURE_ONLY'):
            record['status'] = 'FAIL'
        cleanup = fixture.cleanup_control_plane(docker, docker_env, name, container, evidence)
        record['owned_k3s_cleanup'] = cleanup
        record['owned_k3s_cleanup_confirmed'] = True if cleanup['status'] == 'CONFIRMED' else 'UNCONFIRMED'
        if cleanup['status'] != 'CONFIRMED':
            record['status'] = 'FAIL'
        fixture.private(evidence / 'record.json', (json.dumps(record, indent=2) + '\n').encode())
        upgrade.require(cleanup['status'] == 'CONFIRMED', 'OWNED_K3S_CLEANUP_UNCONFIRMED')
    print('PASS actual maintained SQLx upgrade, ordinary app preflight and new Kubernetes fixture process rollout')


if __name__ == '__main__':
    main()
