#!/usr/bin/env python3
"""Collect exact host identities after upstream configuration, without inventing hashes."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tomllib
import uuid

RUNTIME_ENDPOINT = 'unix:///run/sandbox-nodeguard/cri.sock'
IMAGE_ENDPOINT = 'unix:///run/containerd/containerd.sock'
KATA_CONFIG = Path('/etc/kata-containers/configuration-qemu.toml')
CONTAINERD_CONFIG = Path('/etc/containerd/config.toml')
KUBELET_CONFIG = Path('/etc/kubernetes/kubelet-config.yaml')
KUBELET_ENVIRONMENT = Path('/etc/kubernetes/kubelet.env')
SHIM = Path('/opt/kata/bin/containerd-shim-kata-v2')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def pinned(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path and '..' not in path.parts, 'noncanonical profile path')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0, 'profile file is not root-owned and immutable to other users')
    require(info.st_size <= 512 * 1024 * 1024, 'profile file exceeds hash budget')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            digest.update(block)
    return {'path': str(path), 'sha256': digest.hexdigest()}


def scalar_yaml(text, key):
    # Kubelet file is emitted by the pinned upstream template. Do not parse a
    # second arbitrary YAML dialect here or silently accept duplicate keys.
    values = re.findall(r'^' + re.escape(key) + r'\s*:\s*(.*?)\s*$', text, re.MULTILINE)
    require(len(values) == 1, 'missing or duplicate kubelet field: ' + key)
    return values[0].strip('\'"')


def validate_configurations(kata, containerd, kubelet):
    hyper = kata['hypervisor']['qemu']
    require(hyper['enable_annotations'] == [] and hyper['enable_debug'] is False, 'unsafe Kata annotation/debug configuration')
    require(hyper['shared_fs'] == 'virtio-fs', 'certified observer requires virtio-fs')
    require(kata['runtime']['sandbox_cgroup_only'] is True and kata['runtime']['disable_new_netns'] is False, 'Kata host namespace/cgroup isolation differs')
    require(kata['factory']['enable_template'] is False and kata['factory']['vm_cache_number'] == 0, 'Kata VM reuse is forbidden')
    require(containerd['version'] == 4, 'containerd configuration must be v4')
    require(containerd.get('disabled_plugins') == ['io.containerd.monitor.container.v1.restart'], 'containerd restart monitor must not bypass the durable CRI gate')
    runtime = containerd['plugins']['io.containerd.cri.v1.runtime']['containerd']
    require(runtime['default_runtime_name'] == 'runc', 'system workload default must remain runc')
    require(set(runtime['runtimes']) == {'runc', 'kata-qemu'}, 'uncontrolled runtime handler')
    kata_runtime = runtime['runtimes']['kata-qemu']
    require(kata_runtime['runtime_type'] == 'io.containerd.kata.v2', 'incorrect Go Kata shim type')
    require(kata_runtime['options'] == {'ConfigPath': str(KATA_CONFIG)}, 'uncontrolled Kata runtime option')
    require(runtime['runtimes']['runc']['options']['SystemdCgroup'] is True, 'runc systemd cgroups are required')
    require(scalar_yaml(kubelet, 'containerRuntimeEndpoint') == RUNTIME_ENDPOINT, 'kubelet bypasses nodeguard')
    require(scalar_yaml(kubelet, 'imageServiceEndpoint') == IMAGE_ENDPOINT, 'explicit image endpoint required')
    require(scalar_yaml(kubelet, 'cgroupDriver') == 'systemd', 'kubelet cgroup driver differs')
    return hyper


def write_new(path, value):
    data = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return hashlib.sha256(data).hexdigest()


def collect(request, destination):
    require(os.geteuid() == 0, 'host profile collection requires root')
    require(not (destination / 'profile.json').exists() and not (destination / 'config.json').exists(), 'refusing to replace enrolled configuration')
    require(not Path('/var/lib/sandbox-nodeguard/initialized.json').exists(), 'existing node identity requires fenced maintenance')
    for key in ['cluster_epoch', 'node_uid']:
        require(str(uuid.UUID(request[key])) == request[key] and uuid.UUID(request[key]).int != 0, 'invalid UUID')
    deployment = request.get('metrics_deployment')
    if deployment is not None:
        require(isinstance(deployment, str) and re.fullmatch(r'[a-zA-Z0-9_-]{1,63}', deployment), 'invalid metrics deployment identity')
    hyper = validate_configurations(tomllib.loads(KATA_CONFIG.read_text()), tomllib.loads(CONTAINERD_CONFIG.read_text()), KUBELET_CONFIG.read_text())
    environment=KUBELET_ENVIRONMENT.read_text()
    require('--container-runtime-endpoint' not in environment and '--image-service-endpoint' not in environment, 'kubelet CLI overrides guarded endpoints')
    require(re.findall(r'--config=([^\s\\"\']+)',environment) == [str(KUBELET_CONFIG)], 'kubelet CLI does not use the pinned configuration')
    profile = {'protocol': 1, 'runtime_handler': 'kata-qemu', 'containerd_version': '2.3.5',
               'qemu': pinned(hyper['path']), 'virtiofs': pinned(hyper['virtio_fs_daemon']), 'shim': pinned(SHIM),
               'kata_configuration': pinned(KATA_CONFIG), 'containerd_configuration': pinned(CONTAINERD_CONFIG), 'kubelet_configuration': pinned(KUBELET_CONFIG), 'kubelet_environment': pinned(KUBELET_ENVIRONMENT)}
    # QEMU /proc/exe must match the actual canonical binary, not a symlink alias.
    node = {key: request[key] for key in ['cluster_epoch', 'node_uid', 'node_name']}
    node['boot_id'] = str(uuid.UUID(Path('/proc/sys/kernel/random/boot_id').read_text().strip()))
    node['profile_sha256'] = write_new(destination / 'profile.json', profile)
    config = {'node': node, 'profile_file': str(destination / 'profile.json'), 'listen': request['private_ip'] + ':9444',
              'tls_certificate': str(destination / 'tls/server.pem'), 'tls_key': str(destination / 'tls/server-key.pem'), 'controller_client_ca': str(destination / 'tls/controller-ca.pem')}
    if deployment is not None:
        config['metrics'] = {'listen': request['private_ip'] + ':9445', 'deployment': deployment, 'scraper_client_ca': str(destination / 'tls/scraper-ca.pem')}
    write_new(destination / 'config.json', config)
    artifact = {'protocol': 1, 'node': node, **{key: request[key] for key in ['cloud_account_id', 'region', 'cloud_instance_id', 'private_ip', 'certification_id']}, 'guard_port': 9444}
    write_new(destination / 'enrollment.json', artifact)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--destination', type=Path, default=Path('/etc/sandbox-nodeguard'))
    args = parser.parse_args()
    collect(json.loads(args.request.read_text()), args.destination)
