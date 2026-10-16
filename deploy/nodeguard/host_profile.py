#!/usr/bin/env python3
"""Collect exact host identities after upstream configuration, without inventing hashes."""
from __future__ import annotations
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tomllib
import uuid

RUNTIME_ENDPOINT = 'unix:///run/sandbox-nodeguard/cri.sock'
IMAGE_ENDPOINT = 'unix:///run/containerd/containerd.sock'
KATA_CONFIG = Path('/etc/kata-containers/configuration-qemu.toml')
CONTAINERD_CONFIG = Path('/etc/containerd/config.toml')
KUBELET_CONFIG = Path('/etc/kubernetes/kubelet-config.yaml')
KUBELET_ENVIRONMENT = Path('/etc/kubernetes/kubelet.env')
SHIM = Path('/opt/kata/bin/containerd-shim-kata-v2')
MAX_CONFIG_BYTES = 1024 * 1024
MAX_BINARY_BYTES = 512 * 1024 * 1024


def require(ok, message):
    if not ok:
        raise ValueError(message)


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class PinnedDirectory:
    """An original directory FD reached through root-owned, non-writable parents."""

    def __init__(self, path):
        self.path, self.descriptors, self.entries = Path(path), [], []
        try:
            require(self.path.is_absolute() and '..' not in self.path.parts
                    and str(self.path) == str(path), 'noncanonical profile path')
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_DIRECTORY
            self.fd = os.open('/', flags)
            self.descriptors.append(self.fd)
            for name in self.path.parts[1:]:
                parent = self.fd
                self.fd = os.open(name, flags, dir_fd=parent)
                self.descriptors.append(self.fd)
                self.entries.append((parent, name, self.fd))
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        for descriptor in self.descriptors:
            info = os.fstat(descriptor)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0,
                    'profile directory is not trusted')
        for parent, name, descriptor in self.entries:
            current, opened = os.stat(name, dir_fd=parent, follow_symlinks=False), os.fstat(descriptor)
            require((current.st_dev, current.st_ino, current.st_mode, current.st_uid, current.st_gid)
                    == (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid, opened.st_gid),
                    'profile directory path changed after open')

    def close(self):
        for descriptor in reversed(self.descriptors):
            os.close(descriptor)
        self.descriptors = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class PinnedInput:
    """Keep the verified bytes, digest and original path identity together."""

    def __init__(self, path, limit=MAX_BINARY_BYTES, retain=False):
        self.path, self.fd, self.directory = Path(path), None, None
        try:
            require(self.path.is_absolute() and '..' not in self.path.parts
                    and str(self.path) == str(path), 'noncanonical profile path')
            self.directory = PinnedDirectory(self.path.parent)
            self.fd = os.open(self.path.name,
                              os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                              dir_fd=self.directory.fd)
            self.before = os.fstat(self.fd)
            require(stat.S_ISREG(self.before.st_mode) and self.before.st_uid == 0
                    and self.before.st_mode & 0o022 == 0, 'profile file is not trusted')
            require(self.before.st_size <= limit, 'profile input exceeds byte budget')
            digest, chunks, total = hashlib.sha256(), [], 0
            while True:
                block = os.read(self.fd, min(65536, limit + 1 - total))
                if not block:
                    break
                total += len(block)
                require(total <= limit, 'profile input exceeds byte budget')
                digest.update(block)
                if retain:
                    chunks.append(block)
            require(total == self.before.st_size, 'profile input changed during read')
            self.value = {'path': str(self.path), 'sha256': digest.hexdigest()}
            self.data = b''.join(chunks) if retain else None
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        self.directory.check()
        require(file_identity(os.fstat(self.fd)) == file_identity(self.before)
                and file_identity(os.stat(self.path.name, dir_fd=self.directory.fd,
                                          follow_symlinks=False)) == file_identity(self.before),
                'profile input changed after read')

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.directory is not None:
            self.directory.close()
            self.directory = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


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
    require(type(containerd.get('version')) is int and containerd['version'] == 4,
            'containerd configuration must be v4')
    require(containerd.get('imports', []) == [] and not containerd.get('plugin_dir')
            and not containerd.get('proxy_plugins') and not containerd.get('stream_processors'),
            'unverified containerd configuration extension')
    # v4 server plugins can override the legacy [grpc] table. Snapshotter plugin
    # roots and other dynamic execution/storage overrides are outside this
    # supported profile, even if the legacy paths still look correct.
    plugins = containerd.get('plugins', {})
    require(isinstance(plugins, dict) and set(plugins) <= {
        'io.containerd.cri.v1.runtime', 'io.containerd.cri.v1.images',
        'io.containerd.nri.v1.nri', 'io.containerd.internal.v1.tracing',
        'io.containerd.tracing.processor.v1.otlp',
    }, 'unverified containerd plugin configuration')
    nri = plugins.get('io.containerd.nri.v1.nri')
    require(isinstance(nri, dict) and set(nri) == {'disable'} and nri['disable'] is True,
            'NRI must be explicitly disabled without plugin overrides')
    require(containerd.get('root') == '/var/lib/containerd'
            and containerd.get('state') == '/run/containerd', 'containerd storage paths differ')
    grpc = containerd.get('grpc', {})
    require(isinstance(grpc, dict) and grpc.get('address', '/run/containerd/containerd.sock')
            == '/run/containerd/containerd.sock' and not grpc.get('tcp_address'),
            'containerd endpoint differs')
    require(containerd.get('disabled_plugins') == ['io.containerd.monitor.container.v1.restart'], 'containerd restart monitor must not bypass the durable CRI gate')
    runtime = containerd['plugins']['io.containerd.cri.v1.runtime']['containerd']
    require(runtime['default_runtime_name'] == 'runc', 'system workload default must remain runc')
    require(set(runtime['runtimes']) == {'runc', 'kata-qemu'}, 'uncontrolled runtime handler')
    kata_runtime = runtime['runtimes']['kata-qemu']
    require(set(kata_runtime) <= {'runtime_type', 'options', 'snapshotter'},
            'unverified Kata runtime override')
    require(kata_runtime['runtime_type'] == 'io.containerd.kata.v2', 'incorrect Go Kata shim type')
    require(kata_runtime['options'] == {'ConfigPath': str(KATA_CONFIG)}, 'uncontrolled Kata runtime option')
    require(runtime['runtimes']['runc']['options']['SystemdCgroup'] is True, 'runc systemd cgroups are required')
    images = containerd.get('plugins', {}).get('io.containerd.cri.v1.images', {})
    require(isinstance(images, dict) and images.get('snapshotter') == 'overlayfs',
            'unsupported default image snapshotter')
    mappings = images.get('runtime_platforms')
    require(isinstance(mappings, dict) and set(mappings) == {'kata-qemu'},
            'explicit Kata image platform mapping is required')
    require(mappings['kata-qemu'] == {'platform': 'linux/amd64', 'snapshotter': 'overlayfs'},
            'unsupported Kata image platform or snapshotter')
    require(kata_runtime.get('snapshotter') in (None, '', 'overlayfs'),
            'runtime and image snapshotter mappings conflict')
    require(scalar_yaml(kubelet, 'containerRuntimeEndpoint') == RUNTIME_ENDPOINT, 'kubelet bypasses nodeguard')
    require(scalar_yaml(kubelet, 'imageServiceEndpoint') == IMAGE_ENDPOINT, 'explicit image endpoint required')
    require(scalar_yaml(kubelet, 'cgroupDriver') == 'systemd', 'kubelet cgroup driver differs')
    return hyper


def write_new(directory, name, value):
    directory.check()
    require(os.fstat(directory.fd).st_mode & 0o077 == 0, 'untrusted profile destination')
    data = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                 0o600, dir_fd=directory.fd)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(directory.fd)
    directory.check()
    require(os.fstat(directory.fd).st_mode & 0o077 == 0, 'untrusted profile destination')
    return hashlib.sha256(data).hexdigest()


def output_exists(directory, name):
    try:
        os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def collect(request, destination):
    require(os.geteuid() == 0, 'host profile collection requires root')
    require(os.uname().sysname == 'Linux' and os.uname().machine == 'x86_64',
            'host profile supports only Linux amd64')
    destination = Path(destination)
    require(not os.path.lexists('/var/lib/sandbox-nodeguard/initialized.json'),
            'existing node identity requires fenced maintenance')
    for key in ['cluster_epoch', 'node_uid']:
        require(str(uuid.UUID(request[key])) == request[key]
                and uuid.UUID(request[key]).int != 0, 'invalid UUID')
    deployment = request.get('metrics_deployment')
    if deployment is not None:
        require(isinstance(deployment, str) and re.fullmatch(r'[a-zA-Z0-9_-]{1,63}', deployment),
                'invalid metrics deployment identity')
    with ExitStack() as stack:
        output = stack.enter_context(PinnedDirectory(destination))
        require(os.fstat(output.fd).st_mode & 0o077 == 0, 'untrusted profile destination')
        require(not any(output_exists(output, name) for name in
                        ('profile.json', 'config.json', 'enrollment.json')),
                'refusing to replace enrolled configuration')
        inputs = []
        def capture(path, retain=False):
            item = stack.enter_context(PinnedInput(path, MAX_CONFIG_BYTES if retain
                                                  else MAX_BINARY_BYTES, retain))
            inputs.append(item)
            return item
        kata = capture(KATA_CONFIG, True)
        containerd = capture(CONTAINERD_CONFIG, True)
        kubelet = capture(KUBELET_CONFIG, True)
        environment = capture(KUBELET_ENVIRONMENT, True)
        hyper = validate_configurations(tomllib.loads(kata.data.decode()),
                                        tomllib.loads(containerd.data.decode()),
                                        kubelet.data.decode())
        text = environment.data.decode()
        require('--container-runtime-endpoint' not in text and '--image-service-endpoint' not in text,
                'kubelet CLI overrides guarded endpoints')
        require(re.findall(r'--config=([^\s\\"\']+)', text) == [str(KUBELET_CONFIG)],
                'kubelet CLI does not use the pinned configuration')
        qemu, virtiofs, shim = capture(hyper['path']), capture(hyper['virtio_fs_daemon']), capture(SHIM)
        profile = {'protocol': 1, 'runtime_handler': 'kata-qemu', 'containerd_version': '2.3.5',
                   'qemu': qemu.value, 'virtiofs': virtiofs.value, 'shim': shim.value,
                   'kata_configuration': kata.value, 'containerd_configuration': containerd.value,
                   'kubelet_configuration': kubelet.value, 'kubelet_environment': environment.value}
        # This is a configuration identity, not evidence of a running Kata VM,
        # actual pull/unpack, native references, or preparation resource limits.
        node = {key: request[key] for key in ['cluster_epoch', 'node_uid', 'node_name']}
        node['boot_id'] = str(uuid.UUID(Path('/proc/sys/kernel/random/boot_id').read_text().strip()))
        for item in inputs:
            item.check()
        node['profile_sha256'] = write_new(output, 'profile.json', profile)
        config = {'node': node, 'profile_file': str(destination / 'profile.json'),
                  'listen': request['private_ip'] + ':9444',
                  'tls_certificate': str(destination / 'tls/server.pem'),
                  'tls_key': str(destination / 'tls/server-key.pem'),
                  'controller_client_ca': str(destination / 'tls/controller-ca.pem')}
        if deployment is not None:
            config['metrics'] = {'listen': request['private_ip'] + ':9445',
                                 'deployment': deployment,
                                 'scraper_client_ca': str(destination / 'tls/scraper-ca.pem')}
        write_new(output, 'config.json', config)
        # Enrollment is the last published artifact. A partial earlier failure
        # remains quarantined and must be reviewed; never remove existing files.
        for item in inputs:
            item.check()
        artifact = {'protocol': 1, 'node': node,
                    **{key: request[key] for key in ['cloud_account_id', 'region',
                         'cloud_instance_id', 'private_ip', 'certification_id']}, 'guard_port': 9444}
        write_new(output, 'enrollment.json', artifact)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--destination', type=Path, default=Path('/etc/sandbox-nodeguard'))
    args = parser.parse_args()
    try:
        with PinnedInput(args.request, MAX_CONFIG_BYTES, True) as request:
            collect(json.loads(request.data), args.destination)
    except Exception:
        print('Host profile collection failed', file=sys.stderr)
        raise SystemExit(1)
