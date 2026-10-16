#!/usr/bin/env python3
"""Exercise the real host-profile collector inside its disposable Linux fixture.

The public placeholder binaries establish file identity only. They are never
executed and do not certify Kata, containerd, a VM, or image preparation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

MARKER = Path('/fixture/CONFINED_HOST_PROFILE_TEST')
WORK = Path('/tmp/host-profile-cli')
KATA = Path('/etc/kata-containers/configuration-qemu.toml')
CONTAINERD = Path('/etc/containerd/config.toml')
KUBELET = Path('/etc/kubernetes/kubelet-config.yaml')
ENVIRONMENT = Path('/etc/kubernetes/kubelet.env')
QEMU = Path('/opt/kata/bin/qemu-system-x86_64')
VIRTIOFS = Path('/opt/kata/bin/virtiofsd')
SHIM = Path('/opt/kata/bin/containerd-shim-kata-v2')
SECRET = b'PUBLIC_SECRET_SENTINEL_HOST_PROFILE'
CASES = ('valid', 'missing-mapping', 'runtime-conflict', 'legacy-mapping',
         'imports', 'wrong-platform', 'root-override', 'symlink-file',
         'symlink-parent', 'fifo', 'oversized-config', 'group-writable',
         'destination-untrusted-parent', 'output-existing', 'runtime-path',
         'server-endpoint', 'snapshotter-root', 'stream-processor', 'nri-enabled',
         'config-race')
REQUEST = {
    'cluster_epoch': '11111111-1111-4111-8111-111111111111',
    'node_uid': '22222222-2222-4222-8222-222222222222',
    'node_name': 'public-host-profile-cli-fixture',
    'private_ip': '10.0.0.12', 'cloud_account_id': '100000000000',
    'region': 'cn-hangzhou', 'cloud_instance_id': 'i-host-profile-fixture',
    'certification_id': '33333333-3333-4333-8333-333333333333',
    'metrics_deployment': 'host-profile-cli-fixture',
}
KATA_BYTES = b'''[hypervisor.qemu]
path = "/opt/kata/bin/qemu-system-x86_64"
virtio_fs_daemon = "/opt/kata/bin/virtiofsd"
enable_annotations = []
enable_debug = false
shared_fs = "virtio-fs"
[runtime]
sandbox_cgroup_only = true
disable_new_netns = false
[factory]
enable_template = false
vm_cache_number = 0
'''
CONTAINERD_BYTES = b'''version = 4
root = "/var/lib/containerd"
state = "/run/containerd"
disabled_plugins = ["io.containerd.monitor.container.v1.restart"]
# PUBLIC_SECRET_SENTINEL_HOST_PROFILE
[grpc]
address = "/run/containerd/containerd.sock"
[plugins."io.containerd.cri.v1.runtime".containerd]
default_runtime_name = "runc"
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runc]
runtime_type = "io.containerd.runc.v2"
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runc.options]
SystemdCgroup = true
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes."kata-qemu"]
runtime_type = "io.containerd.kata.v2"
snapshotter = "overlayfs"
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes."kata-qemu".options]
ConfigPath = "/etc/kata-containers/configuration-qemu.toml"
[plugins."io.containerd.cri.v1.images"]
snapshotter = "overlayfs"
[plugins."io.containerd.cri.v1.images".runtime_platforms."kata-qemu"]
platform = "linux/amd64"
snapshotter = "overlayfs"
[plugins."io.containerd.nri.v1.nri"]
disable = true
'''
KUBELET_BYTES = b'''containerRuntimeEndpoint: unix:///run/sandbox-nodeguard/cri.sock
imageServiceEndpoint: unix:///run/containerd/containerd.sock
cgroupDriver: systemd
'''
ENVIRONMENT_BYTES = b'KUBELET_ARGS="--config=/etc/kubernetes/kubelet-config.yaml"\n'
INPUTS = {
    KATA: KATA_BYTES, CONTAINERD: CONTAINERD_BYTES,
    KUBELET: KUBELET_BYTES, ENVIRONMENT: ENVIRONMENT_BYTES,
    QEMU: b'public qemu identity fixture; never execute\n',
    VIRTIOFS: b'public virtiofs identity fixture; never execute\n',
    SHIM: b'public shim identity fixture; never execute\n',
}


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    value = path.lstat()
    return value.st_dev, value.st_ino


class OwnedInputs:
    def __init__(self):
        self.paths = {}

    def remember(self, path):
        self.paths[path] = identity(path)

    def directories(self, path):
        if path.exists():
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                    and info.st_mode & 0o022 == 0, 'untrusted fixture parent')
            return
        self.directories(path.parent)
        path.mkdir(mode=0o755)
        self.remember(path)

    def write(self, path, data, mode=0o600):
        self.directories(path.parent)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
        self.remember(path)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
        return path

    def replace(self, path, data):
        require(path in self.paths and identity(path) == self.paths[path],
                'owned input replacement identity differs')
        temporary = self.write(path.with_name(path.name + '.fixture-replacement'), data)
        os.replace(temporary, path)
        del self.paths[temporary]
        self.remember(path)

    def unlink(self, path):
        require(path in self.paths and identity(path) == self.paths[path],
                'owned input removal identity differs')
        path.unlink()
        del self.paths[path]

    def cleanup(self):
        for path in sorted(self.paths, key=lambda value: len(value.parts), reverse=True):
            require(identity(path) == self.paths[path], 'owned fixture cleanup identity differs')
            if stat.S_ISDIR(path.lstat().st_mode):
                path.rmdir()
            else:
                path.unlink()
        self.paths.clear()


def qemu_descriptors(pid):
    result = []
    try:
        descriptors = list(Path('/proc', str(pid), 'fd').iterdir())
    except FileNotFoundError:
        return result
    for descriptor in descriptors:
        try:
            if os.readlink(descriptor) == str(QEMU):
                result.append(descriptor.name)
        except FileNotFoundError:
            continue
    return result


def configuration_is_open(pid):
    try:
        return any(os.readlink(item) == str(CONTAINERD)
                   for item in Path('/proc', str(pid), 'fd').iterdir())
    except FileNotFoundError:
        return False


def race_after_qemu_open(child, owned, deadline, result):
    while child.poll() is None and time.monotonic() < deadline:
        descriptors = qemu_descriptors(child.pid)
        if not descriptors:
            time.sleep(0.001)
            continue
        os.kill(child.pid, signal.SIGSTOP)
        try:
            while time.monotonic() < deadline:
                state = Path('/proc', str(child.pid), 'status').read_text()
                if any(line.startswith('State:') and '\tT' in line for line in state.splitlines()):
                    break
                time.sleep(0.001)
            else:
                raise RuntimeError('race child did not stop within original deadline')
            require(qemu_descriptors(child.pid), 'qemu descriptor closed before race barrier')
            result['race_barrier'] = {
                'observed_qemu_fd': descriptors,
                'config_fd_still_open': configuration_is_open(child.pid),
                'method': 'actual proc FD observation, owned child SIGSTOP, atomic replacement, SIGCONT',
            }
            replacement = CONTAINERD_BYTES.replace(b'default_runtime_name = "runc"',
                                                   b'default_runtime_name = "wrong"')
            owned.replace(CONTAINERD, replacement)
            result['race_barrier']['replacement_sha256'] = sha(replacement)
            return
        finally:
            if child.poll() is None:
                os.kill(child.pid, signal.SIGCONT)
    raise RuntimeError('real qemu-open race barrier was not observed')


def check_valid(destination):
    expected_profile = {
        'protocol': 1, 'runtime_handler': 'kata-qemu', 'containerd_version': '2.3.5',
        **{key: {'path': str(path), 'sha256': sha(INPUTS[path])}
           for key, path in [('qemu', QEMU), ('virtiofs', VIRTIOFS), ('shim', SHIM),
                             ('kata_configuration', KATA), ('containerd_configuration', CONTAINERD),
                             ('kubelet_configuration', KUBELET), ('kubelet_environment', ENVIRONMENT)]},
    }
    values = {}
    for name in ('profile', 'config', 'enrollment'):
        path = destination / (name + '.json')
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
                'collector artifact ownership or mode differs')
        values[name] = json.loads(path.read_bytes())
    require(values['profile'] == expected_profile, 'independent seven-input profile oracle differs')
    profile_sha = sha((destination / 'profile.json').read_bytes())
    node = {key: REQUEST[key] for key in ('cluster_epoch', 'node_uid', 'node_name')}
    node.update(boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                profile_sha256=profile_sha)
    expected_config = {
        'node': node, 'profile_file': str(destination / 'profile.json'),
        'listen': REQUEST['private_ip'] + ':9444',
        'tls_certificate': str(destination / 'tls/server.pem'),
        'tls_key': str(destination / 'tls/server-key.pem'),
        'controller_client_ca': str(destination / 'tls/controller-ca.pem'),
        'metrics': {'listen': REQUEST['private_ip'] + ':9445',
                    'deployment': REQUEST['metrics_deployment'],
                    'scraper_client_ca': str(destination / 'tls/scraper-ca.pem')},
    }
    expected_enrollment = {
        'protocol': 1, 'node': node, 'guard_port': 9444,
        **{key: REQUEST[key] for key in ('cloud_account_id', 'region', 'cloud_instance_id',
                                       'private_ip', 'certification_id')},
    }
    require(values['config'] == expected_config, 'actual config oracle differs')
    require(values['enrollment'] == expected_enrollment, 'actual enrollment oracle differs')
    return {'profile_sha256': profile_sha, 'seven_input_hashes_verified': True,
            'config_and_enrollment_verified': True, 'physical_runtime_certified': False}


def one_case(case, collector):
    owned = OwnedInputs()
    destination = WORK / case
    if case == 'destination-untrusted-parent':
        parent = Path('/tmp/user-parent')
        require(not os.path.lexists(parent), 'untrusted-parent fixture must be new')
        owned.directories(parent)
        destination = parent / 'private'
        destination.mkdir(mode=0o700)
        owned.remember(destination)
        parent.chmod(0o777)
    else:
        destination.mkdir(mode=0o700)
    logs = WORK / 'logs'
    logs.mkdir(mode=0o700, exist_ok=True)
    result = {'case': case, 'expected': 'success' if case == 'valid' else 'reject',
              'status': 'FAIL', 'timed_out': False}
    child = None
    try:
        for path, data in INPUTS.items():
            owned.write(path, data, 0o555 if path in (QEMU, VIRTIOFS, SHIM) else 0o600)
        if case == 'missing-mapping':
            owned.replace(CONTAINERD, CONTAINERD_BYTES.split(b'[plugins."io.containerd.cri.v1.images".runtime_platforms.')[0])
        elif case == 'runtime-conflict':
            owned.replace(CONTAINERD, CONTAINERD_BYTES.replace(
                b'snapshotter = "overlayfs"', b'snapshotter = "devmapper"', 1))
        elif case == 'legacy-mapping':
            owned.replace(CONTAINERD, CONTAINERD_BYTES.replace(b'.runtime_platforms.', b'.runtime_platform.'))
        elif case == 'imports':
            owned.replace(CONTAINERD, CONTAINERD_BYTES.replace(
                b'version = 4\n', b'version = 4\nimports = ["/etc/containerd/other.toml"]\n'))
        elif case == 'wrong-platform':
            owned.replace(CONTAINERD, CONTAINERD_BYTES.replace(b'linux/amd64', b'linux/arm64'))
        elif case == 'root-override':
            owned.replace(CONTAINERD, CONTAINERD_BYTES.replace(b'root = "/var/lib/containerd"', b'root = "/var/lib/other"'))
        elif case == 'runtime-path':
            owned.replace(CONTAINERD, CONTAINERD_BYTES.replace(
                b'runtime_type = "io.containerd.kata.v2"',
                b'runtime_type = "io.containerd.kata.v2"\nruntime_path = "/opt/other/shim"'))
        elif case == 'server-endpoint':
            owned.replace(CONTAINERD, CONTAINERD_BYTES +
                          b'\n[plugins."io.containerd.server.v1.grpc"]\naddress = "/run/other.sock"\n')
        elif case == 'snapshotter-root':
            owned.replace(CONTAINERD, CONTAINERD_BYTES +
                          b'\n[plugins."io.containerd.snapshotter.v1.overlayfs"]\nroot_path = "/var/lib/other"\n')
        elif case == 'stream-processor':
            owned.replace(CONTAINERD, CONTAINERD_BYTES.replace(
                b'version = 4\n',
                b'version = 4\nstream_processors = { sample = { path = "/opt/other/process" } }\n'))
        elif case == 'nri-enabled':
            owned.replace(CONTAINERD, CONTAINERD_BYTES.replace(b'\ndisable = true\n', b'\ndisable = false\n'))
        elif case == 'symlink-file':
            alternate = owned.write(CONTAINERD.with_name('public-alternate.toml'), CONTAINERD_BYTES)
            owned.unlink(CONTAINERD)
            CONTAINERD.symlink_to(alternate)
            owned.remember(CONTAINERD)
        elif case == 'symlink-parent':
            original, alternate = QEMU.parent, QEMU.parent.with_name('public-alternate-bin')
            require(original in owned.paths and not os.path.lexists(alternate), 'owned binary directory required')
            original.rename(alternate)
            for path in list(owned.paths):
                if path == original or original in path.parents:
                    value = owned.paths.pop(path)
                    owned.paths[alternate / path.relative_to(original)] = value
            original.symlink_to(alternate, target_is_directory=True)
            owned.remember(original)
        elif case == 'fifo':
            owned.unlink(CONTAINERD)
            os.mkfifo(CONTAINERD, 0o600)
            owned.remember(CONTAINERD)
        elif case == 'oversized-config':
            owned.replace(CONTAINERD, CONTAINERD_BYTES + b'\n#' + b'x' * (1024 * 1024))
        elif case == 'group-writable':
            CONTAINERD.chmod(0o620)
        elif case == 'output-existing':
            owned.write(destination / 'profile.json', b'{"public":"preserve-existing"}\n')
        elif case == 'config-race':
            # UID 0 inside a cap-drop-ALL fixture still needs the owner's write
            # bit to create this sparse file; no DAC override is requested.
            QEMU.chmod(0o755)
            with QEMU.open('r+b') as stream:
                stream.truncate(512 * 1024 * 1024)
            info = QEMU.stat()
            require(info.st_size == 512 * 1024 * 1024 and info.st_blocks * 512 < 1024 * 1024,
                    'race qemu must be a sparse, bounded fixture')
            result['sparse_qemu_bytes'] = info.st_size
            result['sparse_qemu_allocated_bytes'] = info.st_blocks * 512
        request = WORK / (case + '-request.json')
        request.write_bytes(json.dumps(REQUEST, sort_keys=True).encode())
        request.chmod(0o600)
        stdout_path, stderr_path = logs / (case + '.stdout'), logs / (case + '.stderr')
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(('SANDBOX_', 'TEST_')) and key != 'RUST_MIN_STACK'}
        with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
            stdout_path.chmod(0o600)
            stderr_path.chmod(0o600)
            started = time.monotonic()
            deadline = started + 5
            child = subprocess.Popen([sys.executable, str(collector), '--request', str(request),
                                      '--destination', str(destination)], stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, env=environment)
            if case == 'config-race':
                race_after_qemu_open(child, owned, deadline, result)
            try:
                child.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                result['timed_out'] = True
                child.kill()
                child.wait()
            result['seconds'] = round(time.monotonic() - started, 6)
            result['exit_code'] = child.returncode
        require(stdout_path.stat().st_size <= 1024 * 1024 and stderr_path.stat().st_size <= 1024 * 1024,
                'collector output exceeded fixed evidence bound')
        stdout, stderr = stdout_path.read_bytes(), stderr_path.read_bytes()
        result.update(stdout_bytes=len(stdout), stderr_bytes=len(stderr), stderr_sha256=sha(stderr),
                      enrollment_exists=os.path.lexists(destination / 'enrollment.json'))
        require(not stdout, 'actual collector must keep stdout empty')
        require(SECRET not in stdout + stderr, 'collector echoed public secret sentinel')
        require(not result['timed_out'], 'collector exceeded fixed five-second deadline')
        if case == 'valid':
            require(child.returncode == 0 and not stderr, 'valid collector process failed')
            result.update(check_valid(destination))
        else:
            require(child.returncode != 0 and not result['enrollment_exists'],
                    'rejected input must not publish enrollment')
            if case == 'output-existing':
                require((destination / 'profile.json').read_bytes() == b'{"public":"preserve-existing"}\n',
                        'existing profile was changed')
                result['existing_profile_preserved'] = True
        result['status'] = 'PASS'
    except Exception as error:
        result['failure'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait()
            result['exit_code'] = child.returncode
        try:
            owned.cleanup()
            result['owned_inputs_removed'] = True
        except Exception as error:
            result['owned_inputs_removed'] = False
            result['cleanup_failure'] = {'type': type(error).__name__, 'message': str(error)}
            result['status'] = 'FAIL'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--collector', type=Path, required=True)
    parser.add_argument('--case', choices=CASES)
    parser.add_argument('--record', type=Path)
    args = parser.parse_args()
    require(os.geteuid() == 0 and os.uname().sysname == 'Linux'
            and os.uname().machine == 'x86_64', 'confined root Linux amd64 fixture required')
    marker = MARKER.lstat()
    require(stat.S_ISREG(marker.st_mode) and marker.st_uid == 0
            and marker.st_mode & 0o022 == 0, 'explicit immutable fixture marker required')
    require(args.collector.is_absolute() and args.collector.resolve() == args.collector
            and args.collector.is_file(), 'exact regular collector source required')
    for directory in (Path('/tmp'), Path('/etc'), Path('/opt'), Path('/opt/kata')):
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0,
                'root-owned non-writable fixture parents required')
    require(not os.path.lexists('/var/lib/sandbox-nodeguard/initialized.json'),
            'fixture must not contain an enrolled node')
    WORK.mkdir(mode=0o700)
    cases = [one_case(case, args.collector) for case in ([args.case] if args.case else CASES)]
    record = {'status': 'PASS' if all(case['status'] == 'PASS' for case in cases) else 'FAIL',
              'scope': 'actual host_profile.py CLI, public file fixtures, no physical runtime certification',
              'collector_sha256': sha(args.collector.read_bytes()), 'cases': cases}
    text = json.dumps(record, sort_keys=True)
    if args.record:
        require(args.record.is_absolute() and args.record.parent.resolve() == args.record.parent
                and not os.path.lexists(args.record), 'new exact record path required')
        descriptor = os.open(args.record, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(text + '\n')
    print(text)
    return 0 if record['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
