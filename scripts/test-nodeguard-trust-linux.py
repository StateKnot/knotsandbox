#!/usr/bin/env python3
"""Verify projected Nodeguard trust with a compiled Linux test ELF and public fixtures."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid

REPO = Path(__file__).resolve().parents[1]
TEST = 'real_linux_projected_identity_uses_primary_group_without_broadening_trust'
INPUT = '/nodeguard-public-test'
FIXTURE = '/run/nodeguard-trust'
MAX_ELF = 512 * 1024 * 1024
OUTPUT_LIMIT = 128 * 1024
CAPS = ('CHOWN', 'SETUID', 'SETGID', 'SETPCAP')
PUBLIC_FILES = ('server-ca.pem', 'client.pem', 'client.key')
IMAGE_PATTERN = r'[a-z0-9][a-z0-9.-]*(?::[0-9]+)?(?:/[a-z0-9][a-z0-9._-]*)*(?::[A-Za-z0-9][A-Za-z0-9._-]*)?@sha256:[0-9a-f]{64}'
DOCKER_HOST = 'unix:///var/run/docker.sock'


class CheckError(ValueError):
    pass


def require(condition, category):
    if not condition:
        raise CheckError(category)


def immutable_image(value):
    require(isinstance(value, str) and re.fullmatch(IMAGE_PATTERN, value),
            'FIXED_REPOSITORY_DIGEST_REQUIRED')
    return value


def local_docker_host(value):
    require(isinstance(value, str) and value.startswith('unix:///')
            and not any(character in value for character in ('\x00', '\n', '\r', '?', '#'))
            and Path(value[len('unix://'):]).is_absolute(), 'LOCAL_UNIX_DOCKER_SOCKET_REQUIRED')
    return value


def repository(value):
    name = value.split('@')[0]
    segments = name.split('/')
    segments[-1] = segments[-1].split(':')[0]
    if len(segments) == 1:
        segments = ['docker.io', 'library', *segments]
    elif not any(marker in segments[0] for marker in ('.', ':')) and segments[0] != 'localhost':
        segments.insert(0, 'docker.io')
    if segments[0] in ('index.docker.io', 'registry-1.docker.io'):
        segments[0] = 'docker.io'
    return '/'.join(segments)


def elf_header(header):
    require(len(header) >= 64 and header[:7] == b'\x7fELF\x02\x01\x01'
            and int.from_bytes(header[16:18], 'little') in (2, 3)
            and int.from_bytes(header[18:20], 'little') == 62,
            'LINUX_AMD64_EXECUTABLE_ELF_REQUIRED')


def snapshot(source, destination, limit, executable=False):
    """Copy the opened, bounded input; Docker never mounts or chowns its source."""
    source = Path(source)
    require(source.is_absolute(), 'ABSOLUTE_INPUT_REQUIRED')
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    descriptor = os.open(source, flags)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid in (0, os.geteuid())
                and not before.st_mode & 0o7022 and 0 < before.st_size <= limit,
                'INPUT_TYPE_OWNER_MODE_OR_BOUND')
        digest = hashlib.sha256()
        length = 0
        with open(destination, 'xb') as output:
            while chunk := os.read(descriptor, min(1024 * 1024, limit - length + 1)):
                length += len(chunk)
                require(length <= limit, 'INPUT_SIZE_CHANGED')
                if executable and length == len(chunk):
                    elf_header(chunk[:64])
                digest.update(chunk)
                output.write(chunk)
        after = os.fstat(descriptor)
        require(length == before.st_size and (before.st_ino, before.st_dev,
                before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'INPUT_CHANGED_DURING_SNAPSHOT')
        os.chmod(destination, 0o555 if executable else 0o444)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


# No caller-supplied Python, certificate, environment or staging path. These
# three PEMs are the repository's intentionally public protocol test material.
STAGE = r'''
import ctypes
import os
from pathlib import Path

def require(condition):
    if not condition:
        raise SystemExit('PUBLIC_TRUST_STAGING_OR_PRIVILEGE_BOUNDARY_FAILED')

def status():
    return dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)

def file(name, data, uid, gid, mode):
    fd = os.open('/run/nodeguard-trust/' + name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(data)
        os.fchmod(output.fileno(), mode)
        os.fchown(output.fileno(), uid, gid)

require(os.getuid() == 0 and os.geteuid() == 0 and os.getgid() == 0)
initial = status()
require(int(initial['NoNewPrivs']) == 1)
required_caps = (1 << 0) | (1 << 6) | (1 << 7) | (1 << 8)
require(all(int(initial[key], 16) == required_caps for key in ('CapPrm', 'CapEff', 'CapBnd')))
require(all(int(initial[key], 16) == 0 for key in ('CapInh', 'CapAmb')))
root = Path('/run/nodeguard-trust')
require(root.is_dir() and not root.is_symlink())
public = Path('/nodeguard-public-test')
ca = (public / 'server-ca.pem').read_bytes()
identity = (public / 'client.pem').read_bytes() + (public / 'client.key').read_bytes()
file('server-ca.pem', ca, 0, 0, 0o444)
file('identity.pem', identity, 0, 10001, 0o440)
file('wrong-group-identity.pem', identity, 0, 10002, 0o440)
file('group-write-identity.pem', identity, 0, 10001, 0o660)
file('public-identity.pem', identity, 0, 10001, 0o444)
file('nonroot-group-identity.pem', identity, 10001, 10001, 0o440)
file('writable-ca.pem', ca, 0, 0, 0o666)
os.symlink('identity.pem', root / 'projected-identity.pem')
os.setgroups([10002])
os.setresgid(10001, 10001, 10001)

# SETPCAP exists only to erase the capability bounding set before the test.
# Keep that bit until last; setresuid then clears permitted/effective caps.
last = int(Path('/proc/sys/kernel/cap_last_cap').read_text())
require(8 <= last <= 63)
libc = ctypes.CDLL(None, use_errno=True)
for cap in [value for value in range(last + 1) if value != 8] + [8]:
    require(libc.prctl(24, cap, 0, 0, 0) == 0)  # PR_CAPBSET_DROP
os.setresuid(10001, 10001, 10001)
final = status()
require(os.getresuid() == (10001, 10001, 10001) and os.getresgid() == (10001, 10001, 10001))
require(os.getgroups() == [10002] and int(final['NoNewPrivs']) == 1)
require(all(int(final[key], 16) == 0 for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')))
os.execve('/nodeguard-public-test/termination-credentials',
          ['termination-credentials', '--exact',
           'real_linux_projected_identity_uses_primary_group_without_broadening_trust',
           '--ignored', '--nocapture', '--test-threads=1'],
          {'SANDBOX_PROJECTED_NODEGUARD_TRUST_FIXTURE': '/run/nodeguard-trust', 'RUST_BACKTRACE': '0'})
'''


def create_arguments(image, directory, name):
    immutable_image(image)
    require(Path(directory).is_absolute() and ',' not in str(directory), 'ABSOLUTE_BIND_PATH_REQUIRED')
    arguments = ['create', '--name', name, '--platform', 'linux/amd64', '--pull=never',
                 '--network', 'none', '--read-only', '--cap-drop', 'ALL']
    for capability in CAPS:
        arguments += ['--cap-add', capability]
    return arguments + ['--security-opt', 'no-new-privileges', '--user', '0:0',
        '--memory', '268435456', '--cpus', '1', '--pids-limit', '32',
        '--ulimit', 'core=0:0', '--ulimit', 'nofile=128:128',
        '--mount', f'type=bind,src={directory},dst={INPUT},readonly',
        '--tmpfs', f'{FIXTURE}:rw,nosuid,nodev,noexec,size=1048576,mode=0755',
        '--entrypoint', '/usr/bin/python3', image, '-I', '-B', INPUT + '/stage.py']


def test_result(output):
    require(output.count(b'running 1 test') == 1
            and output.count(('test ' + TEST + ' ... ok').encode()) == 1
            and re.search(rb'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured;', output),
            'EXACT_IGNORED_LINUX_TEST_NOT_PASSED')


def command(arguments, timeout=30):
    # Regular-file capture with a child FSIZE limit bounds Docker diagnostics
    # even when a broken input ELF writes continuously to stdout or stderr.
    def output_bound():
        resource.setrlimit(resource.RLIMIT_FSIZE, (OUTPUT_LIMIT, OUTPUT_LIMIT))
    environment = {key: value for key, value in os.environ.items()
                   if key not in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH')}
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        result = subprocess.run(['docker', '--host', DOCKER_HOST, *arguments], stdin=subprocess.DEVNULL,
            stdout=stdout, stderr=stderr, timeout=timeout, preexec_fn=output_bound, env=environment)
        require(os.fstat(stdout.fileno()).st_size <= OUTPUT_LIMIT
                and os.fstat(stderr.fileno()).st_size <= OUTPUT_LIMIT, 'DOCKER_OUTPUT_BOUND')
        stdout.seek(0); stderr.seek(0)
        return result.returncode, stdout.read(OUTPUT_LIMIT), stderr.read(OUTPUT_LIMIT)


def checked(arguments, timeout=30):
    code, stdout, _ = command(arguments, timeout)
    require(code == 0, 'LOCAL_DOCKER_' + arguments[0].upper() + '_FAILED')
    return stdout


def cleanup(name):
    # A lost create ACK can still leave a container. Observe only this exact
    # random name; normal completion needs neither stop nor force removal.
    listed = checked(['container', 'ls', '--all', '--filter', 'name=^/' + name + '$',
                      '--format', '{{.Names}}']).strip()
    if not listed:
        return
    require(listed == name.encode(), 'EXACT_TEST_CONTAINER_CLEANUP_BINDING')
    state = json.loads(checked(['inspect', '--format', '{{json .State}}', name]))
    if state['Running']:
        checked(['stop', '--time', '3', name], 10)
    checked(['rm', name])


def run(binary, image, docker_host):
    global DOCKER_HOST
    DOCKER_HOST = local_docker_host(docker_host)
    socket = Path(DOCKER_HOST[len('unix://'):]).stat()
    require(stat.S_ISSOCK(socket.st_mode) and socket.st_uid in (0, os.geteuid())
            and not socket.st_mode & 0o0002, 'LOCAL_DOCKER_SOCKET_OWNER_OR_TYPE')
    immutable_image(image)
    image_info = json.loads(checked(['image', 'inspect', '--platform', 'linux/amd64', image]))
    require(isinstance(image_info, list) and len(image_info) == 1
            and image_info[0]['Os'] == 'linux' and image_info[0]['Architecture'] == 'amd64',
            'LOCAL_LINUX_AMD64_IMAGE_REQUIRED')
    image_info = image_info[0]
    require(any(digest.split('@')[-1] == image.split('@')[-1]
                and repository(digest) == repository(image)
                for digest in image_info.get('RepoDigests', [])), 'LOCAL_REPOSITORY_DIGEST_BINDING')
    name = 'sandbox-nodeguard-trust-' + uuid.uuid4().hex
    created = False
    failure = None
    with tempfile.TemporaryDirectory(prefix='sandbox-public-trust-') as directory:
        path = Path(directory)
        os.chmod(path, 0o755)
        elf_sha = snapshot(binary, path / 'termination-credentials', MAX_ELF, True)
        fixture_hashes = {filename: snapshot(REPO / 'tests/fixtures/nodeguard' / filename,
                                            path / filename, 65536) for filename in PUBLIC_FILES}
        (path / 'stage.py').write_text(STAGE)
        os.chmod(path / 'stage.py', 0o444)
        try:
            # A create ACK may be lost; cleanup still targets only our exact
            # random name rather than leaking a successfully created container.
            created = True
            checked(create_arguments(image, directory, name))
            output = checked(['start', '--attach', name], 90)
            state = json.loads(checked(['inspect', '--format', '{{json .State}}', name]))
            require(not state['Running'] and not state['OOMKilled'] and state['ExitCode'] == 0,
                    'LINUX_TEST_EXIT_OR_RESOURCE_FAILURE')
            test_result(output)
        except BaseException as error:
            failure = error
        finally:
            # Only this uniquely named local test container is removed. No
            # volume/cache/image/service or source file ownership is modified.
            if created:
                try:
                    cleanup(name)
                except (CheckError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                    print(json.dumps({'cleanup': 'FAILED', 'local_test_container': name}), file=sys.stderr)
                    if failure is None:
                        failure = CheckError('LOCAL_TEST_CONTAINER_CLEANUP_FAILED')
    if failure is not None:
        raise failure
    print(json.dumps({'linux_projected_trust_test': 'PASS', 'test': TEST,
        'image': image, 'image_id': image_info['Id'], 'test_elf_sha256': elf_sha,
        'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'public_fixture_sha256': fixture_hashes, 'uid': 10001, 'primary_gid': 10001,
        'supplementary_groups': [10002], 'all_capability_sets_zero': True,
        'network': 'none', 'root_filesystem_read_only': True,
        'kubernetes_projection_tested': False, 'runtime_certification': 'NOT_ASSERTED'}))


class ProtocolTests(unittest.TestCase):
    def test_fixed_repository_digest_only(self):
        good = 'rust:1.98.1-bookworm@sha256:' + 'a' * 64
        self.assertEqual(immutable_image(good), good)
        for bad in ('rust:latest', 'sha256:' + 'a' * 64, 'rust@sha256:' + 'A' * 64,
                    'https://registry/test@sha256:' + 'a' * 64, good + ' --privileged'):
            with self.subTest(bad=bad), self.assertRaises(CheckError): immutable_image(bad)
        self.assertEqual(repository(good), repository('docker.io/library/rust@sha256:' + 'a' * 64))
        self.assertEqual(local_docker_host('unix:///var/run/docker.sock'), 'unix:///var/run/docker.sock')
        for bad in ('tcp://127.0.0.1:2375', 'ssh://remote', 'unix://relative', 'unix:///tmp/sock?remote=1'):
            with self.assertRaises(CheckError): local_docker_host(bad)

    def test_elf_architecture_and_type(self):
        header = bytearray(64); header[:7] = b'\x7fELF\x02\x01\x01'
        header[16:18] = (3).to_bytes(2, 'little'); header[18:20] = (62).to_bytes(2, 'little')
        elf_header(header)
        for position, value in ((0, 0), (4, 1), (5, 2), (16, 1), (18, 183)):
            broken = bytearray(header); broken[position] = value
            with self.assertRaises(CheckError): elf_header(broken)

    def test_snapshot_rejects_link_fifo_directory_and_group_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / 'input'; source.write_bytes(b'PUBLIC')
            link = root / 'link'; link.symlink_to(source)
            fifo = root / 'fifo'; os.mkfifo(fifo, 0o600)
            for path in (link, fifo, root):
                with self.subTest(path=path.name), self.assertRaises((CheckError, OSError)):
                    snapshot(path, root / ('copy-' + path.name), 64)
            os.chmod(source, 0o666)
            with self.assertRaises(CheckError): snapshot(source, root / 'unsafe', 64)
            os.chmod(source, 0o644)
            with self.assertRaises(CheckError): snapshot(source, root / 'large', 2)
            self.assertEqual(snapshot(source, root / 'valid', 64), hashlib.sha256(b'PUBLIC').hexdigest())
            self.assertEqual(stat.S_IMODE((root / 'valid').stat().st_mode), 0o444)

    def test_container_boundary(self):
        args = create_arguments('rust@sha256:' + 'a' * 64, '/tmp/fixed', 'fixed')
        self.assertEqual([args[i + 1] for i, value in enumerate(args) if value == '--cap-add'], list(CAPS))
        for option, value in (('--network', 'none'), ('--cap-drop', 'ALL'),
                              ('--user', '0:0'), ('--security-opt', 'no-new-privileges')):
            self.assertEqual(args[args.index(option) + 1], value)
        self.assertIn('--read-only', args); self.assertIn('--pull=never', args)
        self.assertEqual(args[args.index('--mount') + 1], 'type=bind,src=/tmp/fixed,dst=' + INPUT + ',readonly')
        self.assertIn('nosuid,nodev,noexec', args[args.index('--tmpfs') + 1])
        compile(STAGE, '<fixed-public-staging>', 'exec')
        self.assertIn("os.setresuid(10001, 10001, 10001)", STAGE)
        self.assertIn("'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'", STAGE)
        with self.assertRaises(CheckError): create_arguments('rust@sha256:' + 'a' * 64, '/tmp/a,b', 'fixed')

    def test_one_executed_test_required(self):
        output = ('running 1 test\ntest ' + TEST + ' ... ok\n'
                  'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out;\n').encode()
        test_result(output)
        for bad in (b'running 0 tests\ntest result: ok.', output.replace(b' ... ok', b' ... ignored'),
                    output.replace(b'0 failed', b'1 failed'), output + output):
            with self.assertRaises(CheckError): test_result(bad)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test-binary', type=Path)
    parser.add_argument('--image', help='Locally available reviewed repository@sha256 digest with /usr/bin/python3')
    parser.add_argument('--docker-host', help='Absolute local unix:// socket; defaults to unix:///var/run/docker.sock')
    parser.add_argument('--self-test', action='store_true', help='Static protocol/negative tests; never invokes Docker')
    args = parser.parse_args()
    if args.self_test:
        require(args.test_binary is None and args.image is None and args.docker_host is None,
                'SELF_TEST_ACCEPTS_NO_RUNTIME_INPUT')
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ProtocolTests))
        require(result.wasSuccessful(), 'STATIC_PROTOCOL_TEST_FAILED')
        print('STATIC_PROTOCOL_PASS; actual Linux execution NOT_RUN')
    else:
        require(args.test_binary is not None and args.image is not None, 'TEST_ELF_AND_FIXED_IMAGE_REQUIRED')
        run(args.test_binary, args.image, args.docker_host or DOCKER_HOST)


if __name__ == '__main__':
    try: main()
    except CheckError as error:
        raise SystemExit('NODEGUARD_TRUST_LINUX_FAILED category=' + str(error) + '; input values omitted') from None
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('NODEGUARD_TRUST_LINUX_FAILED; input values omitted') from None
