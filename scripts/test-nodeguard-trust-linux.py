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
from unittest.mock import patch
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
    def __init__(self, category, diagnostic=None):
        super().__init__(category)
        self.diagnostic = diagnostic


def require(condition, category, diagnostic=None):
    if not condition:
        raise CheckError(category, diagnostic)


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


def reviewed_image_info(images, image):
    require(isinstance(images, list) and len(images) == 1 and isinstance(images[0], dict),
            'LOCAL_IMAGE_METADATA_REQUIRED')
    info = images[0]
    require(isinstance(info.get('Id'), str) and re.fullmatch(r'sha256:[0-9a-f]{64}', info['Id']),
            'LOCAL_IMAGE_ID_REQUIRED')
    digests = info.get('RepoDigests')
    require(isinstance(digests, list) and sum(isinstance(digest, str)
            and digest.split('@')[-1] == image.split('@')[-1]
            and repository(digest) == repository(image) for digest in digests) == 1,
            'LOCAL_REPOSITORY_DIGEST_BINDING')
    return info


def selected_image_binding(info, container, image):
    """Bind the actual, not-yet-started container in both Docker image stores.

    API 1.48 exposes the selected manifest for a multi-platform store. Classic
    stores instead identify the selected image directly. These are explicit
    data contracts; a malformed descriptor never becomes a classic image.
    """
    reviewed_image_info([info], image)
    require(isinstance(container, dict) and isinstance(container.get('Config'), dict)
            and container['Config'].get('Image') == image
            and container.get('Image') == info['Id'] and container.get('Platform') == 'linux',
            'LOCAL_CREATED_IMAGE_BINDING')
    selected = None
    if 'ImageManifestDescriptor' in container:
        descriptor = container['ImageManifestDescriptor']
        require(isinstance(descriptor, dict)
                and descriptor.get('mediaType') in ('application/vnd.oci.image.manifest.v1+json',
                                                   'application/vnd.docker.distribution.manifest.v2+json')
                and isinstance(descriptor.get('digest'), str)
                and re.fullmatch(r'sha256:[0-9a-f]{64}', descriptor['digest'])
                and isinstance(descriptor.get('platform'), dict)
                and descriptor['platform'].get('os') == 'linux'
                and descriptor['platform'].get('architecture') == 'amd64'
                and descriptor['platform'].get('variant', '') == '',
                'LOCAL_SELECTED_MANIFEST_BINDING')
        selected = descriptor['digest']
        source = 'CREATED_PLATFORM_MANIFEST'
    else:
        require(info.get('Os') == 'linux' and info.get('Architecture') == 'amd64',
                'LOCAL_LINUX_AMD64_IMAGE_REQUIRED')
        source = 'CLASSIC_IMAGE_METADATA'
    return {'container_image_id': container['Image'], 'selected_manifest_digest': selected,
            'selection_source': source, 'os': 'linux', 'architecture': 'amd64'}


FAILURE_CATEGORIES = frozenset((
    'FIXED_REPOSITORY_DIGEST_REQUIRED', 'LOCAL_UNIX_DOCKER_SOCKET_REQUIRED',
    'ABSOLUTE_INPUT_REQUIRED', 'INPUT_TYPE_OWNER_MODE_OR_BOUND', 'INPUT_SIZE_CHANGED',
    'INPUT_CHANGED_DURING_SNAPSHOT', 'LINUX_AMD64_EXECUTABLE_ELF_REQUIRED',
    'ABSOLUTE_BIND_PATH_REQUIRED', 'EXACT_IGNORED_LINUX_TEST_NOT_PASSED',
    'DOCKER_OUTPUT_BOUND', 'LOCAL_DOCKER_IMAGE_FAILED', 'LOCAL_DOCKER_CREATE_FAILED',
    'LOCAL_DOCKER_START_FAILED', 'LOCAL_DOCKER_INSPECT_FAILED', 'LOCAL_DOCKER_CONTAINER_FAILED',
    'LOCAL_DOCKER_STOP_FAILED', 'LOCAL_DOCKER_RM_FAILED', 'EXACT_TEST_CONTAINER_CLEANUP_BINDING',
    'LOCAL_DOCKER_SOCKET_OWNER_OR_TYPE', 'LOCAL_IMAGE_METADATA_REQUIRED', 'LOCAL_IMAGE_ID_REQUIRED',
    'LOCAL_REPOSITORY_DIGEST_BINDING', 'LOCAL_CREATED_IMAGE_BINDING',
    'LOCAL_SELECTED_MANIFEST_BINDING', 'LOCAL_LINUX_AMD64_IMAGE_REQUIRED',
    'LOCAL_CONTAINER_STATE_FORMAT_REQUIRED',
    'LINUX_TEST_EXIT_OR_RESOURCE_FAILURE', 'LOCAL_TEST_CONTAINER_CLEANUP_FAILED',
    'SELF_TEST_ACCEPTS_NO_RUNTIME_INPUT', 'STATIC_PROTOCOL_TEST_FAILED',
    'TEST_ELF_AND_FIXED_IMAGE_REQUIRED', 'CHILD_FAILURE_REQUIRES_NONZERO_EXIT',
    'CHILD_FAILURE_BYTES_REQUIRED'))


START_DIAGNOSTIC_KEYS = frozenset((
    'start_exit_code', 'start_stdout_sha256', 'start_stdout_bytes',
    'start_stderr_sha256', 'start_stderr_bytes', 'container_running',
    'container_oom_killed', 'container_exit_code'))


def valid_start_diagnostic(value):
    if type(value) is not dict or set(value) != START_DIAGNOSTIC_KEYS:
        return False
    return (type(value['start_exit_code']) is int and -255 <= value['start_exit_code'] <= 255
        and type(value['container_exit_code']) is int and 0 <= value['container_exit_code'] <= 255
        and all(type(value[key]) is bool for key in ('container_running', 'container_oom_killed'))
        and all(type(value[key]) is int and 0 <= value[key] <= OUTPUT_LIMIT
                for key in ('start_stdout_bytes', 'start_stderr_bytes'))
        and all(type(value[key]) is str and re.fullmatch(r'[0-9a-f]{64}', value[key])
                for key in ('start_stdout_sha256', 'start_stderr_sha256')))


def failure_start_diagnostic(stdout, category):
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('Duplicate failure field')
            value[key] = item
        return value
    try:
        value = json.loads(stdout, object_pairs_hook=unique_object)
    except (ValueError, TypeError, RecursionError):
        return None
    if (type(value) is not dict or set(value) != {
            'linux_projected_trust_test', 'test_execution', 'start_diagnostic'}
            or value['linux_projected_trust_test'] != 'FAIL' or value['test_execution'] != 'UNKNOWN'
            or not valid_start_diagnostic(value['start_diagnostic'])):
        return None
    diagnostic = value['start_diagnostic']
    exit_failure = (diagnostic['container_running'] or diagnostic['container_oom_killed']
                    or diagnostic['container_exit_code'] != 0)
    consistent = ((category == 'LOCAL_DOCKER_START_FAILED' and diagnostic['start_exit_code'] != 0)
        or (category == 'LINUX_TEST_EXIT_OR_RESOURCE_FAILURE' and diagnostic['start_exit_code'] == 0
            and exit_failure)
        or (category == 'EXACT_IGNORED_LINUX_TEST_NOT_PASSED' and diagnostic['start_exit_code'] == 0
            and not exit_failure))
    return diagnostic if consistent else None


def child_failure_receipt(returncode, stdout: bytes, stderr: bytes):
    """Derive a public failure receipt without publishing any child output."""
    require(type(returncode) is int and returncode != 0, 'CHILD_FAILURE_REQUIRES_NONZERO_EXIT')
    require(isinstance(stdout, bytes) and isinstance(stderr, bytes), 'CHILD_FAILURE_BYTES_REQUIRED')
    category = 'UNKNOWN'
    diagnostic = None
    if len(stdout) <= OUTPUT_LIMIT and len(stderr) <= OUTPUT_LIMIT:
        match = re.fullmatch(rb'NODEGUARD_TRUST_LINUX_FAILED category=([A-Z_]+); input values omitted\n?', stderr)
        if match is not None and match[1].decode('ascii') in FAILURE_CATEGORIES:
            candidate = match[1].decode('ascii')
            diagnostic = failure_start_diagnostic(stdout, candidate) if stdout else None
            if not stdout or diagnostic is not None:
                category = candidate
    receipt = {'linux_projected_trust_test': 'FAIL', 'test': TEST, 'test_execution': 'UNKNOWN',
            'exit_code': returncode, 'category': category,
            'stdout_sha256': hashlib.sha256(stdout).hexdigest(), 'stdout_bytes': len(stdout),
            'stderr_sha256': hashlib.sha256(stderr).hexdigest(), 'stderr_bytes': len(stderr),
            'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'diagnostic_scope': 'DERIVED_ALLOWLIST_ONLY_NO_RAW_OUTPUT'}
    if diagnostic is not None:
        receipt['start_diagnostic'] = diagnostic
    return receipt


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


def start_diagnostic(code, stdout, stderr, state):
    require(type(state) is dict and type(state.get('Running')) is bool
            and type(state.get('OOMKilled')) is bool and type(state.get('ExitCode')) is int
            and 0 <= state['ExitCode'] <= 255, 'LOCAL_CONTAINER_STATE_FORMAT_REQUIRED')
    value = {'start_exit_code': code, 'start_stdout_sha256': hashlib.sha256(stdout).hexdigest(),
        'start_stdout_bytes': len(stdout), 'start_stderr_sha256': hashlib.sha256(stderr).hexdigest(),
        'start_stderr_bytes': len(stderr), 'container_running': state['Running'],
        'container_oom_killed': state['OOMKilled'], 'container_exit_code': state['ExitCode']}
    require(valid_start_diagnostic(value), 'LOCAL_CONTAINER_STATE_FORMAT_REQUIRED')
    return value


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
    # --platform on image inspect requires API 1.49, while the CI Docker 28.0
    # engine provides 1.48. Select with create, then validate before start.
    image_info = reviewed_image_info(json.loads(checked(['image', 'inspect', image])), image)
    name = 'sandbox-nodeguard-trust-' + uuid.uuid4().hex
    created = False
    failure = None
    diagnostic = None
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
            containers = json.loads(checked(['inspect', name]))
            require(isinstance(containers, list) and len(containers) == 1,
                    'LOCAL_CREATED_IMAGE_BINDING')
            binding = selected_image_binding(image_info, containers[0], image)
            start_code, output, start_stderr = command(['start', '--attach', name], 90)
            state = json.loads(checked(['inspect', '--format', '{{json .State}}', name]))
            diagnostic = start_diagnostic(start_code, output, start_stderr, state)
            require(start_code == 0, 'LOCAL_DOCKER_START_FAILED', diagnostic)
            require(not state['Running'] and not state['OOMKilled'] and state['ExitCode'] == 0,
                    'LINUX_TEST_EXIT_OR_RESOURCE_FAILURE', diagnostic)
            test_result(output)
        except BaseException as error:
            if isinstance(error, CheckError) and error.diagnostic is None:
                error.diagnostic = diagnostic
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
        'image': image, 'image_id': binding['container_image_id'], 'image_binding': binding,
        'test_elf_sha256': elf_sha,
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

    def test_classic_image_and_container_binding(self):
        image = 'rust@sha256:' + 'a' * 64
        info = {'Id': 'sha256:' + 'b' * 64, 'Os': 'linux', 'Architecture': 'amd64',
                'RepoDigests': [image]}
        container = {'Image': info['Id'], 'Config': {'Image': image}, 'Platform': 'linux'}
        self.assertEqual(selected_image_binding(info, container, image),
                         {'container_image_id': info['Id'], 'selected_manifest_digest': None,
                          'selection_source': 'CLASSIC_IMAGE_METADATA', 'os': 'linux', 'architecture': 'amd64'})
        for change in ({'Architecture': 'arm64'}, {'Os': 'windows'}, {'RepoDigests': []},
                       {'Id': 'sha256:' + 'c' * 64}):
            with self.subTest(change=change), self.assertRaises(CheckError):
                selected_image_binding({**info, **change}, container, image)
        for change in ({'Image': 'sha256:' + 'c' * 64}, {'Config': {'Image': 'rust:latest'}},
                       {'Platform': 'windows'}, {'ImageManifestDescriptor': None}):
            with self.subTest(change=change), self.assertRaises(CheckError):
                selected_image_binding(info, {**container, **change}, image)

    def test_selected_manifest_preserves_actual_platform_over_index_metadata(self):
        image = 'rust@sha256:' + 'a' * 64
        info = {'Id': 'sha256:' + 'a' * 64, 'Os': 'linux', 'Architecture': 'arm64',
                'RepoDigests': [image]}
        descriptor = {'digest': 'sha256:' + 'b' * 64,
                      'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                      'platform': {'os': 'linux', 'architecture': 'amd64'}}
        container = {'Image': info['Id'], 'Config': {'Image': image}, 'Platform': 'linux',
                     'ImageManifestDescriptor': descriptor}
        binding = selected_image_binding(info, container, image)
        self.assertEqual(binding['container_image_id'], info['Id'])
        self.assertEqual(binding['selected_manifest_digest'], descriptor['digest'])
        self.assertEqual(binding['architecture'], 'amd64')
        for change in ({'digest': ''}, {'digest': 'sha256:' + 'B' * 64},
                       {'mediaType': 'application/vnd.oci.image.index.v1+json'},
                       {'platform': {'os': 'linux', 'architecture': 'arm64'}},
                       {'platform': {'os': 'windows', 'architecture': 'amd64'}},
                       {'platform': None}, {'platform': {'os': 'linux'}}):
            with self.subTest(change=change), self.assertRaises(CheckError):
                selected_image_binding(info, {**container, 'ImageManifestDescriptor': {**descriptor, **change}}, image)
        for change in ({'Config': {'Image': 'other@sha256:' + 'a' * 64}},
                       {'Image': 'sha256:' + 'c' * 64}):
            with self.subTest(change=change), self.assertRaises(CheckError):
                selected_image_binding(info, {**container, **change}, image)
        with self.assertRaises(CheckError):
            selected_image_binding({**info, 'RepoDigests': ['other@sha256:' + 'a' * 64]}, container, image)

    def test_invalid_created_binding_is_cleaned_before_any_start(self):
        image = 'rust@sha256:' + 'a' * 64
        info = {'Id': 'sha256:' + 'b' * 64, 'Os': 'linux', 'Architecture': 'amd64',
                'RepoDigests': [image]}
        container = {'Image': info['Id'], 'Config': {'Image': image}, 'Platform': 'linux'}
        invalid = ({**container, 'Image': 'sha256:' + 'c' * 64},
                   {**container, 'Config': {'Image': 'rust:latest'}},
                   {**container, 'ImageManifestDescriptor': None},
                   {**container, 'ImageManifestDescriptor': {}},
                   {**container, 'ImageManifestDescriptor': {
                       'digest': 'sha256:' + 'd' * 64,
                       'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                       'platform': {'os': 'linux', 'architecture': 'arm64'}}})
        socket = os.stat_result((stat.S_IFSOCK | 0o600, 0, 0, 1, os.geteuid(), 0, 0, 0, 0, 0))
        for record in invalid:
            calls, cleaned = [], []
            def docker(arguments, timeout=30):
                calls.append(arguments)
                if arguments[:2] == ['image', 'inspect']: return json.dumps([info]).encode()
                if arguments[0] == 'create': return b'PUBLIC_CONTAINER_ID\n'
                if arguments[0] == 'inspect': return json.dumps([record]).encode()
                raise AssertionError('Invalid binding must not start a container')
            with self.subTest(record=record), patch.object(Path, 'stat', return_value=socket), \
                    patch.dict(globals(), {'checked': docker, 'snapshot': lambda *args: 'e' * 64,
                                           'cleanup': lambda name: cleaned.append(name)}):
                with self.assertRaises(CheckError): run(Path('/public-elf'), image, 'unix:///local-socket')
            self.assertEqual(sum(command[0] == 'create' for command in calls), 1)
            self.assertFalse(any(command[0] == 'start' for command in calls))
            self.assertEqual(len(cleaned), 1)

    def test_child_failure_receipt_from_real_nonzero_child(self):
        child = subprocess.run([sys.executable, str(Path(__file__).resolve())],
                               capture_output=True, timeout=10)
        self.assertNotEqual(child.returncode, 0)
        receipt = child_failure_receipt(child.returncode, child.stdout, child.stderr)
        self.assertEqual(receipt['linux_projected_trust_test'], 'FAIL')
        self.assertEqual(receipt['category'], 'TEST_ELF_AND_FIXED_IMAGE_REQUIRED')
        self.assertEqual(receipt['test_execution'], 'UNKNOWN')
        self.assertEqual(receipt['stderr_sha256'], hashlib.sha256(child.stderr).hexdigest())
        self.assertEqual(receipt['stderr_bytes'], len(child.stderr))

    def test_child_failure_receipt_never_reflects_unknown_or_secret_output(self):
        known = b'NODEGUARD_TRUST_LINUX_FAILED category=LOCAL_DOCKER_IMAGE_FAILED; input values omitted\n'
        secret = b'https://private:password@operator.invalid/path?token=PRIVATE_BODY'
        good = child_failure_receipt(1, b'', known)
        self.assertEqual(good['category'], 'LOCAL_DOCKER_IMAGE_FAILED')
        for stdout, stderr in ((b'', known + secret), (secret, secret),
                               (b'', known.replace(b'LOCAL_DOCKER_IMAGE_FAILED', b'INVENTED_CATEGORY')),
                               (b'', known * 2), (b'', known + b'x' * OUTPUT_LIMIT)):
            with self.subTest(length=len(stderr)):
                receipt = child_failure_receipt(1, stdout, stderr)
                self.assertEqual(receipt['category'], 'UNKNOWN')
                self.assertEqual(receipt['linux_projected_trust_test'], 'FAIL')
                encoded = json.dumps(receipt).encode()
                for raw in (b'password', b'operator.invalid', b'PRIVATE_BODY', b'INVENTED_CATEGORY'):
                    self.assertNotIn(raw, encoded)
                self.assertEqual(receipt['stderr_sha256'], hashlib.sha256(stderr).hexdigest())
        with self.assertRaises(CheckError): child_failure_receipt(0, b'', b'')
        with self.assertRaises(CheckError): child_failure_receipt(True, b'', b'')

    def test_nonzero_start_inspects_state_and_preserves_only_safe_diagnostics(self):
        image = 'rust@sha256:' + 'a' * 64
        info = {'Id': 'sha256:' + 'b' * 64, 'Os': 'linux', 'Architecture': 'amd64',
                'RepoDigests': [image]}
        container = {'Image': info['Id'], 'Config': {'Image': image}, 'Platform': 'linux'}
        state = {'Running': False, 'OOMKilled': False, 'ExitCode': 127,
                 'Error': 'PRIVATE_STATE_ERROR_NEVER_RETURNED'}
        socket = os.stat_result((stat.S_IFSOCK | 0o600, 0, 0, 1, os.geteuid(), 0, 0, 0, 0, 0))
        calls, cleaned = [], []
        original_checked = checked
        stdout, stderr = b'PRIVATE_STDOUT_NEVER_RETURNED', b'PRIVATE_STDERR_NEVER_RETURNED'
        def docker(arguments, timeout=30):
            calls.append(arguments)
            if arguments[:2] == ['image', 'inspect']: return json.dumps([info]).encode()
            if arguments[0] == 'create': return b'PUBLIC_CONTAINER_ID\n'
            if arguments[:3] == ['inspect', '--format', '{{json .State}}']:
                return json.dumps(state).encode()
            if arguments[0] == 'inspect': return json.dumps([container]).encode()
            return original_checked(arguments, timeout)
        def start(arguments, timeout=30):
            calls.append(arguments)
            self.assertEqual(arguments[:2], ['start', '--attach'])
            return 17, stdout, stderr
        with patch.object(Path, 'stat', return_value=socket), patch.dict(globals(), {
                'checked': docker, 'command': start, 'snapshot': lambda *args: 'e' * 64,
                'cleanup': lambda name: cleaned.append(name)}):
            with self.assertRaises(CheckError) as failure:
                run(Path('/public-elf'), image, 'unix:///local-socket')
        self.assertTrue(any(call[:3] == ['inspect', '--format', '{{json .State}}'] for call in calls))
        self.assertEqual(len(cleaned), 1)
        self.assertEqual(str(failure.exception), 'LOCAL_DOCKER_START_FAILED')
        diagnostic = getattr(failure.exception, 'diagnostic', None)
        self.assertEqual(diagnostic, {
            'start_exit_code': 17, 'start_stdout_sha256': hashlib.sha256(stdout).hexdigest(),
            'start_stdout_bytes': len(stdout), 'start_stderr_sha256': hashlib.sha256(stderr).hexdigest(),
            'start_stderr_bytes': len(stderr), 'container_running': False,
            'container_oom_killed': False, 'container_exit_code': 127})
        self.assertNotIn('PRIVATE_', json.dumps(diagnostic))
        valid_state = state
        for change in ({'Running': 0}, {'OOMKilled': 1}, {'ExitCode': True}, {'ExitCode': -1},
                       {'ExitCode': 256}):
            state = {**valid_state, **change}
            with self.subTest(change=change), patch.object(Path, 'stat', return_value=socket), \
                    patch.dict(globals(), {'checked': docker, 'command': start,
                        'snapshot': lambda *args: 'e' * 64, 'cleanup': lambda name: cleaned.append(name)}):
                with self.assertRaises(CheckError) as failure:
                    run(Path('/public-elf'), image, 'unix:///local-socket')
            self.assertEqual(str(failure.exception), 'LOCAL_CONTAINER_STATE_FORMAT_REQUIRED')
            self.assertIsNone(failure.exception.diagnostic)

    def test_real_nonzero_child_safe_start_receipt_is_strictly_adopted(self):
        diagnostic = {'start_exit_code': 17, 'start_stdout_sha256': 'c' * 64,
            'start_stdout_bytes': 4, 'start_stderr_sha256': 'd' * 64, 'start_stderr_bytes': 8,
            'container_running': False, 'container_oom_killed': False, 'container_exit_code': 127}
        payload = {'linux_projected_trust_test': 'FAIL', 'test_execution': 'UNKNOWN',
                   'start_diagnostic': diagnostic}
        message = 'NODEGUARD_TRUST_LINUX_FAILED category=LOCAL_DOCKER_START_FAILED; input values omitted\n'
        child = subprocess.run([sys.executable, '-c',
            'import sys; sys.stdout.write(' + repr(json.dumps(payload) + '\n') +
            '); sys.stderr.write(' + repr(message) + '); sys.exit(5)'], capture_output=True, timeout=10)
        self.assertEqual(child.returncode, 5)
        receipt = child_failure_receipt(child.returncode, child.stdout, child.stderr)
        self.assertEqual(receipt['category'], 'LOCAL_DOCKER_START_FAILED')
        self.assertEqual(receipt['test_execution'], 'UNKNOWN')
        self.assertEqual(receipt.get('start_diagnostic'), diagnostic)
        self.assertEqual(receipt['stdout_sha256'], hashlib.sha256(child.stdout).hexdigest())

    def test_start_receipt_rejects_oversize_unknown_extra_and_unsafe_types(self):
        diagnostic = {'start_exit_code': 17, 'start_stdout_sha256': 'c' * 64,
            'start_stdout_bytes': 4, 'start_stderr_sha256': 'd' * 64, 'start_stderr_bytes': 8,
            'container_running': False, 'container_oom_killed': False, 'container_exit_code': 127}
        payload = {'linux_projected_trust_test': 'FAIL', 'test_execution': 'UNKNOWN',
                   'start_diagnostic': diagnostic}
        message = b'NODEGUARD_TRUST_LINUX_FAILED category=LOCAL_DOCKER_START_FAILED; input values omitted\n'
        invalid = [b'PRIVATE_UNKNOWN_BODY', b'\xff', b'[' * 4096 + b'0' + b']' * 4096,
            json.dumps({**payload, 'secret': 'PRIVATE_BODY'}).encode(),
            json.dumps({**payload, 'linux_projected_trust_test': 'PASS'}).encode(),
            json.dumps({**payload, 'test_execution': 'PASS'}).encode()]
        for change in ({'start_exit_code': True}, {'start_stdout_bytes': OUTPUT_LIMIT + 1},
                       {'start_stdout_sha256': 'z' * 64}, {'container_running': 0},
                       {'start_exit_code': -256}, {'container_oom_killed': 1},
                       {'container_exit_code': -1}, {'container_exit_code': 256},
                       {'secret': 'PRIVATE_BODY'}):
            invalid.append(json.dumps({**payload, 'start_diagnostic': {**diagnostic, **change}}).encode())
        duplicate = json.dumps(payload).replace('"container_exit_code": 127',
                                                  '"container_exit_code": 127, "container_exit_code": 0')
        invalid.append(duplicate.encode())
        child = subprocess.run([sys.executable, '-c',
            'import sys; sys.stdout.buffer.write(b"PRIVATE_BODY" * ' + str(OUTPUT_LIMIT) +
            '); sys.stderr.buffer.write(' + repr(message) + '); sys.exit(5)'], capture_output=True, timeout=10)
        self.assertGreater(len(child.stdout), OUTPUT_LIMIT)
        invalid.append(child.stdout)
        for stdout in invalid:
            with self.subTest(length=len(stdout)):
                receipt = child_failure_receipt(5, stdout, message)
                self.assertEqual(receipt['category'], 'UNKNOWN')
                self.assertNotIn('start_diagnostic', receipt)
                self.assertNotIn('PRIVATE_', json.dumps(receipt))

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
        if valid_start_diagnostic(error.diagnostic):
            print(json.dumps({'linux_projected_trust_test': 'FAIL', 'test_execution': 'UNKNOWN',
                              'start_diagnostic': error.diagnostic}, sort_keys=True))
        raise SystemExit('NODEGUARD_TRUST_LINUX_FAILED category=' + str(error) + '; input values omitted') from None
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('NODEGUARD_TRUST_LINUX_FAILED; input values omitted') from None
