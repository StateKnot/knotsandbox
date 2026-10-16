#!/usr/bin/env python3
"""Run the real host-profile CLI in one owned, isolated Linux amd64 fixture."""
import argparse
import base64
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
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('host_profile_native_contract', ROOT / 'scripts/test-nodeguard-image-observation.py')
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)
require = CONTRACT.require
LABEL = 'host-profile-cli'
TIMEOUT = 90
HOLD_COMMAND = ('/usr/local/bin/python3 /fixture/host_profile_cli.py '
                '--collector /fixture/host_profile.py --record /tmp/host-profile-record.json\n'
                'fixture_status=$?\n'
                'printf "%s\\n" "$fixture_status" > /tmp/fixture-exit-code\n'
                'while [ ! -f /tmp/fixture-retire ]; do /bin/sleep 0.05; done\n'
                'exit "$fixture_status"')
LOG_CONFIG = {'Type': 'local', 'Config': {'max-size': '1m', 'max-file': '1', 'compress': 'false'}}
TMPFS = {
    '/tmp': 'rw,nosuid,nodev,noexec,mode=0755,size=100663296',
    '/opt/kata': 'rw,nosuid,nodev,noexec,mode=0755,size=8388608',
    '/etc/kata-containers': 'rw,nosuid,nodev,noexec,mode=0755,size=3145728',
    '/etc/containerd': 'rw,nosuid,nodev,noexec,mode=0755,size=3145728',
    '/etc/kubernetes': 'rw,nosuid,nodev,noexec,mode=0755,size=3145728',
}
CASES = {'valid', 'missing-mapping', 'runtime-conflict', 'legacy-mapping', 'imports',
         'wrong-platform', 'root-override', 'symlink-file', 'symlink-parent', 'fifo',
         'oversized-config', 'group-writable', 'destination-untrusted-parent',
         'output-existing', 'runtime-path', 'server-endpoint', 'snapshotter-root',
         'stream-processor', 'nri-enabled', 'config-race'}
LIVE_EXPORT = r'''
import base64, hashlib, json, os, re, stat

result = {'version': 1, 'record': None, 'logs': {}, 'errors': []}
descriptors = []
flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC

def directory(path):
    current = os.open('/', flags | os.O_DIRECTORY)
    descriptors.append(current)
    for name in path.split('/')[1:]:
        current = os.open(name, flags | os.O_DIRECTORY, dir_fd=current)
        descriptors.append(current)
        info = os.fstat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('UNTRUSTED_EVIDENCE_DIRECTORY')
    return current

def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def capture(parent, name, limit):
    descriptor = os.open(name, flags, dir_fd=parent)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022:
            raise ValueError('UNTRUSTED_EVIDENCE_FILE')
        if before.st_size > limit:
            raise ValueError('EVIDENCE_BYTE_LIMIT')
        data = bytearray()
        while True:
            block = os.read(descriptor, min(65536, limit + 1 - len(data)))
            if not block:
                break
            data.extend(block)
            if len(data) > limit:
                raise ValueError('EVIDENCE_BYTE_LIMIT')
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (len(data) != before.st_size or file_identity(before) != file_identity(after)
                or file_identity(after) != file_identity(current)):
            raise ValueError('EVIDENCE_CHANGED')
        data = bytes(data)
        return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                'base64': base64.b64encode(data).decode('ascii')}
    finally:
        os.close(descriptor)

try:
    try:
        temporary = directory('/tmp')
        result['record'] = capture(temporary, 'host-profile-record.json', 128 * 1024)
    except Exception:
        result['errors'].append('RECORD_UNAVAILABLE_OR_INVALID')
    try:
        logs = directory('/tmp/host-profile-cli/logs')
        total, count = 0, 0
        with os.scandir(logs) as entries:
            for entry in entries:
                count += 1
                if count > 40:
                    result['errors'].append('LOG_COUNT_LIMIT')
                    break
                if not re.fullmatch(r'[a-z0-9-]{1,64}\.(stdout|stderr)', entry.name):
                    result['errors'].append('UNSAFE_LOG_NAME')
                    continue
                try:
                    value = capture(logs, entry.name, 256 * 1024 - total)
                    total += value['bytes']
                    result['logs'][entry.name] = value
                except Exception:
                    result['errors'].append('LOG_UNAVAILABLE_OR_INVALID')
    except Exception:
        result['errors'].append('LOG_DIRECTORY_UNAVAILABLE_OR_INVALID')
finally:
    for descriptor in reversed(descriptors):
        os.close(descriptor)
print(json.dumps(result, sort_keys=True))
'''


def sources():
    result = CONTRACT.source_fingerprints()
    paths = [ROOT / 'deploy/backup/Dockerfile']
    paths.extend(path for path in (ROOT / 'deploy/nodeguard').rglob('*')
                 if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc')
    for path in paths:
        path = CONTRACT.regular(path)
        result[str(path.relative_to(ROOT))] = {'sha256': CONTRACT.digest(path), 'mode': path.stat().st_mode & 0o777}
    return result


def run(args, evidence, record):
    require(os.geteuid() != 0 and not os.environ.get('RUST_MIN_STACK'), 'ORDINARY_CALLER_WITHOUT_STACK_OVERRIDE_REQUIRED')
    require(Path.cwd().resolve() == ROOT, 'REPOSITORY_WORKING_DIRECTORY_REQUIRED')
    for cache in [ROOT / 'target', Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target')).resolve()]:
        require(evidence != cache and cache not in evidence.parents, 'EVIDENCE_OUTSIDE_CARGO_CACHE_REQUIRED')
    disk = subprocess.check_output(['df', '-Pk', str(ROOT)], text=True)
    record['disk_before'] = disk
    available = int(disk.splitlines()[-1].split()[3]) * 1024
    require(available >= (2 if args.python_image else 8) * 1024**3, 'BOUNDED_FIXTURE_DISK_HEADROOM_REQUIRED')
    if available < 50 * 1024**3:
        record['low_disk_assessment'] = ('No Rust compilation or target copy. Only the locked Python runtime may be built, '
                                         'plus three public COPY inputs and one marker. Owned images/context are removed; '
                                         'no shared cache, existing image, database or volume is pruned.')
    source_before = sources()
    automation = CONTRACT.module('host_profile_local_docker', ROOT / 'scripts/test-automation.py')
    docker, environment = automation.local_docker()
    owner = uuid.uuid4().hex
    name = 'sandbox-host-profile-' + owner
    tag = 'knotsandbox-host-profile-fixture:' + owner
    base_tag = 'knotsandbox-host-profile-python:' + owner
    stage, base_stage = evidence / 'context', evidence / 'base-context'
    image_id, base_id, container_id = None, None, None
    image_attempted, base_attempted, create_attempted = False, False, False
    alias_attempted = False
    original_tags = set()
    retained = set()
    record.update(owner=owner, commands=[], cleanup_errors=[], containers_removed=False,
                  owned_images_removed=False, source_unchanged=False,
                  supplied_base_alias_created=False, supplied_base_alias_removed=False)

    def call(label, arguments, *, check=True, timeout=30):
        started = time.monotonic()
        result, failure = None, None
        try:
            result = subprocess.run([*docker, *arguments], cwd=ROOT, env=environment,
                                    capture_output=True, timeout=timeout)
            output = result.stdout + result.stderr
        except subprocess.TimeoutExpired as error:
            failure = error
            output = (error.stdout or b'') + (error.stderr or b'')
        path = evidence / (str(len(record['commands']) + 1).zfill(3) + '-' + label + '.log')
        path.write_bytes(output[:1024 * 1024])
        path.chmod(0o600)
        record['commands'].append({'label': label, 'exit_code': result.returncode if result is not None else None,
                                   'seconds': round(time.monotonic() - started, 3), 'log': path.name,
                                   'sha256': CONTRACT.digest(path), 'timed_out': failure is not None})
        if failure is not None:
            raise failure
        require(len(output) <= 1024 * 1024, 'FIXTURE_COMMAND_OUTPUT_BOUND')
        require(not check or result.returncode == 0, 'OWNED_FIXTURE_COMMAND_FAILED_' + label)
        return result

    def inspect_image(reference, owned=False):
        value = json.loads(call('inspect-image', ['image', 'inspect', reference]).stdout)[0]
        require(value['Os'] == 'linux' and value['Architecture'] == 'amd64'
                and not value['Config'].get('Volumes'), 'LINUX_AMD64_VOLUME_FREE_IMAGE_REQUIRED')
        if owned:
            labels = value['Config'].get('Labels', {})
            require(labels.get('com.sandbox.fixture') == LABEL
                    and labels.get('com.sandbox.owner') == owner, 'EXACT_OWNED_IMAGE_LABELS_REQUIRED')
        return value

    def inspect_container(identity, timeout=30):
        value = json.loads(call('inspect-owned-container', ['inspect', identity], timeout=timeout).stdout)[0]
        labels = value['Config'].get('Labels', {})
        require(value['Id'] == identity and value['Name'] == '/' + name and value['Image'] == image_id
                and labels.get('com.sandbox.fixture') == LABEL
                and labels.get('com.sandbox.owner') == owner, 'EXACT_FIXTURE_CONTAINER_OWNER_REQUIRED')
        return value

    def manifest(directory):
        return {str(path.relative_to(directory)): CONTRACT.digest(CONTRACT.regular(path))
                for path in directory.rglob('*') if path.is_file()}

    def retain_evidence(identity, deadline=None):
        # Docker archive endpoints need not expose tmpfs. Read only fixed paths
        # through the live process and validate the bounded envelope ourselves.
        if retained:
            return
        retained.add('live-export')
        try:
            timeout = 30 if deadline is None else min(30, deadline - time.monotonic())
            require(timeout > 0, 'ORIGINAL_FIXTURE_DEADLINE_EXPIRED')
            exported = call('retain-live-private-evidence', ['exec', identity, '/usr/local/bin/python3', '-c', LIVE_EXPORT],
                            timeout=timeout)
            require(not exported.stderr, 'LIVE_EXPORT_STDERR_MUST_BE_EMPTY')
            def unique_members(items):
                value = {}
                for key, item in items:
                    require(key not in value, 'DUPLICATE_EXPORT_JSON_MEMBER')
                    value[key] = item
                return value
            envelope = json.loads(exported.stdout, object_pairs_hook=unique_members)
            require(isinstance(envelope, dict) and set(envelope) == {'version', 'record', 'logs', 'errors'}
                    and type(envelope['version']) is int and envelope['version'] == 1,
                    'EXACT_LIVE_EXPORT_ENVELOPE_REQUIRED')
            errors, logs = envelope['errors'], envelope['logs']
            require(isinstance(errors, list) and len(errors) <= 42
                    and all(isinstance(error, str) and re.fullmatch(r'[A-Z_]{1,64}', error) for error in errors)
                    and isinstance(logs, dict) and len(logs) <= 40, 'BOUNDED_EXPORT_METADATA_REQUIRED')
            allowed_logs = {case + suffix for case in CASES for suffix in ('.stdout', '.stderr')}
            require(set(logs) <= allowed_logs, 'FIXED_LOG_NAMES_REQUIRED')
            def decode(value, limit):
                require(isinstance(value, dict) and set(value) == {'bytes', 'sha256', 'base64'}
                        and type(value['bytes']) is int and 0 <= value['bytes'] <= limit
                        and isinstance(value['sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', value['sha256'])
                        and isinstance(value['base64'], str)
                        and len(value['base64']) <= ((limit + 2) // 3) * 4, 'BOUNDED_EXPORT_FILE_REQUIRED')
                data = base64.b64decode(value['base64'], validate=True)
                require(len(data) == value['bytes'] and hashlib.sha256(data).hexdigest() == value['sha256']
                        and base64.b64encode(data).decode('ascii') == value['base64'], 'LIVE_EXPORT_FILE_IDENTITY_REQUIRED')
                return data
            files, total = {}, 0
            if envelope['record'] is not None:
                files['inside-record.json'] = decode(envelope['record'], 128 * 1024)
            for name, value in logs.items():
                data = decode(value, 256 * 1024)
                total += len(data)
                require(total <= 256 * 1024, 'AGGREGATE_LOG_BYTE_LIMIT')
                files['cli-logs/' + name] = data
            require(not (evidence / 'cli-logs').exists(), 'NEW_PRIVATE_LOG_DIRECTORY_REQUIRED')
            (evidence / 'cli-logs').mkdir(mode=0o700)
            for name, data in files.items():
                descriptor = os.open(evidence / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(data)
            record.update(exported_log_count=len(logs), exported_log_bytes=total,
                          live_export_errors=errors,
                          private_evidence_sha256={name: hashlib.sha256(data).hexdigest() for name, data in files.items()})
            if errors:
                record['cleanup_errors'].append('LIVE_EXPORT_REPORTED_PARTIAL_EVIDENCE')
        except Exception as error:
            record['cleanup_errors'].append(type(error).__name__ + ':' + str(error))

    try:
        server = json.loads(call('docker-server', ['version', '--format', '{{json .Server}}']).stdout)
        require(server['Os'] == 'linux', 'LINUX_DOCKER_REQUIRED')
        record.update(docker_server_arch=server['Arch'], fixture_platform='linux/amd64')
        if args.python_image:
            require(re.fullmatch(r'sha256:[0-9a-f]{64}', args.python_image), 'EXACT_LOCAL_PYTHON_IMAGE_ID_REQUIRED')
            base = inspect_image(args.python_image)
            require(base['Id'] == args.python_image, 'EXACT_SUPPLIED_PYTHON_IMAGE_REQUIRED')
            base_id = base['Id']
            record['supplied_python_image'] = base_id
            original_tags = set(base.get('RepoTags') or [])
            require(original_tags, 'SUPPLIED_PYTHON_IMAGE_REQUIRES_AN_EXISTING_TAG_TO_PRESERVE_ID')
            require(not call('base-alias-absence', ['image', 'ls', '-aq', '--filter', 'reference=' + base_tag]).stdout.strip(),
                    'NEW_RANDOM_BASE_ALIAS_REQUIRED')
            alias_attempted = True
            call('create-supplied-base-alias', ['tag', base_id, base_tag])
            require(inspect_image(base_tag)['Id'] == base_id, 'EXACT_SUPPLIED_BASE_ALIAS_REQUIRED')
            record.update(supplied_base_alias=base_tag, supplied_base_alias_created=True,
                          supplied_base_original_tags=sorted(original_tags))
        else:
            base_stage.mkdir(mode=0o700)
            shutil.copyfile(ROOT / 'deploy/backup/Dockerfile', base_stage / 'Dockerfile')
            base_before = manifest(base_stage)
            require(set(base_before) == {'Dockerfile'}, 'ONLY_EXISTING_LOCKED_PYTHON_DOCKERFILE_ALLOWED')
            base_attempted = True
            call('build-owned-python', ['build', '--pull', '--network=none', '--platform=linux/amd64',
                 '--target=python-runtime', '--label', 'com.sandbox.fixture=' + LABEL,
                 '--label', 'com.sandbox.owner=' + owner, '--tag', base_tag, str(base_stage)], timeout=180)
            base_id = inspect_image(base_tag, owned=True)['Id']
            require(manifest(base_stage) == base_before, 'PYTHON_BASE_INPUT_CHANGED')
            record['python_base_context'] = base_before
            record['owned_python_image'] = base_id
        stage.mkdir(mode=0o700)
        for source, target in [('deploy/nodeguard/host_profile.py', 'host_profile.py'),
                               ('deploy/nodeguard/tests/host_profile_cli.py', 'host_profile_cli.py')]:
            shutil.copyfile(CONTRACT.regular(ROOT / source), stage / target)
            (stage / target).chmod(0o444)
        (stage / 'CONFINED_HOST_PROFILE_TEST').write_text('public disposable host-profile CLI fixture\n')
        (stage / 'CONFINED_HOST_PROFILE_TEST').chmod(0o444)
        (stage / 'Dockerfile').write_text(
            'FROM ' + base_tag + '\n'
            'COPY --chown=0:0 --chmod=0444 host_profile.py host_profile_cli.py CONFINED_HOST_PROFILE_TEST /fixture/\n'
            'RUN ["/bin/sh","-ceu","mkdir -p /etc/kata-containers /etc/containerd /etc/kubernetes /opt/kata; '
            'chown 0:0 /fixture; chmod 0555 /fixture"]\n')
        context_before = manifest(stage)
        require(set(context_before) == {'Dockerfile', 'host_profile.py', 'host_profile_cli.py', 'CONFINED_HOST_PROFILE_TEST'},
                'EXACT_PUBLIC_COPY_CONTEXT_REQUIRED')
        record['build_context'] = context_before
        image_attempted = True
        call('build-owned-fixture', ['build', '--network=none', '--platform=linux/amd64',
             '--label', 'com.sandbox.fixture=' + LABEL, '--label', 'com.sandbox.owner=' + owner,
             '--tag', tag, str(stage)], timeout=90)
        image_id = inspect_image(tag, owned=True)['Id']
        record['fixture_image'] = image_id
        require(inspect_image(base_tag)['Id'] == base_id, 'BASE_ALIAS_CHANGED_DURING_FIXTURE_BUILD')
        require(context_before == manifest(stage), 'COPY_INPUTS_CHANGED')
        record['copy_inputs_unchanged'] = True
        arguments = ['create', '--name', name, '--platform=linux/amd64',
            '--label', 'com.sandbox.fixture=' + LABEL, '--label', 'com.sandbox.owner=' + owner,
            '--user=0:0', '--network=none', '--read-only', '--cap-drop=ALL',
            '--security-opt=no-new-privileges:true', '--cgroupns=private',
            '--memory=268435456', '--memory-swap=268435456', '--cpus=1', '--pids-limit=64',
            '--ulimit=nofile=1024:1024', '--log-driver=local', '--log-opt=max-size=1m',
            '--log-opt=max-file=1', '--log-opt=compress=false']
        for path, options in TMPFS.items():
            arguments.extend(['--tmpfs', path + ':' + options])
        arguments.extend(['--entrypoint=/bin/sh', image_id, '-cu', HOLD_COMMAND])
        create_attempted = True
        container_id = call('create-owned', arguments).stdout.decode().strip()
        require(re.fullmatch(r'[0-9a-f]{64}', container_id), 'EXACT_CONTAINER_ID_REQUIRED')
        value = inspect_container(container_id)
        host = value['HostConfig']
        require(not value['Mounts'] and not host.get('Binds') and host['Tmpfs'] == TMPFS
                and not host.get('Privileged') and not host.get('CapAdd') and host['CapDrop'] == ['ALL']
                and host['ReadonlyRootfs'] and host['NetworkMode'] == 'none' and not host.get('PortBindings')
                and not host.get('PidMode') and host['CgroupnsMode'] == 'private'
                and host['Memory'] == 256 * 1024**2 and host['MemorySwap'] == host['Memory']
                and host['NanoCpus'] == 1_000_000_000 and host['PidsLimit'] == 64
                and host['LogConfig'] == LOG_CONFIG and value['Config']['User'] == '0:0'
                and 'no-new-privileges:true' in host['SecurityOpt']
                and host['Ulimits'] == [{'Name': 'nofile', 'Hard': 1024, 'Soft': 1024}]
                and value['Config']['Entrypoint'] == ['/bin/sh']
                and value['Config']['Cmd'] == ['-cu', HOLD_COMMAND],
                'EXACT_RESOURCE_AND_ISOLATION_CONTRACT_REQUIRED')
        record['container_entrypoint'] = value['Config']['Entrypoint']
        record['container_command'] = value['Config']['Cmd']
        started = time.monotonic()
        deadline = started + TIMEOUT
        def remaining():
            value = deadline - time.monotonic()
            require(value > 0, 'ORIGINAL_FIXTURE_DEADLINE_EXPIRED')
            return value
        call('start-owned', ['start', container_id], timeout=min(10, remaining()))
        while True:
            ready = call('observe-helper-exit-record', ['exec', container_id, '/bin/sh', '-cu',
                         'test -f /tmp/fixture-exit-code'], check=False, timeout=min(5, remaining()))
            if ready.returncode == 0:
                break
            require(ready.returncode == 1, 'OWNED_HELPER_EXIT_OBSERVATION_FAILED')
            time.sleep(min(0.2, remaining()))
        require(inspect_container(container_id, timeout=min(5, remaining()))['State']['Running'], 'LIVE_TMPFS_EVIDENCE_REQUIRED')
        retain_evidence(container_id, deadline)
        exit_record = call('actual-helper-exit', ['exec', container_id, '/bin/cat', '/tmp/fixture-exit-code'],
                           timeout=min(5, remaining())).stdout.strip()
        require(re.fullmatch(rb'[0-9]{1,3}', exit_record), 'FIXED_HELPER_EXIT_RECORD_REQUIRED')
        record['helper_exit_code'] = int(exit_record)
        require(record['helper_exit_code'] <= 255, 'VALID_HELPER_EXIT_CODE_REQUIRED')
        logs = call('actual-cli-summary', ['logs', container_id], timeout=min(5, remaining()))
        require(not logs.stderr, 'FIXTURE_STDERR_MUST_BE_EMPTY')
        summary = json.loads(logs.stdout)
        record['summary'] = summary
        require((evidence / 'inside-record.json').is_file()
                and json.loads((evidence / 'inside-record.json').read_bytes()) == summary,
                'PRESERVED_LIVE_RECORD_MUST_MATCH_ACTUAL_STDOUT')
        require(record.get('exported_log_count') == 40 and not record.get('live_export_errors'),
                'ALL_FORTY_CLOSED_CLI_LOGS_REQUIRED')
        require(summary['status'] == 'PASS' and summary['collector_sha256'] == source_before['deploy/nodeguard/host_profile.py']['sha256'],
                'ACTUAL_COLLECTOR_AND_CLI_SUMMARY_REQUIRED')
        cases = summary['cases']
        require(len(cases) == 20 and {case['case'] for case in cases} == CASES
                and all(case['status'] == 'PASS' and not case['timed_out'] and case['owned_inputs_removed']
                        and case['expected'] == ('success' if case['case'] == 'valid' else 'reject')
                        and (case['exit_code'] == 0 if case['case'] == 'valid'
                             else case['exit_code'] != 0 and not case['enrollment_exists']) for case in cases),
                'ALL_TWENTY_ACTUAL_CLI_CASES_REQUIRED')
        race = next(case for case in cases if case['case'] == 'config-race')
        require(race['race_barrier']['observed_qemu_fd'] and race['race_barrier']['config_fd_still_open'],
                'ACTUAL_RETAINED_CONFIG_FD_RACE_BARRIER_REQUIRED')
        require(record['helper_exit_code'] == 0, 'ACTUAL_HELPER_EXIT_ZERO_REQUIRED')
        call('retire-owned-helper', ['exec', container_id, '/usr/bin/touch', '/tmp/fixture-retire'],
             timeout=min(5, remaining()))
        waited = call('wait-owned', ['wait', container_id], timeout=remaining())
        record['fixture_seconds'] = round(time.monotonic() - started, 6)
        state = inspect_container(container_id)['State']
        require(waited.stdout.strip() == b'0' and not state['Running'] and not state.get('OOMKilled')
                and state['ExitCode'] == 0, 'ACTUAL_CONTAINER_EXIT_ZERO_REQUIRED')
        require(context_before == manifest(stage), 'FINAL_COPY_INPUTS_CHANGED')
        if not args.python_image:
            require(base_before == manifest(base_stage), 'FINAL_PYTHON_BASE_INPUT_CHANGED')
        if args.python_image:
            require(inspect_image(args.python_image)['Id'] == base_id
                    and inspect_image(base_tag)['Id'] == base_id, 'SUPPLIED_PYTHON_IMAGE_CHANGED')
            record['supplied_python_image_unchanged'] = True
    finally:
        primary = sys.exc_info()[0] is not None
        if create_attempted:
            try:
                if container_id is None or not re.fullmatch(r'[0-9a-f]{64}', container_id):
                    found = call('recover-create-identity', ['inspect', name], check=False)
                    container_id = None
                    if found.returncode == 0:
                        container_id = json.loads(found.stdout)[0]['Id']
                if container_id is not None:
                    value = inspect_container(container_id)
                    if value['State']['Running']:
                        retain_evidence(container_id)
                    call('remove-owned-container', ['rm', '-f', '-v', container_id])
                require(not call('verify-container-absence', ['ps', '-aq', '--no-trunc', '--filter', 'name=^/' + name + '$']).stdout.strip(),
                        'OWNED_CONTAINER_ABSENCE_REQUIRED')
                record['containers_removed'] = True
            except Exception as error:
                record['cleanup_errors'].append(type(error).__name__ + ':' + str(error))
        else:
            record['containers_removed'] = True
        for attempted, reference, expected in [(image_attempted, tag, image_id), (base_attempted, base_tag, base_id)]:
            if not attempted:
                continue
            try:
                found = call('cleanup-image-inspect', ['image', 'inspect', reference], check=False)
                if found.returncode == 0:
                    value = json.loads(found.stdout)[0]
                    labels = value['Config'].get('Labels', {})
                    require(labels.get('com.sandbox.owner') == owner and labels.get('com.sandbox.fixture') == LABEL
                            and (expected is None or value['Id'] == expected), 'EXACT_OWNED_IMAGE_CLEANUP_REQUIRED')
                    call('remove-owned-image', ['image', 'rm', value['Id']])
            except Exception as error:
                record['cleanup_errors'].append(type(error).__name__ + ':' + str(error))
        if alias_attempted:
            try:
                found = call('supplied-base-alias-cleanup-inspect', ['image', 'inspect', base_tag], check=False)
                if found.returncode == 0:
                    value = json.loads(found.stdout)[0]
                    require(value['Id'] == base_id, 'EXACT_SUPPLIED_BASE_ALIAS_CLEANUP_REQUIRED')
                    # Removing an image's sole tag can delete the original ID.
                    # Retain at least one pre-existing tag before untagging ours.
                    require(original_tags.intersection(value.get('RepoTags') or []),
                            'ORIGINAL_BASE_TAG_REQUIRED_BEFORE_ALIAS_REMOVAL')
                    call('remove-only-supplied-base-alias', ['image', 'rm', base_tag])
                require(not call('supplied-base-alias-absence', ['image', 'ls', '-aq', '--filter', 'reference=' + base_tag]).stdout.strip(),
                        'SUPPLIED_BASE_ALIAS_ABSENCE_REQUIRED')
                require(inspect_image(args.python_image)['Id'] == base_id, 'ORIGINAL_SUPPLIED_IMAGE_MUST_REMAIN')
                record['supplied_base_alias_removed'] = True
                record['supplied_python_image_unchanged'] = True
            except Exception as error:
                record['cleanup_errors'].append(type(error).__name__ + ':' + str(error))
        try:
            require(not call('verify-image-absence', ['image', 'ls', '-aq', '--filter', 'label=com.sandbox.owner=' + owner]).stdout.strip(),
                    'OWNED_IMAGE_ABSENCE_REQUIRED')
            record['owned_images_removed'] = True
        except Exception as error:
            record['cleanup_errors'].append(type(error).__name__ + ':' + str(error))
        for directory in (stage, base_stage):
            try:
                if directory.exists():
                    shutil.rmtree(directory)
            except Exception as error:
                record['cleanup_errors'].append(type(error).__name__ + ':' + str(error))
        record['contexts_removed'] = not stage.exists() and not base_stage.exists()
        try:
            record['source_unchanged'] = sources() == source_before
        except Exception as error:
            record['cleanup_errors'].append(type(error).__name__ + ':' + str(error))
        try:
            record['disk_after'] = subprocess.check_output(['df', '-Pk', str(ROOT)], text=True)
        except Exception as error:
            record['cleanup_errors'].append(type(error).__name__ + ':' + str(error))
        if not primary:
            require(not record['cleanup_errors'] and record['containers_removed'] and record['owned_images_removed']
                    and record['contexts_removed'] and record['source_unchanged'], 'OWNED_CLEANUP_AND_SOURCE_CONTRACT_REQUIRED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    parser.add_argument('--python-image')
    args = parser.parse_args()
    evidence = args.evidence_dir.absolute()
    require('..' not in evidence.parts and not any(path.is_symlink() for path in evidence.parents), 'REAL_EVIDENCE_PATH_REQUIRED')
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    evidence = evidence.resolve()
    record = {'status': 'FAIL', 'scope': 'actual host-profile configuration CLI, not native preparation or physical Kata certification'}
    try:
        run(args, evidence, record)
        record['status'] = 'PASS'
    except Exception as error:
        record['failure'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        path = evidence / 'record.json'
        path.write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
        path.chmod(0o600)
    print(json.dumps({'status': record['status'], 'evidence': str(evidence), 'failure': record.get('failure')}))
    return 0 if record['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
