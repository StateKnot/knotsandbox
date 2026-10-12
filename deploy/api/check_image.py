#!/usr/bin/env python3
"""Local Linux candidate check: fixed public fixtures, no shell or cloud access."""
import argparse
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import uuid


REPO = Path(__file__).resolve().parents[2]
SOURCE = '/var/run/api-secret-source'
DESTINATION = '/run/api-private'
STAGED_OUTPUT = '/api-fixture-output'
PUBLIC = {
    'cursor/keyring.json': (REPO / 'tests/fixtures/history/cursor-keys.json').read_bytes(),
    'browser/client-secret': b'PUBLIC-LOCAL-ONLY-CLIENT-SECRET-FIXTURE-000000000000\n',
    'browser/session-keys.json': b'{"active":"public","keys":[{"id":"public","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}\n',
    'metrics/token': b'PUBLIC-LOCAL-ONLY-METRICS-TOKEN-FIXTURE\n',
    'metrics/username': b'public-local-fixture\n',
    'metrics/password': b'PUBLIC-LOCAL-ONLY-METRICS-PASSWORD-FIXTURE\n',
}
TARGETS = {'cursor/keyring.json': 'cursor.json', 'browser/client-secret': 'browser-client-secret',
           'browser/session-keys.json': 'browser-session-keys.json', 'metrics/token': 'metrics-token',
           'metrics/username': 'metrics-username', 'metrics/password': 'metrics-password'}
STAGE = 'STARTUP'


class CheckError(ValueError):
    pass


def require(condition, category):
    if not condition:
        raise CheckError(category)


def archive(files, directory_mode, file_mode=0o440, root='.'):
    """Docker archive restore sets public fixture ownership without a helper ELF."""
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w') as output:
        directories = {root} | {str(Path(path).parent) for path in files}
        for path in sorted(directories):
            member = tarfile.TarInfo(path)
            member.type = tarfile.DIRTYPE; member.mode = directory_mode
            member.uid = 0; member.gid = 10001; member.mtime = 0
            output.addfile(member)
        for path, content in sorted(files.items()):
            member = tarfile.TarInfo(path); member.mode = file_mode; member.size = len(content)
            member.uid = 0; member.gid = 10001; member.mtime = 0
            output.addfile(member, io.BytesIO(content))
    return data.getvalue()


def inspect_bundle(data, expected):
    require(len(data) <= 65536, 'BUNDLE_ARCHIVE_BOUND')
    inventory = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as bundle:
        for member in bundle:
            name = member.name.rstrip('/')
            require(member.uid == 10001 and member.gid == 10001, 'BUNDLE_OWNER')
            if member.isdir():
                require(name == 'private' and member.mode == 0o700, 'BUNDLE_DIRECTORY')
            else:
                require(member.isfile() and name.startswith('private/') and member.mode == 0o600,
                        'BUNDLE_FILE_TYPE_OR_MODE')
                target = name[len('private/'):]
                require(target in expected and target not in inventory and member.size <= 16384,
                        'BUNDLE_INVENTORY')
                stream = bundle.extractfile(member)
                require(stream is not None, 'BUNDLE_READ')
                inventory[target] = stream.read(16385)
    require(inventory == expected, 'BUNDLE_EXACT_BYTES')


def remove_fixture_container(command, name):
    require(re.fullmatch(r'sandbox-api-init-[a-f0-9]{32}-[a-z0-9-]{1,64}', name),
            'LOCAL_PUBLIC_FIXTURE_NAME')
    current = json.loads(command(['inspect', name]).stdout)
    require(isinstance(current, list) and len(current) == 1
            and isinstance(current[0], dict) and current[0].get('Name') == '/' + name
            and isinstance(current[0].get('State'), dict)
            and type(current[0]['State'].get('Running')) is bool,
            'LOCAL_PUBLIC_FIXTURE_IDENTITY')
    if current[0]['State']['Running']:
        command(['stop', '--time', '3', name])
    command(['rm', name])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--docker-host')
    parser.add_argument('--docker-config')
    args = parser.parse_args()
    require(re.fullmatch(r'(?:[a-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9/_-]+@)?sha256:[a-f0-9]{64}', args.image),
            'IMMUTABLE_CANDIDATE_REQUIRED')
    docker = ['docker']
    if args.docker_config: docker += ['--config', args.docker_config]
    if args.docker_host: docker += ['--host', args.docker_host]

    def command(arguments, data=None, acceptable=(0,)):
        result = subprocess.run(docker + arguments, input=data, capture_output=True, timeout=30)
        require(result.returncode in acceptable, 'LOCAL_DOCKER_' + arguments[0].upper() + '_FAILED')
        require(len(result.stdout) <= 1048576 and len(result.stderr) <= 65536, 'LOCAL_DOCKER_OUTPUT_BOUND')
        return result

    # Image metadata is only local content evidence. The release pipeline must
    # separately verify signature/security; this script never grants that gate.
    image = json.loads(command(['image', 'inspect', args.image]).stdout)
    require(len(image) == 1 and image[0]['Os'] == 'linux', 'LINUX_IMAGE_REQUIRED')
    require(image[0]['Config']['User'] in ('10001', '10001:10001'), 'IMAGE_NONROOT_USER')
    image_id = image[0]['Id']
    if args.image.startswith('sha256:'):
        require(image_id == args.image, 'LOCAL_IMAGE_ID_BINDING')
    else:
        require(args.image in image[0].get('RepoDigests', []), 'LOCAL_REPOSITORY_DIGEST_BINDING')
    containers = []; volumes = []; cleanup_ok = True
    suffix = uuid.uuid4().hex

    def fixture(case, files, mode=0o440):
        source = 'sandbox-api-init-' + suffix + '-' + case + '-source'
        output = 'sandbox-api-init-' + suffix + '-' + case + '-output'
        for volume in (source, output):
            command(['volume', 'create', volume]); volumes.append(volume)
        staging = 'sandbox-api-init-' + suffix + '-' + case + '-staging'
        # Docker's copyUIDGID archive API applies the container's configured
        # UID/GID, even for supplied tar headers. This container never runs;
        # its only purpose is setting the PUBLIC projected-fixture metadata.
        command(['create', '--name', staging, '--network', 'none', '--read-only', '--user', '0:10001',
                 '--mount', 'type=volume,src=' + source + ',dst=' + SOURCE,
                 '--mount', 'type=volume,src=' + output + ',dst=' + STAGED_OUTPUT,
                 '--entrypoint', '/usr/local/bin/sandboxd', args.image,
                 'secrets-init', '--profile', 'bearer'])
        containers.append(staging)
        # Staging is never started. Docker's archive API copies only the fixed
        # PUBLIC test files; the tested init mounts its input read-only.
        command(['cp', '-a', '-', staging + ':' + SOURCE], archive(files, 0o550, mode))
        # Docker intentionally does not restore metadata of an existing
        # destination root ('.'). Create an owned subdirectory, then mount
        # that exact subpath where Kubelet supplies the fsGroup memory root.
        command(['cp', '-a', '-', staging + ':' + STAGED_OUTPUT], archive({}, 0o770, root='api-private'))
        return source, output, staging

    def execute(case, source, output, arguments, user='10001:10001', expected_exit=0):
        name = 'sandbox-api-init-' + suffix + '-' + case
        command(['create', '--name', name, '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                 '--security-opt', 'no-new-privileges', '--memory', '67108864', '--cpus', '0.25',
                 '--pids-limit', '32', '--user', user,
                 '--mount', 'type=volume,src=' + source + ',dst=' + SOURCE + ',readonly',
                 '--mount', 'type=volume,src=' + output + ',dst=' + DESTINATION + ',volume-subpath=api-private',
                 '--entrypoint', '/usr/local/bin/sandboxd', args.image, 'secrets-init', *arguments])
        containers.append(name)
        result = command(['start', '--attach', name], acceptable=(0, 1, 125))
        state = json.loads(command(['inspect', '--format', '{{json .State}}', name]).stdout)
        if state['ExitCode'] != expected_exit or state['OOMKilled']:
            categories = [(b'API memory volume ownership rejected', 'MEMORY_VOLUME_OWNER'),
                          (b'API credential type, size or permissions rejected', 'SOURCE_PERMISSIONS'),
                          (b'API credential source unavailable', 'SOURCE_UNAVAILABLE'),
                          (b'Invalid secrets-init arguments', 'ARGUMENTS'),
                          (b'API secrets-init requires UID', 'PROCESS_UID'),
                          (b'Operation not permitted', 'OS_PERMISSION'),
                          (b'Permission denied', 'OS_PERMISSION'),
                          (b'failed to spawn thread', 'RUNTIME_THREADS')]
            category = next((category for marker, category in categories if marker in result.stderr), 'UNCLASSIFIED')
            print(json.dumps({'local_init_exit': state['ExitCode'], 'oom': state['OOMKilled'],
                              'category': category}), flush=True)
        require(not state['Running'] and not state['OOMKilled'] and state['ExitCode'] == expected_exit,
                'INIT_EXIT_OR_RESOURCE_FAILURE')
        require(not result.stdout, 'INIT_UNEXPECTED_STDOUT')
        if expected_exit == 0: require(not result.stderr, 'INIT_UNEXPECTED_STDERR')
        require(not any(content.strip() in result.stdout + result.stderr for content in PUBLIC.values()),
                'PUBLIC_FIXTURE_CONTENT_LEAK')

    try:
        global STAGE
        for case, profile, metrics, paths in [
            ('bearer', 'bearer', 'none', ['cursor/keyring.json']),
            ('browser-token', 'browser', 'bearer', ['cursor/keyring.json', 'browser/client-secret', 'browser/session-keys.json', 'metrics/token']),
            ('browser-basic', 'browser', 'basic', ['cursor/keyring.json', 'browser/client-secret', 'browser/session-keys.json', 'metrics/username', 'metrics/password']),
        ]:
            STAGE = case.upper()
            selected = {path: PUBLIC[path] for path in paths}
            source, output, staging = fixture(case, selected)
            arguments = ['--profile', profile, '--metrics-auth', metrics]
            execute(case, source, output, arguments)
            expected = {TARGETS[path]: PUBLIC[path] for path in paths}
            inspect_bundle(command(['cp', staging + ':' + STAGED_OUTPUT + '/api-private/private', '-']).stdout, expected)
            execute(case + '-idempotent', source, output, arguments)
            inspect_bundle(command(['cp', staging + ':' + STAGED_OUTPUT + '/api-private/private', '-']).stdout, expected)
            if case == 'browser-token':
                changed = dict(selected, **{'metrics/token': b'PUBLIC-LOCAL-ONLY-CHANGED-TOKEN\n'})
                command(['cp', '-a', '-', staging + ':' + SOURCE], archive(changed, 0o550))
                execute(case + '-changed', source, output, arguments, expected_exit=1)
                inspect_bundle(command(['cp', staging + ':' + STAGED_OUTPUT + '/api-private/private', '-']).stdout, expected)
        STAGE = 'NEGATIVE_FIXTURES'
        source, output, staging = fixture('unsafe', {'cursor/keyring.json': PUBLIC['cursor/keyring.json']}, 0o644)
        for case, user, arguments in [('unsafe-mode', '10001:10001', ['--profile', 'bearer']),
                                     ('wrong-owner', '0:0', ['--profile', 'bearer']),
                                     ('wrong-primary-group', '10001:0', ['--profile', 'bearer']),
                                     ('unknown-argument', '10001:10001', ['--profile', 'bearer', '--unknown', 'PUBLIC-LOCAL-ONLY-REJECTED'])]:
            execute(case, source, output, arguments, user, 1)
        content = command(['cp', staging + ':' + STAGED_OUTPUT + '/api-private', '-']).stdout
        with tarfile.open(fileobj=io.BytesIO(content), mode='r:') as output_archive:
            require(all('private' not in Path(member.name).parts for member in output_archive), 'FAILED_INIT_PUBLISHED_BUNDLE')
    finally:
        for name in reversed(containers):
            try: remove_fixture_container(command, name)
            except (ValueError, OSError, KeyError, subprocess.TimeoutExpired):
                cleanup_ok = False
                print('API_PUBLIC_FIXTURE_CLEANUP_FAILED category=CONTAINER name=' + name,
                      file=sys.stderr)
        for name in reversed(volumes):
            try: command(['volume', 'rm', name])
            except (ValueError, OSError, KeyError, subprocess.TimeoutExpired):
                cleanup_ok = False
                print('API_PUBLIC_FIXTURE_CLEANUP_FAILED category=VOLUME name=' + name,
                      file=sys.stderr)
    require(cleanup_ok, 'LOCAL_PUBLIC_FIXTURE_CLEANUP_FAILED')
    print(json.dumps({'image_id': image_id, 'linux_uid10001_readonly_no_shell_init': True,
                      'three_profiles_exact_owned_bundle': True, 'idempotent_and_changed_secret_fenced': True,
                      'permission_uid_unknown_argument_rejected': True, 'public_fixture_cleanup': True,
                      'output_volume_is_memory': False, 'release_signature_verified': False,
                      'cloud_installation_tested': False}))


if __name__ == '__main__':
    try: main()
    except CheckError as error:
        raise SystemExit('API_IMAGE_CHECK_FAILED stage=' + STAGE + ' category=' + str(error)
                         + '; fixture and credential values omitted') from None
    except (ValueError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError, tarfile.TarError, KeyError):
        raise SystemExit('API_IMAGE_CHECK_FAILED; fixture and credential values omitted') from None
