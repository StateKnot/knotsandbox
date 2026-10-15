#!/usr/bin/env python3
"""Actual offline Linux admin CLI in an owned non-root, read-only, network-none image."""
import argparse
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
SPEC = importlib.util.spec_from_file_location('image_artifact_native_contract', ROOT / 'scripts/test-nodeguard-image-observation.py')
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)
EXPECTED_ROOT = 'sha256:bbcc60ed9423dd84b19a56d09759aec31ee3db1b729455f9414646808b624379'
AMD_CONFIG = '7bfed7d6080f5d9aa427991b771a274ee4845f93232f914a49afbe3f895a141c'
LABEL = 'image-artifact-metadata'
require = CONTRACT.require


def run(args, evidence, record):
    require(os.geteuid() != 0 and not os.environ.get('RUST_MIN_STACK'), 'ORDINARY_CALLER_WITHOUT_STACK_OVERRIDE_REQUIRED')
    require(Path.cwd().resolve() == ROOT, 'REPOSITORY_WORKING_DIRECTORY_REQUIRED')
    source_before = CONTRACT.source_fingerprints()
    disk = subprocess.check_output(['df', '-Pk', str(ROOT)], text=True)
    record['disk_before'] = disk
    available = int(disk.splitlines()[-1].split()[3]) * 1024
    require(available >= 2 * 1024**3, 'BOUNDED_FIXTURE_DISK_HEADROOM_REQUIRED')
    if available < 50 * 1024**3:
        record['low_disk_assessment'] = ('No compilation or target copy. One <=512MiB exact executable and seven public metadata files '
                                         'enter an owned image; image and staging data are removed. Active artifacts remain in use; '
                                         'no shared cache or volume is pruned.')
    fixture = CONTRACT.module('image_artifact_automation', ROOT / 'scripts/test-automation.py')
    docker, environment = fixture.local_docker()
    owner = uuid.uuid4().hex
    tag = 'knotsandbox-image-artifact-fixture:' + owner
    image_id = None
    built = False
    containers = {}
    attempted_names = set()
    retired_names = set()
    stage = evidence / 'context'
    record.update(owner=owner, cases=[], commands=[], cleanup_errors=[])

    def call(label, arguments, *, check=True, timeout=30):
        started = time.monotonic()
        failure = None
        try:
            result = subprocess.run([*docker, *arguments], cwd=ROOT, env=environment,
                                    capture_output=True, timeout=timeout)
            output = result.stdout + result.stderr
        except subprocess.TimeoutExpired as error:
            failure = error
            output = (error.stdout or b'') + (error.stderr or b'')
        log = evidence / (str(len(record['commands']) + 1).zfill(3) + '-' + label + '.log')
        log.write_bytes(output[:1024 * 1024])
        log.chmod(0o600)
        record['commands'].append({'label': label, 'exit_code': result.returncode if failure is None else None,
                                   'seconds': round(time.monotonic() - started, 3),
                                   'log': log.name, 'sha256': CONTRACT.digest(log), 'timed_out': failure is not None})
        if failure is not None:
            raise failure
        require(len(output) <= 1024 * 1024, 'FIXTURE_COMMAND_OUTPUT_BOUND')
        require(not check or result.returncode == 0, 'OWNED_FIXTURE_COMMAND_FAILED_' + label)
        return result

    def inspect_owned(identity, name):
        value = json.loads(call('inspect-owned', ['inspect', identity]).stdout)[0]
        labels = value['Config'].get('Labels', {})
        require(value['Id'] == identity and value['Name'] == '/' + name and value['Image'] == image_id
                and labels.get('com.sandbox.fixture') == LABEL and labels.get('com.sandbox.owner') == owner,
                'EXACT_FIXTURE_CONTAINER_OWNER_REQUIRED')
        return value

    def retire(identity, name):
        inspect_owned(identity, name)
        call('remove-owned', ['rm', '-f', '-v', identity])
        require(not call('verify-absence', ['ps', '-aq', '--no-trunc', '--filter', 'id=' + identity]).stdout.strip(),
                'OWNED_CONTAINER_ABSENCE_REQUIRED')
        del containers[identity]
        retired_names.add(name)

    try:
        artifacts = CONTRACT.regular(args.artifacts)
        require(artifacts.stat().st_size <= 32 * 1024 * 1024, 'CARGO_MESSAGE_BOUND')
        artifact_sha = CONTRACT.digest(artifacts)
        metadata = subprocess.run(['cargo', 'metadata', '--locked', '--offline', '--no-deps', '--format-version=1'],
                                  cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30)
        require(metadata.returncode == 0, 'CARGO_METADATA_REQUIRED')
        metadata = json.loads(metadata.stdout)
        require(metadata['workspace_root'] == str(ROOT), 'EXACT_CARGO_WORKSPACE_REQUIRED')
        package = [p for p in metadata['packages'] if p['name'] == 'sandbox-platform' and p['manifest_path'] == str(ROOT / 'Cargo.toml')]
        require(len(package) == 1, 'EXACT_ROOT_PACKAGE_REQUIRED')
        rows = [json.loads(line) for line in artifacts.read_text().splitlines() if line.strip()]
        selected = [row for row in rows if row.get('reason') == 'compiler-artifact' and row.get('executable')
                    and row.get('target', {}).get('name') == 'sandbox-admin' and row.get('target', {}).get('kind') == ['bin']
                    and row.get('profile', {}).get('test') is False]
        require(len(selected) == 1, 'EXACT_ONE_ADMIN_ARTIFACT_REQUIRED')
        item = selected[0]
        require(item['package_id'] == package[0]['id'] and item['manifest_path'] == str(ROOT / 'Cargo.toml')
                and item['target']['src_path'] == str(ROOT / 'src/bin/sandbox-admin.rs'), 'EXACT_ADMIN_ARTIFACT_IDENTITY_REQUIRED')
        binary = CONTRACT.regular(item['executable'])
        require(binary == Path(metadata['target_directory']) / 'debug/sandbox-admin'
                and binary.stat().st_uid == os.geteuid() and binary.stat().st_mode & 0o111
                and not binary.stat().st_mode & 0o022 and binary.stat().st_size <= 512 * 1024 * 1024,
                'ORDINARY_TARGET_ADMIN_BINARY_REQUIRED')
        before_binary = CONTRACT.fingerprint(binary)
        server = json.loads(call('docker-server', ['version', '--format', '{{json .Server}}']).stdout)
        arch = server['Arch']
        require(server['Os'] == 'linux' and arch in ('arm64', 'amd64'), 'NATIVE_LINUX_DOCKER_REQUIRED')
        with binary.open('rb') as stream:
            header = stream.read(64)
        require(len(header) == 64 and header[:7] == b'\x7fELF\x02\x01\x01'
                and int.from_bytes(header[18:20], 'little') == {'amd64': 62, 'arm64': 183}[arch], 'NATIVE_LINUX_ADMIN_ELF_REQUIRED')
        require(Path(metadata['target_directory']) not in evidence.parents, 'EVIDENCE_OUTSIDE_CARGO_CACHE_REQUIRED')
        bases = re.findall(r'^ARG RUNTIME_IMAGE=(debian:trixie-slim@sha256:[0-9a-f]{64})$', (ROOT / 'Dockerfile').read_text(), re.M)
        require(len(bases) == 1, 'LOCKED_RUNTIME_IMAGE_REQUIRED')
        stage.mkdir(mode=0o700)
        files = stage / 'rootfs/fixture'
        files.mkdir(parents=True)
        shutil.copyfile(binary, files / 'sandbox-admin')
        (files / 'sandbox-admin').chmod(0o555)
        golden = ROOT / 'tests/fixtures/image-artifact'
        inputs = [path for path in golden.rglob('*') if path.is_file()]
        require(len(inputs) == 7 and all(not path.is_symlink() for path in inputs), 'EXACT_PUBLIC_OCI_FIXTURE_INPUTS_REQUIRED')
        for destination in ('layout', 'link-blob'):
            for source in inputs:
                target = files / destination / source.relative_to(golden)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read_bytes())
                target.chmod(0o444)
        (files / 'link-blob/blobs/sha256' / AMD_CONFIG).unlink()
        (files / 'fifo/blobs/sha256').mkdir(parents=True)
        for directory in [files, *(p for p in files.rglob('*') if p.is_dir())]:
            directory.chmod(0o555)
        dockerfile = ('FROM ' + bases[0] + '\nCOPY rootfs/ /\nRUN ["/bin/sh","-ceu",'
                      + json.dumps('ln -s /fixture/layout /fixture/link-layout; '
                                   'ln -s /fixture/layout/blobs/sha256/' + AMD_CONFIG + ' /fixture/link-blob/blobs/sha256/' + AMD_CONFIG + '; '
                                   'mkfifo -m 444 /fixture/fifo/oci-layout') + ']\n')
        (stage / 'Dockerfile').write_text(dockerfile)
        def context_manifest():
            return {str(p.relative_to(stage)): CONTRACT.digest(p) for p in stage.rglob('*') if p.is_file()}
        context_before = context_manifest()
        record.update(binary_sha256=before_binary['sha256'], artifacts_sha256=artifact_sha,
                      runtime_image=bases[0], architecture='linux/' + arch, build_context=context_before)
        built = True
        call('build-owned-image', ['build', '--pull', '--network=none', '--platform', 'linux/' + arch,
             '--label', 'com.sandbox.fixture=' + LABEL, '--label', 'com.sandbox.owner=' + owner,
             '--tag', tag, str(stage)], timeout=180)
        image = json.loads(call('inspect-image', ['image', 'inspect', tag]).stdout)[0]
        require(image['Config']['Labels'].get('com.sandbox.owner') == owner
                and image['Config']['Labels'].get('com.sandbox.fixture') == LABEL
                and image['Architecture'] == arch, 'OWNED_IMAGE_IDENTITY_REQUIRED')
        image_id = image['Id']
        require(context_before == context_manifest(), 'COPY_INPUTS_CHANGED')
        cases = [('amd64', '/fixture/layout', EXPECTED_ROOT, 'linux/amd64', None),
                 ('arm64', '/fixture/layout', EXPECTED_ROOT, 'linux/arm64/v8', None),
                 ('wrong-platform', '/fixture/layout', EXPECTED_ROOT, 'linux/arm64', 'PLATFORM_MISMATCH'),
                 ('wrong-digest', '/fixture/layout', 'sha256:' + '0' * 64, 'linux/amd64', 'METADATA_UNAVAILABLE'),
                 ('symlink-root', '/fixture/link-layout', EXPECTED_ROOT, 'linux/amd64', 'METADATA_UNAVAILABLE'),
                 ('symlink-blob', '/fixture/link-blob', EXPECTED_ROOT, 'linux/amd64', 'METADATA_UNAVAILABLE'),
                 ('fifo-metadata', '/fixture/fifo', EXPECTED_ROOT, 'linux/amd64', 'METADATA_UNAVAILABLE')]
        for label, layout, digest, platform, error in cases:
            name = 'sandbox-image-artifact-' + owner + '-' + label
            attempted_names.add(name)
            identity = call('create-' + label, ['create', '--name', name, '--platform', 'linux/' + arch,
                '--label', 'com.sandbox.fixture=' + LABEL, '--label', 'com.sandbox.owner=' + owner,
                '--user', '501:20', '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
                '--cgroupns=private', '--memory=134217728', '--memory-swap=134217728', '--cpus=1', '--pids-limit=64',
                '--ulimit=nofile=1024:1024', '--log-driver=local', '--log-opt=max-size=1m', '--log-opt=max-file=1', '--log-opt=compress=false',
                '--env', 'SANDBOX_ADMIN_DATABASE_URL=postgresql://unused.invalid/forbidden', '--env', 'HTTPS_PROXY=http://unused.invalid:1',
                '--entrypoint', '/fixture/sandbox-admin', tag, 'image-artifact', 'verify', '--layout', layout,
                '--expected-digest', digest, '--platform', platform]).stdout.decode().strip()
            require(re.fullmatch(r'[0-9a-f]{64}', identity), 'EXACT_CONTAINER_ID_REQUIRED')
            containers[identity] = name
            value = inspect_owned(identity, name)
            host = value['HostConfig']
            require(not value['Mounts'] and not host.get('Binds') and not host.get('Tmpfs') and not host.get('Privileged')
                    and not host.get('CapAdd') and host['CapDrop'] == ['ALL'] and host['ReadonlyRootfs']
                    and host['NetworkMode'] == 'none' and not host.get('PortBindings') and not host.get('PidMode')
                    and host['CgroupnsMode'] == 'private' and host['Memory'] == 128 * 1024**2 and host['MemorySwap'] == host['Memory']
                    and host['NanoCpus'] == 1_000_000_000 and host['PidsLimit'] == 64
                    and 'no-new-privileges:true' in host['SecurityOpt'] and value['Config']['User'] == '501:20',
                    'EXACT_RESOURCE_AND_ISOLATION_CONTRACT_REQUIRED')
            result = call('case-' + label, ['start', '--attach', identity], check=False, timeout=5)
            require(b'PUBLIC_SECRET_SENTINEL' not in result.stdout + result.stderr, 'CONFIG_MUST_NOT_BE_ECHOED')
            if error:
                require(result.returncode != 0 and not result.stdout and
                        result.stderr.strip() == ('Error: image artifact metadata verification failed: ' + error).encode(), 'FIXED_REJECTION_REQUIRED_' + label)
                output = {'error_code': error}
            else:
                require(result.returncode == 0 and not result.stderr, 'ACTUAL_OFFLINE_CLI_SUCCESS_REQUIRED')
                output = json.loads(result.stdout)
                require(output['scope'] == 'OCI_METADATA_ONLY' and output['approval_checked'] is False
                        and output['layer_payloads_verified'] is False and output['preparation_allowed'] is False
                        and output['root']['digest'] == EXPECTED_ROOT, 'METADATA_SCOPE_MUST_NOT_GRANT_AUTHORITY')
                require(output['declared_layer_bytes'] == ('62' if label == 'amd64' else '0')
                        and output['unique_declared_layer_bytes'] == ('31' if label == 'amd64' else '0'), 'INDEPENDENT_DECLARED_SIZE_ORACLE')
            state = inspect_owned(identity, name)['State']
            require(not state['Running'] and not state.get('OOMKilled') and state['ExitCode'] == result.returncode, 'ACTUAL_CLI_EXIT_REQUIRED')
            record['cases'].append({'case': label, 'exit_code': result.returncode, 'result': output})
            retire(identity, name)
        require(CONTRACT.fingerprint(binary) == before_binary and CONTRACT.digest(artifacts) == artifact_sha,
                'BINARY_OR_ARTIFACTS_CHANGED')
        record['binary_and_artifacts_unchanged'] = True
    finally:
        primary = sys.exc_info()[0] is not None
        for identity, name in list(containers.items()):
            try:
                retire(identity, name)
            except Exception as error:
                record['cleanup_errors'].append(type(error).__name__ + ':' + str(error))
        # Docker may finish create even if its local CLI times out before an ID
        # is returned. Recover only the exact random name and owner/image labels.
        for name in attempted_names - retired_names:
            try:
                observed = call('recover-create-identity', ['inspect', name], check=False)
                if observed.returncode == 0:
                    identity = json.loads(observed.stdout)[0]['Id']
                    inspect_owned(identity, name)
                    containers[identity] = name
                    retire(identity, name)
                require(not call('name-absence', ['ps', '-aq', '--filter', 'name=^/' + name + '$']).stdout.strip(),
                        'OWNED_CREATE_RETIREMENT_REQUIRED')
            except Exception as error:
                record['cleanup_errors'].append(type(error).__name__ + ':' + str(error))
        if built:
            try:
                observed = call('image-cleanup-inspect', ['image', 'inspect', tag], check=False)
                if observed.returncode == 0:
                    value = json.loads(observed.stdout)[0]
                    require(value['Config']['Labels'].get('com.sandbox.owner') == owner
                            and value['Config']['Labels'].get('com.sandbox.fixture') == LABEL
                            and (image_id is None or value['Id'] == image_id), 'EXACT_OWNED_IMAGE_CLEANUP_REQUIRED')
                    call('remove-image', ['image', 'rm', value['Id']])
                require(not call('image-absence', ['image', 'ls', '-aq', '--filter', 'label=com.sandbox.owner=' + owner]).stdout.strip(), 'OWNED_IMAGE_ABSENCE_REQUIRED')
            except Exception as error:
                record['cleanup_errors'].append(type(error).__name__ + ':' + str(error))
        try:
            if stage.exists():
                for path in [stage, *(p for p in stage.rglob('*') if p.is_dir())]:
                    path.chmod(0o700)
                shutil.rmtree(stage)
        except Exception as error:
            record['cleanup_errors'].append(type(error).__name__ + ':' + str(error))
        record['containers_removed'] = not containers
        record['context_removed'] = not stage.exists()
        record['source_unchanged'] = CONTRACT.source_fingerprints() == source_before
        record['disk_after'] = subprocess.check_output(['df', '-Pk', str(ROOT)], text=True)
        if not primary:
            require(not record['cleanup_errors'] and record['containers_removed'] and record['context_removed']
                    and record['source_unchanged'], 'OWNED_FIXTURE_CLEANUP_AND_SOURCE_CONTRACT')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    args = parser.parse_args()
    evidence = args.evidence_dir.absolute()
    require('..' not in evidence.parts and not any(p.is_symlink() for p in evidence.parents), 'REAL_EVIDENCE_PATH_REQUIRED')
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    evidence = evidence.resolve()
    record = {'status': 'FAIL', 'scope': 'offline OCI metadata CLI, not native preparation or cloud certification'}
    try:
        run(args, evidence, record)
        record['status'] = 'PASS'
    except Exception as error:
        record['failure'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        (evidence / 'record.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
        (evidence / 'record.json').chmod(0o600)
    print(json.dumps({'status': record['status'], 'evidence': str(evidence), 'failure': record.get('failure')}))
    return 0 if record['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
