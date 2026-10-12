#!/usr/bin/env python3
"""Build local OCI layouts, Linux host binaries and evidence. Never pushes/signs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import uuid
from security_packages import validate_dockerfile, validate_lock
from console_assets import image_files, inventory, stage_context, validate_selection, verify_previous
from console_security import validate_lock as validate_console_lock, validate_dockerfile as validate_console_dockerfile
from common import BINARIES, COMPONENTS, SCAN_NAMES, BOM_CDX, ROOT, dump, image_digest, load, now, require, run, sha, subject, tool
from native import export_dockerfile, record as record_native, validate_runtime
from elf import validate_file


def scanner_environment(**settings):
    # CLI --config does not outrank inherited scanner environment variables.
    # Preserve registry/proxy authentication, never ambient scan filters.
    require(set(settings) <= {'GRYPE_CHECK_FOR_APP_UPDATE', 'GRYPE_DB_CACHE_DIR', 'GRYPE_DB_AUTO_UPDATE'}, 'SCANNER_ENVIRONMENT')
    result = {key: value for key, value in os.environ.items() if not key.startswith(('GRYPE_', 'SYFT_'))}
    result.update(settings)
    return result


def output(command):
    return subprocess.check_output(command, timeout=30).decode().strip()


def build_native_export(buildctl_args, source, destination):
    # Inherit the exact production builder. Its network-disabled acceptance
    # links the production O3 library; inventory copies the actual native inputs.
    with tempfile.TemporaryDirectory(prefix='release-native-dockerfile-') as temporary:
        dockerfiles = Path(temporary)
        (dockerfiles / 'Dockerfile').write_text(export_dockerfile(source, load(ROOT / 'native-security.lock.json')))
        command = buildctl_args + ['--local', 'context=' + str(source), '--local', 'dockerfile=' + str(dockerfiles),
            '--opt', 'target=native-export', '--output', 'type=local,dest=' + str(destination)]
        run(command, timeout=3600)


def create_manifest(directory, repository, tag, commit, run_id, console_assets):
    images = {name: {'digest': image_digest(directory / name, name), 'archive': name + '.oci.tar'} for name in COMPONENTS}
    files = {p.name: {'sha256': sha(p), 'size': p.stat().st_size} for p in directory.iterdir() if p.is_file()}
    manifest = {'version': 2, 'repository': repository, 'tag': tag, 'commit': commit, 'platform': 'linux/amd64',
        'workflow': '.github/workflows/release.yml', 'workflow_identity': subject(repository, tag, commit),
        'run_id': run_id, 'console_assets': console_assets, 'created_at': now().isoformat(), 'images': images, 'binaries': list(BINARIES), 'files': files}
    dump(directory / 'release-manifest.json', manifest)
    definition = {'buildType': 'https://github.com/' + repository + '/.github/workflows/release.yml',
        'externalParameters': {'repository': repository, 'tag': tag, 'commit': commit, 'platform': 'linux/amd64', 'console_assets': console_assets},
        'resolvedDependencies': [{'uri': 'git+https://github.com/' + repository + '@refs/tags/' + tag, 'digest': {'gitCommit': commit}}]}
    predicate = {'buildDefinition': definition, 'runDetails': {'builder': {'id': manifest['workflow_identity']},
        'metadata': {'invocationId': 'https://github.com/' + repository + '/actions/runs/' + run_id,
                     'finishedOn': manifest['created_at']}}}
    dump(directory / 'provenance.json', predicate)


def verify_docker_config(archive_path, config_digest):
    # Image IDs differ between Docker's classic and containerd image stores.
    # Compare the exported config bytes, not daemon-specific .Id semantics.
    with tarfile.open(archive_path, 'r') as archive:
        manifest_entry = archive.getmember('manifest.json')
        require(manifest_entry.isfile() and manifest_entry.size <= 1024 * 1024, 'SMOKE_ARCHIVE_MANIFEST')
        manifest = json.load(archive.extractfile(manifest_entry))
        require(isinstance(manifest, list) and len(manifest) == 1, 'SMOKE_ARCHIVE_IMAGE_COUNT')
        entry = archive.getmember(manifest[0]['Config'])
        require(entry.isfile() and entry.size <= 1024 * 1024, 'SMOKE_ARCHIVE_CONFIG')
        data = archive.extractfile(entry).read()
        require('sha256:' + hashlib.sha256(data).hexdigest() == config_digest, 'SMOKE_IMAGE_CONFIG')


def build_artifact(buildctl_args, context, target, destination, local=False, smoke=None, filename="Dockerfile", buildargs=None):
    require(filename in ('Dockerfile', 'deploy/console/Dockerfile'), 'BUILD_DOCKERFILE_NOT_ALLOWED')
    buildargs = buildargs or {}
    require(not buildargs or filename == 'deploy/console/Dockerfile', 'BUILD_ARGUMENT_SCOPE')
    require(set(buildargs) <= {'SANDBOX_CONSOLE_FIRST_RELEASE'} and all(v in ('true','false') for v in buildargs.values()), 'BUILD_ARGUMENT_NOT_ALLOWED')
    require(filename != 'deploy/console/Dockerfile' or set(buildargs) == {'SANDBOX_CONSOLE_FIRST_RELEASE'}, 'CONSOLE_RELEASE_MODE_REQUIRED')
    command = buildctl_args + ['--local', 'context=' + str(context), '--local', 'dockerfile=' + str(context)]
    command += ['--opt', 'filename=' + filename]
    for key,value in sorted(buildargs.items()): command += ['--opt', 'build-arg:' + key + '=' + value]
    if target:
        command += ['--opt', 'target=' + target]
    command += ['--output', ('type=local,dest=' if local else 'type=oci,tar=false,rewrite-timestamp=true,dest=') + str(destination)]
    if local:
        run(command, timeout=3600)
    else:
        with tempfile.TemporaryDirectory(prefix='release-smoke-') as temporary:
            docker_archive = Path(temporary) / 'image.tar'
            smoke_image = 'sandbox-release-smoke:' + uuid.uuid4().hex
            run(command + ['--output', 'type=docker,name=' + smoke_image + ',rewrite-timestamp=true,dest=' + str(docker_archive)], timeout=3600)
            image_digest(destination, "console" if smoke == "console" else None)
            index = load(destination / 'index.json')
            manifest = load(destination / 'blobs/sha256' / index['manifests'][0]['digest'][7:])
            config_digest = manifest['config']['digest']
            verify_docker_config(docker_archive, config_digest)
            run(['docker', 'load', '--input', docker_archive], stdout=subprocess.DEVNULL)
            loaded_archive = Path(temporary) / 'loaded.tar'
            run(['docker', 'image', 'save', '--output', loaded_archive, smoke_image], timeout=600)
            verify_docker_config(loaded_archive, config_digest)
            smoke_base = ['docker', 'run', '--rm', '--platform', 'linux/amd64', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges']
            if smoke == 'service':
                run([*smoke_base, smoke_image, '--version'])
                for binary in ('sandbox-admin', 'sandbox-admission', 'sandbox-backup-worm', 'sandbox-credentials', 'sandbox-automation'):
                    run([*smoke_base, '--entrypoint', '/usr/local/bin/' + binary, smoke_image, '--help'], stdout=subprocess.DEVNULL)
            elif smoke == 'runner':
                run([*smoke_base, smoke_image, 'health'])
                execution = '00000000-0000-4000-8000-000000000001'
                request = {'execution_id': execution, 'argv': ['/bin/sh', '-c', 'printf runner-release-smoke'], 'env': {}, 'cwd': '/workspace', 'timeout_seconds': 5, 'output_limit_bytes': 1024}
                result = subprocess.run([*smoke_base, '-i', smoke_image, 'exec', '--execution-id', execution, '--dispatch-attempt-id', '00000000-0000-4000-8000-000000000002'], input=json.dumps(request).encode(), capture_output=True, timeout=20, check=True)
                frames = [json.loads(line) for line in result.stdout.splitlines()]
                require(frames[-1]['type'] == 'exited' and frames[-1]['exit_code'] == 0 and frames[-1]['bytes_emitted'] == 20, 'RUNNER_COMMAND_SMOKE')
            elif smoke == 'console':
                image_id = output(['docker', 'image', 'inspect', '--format', '{{.Id}}', smoke_image])
                run(['python3', ROOT.parent.parent / 'deploy/console/check_image.py', '--image', image_id], timeout=120)
            elif smoke == 'proxy':
                run([*smoke_base, smoke_image, '-v'])
            else:
                raise ValueError('UNKNOWN_SMOKE_COMPONENT')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--console-first-release', action='store_true')
    parser.add_argument('--console-previous-tag', default='')
    parser.add_argument('--console-previous-commit', default='')
    parser.add_argument('--console-previous-directory', type=Path)
    args = parser.parse_args()
    validate_selection(args.console_first_release,args.console_previous_tag,args.console_previous_commit,args.tag)
    require((args.console_previous_directory is None) == args.console_first_release, 'PREVIOUS_RELEASE_DIRECTORY_REQUIRED')
    subject(args.repository, args.tag, args.commit)
    require(re.fullmatch(r'[1-9][0-9]{0,30}', args.run_id), 'RUN_ID')
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'LINUX_AMD64_BUILDER_REQUIRED')
    require(os.environ.get('BUILDKIT_HOST', '').startswith('unix://'), 'PRIVATE_BUILDKIT_REQUIRED')
    source = Path.cwd()
    require(output(['git', 'rev-parse', 'HEAD']) == args.commit and output(['git', 'rev-parse', 'refs/tags/' + args.tag + '^{commit}']) == args.commit, 'SOURCE_TAG_COMMIT_MISMATCH')
    require(not output(['git', 'status', '--porcelain', '--untracked-files=normal']), 'DIRTY_SOURCE')
    require(not args.output.exists(), 'FRESH_OUTPUT_REQUIRED')
    directory = args.output.resolve(); directory.mkdir(parents=True)
    validate_dockerfile(validate_lock(load(ROOT / 'debian-security.lock.json')), (source / 'Dockerfile').read_text())
    console_lock = load(source / 'deploy/console/versions.lock.json')
    console_dockerfile = (source / 'deploy/console/Dockerfile').read_text()
    require('FROM '+console_lock['node_image']+' AS build' in console_dockerfile and 'FROM '+console_lock['nginx_image']+'\n' in console_dockerfile, 'CONSOLE_BUILD_IMAGE_DRIFT')
    validate_console_dockerfile(validate_console_lock(load(ROOT / 'console-security.lock.json')), console_dockerfile)
    epoch = output(['git', 'show', '-s', '--format=%ct', args.commit])
    buildctl = tool(args.tools, 'buildctl')
    base = [buildctl, '--addr', os.environ['BUILDKIT_HOST'], 'build', '--frontend=dockerfile.v0', '--opt', 'platform=linux/amd64', '--opt', 'build-arg:SOURCE_DATE_EPOCH=' + epoch]
    chain = {'first_release': args.console_first_release, 'previous': None}
    previous_files = None
    if not args.console_first_release:
        previous = verify_previous(args.console_previous_directory, args.tools, args.repository, args.console_previous_tag, args.console_previous_commit)
        chain['previous'] = {k: previous[k] for k in ('repository','tag','commit','created_at')}
        chain['previous'].update(manifest_sha256=sha(args.console_previous_directory / 'release-manifest.json'), console_digest=previous['images']['console']['digest'])
        from verify import extract_oci
        with tempfile.TemporaryDirectory(prefix='previous-console-oci-') as temporary:
            oci = Path(temporary)
            extract_oci(args.console_previous_directory / 'console.oci.tar', oci, 'console')
            previous_files = image_files(oci)
    with tempfile.TemporaryDirectory(prefix='release-console-source-') as temporary:
        context = Path(temporary) / 'context'
        stage_context(source, context, previous_files)
        build_artifact(base, context, None, directory / 'console', smoke='console', filename='deploy/console/Dockerfile', buildargs={'SANDBOX_CONSOLE_FIRST_RELEASE': str(args.console_first_release).lower()})
    dump(directory / 'console-npm-locks.json', inventory(image_files(directory / 'console')))
    build_artifact(base, source, 'runtime', directory / 'service', smoke='service')
    build_artifact(base, source, 'runner', directory / 'runner', smoke='runner')
    with tempfile.TemporaryDirectory(prefix='release-binaries-') as temporary:
        binary_dir = Path(temporary)
        build_artifact(base, source, 'binaries-export', binary_dir, True)
        linkage = load(ROOT / 'native-security.lock.json')['profile']
        for name in BINARIES:
            validate_file(binary_dir / name, linkage)
            shutil.copy2(binary_dir / name, directory / name)
        shutil.copy2(source / 'Cargo.lock', directory / 'Cargo.lock')
        with tempfile.TemporaryDirectory(prefix='release-native-export-') as native_temporary:
            exported = Path(native_temporary)
            build_native_export(base, source, exported)
            record_native(exported, directory)
        run([directory / 'sandbox-runner', 'health'])
        run([directory / 'sandbox-nodeguard', '--help'], stdout=subprocess.DEVNULL)
        run([directory / 'sandboxd', '--version'])
        run([directory / 'sandbox-admin', '--help'], stdout=subprocess.DEVNULL)
        run([directory / 'sandbox-admission', '--help'], stdout=subprocess.DEVNULL)
        run([directory / 'sandbox-backup-worm', '--help'], stdout=subprocess.DEVNULL)
        run([directory / 'sandbox-credentials', '--help'], stdout=subprocess.DEVNULL)
        run([directory / 'sandbox-automation', '--help'], stdout=subprocess.DEVNULL)
        shutil.copy2(source / 'Cargo.lock', binary_dir / 'Cargo.lock')
        run([tool(args.tools, 'syft'), 'scan', 'dir:' + str(binary_dir), '--select-catalogers', '+rust-cargo-lock-cataloger,+javascript-lock-cataloger', '--config', str(ROOT / 'syft.yaml'), '-o', 'syft-json=' + str(directory / 'rust-binaries.syft.json'), '-o', 'spdx-json=' + str(directory / 'rust-binaries.spdx.json')], env=scanner_environment(), timeout=600)
    identity = load(source / 'deploy/identity/versions.lock.json')
    with tempfile.TemporaryDirectory(prefix='release-proxy-') as temporary:
        temporary = Path(temporary)
        archive = temporary / 'haproxy.tar.gz'
        with urllib.request.urlopen(identity['proxy_source']['url'], timeout=60) as response:
            data = response.read(16 * 1024 * 1024 + 1)
        require(len(data) <= 16 * 1024 * 1024 and hashlib.sha256(data).hexdigest() == identity['proxy_source']['sha256'], 'PROXY_SOURCE_HASH')
        archive.write_bytes(data)
        run(['python3', source / 'deploy/identity/prepare_proxy.py', '--source-archive', archive, '--output', temporary / 'context'])
        build_artifact(base, temporary / 'context', None, directory / 'identity-proxy', smoke='proxy')
    for name in COMPONENTS:
        image_digest(directory / name, name)
        if name in ('service','runner'):
            validate_runtime(directory / name, name, load(directory / 'native-provenance.json'))
        run([tool(args.tools, 'syft'), 'scan', 'oci-dir:' + str(directory / name), '--select-catalogers', '+rust-cargo-lock-cataloger,+javascript-lock-cataloger', '--config', str(ROOT / 'syft.yaml'), '-o', 'syft-json=' + str(directory / (name + '.syft.json')), '-o', 'spdx-json=' + str(directory / (name + '.spdx.json'))], env=scanner_environment(), timeout=600)
        # Only files/directories produced by the local OCI exporter, no symlinks.
        with tarfile.open(directory / (name + '.oci.tar'), 'w') as archive:
            for path in sorted((directory / name).rglob('*')):
                require(not path.is_symlink(), 'OCI_SYMLINK')
                archive.add(path, arcname=str(path.relative_to(directory / name)), recursive=False)
    rust_image = re.search(r'ARG RUST_IMAGE=(\S+)', (source / 'Dockerfile').read_text()).group(1)
    # Also scan the full pinned builder: includes OpenSSL copied into HAProxy,
    # as well as compiler/tool dependencies. This intentionally overapproximates.
    run([tool(args.tools, 'syft'), 'scan', 'registry:' + rust_image, '--platform', 'linux/amd64', '--select-catalogers', '+rust-cargo-lock-cataloger,+javascript-lock-cataloger', '--config', str(ROOT / 'syft.yaml'), '-o', 'syft-json=' + str(directory / 'builder.syft.json'), '-o', 'spdx-json=' + str(directory / 'builder.spdx.json')], env=scanner_environment(), timeout=600)
    run([tool(args.tools, 'syft'), 'scan', 'registry:' + console_lock['node_image'], '--platform', 'linux/amd64', '--select-catalogers', '+javascript-lock-cataloger', '--config', str(ROOT / 'syft.yaml'), '-o', 'syft-json=' + str(directory / 'console-builder.syft.json'), '-o', 'spdx-json=' + str(directory / 'console-builder.spdx.json')], env=scanner_environment(), timeout=600)
    proxy = identity['proxy_source']
    dump(directory / 'proxy-source.cdx.json', {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1, 'components': [
        {'type': 'application', 'name': 'haproxy', 'version': proxy['version'], 'purl': 'pkg:generic/haproxy@' + proxy['version'],
         'cpe': 'cpe:2.3:a:haproxy:haproxy:' + proxy['version'] + ':*:*:*:*:*:*:*', 'externalReferences': [{'type': 'distribution', 'url': proxy['url'], 'hashes': [{'alg': 'SHA-256', 'content': proxy['sha256']}]}]}]})
    shutil.copy2(ROOT / 'debian-security.lock.json', directory / 'debian-security.lock.json')
    shutil.copy2(ROOT / 'console-security.lock.json', directory / 'console-security.lock.json')
    shutil.copy2(ROOT / 'risk-exceptions.json', directory / 'risk-exceptions.json')
    shutil.copy2(ROOT / 'tools.lock.json', directory / 'tools.lock.json')
    grype = tool(args.tools, 'grype')
    env = scanner_environment(GRYPE_CHECK_FOR_APP_UPDATE='false', GRYPE_DB_CACHE_DIR=str(directory / '.grype-db'))
    run([grype, 'db', 'update', '--config', ROOT / 'grype.yaml'], env=env, timeout=600)
    with open(directory / 'database.json', 'xb') as result:
        run([grype, 'db', 'status', '-o', 'json', '--config', ROOT / 'grype.yaml'], env=env, stdout=result)
    env['GRYPE_DB_AUTO_UPDATE'] = 'false'
    for name in SCAN_NAMES:
        sbom = directory / (name + ('.cdx.json' if name in BOM_CDX else '.syft.json'))
        with open(directory / (name + '.grype.json'), 'xb') as result:
            run([grype, 'sbom:' + str(sbom), '--config', ROOT / 'grype.yaml', '-o', 'json'], env=env, stdout=result, timeout=600)
    # A failed gate preserves candidate reports for inspection, never a manifest.
    run(['python3', ROOT / 'gate.py', '--directory', directory])
    create_manifest(directory, args.repository, args.tag, args.commit, args.run_id, chain)


if __name__ == '__main__':
    main()
