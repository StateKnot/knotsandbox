#!/usr/bin/env python3
"""Check real BuildKit filtering and the four OCI notice COPY contracts.

Requires Docker Buildx and Python 3.11+. Uses scratch exports, not Rust builds
or production images. Run from any directory; evidence must be a new directory.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time


STAGES = ('nodeguard-export', 'binaries-export', 'runner', 'runtime')
LICENSES = (
    'README.md', 'adler2-2.0.1-MIT.txt', 'crc32fast-1.5.2-MIT.txt',
    'flate2-1.1.10-MIT.txt', 'miniz_oxide-0.9.1-MIT.txt',
    'simd-adler32-0.3.10-MIT.txt',
)
INPUTS = ('Cargo.lock', 'scripts/release/common.py',
          'scripts/release/oci_payload_notices.py',
          *(f'licenses/oci-payload/{name}' for name in LICENSES))
CANARIES = (
    '.env', '.env.production', '.local/private', '.git/config',
    '.aws/credentials', '.ssh/private', '.docker/config.json',
    '.codex/private', '.agents/private', 'target/private',
    'node_modules/private', '__pycache__/private',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def copy_contracts(dockerfile):
    licenses, notices, stage = {}, {}, None
    for line in dockerfile.splitlines():
        if line.startswith('FROM '):
            stage = line.rsplit(' AS ', 1)[-1]
        elif line.startswith('COPY licenses/oci-payload/ '):
            require(stage not in licenses, 'Duplicate OCI license COPY')
            licenses[stage] = line
        elif line.startswith('COPY --from=builder /opt/sandbox-oci-payload-notices.json '):
            require(stage not in notices, 'Duplicate OCI notice COPY')
            notices[stage] = line
    require(set(licenses) == set(notices) == set(STAGES), 'OCI COPY stage coverage changed')
    result = {}
    for stage in STAGES:
        prefix = ('/licenses' if stage.endswith('-export')
                  else '/usr/share/sandbox-platform/licenses')
        require(shlex.split(licenses[stage])[-1] == prefix + '/oci-payload/'
                and shlex.split(notices[stage])[-1] == prefix + '/oci-payload-notices.json',
                f'OCI COPY destination changed: {stage}')
        result[stage] = (licenses[stage], notices[stage], prefix.lstrip('/'))
    return result


def verify(source, evidence, receipt):
    paths = ('.dockerignore', 'Dockerfile', *INPUTS)
    require(all((source / path).is_file() and not (source / path).is_symlink()
                for path in paths), 'Required source input missing or linked')
    original = {path: digest(source / path) for path in paths}
    receipt['source_sha256'] = original
    contracts = copy_contracts((source / 'Dockerfile').read_text())

    def build(name, context, dockerfile, destination, extra=()):
        command = ['docker', 'buildx', 'build', '--network=none', '--progress=plain',
                   '--file', '-', '--output', f'type=local,dest={destination}',
                   *extra, str(context)]
        log_path = evidence / (name + '.log')
        started = time.monotonic()
        record = {'name': name, 'command': command, 'dockerfile': dockerfile, 'exit': None}
        receipt['builds'].append(record)
        try:
            receipt['phase'] = 'df-before-' + name
            record['df_before'] = subprocess.check_output(
                ['df', '-k', str(source)], text=True, timeout=5)
            receipt['phase'] = name
            with log_path.open('w') as log:
                completed = subprocess.run(command, input=dockerfile, text=True,
                                           stdout=log, stderr=subprocess.STDOUT, timeout=60)
            record['exit'] = completed.returncode
        finally:
            record['seconds'] = time.monotonic() - started
        if completed.returncode:
            print('\n'.join(log_path.read_text().splitlines()[-20:]), file=sys.stderr)
        require(completed.returncode == 0, f'BuildKit failed: {log_path}')

    # The control proves the probe subtree was allowed. Only our randomly named
    # subtree is modified; real private/generated directories are never touched.
    with tempfile.TemporaryDirectory(prefix='docker-license-context-', dir=source / 'src') as raw_probe:
        probe = Path(raw_probe)
        receipt['canary_subtree'] = str(probe)
        (probe / 'control.txt').write_text('public Docker context control\n')
        for name in CANARIES:
            path = probe / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('synthetic private/generated canary\n')
        with tempfile.TemporaryDirectory(prefix='sandbox-docker-license-context-') as raw_work:
            work = Path(raw_work)
            filtered = work / 'filtered'
            # stdin prevents a Dockerfile-specific ignore file from replacing
            # the production root .dockerignore under test.
            build('filtered-context', source, 'FROM scratch\nCOPY . /\n', filtered)
            receipt['phase'] = 'filtered-inputs-and-canaries'
            relative_probe = probe.relative_to(source)
            require((filtered / relative_probe / 'control.txt').read_bytes()
                    == (probe / 'control.txt').read_bytes(), 'Context control missing')
            receipt['canary_control_verified'] = True
            receipt['leaked_canaries'] = [path for path in CANARIES
                                         if (filtered / relative_probe / path).exists()]
            require(not receipt['leaked_canaries'],
                    'Private/generated canary entered Docker context')
            receipt['excluded_canaries'] = list(CANARIES)
            missing = [path for path in INPUTS if not (filtered / path).is_file()]
            receipt['missing_filtered_inputs'] = missing
            require(not missing, 'Filtered producer/license inputs missing: ' + ', '.join(missing))
            require(all(digest(filtered / path) == original[path] for path in INPUTS),
                    'Filtered input bytes changed')
            require(digest(filtered / '.dockerignore') == original['.dockerignore'],
                    'Filtered Dockerignore bytes changed')
            receipt['filtered_input_sha256'] = {path: digest(filtered / path) for path in INPUTS}

            builder = work / 'builder'
            notice = builder / 'opt/sandbox-oci-payload-notices.json'
            notice.parent.mkdir(parents=True)
            environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
            receipt['phase'] = 'filtered-producer'
            with (evidence / 'producer.log').open('w') as log:
                produced = subprocess.run(
                    [sys.executable, str(filtered / 'scripts/release/oci_payload_notices.py'),
                     '--source', str(filtered), '--output', str(notice)],
                    env=environment, stdout=log, stderr=subprocess.STDOUT, timeout=15)
            if produced.returncode:
                print('\n'.join((evidence / 'producer.log').read_text().splitlines()[-20:]),
                      file=sys.stderr)
            require(produced.returncode == 0, f'Filtered producer failed: {evidence / "producer.log"}')

            # Validate with the exported producer and exported common.py, never
            # import either helper or supplement any input from the checkout.
            sys.path.insert(0, str(filtered / 'scripts/release'))
            try:
                receipt['phase'] = 'filtered-notice-validation'
                spec = importlib.util.spec_from_file_location(
                    'filtered_oci_payload_notices', filtered / 'scripts/release/oci_payload_notices.py')
                notices = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(notices)
                require(Path(sys.modules['common'].__file__).resolve()
                        == (filtered / 'scripts/release/common.py').resolve(),
                        'Producer imported an ambient helper')
                value = notices.validate(json.loads(notice.read_text()), notices.read_cargo_lock(filtered))
                receipt['notice_sha256'] = digest(notice)
                for stage, (license_copy, notice_copy, prefix) in contracts.items():
                    destination = work / stage
                    build(stage, filtered, 'FROM scratch\n' + license_copy + '\n' + notice_copy + '\n',
                          destination, ('--build-context', f'builder={builder}'))
                    receipt['phase'] = 'validate-copy-' + stage
                    files = {str(path.relative_to(destination)): path.read_bytes()
                             for path in destination.rglob('*') if path.is_file()}
                    notices.validate_distribution(files, prefix, value)
                    require(len(files) == 7, f'Unexpected exported file coverage: {stage}')
                    require(all(files[prefix + '/oci-payload/' + name]
                                == (filtered / 'licenses/oci-payload' / name).read_bytes()
                                for name in LICENSES), f'License text changed: {stage}')
                    require(files[prefix + '/oci-payload-notices.json'] == notice.read_bytes(),
                            f'Notice bytes changed: {stage}')
                    receipt['copies'][stage] = {
                        'instructions': [license_copy, notice_copy],
                        'files_sha256': {name: hashlib.sha256(data).hexdigest()
                                         for name, data in sorted(files.items())},
                    }
            finally:
                sys.path.pop(0)
    receipt['phase'] = 'source-guard'
    require(all(digest(source / path) == expected for path, expected in original.items()),
            'Source inputs changed during validation')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--evidence-dir', type=Path, required=True)
    args = parser.parse_args()
    require(sys.version_info >= (3, 11), 'Python 3.11+ is required by the existing notice producer')
    source, evidence = args.source.resolve(), args.evidence_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    receipt = {'status': 'FAIL', 'source': str(source), 'builds': [], 'copies': {},
               'scope': 'real production Dockerignore and four scratch COPY contracts; not a production image build'}
    try:
        verify(source, evidence, receipt)
        receipt['status'] = 'PASS'
        receipt['phase'] = 'complete'
    except Exception as error:
        receipt['error'] = str(error)
    finally:
        probe = receipt.get('canary_subtree')
        receipt['canary_subtree_cleaned'] = probe is None or not Path(probe).exists()
        if 'source_sha256' in receipt:
            receipt['source_hashes_unchanged'] = all(
                (source / path).is_file() and digest(source / path) == expected
                for path, expected in receipt['source_sha256'].items())
            if not receipt['source_hashes_unchanged']:
                receipt.update(status='FAIL', error='Source inputs changed during validation')
        (evidence / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'status': receipt['status'], 'receipt': str(evidence / 'receipt.json'),
                      'error': receipt.get('error')}))
    return 0 if receipt['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
