#!/usr/bin/env python3
"""Verify the actual backup image offline; this report is not a cloud/Kata certificate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

from backup import canonical, decode, require, run

ROOT = Path(__file__).resolve().parent


def image_identity(image, inspected):
    require(re.fullmatch(r'(?:[A-Za-z0-9._:/-]+@)?sha256:[0-9a-f]{64}', image), 'IMAGE_DIGEST_REQUIRED')
    require(isinstance(inspected, list) and len(inspected) == 1, 'IMAGE_INSPECT')
    obj = inspected[0]
    require(obj.get('Os') == 'linux' and obj.get('Architecture') == 'amd64', 'IMAGE_PLATFORM')
    cfg = obj.get('Config', {})
    require(cfg.get('Entrypoint') == ['/usr/local/bin/python3', '/app/backup.py'] and cfg.get('User') == '0:0', 'IMAGE_ENTRYPOINT')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', obj.get('Id', '')), 'DOCKER_IMAGE_ID')
    if '@' in image:
        require(image in obj.get('RepoDigests', []), 'REGISTRY_DIGEST_NOT_PRESENT')
    else:
        require(obj['Id'] == image, 'LOCAL_IMAGE_ID_CHANGED')
    require(obj.get('RootFS', {}).get('Layers'), 'IMAGE_LAYERS')
    return obj['Id']


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image', required=True)
    p.add_argument('--report', type=Path, required=True)
    a = p.parse_args()
    require(not a.report.exists(), 'REPORT_MUST_BE_NEW')
    env = {'PATH': os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}
    for key in ('DOCKER_HOST', 'DOCKER_CONFIG'):
        if key in os.environ:
            env[key] = os.environ[key]
    try:
        inspected = decode(run(['docker', 'image', 'inspect', a.image], time.time() + 60, env, maximum=1024*1024))
    except ValueError as error:
        raise ValueError('IMAGE_INSPECT_' + str(error)) from None
    identifier = image_identity(a.image, inspected)
    container = 'sbx-backup-verify-' + uuid.uuid4().hex
    command = ['docker', 'run', '--detach', '--name', container, '--platform', 'linux/amd64', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
               '--security-opt', 'no-new-privileges', '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m',
               '--mount', f'type=bind,source={ROOT},target=/verify,readonly',
               '--entrypoint', '/usr/local/bin/python3', a.image, '/verify/verify_runtime.py']
    # Docker Desktop may emulate amd64. This is a bounded offline acceptance
    # budget, independent of the production Job deadline and cloud STS expiry.
    try:
        # Detach then wait avoids keeping Docker's multiplexed attach stream open;
        # cleanup is tied to this exact generated name even if the client times out.
        identifier_reply = run(command, time.time() + 60, env, maximum=1024).strip()
        require(re.fullmatch(rb'[0-9a-f]{64}', identifier_reply), 'EXACT_TEST_CONTAINER_REQUIRED')
        exit_code = run(['docker', 'wait', container], time.time() + 600, env, maximum=1024).strip()
        require(exit_code == b'0', 'OFFLINE_CONTAINER_FAILED')
        result = decode(run(['docker', 'logs', container], time.time() + 30, env, maximum=64*1024))
    except ValueError as error:
        raise ValueError('OFFLINE_RUNTIME_' + str(error)) from None
    finally:
        run(['docker', 'rm', '--force', container], time.time() + 30, env, maximum=1024)
    require(result.get('protocol') == 1 and result.get('result') == 'PASSED', 'IMAGE_RUNTIME_VERIFICATION_FAILED')
    report = {'protocol': 1, 'image': a.image, 'docker_image_id': identifier, 'platform': 'linux/amd64',
              'versions_lock_sha256': hashlib.sha256((ROOT/'versions.lock.json').read_bytes()).hexdigest(),
              'checks': result, 'registry_distribution_verified': '@' in a.image,
              'cloud_verified': False, 'kata_raw_block_verified': False, 'signature_status': 'UNSIGNED'}
    fd = os.open(a.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(canonical(report) + b'\n')
    print('Actual linux/amd64 image and encrypted independent restore verified; cloud/Kata certification remains required.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError) as error:
        # This verifier accepts only a local/public image identity and report path.
        # Child stderr remains discarded, including dummy credential test output.
        print('BACKUP_IMAGE_VERIFICATION_FAILED: ' + str(error), file=sys.stderr)
        sys.exit(1)
