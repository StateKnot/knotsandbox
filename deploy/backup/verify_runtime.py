#!/usr/bin/env python3
"""Runs only inside the reviewed image under verify_image's offline restrictions."""
import json
from pathlib import Path
import platform
import subprocess
import sys


def checked(argv):
    return subprocess.run(argv, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240).stdout.decode()


root = Path(__file__).resolve().parent
versions = json.loads((root / 'versions.lock.json').read_text())['versions']
assert platform.system() == 'Linux' and platform.machine() == 'x86_64'
restic = checked(['/usr/local/bin/restic', 'version'])
rclone = checked(['/usr/local/bin/rclone', 'version'])
assert restic.startswith('restic ' + versions['restic'] + ' ')
assert rclone.startswith('rclone v' + versions['rclone'] + '\n')
assert 'linux/amd64' in restic and '- os/type: linux' in rclone and '- os/arch: amd64' in rclone
checked([sys.executable, '-m', 'unittest', 'discover', '-s', str(root/'tests'), '-p', 'test_*.py'])
checked([sys.executable, str(root/'tests/local_restic.py'), '--restic', '/usr/local/bin/restic', '--rclone', '/usr/local/bin/rclone', '--openssl', '/usr/bin/openssl'])
checked([sys.executable, str(root/'tests/rclone_sts.py'), '--rclone', '/usr/local/bin/rclone', '--openssl', '/usr/bin/openssl'])
print(json.dumps({'protocol': 1, 'result': 'PASSED', 'restic': versions['restic'], 'rclone': versions['rclone'],
                  'independent_encrypted_restore': True, 'corruption_rejected': True, 'local_sts_signature_refresh': True,
                  'cloud_verified': False, 'kata_raw_block_verified': False}))
