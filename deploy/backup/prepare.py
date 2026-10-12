#!/usr/bin/env python3
"""Verify official archives and produce an offline linux/amd64 build context."""
import argparse
import bz2
import hashlib
import json
from pathlib import Path
import shutil
import zipfile

ROOT = Path(__file__).resolve().parent
lock = json.loads((ROOT / 'versions.lock.json').read_text())
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--artifacts', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
for name, binary in [('restic_0.19.1_linux_amd64.bz2', 'restic'), ('rclone-v1.75.1-linux-amd64.zip', 'rclone')]:
    raw = (a.artifacts / name).read_bytes()
    if hashlib.sha256(raw).hexdigest() != lock['artifacts'][name]['sha256']:
        raise SystemExit('ARCHIVE_SHA256_MISMATCH')
    if binary == 'restic':
        data = bz2.decompress(raw)
    else:
        with zipfile.ZipFile(a.artifacts / name) as archive:
            data = archive.read('rclone-v1.75.1-linux-amd64/rclone')
    if data[:6] != b'\x7fELF\x02\x01' or data[18:20] != b'\x3e\x00':
        raise SystemExit('EXPECTED_LINUX_AMD64_ELF')
    (a.output / binary).write_bytes(data)
    (a.output / binary).chmod(0o555)
for name in ('Dockerfile', 'backup.py', 'inventory.py', 'reader_credentials.py'):
    shutil.copyfile(ROOT / name, a.output / name)
shutil.copytree(ROOT / 'licenses', a.output / 'licenses')
print('Verified linux/amd64 build context; build --network=none, test, sign and publish a reviewed image digest.')
