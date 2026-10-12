#!/usr/bin/env python3
"""Real pinned Restic/rclone local transport; not CSI, Kata or OSS certification."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backup import Repository, environment, run, signature
import inventory

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--restic', required=True, type=Path)
p.add_argument('--rclone', required=True, type=Path)
p.add_argument('--openssl', default='/opt/homebrew/opt/openssl@3/bin/openssl')
a = p.parse_args()
restic, rclone = a.restic.resolve(), a.rclone.resolve()
assert run([str(restic), 'version'], time.time() + 10).startswith(b'restic 0.19.1 ')
assert run([str(rclone), 'version'], time.time() + 10).startswith(b'rclone v1.75.1\n')
with tempfile.TemporaryDirectory(prefix='sandbox-backup-e2e-') as folder:
    root = Path(folder)
    password = root / 'password'
    password.write_text(os.urandom(32).hex())
    password.chmod(0o600)
    source = root / 'source-disk.img'
    # Opaque bytes include invalid filesystem/path data. No archive/file walk or mount occurs.
    data = os.urandom(5 * 1024 * 1024) + b'\0' * (16 * 1024 * 1024) + b'../etc/shadow\0malicious-link\xff' * 8192
    source.write_bytes(data)
    expected, size = hashlib.sha256(data).hexdigest(), len(data)
    del data
    env = environment()
    env['PATH'] = str(rclone.parent) + ':/usr/bin:/bin'
    env['RCLONE_CONFIG'] = '/dev/null'
    # The same mature Restic-rclone stdio adapter used by production; remote is local only in this test.
    mutable = root / 'mutable'
    repo = Repository(restic, 'rclone::local:' + str(mutable), password, time.time() + 180, env)
    snapshot = repo.capture([sys.executable, '-c', 'import sys;sys.stdout.buffer.write(open(sys.argv[1],"rb").read())', str(source)])
    repo.check(snapshot, size, expected)
    vault = root / 'vault'
    run([str(rclone), 'copy', '--immutable', str(mutable), str(vault)], time.time() + 30, env)
    run([str(rclone), 'check', '--download', str(mutable), str(vault)], time.time() + 30, env)
    binding = {k: str(uuid.uuid4()) for k in ('tenant_id', 'backup_id', 'seal_attempt_id', 'cluster_epoch')}
    inventory_dir = root / 'inventory'
    checked = inventory.build(binding, snapshot, ':local:' + str(vault), inventory_dir,
                              time.time() + 180, env, run, rclone=str(rclone))
    inventory.validate(checked)
    assert checked['object_count'] == sum(1 for path in vault.rglob('*') if path.is_file())
    assert checked['total_bytes'] == sum(path.stat().st_size for path in vault.rglob('*') if path.is_file())
    # Remove original and ALL mutable repository data. Restore has only the independent copy+key.
    source.unlink()
    shutil.rmtree(mutable)
    restored = Repository(restic, 'rclone::local:' + str(vault), password, time.time() + 180, env)
    restored.check(snapshot, size, expected)
    output = root / 'new-disk.img'
    with output.open('wb') as file:
        restored.call('--no-lock', 'dump', snapshot, '/disk.img', sink=file.write)
    assert hashlib.sha256(output.read_bytes()).hexdigest() == expected
    assert output.stat().st_size == size
    # Truncation/bad size and missing key cannot be reported as success.
    try:
        restored.digest(snapshot, size - 1)
        raise AssertionError('oversize accepted')
    except (ValueError, OSError):
        pass  # macOS execution sandbox may deny killpg after the oversize was detected.
    wrong = root / 'wrong-password'
    wrong.write_text('different-key-material-that-must-not-decrypt')
    try:
        Repository(restic, restored.repository, wrong, time.time() + 30, env).check(snapshot, size, expected)
        raise AssertionError('wrong key accepted')
    except ValueError:
        pass
    pack = next((vault / 'data').glob('*/*'))
    with pack.open('r+b') as file:
        file.seek(0)
        file.write(b'corrupt!')
    try:
        restored.check(snapshot, size, expected)
        raise AssertionError('corrupt pack accepted')
    except ValueError:
        pass
    private, public = root / 'private.pem', root / 'public.pem'
    run([a.openssl, 'genpkey', '-algorithm', 'ED25519', '-out', str(private)], time.time() + 10)
    private.chmod(0o600)
    run([a.openssl, 'pkey', '-in', str(private), '-pubout', '-out', str(public)], time.time() + 10)
    document, signed = root / 'manifest.json', root / 'manifest.sig'
    document.write_bytes(b'{"backup":"bound"}')
    signature(a.openssl, 'sign', private, document, signed, time.time() + 10)
    signature(a.openssl, 'verify', public, document, signed, time.time() + 10)
    document.write_bytes(b'{"backup":"different-tenant"}')
    try:
        signature(a.openssl, 'verify', public, document, signed, time.time() + 10)
        raise AssertionError('modified signed manifest accepted')
    except ValueError:
        pass
print('PASS real Restic/rclone stdio: source+mutable deletion, independent full restore, wrong key, oversize, corrupted pack, Ed25519 tampering, full encrypted-object inventory; cloud/CSI/Kata certification=false')
