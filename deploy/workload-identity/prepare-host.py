#!/usr/bin/env python3
"""Freeze/install exact Ubuntu packages for a dedicated publisher image builder.
Run only on an isolated Ubuntu 24.04 build VM; never on a cluster node.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys

PACKAGES = {'nginx', 'python3.12', 'python3.12-venv', 'openssl', 'openssh-server', 'ca-certificates', 'chrony'}


def check(condition, message):
    if not condition:
        raise ValueError(message)


def command(argv):
    return subprocess.check_output(argv, stderr=subprocess.PIPE, timeout=300).decode().strip()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def package_snapshot():
    return hashlib.sha256(command(['dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n']).encode()).hexdigest()


def validate_spec(spec):
    check(set(spec) == {'packages', 'ntp_server_ips'} and set(spec['packages']) == PACKAGES, 'exact package set required')
    check(all(isinstance(v, str) and re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]+', v) for v in spec['packages'].values()), 'explicit exact package versions required')
    check(1 <= len(spec['ntp_server_ips']) <= 4 and all(ipaddress.ip_address(ip).version == 4 for ip in spec['ntp_server_ips']), 'reviewed fixed NTP IPv4 peers required')


def verify_bundle(bundle, expected_hash, base_hash):
    lock = bundle / 'packages.lock.json'
    check(re.fullmatch(r'[a-f0-9]{64}', expected_hash) and sha(lock) == expected_hash, 'package lock hash mismatch')
    manifest = json.loads(lock.read_text())
    check(manifest['version'] == 1 and manifest['base_packages_sha256'] == base_hash, 'different base image package set')
    validate_spec(manifest['spec'])
    check(1 <= len(manifest['debs']) <= 500, 'package count')
    paths = []
    for name, digest in manifest['debs'].items():
        check(re.fullmatch(r'[A-Za-z0-9_+.%:~\-]+\.deb', name), 'package filename')
        path = bundle / name
        check(path.is_file() and not path.is_symlink() and sha(path) == digest, 'package hash mismatch')
        paths.append(str(path))
    return manifest, paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['freeze', 'install'])
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--versions', type=Path)
    parser.add_argument('--lock-sha256')
    args = parser.parse_args()
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    check(release.get('ID', '').strip('"') == 'ubuntu' and release.get('VERSION_ID', '').strip('"') == '24.04' and os.geteuid() == 0, 'isolated Ubuntu 24.04 root build VM required')
    bundle = args.bundle.resolve()
    check(not Path('/etc/kubernetes').exists() and not Path('/srv/workload-identity/current').exists(), 'not a live cluster or publisher')
    baseline = package_snapshot()
    if args.action == 'freeze':
        check(args.versions and not bundle.exists(), 'versions and fresh output directory required')
        spec = json.loads(args.versions.read_text())
        validate_spec(spec)
        bundle.mkdir(mode=0o755)
        cache = bundle / 'cache'
        cache.mkdir()
        (cache / 'partial').mkdir()
        secure = ['-o', 'APT::Get::AllowUnauthenticated=false', '-o', 'Acquire::AllowInsecureRepositories=false', '-o', 'Acquire::AllowDowngradeToInsecureRepositories=false']
        command(['apt-get', *secure, 'update'])
        command(['apt-get', *secure, '-o', 'Dir::Cache::archives=' + str(cache), '--download-only', '--reinstall', '--no-install-recommends', '--yes', 'install', *[p + '=' + v for p, v in sorted(spec['packages'].items())]])
        debs = {}
        for path in sorted(cache.glob('*.deb')):
            path.rename(bundle / path.name)
            debs[path.name] = sha(bundle / path.name)
        check(debs and package_snapshot() == baseline, 'freeze unexpectedly changed base packages')
        manifest = {'version': 1, 'base_packages_sha256': baseline, 'architecture': command(['dpkg', '--print-architecture']), 'spec': spec, 'debs': debs}
        lock = bundle / 'packages.lock.json'
        lock.write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
        print(json.dumps({'lock_sha256': sha(lock), 'packages': len(debs)}))
    else:
        manifest, paths = verify_bundle(bundle, args.lock_sha256 or '', baseline)
        check(command(['dpkg', '--print-architecture']) == manifest['architecture'], 'different CPU architecture')
        policy = Path('/usr/sbin/policy-rc.d')
        check(not policy.exists(), 'existing service-start policy requires separate image review')
        policy.write_text('#!/bin/sh\nexit 101\n')
        policy.chmod(0o755)
        try:
            command(['dpkg', '--unpack', *paths])
            command(['dpkg', '--configure', '--pending'])
        finally:
            policy.unlink()
        for package, version in manifest['spec']['packages'].items():
            check(command(['dpkg-query', '-W', '-f=${Version}', package]) == version, 'installed package version differs')
        Path('/etc/chrony/chrony.conf').write_text('driftfile /var/lib/chrony/chrony.drift\nmakestep 1.0 3\nrtcsync\n' + ''.join('server ' + ip + ' iburst\n' for ip in manifest['spec']['ntp_server_ips']))
        command(['systemctl', 'enable', '--now', 'chrony'])
        command(['systemctl', 'restart', 'chrony'])
        command(['chronyc', 'waitsync', '30', '0.1', '0.0', '1'])
        command(['systemctl', 'disable', '--now', 'nginx'])
        print(json.dumps({'image_packages_installed': True, 'package_lock_sha256': args.lock_sha256}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # apt/repository/subprocess diagnostics can include credential-bearing URLs.
        sys.exit('publisher image preparation failed; inspect the isolated builder securely')
