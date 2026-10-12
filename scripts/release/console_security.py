"""Fixed, signed Alpine updates for the minimal console runtime; no CVE waiver."""
import datetime as dt
import re
from common import now, require, timevalue


def validate_lock(lock, current=None):
    current = current or now()
    require(set(lock) == {'version', 'target', 'base_image', 'reviewed_at', 'review_expires_at', 'packages'}, 'CONSOLE_SECURITY_LOCK_FORMAT')
    require(lock['version'] == 1 and lock['target'] == 'console', 'CONSOLE_SECURITY_TARGET')
    require(re.fullmatch(r'nginxinc/nginx-unprivileged:[0-9]+\.[0-9]+\.[0-9]+-alpine-slim@sha256:[0-9a-f]{64}', lock['base_image']), 'CONSOLE_SECURITY_BASE')
    start, end = timevalue(lock['reviewed_at']), timevalue(lock['review_expires_at'])
    require(start <= current < end and dt.timedelta(0) < end - start <= dt.timedelta(days=30), 'CONSOLE_SECURITY_REVIEW_EXPIRED')
    require(isinstance(lock['packages'], list) and len(lock['packages']) == 2, 'CONSOLE_SECURITY_PACKAGE_COUNT')
    architectures = set()
    for package in lock['packages']:
        require(set(package) == {'name', 'version', 'architecture', 'size_bytes', 'sha256', 'url', 'file', 'signature_key'}, 'CONSOLE_SECURITY_PACKAGE_FORMAT')
        arch = package['architecture']
        require(arch in {'x86_64', 'aarch64'} and arch not in architectures, 'CONSOLE_SECURITY_ARCHITECTURE')
        architectures.add(arch)
        require(package['name'] == 'zlib' and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+-r[0-9]+', package['version']), 'CONSOLE_SECURITY_PACKAGE_VERSION')
        require(type(package['size_bytes']) is int and 0 < package['size_bytes'] <= 1024 * 1024 and re.fullmatch('[0-9a-f]{64}', package['sha256']), 'CONSOLE_SECURITY_PACKAGE_HASH_SIZE')
        filename = package['name'] + '-' + package['version'] + '.apk'
        require(package['url'] == 'https://dl-cdn.alpinelinux.org/alpine/v3.24/main/' + arch + '/' + filename and package['file'] == arch + '-' + filename, 'CONSOLE_SECURITY_PACKAGE_ORIGIN')
        require(re.fullmatch(r'alpine-devel@lists\.alpinelinux\.org-[0-9a-f]{8}\.rsa\.pub', package['signature_key']), 'CONSOLE_SECURITY_SIGNATURE_KEY')
    require(len({p['version'] for p in lock['packages']}) == 1, 'CONSOLE_SECURITY_VERSION_DRIFT')
    return lock


def validate_dockerfile(lock, text):
    require('\nFROM ' + lock['base_image'] + '\n' in text, 'CONSOLE_SECURITY_BASE_DRIFT')
    runtime = text.split('\nFROM ' + lock['base_image'] + '\n', 1)[1]
    expected = {'ADD --checksum=sha256:' + p['sha256'] + ' ' + p['url'] + ' /tmp/security/' + p['file'] for p in lock['packages']}
    require({line for line in runtime.splitlines() if line.startswith('ADD ')} == expected, 'CONSOLE_SECURITY_DOWNLOAD_DRIFT')
    require('ARG TARGETARCH\nUSER 0:0\nRUN --network=none ' in runtime and 'apk add --no-network --repositories-file /dev/null "/tmp/security/${apk_arch}-zlib-' in runtime, 'CONSOLE_SECURITY_OFFLINE_INSTALL_MISSING')
    require('amd64) apk_arch=x86_64; test -f ' in runtime and 'arm64) apk_arch=aarch64; test -f ' in runtime and '*) exit 1 ;; esac' in runtime, 'CONSOLE_SECURITY_ARCH_MAPPING')
    require('--allow-untrusted' not in runtime and 'rm -rf /tmp/security' in runtime and '\nUSER 101:101\n' in runtime, 'CONSOLE_SECURITY_INSTALL_POLICY')
    for p in lock['packages']:
        require('test -f "/etc/apk/keys/' + p['signature_key'] + '"' in runtime, 'CONSOLE_SECURITY_SIGNATURE_KEY_MISSING')
        require('test "$(apk --no-network --repositories-file /dev/null info -v | sed -n \'/^zlib-[0-9]/p\')" = "zlib-' + p['version'] + '"' in runtime, 'CONSOLE_SECURITY_INSTALLED_VERSION_UNCHECKED')


def validate_inventory(lock, artifacts):
    expected = next(p for p in lock['packages'] if p['architecture'] == 'x86_64')
    actual = {(p.get('name'), p.get('version')) for p in artifacts if p.get('type') == 'apk'}
    require((expected['name'], expected['version']) in actual, 'CONSOLE_SECURITY_UPDATE_MISSING_FROM_SBOM')
