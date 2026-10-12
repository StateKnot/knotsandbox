"""Auditable fixed Debian security packages; this is not a vulnerability waiver."""
import datetime as dt
from email.utils import parsedate_to_datetime
import re
import urllib.parse
from common import now, require, timevalue


def validate_lock(lock, current=None):
    current = current or now()
    require(set(lock) == {'version', 'platform', 'target', 'base_image', 'reviewed_at', 'review_expires_at', 'source', 'packages'}, 'SECURITY_LOCK_FORMAT')
    require(lock['version'] == 1 and lock['platform'] == 'linux/amd64' and lock['target'] == 'runner', 'SECURITY_TARGET')
    require(re.fullmatch(r'debian:trixie-slim@sha256:[0-9a-f]{64}', lock['base_image']), 'SECURITY_BASE')
    start, end = timevalue(lock['reviewed_at']), timevalue(lock['review_expires_at'])
    require(start <= current < end and dt.timedelta(0) < end-start <= dt.timedelta(days=30), 'SECURITY_REVIEW_EXPIRED')
    source = lock['source']
    require(set(source) == {'origin', 'suite', 'inrelease_sha256', 'packages_xz_sha256', 'archive_keyring_version', 'verified_signer', 'release_date', 'release_valid_until'}, 'SECURITY_SOURCE_FORMAT')
    require(source['origin'] == 'https://security.debian.org/debian-security' and source['suite'] == 'trixie-security', 'SECURITY_ORIGIN')
    require(all(re.fullmatch('[0-9a-f]{64}', source[k]) for k in ['inrelease_sha256', 'packages_xz_sha256']) and re.fullmatch('[0-9A-F]{40}', source['verified_signer']), 'SECURITY_PROVENANCE')
    issued, valid_until = parsedate_to_datetime(source['release_date']), parsedate_to_datetime(source['release_valid_until'])
    require(issued.tzinfo is not None and valid_until.tzinfo is not None and issued <= start < end <= valid_until, 'SECURITY_INDEX_EXPIRED')
    require(re.fullmatch('[a-zA-Z0-9.+~:-]+', source['archive_keyring_version']), 'SECURITY_KEYRING_VERSION')
    require(isinstance(lock['packages'], list) and 0 < len(lock['packages']) <= 16, 'SECURITY_PACKAGE_COUNT')
    names = set()
    for p in lock['packages']:
        require(set(p) == {'name', 'version', 'architecture', 'size_bytes', 'sha256', 'url', 'file'}, 'SECURITY_PACKAGE_FORMAT')
        require(re.fullmatch('[a-z0-9][a-z0-9+.-]+', p['name']) and p['name'] not in names, 'SECURITY_PACKAGE_NAME')
        names.add(p['name'])
        require(re.fullmatch('[a-zA-Z0-9.+~:-]+', p['version']) and p['architecture'] == 'amd64', 'SECURITY_PACKAGE_VERSION')
        require(isinstance(p['size_bytes'], int) and 0 < p['size_bytes'] <= 32*1024*1024 and re.fullmatch('[0-9a-f]{64}', p['sha256']), 'SECURITY_PACKAGE_HASH_SIZE')
        uri = urllib.parse.urlsplit(p['url'])
        require(uri.scheme == 'https' and uri.netloc == 'security.debian.org' and not uri.query and not uri.fragment and uri.path.startswith('/debian-security/pool/updates/main/') and '/..' not in uri.path, 'SECURITY_PACKAGE_ORIGIN')
        require(p['file'] == p['name']+'_'+p['version']+'_amd64.deb' and uri.path.endswith('/'+p['file']), 'SECURITY_PACKAGE_FILE')
    return lock


def validate_dockerfile(lock, text):
    require('ARG RUNTIME_IMAGE='+lock['base_image'] in text, 'SECURITY_BASE_DRIFT')
    runner = text.split('FROM ${RUNTIME_IMAGE} AS runner\n', 1)[1].split('\nFROM ', 1)[0]
    expected = {'ADD --checksum=sha256:'+p['sha256']+' '+p['url']+' /tmp/security/'+p['file'] for p in lock['packages']}
    actual = {line for line in runner.splitlines() if line.startswith('ADD ')}
    require(actual == expected, 'SECURITY_DOCKER_DOWNLOAD_DRIFT')
    require('RUN --network=none dpkg -i /tmp/security/*.deb' in runner and 'rm -rf /tmp/security' in runner, 'SECURITY_INSTALL_MISSING')
    for p in lock['packages']:
        require("$(dpkg-query -W -f='${Version}' "+p['name']+")\" = '"+p['version']+"'" in runner, 'SECURITY_INSTALLED_VERSION_UNCHECKED')
