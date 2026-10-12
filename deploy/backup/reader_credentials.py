#!/usr/bin/env python3
"""Dedicated backup-reader OIDC -> short-lived STS file; never prints credentials."""
import argparse
import datetime as dt
import fcntl
import http.client
import os
from pathlib import Path
import re
import signal
import stat
import sys
import threading
import time
import urllib.parse
from backup import atomic, canonical, credentials, decode, read, require, timestamp

TOKEN = '/var/run/backup-reader-oidc/token'
OUTPUT = '/run/backup-reader/private/credentials.json'
SUBJECT = 'system:serviceaccount:sandbox-system:sandbox-backup-controller'


def config(path):
    return validate(decode(read(path)))


def validate(value):
    require(isinstance(value, dict) and set(value) == {'region', 'account_id', 'vault_bucket', 'vault_kms_key_id', 'issuer', 'oidc_provider_arn', 'role_arn'}, 'READER_CONFIG_FIELDS')
    require(re.fullmatch(r'[a-z]{2}-[a-z][a-z0-9-]{1,24}', value['region']), 'READER_REGION')
    require(re.fullmatch(r'\d{16}', value['account_id']), 'READER_ACCOUNT')
    require(re.fullmatch(r'[a-z0-9][a-z0-9-]{1,61}[a-z0-9]', value['vault_bucket']), 'READER_BUCKET')
    require(re.fullmatch(r'[a-zA-Z0-9-]{1,128}', value['vault_kms_key_id']), 'READER_KMS')
    require(re.fullmatch(r'acs:ram::' + value['account_id'] + r':role/[a-z0-9-]+-backup-reader', value['role_arn']), 'READER_ROLE')
    require(re.fullmatch(r'acs:ram::' + value['account_id'] + r':oidc-provider/[A-Za-z0-9._-]+', value['oidc_provider_arn']), 'READER_PROVIDER')
    origin = urllib.parse.urlsplit(value['issuer'])
    require(origin.scheme == 'https' and origin.hostname and not origin.username and not origin.password and not origin.query and not origin.fragment and origin.port in (None, 443), 'READER_ISSUER')
    return value


def policy(c):
    bucket = 'acs:oss:*:*:' + c['vault_bucket']
    return {'Version': '1', 'Statement': [
        {'Effect': 'Allow', 'Action': ['oss:GetObject'], 'Resource': [bucket + '/tenants/*/backups/*/*']},
        {'Effect': 'Allow', 'Action': ['oss:ListObjects'], 'Resource': [bucket],
         'Condition': {'StringLike': {'oss:Prefix': ['tenants/*/backups/*/repository/']}}},
        {'Effect': 'Allow', 'Action': ['kms:Decrypt'], 'Resource': [f'acs:kms:{c["region"]}:{c["account_id"]}:key/{c["vault_kms_key_id"]}']}]}


def refresh(c, token, destination):
    exchange = {**c, 'roles': {'backup-reader': {'arn': c['role_arn'], 'subject': SUBJECT}},
                'deadline': (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()}
    result = credentials(exchange, 'backup-reader', token, policy(c))
    # Format consumed by BackupVaultVerifier; no shell, environment or SDK chain.
    value = {'access_key_id': result['AccessKeyId'], 'access_key_secret': result['SecretAccessKey'],
             'security_token': result['SessionToken'], 'expires_at': result['Expiration']}
    for key, maximum in [('access_key_id', 256), ('access_key_secret', 256), ('security_token', 12288)]:
        require(isinstance(value[key], str) and 0 < len(value[key]) <= maximum and value[key].isascii() and all(33 <= ord(ch) <= 126 for ch in value[key]), 'READER_CREDENTIAL_SHAPE')
    atomic(destination, value)  # mkstemp 0600 + fsync + atomic replacement.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='/run/backup-reader-config/reader.json')
    parser.add_argument('--once', action='store_true', help='Write once; intended only for controlled startup validation.')
    args = parser.parse_args()
    target = Path(OUTPUT)
    target.parent.mkdir(mode=0o700, exist_ok=True)
    info = target.parent.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_mode & 0o777 == 0o700 and info.st_uid == os.geteuid(), 'READER_PRIVATE_DIRECTORY')
    fd = os.open(target.parent / 'refresh.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    locked = False
    completed_once = False
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        locked = True
        c = config(args.config)
        delay = 5
        while not stopped.is_set():
            try:
                refresh(c, TOKEN, target)
                delay = 5
                if args.once:
                    completed_once = True
                    return
                stopped.wait(300)
            except (ValueError, OSError, KeyError, TypeError, http.client.HTTPException):
                target.unlink(missing_ok=True)  # Never continue with stale credentials after a failed refresh.
                print('BACKUP_READER_STS_UNAVAILABLE', file=sys.stderr, flush=True)
                if args.once:
                    raise ValueError('BACKUP_READER_STS_UNAVAILABLE') from None
                stopped.wait(delay)
                delay = min(delay * 2, 60)
    finally:
        if locked and (not args.once or not completed_once):
            target.unlink(missing_ok=True)
        os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, http.client.HTTPException):
        print('BACKUP_READER_FAILED: no usable credentials', file=sys.stderr)
        sys.exit(1)
