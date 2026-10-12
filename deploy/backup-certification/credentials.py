#!/usr/bin/env python3
"""One-shot dedicated OIDC -> STS for read-only bucket certification; no stdout secrets."""
import argparse
import datetime as dt
import http.client
import os
from pathlib import Path
import re
import stat
import sys
import urllib.parse
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backup'))
from backup import atomic, credentials, decode, require  # existing bounded official STS exchange

SUBJECT = 'system:serviceaccount:sandbox-system:sandbox-backup-certifier'


def bounded(path, maximum=16384):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, 'CONFIG_FILE')
        value = os.read(fd, maximum + 1)
        require(len(value) <= maximum, 'CONFIG_SIZE')
        return decode(value)
    finally:
        os.close(fd)


def validate(c):
    require(isinstance(c, dict) and set(c) == {'account_id', 'region', 'bucket', 'cluster_epoch', 'profile_id', 'anchor_key', 'issuer', 'oidc_provider_arn', 'role_arn'}, 'CONFIG_FIELDS')
    require(re.fullmatch(r'\d{16}', c['account_id']), 'ACCOUNT')
    require(re.fullmatch(r'cn-[a-z0-9-]{1,28}', c['region']), 'REGION')
    require(re.fullmatch(r'[a-z0-9][a-z0-9-]{1,61}[a-z0-9]', c['bucket']), 'BUCKET')
    for key in ('cluster_epoch', 'profile_id'):
        value = uuid.UUID(c[key])
        require(value.int != 0 and str(value) == c[key], 'IDENTITY')
    prefix = 'certification/' + c['cluster_epoch'] + '/' + c['profile_id'] + '/'
    require(c['anchor_key'].startswith(prefix) and re.fullmatch(r'[A-Za-z0-9._-]{1,128}', c['anchor_key'][len(prefix):]) and '..' not in c['anchor_key'], 'ANCHOR')
    require(re.fullmatch('acs:ram::' + c['account_id'] + r':role/[a-z0-9-]+-backup-certifier', c['role_arn']), 'ROLE')
    require(re.fullmatch('acs:ram::' + c['account_id'] + r':oidc-provider/[A-Za-z0-9._-]+', c['oidc_provider_arn']), 'PROVIDER')
    origin = urllib.parse.urlsplit(c['issuer'])
    require(origin.scheme == 'https' and origin.hostname and origin.port in (None, 443) and not origin.username and not origin.password and not origin.query and not origin.fragment, 'ISSUER')
    return c


def policy(c):
    resource = 'acs:oss:*:*:' + c['bucket']
    return {'Version': '1', 'Statement': [
        {'Effect': 'Allow', 'Action': ['oss:GetBucketInfo', 'oss:GetBucketWorm', 'oss:GetBucketVersioning'], 'Resource': [resource]},
        {'Effect': 'Allow', 'Action': ['oss:GetObject'], 'Resource': [resource + '/' + c['anchor_key']]}]}


def trust(c):
    return {'Version': '1', 'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRoleWithOIDC',
        'Principal': {'Federated': [c['oidc_provider_arn']]}, 'Condition': {'StringEquals': {
            'oidc:iss': c['issuer'], 'oidc:aud': 'sts.aliyuncs.com', 'oidc:sub': SUBJECT}}}]}


def refresh(c, token_path, output):
    target = Path(output)
    parent = target.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_mode & 0o777 == 0o700 and parent.st_uid == os.geteuid(), 'PRIVATE_DIRECTORY')
    fd = None
    try:
        fd = os.open(token_path, os.O_RDONLY | os.O_NONBLOCK)
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 32768, 'PROJECTED_TOKEN_FILE')
        # Re-open the already checked descriptor, preserving atomic projected token
        # symlinks without racing a different path or copying a token to disk.
        descriptor = ('/proc/self/fd/' if sys.platform == 'linux' else '/dev/fd/') + str(fd)
        c = {**c, 'roles': {'backup-certifier': {'arn': c['role_arn'], 'subject': SUBJECT}},
             'deadline': (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()}
        result = credentials(c, 'backup-certifier', descriptor, policy(c))
        value = {'access_key_id': result['AccessKeyId'], 'access_key_secret': result['SecretAccessKey'],
                 'security_token': result['SessionToken'], 'expires_at': result['Expiration']}
        for key, limit in [('access_key_id', 256), ('access_key_secret', 256), ('security_token', 12288)]:
            require(isinstance(value[key], str) and 0 < len(value[key]) <= limit and all(33 <= ord(ch) <= 126 for ch in value[key]), 'STS_SHAPE')
        atomic(target, value)
    except Exception:
        target.unlink(missing_ok=True)  # Failed refresh must not retain previous credentials.
        raise
    finally:
        if fd is not None:
            os.close(fd)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', required=True)
    sub = p.add_subparsers(dest='command', required=True)
    render = sub.add_parser('policy', help='Emit public RAM policy/trust for review; never applies it')
    render.add_argument('--kind', choices=['permission', 'trust'], required=True)
    run = sub.add_parser('refresh')
    run.add_argument('--token-file', required=True)
    run.add_argument('--output', required=True)
    a = p.parse_args()
    c = validate(bounded(a.config))
    if a.command == 'policy':
        import json
        print(json.dumps(policy(c) if a.kind == 'permission' else trust(c), indent=2))
    else:
        refresh(c, a.token_file, a.output)
        print('BACKUP_CERTIFIER_STS_READY; short-lived private file written')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError, http.client.HTTPException):
        print('BACKUP_CERTIFIER_FAILED; no usable certification credentials', file=sys.stderr)
        sys.exit(1)
