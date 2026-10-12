#!/usr/bin/env python3
"""Bounded raw-device Restic jobs. No filesystem mount, shell, or cloud credential fallback."""
import argparse
import datetime as dt
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid
import inventory

HERE = Path(__file__).resolve().parent
CHUNK = 1024 * 1024
MAX_METADATA = 1024 * 1024
DEVICE = '/dev/sandbox-data'
PREFIX = 'tenants/{tenant_id}/backups/{backup_id}/repository'


def require(condition, code):
    if not condition:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False, 'INVALID_JSON_NUMBER'))


def read(path, maximum=MAX_METADATA, secret=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, 'FILE_SHAPE')
        if secret:
            require(info.st_mode & 0o077 == 0, 'SECRET_FILE_MODE')
        result = os.read(fd, maximum + 1)
        require(len(result) <= maximum, 'FILE_LIMIT')
        return result
    finally:
        os.close(fd)


def atomic(path, value):
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as file:
            file.write(canonical(value))
            file.flush()
            os.fsync(file.fileno())
        os.replace(name, path)
        parent = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def timestamp(value):
    result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(result.tzinfo is not None, 'TIMESTAMP_ZONE')
    return result.timestamp()


def sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def uuid_text(value):
    return isinstance(value, str) and str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0


def config(path):
    value = decode(read(path))
    required = {'protocol', 'tenant_id', 'project_id', 'backup_id', 'source_instance_id',
                'source_generation', 'source_pvc_uid', 'snapshot_content_uid', 'clone_pvc_uid', 'seal_attempt_id', 'cluster_epoch',
                'size_bytes', 'data_timestamp', 'consistency', 'retention_until', 'key_ref',
                'region', 'account_id', 'bucket', 'vault_bucket', 'kms_key_id', 'vault_kms_key_id',
                'issuer', 'oidc_provider_arn', 'roles', 'deadline', 'template_digest',
                'runtime_certification_sha256'}
    require(isinstance(value, dict) and set(value) == required and type(value['protocol']) is int and value['protocol'] == 1, 'CONFIG_FIELDS')
    for key in ('tenant_id', 'project_id', 'backup_id', 'source_instance_id', 'source_pvc_uid', 'snapshot_content_uid', 'clone_pvc_uid', 'seal_attempt_id', 'cluster_epoch'):
        require(uuid_text(value[key]), 'CONFIG_UUID')
    require(type(value['source_generation']) is int and value['source_generation'] > 0, 'GENERATION')
    require(type(value['size_bytes']) is int and 0 < value['size_bytes'] <= 16 * 1024**4 and value['size_bytes'] % 512 == 0, 'VOLUME_SIZE')
    require(value['consistency'] in ('CRASH_CONSISTENT', 'STOPPED_CONSISTENT'), 'CONSISTENCY')
    require(re.fullmatch(r'[a-z]{2}-[a-z][a-z0-9-]{1,24}', value['region']), 'REGION')
    require(re.fullmatch(r'\d{16}', value['account_id']), 'ACCOUNT')
    for key in ('bucket', 'vault_bucket'):
        require(re.fullmatch(r'[a-z0-9][a-z0-9-]{1,61}[a-z0-9]', value[key]), 'BUCKET')
    require(value['bucket'] != value['vault_bucket'], 'INDEPENDENT_VAULT')
    for key in ('kms_key_id', 'vault_kms_key_id', 'key_ref'):
        require(isinstance(value[key], str) and re.fullmatch(r'[a-zA-Z0-9/_:-]{1,256}', value[key]), 'KEY_REFERENCE')
    require(value['kms_key_id'] != value['vault_kms_key_id'], 'INDEPENDENT_KMS')
    require(sha(value['runtime_certification_sha256']) and re.fullmatch(r'sha256:[0-9a-f]{64}', value['template_digest']), 'CERTIFICATION_OR_TEMPLATE')
    origin = urllib.parse.urlsplit(value['issuer'])
    require(origin.scheme == 'https' and origin.hostname and not origin.username and not origin.query and not origin.fragment, 'ISSUER')
    require(re.fullmatch(r'acs:ram::' + value['account_id'] + r':oidc-provider/[A-Za-z0-9._-]+', value['oidc_provider_arn']), 'PROVIDER')
    require(set(value['roles']) == {'backup', 'backup-export', 'restore'}, 'ROLE_FIELDS')
    for key, role in value['roles'].items():
        require(set(role) == {'arn', 'subject'} and re.fullmatch(r'acs:ram::' + value['account_id'] + r':role/[a-z0-9-]+', role['arn']), 'ROLE_ARN')
        require(role['subject'] == 'system:serviceaccount:sandbox-system:sandbox-' + key, 'ROLE_SUBJECT')
    require(timestamp(value['data_timestamp']) <= time.time(), 'DATA_TIME')
    require(timestamp(value['retention_until']) >= timestamp(value['data_timestamp']) + 30 * 86400, 'RETENTION_MINIMUM')
    require(time.time() < timestamp(value['deadline']) <= time.time() + 7200, 'DEADLINE')
    return value


def environment():
    # No inherited AWS/RCLONE credentials, proxies, shared config, debug flags, or password variables.
    return {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/run/backup',
            'LANG': 'C.UTF-8', 'AWS_EC2_METADATA_DISABLED': 'true',
            'AWS_CONFIG_FILE': '/dev/null', 'PYTHONDONTWRITEBYTECODE': '1',
            'SSL_CERT_FILE': '/etc/ssl/certs/ca-certificates.crt'}


def run(argv, deadline, env=None, sink=None, maximum=MAX_METADATA):
    """Bound output and total wall time; discard potentially credential-bearing stderr."""
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, env=env or environment(), start_new_session=True)
    output = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.time()
                require(remaining > 0, 'COMMAND_DEADLINE')
                for key, _ in selector.select(min(remaining, 1)):
                    part = os.read(key.fd, CHUNK)
                    if not part:
                        selector.unregister(key.fd)
                    elif sink:
                        sink(part)
                    else:
                        require(len(output) + len(part) <= maximum, 'COMMAND_OUTPUT_LIMIT')
                        output.extend(part)
        require(proc.wait(timeout=max(0.01, deadline - time.time())) == 0, 'COMMAND_FAILED')
        return bytes(output)
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # D-state I/O cannot be proven stopped by a userspace timeout. Controller must fence the VM.
                raise ValueError('TERMINATION_UNKNOWN') from None
        proc.stdout.close()


def device_open(size, write=False):
    fd = os.open(DEVICE, (os.O_RDWR if write else os.O_RDONLY) | os.O_NOFOLLOW)
    try:
        require(stat.S_ISBLK(os.fstat(fd).st_mode), 'RAW_BLOCK_REQUIRED')
        actual = struct.unpack('Q', fcntl.ioctl(fd, 0x80081272, bytes(8)))[0]  # Linux BLKGETSIZE64
        require(actual == size, 'EXACT_DEVICE_SIZE')
        return fd
    except BaseException:
        os.close(fd)
        raise


def stream_device(size, receipt):
    fd = device_open(size)
    digest = hashlib.sha256()
    total = 0
    try:
        while total < size:
            block = os.read(fd, min(CHUNK, size - total))
            require(block, 'SHORT_DEVICE_READ')
            sys.stdout.buffer.write(block)
            digest.update(block)
            total += len(block)
        sys.stdout.buffer.flush()
        atomic(receipt, {'size_bytes': total, 'sha256': digest.hexdigest()})
    finally:
        os.close(fd)


def session_policy(c, role):
    root = PREFIX.format(**c).removesuffix('/repository')
    targets = {'backup': [(c['bucket'], True)], 'backup-export': [(c['bucket'], False), (c['vault_bucket'], True)], 'restore': [(c['vault_bucket'], False)]}[role]
    statements = []
    for bucket, write in targets:
        actions = ['oss:GetObject']
        if write:
            actions += ['oss:PutObject', 'oss:AbortMultipartUpload', 'oss:ListParts']
        if role == 'backup':
            actions += ['oss:DeleteObject']
        statements += [{'Effect': 'Allow', 'Action': actions, 'Resource': [f'acs:oss:*:*:{bucket}/{root}/*']},
                       {'Effect': 'Allow', 'Action': ['oss:ListObjects'], 'Resource': [f'acs:oss:*:*:{bucket}'],
                        'Condition': {'StringLike': {'oss:Prefix': [root, root + '/*']}}}]
        key = c['kms_key_id'] if bucket == c['bucket'] else c['vault_kms_key_id']
        statements.append({'Effect': 'Allow', 'Action': ['kms:Decrypt'] + (['kms:GenerateDataKey'] if write else []),
                           'Resource': [f'acs:kms:{c["region"]}:{c["account_id"]}:key/{key}']})
    return {'Version': '1', 'Statement': statements}


def credentials(c, role, token_file, policy=None):
    # Kubernetes projected tokens use atomic symlinks; validate the opened file.
    with open(token_file, "rb") as projected:
        info = os.fstat(projected.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 32768, "OIDC_TOKEN_FILE")
        token = projected.read(32769)
    require(0 < len(token) <= 32768 and token.count(b'.') == 2, 'OIDC_TOKEN')
    require(time.time() + 120 < timestamp(c['deadline']), 'CREDENTIAL_JOB_DEADLINE')
    session = 'backup-' + uuid.uuid4().hex
    body = urllib.parse.urlencode({'Action': 'AssumeRoleWithOIDC', 'Version': '2015-04-01', 'Format': 'JSON',
        'RoleArn': c['roles'][role]['arn'], 'OIDCProviderArn': c['oidc_provider_arn'],
        'RoleSessionName': session, 'DurationSeconds': '900', 'OIDCToken': token.decode('ascii'),
        'Policy': canonical(session_policy(c, role) if policy is None else policy).decode()}).encode()
    conn = http.client.HTTPSConnection('sts.' + c['region'] + '.aliyuncs.com', timeout=10)
    try:
        conn.request('POST', '/', body, {'Content-Type': 'application/x-www-form-urlencoded'})
        response = conn.getresponse()
        raw = response.read(MAX_METADATA + 1)
        require(response.status == 200 and len(raw) <= MAX_METADATA, 'STS_RESPONSE')
        data = decode(raw)
    finally:
        conn.close()
    info, creds = data.get('OIDCTokenInfo', {}), data.get('Credentials', {})
    require(data.get('AssumedRoleUser', {}).get('Arn') == c['roles'][role]['arn'] + '/' + session, 'STS_ROLE')
    require(info.get('Issuer') == c['issuer'] and info.get('Subject') == c['roles'][role]['subject']
            and info.get('ClientIds') == 'sts.aliyuncs.com' and info.get('VerificationInfo') == 'Success', 'STS_IDENTITY')
    require(time.time() + 120 < timestamp(creds['Expiration']) <= time.time() + 930, 'STS_EXPIRY')
    require(creds['AccessKeyId'].startswith('STS.') and creds['AccessKeySecret'] and creds['SecurityToken'], 'STS_CREDENTIALS')
    return {'Version': 1, 'AccessKeyId': creds['AccessKeyId'], 'SecretAccessKey': creds['AccessKeySecret'],
            'SessionToken': creds['SecurityToken'], 'Expiration': creds['Expiration']}


def setup_remote(c, role, config_path, work):
    """AWS SDK process provider renews native AliCloud STS; explicit profile cannot fall back to IMDS."""
    work = Path(work)
    require(work.is_dir() and work.stat().st_mode & 0o077 == 0, 'PRIVATE_WORK_DIRECTORY')
    require(str(Path(config_path).resolve()) == '/run/backup-config/job.json', 'CONFIG_MOUNT_PATH')
    profile = work / 'aws-credentials'
    profile.write_text('[profile sandbox-backup]\ncredential_process = /usr/local/bin/python3 /app/backup.py credentials --config /run/backup-config/job.json --role ' + role + '\n')
    profile.chmod(0o600)
    rclone = work / 'rclone.conf'
    rclone.write_text('[oss]\ntype = s3\nprovider = Alibaba\nenv_auth = true\nprofile = sandbox-backup\nshared_credentials_file = ' + str(profile) + '\nendpoint = https://oss-' + c['region'] + '-internal.aliyuncs.com\nregion = ' + c['region'] + '\nforce_path_style = false\nno_check_bucket = true\nuse_multipart_etag = false\nchunk_size = 8Mi\nupload_concurrency = 2\nupload_cutoff = 16Mi\nlist_version = 2\n')
    rclone.chmod(0o600)
    env = environment()
    env['RCLONE_CONFIG'] = str(rclone)
    env['RESTIC_PASSWORD_FILE'] = '/run/backup-key/password'
    env['RCLONE_RETRIES'] = '2'
    env['RCLONE_LOW_LEVEL_RETRIES'] = '2'
    env['RCLONE_CONNECT_TIMEOUT'] = '10s'
    env['RCLONE_TIMEOUT'] = '60s'
    env['RCLONE_LOG_LEVEL'] = 'ERROR'
    return env


class Repository:
    def __init__(self, restic, repository, password, deadline, env=None):
        self.restic, self.repository, self.password, self.deadline = str(restic), repository, str(password), deadline
        self.env = env or environment()

    def call(self, *args, sink=None):
        return run([self.restic, '--repo', self.repository, '--password-file', self.password,
                    '--no-cache', *args], self.deadline, self.env, sink=sink)

    def capture(self, command):
        self.call('init', '--repository-version', '2')  # Existing repo is an error; never implicit unlock/reuse.
        pending = bytearray()
        summary = None
        def progress(block):
            nonlocal summary
            pending.extend(block)
            while b'\n' in pending:
                line, _, tail = pending.partition(b'\n')
                pending[:] = tail
                require(len(line) <= 65536, 'RESTIC_FRAME_LIMIT')
                value = decode(line)
                if value.get('message_type') == 'summary':
                    require(summary is None, 'DUPLICATE_RESTIC_SUMMARY')
                    summary = value
            require(len(pending) <= 65536, 'RESTIC_FRAME_LIMIT')
        self.call('backup', '--json', '--host', 'sandbox-backup', '--stdin-filename', 'disk.img',
                  '--stdin-from-command', '--', *command, sink=progress)
        require(not pending, 'INCOMPLETE_RESTIC_FRAME')
        require(summary and sha(summary.get('snapshot_id')), 'SNAPSHOT_ID')
        self.call('--no-lock', 'check', '--read-data')
        return summary['snapshot_id']

    def digest(self, snapshot, expected_size):
        result = hashlib.sha256()
        count = 0
        def consume(block):
            nonlocal count
            count += len(block)
            require(count <= expected_size, 'RESTORE_OVERSIZE')
            result.update(block)
        self.call('--no-lock', 'dump', snapshot, '/disk.img', sink=consume)
        require(count == expected_size, 'RESTORE_SHORT')
        return result.hexdigest()

    def check(self, snapshot, expected_size, expected_sha):
        require(sha(snapshot) and sha(expected_sha), 'MANIFEST_HASH')
        self.call('--no-lock', 'check', '--read-data')
        require(self.digest(snapshot, expected_size) == expected_sha, 'RESTORE_CHECKSUM')


def manifest(c, snapshot, disk, object_inventory):
    inventory.validate(object_inventory)
    require(sha(snapshot) and set(disk) == {'size_bytes', 'sha256'} and disk['size_bytes'] == c['size_bytes'] and sha(disk['sha256']), 'CAPTURE_RECEIPT')
    return {'protocol': 2, 'format': 'restic-raw-disk-v2', 'inventory': object_inventory, 'backup': backup_identity(c), 'snapshot_id': snapshot,
            'disk': disk, 'repository_prefix': PREFIX.format(**c), 'sealed_at': utc(),
            'retain_objects_until': dt.datetime.fromtimestamp(max(timestamp(c['retention_until']), timestamp(c['deadline']) + 30 * 86400 + 300), dt.timezone.utc).isoformat(),
            'repository_read_data_verified': True, 'raw_restore_sha256_verified': True,
            'cloud_restore_tested_at': None}


def backup_identity(c):
    # A restore has a fresh job deadline/current cloud identity and certification.
    return {k: v for k, v in c.items() if k not in ('deadline', 'roles', 'issuer', 'oidc_provider_arn', 'runtime_certification_sha256')}


def validate_manifest(value, c):
    require(set(value) == {'protocol', 'format', 'backup', 'snapshot_id', 'disk', 'repository_prefix', 'sealed_at', 'retain_objects_until',
                          'repository_read_data_verified', 'raw_restore_sha256_verified', 'cloud_restore_tested_at', 'inventory'}, 'MANIFEST_FIELDS')
    inventory.validate(value['inventory'])
    require(value['protocol'] == 2 and value['format'] == 'restic-raw-disk-v2' and value['backup'] == backup_identity(c), 'MANIFEST_IDENTITY')
    require(value['repository_prefix'] == PREFIX.format(**c) and sha(value['snapshot_id']), 'MANIFEST_REPOSITORY')
    require(set(value['disk']) == {'size_bytes', 'sha256'} and value['disk']['size_bytes'] == c['size_bytes'] and sha(value['disk']['sha256']), 'MANIFEST_DISK')
    require(value['cloud_restore_tested_at'] is None, 'MANIFEST_CLOUD_CLAIM')
    require(value['repository_read_data_verified'] is True and value['raw_restore_sha256_verified'] is True, 'MANIFEST_UNVERIFIED')
    require(timestamp(c['data_timestamp']) <= timestamp(value['sealed_at']) <= time.time(), 'MANIFEST_TIME')
    require(timestamp(value['retain_objects_until']) >= max(timestamp(c['retention_until']), timestamp(value['sealed_at']) + 30 * 86400), 'MANIFEST_RETENTION')


def signature(openssl, mode, key, data, signature_path, deadline):
    require(mode in ('sign', 'verify'), 'SIGNATURE_MODE')
    if mode == 'sign':
        read(key, 16384, secret=True)
    public = run([openssl, 'pkey', '-in', str(key), *([] if mode == 'sign' else ['-pubin']),
                  '-pubout', '-outform', 'DER'], deadline)
    require(len(public) == 44 and public.startswith(bytes.fromhex('302a300506032b6570032100')), 'ED25519_KEY_REQUIRED')
    args = [openssl, 'pkeyutl', '-' + mode, '-rawin', '-inkey', str(key), '-in', str(data)]
    args += ['-out', str(signature_path)] if mode == 'sign' else ['-pubin', '-sigfile', str(signature_path)]
    run(args, deadline)


def restore_device(repo, value):
    size, expected = value['disk']['size_bytes'], value['disk']['sha256']
    repo.check(value['snapshot_id'], size, expected)  # Validate *before* modifying a new target device.
    fd = device_open(size, write=True)
    count = 0
    try:
        def consume(block):
            nonlocal count
            require(time.time() < repo.deadline, 'RESTORE_DEADLINE')
            require(count + len(block) <= size, 'RESTORE_OVERSIZE')
            view = memoryview(block)
            while view:
                written = os.write(fd, view)
                require(written > 0, 'RESTORE_WRITE')
                view = view[written:]
                count += written
        repo.call('--no-lock', 'dump', value['snapshot_id'], '/disk.img', sink=consume)
        require(count == size, 'RESTORE_SHORT')
        os.fsync(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        count = 0
        while count < size:
            require(time.time() < repo.deadline, 'RESTORE_DEADLINE')
            block = os.read(fd, min(CHUNK, size - count))
            require(block, 'READBACK_SHORT')
            digest.update(block)
            count += len(block)
        require(digest.hexdigest() == expected, 'READBACK_CHECKSUM')
    finally:
        os.close(fd)
    return {'protocol': 1, 'backup_id': value['backup']['backup_id'], 'bytes': size,
            'sha256': expected, 'restored_at': utc(), 'filesystem_mounted': False,
            'application_recovery_tested': False, 'cloud_restore_certified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['capture', 'seal', 'restore', 'credentials', 'stream'])
    parser.add_argument('--config', default='/run/backup-config/job.json')
    parser.add_argument('--role', choices=['backup', 'backup-export', 'restore'])
    parser.add_argument('--size', type=int)
    parser.add_argument('--receipt', default='/run/backup/capture.json')
    args = parser.parse_args()
    if args.command == 'stream':
        require(args.size is not None and 0 < args.size <= 16 * 1024**4, 'STREAM_SIZE')
        stream_device(args.size, args.receipt)
        return
    c = config(args.config)
    if args.command == 'credentials':
        require(args.role is not None, 'CREDENTIAL_ROLE')
        # Intentionally credential_process stdout ONLY. Never invoke from interactive diagnostics/logs.
        sys.stdout.buffer.write(canonical(credentials(c, args.role, '/var/run/sandbox-cloud/token')))
        return
    role = {'capture': 'backup', 'seal': 'backup-export', 'restore': 'restore'}[args.command]
    os.makedirs('/run/backup', mode=0o700, exist_ok=True)
    os.chmod('/run/backup', 0o700)  # Kubernetes creates the emptyDir root before the process starts.
    env = setup_remote(c, role, args.config, '/run/backup')
    password = '/run/backup-key/password'
    require(32 <= len(read(password, 4096, secret=True).strip()) <= 1024, 'REPOSITORY_KEY')
    deadline = timestamp(c['deadline'])
    prefix = PREFIX.format(**c)
    mutable = f'rclone:oss:{c["bucket"]}/{prefix}'
    vault = f'rclone:oss:{c["vault_bucket"]}/{prefix}'
    repo = Repository('/usr/local/bin/restic', vault if args.command == 'restore' else mutable, password, deadline, env)
    if args.command == 'capture':
        snapshot = repo.capture(['/usr/local/bin/python3', str(HERE / 'backup.py'), 'stream', '--size', str(c['size_bytes'])])
        disk = decode(read('/run/backup/capture.json'))
        require(disk['size_bytes'] == c['size_bytes'], 'CAPTURE_SIZE')
        require(repo.digest(snapshot, c['size_bytes']) == disk['sha256'], 'CAPTURE_CHECKSUM')
        # Unsigned report is not platform AVAILABLE or evidence of VM termination.
        atomic('/run/backup/result.json', {'snapshot_id': snapshot, 'disk': disk})
    elif args.command == 'seal':
        report = decode(read('/run/backup-source/capture.json'))
        repo.check(report['snapshot_id'], c['size_bytes'], report['disk']['sha256'])
        snapshots = decode(repo.call('--no-lock', 'snapshots', '--json'))
        require(len(snapshots) == 1 and snapshots[0]['id'] == report['snapshot_id'], 'SINGLE_SNAPSHOT_REQUIRED')
        # Copy only a quiesced, per-backup repository; never sync/delete or mutate destination repository locks.
        source, destination = mutable.removeprefix('rclone:'), vault.removeprefix('rclone:')
        run(['/usr/local/bin/rclone', 'copy', '--immutable', '--transfers', '2', '--checkers', '2', source, destination], deadline, env)
        run(['/usr/local/bin/rclone', 'check', '--download', '--checkers', '2', source, destination], deadline, env)
        vault_repo = Repository('/usr/local/bin/restic', vault, password, deadline, env)
        vault_repo.check(report['snapshot_id'], c['size_bytes'], report['disk']['sha256'])
        inventory_path = Path('/run/backup/inventory')
        object_inventory = inventory.build(c, report['snapshot_id'], destination, inventory_path, deadline, env, run)
        parent = destination.removesuffix('/repository')
        names = run(['/usr/local/bin/rclone', 'lsf', '--max-depth', '1', '--files-only', parent], deadline, env).splitlines()
        existing = 'manifest.json' if b'manifest.json' in names else ('manifest.pending.json' if b'manifest.pending.json' in names else None)
        if existing:
            # Recover an interrupted publication using the original immutable bytes, never a new timestamp/signature payload.
            raw = run(['/usr/local/bin/rclone', 'cat', '--count', str(MAX_METADATA + 1), parent + '/' + existing], deadline, env)
            result = decode(raw)
            validate_manifest(result, c)
            require(result['snapshot_id'] == report['snapshot_id'] and result['disk'] == report['disk'] and result['inventory'] == object_inventory and raw == canonical(result), 'EXISTING_MANIFEST_DRIFT')
        else:
            result = manifest(c, report['snapshot_id'], report['disk'], object_inventory)
        atomic('/run/backup/manifest.json', result)
        for shard in object_inventory['shards']:
            run(['/usr/local/bin/rclone', 'copyto', '--immutable', str(inventory_path / Path(shard['key']).name), parent + '/' + shard['key']], deadline, env)
        # Persist the same unsigned candidate before its detached signature so
        # interruption after sig upload can resume without replacing WORM bytes.
        run(['/usr/local/bin/rclone', 'copyto', '--immutable', '/run/backup/manifest.json', parent + '/manifest.pending.json'], deadline, env)
        signature('/usr/bin/openssl', 'sign', '/run/backup-signing/private.pem', '/run/backup/manifest.json', '/run/backup/manifest.sig', deadline)
        # The final manifest pointer is uploaded last, after inventory and signature. WORM prevents overwrite.
        for name in ('manifest.sig', 'manifest.json'):
            run(['/usr/local/bin/rclone', 'copyto', '--immutable', '/run/backup/' + name,
                 destination.removesuffix('/repository') + '/' + name], deadline, env)
        atomic('/run/backup/result.json', {'manifest_sha256': hashlib.sha256(canonical(result)).hexdigest(),
               'state': 'SEALED_REPOSITORY', 'cloud_restore_tested_at': None})
    else:
        require(sha(os.environ.get('SANDBOX_EXPECTED_MANIFEST_SHA256')), 'EXPECTED_MANIFEST_REQUIRED')
        for name in ('manifest.json', 'manifest.sig'):
            data = run(['/usr/local/bin/rclone', 'cat', '--count', str(MAX_METADATA + 1),
                        vault.removeprefix('rclone:').removesuffix('/repository') + '/' + name], deadline, env)
            Path('/run/backup/' + name).write_bytes(data)
        raw = read('/run/backup/manifest.json')
        require(hashlib.sha256(raw).hexdigest() == os.environ['SANDBOX_EXPECTED_MANIFEST_SHA256'], 'MANIFEST_DIGEST')
        signature('/usr/bin/openssl', 'verify', '/run/backup-signing/public.pem', '/run/backup/manifest.json', '/run/backup/manifest.sig', deadline)
        value = decode(raw)
        validate_manifest(value, c)
        atomic('/run/backup/result.json', restore_device(repo, value))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError, subprocess.SubprocessError, inventory.sqlite3.Error, http.client.HTTPException):
        # SDK/HTTP/child error text may include signed URLs or credentials.
        print('BACKUP_STAGE_FAILED: no completion receipt; inspect trusted controller stage metadata', file=sys.stderr)
        sys.exit(1)
