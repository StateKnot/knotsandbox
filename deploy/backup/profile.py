#!/usr/bin/env python3
"""Static owner-profile artifact validation. It never certifies or activates a cloud profile."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
from backup import canonical, decode, read, require, sha, timestamp, uuid_text

FIELDS = {'protocol', 'profile_id', 'cluster_epoch', 'enabled', 'certification_report_sha256',
          'certified_until', 'image', 'snapshot_class', 'clone_storage_class', 'password_secret',
          'signing_private_secret', 'signing_public_secret', 'settings'}
SETTINGS = {'deployment', 'secret_bindings', 'signing_key_sha256', 'vault_endpoint', 'clone_kms_key_id', 'vault_retention_days',
            'key_ref', 'region', 'account_id', 'bucket', 'vault_bucket', 'kms_key_id',
            'vault_kms_key_id', 'issuer', 'oidc_provider_arn', 'roles'}
CHECKS = {'kata_raw_block_no_host_mount', 'csi_filesystem_snapshot_to_block',
          'nodeguard_backup_launch_and_termination', 'network_first_packet_and_metadata',
          'isolated_source_vault_ram_prefix', 'vault_locked_worm', 'kms_recovery_and_rotation',
          'full_repository_read_and_independent_restore', 'controller_admission_race_and_recovery'}
BINDINGS = {'deployment', 'profile_spec_sha256', 'profile_id', 'cluster_epoch', 'image', 'versions_lock_sha256', 'account_id', 'region',
            'bucket', 'vault_bucket', 'kms_key_id', 'vault_kms_key_id', 'clone_kms_key_id',
            'signing_key_sha256', 'vault_retention_days', 'snapshot_class', 'clone_storage_class'}

def name(v):
    return isinstance(v, str) and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,62}', v)


def validate(value, report_bytes, now=None):
    now = dt.datetime.now(dt.timezone.utc).timestamp() if now is None else now
    require(isinstance(value, dict) and set(value) == FIELDS, 'PROFILE_FIELDS')
    require(value['protocol'] == 1 and value['enabled'] is False, 'REGISTER_DISABLED_ONLY')
    require(uuid_text(value['profile_id']) and uuid_text(value['cluster_epoch']), 'PROFILE_IDENTITY')
    require(re.fullmatch(r'[a-z0-9.-]+(?::[0-9]+)?/[a-zA-Z0-9/_-]+@sha256:[0-9a-f]{64}', value['image']), 'PINNED_IMAGE')
    for field in ('snapshot_class', 'clone_storage_class', 'password_secret', 'signing_private_secret', 'signing_public_secret'):
        require(name(value[field]), 'PROFILE_RESOURCE_NAME')
    require(len({value[k] for k in ('password_secret', 'signing_private_secret', 'signing_public_secret')}) == 3, 'SEPARATE_KEYS')
    cloud = value['settings']
    require(isinstance(cloud, dict) and set(cloud) == SETTINGS, 'CLOUD_FIELDS')
    require(isinstance(cloud['deployment'], str) and re.fullmatch(r'[a-z][a-z0-9-]{3,19}', cloud['deployment']), 'DEPLOYMENT_TAG')
    require(re.fullmatch(r'cn-[a-z0-9-]{1,29}', cloud['region']) and re.fullmatch(r'[0-9]{16}', cloud['account_id']), 'CLOUD_IDENTITY')
    require(all(name(cloud[k]) and len(cloud[k]) >= 3 for k in ('bucket', 'vault_bucket')) and cloud['bucket'] != cloud['vault_bucket'], 'INDEPENDENT_BUCKETS')
    require(cloud['vault_endpoint'] == f'https://oss-{cloud["region"]}-internal.aliyuncs.com', 'FIXED_INTERNAL_ENDPOINT')
    require(type(cloud['vault_retention_days']) is int and 31 <= cloud['vault_retention_days'] <= 3650, 'LOCKED_RETENTION_RANGE')
    bindings = cloud['secret_bindings']
    require(isinstance(bindings, dict) and set(bindings) == {'password', 'signing_private', 'signing_public'}, 'SECRET_BINDINGS')
    for purpose, field in [('password', 'password_secret'), ('signing_private', 'signing_private_secret'), ('signing_public', 'signing_public_secret')]:
        b = bindings[purpose]
        require(set(b) == {'name', 'uid', 'content_sha256'} and b['name'] == value[field] and b['name'].startswith('sbx-bkey-') and uuid_text(b['uid']) and sha(b['content_sha256']), 'SECRET_IDENTITY')
    require(len({b['uid'] for b in bindings.values()}) == 3, 'SEPARATE_SECRET_UIDS')
    require(sha(cloud['signing_key_sha256']), 'APPROVED_SIGNING_KEY')
    for k in ('key_ref', 'kms_key_id', 'vault_kms_key_id', 'clone_kms_key_id'):
        require(isinstance(cloud[k], str) and re.fullmatch(r'[A-Za-z0-9/_:-]{1,256}', cloud[k]), 'KEY_REFERENCE')
    require(cloud['kms_key_id'] != cloud['vault_kms_key_id'], 'INDEPENDENT_VAULT_KEY')
    require(set(cloud['roles']) == {'backup', 'backup-export', 'restore'}, 'ROLE_FIELDS')
    for role, identity in cloud['roles'].items():
        require(set(identity) == {'arn', 'subject'} and identity['subject'] == f'system:serviceaccount:sandbox-system:sandbox-{role}', 'ROLE_SUBJECT')
        require(identity['arn'].startswith(f'acs:ram::{cloud["account_id"]}:role/') and identity['arn'].endswith('-' + role), 'ROLE_ARN')
    require(sha(value['certification_report_sha256']) and hashlib.sha256(report_bytes).hexdigest() == value['certification_report_sha256'], 'REPORT_DIGEST')
    report = decode(report_bytes)
    require(canonical(report) == report_bytes, 'CANONICAL_REPORT_REQUIRED')
    require(set(report) == {'protocol', 'bindings', 'reviewed_at', 'expires_at', 'checks'} and report['protocol'] == 1, 'REPORT_FIELDS')
    binding = report['bindings']
    require(set(binding) == BINDINGS, 'CERTIFICATION_BINDINGS')
    for key in BINDINGS - {'versions_lock_sha256', 'profile_spec_sha256'}:
        require(binding[key] == value.get(key, cloud.get(key)), 'CERTIFICATION_IDENTITY_MISMATCH')
    require(binding['profile_spec_sha256'] == hashlib.sha256(canonical({k: v for k, v in value.items() if k != 'certification_report_sha256'})).hexdigest(), 'FULL_PROFILE_SPEC_BINDING')
    lock = Path(__file__).with_name('versions.lock.json').read_bytes()
    require(binding['versions_lock_sha256'] == hashlib.sha256(lock).hexdigest(), 'APPROVED_TOOL_LOCK')
    reviewed, expires = timestamp(report['reviewed_at']), timestamp(report['expires_at'])
    require(reviewed <= now < expires <= reviewed + 30 * 86400 and expires == timestamp(value['certified_until']), 'CERTIFICATION_WINDOW')
    require(set(report['checks']) == CHECKS, 'REQUIRED_CHECKS')
    for check in report['checks'].values():
        require(set(check) == {'result', 'evidence_sha256', 'observed_at'} and check['result'] == 'PASS' and sha(check['evidence_sha256']), 'CHECK_EVIDENCE')
        require(reviewed - 7 * 86400 <= timestamp(check['observed_at']) <= reviewed, 'CHECK_WINDOW')
    # No "passed" output: these are operator claims, not authenticated live evidence.
    return {'profile_sha256': hashlib.sha256(canonical(value)).hexdigest(),
            'report_sha256': hashlib.sha256(report_bytes).hexdigest(),
            'registration_enabled': False, 'live_activation_verified': False}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--file', required=True)
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    try:
        raw = read(args.file)
        value = decode(raw)
        require(raw == canonical(value), 'CANONICAL_PROFILE_REQUIRED')
        print(json.dumps(validate(value, read(args.report)), sort_keys=True))
    except (ValueError, TypeError, KeyError) as error:
        raise SystemExit(str(error)) from None
