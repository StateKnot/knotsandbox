#!/usr/bin/env python3
"""Export public backup-reader configuration from reviewed Terraform outputs."""
import argparse
import os
import sys
from backup import canonical, decode, read, require
from reader_credentials import SUBJECT, validate


def export(value):
    deployment = value['deployment_identity']['value']
    role = value['workload_roles']['value']['backup-reader']
    vault = value['object_storage']['value']['backup-vault']
    require(role['subject'] == SUBJECT and role['audience'] == 'sts.aliyuncs.com', 'READER_TRUST')
    return validate({'region': deployment['region'], 'account_id': deployment['cloud_account_id'],
        'vault_bucket': vault['bucket'], 'vault_kms_key_id': vault['kms_key_id'], 'issuer': role['issuer'],
        'oidc_provider_arn': value['workload_oidc_provider_arn']['value'], 'role_arn': role['arn']})


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--terraform-output',required=True)
    p.add_argument('--output',required=True)
    a=p.parse_args()
    data=canonical(export(decode(read(a.terraform_output))))
    fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(data);f.flush();os.fsync(f.fileno())
    print('Public backup-reader configuration exported; no token or cloud action performed.')


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError):
        print('BACKUP_READER_CONFIG_REJECTED',file=sys.stderr)
        sys.exit(1)
