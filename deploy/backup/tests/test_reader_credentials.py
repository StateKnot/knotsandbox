import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.parse
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import reader_credentials as reader
import reader_config
import contextlib
import io


def settings():
    return {'region':'cn-hangzhou','account_id':'1234567890123456','vault_bucket':'fixture-vault','vault_kms_key_id':'vault-key',
        'issuer':'https://oidc.fixture.invalid','oidc_provider_arn':'acs:ram::1234567890123456:oidc-provider/fixture',
        'role_arn':'acs:ram::1234567890123456:role/fixture-backup-reader'}


class Reader(unittest.TestCase):
    def test_policy_is_exact_vault_read_and_repository_listing_only(self):
        policy=reader.policy(settings())
        self.assertEqual([s['Action'] for s in policy['Statement']], [['oss:GetObject'],['oss:ListObjects'],['kms:Decrypt']])
        self.assertEqual(policy['Statement'][1]['Condition']['StringLike']['oss:Prefix'], ['tenants/*/backups/*/repository/'])
    def test_invalid_config_role_account_endpoint_or_extra_fields_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'config.json'
            p.write_text(json.dumps(settings()));self.assertEqual(reader.config(p),settings())
            for key,value in [('role_arn','acs:ram::1234567890123456:role/fixture-restore'),('account_id','0000000000000000'),('issuer','http://oidc.fixture.invalid'),('region','localhost:123'),('token','not-accepted')]:
                p.write_text(json.dumps(settings()|{key:value}))
                with self.assertRaises(ValueError):reader.config(p)
    def test_actual_exchange_contract_binds_subject_and_role_and_atomically_writes_0600(self):
        for failure in [None,'role','subject','issuer','audience','expiry','oversized','status']:
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as tmp:
                folder=Path(tmp);token=folder/'token';token.write_text('test.projected.token');target=folder/'credentials.json'
                calls=[]
                class Connection:
                    def __init__(self, host, timeout):
                        self.host=host;self.request_data=None
                        self.assertions=(host,timeout)
                    def request(self,method,path,body,headers):
                        self.request_data=urllib.parse.parse_qs(body.decode());calls.append((self.host,method,path,self.request_data))
                    def getresponse(self):
                        session=self.request_data['RoleSessionName'][0]
                        value={'AssumedRoleUser':{'Arn':settings()['role_arn']+'/'+session},'OIDCTokenInfo':{'Issuer':settings()['issuer'],'Subject':reader.SUBJECT,'ClientIds':'sts.aliyuncs.com','VerificationInfo':'Success'},'Credentials':{'AccessKeyId':'STS.fixture','AccessKeySecret':'test-secret','SecurityToken':'test-token','Expiration':(dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=900)).isoformat()}}
                        if failure=='role':value['AssumedRoleUser']['Arn']='acs:ram::1234567890123456:role/restore/'+session
                        if failure in ('subject','issuer','audience'):value['OIDCTokenInfo'][{'subject':'Subject','issuer':'Issuer','audience':'ClientIds'}[failure]]='wrong'
                        if failure=='expiry':value['Credentials']['Expiration']='2000-01-01T00:00:00Z'
                        data=b'x'*(1024*1024+1) if failure=='oversized' else json.dumps(value).encode()
                        return type('Response',(),{'status':500 if failure=='status' else 200,'read':lambda _self,max:data[:max]})()
                    def close(self):pass
                with patch('backup.http.client.HTTPSConnection',Connection):
                    if failure:
                        with self.assertRaises(ValueError):reader.refresh(settings(),token,target)
                        self.assertFalse(target.exists())
                    else:
                        reader.refresh(settings(),token,target)
                        value=json.loads(target.read_text());self.assertEqual(set(value),{'access_key_id','access_key_secret','security_token','expires_at'})
                        self.assertEqual(target.stat().st_mode&0o777,0o600)
                self.assertEqual(calls[0][0],'sts.cn-hangzhou.aliyuncs.com')
                self.assertEqual(calls[0][3]['DurationSeconds'],['900'])
                self.assertEqual(json.loads(calls[0][3]['Policy'][0]),reader.policy(settings()))
    def test_refresh_failure_removes_previous_file_and_redacts_provider_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);private=root/'private';private.mkdir(mode=0o700)
            target=private/'credentials.json';target.write_text('old-credentials')
            config=root/'reader.json';config.write_text(json.dumps(settings()))
            stderr=io.StringIO()
            with patch('reader_credentials.OUTPUT',str(target)), patch.object(sys,'argv',['reader','--config',str(config),'--once']), patch('reader_credentials.refresh',side_effect=ValueError('private-provider-marker')), contextlib.redirect_stderr(stderr), self.assertRaises(ValueError):
                reader.main()
            self.assertFalse(target.exists())
            self.assertNotIn('private-provider-marker',stderr.getvalue())
    def test_terraform_export_checks_role_subject_and_account(self):
        c=settings()
        value={'deployment_identity':{'value':{'region':c['region'],'cloud_account_id':c['account_id']}},
               'workload_roles':{'value':{'backup-reader':{'arn':c['role_arn'],'subject':reader.SUBJECT,'issuer':c['issuer'],'audience':'sts.aliyuncs.com'}}},
               'object_storage':{'value':{'backup-vault':{'bucket':c['vault_bucket'],'kms_key_id':c['vault_kms_key_id']}}},
               'workload_oidc_provider_arn':{'value':c['oidc_provider_arn']}}
        self.assertEqual(reader_config.export(value),c)
        value['workload_roles']['value']['backup-reader']['subject']='system:serviceaccount:sandbox-system:sandbox-restore'
        with self.assertRaises(ValueError):reader_config.export(value)
    def test_oversized_projected_token_never_calls_sts(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'token';p.write_bytes(b'a.'*20000)
            with patch('backup.http.client.HTTPSConnection') as network,self.assertRaises(ValueError):reader.refresh(settings(),p,Path(tmp)/'out')
            network.assert_not_called()


if __name__=='__main__':unittest.main()
