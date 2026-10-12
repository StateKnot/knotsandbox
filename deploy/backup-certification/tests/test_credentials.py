import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('certifier', ROOT / 'credentials.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def config():
    epoch, profile = '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000002'
    return {'account_id': '1234567890123456', 'region': 'cn-hangzhou', 'bucket': 'fixture-vault',
            'cluster_epoch': epoch, 'profile_id': profile, 'anchor_key': f'certification/{epoch}/{profile}/anchor',
            'issuer': 'https://issuer.fixture.invalid',
            'oidc_provider_arn': 'acs:ram::1234567890123456:oidc-provider/fixture',
            'role_arn': 'acs:ram::1234567890123456:role/fixture-backup-certifier'}


class Connection:
    calls = []
    def __init__(self, host, timeout):
        assert host == 'sts.cn-hangzhou.aliyuncs.com' and timeout == 10
    def request(self, method, path, body, headers):
        assert method == 'POST' and path == '/'
        self.form = urllib.parse.parse_qs(body.decode(), strict_parsing=True)
        Connection.calls.append(self.form)
    def getresponse(self):
        self.status = 200
        return self
    def read(self, maximum):
        assert maximum == 1024 * 1024 + 1
        return json.dumps({'AssumedRoleUser': {'Arn': self.form['RoleArn'][0] + '/' + self.form['RoleSessionName'][0]},
            'OIDCTokenInfo': {'Issuer': config()['issuer'], 'Subject': c.SUBJECT, 'ClientIds': 'sts.aliyuncs.com', 'VerificationInfo': 'Success'},
            'Credentials': {'AccessKeyId': 'STS.fixture', 'AccessKeySecret': 'SECRET_MARKER', 'SecurityToken': 'TOKEN_MARKER',
                'Expiration': (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=15)).isoformat()}}).encode()
    def close(self):
        pass


class Tests(unittest.TestCase):
    def test_exact_permission_and_oidc_trust_no_write_decrypt_or_wildcard_key(self):
        value = c.validate(config())
        p = c.policy(value)
        self.assertEqual(p['Statement'][0]['Action'], ['oss:GetBucketInfo', 'oss:GetBucketWorm', 'oss:GetBucketVersioning'])
        self.assertEqual(p['Statement'][1]['Resource'], ['acs:oss:*:*:fixture-vault/' + value['anchor_key']])
        self.assertNotIn('kms:', json.dumps(p))
        self.assertNotIn('Put', json.dumps(p))
        self.assertEqual(c.trust(value)['Statement'][0]['Condition']['StringEquals'], {
            'oidc:iss': value['issuer'], 'oidc:sub': c.SUBJECT, 'oidc:aud': 'sts.aliyuncs.com'})
    def test_invalid_config_cannot_expand_identity_or_anchor(self):
        for key, value in [('account_id', '*'), ('region', 'cn-hangzhou.evil'), ('bucket', '*'),
                           ('role_arn', config()['role_arn'].replace('1234567890123456', '9999999999999999')),
                           ('anchor_key', 'tenants/other/secret'), ('issuer', 'https://user:pass@fixture.invalid'),
                           ('cluster_epoch', '00000000-0000-0000-0000-000000000000')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                c.validate({**config(), key: value})
        with self.assertRaises(ValueError):
            c.validate({**config(), 'endpoint': 'https://evil.invalid'})
    def test_exchange_uses_real_sts_parser_exact_session_policy_and_private_atomic_file(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            token = base / 'token'
            token.write_text('header.payload.signature')
            (base / 'projected').symlink_to(token)
            output = base / 'sts.json'
            capture = io.StringIO()
            Connection.calls.clear()
            with patch('http.client.HTTPSConnection', Connection), patch('sys.stdout', capture):
                c.refresh(c.validate(config()), base / 'projected', output)
            self.assertEqual(capture.getvalue(), '')
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(set(json.loads(output.read_bytes())), {'access_key_id', 'access_key_secret', 'security_token', 'expires_at'})
            self.assertEqual(json.loads(Connection.calls[0]['Policy'][0]), c.policy(config()))
            self.assertEqual(Connection.calls[0]['DurationSeconds'], ['900'])
    def test_missing_or_fifo_token_removes_stale_file_without_network_or_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for path in [base / 'missing', base / 'pipe']:
                if path.name == 'pipe':
                    os.mkfifo(path)
                output = base / 'sts.json'
                output.write_text('stale')
                with patch('http.client.HTTPSConnection') as network, self.assertRaises((ValueError, OSError)):
                    c.refresh(config(), path, output)
                network.assert_not_called()
                self.assertFalse(output.exists())
    def test_duplicate_config_fields_and_nonregular_config_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config'
            path.write_text('{"account_id":"a","account_id":"b"}')
            with self.assertRaises(ValueError):
                c.bounded(path)
            path.unlink()
            os.mkfifo(path)
            with self.assertRaises(ValueError):
                c.bounded(path)


if __name__ == '__main__':
    unittest.main()
