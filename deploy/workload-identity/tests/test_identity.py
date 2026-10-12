import base64
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('workload_identity', ROOT / 'identity.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
NOW = 1900000000


def enc(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode()


def fixture():
    settings = {'version': 1, 'issuer': 'https://issuer.example.test', 'audience': 'sts.aliyuncs.com',
                'deployment': 'sandbox-test', 'cluster_epoch': '11111111-2222-4333-8444-555555555555',
                'account_id': '1234567890123456', 'region': 'cn-hangzhou',
                'oidc_provider_arn': 'acs:ram::1234567890123456:oidc-provider/workloads',
                'roles': {'fencing': {'arn': 'acs:ram::1234567890123456:role/fencing', 'role_id': '123456789',
                                     'subject': 'system:serviceaccount:sandbox-system:sandbox-fencing'}},
                'control_plane_contexts': ['control-1', 'control-2', 'control-3'],
                'control_plane_nodes': {f'control-{i}': {'name': f'control-{i}', 'private_ip': f'10.0.0.{i}', 'instance_id': f'i-control{i}'} for i in range(1, 4)},
                'origins': [{'ssh_host': 'origin1.example.test', 'https_ip': '192.0.2.10'},
                            {'ssh_host': 'origin2.example.test', 'https_ip': '192.0.2.11'}],
                'ssh_known_hosts_file': '/etc/sandbox-identity/known_hosts',
                'max_token_lifetime_seconds': 3600, 'clock_skew_seconds': 30, 'cache_seconds': 60,
                'ca_sha1_fingerprints': ['1' * 40]}
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    key = {'kty': 'RSA', 'alg': 'RS256', 'use': 'sig', 'kid': 'test-key-1',
           'n': enc(numbers.n.to_bytes(256)), 'e': enc(numbers.e.to_bytes(3))}
    disc = {'issuer': settings['issuer'], 'jwks_uri': settings['issuer'] + m.JWKS,
            'response_types_supported': ['id_token'], 'subject_types_supported': ['public'],
            'id_token_signing_alg_values_supported': ['RS256']}
    bundle = {'version': 1, 'issuer': settings['issuer'], 'exported_at': NOW,
              'deployment': settings['deployment'], 'cluster_epoch': settings['cluster_epoch'], 'config_sha256': m.hashlib.sha256(m.canonical(settings)).hexdigest(),
              'control_planes': [{**node, 'node_uid': 'node-uid-' + context, 'apiserver_pod_uid': 'pod-uid-' + context, 'flags': m.issuer_flags(settings)} for context, node in settings['control_plane_nodes'].items()],
              'discovery': disc, 'jwks': {'keys': [key]}}
    pod = {'metadata': {'namespace': 'sandbox-system', 'name': 'fencing-1', 'uid': 'pod-uid'},
           'spec': {'serviceAccountName': 'sandbox-fencing', 'containers': [{'name': 'fencing', 'volumeMounts': [
               {'name': 'cloud', 'mountPath': '/var/run/sandbox-cloud', 'readOnly': True}]}],
                    'volumes': [{'name': 'cloud', 'projected': {'sources': [{'serviceAccountToken': {
                        'audience': settings['audience'], 'expirationSeconds': 600, 'path': 'token'}}]}}]}}
    sa = {'metadata': {'namespace': 'sandbox-system', 'name': 'sandbox-fencing', 'uid': 'sa-uid'}}
    return settings, private, bundle, pod, sa


def token(private, settings, pod, sa, **changes):
    claims = {'iss': settings['issuer'], 'aud': [settings['audience']], 'sub': settings['roles']['fencing']['subject'],
              'iat': NOW - 10, 'nbf': NOW - 10, 'exp': NOW + 590,
              'kubernetes.io': {'namespace': pod['metadata']['namespace'], 'pod': {k: pod['metadata'][k] for k in ('name', 'uid')},
                                'serviceaccount': {k: sa['metadata'][k] for k in ('name', 'uid')}}}
    claims.update(changes)
    head = enc(m.canonical({'alg': 'RS256', 'typ': 'JWT', 'kid': 'test-key-1'}))
    data = (head + '.' + enc(m.canonical(claims))).encode()
    return data + b'.' + enc(private.sign(data, padding.PKCS1v15(), hashes.SHA256())).encode()


class IdentityTest(unittest.TestCase):
    def test_alibaba_official_acs3_signature_vector(self):
        # Alibaba OpenAPI V3 documentation's independent fixed vector.
        headers = {'host': 'ecs.cn-shanghai.aliyuncs.com', 'x-acs-action': 'RunInstances',
                   'x-acs-version': '2014-05-26', 'x-acs-date': '2023-10-26T10:22:32Z',
                   'x-acs-signature-nonce': '3156853299f313e23d1673dc12e1703d',
                   'x-acs-content-sha256': m.hashlib.sha256(b'').hexdigest()}
        _, signature = m.rpc_signature(headers, 'YourAccessKeySecret',
            'ImageId=win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd&RegionId=cn-shanghai')
        self.assertEqual(signature, '06563a9e1b43f5dfe96b81484da74bceab24a1d853912eee15083a6f0f3283c0')

    def test_schema_and_public_key_boundaries(self):
        settings, _, bundle, _, _ = fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            path.write_bytes(m.canonical(settings))
            self.assertEqual(m.config(path), settings)
            for change in [lambda c: c.update(issuer='http://metadata/'), lambda c: c.update(issuer='https://a;bad.example'),
                           lambda c: c.update(audience='*'), lambda c: c.update(private_key_file='/sa.key'),
                           lambda c: c['roles']['fencing'].update(arn='acs:ram::0000000000000000:role/other')]:
                modified = copy.deepcopy(settings)
                change(modified)
                path.write_bytes(m.canonical(modified))
                with self.assertRaises(m.Rejected):
                    m.config(path)
        for change in [lambda j: j['keys'][0].update(d='NEVER_EXPORT_PRIVATE_KEY'),
                       lambda j: j['keys'].append(copy.deepcopy(j['keys'][0])),
                       lambda j: j['keys'][0].update(alg='HS256'), lambda j: j['keys'][0].update(e='Aw')]:
            modified = copy.deepcopy(bundle['jwks'])
            change(modified)
            with self.assertRaises(m.Rejected):
                m.public_keys(modified)
        with self.assertRaises(m.Rejected):
            m.decode(b'{"kid":"one","kid":"two"}')

    def test_export_is_public_only_and_all_control_planes_must_match(self):
        settings, _, bundle, _, _ = fixture()
        calls = []
        def kube(context, *args):
            calls.append(args)
            if args[0] == 'config':
                if 'insecure-skip-tls-verify' in args[-1]:
                    return b'false'
                return ('https://' + settings['control_plane_nodes'][context]['private_ip'] + ':6443').encode()
            expected = settings['control_plane_nodes'][context]
            if args[:2] == ('get', 'node'):
                return m.canonical({'metadata': {'name': expected['name'], 'uid': 'node-uid-' + context}, 'status': {'conditions': [{'type': 'Ready', 'status': 'True'}], 'addresses': [{'type': 'InternalIP', 'address': expected['private_ip']}]}})
            if args[:4] == ('-n', 'kube-system', 'get', 'pods'):
                return m.canonical({'items': [{'metadata': {'uid': 'pod-uid-' + context, 'annotations': {'kubernetes.io/config.mirror': 'mirror'}}, 'spec': {'nodeName': expected['name'], 'containers': [{'name': 'kube-apiserver', 'command': ['kube-apiserver'] + ['--' + k + '=' + v for k, v in m.issuer_flags(settings).items()]}]}, 'status': {'phase': 'Running', 'containerStatuses': [{'name': 'kube-apiserver', 'ready': True}]}}]})
            return m.canonical(bundle['discovery'] if args[-1] == '--raw=' + m.DISCOVERY else bundle['jwks'])
        with patch.object(m, 'kubectl', side_effect=kube), patch.object(m.time, 'time', return_value=NOW):
            self.assertEqual(m.export(settings), bundle)
        self.assertTrue(all(args[0] == 'config' or args[:2] == ('get', 'node') or args[:4] == ('-n', 'kube-system', 'get', 'pods') or args in [('get', '--raw=' + m.DISCOVERY), ('get', '--raw=' + m.JWKS)] for args in calls))
        original = kube
        def disagreement(context, *args):
            if context == 'control-3' and args[-1] == '--raw=' + m.JWKS:
                changed = copy.deepcopy(bundle['jwks'])
                changed['keys'][0]['kid'] = 'wrong-control-plane'
                return m.canonical(changed)
            return original(context, *args)
        with patch.object(m, 'kubectl', side_effect=disagreement), self.assertRaisesRegex(m.Rejected, 'CONTROL_PLANES_DISAGREE'):
            m.export(settings)
        for wrong in ['insecure', 'flags', 'node_ip']:
            def changed(context, *args):
                value = original(context, *args)
                if wrong == 'insecure' and 'insecure-skip-tls-verify' in args[-1]:
                    return b'true'
                if wrong == 'flags' and args[:4] == ('-n', 'kube-system', 'get', 'pods'):
                    obj = m.decode(value)
                    command = obj['items'][0]['spec']['containers'][0]['command']
                    command[command.index('--service-account-extend-token-expiration=false')] = '--service-account-extend-token-expiration=true'
                    return m.canonical(obj)
                if wrong == 'node_ip' and args[:2] == ('get', 'node'):
                    obj = m.decode(value)
                    obj['status']['addresses'][0]['address'] = '10.99.99.99'
                    return m.canonical(obj)
                return value
            with self.subTest(wrong=wrong), patch.object(m, 'kubectl', side_effect=changed), self.assertRaises(m.Rejected):
                m.export(settings)

    def test_actual_signed_projected_token_and_binding_negative_cases(self):
        settings, private, bundle, pod, sa = fixture()
        keys = m.public_keys(bundle['jwks'])
        subject = settings['roles']['fencing']['subject']
        good = token(private, settings, pod, sa)
        self.assertEqual(m.verify_token(good, settings, keys, subject, pod, sa, NOW)['kid'], 'test-key-1')
        for changes in [{'aud': ['different']}, {'iss': 'https://wrong.test'}, {'exp': NOW - 1}, {'exp': NOW + 4000}, {'nbf': NOW + 60}, {'sub': subject + '-other'}]:
            with self.assertRaises(m.Rejected):
                m.verify_token(token(private, settings, pod, sa, **changes), settings, keys, subject, pod, sa, NOW)
        with self.assertRaises(m.Rejected):
            m.verify_token(good[:-1] + (b'A' if good[-1:] != b'A' else b'B'), settings, keys, subject, pod, sa, NOW)
        changed_pod = copy.deepcopy(pod)
        changed_pod['metadata']['uid'] = 'different-pod'
        with self.assertRaisesRegex(m.Rejected, 'TOKEN_OBJECT_BINDING'):
            m.verify_token(good, settings, keys, subject, changed_pod, sa, NOW)

    def test_pod_probe_requires_real_projection_and_rechecks_uids(self):
        settings, private, _, pod, sa = fixture()
        good = token(private, settings, pod, sa)
        calls = []
        def kube(context, *args):
            calls.append(args)
            if 'exec' in args:
                self.assertEqual(args[-3:], ('--', 'cat', m.TOKEN_PATH))
                return good
            return m.canonical(pod if 'pod' in args else sa)
        with patch.object(m, 'kubectl', side_effect=kube):
            self.assertEqual(m.pod_token(settings, 'fencing', 'control-1', 'sandbox-system', 'fencing-1', 'fencing')[3], good)
        self.assertEqual(sum('exec' in c for c in calls), 1)
        pod['spec']['volumes'][0]['projected']['sources'][0]['serviceAccountToken']['audience'] = 'other'
        with patch.object(m, 'kubectl', side_effect=kube), self.assertRaisesRegex(m.Rejected, 'POD_TOKEN_PROJECTION'):
            m.pod_token(settings, 'fencing', 'control-1', 'sandbox-system', 'fencing-1', 'fencing')
        self.assertEqual(sum('exec' in c for c in calls), 1)

    def test_rotation_retains_old_key_and_rejects_early_retirement_or_rebinding(self):
        settings, _, first, _, _ = fixture()
        second = copy.deepcopy(first)
        second['jwks']['keys'][0]['kid'] = 'test-key-2'
        old = m.merge_release(first, settings, now=NOW)
        combined = m.merge_release(second, settings, old, now=NOW)
        self.assertEqual(set(m.public_keys(combined['jwks'])), {'test-key-1', 'test-key-2'})
        with self.assertRaisesRegex(m.Rejected, 'KEY_RETIREMENT_TOO_EARLY'):
            m.merge_release(second, settings, combined, ['test-key-1'], NOW + 1)
        lowered = copy.deepcopy(settings)
        lowered.update(max_token_lifetime_seconds=600, clock_skew_seconds=0, cache_seconds=30)
        fresh = copy.deepcopy(second)
        fresh['exported_at'] = NOW + 1000
        fresh['config_sha256'] = m.hashlib.sha256(m.canonical(lowered)).hexdigest()
        for evidence in fresh['control_planes']:
            evidence['flags'] = m.issuer_flags(lowered)
        with self.assertRaisesRegex(m.Rejected, 'KEY_RETIREMENT_TOO_EARLY'):
            m.merge_release(fresh, lowered, combined, ['test-key-1'], NOW + 1000)
        second['exported_at'] = NOW + 4000
        retired = m.merge_release(second, settings, combined, ['test-key-1'], NOW + 4000)
        self.assertEqual(set(m.public_keys(retired['jwks'])), {'test-key-2'})
        rebound = copy.deepcopy(first)
        rebound['jwks']['keys'][0]['n'] = fixture()[2]['jwks']['keys'][0]['n']
        with self.assertRaisesRegex(m.Rejected, 'KID_REBOUND'):
            m.merge_release(rebound, settings, old, now=NOW)

    def test_receiver_atomic_public_files_and_failed_publish_preserves_previous(self):
        settings, _, bundle, _, _ = fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = {'bundle': bundle, 'retire_kids': []}
            m.receive(settings, root, request, NOW)
            before = (root / 'current').readlink()
            self.assertEqual(set(p.name for p in (root / before).iterdir()), {'discovery.json', 'jwks.json', 'manifest.json'})
            request['bundle']['jwks']['keys'][0]['d'] = 'SENSITIVE_PRIVATE_MARKER'
            with self.assertRaises(m.Rejected):
                m.receive(settings, root, request, NOW)
            self.assertEqual((root / 'current').readlink(), before)
            self.assertNotIn(b'SENSITIVE_PRIVATE_MARKER', (root / 'current' / 'jwks.json').read_bytes())

    def test_partial_origin_failure_cannot_report_success_or_delete_old_keys(self):
        settings, _, bundle, _, _ = fixture()
        events = []
        def fingerprint(s, origin=None):
            events.append(('tls', origin))
        def remote(command, request, timeout):
            events.append(('ssh', command))
            self.assertIn('StrictHostKeyChecking=yes', command)
            self.assertEqual(command[-1], m.REMOTE_COMMAND)
            if sum(e[0] == 'ssh' for e in events) == 2:
                raise m.Rejected('COMMAND_FAILED')
            return b'{"published":true}'
        with patch.object(m.time, 'time', return_value=NOW), patch.object(m, 'tls_fingerprint', side_effect=fingerprint), patch.object(m, 'run', side_effect=remote), patch.object(m, 'verify_public') as verify:
            with self.assertRaises(m.Rejected):
                m.publish(settings, bundle, [])
            verify.assert_not_called()
        self.assertEqual([e[0] for e in events], ['tls', 'tls', 'tls', 'ssh', 'ssh'])

    def test_sts_exchange_fixed_binding_and_no_credentials_in_result(self):
        settings, _, _, _, _ = fixture()
        role = settings['roles']['fencing']
        seen = []
        def http(host, path, origin=None, headers=None, method='GET'):
            seen.append((host, path, headers))
            if len(seen) == 1:
                import urllib.parse
                query = urllib.parse.parse_qs(path[2:])
                session = query['RoleSessionName'][0]
                self.assertEqual(query['OIDCToken'], ['SECRET_TOKEN_MARKER'])
                self.arn = role['arn'] + '/' + session
                return {'RequestId': 'request-1', 'AssumedRoleUser': {'Arn': self.arn},
                        'OIDCTokenInfo': {'Issuer': settings['issuer'], 'Subject': role['subject'], 'ClientIds': settings['audience'], 'VerificationInfo': 'Success',
                                          'ExpirationTime': '2030-03-17T17:56:30Z', 'IssuanceTime': '2030-03-17T17:46:30Z'},
                        'Credentials': {'AccessKeyId': 'STS.TEST_ONLY', 'AccessKeySecret': 'SECRET_KEY_MARKER', 'SecurityToken': 'SECRET_STS_MARKER', 'Expiration': '2030-03-17T18:01:30Z'}}
            self.assertEqual(headers['x-acs-action'], 'GetCallerIdentity')
            return {'RequestId': 'request-2', 'IdentityType': 'AssumedRoleUser', 'AccountId': settings['account_id'], 'RoleId': role['role_id'], 'Arn': self.arn}
        # Fixed clock corresponding to the official RFC3339 response shape.
        now = m.timestamp('2030-03-17T17:46:30Z')
        with patch.object(m.time, 'time', return_value=now), patch.object(m, 'https_json', side_effect=http):
            result = m.exchange(settings, role, b'SECRET_TOKEN_MARKER')
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertEqual(len(seen), 2)
        seen.clear()
        def wrong_role(*args, **kwargs):
            result = http(*args, **kwargs)
            if 'RoleId' in result:
                result['RoleId'] = 'unrelated-role'
            return result
        with patch.object(m.time, 'time', return_value=now), patch.object(m, 'https_json', side_effect=wrong_role), self.assertRaisesRegex(m.Rejected, 'STS_CALLER_BINDING'):
            m.exchange(settings, role, b'SECRET_TOKEN_MARKER')

    def test_nginx_exposes_only_public_metadata(self):
        settings, _, _, _, _ = fixture()
        conf = m.nginx(settings)
        self.assertEqual(conf.count('location = '), 2)
        self.assertIn('location / { return 404; }', conf)
        self.assertNotIn('proxy_pass', conf)
        self.assertIn('ssl_reject_handshake on', conf)


if __name__ == '__main__':
    unittest.main()
