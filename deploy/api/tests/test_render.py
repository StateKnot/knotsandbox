import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
spec = importlib.util.spec_from_file_location('api_renderer', ROOT / 'render.py')
renderer = importlib.util.module_from_spec(spec); spec.loader.exec_module(renderer)


def fixture(full=True):
    ca = (REPO / 'tests/fixtures/admission/server-ca.pem').read_text()
    ref = lambda name, key: {'name': name, 'key': key}
    roles = {purpose: {'arn': 'acs:ram::1234567890123456:role/sbx-test-' + purpose, 'role_id': str(index),
                      'subject': 'system:serviceaccount:sandbox-system:sandbox-api', 'issuer': 'https://oidc.example.test/cluster',
                      'audience': 'sts.aliyuncs.com'} for index, purpose in enumerate(['file-upload', 'file-reader', 'output-reader'], 1)}
    return {'schema_version': 1, 'deployment': 'sbx-test', 'namespace': 'sandbox-system', 'service_name': 'sandbox-api',
            'image': 'registry.example.test/sandbox-service@sha256:' + 'a' * 64,
            'replicas': 3, 'zones': ['cn-hangzhou-h', 'cn-hangzhou-i', 'cn-hangzhou-j'],
            'tls': {'secret_name': 'api-tls-revision1', 'certificate_key': 'tls.crt', 'private_key_key': 'tls.key', 'ca_pem': ca},
            'cursor_secret': ref('api-cursor-revision1', 'keyring.json'),
            'database': {'secret': ref('api-database-revision1', 'url'), 'host': 'database.example.test', 'port': 5432, 'ca_pem': ca},
            'oidc': {'issuer': 'https://identity.example.test/realms/sandbox', 'audience': 'sandbox-api',
                     'jwks_url': 'https://identity.example.test/realms/sandbox/protocol/openid-connect/certs', 'required_scope': 'sandbox:access', 'scope_profile': 'generic-access'},
            'browser': {'public_origin': 'https://console.example.test', 'authorization_url': 'https://identity.example.test/realms/sandbox/protocol/openid-connect/auth',
                        'token_url': 'https://identity.example.test/realms/sandbox/protocol/openid-connect/token', 'client_id': 'sandbox-browser',
                        'scopes': ['openid', 'sandbox:access'], 'client_secret': ref('api-browser-client-revision1', 'client-secret'),
                        'session_key_secret': ref('api-browser-session-revision1', 'keyring.json')} if full else None,
            'metrics': {'endpoint': 'https://metrics.example.test/read', 'ca_pem': ca, 'replicas': ['a', 'b'],
                        'auth': {'type': 'BEARER', 'token_secret': ref('api-metrics-revision1', 'token')}} if full else None,
            'files': {'endpoint': 'https://oss-cn-hangzhou-internal.aliyuncs.com', 'bucket': 'sandbox-files-test', 'kms_key_id': 'file-kms-test', 'max_file_bytes': 104857600} if full else None,
            'output': {'endpoint': 'https://oss-cn-hangzhou-internal.aliyuncs.com', 'bucket': 'sandbox-output-test', 'kms_key_id': 'output-kms-test'} if full else None,
            'storage': {'deployment': 'sbx-test', 'account_id': '1234567890123456', 'region': 'cn-hangzhou', 'workload_roles': roles} if full else None,
            'callers': [{'namespace': 'product-system', 'app_name': 'agent-service'}], 'default_ttl_seconds': 3600, 'max_ttl_seconds': 86400, 'db_max_connections': 20}


class ApiRenderer(unittest.TestCase):
    def test_actual_api_fields_fixed_paths_tls_and_private_init_no_shell(self):
        resources = renderer.render(fixture())['items']
        deployment = next(r for r in resources if r['kind'] == 'Deployment')
        pod = deployment['spec']['template']['spec']; api = pod['containers'][0]
        env = {v['name']: v.get('value', v.get('valueFrom')) for v in api['env']}
        self.assertEqual(env['SANDBOX_PROCESS_POD_UID'], {'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.uid'}})
        self.assertEqual(sum(v['name'] == 'SANDBOX_PROCESS_POD_UID' for v in api['env']), 1)
        self.assertEqual(env['SANDBOX_API_TLS_SERVER_NAME'], 'sandbox-api.sandbox-system.svc.cluster.local')
        self.assertEqual(env['SANDBOX_API_TLS_KEY_FILE'], '/run/api-tls/tls.key')
        self.assertEqual(env['SANDBOX_ALLOW_LOOPBACK_HTTP'], 'false')
        self.assertEqual(env['SANDBOX_OIDC_SCOPE_PROFILE'], 'generic-access')
        self.assertEqual(env['SANDBOX_DATABASE_URL'], {'secretKeyRef': fixture()['database']['secret']})
        self.assertEqual(pod['securityContext']['runAsUser'], 10001); self.assertEqual(pod['securityContext']['fsGroup'], 10001)
        self.assertFalse(pod['automountServiceAccountToken'])
        self.assertEqual(pod['nodeSelector'], {'sandbox.platform/node-pool': 'platform'})
        self.assertEqual(pod['initContainers'][0]['command'], ['/usr/local/bin/sandboxd', 'secrets-init', '--profile', 'browser', '--metrics-auth', 'bearer'])
        self.assertEqual([c['name'] for c in pod['initContainers']], ['api-secrets-init', 'storage-file-upload', 'storage-file-reader', 'storage-output-reader'])
        for init in pod['initContainers']:
            self.assertNotIn('SANDBOX_PROCESS_POD_UID', {v['name'] for v in init.get('env', [])})
            self.assertEqual(init['image'], api['image']); self.assertNotIn('/bin/sh', init['command'])
            self.assertFalse(init['securityContext']['allowPrivilegeEscalation']); self.assertEqual(init['securityContext']['capabilities']['drop'], ['ALL'])
        for probe in ['startupProbe', 'readinessProbe', 'livenessProbe']:
            self.assertEqual(api[probe]['httpGet']['scheme'], 'HTTPS')
        self.assertEqual(pod['terminationGracePeriodSeconds'], 35)
        tls = next(v for v in pod['volumes'] if v['name'] == 'api-tls')['secret']; self.assertEqual(tls['defaultMode'], 0o440)
        private = next(m for m in api['volumeMounts'] if m['name'] == 'api-private'); self.assertTrue(private['readOnly'])
        configs = next(r for r in resources if r['kind'] == 'ConfigMap' and 'browser.json' in r['data'])['data']
        browser = json.loads(configs['browser.json']); self.assertEqual(browser['client_secret_file'], '/run/api-private/private/browser-client-secret')
        files = json.loads(configs['files.json']); self.assertEqual(len(set(files[key] for key in ['api_upload_sts_file', 'read_sts_file', 'gateway_sts_file', 'cleanup_sts_file'])), 4)
        self.assertFalse(any(r['kind'] in ['Secret','Role','ClusterRole','RoleBinding','ClusterRoleBinding'] for r in resources))

    def test_explicit_scope_profile_reaches_api_without_silent_fallback(self):
        value = fixture(); value['oidc']['scope_profile'] = 'action-scopes'
        deployment = next(item for item in renderer.render(value)['items'] if item['kind'] == 'Deployment')
        env = {item['name']: item.get('value') for item in deployment['spec']['template']['spec']['containers'][0]['env']}
        self.assertEqual(env['SANDBOX_OIDC_SCOPE_PROFILE'], 'action-scopes')
        del value['oidc']['scope_profile']
        with self.assertRaises(ValueError): renderer.render(value)
        value['oidc']['scope_profile'] = 'request-selected'
        with self.assertRaises(ValueError): renderer.render(value)

    def test_ha_distribution_service_and_narrow_dependency_policy(self):
        value = fixture(); value['replicas'] = 8
        resources = renderer.render(value)['items']; d = next(r for r in resources if r['kind'] == 'Deployment'); pod = d['spec']['template']['spec']
        self.assertEqual(d['spec']['replicas'], 8)
        self.assertEqual(pod['topologySpreadConstraints'][0]['minDomains'], 2)
        self.assertEqual(pod['topologySpreadConstraints'][0]['whenUnsatisfiable'], 'DoNotSchedule')
        self.assertEqual(pod['affinity']['podAntiAffinity']['requiredDuringSchedulingIgnoredDuringExecution'][0]['topologyKey'], 'kubernetes.io/hostname')
        self.assertEqual(next(r for r in resources if r['kind']=='Service')['spec']['ports'], [{'name':'https','port':8443,'targetPort':'https'}])
        policy = next(r for r in resources if r['kind']=='CiliumNetworkPolicy')['spec']
        self.assertEqual(policy['endpointSelector']['matchLabels']['k8s:sandbox.platform/network-policy'], 'api-v1')
        text = json.dumps(policy); self.assertNotIn('100.100.100.200',text); self.assertNotIn('world',text); self.assertNotIn('0.0.0.0/0',text)
        names = {item['matchName'] for rule in policy['egress'] for item in rule.get('toFQDNs',[])}
        self.assertEqual(names, {'database.example.test','identity.example.test','metrics.example.test','oidc.example.test','sts.cn-hangzhou.aliyuncs.com',
                                 'sandbox-files-test.oss-cn-hangzhou-internal.aliyuncs.com','sandbox-output-test.oss-cn-hangzhou-internal.aliyuncs.com'})

    def test_bearer_only_optional_features_are_absent_not_advertised(self):
        resources = renderer.render(fixture(False))['items']; pod = next(r for r in resources if r['kind']=='Deployment')['spec']['template']['spec']
        self.assertEqual(len(pod['initContainers']),1)
        self.assertEqual(pod['initContainers'][0]['command'][3:],'bearer --metrics-auth none'.split())
        env = {v['name'] for v in pod['containers'][0]['env']}
        self.assertNotIn('SANDBOX_BROWSER_CONFIG_FILE',env); self.assertNotIn('SANDBOX_FILES_CONFIG_FILE',env); self.assertNotIn('SANDBOX_OUTPUT_READ_STS_FILE',env)
        self.assertNotIn('SANDBOX_METRICS_CONFIG_FILE',env)

    def test_basic_metrics_auth_uses_two_independent_private_files(self):
        value=fixture(); value['metrics']['auth']={'type':'BASIC','username_secret':{'name':'metrics-user','key':'username'},'password_secret':{'name':'metrics-password','key':'password'}}
        resources=renderer.render(value)['items']; c=next(r for r in resources if r['kind']=='ConfigMap' and 'metrics.json' in r['data'])
        self.assertEqual(json.loads(c['data']['metrics.json'])['auth'], {'type':'BASIC','username_file':'/run/api-private/private/metrics-username','password_file':'/run/api-private/private/metrics-password'})

    def test_unknown_draft_secrets_aliases_types_and_unsafe_endpoints_rejected(self):
        mutations=[lambda x:x.update({'restore':{}}),lambda x:x.update({'automation':{}}),lambda x:x.update({'replicas':True}),lambda x:x.update({'replicas':1}),lambda x:x.update({'zones':['cn-hangzhou-h']}),
                   lambda x:x.update({'image':'product:latest'}),lambda x:x['tls'].update({'server_name':'wrong'}),lambda x:x['oidc'].update({'issuer':'http://identity.example.test'}),
                   lambda x:x['browser'].update({'public_origin':'https://console.example.test/?state=x'}),lambda x:x['browser']['client_secret'].update({'name':x['cursor_secret']['name']}),
                   lambda x:x['files'].update({'max_file_bytes':104857601}),lambda x:x['files'].update({'endpoint':'https://oss-cn-beijing-internal.aliyuncs.com'}),
                   lambda x:x['database'].update({'host':'postgres.sandbox-system.svc.cluster.local'}),
                   lambda x:x['oidc'].update({'jwks_url':'https://identity.sandbox-system.svc/certs'}),
                   lambda x:x['storage']['workload_roles']['file-upload'].update({'subject':'system:serviceaccount:sandbox-system:other'}),
                   lambda x:x['callers'][0].update({'namespace':'sbx-untrusted'}),lambda x:x['metrics']['auth'].update({'token':'STATIC-SECRET'}),lambda x:x.update({'namespace':'default'})]
        for mutate in mutations:
            value=fixture(); mutate(value)
            with self.assertRaises((ValueError,TypeError)):renderer.render(value)

    def test_duplicate_input_and_oversize_input_fail_before_render(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'inputs.json'; path.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaises(ValueError):renderer.load(path)
            path.write_bytes(b'x'*262145)
            with self.assertRaises(ValueError):renderer.load(path)


if __name__ == '__main__': unittest.main()
