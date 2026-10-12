import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import identity
import proxy
import realm
import verify as realm_verify
import browser_client


def fixture():
    s = json.loads((identity.ROOT/'settings.example.json').read_text())
    s['proxy']['image'] = 'docker.io/library/haproxy:3.2.25-alpine@sha256:' + 'a'*64
    return s


class IdentityTests(unittest.TestCase):
    def test_pinned_official_resources_and_real_crd_schema(self):
        identity.verify_vendor()
        rendered = identity.render(fixture())
        spec = rendered['keycloak.json']['items'][0]['spec']
        self.assertEqual(spec['instances'], 3)
        self.assertIn('@sha256:', spec['image'])
        self.assertFalse(spec['http']['httpEnabled'])
        self.assertFalse(spec['ingress']['enabled'])
        self.assertFalse(spec['networkPolicy']['enabled'])  # Separate explicit rules; no additive allow-all.
        self.assertFalse(spec['automountServiceAccountToken'])
        options = {x['name']: x['value'] for x in spec['additionalOptions']}
        self.assertEqual(options['db-tls-mode'], 'verify-server')
        self.assertEqual(options['cache-embedded-mtls-enabled'], 'true')
        self.assertNotIn('unsupported', spec)
        for obj in rendered['operator.json']['items']:
            if obj['kind'] == 'Deployment':
                self.assertIn('@sha256:', obj['spec']['template']['spec']['containers'][0]['image'])
            for subject in obj.get('subjects', []):
                if subject['kind'] == 'ServiceAccount':
                    self.assertEqual(subject['namespace'], 'sandbox-identity')

    def test_no_credentials_or_bootstrap_users_in_rendered_documents(self):
        rendered = identity.render(fixture())
        text = json.dumps(rendered)
        self.assertNotIn('/secure/', text)
        self.assertNotIn('start-dev', text)
        self.assertEqual(rendered['initial-realm.json']['spec']['realm']['users'], [])
        self.assertEqual([c['clientId'] for c in rendered['initial-realm.json']['spec']['realm']['clients']], ['admin-cli'])
        self.assertNotIn('Secret', [x['kind'] for x in rendered['operator.json']['items']])

    def test_mfa_is_unconditional_and_machine_flows_are_separate(self):
        r = realm.build(fixture())
        otp = next(f for f in r['authenticationFlows'] if f['alias'] == 'sandbox-password-and-otp')
        self.assertEqual([(e['authenticator'], e['requirement']) for e in otp['authenticationExecutions']],
                         [('auth-username-password-form', 'REQUIRED'), ('auth-otp-form', 'REQUIRED')])
        self.assertTrue(r['verifyEmail'])
        self.assertTrue(r['resetPasswordAllowed'])
        self.assertEqual(r['smtpServer']['starttls'], 'true')
        c = realm.machine_client('billing-service')
        self.assertTrue(c['serviceAccountsEnabled'])
        self.assertEqual(c['clientAuthenticatorType'], 'client-jwt')
        self.assertFalse(c['directAccessGrantsEnabled'])
        self.assertFalse(c['standardFlowEnabled'])
        self.assertFalse(c['implicitFlowEnabled'])

    def test_machine_templates_pin_the_same_subject_contract_without_weakening_auth(self):
        production = realm.machine_client('billing-service')
        development = json.loads((identity.ROOT.parent/'keycloak/realm.template.json').read_text())['clients'][0]
        browser = browser_client.build('browser', 'https://console.example.test')
        self.assertEqual(production['protocolMappers'], browser['protocolMappers'])
        self.assertEqual(development['protocolMappers'], production['protocolMappers'])
        self.assertEqual(production['clientAuthenticatorType'], 'client-jwt')
        self.assertEqual(production['attributes']['token.endpoint.auth.signing.alg'], 'RS256')
        self.assertEqual(production['defaultClientScopes'], ['sandbox:access'])
        self.assertEqual(production['optionalClientScopes'], [])
        self.assertNotIn('secret', production)

    def test_machine_subject_mapper_rejects_missing_overrides_and_boolean_type_drift(self):
        expected = [realm.subject_mapper()]
        with_id = copy.deepcopy(expected)
        with_id[0]['id'] = 'server-assigned-id'
        realm_verify.verify_mappers(with_id, expected, 'machine subject')
        cases = [None, [], expected + copy.deepcopy(expected)]
        for change in [('protocolMapper', 'oidc-pairwise-sub-mapper'), ('consentRequired', 0),
                       ('config', {'access.token.claim': 'false', 'introspection.token.claim': 'true'}),
                       ('config', {'access.token.claim': 'true', 'introspection.token.claim': 'true',
                                   'claim.name': 'sub', 'claim.value': 'forged'}), ('unknown', 'field')]:
            changed = copy.deepcopy(expected); changed[0][change[0]] = change[1]; cases.append(changed)
        for value in cases:
            with self.subTest(shape=value):
                with self.assertRaises(ValueError):
                    realm_verify.verify_mappers(value, expected, 'machine subject')

    def test_machine_assigned_scopes_cannot_inherit_subject_override(self):
        prefix = '/admin/realms/sandbox'
        scope = realm.build(fixture())['clientScopes'][0]
        client = realm.machine_client('billing-service') | {'id': 'machine-server-id'}
        class ScopeAdmin:
            def __init__(self):
                self.defaults = [{'id': 'access-id', 'name': 'sandbox:access'}]
                self.optional = []
                self.mappers = copy.deepcopy(scope['protocolMappers'])
                self.calls = []
            def call(self, path):
                self.calls.append(path)
                if path.endswith('/default-client-scopes'): return self.defaults
                if path.endswith('/optional-client-scopes'): return self.optional
                if path == prefix + '/client-scopes/access-id/protocol-mappers/models': return self.mappers
                raise AssertionError('Unexpected Admin read')
        admin = ScopeAdmin()
        realm_verify.verify_machine_subject(admin, prefix, client, scope)
        self.assertEqual(len(admin.calls), 3)
        for change in ('missing', 'extra-default', 'optional', 'sub-override'):
            admin = ScopeAdmin()
            if change == 'missing': admin.defaults = []
            if change == 'extra-default': admin.defaults.append({'id': 'basic-id', 'name': 'basic'})
            if change == 'optional': admin.optional.append({'id': 'other', 'name': 'other'})
            if change == 'sub-override': admin.mappers.append({'name': 'forged-sub',
                'protocol': 'openid-connect', 'protocolMapper': 'oidc-hardcoded-claim-mapper',
                'consentRequired': False, 'config': {'claim.name': 'sub', 'claim.value': 'forged',
                                                    'access.token.claim': 'true'}})
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    realm_verify.verify_machine_subject(admin, prefix, client, scope)

    def test_machine_audience_destinations_match_native_import_and_reject_drift(self):
        scope = realm.build(fixture())['clientScopes'][0]
        development = json.loads((identity.ROOT.parent/'keycloak/realm.template.json').read_text())['clientScopes'][0]
        native_config = {'included.custom.audience': 'sandbox-api', 'id.token.claim': 'false',
                         'access.token.claim': 'true', 'userinfo.token.claim': 'false',
                         'introspection.token.claim': 'true'}
        self.assertEqual(scope['protocolMappers'][0]['config'], native_config)
        self.assertEqual(development['protocolMappers'][0]['config'], native_config)
        observed = copy.deepcopy(scope['protocolMappers'])
        observed[0]['id'] = 'native-mapper-id'
        realm_verify.verify_mappers(observed, scope['protocolMappers'], 'machine access scope')
        for key, value in [('userinfo.token.claim', 'true'), ('introspection.token.claim', 'false'),
                           ('userinfo.token.claim', None), ('unknown.claim', 'false')]:
            changed = copy.deepcopy(observed)
            if value is None: changed[0]['config'].pop(key)
            else: changed[0]['config'][key] = value
            with self.subTest(claim=key, value=value):
                with self.assertRaises(ValueError):
                    realm_verify.verify_mappers(changed, scope['protocolMappers'], 'machine access scope')

    def test_oidc_broker_never_automatically_links_by_email(self):
        s = fixture()
        s['broker'] = {'issuer': 'https://sso.example.com', 'authorization_url': 'https://sso.example.com/auth',
                       'token_url': 'https://sso.example.com/token', 'jwks_url': 'https://sso.example.com/keys',
                       'client_id': 'sandbox-broker'}
        s['secret_files']['keycloak-broker'] = {'secret': '/secure/broker-secret'}
        r = identity.render(s)['initial-realm.json']['spec']['realm']
        self.assertFalse(r['identityProviders'][0]['trustEmail'])
        self.assertEqual(r['identityProviders'][0]['postBrokerLoginFlowAlias'], 'sandbox-post-broker-mfa')
        flow = next(f for f in r['authenticationFlows'] if f['alias'] == 'sandbox-first-broker')
        self.assertEqual(flow['authenticationExecutions'][0]['authenticator'], 'idp-create-user-if-unique')
        self.assertNotIn('idp-auto-link', json.dumps(r))

    def test_missing_unsafe_configuration_fails_before_render(self):
        cases = []
        for key in ('smtp', 'secret_files', 'admin_cidrs', 'apiserver_cidrs'):
            s = fixture(); del s[key]; cases.append(s)
        for key, value in [('public_url', 'http://login.example.com'), ('admin_url', 'https://login.example.com'),
                           ('proxy_cidrs', ['0.0.0.0/0']), ('admin_cidrs', ['8.8.8.8/32']),
                           ('zones', ['same', 'same', 'same']), ('realm', 'master')]:
            s = fixture(); s[key] = value; cases.append(s)
        for s in cases:
            with self.subTest(s=s):
                with self.assertRaises(ValueError): identity.render(s)

    def test_external_contract_has_no_keycloak_or_runtime_http(self):
        s = json.loads((identity.ROOT/'external.example.json').read_text())
        generated = identity.render(s)
        self.assertEqual(set(generated), {'auth.json'})
        self.assertFalse(generated['auth.json']['allow_loopback_http'])
        self.assertEqual(generated['auth.json']['scope_profile'], 'ACTION_SCOPES')
        for key, value in [('allowed_algorithms', ['HS256']), ('max_token_lifetime_seconds', 3600),
                           ('token_profile', 'id_token'), ('scope_profile', 'unknown'), ('jwks_url', 'http://metadata/keys')]:
            bad = copy.deepcopy(s); bad[key] = value
            with self.assertRaises(ValueError): identity.render(bad)

    def test_network_default_deny_and_exact_egress(self):
        docs = identity.render(fixture())['network.json']['items']
        self.assertEqual(docs[0]['spec']['policyTypes'], ['Ingress','Egress'])
        self.assertNotIn('0.0.0.0/0', json.dumps(docs))
        ingress = docs[1]['spec']['ingress']
        self.assertEqual(ingress[0]['from'][0]['podSelector']['matchLabels'], fixture()['proxy_labels'])
        self.assertEqual(ingress[0]['from'][0]['namespaceSelector']['matchLabels']['kubernetes.io/metadata.name'],
                         fixture()['proxy_namespace'])
        self.assertNotIn('matchPattern', json.dumps(docs[-1]['spec']['egress'][1:]))

    def test_proxy_filters_public_admin_master_and_forged_forwarding(self):
        p = proxy.configuration(fixture())
        public = p.split('frontend identity_public')[1].split('frontend identity_admin')[0]
        self.assertIn('path_beg /realms/sandbox/ /resources/', public)
        self.assertNotIn('path_beg /realms/', public.replace('path_beg /realms/sandbox/', ''))
        self.assertIn('http-request del-header X-Forwarded-For', public)
        self.assertIn('http-request set-header X-Forwarded-For %[src]', public)
        self.assertIn('unless { src 10.20.0.0/24 }', p)
        self.assertIn('verify required', p)
        self.assertIn('verifyhost login.example.com', p)
        self.assertNotIn('verify none', p)
        self.assertNotIn(':9000', p)

    def test_secret_files_are_private_bounded_and_never_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory)/'secret'; file.write_text('value'); file.chmod(0o600)
            self.assertEqual(identity.private_file(file), b'value')
            file.chmod(0o644)
            with self.assertRaises(ValueError): identity.private_file(file)
            link = Path(directory)/'link'; link.symlink_to(file)
            with self.assertRaises(ValueError): identity.private_file(link)

    def test_upgrade_does_not_submit_realm_or_rotate_secrets(self):
        s = fixture()
        calls = []
        def mock(args, payload=None, capture=True):
            calls.append((args,payload))
            return b''
        def secret(path):
            if path.endswith('db-username'): return b'keycloak_prod'
            if path.endswith('bootstrap-username'): return b'initial-operator'
            return b'x' * 32
        with patch.object(identity,'private_file',return_value=b'validated-test-ca'), patch('proxy_resources.install'), patch('ssl.create_default_context'), patch('ingress.preflight'), patch('ingress.verify_namespace_roles'), patch('ingress.verify_endpoints'), patch.object(identity, 'kubectl', side_effect=mock), patch.object(identity, 'validate_secret_material', return_value={name: {key: secret(path) for key, path in files.items()} for name, files in s['secret_files'].items()}):
            identity.apply(s)
        self.assertFalse(any(payload.get('kind') == 'KeycloakRealmImport' for _,payload in calls if payload))
        self.assertTrue(any(args[0] == 'create' and payload and payload.get('kind') == 'Secret' for args,payload in calls))
        self.assertFalse(any(args[0] == 'apply' and payload and payload.get('kind') == 'Secret' for args,payload in calls))


if __name__ == '__main__': unittest.main()
