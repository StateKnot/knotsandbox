import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import browser_client


class BrowserClientTests(unittest.TestCase):
    def test_confidential_client_is_exact_and_has_no_embedded_secret(self):
        client = browser_client.build('sandbox-browser', 'https://console.example.test')
        self.assertNotIn('secret', client)
        self.assertEqual(client['redirectUris'], ['https://console.example.test/auth/callback'])
        self.assertTrue(browser_client.verify(client, client)['policy_verified'])
        mapper = client['protocolMappers'][0]
        self.assertEqual(mapper['protocolMapper'], 'oidc-sub-mapper')
        self.assertEqual(mapper['config']['access.token.claim'], 'true')
        actual = copy.deepcopy(client)
        actual['protocolMappers'][0]['id'] = 'server-generated-id'
        self.assertTrue(browser_client.verify(actual, client)['policy_verified'])

    def test_public_password_wildcard_and_pkce_drift_are_rejected(self):
        expected = browser_client.build('sandbox-browser', 'https://console.example.test')
        for key, value in [('publicClient', True), ('directAccessGrantsEnabled', True),
                           ('redirectUris', ['https://console.example.test/*']),
                           ('serviceAccountsEnabled', True)]:
            actual = copy.deepcopy(expected)
            actual[key] = value
            with self.assertRaises(ValueError):
                browser_client.verify(actual, expected)
        actual = copy.deepcopy(expected)
        actual['attributes']['pkce.code.challenge.method'] = 'plain'
        with self.assertRaises(ValueError):
            browser_client.verify(actual, expected)

    def test_non_origin_and_http_are_rejected(self):
        for origin in ['http://127.0.0.1', 'https://console.example.test/',
                       'https://console.example.test/other', 'https://user:pass@console.example.test',
                       'https://console.example.test?callback=other']:
            with self.assertRaises(ValueError):
                browser_client.build('browser', origin)

    def test_missing_disabled_pairwise_or_extra_subject_mappers_rejected(self):
        expected = browser_client.build('browser', 'https://console.example.test')
        for mutate in [lambda x: x.pop('protocolMappers'),
                       lambda x: x['protocolMappers'][0]['config'].update({'access.token.claim': 'false'}),
                       lambda x: x['protocolMappers'][0].update({'protocolMapper': 'oidc-pairwise-sub-mapper'}),
                       lambda x: x['protocolMappers'].append(copy.deepcopy(x['protocolMappers'][0]))]:
            actual = copy.deepcopy(expected); mutate(actual)
            with self.assertRaises(ValueError):
                browser_client.verify(actual, expected)
