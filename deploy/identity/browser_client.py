#!/usr/bin/env python3
"""Render or verify the exact confidential BFF client; never writes an IdP."""
import argparse
import json
import sys
from urllib.parse import quote, urlsplit
from identity import private_file, require, url
from verify import Admin


def build(client_id, origin):
    url(origin, True)
    parsed = urlsplit(origin)
    require(parsed.path == '' and not parsed.query and not parsed.fragment,
            'browser origin must be an exact HTTPS origin without a path')
    require(1 <= len(client_id) <= 256 and not any(ord(c) < 32 for c in client_id),
            'invalid browser client identifier')
    return {'clientId': client_id, 'protocol': 'openid-connect', 'enabled': True,
            'publicClient': False, 'clientAuthenticatorType': 'client-secret',
            'serviceAccountsEnabled': False, 'standardFlowEnabled': True,
            'implicitFlowEnabled': False, 'directAccessGrantsEnabled': False,
            'fullScopeAllowed': False, 'redirectUris': [origin + '/auth/callback'],
            'webOrigins': [], 'defaultClientScopes': ['sandbox:access'],
            'optionalClientScopes': [],
            # Keycloak 25+ moves access-token sub to the basic scope. Explicit
            # default scopes replace that link, so pin the actual subject mapper
            # on this client instead of depending on an editable realm default.
            'protocolMappers': [{'name': 'sandbox-subject', 'protocol': 'openid-connect',
                'protocolMapper': 'oidc-sub-mapper', 'consentRequired': False,
                'config': {'access.token.claim': 'true', 'introspection.token.claim': 'true'}}],
            'attributes': {'pkce.code.challenge.method': 'S256',
                           'access.token.lifespan': '300',
                           'id.token.signed.response.alg': 'RS256',
                           'client.session.idle.timeout': '1800',
                           'client.session.max.lifespan': '28800'}}


def verify(actual, expected):
    for key, value in expected.items():
        if key == 'protocolMappers':
            observed = actual.get(key, [])
            require(isinstance(observed, list) and len(observed) == len(value),
                    'browser client subject mapper missing or extended')
            # Admin REST adds a server-generated mapper id. It is metadata,
            # never a reason to ignore a changed mapper provider or config.
            for mapper, wanted in zip(observed, value):
                require(isinstance(mapper, dict) and set(mapper) <= set(wanted) | {'id'}
                        and {k: v for k, v in mapper.items() if k != 'id'} == wanted,
                        'browser client subject mapper drift')
        elif key == 'attributes':
            for attribute, wanted in value.items():
                require(actual.get('attributes', {}).get(attribute) == wanted,
                        'browser client policy drift: ' + attribute)
        else:
            require(actual.get(key) == value, 'browser client policy drift: ' + key)
    require(not actual.get('authorizationServicesEnabled') and
            not actual.get('attributes', {}).get('request.uris'),
            'unexpected browser authorization extension')
    return {'client_id': expected['clientId'], 'policy_verified': True,
            'interactive_login_tested': False, 'secret_rotation_tested': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['render', 'verify'])
    parser.add_argument('--client-id', required=True)
    parser.add_argument('--public-origin', required=True)
    parser.add_argument('--admin-url')
    parser.add_argument('--realm')
    parser.add_argument('--admin-token-file')
    parser.add_argument('--ca-file')
    args = parser.parse_args()
    expected = build(args.client_id, args.public_origin)
    if args.mode == 'render':
        print(json.dumps(expected, indent=2))
        return
    require(args.admin_url and args.realm and args.admin_token_file,
            'verification requires private Admin endpoint, realm and token file')
    token = private_file(args.admin_token_file).decode().strip()
    require(token and len(token) <= 16384 and not any(c.isspace() for c in token),
            'invalid administrator token')
    admin = Admin(args.admin_url, token, args.ca_file)
    clients = admin.call('/admin/realms/' + quote(args.realm, safe='') +
                         '/clients?clientId=' + quote(args.client_id, safe=''))
    require(len(clients) == 1 and clients[0]['clientId'] == args.client_id,
            'exact browser client does not exist')
    print(json.dumps(verify(clients[0], expected)))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError):
        print('browser client configuration rejected; secret values omitted', file=sys.stderr)
        sys.exit(1)
