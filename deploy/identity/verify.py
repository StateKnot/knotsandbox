#!/usr/bin/env python3
"""Read-only realm policy verification via private Admin REST; never sends email."""
import argparse
import json
import ssl
import sys
from urllib import request, error
from urllib.parse import quote

from identity import private_file, require, validate, url
import realm


class Admin:
    def __init__(self, base, token, ca=None):
        url(base, True)
        self.base = base
        self.token = token
        self.opener = request.build_opener(request.ProxyHandler({}),
            request.HTTPSHandler(context=ssl.create_default_context(cafile=ca)), NoRedirect())

    def call(self, path, method='GET', body=None):
        req = request.Request(self.base + path, data=None if body is None else json.dumps(body).encode(),
            method=method, headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
        try:
            with self.opener.open(req, timeout=10) as result:
                data = result.read(2 * 1024 * 1024 + 1)
                require(len(data) <= 2 * 1024 * 1024, 'Admin response too large')
                return json.loads(data) if data else None
        except error.HTTPError as e:
            raise ValueError(f'Admin request refused (HTTP {e.code}); body omitted') from None


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None



def verify_mappers(observed, expected, purpose):
    # IDs assigned by Admin REST are metadata. Every claim mapper/config is exact.
    require(isinstance(observed, list) and len(observed) == len(expected),
            purpose + ' mapper missing or extended')
    for mapper, wanted in zip(observed, expected):
        require(isinstance(mapper, dict) and set(mapper) <= set(wanted) | {'id'}
                and mapper.get('consentRequired') is False
                and {k: v for k, v in mapper.items() if k != 'id'} == wanted,
                purpose + ' mapper drift')
        if 'id' in mapper:
            require(isinstance(mapper['id'], str) and 1 <= len(mapper['id']) <= 256
                    and all(32 <= ord(c) <= 126 for c in mapper['id']),
                    purpose + ' mapper metadata invalid')


def verify_machine_subject(admin, prefix, client, access_scope):
    verify_mappers(client.get('protocolMappers'), [realm.subject_mapper()], 'machine subject')
    identifier = client.get('id')
    require(isinstance(identifier, str) and 1 <= len(identifier) <= 256,
            'machine client server id missing')
    path = prefix + '/clients/' + quote(identifier, safe='')
    defaults = admin.call(path + '/default-client-scopes')
    require(isinstance(defaults, list) and len(defaults) == 1
            and isinstance(defaults[0], dict) and defaults[0].get('name') == 'sandbox:access',
            'machine assigned default scope drift')
    require(admin.call(path + '/optional-client-scopes') == [],
            'machine optional scope drift')
    scope_id = defaults[0].get('id')
    require(isinstance(scope_id, str) and 1 <= len(scope_id) <= 256,
            'machine assigned scope id missing')
    # An inherited mapper must not replace sub, even if the direct mapper is exact.
    mappers = admin.call(prefix + '/client-scopes/' + quote(scope_id, safe='') +
                         '/protocol-mappers/models')
    verify_mappers(mappers, access_scope['protocolMappers'], 'machine access scope')


def verify(admin, settings):
    expected = realm.build(settings)
    prefix = '/admin/realms/' + quote(settings['realm'], safe='')
    actual = admin.call(prefix)
    keys = ['enabled','sslRequired','registrationAllowed','verifyEmail','resetPasswordAllowed',
            'duplicateEmailsAllowed','bruteForceProtected','accessTokenLifespan','defaultSignatureAlgorithm',
            'browserFlow','revokeRefreshToken','refreshTokenMaxReuse','passwordPolicy']
    for key in keys:
        require(actual.get(key) == expected[key], 'realm policy drift: ' + key)
    for key in ['host','port','from','starttls','ssl','auth']:
        require(actual.get('smtpServer', {}).get(key) == expected['smtpServer'][key], 'SMTP policy drift: ' + key)
    require(actual.get('smtpServer', {}).get('password') and actual['smtpServer'].get('user'), 'SMTP credentials missing')
    for name in ['sandbox-password-and-otp', 'sandbox-post-broker-mfa']:
        flows = admin.call(prefix + '/authentication/flows/' + name + '/executions')
        otp = [x for x in flows if x.get('providerId') == 'auth-otp-form']
        require(len(otp) == 1 and otp[0]['requirement'] == 'REQUIRED', 'OTP must be unconditional REQUIRED')
    first = admin.call(prefix + '/authentication/flows/sandbox-first-broker/executions')
    require(len(first) == 1 and first[0].get('providerId') == 'idp-create-user-if-unique' and
            first[0]['requirement'] == 'REQUIRED', 'broker auto-link flow rejected')
    clients = admin.call(prefix + '/clients')
    for c in clients:
        require(not c.get('directAccessGrantsEnabled') and not c.get('implicitFlowEnabled'),
                'password/implicit grant enabled on application realm client')
        if c.get('serviceAccountsEnabled'):
            require(not c.get('publicClient') and not c.get('standardFlowEnabled') and not c.get('fullScopeAllowed'),
                    'machine client permits human flow or implicit full scope')
            verify_machine_subject(admin, prefix, c, expected['clientScopes'][0])
    providers = admin.call(prefix + '/identity-provider/instances')
    if settings['broker']:
        require(len(providers) == 1 and providers[0].get('alias') == 'enterprise', 'broker set drift')
        for key in ['trustEmail','storeToken','firstBrokerLoginFlowAlias','postBrokerLoginFlowAlias']:
            require(providers[0].get(key) == expected['identityProviders'][0][key], 'broker policy drift: ' + key)
    else:
        require(not providers, 'unexpected identity broker')
    return {'realm': settings['realm'], 'policy_verified': True, 'email_delivery_tested': False,
            'interactive_mfa_tested': False, 'ha_tested': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--settings', required=True)
    p.add_argument('--admin-token-file', required=True)
    p.add_argument('--ca-file')
    args = p.parse_args()
    s = validate(json.load(open(args.settings)))
    require(s['mode'] == 'standalone', 'realm verification applies only to standalone identity')
    token = private_file(args.admin_token_file).decode().strip()
    require(token and len(token) <= 16384 and not any(c.isspace() for c in token), 'invalid token file')
    print(json.dumps(verify(Admin(s['admin_url'], token, args.ca_file), s)))


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError) as e:
        print('identity verification failed: ' + (str(e) if isinstance(e, ValueError) else 'I/O failure'), file=sys.stderr)
        sys.exit(1)
