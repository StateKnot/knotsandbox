"""Isolated Keycloak 26.8.0 TLS test; invoked only by live-test.sh, no shared DB."""
import json
import base64
import subprocess
from pathlib import Path
import ssl
import sys
import time
from urllib import request, parse
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import identity
import realm
from verify import Admin, NoRedirect, verify

base = 'https://localhost:58443'
private = Path(sys.argv[1])
password = (private/'password').read_text()
opener = request.build_opener(request.ProxyHandler({}),
    request.HTTPSHandler(context=ssl.create_default_context(cafile=str(private/'tls.crt'))), NoRedirect())
for _ in range(120):
    try:
        with opener.open(base+'/realms/master/.well-known/openid-configuration', timeout=2) as response:
            if response.status == 200: break
    except OSError: time.sleep(1)
else: raise RuntimeError('isolated TLS identity server did not become ready')
body = parse.urlencode({'client_id':'admin-cli','grant_type':'password',
    'username':'isolated-test-bootstrap','password':password}).encode()
with opener.open(request.Request(base+'/realms/master/protocol/openid-connect/token', data=body), timeout=10) as response:
    token = json.load(response)['access_token']
# Production Admin constructor rejects loopback nonstandard origins. Only this test binds its dedicated TLS port.
admin = object.__new__(Admin)
admin.base = base; admin.token = token; admin.opener = opener
version = admin.call('/admin/serverinfo')['systemInfo']['version']
assert version == '26.8.0', 'test requires exact locked Keycloak version'


def verified_machine_claims(access_token, expected_issuer, expected_subject):
    # This is a locked live-test check, not an alternative product authenticator.
    # The TLS-authenticated JWKS selects the real Keycloak RS256 verification key.
    assert isinstance(access_token, str) and len(access_token) <= 16384
    parts = access_token.split('.')
    assert len(parts) == 3 and all(parts)
    def decode(segment):
        return base64.b64decode(segment + '=' * (-len(segment) % 4), altchars=b'-_', validate=True)
    header = json.loads(decode(parts[0]))
    assert header.get('alg') == 'RS256' and header.get('typ') == 'JWT'
    assert isinstance(header.get('kid'), str) and header['kid']
    with opener.open(expected_issuer + '/protocol/openid-connect/certs', timeout=10) as response:
        raw = response.read(128 * 1024 + 1)
    assert len(raw) <= 128 * 1024
    keys = json.loads(raw)['keys']
    assert isinstance(keys, list) and len(keys) <= 32
    matching = [key for key in keys if key.get('kid') == header['kid']]
    assert len(matching) == 1
    key = matching[0]
    assert key.get('kty') == 'RSA' and key.get('alg') == 'RS256' and key.get('use') == 'sig'
    assert isinstance(key.get('x5c'), list) and key['x5c']
    certificate = base64.b64decode(key['x5c'][0], validate=True)
    public_key = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-pubkey', '-noout'],
        input=certificate, capture_output=True, check=True, timeout=10).stdout
    # Only the public key/signature use short-lived files; no token/claims are written.
    public_path = private / 'machine-access-public.pem'
    signature_path = private / 'machine-access-signature.bin'
    try:
        public_path.write_bytes(public_key)
        signature_path.write_bytes(decode(parts[2]))
        subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(public_path),
            '-signature', str(signature_path)], input=(parts[0] + '.' + parts[1]).encode('ascii'),
            capture_output=True, check=True, timeout=10)
    finally:
        public_path.unlink(missing_ok=True)
        signature_path.unlink(missing_ok=True)
    claims = json.loads(decode(parts[1]))
    assert claims.get('iss') == expected_issuer and claims.get('sub') == expected_subject
    assert isinstance(claims['sub'], str) and str(uuid.UUID(claims['sub'])) == claims['sub']
    assert uuid.UUID(claims['sub']).int != 0
    assert type(claims.get('iat')) is int and type(claims.get('exp')) is int
    assert 0 < claims['exp'] - claims['iat'] <= 300
    assert claims['iat'] <= time.time() < claims['exp']
    if 'nbf' in claims:
        assert type(claims['nbf']) is int and claims['nbf'] <= time.time()
    return claims

for broker in (False, True):
    s = json.loads((identity.ROOT/'settings.example.json').read_text())
    s['realm'] = 'sandbox-identity-test-' + uuid.uuid4().hex
    if broker:
        s['broker'] = {'issuer':'https://upstream.example.com','authorization_url':'https://upstream.example.com/auth',
            'token_url':'https://upstream.example.com/token','jwks_url':'https://upstream.example.com/keys','client_id':'sandbox-test'}
    r = realm.build(s)
    r['smtpServer']['user'] = 'test-no-send'; r['smtpServer']['password'] = 'test-no-send'
    if broker: r['identityProviders'][0]['config']['clientSecret'] = 'test-no-connect'
    admin.call('/admin/realms', 'POST', r)
    try:
        # Native private_key_jwt machine authentication uses a stored public certificate, no network JWKS fetch.
        client=realm.machine_client('isolated-machine')
        client['attributes']['jwt.credential.certificate']=''.join(line for line in (private/'tls.crt').read_text().splitlines() if not line.startswith('-----'))
        admin.call('/admin/realms/'+s['realm']+'/clients','POST',client)
        actual_clients = admin.call('/admin/realms/' + s['realm'] + '/clients?clientId=isolated-machine')
        assert len(actual_clients) == 1 and actual_clients[0]['clientId'] == 'isolated-machine'
        service_user = admin.call('/admin/realms/' + s['realm'] + '/clients/' +
                                  actual_clients[0]['id'] + '/service-account-user')
        assert service_user['enabled'] and service_user['username'] == 'service-account-isolated-machine'
        endpoint=base+'/realms/'+s['realm']+'/protocol/openid-connect/token'
        def b64(data):return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
        now=int(time.time())
        signing=b64(json.dumps({'alg':'RS256','typ':'JWT'}).encode())+'.'+b64(json.dumps({
            'iss':'isolated-machine','sub':'isolated-machine','aud':endpoint,'iat':now,'exp':now+60,'jti':str(uuid.uuid4())}).encode())
        signature=subprocess.run(['openssl','dgst','-sha256','-sign',str(private/'tls.key')],input=signing.encode(),capture_output=True,check=True).stdout
        assertion=signing+'.'+b64(signature)
        fields={'grant_type':'client_credentials','client_id':'isolated-machine',
            'client_assertion_type':'urn:ietf:params:oauth:client-assertion-type:jwt-bearer','client_assertion':assertion}
        with opener.open(request.Request(endpoint,data=parse.urlencode(fields).encode()),timeout=10) as response:
            issued=json.load(response)
        claims = verified_machine_claims(issued['access_token'], base + '/realms/' + s['realm'], service_user['id'])
        assert claims['typ']=='Bearer' and claims['azp']=='isolated-machine' and claims['exp']-claims['iat']<=300
        assert s['audience'] in ([claims['aud']] if isinstance(claims['aud'],str) else claims['aud'])
        assert 'sandbox:access' in claims['scope'].split()
        assert issued['token_type'].lower()=='bearer' and 'id_token' not in issued
        result = verify(admin, s)
        assert result['policy_verified']
        # Demonstrate that a second initial realm creation cannot overwrite policy/users.
        try: admin.call('/admin/realms','POST', r)
        except ValueError as e: assert '409' in str(e)
        else: raise AssertionError('duplicate realm was overwritten')
        assert verify(admin, s)['policy_verified']
    finally:
        admin.call('/admin/realms/'+s['realm'], 'DELETE')
print('Keycloak 26.8.0 TLS: standalone + broker realm import/policy, real private_key_jwt machine tokens with TLS-JWKS verified signature and exact service-account sub, and duplicate-create protection passed; no emails/users/upstream calls.')
