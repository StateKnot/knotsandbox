"""Actual Keycloak + HAProxy private administration login chain, using disposable loopback TLS."""
import base64
import hashlib
import http.client
import json
from pathlib import Path
import ssl
import subprocess
import sys
import time
from urllib import request, parse

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from proxy import configuration
from master import configure_master
from verify import Admin,NoRedirect
from proxy_readiness import wait_for_proxy

private=Path(sys.argv[1]);binary=Path(sys.argv[2]).resolve()
assert 'HAProxy version 3.2.25-' in subprocess.run([str(binary),'-v'],capture_output=True,check=True).stdout.decode()
context=ssl.create_default_context(cafile=str(private/'tls.crt'))
opener=request.build_opener(request.ProxyHandler({}),request.HTTPSHandler(context=context),NoRedirect())
for _ in range(120):
    try:
        with opener.open('https://localhost:58443/realms/master/.well-known/openid-configuration',timeout=2) as response:
            if response.status==200:break
    except OSError:time.sleep(1)
else:raise AssertionError('Keycloak TLS not ready')
s={'public_url':'https://localhost:58445','admin_url':'https://localhost:58446','realm':'sandbox',
   'namespace':'sandbox-identity','admin_cidrs':['127.0.0.1/32']}
(private/'frontend.pem').write_bytes((private/'tls.crt').read_bytes()+(private/'tls.key').read_bytes())
config=configuration(s).replace(':8443 ssl crt',':58445 ssl crt').replace(':9443 ssl crt',':58446 ssl crt')
config=config.replace('localhost localhost:443','localhost localhost:443 localhost:58445',1)
# Both test origins use localhost with separate high ports; production has separate origins on 443.
start=config.index('frontend identity_admin')
config=config[:start]+config[start:].replace('localhost localhost:443','localhost localhost:443 localhost:58446',1)
config=config.replace('/run/identity-tls/frontend.pem',str(private/'frontend.pem')).replace('/run/identity-tls/backend-ca.pem',str(private/'tls.crt'))
config=config.replace('keycloak-service.sandbox-identity.svc.cluster.local:8443','127.0.0.1:58443')
(private/'haproxy.cfg').write_text(config)
subprocess.run([str(binary),'-c','-f',str(private/'haproxy.cfg')],check=True,capture_output=True)
process=subprocess.Popen([str(binary),'-db','-f',str(private/'haproxy.cfg')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
def get(path,public=False):
    c=http.client.HTTPSConnection('localhost',58445 if public else 58446,context=context,timeout=10)
    try:
        c.request('GET',path);r=c.getresponse();return r.status,r.read(),dict(r.getheaders())
    finally:c.close()
try:
    wait_for_proxy(lambda: get('/realms/master/.well-known/openid-configuration')[0], process, 'Proxy TLS not ready')
    password=(private/'password').read_text()
    form=parse.urlencode({'client_id':'admin-cli','grant_type':'password','username':'isolated-test-bootstrap','password':password}).encode()
    def login():
        with opener.open(request.Request(s['admin_url']+'/realms/master/protocol/openid-connect/token',data=form),timeout=10) as response:
            return json.load(response)['access_token']
    admin=object.__new__(Admin);admin.base=s['admin_url'];admin.token=login();admin.opener=opener
    assert configure_master(admin,s['admin_url'])
    admin.token=login()
    assert not configure_master(admin,s['admin_url'])
    code,data,_=get('/realms/master/.well-known/openid-configuration');assert code==200
    d=json.loads(data);prefix=s['admin_url']+'/realms/master'
    assert d['issuer']==prefix
    for key,tail in [('authorization_endpoint','auth'),('token_endpoint','token'),('jwks_uri','certs')]:
        assert d[key]==prefix+'/protocol/openid-connect/'+tail, (key,d[key])
    code,console_html,_=get('/admin/master/console/');assert code==200, (code,console_html[:200])
    assert b'https://localhost:58446' in console_html, console_html[:2000]
    assert b'https://localhost:58445' not in console_html, console_html[:2000]
    challenge=base64.urlsafe_b64encode(hashlib.sha256(b'sandbox-test-verifier-long-enough-for-pkce').digest()).rstrip(b'=').decode()
    query=parse.urlencode({'client_id':'security-admin-console','response_type':'code','scope':'openid',
          'redirect_uri':s['admin_url']+'/admin/master/console/','code_challenge':challenge,'code_challenge_method':'S256'})
    code,html,headers=get('/realms/master/protocol/openid-connect/auth?'+query)
    assert code==200 and b'kc-form-login' in html, (code,headers)
    assert b'https://localhost:58446/realms/master/login-actions/' in html
    assert get('/realms/master/.well-known/openid-configuration',public=True)[0]==404
    assert get('/admin/master/console/',public=True)[0]==404
    assert get('/realms/master/protocol/openid-connect/certs')[0]==200
    print('Real Keycloak 26.8.0 + HAProxy 3.2.25: admin console, login form, token, issuer and JWKS remain private; public master/admin blocked; initialization idempotent.')
finally:
    process.terminate();process.wait(timeout=10)
