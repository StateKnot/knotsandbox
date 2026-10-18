"""Exercise the rendered contract using an actual reviewed HAProxy binary and TLS on both hops."""
import http.client
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import proxy
from proxy_readiness import wait_for_proxy

binary = Path(sys.argv[1]).resolve()
version = subprocess.run([str(binary),'-v'],capture_output=True,check=True).stdout.decode()
assert 'HAProxy version 3.2.25-' in version, 'exact reviewed HAProxy version required'

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body=json.dumps({'path':self.path,'headers':dict(self.headers)}).encode()
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*args): pass

with tempfile.TemporaryDirectory() as directory:
    p=Path(directory)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
        '-addext','subjectAltName=DNS:localhost,DNS:admin.localhost','-keyout',str(p/'tls.key'),'-out',str(p/'tls.crt')],
        capture_output=True,check=True)
    (p/'frontend.pem').write_bytes((p/'tls.crt').read_bytes()+(p/'tls.key').read_bytes())
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(p/'tls.crt',p/'tls.key')
    server.socket=tls.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    s={'public_url':'https://localhost','admin_url':'https://admin.localhost','realm':'sandbox',
       'namespace':'sandbox-identity','admin_cidrs':['127.0.0.1/32']}
    config=proxy.configuration(s).replace(':8443 ssl crt',':58445 ssl crt').replace(':9443 ssl crt',':58446 ssl crt')
    config=config.replace('/run/identity-tls/frontend.pem',str(p/'frontend.pem')).replace('/run/identity-tls/backend-ca.pem',str(p/'tls.crt'))
    config=config.replace('keycloak-service.sandbox-identity.svc.cluster.local:8443',f'127.0.0.1:{server.server_port}')
    (p/'haproxy.cfg').write_text(config)
    subprocess.run([str(binary),'-c','-f',str(p/'haproxy.cfg')],capture_output=True,check=True)
    process=subprocess.Popen([str(binary),'-db','-f',str(p/'haproxy.cfg')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    context=ssl.create_default_context(cafile=str(p/'tls.crt'))
    def get(path,admin=False,headers=None,client_context=context):
        connection=http.client.HTTPSConnection('localhost',58446 if admin else 58445,context=client_context,timeout=5)
        try:
            connection.request('GET',path,headers={'Host':'admin.localhost' if admin else 'localhost'} | (headers or {}))
            response=connection.getresponse();return response.status,response.read()
        finally:connection.close()
    try:
        wait_for_proxy(lambda: get('/realms/sandbox/.well-known/openid-configuration')[0], process, 'TLS proxy did not become ready')
        status,body=get('/realms/sandbox/.well-known/openid-configuration',headers={'X-Forwarded-For':'1.2.3.4','Forwarded':'host=evil',
                    'X-Forwarded-Host':'evil.example','X-Original-URL':'/admin','X-Forwarded-Access-Token':'sensitive-marker'})
        assert status==200
        observed=json.loads(body)['headers']
        assert observed['x-forwarded-for']=='127.0.0.1' and observed['x-forwarded-host']=='localhost'
        assert 'forwarded' not in observed and 'x-forwarded-access-token' not in observed
        for path in ['/admin/','/realms/master/.well-known/openid-configuration','/health','/realms/sandbox/../../admin/',
                     '/realms/sandbox/%2e%2e/%2e%2e/admin/','/realms/sandbox/..;/../admin/', '/realms/sandbox/\\..\\..\\admin/']:
            assert get(path)[0] in (400,403,404), path
        assert get('/admin/',admin=True)[0]==200
        assert get('/realms/sandbox/',headers={'Host':'admin.localhost'})[0]==400
        assert get('/realms/sandbox/',headers={'Host':'untrusted.example'})[0]==400
        print('HAProxy 3.2.25: native syntax, verified TLS on both hops, private admin, public path filtering, and forged forwarding checks passed.')

        opaque_marker='opaque-readiness-do-not-disclose'
        negative_path='/realms/sandbox/?private='+opaque_marker
        failure_message='TLS proxy did not become ready'
        def expect_diagnostics(get_status, http, transport, status, reason, process_state):
            try:
                wait_for_proxy(get_status, process, failure_message)
            except AssertionError as error:
                diagnostic=str(error)
            else:
                raise AssertionError('negative readiness unexpectedly succeeded')
            expected=(failure_message+f': attempts=50 http={http} transport={transport} '
                      f'last_status={status} last_transport={reason} process={process_state}')
            assert opaque_marker not in diagnostic, 'readiness diagnostic leaked opaque input'
            assert diagnostic==expected, 'missing fixed readiness diagnostics: '+diagnostic

        disallowed=lambda: get(negative_path,headers={'Host':opaque_marker+'.invalid'})[0]
        assert disallowed()==400 and process.poll() is None
        print('IDENTITY_PROXY_READINESS_REAL_HTTP_400_OBSERVED',flush=True)
        expect_diagnostics(disallowed,50,0,'400','NONE','RUNNING')
        assert process.poll() is None
        print('IDENTITY_PROXY_READINESS_LIVE_HTTP_400_DIAGNOSTICS_VERIFIED',flush=True)

        untrusted_context=ssl.create_default_context()
        untrusted=lambda: get(negative_path,client_context=untrusted_context)[0]
        try:
            untrusted()
        except ssl.SSLCertVerificationError:
            pass
        else:
            raise AssertionError('untrusted client unexpectedly accepted fixture certificate')
        assert process.poll() is None
        expect_diagnostics(untrusted,0,50,'UNKNOWN','CERTIFICATE_VERIFICATION','RUNNING')
        assert process.poll() is None
        print('IDENTITY_PROXY_READINESS_LIVE_CERTIFICATE_DIAGNOSTICS_VERIFIED',flush=True)

        process.terminate();process.wait(timeout=10)
        exit_code=process.poll();assert isinstance(exit_code,int)
        refused=lambda: get(negative_path)[0]
        try:
            refused()
        except ConnectionRefusedError:
            pass
        else:
            raise AssertionError('stopped owned proxy unexpectedly accepted connection')
        expect_diagnostics(refused,0,50,'UNKNOWN','CONNECTION_REFUSED',str(exit_code))
        print('IDENTITY_PROXY_READINESS_EXITED_REFUSAL_DIAGNOSTICS_VERIFIED',flush=True)
    finally:
        if process.poll() is None: process.terminate()
        process.wait(timeout=10);server.shutdown();server.server_close()
