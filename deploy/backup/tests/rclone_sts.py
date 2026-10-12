#!/usr/bin/env python3
"""Real rclone AWS V4/STS/profile behavior against a local TLS recorder, never OSS."""
import argparse
import datetime as dt
import http.server
import json
from pathlib import Path
import ssl
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backup import environment, run

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--rclone', required=True)
p.add_argument('--openssl', default='/opt/homebrew/opt/openssl@3/bin/openssl')
a = p.parse_args()
seen = []
delay_head = False


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, body):
        seen.append({**dict(self.headers), '_method': self.command, '_path': self.path})
        if self.command == 'HEAD' and delay_head:
            time.sleep(2.5)
        self.send_response(200)
        self.send_header('Content-Length', '2')
        self.send_header('Last-Modified', 'Sat, 03 Oct 2026 00:00:00 GMT')
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('ETag', '"444bcb3a3fcf8389296c49467f27e1d6"')
        self.end_headers()
        if body:
            self.wfile.write(b'ok')

    def do_HEAD(self):
        if self.path.rstrip('/').endswith('/probe'):
            self.respond(False)
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if 'list-type=' in self.path:
            seen.append({**dict(self.headers), '_method': self.command, '_path': self.path})
            body = b'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>fixturebucket</Name><Prefix></Prefix><KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>probe</Key><LastModified>2026-10-03T00:00:00.000Z</LastModified><ETag>"444bcb3a3fcf8389296c49467f27e1d6"</ETag><Size>2</Size><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Content-Type', 'application/xml')
            self.end_headers()
            self.wfile.write(body)
        else:
            self.respond(True)


with tempfile.TemporaryDirectory(prefix='rclone-sts-') as tmp:
    root = Path(tmp)
    key, cert = root / 'key.pem', root / 'cert.pem'
    run([a.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert),
         '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'], time.time() + 30)
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        helper = root / 'credentials.py'
        creds = {'Version': 1, 'AccessKeyId': 'STS.local-fixture-only', 'SecretAccessKey': 'local-fixture-secret',
                 'SessionToken': 'local-fixture-token', 'Expiration': (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)).isoformat()}
        helper.write_text('import json;print(' + repr(json.dumps(creds)) + ')')
        profile = root / 'profile'
        profile.write_text('[profile sandbox-backup]\ncredential_process = ' + sys.executable + ' ' + str(helper) + '\n')
        remote = root / 'rclone.conf'
        remote.write_text('[oss]\ntype=s3\nprovider=Alibaba\nenv_auth=true\nprofile=sandbox-backup\nshared_credentials_file=' + str(profile) + '\nregion=cn-hangzhou\nendpoint=https://127.0.0.1:' + str(server.server_port) + '\nforce_path_style=false\nno_check_bucket=true\n')
        env = environment()
        env['RCLONE_CONFIG'] = str(remote)
        args = [a.rclone, '--ca-cert', str(cert), '--retries', '1', '--low-level-retries', '1', 'cat', 'oss:fixturebucket/probe']
        result = run(args, time.time() + 20, env)
        assert result == b'ok', (result, [(s['_method'],s['_path']) for s in seen])
        assert seen and all(x['Authorization'].startswith('AWS4-HMAC-SHA256 Credential=STS.local-fixture-only/') for x in seen)
        assert all(x['X-Amz-Security-Token'] == 'local-fixture-token' for x in seen)
        assert all('cn-hangzhou/s3/aws4_request' in x['Authorization'] for x in seen)
        # A single long-lived rclone command refreshes process credentials after expiration.
        counter = root / 'counter'
        helper.write_text('import json,datetime,pathlib\np=pathlib.Path(' + repr(str(counter)) + ')\nn=int(p.read_text())+1 if p.exists() else 1\np.write_text(str(n))\nx=' + repr(creds) + '\nx["SessionToken"]="refresh-token-"+str(n)\nx["Expiration"]=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=1)).isoformat()\nprint(json.dumps(x))\n')
        delay_head = True
        start = len(seen)
        assert run(args, time.time() + 20, env) == b'ok'
        tokens = {x['X-Amz-Security-Token'] for x in seen[start:]}
        assert len(tokens) >= 2, 'long-lived SDK credential refresh did not occur'
        delay_head = False
        previous = len(seen)
        helper.write_text('raise SystemExit(1)\n')  # Expired/missing STS helper fails; must not select another credential source.
        try:
            run(args, time.time() + 20, env)
            raise AssertionError('credential-process failure accepted')
        except ValueError:
            pass
        assert len(seen) == previous
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)
print('PASS real rclone Alibaba provider: TLS verified, AWS4 signing, STS token, explicit credential_process; failed process sends no object request. Real OSS interoperability remains unverified.')
