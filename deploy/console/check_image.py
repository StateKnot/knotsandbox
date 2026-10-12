#!/usr/bin/env python3
"""Local immutable-image TLS checks. Public disposable fixtures; no cloud changes."""
import argparse
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from render import configuration


API_NAME = 'api.test.svc.cluster.local'


def openssl(args):
    subprocess.run(['openssl', *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def certificates(root):
    for ca in ['trusted', 'other']:
        openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=' + ca,
                 '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
                 '-keyout', str(root / (ca + '.key')), '-out', str(root / (ca + '.crt'))])
    for name, host, ca in [('valid', API_NAME, 'trusted'), ('wrong-ca', API_NAME, 'other'),
                            ('wrong-san', 'wrong.example.test', 'trusted')]:
        openssl(['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + host,
                 '-keyout', str(root / (name + '.key')), '-out', str(root / (name + '.csr'))])
        ext = root / (name + '.ext')
        ext.write_text('subjectAltName=DNS:' + host + '\nbasicConstraints=critical,CA:FALSE\n'
                       'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
        openssl(['x509', '-req', '-days', '1', '-in', str(root / (name + '.csr')),
                 '-CA', str(root / (ca + '.crt')), '-CAkey', str(root / (ca + '.key')), '-CAcreateserial',
                 '-extfile', str(ext), '-out', str(root / (name + '.crt'))])
        # Explicitly disposable generated test keys, never production secrets.
        os.chmod(root / (name + '.key'), 0o644)
    openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
             '-addext', 'subjectAltName=DNS:localhost', '-keyout', str(root / 'tls.key'), '-out', str(root / 'tls.crt')])
    os.chmod(root / 'tls.key', 0o644)


def fixture_configuration():
    servers = []
    for port, name in [(8443, 'valid'), (8444, 'wrong-ca'), (8445, 'wrong-san')]:
        servers.append(f'''server {{ listen {port} ssl; server_name {API_NAME};
          ssl_certificate /fixture/{name}.crt; ssl_certificate_key /fixture/{name}.key;
          ssl_protocols TLSv1.2 TLSv1.3; ssl_session_tickets off;
          location / {{ default_type application/json; return 200 '{{"transport_fixture":true,"protocol":"$ssl_protocol","sni":"$ssl_server_name"}}'; }}
        }}''')
    servers.append('server { listen 8446; location / { return 200 "plaintext-fixture"; } }')
    return ('pid /tmp/nginx.pid; error_log /dev/null crit; events {} http { access_log off; '
            'client_body_temp_path /tmp/client_temp; proxy_temp_path /tmp/proxy_temp; '
            'fastcgi_temp_path /tmp/fastcgi_temp; scgi_temp_path /tmp/scgi_temp; '
            'uwsgi_temp_path /tmp/uwsgi_temp; ' + ''.join(servers) + ' }')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image', required=True)
    p.add_argument('--docker-host')
    p.add_argument('--docker-config')
    p.add_argument('--port', type=int, default=19443)
    a = p.parse_args()
    if not re.fullmatch(r'(?:[a-z0-9./:_-]+@)?sha256:[a-f0-9]{64}', a.image) or not 1024 <= a.port <= 65535:
        p.error('immutable image and nonprivileged local test port required')
    docker = ['docker']
    if a.docker_config:
        docker += ['--config', a.docker_config]
    if a.docker_host:
        docker += ['--host', a.docker_host]

    def run(args):
        result = subprocess.run(docker + args, capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError('Local image check ' + args[0] + ' failed: ' + result.stderr[:3000])
        return result

    suffix = uuid.uuid4().hex
    network = 'sandbox-console-test-' + suffix
    backend = network + '-backend'
    started = []
    network_created = False
    local = Path.cwd() / '.local'
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='sandbox-console-', dir=local) as td:
        root = Path(td).resolve()
        os.chmod(root, 0o755)
        certificates(root)
        upstream_cfg = root / 'upstream.conf'
        upstream_cfg.write_text(fixture_configuration())
        base = ['--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '101:101',
                '--tmpfs', '/tmp:rw,noexec,nosuid,size=33554432']
        context = ssl.create_default_context(cafile=str(root / 'tls.crt'))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))

        def request(path):
            return opener.open(f'https://localhost:{a.port}' + path, timeout=8)

        try:
            # Docker Desktop cannot publish ports from an internal-only bridge.
            # This unique bridge has only these fixture containers; no external
            # URLs are requested and the sole host port binds 127.0.0.1.
            run(['network', 'create', network])
            network_created = True
            run(['run', '--detach', '--name', backend, '--network', network, '--network-alias', API_NAME,
                 *base, '--volume', f'{upstream_cfg}:/etc/sandbox/nginx.conf:ro', '--volume', f'{root}:/fixture:ro',
                 a.image])
            started.append(backend)
            for upstream_port, expected in [(8443, 200), (8444, 502), (8445, 502), (8446, 502)]:
                cfg = root / ('console-' + str(upstream_port) + '.conf')
                # The production renderer accepts only a qualified public name.
                # Only this test copy changes it to localhost for a public test CA.
                cfg.write_text(configuration('https://localhost.example.com', f'{API_NAME}:{upstream_port}')
                               .replace('localhost.example.com', 'localhost'))
                args = [*base, '--volume', f'{cfg}:/etc/sandbox/nginx.conf:ro', '--volume', f'{root}:/tls:ro',
                        '--volume', f'{root / "trusted.crt"}:/api-ca/ca.crt:ro']
                run(['run', '--rm', '--network', network, *args, a.image, '-t', '-c', '/etc/sandbox/nginx.conf'])
                name = network + '-console-' + str(upstream_port)
                run(['run', '--detach', '--name', name, '--network', network,
                     '--publish', f'127.0.0.1:{a.port}:8443', *args, a.image])
                started.append(name)
                for attempt in range(50):
                    try:
                        with request('/') as response:
                            html = response.read(65537)
                            assert response.status == 200 and len(html) <= 65536
                            assert response.headers['Cache-Control'] == 'no-store'
                            assert "frame-ancestors 'none'" in response.headers['Content-Security-Policy']
                            assert response.headers['Referrer-Policy'] == 'no-referrer'
                            assert b'/assets/' in html and b'sourceMappingURL' not in html
                        break
                    except (urllib.error.URLError, TimeoutError):
                        if attempt == 49:
                            raise
                        time.sleep(.1)
                try:
                    with request('/v1/transport-fixture') as response:
                        assert response.status == expected == 200
                        receipt = json.loads(response.read(4097))
                        assert receipt == {'transport_fixture': True, 'protocol': 'TLSv1.3', 'sni': API_NAME}
                except urllib.error.HTTPError as exc:
                    assert expected == exc.code == 502
                    assert exc.headers['Cache-Control'] == 'no-store'
                if upstream_port == 8443:
                    with request('/health/live') as response:
                        assert response.status == 204
                    assets = re.findall(rb'(?:src|href)="(/assets/[A-Za-z0-9_-]+\.(?:js|css))"', html)
                    assert assets, 'HTML must reference content-hash assets'
                    for path in assets:
                        with request(path.decode()) as response:
                            assert response.status == 200
                            assert response.headers['Cache-Control'] == 'public, max-age=31536000, immutable'
                            assert "frame-ancestors 'none'" in response.headers['Content-Security-Policy']
                            assert response.headers['X-Content-Type-Options'] == 'nosniff'
                            assert len(response.read(4 * 1024 * 1024 + 1)) <= 4 * 1024 * 1024
                    wrong = urllib.request.Request(f'https://localhost:{a.port}/', headers={'Host': 'other.example.com'})
                    try:
                        opener.open(wrong, timeout=2)
                        raise AssertionError('unexpected host accepted')
                    except urllib.error.HTTPError as exc:
                        assert exc.code == 421
                    for path in ['/unknown', '/.git/config', '/assets/nonexistent.js', '/bundle-manifest.json',
                                 '/package-lock.json', '/usr/share/sandbox-console/package-lock.json']:
                        try:
                            request(path)
                            raise AssertionError('unexpected public path')
                        except urllib.error.HTTPError as exc:
                            assert exc.code == 404 and exc.headers['Cache-Control'] == 'no-store'
                    inspect = json.loads(run(['inspect', name]).stdout)[0]
                    assert inspect['Config']['User'] == '101:101' and inspect['HostConfig']['ReadonlyRootfs']
                run(['stop', '--time', '5', name])
                run(['rm', name])
                started.remove(name)
            print(json.dumps({'nonroot_readonly_tls_html_headers': True, 'immutable_assets_csp': True,
                              'host_paths_denied': True, 'upstream_https_verified_ca_sni': True,
                              'wrong_ca_san_plaintext_rejected': True, 'api_oidc_live_acceptance': False}))
        finally:
            for name in reversed(started):
                run(['stop', '--time', '5', name])
                run(['rm', name])
            if network_created:
                run(['network', 'rm', network])


if __name__ == '__main__':
    main()
