"""Owned dual-Agent/receiver protocol boundary for the native image chain only."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse

import bcrypt
import yaml

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / 'deploy/observability'))
from fixture_cleanup import fixture_directory
from observability import LOCK, prometheus

WRITER = 'PUBLIC_CHAIN_WRITER'
READER = 'PUBLIC_CHAIN_READER'
TOKEN = 'PUBLIC_CHAIN_QUERY_TOKEN'


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


class Pipeline:
    def __init__(self, native, work, docker, environment, receipt):
        self.native, self.work, self.docker, self.environment, self.receipt = native, work, docker, environment, receipt
        self.owner = native.container_id[:12]
        self.names = []
        self.proxy = None
        self.proxy_thread = None
        self.hold = threading.Event()
        self.proxy_errors = []
        self.proxy_calls = 0
        self.recovery_after = None
        self.control = work / 'control'
        self.control.mkdir(mode=0o700)
        self.record_lock = threading.Lock()

    def call(self, *arguments, check=True):
        result = subprocess.run([*self.docker, *arguments], env=self.environment, capture_output=True, text=True, timeout=30)
        require(not check or result.returncode == 0, 'OWNED_PROMETHEUS_DOCKER_COMMAND_FAILED')
        return result

    def receiver_request(self, path, data=None):
        # Docker's internal bridge intentionally publishes no host sockets.
        # The exact owned non-root native sidecar performs the real HTTPS
        # request on that bridge and returns the unchanged bounded bytes.
        return self.native.query_receiver(path, data)

    def query(self, expression):
        status, body = self.receiver_request('/api/v1/query', urllib.parse.urlencode({'query': expression}).encode())
        require(status == 200, 'ACTUAL_RECEIVER_QUERY_STATUS')
        envelope = json.loads(body)
        require(envelope.get('status') == 'success', 'ACTUAL_RECEIVER_QUERY_RESULT')
        return envelope['data']['result']

    def snapshot(self):
        names = ['up', 'sandbox_node_image_inventory_observation_success', 'sandbox_node_image_filesystem_observation_success',
                 'sandbox_node_image_inventory_count', 'sandbox_node_image_compressed_logical_bytes', 'sandbox_node_image_observed_at_seconds']
        result = {name: {} for name in names}
        result['timestamps'] = {name: {} for name in names}
        branches = []
        for name in names:
            selector = name + '{job="node-images-' + self.native.node['node_uid'] + '"}'
            for kind, expression in [('VALUE', selector), ('SAMPLED_AT', 'timestamp(' + selector + ')')]:
                # timestamp must precede label_replace: label_replace creates
                # an evaluated sample and would lose the original scrape time.
                branches.append('label_replace(label_replace(' + expression + ',"fixture_metric","' + name
                                + '","",""),"fixture_kind","' + kind + '","","")')
        expression = ' or on(fixture_metric,fixture_kind,collector_replica) '.join(branches)
        for row in self.query(expression):
            name = row['metric'].get('fixture_metric')
            kind = row['metric'].get('fixture_kind')
            replica = row['metric'].get('collector_replica')
            require(name in names and kind in ('VALUE', 'SAMPLED_AT') and replica in ('a', 'b'), 'EXACT_RECEIVER_METRIC_AND_REPLICA')
            values = result['timestamps'][name] if kind == 'SAMPLED_AT' else result[name]
            require(replica not in values, 'EXACT_TWO_REPLICA_SERIES')
            values[replica] = float(row['value'][1])
        return result

    def wait_state(self, wanted, deadline):
        latest = None
        while time.monotonic() < deadline:
            latest = self.snapshot()
            up = latest['up']
            flags = latest['sandbox_node_image_inventory_observation_success']
            fs = latest['sandbox_node_image_filesystem_observation_success']
            both = {'a', 'b'}
            if wanted == 'FRESH':
                original = latest['sandbox_node_image_observed_at_seconds']
                good = (up == {'a': 1, 'b': 1} and flags == {'a': 1, 'b': 1} and fs == {'a': 1, 'b': 1}
                        and latest['sandbox_node_image_inventory_count'] == {'a': 1, 'b': 1}
                        and latest['sandbox_node_image_compressed_logical_bytes'] == dict.fromkeys(('a', 'b'), float(self.native.expected_compressed_logical_bytes))
                        and set(original) == both and all(0 <= time.time() - value < 60 for value in original.values())
                        and (self.recovery_after is None or all(value > self.recovery_after for value in original.values()))
                        and all(set(values) == both for values in latest['timestamps'].values())
                        and all(len({values[replica] for values in latest['timestamps'].values()}) == 1 for replica in both))
            elif wanted == 'RPC_FAILURE':
                good = up == {'a': 1, 'b': 1} and flags == {'a': 0, 'b': 0} and fs == {'a': 0, 'b': 0}
            else:
                require(wanted == 'TRANSPORT_FAILURE', 'FIXED_PIPELINE_STATE')
                good = up == {'a': 0, 'b': 0}
            if good:
                if wanted != 'FRESH':
                    self.recovery_after = time.time()
                self.receipt.setdefault('states', []).append({'state': wanted, 'observed_at_seconds': time.time(), 'raw_receiver': latest})
                return latest
            time.sleep(0.2)
        self.receipt['last_raw_receiver'] = latest
        raise RuntimeError('ORIGINAL_CHAIN_BUDGET_STATE_NOT_OBSERVED_' + wanted)

    def start_proxy(self):
        pipeline = self
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(ROOT / 'tests/fixtures/admission/server.pem', ROOT / 'tests/fixtures/admission/server.key')
        class BoundedTlsServer(ThreadingHTTPServer):
            # Set the timeout before the TLS handshake, which otherwise occurs
            # in accept() before BaseHTTPRequestHandler.setup can bound it.
            def get_request(self):
                connection, address = self.socket.accept()
                connection.settimeout(5)
                try:
                    return context.wrap_socket(connection, server_side=True), address
                except BaseException:
                    connection.close()
                    raise

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                self.request.settimeout(5)
                super().setup()

            def log_message(self, *_):
                pass

            def do_POST(self):
                try:
                    require(self.path == '/managed/api/v1/query' and self.headers.get('Authorization') == 'Bearer ' + TOKEN, 'QUERY_PROXY_FIXED_AUTH_PATH')
                    length = int(self.headers.get('Content-Length', '0'))
                    require(0 < length <= 64 * 1024, 'QUERY_PROXY_REQUEST_BOUND')
                    data = self.rfile.read(length)
                    require(len(data) == length, 'QUERY_PROXY_TRUNCATED_REQUEST')
                    form = urllib.parse.parse_qs(data.decode(), strict_parsing=True)
                    require(set(form) == {'query', 'time', 'timeout', 'limit'} and all(len(v) == 1 for v in form.values())
                            and form['limit'] == ['217'] and form['timeout'] == ['5s'], 'QUERY_PROXY_FIXED_FORM')
                    status, body = pipeline.receiver_request('/api/v1/query', data)
                    with pipeline.record_lock:
                        pipeline.proxy_calls += 1
                        number = pipeline.proxy_calls
                    # Preserve the exact receiver bytes before the optional
                    # in-flight revocation barrier. No metrics are fabricated.
                    (pipeline.work / f'query-{number}.json').write_bytes(body)
                    if pipeline.hold.is_set():
                        pipeline.hold.clear()
                        held = pipeline.control / 'query-held'
                        held.touch(mode=0o600, exist_ok=False)
                        until = time.monotonic() + 5
                        while not (pipeline.control / 'query-release').exists():
                            require(time.monotonic() < until, 'ORIGINAL_QUERY_REVOCATION_BARRIER_EXPIRED')
                            time.sleep(0.01)
                    self.send_response(status)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except Exception as error:
                    with pipeline.record_lock:
                        pipeline.proxy_errors.append(type(error).__name__ + ':' + str(error))
                    self.send_error(502, 'Owned query fixture failed')
        self.proxy = BoundedTlsServer(('127.0.0.1', 0), Handler)
        self.proxy.daemon_threads = False
        self.proxy_thread = threading.Thread(target=self.proxy.serve_forever, daemon=False)
        self.proxy_thread.start()
        token = self.control / 'query-token'
        token.write_text(TOKEN)
        token.chmod(0o600)
        self.backend = {'endpoint': f'https://127.0.0.1:{self.proxy.server_port}/managed', 'deployment': 'native-chain',
                        'auth': {'type': 'BEARER', 'token_file': str(token)}, 'ca_file': str(ROOT / 'tests/fixtures/admission/server-ca.pem'), 'replicas': ['a', 'b']}

    def launch(self, path):
        # Everything under this mount is generated PUBLIC fixture material;
        # OIDC and PostgreSQL credentials remain only in the host child env.
        pki = self.work / 'pki'
        for source, destination in [('server.crt', 'receiver.crt'), ('server.key', 'receiver.key'),
                                    ('server-root.crt', 'server-ca.pem'), ('client.crt', 'client.crt'), ('client.key', 'client.key')]:
            (path / destination).write_bytes((pki / source).read_bytes())
            (path / destination).chmod(0o444)
        web = {'tls_server_config': {'cert_file': '/fixture/receiver.crt', 'key_file': '/fixture/receiver.key', 'min_version': 'TLS12'},
               'basic_auth_users': {user: bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4)).decode() for user, password in [('writer', WRITER), ('reader', READER)]}}
        (path / 'web.yml').write_text(yaml.safe_dump(web))
        (path / 'receiver.yml').write_text('scrape_configs: []\n')
        (path / 'username').write_text('writer')
        (path / 'password').write_text(WRITER)
        self.image_id = json.loads(self.call('image', 'inspect', LOCK['prometheus_image']).stdout)[0]['Id']
        base = ['run', '-d', '--pull=never', '--network', self.native.network_name, '--read-only', '--cap-drop=ALL', '--cgroupns=private',
                '--security-opt=no-new-privileges:true', '--memory=256m', '--memory-swap=256m', '--cpus=1', '--pids-limit=64',
                '--label', 'com.sandbox.fixture=node-image-chain', '--label', 'com.sandbox.owner=' + self.owner,
                '--log-driver=local', '--log-opt=max-size=1m', '--log-opt=max-file=1', '--log-opt=compress=false',
                '--mount', f'type=bind,src={path},dst=/fixture,readonly']
        name = 'sandbox-chain-receiver-' + self.owner
        self.names.append(name)
        self.call(*base, '--name', name, '--network-alias', 'receiver', '--mount', f'type=bind,src={path / "receiver"},dst=/prometheus',
                  LOCK['prometheus_image'], '--config.file=/fixture/receiver.yml', '--web.config.file=/fixture/web.yml',
                  '--storage.tsdb.path=/prometheus', '--web.enable-remote-write-receiver', '--storage.tsdb.retention.time=2h', '--storage.tsdb.retention.size=32MB', '--log.level=error')
        self.verify_container(name, path, 'receiver')
        self.receipt['prometheus_image'] = LOCK['prometheus_image']
        until = time.monotonic() + 10
        while True:
            try:
                if self.receiver_request('/-/ready')[0] == 200:
                    break
            except (OSError, RuntimeError):
                pass
            require(time.monotonic() < until, 'OWN_RECEIVER_ORIGINAL_READY_BUDGET')
            time.sleep(0.1)
        settings = {'deployment': 'native-chain', 'cluster_epoch': self.native.node['cluster_epoch'], 'nodes': [{
            'node_uid': self.native.node['node_uid'], 'host_boot_id': self.native.node['boot_id'],
            'private_ip': self.native.network_alias, 'image_profile_sha256': self.native.node['profile_sha256']}]}
        for replica in ('a', 'b'):
            config = prometheus(settings, replica, 'https://receiver:9090/api/v1/write')
            for job in config['scrape_configs']:
                if job['scheme'] == 'https':
                    job['tls_config'].update(ca_file='/fixture/server-ca.pem', cert_file='/fixture/client.crt', key_file='/fixture/client.key')
            writer = config['remote_write'][0]
            writer['basic_auth'] = {'username_file': '/fixture/username', 'password_file': '/fixture/password'}
            writer['tls_config']['ca_file'] = '/fixture/server-ca.pem'
            file = path / f'agent-{replica}.yml'
            file.write_text(yaml.safe_dump(config, sort_keys=False))
            name = 'sandbox-chain-agent-' + replica + '-' + self.owner
            self.names.append(name)
            self.call(*base, '--name', name, '--mount', f'type=bind,src={path / ("agent-" + replica)},dst=/prometheus', LOCK['prometheus_image'],
                      '--agent', '--config.file=/fixture/' + file.name, '--storage.agent.path=/prometheus', '--web.listen-address=0.0.0.0:9090', '--log.level=error')
            self.verify_container(name, path, 'agent-' + replica)
        self.start_proxy()

    def verify_container(self, name, path, store):
        value = json.loads(self.call('inspect', name).stdout)[0]
        host = value['HostConfig']
        labels = value['Config'].get('Labels', {})
        require(value['Name'] == '/' + name and value['Image'] == self.image_id
                and value['Config']['Image'] == LOCK['prometheus_image']
                and value['Config'].get('User') not in (None, '', 'root', '0', '0:0')
                and labels.get('com.sandbox.owner') == self.owner
                and labels.get('com.sandbox.fixture') == 'node-image-chain', 'EXACT_PROMETHEUS_IDENTITY_REQUIRED')
        require(host['Memory'] == 256 * 1024 * 1024 and host['MemorySwap'] == host['Memory']
                and host['NanoCpus'] == 1_000_000_000 and host['PidsLimit'] == 64
                and host['ReadonlyRootfs'] and not host['Privileged'] and not host.get('CapAdd')
                and host['CapDrop'] == ['ALL'] and host['CgroupnsMode'] == 'private'
                and not host.get('PidMode') and 'no-new-privileges:true' in host['SecurityOpt']
                and host['NetworkMode'] == self.native.network_name
                and set(value['NetworkSettings']['Networks']) == {self.native.network_name}
                and host['LogConfig'] == {'Type': 'local', 'Config': {'max-size': '1m', 'max-file': '1', 'compress': 'false'}},
                'PROMETHEUS_RESOURCE_OR_ISOLATION_BOUND_CHANGED')
        mounts = {mount['Destination']: mount for mount in value['Mounts']}
        require(set(mounts) == {'/fixture', '/prometheus'} and all(m['Type'] == 'bind' for m in mounts.values())
                and mounts['/fixture']['Source'] == str(path) and not mounts['/fixture']['RW']
                and mounts['/prometheus']['Source'] == str(path / store) and mounts['/prometheus']['RW'], 'EXACT_OWN_PROMETHEUS_MOUNTS')
        ports = host.get('PortBindings') or {}
        require(not ports, 'PROMETHEUS_INTERNAL_NETWORK_ONLY')
        self.receipt.setdefault('prometheus_containers', []).append({'id': value['Id'], 'name': name, 'image_id': value['Image'], 'store': store})

    def close(self):
        errors = []
        try:
            (self.control / 'query-release').touch(mode=0o600, exist_ok=True)
            if self.proxy:
                self.proxy.shutdown()
                self.proxy.server_close()
                self.proxy_thread.join(timeout=6)
                if self.proxy_thread.is_alive():
                    errors.append('QUERY_PROXY_THREAD_NOT_JOINED')
        except Exception as error:
            errors.append('QUERY_PROXY_CLEANUP_FAILED:' + str(error))
        for name in reversed(self.names):
            try:
                observed = self.call('inspect', name, check=False)
                if observed.returncode == 0:
                    value = json.loads(observed.stdout)[0]
                    labels = value['Config']['Labels']
                    require(value['Name'] == '/' + name and labels.get('com.sandbox.owner') == self.owner
                            and labels.get('com.sandbox.fixture') == 'node-image-chain', 'EXACT_PROMETHEUS_OWNER_REQUIRED')
                    known = [entry for entry in self.receipt.get('prometheus_containers', []) if entry['name'] == name]
                    require(not known or (len(known) == 1 and known[0]['id'] == value['Id']), 'PROMETHEUS_CONTAINER_ID_CHANGED')
                    try:
                        logs = self.call('logs', '--tail', '100', name, check=False)
                        self.receipt.setdefault('logs', {})[name] = (logs.stdout + logs.stderr)[-16384:]
                    except Exception as error:
                        errors.append('PROMETHEUS_DIAGNOSTIC_FAILED:' + str(error))
                    self.call('rm', '-f', '-v', value['Id'])
                if self.call('ps', '-aq', '--filter', f'name=^/{name}$').stdout.strip():
                    errors.append('OWN_PROMETHEUS_CONTAINER_NOT_REMOVED')
            except Exception as error:
                errors.append(str(error))
        self.receipt['prometheus_containers_removed'] = not errors
        self.receipt['query_proxy_calls'] = self.proxy_calls
        self.receipt['query_proxy_errors'] = self.proxy_errors
        if self.proxy_errors:
            errors.append('ACTUAL_QUERY_PROXY_FAILED')
        self.receipt['cleanup_errors'] = errors
        require(not errors, ','.join(errors))


@contextmanager
def owned_pipeline(native, work, docker, environment, receipt):
    pipeline = Pipeline(native, work, docker, environment, receipt)
    try:
        with fixture_directory('sandbox-prometheus-pipeline-', ('receiver', 'agent-a', 'agent-b'),
                               docker_command=docker, environment=environment) as directory:
            directory = directory.resolve(strict=True)
            directory.chmod(0o755)
            for name in ('receiver', 'agent-a', 'agent-b'):
                (directory / name).mkdir(mode=0o777)
                (directory / name).chmod(0o777)
            try:
                pipeline.launch(directory)
                yield pipeline
            finally:
                primary = sys.exc_info()[0] is not None
                try:
                    pipeline.close()
                except Exception:
                    if not primary:
                        raise
        receipt['prometheus_data_removed'] = not directory.exists()
        require(receipt['prometheus_data_removed'], 'OWN_PROMETHEUS_DATA_NOT_REMOVED')
    finally:
        if 'directory' in locals():
            receipt['prometheus_data_removed'] = not directory.exists()
