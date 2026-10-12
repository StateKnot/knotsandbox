import copy
import datetime as dt
import hashlib
import http.server
import importlib.util
import json
from pathlib import Path
import ssl
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import yaml

from test_identity import m, fixture, token, NOW, ROOT


def tls_material():
    now = dt.datetime.now(dt.timezone.utc)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Public test CA')])
    root = x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name).public_key(root_key.public_key()).serial_number(1).not_valid_before(now-dt.timedelta(days=1)).not_valid_after(now+dt.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(root_key, hashes.SHA256())
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'issuer.example.test')])).issuer_name(root_name).public_key(server_key.public_key()).serial_number(2).not_valid_before(now-dt.timedelta(days=1)).not_valid_after(now+dt.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).add_extension(x509.SubjectAlternativeName([x509.DNSName('issuer.example.test')]), critical=False).sign(root_key, hashes.SHA256())
    return root, leaf, server_key


class AcceptanceTest(unittest.TestCase):
    def test_publisher_key_remains_forced_command_if_later_installation_fails(self):
        tasks = yaml.safe_load((ROOT / 'install.yaml').read_text())[0]['tasks']
        key_index = next(i for i, task in enumerate(tasks) if 'ansible.posix.authorized_key' in task)
        self.assertEqual(tasks[key_index - 1]['ansible.builtin.meta'], 'flush_handlers')
        options = tasks[key_index]['ansible.posix.authorized_key']['key_options']
        self.assertTrue(options.startswith('restrict,command="'))
        self.assertIn('identity.py receive --config /etc/sandbox-workload-identity.json --root /srv/workload-identity"', options)

    def test_actual_csi_acceptance_requires_both_current_ready_workloads(self):
        settings, _, bundle, pod, sa = fixture()
        settings['roles'] = {name: {**settings['roles']['fencing'], 'subject': 'system:serviceaccount:kube-system:sandbox-' + name}
                             for name in ['csi-controller', 'csi-node']}
        pod = copy.deepcopy(pod)
        pod['metadata']['namespace'] = 'kube-system'
        workload = {'metadata': {'generation': 3}, 'spec': {'replicas': 1, 'selector': {'matchLabels': {'app': 'csi'}}},
                    'status': {'observedGeneration': 3, 'readyReplicas': 1, 'desiredNumberScheduled': 1, 'numberReady': 1}}
        state = {'role': '', 'unready': False, 'deleted': False}
        def kube(context, *args):
            if args[3] in ['deployment', 'daemonset']:
                state['role'] = 'csi-controller' if args[3] == 'deployment' else 'csi-node'
                obj = copy.deepcopy(workload)
                if state['unready']:
                    obj['status']['observedGeneration'] = 2
                return m.canonical(obj)
            obj = copy.deepcopy(pod)
            role = settings['roles'][state['role']]
            obj['spec']['containers'][0]['env'] = [{'name': key, 'value': value} for key, value in {
                'ALIBABA_CLOUD_ROLE_ARN': role['arn'], 'ALIBABA_CLOUD_OIDC_PROVIDER_ARN': settings['oidc_provider_arn'],
                'ALIBABA_CLOUD_ECS_METADATA_DISABLED': 'true'}.items()]
            if state['deleted'] and state['role'] == 'csi-node':
                obj['metadata']['deletionTimestamp'] = '2026-01-01T00:00:00Z'
            return m.canonical({'items': [obj]})
        with patch.object(m, 'export', return_value=bundle), patch.object(m, 'verify_public', return_value={}), \
             patch.object(m, 'kubectl', side_effect=kube), patch.object(m, 'pod_token', side_effect=lambda _, role, *args: (settings['roles'][role], pod, sa, b'not-output')), \
             patch.object(m, 'verify_token', return_value={'kid': 'key'}), patch.object(m, 'exchange', return_value={'role_id': 'id'}):
            self.assertEqual(len(m.verify_installed_csi(settings)), 2)
            state['unready'] = True
            with self.assertRaisesRegex(m.Rejected, 'CSI_WORKLOAD_NOT_READY'):
                m.verify_installed_csi(settings)
            state.update(unready=False, deleted=True)
            with self.assertRaisesRegex(m.Rejected, 'CSI_POD_COUNT'):
                m.verify_installed_csi(settings)

    def test_tls_public_metadata_uses_hostname_validation_and_rejects_redirect(self):
        settings, _, bundle, _, _ = fixture()
        root, leaf, key = tls_material()
        pem = serialization.Encoding.PEM
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            (directory/'ca.pem').write_bytes(root.public_bytes(pem))
            (directory/'leaf.pem').write_bytes(leaf.public_bytes(pem) + root.public_bytes(pem))
            (directory/'key.pem').write_bytes(key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            (directory/'key.pem').chmod(0o600)
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *_):
                    pass
                def do_GET(self):
                    self.send_response(302 if self.path == '/redirect' else 200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(m.canonical(bundle['discovery'] if self.path == m.DISCOVERY else bundle['jwks']))
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(directory/'leaf.pem', directory/'key.pem')
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            client_context = ssl.create_default_context(cafile=str(directory/'ca.pem'))
            real_connect = m.socket.create_connection
            try:
                with patch.object(m.ssl, 'create_default_context', return_value=client_context), patch.object(m.socket, 'create_connection', side_effect=lambda address, timeout: real_connect(('127.0.0.1', server.server_port), timeout)):
                    self.assertEqual(m.public_metadata(settings)[1], m.public_keys(bundle['jwks']))
                    with self.assertRaises(ssl.SSLCertVerificationError):
                        m.https_json('wrong.example.test', m.DISCOVERY)
                    with self.assertRaisesRegex(m.Rejected, 'HTTP_FAILED'):
                        m.https_json('issuer.example.test', '/redirect')
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_certificate_pin_is_chained_ca_not_arbitrary_trailing_certificate(self):
        root, leaf, _ = tls_material()
        other, _, _ = tls_material()
        pem = serialization.Encoding.PEM
        chain = [leaf.public_bytes(pem), root.public_bytes(pem)]
        fingerprint = root.fingerprint(hashes.SHA1()).hex()
        self.assertEqual(m.validate_certificate_chain(chain, [fingerprint]), fingerprint)
        with self.assertRaises(m.Rejected):
            m.validate_certificate_chain(chain, ['0'*40])
        with self.assertRaises((ValueError, m.InvalidSignature)):
            m.validate_certificate_chain(chain + [other.public_bytes(pem)], [other.fingerprint(hashes.SHA1()).hex()])

    def test_process_output_limit_and_failure_do_not_expose_secret_stdout(self):
        with self.assertRaisesRegex(m.Rejected, 'COMMAND_OUTPUT_LIMIT'):
            m.run([sys.executable, '-c', 'print("SECRET_MARKER"*10000)'], limit=100)
        with self.assertRaisesRegex(m.Rejected, 'COMMAND_FAILED') as error:
            m.run([sys.executable, '-c', 'import sys;print("SECRET_MARKER");sys.exit(1)'])
        self.assertNotIn('SECRET_MARKER', str(error.exception))

    def test_retirement_rejects_uncertified_issuer_limits_and_rebound_epoch(self):
        settings, _, bundle, _, _ = fixture()
        for change in [lambda b: b['control_planes'][0]['flags'].update(**{'service-account-extend-token-expiration': 'true'}),
                       lambda b: b.update(cluster_epoch='99999999-2222-4333-8444-555555555555'),
                       lambda b: b['control_planes'][1].update(private_ip='10.0.0.99')]:
            changed = copy.deepcopy(bundle)
            change(changed)
            with self.assertRaises(m.Rejected):
                m.merge_release(changed, settings, retire=['test-key-1'], now=NOW)

    def test_deployment_binding_uses_audited_inventory_not_editable_side_file(self):
        settings, _, _, _, _ = fixture()
        sys.path.insert(0, str(ROOT.parent / 'cluster/tests'))
        from test_cluster import fixture as cluster_fixture
        from cluster import generate
        tf, values = cluster_fixture()
        values.update({key: settings[key] for key in ('deployment', 'region', 'oidc_provider_arn')})
        for role, value in tf['workload_roles']['value'].items():
            value.update(arn=f"acs:ram::{settings['account_id']}:role/{settings['deployment']}-{role}",
                         issuer=settings['issuer'], audience=settings['audience'])
        tf['workload_roles']['value'].update({k: {**v, 'issuer': settings['issuer'], 'audience': settings['audience']}
                                            for k, v in settings['roles'].items()})
        settings['control_plane_nodes'] = {name: {'name': name, 'private_ip': node['private_ip'], 'instance_id': node['id']}
                                            for name, node in tf['node_inventory']['value'].items() if node['role'] == 'control'}
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            (directory/'tf.json').write_bytes(m.canonical(tf))
            (directory/'settings.json').write_bytes(m.canonical(values))
            deployment = directory/'deployment'
            generate(directory/'tf.json', directory/'settings.json', deployment)
            m.bind_deployment(settings, deployment, settings['cluster_epoch'])
            inputs = json.loads((deployment/'inputs.json').read_bytes())
            inputs['outputs']['node_inventory']['control-1']['private_ip'] = '10.0.0.99'
            (deployment/'inputs.json').write_bytes(m.canonical(inputs))
            with self.assertRaisesRegex(m.Rejected, 'INSTALLATION_SNAPSHOT_CHANGED'):
                m.bind_deployment(settings, deployment, settings['cluster_epoch'])

    def test_live_probe_exchange_receipt_and_cleanup_required_for_addons(self):
        settings, private, bundle, pod, sa = fixture()
        for role in ('csi-controller', 'csi-node'):
            settings['roles'][role] = {'arn': settings['roles']['fencing']['arn'] + role, 'role_id': '123', 'subject': 'system:serviceaccount:kube-system:sandbox-' + role}
        commands = []
        def process(command, data=None, **kwargs):
            commands.append((command, data))
            if 'create' in command:
                obj = m.decode(data)
                obj['metadata']['uid'] = 'pod-uid'
                return m.canonical(obj)
            if 'delete' in command:
                self.assertEqual(m.decode(data)['preconditions'], {'uid': 'pod-uid'})
            return b'{}'
        def actual_token(config, role_name, context, namespace, name, container):
            p, s = copy.deepcopy(pod), copy.deepcopy(sa)
            p['metadata'].update(namespace=namespace, name=name)
            s['metadata'].update(namespace=namespace, name='sandbox-' + role_name)
            role = settings['roles'][role_name]
            return role, p, s, token(private, config, p, s, sub=role['subject'])
        with patch.object(m, 'bind_deployment', return_value='inventory-hash'), patch.object(m, 'export', return_value=bundle), patch.object(m, 'verify_public', return_value=m.public_keys(bundle['jwks'])), patch.object(m, 'kubectl', return_value=b'{}'), patch.object(m, 'run', side_effect=process), patch.object(m, 'pod_token', side_effect=actual_token), patch.object(m, 'exchange', return_value={'sts_request_id': 'provider-id'}), patch.object(m.time, 'time', return_value=NOW):
            receipt = m.accept_addons(settings, '/unused-fixture', settings['cluster_epoch'])
            self.assertEqual(set(receipt['roles']), {'csi-controller', 'csi-node'})
            self.assertEqual(receipt['inventory_sha256'], 'inventory-hash')
            self.assertEqual(receipt['cluster_epoch'], settings['cluster_epoch'])
            self.assertEqual(receipt['expires_at'], NOW + 300)
            self.assertEqual(sum('delete' in c for c, _ in commands), 2)
            with patch.object(m, 'exchange', side_effect=m.Rejected('STS_REJECTED')), self.assertRaisesRegex(m.Rejected, 'STS_REJECTED'):
                m.accept_addons(settings, '/unused-fixture', settings['cluster_epoch'])
            self.assertEqual(sum('delete' in c for c, _ in commands), 3)

    def test_host_image_bundle_requires_exact_versions_base_and_hashes(self):
        spec = importlib.util.spec_from_file_location('prepare_host', ROOT/'prepare-host.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with self.assertRaises(ValueError):
            module.validate_spec(json.loads((ROOT/'package-versions.template.json').read_text()))
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            (directory/'fixture.deb').write_bytes(b'PUBLIC_TEST_PACKAGE_ONLY')
            manifest = {'version': 1, 'base_packages_sha256': 'base', 'spec': {'packages': {p: '1.2.3-1' for p in module.PACKAGES}, 'ntp_server_ips': ['10.0.0.1']}, 'debs': {'fixture.deb': module.sha(directory/'fixture.deb')}}
            (directory/'packages.lock.json').write_text(json.dumps(manifest))
            digest = module.sha(directory/'packages.lock.json')
            module.verify_bundle(directory, digest, 'base')
            with self.assertRaises(ValueError):
                module.verify_bundle(directory, digest, 'another-image')
            (directory/'fixture.deb').write_bytes(b'TAMPERED')
            with self.assertRaises(ValueError):
                module.verify_bundle(directory, digest, 'base')


if __name__ == '__main__':
    unittest.main()
