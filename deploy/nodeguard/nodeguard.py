#!/usr/bin/env python3
"""Plan and install the guarded host runtime; never equate installation with certification."""
from __future__ import annotations
import argparse
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid
import yaml

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'cluster'))
import cluster
import certification


def require(ok, message):
    if not ok:
        raise ValueError(message)


def canonical_uuid(value):
    require(isinstance(value, str) and str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0, 'invalid canonical UUID')
    return value


def regular(path, private=False):
    path = Path(path)
    require(path.is_absolute() and path.is_file() and not path.is_symlink(), 'expected absolute regular artifact path')
    require(not (path.stat().st_mode & (0o077 if private else 0o022)), 'artifact permissions allow unauthorized access')
    return path


def openssl(*args):
    return subprocess.check_output(['openssl', *map(str, args)], stderr=subprocess.DEVNULL, timeout=10)


def verify_certificate(certificate, key, ca, node_uid):
    regular(certificate); regular(key, True); regular(ca)
    openssl('verify', '-no-CApath', '-no-CAstore', '-purpose', 'sslserver', '-verify_hostname', node_uid + '.nodeguard.sandbox.internal', '-CAfile', ca, certificate)
    openssl('x509', '-in', certificate, '-checkend', '86400', '-noout')
    pub = openssl('x509', '-in', certificate, '-pubkey', '-noout')
    key_pub = openssl('pkey', '-in', key, '-passin', 'pass:', '-pubout')
    require(pub == key_pub, 'server certificate and key differ')


def verify_scraper_ca(scraper_ca, server_ca, controller_ca):
    scraper_ca = regular(scraper_ca)
    require(scraper_ca.read_bytes().count(b'-----BEGIN CERTIFICATE-----') == 1, 'scraper trust must contain one dedicated CA')
    require(b'CA:TRUE' in openssl('x509', '-in', scraper_ca, '-noout', '-ext', 'basicConstraints'), 'scraper trust must be a CA certificate')
    scraper_key = openssl('x509', '-in', scraper_ca, '-pubkey', '-noout')
    require(all(scraper_key != openssl('x509', '-in', regular(other), '-pubkey', '-noout') for other in (server_ca, controller_ca)), 'scraper CA must have a separate key from server/controller CAs')


def validate_inputs(deployment, settings, check_files=True):
    installation = cluster.load_installation(deployment)
    inputs = {key: installation[key] for key in ('outputs', 'settings')}
    required = {'cluster_epoch', 'certification_id', 'binary_file', 'binary_sha256', 'nodeguard_server_ca_file', 'controller_client_ca_file', 'nodes'}
    require(set(settings) in (required, required | {'metrics'}), 'unknown or missing nodeguard settings')
    if 'metrics' in settings:
        require(isinstance(settings['metrics'], dict) and set(settings['metrics']) == {'scraper_client_ca_file'}, 'metrics requires a separate scraper client CA')
    canonical_uuid(settings['cluster_epoch'])
    require(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{7,127}', settings['certification_id']), 'invalid certification reference')
    require(re.fullmatch(r'[0-9a-f]{64}', settings['binary_sha256']), 'release binary SHA256 required')
    identity=inputs['outputs']['deployment_identity']
    require(identity['cloud_account_id'] == inputs['settings']['oidc_provider_arn'].split(':')[3] and identity['region'] == inputs['settings']['region'] and identity['deployment'] == inputs['settings']['deployment'] and identity['environment'] in ['preproduction','production'], 'independent Terraform deployment identity differs from reviewed settings')
    nodes = {name: node for name, node in inputs['outputs']['node_inventory'].items() if node['role'] == 'kata'}
    require(set(settings['nodes']) == set(nodes), 'node enrollment must exactly cover the Kata pool')
    seen = set()
    for name, supplied in settings['nodes'].items():
        require(set(supplied) == {'node_uid', 'server_certificate_file', 'server_key_file'}, 'unknown or missing node enrollment field')
        canonical_uuid(supplied['node_uid'])
        require(supplied['node_uid'] not in seen, 'duplicate Node UID')
        seen.add(supplied['node_uid'])
        require(ipaddress.ip_address(nodes[name]['private_ip']).is_private, 'nodeguard address must be private')
        if check_files:
            verify_certificate(supplied['server_certificate_file'], supplied['server_key_file'], settings['nodeguard_server_ca_file'], supplied['node_uid'])
    if check_files:
        binary = regular(settings['binary_file'])
        require(cluster.digest(binary) == settings['binary_sha256'], 'nodeguard release binary checksum differs')
        with binary.open('rb') as stream:
            header = stream.read(20)
        require(header[:6] == b'\x7fELF\x02\x01' and header[18:20] == b'\x3e\x00', 'nodeguard requires a reviewed Linux amd64 ELF binary')
        ca = regular(settings['nodeguard_server_ca_file'])
        client_ca = regular(settings['controller_client_ca_file'])
        require(openssl('x509', '-in', ca, '-outform', 'DER') != openssl('x509', '-in', client_ca, '-outform', 'DER'), 'server and controller trust CAs must be distinct')
        if 'metrics' in settings:
            verify_scraper_ca(settings['metrics']['scraper_client_ca_file'], ca, client_ca)
    return inputs


def guarded_inventory(original, settings):
    result = copy.deepcopy(original)
    for name, item in settings['nodes'].items():
        host = result['all']['hosts'][name]
        require('sandbox.platform/unverified=true:NoSchedule' in host['node_taints'], 'node must retain quarantine')
        host.update({'kubelet_custom_flags': [], 'containerd_extra_args': 'disabled_plugins = ["io.containerd.monitor.container.v1.restart"]', 'cri_socket': 'unix:///run/sandbox-nodeguard/cri.sock',
                     'kubelet_config_extra_args': {'imageServiceEndpoint': 'unix:///run/containerd/containerd.sock'},
                     'containerd_additional_runtimes': [{'name': 'kata-qemu', 'type': 'io.containerd.kata.v2', 'options': {'ConfigPath': '/etc/kata-containers/configuration-qemu.toml'}}],
                     'sandbox_enrollment_node_uid': item['node_uid']})
    return result


def plan(deployment, settings_file, destination, check_files=True):
    deployment, destination = deployment.resolve(), destination.resolve()
    settings = json.loads(settings_file.read_text())
    inputs = validate_inputs(deployment, settings, check_files)
    require(not destination.exists(), 'refusing to overwrite an existing nodeguard plan')
    destination.mkdir(parents=True, mode=0o700)
    original = yaml.safe_load((deployment / 'inventory.yaml').read_text())
    inventory = guarded_inventory(original, settings)
    inventory['all']['vars']['sandbox_nodeguard_plan_dir'] = str(destination)
    inventory['all']['vars']['sandbox_nodeguard_assets'] = str(ROOT)
    inventory['all']['vars']['sandbox_nodeguard_settings'] = settings
    (destination / 'inventory.yaml').write_text(yaml.safe_dump(inventory, sort_keys=False))
    (destination / 'inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    (destination / 'plan.json').write_text(json.dumps({'protocol': 1, 'bootstrap_deployment': str(deployment), 'bootstrap_inventory_sha256': cluster.digest(deployment / 'inventory.yaml'), 'settings': settings}, indent=2) + '\n')
    (destination / 'inventory.sha256').write_text(cluster.digest(destination / 'inventory.yaml') + '\n')
    (destination / 'artifacts').mkdir(mode=0o700)
    for path in destination.iterdir():
        if path.is_file(): path.chmod(0o600)
    return inventory


def playbook(cache, destination):
    upstream = cache / 'kubespray/playbooks'
    plays = [{'ansible.builtin.import_playbook': str(upstream / 'boilerplate.yml')},
             {'ansible.builtin.import_playbook': str(upstream / 'internal_facts.yml')},
             {'ansible.builtin.import_playbook': str(ROOT / 'install.yaml')}]
    path = destination / 'install-playbook.yaml'
    path.write_text(yaml.safe_dump(plays, sort_keys=False)); path.chmod(0o600)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, default=cluster.DEFAULT_CACHE)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('plan')
    create.add_argument('--deployment', type=Path, required=True)
    create.add_argument('--settings', type=Path, required=True)
    create.add_argument('--out', type=Path, required=True)
    for name in ['check', 'install']:
        sub = commands.add_parser(name); sub.add_argument('--plan', type=Path, required=True)
        if name == 'install': sub.add_argument('--execute', action='store_true')
    for name in ['verify-enrollment', 'enable']:
        sub = commands.add_parser(name)
        for item in ['artifact', 'receipt', 'terraform-output', 'cluster-settings', 'certification-report']:
            sub.add_argument('--' + item, type=Path, required=True)
    args = parser.parse_args()
    if args.command in ['verify-enrollment', 'enable']:
        artifact_raw, terraform_raw, report_raw = args.artifact.read_bytes(), args.terraform_output.read_bytes(), args.certification_report.read_bytes()
        settings = json.loads(args.cluster_settings.read_bytes())
        report = certification.validate_report(json.loads(report_raw), report_raw, settings)
        require(cluster.digest(ROOT.parent / 'cluster/versions.lock.json') == report['versions_lock_sha256'], 'report covers a different release matrix')
        certification.validate_receipt(json.loads(artifact_raw), artifact_raw, json.loads(args.receipt.read_bytes()), terraform_raw, report, report_raw)
        if args.command == 'enable':
            # This is a release capability, deliberately not an input flag. A
            # human-written PASS cannot manufacture a missing cloud fence driver.
            raise ValueError('release capability unavailable: cloud fencing and its certified end-to-end recovery path are not delivered; keep unverified taint and RuntimeClass absent')
        print('Evidence and enrollment receipt identities match. This offline check does not revalidate a live node or authorize activation.')
        return
    if args.command == 'plan':
        plan(args.deployment, args.settings, args.out)
        print('Guarded inventory written; no hosts contacted and no node enabled.')
        return
    destination = args.plan.resolve()
    require(cluster.digest(destination / 'inventory.yaml') == (destination / 'inventory.sha256').read_text().strip(), 'guarded inventory changed')
    metadata = json.loads((destination / 'plan.json').read_text())
    bootstrap = Path(metadata['bootstrap_deployment'])
    validate_inputs(bootstrap, metadata['settings'])
    require(cluster.digest(bootstrap / 'inventory.yaml') == metadata['bootstrap_inventory_sha256'], 'bootstrap inventory no longer matches this plan')
    generated = playbook(args.cache.resolve(), destination)
    if args.command == 'check':
        cluster.ansible(args.cache.resolve(), destination, generated, ['--syntax-check'])
        return
    require(args.execute, 'host mutation requires explicit --execute')
    marker = bootstrap / 'nodeguard-plan.json'
    require(not marker.exists() or json.loads(marker.read_text())['plan'] == str(destination), 'another guarded plan already owns these hosts')
    marker.write_text(json.dumps({'plan': str(destination), 'inventory_sha256': cluster.digest(destination / 'inventory.yaml')}) + '\n'); marker.chmod(0o600)
    cluster.ansible(args.cache.resolve(), destination, generated)
    print('Installed under quarantine. Enroll exported artifacts using sandbox-admin; certification and enable are separate gates.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        sys.exit('nodeguard: ' + str(error))
