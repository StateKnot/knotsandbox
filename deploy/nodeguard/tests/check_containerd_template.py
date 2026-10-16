#!/usr/bin/env python3
"""Render the locked upstream containerd template locally, without host installation."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib

import yaml

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_nodeguard import NodeguardPlanTests, configs
import cluster
import host_profile
import nodeguard


def checked_sources(cache):
    """Verify inputs against the existing release archive, never fetch or edit it."""
    cluster.require(cluster.LOCK['versions']['kubespray'] == '2.32.0', 'review the template check for the new Kubespray release')
    artifact = cluster.LOCK['artifacts']['kubespray']
    archive = cache / artifact['filename']
    cluster.require(cluster.digest(archive) == artifact['sha256'], 'locked Kubespray archive digest differs')
    source = cache / 'kubespray'
    relative = {
        Path('roles/container-engine/containerd/templates/config.toml.j2'),
        Path('roles/container-engine/containerd/defaults/main.yml'),
    }
    for directory in ['defaults', 'vars']:
        relative.update(path.relative_to(source) for path in (source / 'roles/kubespray_defaults' / directory).rglob('*.yml'))
    fingerprints = {}
    with tarfile.open(archive, 'r:gz') as package:
        for name in sorted(relative):
            path = source / name
            cluster.require(path.is_file() and not path.is_symlink(), 'upstream template input must be a regular file')
            matches = [entry for entry in package.getmembers() if entry.name.partition('/')[2] == name.as_posix()]
            cluster.require(len(matches) == 1 and matches[0].isfile(), 'locked archive has no unique template input')
            with package.extractfile(matches[0]) as stream:
                expected = hashlib.sha256(stream.read()).hexdigest()
            actual = cluster.digest(path)
            cluster.require(actual == expected, 'cached upstream template input differs from the locked archive')
            fingerprints[name.as_posix()] = actual
    return fingerprints


def check(cache):
    cache = cache.resolve()
    source = cache / 'kubespray'
    before = checked_sources(cache)
    # Only this owned directory receives Ansible output, module temporaries and
    # fact-cache files. Inventory identity is synthetic; no SSH or become occurs.
    with tempfile.TemporaryDirectory(prefix='sandbox-nodeguard-template-') as directory:
        work = Path(directory).resolve()
        path, _ = NodeguardPlanTests().create(work)
        nodeguard.plan(path / 'bootstrap', path / 'guard.json', path / 'guarded', check_files=False)
        rendered = work / 'rendered-containerd.toml'
        playbook = work / 'template-playbook.yaml'
        playbook.write_text(yaml.safe_dump([{
            'name': 'Render only the locked containerd configuration into an owned local directory',
            'hosts': 'kata-0',
            'connection': 'local',
            'become': False,
            'gather_facts': False,
            'roles': [
                {'role': 'kubespray_defaults'},
                # Load actual role defaults at their real low precedence. Every
                # containerd installation task is unconditionally skipped; an
                # include_vars would incorrectly override reviewed host values.
                {'role': 'container-engine/containerd', 'when': False},
            ],
            'tasks': [
                {'name': 'Render the complete original config.toml.j2 without invoking containerd installation',
                 'ansible.builtin.template': {'src': str(source / 'roles/container-engine/containerd/templates/config.toml.j2'),
                                            'dest': str(rendered), 'mode': '0600'}},
            ],
        }], sort_keys=False))
        environment = os.environ.copy()
        environment.update({
            'ANSIBLE_CONFIG': str(source / 'ansible.cfg'),
            'ANSIBLE_ROLES_PATH': str(source / 'roles'),
            'ANSIBLE_LIBRARY': str(source / 'plugins/modules'),
            'ANSIBLE_FILTER_PLUGINS': str(source / 'plugins/filter'),
            'ANSIBLE_ACTION_PLUGINS': str(source / 'plugins/action'),
            'ANSIBLE_LOCAL_TEMP': str(work / 'ansible-local'),
            'ANSIBLE_REMOTE_TEMP': str(work / 'ansible-remote'),
            'ANSIBLE_HOME': str(work / 'ansible-home'),
            'ANSIBLE_CACHE_PLUGIN_CONNECTION': str(work / 'facts'),
            'ANSIBLE_HOST_KEY_CHECKING': 'True',
        })
        variables = {
            'ansible_connection': 'local',
            'ansible_become': False,
            'ansible_python_interpreter': sys.executable,
            'ansible_remote_tmp': str(work / 'ansible-remote'),
            # These are rendering inputs, explicitly not observations of the
            # developer's host or proof that a Kata installation is certified.
            'ansible_facts': {'distribution': 'Ubuntu', 'distribution_version': '24.04',
                              'distribution_major_version': '24', 'os_family': 'Debian',
                              'architecture': 'x86_64', 'system': 'Linux'},
        }
        command = [sys.executable, '-m', 'ansible.cli.playbook', '-i', str(path / 'guarded/inventory.yaml'),
                   str(playbook), '--limit', 'kata-0', '--connection', 'local', '--forks', '1',
                   '--extra-vars', json.dumps(variables)]
        result = subprocess.run(command, cwd=source, env=environment, capture_output=True, timeout=60)
        sys.stdout.buffer.write(result.stdout)
        sys.stderr.buffer.write(result.stderr)
        result.check_returncode()
        # This fresh temporary destination must account for the only executed
        # task. Fail if a future role dependency or handler performs extra work.
        cluster.require(re.search(rb'(?m)^kata-0\s*:\s*ok=1\s+changed=1\s+unreachable=0\s+failed=0\s+skipped=\d+\s+rescued=0\s+ignored=0\s*$', result.stdout),
                        'only the local template task may execute')
        containerd = tomllib.loads(rendered.read_text())
        kata, _, kubelet = configs()
        host_profile.validate_configurations(kata, containerd, kubelet)
        cluster.require(checked_sources(cache) == before, 'upstream rendering inputs changed during validation')
        print(json.dumps({'status': 'PASS', 'scope': 'offline locked upstream template, not host installation or runtime certification',
                          'kubespray_version': '2.32.0', 'containerd_config_version': containerd['version'],
                          'rendered_sha256': cluster.digest(rendered), 'source_unchanged': True,
                          'sources': before}, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, default=cluster.DEFAULT_CACHE)
    check(parser.parse_args().cache)
