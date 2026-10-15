#!/usr/bin/env python3
"""Run the pinned Prometheus rule engine against declared local fault cases."""
from pathlib import Path
import subprocess
import sys
import tempfile
import yaml

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'tests'))
from alerts import rules
from alert_cases import cases, node_image_cases
from observability import LOCK, validate, require
from test_observability import fixture


def main():
    settings, terraform, url = fixture()
    validate(settings, terraform, url)
    with tempfile.TemporaryDirectory(prefix='sandbox-alert-rules-') as temporary:
        path = Path(temporary)
        path.chmod(0o755)
        base = ['docker', 'run', '--rm', '--pull=never', '--network=none',
                '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--tmpfs=/tmp:rw,noexec,nosuid,size=128m',
                '--mount', f'type=bind,src={path},dst=/test,readonly',
                '--entrypoint=/bin/promtool', LOCK['prometheus_image']]
        counts = []
        for optional in (False, True):
            if optional:
                settings['nodes'][0]['image_profile_sha256'] = 'a' * 64
            document = node_image_cases(settings) if optional else cases(settings)
            for name, value in [('alerts.rules.yaml', rules(settings)), ('cases.yaml', document)]:
                (path / name).write_text(yaml.safe_dump(value, sort_keys=False))
            for command in [('check', 'rules', '/test/alerts.rules.yaml'), ('test', 'rules', '/test/cases.yaml')]:
                result = subprocess.run(base + list(command), capture_output=True, timeout=60)
                if result.returncode:
                    # These are public synthetic rule inputs, never deployment settings.
                    sys.stderr.buffer.write((result.stdout + result.stderr)[:1024 * 1024])
                require(result.returncode == 0, 'ALERT_RULE_ENGINE_CHECK_FAILED')
            counts.append(len(document['tests']))
    print(f'PASS pinned Prometheus: {counts[0]} existing and {counts[1]} optional node-image alert fault cases; no cloud rule activation or notifications.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        print('OBSERVABILITY_ALERT_CHECK_FAILED', file=sys.stderr)
        sys.exit(1)
