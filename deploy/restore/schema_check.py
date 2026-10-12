#!/usr/bin/env python3
"""Check the two restore classes against the repository's checksum-pinned official Kubernetes schema."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT/'tests'))
from test_storage import fixture
from storage import render

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=ROOT.parents[1])
    args = parser.parse_args()
    repo = args.repo_root.resolve()
    cache = repo / '.local/cluster-artifacts'
    lock = json.loads((repo/'deploy/cluster/versions.lock.json').read_text())
    assert hashlib.sha256((cache/'kubernetes-schema.json').read_bytes()).hexdigest() == lock['artifacts']['kubernetes-schema']['sha256']
    spec = importlib.util.spec_from_file_location('official_restore_schema', repo/'deploy/cluster/render.py')
    sys.path.insert(0, str(repo/'deploy/cluster'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    config, terraform, _ = fixture()
    documents = render(config, terraform)['items']
    module.validate_schema(documents, cache)
    print('PASS 2 restore StorageClasses against fixed official Kubernetes schema; no CSI or cloud certification implied.')

if __name__ == '__main__':
    main()
