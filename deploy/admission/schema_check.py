#!/usr/bin/env python3
"""Check admission workload/activation against checksum-pinned official schemas."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import yaml

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from test_render import fixture, renderer
sys.path.insert(0, str(ROOT.parent / 'cluster'))
spec = importlib.util.spec_from_file_location('admission_official_schema', ROOT.parent / 'cluster/render.py')
cluster = importlib.util.module_from_spec(spec); spec.loader.exec_module(cluster)
cache = REPO / '.local/cluster-artifacts'
lock = json.loads((ROOT.parent / 'cluster/versions.lock.json').read_text())
if hashlib.sha256((cache / 'kubernetes-schema.json').read_bytes()).hexdigest() != lock['artifacts']['kubernetes-schema']['sha256']:
    raise SystemExit('Official Kubernetes schema checksum differs')
identity = json.loads((ROOT.parent / 'identity/versions.lock.json').read_text())
cnp = ROOT.parent / 'identity' / identity['cnp_schema']['path']
if hashlib.sha256(cnp.read_bytes()).hexdigest() != identity['cnp_schema']['sha256']:
    raise SystemExit('Official Cilium schema checksum differs')
documents = [yaml.safe_load(cnp.read_text())]
for replicas in range(2, 9):
    documents += renderer.render(fixture(replicas))['items'] + [renderer.webhook(fixture(replicas))]
cluster.validate_schema(documents, cache)
print(f'PASS {len(documents)} admission objects against pinned official Kubernetes/Cilium schemas; public fixtures only, no installation/certification.')
