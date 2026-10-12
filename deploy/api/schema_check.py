#!/usr/bin/env python3
"""Validate API and console fixtures against checksum-pinned official schemas."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import yaml
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tests'))
from test_render import fixture
from render import render
spec=importlib.util.spec_from_file_location('official_cluster_schema',ROOT.parent/'cluster/render.py')
sys.path.insert(0,str(ROOT.parent/'cluster'))
cluster=importlib.util.module_from_spec(spec);spec.loader.exec_module(cluster)
cache=ROOT.parents[1]/'.local/cluster-artifacts'
lock=json.loads((ROOT.parent/'cluster/versions.lock.json').read_text())
assert hashlib.sha256((cache/'kubernetes-schema.json').read_bytes()).hexdigest()==lock['artifacts']['kubernetes-schema']['sha256']
identity=json.loads((ROOT.parent/'identity/versions.lock.json').read_text())
cnp=ROOT.parent/'identity'/identity['cnp_schema']['path']
assert hashlib.sha256(cnp.read_bytes()).hexdigest()==identity['cnp_schema']['sha256']
spec=importlib.util.spec_from_file_location('api_console_renderer',ROOT.parent/'console/render.py')
console=importlib.util.module_from_spec(spec);spec.loader.exec_module(console)
ca=fixture()['tls']['ca_pem']
objects=[yaml.safe_load(cnp.read_text())]+render(fixture())['items']+render(fixture(False))['items']
objects+=console.manifests('https://console.example.test','sandbox-api.sandbox-system.svc.cluster.local:8443','registry.example.test/console@sha256:'+'a'*64,'sandbox-system','console-tls',ca,['10.80.1.10/32'])['items']
cluster.validate_schema(objects,cache)
print(f'PASS {len(objects)} API/console objects against pinned official Kubernetes/Cilium schemas; fixture digests only, no installation or cloud certification.')
