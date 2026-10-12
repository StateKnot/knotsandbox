#!/usr/bin/env python3
"""Check actual rendered resources against checksum-pinned official schemas."""
import hashlib
import json
from pathlib import Path
import sys
import yaml
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tests'))
from test_observability import fixture
from observability import resources,validate
sys.path.insert(0,str(ROOT.parent/'cluster'))
from render import validate_schema
cache=ROOT.parent.parent/'.local/cluster-artifacts'
lock=json.loads((ROOT.parent/'cluster/versions.lock.json').read_text())
assert hashlib.sha256((cache/'kubernetes-schema.json').read_bytes()).hexdigest()==lock['artifacts']['kubernetes-schema']['sha256']
lock=json.loads((ROOT.parent/'identity/versions.lock.json').read_text())
cnp=ROOT.parent/'identity'/lock['cnp_schema']['path']
assert hashlib.sha256(cnp.read_bytes()).hexdigest()==lock['cnp_schema']['sha256']
ccnp=cache/'cilium-policy-crd.yaml'
cluster_lock=json.loads((ROOT.parent/'cluster/versions.lock.json').read_text())
assert hashlib.sha256(ccnp.read_bytes()).hexdigest()==cluster_lock['artifacts']['cilium-policy-crd']['sha256']
s,tf,u=fixture(); objects=[yaml.safe_load(cnp.read_text()),yaml.safe_load(ccnp.read_text())]+resources(s,validate(s,tf,u),u)
validate_schema(objects,cache)
print(f'PASS: {len(objects)} generated objects against fixed official Kubernetes/Cilium schemas; no cluster installation performed.')
