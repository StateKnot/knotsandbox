#!/usr/bin/env python3
"""Offline validation using the existing locked Kubernetes schema and official vendored CRDs."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import yaml

from identity import ROOT, LOCK, render, require
sys.path.insert(0, str(ROOT.parent/'cluster'))
from render import validate_schema

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--cache',type=Path,default=ROOT.parent.parent/'.local/cluster-artifacts')
args=p.parse_args()
cluster_lock=json.loads((ROOT.parent/'cluster/versions.lock.json').read_text())
expected=cluster_lock['artifacts']['kubernetes-schema']['sha256']
require(hashlib.sha256((args.cache/'kubernetes-schema.json').read_bytes()).hexdigest()==expected,'Kubernetes schema hash mismatch')
cnp=ROOT/LOCK['cnp_schema']['path']
require(hashlib.sha256(cnp.read_bytes()).hexdigest()==LOCK['cnp_schema']['sha256'],'Cilium schema hash mismatch')
s=json.loads((ROOT/'settings.example.json').read_text())
# Schema fixture only; it is never installable because no production proxy is associated with this digest.
s['proxy']['image']='docker.io/library/haproxy:3.2.25-alpine@sha256:'+'a'*64
objects=[yaml.safe_load(cnp.read_text())]
for name, obj in render(s).items():
    if not isinstance(obj,dict) or 'apiVersion' not in obj: continue
    objects.extend(obj['items'] if obj['kind']=='List' else [obj])
validate_schema(objects,args.cache)
print(f'Validated {len(objects)} identity objects against locked Kubernetes, Keycloak and Cilium schemas (offline).')
