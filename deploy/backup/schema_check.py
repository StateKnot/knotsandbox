#!/usr/bin/env python3
"""Validate generated core objects using the repository's fixed official Kubernetes/Cilium schemas."""
import hashlib
import json
from pathlib import Path
import sys
import yaml

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'tests'))
from test_deploy import fixture
from test_controller import fixture as controller_fixture
from controller import resources as controller_resources
from deploy import resources, foundations
sys.path.insert(0, str(ROOT.parent / 'cluster'))
from render import validate_schema

cache = ROOT.parent.parent / '.local/cluster-artifacts'
lock = json.loads((ROOT.parent / 'cluster/versions.lock.json').read_text())
assert hashlib.sha256((cache / 'kubernetes-schema.json').read_bytes()).hexdigest() == lock['artifacts']['kubernetes-schema']['sha256']
identity_lock = json.loads((ROOT.parent / 'identity/versions.lock.json').read_text())
cnp = ROOT.parent / 'identity' / identity_lock['cnp_schema']['path']
assert hashlib.sha256(cnp.read_bytes()).hexdigest() == identity_lock['cnp_schema']['sha256']
settings, job = fixture()
values = [yaml.safe_load(cnp.read_text())] + foundations(settings, job)
for stage in ('capture', 'seal', 'restore'):
    values += resources(settings, job, stage, 'snapshot-derived-volume', 'a' * 64, attempt_id=job['backup_id'], cluster_epoch=job['tenant_id'])
snapshot_crd=cache / 'csi/deploy/charts/alibaba-cloud-csi-driver/crds/snapshot.storage.k8s.io_volumesnapshotclasses.yaml'
values += [yaml.safe_load(snapshot_crd.read_text())] + controller_resources(controller_fixture())
validate_schema(values, cache)
print(f'PASS {len(values)} generated backup objects against fixed official Kubernetes/Cilium schemas; no cluster certification implied.')
