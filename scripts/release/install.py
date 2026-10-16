#!/usr/bin/env python3
"""Install a new verified artifact directory atomically; never starts services."""
import argparse
import os
from pathlib import Path
import shutil
import sys
import tempfile
from common import ROOT, BINARIES, COMPONENTS, SQLX_POSTGRES_NOTICES, NATIVE_PROTOCOL_NOTICES, load, require, run, safe_child, sha

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--directory',type=Path,required=True)
parser.add_argument('--tools',type=Path,required=True)
parser.add_argument('--repository',required=True)
parser.add_argument('--tag',required=True)
parser.add_argument('--commit',required=True)
parser.add_argument('--destination',type=Path,required=True)
args=parser.parse_args()
require(args.destination.is_absolute() and not args.destination.exists() and not args.destination.is_symlink(),'NEW_ABSOLUTE_INSTALL_DIRECTORY_REQUIRED')
require(args.destination.parent.is_dir(),'INSTALL_PARENT_MISSING')
with tempfile.TemporaryDirectory(prefix='.verified-release-',dir=args.destination.parent) as temporary:
    stage=Path(temporary)/'artifacts';stage.mkdir(mode=0o700)
    run([sys.executable,ROOT/'verify.py','--directory',args.directory,'--tools',args.tools,'--repository',args.repository,'--tag',args.tag,'--commit',args.commit,'--output',stage/'deployment-lock.json'],timeout=600)
    lock=load(stage/'deployment-lock.json')
    manifest_path=safe_child(args.directory,'release-manifest.json')
    require(sha(manifest_path)==lock['manifest_sha256'],'MANIFEST_CHANGED_AFTER_VERIFICATION')
    manifest=load(manifest_path)
    require(type(manifest.get('version')) is int and manifest['version']==4,'CURRENT_RELEASE_SCHEMA_REQUIRED')
    for name in (*BINARIES,*(name+'.oci.tar' for name in COMPONENTS),SQLX_POSTGRES_NOTICES,NATIVE_PROTOCOL_NOTICES):
        source=safe_child(args.directory,name);target=stage/name
        shutil.copyfile(source,target)
        require(sha(target)==manifest['files'][name]['sha256'],'ARTIFACT_CHANGED_AFTER_VERIFICATION')
        target.chmod(0o555 if name in BINARIES else 0o444)
    (stage/'deployment-lock.json').chmod(0o444);stage.chmod(0o755)
    # Destination is new; deploying hosts must restrict parent directory writes.
    require(not args.destination.exists(),'INSTALL_DESTINATION_CHANGED')
    stage.rename(args.destination)
print('Verified artifacts installed. No workload or service was started.')
