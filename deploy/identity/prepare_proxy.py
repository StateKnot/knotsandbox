#!/usr/bin/env python3
"""Create an offline build context from an explicitly supplied, SHA256-verified official source archive."""
import argparse
import hashlib
import shutil
from pathlib import Path
from identity import ROOT, LOCK, require
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--source-archive',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
require(a.source_archive.stat().st_size<=16*1024*1024,'source archive too large')
require(hashlib.sha256(a.source_archive.read_bytes()).hexdigest()==LOCK['proxy_source']['sha256'],'HAProxy source SHA256 mismatch')
a.output.mkdir(mode=0o700,parents=True,exist_ok=False)
shutil.copyfile(a.source_archive,a.output/'haproxy.tar.gz')
shutil.copyfile(ROOT/'Dockerfile.proxy',a.output/'Dockerfile')
(a.output/'haproxy.sha256').write_text(LOCK['proxy_source']['sha256']+'  haproxy.tar.gz\n')
print('Verified offline HAProxy 3.2.25 build context; build/test/sign/push and record the resulting digest before install.')
