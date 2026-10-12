#!/usr/bin/env python3
"""Real upstream signature fixture; proves local tooling, not our release identity."""
import argparse
from pathlib import Path
import subprocess
import tempfile
from common import ROOT, require, run, sha, tool

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--tools',type=Path,required=True)
args=parser.parse_args()
cosign=tool(args.tools,'cosign')
bundle=ROOT/'tests/fixtures/cosign-upstream.sigstore.json'
require(sha(bundle)=='e16547fbee348eb23bd7e5a4d542b540395faea2e7bb1d18da01bbc3cc74d57d','FIXTURE_HASH')
base=[cosign,'verify-blob','--trusted-root',ROOT/'trusted-root.json','--bundle',bundle,'--certificate-identity','keyless@projectsigstore.iam.gserviceaccount.com','--certificate-oidc-issuer','https://accounts.google.com']
run([*base,cosign],stdout=subprocess.DEVNULL)
with tempfile.TemporaryDirectory() as d:
    tampered=Path(d)/'changed';tampered.write_bytes(b'this is not the signed official binary')
    wrong_issuer=[str(v) for v in base];wrong_issuer[-1]='https://token.actions.githubusercontent.com'
    wrong_identity=[str(v) for v in base];wrong_identity[wrong_identity.index('--certificate-identity')+1]='https://github.com/test/repo/.github/workflows/release.yml@refs/tags/v1.2.3'
    for command in [[*base,tampered],[*wrong_issuer,cosign],[*wrong_identity,cosign]]:
        result=subprocess.run([str(v) for v in command],capture_output=True,timeout=60)
        require(result.returncode!=0,'INVALID_SIGNATURE_ACCEPTED')
print('Official fixture: valid signature accepted; tamper, wrong issuer and wrong identity rejected. No project release certified.')
