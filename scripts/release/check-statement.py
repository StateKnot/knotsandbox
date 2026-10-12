#!/usr/bin/env python3
"""Local test-key Cosign v1 statement roundtrip. Never a production proof."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from common import dump, require, run, tool

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--tools',type=Path,required=True)
args=parser.parse_args()
cosign=tool(args.tools,'cosign')
with tempfile.TemporaryDirectory(prefix='cosign-local-protocol-') as directory:
    d=Path(directory);blob=d/'fixture.json';blob.write_bytes(b'{"local_protocol_fixture":true}\n')
    predicate={'buildDefinition':{'buildType':'https://example.test/local-protocol','externalParameters':{},'resolvedDependencies':[]},'runDetails':{'builder':{'id':'local-test-only'}}}
    statement={'_type':'https://in-toto.io/Statement/v1','subject':[{'name':blob.name,'digest':{'sha256':hashlib.sha256(blob.read_bytes()).hexdigest()}}],'predicateType':'https://slsa.dev/provenance/v1','predicate':predicate}
    dump(d/'statement.json',statement)
    env=dict(os.environ,COSIGN_PASSWORD='ephemeral-local-test-only')
    run([cosign,'generate-key-pair','--output-key-prefix',d/'test'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    # Test-only flags: no OIDC, registry, transparency write or trusted release.
    run([cosign,'attest-blob','--yes','--key',d/'test.key','--tlog-upload=false','--use-signing-config=false','--statement',d/'statement.json','--bundle',d/'bundle.json',blob],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    command=[cosign,'verify-blob-attestation','--key',d/'test.pub','--bundle',d/'bundle.json','--type','slsaprovenance1','--insecure-ignore-tlog',blob]
    run(command,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    payload=json.loads(base64.b64decode(json.loads((d/'bundle.json').read_text())['dsseEnvelope']['payload']))
    require(payload==statement,'STATEMENT_MUTATED_BY_SIGNER')
    blob.write_bytes(b'{"tampered":true}\n')
    invalid=subprocess.run([str(v) for v in command],capture_output=True,timeout=60)
    require(invalid.returncode!=0,'TAMPERED_STATEMENT_ACCEPTED')
    blob.write_bytes(b'{"local_protocol_fixture":true}\n')
    # Production policy must reject this key-only bundle, even with its valid signature.
    production=[cosign,'verify-blob-attestation','--bundle',d/'bundle.json','--trusted-root',Path(__file__).parent/'trusted-root.json','--type','slsaprovenance1','--certificate-identity','https://github.com/local/test/.github/workflows/release.yml@refs/tags/v1.0.0','--certificate-oidc-issuer','https://token.actions.githubusercontent.com',blob]
    rejected=subprocess.run([str(v) for v in production],capture_output=True,timeout=60)
    require(rejected.returncode!=0,'TEST_KEY_ACCEPTED_AS_PRODUCTION_IDENTITY')
print('Local test key: Statement v1 roundtrip passed; tampered blob and production identity substitution rejected. No release signed.')
