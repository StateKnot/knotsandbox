#!/usr/bin/env python3
"""Explicit publication only; requires protected GitHub environment and OIDC."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
from common import COMPONENTS, ROOT, image_digest, load, dump, require, run, safe_child, sha, subject, tool
from preflight import check, publication_policy, console_policy
from verify import cosign_arguments, verify_candidate, verify_statement


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--confirm-publish', action='store_true')
    args = parser.parse_args()
    require(args.confirm_publish and os.environ.get('RELEASE_MODE') == 'publish', 'EXPLICIT_PUBLICATION_REQUIRED')
    require(os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL') and os.environ.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN'), 'GITHUB_OIDC_REQUIRED')
    check(args.repository, args.tag, args.commit)
    manifest = verify_candidate(args.directory, args.repository, args.tag, args.commit)
    selection = manifest['console_assets']; previous = selection['previous'] or {}
    console_policy(args.repository, args.tag, selection['first_release'], previous.get('tag',''), previous.get('commit',''))
    require(manifest['run_id'] == os.environ.get('GITHUB_RUN_ID'), 'CURRENT_BUILD_RUN_REQUIRED')
    gh, crane, cosign = (tool(args.tools, name) for name in ('gh', 'crane', 'cosign'))
    publication_policy(args.repository, args.tag)
    with tempfile.TemporaryDirectory(prefix='release-registry-') as temporary:
        env = dict(os.environ, DOCKER_CONFIG=temporary)
        require(env.get('GH_TOKEN') and env.get('GITHUB_ACTOR'), 'REGISTRY_CREDENTIAL_REQUIRED')
        # Token never appears in argv, reports or process logs.
        run([crane, 'auth', 'login', 'ghcr.io', '--username', env['GITHUB_ACTOR'], '--password-stdin'], input=env['GH_TOKEN'].encode(), env=env, stdout=subprocess.DEVNULL)
        for name in COMPONENTS:
            digest = manifest['images'][name]['digest']
            require(image_digest(args.directory / name, name) == digest, 'OCI_LAYOUT_CHANGED')
            repository = 'ghcr.io/' + args.repository.lower() + '/' + name
            # A unique candidate tag cannot affect an installed digest. Stable
            # installation references are emitted only by offline verification.
            reference = repository + ':candidate-' + args.commit + '-' + manifest['run_id']
            run([crane, 'push', args.directory / name, reference], env=env, timeout=600)
            remote = subprocess.check_output([str(crane), 'digest', reference], env=env, timeout=60).decode().strip()
            require(remote == digest, 'REGISTRY_CHANGED_DIGEST')
            run([cosign, 'sign', '--yes', repository + '@' + digest], env=env, timeout=180)
            run([cosign, 'verify', '--certificate-identity', manifest['workflow_identity'], '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com', '--certificate-github-workflow-sha', args.commit, repository + '@' + digest], env=env, stdout=subprocess.DEVNULL, timeout=180)
    bundle = args.directory / 'release-manifest.sigstore.json'
    require(not bundle.exists(), 'BUNDLE_ALREADY_EXISTS')
    # Cosign 3.1.3's --predicate builder emits Statement/v0.1 even for SLSA1.
    # Supply a complete v1 statement explicitly instead of guessing its output.
    with tempfile.TemporaryDirectory(prefix='release-statement-') as temporary:
        statement = Path(temporary) / 'statement.json'
        dump(statement, {'_type': 'https://in-toto.io/Statement/v1', 'subject': [
            {'name': 'release-manifest.json', 'digest': {'sha256': sha(args.directory / 'release-manifest.json')}}],
            'predicateType': 'https://slsa.dev/provenance/v1', 'predicate': load(safe_child(args.directory, 'provenance.json'))})
        run([cosign, 'attest-blob', '--yes', '--statement', statement, '--bundle', bundle, safe_child(args.directory, 'release-manifest.json')], timeout=180)
    run(cosign_arguments(args.directory, args.tools, args.repository, args.tag, args.commit), stdout=subprocess.DEVNULL, timeout=60)
    verify_statement(args.directory, manifest)
    with tempfile.TemporaryDirectory(prefix='release-notes-') as temporary:
        notes = Path(temporary) / 'notes.md'
        notes.write_text('Linux AMD64 release. Verify release-manifest.sigstore.json using the reviewed offline verifier before installation.\n\nSource commit: ' + args.commit + '\n\nRuntime certification and cloud acceptance are separate deployment gates.\n')
        files = [safe_child(args.directory, name) for name in (*manifest['files'], 'release-manifest.json', 'provenance.json', 'release-manifest.sigstore.json')]
        # Stage all assets on a draft; expose only after upload succeeds.
        run([gh, 'release', 'create', args.tag, '--repo', args.repository, '--verify-tag', '--target', args.commit, '--draft', '--title', args.tag, '--notes-file', notes, *files], timeout=1200)
        run([gh, 'release', 'edit', args.tag, '--repo', args.repository, '--draft=false'], timeout=60)


if __name__ == '__main__':
    main()
