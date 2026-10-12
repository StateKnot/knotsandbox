# Formal automation acceptance

Only the signed HTTP/SDK helper and CI composite action remain here. Production
SQL is `migrations/0039_automations.sql`, grants are
`scripts/sql/automation-role.sql`, and the process is
`src/bin/sandbox-automation.rs`. Obsolete draft copies are removed.

Run `python3 scripts/test-automation.py` after the locked Rust/Node toolchains,
Docker, Python 3 and OpenSSL are available. It builds ordinary Cargo test artifacts
and the locked SDK, creates only a fresh disposable loopback PostgreSQL container
with random SCRAM identities and a test CA/IP-SAN leaf, then invokes actual
`sandboxd --role migrate`. It verifies formal versions 1..37 + 39 with embedded
checksums; unpublished 38 is permanently reserved and never loaded or faked.

The original 18 durable acceptance/fault/real HTTP/SDK cases remain. The separate
real worker process test covers check, post-connect startup failure, two normal
ready/SIGTERM runs, full process labels, restart UUID changes and same-login
physical backend absence. Its test locks and disposable TLS do not establish
production PKI, Kubernetes identities, cloud isolation or measured capacity.

The runner cannot select an existing database or reuse credentials. Passwords
stay in memory and child environments/stdin; source fingerprints, non-secret
ledger and private logs are written to a new evidence directory. Only its own
child process group and container are cleaned up. To use previously built
artifacts, provide all of `--test-binary`, `--process-test-binary` and
`--migration-binary`; `--skip-sdk-prepare` requires an already built locked SDK.

CI after checkout and locked Rust/Node setup uses:

```yaml
- name: Independent formal automation acceptance
  uses: ./tests/fixtures/automation
  with:
    evidence-directory: .local/automation-ci-evidence
```

No image, code, or evidence is uploaded or published by this action.
