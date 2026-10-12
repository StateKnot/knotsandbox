# Installation bootstrap

`sandbox-admin` is an operator CLI, not an HTTP endpoint. It registers one tenant,
one project, an existing identity-provider subject, explicit project grants, an
approved template/policy, and finite tenant/project quotas in one database
transaction. It does not create an IdP account, sign tokens, provision a namespace
or StorageClass, scan an image, deploy a runtime, or verify production isolation.

Run database migrations first. Supply a **dedicated schema/table-owner** database
connection through `SANDBOX_ADMIN_DATABASE_URL`, injected by your secret manager.
Never give that connection to `sandboxd` or an application microservice. The CLI
checks ownership of all ten tables it needs; the limited `sandbox_app` role is
rejected. Avoid `--database-url` in shell history/process arguments even though the
CLI accepts it. JSON input contains no database passwords or IdP client secrets.

## Prepare the input

Save the following structure as a reviewed deployment file, such as
`install/bootstrap.json`. Every UUID must be deliberately allocated and preserved
for retries. Replace the sample issuer/subject, registry/digest, placement and
budgets with verified deployment values. The digest below is an illustrative
placeholder, not a published image. `subject` is the IdP's immutable `sub`, not an
email or a client display name; for Keycloak service clients use the actual
service-account subject from a validated access token.

```json
{
  "tenant": {
    "id": "00000000-0000-4000-8000-000000000101",
    "name": "Example enterprise"
  },
  "project": {
    "id": "00000000-0000-4000-8000-000000000102",
    "name": "Agent workloads",
    "runtime_namespace": "sandbox-agent-workloads",
    "storage_class": "sandbox-workspace-csi",
    "max_ttl_seconds": 3600
  },
  "initial_principal": {
    "id": "00000000-0000-4000-8000-000000000103",
    "issuer": "https://identity.example.com/realms/sandbox",
    "subject": "replace-with-actual-immutable-subject",
    "kind": "USER",
    "display_name": "Initial sandbox administrator",
    "project_actions": ["*"],
    "tenant_actions": []
  },
  "approved_template": {
    "id": "00000000-0000-4000-8000-000000000104",
    "name": "python-approved",
    "version": 1,
    "image_ref": "registry.example.com/sandbox/python",
    "image_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "runner_version": "1.0.0"
  },
  "security_policy": {
    "id": "00000000-0000-4000-8000-000000000105",
    "name": "deny-all-with-managed-dns",
    "version": 1,
    "rules": {"profile": "deny-all", "dns": true}
  },
  "quotas": {
    "tenant": {
      "instances": 20,
      "cpu_millis": 20000,
      "memory_mib": 40960,
      "workspace_gib": 400,
      "executions": 20
    },
    "project": {
      "instances": 10,
      "cpu_millis": 10000,
      "memory_mib": 20480,
      "workspace_gib": 200,
      "executions": 10
    }
  }
}
```

`kind` is `USER` or `SERVICE`. SERVICE must include the exact reviewed `client_id` from its access token (`azp` in Keycloak); USER must omit `client_id`. `project_actions` is mandatory. A project administrator
uses explicit `["*"]`; a calling microservice should receive only the needed actions,
for example `instances:create`, `instances:read`, `instances:start`, `instances:stop`,
`instances:restart`, `instances:renew`, `instances:delete`, `operations:read`.
Project history consumers may also receive `events:read` and `audit:read`.
Capability discovery requires the separate `capabilities:read` grant.
Execution callers additionally use `executions:create`, `executions:read`, and
`instances:hard_stop`; submission requires explicit `on_timeout:HARD_STOP_INSTANCE`.
Whole-instance execution cancellation requires both `executions:cancel` and
`instances:hard_stop`; the API also requires explicit `hard_stop_instance:true`.
Bootstrap defaults to no tenant-wide grant and never infers grants from OAuth claims.
Optional `tenant_actions` accepts only `service_clients:read`,
`service_clients:write`, and `tenant_audit:read`; explicitly list the required actions when initializing a tenant identity
administrator. Project wildcard authority does not imply tenant identity management.
Exact retries compare both scope sets. Adding identity-administration permissions
to an existing installation requires a reviewed owner grant change, not silently
changing a prior bootstrap file.

All five quota dimensions are required for both scopes. Values must be nonnegative;
zero deliberately disables that budget. Project limits cannot exceed tenant limits;
missing values and the `i64::MAX` unlimited sentinel are rejected. Existing usage
counters are never reset. CPU is in millicores, memory in MiB, storage in GiB.

Only `{ "profile": "deny-all", "dns": true }` is approved by this CLI version.
Unknown policy fields, permissive egress lists and alternate profiles fail validation.
The runtime must independently enforce that policy and the explicitly configured
cluster DNS endpoint. Registering a policy is not evidence that a CNI enforces it.

`image_ref` is a repository without tag or digest, and `image_digest` is a mandatory
lowercase SHA-256 digest. The operator is responsible for the image approval evidence,
signature, vulnerability assessment and runner compatibility before using `--apply`.
The CLI cannot infer those from a well-formed digest.

## Validate and apply

These commands use the repository's pinned toolchain and locked dependencies:

```sh
cargo run --locked --bin sandbox-admin -- \
  --file install/bootstrap.json --validate-only
```

Validation reads at most 65537 bytes, accepts at most 65536, rejects unknown JSON
fields and does not contact any database or IdP. The result includes the normalized
specification SHA-256 and `database_checked: false`.

For the first installation, deliberately allocate and record a cluster epoch UUID
in the operator configuration. Pass that exact value explicitly:

```sh
cargo run --locked --bin sandbox-admin -- \
  --file install/bootstrap.json --apply \
  --initialize-cluster-epoch 00000000-0000-4000-8000-000000000106
```

Replace the sample epoch with the installation's recorded UUID. A missing operator
configuration requires `--initialize-cluster-epoch`; the CLI never invents one.
An existing different epoch causes the entire transaction to fail. This is **not**
a disaster-recovery epoch rotation tool. On retry, pass the same value or omit the
flag after initialization.

A newly created `platform_configuration` always has `safe_mode=true`. Bootstrap
never turns safe mode off; an existing configuration preserves its current mode.
Review the returned `cluster_epoch`, `safe_mode`, IDs and `spec_sha256`. Enabling
compute is a separate controlled operator procedure after runtime, networking,
storage and recovery validation. The owner connection is not retained by the API.

Local development may add `--allow-loopback-http`, permitting only a literal
loopback issuer (`127.0.0.1` or `::1`) without TLS. This does not permit arbitrary
HTTP hostnames or private IPs. Use the actual port from the local environment;
production issuers require HTTPS.

## Retry and conflict behavior

Repeating the same IDs and configuration succeeds and reports `changed:false`.
Each successful invocation appends an audit record with the request ID, actual
database role, specification hash, affected IDs, explicit grants and resulting
safe mode. It does not impersonate the newly registered user as the actor.

Existing records are compared before acceptance. The command does not silently
replace tenant/project ownership or settings, template/policy contents, quota
limits, disabled identities, existing grants, or the cluster epoch. An issuer/sub
already bound to a different principal is rejected. Adding a new issuer alias to
an existing principal requires a separate IdP migration workflow; an email match
is never used. Grant changes, quota changes and re-enabling a revoked principal
are not bootstrap operations.

Conflicts and database failures roll back the whole transaction. A lost connection
while committing can leave the client uncertain whether the commit succeeded;
rerun the same file and identifiers to reconcile safely. Do not generate fresh IDs
to get around an unexplained conflict. Retain the JSON, its hash and CLI exit/result
in the deployment change record; do not retain tokens or secrets there.

Instance `stop`, `delete`, and `restart` each require both their corresponding
action grant and `instances:hard_stop`, including retries with an existing
idempotency key. This version terminates the whole VM; an empty activity slot
does not imply there are no guest background processes. `start` and `renew`
do not require `instances:hard_stop`. Grant revocation prevents new requests and
replays; it does not obstruct safety cleanup that was already accepted.

Project authorization administrators require `grants:read` and `grants:write`, plus
every exact action they will delegate. The grant API bounds both scope and expiry
and cannot create wildcard or tenant-wide grants; see [grant management](grants.md).
Persisted execution output additionally requires `executions:output:read`; this is
separate from metadata access and is not granted automatically.

File transfer access requires explicit `files:read` for downloads or `files:write`
for uploads. Metadata permissions do not imply either action. Bootstrap accepts
both permissions, and the project grant API applies the same scope and expiry
limits as other delegated actions. File quotas and configured storage credentials
are additionally required; permissions alone do not enable a transfer.

Automation management similarly requires explicit `automations:read` and
`automations:write`. These permissions authorize rule management only. Each rule
also retains a finite delegation of the creator's exact business actions, whose
current scope, expiry and identity are rechecked before a run is accepted.
Bootstrap accepts these two permissions. Their delegated grant API requires the
automation migration (0039), which is currently a private development draft.
Provisioning them does not enable the automation controller or bypass its
migration and startup checks.

Restore acceptance separately requires `backups:restore` on the source project
and `instances:create` on the target project; restore metadata requires
`restores:read`. Bootstrap accepts the restore permissions explicitly, while
delegated grant management requires formal migration 0038. That migration is
currently a private development draft. A grant cannot enable restoration,
turn a source backup into a writable workspace, or bypass current runtime and
cleanup certification.

## Optional feature budgets

Both `quotas.tenant` and `quotas.project` may explicitly provide `backup_gib` (retained backups) and `backup_temp_gib` (temporary isolated backup volumes). Missing values create no account and do not grant an unlimited budget. Specify each dimension in both scopes, with nonnegative project limits no greater than tenant limits. Adding previously absent dimensions through the same owner bootstrap preserves existing limits and allocations; changing an existing limit remains a conflict. Old bootstrap files retain their original quota encoding and do not remove newer accounts. Backup jobs also reserve their own CPU and memory while running.

`file_transfers` and `file_transfer_bytes` use the same optional contract; provisioning those accounts requires the file-transfer migration (0036). The byte budget is measured in bytes and covers retained temporary objects until verified cleanup. These parser fields do not themselves enable file-transfer APIs.
