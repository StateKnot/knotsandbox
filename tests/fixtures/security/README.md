# Instance security read contract

`instance-security.json` is a non-secret DTO example for
`GET /v1/instances/{id}/security`. It is test data, not a cloud certification.
`instance-security.enums.json` lists every security-specific enum and the
existing lifecycle observation enums. The schema has no free-form findings,
reasons, commands, URLs, host identities, receipts or policy documents.

The endpoint requires current `instances:read` in the instance's project.
`operations:read` controls only `active_operation.resource`; absent or withdrawn
permission produces `REDACTED` with `resource: null`. It does not require a new
policy permission or change database grants. A mandatory grant, project,
tenant, tenant membership, principal or identity withdrawal hides the resource.
The verified JWT must still be unexpired according to the database clock at
final authorization. The transaction is read only and uses READ COMMITTED to
see revocations after waits.

All evidence comes from one statement snapshot, then is read again with the
same binding. Changed instance/catalog/object/certification records return
409 `SECURITY_TARGET_CHANGED` and can be retried with GET. Mandatory withdrawal
wins over this conflict. Object metadata is a historical control-plane record;
matching Ready metadata is historical launch validation. Node authorization
only describes whether the existing enrollment covers the compute lease at
`as_of`. None proves independent enforcement, a living VM, image signature
verification or a certified runtime. Applied policy, runtime isolation and
image verification therefore remain `UNKNOWN`; runtime certification remains
`NOT_ASSERTED`. Current guard findings also do not claim to be recorded
admission denials; durable denial history is `NOT_CAPTURED`.

`rules_sha256` identifies the exact UTF-8 text returned by PostgreSQL
`rules::text` for JSONB. It preserves decimal/integer precision and is not a
signature, approval or RFC 8785 canonicalization. Both hashing input and read
back are limited to 65,536 **expanded UTF-8 bytes**, independently of TOAST
compression. A larger document is `UNAVAILABLE` with null digest/profile. A
supported policy must exactly equal `{"profile":"deny-all","dns":true}` as
JSONB; extra keys are unsupported. Arbitrary rules are never returned.

Nullable keys are always present: policy `rules_sha256`, `profile`; lifecycle
`observed_at`, `age_seconds`; policy object `ledger_status`,
`recorded_generation`, `observed_at`; launch validation `observed_at`,
`generation`; node authorization `valid_until`; active operation `resource`;
and operation resource `error`. IDs are UUIDs, timestamps are RFC 3339 UTC,
versions/counts are integers. Error output uses the existing public operation
classifier (DEPENDENCY_UNAVAILABLE, OUTCOME_UNKNOWN, OPERATION_FAILED and its
derived retryable flag), not raw errors.

`api_features.instance_security=true` advertises the installed read API. It
never changes runtime certification or enables quarantine/unquarantine.

Run the ordinary, reproducible integration suite against a disposable
PostgreSQL 17+ database whose name ends `_test`. Supply distinct app and
migration/owner connection URLs through private environment configuration;
normal `Fixture::new` applies migrations and validates the app role without
bypasses or private draft DDL:

The real Node case requires the actual SDK build, never a mocked transport or
Rust-only substitute. Install its locked dependencies and build first:

```sh
(cd sdk/typescript && npm ci --ignore-scripts && npm run build)
CARGO_INCREMENTAL=0 cargo test --locked --offline --test instance_security
CARGO_INCREMENTAL=0 cargo test --locked --offline --test instance_security -- --ignored --test-threads=1
```

The ignored cases exercise actual PostgreSQL RLS/revocation and lock waits,
expanded compressed JSON, read-only effects, actual RS256 JWT/JWKS HTTP,
headers, feature flags and optional error redaction. The historical epoch case
changes the installation-wide epoch/safe mode only within that disposable
database and restores them before returning. These tests certify the API
contract and control-plane semantics; they do not certify the cloud runtime.

`real_node_sdk_security_read_redaction_and_live_required_revocation` starts a
real Rust TCP listener and fixture JWKS, then invokes `sdk-http.mjs` through a
private stdin pipe. It imports the actual built SDK, uses its TokenProvider and
generated GET, and verifies three live PG permission phases: normal sanitized
read, optional-operation redaction, and mandatory 404 after withdrawal. The
Node process has a cleared environment, no custom fetch/proxy/auth headers, a
bounded deadline, and only fixed public receipt output. The signed fixture
JWT is validated by the normal Rust authenticator; loopback HTTP is explicitly
test-only. No production guard is replaced or relaxed.
