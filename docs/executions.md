# Execution API and dispatch boundary

This build implements durable command acceptance, execution metadata reads and
whole-instance cancellation. The worker currently retains commands at
`WAITING_GATEWAY`; it does **not** remotely launch accepted commands. The database
dispatch gate is implemented for the future verified Kubernetes exec caller.
These APIs and database tests do not demonstrate cloud execution or VM isolation.

## Microservice contract

Use a verified OAuth access token, `X-Tenant-ID`, and current product grants.
`executions:create`, `executions:read`, and `executions:cancel` are separate grants.
Command acceptance also requires `instances:hard_stop`: every command must
explicitly select `on_timeout: HARD_STOP_INSTANCE`, authorizing whole-instance
termination at its accepted execution deadline.
Strong cancellation additionally requires `instances:hard_stop` and the explicit
body `{"hard_stop_instance":true}`. Bootstrap accepts these explicit project grants.

1. Read the instance and retain its ETag.
2. Send `POST /v1/instances/{id}/executions` with that `If-Match` and a persisted
   `Idempotency-Key`:

   ```json
   {
     "argv": ["/usr/bin/python3", "-c", "print('hello')"],
     "public_env": {"TASK_MODE": "batch"},
     "cwd": "/workspace",
     "timeout_seconds": 60,
     "on_timeout": "HARD_STOP_INSTANCE",
     "output_limit_bytes": 1048576,
     "client_reference": "job-2026-001"
   }
   ```

3. Persist the returned execution ID and operation ID. HTTP 202 means acceptance.
   `Location` points to the execution; `ETag` is its version. `X-Instance-ETag` and
   `instance_spec_version` describe the instance version after acquiring its slot.
4. Read `GET /v1/executions/{id}` for current status. An idempotent POST replay
   returns its original receipt, which may be older than the current execution.
5. To request cancellation, send `POST /v1/executions/{id}/cancel` with the current
   **execution** ETag, a persisted new idempotency key and
   `{"hard_stop_instance":true}`. This terminates the entire instance; the
   workspace remains retained. Observe `termination_status` separately from status.

After a timeout or broken connection, reuse the original body, key and ETag.
Never manufacture a new key merely because the result is uncertain. A key is
scoped to tenant, principal, action and target. The active operation keeps replay
available; otherwise the seven-day receipt period and retained tombstone prevent
silent re-execution after expiration. Changed parameters with the same key return
`IDEMPOTENCY_CONFLICT`; an expired retained key returns `IDEMPOTENCY_EXPIRED`.

## Input and data handling

`public_env` is deliberately **non-sensitive** configuration. Its values and argv
are stored in the private EXECUTE operation request as plaintext for the worker.
Do not put tokens, passwords, keys or other secrets in either field. This version
has no secret-reference resolution or encrypted execution-secret store, and rejects
unknown secret fields. The name `public_env` is a caller contract, not a content
scanner that can infer whether an arbitrary value is a secret.

The API reuses the Runner's validator and duplicate-environment-name parser.
There are at most 64 argv entries and 64 environment variables, a 16 KiB environment
budget, 4 KiB per environment value, and 64 KiB encoded Runner input. Timeout is
1–3600 seconds; retained raw output is limited to 16 MiB. Reserved environment names,
NUL characters, parent-directory traversal and working directories outside
`/workspace` are rejected. The Runner later opens each directory component without
following symlinks. Shell expansion occurs only when the caller explicitly invokes
a shell in argv. The API never interpolates a command into a shell or exec URL.

GET, mutation receipts, audit details and domain-event payloads exclude argv,
environment values and raw Runner messages. HTTP completion logs contain request
ID, status and duration. Errors never echo submitted command parameters.

`result_ref` is null until a trusted output store has persisted a manifest. A
reference contains an object key scoped to
`tenants/{tenant_id}/executions/{execution_id}/`, SHA-256 and size. The API validates
these fields and does not return arbitrary stored JSON or Runner-supplied URLs.
Invalid references are withheld with `output_status: LOST`; execution metadata
and its current ETag remain readable so damaged output cannot block cancellation.
This build has no output download or SSE-output route and issues no presigned URL.

## Acceptance, dispatch and termination

Acceptance locks workspace → instance, checks current authorization, safe mode,
compute lease, lifecycle ownership and an empty activity slot, then verifies typed
worker-written Ready evidence against the current generation, launch, Pod UID and
cluster epoch. A historical `RUNNING` string without matching evidence is
insufficient. The workspace must be in use without another operation or deletion.
Tenant and project EXECUTIONS quota are both reserved in the same transaction as
the execution, operation, slot, audit event and idempotency receipt.

Timeout includes queue time and starts at acceptance. Its deadline must fit the
current compute lease. The dispatcher reduces the Runner timeout to the remaining
budget. An elapsed deadline prevents dispatch; it does not by itself prove that
a previously dispatched workload has terminated.

Admission, idempotent replay and dispatch all check the current hard-stop grant.
Accepted timeout safety work subsequently uses the system identity, so later
revocation does not disable safety termination. The policy is persisted with the
command. Older queued records lacking that policy cannot be dispatched by silently
adding a default.

`Database::begin_execution_dispatch` is an internal worker boundary, not an HTTP
endpoint. Before calling it, the dispatcher must freshly verify Kubernetes Pod
identity/readiness, the PVC and network policy. It supplies the exact
`DispatchIdentity`; the transaction rechecks the current launch, slot, grant,
worker claim, cancellation and deadline. It commits a unique attempt ID and
`DISPATCHING` **before** returning the in-memory Runner request. Only after that
successful commit may the caller initiate one remote exec call.

A retry finds the persisted attempt and refuses to return another dispatch.
After an ambiguous commit or transport loss, the caller must reconcile or record
`OUTCOME_UNKNOWN`; it must never automatically repeat the command. Dispatch
evidence cannot be replaced or cleared in SQL. API idempotency does not make a
command's external side effects idempotent; callers still need their own business
idempotency key and reconciliation logic for those effects.

Strong cancellation fences the original EXECUTE operation and creates, or reuses,
a STOP operation. It preserves activity slots and quotas while setting termination
to `PENDING`. A queued execution can therefore remain `QUEUED` with an explicit
`cancel_requested_at` while awaiting VM termination evidence. A dispatched execution
with an uncertain result becomes `OUTCOME_UNKNOWN`.

Cancellation, timeout and ambiguous transport failure retain the slot and
EXECUTIONS quota until trusted VM termination. A guest exit receipt, guest
`killpg`, a Pod delete request or cancellation acceptance does not establish that
evidence. Normal platform activity completion may be established separately by
independent Kubernetes exec terminal status; it does not prove that malicious
background processes or the VM have stopped and must not set VM termination to
`CONFIRMED`. Even after VM termination is `CONFIRMED`, an
`OUTCOME_UNKNOWN` business result remains unknown. A cancellation for an older
launch cannot stop a different current launch.

## Verification

Run the execution transaction suite against the disposable PostgreSQL database:

```sh
set -a
source .local/dev.env
set +a
cargo test --locked --test executions -- --include-ignored
```

The tests use real PostgreSQL transactions and RSA-signed access tokens. Ready
records are owner-seeded test prerequisites; they do not represent a Kubernetes
observation. Tests cover concurrency, idempotency, quota rollback, launch evidence,
revocation, a single durable dispatch attempt, strong cancellation and metadata
privacy. Production release still requires the actual exec transport, output
storage, node-failure handling and trusted VM-termination verification.
