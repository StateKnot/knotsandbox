# Durable schedules and event automations

The normal API and independent `sandbox-automation` worker use formal migration
0039, the 0040 SERVICE identity binding contract, 0041 private scan metadata,
0042 anomaly notifications, and 0043 scoped deferred file-activity validation with
the embedded checksum ledger. The complete formal ledger is 1..37 + 39..43
(42 migrations). Migration 0038 was never published and
is permanently reserved; it must not be backfilled later. Future restore
promotion requires a new higher version. Automation has no restore dependency;
restore routes and partial-schema refusal remain closed independently.
Normal `sandboxd --role migrate` installs API grants and, when provisioned,
the coordinator's dedicated grants. Runtime startup checks these before binding.
API capability flags describe enabled routes, not a running worker or runtime
certification. No draft SQL or fabricated migration ledger is accepted.

Normal `GET /v1/capabilities` also returns the versioned, nullable `automation`
contract. When enabled, version 1 publishes all seven actions/three triggers,
UTC cron and missed-run semantics, finite creation limits and UNKNOWN handling.
The API validator and contract share `src/automation_contract.rs`; no migration,
extra authority or new scheduler is introduced. Disabled routes return `null`.
The console requires a recognized contract for creation/resume and uses its
limits in the form. Missing/malformed/unknown-version contracts clear only
unsubmitted drafts, while reads, pause/revoke and original-key reconciliation
remain available under their normal authorization. See [discovery contract](capabilities.md).

## Management and microservice contract

The normal router implements eight versioned endpoints: creation under
`/v1/instances/{id}/automations`, policy list/read, per-policy run history,
`/v1/automation-runs/{id}` and explicit pause/resume/revoke actions. Creation
uses the instance ETag; each action accepts `{}` with the policy ETag. Mutations
require the existing management idempotency header. The real HTTP fixture uses
the core identity resolver, request boundary and permission-delegation endpoints.
The TypeScript `waitAutomationRun` helper reads only the original run. A timeout
returns the last observed status and starts no replacement action.

Formal migration 0042 adds a project-scoped durable anomaly inbox through three
normal authenticated routes: project history, one notification and versioned
acknowledgement. It records immutable FAILED/OUTCOME_UNKNOWN facts from newly
committed run events, with no backfill or external delivery. ACK uses current
`automations:write`, the notification ETag and the original management key; it
never changes or retries the run. Installation, closed metadata, live grants,
pagination, lost-receipt handling and operational limits are specified in
[automation notifications](automation-notifications.md). Its current-source real
PostgreSQL/HTTP/SDK and separately scoped Chrome/BFF acceptance passed locally
on 2026-10-11; the exact scope and retained evidence are recorded in
[the delivery checkpoint](../research/automation-notification-inbox-20261011.md).

An automation targets one tenant/project/instance/workspace and one immutable
operation. Creation requires a current verified identity, `automations:write`,
the requested action permissions, an instance `If-Match`, and an idempotency key.
Responses return policy metadata and the management receipt expiry. Neither
policy metadata nor run history returns raw command/environment/backup arguments,
issuer/sub mappings, cloud credentials, lease tokens, request keys or dispatch
attempt IDs.

| Database method | Input and resulting behavior |
| --- | --- |
| `create_automation` | Actor, VerifiedIdentity, instance ID, CreateAutomation, key, instance version, configured max TTL. Returns 201 or the original retained receipt. |
| `get_automation` | Current Actor and automation ID; requires `automations:read` in the policy project. |
| `list_automations` | Actor, HistoryQuery and CursorSigner; tenant/project scope, signed cutoff pagination. |
| `change_automation` | Actor, VerifiedIdentity, policy ID, PAUSE/RESUME/REVOKE, key and policy version. Returns current committed metadata. |
| `get_automation_run` | Current Actor and original run ID; exact metadata lookup and current `automations:read` authorization. |
| `list_automation_runs` | Actor, policy ID, HistoryQuery and CursorSigner; scope-bound metadata, operation link, status and sanitized failure code. |
| `check_automation_api_schema` | Refuses draft/incorrect migrations or incomplete API grants before route availability. |

`CreateAutomation` has explicit `name`, `action`, `trigger`,
`delegation_expires_at`, `run_budget`, `minimum_interval_seconds` and
`grace_seconds`. No implicit infinite lifetime/budget is allowed. Request/action/
trigger structs reject unknown fields. Actions are START, STOP, RESTART, DELETE
(instance only), RENEW, EXECUTE and BACKUP. EXECUTE and BACKUP reuse the production
request types and validation. No workspace destruction, arbitrary HTTP callback,
predicate interpreter or host script is introduced.

Permission intersection is fixed to the creator's identity and concrete required
actions. STOP/RESTART/DELETE and EXECUTE include the existing
`instances:hard_stop` requirement; EVENT also needs `events:read`. Both creation
and every acceptance check current identity mapping, principal, tenant/project,
local grants and explicit finite delegation. Only USER/SERVICE creators may
delegate. No JWT/refresh token is stored, and the scheduler does not assert that
an old JWT remains valid: the creator explicitly delegates limited lasting
authority, bounded by current grant expiry, at most 366 days and 1–10,000 runs.

Pause, resume and revoke require a current valid caller identity and
`automations:write` in the policy's project; the caller need not be its creator.
Pause and revoke require management authority without the rule's execution
permissions. Resume additionally checks every concrete action required by the
existing rule against the caller's current token scopes and database grants.
A new resume acceptance also revalidates the original creator's durable
delegation and current authority. Management never replaces or extends that
delegation's identity, scope or expiry.
Pause prevents new acceptance, and revocation is irreversible. Neither pause nor
revocation cancels the real effect of an already accepted operation. Rule status is ACTIVE/PAUSED/REVOKED/EXHAUSTED/
EXPIRED. Policy/action/body/delegation scope are immutable; changes to the action
or trigger require a new versioned creation receipt and explicit old-rule revoke.
There are fixed limits of 100 live policies per project and 1,000 per tenant;
paused delegations receive a durable expiry wakeup.

## Policy-management console increment

Status: local management acceptance passed; production certification remains open. The formal backend checkpoint is `0b0985e`;
versions 1..37 plus 39 remain the normal ledger, and unpublished 38 is permanently
reserved. The console now exposes finite authorizations for the seven actions
and three trigger kinds above, with an explicit proposal preview and typed
instance UUID confirmation. It runs no scheduler and grants no authority from
capability flags. Creation reads the current exact instance ETag; explicit
pause/resume/permanent revoke use the policy's actual GET ETag. Policy and original
run views validate the current tenant/project/instance or policy scope and expose
metadata only, without requiring operations:read or displaying raw workload data.
Read denial clears old evidence and drafts; restoration requires explicit reread.

For automation creation, the journal persists only the original key/ETag/body
hash and reconciliation metadata. The original body is held in actor/CSRF-bound
memory and forgotten on scope changes. After reload, UNKNOWN requires explicit
re-entry of identical original JSON; digest validation restores memory only,
and the ordinary original-key confirmation sends it. It cannot replace the key
or silently create a new request. Accepted entries retain resource lookup facts.

The root-run local driver is `scripts/test-console-browser.py`, reusing the exact
existing ignored BFF browser selector, protected local role inputs, explicit
absolute executables and fixed local PostgreSQL/Keycloak containers. Its actual
branch created only a +30-minute ONCE RENEW with +1-hour delegation
and budget1; deliberately lose a real committed response; reload/recover/replay
its original key/body/ETag; and verify unique policy/delegation/receipts/audits,
three versioned management changes, CSRF/stale-ETag refusal, empty run history
without operations:read and live read revocation. Full instance/workspace/
execution/operation facts must remain unchanged. No automation worker is started
by this browser fixture; this is management acceptance, not seven-action or
three-trigger execution certification. Original account/diagnosis/event/stop
assertions and deadlines stay intact.

At the immutable 758-file source `b18d4ac4ab89205dea2e94882023f43485962585821a8f962744f9b0c35261db`,
59 console unit tests, eight mock-Chrome contracts and strict Clippy/fmt passed.
The actual Chrome/Keycloak/BFF/API/PostgreSQL management and original account,
diagnosis, event and stop/revocation chain passed 1/1 (17.91 seconds; command
18.576 seconds); record `.local/evidence/console-automations/1791554745346766000/record.json`
binds unchanged bytes/modes. The production context contains 22 direct source inputs and one first-release
manifest derived by stage_context(previous=None). Recreating the context from
the actual immutable snapshot matched all 23 build-input hashes and built native arm64 image `sha256:8348e298b2810ea24c3b5f384b99e3160d68e08a617d8a69feba09422797da86`;
nonroot/readonly, CSP/assets and TLS CA/SAN/SNI positive/negative checks passed
using a separate transport fixture. Aggregate `.local/automation-console-20261009/validation-final.json`.
The first actual chain failed because its test expected FORBIDDEN rather than the
existing 403 PERMISSION_DENIED; only that expected code changed, preserving
production behavior, 403/412, deadlines and all fact assertions. Failed browser
attempts and original authored-NOT_RUN receipts remain recorded. Malformed or
settled-null capability responses forget payloads and old selection; transient
loading retains state but blocks writes. Target-cluster HA, real cloud effects/execution
capacity and current-source eight-ELF scans/signed release acceptance remain open.

## Trigger and missed-run semantics

ONCE uses an explicit RFC3339 timestamp. CRON_UTC uses the pinned `cron =0.17.0`
parser with seven fields: second/minute/hour/day-of-month/month/day-of-week/year.
Second must be `0`, year `*`; the time zone is UTC. Day-of-month and day-of-week
use the parser's intersection semantics. Local system timezone and DST are never
inferred. See the [official parser documentation](https://docs.rs/cron/0.17.0/cron/struct.Schedule.html).

PostgreSQL clock time owns due times, grace and deadlines. A scheduler processes
one occurrence per declaration and moves the next due time into the future. It
does not replay each interval missed during downtime; within grace it accepts at
most one past occurrence, and outside grace it records one SKIPPED span. Cron,
Once and Event all consume their finite run budget when a run/skipped span is
persisted. Grace is 1–3,600 seconds. Only one unclosed run may exist per rule;
a future occurrence never bypasses an execution slot or backup hold that is still
held by an earlier run.

EVENT matches an exact event type plus aggregate UUID in the policy project.
Creation starts after the committed stream head. Processing reads at most 256
ordered stream positions per transaction and commits the scan position even when
nothing matches. Each source event is uniquely linked to one rule run. Events
known to originate from automation runs/operations do not retrigger rules. An
explicit 60–86,400 second `minimum_interval_seconds` EVENT cooldown, finite run
budget and delegation lifetime bound indirect feedback. Rate-limited matching
events become SKIPPED runs and consume budget; they are not buffered for dispatch
after cooldown. ONCE and CRON_UTC also require this field within its fixed range,
but cron frequency is determined by the expression, not by this cooldown.
Guest-controlled telemetry is not an event
trust source. Stream epoch is immutable in a rule: a stream reset fences old
prepared intents and pauses the rule; resuming cannot reinterpret an old cursor
in a new stream, so an operator must explicitly recreate it.

## Dispatch and failure safety

The dedicated `sandbox_automation` login obtains one private 30-second queue
claim through SECURITY DEFINER functions, commits that claim, then takes tenant
resource locks. It cannot SELECT the queue/private run tokens or UPDATE the run
claim/attempt fields. Each claim captures the current control epoch; an old
claim cannot prepare/accept after epoch change or while global safe mode is on.
A new coordinator may reconcile the existing intent under a fresh claim.

Before calling any management acceptor, a transaction persists the run UUID,
fixed execution/backup resource UUID, original request, exact normalized
operation request/hash, one key, original If-Match/generation/control epoch,
deadline and dispatch identity. The four existing production acceptors share
one private implementation with their normal public paths. Automation adds only
a narrow transaction fence, operation INSERT gate, and atomic operation/run
link. It does not duplicate business SQL or use a SYSTEM principal.

All action paths take workspace → instance → optional prior operation → policy
→ delegation → run → new operation → quotas → event head. Prepare, pause,
revocation and reconciliation use the same resource-first order; the queue claim
never holds resource locks. After the final event-head wait, a deferred database
constraint verifies present delegation, grants, claim, deadline and epoch before
commit. An accepted operation and its run link either both commit or both roll
back.

A lost receipt reconciles that durable link. If the link is absent, resource
locks first prove that a previous acceptance transaction ended; any retry uses
only the same run/request/key/If-Match/resource UUID. An idempotency timeout is
never permission to replace an ambiguous accepted execution. OUTCOME_UNKNOWN
blocks a second run. Completion requires the real operation's terminal result
and its physical effect closure: execution slot released, backup hold-release
receipt, or lifecycle ownership closed. Process exit, elapsed lease time and a
failed operation alone are not VM-death or cleanup evidence.

Run states are PENDING → CLAIMED → DISPATCHING → SUBMITTED → SUCCEEDED/FAILED,
with explicit SKIPPED/CANCELLED/OUTCOME_UNKNOWN branches. Preparation, completion, failure/cancellation and
policy state changes produce audit/domain events using the committed policy/run
version. History is tenant RLS protected and uses the existing signed cursor
format. Current creator revocation blocks new work but does not suppress safe
reconciliation of an already accepted operation.

The worker distinguishes business rejection, temporary infrastructure failure
and fatal infrastructure/invariant failure. Missing runtime privileges, invalid
persisted action/schedule/request data, an inconsistent original request or a
closed database pool stop scheduling. A fatal acceptance error leaves the
prepared run and its original claim intact; it does not mark the intent FAILED
or finish the claim. The controller cancels and joins the health server, awaits
the shared database drain and exits nonzero with a fixed sanitized error. A
fresh worker can reconcile the same intent after the original lease expires.

Retryable acceptance failures reconcile the original intent, normally finish
the routing claim, advertise unready and use the existing two-second backoff.
The queue's actual `eligible_at` still governs reclaim: it may retain the
original thirty-second run lease, rather than becoming eligible in five
seconds. Current authority/lease/version guard SQLSTATEs P4090/P4120 are mapped
only inside automation to retryable `AUTOMATION_FENCE_CHANGED`; all other
callers retain their existing SQL-to-HTTP behavior. Safe mode can invalidate a
claim before error recording, so a rejected final commit may retain the original
DISPATCHING intent with no failure code instead of recording OUTCOME_UNKNOWN.
Neither branch permits a new key, request, resource or second run.

Readiness requires a successful scheduling poll and, within its original
two-second budget, the shared formal migration/role/complete minimum privilege
verification. A prior successful poll cannot hide later privilege revocation.
Shutdown is checked before and after the probe; responses expose no SQLSTATE,
provider message or role metadata. Internal SQLSTATE provenance is a fixed
five-character class/code and is not part of the public Problem response.

## Evidence and promotion

The 2026-10-10 runtime supervision increment used immutable 760-file source
`92bda2d8de4eb9f48c2ad18873e0e965c23373062adf90f6b2a31d76cc75805f`.
In one owned disposable PostgreSQL 17.11 TLS server, the runner migrated two
independent databases through the normal binary. The original 18 signed
HTTP/SDK/durable acceptance cases passed in 49.05 seconds. The one real process
test passed in 116.79 seconds, retained the original four startup/shutdown
trials, and added five real runtime scenarios:

| Scenario | Required observed result |
| --- | --- |
| Revoke queue-claim EXECUTE after ready | ready503, nonzero exit, health listener and exact physical backend absent after the shared drain |
| Hold queue lock through the original lock timeout | ready503 while alive, observed timeout plus backoff, then same process returns ready204 |
| Revoke execution INSERT during real acceptance | original committed DISPATCHING intent, zero committed acceptance facts, fatal exit; restored grant and replacement process reclaim after natural lease expiry and accept that same intent once |
| Hold the exact EXECUTIONS quota rows | real acceptance timeout and rollback, OUTCOME_UNKNOWN and normal routing-claim finish, then same process accepts once at actual eligibility |
| Enable safe mode before releasing the acceptance quota lock | actual deferred COMMIT P4090 rejection, no committed operation/execution/quota, normal routing-claim finish; restore safe mode and same process reconciles the original intent once |

These scenarios use the normal worker and public database management entry
points. They do not delete queue rows, rewrite leases or shorten production
timeouts. Recovery compares the original request/key/resource/version/epoch and
immutable dispatch facts, then checks the unique operation, execution,
idempotency entry and tenant/project quota reservations. Accepted execution
activity remains held through SIGTERM. Owner-provided RUNNING/readiness fixture
facts establish controlled acceptance preconditions, not guest/VM certification.
P4120 follows the reviewed same guard classification but has no separate real
process injection; persisted-payload corruption has not been injected by
bypassing database constraints.

Runner duration was 177.429 seconds. Each database's 38 actual SHA384 ledger
entries matched formal 1..37 plus 39, with no 38 or restore schema. Owned test
process and container cleanup were confirmed. The same source passed ordinary
all-target regression: 52 programs, 417 passed, zero failed and 224 explicitly
ignored; strict Clippy, fmt and SDK build also passed. The ignored tests require
external prerequisites and are not acceptance passes. Evidence is
`.local/automation-supervision-20261010/1791598764490565000/record.json`
(SHA256 `373c34225695f27fa30ebc8c9d3e3365e9ab23b74d95360546f8c5ecc327681b`),
with `actual/evidence.json`, `actual/acceptance.log`, `actual/process.log` and
`ordinary.log` in the same directory. All recorded implementation source bytes
and modes stayed unchanged across these checks; delivery documentation is a
later, separately captured change. This evidence does not promote G3-07 to
cloud/HA/capacity or signed-release acceptance.

The 2026-10-09 final local formal run used the immutable 751-file source
`00e07e85dd815dc330061fcccbdeff6981c849cb9181b463a63a484e656bb1e5`.
The original 18 real PostgreSQL/signed HTTP/Node SDK cases passed in 50.22 seconds;
one separate process test passed in 2.14 seconds and exercised four real worker
processes: check, occupied-listener startup failure and two ready/SIGTERM runs
under one fixture Pod UID. Their process UUIDs were distinct, database sessions
used actual TLS, and an independent same-LOGIN observer verified the physical
backends absent after exit. The runner took 63.077 seconds, invoked normal
`sandboxd --role migrate`, matched all 38 embedded SHA384 checksums for versions
1..37 plus 39, and confirmed both its child and container cleanup. No 38 ledger
row or private restore schema was installed. Evidence is
`.local/automation-production-20261009/actual-3-record.json`,
`actual-3/evidence.json` and `validation-final.json` in the same directory;
The same source subsequently passed the complete ordinary all-target run:
52 programs, 416 passed, zero failed and 224 explicitly ignored. The ignored
cases require external prerequisites and are not additional acceptance passes.
`rust-all-targets-final-record.json` binds this result and unchanged source/modes;
its log SHA is `d97729cc6d6e458c0ca1e07683232b6942de805dc49b8b0a7d9b151da0a9b180`.

Only this final source passed. The earlier source
`e385b59f8408975d946155ed3abb1af1d0ac59d7d9c94a98f8bda11cced3e29d`
completed five cases, then hung at the retained draft startup test until owned
interruption (exit 130; 336.551 seconds). Source
`b2ccaff32e88a714366041fb62870a500110b33f3cf65d7a2f8103639afd8141`
returned exit 101 after 17 passes and one signed HTTP failure (54.722 seconds);
its process suite was not reached. The corrections replace the stale draft
failure assertion with successful formal API/controller checks, ensure the test
worker is aborted and joined if its original five-second join expires, and remove
the two unpublished restore actions from the normal API/OpenAPI allowlists.
Business, lost-receipt, idempotency and metadata assertions remain; no deadline
or authority was widened. `failure-summary.json` and both original actual records
retain these failures rather than treating them as a final-source pass.

The associated SDK 61 tests, release protocol 63 tests, renderer four tests,
fixed official resource schema validation, five API contract tests, console
build and strict Clippy/fmt passed as separate checks. None substitutes for a
current-source eight-ELF Linux build, full scans or signed release acceptance.
The signed HTTP identity/closure fixtures and disposable database test CA prove
local management and connection behavior; they do not prove production OIDC/PKI,
Kubernetes placement, actual VM/CSI/cloud effects, HA or database capacity.
At that formal backend checkpoint the policy-management UI was unfinished.
The console increment above has passed local management acceptance. G3-07 remains in development: target-cluster HA and
execution capacity, real cloud effects and current-source eight-ELF scans/unified
signed release acceptance are unfinished.

The formal-only real-PG suite covers real EXECUTE/RENEW/cold BACKUP acceptance,
concurrent same-key calls, dropped ACK recovery, real execution/backup closure
holds, issuer/principal/project revocation, deadline/grant changes during an
event-head wait, old/new claims and epochs, skipped cron spans, event feedback,
signed history/RLS, and both lock-order winners for concurrent pause/revocation.
Cold-backup observations are controlled fixture evidence, not cloud runtime
certification.

`scripts/test-automation.py` creates a new loopback Docker PostgreSQL server,
random dedicated SCRAM logins and disposable TLS CA/leaf. It invokes the actual
`sandboxd --role migrate` independently for the acceptance database and the
process database, then runs the existing 18 signed HTTP/SDK, durable acceptance
and fault cases followed by the real worker process test. The process suite has
a 240-second aggregate runner budget for its independent natural-lease recovery
scenarios; each trial retains its original individual deadline and all production
lease/lock/probe/shutdown limits. Processes use canonical `verify-full` URLs;
library fixtures do not certify production PKI. The runner verifies both complete
real 1..37 + 39 ledgers, no 38 or restore schema, and unchanged source/artifacts,
including the two nested process-test modules and reviewed base-role source. It
records the failed stage and preserves acceptance evidence if the process stage
is not reached. It removes only its own container.
CI uses the same runner through `tests/fixtures/automation/action.yml`.

The worker is a normal Cargo binary and the eighth required production ELF in
Docker/export/native provenance/OCI/SBOM/release gates. Current releases require
all eight; only the internally authenticated historical path accepts the fixed
old seven or current eight complete names. These contracts do not themselves
prove current-source Linux artifacts or a successful security scan.

The independent worker's TLS URL must use its dedicated `sandbox_automation`
login, `sslmode=verify-full` and an absolute `sslrootcert` pointing at the reviewed
mounted database CA. It reuses the platform's canonical URL validator, rejects
duplicate/alias/override query parameters and has no loopback TLS exception.
Its startup verifies the formal migration
checksums and narrow queue grants before opening health probes. The reviewed
renderer in `deploy/automation` supplies separate replicas, private DB/DNS-only
network access, CA/Secret references and bounded SIGTERM draining. PostgreSQL
owns due times and leases; process shutdown never changes an accepted operation's
result or establishes VM/backup closure.

Every connected ordinary worker return awaits the shared pool drain, including
`--check` and startup errors. Controller and health server join under shared
shutdown; health draining is bounded to five seconds. The process label records
the full process UUID and Downward API Pod UID; labels are not authorization.


Action-scopes issuer mode intersects every required automation action with the
creating token's exact scopes before accepting the delegation. The stored bounded
action set never expands after token expiry; durable authority has its own explicit
expiry and live local grants. Resume requires every action of the existing rule in
both the current caller's token and current local grants, before an idempotency
replay and again before committing the mutation. A new resume also revalidates
the original creator's durable delegation; it remains bound to its original
identity, scope and expiry. All three management actions require a current valid
identity and the policy project's `automations:write`, without a same-creator
restriction. Pause and revoke require management authority only, so a token can
reduce a rule's authority without gaining its execution scope.
SERVICE delegations retain client ID and monotonic
binding generation. A client binding change permanently invalidates prior
SERVICE delegations even when the old client ID is later rebound. USER subjects
remain client-independent. Legacy SERVICE delegation rows without a reviewed
client binding fail closed; recreate them after the owner migration in
[service-clients.md](service-clients.md).
