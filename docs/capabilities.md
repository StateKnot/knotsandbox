# Capability discovery

Call `GET /v1/capabilities?project_id=<uuid>` with a verified OAuth access token, `X-Tenant-ID` and the explicit `capabilities:read` project grant. A tenant/project/principal/grant that is disabled, revoked, expired or inaccessible returns the same not-found response. Bootstrap can grant this action to a calling microservice independently of mutation permissions.

The response reports API/build version, implemented API features, the three accepted CPU/memory flavors and request limits. These are protocol capabilities, not current free capacity or a grant to perform every advertised action. It does not expose project namespace/storage configuration, tenant-wide quotas or template records.

`limits.ttl_seconds.maximum` is the smaller of the deployment ceiling and current project ceiling. `configured_default` remains the API's actual default. If the default exceeds the project maximum, `explicit_value_required` is true: supply an allowed TTL rather than assuming the server silently clamps it. Project configuration is read on every request.

`execution_acceptance` means the public API can durably accept an execution request. It does not establish that a gateway has executed it or that Kubernetes/Kata/Cilium isolation passed independent acceptance. `runtime_certification` is always `NOT_ASSERTED`. `execution_output_download` and `execution_output_streaming` require the API's separate output reader; they describe bounded verified reads, not current cloud health or caller permission. `runtime_metrics` requires a configured independent metrics reader and provides fixed queries for an authorized launch; missing observations remain missing. See [metric semantics](runtime-metrics.md).

`file_transfer` requires the configured file API and its normally applied schema, separate upload/read credentials and startup checks. It describes the bounded file protocol and durable ledger; it does not assert live gateway availability or independent cloud isolation acceptance. See [file transfer semantics](file-transfers.md).

`control_plane_diagnoses` is true: durable read-only `POST /v1/instances/{id}/diagnoses` and `GET /v1/diagnoses/{id}` reports are implemented. Every call still needs live `diagnoses:create` or `diagnoses:read`, respectively, plus `instances:read`; optional operation/execution evidence has its separate read authorization. This flag does not assert worker availability, current observation freshness, guest health, repair or runtime certification. Reports can complete with unknown or redacted evidence.

This additional response boolean is additive for existing clients; it does not change existing feature values, permissions or routes. Clients targeting an older deployment must treat an absent `control_plane_diagnoses` as unsupported instead of inferring it from `health_diagnostics`.

`scheduled_tasks` and `event_automation` are true when the normal API enables its schema-checked automation routes. They describe finite UTC schedules and bounded event rules under live delegated authority, not worker health, notifications or runtime certification. An embedding that omits those routes reports both false. See [automation semantics](automation-development.md).

`automation_notifications` is true only when the normal API mounts its
schema-checked project exception inbox. Migration 0042 derives durable notices
from newly committed FAILED / OUTCOME_UNKNOWN run events. Microservices can
page/read notices and acknowledge receipt with the original key and ETag;
acknowledgement does not repair or retry a run. Current `automations:read` and
`automations:write` authority still applies. An absent or false flag means the
inbox is unavailable; it does not alter the version 1 `automation` object or
assert email/webhook delivery, worker health or cloud certification. See
[inbox installation and API semantics](automation-notifications.md).

The top-level `automation` key is always present. It is `null` when those routes
are not mounted; otherwise it contains the version 1 automation contract. Older
responses without this additive key do not establish a recognized creation
contract. Existing clients that tolerate additional JSON fields can ignore it;
strict third-party decoders must update their response schema. The current console
requires a valid version 1 contract for new policies and explicit resume.

Roll out the backend contract to every API replica before deploying the new
console. Against an older backend without this field, the new console blocks
creation and resume while preserving otherwise authorized reads, pause/revoke
and explicit reconciliation of already journaled requests.

| Contract field | Version 1 meaning |
| --- | --- |
| `supported_actions` / `supported_triggers` | START, STOP, RESTART, DELETE, RENEW, EXECUTE, BACKUP; ONCE, CRON_UTC, EVENT. DELETE preserves the workspace. |
| `clock` / `time_zone` / `cron` | PostgreSQL owns deadlines; UTC only, seven fields, second `0`, year `*`, intersecting day-of-month/day-of-week. |
| `missed_run_policy` / `skipped_runs_consume_budget` | At most one occurrence within grace, otherwise one skipped span; skipped runs consume the finite budget. |
| `known_automated_events_retrigger` | False; known automation-originated events do not feed rules back into themselves. |
| `outcome_unknown_policy` | Reconcile the original run and intent; no replacement key or automatic fresh execution. |
| `limits` | Budget 1–10,000; EVENT cooldown 60–86,400 seconds; grace 1–3,600 seconds; delegation strictly greater than 60 seconds and at most 366 days. At most 100 live policies per project and 1,000 per tenant. Name/cron/event type each have a 128-byte UTF-8 ceiling; other syntax validation still applies. |
| `assurance` | `API_CONTRACT_ONLY`; not authorization, remaining quota, worker readiness or runtime certification. |

The API validator, cron/grace logic and response use the same fixed Rust limits.
The metadata does not replace action-specific request validation, current
identity/grants, resource ETags or admission. `minimum_interval_seconds` governs
only EVENT cooldown. ONCE and CRON_UTC also require an in-range value, but it does
not limit cron expression frequency. Required current grants can impose a
shorter allowed delegation lifetime; an explicit expiry beyond any applicable
grant is rejected rather than silently shortened. The published ceiling is not
a personal entitlement.
Live-policy limits count ACTIVE/PAUSED policies with effective delegations,
not historical policies, and do not report remaining slots.

The console reads these fields for its form and rejects an incomplete or
unrecognized contract. Losing the creation contract clears only unsubmitted
drafts/proposals. Policy reads, pause/revoke and explicit reconciliation of an
already journaled request retain their existing authorization and original-key
rules. Identity/project/CSRF changes still clear sensitive in-memory payloads;
contract metadata never restores revoked authority. See the generated
`AutomationCapability` SDK type and the normal `client.GET('/v1/capabilities', …)`
Interface.

Terminal sessions, complete monitoring/alerting, complete guest health diagnosis (`health_diagnostics`) and backup/restore production capabilities remain false. Cold backup acceptance/read routes are wired but require a separately reviewed, enabled backup profile; the full delivery gate is not asserted merely because an endpoint exists.

# Public operation errors

`Operation.error` is null or exactly a public `code` and `retryable` boolean. This contract applies to GET operation details and all mutation receipts, including receipts stored before sanitization was introduced. Arbitrary stored JSON is decoded through the same restricted mapping at read time; provider/guest messages, command data, environment values, nested objects and unknown fields are never returned as an operation error.

| Code | retryable | Meaning |
| --- | --- | --- |
| `DEPENDENCY_UNAVAILABLE` | true | A known dependency classification allows querying/reconciling the existing operation with backoff. |
| `OUTCOME_UNKNOWN` | false | Outcome is uncertain; do not automatically execute the command again. |
| `OPERATION_FAILED` | false | Generic failure, including unrecognized historical/internal error formats. |

The server derives retryability from its fixed classification, never from a stored provider/guest boolean. A retryable classification does not authorize a new idempotency key or a fresh command submission. Retain the original operation/execution IDs and follow their existing retry/reconciliation contract.
