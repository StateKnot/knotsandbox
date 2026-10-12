# Project history API

The implemented endpoints read existing PostgreSQL records. They do not publish messages or acknowledge event delivery:

| Endpoint | Required project grant | Source |
| --- | --- | --- |
| `GET /v1/operations` | `operations:read` | Operations, with request and raw error fields withheld |
| `GET /v1/events` | `events:read` | Domain event envelopes, including unpublished outbox records |
| `GET /v1/audit-records` | `audit:read` | Audit envelopes; arbitrary details withheld |

Each request requires an OAuth access token, `X-Tenant-ID`, and `project_id`. Optional `instance_id` selects records attached directly to that instance or through an operation. Unavailable tenant, principal, grant, project or instance scope returns the same resource-not-found response. Tenant-wide audit records whose `project_id` is null are outside these project views.

Use `limit=1..100` (default 50). Results are newest first, ordered by `(created_at,id)` for operations and `(occurred_at,id)` for events/audit. Each response has `items`, `next_cursor` and `cutoff`. Follow `next_cursor` using the same endpoint, token subject, tenant, project, instance filter and page size. Every page rechecks database authorization; possessing a cursor never substitutes for a grant. Empty pages and the last page have a null cursor.

Cursors are HMAC-SHA256 signed and expire 24 hours after the first page. Malformed, tampered, expired or differently scoped cursors return `400 INVALID_CURSOR`. Their time cutoff excludes newer records, but a cursor is not a database snapshot: a transaction that commits late or a retention job can change which records are visible while paging. Use the separate outbox delivery mechanism, when deployed, for acknowledged consumption; polling these views does not establish exactly-once delivery.

Only typed envelope fields are returned. The API excludes command arguments, environment values, operation requests/raw errors, event payload JSON and audit details JSON. This keeps operational correlation useful without copying arbitrary workload or provider data into a broad history permission. Actor principal IDs are product identifiers, not IdP credentials or user profiles.

## Signing keys and rotation

All API replicas must use the same operator-managed key configuration. `SANDBOX_CURSOR_SIGNING_KEY_FILE` points to an owner-readable regular file with mode `0400` or `0600`; startup rejects broad permissions and files larger than 8 KiB. Kubernetes atomic secret projection is supported when the resolved file has the required ownership permissions. Mount or copy the file so the API's UID can read it.

The JSON shape is `{"active":{"kid":"2026-10","key_base64":"<base64 of 32–64 random bytes>"},"previous":[]}`. The product does not invent a random key per process. Key IDs use 1–32 ASCII letters, digits, underscores or hyphens. Up to two previous keys may verify existing cursors; only the active key signs new ones. Do not put key material in logs, source control or API responses.

For rotation, first deploy the new key as a previous key on every replica. Then make it active everywhere, keeping the old key as previous. Wait at least 24 hours after the last old signer is replaced before removing its verification key. This avoids both mixed-fleet rejection and premature invalidation. An emergency key removal intentionally invalidates cursors signed by it.

## Verification and limits

`tests/history.rs` exercises real PostgreSQL RLS and live grant checks, same-timestamp pagination, cross-tenant and guessed-resource failures, and real-RSA signed HTTP requests. Cursor unit tests exercise tampering, expiration, actor/filter/endpoint binding and key rotation. These tests do not demonstrate cloud event delivery or archival retention; those are separate deployment capabilities.
