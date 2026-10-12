# Project grant management

`GET/POST /v1/projects/{id}/grants` and
`GET/PATCH/DELETE /v1/projects/{id}/grants/{grant_id}` manage the current tenant's
project grants. Reads require `grants:read`. Mutations require `grants:write` **and**
a current grant for the exact action being delegated. All queries use tenant RLS,
current membership, project/tenant enabled state and current grant expiry.

The API accepts only the documented action allowlist. It cannot issue wildcard,
tenant-wide or other-project authority. Owner-bootstrap wildcard grants may be
listed, but can only be changed through a controlled owner procedure. The target
principal must already have a registration in this tenant; UUID knowledge does
not establish membership. Registering an IdP identity and granting permissions
are separate operations.

Creation takes `principal_id`, `action`, and **required** `expires_at`. A null
expiry explicitly requests unbounded duration. An enabled grant cannot outlive
the earlier ceiling of the caller's current management authority and delegated
action authority. A bounded caller cannot grant an unbounded duration. Multiple
currently effective grants for one action contribute their maximum expiry;
an unbounded grant removes that action's bound. Project scope is always fixed.

Creation requires `Idempotency-Key` and returns 201. PATCH and DELETE require both
that key and a strong quoted `If-Match` from this grant's ETag, and return 200.
PATCH takes both `enabled` and `expires_at`; identity, action and project cannot
be changed. DELETE takes no body, preserves the grant record, sets it disabled
and records revocation. Explicit PATCH `enabled:true` can restore the same grant
after fresh authority checks. It does not create a second permission record.

The response is `{ resource, idempotency_expires_at }`; `resource.version` is also
the ETag. Resource writes, domain events, audit events and receipt insertion commit
in one transaction. A lost response must be retried with the original key,
parameters and ETag. Live delegation is checked before receipt replay, so a
revoked caller cannot recover access using an old receipt. Replay returns the
original result and does not undo subsequent changes. Receipts replay for seven
days; retained expired keys return 410 and remain tombstoned for at least 90 days.
The current resource must be reconciled before a new intent/key is used.

Lists use descending `(created_at,id)` keyset pagination, 1–100 items (default 50),
and a signed cursor with a 24-hour lifetime bound to caller, tenant, project and
page size. Keep those values unchanged. This fixes the creation cutoff, not the
status of records concurrently updated. Disabled and revoked records remain
visible to an authorized reader. Unknown or inaccessible resource IDs return 404;
known delegation beyond current authority returns `DELEGATION_DENIED` (403).
A stale ETag returns 412; a missing one returns 428; a changed idempotent request
returns 409. Errors never contain database/provider text.

Database role `sandbox_app` receives only narrow authorization/mutation functions,
read access to scoped records and receipt insertion; it has no generic identity
or grant write privilege. Management changes serialize on a tenant advisory lock.
Ordinary authorization does not take that lock or wait for lifecycle locks.
Tenant membership disable is local: it blocks old JWTs, old receipts and new
execution dispatch in that tenant without disabling the global principal or the
same identity in another tenant. Already accepted SYSTEM safety cleanup remains
available.
