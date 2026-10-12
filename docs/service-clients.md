# Tenant machine identity registration

The platform registers an existing OAuth/OIDC service-account subject and manages
its access in one tenant. It does not create an IdP account, obtain/issue tokens,
store client secrets, or rotate credentials. Use bundled Keycloak or the external
IdP's existing service-account and credential-rotation workflow. Obtain the actual
immutable `sub` from that controlled workflow; a client display name or email is
not an identity. The registry does not independently certify that an arbitrary
subject exists in the IdP.

`GET/POST /v1/service-clients` and `GET/PATCH /v1/service-clients/{id}` require
**tenant-wide** `service_clients:read` or `service_clients:write`, respectively.
Project-scoped permissions, including a project wildcard, do not suffice. The
owner bootstrap CLI accepts an explicit optional `tenant_actions` array containing
these two actions and the separate `tenant_audit:read` permission; its default empty array grants nothing. The public API
cannot grant tenant-wide authority.

POST takes exactly `issuer`, `subject`, `client_id`, and a tenant-local `display_name`, plus
`Idempotency-Key`. The issuer must exactly equal the API's single configured
trusted issuer. Client identifiers are exact, case-sensitive strings limited to
256 UTF-8 bytes, without control characters and nonempty after Unicode whitespace
trimming. Leading or trailing whitespace is retained when the identifier contains
non-whitespace characters; registration never normalizes an IdP identifier.
JWT validation, tenant registration and the owner binding command use this same
contract. An existing SERVICE `(issuer,sub)` binding can be registered in
another tenant only with the same registered `client_id`, without changing the global principal or exposing another tenant's
registration. The API compares the signed `client_id` (or Keycloak `azp`) to this exact binding on authentication and shared action authorization. Global USER/SYSTEM bindings and disabled global identities return a
generic 404. There is no tenant API rebinding, email merging or implicit cross-issuer alias. An unbound historical SERVICE identity fails authentication and requires the owner migration below.
A previously owner-registered enabled tenant SERVICE principal can be associated
with its exact existing identity; a disabled unassociated membership requires an
owner migration, never an implicit re-enable.

A successful creation returns 201 and `{resource,idempotency_expires_at}` with
Location and ETag. The `id` is the tenant registration UUID; `principal_id` is the
subject used by project grants. Registration grants no resource permission. Use
the separately authorized project grant API to add explicit actions and expiry.
No client secret is accepted by these strict DTOs or returned.

PATCH requires both mutable fields `enabled` and `display_name`, an
`Idempotency-Key`, and the strong quoted `If-Match` from the registration ETag.
It returns 200 with the incremented version. Identity, principal and tenant fields
are immutable. Disabling changes only the tenant membership: old JWTs, old
mutation receipts requested by that disabled caller, execution dispatch and live
gateway authorization checks fail in that tenant. The global principal and other
tenants remain enabled. This does not undo already executed guest side effects;
accepted SYSTEM safety-stop work continues independently of the original grant.

Explicitly changing false to true restores still-valid stored project/tenant
grants. To prevent privilege escalation through restoration, the caller must
currently hold tenant identity management, grant management, and each restored
action within the required scope and expiry ceiling. An expiring manager cannot
restore an unbounded grant. Disabled, revoked or expired grants are not restored.
If authority is insufficient, narrow/revoke the old grants through authorized
administration before retrying. Re-enabling does not alter IdP or global identity
flags. `enabled` reports the tenant state; `identity_enabled` reports the stored
global principal-and-identity flags, not real-time IdP account health.

Mutations, safe audit metadata and receipts commit in one PostgreSQL transaction.
No subject, display name, token or credential enters mutation audit details.
Tenant-level audit rows are retained in `audit_events` with a null project; the
current project audit API intentionally does not expose them across projects.
The separate `GET /v1/tenant-audit-records` exposes only current-tenant NULL-project
audit envelopes under an independent tenant grant and live identity checks;
see [tenant account audit](tenant-audit.md). Account-read permission alone does
not grant audit-read permission. There is no fabricated project event or async
Operation for these synchronous writes.

Reuse the original key/body/ETag after ambiguous responses. Replays check current
management authorization and return the original receipt without applying it
again. A replay can therefore show an older enabled state; GET resolves current
state. The replay window is seven days with at least 90 days of expired-key
retention. Changed requests conflict; expired receipts return 410. PATCH missing
If-Match returns 428; a stale version returns 412. Errors contain fixed public
codes and never raw provider/database text.

Lists use descending `(created_at,id)` signed keyset pagination: limit 1–100,
default 50, cursor expiry 24 hours, bound to tenant, caller and limit. Changing any
bound value is rejected. Lists include disabled registrations but never the global
identity directory. No DELETE route exists; disable preserves identity/audit
history. IdP migration remains an explicit owner binding migration with verified
subjects; changing deployment issuer never silently migrates accounts.

## Owner binding and migration 0040

Migration 0040 never guesses a client identifier from `sub`. Before rolling API
or automation replicas to this version, inventory each existing SERVICE identity
against the actual issuer's reviewed client metadata; apply migrations, bind each
legacy identity through the dedicated owner connection, reapply runtime role
scripts, then roll the replicas. Keep public ingress closed until all expected
clients pass signed access-token and negative-client checks. USER identities omit
`client_id` in bootstrap and remain bound to `(issuer,sub)` across browser clients.

Use a reviewed JSON file containing all five fields:

```json
{"issuer":"https://identity.example.com/realms/sandbox","subject":"actual-service-sub","expected_client_id":null,"client_id":"job-runner","reason":"Reviewed legacy service-client metadata"}
```

```bash
sandbox-admin bind-service-identity --file /secure/identity-binding.json --validate-only
sandbox-admin bind-service-identity --file /secure/identity-binding.json --apply
```

The apply command uses `SANDBOX_ADMIN_DATABASE_URL`; never supply the owner login
to an API or automation Pod. `expected_client_id` is explicitly null for an
unbound legacy identity or the exact previous value for rotation. A stale CAS
fails without mutation. The owner-only audit table records the principal, old/new
client IDs, reason and database login, but no credentials. Runtime logins cannot
invoke this function or modify the identity directory.

Each change increments a monotonic binding generation. Old durable automations
stop authorizing after rotation, including when an operator later binds the old
client again; recreate them using the new verified identity and fresh delegation.
Rotating credentials within the same IdP client ID remains an IdP workflow and
keeps the same product binding. Changing issuer/sub requires creating a new
identity/principal, explicitly delegating reviewed grants, and revoking old grants
and delegations; the tenant PATCH does not migrate identity or grant history.
