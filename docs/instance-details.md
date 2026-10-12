# Instance details and evidence

`GET /v1/instances/{id}/details` requires the same live `instances:read` project grant as the existing instance endpoint. It returns one read-only repeatable-read database snapshot containing the instance record, workspace retention/deletion state and size, pinned template digest/runner version, security policy version, compute lease and lifecycle evidence. It does not mutate state or call Kubernetes while rendering the response.

The existing `GET /v1/instances/{id}` contract remains unchanged. Details return `X-Instance-ETag` for subsequent instance mutations and use `Cache-Control: no-store`; they do not issue a strong `ETag` for a response containing derived time values. `as_of` is the database time used to evaluate lease remaining time and evidence age. An expired lease or accepted stop is not proof that the VM has terminated.

Launch readiness reports its lifecycle-reconciler source, verification time and generation, and whether its stored generation/launch/Pod/epoch still match the instance and current cluster epoch. `VERIFIED_CURRENT_LAUNCH` means that launch has a matching validation record. It does not say the workload is still healthy, network isolation was independently certified, the user is currently allowed to execute, or a new dispatcher can skip a fresh authoritative check.

The worker currently writes observations while reconciling lifecycle operations; it has no continuous health sampler for a completed RUNNING instance. Accordingly, `runtime_health` is always `UNKNOWN` with reason `CONTINUOUS_OBSERVATION_UNAVAILABLE`. Historical records remain visible rather than silently becoming a fabricated current health status.

Observation freshness uses an explicit 60-second reporting threshold (`recent_threshold_seconds`): missing timestamps are `MISSING`, timestamps in the future are `INVALID_TIMESTAMP`, age over 60 seconds is `HISTORICAL`, and other timestamps are `RECENT`. This fixed API reporting threshold is documented and returned in the response; it is not a background monitoring interval or permission to execute. A recent lifecycle observation still does not establish current health.

Active execution metadata has a separate `executions:read` check. Without that grant the subview is `REDACTED` with a null resource, and the instance response still succeeds. With the grant it returns `AVAILABLE` metadata, `NONE` when there is no active execution, or `UNKNOWN` when an execution activity pointer has no matching held execution slot. No argv, environment, output reference, output content or guest result is included. Workspace volume identifiers, key references, namespace/storage configuration and raw policy JSON are also withheld.

# API process readiness

`GET /health/ready` checks database access and the platform configuration singleton. A reachable but uninitialized database returns `503 PLATFORM_NOT_INITIALIZED`. Safe mode keeps readiness at 204 so read and safety-stop requests can continue. This endpoint does not attest runtime health or isolation.
