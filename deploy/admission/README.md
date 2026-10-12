# Sandbox admission installation contract

For production installation use [the admission renderer and installation guide](../../docs/admission-installation.md).
`workload.yaml` is retained as a historical structure reference; its placeholders,
old UID and kubelet TCP probes are not the current production deployment.

`sandbox-admission` is a separate, mTLS-only Rust process. It validates the same
controlled manifests as the worker, then reads current PostgreSQL authorization
and Kubernetes namespace/Pod/node/PV bindings. It does not create workloads or
release quotas. The YAML files are installation templates: replace their marked
values with the actual installation's image digest, service-account UIDs, CA and
certification reference. No production passwords or signing keys are included.

## Trust and permissions

1. The webhook server accepts **only client certificates from a dedicated CA
   that signs kube-apiserver webhook clients**. Never reuse Kubernetes' general
   user/node client CA or a corporate CA. Possession of this client certificate
   permits submission of `AdmissionReview.userInfo`; therefore only API servers
   may hold it. The server certificate uses a separate server CA, has SAN
   `sandbox-admission.sandbox-system.svc`, and the webhook's `caBundle` trusts
   that server CA. Both chains and expiry must be monitored.
2. Once mTLS authenticates the API server, `request.userInfo` identifies the
   original Kubernetes caller. Worker, execution gateway, termination controller and namespace provisioner require exact
   service-account username **and API-assigned UID**. Deleting/recreating a
   service account changes its UID and blocks access until reviewed configuration
   rollout. Product OIDC users and the API process have no workload write rights.
3. Scheduler/storage/namespace controllers accept explicitly configured service
   accounts, or the two built-in certificate usernames `system:kube-scheduler`
   and `system:kube-controller-manager`. Certificate identities require an empty
   `uid` and exactly the `system:authenticated` group, as in the baseline control
   plane. There is no group-wide bypass. For controller-manager with
   `--use-service-account-credentials`, configure the actual per-controller
   service accounts instead. Cilium/CSI names differ by installation; inspect
   their actual accounts and obtain each UID with `kubectl get sa -o jsonpath`.
   Extra certificate groups are rejected; do not widen this to `system:masters`.
4. Configure Kubernetes OIDC usernames with a non-`system:` prefix and prohibit
   product/tenant identities from `impersonate`, certificate signing, RBAC,
   Namespace/Node/PV/RuntimeClass/StorageClass modification, privileged CSI access,
   webhook configuration or namespace deletion. Cluster administrators and the
   certificate issuer remain the control-plane trust root. Anyone able to remove
   the webhook or impersonate its trusted principals can bypass this boundary.
5. Provision a separate unprivileged PostgreSQL LOGIN `sandbox_admission`; run
   `scripts/sql/admission-role.sql` as the migration owner. This role has scoped
   SELECT plus a narrow consume-once execution admission function; FORCE RLS
   still applies. It has no generic table DML, migration-owner membership or
   operation-claim rights.
   A remote database URL must use `sslmode=verify-full`. Store it under key `url`
   in `sandbox-admission-database`, through the installation's secret manager.

Object labels route a database lookup; they never authorize a caller. A protected
namespace must already match the product project's `runtime_namespace`, immutable
tenant/project/epoch labels, and the operator's configured certification reference.
The latter points to evidence; it is not itself evidence of isolation. Pod CREATE
also requires a live CREATE/START (or renewed-generation RESTART) operation, approved immutable template/policy,
current epoch, unexpired compute lease, enabled tenant/project/principal and
current grant. Exact generated names/spec/labels block second writers, additional
containers, host access, token mounts, security annotations and runtime changes.

The API server assigns a CREATE object's UID before validating admission. The
webhook therefore validates the server-assigned UID and rejects a new creation
when PostgreSQL already records that resource; it does not require an empty UID.
Updates cannot change recorded UIDs or identity labels. Scheduler bindings fetch
the actual Pod and check binding UID and a Ready, schedulable Kata node. Kubelet
status accepts only the authenticated assigned node. Scheduler status can change
only scheduling conditions and nominated node, never readiness/container status.
PVC binding verifies the fetched PV's exact claimRef UID/name/namespace and class.
For WaitForFirstConsumer, the exact scheduler may only add/change `selected-node`
on a still-authorized unbound PVC; all other metadata/spec/status remain unchanged.
This does not grant it generic storage-controller writes.

The controlled native `sandbox-default-deny` NetworkPolicy is provisioner-only and
immutable in effect. No other native policy may be created in protected
namespaces. Per-workspace Cilium policies permit only the approved DNS profile;
additional policies could add egress permissions, so they are denied. Cilium must
use the G1-certified `always` enforcement configuration and tested first-packet
behavior. Cilium cluster-wide policy, privileged operators, CSI and node agents
are installation trust dependencies and must not be tenant-writable.

## Transport and startup bounds

The production listener uses a dedicated apiserver-client CA, TLS 1.2/1.3 and
HTTP/2 or HTTP/1.1. It disables TLS session resumption and checks the client
leaf/intermediate chain at handshake time and through the complete 10-second
connection lifetime, including whole-second rounding. Connections are capped
at 32 and in-flight requests at 32 per replica; saturation returns an empty
HTTP 503, so Kubernetes `failurePolicy: Fail` continues to reject writes.
HTTP/2 permits four streams per connection with bounded flow-control windows
and 8 KiB header lists. HTTP/1 headers have a two-second deadline. Handshakes
have three seconds, idle and stalled writes five seconds, and shutdown drains
for at most three seconds. The existing four-second decision deadline and
1 MiB AdmissionReview body limit remain independent. These limits still need
capacity validation on the target cluster.

Startup requires the exact `sandbox_admission` database login and the shared
canonical URL validator: verified remote PostgreSQL TLS, an absolute CA path
and no conflicting SSL/host overrides. TLS/config files are opened once as
bounded regular files. Projected Kubernetes symlinks are allowed; private keys
require owner-only 0400/0600 or root-owned 0440 for the process's nonzero primary
group. No key or URL value is printed in a validation error.

`/usr/local/bin/sandbox-admission --probe-local` checks only the fixed
`127.0.0.1:8443` listener, with a one-second total deadline. It reads no config
or certificate file and ignores the inherited database environment variable.
It has no arbitrary host/port mode. The listener is bound only after successful
config, TLS, database-role/schema and Kubernetes-client initialization. Use an
exec probe with a two-second Kubernetes timeout; it tests local listener
availability, not current DB/API health or certified sandbox isolation. Keep
external mTLS, dependency-outage and policy probes as separate acceptance.

## Installation order

1. Complete the isolated locked K8s/Kata/Cilium/CSI certification environment from `../cluster/versions.lock.json`. Keep
   sandbox compute admission disabled in the product until the final smoke test.
   Obtain actual SA UIDs, approved runtime settings and G1 evidence reference.
   Populate a reviewed copy of `config.example.json`; dummy UIDs cause startup
   failure. Apply the dedicated database role after migrations.
2. Issue server/client leaf certificates using the installation PKI. Create the
   config map `sandbox-admission-config` (key `config.json`), TLS secret
   `sandbox-admission-server-tls` (`tls.crt`, `tls.key`), and config map
   `sandbox-apiserver-client-ca` (`ca.crt`). Client leaf certificates/keys belong
   only on API-server hosts, not in the webhook pod or product API containers.
3. Integrate `apiserver-admission.yaml` and
   `apiserver-client.kubeconfig.example` into the existing API-server admission
   configuration on **every** control-plane host; preserve existing plugin
   configuration. Roll API servers one at a time. The kubeconfig user name must
   match `sandbox-admission.sandbox-system.svc` for service port 443.
4. Apply `workload.yaml` with a verified image digest. It runs two non-root,
   read-only replicas across distinct nodes, a PDB and get-only Kubernetes RBAC.
   Configure installation network policy/firewalls: control-plane egress to
   service/Pod TCP 8443 and admission egress to verified PostgreSQL and Kubernetes
   API only, plus required DNS. No Internet or tenant access is needed.
5. Perform an mTLS `/validate` probe from an API server and verify response UID.
   Missing/unrelated client certificates must fail handshake. The TCP readiness
   probe only verifies the listener; it does not certify dependencies, PKI or
   policy. Probe DB/API outages separately before opening compute admission.
6. Insert the product tenant/project namespace binding, then apply `webhook.yaml`
   **last**, with the real server-CA bundle. It intentionally has no object or
   namespace selector: clients cannot opt out by removing labels. `Fail`, 5-second
   API-server timeout and a 4-second internal decision deadline are mandatory.
   Its global resource matching means a webhook outage blocks matched resource
   writes cluster-wide, including unrelated namespaces. Capacity, HA and the
   isolated cluster failure domain must be accepted at G1; do not switch to Ignore.
7. Using the exact provisioner account, create `project-namespace.yaml` with real
   IDs/epoch, then the fixed baseline policy and the restricted `sandbox-workload`
   service account. The latter must have no Kubernetes API permissions or image
   pull secrets that cause Pod mutation; supply registry authorization through
   the certified node/runtime mechanism. Namespace labels and certification
   annotation become immutable. Start a controlled instance through the product
   API; observe admission, scheduler binding, CSI binding, Cilium status and
   worker readiness with their actual production identities.

Apply `gateway-rbac.yaml` only after CONNECT admission passes its probes, with a
project RoleBinding for each registered namespace. It grants `get pods/exec` for
the locked kube client WebSocket transport, never attach, port-forward, arbitrary
Pod writes or tenant impersonation. A credential with this role alone is not
authorization for an arbitrary exec; the validating webhook and consume-once
gate remain mandatory. Do not apply this RBAC with a disabled/Ignore webhook.

Runtime limits/DNS selectors in admission config must exactly match the worker.
Admission does not expose an HTTP fallback. Certificates/configuration are loaded
at process startup; rotate via overlapping CA trust and a rolling restart, then
remove old trust only after every apiserver and replica has changed. Confirm both
old/new valid clients during overlap and reject the old chain after retirement.
Do not place client private keys in diagnostic logs or test fixtures.

## Supported boundary and rollout evidence

A stop/delete/restart request permits worker or the separately configured
termination service account to DELETE with exact Pod UID/resourceVersion and a
30-second grace period. Revoked original caller/template or safe mode does not
block accepted cleanup. Apply `termination-rbac.yaml` per project only after
registering that account's actual UID; it must not share username or UID with the
worker, gateway or provisioner. Admission never trusts Pod labels as caller identity.

Only that termination identity can remove the single controlled finalizer from an
already deleting Pod. This requires a fresh committed `local_termination_proofs`
record, its exact launch permit/node/challenge, current instance/workspace/Pod UID,
generation/launch/cluster epoch, current stop operation and its live lease token.
The challenge must still be unexpired, and metadata/spec/status cannot change in
the same patch. The admission DB role has SELECT on the required evidence columns,
with tenant RLS, and no INSERT/UPDATE rights to any proof table. A timeout or missing
proof fails closed. No direct worker or ordinary controller finalizer removal is
permitted, including an otherwise correct object.

After removal, immutable historical proof for that same Pod permits normal assigned
node status updates and the explicitly configured garbage collector's terminal
status update and zero-grace DELETE even after challenge/lease expiry. The pinned
upstream PodGC sends no DeleteOptions UID precondition; the webhook
uses the API server's stored Pod UID and exact historical proof, and still denies
a supplied mismatched UID. It can only set phase Failed and DisruptionTarget,
never readiness/container status. See the [official PodGC implementation](https://github.com/kubernetes/kubernetes/blob/v1.36.4/pkg/controller/podgc/gc_controller.go).
This narrow GC exception never removes a finalizer or authorizes a new launch. A RESTART with `restart_generation` set to the
current generation is a new compute phase: current `instances:restart` and
`instances:hard_stop` permissions are both required; it is no longer a stop phase.

PVC deletion and protected namespace deletion/finalization remain blocked. Pod
attach/port-forward, ephemeral containers, resize and eviction fail closed. The
nodeguard source and database protocol do not constitute target-cloud physical
termination certification. `WAITING_TERMINATION` remains a blocker when no certified
proof is available; the installation package keeps tenant compute quarantined.

Only the configured gateway service-account username **and UID** may CONNECT to
`pods/exec`. Its command is exactly `/usr/local/bin/sandbox-runner exec
--execution-id <UUID> --dispatch-attempt-id <UUID>`, with the current
`workload-<launch UUID>` container, stdin/stdout/stderr enabled and TTY disabled.
User argv/environment travels through the runner's stdin protocol, never URL
arguments. The webhook freshly verifies Pod UID/readiness, certified node, PVC UID
and bound state, and exact Cilium policy. It then calls
`sandbox_admit_execution_connect(tenant, execution, attempt, review_uid)`.

That SECURITY DEFINER function has a fixed search path and no PUBLIC execution
privilege. Only the dedicated admission role is granted EXECUTE; other runtime
roles cannot write the receipt directly. Under workspace → instance → execution
→ operation locks it rechecks current launch/generation/Pod UID/epoch, Ready
identity, current activity slot, safe mode, cancellation, deadlines, caller's live
`executions:create` **and** `instances:hard_stop` grants, approved template/policy,
and the dispatch's original worker lease token against the still-live operation
lease. It records one immutable `exec_admission_uid`/`exec_admitted_at` pair.

A retry with the same **API-server-assigned** AdmissionReview UID rechecks every
condition and is idempotent. A different UID is denied even for the same dispatch
attempt. The gateway cannot choose or reuse that API-server UID. If the allow
response is lost, execution is ambiguous: record UNKNOWN and request the already
authorized whole-instance safety stop, never issue another exec connection.
`sideEffects: NoneOnDryRun` describes the receipt write; dry-run CONNECT is rejected
before the gate and consumes nothing. Other dry-run resource checks remain read-only.

SQL checks and Kubernetes commit are not one transaction. A stop can arrive after
a CREATE validation has read state. The fixed per-workspace Pod name, generation/
launch/epoch binding and retained finalizer prevent another launch/writer from
being admitted; the stop worker must keep checking that generation and must never
interpret a temporary 404 as proof of VM termination. G1 must exercise this race,
API-server retries, admission unavailability and storage delayed attachment.

Local automated evidence consists of exact legal Pod/PVC/Cilium policy samples,
attack mutations, real loopback mTLS HTTP handshakes and dedicated-role PostgreSQL authorization and concurrent one-use gate tests. The Kubernetes GET transport in the SQL test is
simulated. These tests do **not** verify physical Kata isolation, control-plane
certificate settings, Cilium first-packet enforcement, CSI controller defaults,
CA rotation, scheduler identities or production availability. Record those
cluster observations and every required control-plane default before the G1
release gate; an unexpected mutation/identity must fail closed and be reviewed.

Protocol references: [Kubernetes 1.35 scheduler PVC updates](https://github.com/kubernetes/kubernetes/blob/v1.35.0/pkg/scheduler/framework/plugins/volumebinding/binder.go),
[Kubernetes dynamic admission and webhook authentication](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/),
[Kubernetes 1.35 generic storage assigns UID before validation](https://github.com/kubernetes/kubernetes/blob/v1.35.0/staging/src/k8s.io/apiserver/pkg/registry/generic/registry/store.go).

已按 [never-authorized 协议](../../docs/never-authorized-closure.md) 完成计算删除的迟到 Pod，必须先有完整清单核验后的 UID 观察记录。只有专用 termination 身份可按该永久证明移除保护 finalizer；当前 epoch 不符、未知 UID、普通 worker 或漂移的 Pod 清单均拒绝。
