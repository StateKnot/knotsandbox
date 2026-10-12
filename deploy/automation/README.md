# Automation worker deployment

This package renders the trusted scheduler only. It needs no Kubernetes API
role, guest identity, OSS writer or saved OAuth token. It calls the existing
management acceptance implementation using the separate `sandbox_automation`
PostgreSQL login and the creator's finite persistent delegation.

Use the normal `src/bin/sandbox-automation.rs` binary in the service image.
Apply all 42 formal migrations 1..37 + 39..43 using `sandboxd --role migrate`; version 38
is unpublished and permanently reserved, and automation requires no restore
schema. The migrator always installs automation API grants and installs worker
grants when its DBA-provisioned login exists. Missing, partial, incorrect-checksum
schema or broad component privileges fail before probes bind. Never apply draft
SQL or fabricate the SQLx ledger. Both enabled capability flags describe the
checked API contract, not worker availability.

Migration 0043 installs the scoped definer for deferred file-activity validation
used during limited component transactions, including node fencing. Keep every
previous migration byte/checksum unchanged; apply the new migration through the
normal migrator rather than granting components broad file-table access.

The worker is included in the required eight-ELF Docker/native/OCI/SBOM release
inventory. A deployment still requires an independently signed, accepted image,
real database capacity and TLS trust, isolation and cloud acceptance. Local
process tests use a disposable test CA and do not establish those facts.

Provision a separate NOINHERIT/NOSUPERUSER/NOBYPASSRLS/NOCREATEDB/NOCREATEROLE login,
with no component memberships or owned objects. Apply the reviewed automation
role grants after the formal migration. Store its URL in the referenced Secret
using the existing secret-management process; never put the URL/password in the
rendering JSON. The URL must use `sandbox_automation`, `sslmode=verify-full`, the
private RDS hostname and `sslrootcert=/etc/sandbox-automation-db-ca/ca.crt`. The
referenced CA ConfigMap must contain the reviewed server CA in `ca.crt`. URL
parameters overriding the role/host/TLS mode or unrecognized parameters are
rejected before connection; the CLI help hides environment values.

The rendering config contains exactly:

| Field | Value |
| --- | --- |
| `namespace` | Existing trusted control namespace, normally `sandbox-system` |
| `image` | Approved platform image by actual `@sha256:` digest containing the worker binary |
| `database_secret`, `database_secret_key` | Existing Secret reference and key containing the private TLS URL |
| `database_ca_config_map` | Existing ConfigMap reference containing `ca.crt` |
| `database_cidrs` | 1–4 narrow RFC1918 database subnets, prefix /24–/32; include every reviewed RDS failover subnet |
| `replicas` | 2–8 |
| `db_max_connections` | 4–16 per replica; total RDS connection budget includes every replica and rollout surge |
| `default_ttl_seconds`, `max_ttl_seconds` | 60–604800, default no greater than maximum |

```sh
python3 deploy/automation/automation.py config.json --out automation.manifest.json
CLUSTER_PYTHON="$PWD/.local/cluster-venv/bin/python"
"$CLUSTER_PYTHON" -m unittest discover -s deploy/automation/tests -v
"$CLUSTER_PYTHON" deploy/automation/schema_check.py --config config.json \
  --deployment .local/production-cluster-v1
sandbox-automation --check
```

Rendering never applies resources or provisions secrets. Review the rendered
List together with the formal schema/grant and approved image evidence before
normal deployment. The manifest pins non-root UID/GID 10001, a read-only root
filesystem, dropped capabilities, RuntimeDefault seccomp and no service-account
token. It schedules across at least two trusted platform-node zones, has a PDB and zero
unavailable rollout budget, and routes only DNS and private DB TCP/5432 through
the project's Cilium baseline. Host health probes are allowed only on TCP/8091.
The reviewed cluster inventory must provide three schedulable platform zones.
The control-plane NoSchedule taint and Kata quarantine remain intact. RDS
security IPs/hostssl sources and the DB egress security group already select
the platform pool in `infra/alicloud/data.tf`; this worker follows that same
placement contract. Do not broaden DB sources or add control/Kata tolerations
to make a pending worker start. Verify the actual private DB endpoint/failover
routes and host-to-DB source addressing on the target cluster.
Pod and policy both carry `sandbox.platform/network-policy=automation-v1`,
which excludes them from the bootstrap control policy's broader allowances.
The schema check verifies the shared locked official Kubernetes and Cilium CNP
schemas, including their checksums. With `--deployment`, it also checks the
complete installation snapshot and composes the actual node labels/taints with
the worker placement. Without that option the result explicitly states schema
only and is insufficient for production acceptance. The default fixture is only
a schema example; production validation supplies the actual non-secret config
and reviewed deployment. Before activation,
use the shared live policy-boundary check to reject additional selected CNP,
CCNP or Kubernetes NetworkPolicy allowances. A policy listing proves current
configuration only; verify actual allowed and denied traffic separately on the
target cluster before claiming network enforcement.

```sh
python3 deploy/policy_boundary.py --manifest automation.manifest.json \
  --kubeconfig /absolute/private/kubeconfig --context reviewed-context \
  --out automation-policy-boundary.json
```

The manifest must be the actual reviewed component List. Supply a private
0400/0600 regular kubeconfig, owned by the operator or root, with an explicit
context and inline CA plus a direct token or client certificate/key. File
credentials, plugins, YAML aliases, proxies and TLS overrides are rejected.
The checker pins those inputs in a private temporary snapshot, then reads the
live namespace, Pod UID and service account, actual CiliumEndpoint identity
and complete CNP/CCNP/NetworkPolicy collections within one 45-second budget.
It rechecks the complete inputs and refuses changes. A passing report has
`configuration_overlap=PASS` and
`runtime_enforcement=NOT_VERIFIED`; it neither enables the component nor
certifies network traffic. Store the report with the reviewed deployment evidence.

Each replica accepts one management request at a time; the DB queue coordinates
replicas. SIGTERM stops new work and lets the current bounded transaction finish.
A persisted but undispatched intent remains for the next claim. Health listener
drain is bounded to five seconds, and Kubernetes termination grace is sixty
seconds. A killed process never establishes a guest result, VM death, backup
hold release or cancellation of an accepted operation. On restart, only the
original durable run/request/key/resource can be reconciled.

Readiness rechecks the formal schema and complete existing minimum privileges
within the original two-second probe budget, in addition to the controller's
latest scheduling result. Revoked privileges cannot be hidden by an earlier
successful poll. Temporary database failures make the worker unready; it remains
alive and uses the existing two-second backoff and actual queue eligibility to
reconcile the original intent. P4090/P4120 current-authority/version guards use
that same retry path. Safe mode can retain an original DISPATCHING run without
an error record; it does not authorize a replacement request.

Permanent privilege failures or invalid persisted/invariant data make the worker
stop scheduling, join the health server, await the shared database drain and
exit nonzero with a fixed sanitized error. A fatal acceptance failure preserves
the prepared intent and claim; it does not record a business FAILED result.
Investigate the protected process logs and repair the reviewed migration/grant
or data defect before normal restart. The replacement process waits for the
original lease and reconciles the same run/key/request/resource. Do not delete
queue rows, manually clear claims, shorten leases or replace an ambiguous key.
Process recovery establishes neither a guest result nor execution-slot release.

After deployment, verify the dedicated login and formal migration check, both
ready replicas/zones, immutable image digest, CA/Secret references, rendered
Cilium policy and RDS failover routing. Run the signed management API test against
the formal database, then a real canary for each enabled action with the required
runtime/backup certification. The local PostgreSQL and controlled mTLS tests do
not replace cloud/Kata/CSI certification or real failover testing.

`SANDBOX_PROCESS_POD_UID` comes from `metadata.uid` in the renderer. All normal
connected returns await the shared database drain; controller and health parents
join on shutdown with five-second probe-server draining. Run the actual local
formal migration/HTTP/SDK/process suite using `python3 scripts/test-automation.py`.
The rendered replica/pool limits are configuration bounds, not measured database
capacity; include replicas and rolling surge in the full platform connection budget.
