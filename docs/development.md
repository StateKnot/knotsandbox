# Development and build environment

This checkout currently provides application foundations and a real local PostgreSQL/Keycloak environment. The Compose file is **development-only**. It does not deploy a Kubernetes/Kata sandbox, provide cloud high availability, or establish production readiness.

The current formal migration set is 0001..0037 plus 0039 for automation.
Version 0038 was never published and is permanently reserved; it must not be
backfilled. Any future restore promotion requires a new higher version. Normal
`sandboxd --role migrate` installs the formal automation API grants even before
the DBA provisions its separate optional coordinator LOGIN; restore remains
closed. Earlier checkpoint sections below describe the schema and closed routes
at their own source points, not the current formal migration set.

The local PostgreSQL container requires a 2 GiB memory limit for the current restoration acceptance fixture. Its verified connections and statement-cache reset can prewarm 47 connections, including owner connections. A 1 GiB run recorded a backend OOM kill and database recovery; the same source passed at 2 GiB with a sampled container peak of 1,339,023,360 bytes and no new OOM kill. This is a local test baseline, not a production sizing result. Production requires a combined connection budget for every service, rolling and terminating replicas, background work and administrative reserves, plus concurrent memory measurements on the selected database tier.

That earlier result does not establish that 2 GiB is sufficient for later queries. The Source14 acceptance subsequently recorded backend kills at the same limit. The new Bound helper now uses function-local `join_collapse_limit=1` and `from_collapse_limit=1`; its body, guards, locks and ACL remain unchanged. A subsequent actual pass and warm-reader regression retain the original resource and timeout limits. They do not prove the internal planner/JIT/allocation cause or production sizing. Following a later Docker outage, only the existing local PostgreSQL/Keycloak containers were started again; cgroup counters after that restart are a new observation interval and do not erase earlier OOM events.

## Prerequisites

- Rust 1.98.1, including rustfmt and clippy; the repository toolchain file is authoritative.
- Docker Engine/Desktop and Docker Compose v2 with `up --wait` support.
- Bash and Python 3. No Python packages are needed.
- Node.js 22+ and npm for the TypeScript SDK; CI pins Node.js 24.19.0.

Run from the repository root:

```sh
scripts/dev-dependencies.sh up
scripts/dev-dependencies.sh token
```

The first command creates distinct random development passwords in `.local/dev.env` with mode `0600`. PostgreSQL is exposed only at `127.0.0.1:55432`; Keycloak only at `127.0.0.1:58080`. The dependency script never prints passwords or tokens. The token command writes a short-lived response to `.local/machine-token.json`, checks the token claim contract, and does not replace the API's cryptographic verification.

PostgreSQL has three separate databases: `sandbox_dev` and `sandbox_test`, owned by the non-superuser migration identity `sandbox_owner`, and `keycloak_dev`, owned by the separate non-superuser `keycloak_dev`. The API uses `sandbox_app`, the worker uses `sandbox_worker`, execution dispatch uses `sandbox_gateway`, admission uses `sandbox_admission`, trusted termination uses `sandbox_termination`, node incidents use `sandbox_fencing`, and workspace destruction uses `sandbox_volume_deleter`; none is a table owner, superuser, or has RLS bypass. Admission has read permissions and one narrow consume-once execution admission function, without generic table write permission. Each component receives a separate generated password. `scripts/dev-dependencies.sh roles` adds missing worker/admission/gateway/termination/fencing/volume_deleter/backup logins to an existing local volume without rotating existing passwords; `up` also runs this verification. Migrations establish the object grants. `MIGRATION_DATABASE_URL` and `TEST_MIGRATION_DATABASE_URL` use the owner; `SANDBOX_DATABASE_URL`/`DATABASE_URL` and `TEST_DATABASE_URL` use the API runtime role. The generated administrative database password is only for container bootstrap. Keycloak never uses an application database role.

The development script also creates `.local/cursor-signing-keys.json` and sets `SANDBOX_CURSOR_SIGNING_KEY_FILE`. API replicas require a shared HMAC key ring for history pagination; startup rejects a missing, non-regular, oversized, or group/world-accessible key file. Use mode `0400` or `0600`, readable by the API UID. Kubernetes projected Secret symlinks are supported, but the target must satisfy the same permissions. The JSON contains `active: {kid, key_base64}` and `previous: [...]`, with 32–64 random bytes per key and at most two previous keys. For rotation, first deploy the new key as a verification-only previous key to all replicas, then promote it to active while retaining the old key for at least 24 hours after the last old-key issuer stops. Reload requires a rolling process restart. No replica generates an implicit replacement key at startup.

Run the normal regression suite without the development `SANDBOX_*` profile; its negative configuration tests verify production defaults. The cross-language installation contracts require Python 3.12 and the locked cluster dependencies:

```sh
python3 -m venv .local/cluster-venv
.local/cluster-venv/bin/python -m pip install --require-hashes -r deploy/cluster/requirements.lock.txt
npm --prefix sdk/typescript ci --ignore-scripts --no-fund --no-audit
npm --prefix sdk/typescript run build
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
python3 - <<'PY'
import os, subprocess
environment = {name: value for name, value in os.environ.items() if not name.startswith('SANDBOX_')}
environment['CARGO_INCREMENTAL'] = '0'
subprocess.run(['cargo', 'test', '--locked', '--all-targets'], env=environment, check=True)
PY
```

Load generated settings when running the application or real integration tests from the host:

```sh
set -a
source .local/dev.env
set +a
cargo test --locked --test database_roles -- --ignored
cargo test --locked --test database -- --ignored
cargo test --locked --test lifecycle_authorization -- --ignored
cargo test --locked --test bootstrap -- --ignored
cargo test --locked --test timers -- --ignored
cargo test --locked --test executions -- --ignored
cargo test --locked --test worker -- --ignored
cargo test --locked --test gateway_ledger -- --ignored
cargo test --locked --test admission -- --ignored
cargo test --locked --test history -- --ignored
cargo test --locked --test capabilities -- --ignored
cargo test --locked --test review_regressions -- --ignored
cargo test --locked --test migrations -- --ignored
cargo test --locked --test keycloak -- --ignored
cargo test --locked --lib node_fencing::tests -- --ignored --test-threads=1
cargo test --locked --lib volume_deletion::tests -- --ignored --test-threads=1
```

Run the ignored integration suites sequentially in the shown order. Normal `cargo test` alone does not execute them. The shared-database suites require both `TEST_DATABASE_URL` (API runtime identity) and `TEST_MIGRATION_DATABASE_URL` (migration owner), while worker tests additionally require `TEST_WORKER_DATABASE_URL`, fail if either is missing, and reject database names that do not end in `_test`. The shared database fixture applies migrations and `scripts/sql/roles.sql` once per test process, then gives each case fresh UUID tenants. Cases serialize changes to the installation-wide safe-mode fixture; the concurrency cases still execute 16/32 competing real transactions. Tests retain their disposable fixture rows and may modify database configuration; never target a shared or production database. Separate test processes must not run concurrently against the same test database.

The PostgreSQL suite verifies RLS, constraints, permissions, transactional acceptance, idempotency, quota races, lifecycle acceptance, and operation leasing. Some lifecycle cases seed operator-observed states directly in the database to test their admission prerequisites. These are real database tests, **not** proof of Kubernetes execution, VM termination, disk fencing, or cloud disaster recovery.

The `migrations` suite also requires `SANDBOX_POSTGRES_ADMIN_PASSWORD` from the local development environment. It accepts only literal `127.0.0.1`/`::1` hosts and a `sandbox_owner` parent URL whose database name ends in `_test`. Using the fixed local `sandbox_dev_admin` account on `postgres`, it creates one randomly named `sandbox_migration_<uuid>` database owned by `sandbox_owner`; it never reads or changes the parent database schema or enumerates other databases. It installs only migrations `0001–0002`, seeds historical running/queued instances, applies the current migrations, and verifies operation queue recovery, timer recovery for an instance whose create already completed, preserved FORCE RLS and epoch/safe mode, and a safe migration rerun. All test connections close before its exact temporary database is dropped, including on returned test errors. Cleanup failures report that database name and preserve the original failure. Process termination can interrupt cleanup; inspect only the reported temporary database if manual cleanup is needed. This is a focused schema-upgrade regression, not the complete release N/N−1, rolling-deployment, or cloud restore exercise.

The local `0002 → 0022` upgrade regression passed on PostgreSQL 17.11 on 2026-10-03, including successful temporary-database cleanup. It also reproduces the old registration queue clock mismatch under v17, verifies the v18 tenant-catalog backfill cannot bypass FORCE RLS, then proves v19 repairs those existing rows by discovering tenant IDs from the restricted global routing index. Runtime startup checks every embedded migration's success and checksum; a higher maximum version cannot hide a missing intermediate migration. The target-validation test passed, and the missing-environment test returned failure as required.

The Keycloak suite obtains a fresh machine access token from the real token endpoint using `SANDBOX_MACHINE_CLIENT_ID` and `SANDBOX_MACHINE_CLIENT_SECRET`. It reads the exact issuer and JWKS URL from the generated environment, fetches real signing keys, and runs `JwtAuthenticator` signature/profile verification. HTTP is permitted only for a literal loopback identity provider; remote endpoints require HTTPS. Missing credentials, an unavailable identity provider, a signature error, or a database error fails the test; none becomes a skipped success. Tokens and secrets are not printed.

Using the real API router and PostgreSQL runtime role, that suite creates an instance, reads its detail, renews its lease, accepts a stop, and reads its operation. It checks that the create audit record identifies the registered service principal, then reuses the same valid token after revoking grants and disabling the principal to verify immediate rejection, including idempotent replay. Each run registers the real `(issuer, sub)` against a fresh test principal and removes that mapping on completion so the service account can be used again. It also starts a loopback HTTP listener and passes the token through a private stdin pipe to a separate Node.js SDK process. That client verifies 401 refresh, receipt loss after a real database commit, duplicate-free retry, strong ETags, renewal, stop acceptance, and polling timeout without server cancellation. Build the SDK before running this suite. These checks do not claim that a sandbox VM has run or stopped.

Local verification on 2026-10-03 first passed against PostgreSQL 17.11 and cached Keycloak 26.7.3. A second, fresh Compose project then passed the real Keycloak-to-API integration using the exact committed PostgreSQL 17.11-bookworm and Keycloak 26.8.0 digest-pinned images, on isolated loopback ports 55474/58074 with independent databases/credentials. The expanded Node SDK→HTTP API integration was subsequently rerun successfully on that exact combination, including lost committed responses and strong ETags. This verifies the local image combination, not cloud identity HA or disaster recovery. A separate missing-issuer run failed explicitly as expected. No cloud or Kubernetes execution was included in this result.

## Identity contract

The imported development realm issues access tokens with:

| Field | Value |
| --- | --- |
| `iss` | `http://127.0.0.1:58080/realms/sandbox-dev` |
| `aud` | Includes `sandbox-api` |
| `scope` | Includes `sandbox:access` |
| signed `typ` | `Bearer` |
| `azp` | `sandbox-dev-service` for the bootstrap machine client |
| `sub` | The Keycloak service account subject |
| lifetime | At most 300 seconds |

`sandbox:access` is an authentication scope, not a tenant or administrator grant. The product registers `(issuer, subject)` and decides whether the principal is a user or service from its own database. No email, username, client name, or arbitrary custom claim grants resource access. Creating an OAuth client does not automatically authorize sandbox operations.

The Keycloak administration username is `sandbox-dev-admin`; its generated password is in `.local/dev.env`. Read it locally in an editor if needed; avoid posting the file or including it in diagnostic output. No user password, production secret, or predefined tenant administrator is committed.

To register another microservice in the Keycloak Admin Console, create a distinct confidential OpenID Connect client, enable client authentication and service accounts, disable standard/implicit/direct-access-grant flows, and assign `sandbox:access` as a default client scope. Keep access-token lifetime at 300 seconds. Store its generated secret in the caller's secret store, then register its issuer/subject and explicit project actions through the product's service-client and grant APIs. Browser login clients use the separate Authorization Code + PKCE configuration and server-side [BFF](browser-bff.md); OAuth credentials are not sent to browser JavaScript. Complete user account management and cloud identity acceptance remain separate work packages.

`deploy/keycloak/realm.template.json` uses Keycloak's native environment placeholders for realm name, client ID, and client secret. For a separately deployed Keycloak, inject these variables from a secret manager and mount the file under `<realm-name>-realm.json` for a controlled initial import. The template does not contain production users or credentials. Production also requires TLS, a durable supported database, restricted administration, audited bootstrap removal, backups, and independently tested upgrade/recovery procedures; copying the development Compose configuration is not sufficient.

Keycloak startup import skips a realm that already exists. Changing the template or an environment password does **not** update an existing realm/database. Keep `.local/dev.env` while the Docker volume exists; use explicit administration/migrations for changes. Do not delete the environment file to rotate passwords. Realm import/export alone is not a complete identity backup.

## Stop, inspect, and retain local data

```sh
scripts/dev-dependencies.sh status
scripts/dev-dependencies.sh down
```

`down` preserves the PostgreSQL volume and generated credentials. The script intentionally has no implicit data-reset command. Inspect container logs carefully because identity/database startup diagnostics may contain sensitive details; do not attach `.local` to bug reports. If a port is unavailable, stop the conflicting local service or consistently update port and issuer/URL settings in the generated development file before creating the environment. The API runs on the host for this workflow: loopback issuer URLs are not container-to-container URLs.

## Application image and CI

```sh
docker build --target runtime --tag sandbox-platform:local .
docker build --target runner --tag sandbox-runner:local .
```

The multi-stage Dockerfile now shares one locked Rust build across `sandboxd`, `sandbox-admin`, `sandbox-admission`, `sandbox-runner`, `sandbox-nodeguard`, `sandbox-backup-worm`, `sandbox-credentials`, and `sandbox-automation`. The runtime target contains the six control-plane/administrative/credential executables and CA certificates; the separate runner target contains only the guest runner with UID/GID 1000. The runtime runs as UID/GID `10001`, receives `SIGTERM` directly, and contains no Rust toolchain or development credentials. Configure runtime credentials externally; no database URL or OAuth secret is baked into the image. The application must handle graceful shutdown; an image entrypoint alone does not implement it.

`nodeguard-export` exports the host service binary without placing it in an application container. CI builds this target for `linux/amd64` using the digest-locked Rust 1.98.1 builder, checks ELF64/little-endian/x86_64 headers, executes `--help` on the Linux runner, and uploads the binary with `SHA256SUMS`, help output and source/toolchain metadata. The artifact explicitly says `unsigned` and `not-certified`; SHA256 detects byte changes and does not authenticate a release or certify a Kata host. Successful CI execution is required before consuming that artifact; local Linux arm64 tests do not establish amd64 execution evidence.

Runtime database checks validate both `current_user` and `session_user`. None of the API/worker/gateway/admission/termination/fencing/volume-deleter/backup/automation identities may be a member of another component, in either direction, even with `NOINHERIT`: that membership may still permit `SET ROLE`. The earlier seven-identity `database_roles` checkpoint validated twenty-one pairs; the later backup checkpoint recorded twenty-eight pairs. Those historical totals are not a current nine-identity matrix or a capacity certification. Its temporary grants and identity switches remain in a single connection transaction and are rolled back; no role membership commits. It also verifies that assuming an unprivileged current role cannot hide a privileged original login.

Default builder and runtime references are pinned to verified OCI index digests, as are the Compose dependencies. Release updates must review those digests and retain SBOM/scan/build provenance for the resulting image. Debian packages are resolved during the build, so source pinning alone does not claim byte-for-byte reproducibility; the resulting image digest is the deployment identity. This checkout has no cloud release certification.

GitHub Actions runs formatting, clippy, normal tests, real PostgreSQL and bootstrap integration suites, a live Keycloak token-shape check, real Keycloak-to-API authorization integration, and non-root service/runner image builds. A separate job regenerates the TypeScript SDK contract, rejects generated-type drift, builds declarations and runs retry/timeout/tenant/real-HTTP tests. Missing integration-test targets or unavailable dependencies fail the job. The standalone token helper checks token shape only; the Keycloak integration suite verifies its cryptographic signature through the real API authentication implementation.

Primary references: [Keycloak realm import](https://www.keycloak.org/server/importExport), [Keycloak container deployment](https://www.keycloak.org/server/containers), [Keycloak database configuration](https://www.keycloak.org/server/db).

## 真实账户控制台专项

先安装锁定的 console 依赖并构建 `console/dist`。此专项沿用 `bff::live_tests::real_keycloak_chrome_console_bff_and_api_enforce_live_revocation`，不新增测试选择器。源码根必须是本次实际输入的 canonical 绝对路径；共享 Cargo cache 中内嵌的旧 manifest 目录不能决定浏览器脚本或静态资产位置。

受审本地启动器清除继承的 `SANDBOX_*`/`TEST_*`，再向测试子进程注入以下固定输入：

| 输入 | 要求 |
| --- | --- |
| `SANDBOX_TEST_SOURCE_ROOT` | canonical 绝对仓库根，含当前 Cargo 源、浏览器脚本及已构建的 `console/dist/index.html` |
| `SANDBOX_TEST_NODE` | 审阅过的 Node `24.19.0` 绝对可执行路径 |
| `SANDBOX_TEST_CHROME` | 已安装 Chrome 的绝对可执行路径，启动独立 headless 实例 |
| `IDENTITY_PYTHON` | 已安装身份 provisioning 依赖的绝对 Python 路径；默认是上述根下 `.local/cluster-venv/bin/python` |
| `SANDBOX_OIDC_ISSUER` | 现有测试 Keycloak 的 `http://127.0.0.1:端口/realms/测试realm`，本 case 不接受远端 IdP |
| `SANDBOX_KEYCLOAK_ADMIN_PASSWORD` | 本地 `sandbox-dev-admin` 密码，经受保护输入或自有 Keycloak 进程私有捕获注入，不放 argv/日志 |
| `TEST_DATABASE_URL` | 独立新 `_test` 库的 `sandbox_app` 登录，无 superuser、BYPASSRLS 或 owner membership |
| `TEST_MIGRATION_DATABASE_URL` | 同库独立 `sandbox_owner` 登录，负责正常迁移 1..37 与固定 `scripts/sql/{roles,browser-role,worker-role}.sql` |
| `TEST_WORKER_DATABASE_URL` | 同库独立 `sandbox_worker` 登录，诊断验收通过正常 worker 领取并发布，不由 owner 写入报告 |

既有 `scripts/test-service-lifecycle.py` 的 `regular_read`/`private_urls` 提供当前用户拥有、0600、非 symlink、有界且稳定的固定 FD 环境读取；`private_urls` 校验整套分离 runtime 登录都指向同一 literal-loopback `_test` 库。browser case 分别使用 API/owner/worker 登录，不因启动器验证其他组件登录而取得那些组件的权限。不要 shell source 本机 `.local/dev.env`，也不要用 `env`、`set -x` 或打印测试配置 JSON 输出秘密。随机用户/服务凭据和真实 token 仅供测试及私有进程管道；测试只创建并清理自己的随机 realm，不改现有应用 realm。

在私密输入已由上述启动器注入、工作目录为本次固定仓库根且静态资源已构建的条件下，执行：

```sh
cargo test --locked --offline --lib \
  bff::live_tests::real_keycloak_chrome_console_bff_and_api_enforce_live_revocation \
  -- --ignored --exact --nocapture --test-threads=1
```

启动器必须显式设置源码根和两个可执行路径，不能仅在 PATH 中选任意 Node 或依赖旧编译目录。保留正常编译、栈和期限配置；串行运行于一次性库，不目标共享/生产库，不删除旧库或卷。缺输入、IdP、浏览器或数据库错误均失败，不记 skipped 成功。

2026-10-09 最终源码 `51f7dda624fc5c116482f4e76801be89cdaeffc4bdb99d8f693be30c127da574` 在新库完成机器身份 5/5、项目授权 4/4 和此真实浏览器专项 1/1，记录 `.local/evidence/accounts/1791535700763985000/record.json`；启动器运行于固定工作根，源码快照是验收证据副本，前后 SHA/mode 不变。之前缺 Node、旧缓存源码路径和字段标签定位失败均保留；只修正输入绑定与可访问名称，没有放宽时限、权限或计数。随后只补验收文档。此链验证本地 UI/BFF/API 的真实身份与授权事务，包含一个有意注入的已提交回执丢失；不认证生产 TLS、企业身份、Kata/CSI/实云、发布 HA 或 RDS 全局连接容量。

诊断扩展在账户阶段完成后临时禁用该浏览器主体的 `operations:read`，保留诊断创建/读取及实例读取；通过真实提交后丢回执、重载原键重放，核对只有一份报告/Operation/审计/幂等记录。正常 worker 领取精确 DIAGNOSE 操作并 `reconcile` 发布报告，owner 仅核验事实及阶段性授权撤销。浏览器从请求记录打开结构化 COMPLETE 报告，额外真实 Operation GET404证明没有隐式增权，再验证诊断读取撤权404清除及恢复后原报告相等。实例/工作区/活动执行完整JSON行保持不变，恢复原权限后继续旧停止、账户与成员撤权阶段。

诊断专项8/8和能力/授权1/1记录 `.local/evidence/health/1791542218251633000/record.json`。最终747文件源 `d15d90759dc79dc149160c805afd6174b554cf4baaabe00d6c3f0eb674ab2bfc` 的完整浏览器链在两个新库分别1/1通过，记录 `.local/evidence/health/1791542835360872000/record.json` 和 `.local/evidence/health/1791542898336747000/record.json`，输入前后SHA/mode不变；相对专项源码仅 App 历史身份展示和两个 JS 驱动的验收标识变化，Rust/API/SDK相同。32项控制台单测、4项 Chrome合同、61项 SDK、严格Clippy/fmt另存于汇总 `.local/health-console-20261009/final.json`，不能混算真实专项数。保留一次未定位的浏览器Error；增加固定类别/阶段诊断后两次同源码通过，不声称确认根因。随后只补本次交付文档。local公开TLS fixture、忽略测试证书错误、回环IdP仅验证本地链，不认证生产CA/MFA/实云Kata/CSI/HA/容量。



## Admission 服务联调

安装与信任边界见 [`deploy/admission/README.md`](../deploy/admission/README.md)。
独立 `sandbox-admission` 仅提供强制客户端证书的 HTTPS 端点；
`cargo test --locked --test admission` 包含真实 loopback mTLS 正负握手、
AdmissionReview HTTP 回包、合法 Pod/PVC/Cilium policy 和攻击变体。
证书私钥位于 `tests/fixtures/admission`，均为公开测试素材，绝不能安装到任何集群。

共享真实 PostgreSQL 的集成套件必须串行执行。启动本地依赖后，在不打印凭据的 shell 中执行：

```sh
set -a
source .local/dev.env
set +a
cargo test --locked --test admission -- --ignored
```

此测试显式要求 `TEST_ADMISSION_DATABASE_URL`，使用独立、非 owner 角色
`sandbox_admission`（只读表权限与一个消费执行准入的窄函数），验证租户 RLS、禁止写入和抢占队列、SQL 中真实授权/续期状态变化
及已受理停止在主体撤权后仍可收尾。Kubernetes GET transport 在此测试中是模拟的；
真实集群的 mTLS 配置、调度和 CSI 身份、首包策略、失联 VM 确认仍必须通过 G1。

CONNECT 集成用例另外要求 `TEST_GATEWAY_DATABASE_URL`，以真实 gateway 角色先登记
一次 dispatch，再验证准入只消费一次。覆盖同一 API Server 请求 UID 重试、16 个
不同请求并发只有一个成功、强停权限撤销、旧 worker lease token、错误 Pod UID，
以及其他运行角色无法调用准入函数或直接改 receipt。Kubernetes 对象仍由测试传输
提供；不把这些测试称为真实集群执行。

执行网关连接前由 `GatewayRuntime::verify` 每次直接 GET RuntimeClass、已认证项目 namespace、默认拒绝基线、受控 CiliumNetworkPolicy、PVC、其绑定 PV、当前 Pod 和 Kata Node。已登记 UID、launch/generation/epoch、安全清单、就绪状态和 PV claimRef 必须一致；缺失或正在删除的资源、节点隔离/下线 taint、网络策略漂移均拒绝，校验器没有创建、修复、删除或 exec 操作。随后数据库仍需重新授权并持久化唯一 attempt，CONNECT 准入再次消费一次性许可；这些 GET 不能消除跨系统时间差，也不证明物理虚拟机终止。`cargo test --locked --test gateway_runtime` 用合成 Kubernetes HTTP 响应覆盖合法路径和攻击矩阵，不替代 G1 真实 Kata/Cilium/CSI 验收。

The `migrate` role pins a single owner connection and uses a bounded five-minute statement timeout for reviewed backfills and role grants. Runtime roles retain the ten-second limit and three-second lock timeout. Migration lock contention still fails promptly; schedule maintenance and retry the same migration after clearing contention. A timeout rolls back that migration rather than marking it complete. This does not establish a safe rollout without the upgrade/recovery tests for the release.

Node incidents use the separate generated `TEST_FENCING_DATABASE_URL` and the owner fixture. The nine ignored `node_fencing::tests` cases verify cross-tenant freezing, historical boots, real database lock contention, irreversible dispatch intent, observation-only recovery and BREACH, using a local HTTP cloud responder. They also check that a limited fencing role can commit deferred file-activity validation across two tenants without broader table grants or leaked caller context. They never invoke a real cloud stop or release resources based on cloud status. See [the SYSTEM node incident runbook](node-fencing.md) for the executable administrator/controller entry points and the remaining cloud cleanup boundary.


Workspace destruction uses `TEST_VOLUME_DELETER_DATABASE_URL` and the existing dedicated termination/admission fixture roles. Its ten real PostgreSQL regressions include default automatic-snapshot preservation, independent cloud read-back, unknown-response recovery, holds/retention/revocation, exact PV/PVC UID admission, lease expiry during a real event-head lock wait, and the signed-JWKS HTTP contract. The operator resume SQL is executed against the database in the denied-cloud test, including rejection of a changed identity digest. Frozen migrations 0023–0025 also passed the isolated v2 upgrade test. ECS/STS and Kubernetes are local protocol substitutes; actual cloud deletion and Kata/CSI certification remain required. See [workspace deletion](workspace-deletion.md).

The local bootstrap also prepares a separate `sandbox_backup` login. Its component-specific grants are applied after the backup schema and other component grants; it never receives another component's membership. The real PostgreSQL role regression passed all twenty-eight pairs across the eight runtime identities, including `NOINHERIT` membership rejection. These permission checks do not certify the backup workflow or cloud deployment.


The ten ignored `never_authorized::tests` cases use real PostgreSQL to exercise permanent launch closure, lost registration ACKs, racing DELETE/permit transactions, event-head lease expiry, SYSTEM TTL STOP recovery, versioned owner activation, late Pod UID cleanup and exact enrolled-node scheduling. Kubernetes is an explicit protocol substitute, including an empty inventory followed by delayed creates. See [never-authorized closure](never-authorized-closure.md). Migration 0027 does not backfill historical generations; 0029 exposes only a narrow candidate check for authorized DELETE to replace an unstarted safety STOP; 0031 validates fresh Node UID, boot and profile against current database certification and the reviewed node set. The isolated v2-to-current upgrade regression passed through migration 0031.


## 服务退出与数据库连接回收

`sandboxd` 与 `sandbox-admission` 建立连接池后，所有普通成功或错误返回都会等待 `with_database_drain` 完成。连接池关闭不会跳过仍借出的连接，也不会覆盖原始业务错误。worker/file cleanup 和 gateway/file gateway 使用 `run_pair`：任一父任务完成便取消共享 token，并等待另一个父任务的收尾；先成功后失败仍返回失败。网关的原 30 秒子任务等待期限保持，超时后 abort 并 join；持久 UNKNOWN、租约、可信终止和 hold 规则保持。

本地专项 runner 使用显式受保护的 `.local/restore-test.env`（0600），只接受 literal loopback PostgreSQL 及 `_test` 库名，创建全新库而不删除旧库，不打印凭据或隐式 source 环境文件。Docker 必须显式指定本机 Unix socket；继承的远程 Docker context/host 不参与路由。运行命令：

```sh
RESTORE_TEST_DOCKER_CONFIG="$PWD/.local/docker-public" \
RESTORE_TEST_DOCKER_HOST=unix://$HOME/.docker/run/docker.sock \
python3 scripts/test-service-lifecycle.py --env-file .local/restore-test.env
```

八个真实认证角色在正式 1..37 下分别验证成功、启动错误、首父任务错误、另一父任务收尾错误，共 32 组物理连接试验；每组实际持有借出连接，检查 close 等待和 clone pool 已关闭，归还后由独立同角色新事务确认 PID/backend_start/application_name 缺席。单独 `tests/service_lifecycle_process.rs` 运行 Cargo 构建的实际 sandboxd：验证数据库连接后的缺 cursor 配置错误和 idle API ready 后 SIGTERM，检查进程退出及独立 PG 缺席。该进程测试使用明确本地 HTTP 和公开 OIDC/cursor fixture，不代表生产 PKI、登录流程或云部署。

709 文件专项源 `c0f675e61fdac7d0bfd1e1afe2c8dddbde8c2c683693e6a6450a01a8d170f003` 的两项分别 1/1（4.97/2.35 秒）通过；完整普通回归 355 通过、222 ignored、50 个程序、严格 Clippy/fmt 通过。专项 receipt `.local/service-lifecycle-candidate-20261009/root-actual-d1-v1-pass.json` 与普通 checkpoint `.local/evidence/checkpoints/read-gc-1791486514678997000/record.json` 单列。首进程外层驱动因完成标记与 Cargo 测试名称同一行而误判，原记录保留；精确分类器仍拒绝零测试、其他测试或非零退出，然后新库重跑通过。

以上验证普通 Rust 返回与本地进程退出；panic、SIGKILL、所有真实控制器、BFF cleanup parent、部署 Pod/RDS 和全局容量认证均不在此次通过范围。不得依据本地 pool.close 或静态 replica 数释放旧部署容量、云资源、工作区 hold 或租户配额。


## 浏览器清理任务与数据库进程遥测

浏览器 BFF 的 `run_cleanup` 由 sandboxd 持有，与 API 父任务共同取消和等待；Router 构造不启动后台任务，listener 绑定成功后才启动 cleanup。原每 60 秒清理、首次立即 tick、Skip 和 SQL 保持。取消先于新 tick；已经派发的 SQL 不会被丢弃，按原 statement/lock timeout 返回后记录 cleanup stopped，再由外层等待 pool.close。普通错误与绑定失败保留原错误，不以清理失败覆盖。

`Database::connect_for_process` 从固定可执行分支选择角色，连接标签为 `sbx1.<role>.<full-process-uuid-base64url>.<full-pod-uuid-base64url-or-dash>`，最长 62 ASCII 字节。一个进程的连接池共享完整 128 位随机进程 UUID；同 Pod 进程重启获得新 UUID。`SANDBOX_PROCESS_POD_UID` 必须为 canonical nonnil UUID；有 `KUBERNETES_SERVICE_HOST` 时缺失即拒绝。API、admission、termination、volume-deleter 和 backup 生成器只给实际数据库容器注入 `v1 metadata.uid`，init/凭据容器不借用数据库身份。数据库角色、OIDC、URL 参数 allowlist、TLS 校验与查询期限均保持；执行分支覆盖 URL 中的遥测标签。日志不含数据库 URL 或凭据。遥测标签可被有权的数据库用户改变，不能认证身份或证明旧连接释放。

同一公开 runner 现在提供两个可重复专项，每次创建独立本地 `_test` 库并冻结全部 Git 公开输入和 mode：

```sh
RESTORE_TEST_DOCKER_CONFIG="$PWD/.local/docker-public" \
RESTORE_TEST_DOCKER_HOST=unix://$HOME/.docker/run/docker.sock \
python3 scripts/test-service-lifecycle.py --env-file .local/restore-test.env --suite roles

RESTORE_TEST_DOCKER_CONFIG="$PWD/.local/docker-public" \
RESTORE_TEST_DOCKER_HOST=unix://$HOME/.docker/run/docker.sock \
python3 scripts/test-service-lifecycle.py --env-file .local/restore-test.env --suite process
```

roles 在正式 1..37 和八个独立 SCRAM 登录角色下完成 32 组物理连接排空；process 运行实际 Cargo sandboxd 二进制，完成启动错误、idle API SIGTERM 和四组 BFF 场景。BFF 的 busy SQL 由真实独立 owner 锁阻塞，SIGTERM 后进程等待，只有真实 COMMIT ACK 解锁后才退出；错误场景等待原 lock_timeout，并核实 API 继续 ready 和固定 warning，不声称独立验证 SQLSTATE。四个 ready 场景在相同 fixture Pod UID 下读取实际 pg_stat_activity 标签，验证完整 UUID、重启不同进程 UUID以及真实 PID/backend_start 缺席。观察读取的新事务也有固定 5 秒预算；测试子进程和日志 reader 收尾完成后才返回原业务结果。显式 HTTP/OIDC fixture、正常 browser-role grants 和局部测试锁不代表生产登录、Kubernetes Pod、生产 PKI 或实云。

711 文件不可变专项源 `5a6a7373ac58997c0f13959e691b2d7d144681934ec3d34ac277eef938fca274` 的 roles/process 分别 1/1（4.92/5.86 秒）通过。汇总 receipt `.local/database-process-identity-candidate-20261009/root-bff-d2-actual-v1-pass.json` 同时复核三份快照、逐文件 SHA/mode、原实际日志、普通 362/222/50 全目标、严格 Clippy/fmt、45 个 Python 测试及五套 renderer 的 136 个固定输入。固定 Kubernetes 1.36.4/Cilium/CSI 官方 schema 验证 175 个未裁剪生成对象；额外必要 CRD 合计 181 次校验，24 个数据库容器的 Downward API 字段均匹配。两次先前失败（测试中比较不支持 PartialEq 的 SQLx 枚举、SQLx CertificateInput::File 诊断包含 `file: ` 前缀）保留；修正测试断言后重新完整验证，生产 TLS 未改。

本阶段补足 BFF 父任务等待与连接归属遥测。实时 RDS 上限/epoch、未知外部连接、旧新滚动 Pod 与 terminating 总量、实际连接缺席及安装 CAS 尚须采集和验收。不能以 static replica、Pod 标签、pool.close 或此本地专项放行生产容量、云删除、工作区 hold 或租户配额。正式恢复/自动化迁移和入口继续关闭，当前版本尚未通过生产发布验收。


## 恢复 PV 绑定的首末授权读

新的 `sandbox_restore_raw_bound_admission` 与 `sandbox_restore_raw_bound_claim` 只位于关闭恢复模块的开发 fixture，未进入正式迁移、角色安装或生产路由。admission/backup 独立登录的固定用途 wrapper 分离，内部 helper 和云盘伴随表不给普通角色全局读写。SQL 沿既有 workspace→instance→排序 operations→restore→排序资源→节点锁顺序，单条 MATERIALIZED 查询共同推导当前授权和有限 horizon：每个范围取有效替代 grant 的 MAX，六个 tenant/project 必需范围再取 MIN，最后与资源、profile、节点认证和当前 lease 取有限最小值，最多十秒。原 selected scheduling 路径的十一键 ABI 和无 PV 绑定规则保持。

上一检查点的 Bound pin 为严格十三键，新增 block_receipt 和 disk_receipt；PV binding、原媒体记录和新的云盘伴随记录必须三者全部 null 或完整一致。post-record 约束包括正常父 PVC/PV UID、完整 UUID 生成名称、冻结大小/AZ/compute KMS、PV spec SHA、原观察/记录时间和精确 topology receipt。旧媒体记录不能获得 compatibility fallback。伴随表为 owner-only、append-only、forced tenant RLS 和严格 parent FK/JSON；SQL 形状检查不验证云签名，因此没有新普通 publication writer。Rust token 的 scope/pin/time 字段不可外部构造、无 Deserialize；`RawBoundAttempt::start` 必须在首个真实父 PVC selected-node 定位 GET 前调用，首末均保留原总十秒及第一有限 horizon，最终完整 pin 比较先于 COMMIT，COMMIT ACK 后再次检查预算。

复验沿用公开 runner 的原精确 selector：

```sh
env -u DOCKER_CONTEXT -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
RESTORE_TEST_DOCKER_CONFIG="$PWD/.local/docker-public" \
RESTORE_TEST_DOCKER_HOST=unix://$HOME/.docker/run/docker.sock \
bash scripts/test-restore.sh .local/restore-test.env raw_selected_node
```

新 child 复用正常 Pending 父 PVC POST/GET/记录、early PV intent、Job 创建/GET/记录、单次 Pod 创建/GET/记录、真实 mTLS 登记与 owner topology 发布；通过实际 TCP 读取同 UID 的 selected Pending 父对象后执行两独立读接口。实际 PG 覆盖当前 claim 的成功首末 COMMIT、完整 13pin、42501 角色隔离、foreign/missing scope拒绝、六个精确范围逐一撤权、错误 token/operation 和单调 principal authz_version 改变导致末读 pin 不同。未插入未来 PV binding/原媒体/云盘 companion/permit/proof，也未释放 hold/quota；完整原源/目标事实保持。新 child 的末尾 RESET 曾使后续既有 SELECT no-op 用例在错误位置拒绝，原整项失败保留；改为保持原 selected/provisioner hints，经新库完整重跑通过，生产条件保持。

715 文件不可变源 `ada0fcf7d7d04bfb1a4dba82097b91e2769c4ec60b7b4e0a5572aa1f41cc2091` 下整项 1/1（36.56 秒）与普通 363/222/50、严格 Clippy/fmt 通过，汇总 `.local/restore-raw-bound-reader-candidate-20261009/root-pre-record-actual-v1-pass.json` 同时核实际快照、普通快照、SHA/mode及原日志。首次全量在本机执行沙箱拒绝 bind 后产生 76 个 loopback 传输测试失败；原源码/日志保留，正确本地网络权限下重新验证通过。修复过程 fmt 检查失败记录也保留，没有作为通过证据。

Bound 专属故障 child 已直接消费这两个新接口：两个独立登录角色×首/末 COMMIT×延迟/真实 socket 丢 ACK 共八组，以及两个角色×首/末锁等待源撤权共四组。代理看到正常 driver 的实际 COMMIT CommandComplete 后，同 reader 的独立真实 PG 连接在原两秒窗口内确认原 PID idle、xact_start 为空且关系/事务锁缺席；延迟保持原短 lease 并等其实际过期，精确 403，丢 ACK 在 lease 仍有效时关闭真实转发 FD，精确 503。真实锁试验以 pg_blocking_pids 观察原 owner 工作区锁，在原三秒 DB lock_timeout 前提交撤权，新 reader 重新读取并精确拒绝。每组先捕获业务/观察结果，等待两未来、关闭池/join 实际 socket owner并核 PID 缺席后才传播错误；恢复 fixture 只更新其实际 claim lease 或 enabled，grant version 单调，不回写 principal/epoch/节点/拓扑。完整源/目标/hold/quota 不变，locator 恰一 GET、PV/Node/cloud 观察与三条未来记录/permit/proof 均缺席。构造及 PID 获取之前的旧 Drop fallback 和未测失败路径不作有界排空结论。

最初用 owner 观察其他登录角色的 pg_stat_activity.state，因为该角色没有 pg_read_all_stats/pg_monitor，实际整项失败（34.04 秒）；失败源码和日志独立保留。仅改用同 reader 的独立正常池，并在原两秒 timeout_at 内覆盖 acquire/query、idle 发布轮询及响应后时钟检查，无新增权限或期限。修正后 716 文件不可变源 `34bbddec8cae79d7921fc78a0e8d19703d65617b0e42f47f05ece7f028fb2c80` 下整项 1/1（51.48 秒）通过，十二 marker 与原 selected/identity/boundary 收尾均完整，普通全目标 363 通过、222 ignored、50 程序、0 失败，严格 Clippy/fmt 通过。`.local/restore-raw-bound-reader-candidate-20261009/root-ack-actual-v1-pass.json` 同时核两实际快照、失败至通过仅单一 child 修正、普通快照和全 716 SHA/mode；静态审查仍分别标注原候选与修正 SHA，不回填旧失败。

当前通过范围是 pre-record 授权读及上述明确故障场景；PV 绑定完成和新 API 真实 claim 换代未在本点验证。正常 writer 还需同一最终事务重读完整 pin、写入 PV binding+block+disk 三行、返回行严格核验并延续原期限至 COMMIT ACK；先提交独立 recheck 再调用旧 writer 无法满足原子性。宿主 launch gate 必须要求强 companion；RESTORE_RUNNING 之后的 Retain/KCM 受控 metadata retry 需要独立历史用途和完整 immutable/permit pin，不能扩大当前 Pending reader。

接入真实只读云盘客户端时发现原十三键 pin 未携带源原盘与 immutable clone 的 cloud disk ID，原 SQL 仅内部作排除比较；下述 Source14 开发片已补齐同一授权语句和首末等值，不能由调用者裸 ID 或另一独立查询伪造排除来源。备份控制器的实际 SA 是 sandbox-backup-controller；sandbox-backup 属于 Job，不能借用。独立 admission/controller 的精确 RAM read role、短期 token、固定出口、签名 DescribeDisks、完整 PV/Node/CSI 两轮观察及供应商 provisioner transcript 均待接入和验收。正式恢复/自动化迁移与生产入口保持关闭。

## 恢复源身份冻结与同连接查询回归

当前 strict14 pin 增加 `source_storage`，只有 `source`、`capture_attempt_id`、`clone` 三键。完整正常备份 source14 与 immutable clone9 在同一 MATERIALIZED 授权 CTE 中取得，不另开裸 owner/source 查询；历史源 epoch 不被重解释成当前目标 epoch。四个源/clone PVC/PV UID、两个实际 cloud disk ID 与 lineage/size/时间形状严格核验，派生只读比较 facts 与不可外部构造的 admission/backup scope。错误用途、替换 attempt、错误实际 worker/claim 身份均拒绝；最后读取和 COMMIT ACK 保留原十秒 attempt 与首/current 的最短 horizon。facts 可序列化供比较，不能作为独立云证据、publication 或 host permit。

最初四次 Source14 实际运行返回 503，源码与日志全部保留；最后一次固定安全分类为 claim_fetch/IO，服务端同时记录 backend SIG9 与恢复。局部规划设置只改新 helper 入口，两份函数体、锁/守卫和权限逐字保持；没有全局禁用 JIT、增加容器内存或延长期限。初始 717 文件源 `88eed1be9a0bf3971e82983d7775ea2bdde3353a373b5f77657576b3b68fae3e` 在新库整项 1/1（50.98 秒）通过，103 次一秒采样无错误、峰值为采样值而非精确峰值，历史 cgroup OOM 计数无变化。

之后新增两个独立真实登录、max1 固定 reader backend，正式 1..37 验证必须先于私有 DDL，没有 startup fallback；保留原角色池作为独立同角色 observer。每角色在 auto、force_custom_plan、force_generic_plan 各执行六对真实 API 首末读，合计 72 次 strict14 查询和 36 次真实父 PVC locator GET。正常 worker heartbeat 只发生在每个新的原始 attempt 之前，不发生于该对首末之间。每对核对同 PID/backend_start/login、原 statement/lock 10s/3s 与 join/from session 设置；实际 own-session prepared counters 验证外层 custom/generic/auto 的执行次数，不推断内部 SPI 计划或 OOM 根因。结束后显式关闭新增池，并由原同角色独立新事务确认 PID/启动时间缺席；未测构造失败、panic、取消或全产品排空不作认证。

四次较早 prefix 失败分别为代理连接、原 ACK 等待、正常备份初始化 503 和迁移连接超时；均未到达新增热查询 marker，不回填为通过。最后一次后实际 Docker socket 消失，内存观察器完成 join 但 after 读取不可用，因此没有完整 memory record，不能填零或无 OOM。启动已有 Docker Desktop 与既有本地 PG/Keycloak 后，原 2 GiB/3 GiB memory/memory+swap 限额保持，当前 718 文件不可变源 `1e75e4e60b286d4e4619eaed69a161d564315ae75b2e7cfaf7fb3c46eb76b485` 在新库整项 1/1（48.88 秒）通过，Source14、hot72、十二 ACK/锁故障和全部旧边界标记完整。本次 85 次采样无错误，采样峰值 1,271,181,312 字节，当前重启 cgroup OOM 计数前后不变；不证明三个较早 prefix 失败的原因，也不认证生产容量。

相同 718 公开输入普通全目标 365 通过、222 ignored、50 程序、0 失败，严格 Clippy/fmt 通过；`.local/evidence/checkpoints/read-gc-1791513037857479000/record.json` 的 JSON manifest SHA `4ec9a0af8b37d5e0e3bc139bc1711c0bb445d99c64620059ee6948193fd3a387` 前后不变。汇总 `.local/restore-raw-bound-reader-candidate-20261009/root-source14-actual-v1-pass.json`（SHA `c9724bdb2d6a0368abfcdcb2fb735a6d295e939743c5b22171ab56d722c1dce0`）重核当前/实际/普通快照全 SHA/mode 和全部失败；环境恢复独立收据 `.local/restore-raw-bound-reader-candidate-20261009/root-source14-environment-recovery-v1.json`（SHA `51ffafb996446a46eb675c107126905ec4d567a5e5be998e04bf70a24ab69217`）。两份临时诊断和统一错误分类均恢复 HEAD 原内容，没有更改生产错误响应。随后只更新本文件与 implementation-status.md。

此点完整通过的是未产生未来记录的有限授权读，不是云盘绑定或恢复完成。真实两轮只读云协议采集和 vendor PV projector 仍为独立未执行候选；同最终事务三行写入、强宿主 companion 校验、部署 IAM/vendor CSI、Kata/KVM、全局数据库预算与正式发布继续开发。正式 1..37、角色安装、生产配置与恢复/自动化入口保持不变。


## Bound 对象与只读云盘的完整采集调用者

`BackupRawBoundCollector::observe_pending_restore` 复用 normal current backup claim，父 PVC locator GET 前开启原十秒 attempt；同一首末 SQL strict14 pin 提供 source/clone 排除、准确存储契约、云目标、节点/CSI 与可选已记录目标。两轮实际 HTTP GET 保留 PVC/PV/Node/CSINode 原 JSON，再核 Bound、精确 UID/spec/topology。实际目标 disk ID 排除源盘/clone，实际 PV UID 排除四个源/clone PVC/PV UID与目标父 PVC UID，包括目标尚无 PV binding 时。normal final reader 保留 owned token 与最短 horizon；原 attempt、lease、权限与 COMMIT ACK 不重置。输出为不可开放构造/反序列化的模板观察与 attempt，不是三行发布、供应商认证或宿主 permit。

每轮只读云客户端重新读取 projected OIDC，独立新建 STS credential cache，执行 AssumeRoleWithOIDC、GetCallerIdentity 账户/ARN/RoleID 核验及 ACS3 签名单盘 DescribeDisks。备份控制器与 admission 的实际 subject、scope 和用途分离；新传输共用原组件进程节流/并发 Arc 守卫，默认旧构造行为保持，不认证跨副本全局限额。admission 保持原三秒单次上限并在成功返回后核对时钟；原十秒总预算和所有有限 scope 继续收紧。TLS 响应与签名请求不等于独立云响应签名认证。

公开 runner 原 `raw_selected_node` 精确 selector 接入新增 child。正常 Source14/Capture/clone 与 Pending PVC/Job/once Pod/登记/拓扑先经原流程建立，HTTP fixture 提供显式供应商模板形状的 Bound 对象，由 collector 执行自己的完整首末 SQL，没有未来行 seed 或 owner 直接授权。十个分支为正常备份两轮、五种实际 PV UID 混用、第二轮 Node/CSINode UID 各自变化、第二轮云盘 serial 变化和独立 admission 两次 fresh 云观察及首末读。云 server 核签名头/短期 token/准确单盘只读 session policy与精确请求次数；拒绝 UID/节点时不多发后续云请求。新增地址单元测试拒绝非 loopback、DNS、userinfo、非根路径、query/fragment；地址 seam 仅 cfg(test)，仍经原身份/签名/解析/期限代码。admission 分支不声称覆盖完整 admission PV/Node 采集链。

child 在传播实际业务结果前恢复 HTTP fixture并关闭/join 云 server；母测试的旧 Drop fallback 和未测失败/panic/取消路径不获得全路径排空认证。全部 Bound 与云身份为协议替身，没有真实 RAM、CSI vendor、生产 TLS/PKI 或 Kata/KVM 证据。724 文件不可变源 `547712e49d628479805697417f6464d9a401dc3c33f168ca0980679d46985517` 在新库整项 1/1（51.16 秒）通过，十个分支及原 Source14/hot72/十二 ACK/锁撤权/selected 边界 marker 完整。相同公开输入普通全目标 388 通过、222 ignored、50 程序、0 失败，严格 Clippy/fmt 通过；`.local/evidence/checkpoints/read-gc-1791515121997098000/record.json` JSON manifest SHA `c539ecac0146366eb653f19b4aa552baa5f4310cfd8d2de76c73c45f03d79f99` 前后不变。私有严格编译、241/109 library 与格式检查、独立静态复核分别保留，原候选 NOT_RUN 收据不回填。汇总 `.local/restore-raw-disk-collector-candidate-20261009/root-collector-actual-v1-pass.json`（SHA `3b6bb7592fb0331bfb68a520b9853e8739c23367cef4d7ab937d5e5ae1dc34d9`）重核私有/实际/普通/当前全文件 SHA/mode，引用上一 Source14 汇总保留早期全部失败。84 次一秒采样无错误，最大采样值 1,321,414,656 字节、当前 cgroup 计数前后不变；不是精确峰值或生产容量，重启计数不抹去历史 OOM。随后只修改两份说明。

下一步 normal publication producer 必须保留 first、collector final、原 cloud deadline 和原 attempt，在同一最终事务重读最短 horizon、三行写入、严格核验返回 pin和 COMMIT ACK 后再次检查。final 合法收紧不能丢失或因原 cloud deadline 不等被错误重置。当前尚无合法 vendor certification factory 或 production host gate。生产 controller projected token、CSINode 只读 RBAC、实云 IAM/vendor/CSI、Kata/KVM、全局容量、灾备与上线验收继续开发。正式 1..37、角色安装和生产恢复/自动化入口保持不变。


## 最终 Bound 观察的同事务交接与认证拒绝

模板采集产物持有原 attempt、original scope、首/末完整 pin、两轮 PV/云盘观察；交接保留 collector final 的较短期限，不能退回较长 first。`RawBoundPublicationAttempt` 在已有正常 backup 事务内重读 strict14，核首读全部事实与未来三 child 均缺席；post 校验只允许同一三 child 变化且必须完整一致。有限 deadline getter 即使已过期仍返回封存的最短时间用于收尾，不能作为新授权或重置十秒窗口。

正常 consuming `refuse_unverified_publication` 使用 engine 自身数据库，BEGIN、重读后的时钟与 token 检查、rollback 和 ACK 都保留最短期限；超期或依赖故障不会冒充目标 vendor403。只有当前授权仍合法、确实没有认证时返回固定 `RESTORE_RAW_VENDOR_CERTIFICATION_REQUIRED`，零写入、零 Gate、零宿主 permit。无法取得确认的回滚/ACK 仍为 UNKNOWN，不认证资源释放。

新增 actual child 在正常创建的源/Capture/clone/Pending/Job/Pod/登记链后取得同一 owned 模板，以真实 backup 事务核 PID/XID/session_user/current_user 首末相等。同 TX 运行实际 full14 首读与正常固定 SQL 重读结果，实际缺三 child 的 post envelope 被精确403拒绝，不制造 future row 或假1微秒结果。之后确认 rollback，再将原产物交给正常 missing-vendor consumer；独立同角色新事务在单独五秒观察预算下核本测试库/登录的开放事务缺席。这个观察预算仅用于事实复核，不扩大原业务期限，也不证明物理 FD、后台任务全路径排空或配额可释放。

初次实际运行在原 Source14/hot72 之后发生 Rust test thread 栈溢出并 SIGABRT，没有整项 summary；失败日志与724源完整保留。将新 owned handoff 子链抽为 Box::pin 的独立测试阶段，未改业务函数、断言、fixture 收尾顺序或预算；后续私有编译发现两处参数类型未导入，原101/E0425保留，仅用完整类型路径修正。保存的实际 macOS ARM64 原二进制静态 prologue 显示 exercise poll 从560448降至404672字节、新 handoff195296；不把单函数帧相加当实际栈深度或宣称 crash PC/根因。原私有library实际241通过、109 ignored；外层错误预期242造成的驱动exit1由独立纠正收据说明，不更改日志、断言或计数。

最终724文件源 `e7ed55a5b1539bbf8968477892bfa1413481fd8ece7d4b1d24b279ad5519955f`、新独立库整项1/1（51.25秒）通过，五个阶段 marker、同TX/normal403及原采集、热查询、十二ACK/锁撤权和旧边界完整。相同源普通全目标388通过、222 ignored、50程序、0失败，strict Clippy/fmt通过；checkpoint `.local/evidence/checkpoints/read-gc-1791518546208329000/record.json` JSON manifest `cb6a70f04e6b41a682e0b3426b0e6c79827a5769bc2d8831ebfb27be637253d0` 前后不变。94次一秒采样无错误，最大采样1,424,596,992字节、当前cgroup计数无变化，不是精确峰值或生产容量。汇总 `.local/restore-raw-bound-handoff-candidate-20261009/root-handoff-actual-v1-pass.json`（SHA `09239504c5488afed0a9911e168ca29bc17af4bb35f0a877bbf870cb0c3c47f0`）重核实际/普通/B3私有/当前724文件SHA/mode，并关联B1私有、所有失败、独立复核及上一collector历史。随后仅改两份说明，源码验收快照不回填。

当前仅验证无发布的同事务读与认证拒绝。合法 final/新同事务授权收紧的专属动态试验、rollback ACK故障、严格供应商报告/实际CSI observer、真实认证取证、同TX三行写入和强宿主gate继续开发。HTTP/云身份仍为协议替身；生产controller没有合法raw consumer，不能先加闲置token或CSI RBAC。正式1..37、角色安装和0038/0039及生产恢复/自动化入口保持不变。


## 授权收缩与未确认回滚的实际验收

正常管理API更新真实源项目grant，collector首读后至7秒、交接前再至4秒；实际同事务strict14重读得到更短的有限期限，rollback及ACK后检查保留新最小值。回滚响应延迟或丢失固定返回`RESTORE_RAW_HANDOFF_UNCONFIRMED`503、retryable=false并保留请求ID，原认证不足原因只进入固定代码诊断；确认回滚的正常路径仍返回vendor403。没有写入三行、供应商Gate或宿主permit。

真实PG协议代理确认ROLLBACK CommandComplete及后续ReadyForQuery边界，独立同角色观察backend idle/无xact与锁释放。延迟跨授权期限、丢失响应分别得到精确503；pool关闭、拥有的proxy join和PID缺席单独核验。每个故障后用正常管理API恢复grant、创建新attempt验证认证不足403，整个源/目标/hold/配额保持。普通开放事务观察不证明物理媒体/VM排空或资源可释放。

最终726文件源`a04a8c2d61dbb8b41aafb58263cb818f0ca68d018236da09b212f575f1abdf87`、全新库整项1/1（58.82秒）通过，包括grant收缩、两个rollback故障、两次fresh403及原Source14/hot72/十二ACK和旧边界。相同源普通388通过、222 ignored、50程序、0失败，严格Clippy/fmt通过；JSON manifest`c424037157cf9a44bbc99c7c513e6df0ec752d7982dcfcfa6a9359079dab872b`前后不变。101次一秒采样无错误，最大采样1,590,521,856字节、当前cgroup计数不变，不是精确峰值或容量认证。汇总`.local/restore-raw-handoff-fault-candidate-20261009/root-fault-actual-v1-pass.json`（SHA`8fefc29bc57081181a838a17032cf8b790b5657a7b0b9100f645c085b0f40831`）重核实际/普通/私有/当前全文件SHA和mode。

保留前三轮SIGABRT及无summary日志、C4复杂类型告警和格式检查失败。真实macOS崩溃报告UUID与保存的第三轮二进制一致；只读静态测量定位到外层测试exercise的405120字节固定帧。仅拆测试为prefix→fault→suffix，持同一实际collector/cache及原PV路径，保留所有正文、断言与fixture收尾；同步装箱边界和等价返回类型别名只影响测试组织。未扩大栈/线程/标志、原十秒/授权期限或PG/Docker限额，也不将静态帧相加当动态栈深或精确根因。供应商报告及真实CSI观察、合法认证链、原子三行写入、强宿主gate与实云上线继续开发；生产入口仍关闭。


## 严格供应商报告与正常拒绝消费

报告使用受限canonical JSON、严格字段/整数/UUID/UTC时间及已锁定的模板契约；最多131072字节，六个用例覆盖三个AZ且有有限复核期限。报告SHA、profile/certificate/enrollment及存储/云映射只与同一正常sealed14 scope比较，不从报告字段制造SQL或云授权。活动镜像列表仍只是有界期望，并不认证完整controller/node镜像库存。

正常collector携带Option<Arc<RestoreVendorReport>>到已有一次BEGIN/完整重读/rollback消费。纯比较后重核同事务token和原owned claim，保留原/新最短期限；None和即使匹配的报告也不能产生供应商Gate，仍拒绝发布。错绑固定runtime403，文件读取依赖故障503；未确认rollback的专用不可自动重试503与请求ID逻辑保持。

新增8项普通测试验证格式、固定契约及期望绑定。实际新库读取原legacy报告得到Unavailable；两次正常新producer分别消费None与有效格式但SHA不符的合成期望，精确达到vendor403/runtime403、两轮Bound GET和两次fresh云协议读，并确认同事务rollback/零未来记录。合成报告没有登记或取得认证；合法新profile/cert/enrollment/source的matched actual尚未完成。729文件源`d99103638bb704dd6167a4f9127d4ec66a1e6115e101862878eebf740aa0b026`整项1/1（60.04秒）通过，旧Source14/hot72/授权收缩/十二ACK及rollback故障和边界完整；相同源普通396通过、222 ignored、50程序、0失败，严格Clippy/fmt通过，JSON manifest`4609f8565ee395193149446d22d355fde92c24793903b2a1b533710d795f0859`前后不变。98次采样无错误，最大采样1,612,496,896字节，当前cgroup计数不变，不是容量认证。

汇总`.local/restore-vendor-gate-candidate-20261009/root-report-actual-v1-pass.json`（SHA`bf85b78223926a7c3ee491b8808ef23307e9d3b0d07a656a6afa14848a6d48d0`）关联原A1缺正常消费者/contains告警的101失败，等价修正及真实消费者接线后严格通过；未加dead_code allowance或假authority。真实CSI对象/安装defaults、完整镜像身份、供应商wire认证、三行原子写入和强宿主gate继续开发；正式1..37、0038/0039及生产角色/恢复入口保持不变。

## 合法报告匹配与 CSI 两轮正常观察

新增 owner-only `register_restore_report_expectations` 只登记经严格解析的期望配置，沿用不可变报告表和完整十秒预算，不签发运行、介质或发布许可。新独立 `raw_vendor_match` 验收通过正常 P/E1 注册、Kubernetes/保留验证与激活完成备份，再用同一生成的 Secret 对象、私钥/SPKI和内容哈希独立验证激活 Q/E2；源 profile、动作历史、备份、vault、clone、实例和工作区保持完整比较。新 R 正常登记、精确重放、不同审批引用冲突、普通 backup 角色拒绝四个实际分支已到达。epoch、禁用、过期、云/映射错绑以及本 owner 接口专属 COMMIT ACK 故障尚未分别验收。

原采集器持有的 attempt 和原 Kubernetes 客户端继续完成 CSI 观察。每轮十九个读取包括三个控制器 Pod 的 ReplicaSet/Deployment 所有者链及三个可用区节点，以及 selected DaemonSet/ControllerRevision/Pod、ServiceAccount、PriorityClass、Node/CSINode。原始响应累计限制一 MiB，重复键和未知字段在有损类型转换前拒绝；固定投影重建完整 PodSpec，并验证身份、镜像状态及位置。两轮全部原始对象必须一致，包括易变 Node status/resourceVersion；真实节点变化可能导致拒绝，运行性待实云测试。观察后执行正常完整授权重读，把新 token 放回原 owned observation，随后沿原最短期限进入同事务交接和确认回滚，仍返回固定供应商认证不足403。

739 文件不可变源 `ab74db2212b895cfc2b9d2abb022e395c32bda01b166e0963dd70a188925a497` 的两个全新库实际验收分别通过：`raw_vendor_match` 1/1（18.87秒）确认38次CSI请求、正常最终SQL与精确vendor403；`raw_selected_node` 1/1（60.53秒）复验旧完整Source14、hot72、授权收缩、回滚ACK延迟/丢失和撤权边界。Kubernetes/云盘/CSI工作负载与镜像仍是明确协议替身；源 Secret、签名、正常授权与数据库事务使用真实实现。未认证真实CSI安装、OCI provenance、独立云证据、VM状态或资源释放，也未专门强制验证新增CSI final horizon收缩与ACK故障。

首次实际失败来自测试将PROVISIONER误用RESET读取计数；第二次已走通匹配与回滚，但正式37快照与草案38新增工作区列的JSON结构不同。最终保留原正式37完整基线，明确要求旧结构无 `restore_snapshot_name`，仅加入迁移所定义的NULL键后与末尾全行严格相等；没有重取基线或忽略字段。合并编译的一处测试 MutexGuard lint 通过词法作用域修正，未豁免lint。全部失败库、日志和快照保留在汇总收据中。

同一输入常规全目标415通过、223明确ignored、50个测试程序、0失败，新增14个投影测试和5个实际HTTP单位测试均通过；严格Clippy与fmt通过，checkpoint为 `.local/evidence/checkpoints/read-gc-1791530219818960000/record.json`。两次数据库观察分别66/99次采样，无采样错误且当前cgroup事件计数不变，仅为本地观察，不认证生产容量。汇总为 `.local/restore-vendor-gate-candidate-20261009/root-csi-matched-actual-v1-pass.json`，SHA `7049c9f47de18a846fb99e6abe7fa4b83aa91b67dd283008559d18507b396011`。正式迁移仍1..37，恢复与自动化listener/worker继续关闭；供应商Gate、三行原子发布、强宿主校验、身份/RBAC安装、实云/Kata、容量和正式发布继续开发。


## 监控采集链原生告警与故障恢复

双 agent 的原 VM 六指标/13标签及 mTLS 源身份验证保持。新增可信静态目标身份供自动生成的 `up` 使用，避免目标标签覆盖被校验的 exporter 字段；自采仅访问容器 loopback，固定九项原生指标在入 WAL 前去掉 `url`/`remote_name`。写端只保留 VM/up/自身白名单，网络、RBAC、writer 与 API reader 分离保持。WAL 预算包含原始样本、自采64样本上限及每目标五条原生抓取报告；新增16节点/97GiB边界负测拒绝旧 raw-only 模型曾接受的不足预算。

渲染器生成私有 `alerts.rules.yaml`，agent 不执行它。规则按实际 deployment/epoch/节点 UID/boot、严格小于60秒的原始时间判断，以真实当前 shards 而非最大值判断队列；整体采集失联抑制节点洪泛。送达初始零值与真实积压/15分钟滞后/两副本四小时风险分开；最高已送达时间不能证明最旧积压年龄或剩余无损窗口。不可恢复远写失败、WAL写失败和恢复损坏用新鲜的本进程累计正计数捕获首样本前故障；清零可清除告警，进程历史不充当正在发生的故障或持久事故账本。独立审阅发现的单节点 warning 洪泛及首次观测前远写失败漏报已修正并加入用例。

固定3.13.4镜像实测九项名称、类型和标签；该镜像没有 `samples_dropped_total`。746文件不可变输入 `1d343b7d37d53dcfe07105db507347ca7075b2a97f0719402dcb4d9cee4b82a5` 的完整 `deploy/observability/check.sh` 通过：12项测试、14对象官方固定schema、真实镜像配置/TLS验证、无网络启动与WAL跨重启、38个原生promtool场景、两个真实agent与真实接收端的mTLS/BasicAuth/503重试。节点503期间四条可信up为0、两条自采up仍1，最后真实VM值保持4096而非伪造零，恢复后沿原身份送达；九项自身指标各有a/b副本且guest同名伪造被丢弃。故障恢复共享原35秒截止，没有重新计时。运行42.56秒、源前后相同、退出0；完整日志SHA `088c6b80a547bc46700b64a0984ce8171c612a3bfbc8c995e7d8dbda7441fbdf`，收据 `.local/observability-alerts-20261009/final-2/record.json`。

首次原生回放因只读 `/tmp` 无法创建测试TSDB失败，保留 `.local/observability-alerts-20261009/rules-1.log`；只给无网络测试容器增加128MiB临时内存盘，生产配置不受影响。修复后原34场景通过，随后追加首样本远写失败及实际清零至36场景，再加入无stale标记的抓取/自身指标恰好60秒边界共38场景；两次同输入完整检查通过，原失败不改写。本次没有修改 Rust、数据库迁移或生产 API，验证限定于实际变化；后端规则加载、通知路由/送达、平台卷剩余空间与OOM告警、Managed Prometheus/CSI/Kata实云和生产容量仍待验收。随后只更新三份说明。


## 事件控制台交付检查点

2026-10-09，控制台通过同源 cookie GET 接入既有正式事件 API，必须持有项目 `events:read`；能力标志不能替代权限。显式开启后先收 checkpoint，再显示最多50条去重元数据。10秒连接头、45秒单次读进展与300秒总预算，停止保留内存游标，续读必须显式发送原 `Last-Event-ID`；无自动连接、重试、latest重置或管理写入。分页 Remote 与提示独立，跨主体/项目/实例/记录类型、退出或权限拒绝清空，400/409/410须显式重建基线。详见[控制台交付](console.md#实时事件提示)与[事件合同](event-stream.md#控制台实时提示)。

本轮47项控制台单测、61项SDK测试及5项Chrome HTTP合同通过；mock合同不认证真实PG/auth/签名游标。750文件不可变源 `682dc562cbdd5289be6a31870dc0ae9f7a6dabe9caaaa5fd39e16b5516fef2b2` 下，真实 Chrome/Keycloak/BFF/API/PostgreSQL/正常 worker 完整链1/1通过（测试运行18.65秒，含编译命令158.711秒），记录 `.local/evidence/console-events/1791545305718527000/record.json`。真实 CSRF 诊断受理产生事件，停止保留原游标，正常 worker 完成后按原 Last-Event-ID 补读；真实 events:read 撤销清空提示，恢复授权不会自动连接，只有显式重建建立最新基线。事件位置/审计唯一，完整实例/工作区/活动执行事实不变，原账户/诊断/停止撤权链保留。

从正式 stage_context 的22文件最小上下文构建当前 arm64 候选镜像 `sha256:30d822081570ca071b098918ce9af23a0e0d3c516979c74f23e458d2ff659a74`，非root/只读、TLS/CA/SAN/SNI正负检查及原生Nginx在上游未结束前送达checkpoint、显式释放后送达后续事件均通过；记录 `.local/events-console-20261009/native-final.json`。该原生代理测试采用明确 TLS 上游夹具，与上述真实 BFF/API 事件链分别取证，不证明两者组合后的生产PKI或云入口。

首轮实际链因新增验收SELECT多一个右括号失败；仅删除这一字符后重跑，生产代码、断言及期限保持，失败与差异收据保留。首轮离线镜像构建因缺npm缓存/DNS失败；相同上下文按原锁文件联网安装后构建通过，原失败保留。 汇总 `.local/events-console-20261009/final.json` 分别绑定组件、实际链、原生镜像和只读审阅证据，不合并为整产品验收。G3-04/G3-10仍开发中：webhook/通知、生产身份/TLS、云入口慢消费者、实云Kata/CSI、HA/容量与统一签名发布安全门尚未完成。


## 正式自动化 API 与独立 worker 检查点

当前正常迁移是 1..37 加 39，0038 永久保留未发布，未来恢复须使用新的更高版本；没有伪造账本、占位迁移或依赖私有恢复 DDL。`sandboxd --role migrate` 安装 API grants，并在 DBA 已提供独立 LOGIN 时安装 coordinator grants。API 在监听前验证完整 embedded checksum/schema/role，八条正常管理路由的能力标志不以 worker 是否运行作为真值；只新增 `automations:read/write`，未发布恢复动作仍不可委派。策略使用创建者当前权限和有限持久授权，不保存其 JWT。

复现使用正常 `scripts/test-automation.py`（CI 包装见 `tests/fixtures/automation/action.yml`），需锁定 Rust/Node 工具链、Docker、Python 与 OpenSSL。runner 创建自有全新 loopback PostgreSQL、随机独立 SCRAM LOGIN 与一次性 CA/IP-SAN 证书，真实 `sandboxd --role migrate` 后先运行原18项持久受理/故障/签名 HTTP/Node SDK，再运行独立实际 worker 进程测试；不能选择既有库或复用生产凭据。可传入同一次正常构建的 lib/process/migrate/worker 四制品以避免重复编译，runner 绑定源码和制品前后 SHA。详见[自动化合同](automation-development.md)和[部署输入](../deploy/automation/README.md)。

751文件不可变源 `00e07e85dd815dc330061fcccbdeff6981c849cb9181b463a63a484e656bb1e5` 的最终正式验收18/18（50.22秒）与 process1/1（2.14秒）通过，runner总63.077秒。后者包含实际 check、持有自有端口的启动错误、相同 fixture Pod UID 的两次 ready/SIGTERM，四个完整进程 UUID 均不同；独立同 LOGIN 的真实 PG 观察核 TLS ssl=true 与退出后 PID/backend_start 缺席。38条实际迁移 SHA384 与正式1..37+39逐项一致、无38，child与自有container清理均确认。证据 `.local/automation-production-20261009/actual-3-record.json`、`actual-3/evidence.json` 和 `validation-final.json`；相同751文件源随后普通全目标52个程序、416通过、0失败、224明确ignored，source SHA/mode全不变；224属于外部前置专项，不能计为本轮验收通过。记录 `rust-all-targets-final-record.json`，日志SHA `d97729cc6d6e458c0ca1e07683232b6942de805dc49b8b0a7d9b151da0a9b180`。

原 source `e385b59f8408975d946155ed3abb1af1d0ac59d7d9c94a98f8bda11cced3e29d` 在5项完成后因旧草案测试等待未取消的正常 daemon 被中断（130/336.551秒）；source `b2ccaff32e88a714366041fb62870a500110b33f3cf65d7a2f8103639afd8141` 为17通过、1 HTTP失败（101/54.722秒），未执行进程 suite。仅替换正式 schema 成功检查、补原5秒 fixture join 超时 abort+await，及移除 API/OAS 两个未发布恢复 action；原故障/幂等/元数据断言、角色和期限未放宽。两失败及全部原快照由 `failure-summary.json` 保留，不能算作最终源通过。

另 SDK61、发布协议63、renderer4、固定官方资源 schema、API合同5、console build 与严格 Clippy/fmt通过；本次八 ELF 的构建/export/原生库存/OCI/SBOM/scan 闭包是已实现代码，尚未取得当前源码的真实 Linux 八制品构建与统一签名安全门通过。旧七 ELF 冻结候选只能表示原时点历史证据。HTTP OIDC/冷备份关闭观测为明确测试素材，PG TLS用一次性测试CA，库内正常受理不等于实云副作用完成。G3-07仍开发中：政策管理 UI、目标集群 HA/容量、实云和生产签名发布未验收，生产恢复依旧关闭。


## 自动化控制台真实管理验收

验证状态：本地管理链已通过，生产认证仍待完成。正式后端已在 `0b0985e` 检查点接入独立0039，正常迁移仍为1..37加39；0038永久保留未发布，恢复入口保持关闭。本次控制台增量提供七种未来动作 START/STOP/RESTART/DELETE/RENEW/EXECUTE/BACKUP，以及 ONCE、CRON_UTC、EVENT 三种触发方式的有限授权表单、预览和实例 UUID 确认。控制台不运行调度器；能力标志不替代当前授权或 worker/云运行认证。

策略创建先读取当前实例的强 ETag；暂停、恢复、永久撤销使用该策略实际 GET 的 ETag。列表/明细/原运行只读取当前租户、项目、实例或策略的元数据，不依赖 `operations:read`，不展示私有命令、环境或身份映射。404与身份/项目变化清除旧明细、运行和授权草稿；恢复权限后只由显式重新读取恢复同一目标。有限次数、授权到期、UTC规则和危险动作授权仍由正式 API 重新校验。

自动化创建的 journal 仅持久保存原键、ETag、摘要和核对状态，原参数只保留在当前身份/CSRF作用域的内存。UNKNOWN不能换键；重载后须明确重新输入完全相同的原 JSON，摘要匹配只恢复内存，再由原键确认重放。身份、项目、实例或能力撤销清除内存参数；摘要不匹配不发送 HTTP。ACCEPTED仅保留资源查询依据。

根执行器是 `scripts/test-console-browser.py`，需要显式本地 Unix Docker host、绝对 Node24/Chrome/身份 Python 路径，以及受保护的 `.local/restore-test.env`。它复用固定本地开发 PostgreSQL/Keycloak容器，在独立新 `_test` 库运行正常迁移和既有真实浏览器选择器，不删除旧库或读取/打印其他环境秘密；密码只经私有子进程环境注入。执行器先构建当前控制台，绑定所有公开源码字节/模式，要求唯一通过测试、唯一 `VERIFIED real Chrome BFF automations:` 标记，并复查源码未变。浏览器选择器仍为 `bff::live_tests::real_keycloak_chrome_console_bff_and_api_enforce_live_revocation`。

实际管理链已验证未来30分钟的单次 RENEW、1小时有限委派、预算1：正常 UI/CSRF创建后只故意丢弃已提交回执，重载并恢复原参数后原键/body/ETag重放；验证策略/委派/receipt/audit唯一、暂停/恢复/撤销版本、实际缺CSRF和旧ETag拒绝、撤除 `operations:read` 后读取空运行历史、实际撤权清空及明确恢复。父事务核对零运行、全部实例/工作区/活动执行/操作事实不变，保留原账户、诊断、事件、停止与撤权链及原期限。此验收不启动 automation worker，不证明七动作或三触发器已实际执行；它与此前后端18项/四进程证据分别取证。

758文件不可变源 `b18d4ac4ab89205dea2e94882023f43485962585821a8f962744f9b0c35261db` 下，真实 Chrome/Keycloak/BFF/API/PG及原账户、诊断、事件、停止撤权链1/1通过（测试17.91秒，命令18.576秒），记录 `.local/evidence/console-automations/1791554745346766000/record.json`，源码SHA/模式前后不变；59控制台单测、8Chrome HTTP合同、build及严格Clippy/fmt另列。原生arm64候选 `sha256:8348e298b2810ea24c3b5f384b99e3160d68e08a617d8a69feba09422797da86` 从22份直接源码输入及1份stage_context派生的首发清单构建；从上述实际快照重建上下文后，23份构建输入SHA逐项一致；非root/只读、CSP资源及上游TLS/CA/SAN/SNI正负例通过。这是独立传输夹具，未组合认证生产身份/PKI。聚合 `.local/automation-console-20261009/validation-final.json`。首轮真实链因脚本误用403码FORBIDDEN失败（101/106.004秒；测试17.68秒）；仅修为既定PERMISSION_DENIED，生产逻辑、403/412和业务/期限断言保持。4次浏览器失败、构建类型错误和原作者NOT_RUN收据全部保留。能力字段缺失、非法或成功空响应会清除内存载荷与旧选中；临时刷新保留状态但禁止写入。G3-07继续开发中：目标集群 HA、实云动作/执行容量及当前 Linux 八 ELF 的完整构建、扫描和统一签名安全发布门尚未验收。

## 自动化 worker 运行时故障监督与恢复

验证状态：本地正式数据库/实际进程验收通过，G3-07仍开发中。按 `mattpocock-skills:codebase-design` 的深模块/小接口原则，本次复用既有管理受理、父任务监督和数据库池收尾，只增加内部错误分类及共享就绪状态，没有增加调度框架或生产测试入口。正式迁移保持1..37加39，0038永久保留，恢复入口保持关闭。

修复两个生产故障：调度循环曾吞掉永久数据库错误，ready又只能证明角色/配置存在；受理中的权限错误曾被记为业务FAILED。现在永久权限、持久数据解析和程序不变量错误停止调度、取消并join健康服务、await共享数据库池关闭，固定脱敏错误非零退出。受理致命错误保留原prepared intent和租约，不记录FAILED、不finish claim；新进程在原租约自然过期后沿同一请求、键和资源恢复。临时错误降低ready，按原2秒退避与队列实际eligible_at继续；受理错误在可用claim下记录OUTCOME_UNKNOWN并正常finish路由claim。最终safe-mode guard可使claim_live先失效，此时允许保留原DISPATCHING/null并重读，不能据此换键。

SQLSTATE只保存经校验的五字符内部代码，不进入公开Problem。P4090/P4120仅在自动化模块归一为retryable409 AUTOMATION_FENCE_CHANGED，不改变其他API的SQL错误映射。ready在原2秒预算内复用完整checksum/角色/既有最小权限检查，并在探测前后检查停止状态。原3秒锁超时、30秒租约、5秒健康join与其他业务期限保持。正常finish不会保证五秒内重新可用，队列eligible_at可能仍保留原运行租约。

复现使用正常 `scripts/test-automation.py`：一台自有全新Docker PostgreSQL17.11 TLS容器、随机独立SCRAM LOGIN/一次性CA，两个独立库分别由正常 `sandboxd --role migrate` 建库，原18项HTTP/SDK/持久受理与实际worker故障场景互不共享业务状态。实际进程suite总预算240秒容纳各自独立的自然租约恢复；单场景和所有生产期限未扩大。测试只通过正常二进制、公开Database管理入口和受保护owner故障夹具，不调用控制器私有方法，不改队列或租约，不以强杀收尾冒充正常drain。

| 新增实际进程场景 | 已核对的结果 |
| --- | --- |
| 领取函数权限撤销 | 原ready204变503；非零退出后健康端口/同LOGIN精确物理backend缺席，父任务与共享池收尾 |
| 队列锁导致原锁超时 | 进程仍存活/ready503，真实SQL起始时间证明超时加退避；释放锁后同完整进程UUID恢复204 |
| 受理时撤销execution INSERT | 原DISPATCHING/请求/预算保持，零已提交op/execution/idempotency/quota；恢复原grant后新进程等待原租约自然到期，原不可变意图只受理一次 |
| EXECUTIONS配额锁超时 | 真实受理阻塞/回滚，OUTCOME_UNKNOWN与正常finish；原actual eligible_at到期后同进程唯一受理 |
| 最终提交前开启safe mode | 真实延迟COMMIT guard P4090与固定归一错误日志；零已提交受理事实、正常finish；恢复safe mode后同进程沿原意图唯一受理 |

760文件不可变源 `92bda2d8de4eb9f48c2ad18873e0e965c23373062adf90f6b2a31d76cc75805f` 下，原18项49.05秒全部通过；process1/1共116.79秒，保留原check/占用端口/两次ready-SIGTERM四场景并新增上述五类，共启动10个实际worker。每个进程归属单独核对，原四UUID互异、接管者UUID不同；不声称十UUID全局唯一的额外断言。runner177.429秒，两个实际ledger各38条SHA384逐项匹配冻结SQL1..37+39、无38，双cleanup确认、cleanup_errors为空。相同源整仓52个测试程序/417通过/0失败/224明确ignored（173.861秒），严格全目标Clippy（42.366秒）、fmt、SDK build通过。224属于外部前置专项，未执行也不计为通过。

证据目录 `.local/automation-supervision-20261010/1791598764490565000`。`record.json` SHA256为 `373c34225695f27fa30ebc8c9d3e3365e9ab23b74d95360546f8c5ecc327681b`；`actual/evidence.json` SHA256为 `b3b48070cf52eee18b1da95f446902c2fd34700f21b399bb40cb2ccd4074228f`。记录绑定全部760个源文件字节/模式、四个正常编译制品和每项日志，验证期间源未变；七文件实现差异 `implementation.diff` SHA256为 `e002ab8f6a0788b0f5d6e7f69010da334ca8d90421324586e042c90f39f31dc5`。之后仅补四份交付文档，最终快照单独记录。只读独立审阅 `.local/next-phase-20261010/identity/final-review.json` 为PASS_WITH_SCOPED_CLAIMS、确证阻塞0。

此处“唯一受理”核对固定EXECUTE的数据库操作、执行、原key、租户/项目配额和held活动，不证明guest实际执行；SIGTERM不释放已受理执行slot。RUNNING/运行readiness来自明确owner夹具，未认证实云Kata/CSI。P4120虽同分支实现/审阅，但没有另做真实进程注入；持久载荷损坏没有绕过约束故意注入。当前Linux八ELF构建/扫描/统一签名发布、生产身份/PKI组合、目标集群HA/容量及各实云动作仍待验收，本地通过不代表整产品上线完成。

## 真实自动化异常通知 BFF 验收

使用 `scripts/test-console-browser.py`，不再读取或扩展旧的九角色 restore 环境。启动本地开发依赖后，runner 只读取固定本地 Keycloak 容器的管理员凭据，用新临时 realm 登录；新建 loopback-only TLS PostgreSQL 和十个独立最小权限 LOGIN。当前执行器通过正常迁移安装 1..37、39..43 全部 42 条账本，并保持旧迁移逐项 checksum 校验；此前 41 条账本的已通过收据仍属于原源码检查点。测试不修改原开发数据库、卷、口令或身份 realm 配置。

执行前 `df -h .`，空间低于50 GB先评估本任务可重建产物。沿用仓库缓存，普通 Rust 验收环境为 `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`，不改发布配置。Node必须是已安装的绝对可执行路径，身份Python需具备锁文件安装的 jsonschema/yaml；Chrome可用本机版本或CI安装的Playwright版本。下面的Chrome路径适用于本机macOS；证据目录必须全新。

```sh
export RESTORE_TEST_DOCKER_HOST="$(docker context inspect --format '{{.Endpoints.docker.Host}}')"
CARGO_TARGET_DIR="$PWD/target/review-low-debug" \
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
python3 scripts/test-console-browser.py \
  --node "$(command -v node)" \
  --chrome "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --identity-python "$PWD/.local/cluster-venv/bin/python" \
  --evidence-dir "$PWD/.local/evidence/console-notifications/manual-new-attempt"
```

runner 捕获公开源码后强制由当前源执行 locked/offline Cargo build 和 lib no-run；可选 `--artifacts` 仅交叉核对路径，不能跳过编译确认。控制台构建后记录实际 dist全部文件SHA/mode，最后复核源码、Rust/console制品、当前 42 条迁移 checksum 和0600完整事实报告，缺失标记或清理未确认均失败。数据库TLS采用任务专属测试CA；Chrome本地公开fixture证书忽略错误、IdP回环transport不代表生产PKI验收。

当前普通浏览器执行器还要求九个真实界面检查点的私有 PNG 与清单。`browser-screenshots/` 必须为当前用户持有的 canonical 0700 目录，PNG/清单为0600；wrapper 独立核对固定文件集合、顺序、PNG格式包络、字节数和SHA256，并将安全相对路径写入 `record.json` 的 `screenshot_evidence`。缺图、清单不匹配或权限不符均不能得到PASS。这些图来自真实自动Chrome链，不等同于用户已完成可见手工交互，也不证明VM或云效果。独立 `--manual-demo` 路径不要求图，继续仅返回演示停止状态。

原未来自动化零运行矩阵之后，正常域入口以真实浏览器验签身份创建策略和手工续期，实际专用coordinator产生FAILED来源；真实UI读取/ACK、提交后丢回执、UNKNOWN重载与读写撤权、原key/{}旧ETag恢复重放，最后正常STOP及撤权全部验证。源设置两步不是UI创建，不直接写运行状态/通知/事件。完整事实和回执在缓存外保存，原开发数据保留；结束确认本任务容器和进程组清理。详见[本轮验收](../research/automation-notification-bff-20261011.md)。
