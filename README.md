# KnotSandbox

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A Rust control plane for multi-tenant sandboxes, with lifecycle management, OIDC authentication, scoped APIs and durable audit records.

企业多租户沙箱产品，提供独立 Keycloak 或外部 OIDC 接入。按[开发工作表](research/rust-sandbox-development-workbreakdown.md)持续实现，架构约束见[生产开发方案](research/rust-sandbox-production-development.md)。

面向 AI Agent、自动化任务和其他微服务提供独立的沙箱控制与治理能力。计算实例与持久工作区分开管理，调用方通过 API 和 SDK 接入，身份服务可独立部署或对接已有 OIDC。

**当前处于开发阶段，未完成生产上线验收。** 控制事务、身份授权、生命周期、执行/文件网关、监控、诊断、备份、自动化与浏览器会话已接入，控制台已有实际构建；恢复、完整安装与真实云验收继续开发。准确状态见[工作包与证据](docs/implementation-status.md)。

当前代码包含：

- Rust/Axum API，PostgreSQL 持久状态、租户 RLS、项目动作授权。
- RS256 JWT/JWKS 验证，Keycloak 与符合支持契约的外部 OAuth access token。
- 创建、查询、启停、重启、删除计算与续租受理；幂等键、ETag、配额、审计和事件同事务提交。
- 持久操作领取、租约续期、失效 worker 写入隔离。
- 真实 Kubernetes worker：持久阶段、资源 UID 恢复、到期扫描；停止等待可信 VM 终止证明。
- 命令执行受理/读取/强取消、独占槽与唯一派发证据；Linux runner 的受限执行协议。
- 受控 Kata Pod、持久 PVC、Cilium 策略生成与严格资源归属校验。
- 独立 mTLS Kubernetes 准入服务与分离的数据库角色。
- OpenAPI 生成的 TypeScript SDK，保留原幂等键、ETag、令牌刷新和操作/执行等待，单独返回结果未知。
- [执行输出分页](docs/execution-output.md)：独立读取权限与云凭据、逐块校验、最终清单核验和读取后的再次授权。
- [单文件传输](docs/file-transfers.md)：独立文件权限与配额、分块完整性、单次派发；未知写入不重发、不提前释放存储额度。
- [浏览器会话](docs/browser-bff.md)和[控制台](docs/console.md)：服务端OIDC Code+PKCE、密文token、cookie/CSRF、跨标签页原请求防重；浏览器不持有OAuth凭据。
- [存储凭据进程](docs/storage-credentials.md)：独立短期STS身份核验、原子轮换与原生sidecar组合。
- 项目操作/事件/审计分页、跨副本签名游标和能力发现；公共错误统一脱敏。
- 实例详情聚合工作区、模板 digest、租约与启动证据；未采样的实时健康显示未知。
- [运行指标](docs/runtime-metrics.md)：独立 mTLS 宿主采集、双副本持久 WAL、按租户与 launch 授权的固定查询，缺失/陈旧数据不填零。
- [未获启动许可的永久关闭](docs/never-authorized-closure.md)：创建未完成时安全删除计算、清理迟到 Pod，保留持久工作区。
- 运维 bootstrap CLI、数据库迁移、开发依赖与 CI。

HTTP `202` 表示操作已受理，不能据此判断沙箱可执行。停止计算保留工作区；任何未知终止状态都不能被当成卷可安全复用的证据。

## 本地开发

```bash
git clone https://github.com/StateKnot/knotsandbox.git
cd knotsandbox
```

需要 Rust 1.98.1 与 Docker。首次运行会生成仅用于开发的随机凭据，写入被 Git 忽略且权限为 `0600` 的 `.local/dev.env`。

```bash
scripts/dev-dependencies.sh up
set -a
source .local/dev.env
set +a
SANDBOX_DATABASE_URL="$MIGRATION_DATABASE_URL" cargo run --locked --bin sandboxd -- --role migrate
scripts/dev-dependencies.sh token
```

按[bootstrap 说明](docs/bootstrap.md)登记租户、项目及初始主体，然后启动 API：

```bash
cargo run --locked --bin sandboxd -- --role api
```

数据库 owner 凭据只供迁移和 bootstrap；API、worker、gateway 和 admission 分别使用独立的最小权限角色。远端数据库强制 `sslmode=verify-full`。开发明文 OIDC 仅允许字面回环 IP，API 同时必须绑定回环地址。API 分页签名密钥由 `SANDBOX_CURSOR_SIGNING_KEY_FILE` 提供，开发脚本会生成共享密钥文件。

详细依赖操作见[开发说明](docs/development.md)。生产配置不能使用 Compose 的 `start-dev`、回环 HTTP 开关或开发凭据。

## 验证

常规回归需要Python 3.12及锁定的安装器依赖，并在子进程中移除开发用的`SANDBOX_*`配置。真实数据库/OIDC专项再单独加载开发环境；不能用开发HTTP开关验证生产默认值。

```bash
python3 -m venv .local/cluster-venv
.local/cluster-venv/bin/python -m pip install --require-hashes -r deploy/cluster/requirements.lock.txt
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
python3 - <<'PY'
import os, subprocess
environment = {name: value for name, value in os.environ.items() if not name.startswith('SANDBOX_')}
environment['CARGO_INCREMENTAL'] = '0'
subprocess.run(['cargo', 'test', '--locked', '--all-targets'], env=environment, check=True)
PY
# 必须先启动专用开发依赖并导出 .local/dev.env；缺失环境会失败，不会跳过。
cargo test --locked --test database -- --ignored
cargo test --locked --test bootstrap -- --ignored
cargo test --locked --test timers -- --ignored
cargo test --locked --test executions -- --ignored
cargo test --locked --test worker -- --ignored
npm --prefix sdk/typescript ci --ignore-scripts --no-fund --no-audit
npm --prefix sdk/typescript run build
cargo test --locked --test keycloak -- --ignored
```

测试覆盖真实 PostgreSQL 的 RLS、并发幂等、配额、生命周期和操作租约。纯 Kubernetes 对象测试只验证生成与校验逻辑，不替代实际 KVM、Cilium、CSI 和 fencing 测试。

## 调用契约

[OpenAPI](openapi/sandbox-api.yaml)仅列出已接入的 API。业务请求携带 OAuth access token 和 `X-Tenant-ID`；后者只是租户选择器，访问权限仍由产品数据库核验。副作用请求强制 `Idempotency-Key`，修改已有实例还要求 `If-Match`。

[TypeScript SDK](sdk/typescript/README.md)提供生成类型和有界重试。保存调用方业务任务的幂等键和返回的操作ID；等待超时不会取消或重新提交远程任务。[执行网关](docs/gateway-runtime.md)已接通持久派发、v5 exec、OSS 分块和结果事务，本地真实 PostgreSQL/HTTP/WebSocket 整合已覆盖正常、截断、断流和存储失败。Kata 集群、真实 OSS 与可信 VM 终止仍需目标环境验收；当前不能据此承诺已经具备生产发布条件。

外部身份服务需要采用支持的 access token profile：RFC 9068 的 `at+jwt`，或 Keycloak 的 `Bearer` claims；ID token、opaque token 和无明确访问令牌类型的普通 JWT 不接受。默认访问令牌寿命不超过 300 秒，产品主体和权限每次操作重新检查。

备份安装 owner 操作见 [备份配置管理](docs/backup-profile-administration.md)；只读实例报告见 [诊断合同](docs/diagnostics.md)。

## License

项目自研代码、文档和配置以 [MIT License](LICENSE) 开源。仓库内的第三方源码、生成代码和 schema 保留各自原协议，详见 [Third-party notices](THIRD_PARTY_NOTICES.md)。公开测试签名密钥仅供 fixture 使用，不得用于部署。
