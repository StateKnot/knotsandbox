# 2026-10-03 开发检查点

此检查点保存已经实现并验证的开发代码，不是生产发布。当前版本仍为 0.1.0，不能以本文件替代 G1、G4、G5 实云、安全、容量、恢复和上线验收。

验证环境为 macOS arm64、Rust 1.98.1、Node.js 24.19.0。本地隔离 PostgreSQL 17.11 使用独立 migration/API/worker/gateway/admission 角色；机器身份联调另外使用精确固定镜像的 PostgreSQL 17.11-bookworm 和 Keycloak 26.8.0 项目。没有使用云账号或 Kubernetes context。

| 验证 | 结果与范围 |
|---|---|
| Rust 常规测试 | `cargo test --locked --offline --all-targets`：100 项通过。依赖真实 PostgreSQL 的测试明确标记 ignored，由下面的必跑集成命令单独执行。 |
| 核心真实 PostgreSQL | database / lifecycle_authorization / bootstrap / timers / executions / worker / review_regressions / migrations / admission / history / capabilities / http 共 57 项通过；包含 0002→0012 历史升级、租户本地停用后的旧回执/派发拒绝。 |
| 项目权限管理 | grants 集成测试 4 项通过；另 1 项参数校验计入常规测试。 |
| 执行网关及输出 | gateway_ledger 集成测试 6 项通过。真实 PostgreSQL、真实本地 HTTP/WebSocket，以及 OSS 原生签名的传输替身覆盖正常/截断/断流/存储失败、仅读取已提交块、篡改/缺清单、跨租户和读取中撤权。 |
| 机器身份与真实 HTTP SDK | keycloak 集成测试 1 项通过，独立 Node 进程调用真实 HTTP API，包含已提交响应丢失后的原键重试、强 ETag、撤权与等待超时。 |
| TypeScript SDK | OpenAPI 20 个已实现路径生成类型，24 项行为测试通过；包括结果未知不重跑，以及非重试型输出完整性错误。 |
| 云基础设施 | Terraform 1.14.7 / aliyun provider 1.293.0 官方 schema 校验，主模块 9 项 + state bootstrap 2 项 mock plan 通过。没有执行 apply。 |
| 静态检查 | Rust formatting、全 targets clippy `-D warnings`、SDK 类型编译和 staged whitespace 检查通过。 |

Git 检查点排除了 `.local` 中的凭据、构建产物和未接入的机器客户端开发草稿。测试私钥仅位于明确标注的 tests/fixtures 中。

当前关键缺口是可信 VM 终止证明、停止/重启后半程、文件/终端/SSE、机器账户/BFF、监控/诊断/自动化/备份完整产品能力、生产安装与交付包。停止尚未取得可信证据时继续保留工作区、活动槽和配额；不会因 Pod 消失、guest 退出或云请求受理而假报停止。集群安装、实际 OSS/RAM/KMS、节点 fencing、恢复与 72 小时容量证据仍未具备。

## Linux 镜像本机验证

从不可变提交 `ea9110e` 的 Git archive 构建，不包含本机凭据或正在开发的未提交代码。两个产物均为 linux/arm64、本机未签名构建，不代表生产认证。

| 产物 | OCI index digest | 验证 |
| --- | --- | --- |
| sandbox-platform:ea9110e | sha256:977a6baf10a40ee44f1ca22149eebec776bf3cf764999396fda2547efa70ff9e | 非 root、只读根、禁网络、drop ALL capability 下 sandboxd --version 与 admission --help 成功 |
| sandbox-runner:ea9110e | sha256:f3bb4cd154723141a6354a334ee9da88718f471e3fbc2ee71bfd770eee886aea | 同样限制下 runner health 返回 protocol 1/status ok |

精确 PostgreSQL 17.11-bookworm / Keycloak 26.8.0 组合还在独立 Compose 项目中通过真实机器令牌、Node SDK 到 API 及数据库撤权联调。该项目容器和网络已停止，隔离测试卷保留。
