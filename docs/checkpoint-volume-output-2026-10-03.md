# 工作区销毁与输出流检查点

这是 `cb52ba2` 之后的开发检查点，包含迁移 0023–0025、独立工作区销毁控制器、快照保留、输出 SSE/SDK、备份基础包与发布验证流水线。它没有通过真实云上线认证，也没有签名发布。

## 已完成验证

| 范围 | 本轮证据 |
|---|---|
| Rust 常规回归 | 32 个测试程序，173 通过、0 失败、122 环境专项明确 ignored；本地日志 `.local/test-all-volume-output-20261003.log` |
| Rust 质量检查 | `cargo fmt --all -- --check` 和 `cargo clippy --locked --all-targets -- -D warnings` |
| 云协议 | 30 项本地真实 HTTP 测试；ACS3/STS 身份、精确删盘、自动快照保留、属性读回、单次派发与未知结果 |
| 卷销毁 | 10 项真实 PostgreSQL 专项；mTLS 宿主替身、STS/ECS/Kubernetes 替身、hold/保留期/撤权、UID 漂移、崩溃恢复、事件锁等待超过租约、管理员定向恢复 |
| 数据库迁移与角色 | 历史 v2 到 0025 独立临时库升级通过；七个已授予运行身份的 21 对 membership 隔离通过；未来备份身份仅预置 LOGIN，未授权产品功能 |
| 输出流 | 5 项 PG/HTTP 专项，含实际 Node SDK→TCP Rust API→PostgreSQL 的段续读、完成清单和撤权；另 3 项游标/结束语义普通测试 |
| 既有执行和事件回归 | 网关 6 项真实 PG 测试；项目事件流 7 项真实 PG 测试，包含 Node/TCP 联调 |
| TypeScript | 45 项 SDK 测试通过，OpenAPI 重新生成与构建通过 |
| 部署契约 | 卷控制器 7 个官方 Kubernetes schema；Terraform 官方 provider validate 与 9 项主模块 mock plan |
| 备份基础包 | 13 项 Python 测试、12 个官方 schema；真实本地 Restic/rclone 在删除源数据和完整可变仓库之后从独立副本恢复，坏密钥/损坏包拒绝 |
| 宿主备份门禁 | Linux 原样 nodeguard 模块 16 项测试及实际二进制 cargo check；整个 Linux lib 测试链接因本地 Docker 8 GiB 内存不足被终止，未计为通过 |

## 行为与限制

计算 DELETE 保留工作区。独立 `workspaces:delete`、确认 UUID、ETag 和幂等键才可接受数据销毁。所有历史写入者必须已有可信终止与清理；先修正自动快照随盘删除属性并读回确认，再单次派发 DeleteDisk。后续云 absence、精确 PVC/PV 清理和配额释放分别持久化，拒绝拿 ACK 或 Pod 消失代替证据。

输出流读取已提交的不可变段，游标绑定主体、执行 attempt 和恢复纪元。读取前后重新鉴权，COMPLETE/TRUNCATED 要求清单核验；流结束不表示整个 VM 终止。真实负载均衡器的慢消费者、跨副本和容量验证待目标环境。

从未获得 launch permit 的 CREATE 失败尚需专用永久关闭协议；当前保守阻塞。备份 Job 基础包与 nodeguard purpose 门禁已实现，完整备份受理/控制/恢复账本仍在开发，不能启用产品备份能力。未完成的新控制器不纳入已验证路径。

发布过程必须经过完整依赖 SBOM、当前漏洞数据库、镜像验证、签名和独立来源约束。服务基础镜像已更新到 Distroless Debian 13，runner 更新到 Debian 13；本地实际 Linux/amd64 镜像通过非 root、只读、无网络的服务/runner 启动与命令测试。剩余高危依赖仍阻断发布，没有添加自动豁免或推送镜像。

没有执行云 apply、节点部署、真实 KVM/CSI/OSS 数据销毁或 72 小时容量验收。各协议说明中的环境门槛仍须逐项完成。
