# 可信运行时开发检查点（2026-10-03）

此记录描述 ea9110e 之后的可信运行时、机器身份与基础设施开发增量。它不替代目标云的上线验收，也不把旧镜像的测试结果套用到新代码。

## 已接通的代码

- 专用 termination 数据库角色和持久队列，启动许可与续期 ACK、认证有效期、VM 终止挑战和清理凭据；未获得完整证据时保留配额、工作区与未知执行状态。
- 宿主 Linux nodeguard：受控 CRI 代理、SQLite FULL 同步日志、每个 Pod UID 至多一次启动、永久关闭记录、pidfd/cgroup/mount 终止观察、独立 mTLS 身份和冷启动安装门禁。
- 受控节点登记 CLI：Terraform 身份、集群设置、实际 Kubernetes Node、实际 mTLS 节点身份与认证报告交叉验证；原始登记记录不可更改，认证续期追加记录，旧云节点身份不得自动重用。
- 阿里云 STS/ACS3 云隔离客户端：核验账号与角色、短期令牌刷新、共享限速、有界只读重试、StopInstance 只发送一次。Stopped 仅是观察结果，尚未接入完整云隔离完成证明。
- 机器客户端租户内登记、查询、停用/启用、权限交集重激活，API/OpenAPI/TypeScript SDK 同步。
- 固定版本的集群和 nodeguard 安装器、阿里云私网 9444 安全组、迁移维护连接与运行角色隔离检查、Linux amd64 宿主二进制 CI 导出流程。

## 已实际执行的验证

| 范围 | 结果和边界 |
| --- | --- |
| 本机 Rust | `cargo test --locked --offline --all-targets`：131 passed，89 ignored，0 failed；30个测试程序。环境专项没有计为常规通过 |
| Rust 静态检查 | `cargo clippy --locked --offline --all-targets -- -D warnings` 通过 |
| 0017/0018 后真实 PostgreSQL | 终止账本12、准入4、控制事务20、TTL/闲置7、worker 3、gateway 6、节点登记/续期1，共53项；测试执行时隔离数据库窗口 |
| 其他数据库专项 | 运行角色成员/SET ROLE 边界1项、机器身份5项已通过；其他阶段测试见开发记录，不与重跑数字重复相加 |
| 节点登记完整专项 | 4项常规与1项真实PG测试通过；包含本地真实mTLS与Kubernetes协议替身，不是实云登记 |
| 云隔离客户端 | 9项协议/签名/错误与重试专项通过，计入131项常规；无真实云停机调用 |
| Linux nodeguard | 12项 Linux 专项与二进制构建通过；未在真实Kata/KVM节点认证 |
| SDK | 生成类型与24项TypeScript测试通过 |
| 基础设施 | 官方 Terraform provider schema validate、11项mock plan通过；最后新增只读OIDC provider ARN输出后再次fmt/validate通过 |
| 集群安装器 | 7项离线测试、24份原生/CRD资源官方schema、7个Ansible入口语法检查通过 |
| nodeguard 安装器 | 7项离线测试、Ansible安装语法、官方CRI派生代码hash检查通过；未执行SSH安装 |
| 迁移入口 | 单条owner维护连接重放迁移与角色授权成功；维护statement timeout 5分钟，运行时限时未放宽 |
| 0019 历史升级补正 | 独立临时数据库实际演练v2→v17→v18→v19，复现并修复FORCE RLS导致的历史队列回填遗漏；共享开发测试库再验证调度回归，旧迁移未修改 |

## 尚未完成的生产依赖

云整机隔离持久控制器、不可复活证据与云盘解绑/删除闭环仍在开发，安装器继续禁止开启承载入口。生产身份和工作负载 JWKS 发布包单独开发。真实三节点 Kata/KVM、首包网络策略、CSI 单写者、独立备份恢复、发布签名/SBOM、完整功能与72小时容量验收均未完成。

本机 PostgreSQL 与 Keycloak 只用于开发验证；未对用户云账号执行 apply、StopInstance、发布或生产部署。`.local` 凭据、Terraform state/变量/plan 和构建缓存均不进入提交。测试私钥只位于明确注明用途的 `tests/fixtures/nodeguard`。

## 提交后的镜像实测

本检查点提交为 `0d29961`。从该提交的 Git archive 构建，未包含后续开发中的身份包和云盘观察代码。以下为本机 linux/arm64 未签名镜像：

| 产物 | OCI index digest | 本机验证 |
| --- | --- | --- |
| sandbox-platform:0d29961 | sha256:35ac33808094c8d81a3b3cbc5f679aa67de0e77da84372d44dcab7f3887492a8 | 非root、只读、禁网络、drop ALL 下版本及admission帮助成功 |
| sandbox-runner:0d29961 | sha256:8c18f8135e292cbe3661e655fa24adf08beffbedacc053dc6600914bc068c74d | 同样约束下health返回protocol 1/status ok |

同一不可变提交 `0d29961` 的宿主 Linux amd64 二进制已构建成功：ELF64/x86_64，19,156,760字节，SHA256 `78501890d1bbb5bc8a984e33306bb126eadc11eddd712fdb232fe7388d68d95f`。在本机 Linux amd64 容器中以非root、只读、禁网络、drop ALL 运行 `--help` 成功。该产物未签名、未发布，未经过真实Kata/KVM宿主认证；不能把二进制可执行视为节点可承载证明。
