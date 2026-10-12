# 受控节点登记

`sandbox-admin enroll-node` 把经过独立审阅的云节点清单与当前 Kubernetes、宿主 mTLS 身份绑定，并原子写入节点库存和不可修改的安装审计。它不会清除 `unverified` taint，不创建 RuntimeClass，不把报告中的 PASS 当成系统自行测出的结论。当前仍缺真实云、KVM、CSI 和持续 fencing 验收，不能据此开启企业非可信工作负载。

## 输入与信任来源

1. `deploy/nodeguard` 从实际宿主导出的 `enrollment.json`：固定 NodeUID、bootID、cluster epoch、运行时配置摘要、私有 IP、云账号/地域/实例和证书对应的端口 9444。
2. 管理员执行 `terraform output -json` 得到的非敏感输出。必须包含 `deployment_identity`（provider 观察到的账户、region、deployment、environment）与 `node_inventory`；不接受 Terraform state 文件。文件不是云 API 的实时证明；部署者负责保护来源，登记工具负责交叉核验。
3. 独立审阅的集群 settings，在现有 `deployment`、`region`、`oidc_provider_arn`（独立云账号锚点）基础上增加 `cluster_epoch`、`certification_id`、`certification_report_sha256`、`nodeguard_binary_sha256`、`versions_lock_sha256`。后者必须等于此版本内置的 `deploy/cluster/versions.lock.json` 精确字节摘要。
4. 独立审阅的认证报告，其精确字节摘要必须与 settings 一致。顶层字段为 `protocol`（1）、`certification_id`、`cluster_epoch`、`versions_lock_sha256`、`nodeguard_binary_sha256`、`reviewed_at`、`expires_at`、`nodes`、`checks`。每个节点为 `{node: NodeBinding, cloud_instance_id, private_ip}`，必须恰好覆盖 Terraform Kata 池；不允许重复节点、地址或云实例。报告当前未过期，有效窗口不超过 30 天。

`checks` 必须逐项包含 `{status: "PASS", evidence_sha256: "<64位小写SHA256>"}`：

- `kata_process_coverage`
- `cri_start_fencing`
- `crash_recovery_unknown`
- `workspace_single_writer`
- `csi_late_publish_unmount`
- `first_packet_network_isolation`
- `node_boot_reenrollment`
- `cloud_fence_prevents_revival`
- `cloud_volume_detach_safety`

哈希只绑定独立审阅过的报告和原始证据，不能证明测试已经发生；报告产生、原始证据留存和批准者职责属于生产验收流程。当前代码不会生成可用于绕过实测的 PASS 报告。

## 执行

先检查所有输入，无网络或数据库写入：

```sh
sandbox-admin enroll-node \
  --file /secure/artifacts/node/enrollment.json \
  --terraform-output /secure/reviewed/terraform-output.json \
  --cluster-settings /secure/reviewed/settings.json \
  --certification-report /secure/reviewed/certification.json \
  --validate-only
```

使用安装 owner 数据库连接、可信 kubeconfig、专用宿主服务端 CA 与专用控制器客户端证书执行相同命令，将 `--validate-only` 改为 `--apply`。连接从 `SANDBOX_ADMIN_DATABASE_URL` 读取；证书路径使用 `SANDBOX_NODEGUARD_SERVER_CA_FILE` 和 `SANDBOX_NODEGUARD_CLIENT_IDENTITY_FILE` 或对应命令行选项。客户端身份文件须为当前用户或root所有的0400/0600；Kubernetes投射Secret另允许root所有、精确匹配进程非零primary GID的0440。补充组、0640或公开可读模式不构成授权。两种文件均只接受绝对路径、打开后核验的普通文件、最多64KiB且非空；允许投射链接，CA禁止group/other写入，FIFO等特殊文件非阻塞拒绝。不要把凭据写入报告、命令行或Git。

真实登记每次重新读取 Node → 调用该 NodeUID 对应 mTLS `/v1/node` → 再读取 Node。前后均检查 UID、bootID、amd64/Linux、私有地址、运行时摘要、Kata 池、Ready 以及 `untrusted`/`unverified` taints。禁止公共 endpoint、代理、重定向和关闭 TLS 验证。观察过期或数据库 epoch 不匹配会整体失败。

成功回执含 `enrollment_id`、`runtime_node_id`、完整节点/云绑定、认证与输入摘要、时间和 `changed`。相同输入重复执行返回原始回执并令 `changed=false`；仍执行实时身份验证。更改已登记节点身份、自动恢复被禁用节点，以及对历史同一云实例换 boot/NodeUID 再登记都被拒绝。旧实例必须经过独立的受控维护与 fencing 流程，不能通过重装宿主绕过记录。记录原子写入 `runtime_nodes` 和 `runtime_node_enrollments`；后者对 owner 也禁止 UPDATE/DELETE，普通运行角色无读取权限。

初次登记要求保留隔离标记。认证需要续期时，在同一命令显式增加 `--renew-certification`，提供新的独立审阅报告及对应 settings 摘要；必须保持同一 enabled 节点身份，新的 review 时间与有效期都严格增加。每次续期追加独立审计与回执，不更新旧记录，不改变节点调度状态。续期允许在已取消 `unverified` 的运行节点上执行，但仍检查 `untrusted` taint、NodeUID、bootID、运行时摘要和双向 TLS。重复同一新报告返回既有回执。

认证有效期必须覆盖申请的启动/续租期限，已过期认证不能批准新的计算任务；停止旧任务的证明验证不受此期限影响。认证续期不是节点健康检查或重新激活机制。节点维护、禁用或失联后的 fencing 与恢复必须使用对应的受控生命周期，不能手动把旧节点恢复为 enabled。

## 已验证与边界

本地验证包括真实 PostgreSQL、真实双向 TLS、模拟 Kubernetes Node 查询，覆盖原子/重复登记、审计不可变、普通角色无权登记、过期观察、NodeUID/boot/IP/profile 替换以及禁止重新激活。它不证明真实公有云实例、物理隔离或 CSI 挂载状态。实际部署必须保留真实环境测试证据。
