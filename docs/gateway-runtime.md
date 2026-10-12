# 执行网关运行合同

此网关实现控制面持久派发、单次 Kubernetes exec、受限输出协议、原生 OSS 分块持久化和故障安全停止。它不能证明 guest 内没有恶意后台进程，也不把 Pod 消失或 runner 回执当作 VM 已终止。当前本地验证覆盖真实 PostgreSQL 与 HTTP/WebSocket，Kubernetes 对象、guest 和 OSS HTTP 服务使用测试替身；目标 Kata/Cilium/CSI 集群与真实 OSS 尚未验收。

## 启动和凭据

使用独立 `sandbox_gateway` PostgreSQL LOGIN 和独立 Kubernetes ServiceAccount，先执行全部迁移，再应用 `scripts/sql/gateway-role.sql`。运行 `sandboxd --role gateway`，必须提供以下配置：

| 配置 | 合同 |
|---|---|
| `SANDBOX_DATABASE_URL` | 独立 gateway 数据库身份；不能继承 owner/app/worker/admission |
| `SANDBOX_DEPLOYMENT_CERTIFICATION_ID` | 已审批的部署验收证据引用；不是自动认证开关 |
| `SANDBOX_OUTPUT_OSS_ENDPOINT` | 规范化区域地址，例如 `https://oss-cn-hangzhou-internal.aliyuncs.com`，不带尾斜杠、端口、查询、用户信息 |
| `SANDBOX_OUTPUT_OSS_BUCKET` | 专用输出桶 |
| `SANDBOX_OUTPUT_OSS_KMS_KEY_ID` | 该区域受控 KMS key；每次写入要求 KMS 加密 |
| `SANDBOX_OUTPUT_STS_FILE` | 绝对路径，网关 UID 可读的 regular file，权限 0400 或 0600 |
| `SANDBOX_GATEWAY_CONCURRENCY` | 1–32，默认 4；DB 池、OSS连接和集群容量按此值配额 |
| `SANDBOX_DNS_NAMESPACE` / `SANDBOX_DNS_LABEL` | 与已审批 manifest 和实际 CoreDNS 端点一致 |

Kubernetes 客户端使用受控 kubeconfig 或投射 ServiceAccount token，必须 HTTPS 且验证服务端证书。准入配置和 RBAC 见 `deploy/admission/gateway-rbac.yaml`；普通租户没有 Kubernetes 凭据。

STS 文件只接受四个字段：`access_key_id`、`access_key_secret`、`security_token`、RFC3339 `expires_at`。凭据投递程序以临时文件写入、fsync、同目录原子 rename 完成轮换；网关读取打开后的文件并检查类型、权限和最大 16 KiB。每次操作重新读取，剩余有效期必须大于 120 秒；每次存储调用总预算 20 秒，HTTP 单请求最多 10 秒。文件消失、格式错误、过期或剩余时间不足立即拒绝使用缓存 operator。

正式部署须由受控 RAM/OIDC 凭据投递 sidecar 或企业凭据代理提供上述文件，授予专用桶的 PutObject/GetObject 与对应 KMS 最小权限，不向 guest 提供该卷。当前仓库没有把一个未验证的凭据投递 sidecar 宣称为已交付；其镜像、RAM 信任策略、刷新与失效演练属于真实云安装验收的前置项。网关不会自行查询 ECS metadata，不会回退读取 AK 环境变量或用户目录。

OpenDAL 0.59 的显式 OSS static provider 优先返回完整凭据；已核对锁定版本 `reqsign-aliyun-oss 3.2.0` 的实现始终返回 `Some`，不因 OSS 拒绝该 STS 而尝试后续提供器。额外的 transport 白名单只允许指定桶域名的 HTTPS PUT/GET/HEAD，禁代理、重定向和 HTTP 自动重试。依赖链的 debug 日志存在打印凭据风险，统一日志入口强制阻断 `reqsign*`，即使设置 TRACE 也不能打开；不得绕过该日志初始化。

## 派发、完成和安全停止

1. 网关只领取 GATEWAY 队列的 EXECUTE 操作，数据库租约 30 秒，5 秒心跳；生命周期 worker 不领取该队列。
2. 对当前 RuntimeClass、命名空间证据、原生默认拒绝策略、CNP、PVC/PV、Pod 和 Node 做新鲜 GET。所有对象必须匹配账本 UID、固定名称、当前 generation/launch/epoch 及受控规格；不补建、不采用未知对象。
3. 再次持锁核对活动槽、配额、期限与实时权限，提交不可重写的 `dispatch_attempt_id` 与派发租约 token 后，才发一次 exec。CONNECT 准入按 execution/attempt 和 live lease 原子消费 AdmissionReview UID；不同 review UID 不能再次消费。同 review UID 重试仍须通过当前全部条件。
4. exec 固定容器和六项命令：`sandbox-runner exec --execution-id UUID --dispatch-attempt-id UUID`，其绝对路径固定。用户 argv/env 通过最多 64 KiB 的 stdin JSON 发送，不进入 URL，TTY 关闭。只接受 v5 子协议；stdin 的 `[255,0]` 表示单流 EOF，不关闭输出 WebSocket。Kubernetes HTTP 中间件不重试 exec。
5. Kubernetes channel 3 的进程终态与 guest 的 NDJSON 分开解析。只有可信 exec 进程成功结束、guest 结果格式有效且输出已持久化，才提交 SUCCEEDED/FAILED，释放平台活动槽和 EXECUTIONS 配额；guest 退出码明确为 `GUEST_REPORTED`，VM `termination_status` 保持 `NOT_REQUESTED`。
6. 输出达到上限是正常 `TRUNCATED`，包括上限为 0；仍持续读取有界协议。`output_complete=false` 且未声明截断表示不完整，不能作为正常完成。
7. 断流、协议超限、租约/权限变化、输出持久化失败或关闭网关，都会通过已受理的 HARD_STOP_INSTANCE 合同请求安全停止。强期限来自数据库受理的 deadline；不依赖 guest 自报超时。已派发的结果保持 `OUTCOME_UNKNOWN`，保留槽、工作卷和配额，等待可信 VM/云 fencing 终止证据。当前终止证明适配器未完成，因此这类 STOP 会等待，不伪造结束。
8. 进程重启后看到任何已有 attempt，直接恢复安全停止，不再次 CONNECT；即使实际请求还没有发出，也不能凭猜测重发。这里不承诺业务副作用 exactly-once。

固定活动槽只限制平台接受的任务数；恶意任务可能 fork/setsid 留下后台进程。需要两次任务之间完全无残留时，应使用停止并重建 VM 的合同，而不是把平台槽释放当作 guest 清洁证明。

## 输出与内存边界

独立于 runner 的网关限制包括：WebSocket 消息/帧 64 KiB、guest 单行 12 KiB、4096 个输出帧、guest wire 总计 24 MiB、原始保留输出最大 16 MiB。解码后通道只有 16 个事件，每个数据事件最多 6144 字节；每 256 KiB 或 1 秒写一个 OSS 分块。超限/异常的 guest 数据不进入运行日志。

不可变对象键：

```text
tenants/{tenant}/executions/{execution}/attempts/{attempt}/segments/{sequence}-{sha256}.ndjson
tenants/{tenant}/executions/{execution}/attempts/{attempt}/manifest-{sha256}.json
```

先条件 PUT 成功，随后同一数据库事务插入 append-only `execution_output_segments` 和 outbox；只有这时该块对控制面可见。相同 key 重试遇到已存在时，必须 HEAD 检查长度并有界 GET 核对全部字节；不同内容不可覆盖。PUT 成功但数据库提交失败会留下不可见孤儿，不能因此重新执行命令；对象清理须晚于恢复/保留窗口，并由独立受控清理策略处理。

manifest 的公共头包含 tenant/execution/attempt；每条紧凑索引只存序号、原 guest 帧范围、raw/object 字节数与 SHA256，按上述规则推导对象键。不重复保存每段完整路径。4096 段最大索引的序列化尺寸小于 1 MiB，测试预算的 receipt 向量、序列化 capacity、当前分块与事件队列合计小于 2 MiB；该数字不是含 TLS、HTTP、数据库池及 allocator 的整个进程 RSS 承诺。

输出 offset 是平台核验过的 **原始 guest stream 字节位置**，截断后不重编号；没有保留的数据不落盘，manifest 标记 TRUNCATED。stdout/stderr 分别累计 offset，统一 frame sequence 保留原始事件顺序。发生不确定结果时，已索引块仍在账本；有块标记 PARTIAL，无块标记 LOST。当前尚未交付文件下载/SSE/签名 URL 的全部产品接口，不能把对象存储存在等同于终端功能已经验收。

## 本地证据和云验收

`tests/gateway_ledger.rs` 包括真实 PG：普通完成只释放执行配额、未知/失租约拒绝晚回执、输出段不可变/RLS、过期租约重领不再 CONNECT；还启动真正的回环 HTTP/WebSocket 服务，串接真实 consume-once SQL 与原生 OSS 请求签名替身，覆盖正常、1 字节/0 字节截断、断流和 OSS 失败。

`gateway_transport` 单测验证 v5 stdin EOF、可信状态通道和 WebSocket 大帧限制；`gateway_runtime` 测试替换/漂移/缺失/删除对象；`output_store` 验证条件 PUT、重复内容读回核验与短期凭据轮换。上述仍不能代替真实 API server→kubelet→Kata exec、生产 LB 超时、STS/KMS/OSS、首包网络、节点失联与 fencing 验收。

实现依据：[OpenDAL 0.59.3 release](https://github.com/apache/opendal/releases/tag/v0.59.3)、[原生 OSS 服务](https://opendal.apache.org/services/oss/)、[Kubernetes RemoteCommand 协议](https://github.com/kubernetes/kubernetes/tree/master/staging/src/k8s.io/apimachinery/pkg/util/remotecommand)。构建以 Cargo.lock 版本为准，升级 kube/OpenDAL/reqsign/tungstenite 必须重跑完整网关和凭据日志回归。
