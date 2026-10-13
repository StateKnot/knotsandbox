# Worker 调谐与恢复合同

`sandboxd --role worker` 接入 PostgreSQL 操作队列及 Kubernetes 客户端，创建并观察受控资源。[可信终止控制器](trusted-termination.md)、[云节点 fencing](node-fencing.md)和[执行网关](gateway-runtime.md)使用独立身份与进程。通用 worker 不发送 guest 命令，不根据 Pod 消失释放计算配额、活动槽或终止保护 finalizer；缺少当前代际的可信终止证明时，停止、删除和重启保留 `WAITING_TERMINATION`。生产上线仍须完成真实运行时与云基础设施的独立验收。

## 部署依赖

使用 DBA 预置的独立 `sandbox_worker` 登录角色作为 `SANDBOX_DATABASE_URL`。迁移进程应用全部 migration 后，依次执行 `roles.sql` 和已存在组件角色的窄授权脚本；不会创建登录用户、生成生产密码或忽略授权失败。启动会检查非 owner、非 superuser、无 BYPASSRLS、数据库版本以及领取操作/扫描计算租约的函数权限。

必须在独立环境完成 Kata、Cilium、CSI、准入、首包阻断及故障测试，再把认证结果的引用写入 `SANDBOX_DEPLOYMENT_CERTIFICATION_ID`。该字符串和 namespace annotation 是证据引用，不会自动证明网络或虚机隔离。工作 namespace 必须包含：

- `sandbox.platform/managed=true`。
- 与数据库对应的 `sandbox.platform/tenant-id`、`project-id`、`cluster-epoch` labels。
- `sandbox.platform/certification-id` annotation，与 worker 的配置一致。
- 由 namespace provisioner 创建的原生 `NetworkPolicy`：名称 `sandbox-default-deny`，`podSelector: {}`、`policyTypes: [Ingress, Egress]`，无 ingress/egress 放行规则。

RuntimeClass 固定 `kata-qemu`、handler 固定 `kata-qemu`，并选择 `sandbox.platform/worker-pool=kata` 节点。Kubernetes 配置必须使用 HTTPS 和证书验证。Worker 不允许自定义 runtime fallback。

`SANDBOX_DNS_NAMESPACE` 默认 `kube-system`，`SANDBOX_DNS_LABEL` 默认 `k8s-app=kube-dns`；它们必须指向实际 CoreDNS endpoints，并与 admission 配置一致。CiliumNetworkPolicy 仅允许上述 DNS 的 TCP/UDP 53，其余 ingress/egress 默认拒绝。原生 NetworkPolicy 对所有实例生效，Cilium always-enforce 与首包防护由经过认证的部署负责。Worker 不会临时修改这些部署前提。

## 队列与分段观测

Worker 启动立即扫描已有操作，随后在提示、任务完成和固定500ms恢复扫描时填充可用并发槽。0044的空通知只提示重新查询；领取仍由原路由/期限/租约SQL决定。连接池上限包含一个监听连接，max=1使用轮询。详见[队列调度与调用观测](worker-dispatch.md)，包括部署、数据库预算、缺提示恢复和观测范围。

## 持久阶段

每次领取推进一个阶段：验证策略对象并记录 UID → 验证 PVC 并记录 UID → 验证 Pod 并记录 UID → 验证当前代际 Ready 并完成操作。PVC 的 `WaitForFirstConsumer` 不会造成调谐死锁：允许先创建 Pending PVC，再创建消费者 Pod，最终 Ready 时要求 PVC 为 Bound。

固定 Pod、PVC、CNP 名称帮助恢复“远程创建成功、账本提交前进程崩溃”。新 worker 会读取固定名、严格核验归属和完整受控 spec 后，记录同一 UID。已记录 UID 不匹配或对象消失时不创建替代物。PVC 账本标记 DELETED 也不是为同一工作区创建空卷的授权；必须调查数据状态。

每个远程阶段之前和之后都用短事务检查 workspace → instance → operation 锁、worker lease token、当前代际/launch/epoch、计算截止时间、期望状态以及当前授权。租约 30 秒，每 10 秒续约；单阶段最长 25 秒。数据库事务不跨远程请求。失租约后取消本地等待不代表撤销已发出的远程请求：部署的准入服务必须独立根据权威账本拒绝过时代际和已撤销运行意图，不能仅依靠 worker 的调用前检查。

成功 Ready 要求当前 launch 的唯一容器 Ready 且 Running、Pod Ready、PVC Bound，以及仍与账本一致的 CNP/PVC/Pod UID 与 spec。随后同一事务写入 5 个 `ready_*` 字段、实例 RUNNING、操作 SUCCEEDED、配额 PENDING→ALLOCATED、审计及事件。后续命令发出前仍需要新鲜 Kubernetes 核验；历史 Ready 字段不保证节点持续健康。

## 停止、重试与诊断

STOP、DELETE、RESTART 只提交带 UID 和 resourceVersion 前提的优雅 Pod DELETE，保留 finalizer。Pod 不存在、进入终态、返回 DELETE 成功都不是 VM 已死亡的证明。没有可信证明时保留工作卷、配额及槽，持久状态为 `WAITING_TERMINATION`，原因是 `TRUSTED_VM_TERMINATION_PROOF_REQUIRED` 或 `POD_ABSENCE_IS_NOT_TERMINATION_PROOF`。已接受的安全收尾不因原调用者撤权或 safe mode 被取消；跨 cluster epoch 仍拒绝操作，防止删除错误集群中的对象。

暂时数据库连接/容量/锁错误、授权撤销和资源漂移保留持久操作；阶段可写入 `RECONCILE_BLOCKED` 时使用稳定 `wait_reason` 错误码及至多 256 秒指数退避。永久数据库权限、schema、解码/约束合同错误或已关闭连接池不会无限重试：claim、阶段、heartbeat、退避持久化和 timer 的同一分类使父任务停止领取并返回失败。日志与进程错误只包含固定错误码及过滤后的 SQLSTATE，不暴露数据库语句、绑定值或 provider 错误详情。进程失败不删除、伪造成功或释放原有运行意图；修复安装合同后，后继 worker 按自然租约和已有幂等规则恢复。

EXECUTE 由独立 GATEWAY 队列和[执行网关](gateway-runtime.md)处理，通用 worker 的 claim 不领取该类操作。网关发生期限/断流/输出失败时持久接受 STOP，生命周期 worker 随后请求停止，并继续等待可信 VM 终止证明。

并发上限由 `SANDBOX_WORKER_CONCURRENCY` 控制，范围 1–32，默认 4。计算 TTL/idle 扫描每轮完成后等待 5 秒，每批最多 100 项。迁移 `0041` 保留实际 `due_at`，由私有 `last_selected_at` / `next_scan_at` 原子、带 `SKIP LOCKED` 地安排尝试，最久未扫描的可受理项优先；失败和进程崩溃不会让固定首批占满所有后续扫描。5 秒重试资格属于队列调度，不延长计算 TTL，也不是 VM fencing。timer 在 workspace → instance → active operation 上使用 `NOWAIT`，竞争立即延后；该单项事务另外用局部 `lock_timeout=100ms` 覆盖 FK、trigger 和事件流的隐式锁，事务完成/回滚后恢复连接池原值。真正拿到锁后复查最新真实截止时间、运行意图及工作卷所有权，并在同一事务唯一受理保卷 STOP。直接 `accept_due_stop` 保留原等待锁的 Interface，续期、停止与 idle 的原子竞争合同不变。

父任务持续监督关键 timer 与阶段任务，永久错误或异常子任务退出均取消共享 token，最多等待 30 秒收束当前阶段和 5 秒 timer，再由进程的 `with_database_drain` 等待连接池关闭并非 0 退出。收到 SIGINT/SIGTERM 使用同样的有界收束及连接池关闭；剩余租约交由后继 worker 恢复。通用 worker 没有 HTTP readiness listener，不能用“进程仍在”代替 timer 健康；部署必须监控退出、重启、固定错误码和到期积压。

## 本轮故障回归入口

`cargo test --test timers blocked_first_hundred_cannot_starve_later_expiry_and_replicas_accept_one_stop -- --ignored --exact` 使用真实 PG、独立 `sandbox_worker` 登录及 100 个真实工作卷冲突，核对后来的正常到期进入下一批、实际截止时间保持不变、12 个竞争者仅受理一次 STOP。

`cargo test --test worker_process actual_worker_supervises_runtime_acl_drift_and_recovers_timer_lock_timeout -- --ignored --exact --nocapture` 必须由 runner 创建独立 `sandbox_worker_process_<nonce>_test`，为 app/migration/worker 三个显式 URL 注入 `sslmode=verify-full` 和绝对 `sslrootcert`。用真实 worker 可执行文件测试启动后 claim/timer 函数撤权、非 0 退出、物理 PG 连接消失，以及真实表锁超时后的同进程退避、解锁恢复并唯一受理 STOP，再验证 SIGTERM 退出和连接池 drain。shell 环境被清空；Kubernetes 指向该试验持有并拒绝 socket 的 loopback endpoint，不使用用户 kubeconfig 或接触真实 guest。此入口不创建数据库、修改全局角色密码或删除数据库；runner 负责预置正常迁移权限及独立测试数据库。

## 已验证范围

`cargo test --test worker -- --ignored` 需要显式的 `TEST_DATABASE_URL`、`TEST_MIGRATION_DATABASE_URL`、`TEST_WORKER_DATABASE_URL`，全部指向同一 `_test` 数据库；worker 连接必须使用非 owner 的 `sandbox_worker`。测试使用真实 PostgreSQL 和 mock Kubernetes transport，覆盖远程创建后的租约丢失、重启恢复与不重复建卷、已知 UID 消失、被删除的卷账本、安全模式、授权撤销、Ready 账本和停止保留配额/finalizer。

这些测试不证明真实 Kata VM 已运行、Cilium 已阻断首包、CSI 已完成卷 fencing 或云集群已经通过上线验收；这些必须通过真实集群故障实验取证。

Instance `stop`/`delete`/`restart` authorization requires its action scope plus
`instances:hard_stop`, even with an empty activity slot, because the current
backend terminates the whole VM. Both scopes are rechecked before idempotent
replay and after taking lifecycle locks. There is no separately authenticated
graceful-only path in this release. Already accepted cleanup continues after
revocation; retained finalizers and quotas still require physical termination
evidence before release.
