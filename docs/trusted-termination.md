# 可信启动许可、续租与终止账本

此实现把宿主停止证据、Kubernetes 资源清理、数据库资源释放分成三步。控制面只能主动访问预登记节点的 nodeguard；没有接收外部任意 JSON 终止证明的公共 API。真实 PostgreSQL、双向 TLS 和模拟 Kubernetes 测试覆盖这些边界，但不能代替目标 Kata/CSI/裸金属环境认证。

## 部署与权限

先运行正常数据库迁移及各组件角色脚本，再部署对应二进制。`sandboxd --role termination` 使用独立 `sandbox_termination` 数据库登录；API、worker、gateway 不得继承该角色。控制器需要 `SANDBOX_NODEGUARD_SERVER_CA_FILE`、`SANDBOX_NODEGUARD_CLIENT_IDENTITY_FILE`、Kubernetes 身份和 `SANDBOX_DEPLOYMENT_CERTIFICATION_ID`。客户端证书和私钥不可放进镜像、配置输出或公共 API。

`runtime_nodes` 由受控运维身份预登记：集群 epoch、Node UID/name、cloud account/region/instance ID、私网 IP、9444 端口、boot ID、宿主配置摘要。节点身份不可原地替换；普通组件不能写目录。nodeguard TLS 名称由 Node UID 推导，控制面只连接登记的 RFC1918/ULA 地址。节点重建、重启或配置变化必须重新核验登记；禁用节点只阻止新启动与许可延期，已有启动仍允许安全停止；节点身份、证书或证据无法核实时不能释放资源。节点目录当前通过受控 owner 操作维护，不能把 Kubernetes Node 自报身份直接转成信任。

## 启动与正在启动时续租

1. worker 持久登记精确 Pod/PVC/策略资源 UID；控制器重新读取 Kubernetes，核实当前 launch、generation、epoch、Node、PVC/PV/CSI handle。
2. 数据库事务锁定 workspace → instance → 当前活动 → operation，复核实时权限、TTL、safe mode、模板和安全策略，写入不可变 base launch permit。宿主 CRI 前置门禁在许可登记之前拒绝启动。
3. 控制器用双向 TLS 注册许可，将私有已验证响应的 journal revision 写入 ACK 账本。worker 只有在启动登记与 Kubernetes Ready 都通过时才能完成启动。
4. CREATE/START 期间的 RENEW 保持同一 compute lease、launch 和 generation。数据库期限增长后，控制器创建不可变 `launch_permit_extensions`，绑定 base permit、compute lease ID/version 和新期限。新 extension ID 只作为本次注册请求 ID，不改变 base permit，也不改变终止挑战的外键。
5. host 在 OPEN 状态下原子持久化较大期限，并返回 `effective_expires_at`。控制面验证该期限至少覆盖请求，但只把数据库批准的期限用于调度判断。ACK 可重试或乱序到达；旧 ACK 不能降低 journal 水位或替代较新期限。CLOSED/UNKNOWN gate 永不通过续租重开。

RENEW 的同步成功表示数据库接受了新期限，不代表正在启动的宿主已经确认续期。控制器会继续处理待确认许可；缺失确认时不能推断实例可执行。运行中现存 exec/健康读取不因原始启动许可到期而被误判为新启动。新的 Run 始终受单次启动门禁约束。

## STOP、RESTART 与 DELETE

| 阶段 | 必须具备的证据 | 允许变更 |
| --- | --- | --- |
| 受理 STOP | 当前范围/动作权限、实例版本、幂等键；SYSTEM 安全停止使用已受理关系 | 建立停止操作，保留活动槽和配额 |
| 宿主终止 | 当前操作 lease token、短时 challenge、精确 node/boot/launch、单调 journal revision，经主动双向 TLS 核验 | 追加本地终止证明；仍不释放配额 |
| Kubernetes 清理 | 精确 UID/RV 删除 finalizer，旧 Pod UID 不存在；PVC/PV/CSI identity 不变且没有该 PV 的 VolumeAttachment | 产生私有清理凭据；网络超时、未知结果均不能替代凭据 |
| 完成事务 | 上述两种凭据一致且新鲜，当前操作仍持有锁/租约，活动和配额账本一致 | 追加清理回执，释放 CPU/MEM/执行配额及活动槽，workspace AVAILABLE，保留卷 |

Kubernetes Pod/VolumeAttachment 消失只证明控制面资源状态；旧 writer 已停止依赖宿主证明，不把 Kubernetes 缺失视为云 fencing。

STOP 后已派发或原本未知的 execution 仍为 `OUTCOME_UNKNOWN`，单独将 `termination_status` 置为 `CONFIRMED`。不能用“VM 已停”推断用户命令成功或失败。重复完成请求不重复减配额。

RESTART 在旧启动完成终止后再次检查原调用者的 `instances:restart` 与 `instances:hard_stop`、当前 TTL、epoch、safe mode、模板及策略。通过后才产生新 generation/launch，原操作设置 `restart_generation` 并重新进入 worker 创建流程；不延长 compute lease。授权失效时完成安全停止，但不启动新实例。

`DELETE /v1/instances/{id}` 只销毁计算实例，**保留独立工作区和数据卷**。当前 launch 的可信 VM 终止、旧 Pod 消失和卷解绑检查完成后，事务释放 CPU、内存、执行槽与实例数量配额，实例标记 `DELETED`、DELETE 操作完成；工作区恢复 `AVAILABLE`，容量配额保持。已 `STOPPED` 的实例复用同一 launch 的不可变终止与清理证明，不重复释放计算配额。升级前停留在 `WAITING_VOLUME_DELETION` 的实例 DELETE 也由同一恢复事务完成；该旧阶段不能当作卷删除授权。

删除记录不能恢复为存活实例。恢复事务要求当前 worker 租约、当前 cluster epoch、精确 instance/workspace/generation/launch/Pod 身份、无活动执行槽和无遗留计算预留；事件流头锁等待之后再次核验租约，失败整笔回滚。后续工作区销毁使用独立 `workspaces:delete` 权限和明确确认，只有云盘实际销毁证明才能释放工作区容量。独立卷控制器交付前，这一工作区销毁能力仍未开放。

## 失联与旧数据

没有已登记 base permit 的历史 VM 无法被证明“从未启动”，应保留 UNKNOWN 和配额，由独立经过认证的恢复/fencing 流程处理。宿主超时、journal 回退、challenge 过期、错 tenant/node/boot/generation/launch、操作租约接管、CSI 仍挂载时均拒绝资源释放。

安全模式保留只读与安全停止能力；不得通过关闭模式、直接改 STOPPED/CONFIRMED、删数据库证据或手动扣配额绕过终止门槛。云断电/fencing、卷永久删除、宿主覆盖认证以及升级演练仍须在各自实际环境完成验收。

新计算还受节点认证有效期约束。启动许可、许可延期、Ready 和执行 CONNECT 都要求最新不可变认证记录覆盖当前计算租约；API 对已分配节点的续租使用租户内窄查询，超过该期限返回 `409 CERTIFICATION_LEASE_LIMIT`。尚未分配节点的 PENDING 可续租，RUNNING 缺少精确 launch permit 时拒绝续租。通过 `sandbox-admin enroll-node --renew-certification` 追加经审阅的新报告后可重试，不需要修改旧 permit 或审计记录。

STARTING 续租后，只有对应期限的宿主许可 ACK 已落库才能 Ready；旧 base ACK 或较短延期 ACK 不足以确认新租约。乱序 ACK 保持最大已授权期限，不回退宿主 journal。认证到期或节点禁止新启动不阻止已有 launch 的挑战、终止证明和资源清理。未登记历史运行实例在升级后不能凭旧 Ready 标记获得新执行权，须先完成受控认证与身份登记。

0023 本地回归：可信终止账本 15 项真实 PostgreSQL + 回环 mTLS 测试通过，覆盖运行中 DELETE、STOPPED 后 DELETE、旧等待行恢复、并发只完成一次、无证明/残余计算配额拒绝及流头锁等待超过租约后的原子回滚。Kata/KVM、真实 CSI 和云资源验收仍需部署认证。


计算 DELETE 的失败创建路径见 [未签发启动许可关闭协议](never-authorized-closure.md)。它使用独立的永久出生/关闭账本，不伪造 VM 终止证明，且保留 Pending 工作区及全部存储配额。
