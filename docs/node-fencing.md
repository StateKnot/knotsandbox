# 平台节点事故与单次云停机

本模块实现平台 SYSTEM 节点事故、全部受影响启动的冻结、永久云实例墓碑、单次 ECS 停机派发，以及后续状态观察。它不把 `Stopped` 写成本地终止证明，不删除 Pod finalizer，不释放活动槽、配额或工作区；完整云隔离与卷清理完成器仍是独立验收项。

## 运行入口

DBA 单独创建无 owner/BYPASSRLS/跨组件 membership 的 `sandbox_fencing` 登录；迁移后运行 `scripts/sql/fencing-role.sql`。该登录只能消费已有事故，不能创建事故、改节点身份、写本地终止证明或配额。所有七个运行身份相互禁止 membership，包括 `NOINHERIT` 但可 `SET ROLE` 的关系。

运维通过 `sandbox-admin node-fence --file incident.json --validate-only` 校验输入，然后以安装 owner 的 `SANDBOX_ADMIN_DATABASE_URL` 把 `--validate-only` 换成 `--apply` 执行。文件包含 `incident_id`、`runtime_node_id`、完整已登记 `node`、`cloud_account_id`、`region`、`cloud_instance_id`、`reason`、`reference`；`reason` 仅支持 `NODE_UNREACHABLE`、`RUNTIME_INTEGRITY_FAILURE`、`OPERATOR_NODE_MAINTENANCE`。`reference` 是已批准的平台事故编号。身份必须与数据库精确一致，同 incident ID 与相同内容重放返回原回执；不同内容或新 ID 不能覆盖旧墓碑。

这是会影响同节点所有租户的永久隔离决定。租户 `instances:hard_stop` 不授权该命令，任何租户 API 都不能自动升级为整机停机。`--apply` 提交后，已运行的专用控制器可以发出真实云停机请求。

控制器以 `sandboxd --role fencing` 启动，使用专用 `SANDBOX_DATABASE_URL` 和 `SANDBOX_CLOUD_FENCING_CONFIG_FILE`。后者是 [云客户端配置](cloud-fencing.md) 的 JSON：独立 OIDC 工作负载、RAM角色和精确节点 allowlist，禁止永久 AK；配置文件没有凭据内容，令牌仅通过受限 projected-token 路径提供。该进程无需 Kubernetes 写权限，不暴露租户 HTTP 入口。它串行处理节点事故，每次最多冻结 16 个启动，网络请求有界；停机意图与读观察跨进程恢复。

## 持久化顺序

1. 先取得精确云三元组的事务锁，再按固定顺序锁该云实例全部历史节点，写 owner 请求与永久 account/region/ECS 墓碑，统一禁用节点并快照全部历史 boot 已登记的 launch。节点重新登记与事故共享云身份事务锁；许可与延期 INSERT 必须持节点共享锁，因此该事务等待已受理写入完成，之后迟到许可无法越过禁用门禁。
2. 独立事务按已有 workspace → instance → execution → operation 顺序冻结各租户资源。当前 CREATE/START/RESTART 被 SYSTEM STOP 取代；已受理 STOP/DELETE 保留安全停止路径。正在执行的任务变为未知结果/待终止，保留全部槽和配额。每个租户写入 SYSTEM 审计与领域事件；历史 launch 仅记录，不改变当前新 launch。
3. 只有全部快照目标已处理，控制器才提交唯一 `attempt_id` 和 `DISPATCHING`，然后调用一次 `force_stop`。请求前失败、请求结果未知、进程在提交后/发令前崩溃、响应丢失、租约被接管，一律只允许后续查询，不能自动第二次 Stop。
4. 云请求证据原样追加：action、请求 ID、时间、响应摘要，以及精确身份/状态观察。普通失败只追加固定错误码；不记录凭据或底层带 URL 的错误。
5. `STOPPED_OBSERVED` 仍继续轮询。如果之后观察到任何非 Stopped 状态，永久转为 `BREACH`，保留全部原始证据并停止自动派发。旧云实例不能重新登记或启用；续认证不能清除墓碑。数据库 epoch 改变时旧事故不继续消费，须走独立恢复流程。

`FREEZING → READY_TO_STOP → DISPATCHING → OBSERVING/STOPPED_OBSERVED → BREACH` 是事故处理状态，不是沙箱终止证明状态。即使云停机受理或已经 Stopped，配额、卷和最终终止状态都不会被本模块更改。当前本地宿主证明完成器仍可独立按其完整证据安全收尾。

## 诊断与人工处置

`DISPATCHING` 的含义是停机调用额度已经永久消耗，并不表示请求到达云端。若前置身份查询失败、进程中断或调用结果未知，控制器只查询：即使云实例一直显示 Running，也不自动重试 Stop。平台运维需按事故记录核对精确账号、地域、ECS ID、请求 ID 与云操作审计，独立决定经批准的人工隔离动作；不能清空 `attempt_id`、删除墓碑、重建同 ECS 事故来绕过单次派发。数据库拒绝这些回退。`BREACH` 必须升级平台安全事故，不能按普通失败关闭。

诊断通过 owner 对精确事故 ID 查询 `node_fence_incidents`、`node_fence_targets` 和只追加的 `node_fence_events`；这些全局事故资料不直接暴露给租户。租户仅看到自己的 SYSTEM 操作、审计和领域事件。观察结果始终保留请求身份、时间和云证据，`STOPPED_OBSERVED` 无法代替完成回执。

## 交付与后续证据

真实 PostgreSQL 测试使用不同租户、专用运行 role、现有不可变 launch 与配额；云响应由本地真实 HTTP listener 模拟，不连接云账户。验收覆盖所有受影响租户被冻结、用户/其它组件无事故权限、许可与冻结并发、单次派发 CAS、dispatch 后崩溃/未知结果不重发、云重新运行进入不可撤销 BREACH，以及观察不释放资源。

本包不声称云状态观察已经构成持续不可复活证明。后续完成器还必须核验 ECS 休眠配置与停止语义（禁止借内存恢复沿用旧 boot/journal）、宿主关闭或不可复活约束、目标 profile/云 IAM 与自动化认证、精确云盘身份及完整挂载信息、Kubernetes/CSI 清理，并通过真实断电/重新启动/迟到操作演练；不能用事故状态布尔值替代这些证据。

2026-10-03 本地 PostgreSQL 17.11 上，0020 与后续 0022 正常迁移应用后，八条节点账本回归全部通过。云端仅使用真实回环 HTTP 的受控响应，没有访问云账户、发起真实停机或生成完整云终止证明。锁竞争用 PostgreSQL `pg_blocking_pids` 确认 workspace 与事件流 head 上的实际阻塞，再验证过期租约不能提交。窄函数明确拒绝 NULL/空/零/未认领租约；队列跳过历史 cluster epoch，避免旧事故反复抢占新事故。
