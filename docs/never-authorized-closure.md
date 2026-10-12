# 未签发启动许可的计算删除

本协议让失败或未完成的 CREATE/START 能通过显式 `DELETE /v1/instances/{id}` 回收计算。调用者仍必须同时拥有 `instances:delete` 和 `instances:hard_stop`，并提供最新 `If-Match` 与幂等键。DELETE 与工作区、实例行锁一起取消原 CREATE/START 的操作租约；已进入安全 STOP 的同代，仅在有出生合同、无启动许可且无活动 slot 时允许 DELETE 接管；其余正在进行的操作仍返回冲突。操作记录区分 `SUPERSEDED_BY_DELETE` 与普通 STOP。

它只处理计算。即使从未出现 Pod、PVC 仍是 Pending，实例计算删除完成后工作区与 `WORKSPACE_GIB` 配额继续保留。CSI 的异步 CreateDisk 可能晚到；Pod/PVC 404 不是“从未创建云盘”的证明。工作区销毁仍需独立授权、精确云盘身份及现有卷删除账本；尚未取得卷身份的工作区需要等待 CSI 收敛，不能依赖这个协议清空存储记录。

## 首次激活与后续变更

先完成真实 G1 认证和节点登记：所有专用 Kata 节点的 kubelet 必须仅经 nodeguard CRI 启动，nodeguard 没有数据库先持久化的 OPEN 许可便拒绝 Run。注册控制器必须先提交 `launch_permits` 再向宿主发送注册 RPC。这些是出生合同的信任边界，不能用单元测试或一个手写 JSON 替代现场认证。

在维护窗口打开平台 safe mode，完成每台节点的 `sandbox-admin enroll-node` 后，保存以下部署专属文件。UUID、摘要和审批编号必须来自实际登记与评审，下面仅说明结构：

```json
{
  "action": "activate",
  "contract_id": "<new-contract-uuid>",
  "cluster_epoch": "<current-platform-epoch>",
  "certification_report_sha256": "<64-lowercase-hex-of-reviewed-report>",
  "runtime_node_ids": ["<registered-runtime-node-uuid>"],
  "approval_reference": "<change-review-reference>"
}
```

```sh
sandbox-admin guard-contract --file guard-contract.json --validate-only
SANDBOX_ADMIN_DATABASE_URL="<injected-owner-connection>" \
  sandbox-admin guard-contract --file guard-contract.json --apply
```

`--validate-only` 仅检查输入格式，输出明确 `database_checked=false`。`--apply` 需要安装 owner，锁定当前平台配置并要求 safe mode；输入节点集合必须完整且精确覆盖当前 epoch 的全部 enabled 节点，每个节点必须有同一报告摘要的最新、未过期登记。合同有效期取这些登记最早到期时间。成功不会关闭 safe mode，也不会修改节点调度状态。

每个合同、撤销与出生记录不可修改。扩容、报告续期必须重新登记相应节点并显式提交新的合同 UUID。新版本可以覆盖新增节点；已经出生的代仍保留原始合同引用。到期或撤销阻止新出生/许可，不撤销已经完成的“永不启动”证明。撤销文件为 `{"action":"revoke","contract_id":"<uuid>","approval_reference":"<review>"}`，通过同一命令执行。

调度绑定也受此约束。准入服务 fresh GET 目标 Node，校验 Ready、调度状态、真实 Node UID、boot ID 和 runtime profile 摘要，再通过窄数据库函数核验 enabled 节点身份、当前 epoch，以及覆盖实例整个租期的有效认证。有出生记录的代还必须属于当前有效、未撤销合同的节点集合。Kata 标签本身没有授权作用；已登记但 disabled 的节点不能承接新绑定，既有可信终止证明的接收不受此限制。

迁移不回填旧实例。出生触发器只对当前 epoch、有效合同下新建的第 1 代或具有可信前代历史的新一代记录协议。既无原出生记录、又无精确可信前代关闭证明的旧代，不能靠修改 generation 或后来激活合同补发证明。没有出生记录的安装仍走原宿主终止路线；要启用失败创建回收，必须在接收租户创建流量之前完成上述激活。

## 持久化与故障恢复

1. termination 控制器按工作区 → 实例 → 活动执行 → 操作顺序取得锁，并重新检查当前 DELETE、租约、epoch 和无活动执行。
2. 窄授权 `sandbox_close_never_authorized` 要求精确出生记录、当前代没有任何持久化许可、历史已签发许可都已有可信关闭及清理。**只要许可存在，即使注册 ACK 丢失，也必须回到宿主可信关闭。**
3. 关闭记录先单独提交。`launch_permits` 的 BEFORE INSERT 触发器取得同一工作区/实例锁并永久拒绝该代迟到的许可；普通控制器和迁移 owner 的普通 INSERT 均不能绕过这个门禁。
4. 第二个事务核验关闭证明后只释放 CPU、内存和实例数预留，发布 `instance.deleted`，写入 `proof_kind=NEVER_AUTHORIZED` 和 `closure_id`，工作区状态原样保留。发布事件可能等待 stream head，因此完成前再次检查租约和 epoch。等待期间过期会整体回滚配额释放。
5. 第一步之后崩溃，由新的有效租约继续第二步；关闭身份不变。过期租约不能发布完成，恢复 epoch 后旧关闭证明不自动在新 epoch 生效。

`last_termination_proof_id` 不会伪造成本地 VM 证明；实例使用独立的 `never_authorized_closure_id`。API、worker、gateway 没有写出生/关闭记录或调用关闭函数的权限。

## 迟到 Pod 的独立清理

termination 进程包含独立的 live Pod 分页扫描，每页最多 100 个对象，完成一轮后等待 30 秒，每个对象处理上限 10 秒。需同步应用 [termination RBAC](../deploy/admission/termination-rbac.yaml)：集群级只增加 Pod `list`，写入仍仅在各项目 namespace 的原 DELETE/PATCH 权限内。

标签仅选择候选。清理前读取精确数据库出生/关闭、实例身份、当前 epoch 和受控 Pod 完整清单，再 GET 当前 Pod，核验 namespace/name/UID/resourceVersion、镜像、安全配置、Kata runtime 和代际标签。先持久化该 closure 下的 Pod UID 观察，再发带 UID/resourceVersion 前置条件的普通 DELETE；下次观察 deletionTimestamp 后才移除保护 finalizer。准入服务只允许精确 termination SA 移除 finalizer，普通 worker 仍被拒绝。

完成一次清理或扫描到 404 不会删除出生/关闭记录，也不会标记“永远不会再有 Pod”。晚到的另一个 UID 必须重新完整核验并登记后才能清理，旧 UID 的准入凭证不能直接复用。整个清理器不删除 PVC/PV、云盘、快照，也不声称卷已经卸载。

## 验证界限

本地专项使用真实 PostgreSQL 独立角色、事务、RLS 和锁竞争；Kubernetes API 是明确的协议替身。运行：

```sh
set -a
. .local/dev.env
set +a
cargo test --locked --offline --lib never_authorized::tests -- --ignored --test-threads=1
```

实际部署仍必须验证延迟 kube-apiserver CREATE、CRI Run/注册竞态、nodeguard 重启丢账、控制器崩溃、旧 epoch、节点扩容、分页失败与故障恢复。未经真实节点认证不得激活生产合同。本地测试不会创建或销毁任何真实云资源。
