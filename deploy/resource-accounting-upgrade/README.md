# 启动资源账本维护升级门

`upgrade.py` 是实际执行 Kubernetes 准入、停写、排空、正常 owner 迁移、普通应用身份预检与恢复的入口。旧 0044 程序允许成功的额外迁移，不能假定它认识未来触发器。此交付使用维护窗口；没有滚动混跑或旧程序回退承诺。

## 固定输入与权限

唯一公开输入是审阅后的 JSON plan、明确的 kubeconfig/context 和新的私有证据目录。plan 字段如下；不接受数据库 URL、口令、任意迁移命令、跳过步骤或复用成功回执的参数。

```json
{
  "schema_version": 1,
  "namespace": "sandbox-system",
  "cluster_uid": "替换为该集群 kube-system Namespace 的真实 UUID",
  "writers": {
    "sandbox-worker": {
      "containers": {"worker": "替换为已批准的完整 registry/repository@sha256 引用"},
      "init_containers": {}
    }
  },
  "workloads": [
    {"kind": "Deployment", "name": "sandbox-worker", "service_account": "sandbox-worker", "replicas": 2}
  ],
  "sandboxd": "/opt/sandbox/bin/sandboxd",
  "sandboxd_sha256": "替换为目标普通发行二进制的完整 SHA256",
  "database_name": "sandbox"
}
```

上例只有字段说明，含占位符，不能执行。实际 plan 须枚举全部已部署 writer 的 Deployment/StatefulSet，以及每个普通和 init container 的精确名称及目标镜像。credential sidecar 也必须单独绑定；浮动 tag、未审阅 container、遗漏 workload 和未知 writer Job/CronJob/DaemonSet 均拒绝。replicas 是审阅后的恢复数量。

准入固定保护命名空间中的九个产品身份：`sandbox-api`、`sandbox-worker`、`sandbox-gateway`、`sandbox-admission`、`sandbox-termination`、`sandbox-fencing`、`sandbox-volume-deleter`、`sandbox-backup-controller`、`sandbox-automation`。未配置的受保护身份默认拒绝，不会因 plan 遗漏而绕过；普通 PostgreSQL/default 等非 writer 身份不受此策略影响。产品 writer 不允许改用其他 ServiceAccount 或命名空间绕过此合同。

部署身份需要管理本门的 `ValidatingAdmissionPolicy` 和 Binding、在目标命名空间 create/get/delete 操作锁 ConfigMap、创建探针 Pod 和 `pods/eviction`、读取 ServiceAccount/Pod/五种 workload、scale/patch/rollout 指定 Deployment/StatefulSet。探针删除通过真实 Eviction 的 UID precondition 约束，避免删除同名替换对象。运行身份不能修改集群准入、操作锁、ServiceAccount、部署模板、数据库凭据或本 plan。生产 RBAC 必须由集群管理方预先建立；拥有 cluster-admin/DBA 权限的人仍是信任根，不能由本脚本限制。

三种数据库身份仅由环境注入，禁止写入 plan、命令行和证据：

| 环境变量 | 用途 |
| --- | --- |
| `SANDBOX_UPGRADE_OBSERVER_DATABASE_URL` | 独立维护观察身份；要求准确数据库、`sslmode=verify-full` 与 root CA。只执行带 5 秒 statement/3 秒 lock timeout 的 READ ONLY 事务，核对实际 runtime 会话及全部租户的活动租约。由于 FORCE RLS，观察身份须具备 DBA 提供的 BYPASSRLS 或超级用户；runtime 不取得此权限。 |
| `SANDBOX_UPGRADE_MIGRATION_DATABASE_URL` | 原 migration owner；只经环境传给同一固定 SHA 二进制的 `--role migrate`。不使用观察管理员安装被测 schema。 |
| `SANDBOX_UPGRADE_PREFLIGHT_DATABASE_URL` | 普通应用 LOGIN；只经环境传给同一二进制的 `resource-accounting-check`。绝不使用 owner/observer 代替 runtime 预检。 |

## 执行与失败语义

```sh
python3 deploy/resource-accounting-upgrade/upgrade.py maintain \
  --plan /secure/reviewed-resource-upgrade.json \
  --kubeconfig /secure/cluster.kubeconfig --context reviewed-production \
  --evidence-dir /secure/evidence/resource-upgrade-new
```

每次命令先核对真实集群 UUID。`install` 只允许首次安装并真实验证批准策略；`verify` 回读精确策略/Binding spec 后执行实际 server dry-run。它们不能解除已关闭的维护状态。

三个动作均先对目标命名空间的固定名 `sandbox-resource-<namespace SHA256 前16位>-operation` ConfigMap 执行原子 `create`。同一目标的第二个操作者即使使用不同 plan 也不能取得锁，不会进入准入更新、迁移或恢复。锁记录不可变的 plan 摘要与随机 operation ID，证据记录 API 实际返回的 UID；没有 TTL、心跳到期或自动抢占。整个进程成功，或维护失败后实际再次验证 CLOSED 并完成 scale 0，才在清理自身探针后释放锁；先回读 UID 与 operation ID，再发送带相同 UID precondition 的 DELETE，绝不删除同名替换锁。

进程崩溃、清理失败或 CLOSED 无法确认时保留锁。恢复必须由操作员先核实旧执行进程及其子进程已停止、集群和维护状态，再检查锁的真实 UID、operation ID 与 plan 摘要，按该 UID precondition 人工删除；仅凭锁年龄不能判断旧执行者已退出。随后使用同一审阅 plan 和新的证据目录执行维护。不要对锁使用 `apply`、`replace`、无条件删除或超时接管。

`maintain` 首先安装批准镜像策略，实际验证批准 Pod 可接受、错误摘要/普通 sidecar/init/Pod UPDATE/ephemeral containers 被拒绝。ephemeral containers 在所有批准 writer 上一律禁止。准入探针没有 token、绑定不存在的节点，不运行被测镜像，核对真实 UID 后删除。

随后策略切换为 CLOSED，实际验证批准镜像也不能创建。目标 writer 全部 scale 0；确认真实 writer Pod 为零、九种 runtime LOGIN 在准确数据库中的会话为零，及 operation、node-fence、automation claim/run 活动租约为零，才执行正常 owner 迁移。进程标签、客户端 GUC、等待固定秒数或 SQL TTL 均不能替代这些观察。

迁移成功后，普通应用预检须实际退出成功。仍处于 CLOSED 时更新全部目标镜像；然后重新安装与回读批准策略、重复真实准入矩阵，核对没有 writer 提前回来，再恢复计划中的副本数并等待实际 rollout 成功。批准策略持续存在，旧摘要的 Pod 重启仍被拒绝。

任何维护阶段失败都尝试再次安装 CLOSED 并 scale 0，证据明确记录 `FAIL` 与 `maintenance_left_closed`。连接故障使封闭状态不能确认时标记 `UNCONFIRMED`，不会声称安全完成。不会自动恢复旧镜像、回退数据库、修改迁移 checksum 或释放任何计算配额。修复依赖后可以使用**同一 plan、新证据目录**重新执行维护；已关闭的策略在迁移和预检前保持关闭。

迁移、普通应用预检、批准准入与实际 rollout 已完成后，最终探针或操作锁清理若失败，回执使用独立状态 `COMPLETED_WITH_CLEANUP_FAILURE`、记录 `completed_action`，命令退出码为 2。此状态表示已完成的维护需要人工收尾，不能当作迁移失败或完整 PASS。尤其是锁 DELETE 的响应丢失时，锁可能已删除且下一操作者已取得新锁；本进程不会在未持锁时再次封闭或修改 writer。操作员须检查真实锁 UID、当前维护状态及执行进程后处理，禁止自动抢锁或按失败状态盲目回退。

观察使用真实 `psql`（必须预安装）和显式 libpq 环境字段，不把 URI 放入 `PGDATABASE` 假设它自动展开；继承的 PG 配置会清除。证据仅含固定阶段、plan 摘要和观察结果；子进程原始输出、数据库 URL 与密码不写入回执。保留证据目录权限 0700/0600。真实备份恢复演练、外部流量摘除、运维审批、签名发行与现网权限仍是发布方的职责；此脚本不会自报这些事实已经完成。

## 本地真实 Docker 验收

`scripts/test-resource-upgrade-admission.py` 只接受本地 Unix Docker socket，在全新随机命名容器中启动固定 K3s v1.36.4 控制面；不会读取用户 Kubernetes context 或选择已有数据库。所用 ARM64 单文件 SHA256 为 `c920706346d5ad4e5cd3c7bf1bb09ce71ebe07fec829e513e40f1caf98aed8bb`，来自[官方固定发行](https://github.com/k3s-io/k3s/releases/tag/v1.36.4%2Bk3s1)资产 digest；基础镜像复用本机已有 `alpine@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507`。下载内容必须与官方 digest 逐字一致。

```sh
df -h .
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s deploy/resource-accounting-upgrade/tests -v
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-resource-upgrade-admission.py \
  --k3s-arm64 /secure/k3s-arm64 \
  --evidence-dir "$PWD/.local/resource-upgrade-admission-new"
```

该矩阵先验证无策略时真实旧 image 被接纳，再通过相同 API 验证安装策略后的拒绝；覆盖普通/初始化 container、sidecar、Pod UPDATE、ephemeral containers、非 writer 不误封及精确 spec 防篡改。随后使用真实 Deployment/StatefulSet 验证维护失败仍保持 CLOSED 与零副本。单独的无 agent 矩阵不证明数据库迁移、普通应用预检、真实 workload 恢复、Kata/GPU 或公有云认证；完整维护切换必须另运行带实际节点、TLS PostgreSQL 和本次普通 `sandboxd` 的验收。

Docker 夹具在发出 run 前确定随机名称。即使 CLI 超时、没有取得容器 ID，也按该名称回读真实 ID 与精确 ownership label 后清理；身份不符或 Docker 不可查询会记录清理 `UNCONFIRMED`，不会报告清理成功。真实矩阵同时覆盖丢失 run 回执后的恢复清理、操作锁冲突和 UID 删除；单元回归覆盖 Docker 查询超时及成功 rollout 后丢失锁 DELETE 回执。

机制依据为 [Kubernetes ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) 与 [K3s 容器运行说明](https://docs.k3s.io/advanced)。本地控制面只用于准入/编排验收，不能作为产品集群拓扑或生产 HA 部署。
