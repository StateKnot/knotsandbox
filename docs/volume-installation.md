# 独立工作区卷销毁控制器安装

生产入口是 `deploy/volume-deleter/prepare.py` 与 `render.py`。前者把非秘密设置与实际 `infra/alicloud` 的 Terraform outputs 绑定，后者生成分开的身份/RBAC清单和运行清单。工具不连接 Kubernetes 或云 API，不生成凭据，不删除云盘，也不自动激活控制器。

此组件只消费已受理的 `DELETE_WORKSPACE` 账本。实例的计算 DELETE 保留数据；租约到期、guest退出、Pod消失、ECS Stopped和 Kubernetes DELETE 成功都不能单独允许卷销毁。实际销毁继续由独立数据库角色、实时授权、保留期/hold、可信 writer 关闭证明、原盘身份、禁止快照级联和 UID 前提约束。见[工作区销毁协议](workspace-deletion.md)。安装生成成功不证明这些云故障验收已通过。

## 输入和真实资源绑定

使用锁定的 Python 环境：

```sh
.local/cluster-venv/bin/python -m pip install --require-hashes -r deploy/cluster/requirements.lock.txt
```

非秘密设置 JSON 必须包含全部字段且不得包含其他字段：

| 字段 | 生产值与约束 |
|---|---|
| `schema_version` | 整数 `1` |
| `image` | 已扫描、验签的 service OCI digest；必须含 registry 与 `@sha256:` |
| `replicas` | 2..8；平台节点必须足以承载同一组件的全部副本加一个滚动 surge |
| `database` | `secret: {name,key}` 与公开 `ca_pem`；不接受自填 host、端口、URL或口令 |
| `storage_class` | 实际认证的工作区 StorageClass；同时绑定 get-only 的唯一 RBAC resourceName |
| `certification_id` | 当前部署的实际认证引用；生成器只验证格式，不产生或认证该引用 |
| `projects` | 1..128个已登记的 `{tenant_id,project_id,namespace}`；非零规范 UUID，project/namespace不得重复，不接受平台或 `kube-*` namespace |
| `concurrency` | 1..16个并发调谐任务 |
| `requests_per_second` | 1..20，共享区域 STS/ECS限速 |
| `max_in_flight` | 1..16，共享云请求并发上限 |
| `db_max_connections` | 至少 `concurrency+2`，至多64；与 RDS总体连接预算一起审核 |

运行设置中的账号、地域、deployment、RAM role ARN/role ID、工作负载 issuer/audience/subject、OIDC provider ARN、workspace KMS key、数据库 endpoint及平台主机名均取自实际 outputs。RAM role必须为本部署的 `volume-deleter`，provider为本部署的 `-kubernetes`，subject固定为 `system:serviceaccount:sandbox-system:sandbox-volume-deleter`，audience固定为 `sts.aliyuncs.com`。不接受 API/CSI/fencing 的身份替代。平台与存储的三个 AZ 必须一致且属于同一区域；偏斜容量无法容纳均衡 surge时拒绝生成。

```sh
.local/cluster-venv/bin/python deploy/volume-deleter/prepare.py \
  --settings /absolute/reviewed/volume-settings.json \
  --terraform-output /absolute/reviewed/terraform-output.json \
  --output /absolute/reviewed/volume-input.json
.local/cluster-venv/bin/python deploy/volume-deleter/render.py \
  --input /absolute/reviewed/volume-input.json \
  --identity-out /absolute/reviewed/volume-identity.json \
  --workload-out /absolute/reviewed/volume-workload.json
```

三个输出文件均仅创建，不覆盖已审阅的版本。输入拒绝重复 JSON 字段、非有限数、未知字段、超过256KiB的文件、可变镜像、跨账号/provider/role、静态 access key、私钥CA和不正确的数据库/namespace边界。Terraform JSON是资源绑定依据，仍必须由运维核对对应的真实账号、部署及当前注册表；伪造 outputs 不会变成云认证证据。

## 凭据和文件权限

DBA应用正式迁移和 `scripts/sql/volume-deleter-role.sql`，创建独立 LOGIN并通过秘密管理系统提供引用的数据库 Secret。URL必须使用 `sandbox_volume_deleter`、真实 RDS数据库、TLS hostname校验和 `sslmode=verify-full&sslrootcert=/etc/sandbox-db/ca.crt`。进程启动检查实际角色与迁移；生成器不会读取 Secret内容，因此安装前另行验证 URL host与 outputs endpoint一致。

容器使用UID/GID10001、只读根文件系统、RuntimeDefault seccomp、禁止提权和drop ALL，不挂载宿主目录。配置与公开DB CA使用不可变、摘要命名的 ConfigMap，变更会更新 Pod模板的配置引用。ConfigMap与 projected token按 root:10001、0440挂载；不通过 shell 或 root init更改权限。Rust配置读取检查实际打开的文件描述符，支持投射ConfigMap的symlink，拒绝相对路径、FIFO/目录、group/world writable或特殊权限、空文件和超过1MiB的内容。

关闭 ServiceAccount token自动挂载，显式投射两份短期 token：区域STS的600秒token仅位于 `/var/run/sandbox-cloud/token`；Kubernetes API的3600秒token不指定STS audience，位于原生 in-cluster路径并带 API CA和namespace。没有存放静态STS凭据的 Secret、通用credential sidecar、宿主nodeguard证书或共享CSI身份。

## 按顺序激活

1. 验证全局准入已有真实 apiserver mTLS、`failurePolicy=Fail`，以及完整 PVC/PV保护规则；验证 worker/CSI不能绕过账本删除受保护卷。准入停用或未经实际故障验收时不能启动此控制器。
2. 核对每个项目的数据库登记、实际 namespace UID/归属/认证及当前 epoch，再安装身份/RBAC清单。清单只有 ServiceAccount和最小权限，尚无运行工作负载。它不创建项目 namespace或登记项目。
3. 获取该 ServiceAccount的真实 UID，将准确username+UID绑定到准入配置的 `volume_deleter`；滚动更新准入并验证错误UID拒绝、精确删除仅在账本允许时成立。不能填写fixture UID或用同名重建 SA替代身份。namespace get仅允许审阅的项目名称，PVC delete仅在对应项目Role内，StorageClass get固定到实际名称；PV DELETE仍需全局Fail准入逐UID与账本核验。
4. 完成真实 projected token→STS→GetCallerIdentity验证，确认只具备部署标签约束的数据盘删除/禁用自动快照级联所需权限。身份不能停止/启动节点、attach/detach、创建快照、删除快照、改标签或管理KMS。
5. 先安装运行清单中的不可变ConfigMap和 CiliumNetworkPolicy，随后在同版本集群上执行共享[策略配置预检](policy-boundary.md)，确认该边界标签排除了宽bootstrap allow。验证实际数据库、区域STS/ECS和Kubernetes API可达，以及未列入域名、元数据IP、其他平台组件、租户Pod与本地主机流量被阻断；配置预检的 `PASS` 只表示配置重叠检查通过。
6. 最后安装 Deployment/PDB，并检查实际队列进展。生产首次删除必须使用已授权、可丢弃的验收工作区；核验原盘ID、保留快照、PVC/PV UID、无writer/VolumeAttachment和配额只结算一次，再投入正常任务。

该进程不监听网络端口，不生成Service，也不把进程存活当作云销毁成功。Deployment的Pod Ready/PDB只管理进程调度；依赖失效时运行循环保留操作和配额，须监控操作age、租约续期、`WAITING_OPERATOR_REVIEW`、云身份/权限固定错误码及实际队列推进。云网络故障不会通过不断重启进程获得删除成功证明。

网络配置只允许精确DNS查询、实际外部DB:5432、区域 `sts.<region>.aliyuncs.com:443`、`ecs.<region>.aliyuncs.com:443`和 kube-apiserver:443/6443，无入站业务规则、world/cluster/元数据/任意CIDR出口。客户端不请求工作负载issuer，issuer公钥由STS服务核验，因此未开放issuer出口。Cilium规则可叠加放行，[官方规则说明](https://docs.cilium.io/en/stable/security/policy/intro/)要求同时检查其他匹配策略；本地主机行为也必须在实际集群验证，不能凭此清单宣称数据包级认证。

## 验证与升级

```sh
CLUSTER_PYTHON="$PWD/.local/cluster-venv/bin/python" bash deploy/volume-deleter/check.sh
CLUSTER_PYTHON="$PWD/.local/cluster-venv/bin/python" CARGO_INCREMENTAL=0 cargo test --locked --test volume_deployment
```

检查使用公开fixture：输入和最小RBAC负例、真实prepare/render CLI、策略重叠分析、官方固定摘要的 Kubernetes/Cilium schema、实际 Rust Config与云identity constructor。它们不请求云API、不销毁资源、不执行apply。已执行的真实数据库与云协议验证另列在[开发进度](implementation-status.md)，真实云盘删除、CSI故障、滚动升级/SA和数据库凭据轮换仍需目标环境验收。

升级保留旧不可变ConfigMap直至旧ReplicaSet完全终止；更换ServiceAccount会改变UID，必须先更新并实际验收准入绑定。数据库凭据和投射token失效不会放宽旧操作的UID/云盘/hold或writer围栏。这里没有统一签名且通过全部发布门的候选，不能把生成器输出视为已经可以上线的产品。
