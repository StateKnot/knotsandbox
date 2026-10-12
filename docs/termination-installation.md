# 独立实例终止控制器安装

生产安装入口是 `deploy/termination/prepare.py` 与 `render.py`。prepare 绑定实际 Terraform outputs、正常节点登记回执、当前 Kubernetes Node 和 Cilium 远端身份观察；render 分别生成身份/RBAC与运行清单。它们不连接云或 Kubernetes、不生成证书/口令、不执行 apply，也不激活未认证的 Kata 运行时。

运行进程为 `/usr/local/bin/sandboxd --role termination`。它消费持久终止账本，使用独立 `sandbox_termination` 数据库角色和节点守护 mTLS 客户端身份。计算 DELETE 保留工作区；Pod消失、Node NotReady、节点 cordon、进程退出、租约过期或 Kubernetes DELETE 返回成功均不能证明 VM 已死，也不能释放 writer/计算配额。关闭证明仍由当前 epoch、NodeUID/boot/profile、固定活动身份和节点守护协议共同核验；见[节点守护协议](nodeguard.md)与[工作区销毁协议](workspace-deletion.md)。

## 非秘密设置与资源来源

使用 `deploy/cluster/requirements.lock.txt` 锁定的 Python 环境；`cluster.py prepare` 仅下载并核对锁定的官方制品，不安装集群。离线验收需已准备的 Kubernetes schema缓存与已提交的 Cilium CRD，缺缓存或摘要不符会失败。

```sh
python3.12 -m venv .local/cluster-venv
.local/cluster-venv/bin/python -m pip install --require-hashes -r deploy/cluster/requirements.lock.txt
.local/cluster-venv/bin/python deploy/cluster/cluster.py prepare
```

设置文件为严格 JSON，必须恰好包含以下字段：

| 字段 | 约束及来源 |
|---|---|
| `schema_version` | 整数 `1` |
| `image` | 经过发布审阅、扫描、验签的 service OCI digest；必须为 registry 路径加 `@sha256:`。格式校验不代表发布审核通过 |
| `replicas` | 2..8；实际平台池处于同地域三个 AZ，能够均衡容纳副本加一个 surge，每副本使用不同主机 |
| `database` | `{secret:{name,key},ca_pem}`；仅 Secret引用和公开 RDS CA，不接受手填 endpoint、URL、用户或口令 |
| `nodeguard` | `{identity_secret:{name,key},server_ca_pem}`；独立 mTLS identity Secret引用和公开节点守护服务端 CA，不能复用数据库 Secret |
| `certification_id` | 实际受审阅的部署认证引用；不由安装器产生 |
| `projects` | 1..128项已登记的 `{tenant_id,project_id,namespace}`；规范非零 UUID，project/namespace唯一，不接受 default、sandbox-system、kube-*或sandbox-*控制 namespace |
| `concurrency` | 1..16个终止调谐任务 |
| `db_max_connections` | `concurrency+4`..64；同时受 RDS总体连接预算约束 |

`terraform-output.json` 必须是本部署真实 `terraform output -json` 的非敏感输出，包含现有 `infra/alicloud` 的完整输出集合。安装器支持全部输出均为 Terraform `{value,sensitive:false,type}` wrapper 或全部解包，拒绝两种形状混用。数据库只从 PostgreSQL 17 RDS输出读取外部 FQDN/5432；平台主机、Kata节点、账号、region、deployment、environment均取自 outputs。不消费 RAM role、STS或工作负载云身份。

`enrollments.json` 是正常 `sandbox-admin enroll-node --apply` 返回的回执 JSON数组，必须覆盖 outputs中全部 Kata节点，不能使用手写 INSERT或仅包含成功子集。每项是现有完整回执：`protocol,enrollment_id,runtime_node_id,node,cloud_account_id,region,cloud_instance_id,private_ip,guard_port,certification_id,certification_report_sha256,artifact_sha256,terraform_output_sha256,registered_at,changed,enabled`。`node` 包含 `cluster_epoch,node_uid,node_name,boot_id,profile_sha256`，节点、云实例、地址和回执身份均唯一，端口固定9444，enabled必须为true。

保留登记所使用的原始 Terraform文件；回执里的 `terraform_output_sha256` 必须匹配该文件的精确字节，重新编码同一 JSON对象会改变摘要。先对每个节点运行既有 `deploy/nodeguard/nodeguard.py verify-enrollment`，核对真实宿主安装 artifact、报告、settings与回执；详见[受控节点登记](node-enrollment.md)。这些文件/摘要约束输入来源与一致性，不能替代实时数据库登记、独立报告审批或 VM关闭证明。启动前应通过有权的管理身份核对 `platform_configuration.control_epoch` 以及当前 enabled节点登记；历史回执的 enabled字段不代表当前仍 enabled。

## 当前网络身份观察

`cluster-observation.json` 必须恰好包含 `observed_at,cilium_config,nodes,remote_identities`：

- `observed_at` 为完成本轮全部读取后的 UTC时间，prepare要求距今最多5分钟且不能在未来。
- `cilium_config` 为真实 `kube-system/cilium-config` 的完整 v1 ConfigMap，保留 resourceVersion。必须实际读取到 `enable-policy=always`、`enable-node-selector-labels=true`、`policy-default-local-cluster=true`及准确 `cluster-name`；缺失或未知配置拒绝。安装器不会修改全局 Cilium配置。
- `nodes` 为当前 v1 NodeList，保留 UID、resourceVersion、labels、spec、status。所有审阅平台节点必须 Ready、未 cordon、未删除且无 NoSchedule/NoExecute taint；节点标签、AZ和 InternalIP必须与 outputs一致。Kata节点必须绑定当前 NodeUID、bootID、profile注解和私网地址，但允许 NotReady、cordon或故障 taint，继续保留控制通路。
- `remote_identities` 为每个审阅平台主机观察到的每个 Kata私网地址的实际 Cilium IPCache→security identity记录，完整覆盖平台×Kata笛卡尔积。每项严格为 `{source_node,node_name,private_ip,identity_id,labels}`；`labels` 是实际 security labels的字符串映射，不能直接复制 Node.metadata.labels。

每个远端身份的 identity ID必须在 `0x02000001..0x02ffffff`：高8位为 remote-node作用域，低24位为非零分配器ID。全局、CIDR、未知作用域或零分配器ID均拒绝；范围依据固定[Cilium1.20.2身份定义](https://github.com/cilium/cilium/blob/v1.20.2/pkg/identity/numericidentity.go)。以下实际标签也必须齐全，缺失、过滤、错误source、远端集群或本地主机身份都会拒绝：`reserved:remote-node=""`、`node:kubernetes.io/hostname=<实际主机>`、`node:sandbox.platform/node-pool=kata`、`node:topology.kubernetes.io/zone=<实际AZ>`、`k8s:io.cilium.k8s.policy.cluster=<实际cluster-name>`。这是 Cilium1.20.2的节点标签 source与本集群作用域，不是普通 Pod的 `k8s:` 节点标签。

由有权的安装管理员，在每个审阅平台节点上的真实 Cilium agent读取 [`cilium-dbg bpf ipcache list -o json`](https://docs.cilium.io/en/stable/cmdref/cilium-dbg_bpf_ipcache_list/) 和 [`cilium-dbg identity list -o json`](https://docs.cilium.io/en/stable/cmdref/cilium-dbg_identity_list/)，按实际私网地址和身份 ID关联上述字段，保留原始输出、源agent Pod UID、执行节点、读取时间与转换审阅记录。终止控制器的 ServiceAccount不获得 exec或Cilium管理权限。不能从另一台节点的缓存推断全部平台节点已经收敛。

该观察文件是受保护的管理员输入，安装器仅交叉核验它，并不认证 JSON本身的真实性或提供原子集群快照。两次现场读取必须核对当前对象/身份是否变化；发生变化需重新准备。prepare输出保留三份输入的精确摘要，render要求观察仍在15分钟窗口内；摘要只用于审阅绑定，不是数据包级隔离认证。首次安装身份、绑定准入可能超过窗口，此时必须重新读取、prepare与render。

## 生成与凭据安装

```sh
.local/cluster-venv/bin/python deploy/termination/prepare.py \
  --settings /absolute/reviewed/termination-settings.json \
  --terraform-output /absolute/reviewed/terraform-output.json \
  --enrollments /absolute/reviewed/enrollments.json \
  --cluster-observation /absolute/reviewed/cluster-observation.json \
  --output /absolute/reviewed/termination-input.json
.local/cluster-venv/bin/python deploy/termination/render.py \
  --input /absolute/reviewed/termination-input.json \
  --identity-out /absolute/reviewed/termination-identity.json \
  --workload-out /absolute/reviewed/termination-workload.json
```

输出仅创建，不覆盖。输入文件必须为当前用户或root所有、不可由group/other写入、无特殊权限的普通文件；非阻塞打开后核验文件描述符，拒绝叶子链接、FIFO、目录、重复 JSON键和非有限数字。设置/准备输入最多256KiB，Terraform、回执和观察各最多1MiB；秘密不进入这些文件。CA须为当前有效公开 CA证书，拒绝私钥与不正确的 CA属性。

DBA应用正式迁移和 `scripts/sql/termination-role.sql`，用秘密管理系统创建引用的数据库 Secret。URL必须为真实输出 RDS endpoint:5432、用户 `sandbox_termination`，并使用 `sslmode=verify-full&sslrootcert=/etc/sandbox-termination-trust/db-ca.pem`。启动过程检查共享严格 URL规则、实际数据库角色与正式迁移。安装器不读取 Secret，运维须检查 URL endpoint与outputs精确一致；不得设置 insecure/skip-TLS或通过本地回环开发例外上线。

独立 nodeguard identity Secret的指定 key为单个 PEM，包含真实客户端证书链和对应私钥，最多64KiB。签发者为宿主 nodeguard专用控制客户端 CA，禁止拿API/租户/节点服务端证书替代，不把 CA私钥放入 Secret。服务端 CA与客户端签发 CA独立；安装器不读取 Secret，因此需要秘密管理系统和目标环境验证证书用途、链、期限、匹配私钥及陌生签发者拒绝。DB和guard公开 CA以不可变、摘要命名的 ConfigMap安装。

容器固定UID/GID/fsGroup10001，只读根文件系统、RuntimeDefault seccomp、禁止提权并drop ALL。投射的Secret/ConfigMap按 root:10001、0440读取，无root init、chown或复制。实际Rust凭据读取支持投射链接，但必须是绝对路径、已打开后核验的普通文件，非阻塞拒绝FIFO等特殊文件，且每文件非空≤64KiB；私钥文件仅允许当前用户/root的0400/0600，或root所有、精确进程非零primary GID的0440。补充组、0640、group/world写入或公开可读不满足该授权。

只显式投射一份3600秒 Kubernetes API token与API CA/namespace到原生 in-cluster路径，关闭自动挂载；没有STS audience、RAM角色、云凭据、宿主目录或任意互联网出口。数据库URL通过Secret引用进入环境，nodeguard身份仅来自只读文件。

## 身份、准入、网络与激活顺序

1. 验证现有全局 fail-closed准入已使用真实 apiserver mTLS，保护原始UID与终止证明，包括精准 finalizer patch。确认项目数据库登记、namespace UID/归属、当前epoch、真实节点登记和独立认证材料。准入停用或未通过目标环境失败测试时不能启动终止控制器。
2. 先审阅并安装 `termination-identity.json`。它只创建SA/RBAC，没有运行Pod，不创建项目namespace、不登记项目。全局只保留必要pods list/PV get/VolumeAttachment list、固定kata-qemu get；namespace get仅限登记项目，node get仅限精确登记Kata名称。项目Role只允许pods get/delete/patch、PVC get及基线原生策略/项目CNP读取，没有Secret、exec、impersonate、PV/PVC delete或云权限。
3. 读取真实 `sandbox-system/sandbox-termination` ServiceAccount UID，把准确username+UID绑定到 AdmissionConfig的 `termination`。配置更新与准入滚动后，实际验证缺证明/陌生UID/任意Pod修改拒绝，精确已证明finalizer删除与UID前提约束成立。不能填写fixture UID，同名重建SA须重新绑定并验收。
4. 准备新鲜观察和输入，先安装 `termination-workload.json` 中的公开不可变ConfigMap与 CNP。CNP边界为 `sandbox.platform/network-policy=termination-v1`，无业务入站；出口仅DNS精确查询DB、真实DB:5432、kube-apiserver:443/6443，以及精确登记Kata节点的TCP9444。使用共享[策略配置预检](policy-boundary.md)读取实际namespace、SA、Pod/CEP身份和全部叠加策略，拒绝额外放行。首次运行Pod不存在时不得虚构CEP来把预检标为PASS；在初始受控启动后立即检查真实端点并保持未认证runtime关闭。
5. 最后安装Deployment/PDB，确认进程以独立真实数据库角色启动，现场检查每个部署平台节点到精确NodeUID对应的mTLS服务连接与错误证书/UID/boot/IP拒绝，确认非登记节点、非9444端口、其他平台组件、租户Pod、元数据IP和互联网被阻断。保留真实数据面结果，并验证默认localhost行为/节点到Pod流量；清单生成和配置重叠PASS不能代替这些测试。
6. 使用已授权、可丢弃的验收实例验证真实终止：包含已启动VM、启动未决/ACK丢失、nodeguard重启、节点失联/NotReady、异步Pod DELETE、CSI/VolumeAttachment未清理和重复调谐。确认UNKNOWN保留活动/配额、原活动仅关闭一次、停止写入之后才发布独立关闭证明，实例计算DELETE保留工作区。通过正式发布/云认证门后才接入生产流量。

[`toNodes` 官方机制](https://docs.cilium.io/en/stable/security/policy/layer3/)要求节点selector功能及本集群作用域配置；节点标签可能被身份过滤器排除，因此prepare检查每台源平台实际remote identity。这里不用节点 `/32` CIDR推断匹配node identity，不改变全局 `policyCIDRMatchMode`，也不以 `host`/`remote-node`加任意端口作替代。标签只约束实际hostname/pool/AZ/cluster；没有伪造NodeUID或bootID网络标签，防止陈旧节点控制请求的最终权威仍是实时数据库和mTLS固定 `<NodeUID>.nodeguard.sandbox.internal`/精确NodeBinding校验。客户端直连登记私网IP，不经DNS、代理、重定向或自动重试。

## 故障、升级与可复验边界

Deployment固定三AZ/hostname spread、每主机一副本、`maxUnavailable=0/maxSurge=1`，PDB为副本数减1；退出留50秒覆盖控制器安全drain。它不监听端口、不生成Service，也没有把TCP探测当作业务健康。Pod Ready/PDB只管理进程调度；须另监控真实队列进展、操作age、租约/重试、UNKNOWN、等待人工复核与固定依赖错误。重启、延长租约或删Pod不能获得VM死亡证明。

Node NotReady/cordon不移除终止出口。节点重启、UID替换、登记禁用、epoch切换或证书失败时控制器拒绝陈旧身份并保留未完成账本。节点维护与重新登记继续走独立fencing流程，不能重用旧登记来恢复enabled。新增Kata节点需新鲜正式登记、RBAC与网络输入审阅；历史潜在活VM的节点不能在UNKNOWN状态被静默排除或先撤掉唯一关闭通路。SA轮换须先验收新UID准入绑定，CA/Secret使用版本化引用，旧信任材料只能在原受控活动安全收尾后撤下。

```sh
CLUSTER_PYTHON="$PWD/.local/cluster-venv/bin/python" bash deploy/termination/check.sh
CLUSTER_PYTHON="$PWD/.local/cluster-venv/bin/python" CARGO_INCREMENTAL=0 \
  cargo test --locked --test termination_deployment --test termination_credentials
```

本地Python检查包含实际prepare/render CLI、三AZ与surge、精确RBAC/网络、错UID/boot/profile/IP/epoch/证据来源、Cilium过滤/跨集群/缺观察、NotReady控制通路、输入FD权限与FIFO，以及额外叠加策略负例。schema_check对锁定摘要的真实Kubernetes/Cilium官方schema验证；Rust专项使用实际Config/NodeguardCredentials构造，fixture明确为公开测试材料，不能安装。当前host文件权限验证不能声称目标Linux projected root:10001/0440已验收；该投射权限、真实Cilium数据包、集群部署和云fencing仍须目标环境证据。此安装包不会伪造认证报告、解除未认证taint或发布云认证PASS。
