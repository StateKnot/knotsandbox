# 沙箱运行时、执行通道与上线运维设计复核

日期：2026-10-03。供主开发方案合并；本文件是设计和官方文档核实，不是已经通过目标云环境测试的证据。采用 Ponytail：复用 Kubernetes、containerd、Kata、CNI、CSI 和备份产品，不写调度器、VMM、存储引擎或常驻执行 Agent。

## 1 最终建议与云落地裁决

主线保持 **阿里云弹性裸金属工作节点 + 自管 Kubernetes/containerd + 上游 Kata + Cilium**。Kubernetes 用锁版本的 Kubespray 安装维护；IaC 创建 VPC、子网、安全组、节点和负载均衡。控制节点及普通平台工作节点可用普通 ECS，不需要 KVM。只为非可信负载节点采购并验证裸金属 KVM 能力。数据库、对象存储和密钥服务仍采用云托管服务。

这是可落地的选择，但不是阿里云代运维的全栈 ACK 产品：etcd、集群升级、Kata、CNI、CSI 的兼容与值班归本团队。至少配置 3 个控制节点，分别位于 3 个故障域；平台服务节点与非可信工作节点独立。首期只交付这个运行时，不同时实现 ACK runV 适配。

事实依据：阿里云裸金属官方说明支持嵌套虚拟化；Kubespray 官方支持裸机和 HA；Cilium 官方有 Kata 集成路径及已知限制；阿里云 CSI 开源项目提供手工 Helm 安装路径和快照能力。上述组合没有发现明确禁止部署的产品限制，但组合测试仍是上线门槛。[阿里云裸金属](https://www.alibabacloud.com/help/en/ecs/user-guide/elastic-bare-metal-server-overview)、[Kubespray](https://github.com/kubernetes-sigs/kubespray)、[Cilium 与 Kata](https://docs.cilium.io/en/stable/network/kubernetes/kata/)、[阿里云 CSI](https://github.com/kubernetes-sigs/alibaba-cloud-csi-driver)

### 为什么当前不把 ACK runV 作为默认

ACK 的官方沙箱节点池可用，不应误写成不支持：2026-08-11 文档给出的范围为 Kubernetes 1.16–1.34、裸金属节点、1.30 及以后使用 Alibaba Cloud Linux 3、不支持自定义镜像、Terway 不支持独占 ENI 和 DataPath V2。它是官方 runV，不是上游 Kata 的直接同义词。[ACK 沙箱节点池限制](https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/node-pool-management-in-sandboxed-containers)

真正的问题是恶意多租户必需的网络策略：Terway 新集群网络策略默认路径与 DataPath V2 存在版本关联，官方不同专页的版本界线还不一致；不能自行推断关闭 DataPath V2 就能得到受支持的完整隔离方案。ACK 还明确不支持另装第三方 CNI，也仅支持标准 Kubernetes NetworkPolicy。未获得当前受支持组合并实测前，不能写一个看似完整但会冲突的 ACK + runV + Cilium 部署清单。[Terway](https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/work-with-terway)、[ACK 网络策略](https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/use-network-policies)、[ACK 网络 FAQ](https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/faq-about-container-networks)

若未来云方确认符合本平台隔离、元数据封锁、规模和备份要求的 ACK 托管组合，再做单独 ADR 与适配；不为等它停下当前生产实现。

## 2 最少必需组件

自研只保留 `api`、`worker`、`session-gateway` 三个部署角色，同一个 Rust workspace；另有一个模板内的一次性 `sandbox-runner` 二进制，它没有监听端口、数据库、RPC、服务发现或升级控制器。

基础设施包括 Kubernetes/etcd、containerd/Kata、Cilium、CSI/snapshot-controller、受控出口代理、HA PostgreSQL、对象存储、KMS、指标日志平台，以及选定的一个备份实现。已有 OIDC 服务继续负责身份签发；不自建 IdP。

首期不做：自研节点 daemon、进程内存迁移、直接访问 containerd socket、租户 Kubernetes API、通用运行时插件市场、自研增量备份格式、自动跨地域故障切换。业务微服务只调用平台 HTTPS API。

## 3 OCI 模板与 Pod 固定契约

模板必须经过平台发布，不接受创建实例时传任意 Pod YAML。镜像 digest、CPU/内存规格、工作区路径、runner 协议版本、许可出站 profile 和支持能力都写入不可变模板版本。用户需要新依赖，通过模板构建或工作区内无特权包安装完成，不在正在运行的实例里开放宿主 Docker。

每实例固定 1 个 Kata Pod/VM、1 个用户容器、1 个持久工作卷。用户程序非 root；禁止 privileged、hostPID/IPC/network、hostPath、设备透传、额外 capabilities、任意 init/sidecar、任意 annotation 和 ServiceAccount。`automountServiceAccountToken=false`，关闭 service links，`allowPrivilegeEscalation=false`、drop ALL、只读 rootfs，设置经过 Kata 验证的 seccomp 配置。工作节点只允许指定 RuntimeClass；缺失运行时导致失败，不回落 runc。

PID 1 使用固定的成熟 init 加固定等待进程，负责信号和子进程回收；entrypoint 由平台固定。模板在 `/usr/local/bin` 内置只读 runner；`/workspace` 是唯一持久用户目录，`/tmp`、`/run` 是有额度的临时卷，Python venv、npm cache 等定向到工作区。容器重建不保留 rootfs 可写层和进程状态。`restartPolicy: Never`，业务控制器决定何时生成新一代 Pod，避免 kubelet 自动重启造成执行语义混乱。

Pod readiness 只声明运行通道、卷和策略就绪，不使用租户 HTTP 服务返回码来证明安全。实例 `RUNNING` 还需满足：调度到允许池、RuntimeClass 正确、卷已挂载、策略版本已观测、控制执行探测通过。用户应用健康单独显示。

资源约束同时覆盖容器 requests/limits、RuntimeClass overhead、临时磁盘、PID 数、会话数、输出量、命令时长、出口流量、卷数与存储配额。宿主 QEMU/Kata 总开销单独监控；不能只看 guest 内的 `free`。

## 4 Kubernetes 权限和执行通道

`api` 不持有 Kubernetes 写权限；`worker` 有指定工作 Namespace 的受限资源权限；网关只获得执行/读取所需子资源权限。平台命名空间和备份命名空间凭据均不进入沙箱。控制器不接受租户提交的 namespace、pod name、container name、IP、CRI ID；全部通过数据库实例映射推导并验证 `tenant_id/project_id/instance_id/generation/pod_uid`。

执行链为：调用方 → API 鉴权/配额/审计入库 → worker → Kubernetes `pods/exec` → kubelet/containerd/Kata → 一次性 runner → 用户 argv。不通过 shell 拼接命令；`argv` 是数组。确实需要脚本时，显式选择模板解释器和已上传的脚本。敏感输入走 exec stdin 的有界结构化请求，避免出现在 Kubernetes exec URL query、审计和进程列表中。

`kube-rs AttachedProcess` 提供 stdin/stdout/stderr、status 与 join；它只是远端进程流连接，不能把 join 成功解释为业务任务恰好执行一次。[kube-rs AttachedProcess](https://docs.rs/kube/latest/kube/api/struct.AttachedProcess.html)

### 异步 execute 的可实现语义

1. API 同事务提交 execution、operation、幂等键、配额和受理审计；202 返回 execution ID。首期每实例最多 1 个非交互 execution，交互会话与其互斥。需要并行计算时调用方创建多个实例。
2. worker 领取带租约的执行记录，在发出 exec 之前持久写入 `DISPATCHING`、attempt ID、pod UID、instance generation、截止时间与请求摘要。禁止发了命令之后才记录。
3. runner 读取 stdin 请求，检查版本、大小、路径、环境变量名、argv 数量，设置 cwd、env、rlimit、进程组和合作式定时器；输出通过 stdout/stderr 单独通道返回，TTY 只用于交互会话。
4. 控制面按 sequence/stream/offset 写有界输出分块到对象存储，元数据保存已持久 offset、SHA-256、丢失/截断标志。只有已经持久的块才发给可重连输出 API；避免客户看过的输出重新读取时消失。
5. 正常收到退出状态并完成对象存储提交后，写终态、退出码、原因、完整性标志和审计。退出码 0 只说明命令协议返回成功，不说明任意业务副作用正确。
6. worker 崩溃、exec 断链、节点隔离或状态发送结果不明时，记录 `OUTCOME_UNKNOWN`，冻结该实例新的执行。允许重新接管观测和停止，禁止自动重发非幂等命令。落盘回执只能作为 `guest_reported` 证据，不能据此提升为平台确认成功。
7. 只有在请求确定未发出时，才可安全重试派发；一旦请求可能被 kubelet 接受，即使没有收到首字节，也进入“不重放”路径。API 幂等键去重的是提交，不提供任意外部副作用 exactly-once。

### runner 的边界

runner 可以提供进程组终止、输出限额、命令级本地超时及本地回执，便于一般工作负载。但它与恶意命令处于同一 guest，同 UID 命令可能杀掉 runner、fork/setsid 脱离进程组或篡改工作区回执。只读二进制不等于 runner 不可被终止；随机文件名不等于权威存储。禁止引入一个隐藏的“永远可信 guest 回执”假设。

因此，**强超时/强取消以整个实例 Pod/VM 终止为完成条件**。命令取消先尝试合作式信号，再在宽限期后将实例转 `STOPPING`，撤销会话和端口路由，销毁整 Pod，保留工作卷。API 显式包含 `termination_scope: instance`；正常结束、业务失败、超时、请求取消、结果不明、已确认终止是分别可判断的字段。`cancel accepted` 不等于进程已经停止；控制面/节点分区期间只能报告 `TERMINATION_PENDING`，直至运行时确认或云侧 fencing 完成。

这一契约适合微服务调用。若业务要求“一份持久交互环境内并行运行互不影响的恶意任务，并能严格单独杀死其中一个”，需要每任务独立 VM/Pod 或受信 supervisor/cgroup 管理；它不是给 runner 多写几行 signal 代码就能保证的能力。首期不承诺此语义。

## 5 生命周期、删除与单写者

实例期望状态只由 PostgreSQL 操作引擎持有；Kubernetes 保存运行资源和观测状态。资源名由实例 ID 与 generation 决定，create 返回超时后先 GET 同名资源并核对 UID/spec hash，不再次生成随机资源。

| 操作 | 顺序与提交点 | 出错后恢复 |
| --- | --- | --- |
| create/start | 配额预留 → 安全策略/Namespace → PVC → Pod → 观测就绪 → 发布路由 → RUNNING | 保留已创建资源 ID；watch + 定时列举收敛；不因一个超时重复创建卷 |
| stop | 拒绝新命令 → 撤路由/凭证 → 取消执行 → 删除 Pod → 确认终止/卷卸载 → STOPPED | 终止未知不报 STOPPED；保留 PVC/备份 |
| restart | 完整 stop → generation++ → 新 Pod 挂同卷 | 旧 Pod 或节点未 fenced，禁止新写者 |
| destroy | tombstone → stop → 根据已提交 retention 决定卷保留/删除 → 等云资源删除确认 → 释放配额 | 数据卷默认 retain；卷删除是独立显式操作，记录云盘 ID |
| restore | 备份校验 → 新实例、新卷、隔离策略 → 数据校验 → 运行验证 → 授权切换 | 原实例和卷不原地覆盖；失败资源留作受限诊断后清理 |

PVC 不给运行 Pod 设置 ownerReference，防止 Pod GC 删除工作区。销毁不等于删除备份。云盘、快照、临时导出卷和对象存储前缀都有数据库资源账本、owner 标签、生成号、创建操作 ID；垃圾收集器仅在账本确认可删除且超过保护期时删除。

Kubernetes `ReadWriteOnce` 限制节点，不天然限制同节点只挂一个 Pod；`ReadWriteOncePod` 还依赖 CSI 支持。当前阿里云 CSI 主文档只列云盘 RWO，因此生产设计必须以 RWO 为已知基线，不能未经验证宣称 RWOP。业务锁、UID 前置条件、准入策略、资源唯一约束负责同节点单 Pod；云侧 fencing 负责故障旧节点不再写。[Kubernetes 持久卷访问模式](https://kubernetes.io/docs/concepts/storage/persistent-volumes/)

数据库 fencing token 无法直接使既有磁盘写入失效。节点失联时的正确流程是：隔离新流量 → 核对 ECS 实例身份 → 调云 API 停止故障节点并确认关机，或使用已经验收的存储侧撤权 → 确认无旧写者 → 允许云盘 detach/reattach → 创建下一代 Pod。节点恢复后先隔离对账，不能直接恢复接单。自动 fencing 需要专用最小权限身份，只可操作平台标签下节点，且操作有幂等账本。只有 cloud API 超时或 Node NotReady 时不得假设已 fenced。

Kubernetes 强删 Pod 只删除 API 对象，可能留下运行进程，不作为 fencing 证据。[Kubernetes Pod 删除语义](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_delete/)

## 6 网络、元数据和文件传输

Cilium 使用自管集群受控安装；首期保留 kube-proxy，不使用 ClusterMesh、租户直连 BGP 或复杂服务网格。建议 VXLAN 模式和经过实测的保守 MTU；需覆盖大包、TLS、大文件、同节点/跨节点、DNS/TCP/UDP。官方 Kata 文档指出内外网命名空间的 route MTU 传播差异；若启用 socket LB，需 `socketLB.hostNamespaceOnly=true`。为保持租户 Pod 无 NET_ADMIN，首期用经过测量的全局保守 MTU，接受其吞吐代价；不偷偷给租户 init 容器提权。

每项目 Namespace 默认 deny ingress/egress；只允许网关进入已授权端口，工作负载只到受控 DNS 和出口代理。出口代理默认拒绝私网、链路本地、云元数据、集群服务、控制数据库与节点管理地址；代理自身的 upstream 也不能访问这些地址。域名允许规则需防 DNS 重绑定，连接时重新验证最终地址。企业内网 API 若需被沙箱访问，必须显式登记具体目的服务，不开放整个 RFC1918。

仅设置 HTTP_PROXY 不是强制代理。CNI/宿主规则必须拦截直接 TCP/UDP、IPv6、DoH 绕路和 metadata 地址；未验收 IPv6 时全层禁用并回归。普通 NetworkPolicy 对同宿主和节点流量的边界不足以证明隔离，使用 Cilium 明确的 host firewall/host traffic 策略和云安全组组合，逐条验证 kubelet、API server、etcd、CSI、节点 SSH、169.254/metadata 地址以及同节点租户互访。策略未到位前不得进入 RUNNING。

非可信工作节点不附加数据库、备份、fencing 或对象存储广泛 RAM 角色；不能依赖“guest 正常不会访问元数据”。CSI 控制器和备份任务的云权限限于平台资源作用域，凭据仅存受控命名空间；宿主 metadata 访问也必须最小化并监控。产品调用方的 OIDC token 不转交给沙箱；需要云能力时发任务范围、短期、最小权限凭证，默认无任何云凭据。

文件上传先到受限对象前缀（短期签名、Content-Length 上限、校验哈希），校验通过后由网关通过 exec stdin 送入一次性 helper，落到 `/workspace`。文件下载反向流式复制到服务端或对象存储。首期文件 API 不直接解压任意 tar，也不用 shell 拼接 `kubectl cp`；单文件 API 做路径长度、总字节数、相对路径、安全打开与符号链接检查。Linux helper 用目录 fd 为根的 `openat2`/等价安全解析防 `..`、symlink 和 TOCTOU；上传临时文件写完并 fsync 后 rename。文件数据始终视为非可信；平台文件写入完成不保证用户进程随后未改写。

## 7 工作区备份与恢复

不能把“Velero 的资源 YAML 存到 OSS”称为工作区数据备份。备份产品记录必须指明 `storage_mode` 为 `native_snapshot` 或 `exported_data`，并给出实际数据时间点、一致性、所在账号/地域、保留期限、KMS 引用与恢复验证结果。首期默认崩溃一致性；需要更强一致性时采用停机备份，工作负载停止并确认后再取快照，不给非可信租户开放文件系统冻结特权。

可行的通用独立导出路径为 CSI snapshot → 快照派生临时卷 → Velero CSI Snapshot Data Movement/Kopia → 独立对象存储 → 恢复新卷。使用该路径必须验收：选定 CSI snapshot v1、data mover 调度、目标对象插件/认证、KMS、restore StorageClass、uid/gid/mode/xattr/symlink/sparse file 和大目录校验。Velero 完成后通常会清理临时 CSI 快照，因此产品自己的“快照”不能假定沿用该资源。[Velero CSI 数据搬运](https://velero.io/docs/v1.18/csi-snapshot-data-movement/)

阿里云 OSS 的普通 Velero 插件与 Kopia data mover 是不同兼容层，不能因为官方 provider 列表有 AlibabaCloud 就跳过导出链路验证。该 provider 在 Velero 文档中属于社区维护；没有完整恢复实测前，不对外开放 `exported_data` 能力。[Velero Providers](https://velero.io/docs/v1.18/supported-providers/)

选择最短生产路径时，可把首期原生云盘快照作为明确声明的云内备份，再通过经验证的跨账号/地域保留满足灾备目标；对象存储保存 manifest，不谎称存了卷数据。若产品合同要求独立数据副本，data mover 完整恢复是发布阻断项，不能降级。两种模式只选择一个首期主交付路径，由主方案冻结，不同时开发自研导出器。

data mover 读取的是快照派生卷，不挂运行中的原卷。备份节点独立、云账号权限隔离；不把备份容器的 root/宿主挂载权限授给租户。关闭不使用的 Velero fs-backup hostPath；内建 mover 的 root 身份、MountPropagation 和恢复时节点调度限制必须在所选版本上单独验收，不能宣称所有导出/恢复作业永远可在任意独立节点完成。备份储存密码首次初始化即设置并纳入 KMS/灾备；不得直接轮换导致旧库失联。

恢复流程：读取可信 manifest → 校验源权限及当前权限 → 创建新实例和新卷 → 数据搬运 → 独立校验 manifest 中测试对象/数据一致性 → 默认 deny 网络启动 → 标记 `RECOVERABLE` → 经已授权操作切换端点。禁止自动恢复历史计划任务、旧 token、旧外发回调或备份中的旧 Pod YAML 权限配置。模板镜像按 digest 保留，镜像仓库删除受备份引用保护。

## 8 部署、版本、发布和回滚

交付包至少包括：Terraform/OpenTofu 云资源声明、Kubespray 固定 inventory/config、完整 versions.lock、Helm chart、准入策略、RBAC、CNI/CSI 配置、监控告警、数据库迁移、备份策略与可运行验收作业。禁止 Helm 中默认 latest 或现场 curl 主分支脚本；镜像、Kata guest kernel/rootfs、QEMU、host kernel、CSI sidecars 都锁定 digest/版本。

安装顺序为云网络与最小权限 → 节点与内核/KVM验收 → Kubernetes/etcd → Cilium/CSI/RuntimeClass → 存储快照和故障测试 → 平台数据库/密钥/观测 → 平台服务 → OIDC 及微服务接入 → 全链验收 → 接入生产租户。Pod 云盘拓扑采用 WaitForFirstConsumer，不能先等 PVC Bound 再创建消费者 Pod而形成死锁。

平台服务滚动升级前，确认旧新版本能读写同一 schema；数据库采用 expand/contract，破坏性变更分发布批次，运行 schema migration 的单次任务使用迁移锁。worker 不立即杀执行连接：停止领取新任务、迁移可接管工作、等待有界 drain；超出维护窗口进入执行结果不明流程，不重跑命令。网关滚动时 SSE 可用游标续读，PTY 连接可能中断必须在维护语义中说明。

运行时升级走新节点池/镜像，先 1 台 canary、再一故障域、再扩大。旧工作节点停止接单，等实例空闲或按已声明维护规则停机重建；不宣称无损迁移内存。Kata/内核/CNI/CSI 变更需重跑网络、磁盘 fencing 和备份恢复测试。应用回滚只回退 compatible 版本；数据备份格式升级与数据库破坏性迁移有单独恢复方案，不能简单 `helm rollback`。

## 9 故障矩阵与验收

| 故障注入 | 对外状态 | 自动动作 | 不允许的动作/通过标准 |
| --- | --- | --- | --- |
| create 请求超时，Pod 实际已创建 | operation 继续 | 按确定资源名 GET/UID 核对 | 无第二 Pod/第二卷 |
| worker 在 DISPATCHING 后崩溃 | OUTCOME_UNKNOWN | 接管观测，必要时 stop | 不重放可能已执行命令 |
| exec 断链但命令继续运行 | OUTCOME_UNKNOWN/TERMINATION_PENDING | 撤会话，按实例超时销毁 | 不把 socket 关闭等于进程结束 |
| 用户 fork/setsid、kill runner | execution 异常 | 外部截止时间停止整 VM | 不能只发 killpg 后声称成功 |
| PostgreSQL 失联 | 新变更503；现有负载继续 | 停领取/授权签发 | 不使用缓存权限继续敏感变更 |
| Kubernetes API 失联 | observed 状态陈旧 | 重连watch、完整list | 不根据缓存创建重复资源 |
| 工作节点网络分区 | instance UNKNOWN | 云侧fencing后换节点 | 无双写；不能仅强删Pod |
| 旧节点恢复 | QUARANTINED | 云盘/Pod/generation对账 | 不直接重接运行服务 |
| CSI attach超时 | PENDING/RECONCILING | 查询VolumeAttachment/云盘状态 | 不盲目force detach |
| CNI策略未应用 | STARTING/BLOCKED | 阻止发布路由与execute | 漏策略窗口零越权 |
| DNS/出口代理异常 | network unhealthy | 拒绝网络；告警 | 不自动放通直连公网 |
| 输出对象存储不可写 | execution degraded | 有界缓冲后按策略终止/明确丢失 | 不无限占内存，不报完整输出 |
| backup导出失败 | backup FAILED/RETRYING | 有限幂等重试、清理临时卷 | 旧可恢复备份仍可用 |
| restore 数据校验失败 | restore FAILED | 隔离失败实例，保留证据 | 不切生产端点 |
| 所在可用区不可用 | affected instances unavailable | 根据备份手册重建新AZ | 无备用数据/容量就不承诺5分钟恢复 |
| etcd/数据库灾难回滚 | recovery mode | 全量资源与授权对账 | 不复活已删除实例或旧权限 |

上线至少验证 10000 次生命周期循环、并发创建、运行中断电/分区、恶意进程树、文件链接竞态、政策更新窗口、停止后异节点挂盘、备份异集群恢复、升级回滚和持续负载。CPU/内存/IO 指标按来源标识；guest 未暴露可信 IO 时映射云盘指标或返回 unsupported，不返回 0 伪装健康。容量不能只按 CPU 算，必须计入云盘每节点数量、快照临时卷、VM 开销、网络 MTU、Pod/IP 和后台备份吞吐。

## 10 主方案必须冻结的决策

1. 原生云盘快照备份还是要求独立导出数据；若后者，OSS data mover 完整兼容与恢复属于首阶段发布阻断。
2. 业务接受每实例一个非交互任务、强取消停止整个实例；这是首版明确 API 语义，不能藏到故障手册里。
3. 云盘 RWO 的单写者与 cloud fencing 责任由平台承担，不能写“数据库租约足够”或“RWOP天然解决”。
4. 自管 Kubernetes 的升级、etcd 灾备、云侧支持边界、7×24 值班和费用纳入人力排期；不能继续沿用“已有托管集群”预估工期。
5. 精确地域/可用区、裸金属库存、KVM、云盘配额和版本矩阵在正式开工早期固定；不把调研时主分支示例当生产部署包。
