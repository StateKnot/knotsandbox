# Rust 企业多租户沙箱：隔离、持久化与故障恢复预研

研究日期：2026-10-03。下述选型为工程判断，官方文档支持的事实与拟验收指标分别标明。本文不代表已完成性能或安全验证。

## 建议结论

首选 **Rust 产品控制面 + Kubernetes + containerd + Kata Containers + 已验证的 CSI 存储**。该组合保留成熟的调度、网络、卷生命周期与节点运维能力，Rust 用于产品 API、状态收敛、任务编排和接入代理。不要重写 CRI、CNI、CSI、VMM 来证明“全 Rust”。

企业多租户执行非可信代码，应将 **一个沙箱实例对应一个 Kata Pod/VM 隔离单元**，不能将不同租户装入同一个 Pod。Namespace 是权限与配额边界之一，不是敌对租户之间完整的安全边界。专用管理节点/集群与不可信计算节点分离，高保证租户提供专用节点池或专属集群选项。[Kubernetes 多租户](https://kubernetes.io/docs/concepts/security/multi-tenancy/)、[Kata 虚拟化设计](https://github.com/kata-containers/kata-containers/blob/main/docs/design/virtualization.md)

| 候选 | 工程优点 | 必须验证的约束 | 结论 |
|---|---|---|---|
| Kata + Kubernetes | 硬件虚拟化隔离；容器接口；可复用 Kubernetes 运维与 CSI | KVM/嵌套虚拟化、hypervisor 与 CPU、CNI/CSI 组合、冷启动与单实例额外内存 | 首选；固定一个经过验证的 hypervisor/backend，避免第一版同时维护多个后端 |
| gVisor + Kubernetes | 用户态内核隔离；便于容器基础设施接入；可选择无需 KVM 的平台 | 系统调用、文件与网络 I/O、浏览器/编译器/原生依赖兼容性；必须实测 | 可作为独立能力等级，不能在 Kata 失败时静默降级 |
| 直接 Firecracker | 提供精简 microVM 与内存快照原语 | 自建宿主调度、网络、磁盘、镜像、快照生命周期、补丁、HA、容量与运维 | 当毫秒恢复是不可放弃的商业指标时才独立评估，不作为首版默认 |

Kubernetes RuntimeClass 可选择运行时并记账 Pod overhead；运行时差异不是 API 兼容性的自动保证。[RuntimeClass](https://kubernetes.io/docs/concepts/containers/runtime-class/)

gVisor 官方明确其 Linux ABI 有已知差异，例如 io_uring、块设备文件系统、部分网络功能；主流语言运行时通常兼容，但这不能替代业务镜像兼容性验收。[应用兼容性](https://gvisor.dev/docs/user_guide/compatibility/)

Firecracker 的生产隔离依赖宿主补丁、KVM、受约束的 VMM 进程和 jailer 等措施，并非“启动一个 VMM 即具备云服务能力”。[生产宿主要求](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md)

## 必须先固定的产品语义

Kata 是 VM 隔离的容器产品基座，不能因此宣称拥有完整 ECS 虚拟机语义。建议将“像 ECS”明确为管理能力与可观测性体验，第一版实例合约为“镜像定义系统环境 + 持久工作卷”。

| 操作 | 对客户承诺 | 实现与限制 |
|---|---|---|
| restart | 工作卷和实例 ID 保留；进程和连接重建 | 不保证 RAM、PID、TCP 或容器根目录临时修改；应明确区分命令进程 restart 与实例 restart |
| stop/start | 停止计算，保留实例规格、卷、策略及稳定访问名称 | 停止后可以删除运行 Pod；启动时由镜像重建并挂载原卷；存储继续计费 |
| pause/resume | 暂停执行，保持原进程状态 | 保留内存等资源；不具备断电持久性，也不应宣传为零成本休眠 |
| hibernate/resume | 持久化内存、设备和磁盘的一致状态后释放计算 | 独立能力；需要专门后端、兼容性与恢复协议；首版不支持时 API 应明确返回不支持 |
| backup/restore | 将指定持久卷及恢复元数据保存到独立备份存储 | 默认无内存和现存连接；恢复到新实例/新卷，通过验证后切换 |

Kubernetes 临时卷跟随 Pod 生命周期。不要用 emptyDir、容器 writable layer 或节点目录承诺 stop/start、迁移和备份后的持久性。[临时卷](https://kubernetes.io/docs/concepts/storage/ephemeral-volumes/)

运行时 apt/pip/npm 安装能否保留需提前明确：持久工作区、虚拟环境可进入持久卷；系统级变化通过镜像构建/模板版本固化。若业务强制要求任意系统盘修改、完整系统管理和系统盘快照，需另开 VM 产品线路并评估 KubeVirt/Firecracker，不应声称当前 Pod 模型天然满足。

Firecracker 官方快照由内存、VM 状态及调用方管理的磁盘文件构成；网络和 vsock 连接不能保证恢复，克隆同一状态还涉及随机数、身份和令牌的唯一性。因此，“恢复快照”不能被描述成“继续所有连接”。[快照约束](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md)

## 安全与可信边界

1. **失败关闭**：RuntimeClass 固定为经验证的 Kata；无 KVM、Kata 不可用、策略未就绪均拒绝调度/对外开放，禁止降级 runc。准入与 API 双层禁止租户覆盖运行时、宿主网络/命名空间、privileged、宿主路径、运行时 socket 和危险设备。
2. **权限在沙箱外裁决**：公共 API 做 tenant/resource/action 鉴权；短期会话凭证绑定租户、实例、generation、操作、到期时间。exec/files/ports 均不能仅凭实例 ID 授权。沙箱不能获得 Kubernetes API token、平台云凭证或备份存储长期密钥。
3. **Agent 分级**：自研工作负载容器内 agent 的心跳、诊断、日志均可能被租户篡改；不能作为资源计费、安全结论、终止完成的唯一证据。Kata 的 kata-agent 属于运行时 TCB，在 guest root environment，而 workload 在 guest 内独立 container environment；两者不是同一个权限边界。仍应假设 guest 被攻破时 host 管理层能撤销网络和销毁 VM。[Kata 架构](https://github.com/kata-containers/kata-containers/blob/main/docs/design/architecture/README.md)
4. **网络在宿主/网关执行**：默认拒绝 ingress/egress；允许明确批准的 DNS 与外部目标；屏蔽节点网段、服务网段、管理网、元数据服务、链路本地、IPv6 等旁路。采用明确支持 host firewall 与出口控制的 CNI，并验证实际包路径。原生 NetworkPolicy 不能覆盖所有宿主、TLS 和强制网关需求。[NetworkPolicy 边界](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
5. **容量攻击有硬约束**：CPU、内存、进程数、磁盘、IOPS、带宽、连接数、镜像大小、并发 exec、日志与快照总量都应有实例和租户限额；日志落盘与备份队列不能反向耗尽控制面。
6. **升级与供给链**：镜像 digest、模板签名/SBOM/扫描，宿主/guest 内核与 runtime 的补丁窗口、节点轮换、紧急隔离和审计留存纳入发布要求。短周期负载有利于排空，长生命周期负载必须定义维护行为。

## 备份不是一个 CSI Snapshot 对象

CSI VolumeSnapshot 是存储后端时间点副本的标准接口，具体持久性和可移植性受驱动与存储限制。独立灾备需要把数据移到不同故障域的对象存储；Velero 的 CSI snapshot data movement 可复用，应锁定稳定版本并验收，而不是自行实现备份数据搬运。[Kubernetes 快照](https://kubernetes.io/docs/concepts/storage/volume-snapshots/)、[Velero CSI 持久性说明](https://velero.io/docs/v1.18/csi/)、[Velero 版本化数据搬运文档](https://velero.io/docs/v1.18/csi-snapshot-data-movement/)

建议备份清单包含：实例规格、镜像 digest/保留策略、工作卷及一致性等级、网络与策略版本、所需密钥引用、校验和、备份软件与格式版本。默认只能承诺崩溃一致性；对数据库等工作负载，采用经验证的 quiesce/应用备份流程并验证恢复。沙箱内 hook 返回成功本身不足以保证恶意工作负载的数据正确性。

验收必须执行异集群恢复，不只看 Backup 状态 Success。备份凭证分权、对象保留/防篡改、恢复授权与数据删除闭环是正式产品的一部分。删除实例不应级联误删被承诺保留的备份。

## Rust 控制面与 HA 收敛

Rust 能覆盖 HTTP API、数据库事务、Kubernetes controller、终端/文件代理、审计流水和计划任务。kube-rs 官方控制器模型要求幂等收敛，并明确 watch 可能丢失/合并事件；不要按“收到一次创建事件就顺序执行到结束”设计。[kube-rs reconcile](https://kube.rs/controllers/reconciler/)

建议 PostgreSQL 为产品 desired state 与 operation 的权威，事务 outbox 发出变更；集群 CR/Pod 是投影与运行态。每个实例只有一个操作执行权，通过 CAS/generation/租约协调，重试沿用 operation ID 和外部幂等键。恢复依据 desired/observed 差异周期扫描，不能依赖消息完整投递。删除使用 tombstone/finalizer 与补偿，直到运行资源、卷策略、入口及会话全部达成目标后完成。

控制器至少两个副本并不自动构成安全 HA。kube-rs 文档明确直接复制正常 Controller 会产生重复工作与竞争，需要 leader lease 或明确分片；该生态的选举/租约实现需专项验收。[kube-rs availability](https://kube.rs/controllers/availability/)

**租约不等于节点 fencing**：网络分区时旧工作负载可能仍运行。不能看到 Node NotReady 就挂载同一写卷到新节点。必须得到旧节点断电/云平台 fence、存储侧独占权已收回等可信证据后才执行写实例恢复。Kubernetes 官方明确强制 detach 的某些情形会造成数据损坏。[节点异常关机与卷拆卸](https://kubernetes.io/docs/concepts/cluster-administration/node-shutdown/)

同 AZ 节点恢复、跨 AZ 故障恢复、跨区域灾备是三个不同服务等级。单 AZ 云盘不能靠改 Pod 调度位置变成跨 AZ HA；要用明确支持该拓扑的复制存储或以备份创建新卷，并分别给出实测 RPO/RTO。ReadWriteOnce/ReadWriteOncePod 可帮助限制挂载，但不能代替失联宿主的硬件/存储 fencing。

## 3–4 周可验收验证计划

这些是评审门槛，不是未经测试的 SLA。团队至少含 Rust/分布式控制、Kubernetes/存储网络、安全测试能力，使用生产目标同类 CPU、KVM 和 CSI 环境。

| 周 | 必须交付的证据 | 不通过时的决策 |
|---|---|---|
| 第 1 周 | 固定版本矩阵；Kata 启动、exec、文件、网络、PVC 联调；镜像兼容性清单；KVM 不可用/运行时缺失时 100% 拒绝运行；记录空闲额外内存和启动时间 | 目标基础设施不提供可用 KVM 或 CSI 组合时调整基础设施；不准 fallback runc |
| 第 2 周 | 选 20–30 个代表性镜像，至少含 Python/Node/Java、编译器、浏览器、原生依赖；跨租户访问、元数据、IPv4/IPv6、权限覆盖、资源耗尽负面测试；1000 次完整创建/停止/启动/删除循环的正确性记录 | 必需镜像不兼容或存在跨租户泄漏为阻断；安全失败不得以性能优势抵消 |
| 第 3 周 | 控制器/API/数据库故障注入；响应丢失后重复请求不重复创建资源；网络分区和旧节点存活时无双写；外部可信终止；并发操作冲突返回可解释结果 | 无法证明 fencing 或幂等时不得承诺自动故障恢复 |
| 第 4 周 | 20 GiB 和 100 GiB 数据集快照、对象备份、异集群恢复、校验和/应用校验；72 小时负载运行；冷/温启动与恢复的 P50/P95/P99；资源曲线与每活跃实例成本 | 只有对象成功状态、没有成功恢复证据则备份功能不准 GA |

可先设定内部性能候选门槛，例如已有容量且镜像预拉取时创建至可执行 P95 ≤ 10 秒、相同环境冷镜像单列指标；此数值是商业目标，需实测决定是否可承诺。不要把 Firecracker 的裸 VM 启动数字替代用户真实的排队、镜像、存储、策略和 agent 就绪耗时。

最终 Go 条件：全部安全负测通过、生命周期语义明确、恢复数据验证通过、故障演练无重复资源/双写、性能与成本有复现记录、版本与升级回滚策略冻结。预研结束交付 ADR、状态机/API 合约、兼容矩阵、威胁模型、恢复操作手册、基准与故障演练报告，再进入正式实现。
