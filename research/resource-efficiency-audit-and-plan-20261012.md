# KnotSandbox 资源利用率审查与生产开发计划

日期：2026-10-12。目标是在任务正确性、延迟、数据保留和非可信租户隔离达标的前提下，减少 CPU、内存、GPU、存储和节点的无效占用。本文记录**开工前源码审查、官方资料核对和开发拆分**；预研阶段没有新增利用率/GPU实现，也没有进行真实 GPU、目标集群负载或云账单测量。计划登记在[分阶段开发表](rust-sandbox-development-workbreakdown.md)，实现状态登记在[开发进度](../docs/implementation-status.md)。

同日后续实施：G0-08/G3-12已推进首批CPU自身节流、匿名/文件内存和宿主OOM观察，现有接口支持11项固定指标，采集/写入白名单及WAL预算同步扩展。下表保留开工前快照，当前实现与验收以[首批交付记录](resource-observability-delivery-20261012.md)为准；利用率分母、GPU、闲置公开策略、推荐和自动调整仍未交付。

## 1. 开工前结论与证据

当前有“资源用量监控、配额、TTL、安全释放”的基础，尚无完整“发现浪费→推荐→授权调整→核算收益”闭环。GPU 原本不在 CPU 首版范围，目前整个产品链路都未支持；本次将其作为新增交付范围，而不是把已有 CPU 监控改名为 GPU 支持。

| 检查项 | 已有实现 | 实际缺口/证据 |
| --- | --- | --- |
| CPU | VM cgroup CPU 累计计数的固定两分钟速率，返回核数 | 没有预留/limit/有效容量分母、利用率百分比、throttling、压力及规格建议。[定义](../src/metrics.rs#L37)、[查询](../src/metrics.rs#L403) |
| 内存 | `memory.current`，包括缓存 | 没有匿名/文件缓存/可回收分类、OOM/PSI、limit余量与峰值规格画像；低 memory.current 不是直接缩容证明。[读取](../src/nodeguard/host.rs#L576) |
| I/O/任务 | 宿主跨设备字节速率与任务/线程数 | 无 IOPS/延迟/文件系统容量画像；跨设备求和不能直接当计费。[解析](../src/nodeguard/metrics.rs#L45) |
| 配额/规格 | 三种 CPU Flavor；租户和项目双范围预留；Pod requests=limits | 配额是授权容量账，不是实际负载；无小规格、独立比例、有效期规格画像或受控调档。[规格](../src/model.rs#L21)、[配额](../src/db.rs#L515)、[Pod](../src/runtime_manifest.rs#L107) |
| 虚拟化开销 | 接受 RuntimeClass 注入 CPU/内存 overhead | 未把已验证 overhead 数值、宿主 allocatable 和实际 VM 消耗对账，不能只按名义 Flavor 判断浪费。[校验](../src/runtime.rs#L157)、[manifest](../src/runtime_manifest.rs#L249) |
| 回收 | TTL/续租、基于活动槽的 idle STOP、可信 VM 关闭后释放计算配额 | `idle_timeout_seconds` 默认 NULL，当前没有公开 API/Bootstrap 配置入口；idle机制尚不能算可运营功能。[字段](../migrations/0001_core.sql#L169)、[扫描](../src/timers.rs#L83)、[可信释放](../src/termination_ledger.rs#L538) |
| 节点/成本 | 固定节点 IaC；采集链失效/WAL等告警 | 无资源浪费告警、成本归因、装箱画像或节点弹性；现有 deletion_protection/prevent_destroy 不能直接被缩容绕过。[节点](../infra/alicloud/nodes.tf#L1)、[告警](../deploy/observability/alerts.py#L53) |
| GPU | 无产品级实现；当前额外GPU资源被拒绝 | 无 GPU 请求/配额/库存/设备租约/节点池/直通认证/reset回执/指标/API/UI；CRI生成注释不是支持证据。[严格请求](../src/model.rs#L8)、[拒绝案例](../tests/runtime_manifest.rs#L307) |
| 查询安全 | 绑定 tenant/project/instance/launch/generation/epoch/boot，前后鉴权；缺测为null，HA不累加 | 必须扩展并保留这些合同。已有本地/协议证据不能代表目标云容量、GPU或成本验收。[指标合同](../docs/runtime-metrics.md) |

停止后仍被持久卷、备份保护或可信终止要求保留的资源，需要分别归为“数据保留”“安全待确认”“任务/SLO保留”，不能全部标成可直接回收的浪费。当前 VM template/cache 明确禁用，优化方案不擅自改变这条隔离基线。

## 2. 衡量目标与数据合同

主要指标是**单位成功任务总成本**及达到工作负载SLO时的资源占用，而非把每个利用率强推到100%。批处理看成功任务成本、吞吐和排队p95；互动沙箱看启动/响应延迟和保留成本；推理服务看吞吐、尾延迟、显存和OOM。保留已批准的HA最低容量、峰值余量、冷启动预算与保护租约。

| 口径 | 计划采集和计算 | 解释要求 |
| --- | --- | --- |
| 已申请/预留/分配 | 请求与limit、pending/allocated、已验证Pod/runtime overhead、节点allocatable及系统保留，按有效期持久化 | 不混用账务预留、Kubernetes调度与实际消耗。不能用今天的规格作过去launch的分母 |
| CPU | 核数、user/system、throttling、PSI；按一致VM口径计算使用/预留或limit比例，分开显示峰值和p50/p95/p99 | 宿主指标包含VMM/virtiofs开销；分母口径未认证时标UNKNOWN，不制造百分比。不能照Kubernetes Pod配额简单推导guest性能 |
| 内存 | current、anon/file/cache分类、high/max/events、OOM/swap/PSI；容量余量及峰值 | working-set若采用估计必须标记；文件缓存、初始化峰值和脏页不能当成稳定可削减内存 |
| GPU | 分配设备组/物理卡时、GPU-Util、SM/tensor/显存/带宽、功耗/能耗、温度/节流、ECC/Xid；各指标支持矩阵 | GPU-Util不等于算力占比。显存常驻、CPU预处理瓶颈、预热、短核函数与低利用要分开分类，不支持字段为UNSUPPORTED |
| 节点/存储 | 预留占比与真实忙闲、CPU/GPU碎片、调度等待、控制组件/备份开销、卷/输出/备份/镜像的容量和保留原因 | 双副本、host/guest/Pod和设备组不能重复累加；保留数据与临时可清理数据分开 |
| 成本 | 分配时长估算与实际云账单分开；地域/SKU/价格来源/生效时间、节点空闲、磁盘、遥测和冷启动成本 | 有效GPU卡时不等于云计费卡时；释放调度额度不等于已停云费用。没有实际价格/账单时只展示资源时长 |

Kubernetes以request参与调度、CPU limit可能引入节流，不能简单把所有request压低；RuntimeClass overhead参与Pod调度和资源约束。字段读取与版本适用性按锁定组合核对。[资源管理](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)、[1.36 Pod Overhead](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/pod-overhead/)。cgroup内存分类、压力与事件沿内核定义采集，不伪造guest指标。[cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)

每个样本/建议保存来源、采集时间、窗口、覆盖率、设备/资源绑定版本、launch/generation/epoch和置信级别。FRESH/STALE/MISSING沿用，新增UNSUPPORTED及INSUFFICIENT_DATA。建议窗口至少覆盖业务峰值周期；覆盖率与安全余量由G0-08冻结，覆盖不足只读提示，不能自动降规格。guest可影响的GPU遥测即使经mTLS传输，也必须标记为GUEST_OBSERVED，不能单独触发自动STOP/调档，也不能成为设备释放或防篡改消费计费的证明；配置了优化策略或后续会走可信终止链，都不能提升这些样本的可信度。

## 3. 实现技术与架构

复用Rust/Axum、PostgreSQL业务账本、nodeguard身份与终止链、Prometheus固定查询和现有SDK/UI。采集、归属计算、推荐和执行各有小Interface：观测只返回带身份/有效期的固定数据；推荐保存证据与提案；执行只受理现有或新注册的Operation。不给租户任意PromQL、runtimeClass/nodeSelector、设备BDF、CDI或驱动参数。

需要新增/扩展的持久模型是不可变`resource_profiles`、有效期`runtime_resource_bindings`、GPU库存/设备组租约、`optimization_recommendations`和版本化`optimization_policies`。GPU物理UUID/BDF/IOMMU组在管理侧保存，对租户只返回不透明allocation ID与获授权的规格。所有迁移使用更高新版本，补最小角色、复合外键、RLS、状态约束、并发/历史升级与回退策略，不修改已发布迁移字节。

下列接口为**拟开发合同，不是已发布API**：

| 接口族 | 计划行为 |
| --- | --- |
| resource profiles/capabilities | 返回当前已认证CPU/GPU规格、整数设备组大小、模式和指标支持；保留旧CPU Flavor调用兼容。未认证GPU拒绝创建，不降级成CPU或runc |
| utilization查询 | 实例及项目/租户授权聚合，返回申请/实际/峰值/缺测覆盖率/保留原因/可估算成本；平台节点库存仅管理权限可见 |
| optimization recommendations | 分页查询只读建议，证据窗口、理由、收益估算、风险、期限和所需变更权限固定；不自动执行建议 |
| idle/optimization policies | 项目默认与实例覆盖、显式启用/暂停/撤销/豁免、维护窗口、保护租约、预算/冷却；更新使用版本条件、幂等、审计和当前授权 |
| controlled resize/apply | 通过Operation保卷停止，确认可信关闭后用批准规格启动新launch；活动命令/终端/传输和UNKNOWN不被误终止，非可重跑任务不自动抢占 |

CPU/内存首期保留现有硬限制。新增小规格、比例或安全request/limit分离只能作为独立已认证profile；先给推荐，经停机重建合同调整，不能直接patch活跃Pod绕过规格/准入/配额。完整OOM、节流、重启/缓存预热及工作区/hold语义必须验证。

idle运营入口是近期优先项：创建时固定策略来源/版本，项目默认和实例覆盖有范围限制，关停保护或后台服务保留租约有明确TTL和权限。业务槽空闲不保证guest没有自行派生的后台进程；服务型负载需明确保护合同。撤销策略不能影响原计算TTL安全停机，也不能把只读查询当活动续租。

## 4. GPU必须完整交付的链路

首先锁定实际地域/SKU、裸金属或虚拟化能力、IOMMU/ACS/设备组、驱动、guest CUDA、GPU Operator、sandbox device plugin、DCGM/exporter和Kata/QEMU镜像。现有集群版本锁没有这些认证。核对的GPU Operator 26.3 Kata路径把一个GPU节点的全部GPU交给同一VM，资源默认是`nvidia.com/pgpu`；它不支持vGPU。**首期按整个GPU设备组原子申请、计配额和分配，优先单卡SKU，避免单卡任务独占八卡节点**。这些是上游限制，不代表本项目已经支持该组合。[NVIDIA Kata部署](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/26.3/deploy-kata-containers.html)

G1-11需把设备租约和许可真正接入guest执行前的nodeguard/运行时准入，验证实际设备组、node/boot/launch/epoch，不能只增加GPU JSON或GPU Operator标签。驱动/guest/profile不匹配立即隔离，禁止未分配设备访问、重复绑定、旧launch请求和跨VM DMA；运行链缺口不能被普通容器替代。

排队时保存业务受理和配额pending，物理设备只在容量/认证可用并受理placement后被独占，避免在等待输入、镜像、卷或其余GPU时长期占卡。批任务可用经版本认证的Kueue准入投影和原生scheduler；PostgreSQL保持业务/设备分配权威，明确outbox映射、取消/期限/幂等与部分失败，不能有两个独立授卡账本。多卡/多节点group整体ready有截止时间；当前单活动槽合同不因GPU而取消。[Kueue边界](https://kueue.sigs.k8s.io/docs/overview/)

GPU观测使用实际具备设备和驱动的一侧的DCGM/NVML；VFIO host不应假定可读guest GPU。分配映射需验证Pod/node UID和设备租约，host整卡总值不能复制成每租户独立数值。指标不可用时明确缺测/不支持，不以低GPU-Util、无进程列表或Pod删除判断设备可复用。详细模式、观测和版本冲突见[官方预研](gpu-resource-efficiency-reference-20261012.md)。

设备释放必须独立于监控：可信guest/VM结束、旧映射/DMA通路撤销、按认证GPU/驱动/厂商语义完成reset或清理、健康和残留数据验证后才关闭设备租约并释放配额。reset命令成功并不自动证明跨租户数据安全；不支持reset/清理无法认证或Xid等故障时进入QUARANTINED，经已验证节点重建/云fencing路径恢复，不能为省资源强行换租户使用。

MIG另立认证模式；time-slicing/MPS不作为当前非可信跨租户的隔离替代。管理员定义的同信任域并不自动等于同tenant。受控GPU推理服务批处理可另行减小任意代码直通需求，但须明确只提供受限推理API，不能宣称等价于通用CUDA沙箱。

## 5. 开发顺序、负责人和退出条件

新增7个顶层工作包，其他相关项扩展原任务，避免闲置或监控出现两个不一致的实现。

| 编号 | 优先级/依赖 | 完整开发交付 | 完成标准/主责 |
| --- | --- | --- | --- |
| G0-08 资源效率与GPU合同 | P0，近期先做 | 冻结口径/SLO/工作负载、采样覆盖率、资源/价格有效期、保护租约、CPU/GPU profile、节点设备组和支持矩阵；重估GPU工期/成本 | 模型/API/拒绝边界无歧义，GPU版本和实机资源有明确取得路径；技术负责人/运行时/SRE |
| G1-11 GPU节点与运行时 | P0硬件验证并行；G0-08、G1-03..06；完整认证另需G2-13 GPU租约接线 | 先验证专用GPU节点池/版本/guest/driver/IOMMU/ACS与隔离底座，再接device group许可、reset/隔离/fencing及签名组合 | 真实目标SKU完整正负/故障和跨租户残留测试通过才开放GPU；运行时/SRE/安全 |
| G1-12 资源感知节点弹性 | P1；画像/准入/可信回收，GPU另需G1-11/G2-13 | 经认证云adapter的有界扩缩、预算/库存/配额、暖池、min/max/HA余量、空节点可信drain、IaC归属对账；CPU/GPU池分开 | 禁止删除系统HA/活动或待确认节点，云放量/限流/失败恢复/真实账单核验；SRE |
| G2-13 资源规格与GPU账本 | P0 CPU规格与GPU模型先做；GPU运行接线依赖G1-11实机底座子阶段 | 批准profile/兼容CPU Flavor、overhead对账；GPU设备组库存/租约、tenant/project配额、pending/绑定/释放/隔离；API/OpenAPI/SDK/角色/历史迁移 | 同卡无双分配，重试/重启/旧epoch/取消/超时/撤权不超售或重复释放；后端/运行时 |
| G3-12 利用率与成本画像 | P0 CPU先交付；GPU依赖G1-11/G2-13 | capacity有效期、CPU/内存压力与峰值、GPU指标与归属、节点/存储浪费视图、固定聚合、只读API/UI、缺测/可信度和分配时长/成本分类 | 真值比对、HA不累加、撤权/跨租户拒绝、缺样不当零、采集开销有界；后端/SRE/前端 |
| G3-13 资源优化闭环 | P1；G3-12、G2-07、G2-13、操作引擎 | 有证据的推荐/preview、显式策略/授权/期限/撤销、闲置停止和下一launch调档；公平batch排队/可认证装箱，前后收益与回退 | 活跃/保护/UNKNOWN/缺测/撤权/旧generation不会误停或越权，收益/SLO/失败率对比；后端/QA |
| G4-09 GPU与资源效率验收 | P1发布门；以上链路 | 真GPU单卡/多卡、峰谷/低负载/显存常驻/输入瓶颈、设备/节点故障、观测和72h候选测试；共享模式独立认证，报告原始负载/成本/副作用 | 任务正确/SLO/隔离/回收达标且单位成功任务总成本可复核；GPU未通过时能力继续禁用；QA/安全/运行时 |

**复用原任务**：G2-07立即补闲置策略公开入口/默认/暂停/豁免和授权；G3-02继续补实例压力与低效告警；G4-05加入整个平台的GPU/CPU/存储负载及采集成本；G5-04核实际云费用和HA余量。GPU共享与MIG不是首期默认：只在G4-09对应模式认证后开通。

执行顺序为G0-08→CPU画像与G2-07运营入口，同时验证GPU底座；随后GPU规格/租约/观测→推荐与受控变更→队列/节点弹性→真实GPU/72h和账单验收。G1-11内部拆为实机兼容/隔离底座与完整故障认证两个子阶段：底座验证可与G2-13模型开发并行，底座通过后接G2-13设备租约，再完成G1-11全链认证；它们仍属于原工作包，不新增编号，也不让CPU画像等待GPU。新增GPU范围不套用原CPU基线的42周排期，G1-11明确SKU/组合后单独排计划窗口与预算；没有硬件时可以完成合同/数据库与禁用门禁，不能把Docker模拟算作GPU验收。

## 6. 验收样例与保留规则

必须覆盖真实零值/丢样/陈旧/身份与profile换代、分母变化、双采集副本/host-guest重复、临时GPU高峰/常驻显存、cpu/io瓶颈、driver挂起和设备reuse。推荐不足窗口的状态为INSUFFICIENT_DATA，持续低利用率只触发解释/建议，不直接宣称任务空闲。

自动操作需符合当前授权、策略版本/期限、工作负载类别、活动/保护合同、预算与冷却，并走正常Operation/可信终止/数据保留链。缩容只能作用于明确声明的弹性节点池；既有受保护固定节点不因建议被直接删除。存储清理按已授权retention和hold执行，不随计算停止删除长期工作区。

GPU每种SKU/设备模式有独立认证清单：串卡/越权/DMA、显存残留、IOMMU组、进程/VM退出、reset不支持/失败、host reboot/partition、云fencing、旧租约、driver升级/回退、CUDA上下文丢失、Pod/lease错绑及归属标签伪造。冷备份仅持久工作区，不承诺GPU上下文或显存checkpoint。记录未通过项并保持禁用，不能以MIG/time-slicing标签替代证据。

本文预研阶段只更新计划与边界。后续观测开发仍未开启GPU、改变requests=limits或调整生产资源；各批验收数字分别记录，不重新累计以前的CPU/数据库验收数字。


## 7. 2026-10-13 源码逆向补充

已按REA证据分层方法固定CubeSandbox/OpenSandbox及其Fast Sandbox构建依赖，追踪启动、CoW/缓存/预热成本与GPU设备路径。结论与完整落地增量见[总报告](sandbox-fast-start-resource-gpu-reverse-engineering-20261013.md)，已登记[开发表第12节](rust-sandbox-development-workbreakdown.md#12-2026-10-13-竞品逆向输入与快启开发顺序)。本次仅研究和计划追加，不改变本文旧审查快照或当前运行时/资源/GPU状态。

优先补自身控制面分段计时、持久队列唤醒及已提交阶段有界继续，再做受预算约束的artifact预热；当前模板/VM复用禁止基线保持，新快启profile需要完整认证。公开空闲实例密度不作为实际CPU/GPU效率，成功样本延迟必须与失败率同报。GPU分普通设备申请、独占全设备组、另认证MIG和可信GPU服务；最新版MPS的地址/资源管理能力按具体栈核对，继续不默认用于非可信跨租户VM隔离。GPU-ready和安全复用各有独立实机门，不能直接承接CPU快照的性能数字。
