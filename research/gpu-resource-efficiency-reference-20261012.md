# GPU 资源效率：官方能力边界与生产交付建议

核对日期：2026-10-12。本文为预研和开发输入，**没有实现 GPU 调度、配额、采集、共享或自动回收，没有进行真实 GPU / 目标云验收**。官方支持矩阵描述的是上游产品；它不等于 KnotSandbox 的已认证部署能力。本文只引用官方文档、官方仓库与本仓库源码，不包含内部环境地址或个人资料。

## 1. 当前基线及判断

[集群版本锁](../deploy/cluster/versions.lock.json) 当前为 `candidate-awaiting-cloud-certification`：Kubernetes 1.36.4、containerd 2.3.5、Kata 4.2.0、`go-qemu`、Ubuntu 24.04 的安装检查。本仓库安装流程保留未认证节点隔离；不能将“下载了 Kata”解释为非可信代码或 GPU 沙箱已经获准上线，见 [安装工具范围](../deploy/cluster/README.md)。版本锁中没有 GPU Operator、GPU 驱动、NVIDIA guest image、DCGM / exporter、sandbox device plugin、GPU SKU 或 MIG profile。

[实例运行指标](../docs/runtime-metrics.md) 已提供宿主 VM cgroup 的 CPU、内存、I/O 和任务数，带 launch / generation / cluster epoch 与 FRESH / STALE / MISSING 状态；该接口没有 GPU 指标。本次检查未发现产品级 GPU 请求、设备分配账本、显存配额、MIG profile 管理和 GPU 效率归属实现。生成的 CRI 协议示例中出现 `vendor.com/gpu` 不构成功能实现。

生产方案应先交付**全 GPU 节点独占的 Kata passthrough + 可验证的分配与观测**，以减少空闲租约、错选大规格、排队时占卡和未回收节点的成本。跨不可信租户的显卡共享需要另一条完整认证路径。不能为了提高利用率，将当前 VM 隔离退回同一宿主内核的普通容器，或直接开启 time-slicing。

## 2. 上游支持边界

### 2.1 Kata passthrough 路径

核对的是 NVIDIA GPU Operator **26.3** 的 [Kata 部署页](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/26.3/deploy-kata-containers.html)。该页的当前限制是：passthrough 节点全部 GPU 分配给同一个 Kata VM；不支持只配置节点上部分 GPU 为 Kata；不支持 vGPU；使用 containerd。配置入口为 `sandboxWorkloads.enabled=true`、`sandboxWorkloads.mode=kata`，节点 `nvidia.com/gpu.workload.config=vm-passthrough`，NVIDIA runtime class `kata-qemu-nvidia-gpu`，GPU 资源默认 `nvidia.com/pgpu`。硬件需要虚拟化、ACS 和 IOMMU；VFIO 节点不应加载宿主 NVIDIA 驱动。

26.3 的 [支持矩阵](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/26.3/platform-support.html) 列有 Ubuntu 24.04 / Kubernetes 1.32–1.36 / containerd 1.7–2.3，Kata 单卡和多卡 passthrough；矩阵与部署页给出的 Kata 最小版本表述也应一起核对。**大版本落在范围内不能证明 1.36.4 + 2.3.5 + 4.2.0 的具体补丁、云镜像、QEMU 配置和设备组合已验收**。

旧 [gpu-operator-kata 页面](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/latest/gpu-operator-kata.html) 仍可检索到“单 GPU、初装支持”等旧限制。应以选定版本的当前部署页、release notes 和实物矩阵为准，不能把两个安装代际的命令、runtime manager 和限制拼成一套生产配置。

| 路径 | 官方能力与当前产品决策 | 资源效率代价 / 交付门禁 |
| --- | --- | --- |
| Kata + 全节点 GPU passthrough | 首个候选路径；仍未实现、未认证 | 单卡任务若放在八卡节点，同 VM 会独占整组设备；优先选单卡 GPU 节点 SKU / flavor，或明确接受整个节点组的分配成本 |
| 普通容器 + 整卡独占 | 官方 GPU device plugin 的一般部署模式；不是本产品非可信租户的隔离替代 | 宿主驱动、共享内核和共享设备管理面增加租户风险；只可作为另行约定的可信任务节点池 |
| 普通容器 + MIG | GPU Operator 支持 MIG 管理；不等于 Kata 逐 MIG slice passthrough 已支持 | 需要独立安全 / driver / metrics / profile 认证；不能仅增加 `nvidia.com/mig-*` 就对外承诺不可信 VM 隔离 |
| Kata + vGPU / MIG-backed vGPU | 当前 26.3 Kata 部署页不支持 vGPU | 若商业需求要求跨 VM 共享，需要独立 hypervisor / vGPU 许可 / 支持 SKU / guest 驱动 / 计量与安全方案，不能混入首期 |
| 单独的可信 GPU 推理服务 | 产品架构建议：不可信 CPU 沙箱调用受控推理 API | 模型服务可批处理与复用 GPU，但不提供任意 CUDA 代码执行；应明确权限、数据隔离与调用计费边界 |

GPU passthrough VM 的设备组应作为一个原子 capacity unit。这里的“整节点”指该上游 GPU 部署路径的 GPU 分配单位，不应推导成该节点 CPU 可无约束向其他租户开放；节点池和 CPU 共置也须经过安全、性能、生命周期认证。

阿里云官方 [ECS 实例族说明](https://www.alibabacloud.com/help/en/ecs/user-guide/instance-families/) 包含 GPU 裸金属类与 GPU VM 类。选型时必须单独取得目标地域、SKU 的虚拟化 / IOMMU / ACS / GPU reset / VFIO / fencing 支持及实际验证。该实例族说明不是“任意 GPU ECS 都可嵌套 Kata + GPU 重直通”的承诺；云配额、库存与价格也必须按部署时的实际 API / 合同读取。

### 2.2 MIG、time-slicing 与同信任域共享

[MIG 官方说明](https://docs.nvidia.com/datacenter/tesla/mig-user-guide/introduction.html) 描述固定硬件切片、独立计算和内存路径，以及 QoS / 故障隔离。MIG profile 是离散组合，具体型号的容量和组合需查对应 profile，不能按显存总量任意拆分。这里的硬件能力仍不能代替本产品的 VM、宿主驱动、API、网络与设备复用安全认证。

[GPU Operator time-slicing 文档](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/26.3/gpu-sharing.html) 明确：time-slicing 通过 replicas 超售设备访问，不具备 MIG 的显存和故障隔离；配置可用于整卡或 mixed MIG 资源。**replica 数不是物理 GPU 数、显存上限或保证算力份额**。26.3 页面还明确列出 DCGM exporter 不支持该模式下的容器指标归属。

另一个版本边界是 [DCGM latest exporter CLI](https://docs.nvidia.com/datacenter/dcgm/latest/reference/command-line-reference/dcgm-exporter.html) 已列 `--kubernetes-virtual-gpus`，用于部分支持的 time-sharing / MPS 归属。两处文档不能直接合并为“当前捆绑 exporter 已提供准确每租户利用率”。必须锁定 exporter / DCGM / plugin / driver 的具体版本，并验真输出是独立计算、按进程拆分、共享设备总值复制还是分配元数据；未认证前不提供每租户 GPU 算力消费计费或自动回收决策。

产品建议：首期禁用跨不可信租户 time-slicing / MPS。以后同信任域共享也必须由管理员定义允许的信任域，并由主体和项目授权推导；“同租户”不自动意味着该租户内互相不可信的用户可以共享内核或显存。MIG profile 变更必须维护窗口 / 完整 drain；[MIG Manager 文档](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/26.3/gpu-operator-mig.html) 描述其会停 GPU 客户端及管理 Pod，部分情况需要重启，不能在活跃租户任务中随意重划片。

### 2.3 GPU 观测与归属

[DCGM 支持环境](https://docs.nvidia.com/datacenter/dcgm/latest/user-guide/getting-started.html) 包含 bare metal 和 full-passthrough 虚拟化；这并不表示宿主可以跨 VFIO 观察 guest GPU。26.3 Kata passthrough 的节点组件清单不等于普通容器节点的宿主 driver + DCGM 清单。**需要在有设备和受支持驱动的一侧实际采集**，并认证传回平台的路径。

普通 Kubernetes exporter 可从 [kubelet PodResources API](https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/device-plugins/#monitoring-device-plugin-resources) 获取 device plugin 设备 ID 和 Pod / container 分配关系。该 API 描述分配，不能独自产生 GPU 利用率，也不是租户授权证明；以 name / namespace 匹配时还应从 API 验证 Pod UID、node UID、resourceVersion 与生命周期，防止名称复用。不可将 pod-resources / runtime socket 暴露给非可信租户。

[DCGM vGPU 模块](https://docs.nvidia.com/datacenter/dcgm/latest/learn/modules/vgpu.html) 在受支持 vGPU 宿主上提供物理卡 / vGPU / owning VM 元数据和部分遥测。它与 full passthrough 是不同路径；不能把 vGPU host 的观测能力挪用到 VFIO-passthrough host。guest driver / license / 显存字段是否可用须按实际组合逐项验收。

首期建议将 GPU 数据分成三层，禁止混算：

| 数据层 | 拟可信来源 | 对外语义 |
| --- | --- | --- |
| 云成本与物理库存 | 独立只读云 API / 账单、受认证节点清单 | 已付费 GPU / 节点时间、SKU、节点 provisioning / draining / quarantined 时长；云库存不是设备已经安全可用 |
| 设备分配账本 | 平台配额 + nodeguard / runtime 的设备分配事实 | tenant / project / instance / launch / generation / epoch / node UID / GPU UUID / PCI BDF / IOMMU group / assignment epoch 的固定绑定；GPU allocation-hours 与租约占用 |
| 工作负载性能 | 受支持 guest DCGM / 固定采集路径，或可信 GPU 服务 telemetry | GPU-Util、SM / tensor / memory 活跃、显存、功耗、吞吐、queue latency；标记具体 source、粒度、版本、freshness、coverage 和 attribution confidence |

guest 的 root 可能由不可信代码取得；仅放一个受租户影响的 exporter 不能给出可信的跨租户自动决策证明。guest 采集即使经 mTLS 传输，也只验证连接身份，不证明采集值未被 guest 修改。首期允许将经过绑定校验的 guest 遥测作为标有信任级别的性能建议输入，不能单独触发自动 STOP / 调档；显式优化策略也不改变此可信度边界。真正的释放、隔离和分配仍依赖宿主与云的既有可信终止 / fencing 链。若以后要求防篡改 GPU 消耗计费，需另交付可认证 collector 或受控执行架构。

GPU UUID 等物理标签只在管理侧保留；租户 API 返回平台生成的不透明设备引用与其已授权实例的指标。固定指标枚举、固定查询模板、查询前后实时授权、有限并发 / 响应 / label allowlist、HA 去重、缺样不填零，沿用已有 metrics 合同。

## 3. 效率口径及禁止的自动决策

以下是拟产品口径，尚未实现：

- **容量占用率**：同 SKU / mode / profile 的已分配 capacity-unit-seconds ÷ 已认证可分配 capacity-unit-seconds。未知、隔离和维护容量单列。time-slicing replicas 不进入物理卡分母；MIG slice 不与整卡直接相加。
- **保留成本**：云计费节点秒与 GPU 分配秒分开，计入启动、预热、失败等待和 drain；保留价目表版本、币种、账期和来源。账单是成本事实，不能用 GPU-Util 平均值伪造“节省金额”。
- **低效候选**：长时间分配但性能利用率低、显存高度保留但计算停滞、排队任务匹配不到现存规格、无业务租约节点仍付费。每项返回数据覆盖率、原因与置信度；不确定时返回 UNKNOWN。
- **工作收益**：job 完成时间、有效吞吐、排队 p95、OOM / retry / eviction 率、SLO 与成本一起比较。目标是减少完成同一有效工作所需成本，不能单独追求 GPU-Util=100%。

GPU-Util 低可能是 CPU 数据加载、网络 / I/O 等待、同步通信、模型显存常驻或间歇服务。真实零、STALE、MISSING、unsupported field、错误 sentinel 要分别表示。低利用率、无样本、device plugin unhealthy、Pod NotReady / 被删除、租户自报 idle **均不能证明 VM 已死亡、设备已隔离、显存已清除、卷已卸载或配额可释放**。

首期只产出优化建议与 dry-run。后续自动暂停 / 终止须由显式策略授权，校验活动执行、租约、任务、备份 / restore、法律保护、当前授权与 generation / epoch；经过现有 operation、可信 termination / fencing、cleanup 及配额事务才释放资源。GPU detach / reset / 残留数据验证是设备复用的附加必要条件；reset 不成功则保持隔离并继续计算占用，不伪造释放成功。

## 4. 排队、调度和弹性选型

GPU 的 Kubernetes extended resource 使用整数请求；[GPU 调度说明](https://kubernetes.io/docs/tasks/manage-gpus/scheduling-gpus/) 要求相应 device plugin，GPU requests 与 limits 的关系有明确约束。产品 API 应接收受管理员认证的 flavor / resource mode 与整数 count，不允许租户传任意 nodeSelector、runtime class、CDI annotation、VFIO BDF 或 GPU Operator 配置。

建议使用 Kueue 管理受控 batch / Pod group 的排队和配额，kube-scheduler 负责 Pod 放置；[Kueue 概览](https://kueue.sigs.k8s.io/docs/overview/) 明确它不替代 kube-scheduler、node autoscaler 和 job lifecycle controller。[plain Pod 集成](https://kueue.sigs.k8s.io/v0.20/docs/tasks/run/plain_pods/) 可管理单 Pod / Pod group；部署只匹配专用 workload namespaces，禁止劫持平台、nodeguard 或基础设施 Pod。

多卡 / 多节点任务必须作为一个 group 申请，避免先启动半组卡再长期等待其他卡。Kueue 的 [all-or-nothing 说明](https://kueue.sigs.k8s.io/v0.20/docs/concepts/all_or_nothing/) 给出全组 quota admission、Pod readiness 等组合机制；**逻辑配额够不代表物理容量够，也不构成设备安全释放保证**。[ProvisioningRequest](https://kueue.sigs.k8s.io/docs/concepts/admission_check/provisioning_request/) 可联动 Cluster Autoscaler，但须核对所选 cloud provider / provisioning class 支持，不能仅因存在 AliCloud provider 就宣称完整 capacity guarantee 路径已成立。

[Kubernetes 节点弹性](https://kubernetes.io/docs/concepts/cluster-administration/node-autoscaling/) 依赖请求量、调度约束和云 API，不能照 GPU-Util 自动删节点。目标云 adapter 必须把节点 bootstrap、GPU 驱动 / VFIO、nodeguard 登记、存储挂载、网络、fencing 认证完成视为 READY 的必要条件；扩容上限受云 quota / 库存 / 成本预算限制。缩容先阻断新准入，再走可信 drain 和设备清理，最后云实例释放并核对账单状态。

首期单卡任务按已认证单卡 flavor 排队；专用多卡 flavor 为整设备组收费并调度。拓扑需求以后按 [Kueue TAS](https://kueue.sigs.k8s.io/docs/concepts/topology_aware_scheduling/) 的 required / preferred topology 做版本专项认证；beta / alpha feature gate 不默认变成生产承诺。非可重跑任务、长期工作区和互动沙箱禁用自动抢占；batch 抢占需有用户可接受的重跑 / checkpoint 合同。当前项目已有数据库配额是权威业务账本，Kueue 是准入投影；实现时必须定义映射、幂等 outbox / controller、取消、超时和部分失败，不能同时维护两个可各自授予设备的权威。

## 5. 建议分阶段交付及验收依赖

本表为技术建议；正式任务 ID、优先级和依赖由 [开发表](rust-sandbox-development-workbreakdown.md) 统一登记。下列各阶段均未实现。

| 阶段 | 完整开发交付 | 生产验收门禁 |
| --- | --- | --- |
| A. 资源效率合同与库存 | CPU / memory / storage / GPU 的 requested / reserved / allocated / observed / billed 区分；GPU flavor registry、mode / profile / trust domain / pricing version；承载设备绑定的 migration、最小 DB grants、租户 RLS、SDK / OpenAPI / capability；预算、查询覆盖率和 UNKNOWN 语义 | 数据库非空升级、并发配额 / 幂等 / 取消回滚；跨租户读写拒绝；未经认证 GPU flavor 不能启用；API 不接受设备或 runtime 逃逸参数 |
| B. GPU 独占运行链 | 只开放认证的全节点 passthrough mode；候选 GPU 版本锁、镜像 digest / SBOM、安装与诊断脚本；nodeguard 设备 group 分配账本和 permit；实际 guest driver / CUDA 支持；GPU 设备 group 与 launch / epoch 原子绑定；释放前 reset / 残留验证和隔离恢复 | **真实目标 GPU 硬件 / 云 SKU 必需**：恶意 DMA / 非分配设备访问、IOMMU group、ACS、driver crash、重复 permit、API 重启、host reboot、网络分区、双调度、fencing 及旧 launch 复用全部验收；Mac Docker 无法替代 |
| C. GPU / 资源观测与建议 | 固定 exporter / collector、guest trust level、设备绑定与 sample sequence；GPU 指标 capability matrix；CPU 节流 / 内存压力 / I/O 等待关联；成本和 allocation-hours；只读效率 API / 控制台 / 趋势 / reason codes；prometheus 采集限额、retention、告警及租户授权 | 真实 GPU 压测与 idle / loader bottleneck / 显存常驻 / sentinel / 不支持字段 / 缺样 / HA / 设备重用案例；物理卡总值不能复制计入每租户独立数值；撤权、标签伪造、跨 epoch 数据拒绝；低利用率不触发释放 |
| D. 排队和节点弹性 | 锁版本 Kueue + 云已支持的 CA / provisioner；专用 namespace 集成、公平队列 / 借用上限、multi-resource flavors、gang readiness deadline、排队 / cancel API；业务账本向准入投影；云预算、min / max、预热窗口、冷却、scale-to-zero 的可用性合同；安全 drain hook | GPU 库存不足、云 quota / API 限流、半组 readiness、controller 重启、过期 capacity booking、节点认证失败、取消并发、不可抢占任务、挂盘失败；无可信清理证据节点不可缩容；真实云冷启动 / 排队 / 成本测量 |
| E. 受控自动优化 | 优化策略 preview / dry-run / enable / pause / revoke，明确授权范围和期限；闲置 lease、低效建议、下一次 launch 的规格优化；protected operations / active execution checks；每次变更沿既有 operation / audit / event / trusted termination 路径 | 冲突 generation、策略撤权、缺样、突发 workload、活动备份 / 保护记录、通知重放、终止 UNKNOWN、设备 reset 失败均不越权释放；前后 SLO / 总成本 / 完成率对比，证明节省不是牺牲正确任务 |
| F. 共享路径独立认证 | 同信任域 GPU service 批处理优先；MIG 或 vGPU 另立 runtime profile / deployment / license / device cleanup / metrics matrix；time-slicing 若选只在明确允许的可信池启用；MIG geometry / mode 变更维护计划；资源与费用不跨 mode 混算 | 准确隔离及每模式残留数据、OOM / fault blast radius、reset / 重启、profile 碎片、driver 升级回滚、metric attribution；Kata 逐 slice / vGPU 若上游矩阵仍不支持则保持禁用，不通过修改文档放行 |

A 可使用现有 Rust / PostgreSQL / 观测栈落地，部分测试可在隔离 Docker 完成。B 和 C 的 GPU 真值与隔离、D 的目标云弹性无法由本机普通容器证明；必须在真实已授权 GPU 资源上保留可复现证据。没有硬件验收资源时仍可交付合同与 fail-closed 门禁，但不能标为 GPU 产品上线就绪。

上线前按 workload class 制定目标，避免预先承诺统一利用率数字：批处理看单位有效任务成本与队列 p95，互动沙箱看冷启动 / 响应时延与保留成本，模型服务看吞吐 / tail latency / 显存 / OOM。验收报告必须给 baseline、负载、warm-up、采样覆盖率、SKU 与价格版本、失败 / 重试、原始证据及保留开销；部署拓扑、空闲预算和 SLO 达标后再启用自动化。
