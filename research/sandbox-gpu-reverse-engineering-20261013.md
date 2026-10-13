# CubeSandbox / OpenSandbox GPU 源码逆向与 KnotSandbox 落地输入

核对日期：2026-10-13。本文采用 `mattpocock-skills:research` 的一手源码与官方文档取证方式，记录静态实现事实、上游能力边界和拟开发方案。**未运行外部仓库代码，未使用真实 GPU、云 API 或生产部署；没有测得两项目的 GPU 吞吐、利用率、隔离强度或冷启动时间。**

## 1. 先确定研究结论

CubeSandbox 这次固定版本把 GPU 沙箱列在未来路线图；OpenSandbox 已有普通 Docker / Kubernetes GPU 设备申请路径，却没有在所检查链路中交付 GPU 性能观测、设备复用安全回执或 GPU 专用优化器。两者当前公开源码**不足以证明“GPU 利用率很高”**。CPU 沙箱的快速启动、Pool 分配密度、GPU 可见性和真实 GPU 工作效率必须分别验证。

对本产品，继续保留“非可信任意 CUDA 代码使用独占且已认证设备组”的第一条路径；增加“CPU 沙箱调用可信 GPU 服务”的并行路径，先验证批处理和模型常驻的收益。MIG 共享另立运行时及安全认证；time-slicing / MPS 不默认开放给互相不可信的租户。这是基于下列证据的产品判断，**不是对两项目商业服务的性能或安全审计结论**。

## 2. 取证范围与固定版本

| 项目 | 本次固定版本 | 本地静态取证范围 |
| --- | --- | --- |
| CubeSandbox | [`897def3abf1ad9b5df3d42fd4893d38c41ccabd9`](https://github.com/TencentCloud/CubeSandbox/tree/897def3abf1ad9b5df3d42fd4893d38c41ccabd9) | 3,802 个源码 / UTF-8 文本文件；检查 master API、scheduler、Cubelet 资源模型、shim 设备调用、agent 协议与指标、roadmap；媒体 / 二进制 / symlink 不执行 |
| OpenSandbox | [`c806a49c62ee1fc3baa036165e9044e7b0efd97f`](https://github.com/opensandbox-group/OpenSandbox/tree/c806a49c62ee1fc3baa036165e9044e7b0efd97f) | 2,817 个源码 / UTF-8 文本文件；检查 lifecycle schema、Docker / K8s provider、Pool 资源匹配和打分、fast-sandbox template、execd 指标及节点采集 |
| NVIDIA / Kubernetes / Linux | 官方版本页或 latest 页面，2026-10-13 重新打开核对 | 仅上游文档支持；latest 的能力不可直接当作我们版本锁或已认证能力 |

源码档案 SHA-256：CubeSandbox `87422531e07ca453d918e495bc13c6933240e3e1261f918742b2c7dc25af3bea`；OpenSandbox `77d337679f810ef1d4c73f4497c1a25c99694328277261074cfebfd81cfe540e`。源码清单及摘要保存在本次本地取证目录，未执行安装脚本或运行仓库程序。

检索 `GPU / CUDA / NVIDIA / DCGM / NVML / MPS / VFIO / accelerator` 后人工区分路线图、继承协议、测试 mock、通用 VFIO 和真实调用。下文“未发现”限于这个固定版本的文本源码与所列链路，不推导成商业后端永远没有该能力，也不把未搜索到某个名称当作唯一证据。

## 3. CubeSandbox：GPU 产品链仍在路线图

| 检查链路 | 固定源码事实 | 可以得出的结论 |
| --- | --- | --- |
| 产品状态 | [`docs/guide/roadmap.md:5,31–33`](https://github.com/TencentCloud/CubeSandbox/blob/897def3abf1ad9b5df3d42fd4893d38c41ccabd9/docs/guide/roadmap.md#L31) 的 Coming Soon 包含 GPU Sandboxes | GPU-aware inventory / placement 和 CUDA VM 是未来方向；该条不能作为现成功能或 GPU benchmark |
| 调度资源 | [`RequestResource:39–54`](https://github.com/TencentCloud/CubeSandbox/blob/897def3abf1ad9b5df3d42fd4893d38c41ccabd9/CubeMaster/pkg/scheduler/selctx/selectcontext.go#L39) 是 CPU、memory、disk、image、template 等；[`Resource:423–433`](https://github.com/TencentCloud/CubeSandbox/blob/897def3abf1ad9b5df3d42fd4893d38c41ccabd9/pkgs/proto/services/cubebox/v1/cubebox.proto#L423) 只有 CPU / memory 及 guest limit | 标签或 affinity 选到 GPU 节点不等于 GPU 数量 / profile 的配额、设备分配与防双分配 |
| 本地资源构造 | [`Cubelet resource.go:19–61`](https://github.com/TencentCloud/CubeSandbox/blob/897def3abf1ad9b5df3d42fd4893d38c41ccabd9/Cubelet/services/cubebox/resource.go#L19) 汇总 CPU、memory，设置 PCI mode / NUMA | 通用 PCI / NUMA 基础可参考，但这里没有 GPU admission 与设备租约 |
| VFIO 调用 | [`CubeShim add_device:1325–1346`](https://github.com/TencentCloud/CubeSandbox/blob/897def3abf1ad9b5df3d42fd4893d38c41ccabd9/CubeShim/shim/src/sandbox/sb.rs#L1325) 循环处理 `vfio_nets`、`vfio_disks`；[`device.rs:11–14`](https://github.com/TencentCloud/CubeSandbox/blob/897def3abf1ad9b5df3d42fd4893d38c41ccabd9/CubeShim/shim/src/sandbox/device.rs#L11) 也是网络 / 磁盘注解 | Hypervisor 可添加通用 VFIO 设备，不能推导 GPU driver、CUDA、reset、显存清理与租户归属链已接通 |
| 协议残留 / 预留 | [`agent.proto:338–349`](https://github.com/TencentCloud/CubeSandbox/blob/897def3abf1ad9b5df3d42fd4893d38c41ccabd9/agent/libs/protocols/protos/agent.proto#L338) 有 `GPUInfo`；[`cubebox.proto:374–401`](https://github.com/TencentCloud/CubeSandbox/blob/897def3abf1ad9b5df3d42fd4893d38c41ccabd9/pkgs/proto/services/cubebox/v1/cubebox.proto#L374) 有通用 OCI / CDI 字段 | `GPUInfo` 的全仓文本使用检索未找到产品处理接线；CDI 例子的 `vendor.com/gpu` 不构成实际支持 |

公开 [GPU design proposal #174](https://github.com/TencentCloud/CubeSandbox/discussions/174) 也将 VFIO、guest kernel / modules / driver / CUDA 兼容、Cubelet inventory、模板热插拔与生命周期限制作为待讨论设计。提案能提供风险清单；是否合并以及哪些部分实际实现，仍以本次固定源码为准，不按讨论文字宣布可用。

**对启动性能的限定**：CPU VM 模板复用的收益不能无条件继承到 GPU。GPU driver 初始化、设备分配、guest 内存固定和 CUDA context / 模型加载都是另一条成本链。Cube 的通用 `add_device` 仅证明网络 / 磁盘路径，因此本次没有“Cube GPU 快照恢复到可用 CUDA 只需多少毫秒”的证据。

## 4. OpenSandbox：已有设备申请，但请求合同、快照和效率还有边界

### 4.1 普通 Docker / K8s 路径

Docker 创建先解析 `resourceLimits.gpu`：正整数或 `all`，后者映射 Docker count `-1`。[`container_ops.py:329–360`](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/services/docker/container_ops.py#L329) 对非法格式 / 非正数返回 400；[`388–400`](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/services/docker/container_ops.py#L388) 构造 `DeviceRequest(count=gpu_count, capabilities=[["gpu"]])`，GPU 与隔离 runtime 的真实支持取决于宿主工具链。Windows-in-QEMU profile 明确抑制外层 Docker GPU 请求，见 [`docker_service.py:776–784`](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/services/docker/docker_service.py#L776)。

这是**设备可见性请求**。这段代码没有选定物理 UUID 的事务租约 / 跨实例独占账本。NVIDIA Container Toolkit 官方也描述的是用 `--gpus` / `NVIDIA_VISIBLE_DEVICES` 枚举暴露哪些设备；不能从 count 推导“各 Docker 沙箱一定获得不同物理卡、显存限制或算力保证”。后者需要另查调度和驱动模式，本次没有该保证证据。[NVIDIA Docker GPU 配置](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/docker-specialized.html)

K8s provider 将 `gpu` 翻译成 `nvidia.com/gpu`，默认把 translated limits 同时当 requests；正整数可以让 kubelet / device plugin 接收设备请求。`all` 返回 400。**但非法字符串、0、负数会从 GPU 请求中删掉并继续**，见 [`provider_common.py:55–115,180–191`](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/services/k8s/provider_common.py#L55)，并有明确断言这一行为的 [`test_provider_common.py:75–82`](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/tests/k8s/test_provider_common.py#L75)。API [`ResourceLimits`](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/api/schema.py#L82) 是 `Dict[str,str]`，没有在此层补上统一 GPU 正整数限制。这是需要避免继承的失效语义：本产品应明确拒绝，不可静默改成 CPU 任务。

Kubernetes 设备 requests / limits 必须遵循 extended-resource 规则，两者同时指定时相等。普通 `nvidia.com/gpu` 是否整卡、MIG single 模式或 time-slicing replica 由管理员的 device-plugin 配置决定，资源名本身不证明物理独占。[Kubernetes GPU 调度](https://kubernetes.io/docs/tasks/manage-gpus/scheduling-gpus/)、[NVIDIA device-plugin shared access](https://github.com/NVIDIA/k8s-device-plugin#shared-access-to-gpus)

### 4.2 Pool 高分配密度不是 GPU 硬件利用率

[`poolassign/predicate_resource.go:34–53,91–103`](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/kubernetes/internal/controller/poolassign/predicate_resource.go#L34) 按模板中全部 container requests 汇总并比较 Pool 能力；该泛型比较能处理 extended resources，但不测 GPU 实际忙闲。`resBalance` 的 [`Score:50–59`](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/kubernetes/internal/controller/poolassign/scorer_resbalance.go#L50) 仅使用 `pool.Status.Allocated / pool.Status.Total`，可按 MostAllocated 集中或 LeastAllocated 分散。它衡量的是**池槽位分配比例**，不是 SM 活跃、显存使用或有效吞吐。

推断：若 GPU Pool 预先启动持卡 Pod，快申请把 driver / 镜像 / model 预热工作提前，同时持续占卡付费；它可能改善延迟，也可能增加空闲 GPU 成本。必须在本机 / 云实际测算，不能只根据 Pool hit 的 API 延迟宣称总体省资源。

### 4.3 Fast-sandbox 与 GPU 不可混为同一路径

[`template_service.py:72–74,190–204`](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/services/templates/template_service.py#L72) 明确只允许 template 的 `cpu/memory/disk`；`gpu` 请求 400，测试 [`test_templates.py:621–625`](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/tests/test_templates.py#L621) 覆盖该拒绝。普通 GPU API 示例或 SDK 自动生成的 `gpu` 字段不能抵消这个运行路径限制。当前不能把其 CPU 快照 / fast-sandbox benchmark 写成 GPU 已初始化、CUDA 已可执行、模型已常驻的 benchmark。

### 4.4 监控与释放检查

execd 的 [`Metrics:19–34`](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/components/execd/pkg/web/model/metric.go#L19) 只有 CPU count / percent、memory total / used、timestamp。对 `components`、`kubernetes/internal`、服务运行路径检索 GPU 采集库与字段，再沿实际 metric / create / delete 路径检查，没有发现完整 DCGM / NVML GPU 利用率或带 GPU 设备世代的租户指标归属。

Docker 删除是 kill + remove + 常规侧车 / volume 清理，暂停是 `container.pause()`，见 [`docker_service.py:1114–1185`](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/services/docker/docker_service.py#L1114)。这些调用本身不提供 GPU detach / reset / 残留验证回执；不能把 CPU 进程暂停解释为“GPU 设备可安全转给另一租户”。本次未验证宿主 runtime / driver 自动清理的真实行为，也未将常规容器退出等同于跨租户安全认证。

## 5. GPU 高效率的可用机制与安全代价

| 机制 | 上游实际能力 | 本产品可采用的边界 |
| --- | --- | --- |
| 整设备独占 + 短持卡时间 | 控制持卡租约、规格匹配、队列、输入准备和及时安全释放减少无效占用 | 任意非可信 CUDA 首选；先避免单卡任务占整八卡节点，再优化 guest 冷启动和输入瓶颈，不靠跨租户共享降低隔离 |
| MIG | 为支持硬件提供离散计算 / 内存路径及 QoS / 故障隔离；型号 / profile 与拓扑受支持矩阵约束 | 硬件切片是可参考的隔离部件；宿主驱动 / VM / API / 清理仍须认证，不能把 `nvidia.com/mig-*` 加进 Kata 就宣称已支持 VM 逐 slice 直通。[MIG 官方](https://docs.nvidia.com/datacenter/tesla/mig-user-guide/introduction.html) |
| Time-slicing | device plugin 复制共享访问名额，可把分配槽位扩很多；没有 MIG 的显存 / 故障隔离 | replicas 不计入物理卡分母，也不保证等比例 compute；首期禁跨非可信租户共享。[GPU Operator 26.3](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/26.3/gpu-sharing.html) |
| MPS | 合作式多进程复用、独立地址空间、资源限制；当前 MPS v3 另有 namespaces / SM / memory partition 管理 | 不可泛称“无显存隔离”，也不可当成 VM 硬件隔离。共享故障、监控归属与客户端终止是独立合同；仅受控同信任域另行验证。[MPS 当前入口](https://docs.nvidia.com/deploy/mps/latest/index.html)、[使用约束](https://docs.nvidia.com/deploy/mps/latest/when-to-use-mps.html) |
| 常驻模型 + 动态批处理 | 对受支持推理模型合并请求，复用初始化和模型显存 | 可信 GPU 服务并行路线；batch delay 需受 p95 / p99 SLO 约束，租户只调用批准 API，不上传任意 CUDA / Python / backend。[Triton batcher](https://docs.nvidia.com/deeplearning/triton-inference-server/user-guide/docs/user_guide/batcher.html) |

**版本冲突必须保留**：NVIDIA device-plugin README 的 MPS 集成写着不支持启用 MIG 的设备；MIG 官方部署说明则允许 CUDA MPS 运行于 MIG 上。这是“通用 CUDA 能力”与“特定 Kubernetes plugin 集成”的不同层级，不应任选一句拼成受支持部署。新版 MPS v3 的控制功能也不证明当前 plugin / operator 捆绑组件已全部接线。[device-plugin MPS](https://github.com/NVIDIA/k8s-device-plugin#with-cuda-mps)、[MIG application considerations](https://docs.nvidia.com/datacenter/tesla/mig-user-guide/deployment-considerations.html)

NVIDIA 26.3 与目前 latest（示例版本 26.7.1）的 Kata 部署页都仍要求节点全部 GPU 分配给同一个 Kata VM，不支持 vGPU，使用 containerd。当前 KnotSandbox 版本锁不含完整 GPU 组合；保留既定全设备组候选，不因 latest 页面出现新号自动升级或承诺密度。[26.3 Kata 限制](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/26.3/deploy-kata-containers.html)、[latest Kata 限制](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/latest/deploy-kata-containers.html)

另一条启动限制是 NVIDIA Kata reference stack **只支持 cold-plug**：创建 VM 时通过 PodResources / CDI 获得 GPU，再启动 QEMU，不能直接采用 Cube 设计提案里的 restore 后热插 GPU 作为当前受支持配置。[Kata NVIDIA GPU reference flow](https://github.com/kata-containers/kata-containers/blob/main/docs/use-cases/NVIDIA-GPU-passthrough-and-Kata-QEMU.md)。这是上游文档支持边界，具体锁定 Kata / guest / QEMU 仍需源码与实机认证。

## 6. “GPU 利用率”必须分成五种口径

| 口径 | 拟实现计算 / 来源 | 明确不能替代什么 |
| --- | --- | --- |
| 分配密度 | 同 SKU / mode / profile 的已分配 capacity-unit-seconds / 已认证可分配 seconds；Pool 槽位另列 | 高分配率不等于 GPU 在做有用工作；replica 不是物理卡，MIG 各 profile 不直接相加 |
| 硬件活动 | NVML GPU-Util；DCGM SM / tensor / DRAM activity、功耗等；具体字段 runtime capability 确认 | GPU-Util 是采样期间是否有 kernel 运行的时间比例，不是 FLOPS 饱和比例。[nvidia-smi utilization](https://docs.nvidia.com/deploy/nvidia-smi/index.html#utilization) |
| 显存占用 | allocated / resident / peak / cache / context / model 保留，结合 workload 阶段 | 常驻模型显存高且 compute 低可能符合需求；显存比例不是 memory bandwidth utilization |
| 有效吞吐 | 有效完成任务 / 秒、tokens / 秒或模型具体业务吞吐、成功率、retry、queue p95、tail latency | SM 高、occupancy 高不能独自证明更快。DCGM interval 平均也不是 kernel trace。[DCGM profiling](https://docs.nvidia.com/datacenter/dcgm/latest/learn/modules/profiling.html) |
| 单位成功任务总成本 | 实际节点 / GPU / CPU / disk / network / telemetry / warm reservation 费用 / 有效成功任务；估价与账单分列 | 不能把 GPU-Util 平均提升直接换算成节省金额；失败、排队与空闲暖池成本不能删除 |

对 VFIO host 和 guest 的观测分别处理：DCGM 支持 full-passthrough 环境，不意味着未加载 NVIDIA 驱动的 host 能监控 guest GPU。PodResources 只是设备分配映射，必须校验 Pod / node UID、launch、generation、epoch 和 assignment epoch；guest 可控制的遥测即使 mTLS 传输仍标 `GUEST_OBSERVED`，只作建议输入，不独立驱动释放或防篡改计费。[DCGM 环境](https://docs.nvidia.com/datacenter/dcgm/latest/user-guide/getting-started.html)、[Kubernetes device monitoring](https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/device-plugins/#monitoring-device-plugin-resources)

26.3 sharing 页面仍写 time-slicing 无容器指标关联，latest DCGM exporter CLI 已出现 `--kubernetes-virtual-gpus`；应锁版本并验真输出到底是独立进程值还是物理卡总值复制。未知 / 缺样 / unsupported / error sentinel 与真实零分开，拒绝把同卡总量复制计入多个租户。[26.3 sharing limitation](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/26.3/gpu-sharing.html#limitations)、[exporter mapping options](https://docs.nvidia.com/datacenter/dcgm/latest/reference/command-line-reference/dcgm-exporter.html)

## 7. KnotSandbox 三条生产路线与验收门槛

下面是拟开发路线，不表示实现、开通或已通过验收；完整工作包沿用 [G0-08 / G1-11 / G2-13 / G3-12 / G3-13 / G4-09 开发表](rust-sandbox-development-workbreakdown.md)。

### A. 非可信通用 CUDA：已认证全设备组独占

1. `GpuProfile` 固定 SKU、physical group、模式、guest / driver / CUDA / VFIO / Kata / QEMU digest、兼容上限、设备清理流程及计量能力；禁用未经认证 profile，API 不接收任意 BDF / deviceID / runtimeClass / nodeSelector，`all` 和非法数量明确拒绝。
2. PostgreSQL 保存权威配额 / lease / generation / assignment epoch；pending 不给 guest 设备，镜像 / 输入 / 存储就绪后有界准入。Kubernetes resource 是投影，实际 PodResources / CDI / nodeguard inventory 和 permit 必须对账；重复调度、旧 epoch 不能授卡。
3. 选择单卡节点供单卡任务，多卡组整体准入；锁版本 NVIDIA Kata cold-plug 组合。预拉签名镜像、guest kernel / driver 包和常用只读输入可优化；持 GPU 暖 VM 按独占 owner / trust domain、TTL、预算单列，不提前承诺 CPU snapshot 的速度。
4. 正常退出沿现有可信 VM 结束 / fencing，撤旧 DMA / IOMMU 映射，再执行型号认证的清理 / 健康 / 残留验证，最后释放 lease 与配额。失败进入 `QUARANTINED`，不以无指标或低利用率替代安全回执。IOMMU group 是所有权最小隔离单位，不能按一个 BDF 随意拆组。[Linux VFIO](https://docs.kernel.org/driver-api/vfio.html)
5. 真目标 GPU / cloud SKU 验收串卡、DMA、IOMMU / ACS、node / VM crash、driver Xid、double allocation、partition / reboot、旧 permit、清理失败和数据残留。生产 gate 包含 release / provisioning / rollback 证据；只有 Mac Docker 测试时保持 GPU capability 禁用。

清理方案不能只写 `nvidia-smi --gpu-reset`：官方说明 reset 受活跃进程、NVLink / NVSwitch / Fabric Manager 等条件限制，也不保证总成功。具体厂商及云平台没有认证的 reset / 清理路径时，默认隔离并采用已认证节点 power-cycle / rebuild / cloud fencing；命令成功也不能代替数据残留验证。[nvidia-smi reset](https://docs.nvidia.com/deploy/nvidia-smi/index.html#r-gpu-reset)

### B. MIG / 共享：独立运行时认证

1. 单独 mode / trust domain / vendor support matrix / discrete MIG profile、geometry generation 和容量分母；别沿用 A 的 `pgpu` 与全设备组账本假装支持 slice。
2. 普通容器 MIG 池仅开放给明确许可的信任域；任意非可信 VM 跨租户 slice 需受支持 hypervisor / vGPU / license / guest driver / host driver / attestation（若采用）独立路线。当前 NVIDIA Kata vGPU 不支持时直接禁用该组合。
3. 管理员才能改 MIG geometry；drain + 阻断准入 + 无用户 workload + 清理 / 改配置 / 健康 / 新 epoch / 对账后重开，防碎片浪费和正在运行任务受影响。[MIG Manager](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/26.3/gpu-operator-mig.html)
4. profile-specific 指标、OOM / fault blast radius、跨 slice 访问 / 残留、reset 影响范围和 upgrade / rollback 实机通过。Time-slicing / MPS 如果进入受控可信池，要额外实现 client termination、server fault / metrics attribution，不能直接用普通 `SIGKILL` 或 CPU pause 语义。

### C. CPU 沙箱调用可信 GPU 服务：并行优先验证

1. 不可信代码留在 CPU VM；可信模型服务独占或已认证 MIG 后端运行，部署批准模型与固定 engine / backend。禁止租户上传任意动态代码、插件、CUDA kernels；若开放自带模型则另立代码执行 / supply-chain 边界。
2. 独立 OIDC / service identity、tenant / project scopes、per-tenant admission / concurrency / token budget、payload bounds、timeouts、cancel、幂等 job ID 和审计；网络只允许受控 GPU API，结果 / 输入保留与日志脱敏按租户合同。
3. 常驻模型、bounded queue、动态 batch / continuous scheduling 的参数按所选推理引擎认证，模型 / shape / dtype / adapter / deadline 分类，不混入不兼容请求；固定延迟预算、backpressure 和公平策略，逐项测有效吞吐与成本。
4. GPU 服务 telemetry 可信采集；沙箱 API 返回 job 级别队列 / 计算时长 / 用量来源，外部 GPU service 并非给 CPU 沙箱“附加了一张物理卡”。尾延迟、数据越权、取消、部分失败、租户耗尽 / noisy-neighbor、服务重启与预算回退验收通过后才开放。

## 8. 对当前计划的具体调整

| 现有工作包 | 本次需要补充的开发 / 交付 | 退出条件 |
| --- | --- | --- |
| G0-08 | 将 `DEVICE_ACCESS`、`EXCLUSIVE_GROUP`、`MIG_PROFILE`、`TRUSTED_GPU_SERVICE` 分开冻结；效率五口径，invalid / all / unsupported fail-closed；GPU 启动定义包含首次正确 CUDA / 首次模型结果 | API / capability / workload SLO 和 trust source 合同一致；不能静默 CPU fallback |
| G1-11 | 固定 NVIDIA Kata cold-plug 候选及目标单卡 SKU；补设备 reset / IOMMU group / quarantined / 驱动与 guest 完整认证；CPU fast-template 不外推 GPU | 硬件矩阵与安全复用实机通过，失败仍禁用 |
| G2-13 | 权威设备 lease 与 placement 投影、原子 group、assignment epoch、物理库存与“共享访问名额”分账；pool owner / trust domain / GPU 保留预算 | 不重复授卡 / 跨 epoch 误释放 / 未清理复用；读写授权与升级测试通过 |
| G3-12 | DCGM / NVML version+field+source+trust capability；硬件活动、显存、queue、吞吐、assignment-hours、billable node-hours 并列 | 真实零 / stale / unsupported / 模型常驻 / 输入瓶颈可区分；租户归属无复制累加 |
| G3-13 | GPU 排队与输入准备、预拉只读 artifacts、bounded warm reservation；可信推理 API 并行路线；所有优化先 dry-run / 建议，再按显式策略执行 | 同负载同 SLO 成功率和单位成功任务成本可复核；无 guest idle 自报释放 |
| G4-09 | 独占 / MIG / service 分模式 benchmark 和安全 / 故障验收，CPU snapshot benchmark 与 GPU-ready 分列 | raw traces、SKU、driver / guest 组合、warm budget、失败与重试、账单证据完整；未通过模式不列可用 |

## 9. 实机对照实验设计

同一目标 SKU / 节点规模、相同镜像 / CUDA / 模型 / 输入集、相同资源和租户约束下，对比每个方案：冷节点冷镜像、节点热镜像、已预热 CPU 模板、持卡 owner 暖 VM、常驻模型服务；不能用热池命中与对方冷机冷镜像做“公平快多少”结论。

启动阶段统一记 `accepted → admitted → node/VM ready → driver ready → CUDA context ready → first correct GPU result`，至少给 p50 / p95 / p99、失败率、pool miss / fallback、并发和完成率；队列、model load 和网络时长保留。仅 TCP / execd ready 不算 GPU-ready。容量画像同时记录 CPU throttling、数据加载 / I/O、SM / tensor / DRAM 活动、显存、功耗、Xid、监控覆盖率和采集开销。

覆盖五类真实工作：小而稀疏 kernel、长期计算密集、显存常驻低 QPS、CPU / 网络输入瓶颈、多卡通信工作。对每类测独占 baseline、可信 service batching、另认证共享模式；输出同样成功任务的总成本及 SLO。实验门槛由 G0-08 按业务冻结；本次没有硬件结果，不能预填“90% 利用率”“毫秒 GPU 启动”或“节省 N%”。

低 GPU-Util、无 sample、Pod deleted、OOM、device-plugin unhealthy 都不证明设备或 VM 已安全释放。吞吐提升也不能抵消隔离或数据正确性失败；凡涉及租户共享、设备复用或自动缩容的模式，先通过该模式完整安全与生命周期门禁，再评价效率。
