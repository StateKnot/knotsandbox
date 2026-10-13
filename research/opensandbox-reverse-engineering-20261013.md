# OpenSandbox 快速启动、资源效率与 GPU：固定源码逆向记录

日期：2026-10-13。研究对象：OpenSandbox `c806a49c62ee1fc3baa036165e9044e7b0efd97f`，以及其实际构建依赖 fast-sandbox `b702fbe71593df4f36b591e540445c251a698e7c`。源码已按 Git blob 核对；这次没有在实云运行沙箱，也没有实测 GPU。方法采用 REA 的证据分层：产品描述是宣称，函数调用链是实现证据，仓库发布的 benchmark 是一方实验，独立算术复核只能证明报告内部一致性。

## 结论

快速启动来自把工作提前做完：预先创建 Fastlet Pod、网络槽和模板快照，把镜像转换、内核启动、execd 初始化移到模板构建阶段；请求到来时主要做持久化意图、节点选择、CoW 根盘克隆、Firecracker 快照恢复和路由就绪。最新版 README 的 64 ms 数字属于这种模板热启动，不属于普通 Docker 创建、冷镜像下载或所有 Kubernetes 创建。[后端分流源码](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/services/composite_service.py#L62)、[运行时恢复入口](https://github.com/opensandbox-group/fast-sandbox/blob/b702fbe71593df4f36b591e540445c251a698e7c/internal/runtime/firecracker/driver.go#L389)。

资源效率的实现证据是基础设施共享、根盘 CoW、镜像命中优先、可配置聚合预算、回收和检查点释放运行时。没有公开证据证明任意生产负载下 CPU、内存或 GPU 利用率很高。预热需要付空闲成本，超分增加争用和 OOM 风险；不能把“支持高密度”当成利用率测量。[聚合预算实现](https://github.com/opensandbox-group/fast-sandbox/blob/b702fbe71593df4f36b591e540445c251a698e7c/internal/controlplane/reconciler/sandboxpool_controller.go#L1582)、[容器子 cgroup 限额](https://github.com/opensandbox-group/fast-sandbox/blob/b702fbe71593df4f36b591e540445c251a698e7c/internal/runtime/containerd/driver.go#L525)。

普通 Docker 和 Kubernetes 路径已经实现 NVIDIA GPU 整数请求映射；没有找到同等完整的 GPU 利用率治理、MIG 配额、分时隔离或 GPU 状态快照链路。64 ms Firecracker 模板路径的资源类型只有 CPU、内存和 PID，不能据此推定快速 GPU 沙箱已经可用。[Docker 设备请求](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/services/docker/container_ops.py#L329)、[Kubernetes 翻译](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/services/k8s/provider_common.py#L55)、[Fast Sandbox 资源类型](https://github.com/opensandbox-group/fast-sandbox/blob/b702fbe71593df4f36b591e540445c251a698e7c/api/v1alpha2/sandboxpool_types.go#L30)。

## 1. 三条启动路径必须分别比较

| 路径 | 实际调用链与完成边界 | 快的原因与限制 |
|---|---|---|
| Docker image | `create_sandbox → _provision_sandbox → _ensure_image_available → _create_and_start_container → runtime injection → container.start`；服务返回 `Running`，SDK另取 endpoint 并检查健康 | 本地镜像命中免 pull；依然每实例 create/start，有 execd 安装与可选 egress sidecar。没有证据把模板 64 ms 数字应用于它 |
| Kubernetes image / BatchSandbox | workload provider 写工作负载；operator 分配预热 Pod 或创建新 Pod；`_wait_for_sandbox_ready` 观察实际状态 | Pool 命中省新 Pod 调度和启动；空池仍需要补容、镜像与运行时；容器 CPU/memory requests 默认等于 limits |
| Kubernetes template / Fast Sandbox | `CompositeSandboxService → FastSandboxService → FastPath.CreateSandbox → Fastlet.CreateSandbox → runtime.EnsureSandbox → endpoint → SDK /ping` | 一 Fastlet 承载多个实例，绕过每实例新 Pod 的 scheduler/kubelet 链；保留 K8s CR 意图写入和每实例安全准入 |

证据：[Docker image 命中](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/services/docker/container_ops.py#L218)、[Docker create/start](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/services/docker/container_ops.py#L402)、[K8s 创建后等待](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/services/k8s/kubernetes_service.py#L1203)、[Fast Sandbox adapter](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/services/fast_sandbox/service.py#L325)、[SDK readiness](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/sdks/sandbox/python/src/opensandbox/sandbox.py#L743)。

“constant-time create”是文档的架构目标，不能当算法复杂度证明：固定代码的 Registry `TopK` 遍历 Fastlet 集合并排序，规模是约 `O(F log F)`；FastPath 仍调用 `K8sClient.Create` 先写完整 Sandbox CR，再调用 Fastlet。省掉的是新 Pod 的调度、watch 与 kubelet等待，K8s API 并未完全离开热路径。[Registry.TopK](https://github.com/opensandbox-group/fast-sandbox/blob/b702fbe71593df4f36b591e540445c251a698e7c/internal/controlplane/placement/registry.go#L259)、[acceptCreateIntent](https://github.com/opensandbox-group/fast-sandbox/blob/b702fbe71593df4f36b591e540445c251a698e7c/internal/controlplane/fastpath/server.go#L219)。

## 2. 热启动究竟省了什么

| 技术 | 固定源码证据 | 实际省掉的工作 | 仍需付的成本 |
|---|---|---|---|
| 固定模板和运行时 profile | `map_template_create_request` 将模板 artifact 作为 image；`validateRestoreMachineConfig` 检查模板机器形状 | 请求时无需完整装系统、启动内核、重新定义 vCPU/memory | 模板构建、兼容性检查、版本更新；模板请求不能任意改 shape |
| 预建网络槽 | `network.Manager.Initialize/Replenish` 提前准备；`Acquire` 只取 Clean 槽并持久化 owner | 每次建 netns、veth、TAP、网关的大部分成本 | 热槽库存、持久化、清理与补充；无 Clean 槽会拒绝 |
| CoW 根盘 | `prepareJailRoot → copyReflinkOrCopy`；初始化要求 XFS 和实际 `cp --reflink=always` 探针 | 无需逐字节复制整个 rootfs | 后续写入真实分配块；磁盘压力、镜像缓存和 GC；跨文件系统不能靠 reflink |
| 快照恢复 | `configureRestoreVM → LoadSnapshot`，File memory backend、网络接口 override，再 `resumeVM` | 不重新内核冷启动；已有 guest 网络/execd 状态可恢复 | VMM 启动、socket、状态加载、页面访问、路由和 guest readiness |
| 同 Fastlet 共享基础服务 | shared egress / DNS / Fastlet infra，按 subject 与 owner 分配 | 减少每实例常驻 sidecar 与 Pod 开销 | 共享组件容量、故障域、策略绑定和拒绝优先执行；不能丢掉隔离 |
| 命中优先 | Registry 优先 `imageHit`，其次 `used/capacity`，stable hash 打散 | 减少请求时远端 artifact 下载 | 心跳状态可能过时，最终仍由 Fastlet原子准入裁决 |

证据：[模板映射](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/services/fast_sandbox/create_mapping.py#L155)、[机器形状验证](https://github.com/opensandbox-group/fast-sandbox/blob/b702fbe71593df4f36b591e540445c251a698e7c/internal/runtime/firecracker/restore.go#L119)、[网络 Acquire](https://github.com/opensandbox-group/fast-sandbox/blob/b702fbe71593df4f36b591e540445c251a698e7c/internal/fastlet/network/manager.go#L212)、[CoW 根盘和快照链接](https://github.com/opensandbox-group/fast-sandbox/blob/b702fbe71593df4f36b591e540445c251a698e7c/internal/runtime/firecracker/launcher.go#L221)、[XFS 启动探针](https://github.com/opensandbox-group/fast-sandbox/blob/b702fbe71593df4f36b591e540445c251a698e7c/internal/runtime/firecracker/storage.go#L13)、[LoadSnapshot](https://github.com/opensandbox-group/fast-sandbox/blob/b702fbe71593df4f36b591e540445c251a698e7c/internal/runtime/firecracker/restore.go#L299)、[共享服务架构](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/docs/architecture/fast-sandbox/index.md#L22)。

Firecracker 创建先检查完整 rootfs/vmstate/memory artifact，缺失则异步交付并停在 image-pending，完整提交后再恢复，避免下载未完成就消耗网络槽。这是控制面异步化；用户等待 usable guest 时，冷下载仍必须计入。[镜像就绪检查](https://github.com/opensandbox-group/fast-sandbox/blob/b702fbe71593df4f36b591e540445c251a698e7c/internal/runtime/firecracker/driver.go#L429)、[Fastlet 异步交付](https://github.com/opensandbox-group/fast-sandbox/blob/b702fbe71593df4f36b591e540445c251a698e7c/internal/fastlet/sandbox/admission.go#L74)。

## 3. “启动很快”的数字与成功率

官方 2026-10-08 ACK 报告是两节点工程实验，节点各暴露 192 CPU、约742 GiB可分配内存；五个 Fastlet，每个四槽，共20槽。负载是 Alpine + execd、1 vCPU、2 GiB内存、2 GiB rootfs；Firecracker 1.16.1；模板已缓存在两节点，XFS reflink根盘；客户端位于集群内，metrics关闭、健康轮询10 ms而SDK默认200 ms。实际部署是 `release-1.1.1-rc.1` 派生镜像，不能自动视为本次固定SHA的性能证明。[原始环境与逐次样本](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/docs/public/benchmarks/fast-sandbox-ack-2026-10-08.json)。

本次用 Python 标准库对原始 `successful_samples.ready_ms` 做 nearest-rank 复算，结果与报告一致；这是报告算术核对，没有运行他们的工作负载：

| 创建组 | 成功 / 尝试 | P50 | P99 | 含义 |
|---|---:|---:|---:|---|
| 初始热串行 | 100 / 100 | 63.995 ms | 108.324 ms | README 64 ms来源 |
| 与并发实验同期的串行重复 | 100 / 100 | 77.862 ms | 112.521 ms | 保留批次差异，不能把两串行组混成一个分布 |
| 并发10 | 100 / 100 | 102.706 ms | 125.438 ms | 模板缓存、预热容量条件下的 SDK就绪 |
| 并发20 | 51 / 100 | 136.654 ms | 196.965 ms | 仅成功请求的延迟；48次429、1次健康超时，不能宣称可靠20并发 |

每组先做两次未计时warmup、100次计时；定时从 `Sandbox.create_from_template()` 开始，到 gateway 后 guest `/ping` 200。每次创建后销毁，并发批次间有5秒回收等待，销毁和批次等待不进单实例延迟。它证明热创建链路可以很短，不能证明冷创建、持续吞吐、节点高利用率或无回收成本。[基准方法与失败记录](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/docs/public/benchmarks/fast-sandbox-ack-2026-10-08.json)、[采样脚本](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/scripts/fast-sandbox-env/create-bench.py)。

同一次报告还表明 durable pause 中位约61.14秒，SDK同节点 resume到guest ready约62.66秒，仅三个样本；对应缓存后的runtime恢复约35.49 ms。live snapshot只有一个样本、约60.63秒才可用。报告没有重测冷内核启动、DART冷交付/P2P命中或 live snapshot期间连续请求。runtime restore几十毫秒不能替代用户可用的resume时间。[生命周期逐次原始记录与 limitations](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/docs/public/benchmarks/fast-sandbox-ack-2026-10-08.json)。

## 4. “资源利用率高”的真实机制和代价

| 机制 | 实现状态 | 适合借鉴的部分 | 必须计量的代价 |
|---|---|---|---|
| SDK client pool | 已实现但官方标experimental；缓存已创建实例ID，acquire再connect/health/renew；无归还业务沙箱的release | 有TTL、安全清理、限创建QPS的ready buffer | 热实例空闲资源；max_idle不是租户并发上限，direct-create可超出buffer |
| Kubernetes Pool | Pod template、bufferMin/Max、poolMin/Max、Delete/Restart/Noop回收策略 | 用边界明确的容量池减少启动开销 | Restart/Noop不自动证明租户数据清除；不可信多租户首选重建或可信黄金状态 |
| Fastlet aggregate budget | 默认 `overhead + N × per-instance`；显式更低limit才超分；请求不得高于limit | CPU统计超分与外层Pod预算可以组合 | 高峰CPU节流、父cgroup OOM、邻居影响；不能仅看logical slot利用率 |
| 镜像/根盘/内存快照缓存 | CoW rootfs、snapshot hardlink、File backend；命中优先与缓存GC存在 | 镜像digest、来源验证、局部CoW、缓存成本观测 | CoW不会免费存未来写入；File backend不自动证明RSS长期共享比例或内存超分安全 |
| pause释放runtime | 检查点持久化后释放Fastlet容量，保留恢复数据 | 长空闲时段可省计算占用 | hash/upload、storage、冷恢复、网关等待；仍有对象/缓存/平台成本 |
| 自动idle pause/wake | OSEP状态implementing，已有服务端/ingress代码，默认关闭、限Fast Sandbox、需显式opt-in | 活动判断未知时保守不暂停、bounded parking、singleflight、desired-state恢复 | ingress无请求不等于GPU/后台进程闲；websocket/SSE、定时任务需单独处理；现有分钟resume不能许诺亚秒唤醒 |

证据：[client pool acquire](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/sdks/sandbox/python/src/opensandbox/pool_async.py#L233)、[client pool生命周期限制](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/docs/guides/client-pool.md#L83)、[K8s pool规格](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/kubernetes/apis/sandbox/v1alpha1/pool_types.go#L26)、[聚合预算实现](https://github.com/opensandbox-group/fast-sandbox/blob/b702fbe71593df4f36b591e540445c251a698e7c/internal/controlplane/reconciler/sandboxpool_controller.go#L1582)、[容器强制限额](https://github.com/opensandbox-group/fast-sandbox/blob/b702fbe71593df4f36b591e540445c251a698e7c/internal/runtime/containerd/driver.go#L525)、[检查点状态和代价](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/docs/architecture/fast-sandbox/checkpoints.md#L11)、[idle决策源码](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/integrations/idle_pause/decision.py#L15)、[OSEP-0024状态与非目标](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/oseps/0024-auto-pause-and-wake-on-access-for-fast-sandbox.md#L1)。

Fastlet的容器路径有OCI CFS、memory、pids约束证据；Firecracker路径恢复的是模板既有机器形状，本次在其驱动调用链没有找到等价的每VM宿主`cpu.max/memory.max`配置证明。不能把guest vCPU/内存规格直接当作VMM的宿主硬上限；需要在实机读取进程cgroup归属、父层限额、满载节流/OOM以及清理后资源释放。[Firecracker shape验证](https://github.com/opensandbox-group/fast-sandbox/blob/b702fbe71593df4f36b591e540445c251a698e7c/internal/runtime/firecracker/restore.go#L119)、[实际launch argv](https://github.com/opensandbox-group/fast-sandbox/blob/b702fbe71593df4f36b591e540445c251a698e7c/internal/runtime/firecracker/launcher.go#L163)。这是本次证据边界，未作漏洞定性。

最新execd资源采集已用sandbox cgroup的CPU累计时间/容量和memory使用/限额，working set近似为usage减inactive_file；不可读时会回退host视图。guest里host是VM本身，普通容器里host可能是物理节点。Knotsandbox应保留scope/source/quality与未知状态，避免scope在失败时静默变化。[采集源码](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/components/execd/pkg/resources/resources_linux.go#L45)、[内存回退与working set](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/components/execd/pkg/resources/resources_linux.go#L284)。

## 5. GPU：支持设备访问与高利用率是不同交付

| 路径 | 固定源码里可以确认 | 没有被证明的能力 |
|---|---|---|
| Docker | `gpu: "N" → DeviceRequest(count=N, capabilities=[["gpu"]])`；`all → -1`；非法数值400；需要宿主NVIDIA工具链 | 不能据此证明每租户显存限额、MIG实例选择、device UUID稳定租约、MPS/分时QoS或VM内可见 |
| 普通Kubernetes | `gpu: "N" → nvidia.com/gpu: "N"`；默认requests=limits；all拒绝 | 原生整数扩展资源依赖driver/device-plugin；没有专属GPU利用率治理或MIG profile产品契约证据 |
| Windows/QEMU-in-container profile | 外层GPU请求特意不传，因为Windows guest看不到仅给外层Linux容器暴露的GPU | 未形成vGPU/VFIO guest设备链路 |
| Fast Sandbox模板/Firecracker | 模板创建仅接受cpu/memory/disk，gpu返回400；SandboxResourceProfile为CPU、memory、pids，resourceRequests拒绝，模板shape固定 | 没有找到GPU claim/设备注入/guest CUDA/显存状态快照和恢复证据；热启动数字不能外推GPU |

证据：[gpu解析与Docker request](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/services/docker/container_ops.py#L329)、[K8s mapping](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/services/k8s/provider_common.py#L55)、[Windows profile边界](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/services/docker/docker_service.py#L775)、[Fast Sandbox资源类型](https://github.com/opensandbox-group/fast-sandbox/blob/b702fbe71593df4f36b591e540445c251a698e7c/api/v1alpha2/sandboxpool_types.go#L30)、[模板GPU明确拒绝](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/services/templates/template_service.py#L192)、[Fast Sandbox请求限制](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/services/fast_sandbox/create_mapping.py#L277)。更多GPU隔离、身份归因与计量要求见[GPU专项记录](sandbox-gpu-reverse-engineering-20261013.md)。

发现一个值得我们避开的API行为：K8s路径对不可解析/非正的gpu值会删除该字段后继续构造CPU沙箱，其回归测试明确期望这个行为；Docker同类参数会400。我们的产品应统一失败关闭：用户请求GPU但参数非法、设备不可满足、runtime不支持时明确拒绝，不能静默降级。[drop分支](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/opensandbox_server/services/k8s/provider_common.py#L104)、[相应测试](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/server/tests/k8s/test_provider_common.py#L76)。

GPU资源模型必须选定模式，不能用一个`gpu: 0.5`含糊覆盖：

| 模式 | 多租户隔离边界 | 对我们的采用建议 |
|---|---|---|
| 整卡独占 | 明确设备分配；仍需证明runtime/driver/guest安全和释放 | 第一条GPU生产路径：GPU专用节点池、设备租约、硬隔离runtime认证，实际guest运行CUDA验证 |
| MIG | 硬件固定compute/memory分区，具memory/fault isolation；不是完整系统隔离 | 支持的GPU型号上用明确MIG profile + UUID/GI/CI身份、独立配额与观测；仍需VM/容器隔离验证 |
| time-slicing | 官方明确无memory/fault isolation；replica是访问资格，不是固定算力/显存份额 | 仅可信同域可显式选择；不作为企业非可信代码默认隔离方案 |
| MPS /软件分片 | 单独的兼容性、故障域与公平性问题，不能推定等价MIG | 后续专项验证，先记录不支持；避免先承诺分数GPU而后补隔离 |

外部约束：K8s GPU requests/limits只能缺省跟随或相等，不能用CPU式超分；NVIDIA MIG能提供硬件分区隔离，而time-slicing不能提供显存和故障隔离，请求多个replica也不等于得到多份算力。[Kubernetes GPU契约](https://kubernetes.io/docs/tasks/manage-gpus/scheduling-gpus/)、[NVIDIA device plugin](https://github.com/NVIDIA/k8s-device-plugin)、[NVIDIA GPU Operator time-slicing说明](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/latest/gpu-sharing.html)、[NVIDIA MIG介绍](https://www.nvidia.com/en-us/technologies/multi-instance-gpu/)。

## 6. 对 Knotsandbox 的生产落地顺序

以下是从已确认机制提出的研发建议，没有把它们标记成已开发或已通过生产验收：

| 顺序 | 需要实现 | 架构与验收要求 |
|---|---|---|
| 1 | 生命周期分阶段计时与容量/利用率统一口径 | 从API入站到guest成功命令；分admission、调度、artifact、CoW、VMM、策略、route、ready；记录资源申请/实际准入/host限额/当前使用、scope、epoch；冷/热、cache hit/miss、重试/失败均保留 |
| 2 | 镜像/模板缓存与受预算约束的预热池 | 已校验digest与兼容性，模板不得带租户秘密；节点磁盘/内存floor、对象与镜像GC、冷热命中率；buffer与租户并发/配额分离；队列+429带恢复提示；不能通过跳过health加速 |
| 3 | CoW根盘与已认证runtime模板恢复 | 固定Kata/QEMU等现有隔离runtime，先证实自己的可恢复内存/磁盘格式；文件系统真实CoW探针、CPU/kernel/runtime兼容、fresh身份/密钥/网络、并发恢复和回滚；不可直接把Firecracker模板移植到不兼容VMM |
| 4 | 安全闲置治理与CPU受控超分 | 先建议后自动动作；考虑exec/file/网络/后台任务/健康/IO/GPU活跃、多来源未知；CAS和代际fence、外部调度、权限、最大parking与恢复并发；CPU超分必须通过高峰SLO，内存先不默认超分 |
| 5 | GPU整卡与MIG生产路径 | API明确mode/count/profile；admission绑定实际device/MIG租约；GPU专用节点、driver/plugin/runtime pin；guest CUDA、越界隔离、显存耗尽/设备fault、重启/删除释放、配额计费、DRAIN与健康隔离；GPU checkpoint未认证就拒绝pause/迁移 |
| 6 | 资源效率闭环与72小时容量验收 | 同时报告成功率、吞吐、端到端P50/P95/P99、warm idle成本、RSS/working set、节流/OOM、磁盘真实增量、设备SM/显存/功耗/ECC/Xid；故障注入、租户噪声、并发/队列/回收、跨节点恢复；GPU无设备数据标未知，不能填0 |

预热预算可以先按到达率与补容P95估算buffer，再使用真实命中率和空闲成本调节；暂停的经济性按`省下的计算成本 > checkpoint上传/存储/恢复成本 + SLA代价`判断。公式是设计推导，不是OpenSandbox测量结果。我们的基准必须包含0%/50%/100%缓存命中、串行/10/20/目标饱和、短任务/长闲置/高写入/GPU突发；持续arrival测试不得插入未入账回收暂停来抬高吞吐。

## 7. 证据与未知项登记

- 已确认实现：后端分流、Docker本地镜像缓存、普通K8s Pool与资源请求、FastPath持久化CR、TopK局部registry、Fastlet锁内容量准入、预建网络槽、XFS真实CoW检查、File backend snapshot恢复、固定CPU/memory/pids profile、普通Docker/K8s NVIDIA整数请求映射。
- 官方实验：2026-10-08 ACK热创建和生命周期原始样本；本次仅复算其计数和百分位，不是独立性能复现。
- 不足以确认：持续CPU/内存/GPU高利用率、完整多租户GPU隔离、MIG产品契约、GPU checkpoint、Fast Sandbox Firecracker每VM宿主硬限、跨节点resume SLO、冷kernel/artifact交付、生产尾延迟和目标饱和吞吐。
- 需要校验的宣传边界：64 ms有warm/cache/profile条件；并发20成功率51%；runtime恢复35 ms对应SDK约一分钟；client pool是experimental且不是并发配额。
- 源码借鉴采用架构与独立实现；如实际引入Apache-2.0源码或组件，需保留其许可与NOTICE要求，MIT产品自己的许可不能移除上游条款。[OpenSandbox许可](https://github.com/opensandbox-group/OpenSandbox/blob/c806a49c62ee1fc3baa036165e9044e7b0efd97f/LICENSE)。

本地证据目录：`.local/sandbox-reverse-engineering-20261013/`；包含固定version、OpenSandbox和fast-sandbox源码manifest、Git blob/文件SHA、原始仓库benchmark及`opensandbox-benchmark-arithmetic.json`复算结果。外部仓库下载内容仅作为不可信研究数据，没有执行其脚本、构建其镜像或调用商业服务。
