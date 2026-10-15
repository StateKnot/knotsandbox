# 节点镜像预准备：固定版本官方源码核对

日期：2026-10-15。范围为 containerd **v2.3.5**、CRI API **v0.36.4**、OCI image-spec **v1.1.1**；这是研究记录，不是功能完成或目标云认证。
方法：仅查官方版本源码和规格；部分 raw 页面缓存未命中，改用 GitHub 官方 contents API 只读取得同一 tag 原文。没有下载完整仓库、运行容器或改变生产配置。
下文区分上游已实现事实、本仓当前事实与建议；不将上游接口当成本仓已交付功能。

## 1. CRI 镜像接口能证明什么

| 入口 | 固定版本事实 | 产品合同限制 |
| --- | --- | --- |
| `ImageFsInfo` | 返回 image/container filesystem 使用记录；每项含时间、mountpoint、可缺省的 used bytes/inodes，没有 capacity/available 字段。[CRI v0.36.4 定义](https://github.com/kubernetes/cri-api/blob/v0.36.4/pkg/apis/runtime/v1/api.proto) | 不从这个响应推导专属缓存容量、剩余可分配字节或利用率。 |
| `ListImages` | v2.3.5 从内存 imageStore 枚举；代码仍留有检查 snapshot 是否存在的待办。[实际实现](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/images/image_list.go) | 库存存在不单独证明实际 snapshot、内容完整或未来启动命中。 |
| `ImageStatus` | 同样经本地索引解析，未找到时空响应；实际 snapshot 存在性也没有在此完整验证。[实现与 CRI 转换](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/images/image_status.go) | 不能把一次非空响应签发成长期可用或 GC 引用证明。 |
| image `size` | 内部字段表示压缩镜像大小，计算使用平台匹配与 manifest usage；不是已去重的宿主磁盘物理占用。[内部 image store](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/store/image/image.go) | 可展示有来源的逻辑大小；不能将多个 image size 相加作物理使用量或可回收量。 |

`Image.id` 在该实现通常来自 image config digest；批准的 index digest、选中 manifest digest、config digest、rootfs ChainID 必须分列。[image store 的身份与 ChainID](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/store/image/image.go)

## 2. ImageFsInfo 的实际统计范围

v2.3.5 的实现按 snapshotter 聚合 snapshotStore 的 Size/Inodes，返回该组最老 timestamp；代码明确尚未统计 content store。[imagefs_info.go](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/images/imagefs_info.go)

默认 snapshotter 在 store 没有记录时仍会返回当前时间及零值；该零值只能解释为运行时报告，不能单独证明目录为空或物理缓存为零。[同一实现](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/images/imagefs_info.go)

同步器遍历 snapshotter 中的 snapshots，含 active 写层；已缓存的非 active 项可以只刷新 timestamp 而不重新调用 Usage。[实际同步器](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/images/snapshots.go)

单项 Usage 失败可以跳过，末尾删除本轮没有更新的旧记录；响应没有统计完整性标记。因此，即使 RPC 成功且 timestamp 新，也不能证明完整物理占用。[同步与错误路径](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/images/snapshots.go)

**设计推论：** 首个只读切片应命名为“CRI 报告的 snapshotter 使用量与镜像库存基线”，来源标记 `RUNTIME_REPORTED`，完整性、完整缓存物理总量、容量及可回收量保持 UNKNOWN。
其中成功标记仅表示身份、RPC、响应形状与适用时间检查通过；不能作为预拉硬预算准入条件。真实协议零值可保留，但不能改写成宿主实测空缓存。

## 3. PullImage 与 snapshotter 选择

CRI PullImage 请求只有镜像、认证和 sandbox config 等输入，没有本产品需要的预算、审批、可撤销租约或物理释放回执。[CRI v0.36.4 请求合同](https://github.com/kubernetes/cri-api/blob/v0.36.4/pkg/apis/runtime/v1/api.proto)

containerd v2.3.5 有 local pull 与 transfer service 两条路径；local 路径显式 pull/unpack，transfer 路径配置平台和 unpack。不能只观察下载完成就声称目标 snapshotter 可用。[实际 PullImage 路径](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/images/image_pull.go)

重要分支：`snapshotterFromPodSandboxConfig` 在 sandbox config 为 nil 时直接返回默认 snapshotter；只有非 nil config 才继续处理 runtime handler 的选择。[v2.3.5 对应函数](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/images/image_pull.go#L843-L873)

**设计推论：** 未来 Kata 预拉必须绑定实际 runtime handler、非 nil 的受控 sandbox config、实际 snapshotter 与平台；不能仅传一个 handler 字符串便宣称已为 Kata 准备。

CRI 插件使用 `k8s.io` 为 containerd 默认 namespace，默认 namespace 的其他客户端写入不能自动当作 CRI 已准备。[CRI 常量](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/constants/constants.go)、[插件实际客户端与 snapshotter 初始化](https://github.com/containerd/containerd/blob/v2.3.5/plugins/cri/images/plugin.go)

## 4. 删除、原生 lease 与 GC

RemoveImage 会解析 image 并删除其全部 references，最后一项尝试同步删除/触发 GC；源码明确这是尽力行为。[实际 RemoveImage](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/images/image_remove.go)

所以不能用“删除本次准备时提交的一个 tag”假定仅删除自己的缓存引用；共享 alias 的全部所有者必须先被识别。[相同实现](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/images/image_remove.go)

原生 Leases gRPC 提供 Create/Delete/List、AddResource/DeleteResource/ListResources；Delete 仅让没有其他引用的对象可被 GC，`sync` 是独立显式选项。[v2.3.5 leases.proto](https://github.com/containerd/containerd/blob/v2.3.5/api/services/leases/v1/leases.proto)

原生 lease 可关联 content、ingest、snapshotter 资源；Go lease manager 有显式到期标签和同步删除选项。[lease 类型及选项](https://github.com/containerd/containerd/blob/v2.3.5/core/leases/lease.go)

Go client 默认 `WithLease` 在没有现有 lease 时创建 24 小时到期租约；该默认值不等于本产品批准期限。[client/lease.go](https://github.com/containerd/containerd/blob/v2.3.5/client/lease.go)

GC 还遵循 image、container、snapshot parent 和内容引用关系；删除某个准备 lease 不会删除仍被其他对象引用的共享内容。[官方 GC 文档](https://github.com/containerd/containerd/blob/v2.3.5/docs/garbage-collection.md)

文档支持通过 `containerd-lease` gRPC metadata 传递原生 lease；本产品仍须实测 CRI 包装层、内部 transfer/local 路径及 namespace 是否保留所需引用，不直接承诺“加 header 即完成”。[GC 的 gRPC 合同](https://github.com/containerd/containerd/blob/v2.3.5/docs/garbage-collection.md)

**设计推论：** 逻辑准备授权撤销、去掉自己的引用、GC 完成、文件系统空闲量变化是不同事实。时间差额、RPC OK、Pod 缺失均不能归因为本租约释放了某个物理字节数。

## 5. OCI 多平台与预算输入

OCI index 是指向平台 manifest 的上层对象；平台包含 OS、architecture 及可选 variant，index digest 不能与某一平台 manifest digest 混用。[OCI v1.1.1 index](https://github.com/opencontainers/image-spec/blob/v1.1.1/image-index.md)

descriptor 的 size 是被引用原始内容的字节长度，digest 校验用于确认实际取得内容；它不是解压后 snapshot 大小或并发解压内存上限。[OCI v1.1.1 descriptor](https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md)

**尚未认证：** 本仓将采用的 index/manifest/platform 解析器、目标 snapshotter、native lease 实际覆盖、共享层所有权、部分拉取恢复、解压硬限和真实 GC 空间证据。批准 digest 不自动填补这些合同。

## 6. 本仓可复用路径与首个完整交付边界

本仓 `src/runtime_manifest.rs` 已使用批准 repo@digest 与 IfNotPresent；`src/nodeguard/generated/runtime.v1.rs` 有固定 CRI ImageService client，但尚无镜像预准备或原生 lease 集成。
`deploy/nodeguard/host_profile.py` 固定 image endpoint 直连 containerd，且继续禁止 VM template/cache；`src/nodeguard/runtime_observation.rs` 的现有计时明确不含 image pull。
`src/nodeguard/metrics_server.rs`、`src/metrics.rs` 与 `deploy/observability/observability.py` 当前均按 VM/tenant/launch 绑定，不覆盖节点级库存和 snapshotter 报告使用量。

建议先复用同一 nodeguard、scraper CA、Prometheus Agent，增加有界只读采集及明确 operator 消费者；不创建第二 daemon，不将整节点值复制到每个 VM，不暴露镜像名/registry secret。
节点级标签及查询必须独立于 VM 身份，固定 node UID/boot/epoch/profile 与受校验 FS 身份；现行 relabel 会拒绝没有 tenant/launch 标签的样本，须同步更新白名单及 sample/WAL 预算。
mountpoint 只作为受控候选，以固定 FD、挂载/device 身份和前后复核验证；它本身不证明某块盘或独占缓存目录。具体宿主配置仍需独立测试。
operator CLI/status、实际 mTLS→双 Agent→remote-write→固定查询、失败/身份漂移清旧值，是该只读切片的完整消费者与退出门；只新增类型或未接入指标不计交付。

下一阶段才允许批准 artifact→有界准备许可→原生引用→实际拉取/unpack→期限/撤销→GC/释放证据全链；不能用本研究替代实现或真实 Linux containerd 验收。
真实 Kata/目标云 snapshotter 与磁盘配置、端到端冷暖首任务、72 小时成本/SLO、GPU 设备及残留清理均保留独立外部验收门。
