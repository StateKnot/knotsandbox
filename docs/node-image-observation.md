# 节点镜像只读诊断

此接口是镜像预准备计划的 **P0a 宿主诊断子项**。它读取固定 containerd 2.3.5 的库存和 snapshot-store 使用量，不拉取、解包、删除镜像或创建 VM。P0b 的 Prometheus 节点管线与 P0c 的安装级授权/API 尚未交付，整套节点观测默认关闭。

## 接入与身份边界

接口为现有 nodeguard 私网 9445 监听器上的 `GET /v1/node-image-status`，与 `/metrics` 共用独立 scraper-client CA。匿名和 controller 客户端证书无法访问；普通产品 OIDC token 或 `instances:read` 不授予访问权限。响应设置 `Cache-Control: no-store`，读取缓存不触发后端 RPC，也不占用 VM 抓取槽；支持标准 HEAD（无正文），其余方法返回 405。

`metrics.image_observation` 默认为 false，未启用时路由不存在并返回 404。启用还需要重新认证的 HostProfile 包含受控 `image_observation` 策略；唯一支持的策略为 overlayfs 及固定路径 `/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs`。该路径只在宿主核验，不是 API 参数。修改 profile 会改变其摘要，必须经过原节点认证流程，不能就地修改已登记 profile 后继续使用旧身份。安装器目前不生成该策略或开启此开关；完成 P0b/P0c 及目标宿主认证后再统一开放。

原有强制启动配置检查通过后，独立镜像诊断构造/认证失败只关闭该路由，原 CRI/control 服务继续；原有强制 profile、摘要和 boot 校验失败仍按原合同拒绝启动。后端连接和 Version 握手由独立后台 owner 负责，失败返回明确 UNKNOWN，并在原 15 秒间隔后重试；它不成为现有 CRI 启动的新依赖。固定 root UDS、进程身份、profile/config、节点 boot、文件系统 FD/device/inode/mount identity 在收集前后核验，身份冲突不会发布成功值。登记的 cluster epoch 是本地认证事实；安装级当前 epoch/revocation 链路仍待 P0c 实现，不能将此接口当作全局管理接口。

## 响应含义

| 字段 | 含义 |
| --- | --- |
| `enabled` / `node` | 该 collector 的启用状态及原认证 NodeBinding；Node UID/boot/profile/epoch 不由调用方指定 |
| `source` / `completeness` | 固定 `RUNTIME_REPORTED` / `UNKNOWN`；成功响应不证明全量统计完整 |
| `observed_at` | 通过宿主身份检查的本轮采集时间；后端失败也可能有时间，不能替代各成功标记。尚未采集、宿主检查失败或整体缓存过期为 null；读取不刷新 |
| `inventory.observation_success` | ListImages 的 RPC、结构、数量与身份验证成功 |
| `inventory.image_count` | CRI 索引条目数，不保证物理内容或可用 snapshot 仍在 |
| `inventory.compressed_logical_bytes` | 索引压缩逻辑大小之和，共享层可能重复；不是物理占用 |
| `filesystems.observation_success` | ImageFsInfo 报告及固定宿主文件系统核验成功 |
| `filesystems.entries` | 不透明 FS ID、原 `runtime_reported_at_ns`、可空 `used_bytes` / `inodes_used` |

数量和纳秒时间均用十进制字符串，避免 JavaScript 安全整数丢失；缺字段用 null/空列表和成功标记 false，不能补零。库存与 FS 独立缺测，一个失败不抹去另一个有效事实。报告范围分别为 `CRI_INDEX_COMPRESSED_LOGICAL` 和 `RUNTIME_SNAPSHOTSTORE_REPORTED_USAGE`，不输出 repository、镜像 ID 或原始路径。

固定版本 ImageFsInfo 的 snapshot-store 统计排除 content store，且可能遗漏对象；没有 capacity、available、reclaimable、完整 cache bytes 或命中率字段。即使真实 content store 非空、FS 报告为零，也不能推导缓存占用为零或可释放量。完整性必须保持 UNKNOWN，不能用本接口作为下载硬预算准入或 GC 证明。

## 资源与退出规则

单 collector 生命周期、独立单槽宿主工作 owner；RPC/握手期限 2 秒，采集间隔 15 秒，缓存有效期 60 秒。读取同时检查原 FS runtime 时间，超过 5 秒的未来时间或超过 60 秒的旧时间使 FS 失效，即使库存缓存仍新鲜。停止、失败、profile/boot/mount 冲突清除旧成功；后台 owner 随指标监听器取消并 join，阻塞工作在真正退出前仍持有自己的槽。

库存正文最大 1 MiB / 1024 项，FS 最大 64 KiB / 16 项；解码前检查 protobuf 结构、字段与字符串边界。截断或超限是失败，不输出部分和冒充全量。没有新增 VM 指标或节点 Prometheus 样本，没有扩大原 VM 抓取期限、权限或线程栈。

## 可重复验收

`scripts/test-nodeguard-image-observation.py` 使用正常 Cargo JSON 制品，核对实际 ELF/架构/源码，固定官方 containerd 归档与校验资产，构造只有 FROM/COPY 的最小夹具镜像。它在只读、无网络、drop-all-capabilities、无宿主 socket/卷的自有 Docker 容器中导入一个非空 OCI 镜像（不 unpack），通过真实 ImageService 和独立 mTLS HTTP 消费者验证无 VM 库存、整数、独立 FS、权限与清理。对 profile 中 Kata 文件的固定夹具只用于文件身份校验，不执行或认证 Kata。

Linux CI 使用 `--artifacts .local/nodeguard-host-artifacts.jsonl` 复用既有正常构建，失败不跳过该门；回执保留源码/制品稳定性及精确自有清理结果。macOS 可编排同绝对路径生成的 Linux ELF，不能原生执行 ELF。Python 行为测试覆盖预检失败回执、中断和假 PASS 防护。实际 Docker、源码合同和目标云/Kata/GPU/性能认证分别记录，不互相替代。
