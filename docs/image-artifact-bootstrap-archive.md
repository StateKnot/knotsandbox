# 单镜像 OCI 归档导出合同

`sandbox-admin image-artifact export-bootstrap-archive` 和公共 Rust 函数 `sandbox_platform::image_artifact::export_bootstrap_archive` 将一份本地 OCI layout 中的指定镜像，导出为供可信原生导入者消费的确定性 USTAR 流。它复用已有元数据与实际层载荷校验，不维护另一套镜像验证规则，也不连接数据库、注册表或运行时。

这是准备链中的归档生产者。镜像审批、完整准备执行器、在线下载、内核硬限、原生 lease／GC 保护和普通启动许可仍是独立合同；导出成功不会将镜像设为 Ready 或启用 pre-pull。完整方案及当前缺口见[生产计划](../research/image-preparation-production-plan-20261015.md)与[本批交付](../research/image-bootstrap-archive-delivery-20261019.md)。

## 调用接口

参数均须由可信调用方确定，预期摘要必须来自独立可信来源。以下示例的字节预算仅展示参数形状，不是通用生产容量配置；stdout 的接收文件必须由外层执行器在已核实的存储／inode 硬域内排他创建。

```sh
sandbox-admin image-artifact export-bootstrap-archive \
  --layout /srv/reviewed-images/example \
  --expected-digest sha256:<independently-trusted-manifest-digest> \
  --platform linux/amd64 \
  --reference registry.example/team/example@sha256:<same-manifest-digest> \
  --max-layer-bytes 1048576 \
  --max-total-layer-bytes 2097152 \
  --max-decoded-layer-bytes 4194304 \
  --max-total-decoded-bytes 8388608 \
  --max-archive-bytes 3145728 \
  --deadline-seconds 60
```

成功时 stdout 仅含二进制归档，stderr 为空，退出码为 0。失败返回非零及固定诊断码，但 stdout **可能已有部分归档**。不能直接把该命令管道接到 `ctr images import`：导入者可能在生产者失败之前已写入内容。可信消费者须先保存输出，确认进程成功、完整落盘与独立大小／SHA 读回，再消费；flush 不替代调用方对其存储介质执行 fsync 和持久性检查。失败输出保留为本次未知残留，不自动重试或冒充完整归档。

Rust 接口接受 `&Path`、独立 expected digest、精确 platform、reference、`BootstrapArchiveLimits` 和 `&mut impl Write`。`BootstrapArchiveLimits::new` 包含已有 `PayloadLimits`、完整归档字节上限和协作期限。返回值 `ExportedBootstrapArchive` 可序列化，包含归档字节数、SHA-256、条目数、已验元数据及 DiffID 事实；CLI 为保持纯二进制 stdout，不另行混写 JSON。调用方可以自行对成功输出计数和计算摘要。

## 输入与归档边界

| 项目 | 合同 |
| --- | --- |
| 根对象 | 仅直接 OCI image manifest；root index 拒绝。本接口的窄范围不改变原 `verify`／`verify-payloads` 对 index 的既有支持 |
| 平台 | 沿用精确 `linux/amd64`／`linux/arm64` 和显式 variant，不推断或自动选另一个平台 |
| 名称 | 显式 authority／repository 加 `@` 和同一个预期根摘要；使用规范名称子集，不接受隐含 Docker Hub 归一化名称、tag 或 IPv6 authority |
| 允许名称示例 | `registry.example/team/image@sha256:…`、`localhost:5000/team/image@sha256:…`、`docker.io/library/ubuntu@sha256:…` |
| 拒绝名称示例 | `team/image@sha256:…`、`docker.io/ubuntu@sha256:…`、`index.docker.io/library/ubuntu@sha256:…`、另一个根摘要 |
| 归档成员 | 固定 `oci-layout`、新建的 `index.json`、通过验证的 manifest／config／选中层 blob；同摘要一致对象只写一次 |
| 排除内容 | 不枚举目录，不复制源 index、额外 blob、源文件名／owner／mode／时间戳／链接或扩展 tar header |
| 导入命名 | 新 wrapper 只携带调用方明确指定的 `io.containerd.image.name`；不继承源 index 的命名注解 |
| 层类型 | 沿用实际载荷校验的普通 tar／gzip 支持；zstd 与不受支持扩展继续拒绝 |
| tar 表示 | 短固定 ASCII 路径、常规文件、固定权限／owner／mtime、USTAR header、512 字节对齐与两个 EOF block；单条目不超过 8 GiB−1 |

明确构建 wrapper 有实际必要：固定 containerd 2.3.5 导入路径会消费归档中存在的内容，`--base-name` 不构成归档成员白名单。调用方不能把任意 tar 或任意源 index 注解当作批准镜像闭包。本实现只输出明确认证的成员和名称。[固定版本导入实现](https://github.com/containerd/containerd/blob/1294c24a7da8e5a793ed378161673abe94118892/core/images/archive/importer.go)

## 预算、身份与失败

四项层载荷预算均为正数，单层不超过对应总量；重复层引用仍计入逻辑总预算。编码 SHA／大小、完整解码流 DiffID、真实 EOF 与 gzip 成员总量沿用[层载荷合同](image-artifact-metadata.md)。完整归档上限另包含所有 header、padding、wrapper 和 EOF block；可预先算出的超限在开始输出前拒绝。

协作期限为正数且最多 300 秒，仅适用于这个新导出接口。原 `verify-payloads` 与各原生只读检查的 5 秒预算保持。期限检查不能中断阻塞 I/O；16 KiB 顺序传输缓冲也不等于整个进程的内存硬限。外层执行器必须独立限制全部生产者、daemon、客户端与 helper 的内存／CPU／FD／PID／临时文件／inode／网络和真实墙钟。

导出期间保留原 layout 目录 FD。先验证层载荷，再对要输出的每个 blob 通过原目录 FD 顺序打开，重新检查常规文件、大小、SHA、EOF、文件与路径身份；同字节 inode 替换也拒绝。该接口不是跨文件原子快照，对不可信源应使用不可变输入介质和外层写者隔离。读取与导出可能重复读取载荷，不声称零拷贝或已测性能收益。

成功回执的 `scope` 为 `OCI_BOOTSTRAP_ARCHIVE`，`layer_payloads_verified` 与 `diff_ids_verified` 均为 true；`approval_checked` 与 `preparation_allowed` 仍为 false。`layer_archive_semantics_checked`、`unpack_performed` 与 `physical_storage_bound_verified` 均为 false。不要把验证编码／解码字节流解释成验证 tar 路径、设备节点、白化层或真实解包后的容量。

## 后续消费者的生产门

实际原生消费还须固定 daemon 二进制／配置、UDS、namespace、平台与 snapshotter，检查 content、config 引用与真实 committed 快照，再建立并验证原生引用保护、GC 与关闭／交接账本。容器客户端 cgroup、节点 taint 或仅一次读到只读 cgroup 都不能证明共享 daemon 写者受限。需要挂载的 root `CAP_SYS_ADMIN` 执行器也不能仅依靠只读 bind 声称其无法重挂载或抬高限制。[systemd 对文件系统隔离的说明](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#ReadWritePaths=)

当前没有获准上线的受限准备执行器，本接口不提供部署快捷脚本。真实目标节点的不可抬限边界、native lease／GC、云／Kata／CSI／GPU 和冷暖启动／单位成功任务成本均继续单独验收。
