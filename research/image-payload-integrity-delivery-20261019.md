# P1b7a：有界 OCI 层载荷完整性校验

日期：2026-10-19。本批承接[预准备实施计划](image-preparation-production-plan-20261015.md)，通过已有 `image-artifact` CLI 和公共 Rust 接口交付实际字节流校验。[消费合同](../docs/image-artifact-metadata.md#校验实际层载荷)列出参数、回执与失败处理。

## 选取依据及完整 P1 的边界

开始前已核公开精确提交 `510271b43b6a5cf97d95cf01ce943b0499b9b22e` 的 CI [39186957170](https://github.com/StateKnot/knotsandbox/actions/runs/39186957170)：5 job／73 step 全通过。旧自动化、BFF 与身份代理历史失败记录仍保留；当前绿灯不能倒推旧故障根因。

固定 containerd 2.3.5 的 CRI pull 由共享 daemon 内部 image service／transfer 执行，请求没有产品逐任务的内存、FD 或物理存储硬限。只限制调用方进程，不能覆盖 daemon 执行下载和 apply 的资源。当前宿主 profile 也没有接纳独立 daemon／snapshotter 执行组合。因此完整受限准备执行者仍未形成，不能开放准备写入。[固定实现](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/images/image_pull.go)、[CRI 请求](https://github.com/kubernetes/cri-api/blob/v0.36.4/pkg/apis/runtime/v1/api.proto)

本次选择其独立可验收前置依赖：实际验证 layer descriptor 与解码 DiffID。OCI descriptor 的 digest／size 针对编码字节，DiffID 针对整个解码 tar 字节流；不以 tar 结束标记截断哈希。[OCI descriptor](https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md)、[DiffID 定义](https://github.com/opencontainers/image-spec/blob/v1.1.1/config.md#layer-diffid)

## 实现

`image_artifact::verify_oci_payloads` 复用原目录 FD 和元数据闭包校验，公开 `PayloadLimits` 构造器要求四个正整数字节上限。层顺序处理、固定16KiB缓冲、编码和解码各自执行真实 EOF／额外一字节检查；编码 SHA-256、真实大小、完整解码 DiffID 全部匹配才返回成功。重复 blob 实际解码去重，逐次文件身份／DiffID 重核，逻辑总预算按每次层引用累计。

gzip 使用固定 `flate2=1.1.10` 的纯 Rust backend，逐成员验证 CRC／ISIZE，整个调用的唯一 blob 合计最多1024成员，空成员也计数；拒绝损坏、截断和尾随垃圾。选择逐成员解码是为了在空成员之间执行总量与期限检查。[固定解码实现](https://github.com/rust-lang/flate2-rs/blob/1.1.10/src/gz/bufread.rs)、[头部界限](https://github.com/rust-lang/flate2-rs/blob/1.1.10/src/gz/mod.rs)。五秒是协作预算，不能抢占阻塞文件系统调用；固定缓冲不代表已认证的进程 RSS／FD 硬限。

成功仅为 `OCI_PAYLOAD_STREAMS`，不解析／解包 tar，不访问数据库、网络或 runtime，不改变原元数据对缺失层／zstd 的支持。审批、准备、真实 apply、物理存储界限均未认证；无新的 HTTP API、权限、迁移、lease 或 READY／HIT。pre-pull 继续关闭。

新增五个固定 crate 的完整 MIT 选项和上游来源已入仓。当前 release manifest 升为 v5，单独 `oci-payload-notices.json` 绑定固定版本／crate checksum／完整正文及 Cargo.lock 摘要；生成、签名库存验证、历史读取、安装和四个 Docker 分发目标接入。v1—v4 历史库存与 native notice 原 schema 语义保持。没有创建 release 或执行正式生产构建／签名／扫描。

## 验收与失败记录

本地证据根为 `.local/p1-executor-20261019/`，原始失败不覆盖。基线旧 CLI 对独立 Python stdlib 生成的合法 raw／gzip／连接成员输入均以未知子命令拒绝，作为功能 RED；它不是旧 CI 故障复现。

主机针对性库测试9项、真实 CLI 23项、严格all-target Clippy和fmt已通过，单独doctest为0项。随后普通 `cargo test --locked --offline` 在库阶段为232通过／109失败／133 ignored，退出101，后续 target 未运行；109项失败均包含 `Operation not permitted`，涉及现有监听夹具，完整分类保存在 `host-all-failure-classification.json`。该失败保留，不能记成主机全量通过；没有提高权限、期限或线程栈。

Linux第一轮公开候选常规程序在第57个 `termination_deployment` 遇到1项失败并立即停止；按各父程序最后一条summary统计，已执行前缀为561通过／1失败／287 ignored，原含嵌套子summary的原始收据另保留。直接原因是验证源按用户要求排除了虚拟环境，而该测试默认寻找 `.local/cluster-venv/bin/python`；固定镜像的 `/usr/bin/python3` 3.11.2 又缺少渲染夹具依赖。没有修改测试或产品源码。

随后仅补齐实际测试环境：cryptography50.0.1／cffi2.1.1／pycparser3.0／PyYAML6.0.3的Linux aarch64或纯Python wheel逐份对照官方版本记录与仓库requirements锁SHA，复用已有PyYAML、仅下载缺失三份；任务专用目录离线安装197文件／18MB，真实导入与四对象渲染通过。经既有 `CLUSTER_PYTHON`／`PYTHONPATH` 配置重新验证，原只读／无网络／nonroot、1GiB内存、2CPU、128pids、256MiB tmpfs及期限／栈保持。完整记录见 `python-wheels/provenance.json` 与Linux复验收据。

release Python 第三轮115项通过；前两轮分别有9 error／1 failure及1 fixture failure，日志保留为 `release-tests-v1.log`／`v2.log`。修复新增 notice 对 console 专用读取器的误用，以及历史 fixture 库存／ELF mode，未放宽生产校验。

独立 Spec 审查随后发现一项 P2：验证器先 `read_bytes()` 完整读取 Cargo.lock，再执行4MiB检查，可能先产生超限分配。生成和验证消费者现共享实际最多4MiB加一字节的普通文件 FD 读取；拒绝符号链接／FIFO，v5历史下载亦在批量获取前拒绝超限声明，v4语义保持。新增真实4MiB加一字节文件、重算库存／notice摘要的消费者反例，确认实际读取有界且不进入TOML解析，最终第四轮117项通过。前一轮成功不覆盖随后发现的问题。

修复后的实际受限 Linux producer 与原 Docker 八条 COPY 指令再次导出四目标共28文件，完整许可证／来源／notice 逐字一致，见 `distribution-proof-v2/record.json`；前次 `distribution-proof/` 保留。不是四个完整生产镜像构建、正式签名或安全扫描认证。

Linux补齐固定夹具依赖后，第二轮公开候选的63个父测试程序全部通过，按各父程序最后一条summary计为564通过／0失败／309原生ignored；`termination_deployment`为1通过，`volume_deployment`为2通过。73条普通executable记录中另有8个产品二进制与2个只编译example，不把它们编造成额外测试程序。两平台严格all-target Clippy、主机fmt通过；Linux doctest未另执行，主机doctest为0项。ignored专项未因此获认证，没有重跑完整PG／云／Kata／CSI／GPU或性能认证。

Linux普通验收的源输入、73项普通ELF及新依赖目录在执行前后哈希一致，Rust构建输入与主工作区566文件匹配。完整历史源副本1133文件不代表最终release Python字节；最终许可链以独立 `distribution-proof-v2` 和117项release回归为准。两类证据分列，不拼接成完整生产镜像认证。

Standards两轮源审查及文档初审未发现问题；Spec原一项P2在实际有界读取和消费者回归补齐后复审关闭，遗留0项。最终44文件清单按固定字节／模式接受两轴核对后同步。四处历史ROOT／PUBLIC文档差异保留，主工作区不提交；不全量复制ROOT，不强推，不自动公开release。新提交精确CI单独核对，不能沿用基线成功；远端树及运行状态保存在本批本地交付记录。

## 下一依赖

完整 P1 仍须选定可强制部署的执行者／backend／存储组合，覆盖 resolver、下载、content ingest、differ、snapshotter、元数据及清理的真实资源所有者，证明耗尽时普通 CRI 保留量仍可用。原生 lease／content／snapshot 完整闭包、实际 pull 平台／namespace／snapshotter、丢 ACK／崩溃／GC 与安全释放还须 P1—P4 闭合。云、Kata、CSI、GPU、性能／成本收益均未在本批认证。

## 发布后精确 CI 的后续事实

本批44文件已同步为 `0dd7eb7d0003792e70825f296fa88172e65a3b57`，远端1142文件完整树／模式一致，公开工作区clean，四处历史ROOT差异保留。其精确CI 39196350609为4 job成功／verify失败，首个错误来自既有节点镜像指标未来时间夹具，库测试352通过／1失败／149 ignored；不能沿用本地成功称该CI通过。原始失败及确定性夹具修复另见[CI修复记录](node-image-clock-fixture-delivery-20261019.md)，本片的载荷验证范围、pre-pull关闭与完整P1未完成状态不变。后续提交的精确CI独立核对，不改写本次失败。
