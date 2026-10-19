# 镜像完整性校验与原生读回

`sandbox-admin image-artifact verify` 按调用方提供的预期摘要，校验本地 OCI 镜像元数据的身份、平台和必要描述符关系。它只读取元数据，不访问数据库、注册表或运行时，不读取层载荷，不拉取、解包或准备镜像。其他 Rust 模块使用同一公共入口 `sandbox_platform::image_artifact::verify_oci_metadata`，CLI 不维护第二套规则。[实现](../src/image_artifact.rs)、[CLI](../src/admin_image_artifact_cli.rs)

```sh
sandbox-admin image-artifact verify \
  --layout /srv/image-metadata/reviewed-image \
  --expected-digest sha256:<independently-trusted-root-digest> \
  --platform linux/amd64
```

预期摘要必须由调用方从独立可信来源取得。命令不会确认它是否已获产品审批，也不会把从同一不可信目录计算出的摘要变成可信批准。成功回执固定为 `scope: "OCI_METADATA_ONLY"`，并且 `approval_checked`、`layer_payloads_verified`、`preparation_allowed` 全为 `false`。调用方不得据此设置镜像 Ready、授予执行权限或跳过后续准备门。

## 输入和平台

目录按 OCI 布局组织：`oci-layout` 标记使用 `imageLayoutVersion: "1.0.0"`，元数据 blob 位于 `blobs/sha256/<64位小写摘要>`。OCI image-spec 1.1.1 的布局标记仍可为 1.0.0，两种版本号含义不同。[OCI 布局规范](https://github.com/opencontainers/image-spec/blob/v1.1.1/image-layout.md)

本命令从 `--expected-digest` 指定的 blob 开始，接受直接 image manifest，或者一层 image index 后的唯一目标 manifest；不使用 `index.json` 的标签来发现或替换目标，也不检查 `index.json` 是否构成完整布局。它校验的是这条元数据闭包，不提供完整 OCI 布局或 JSON Schema 合规认证。

目标仅接受 `linux/amd64`、`linux/arm64`，可附精确 `/variant`。variant 长度 1—32，首字符为小写字母或数字，其余仅小写字母、数字、`.`、`_`、`-`；不推断默认 variant。缺失 variant 与 `v8` 不同。index 目标平台与 config 的 OS、architecture、variant 必须完全一致；目标中非空的 `os.version`、`os.features`、`features` 要求当前不支持，拒绝而不推定宿主满足。

index 未知 mediaType 的条目整体忽略，不读取其 blob，也不把其 digest 或 size 加入已知描述符冲突判断；未知条目中的合法 `sha512` 不会使已知目标失败。已知 manifest 条目缺少平台时不作为目标候选，其他平台不作为回退；多个精确匹配条目拒绝为歧义。nested index 均拒绝。OCI 要求未知 index mediaType 不产生错误，并建议支持嵌套及多匹配时取首项；拒绝嵌套和歧义是本产品的确定性策略。[OCI index 规范](https://github.com/opencontainers/image-spec/blob/v1.1.1/image-index.md)

## 校验范围与资源界限

已读取的 root、manifest 和 config 使用小写 `sha256`，逐一验证实际字节摘要及被引用大小；已知 descriptor 的单项 size 不超过 OCI 的有符号 64 位上限。JSON 任意对象中的重复键均拒绝，包括未知扩展对象。普通未知字段允许在预算内存在，不回显 config 的 Env、Labels 或其他不透明内容。[OCI descriptor 规范](https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md)

| 项目 | 固定上限或规则 |
| --- | --- |
| `oci-layout` | 4 KiB |
| root／manifest／config，各自 | 1 MiB |
| 实际读取的全部元数据 | 3 MiB，包含布局标记；直接 manifest 不重复计数 |
| index 条目／manifest 层数 | 128／256 |
| 文件访问 | 全路径目录及元数据均不跟随符号链接；只接受常规元数据文件，FIFO 不等待写端 |
| 读取变化 | 比较读取前后文件身份及元信息，检测变化即拒绝；不承诺跨文件原子快照 |

config 的 `rootfs.type` 须为 `layers`，`diff_ids` 与 manifest layers 等长且按序对应。可接受零层 scratch 镜像。uncompressed tar 的 layer digest 与 DiffID 声明须相等；gzip／zstd 的两者无需相等，因为 DiffID 描述未压缩 tar 的摘要。这只检查声明一致性，没有读取或重算 tar 内容。[OCI config 规范](https://github.com/opencontainers/image-spec/blob/v1.1.1/config.md)

本产品仅接受 OCI config 和 tar／gzip／zstd 普通层。root、选中 manifest、其 config／layer 描述符及选中的 index 描述符含 `subject`、`artifactType`、`data` 或非空 `urls` 时拒绝；foreign／nondistributable 层也拒绝。这些是当前产品支持范围，不能解释成 OCI 规范禁止这些合法扩展；OCI manifest 可描述 artifact、subject 和多种层格式。[OCI manifest 规范](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md)

## 回执和失败处理

回执包含精确目标平台，root、可空 index、selected_manifest、config 的 media type／digest／大小，以及保序 layers 和对应 diff_id。所有字节数量以十进制字符串输出，避免其他语言的浮点数丢失精度。

`declared_layer_bytes` 是保序层描述符大小之和，重复引用重复计数；`unique_declared_layer_bytes` 仅对相同 digest、media type、size 的一致引用去重，同一已知 digest 的声明冲突拒绝。总和采用检查溢出的 u64。两者都是声明的逻辑字节，不是已验证载荷大小、物理占用、可回收空间或存储配额。

`metadata_bytes_read` 只统计实际读取的元数据字节；未选择平台的 manifest／config 和层载荷不计入。层文件可以缺失，成功不表示完整镜像内容已经存在。

失败退出非零，stdout 为空，stderr 只给固定错误前缀与稳定 code，例如 `Error: image artifact metadata verification failed: PLATFORM_MISMATCH`，不输出输入路径或配置正文。调用方按退出码和 code 处理，不能继续使用之前的成功回执。

| code | 处理含义 |
| --- | --- |
| `INVALID_DIGEST`／`UNSUPPORTED_PLATFORM`／`UNSUPPORTED_LAYOUT` | 输入标识或产品支持范围不符 |
| `METADATA_UNAVAILABLE`／`METADATA_CHANGED` | 元数据不可用、文件类型不接受或读取中变化 |
| `METADATA_LIMIT_EXCEEDED`／`INTEGER_OVERFLOW` | 元数据预算或总数量越界 |
| `INVALID_METADATA`／`DIGEST_MISMATCH`／`SIZE_MISMATCH` | 文档／声明矛盾，或实际元数据身份不匹配 |
| `UNSUPPORTED_MEDIA_TYPE`／`UNSUPPORTED_DESCRIPTOR` | 当前处理目标超出产品 profile |
| `PLATFORM_MISMATCH`／`AMBIGUOUS_PLATFORM`／`DESCRIPTOR_CONFLICT` | 目标不唯一、不匹配或已知声明冲突 |

该能力不完成签名验证、漏洞扫描、运行硬件兼容认证或下载验证，也不提供新的 HTTP 制备 API。runtime handler／snapshotter／namespace、原生 lease 与引用归属、GC 和守护进程存储硬限仍是后续 P1 门禁。[本批交付证据](../research/image-artifact-delivery-20261016.md)

## 校验实际层载荷

`verify-payloads` 在相同元数据闭包校验后，实际读取所选层，核验压缩／原始字节的 descriptor 大小和 SHA-256，以及完整解码字节流的 DiffID。Rust 消费者使用 `verify_oci_payloads` 和经过构造验证的 `PayloadLimits`；它不访问注册表、数据库或运行时。

```sh
sandbox-admin image-artifact verify-payloads \
  --layout /srv/image-artifacts/reviewed-image \
  --expected-digest sha256:<independently-trusted-root-digest> \
  --platform linux/amd64 \
  --max-layer-bytes 67108864 \
  --max-total-layer-bytes 268435456 \
  --max-decoded-layer-bytes 268435456 \
  --max-total-decoded-bytes 1073741824
```

四项上限均必填，单位为字节，必须为正 u64，单层上限不得大于对应总上限。上述数值只是调用示例，部署方须按资源策略明确设置；没有隐式无限值或失败后自动加大预算。编码总量先按 descriptor 预检，解码过程按剩余预算逐块核验；到达精确边界后仍探测真实 EOF，多一个字节也拒绝。DiffID 覆盖整个解码流，包括 tar 结束标记后的字节。[OCI 层与 DiffID](https://github.com/opencontainers/image-spec/blob/v1.1.1/layer.md)

此模式支持原始 tar 字节流和 gzip，接受连接的 gzip 成员并检查各成员 CRC／ISIZE、完整尾部与流结束；整个调用的唯一 blob 合计最多1024个 gzip 成员，空成员也计数。未知编码、zstd、截断和尾随非 gzip 数据拒绝；原 `verify` 对 zstd 元数据的支持保持。它不解释 tar 条目，不确认 tar 格式、路径安全、whiteout 或文件系统展开语义。

原布局目录 FD 保留到调用结束；层按序打开，文件和目录不跟随符号链接，FIFO／目录拒绝。每层读前后比较文件身份、大小及时间，并重新核对原目录中的同名对象，检测变化即拒绝。重复 digest 的一致引用只解码一次，但重新核对文件身份和 DiffID；四项逻辑预算均按每次引用计费，不能通过重复层绕过总量。所有成功统计使用十进制字节字符串。

成功回执将 `scope` 设为 `OCI_PAYLOAD_STREAMS`，`layer_payloads_verified`、`diff_ids_verified` 为 true。`encoded_bytes_read`、`decoded_bytes_read` 是去重后实际验证的载荷正文，`logical_decoded_bytes` 和保序 `decoded_layer_bytes` 包含重复引用；`unique_layers_verified` 和 `gzip_members_verified` 说明实际工作量。原 `declared_layer_bytes`／`unique_declared_layer_bytes` 定义不变；探测越界的失败不产生成功回执。

`archive_semantics_checked`、`unpack_performed`、`physical_storage_bound_verified`、`approval_checked`、`preparation_allowed` 均为 false。固定16KiB读写缓冲和5秒协作检查预算限制流式校验工作；这不是内核 RSS／FD 配额、物理存储硬限或可强制中断的执行者。阻塞的文件系统调用不能由此同步接口抢占；文件元信息比较也不是跨文件原子快照。服务不得把该入口放进异步请求线程后宣称获得完整取消与资源隔离。

通过命令行语法解析后，校验失败的 stdout 为空，stderr 固定为 `Error: image payload verification failed: <CODE>`，不含路径、配置或解码器正文。除原元数据错误外，新增 `INVALID_PAYLOAD_LIMITS`、`PAYLOAD_LIMIT_EXCEEDED`、`UNSUPPORTED_PAYLOAD_MEDIA_TYPE`、`INVALID_LAYER_ENCODING`、`DIFF_ID_MISMATCH`、`PAYLOAD_DEADLINE_EXCEEDED`；缺失／特殊层文件沿用 `METADATA_UNAVAILABLE`，变化沿用 `METADATA_CHANGED`，编码大小／摘要错误沿用 `SIZE_MISMATCH`／`DIGEST_MISMATCH`。失败不能复用旧回执。

这是 P1b7a 的离线载荷完整性前置能力。受限准备执行者、daemon 侧硬限、真实 pull／unpack、原生租约及 GC 归属尚未完成；不得据此签发 READY／HIT 或开启 pre-pull。

## 检查本机原生已存元数据

Linux root 主机管理员可以直接检查固定 containerd UDS 在 `k8s.io` 中的已存对象：

```sh
sudo sandbox-admin image-artifact inspect-native \
  --reference registry.example.com/team/image@sha256:<root-digest> \
  --expected-digest sha256:<independently-trusted-root-digest> \
  --platform linux/amd64
```

reference 必须是无 tag 的精确 repository@digest，摘要须与独立 expected digest 相同；不推断 registry 名或补全 alias。非 Linux／非 root 拒绝为 `UNSUPPORTED_RUNTIME`。没有远程 socket、namespace、registry 凭据参数；这不是租户或 OAuth API，不改变现有 operator 查询权限。

命令先核固定 containerd 2.3.5 版本，经原生 Images.Get／Content.Info／Read 取得 root、唯一选中 manifest 和 config，再核前后同名根描述符。它与离线命令使用相同 `MetadataPlan → ConfigurationPlan`，原严格 JSON／摘要／大小／平台及描述符冲突规则保持。每块1MiB、累计元数据3MiB，每条Read流最多64帧，小响应64KiB；连接和整个RPC链共用5秒deadline，结束／超时后等待本次I/O收尾。该期限不包括整条CLI的进程启动延迟。

回执增加 `scope: "NATIVE_CONTAINERD_METADATA_ONLY"`、`namespace`、`reference`、`runtime_version`、`observed_at` 和嵌套 `metadata`；metadata 使用原 schema，三个授权／层载荷标志仍全为false。字节统计只计元数据正文，不含RPC开销，不代表物理存储或可释放量。不会输出config的Env／Labels；失败stdout为空，stderr只给 `Error: native image metadata inspection failed: <CODE>`，不能复用旧成功回执。

原生错误包括 `INVALID_IMAGE_REFERENCE`、`RUNTIME_UNAVAILABLE`、`RUNTIME_IDENTITY_MISMATCH`、`RUNTIME_METADATA_UNAVAILABLE`、`RUNTIME_RESPONSE_INVALID`、`RUNTIME_IMAGE_CHANGED`、`RUNTIME_ROOT_MISMATCH`、`RUNTIME_DEADLINE_EXCEEDED`，以及上表已有OCI错误。两次Get不是跨对象原子快照，成功只证明这次读出的元数据符合期望；不读取层载荷、不pull／unpack／写lease，不签发READY、HIT或准备许可，也不证明CRI实际pull平台／snapshotter、快照存在或未来GC保护。[实现和验收边界](../research/native-image-metadata-delivery-20261016.md)

## 核对 CRI 当前索引的配置身份

当原生元数据存在，但需要判断 kubelet 使用的 CRI 索引是否也能以同一精确引用解析到预期平台的配置时，Linux root 管理员使用：

```sh
sudo sandbox-admin image-artifact inspect-cri \
  --reference registry.example.com/team/image@sha256:<root-digest> \
  --expected-digest sha256:<independently-trusted-root-digest> \
  --platform linux/amd64
```

Rust 消费者使用同一公共入口 `nodeguard::native_image_metadata::inspect_cri`。它保留上述固定 endpoint、namespace、独立 expected digest、精确平台、元数据预算及整个 I/O 链共用5秒期限，并在同一连接身份下核对前后 `ImageStatus(verbose=false)` 与原生元数据。CRI 的非空 ID 必须等于已验证 OCI config 的 digest，返回的 repository digests 必须含精确输入引用；缺失、错平台配置或前后身份变化均不返回成功回执。不会按另一个 alias 或 tag 作为调用身份。

回执为 `scope: "CRI_INDEX_CONFIG_IDENTITY_ONLY"`，`cri_image_id` 为已核对的 config digest，`native` 保留原生命令完整回执。`approval_checked`、`pull_selection_checked`、`runtime_handler_checked`、`snapshotter_checked`、`unpack_checked`、`gc_protection_checked`、`preparation_allowed` 全为false。不回传 CRI 的 tags、用户名、配置正文或不透明 Info；不接受 runtime handler 或 snapshotter 参数。

固定 containerd 2.3.5 的 `ImageStatus` 只使用 `ImageSpec.image` 解析内存索引，不使用 runtime handler；索引的配置 ID 按宿主默认平台生成。多平台根摘要相同，不能证明指定平台就是当前 CRI ID 对应的平台。本命令用已验证 config digest 检出这种差异，但不能把索引匹配解释为某次 pull 已采用请求平台或 Kata snapshotter。[实际 ImageStatus](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/images/image_status.go)、[索引配置身份](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/store/image/image.go)、[宿主平台初始化](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/images/service.go)

新增稳定错误 `CRI_IMAGE_UNAVAILABLE` 表示该精确引用没有可用 CRI 索引项，`CRI_IMAGE_MISMATCH` 表示配置摘要或精确 repository digest 不符，`CRI_IMAGE_CHANGED` 表示本次前后索引身份变化；协议形状、超限、版本及期限继续使用已有错误。失败 stdout 为空，stderr 只给 `Error: CRI image identity inspection failed: <CODE>`。两次索引检查与原生检查不构成跨服务原子快照，也不持有原生保护引用。

成功可以发生在未解包的 metadata-only fixture 上；它没有检查实际 snapshot、layer 载荷、GC 存活、审批或资源硬限，不产生准备、启动或缓存命中许可。实际 pull 选择、原生引用／GC 与准备开销硬限仍须分别完成。

## 核对 snapshotter 与配置引用元数据

Linux root 管理员可以检查固定 `overlayfs` 中的当前 rootfs 快照元数据，以及对应配置上的引用标签：

```sh
sudo sandbox-admin image-artifact inspect-snapshot \
  --reference registry.example.com/team/image@sha256:<root-digest> \
  --expected-digest sha256:<independently-trusted-root-digest> \
  --platform linux/amd64
```

Rust 入口为 `nodeguard::native_image_metadata::inspect_snapshot`。输入规则、固定 root UDS／peer／`k8s.io`、containerd 2.3.5、元数据预算和全链共用5秒期限保持；不提供任意 snapshotter、snapshot key、mount、路径或 handler 参数。命令没有 pull、unpack、mount、lease 或 snapshot 写操作。

命令从已验证配置的有序 DiffID 推导 ChainID：首层为该 DiffID，后续为 `sha256(previous ChainID + ASCII space + next DiffID)`；父 ChainID 是去掉最后一层后的结果。它不使用压缩层摘要代替 DiffID。零层 rootfs 返回 `SNAPSHOT_NOT_APPLICABLE`，不会以空 key 查询快照；这不影响原离线／原生命令对零层元数据的支持。

验证顺序为原生元数据读回、config Content.Info A、snapshot Stat A／B、config Content.Info B、最终原生根核对。config 的 digest／大小须与已验配置一致，`containerd.io/gc.ref.snapshot.overlayfs` 须等于 ChainID；快照名称、直接父名称与 `Committed` kind 须匹配，并核对前后创建／更新时间。每个新回复仍限64KiB；标签最多128项、单个键值合计4096字节、累计48KiB。标签正文、mount、目录、物理使用量均不返回。

成功回执固定 `scope: "NATIVE_SNAPSHOT_REFERENCE_METADATA_ONLY"`，包含 `snapshotter`、`chain_id`、可空 `parent_chain_id`、`reference_label_matches: true`、`snapshot_committed_observed: true` 和完整原 `native` 回执。`approval_checked`、`pull_selection_checked`、`runtime_handler_checked`、`layer_payloads_verified`、`gc_protection_checked`、`preparation_allowed` 全为false。

新增错误为 `SNAPSHOT_UNAVAILABLE`、`SNAPSHOT_IDENTITY_MISMATCH`、`SNAPSHOT_REFERENCE_MISMATCH`、`SNAPSHOT_CHANGED`、`SNAPSHOT_NOT_APPLICABLE`；其余版本、协议、元数据和期限错误沿用。失败 stdout 为空，stderr 只给 `Error: native snapshot identity inspection failed: <CODE>`，不能继续沿用旧成功回执。

此检查只观察最终快照和直接父名称，不遍历完整快照祖先或 GC 可达闭包，也不取得保护租约。多次读取不是原子事务。即使空快照被命名成目标 ChainID、标为 Committed 并带匹配标签，也可能通过这项元数据检查；它没有验证层真正 apply 到快照或将被某次启动使用。因此成功不能作为解包完成、实际 pull／Kata snapshotter 选择、内容正确、长期 GC 保护、Ready 或缓存命中证明。
