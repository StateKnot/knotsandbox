# 离线镜像元数据校验

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
