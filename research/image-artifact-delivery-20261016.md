# P1a：离线 OCI 镜像元数据校验交付

状态：P1a 的实际 CLI 11 项测试与本地 Docker 七个场景已通过。它完成快速启动准备之前的元数据校验能力；不完成整个 P1，不开放 pre-pull，也不产生镜像批准或 Ready 权限。[使用合同](../docs/image-artifact-metadata.md)

比较基线为 `57d1689c8dc19734b04032542d49071af6accad1`。其 [GitHub CI 38810699148](https://github.com/StateKnot/knotsandbox/actions/runs/38810699148) 已完成五个 job／64 个 step、全部成功。该结果只对应基线，不能替代本批最终提交及完整远端树的 CI 核对。本批精确提交、完整树及当前 CI 写入缓存之外的私有 `publication-record.json`／`candidate-ci.json`；不在源码提交内自引用提交 SHA 或预记新 CI 成功。

## 生产能力

新增公共库 `verify_oci_metadata(layout, expected_digest, platform)` 与实际 `sandbox-admin image-artifact verify` 命令，CLI 直接复用生产模块。调用方提供独立可信的 expected digest；整个过程不连接 owner 数据库、注册表或运行时，不读取层载荷、解包或执行镜像。[生产模块](../src/image_artifact.rs)、[CLI 适配](../src/admin_image_artifact_cli.rs)

接受 root manifest 或一层 index 后唯一精确平台的 manifest，核对 root／manifest／config 的 SHA256 和引用大小、config 与平台声明、rootfs 数量及关键描述符关系。scratch 零层合法；重复一致的层引用保序统计且单独提供去重逻辑字节。tar digest 与 DiffID 声明须相等，gzip／zstd 不施加该相等要求。它不是完整 OCI Schema 校验、签名／漏洞扫描、硬件兼容或完整层内容验证。

固定回执 scope 为 `OCI_METADATA_ONLY`，`approval_checked`、`layer_payloads_verified`、`preparation_allowed` 都为 false；精确字节数使用十进制字符串。Env 等配置正文不回显。固定错误只给 code，失败无 stdout，不输出部分成功回执。没有数据库迁移、权限扩大或新制备 API。

已知 descriptor 使用小写 SHA256，单项 size 至多 `i64::MAX`，总层字节以 u64 检查溢出。每个 root／manifest／config 至多 1 MiB，总读取元数据至多 3 MiB（含最多 4 KiB 布局标记），index 128 项、层 256 项。目录与元数据读取不跟随符号链接，拒绝 FIFO 等非常规文件，并检查读取期间文件变化。

规则以固定 OCI image-spec 1.1.1 为参考：未知 index mediaType 整体忽略，与 [index 的扩展兼容要求](https://github.com/opencontainers/image-spec/blob/v1.1.1/image-index.md)一致；单项大小与内容身份参考 [descriptor](https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md)，DiffID 含义参考 [config](https://github.com/opencontainers/image-spec/blob/v1.1.1/config.md)。拒绝 nested index、歧义匹配、subject／artifactType／data／非空 urls／foreign 层属于当前产品 profile，不宣称这些内容违反 OCI。布局标记 `1.0.0` 与 image-spec `1.1.1` 的版本含义见 [image-layout](https://github.com/opencontainers/image-spec/blob/v1.1.1/image-layout.md)；artifact 与层扩展定义见 [manifest](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md)。

## 独立预期与实际验证

静态 fixture 的原始 bytes 用独立 Python `hashlib` 计算 SHA256 和长度，再硬编码于实际 CLI 测试；预期值不调用生产验证函数生成。[golden fixture](../tests/fixtures/image-artifact)、[CLI 验收](../tests/image_artifact.rs)

| 元数据 | SHA256（省略 `sha256:` 前缀） | 字节 |
| --- | --- | ---: |
| root index | `bbcc60ed9423dd84b19a56d09759aec31ee3db1b729455f9414646808b624379` | 507 |
| amd64 manifest | `0a14e0296c0ab0d00e9b8c9053f9cab062c5848a9e763ecd3bb5288dcb8fbb57` | 554 |
| amd64 config | `7bfed7d6080f5d9aa427991b771a274ee4845f93232f914a49afbe3f895a141c` | 362 |
| arm64/v8 manifest | `99662d44a999ecc83060817f9abdbbe10fca3322c27d543f6171ef3b9581f5d7` | 249 |
| arm64/v8 config | `fdba5256818185b1fbbca0f0237eb6230592011a42bf19e5575d56059b56e4fd` | 106 |

布局标记为 31 字节。amd64 总读取 1454 字节，两个相同 31 字节层声明的保序和为 62、去重和为 31；arm64/v8 是零层，总读取 893 字节。直接 arm64 manifest 读取 386 字节且 index 为 null。层载荷故意未放入 fixture；这验证没有读取 payload，不代表该目录是可直接运行的完整镜像。

本机私有证据目录为 `.local/image-artifact-20261016/`，日志与报告位于构建缓存之外。

| 验证 | 实际结果与边界 |
| --- | --- |
| `cli-tests-v2.log` | 11 passed、0 failed、0 ignored；真实 `sandbox-admin` 子进程，固定五秒 deadline，超时 kill／wait。投毒实际 owner DB URL 和代理；覆盖精确平台、直接 manifest、scratch、摘要／大小、未知类型、歧义／嵌套／冲突、重复 JSON、内容 profile、rootfs、预算、int64／u64、tar／gzip／zstd、符号链接／FIFO、输入不变与秘密不回显 |
| `ordinary-tests.log` | 最终普通 Rust 全 target 65 个程序、497 passed、0 failed、291 ignored；ignored 为明确环境专项，不代表本轮通过 PG／云／Kata／GPU 验收 |
| `host-final-build.log`／`host-final-artifacts.jsonl` | 最终普通身份、低调试缓存的全 target no-run 编译成功，保留精确 Cargo 制品消息 |
| `clippy-host.log`／`linux-build-v2/clippy.log`／`fmt.log` | 最终 Mac 与实际 Linux arm64 严格全 target Clippy、全仓 fmt 检查通过；既有 vendor 警告未修改为产品验收结果 |
| `docker-v1/record.json` | 实际 Linux arm64 ELF 的七个场景全部达到预期：amd64 与 arm64/v8 元数据成功；wrong-platform、missing expected digest、root symlink、config blob symlink、FIFO metadata 均拒绝。选择 amd64 元数据不执行 amd64 镜像，不证明跨架构运行能力 |
| Docker 身份与输入 | `source_unchanged`、`binary_and_artifacts_unchanged` 为 true；原始 Cargo artifact 与 Linux binary 保持一致。binary SHA256 为 `bbd93fb0dd139fc5bef7d9ca17cc2b8d52e9184ec2e3803a260a4575ed3d920f` |
| Docker 退役 | 七个自有容器逐一退出、按所有权清理并确认不存在；自有 COPY 镜像删除及 absence 检查成功，暂存 context 清理，`cleanup_errors` 为空。不清理共享镜像或用户数据 |

Docker 以固定摘要 Debian trixie 运行实际 CLI，`--network=none`、只读 root、UID/GID `501:20`、drop ALL、no-new-privileges，128 MiB／1 CPU／64 PID；每次 CLI 仍为固定五秒验收预算。没有为通过测试增加网络、权限、线程栈或期限。[Docker 验收入口](../scripts/test-image-artifact.py)

## 失败记录和修复

| 保留记录 | 实际失败及闭环 |
| --- | --- |
| `baseline-red.json` | 基线实际 CLI 不存在 image-artifact 子命令，退出 2、stdout 为空；以该真实边界建立初始 RED |
| `cli-tests-v1.log` | 9 通过、1 失败；测试对 unknown index 条目与已知 digest 的冲突策略假设错误，按规范兼容要求修正测试，不把失败日志覆盖掉 |
| `unknown-digest-red.json` | unknown index mediaType 使用合法 sha512 时被错误地按已知 SHA256 规则拒绝为 INVALID_DIGEST；修为先按 mediaType 忽略，未知条目不参与已知 descriptor registry |
| `descriptor-red.json` | 实际 CLI 曾接受单层 size `2^63`，以及 uncompressed tar layer digest 与 DiffID 声明不相等；修为分别拒绝 INVALID_METADATA，保留压缩层无需相等的规则 |
| `review-regressions-green.json`、`cli-tests-v2.log` | 三项审查反例经同一实际 CLI 从 RED 到 GREEN；unknown 成功，int64 与 tar 矛盾拒绝。全部 11 项最终真实测试通过，不将预期拒绝计作程序成功 |

上述生产模块最终 SHA256 为 `2c52dd9e0ea5b8345664f7ca664d8ecac666946a3a36d40b292b9abfc319204d`。最终普通全集、两平台 Clippy 与 fmt 均已核对退出 0，精确日志和制品摘要保存于 `verification-final.json`。本轮未变更 Cargo 依赖、锁文件、正式迁移或已有授权期限；未将旧 PG 矩阵说成本轮重跑。

编译前与验收后均读取 `df`，可用空间约 303 GiB；复用 Mac `target/review-low-debug`（约 6.7 GiB）和 Linux `target/image-observation-linux-arm64-low-debug`（约 2.1 GiB）。它们用于同仓库／工具链／配置后续验收，均低于单任务 20 GiB，不复制或新建整份 target；后续复用前重新核对年龄、容量与活动锁。本轮不清理这两处缓存，不声称释放磁盘空间；证据与报告保存在缓存之外。

## 重现与后续门

按既有磁盘政策先检查 `df`，在同一工具链／配置复用缓存，普通验收使用 `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`，再执行 `cargo test --locked --test image_artifact`。Docker runner 接受同次 Linux 普通 Cargo 构建的 JSON artifact 消息，拒绝 Mac 制品替代 Linux ELF，使用全新证据目录：

```sh
.local/cluster-venv/bin/python scripts/test-image-artifact.py \
  --artifacts /path/to/linux-cargo-artifacts.jsonl \
  --evidence-dir .local/image-artifact-local
```

后续 P1 仍需实现并独立验收 runtime handler／平台／snapshotter／namespace 绑定，原生 lease 与镜像引用归属，GC 交互和 daemon 存储硬限；P1a 回执本身不满足这些条件。pre-pull、GPU、目标公有云／Kata／CSI、快速启动性能与资源收益仍为 UNKNOWN。继续依赖顺序见[镜像准备计划](image-preparation-production-plan-20261015.md)和[开发表](rust-sandbox-development-workbreakdown.md)。
