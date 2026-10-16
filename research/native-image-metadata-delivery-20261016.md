# 原生已存镜像元数据读回与完整许可证交付

日期：2026-10-16。范围为快速启动计划 **P1b4**：只读检查本机 containerd 已存的 OCI 元数据。完整 P1、准备授权／预算与 pre-pull 尚未完成；无新数据库迁移、公共 HTTP 接口或 GPU／VM 配额。

## 生产行为和消费者

`sandbox-admin image-artifact inspect-native --reference <repo@sha256> --expected-digest <independent-sha256> --platform linux/amd64` 调用公共 Rust 入口 `nodeguard::native_image_metadata::inspect`。只允许 Linux root 使用原固定 containerd UDS，复用 P1b3 对象／peer 绑定；每个 RPC 都固定 `containerd-namespace: k8s.io`，不接受 socket、namespace、registry 凭据或任意 RPC 输入。非 Linux／非 root 返回固定 `UNSUPPORTED_RUNTIME`。

Version 须为 containerd 2.3.5／CRI v1；随后 Images.Get 取得精确名称及根描述符，Content.Info／Read 读取 root、必要的唯一选中 manifest 和 config，末尾再次 Get 核对名称与根描述符。reference 必须是有界、无 tag 的精确 repository@digest，与独立 expected digest 相同。名字／摘要／大小／media type 冲突、缺失、畸形、流尾错误或期限耗尽均拒绝，不返回提供方原始错误、文件路径或配置正文。

原同步 `image_artifact::verify_oci_metadata` 和新原生 adapter 复用 `MetadataPlan → ConfigurationPlan`：状态持有平台、描述符注册表及累计预算，读取阶段消耗原状态；共享相同的严格 JSON、摘要／大小、平台、descriptor 冲突和 rootfs 声明校验。原离线命令、输出 schema、同 FD 文件／路径与变化检查保持。新 adapter 不把元数据复制到临时磁盘布局，也不另写一套解析规则。

连接与 RPC 链共用 5 秒 deadline；小回复 64 KiB，Version 4 KiB；每 blob 1 MiB、总元数据 3 MiB，每条 Read 流最多 64 帧。逐帧检查非空、连续 offset、字节数及完整 EOF；Read 请求上限为 Info.size+1，以检测额外字节，仍独立验证 Info 身份及实际完整内容。正常结束和超时均关闭并等待本次 transport；Drop 只提供取消保护，不声称已实测所有 caller-abort 场景。期限不是对进程启动与收尾时间的整条 CLI 延迟承诺。

回执 `scope=NATIVE_CONTAINERD_METADATA_ONLY`，含 namespace、reference、runtime_version、observed_at 及原 OCI metadata 回执；后者的 approval_checked、layer_payloads_verified、preparation_allowed 均为 false。它不访问注册表、不读取层载荷，不 pull／unpack／写 lease／创建 VM。逻辑 descriptor 字节不代表物理容量或回收量，两次 Get 也不是跨对象原子快照或长期引用保护。

官方依据固定为 [Images 元数据合同](https://github.com/containerd/containerd/blob/v2.3.5/api/services/images/v1/images.proto)、[Content 协议](https://github.com/containerd/containerd/blob/v2.3.5/api/services/content/v1/content.proto)和[Read 实现](https://github.com/containerd/containerd/blob/v2.3.5/plugins/services/content/contentserver/contentserver.go)。Images.Get 仅给浅层引用；Read 会将超出对象末尾的读取范围截至实际长度。不能把这个检查解释为 CRI 实际 pull 平台／snapshotter 选择、内容完整或快照可用。

## 协议与二进制交付

固定官方 v2.3.5 三份协议及 Apache 许可证已入库；WKT 的三份 Google 原始定义由锁定 protoc 分发包原样保留，包含完整 BSD 三条款。两组共六份协议及两份许可证均有固定摘要。独立生成工具不新增运行时依赖，只生成私有消息；生产只暴露固定读方法，不导出通用写客户端。CI 校验固定输入 SHA、WKT 来源清单及四份生成代码的重生成一致性。

Standards 发现新增派生内容的许可最初只存在于源码，已补真实分发链：当前签名 manifest v4 必须包含 `native-protocol-notices.json`，包括固定来源／输入摘要及完整 Apache／BSD 文本；与原 SQLx notices 一起进入签名文件 inventory、字节／语义验证、下载上限与原安装锁。当前验证／安装只接受 v4，历史 v1／v2／v3／v4 路径仍经原认证，v3 继续为 SQLx-only，不改写旧格式含义。

Docker 的 nodeguard-export、binaries-export、runner、runtime 四个目标携带完整源许可证、来源文件与经过真实 producer 校验的 JSON；`.dockerignore` 仅精确放行所需路径。项目原创仍为 MIT，不覆盖这些第三方许可。没有执行签名、发布 release 或授予新的执行范围。

## 实际验收

精确公开基线为 `32910f0402d35057ec69f1ecc66a8aaf0d893311`，远端完整 1084 文件树与干净公开副本一致；[CI run38846203669](https://github.com/StateKnot/knotsandbox/actions/runs/38846203669) 五 job／69 step 全部成功。本片新提交完整树和 CI 独立核对，不沿用该结果。

| 验收 | 实际结果与范围 |
| --- | --- |
| 普通 Rust | 65 程序、509 通过／0 失败／291 环境 ignored；包含原实际 admin CLI 回归，非实云／数据库专项全跑 |
| 新共享规则 | 上述509中含4项：原离线回执逐字段相同、direct manifest、分阶段身份／大小／错阶段拒绝、单块／累计预算；没有以自比较替代旧 CLI 验收 |
| 新真实 wire | 上述509中含4项：direct／index、15类坏协议模式、跨 RPC 总5秒 deadline、请求引用校验；真实 TCP/HTTP2，namespace／剩余期限、offset／EOF／错误尾帧、提供方 secret 不回显及双方 I/O owner 归零 |
| 最终原生新消费者 | `native-final` 一项 PASS；官方 containerd 2.3.5、Linux arm64、独立产生 index／manifest 根摘要，实际 inspect＋普通 admin ELF 的两种成功与4类拒绝；配置 Env marker 不回显，no-unpack 和无 snapshot／container／task 后置门通过 |
| 既有原生回归 | 同一 Linux 制品的 peer／startup profile／image scraper-mTLS 三个 case 各一项 PASS，自有清理通过；新 native CLI 本身没有 mTLS／OIDC 认证声称 |
| 既有离线 Docker CLI | 同一新 admin 制品，七场景 PASS，源码／制品稳定；containers_removed／context_removed 为 true，清理日志无错误 |
| 质量门 | Mac／Linux 严格 all-target Clippy、fmt、11项旧 Python runner 测试、新 wrapper 静态输入检查和固定协议重生成一致性通过 |
| 发布分发 | 支持的 Python3.12.14 下100项 release 测试 PASS；v4遗漏／篡改／超限、原安装锁和真实文件安装、显式历史v3覆盖。实际受限 Linux producer＋复用产品四处 COPY 的 Docker 导出48文件逐字节 PASS；不是完整 release 构建或签名认证 |

四项最终原生回执均为 PASS，源码／lib／制品 JSON 稳定与 owned container／image cleanup 为 true；新 native 还独立核对 admin ELF／admin artifact JSON 不变。原生 fixture 保持 no-network、只读 rootfs、cap-drop ALL、no-new-privileges、768 MiB memory／swap、1 CPU、128 PID、nofile1024 及原45秒 case期限。没有执行 Kata shim／VM／GPU；时间不作为启动基准。

最终源码副本共1105文件、16,210,620 bytes；仅源码／锁与必要配置，不复制 target、node_modules、私有文件或 Git。Rust 全部使用既有低 debug、无 incremental 缓存；后续仅非 Rust 的分发链变化，Rust输入及两平台验收制品不变。日志与回执均在编译缓存之外的 `.local/native-metadata-20261016/`，包含 `code-manifest-v1/v2.json`、各构建日志、`native-final`／三原生回归／`offline-cli-regression`、`license-copy/record.json`、发布测试及后续公开记录。

保留的失败／修正：Linux首次构建尚未执行编译即因只读源码内缺少嵌套挂载点被 runc 拒绝，预建本轮空挂载目录后同一限制通过；首次 wrapper 静态检查因 macOS `/var` 别名触发严格路径门，原输出未保存，说明如实记录，后续只修静态测试临时路径 resolve；root 初次发布测试误用系统 Python3.9，缺少项目既有 tomllib，失败日志保留，改用已有受支持3.12后100项通过，未加 shim 或改生产规则。审查发现的二进制许可缺口已实际补齐，不将开发失败冒充产品安全反例。

## Standards

独立最终复核覆盖全部46个候选文件及其 SHA／权限和实际交付证据：累计发现1项 P2（许可证未随二进制分发），已修复；遗留硬问题0项、需修复 smell 0项。完整 v4 分发链和历史 v3 原语义均核对通过，不以源码声明代替实际交付。

## Spec

独立最终复核覆盖全部46个候选文件：总发现0项，遗留 P1/P2 为0。四项原生、离线 CLI、100项发布测试及48个实际许可证导出文件的证据与范围一致；该片不越过 P1 的引用、实际选择或硬限门。

## 下一依赖

继续核实实际 CRI pull 的 manifest／platform、Kata handler／snapshotter 选择及 `k8s.io` 原生 lease／content／snapshot 引用与 GC，再闭合真实存储、内存、FD、专用网络槽及临时空间硬限。本片只有已有对象的 namespace／元数据读回，不证明实际 pull 采用了请求平台或 snapshotter，不保护未来 GC。

P2—P6、实云／Kata／CSI、真实 GPU、冷暖启动和单位成功任务成本仍未完成／未认证；pre-pull 继续关闭。
