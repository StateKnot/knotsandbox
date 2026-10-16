# CRI 当前镜像索引与 OCI 配置身份核对

日期：2026-10-16。切片 **P1b5**。这是独立可用的本机只读排障消费者；完整P1的实际pull平台／snapshotter选择、原生引用／GC和准备开销硬限仍未完成，pre-pull保持关闭。

## 产品行为

新增 `sandbox-admin image-artifact inspect-cri --reference <repo@sha256> --expected-digest <independent-sha256> --platform linux/amd64`，直接使用公共 `nodeguard::native_image_metadata::inspect_cri`。root／Linux、独立摘要与精确平台、原固定UDS／peer对象绑定和 `k8s.io` 均保持；没有handler、namespace、socket、registry凭据或任意RPC参数。旧离线和inspect-native消费者及输出保持兼容。

同一Channel和I/O owner执行 `Version → ImageStatus A → 原生Get/Info/Read闭包 → ImageStatus B → 最终Get`。两个CRI请求均为verbose=false，只填精确ImageSpec.image。响应须有合法config digest ID，repository digests含输入精确引用，ID与独立验证的OCI config一致，前后身份投影相同。没有按另一个alias补成功；不要求无关alias列表完全不变。

单一原5秒连接／RPC预算，原元数据1MiB单块／3MiB累计、64帧，以及64KiB小回复继续生效。CRI额外固定128个alias合计、单项2048字节、累计48KiB；Info非空或形状／预算冲突拒绝。正常返回／超时等待I/O owner退出，原Drop取消保护保持，不声称已验证所有caller-abort路径。

回执为 `scope=CRI_INDEX_CONFIG_IDENTITY_ONLY`、`cri_image_id`、完整嵌套`native`回执；approval_checked／pull_selection_checked／runtime_handler_checked／snapshotter_checked／unpack_checked／gc_protection_checked／preparation_allowed全部false。CRI tags、User、size、pinned、Info和配置正文不回传。新增固定码CRI_IMAGE_UNAVAILABLE／CRI_IMAGE_MISMATCH／CRI_IMAGE_CHANGED；原协议／OCI／期限错误继续适用，CLI只输出稳定错误前缀，无失败成功回执。

## 固定来源和局限

官方2.3.5的[ImageStatus](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/images/image_status.go)只用image字符串解析索引，不处理runtime handler，snapshot存在性仍有待办。[索引getImage](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/store/image/image.go)以config digest作为ID，[初始化](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/images/service.go)固定宿主默认平台。因此某个多平台index已存，不能证明CRI索引的config属于调用方指定平台；本消费者核对这种具体身份差异。

这不是实际pull选择证明；[PullImage](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/images/image_pull.go)另行选择snapshotter，nil sandbox config会使用default。实际[IsUnpacked](https://github.com/containerd/containerd/blob/v2.3.5/client/image.go)还需目标snapshotter对ChainID的Stat；content／snapshot GC引用也须独立核验。两次CRI读与原生读不是跨服务原子快照，不提供长期保护引用。

本片不新增pull／unpack／lease写、数据库迁移、公共HTTP／OIDC权限或协议派生文件，第三方完整许可v4分发合同不变。正常业务启动授权、Ready／HIT定义及配额不变。

## 真实验收

公开基线精确为 `e3debc575e321f0776235302ebcf3d9ee043f2da`；[CI run38853793783](https://github.com/StateKnot/knotsandbox/actions/runs/38853793783) 五job／71step全成功。远端完整1106文件树、实际工作树blob SHA／可执行模式与干净公开副本一致；本片提交及CI独立核对，不能沿用基线证明。

| 验收 | 实际结果与范围 |
| --- | --- |
| 普通Rust | 65程序，513通过／0失败／291环境ignored；非所有实云／数据库专项全跑 |
| 新HTTP2 wire | 上述513含4项：index/direct身份与全部false标志、14类拒绝、双平台config错配、跨两次CRI请求的原5秒预算；真实TCP/HTTP2，非真实daemon平台选择认证；两端I/O owner及stream退役、无写RPC |
| 精确期限回归 | 同一失败入口的RED→GREEN，1通过；远端相同文案Cancelled仍Unavailable包含在普通负面矩阵内，无期限扩展 |
| 真实新CRI消费者 | 官方containerd2.3.5／Linux arm64，公共inspect_cri index/direct各一次；普通admin七进程包含index/direct成功、4类拒绝及旧native成功对照；独立fixture configdigest、Env不回显，no-unpack／无snapshot/container/task门通过 |
| 既有原生消费者 | 同一Linux lib/admin制品，native元数据、peer重连、startup profile、scraper-mTLS四项case各1 PASS；源码／制品不变与自有容器／镜像清理均确认 |
| 既有离线CLI | 实际新admin的Docker七场景PASS，源码／制品稳定，containers/context removed为true且无cleanup错误 |
| 质量门 | Mac／Linux严格all-target Clippy、fmt；11项Python原runner测试、新wrapper静态复用／独立config输入／资源边界检查通过；未改协议／依赖／许可输入，不将前轮100项发布测试冒充本轮重跑 |

本轮最终输入固定在`code-manifest-v2.json`，只复制源码／锁／必要配置的新Linux源码副本1108文件／16,263,789bytes，没有复制target或node_modules。使用原host与Linux低debug／无incremental缓存；编译前df，所有缓存保持20GiB内、可用空间大于50GB。构建／测试日志、原失败、固定输入摘要及回执保存在编译缓存外 `.local/pull-selection-20261016/`。

## 失败、诊断与修复

初次普通Rust运行在lib阶段331通过／1失败／132ignored，失败是新增跨RPC总期限用例；没有把未执行的其他程序算成通过。相同原ELF独立运行仍约5.04秒失败，增强断言后的精确RED为 `Err(RuntimeUnavailable), elapsed=5.00902975s`。锁定Tonic0.14.6原始源码显示本地TimeoutExpired转成Cancelled并保留source链。现在只识别该本地错误类型，不解析文本、不把全部Cancelled当deadline，不修改5秒预算。精确GREEN为1项通过／约5.01秒；完整回归包含远端立即返回相同Timeout expired文案仍Unavailable的真实HTTP2反例。没有临时日志打印或线程栈扩展。

初次Linux libtest编译被cgroup OOM杀死：本轮错误地显式将memory+swap从前轮原4GiB物理／8GiB总量缩为4GiB／4GiB。保留原command、inspect的OOMKilled、日志和exit101；恢复前轮原有配置，并将Cargo并发2降为1后重建。UID501:20、无网络、只读rootfs、cap-drop ALL／no-new-privileges、2CPU／256PID保持。实际native fixture仍用原768MiB memory/swap、1CPU、128PID、nofile1024、45秒case，不扩大其权限／期限。

## Standards

独立最终复核14个候选文件的SHA／权限、六份文档和原始验收证据：文档标准违反0项、有意义smell 0项。期限分类缺陷已闭合，OOM失败保留；功能验收的权限、期限、线程栈与资源边界未扩大。

## Spec

独立最终复核14个候选文件：新增发现0项，未发现缺失要求、范围蔓延或错误实现。已逐项核对精确RED／GREEN、五项原生回执及离线七场景、输入稳定和清理证据；当前索引身份未被提升为实际pull、snapshotter、GC保护或准备许可。

## 下一依赖

实际CRI pull的manifest／platform与Kata handler／snapshotter组合、native lease／content／snapshot引用及CRI GC交互仍待实现与真实验证。准备写路径必须证明实际执行者的存储／内存／FD／专用网络槽和临时空间硬限，限制客户端不足以限制共享daemon解包；无法隔离的profile不开放。

P2—P6、云／Kata／CSI、真实GPU、冷暖分位数及单位成功任务成本继续待完成／未认证。当前索引匹配不代表准备成功、缓存命中或可回收物理空间。
