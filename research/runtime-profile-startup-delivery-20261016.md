# 启动时已加载 runtime 配置读回交付

日期：2026-10-16。范围为快速启动计划的 **P1b2**，承接 P1b1 配置文件准入。完整 P1、准备授权／预算及 pre-pull 仍未完成；本片没有新增 schema、权限、公共 DTO 或 VM／GPU 配额。

## 实际行为

生产 `CriProxy::verify_startup` 在 Version 验证后，通过原固定 containerd UDS 的同一客户端配置调用 `Status(verbose=true)`，核对固定 2.3.5 runtime 配置子集，随后才继续原 ListPodSandbox、既有进程恢复和 coverage 开放。HostObserver 仅向同层模块提供已验证档案中的期望 Kata 配置路径。

读回须有唯一 RuntimeReady=true 条件、默认空别名／runc／kata-qemu 三个报告 handler；配置中则须精确包含 runc 和 kata-qemu 两项且默认 runc。固定 root／state／endpoint、runtime type、systemd cgroups、Kata ConfigPath、安全空选项及受支持 snapshotter／sandboxer／IO 模式不符时拒绝。typed JSON 拒绝重复已解释字段，包括转义同名字段；Kata options 和 runtime 对象拒绝未知字段，其他未解释的顶层设置不被认证。缺失／畸形／超限／错误均返回固定错误，不输出 provider 配置。

新 Status 调用仍使用 5 秒 deadline／本地 timeout，克隆客户端单独限制 protobuf 解码为 256 KiB，info 最多 8 项、key 最多 64 bytes、每值最多 64 KiB；不改变原 CRI 转发的 16 MiB 限制。这些是读调用上界，**不代表 daemon 准备开销的内存／磁盘／FD 硬限**。

每次重启原 journal 初始化先清除 coverage，新核对失败发生在唯一生产开放动作之前，因此 fresh journal 不能登记。NetworkReady=false 可存在于尚无 CNI 的冷启动；RuntimeReady=true 不证明 shim 或 VM 能运行。

固定版本源码依据为 [Status](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/status.go)、[JSON 字段与默认值](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/config/config.go)及[runtime 插件加载](https://github.com/containerd/containerd/blob/v2.3.5/plugins/cri/runtime/plugin.go)。Status 的 config 来自 runtime 配置对象，未包含独立 images 配置或 NRI 状态；不能由此推断实际 image 平台和解包目标。

## 本地验收

精确公开基线为 `686b9b80677424fa969fa32737c35ee248280750`，远端完整 1075 文件树与公开副本相同；该提交 CI run38830234782 的 5 job／67 step 均成功。本片新提交 CI 独立核对，不沿用该结果。

| 验收 | 真实结果与范围 |
| --- | --- |
| 普通 Rust | `cargo test --locked --offline --all-targets`，65 程序、501通过／0失败／291环境ignored；不是实云／数据库专项全跑 |
| 新合同 | 上述501中含4项：合法冷启动、路径／执行选项／handler冲突、缺失／重复／畸形／超限，以及真实TCP/HTTP2 gRPC 的 verbose／decode 上界／原5秒timeout |
| 原生生产启动门 | 本地 Docker 内官方固定 containerd 2.3.5、Linux arm64、实际 HostObserver／CriProxy／GateJournal，1项通过；正例允许精确登记，独立有效profile的ConfigPath错配在Version／List正常时拒绝，实际register仍Closed |
| 原有原生只读链回归 | 同一新Linux制品的原containerd→scraper mTLS镜像观察case 1项通过，旧runner默认scope／message保持 |
| 质量检查 | Mac／Linux 严格all-target Clippy、fmt通过；复用runner的11项Python测试通过 |

原生fixture不需要真实Kata二进制：七份公开root-owned文件仅提供身份字节，shim从未执行。fixture的原image import仅用于现有库存断言，保持no-unpack；后置核对没有snapshot、container或task。网络为none、rootfs只读、cap-drop ALL、no-new-privileges、768MiB memory/swap、1CPU、128PID、nofile1024及原tmpfs／日志上限和45秒runner deadline不变。架构为本地Docker引擎原生arm64，不扩大安装器的amd64支持；fixture耗时不能作为沙箱启动基准。

两项原生验收均核对源码／制品／artifact JSON稳定，并确认自有container／image清理。Linux构建使用1079文件、15,969,165 bytes源码副本，不复制target／node_modules／私有配置；普通501回归在主工作区执行，现有其他改动保留。两平台沿用低debug、无incremental的既有受控缓存，不修改发布配置／断言／溢出检查或线程栈。

私有原始证据位于 `.local/runtime-image-binding-20261016/`：`ordinary-tests.log`、`clippy-host-v2.log`、`fmt-final.log`、`linux-build/clippy.log`、`native-v2/record.json`、`native-image-regression/record.json`、对应逐步日志及冻结清单。日志／完整验收汇总保留在编译缓存之外。

## 保留的失败与修正

- 首次Mac编译错误：测试引用未声明的tokio-stream；改用既有futures_util listener流，没有新增依赖。
- 首次本机wire测试的回环bind被默认文件沙箱拒绝；按现有授权以普通用户运行同一测试，没有root提权、扩容或更改测试期限。
- 首次严格Clippy拒绝测试unwrap；改为明确可诊断的Result。首次Linux编译发现HostObserver位于嵌套linux模块，getter的pub(super)不可供cri访问；收敛为pub(in crate::nodeguard)，未公开对外接口。
- 原生v1在创建资源前因调用命令未传实际CARGO_TARGET_DIR而拒绝制品布局；v2明确指定原Linux缓存路径后通过，原v1失败回执不改写。没有放宽Cargo身份检查。

这些是开发／包装失败，不能伪称旧产品运行时反例或完整安全认证。未为通过增加生产权限、CAP、期限或线程栈。

## 剩余退出门

本片只有启动时runtime子集核对。信任仍为原受控root本地UDS；没有新增SO_PEERCRED／PID-start绑定或daemon二进制身份认证，也不持续检测之后daemon重启／重连／漂移。该结果不可复用为未来准备许可、HIT或READY。

实际images平台／namespace／snapshotter选择、pull／unpack、lease／content／snapshot保护引用、GC交互，以及真实存储／内存／FD／网络准备硬限仍属于后续P1。P2—P6、目标Kata／云／CSI／GPU和性能／资源节省／成本认证未完成，pre-pull继续关闭。
