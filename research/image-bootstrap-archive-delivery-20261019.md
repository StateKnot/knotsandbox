# P1b7b：单镜像归档生产者交付

## 范围与基线

本片在已验 OCI 元数据／实际层载荷内核上增加公共 Rust `export_bootstrap_archive` 和实际 `sandbox-admin image-artifact export-bootstrap-archive` 消费者。交付的是确定性、受逻辑预算约束的单镜像归档接口；完整 P1 准备执行器、pre-pull、审批、普通 launch、native lease／GC 和目标云生产认证仍未完成。

开发前核对公开基线完整提交 `01d320d49fc66c1ad3eba0762b2d87b0356be9ee`：2026-10-19 06:17:24 UTC，精确 push [CI run 39203873162](https://github.com/StateKnot/knotsandbox/actions/runs/39203873162) 已完成／成功，5 job／75 step，没有失败。该结果不用于证明本片新源码；本片发布后的精确提交和 CI 另存私有交付回执，不能引用旧绿灯替代。

主工作区保留历史改动，不全量提交。公开副本只同步本批最终清单中经审查验收的文件；未通过审查的部署执行器不进入公开仓库。没有创建 release、强推或改变 pre-pull 开关。

## 实现

- 新 `src/image_artifact/bootstrap_archive.rs` 构造单直接 manifest 的 canonical OCI wrapper；只写固定标记／index 与已认证 manifest／config／去重层 blob，不枚举目录或复制源 index 的导入名称。
- 基于原 layout 目录 FD 验证实际载荷，再逐条输出时复核文件／原路径身份、大小、SHA 和真实 EOF。同字节 inode 替换拒绝；固定 16 KiB 传输缓冲，精确 USTAR header／padding／EOF 计入独立输出上限。
- 明确规范 authority／repository@同根摘要，拒绝 tag、隐含 Docker Hub 归一化、root index 和不受支持类型；原元数据／载荷 index 支持不变。
- 公共 `BootstrapArchiveLimits` 提供新接口显式正值／最多 300 秒协作期限，不放宽原载荷／原生检查 5 秒。CLI stdout 为二进制流，成功无 stderr；错误可能留部分归档，消费者必须先确认成功及完整持久落盘，再导入。
- 新增 3 项库测试与 4 项实际 CLI 进程测试，独立 tar reader 检查内容／命名／预算／输出错误和写入期间文件替换。无新依赖、迁移、网络端点、权限或默认开关。

完整参数、失败合同与 false 回执见[使用合同](../docs/image-artifact-bootstrap-archive.md)。导出器不解释层 tar 条目、不解包、不执行镜像，也不提供 OS 硬限或镜像审批。

## 本地验证

| 验证 | 实际结果与边界 |
| --- | --- |
| 主机新接口及原镜像回归 | `image_artifact` 27 项／库过滤 12 项通过，fmt 与 `clippy --all-targets -D warnings` 通过。未把历史主机权限拒绝的全量失败改写为通过 |
| 冻结公开候选 Linux 全目标 | 从 01d 完整公开源加本批 5 个 Rust 文件建立源码副本，无 target／node_modules／虚拟环境复制；实际 65 个父测试程序，573 通过／0 失败／309 既有环境专项 ignored；两层子进程结果仅计最外层最终摘要，原始嵌套摘要保留 |
| Linux 编译与质量 | 全目标 test `--no-run` 与 strict Clippy 通过；原工具链、单构建并发、低调试非增量配置、编译原 4 GiB 内存／8 GiB 含 swap；测试原 1 GiB／无 swap、CPU2／PID128、不加线程栈、非 root／只读／无网络／drop ALL 保持 |
| amd64 实际制品 | 在非特权 Linux 容器内使用固定 Rust 1.98.1 与官方目标标准库、Debian 签名源交叉 GCC，正常编译 ELF。`sandbox-admin` SHA-256 `5d7e7fee66e38cd6b583fd3c53dae9c5637c8053b55b57c9f464d32d890dbe00`，源清单／制品前后稳定 |
| 独立审查 | 最终 Rust 五文件 Standards／Spec 均 APPROVE，0 未关闭发现；部署执行器的拒绝结论与该独立范围分开记录，最终整批文件另绑定审查清单 |

### 真实原生消费与同一存储重启

2026-10-19 08:09:30 UTC，最终 amd64 制品在上述独立一次性 guest 的真实 containerd 2.3.5 上一次通过：外层含启动／关机 271.536 秒，guest 专项工作 19.620 秒，实际 38 个命令均退出 0。这里的时间只是本次功能回执，不是启动性能基准或 SLO。

独立 Python stdlib 构造一个直接 manifest／gzip tar 及真实 proof 文件；源 index 故意携带恶意导入名，并放入未引用 blob。通过新 CLI 只导出一次 6144 字节、5 个成员的 canonical archive，独立 tar／JSON／SHA 检查内容和唯一明确名称；实际 ctr 在固定 UDS、`k8s.io`、`linux/amd64`、`overlayfs` 下仅导入一次并完成真实层 apply。原生库存两轮实际只观察到批准 manifest／config／层，受控 wrapper 未观察到保留，不据此推断已验 GC 回收；恶意源 index／extra blob 不在库存，名字只含明确引用与合法 CRI config-ID alias。

两轮共 6 个正式 `inspect-native`／`inspect-cri`／`inspect-snapshot` 回执通过。每轮由已存在 committed ChainID 创建本次只读 snapshot view，真正 mount 后读到独立 proof 字节，再只移除本次 view。没有调用会自动补 Unpack 的 `images mount`。两次自有 daemon 正常退出，原 PID 消失，containerd／runc／shim 名称进程扫描为空；同一盘重启后，committed Created、实际 source 目录 inode 与内容保持，不重新 export／import／pull／unpack。

原 admin／ctr 5 秒守卫、初始 guest 总工作 300 秒及外层含 boot／shutdown 900 秒均保持，无失败重试。未执行 CRI task 或 runc 容器；未建立 lease／GC 完整保护，不认证执行器的不可抬限边界、未来普通启动命中、Kata／GPU／云或性能。完整 `vm/archive-native-v1/record.json`、原始 serial／已核 SHA 的附件与输入／ELF／外层 inspect 保存于私有证据目录。

### 内核机制专项

为避免给本机 Docker 额外权限，在无网络、非 root、只读、drop ALL、no-new-privileges 的 Docker 内用 QEMU TCG 运行一次性 Ubuntu 24.04 amd64，使用只读官方基础镜像、任务自有 root overlay 和独立 128 MiB 空白 ext4 盘，无 KVM、宿主设备、宿主 cgroup 或端口。

基础镜像为[Ubuntu 官方 20261017 Noble amd64 cloud image](https://cloud-images.ubuntu.com/releases/noble/release-20261017/)，SHA-256 `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94`；下载与官方 SHA256SUMS 一致，未独立验证签名。固定 [containerd 2.3.5 amd64 官方制品](https://github.com/containerd/containerd/releases/tag/v2.3.5)归档 SHA-256 `2f0a095a71e3262d0d91ff0e50e2e4ae73c3866c4d1ff6a15f341097fba3dd44`，runc 沿用已有锁定 1.4.3，不随 containerd 推荐版本升级；均不安装到宿主机。

实际 guest 为 Ubuntu 24.04.5／Linux 6.8.0-147-generic／systemd 255.4。机制 probe 成功读回 cgroup v2 内存／CPU／PID 与 FD 上限；低内存独立单元实际 OOM kill，父进程存活；FD 耗尽得到 EMFILE；独立 ext4 上容量与 inode 均实际 ENOSPC；私网接口仅实际读回 lo，未执行该域的实际外连拒绝探针。这些只是 guest 原生机制验证，不认证部署候选不能 remount／改限／逃逸，不代生产宿主、云、Kata、GPU 或性能认证。

## 保留的失败与修复事实

1. 首次 fmt 检查失败后修正格式。首次主机接口 26 通过／1 失败：否例值以 `-` 开头，测试 helper 分开的 `--reference value` 被 Clap 当作选项。仅改测试传参为 `--reference=value` 后，原 validator 正常收到否例并拒绝；生产解析与限制不放宽。
2. Linux 私有 runner 首次在启动任何 Docker 前因既有依赖清单路径拼错而失败；改为原只读四包目录后执行完整 65 程序，没有复制虚拟环境或更换依赖。
3. 首次 BuildKit 工具镜像尝试长期停在 registry 元数据解析，未进入安装；精确中止该次自有进程并保存 Canceled 记录。随后由现有固定本地镜像 ID、官方签名 Debian 仓库构造任务验证工具，另存镜像和依赖来源，不把中止记录写成成功。
4. 部署候选在默认 macOS Python 3.9 缺少 tomllib 的失败、协议测试和独立审查否例均保留；不发布该候选，不用协议测试代替实际 Linux 验收。

原公开 0dd／e9 的 CI 失败及更早 BFF／代理／自动化 UNKNOWN 根因均保留；本片通过不倒推它们的历史原因或宣称旧失败已被修复。

## 准备执行器尚未通过的架构门

真实固定 containerd 2.3.5 源码核对确认：只限制下载／导入客户端不限制共享 daemon 和 helper 的写入；namespace／lease／taint 不是物理写者隔离，独立 store 再导入共享 store 也会重新产生写入。因此不能把客户端 cgroup 当作完整 P1。

本机开发了 fresh prejoin、离线单镜像、最终同一独立 ext4 的部署候选，独立审查发现：root `CAP_SYS_ADMIN` 加可用 mount 操作，可以撤销只读 bind 所依赖的限制，初始只读读回不是不可抬限证明；`/dev/shm`、持久 journal 等额外写域也必须有实际 bytes／inode 硬限，单文件大小软件检查不能替代。仅添加 unit 文本或 taint 不足以闭合。[systemd 官方边界说明](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#ReadWritePaths=)

候选还发现并实际复现 unit 恢复竞态覆盖；cancel 归属和跨文件系统恢复同样必须真实验证。候选继续保留本机开发与失败证据，不同步到公开部署目录；任何后续修复须重新冻结、双轴审查及实机验证。

下一项仍为全写者硬域：固定可执行、不可由后代提限的 LSM／外层隔离方案，实际验证重挂 cgroup／迁移与改限、mount API、设备节点／其他文件系统和 tmpfs spill 全部拒绝；再完成 native 引用／GC、失败残留与同一存储交接。只有 P1 完整通过后推进 P2—P6，pre-pull 继续关闭。

## 私有回执与缓存

完整日志和源／ELF／命令／容器 inspect／失败记录保存在工作区 `.local/p1-executor-20261019b/`，不上传到公共源码树。主要记录为 `host-producer-build-v2/record.json`、`linux-all-build/record.json`、`linux-all-targets-tests.json`、`cross-build/record.json`、`vm/capability-probe-v1/record.json`、`vm/archive-native-v1/record.json` 及两轴精确输入清单。

编译、测试和虚拟机前均读取 df。复用 `target/review-low-debug`（主机）及 `target/image-observation-linux-arm64-low-debug`（固定 Linux 工具链，含 amd64 交叉目标），没有复制已有 target；任务日志存于缓存之外。保留本轮可复用缓存和失败现场，不清共享数据库、数据卷或其他镜像，不以 du 汇总大小冒充实际释放空间。GPU、云、Kata、CSI、72h／冷暖性能和单位成功任务成本仍未认证。
