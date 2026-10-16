# P1b1：宿主镜像运行时配置准入与身份绑定

状态：本批已完成本地验收。它接入现有 nodeguard 安装 plan／collect，阻止不支持的配置和验证后变化的输入形成节点登记资料；完整 P1、实际 daemon 读回、pull／unpack、原生引用和硬限仍未完成。[安装合同](../deploy/nodeguard/README.md)、[后续计划](image-preparation-production-plan-20261015.md)

比较基线是 `072169993552e3dde13541be476425bba24d0ca7`；其 [CI 38819043992](https://github.com/StateKnot/knotsandbox/actions/runs/38819043992) 已完成 5 job／65 step、全部成功。本轮重新核对 GitHub main 及完整 1071 文件树与公开副本一致。新提交、完整树和当前 CI 在本地 `publication-record.json`／`candidate-ci.json` 单独记录，不在源码提交内自引用 SHA，也不沿用基线成功。

## 实际生产变更

既有 `nodeguard.py plan` 为受控节点明确生成 `containerd_snapshotter=overlayfs`、`nri_enabled=False` 及 `images.runtime_platforms.kata-qemu` 的 `linux/amd64`／`overlayfs` 映射。它使用锁定 Kubespray 的原模板，不替换上游 role，也不新建第二套安装器。

既有 `host_profile.py --request ... --destination ...` 校验 v4、准确 root/state／Unix socket、唯一显式 image handler 映射，并拒绝额外 imports、动态插件目录、proxy plugins、stream processors 和 server／snapshotter 等未认证插件配置。Kata runtime 表仅接受类型、options 和兼容 snapshotter 字段，不允许 `runtime_path`／`base_runtime_spec` 绕过已哈希 shim 或规格；非空 legacy snapshotter 与 image 组合冲突也拒绝。NRI 要求唯一 `disable` 键且值为真正的 bool true；配置版本要求 int 4，不能用 Python 的数值相等将 1／4.0 认证为所需类型。

七份输入通过同一读取入口取得原 FD、原路径身份、原始字节和 SHA256。配置解析直接使用所哈希的字节，配置最多 1 MiB、每二进制最多 512 MiB。目录逐级 NOFOLLOW，常规文件使用 NOFOLLOW／NONBLOCK 并验证 root 所有、无 group/other 写权限；FIFO、符号链接、替换、读取中变化和越界均拒绝。发布前保持七个原文件 FD，再复核原文件和目录链；没有先验证一份配置、随后重开另一份取摘要的窗口。

输出目录也持有可信 FD，root 所有且 group/other 无权限；安装流程使用 0700。排他写入 0600 文件并 fsync，写前后都核验原目录，最后才发布 enrollment。部分较早输出可保留供隔离复核，不自动删旧资料；不承诺跨七文件和三个输出的原子事务。既有 Rust HostObserver 继续独立核验当前文件。

HostProfile 协议及七字段形状不变，没有 Rust 源码、依赖、正式迁移、数据库权限或现有 VM listener 改动。安装目标继续是 Ubuntu 24.04／amd64；collector 也拒绝非 Linux amd64。已有档案不自动更新，采用新组合须按现有隔离／维护／重新认证流程处理，不能覆盖原 profile、journal 或移除 taint。pre-pull 与 lease 写入口仍未开放。

## 固定官方事实与本批边界

| 官方固定来源 | 实现据此采取的约束 |
| --- | --- |
| [containerd 2.3.5 version.go](https://github.com/containerd/containerd/blob/v2.3.5/version/version.go) | 生产配置版本为 4。旧 native 观察夹具使用 v3 的兼容迁移，不用于降低此门 |
| [CRI 配置结构](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/config/config.go)、[images 映射更新](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/images/service.go) | runtime 的 snapshotter 与独立 images runtime_platforms 都可能影响选择；已有 image 映射不会被 runtime 传播覆盖，因此拒绝冲突；runtime_path 可选择不同 shim |
| [v4 服务端配置](https://github.com/containerd/containerd/blob/v2.3.5/cmd/containerd/server/config/config.go)、[实际 gRPC 插件](https://github.com/containerd/containerd/blob/v2.3.5/plugins/server/grpc/plugin.go) | 不能仅检查 legacy `[grpc]` 后声称 v4 endpoint 固定；本组合拒绝额外 server 插件表 |
| [NRI 默认配置](https://github.com/containerd/containerd/blob/v2.3.5/internal/nri/config.go) | NRI 默认并未关闭；本组合显式禁用，不能靠缺表推断关闭 |
| [Status 实现](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/status.go)、[PullImage](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/images/image_pull.go) | Status.verbose 仅包含 runtime 配置，未给独立 images 已加载配置；映射中的 platform 也不能代替实际 pull 平台选择证据 |

因此，本批成功只表示受支持配置与所认证文件身份一致。不证明 daemon 已采用它、目标 snapshotter 插件／挂载或内容闭包存在，也不证明 native lease、GC、安全解包、物理存储／内存／FD／网络预算已生效。没有实际 Kata、CSI、云或 GPU 测试，没有启动加速、节省比例或利用率结论。

## 实际验收与失败保留

私有证据目录：`.local/host-image-binding-20261016/`，位于所有编译缓存之外。

| 证据 | 实际结果 |
| --- | --- |
| `config-red.log` | 初始缺少 runtime_platforms 的真实生产 validator 未拒绝，测试失败；日志保留 |
| `nodeguard-check-v2.log` | Python 3.12.14：14 项 unittest 全通过；既有 Ansible 语法检查和新增完整模板检查通过 |
| `template-v1.log`／`template-v3.log` | 最初错误使用 include_vars 覆盖 host 值，真实模板验证失败；改用真实 role defaults 优先级后通过。最终以 `nodeguard-check-v2.log` 为准 |
| 完整模板 | 使用与固定 archive 逐一比对的原模板和 defaults／vars；只在本机临时目录执行 1 个 template task，28 个安装任务全部跳过，无 become 或远端操作。最终 v4 输出 SHA256 `430a3f59f3cbcbb23042ace029d19baa83d7b543646b548117434748360a7206`，上游输入前后不变 |
| `docker-v4-default/record.json` | **PASS**：按 CI 默认入口从现有锁定 backup Dockerfile 的 python-runtime target 构建，20 个真实 collector 子进程场景全部达到预期，40 份关闭后的日志已导出并逐项校验。包含成功、配置覆盖／映射冲突／NRI、符号链接／FIFO／预算／权限、旧输出保护和配置换档竞态 |
| Docker 身份与限制 | 实际执行平台 linux/amd64，Docker engine arm64，Python 为固定 Debian runtime；不作为物理 amd64 或 Ubuntu/Kata 认证。容器 root 仅用于原 CLI 所需的宿主文件所有权语义，capabilities ALL dropped、network none、只读 root、no-new-privileges、私有 cgroup、256 MiB、1 CPU、64 PID、nofile 1024，无 host bind、volume 或端口；单项 5 秒、总执行 90 秒保持 |
| 最终证据与退役 | inside record 与实际 stdout 完全一致，40 个安全文件名／大小／SHA 和 base64 校验通过；源码在验收期间不变，COPY 输入不变，自有容器／两个自建镜像／context 清理且确认不存在，cleanup_errors 为空。共享基础镜像不删除 |

竞态通过真正的 `/proc/<child>/fd` 确认 QEMU 输入已打开，停止该自有子进程、原子替换之前验证过的 containerd 配置，再恢复进程；没有 mock、猜测 sleep 或调用生产私有函数。稀疏文件逻辑大小 512 MiB、实际分配 4096 字节，不复制 target 或分配整份载荷。最终 CLI 保持原配置 FD，非零退出且没有 enrollment。

`baseline-cli-race-red/` 使用仅 12 个必要源码／配置文件的独立副本，collector 原文来自精确公开基线；私有 harness 仅选择既有单项 `--case config-race`、期待 2 份日志，未调整正式 20 项验收或期限。实际旧 CLI 在同一替换内容下退出 0 并发布 enrollment，屏障时配置 FD 已关闭；这是期望捕获的 RED，不能标成该旧版本验收通过。`race-red-green.json` 保存它与最终整轮 GREEN 的对应事实和 SHA；两次自有资源清理均确认。

早期 `baseline-cli-red/` 批量反例在“不可信输出祖先”被旧 CLI 接受后，夹具因保留输出而未清完后续固定输入，后续未启动的 case 不计产品反例；FIFO 则真实超过原五秒并被回收。完整旧失败记录保留，再以独立单项完成上述竞态证明。其他已实际执行的基线映射／覆盖反例与 validator 对照不外推为全部旧版场景均被验证。

| 首轮失败 | 后续处理及范围 |
| --- | --- |
| `docker-v1/` | FROM 本地 image ID 被 BuildKit 当作远端仓库名，构建失败；改为核验 ID 后使用本次随机临时 tag，提供的旧镜像及原 tag 保留 |
| `docker-v2/` | COPY 目录没有正确遍历权限，actual helper 未启动；镜像内目录修为 root:0555、文件 0444，未增加运行时 capabilities |
| `docker-v3/` | 20 项实际 CLI 已通过，但 Docker cp 不能导出 live tmpfs，整轮仍 FAIL；改为活体内固定、只读、有界 FD 提取，不放宽证据门 |
| 命令预检 | 本机默认 Python 缺 tomllib、独立副本中相对 venv 路径无效的命令未启动目标验证；改用既有绝对 Python 3.12 环境。记录不作为产品反例 |

Standards 初始输出祖先 P2 已修复；Spec 的 shim／v4 插件覆盖问题及输出写后终检、NRI 和类型要求均已补齐。写入中途 root 维护进程替换最后输出目录的精确调度点未单独注入；本轮真实竞态证据针对输入换档，输出写后路径检查另经静态审查。最终两轴结论和 14 文件清单写入私有 review／verification 记录，未完成的 CI 不预记成功。

本轮未改 Rust 输入，因此没有重编译或将基线 497 项／291 ignored、Clippy 当作本轮重跑。源码、锁与迁移相对已验基线逐字节比对；Python／Ansible／Docker 为本轮新增行为证据。磁盘开始约 303 GiB 可用，包装中仍约 304 GiB；没有清理共享 Rust 缓存，不把后台磁盘波动归因于本轮。保留 Mac `target/review-low-debug` 与 Linux `target/image-observation-linux-arm64-low-debug` 供同工具链后续复用，后续使用前继续核对年龄、容量和活动锁。

## 后续起点

先核对本批精确 CI，再实现已加载 runtime 的实际读回与受控配置比较，明确独立 images 配置及真实 manifest／snapshotter 的证据缺口。随后闭合原生 lease／共享引用与 GC、daemon 的存储／内存／FD／专用网络槽硬限。P1—P4 全部验收前保持 pre-pull 关闭，普通 launch 许可、用户工作区和 GPU 独立授权合同不变。
