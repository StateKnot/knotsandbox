# 持续 fencing 审查（固定 containerd 2.3.5 / Kata Go QEMU 4.2.0）

当前本地门禁可以形成“旧 launch 不再由受控 CRI 启动”的证据链，但单次 ECS `Stopped` 仍不是可消费的永久云 fencing 或存储释放证明。云客户端应仅返回停止观察；启用门槛继续关闭，直到云状态、不可复活约束、旧卷关联以及真实节点故障测试形成完整证据。

## 宿主证据链

1. 托管 Pod 在转发 Run 前，绑定控制面许可和精确 Node UID/boot ID/profile。SQLite FULL-sync 将 IN_FLIGHT 写盘后才转发；每个 Pod UID 最多一次 Run。CLOSE 永久关闭同 UID，调用者取消、CRI 超时和进程崩溃不使请求恢复为可重试。
2. 同一 boot 的 daemon 重启不把 CRI 空列表当成“没有 VM”：恢复全部未完成终止的本地观察，包括运行时已遗忘的 sandbox。无法恢复 pidfd/cgroup 身份或存在未知启动则保持 UNKNOWN。
3. 系统 hard stop 后，旧宿主进程应已不存在；重新 Start/Reboot 出现新 boot ID 时，旧配置/initialized.json 与实际 boot 不同，nodeguard 启动失败。kubelet unit 要求并排在 nodeguard 后，不能在门禁失败时启动托管工作负载。丢失 journal/marker 同样拒绝自动初始化；已初始化记录不能被普通安装覆盖。
4. 固定 Kata 配置关闭 VM cache/template，拒绝 annotation 改写 hypervisor 配置。旧 PID、cloud instance ID 或相同路径本身都不是可复用身份。禁止以 hibernate/内存快照恢复作为已确认的硬停止。
5. 新 Pod UID 也不能自动取得旧许可。仍需新的控制面记录、实际调度 Node/boot 身份、mTLS 登记和准入核对；旧 cloud instance ID 的永久墓碑应由控制面阻止重新启用，不能仅依赖 partial unique index 中的 enabled 行。

这些保证以宿主 root、固定 runtime 和 cloud provider 受信任为前提。能修改 host rootfs、systemd、Unix socket 权限、云 IAM 或恢复旧磁盘快照的管理员，也能绕过纯软件门禁；这类操作必须走独立维护授权，并保留控制面的不可变墓碑。

## 已找到并修复的确定旁路

containerd 2.3.5 的 restart monitor 会扫描带 restart 状态标签的容器；任务消失时，`startChange` 直接 NewTask/Start，并不经过 nodeguard 的 CRI socket。因此不能把“正常 CRI 没有这种标签”当作关闭证明。guarded inventory 已显式禁用 `io.containerd.monitor.container.v1.restart`，实际宿主配置采集也校验禁用状态。系统 runc 工作负载继续由 kubelet 管理。依据：[monitor.go](https://github.com/containerd/containerd/blob/v2.3.5/plugins/restart/monitor.go)、[change.go](https://github.com/containerd/containerd/blob/v2.3.5/plugins/restart/change.go)、[插件类型](https://github.com/containerd/containerd/blob/v2.3.5/plugins/types.go)。

kubelet 命令行参数可以覆盖 YAML。guarded inventory 固定 `kubelet_custom_flags=[]`，采集器要求唯一的受控 `--config`，拒绝额外 runtime/image endpoint 参数，并将实际 `/etc/kubernetes/kubelet.env` 纳入运行 profile 摘要。不能只检查 YAML 中的 socket 字符串。

## 上游恢复行为核对

固定版本的 CRI recovery 加载现有 task 并同步其状态；sandbox task 不存在时置为 NotReady，已有容器 task 不存在时保留 Created 或转未知退出。该路径没有直接 NewTask/Start，随后应由 kubelet处理；这与独立 restart monitor 的自发重启路径不同。依据：[CRI restart.go](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/restart.go)、[Pod sandbox recovery](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/podsandbox/recover.go)。这只是对所选源码路径的核对，仍须证明最终安装的插件配置、Kata进程布局与目标节点行为一致。

## 仍需闭合的云与存储条件

| 条件 | 当前状态与要求 |
| --- | --- |
| 云停止观察 | StopInstance 请求返回或 DescribeInstances=Stopped 仅是观察；超时/查询不确定不释放任何槽或卷 |
| 持续不可复活 | 控制面永久记录已 fencing 的云实例身份；禁止启用/自动替换旧 boot，禁止ASG/定时任务/其他RAM身份恢复旧节点；新机器使用独立注册身份 |
| 磁盘身份 | 需要精确 account/region/disk/instance 匹配，确认旧卷关联已经清理，并与CSI/PV/PVC UID绑定；未实现前不能从compute关机推断detach完成 |
| 迟到操作 | 验证关机后迟到 Start/Run/NodePublish/attach、控制器重试、DB恢复、journal丢失均不会产生两个写者；运行时死亡缓存每次仍重新检查挂载 |
| 真实验收 | 至少覆盖宿主/代理/CRI进程分别被杀、云强制停止并再次Start、断网、CSI超时、旧API迟到及控制面重启。Linux子进程、mock CRI、语法验证不能替代此项 |

installer 的 `verify-enrollment` 只检查被审阅报告、登记回执及原始文件身份一致；`enable` 目前继续拒绝缺少云 fencing release capability，报告里的 PASS 不能打开该开关。
