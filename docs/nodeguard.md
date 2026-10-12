# 宿主节点门禁与本地终止证据

`sandbox-nodeguard` 是运行在 Linux 宿主初始 mount namespace 中的受信任 root 服务。它用官方 CRI v1 转发接口控制启动，用 SQLite 持久账本保留启动归属，再用宿主 pidfd、cgroup v2 和 Pod 挂载检查提供终止证据。普通 API、租户容器、runner 和 Kubernetes Pod 状态都不能提交该证据。

本实现具备可执行协议和故障测试；真实 Kata/QEMU 进程布局、CSI 行为、绕行防护、节点断电和云 fencing 仍须在选定云节点完成验收。安装器应保持 bootstrap-only，直到指定矩阵的认证证据齐备。测试中的宿主子进程与模拟 CRI 不等同于真实 KVM 认证。

## 固定运行合同

候选组合为 Kubernetes 1.36.4、containerd 2.3.5、Kata 4.2.0 Go QEMU、cgroup v2 和 systemd cgroup driver。Kata 的 VM cache/template 必须关闭，`sandbox_cgroup_only` 必须开启。Go QEMU 已被上游标记 deprecated；本实现不自动切换到 runtime-rs 或其他 hypervisor。

- kubelet `containerRuntimeEndpoint`: `unix:///run/sandbox-nodeguard/cri.sock`。
- kubelet `imageServiceEndpoint`: `unix:///run/containerd/containerd.sock`。nodeguard 转发全部 RuntimeService，包括新增流式读方法；ImageService 独立直连，不负责启动容器。
- nodeguard 上游固定为 `/run/containerd/containerd.sock`；外部调用者不能指定上游地址。
- 所有 `kata-qemu` Run 请求均须已有精确启动许可，即使请求没有平台标签。未知 handler 和带平台标签的 runc 请求拒绝；受集群准入约束的系统 runc 请求透明转发。
- 每个 Pod UID 最多转发一个 RunPodSandbox。已成功或结果不明的 Run 都不会自动重试。kubelet 请求新 sandbox 时拒绝，需要平台安全终止原实例后通过新 Pod UID 启动。
- 启动许可到期只限制后续 Run/Create/Start。已有 VM 的 exec/health 要求门禁仍 OPEN；计算 TTL、调用授权和执行 attempt 的实时校验由控制面及 CONNECT 准入实施。
- 注册绑定 tenant/project/instance/workspace、generation、launch、Pod/PVC/PV UID、CSI handle，以及 cluster epoch、Node UID/name、boot ID 和运行配置 SHA256。

固定安装同时禁用 containerd 的 `io.containerd.monitor.container.v1.restart` 自发恢复插件；否则持久 restart label 可以绕过 CRI 前门启动旧任务。实际 kubelet env 也纳入 profile，禁止命令行覆盖两个受控 endpoint。持续 fencing 证据与剩余云/存储边界见 [审查记录](nodeguard-fencing-review.md)。

CRI 原始 socket、nodeguard socket、Kata runtime 二进制、cgroup 控制面和配置必须只对宿主受信任 root 开放。禁止旁路 kubelet endpoint、直连 containerd 启动、共享宿主 PID/卷或其他未记录的启动来源。文件 SHA256 只检查与已登记配置一致，不会自动证明配置语义安全。

## 安装、首次初始化和重启

二进制配置默认为 `/etc/sandbox-nodeguard/config.json`，字段为：

```json
{
  "node": {
    "cluster_epoch": "<登记的 UUID>",
    "node_uid": "<Kubernetes Node UID>",
    "node_name": "<Node 名称>",
    "boot_id": "</proc/sys/kernel/random/boot_id>",
    "profile_sha256": "<profile 文件原始字节 SHA256>"
  },
  "profile_file": "/etc/sandbox-nodeguard/profile.json",
  "listen": "<登记的私网 IP>:9444",
  "tls_certificate": "/etc/sandbox-nodeguard/tls/server.pem",
  "tls_key": "/etc/sandbox-nodeguard/tls/server-key.pem",
  "controller_client_ca": "/etc/sandbox-nodeguard/tls/controller-ca.pem"
}
```

上例仅展示字段；占位符不能用于运行。`profile.json` 含 `protocol:1`、`runtime_handler:"kata-qemu"`、`containerd_version:"2.3.5"`，以及七个 `{path,sha256}`：`qemu`、`virtiofs`、`shim`、`kata_configuration`、`containerd_configuration`、`kubelet_configuration`、`kubelet_environment`。实际路径和摘要必须来自受控安装产物及认证配置，不能复制示例值。

配置、profile、私钥须 root 拥有、0600；证书和 CA 不得被 group/other 写入。目录 `/var/lib/sandbox-nodeguard` 和 `/run/sandbox-nodeguard` 为 root:root 0700，代理 socket 0600。服务独占 `daemon.lock`，防止两个代理同时读写同一账本。

1. 节点保持隔离，安装固定 runtime 和配置；先启动 containerd，不允许托管租户工作负载。
2. 提供本次 Node UID/boot ID/profile 的受信任注册资料和双专用 CA 证书。服务端证书 SAN 为 `<node_uid>.nodeguard.sandbox.internal`；客户端 CA 只签发终止控制器身份。控制端口仅允许该控制器网络访问。
3. 运行 `sandbox-nodeguard --initialize-journal` 一次。它先独占创建并 fsync 永久标记，再初始化 SQLite WAL/FULL-sync 账本，并检查现有 CRI 运行体覆盖情况。已有数据库或标记不能被此命令覆盖。
4. 使用普通服务模式启动，随后启用指向代理的 kubelet。不得通过 PrivateMounts、ProtectSystem、容器化运行或其他会改变 mount namespace 的 systemd 隔离设置使服务偏离宿主初始 mount namespace。
5. 相同 boot 的进程重启先关闭启动门禁，恢复全部账本中尚未取得终止证据的观察记录，包括已从 CRI 列表消失的 VM。恢复失败保持 UNKNOWN；不能因 CRI 列表为空推断无 VM。
6. 数据库、永久标记缺失，boot/profile/Node 身份改变或不完整初始化都拒绝自动恢复。先隔离并完成可信 fencing，再按运维登记流程处理；不得删除账本并把仍可能运行的旧节点当成新节点。

启动检查限制 CRI Version/List RPC 每次 5 秒，账本恢复最多 4096 个未完成运行体并具有 20 秒内部检查期限；超过上限保持关闭。该上限是失败关闭边界，不是节点支持容量声明。

正常停止先关闭监听并拒绝新的宿主工作，等待已经受理的 CRI、内核观察和 SQLite worker 真正退出，再关闭数据库连接池、fsync 状态目录，最后释放 `daemon.lock`。后台工作超出排空提示期限只记录告警并继续等待；不能通过取消等待 future 提前宣称收尾完成。35个 CRI 入口均在第一次 await 前登记关闭围栏；16个有副作用的方法完整追踪到实际 RPC/账本收尾，19个只读方法允许调用者取消。停止信号或 CRI transport 退出先关闭任务入口，再单独关闭只读请求。正常可写连接上，尚未返回 headers 的请求收到 `UNAVAILABLE`，六类只读流保留响应 metadata，并以一次 `UNAVAILABLE` 和 EOF 结束，不能把被截断的有限列表当成成功结果。

客户端完全停读、HTTP/2 窗口耗尽时，错误帧也可能无法写出。CRI 连接先有3秒排空宽限，随后只关闭实际传输 FD；仍等待原 tonic parent、每个连接的真实 FD 释放和已受理的后台工作。该路径可能使尚未送达的 ACK 保持 UNKNOWN，不能重发原有副作用或据连接关闭宣称 VM 已终止。传输连接与宿主工作分别追踪；关闭连接不取消启动、停止、内核观察或 SQLite worker，也不提前释放 `daemon.lock`。

systemd unit 固定 `TimeoutStopSec=infinity`、`KillMode=mixed` 和 `SendSIGKILL=no`。这使普通 stop/restart 保持排空状态，避免45秒强杀释放宿主锁后仍有未结算操作。运维可用 `systemctl --no-block stop sandbox-nodeguard` 发起停止并观察排空日志；无限等待的节点须保持隔离，走精确旧节点的可信云 fencing 与重新登记流程。不得通过 force kill、删除锁文件或清空 journal 取得终止证明。该配置不保证整机断电或管理员强杀的优雅关闭，异常退出仍按 UNKNOWN 恢复。[systemd 停止期限](https://github.com/systemd/systemd/blob/v255/man/systemd.service.xml)、[终止信号配置](https://github.com/systemd/systemd/blob/v255/man/systemd.kill.xml)说明了这两个选项的行为。

## 控制协议与证据

协议版本为 1，请求/响应应限制在 64 KiB。仅暴露：

| 路径 | 合同 |
| --- | --- |
| `GET /v1/node` | 返回 `{protocol,node}`，供受信任客户端核对固定身份 |
| `POST /v1/launches/register` | 精确启动许可持久化后才 ACK，返回 journal revision；不能重新打开 CLOSED/UNKNOWN 的 Pod UID |
| `POST /v1/launches/close` | 先持久关闭该 UID，再处理已开始的调用和内核观察；包含有时限 challenge |

生产控制入口使用 `control_mutual_tls` 与 `serve_control`：最多32个连接（含未完成握手、读写和handler），跨连接/HTTP版本最多16个活动请求；满额直接返回空503，不排队读取请求体。握手3秒、HTTP/1头2秒、无IO进展12秒、写阻塞5秒、连接总寿命15秒、关闭排空3秒。HTTP/2每连接最多4个并发流，头8KiB、流/连接窗口32/128KiB、发送缓冲32KiB；HTTP/1保留连接也受总寿命约束。控制入口保留上述3秒CRI停止加4秒内核观察的正常预算，不能照搬采集入口的5秒空闲期限。连接上限不等于支持的VM容量。

每次握手重新验证专用controller客户端证书链，要求叶证书及中间证书有效期覆盖完整连接期限及2秒时钟取整余量；关闭TLS会话缓存和TLS1.3 ticket，不能借恢复握手沿用旧验证。服务端SAN/CA由控制客户端按精确Node UID验证；这里的客户端链期限检查不替代服务端证书轮换或节点认证。连接超时、取消或503仅代表未取得当前有效证明；即使内核工作已经发生，也不能据此把实例标记终止、删除卷或释放配额。后续仍走精确challenge、持久门禁及新鲜挂载检查。

内置Rust控制客户端固定HTTP/1且禁用idle连接池，每次调用重新建连/验证证书；不能复用接近15秒寿命的旧连接来执行新的7秒关闭流程。服务器保留受限HTTP/2支持，其他受审客户端必须自行满足同样的完整请求预算。已通过实际 `verify_node → 空闲9秒 → close处理7秒` 单次请求回归，不用延长服务端连接期限或自动重试来掩盖请求失败。

CONTROL 的阻塞宿主观察另有跨请求16个许可，不排队；许可和任务登记归真实阻塞闭包所有。HTTP/2 reset、连接期限或调用者取消不会释放仍在内核中工作的许可，容量满额拒绝新的观察。它只约束 CONTROL 的终止、句柄释放和挂载检查，不声称给启动恢复、CRI capture 或整个宿主建立同一容量上限。死亡证据已经提交但 ACK 丢失时，重试会幂等释放原 pidfd/cgroup 句柄，并重新检查当前挂载；旧证据不允许跳过该检查。

Run/Create/Start 转发前先 FULL-sync 写入 IN_FLIGHT。调用者断开后内部跟踪任务仍完成结果登记；服务崩溃或结果不明时永久保留 UNKNOWN 并关闭该节点的托管启动。观察到的启动数量必须与已转发 Run 数量一致。缺失注册只会建立 UNKNOWN 墓碑，不会产生“从未启动”证明。

成功 Run 在返回 kubelet 前读取 `/run/vc/vm/<sandbox-id>/pid`，核对 QEMU 的真实 executable SHA256、`/proc/<pid>/stat` start time、精确 Pod cgroup，再获取 pidfd 和 cgroup 目录 FD。当前 profile 要求观察范围中恰好各一个 QEMU、virtiofsd、Kata shim；任何额外进程、遗漏、不同分组或身份变化都失败关闭。cgroup 协议路径相对于 `/sys/fs/cgroup`，不接受绝对路径或 `..`。真实 Kata 若不满足该布局，须调整并重新认证 profile/观察实现，不能在生产忽略额外进程继续放行。

CLOSE 可以请求 StopPodSandbox，但 RPC 成功或返回 NotFound 均不作为证明。观察器只对已固定的 cgroup 和 pidfd 发出终止信号，并同时确认已登记进程退出、该精确 cgroup 被删除或 `populated 0`，最后重新检查宿主 `/proc/1/mountinfo` 中没有该 Pod 的 CSI target mount。CSI 全局 staging mount 可保留，由控制面另行核验绑定和清理。

已登记进程退出且启动门禁永久关闭后，进程死亡证据持久化到 SQLite，再释放 pidfd/cgroup FD。每次新的 challenge 都重新读取 mountinfo；旧的“无挂载”结果不会直接复用。cached exited 时间可以较早，`pod_mounts_absent_at` 和 `observed_at` 必须来自本次检查。只有已登记且未转发任何 Run 的 UID 可以获得零运行体证明。

Stop RPC 并发最多 32、单次最多 3 秒（本版本每 UID 实际最多一个）；随后的内核终止检查在每个潜在副作用前检查内部 4 秒期限。扫描有输入字节数、目录数量、深度和 PID 数上限。Linux 不可中断 I/O、失效内核或 D-state 不能由用户态超时可靠取消；这类故障不能产出证明，应由控制面保持保留状态并进入节点/云 fencing。

## 故障处置

| 条件 | 本地行为 | 控制面后续 |
| --- | --- | --- |
| CLOSE 与 Run 竞争 | 只有提交 IN_FLIGHT 的 Run 可以继续；CLOSE 后新的启动拒绝 | 等该调用精确结算，未结算不释放卷或配额 |
| Run 已结算，kubelet 再次 Run | 拒绝第二个 VM | 显式安全 restart 产生新 Pod UID |
| 宿主代理在转发期间崩溃 | 重启后 UNKNOWN，禁止重发 | 进入可信 fencing，不用 Stop RPC 覆盖未知结果 |
| CRI 删除记录但本地 VM 尚存 | 从持久账本恢复 pidfd/cgroup 身份 | 等待退出；无法恢复则要求 fencing |
| 已记录 PID 被重用、cgroup inode 变化、额外 helper | 身份不满足，拒绝证明 | 保持终止等待，运维诊断/节点 fencing |
| CLOSED 后 CSI 迟到挂载 | 本次 mountinfo 检查返回 WAITING_UNMOUNT | 等可信 CSI 清理；不使用旧缓存跳过 |
| 节点失联、boot 改变、journal 丢失 | 不伪造本地成功 | 独立云 fencing：精确云实例确认停止、永久禁止旧节点复活、旧卷关联清理；请求受理或 Stopping 不够 |

CLOSED 墓碑不因服务重启、TTL、普通 API 删除而回收。更换节点、配置和 CA 的运维流程须保持旧实例不可复活；受信任管理员对宿主 root 或云 IAM 的绕行操作不属于此协议能隔离的范围。

## 验证与来源

常规命令：`cargo test --locked --offline --lib nodeguard::`。Linux 特有测试覆盖真实 pidfd 子进程退出、真实 gRPC 断开后 IN_FLIGHT/UNKNOWN 与无重发；SQLite 用例覆盖 FULL-sync、并发启动、关闭竞态、单 Run、启动许可过期、服务重启、冷启动和缓存恢复。真实 Kata/KVM、卷卸载和云节点失联需独立系统验收。

投射控制端凭据的 Linux UID/GID 验收使用[独立可复现脚本](nodeguard-trust-linux.md)，以真实UID/GID10001、可读的错误补充组和零capability执行现有精确测试；CI已接该检查。脚本自测不计实际Linux通过，实际文件权限检查也不代替Kubernetes投射或Kata认证。

CRI proto 固定为 Kubernetes `cri-api v0.36.4`，摘要和许可证见 `vendor/cri/v0.36.4/README.md`。生成 Rust 已入仓，生产 build 不执行代码生成；工具独立 lockfile 和 `scripts/check-cri-generated.sh` 用于再生成检查。

行为依据：

- [containerd 2.3.5 sandbox_stop.go](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/server/sandbox_stop.go)：不存在记录的 Stop 可以成功，且启动/停止竞态不等于可靠终止证据。
- [Kata 4.2.0 QEMU 实现](https://github.com/kata-containers/kata-containers/blob/4.2.0/src/runtime/virtcontainers/qemu.go)、[Sandbox stop](https://github.com/kata-containers/kata-containers/blob/4.2.0/src/runtime/virtcontainers/sandbox.go)、[virtiofsd stop](https://github.com/kata-containers/kata-containers/blob/4.2.0/src/runtime/virtcontainers/virtiofsd.go)：停止调用不能代替实际宿主进程退出观察。
- [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)：`populated` 和 `cgroup.kill` 需要与启动门禁及进程身份结合。
- [阿里云 StopInstance](https://www.alibabacloud.com/help/en/ecs/developer-reference/api-ecs-2014-05-26-stopinstance)：异步停止请求还需要状态查询及平台侧持久 fencing。
