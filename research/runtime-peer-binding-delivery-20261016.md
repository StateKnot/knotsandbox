# 固定运行时端点重连身份与请求排空

日期：2026-10-16。范围是快速启动计划的 **P1b3**。完整 P1、准备预算与 pre-pull 尚未完成；没有新增数据库迁移、公共 API、权限或 VM／GPU 配额。

## 生产行为

原 CRI Tonic connector 只固定 socket 路径，断线重连时仍可能接到另一个同路径服务。本片增加私有 `runtime_endpoint` 深模块，CRI 和镜像观察复用连接算法，各自保留独立 binding；不把一方的成功当作另一方的身份认证。

每次连接只允许 `/run/containerd/containerd.sock`。逐级 `NOFOLLOW` 打开 root 所有且无 group／world-write 的目录，并保留目录 FD；socket 必须是 root 所有的真实 socket，正常 0660 权限允许连接。以 `O_PATH` 固定 socket 对象，再通过 `/proc/self/fd/<fd>` 连接该对象，连接前后比较持有 FD 与原路径的 device／inode。不会把第二次可变路径查找当作已固定对象。

连接后检查 `SO_PEERCRED` 的 uid=0、有效 PID，以及两次有界读取的 `/proc/PID/stat` start time。一旦成功绑定，重连必须保持相同目录、socket 对象和观察到的 PID／start。身份冲突、已绑定对象丢失或检查失败进入永久拒绝；后续健康 root listener 也不能令它重新学习。首次尚未绑定时，部分路径缺失／系统错误可按既有 optional collector 策略重试，不能声称所有初次错误均永久拒绝。

`Bound` 期间每个 binding 保留三个目录 FD 和一个 socket pin；每次尝试另开临时四个 pin、连接 socket 及短时 proc FD。CRI／collector 都绑定时常驻 pin 合计八个。进入拒绝会释放原 pin，永久拒绝状态仍保留。这是局部 FD 占用说明，不是进程／daemon 的 FD 硬限。

CRI connector 发现永久拒绝后调用既有 `begin_drain`：停止新任务准入，取消纯读，正常 CONTROL 与新 CRI mutation 也通过原请求门拒绝。已准入 mutation／宿主工作的 owner 继续沿既有规则持有和结算。该动作不清 SQLite coverage、不直接写 quarantine、不生成终止证明或释放资源／配额；在途 mutation 失败仍由原 journal 规则处理。镜像观察保留自己的连接收尾和 UNKNOWN 行为。

这层身份基于受控 root UDS 和内核观察，不认证 daemon 二进制、同 PID exec、FD 转交、真实 PID 复用或持续配置不变。原已连接 FD 可以继续访问旧服务，检查发生在建立连接时；不存在持续监控或自动恢复承诺。运维应按既有隔离／证据流程处理 daemon 换代，不能删 journal 或放宽身份门恢复服务。

内核语义核对参考 [Linux AF_UNIX 对象查找](https://github.com/torvalds/linux/blob/v6.8/net/unix/af_unix.c)和[proc 文档](https://www.kernel.org/doc/html/latest/filesystems/proc.html)。本机真实 Linux 的独立 O_PATH／procfd socket 探针通过；不由源码参考版本推断目标云内核已认证。

## 验收与失败记录

精确公开基线 `cb47bc95d49d7b4196653c53133a4e28b1068e90` 的远端完整 1080 文件树与公开副本一致；其 CI [run38836529105](https://github.com/StateKnot/knotsandbox/actions/runs/38836529105) 五 job／68 step 全部成功。本片新提交完整树与 CI 独立核对，不沿用基线结果。

| 验收 | 最终结果与范围 |
| --- | --- |
| 普通 Rust | 65 程序／501 通过／0 失败／291 环境 ignored；本片生产代码冻结后运行，随后仅修改 Linux cfg 的新夹具，不将其称为数据库或云全量专项 |
| 最终重连门 | `native-peer-final`，实际生产 connector／CONTROL，1 通过，原官方 socket 恢复和无解包后置条件通过 |
| 原生产启动门回归 | `native-profile-regression`，同一最终 Linux 制品，官方 2.3.5 正例／ConfigPath 错配及正常登记闭合，1 通过 |
| 原镜像只读回归 | `native-image-regression`，同一最终 Linux 制品的 containerd→scraper mTLS，1 通过 |
| 质量门 | Mac／最终 Linux 严格 all-target Clippy、fmt、11 项既有 Python runner 测试及新 wrapper AST 均通过 |

三项最终原生 record 均为 PASS，source／binary／artifacts unchanged 和 owned container／image cleanup 均为 true。最终 Linux 构建 1 分 58 秒；该时间及 fixture 耗时不作为产品性能数据。

原生重连 case 使用官方固定 containerd 2.3.5 的真实 Version／Status 回包及生产 HostObserver／CriProxy／GateJournal／CONTROL router。先验证正常登记成功，再关闭原替代 server；同 PID 新 socket 和独立 root child 新 socket 分别作为健康替代端。独立直连健康探针收到 Version 后，实际 Tonic 重连拒绝，纯读／任务门排空，正常 runc CRI mutation 与 CONTROL 拒绝且替代端事件计数不增加。之后再换健康 root listener，旧 binding 仍拒绝。两个阶段均在 mutation／CONTROL 之后核对零业务转发，最后精确恢复官方 daemon 原 socket 并核对真实 Version／Status 与 no-unpack 后置条件。

替代 server 只是传输夹具；该 CONTROL seam 直接使用正常 router，不是 mTLS 验收。独立 child 同时换了 socket inode，因此不是对 PID 比较分支的单独故障注入，更不证明真实 PID 复用防护。原有镜像观察 case 才覆盖 scraper mTLS 正常链。fixture 没有执行 Kata shim、创建 VM 或 GPU 工作。

原生 runner 复用原 no-network、只读 rootfs、cap-drop ALL、no-new-privileges、768 MiB memory／swap、1 CPU、128 PID、nofile1024、日志／tmpfs 上限及 45 秒总期限，不添加权限／期限。新 CI 必跑重连 case 并保留失败日志。Linux 源码副本仅 1083 文件／16,020,813 bytes，不复制 target、node_modules、私有配置或 Git。

保留的两次真实失败：`native-peer-v1` 的 child 就绪前退出；增加有界 child 输出的 `native-peer-diagnostic` 确认 uid=0／mode=0755，被子进程私有目录门拒绝。修复为显式 0700 目录及 create_new 0600 通信文件；`native-peer-v2` 随后通过。审查另修复首次替代端在 mutation／CONTROL 后缺少计数复核，以及 ready 先创建后写内容的竞态；ready 现写完私有 pending 文件再原子发布。后者是静态发现，不伪称已有实际竞态重现。失败均保留 FAIL，没有弱化生产门或扩大测试权限。

证据保留在编译缓存之外的 `.local/runtime-peer-binding-20261016/`：初始／诊断／最终源码清单、各次 native record／日志、普通回归、两平台 Clippy、Python 与 fmt 日志及后续发布记录。冻结后仅修改交付文档，行为源码不变。只选择本轮 13 个文件同步公开仓库，保留主工作区既有所有改动。

## Standards

独立审查共发现 1 项 fixture P2：ready 在内容写完前可见。已通过私有 pending 文件完整写完后原子发布修复；剩余标准硬问题 0、需修复 smell 0。最终 13 文件摘要、三个原生回执、普通回归与范围说明均已复核。

## Spec

独立审查共发现 1 项 P2：首次替代端的计数核对早于 mutation／CONTROL，证据不足。已在两者返回后再次核对零新增 RPC；剩余 0。CONTROL 200→503、永久拒绝、官方 socket 恢复、失败保留及未认证范围与计划一致。

两轴各 1 项发现均已修复，最终未关闭项分别为 0；不将一轴通过替代另一轴。

## 后续依赖

下一项继续 P1b 的实际 images 平台／manifest、`k8s.io` namespace、Kata handler／snapshotter 选择，以及 lease／content／snapshot 引用和 CRI GC 行为；随后闭合真实存储、内存、FD、专用网络槽与临时空间硬限。配置声明和 Status 不代替实际 pull 选择，`sandboxConfig=nil` 导致 default snapshotter 回退的组合不能报 READY。

P1b3 不产生准备许可、pull、HIT 或 READY。P2—P6、目标云／Kata／CSI、真实 GPU、冷暖启动、资源节省和单位成功任务成本仍分别未完成／未认证，pre-pull 继续关闭。
