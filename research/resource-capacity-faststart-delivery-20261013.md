# 宿主容量与启动调用观测交付（2026-10-13）

本轮推进开发表12.3的两个子项：宿主真实CPU/内存容量上界，以及实际CRI启动调用耗时。G0-08/G3-12和快速启动工作包仍进行中；本轮没有交付节点整体利用率、自动调档、预热池或GPU共享。

## 上一提交CI

基线提交`3a6752eb31a979baf9b770e7e730d87b4e965812`的[CI运行38386853730](https://github.com/StateKnot/knotsandbox/actions/runs/38386853730)失败。production-console、typescript-sdk、cloud-infrastructure-contract和cluster-installation-contract通过；verify在真实Keycloak浏览器账号流程读取重新启用PATCH响应体时出现`RESPONSE_BODY_UNAVAILABLE`/`net::ERR_ABORTED`。此前独立PG回归通过，不能把更早的BFF清理失败当作本次原因。

本地原场景三次通过、一次出现另一种刷新定位器超时；没有稳定复现远端缺响应体错误，底层原因仍未证实。测试观测入口现使用**同一次原生fetch的Response clone**，在SDK绑定fetch之前安装。原Promise、Request/signal和Response原样返回；无重试、替代GET、合成响应或弱化版本断言。限定同源服务身份POST/PATCH，真实Idempotency-Key、状态和ETag匹配；最多16条、每条256KiB，消费后删除，异常和超预算失败。生产SDK与控制台请求实现未改。

新增真实浏览器合同10/10通过，包括原生身份保留、CDP单独读取失败、正文截断/取消/非法/超限、重复/容量限制、错误匹配、认证路径排除和页面重新加载。CI在完整真实场景前执行精确10项、零失败、零跳过检查，并保留日志；不能仅凭此宣称远端底层故障已根治。

## 宿主容量

新增`VM_CPU_CAPACITY_CORES`、`VM_MEMORY_CAPACITY_BYTES`两项gauge，贯通nodeguard、采集/写入白名单、固定查询、API/OpenAPI、TypeScript SDK和控制台。共13项公开资源指标、14条原始序列（含观察标记）、每节点3584样本预算，WAL容量校验仍保留原70%磁盘门槛。

CPU读取叶级有效cpuset，并取叶级和全部非根祖先有限`cpu.max`最紧quota/period。内存取完整同一路径有限`memory.max`最小值。父级可能共享；这些是实际采样的上界，不能当作专属预留、剩余容量或节点利用率。CPU是名义CFS/fair class带宽约束，burst、周期与其他调度类别使其不构成瞬时上限。

固定FD、device/inode、pidfd、完整宿主cgroup2挂载和祖先链接前后复核；限制前后双读只能证明观测期间未发现变化，并非原子快照。CPU/内存独立缺测，可选容量失败不抹掉原基础计数。全无限内存、非法/缺失文件、无法证明完整路径或观测失效保持缺测；真实内核零限制保留零。无Flavor、guest或宿主总RAM补值，无百分比或clamp。

## 启动调用

在现有受管`RunPodSandbox`调用周围记录单调`duration_micros`，固定`HOST_RUNTIME_CALL`/`CRI_RUN_SANDBOX_ROUND_TRIP`与launch关联。`OK`、`ERROR`与`CANCELLED_UNKNOWN`分列；返回Cancelled/DeadlineExceeded或已开始future被drop都保留未知。原Status、响应、所有权许可、120秒deadline及UNKNOWN处理保持，无请求/响应正文或provider错误消息日志。

此间隔不含走独立containerd端点的镜像拉取，不是VM Ready、端到端首次正确执行或VM死亡证据。未被poll的future不生成耗时。下一步须把accepted、排队、资源就绪、路由和首次正确执行按同一launch关联，并在真实Kata节点测量冷暖启动；不能拿本轮测试用例耗时代替产品启动基线。

## 当前源码本地验收

| 验收 | 结果及边界 |
| --- | --- |
| Rust普通库、严格native Clippy/fmt | 内核兼容补验后288通过，120个环境专用用例未执行；lint/format通过 |
| 严格Linux全target Clippy | 锁定工具链镜像通过 |
| Linux nodeguard普通合同 | 内核兼容补验后49通过，3个环境专用用例未执行 |
| 真实Linux内核容量精确用例 | 1通过；固定Docker运行镜像、0.75 CPU/256MiB、完整cgroup层级、inode变化和PID退出拒绝；不是Kata认证 |
| 锁定官方Prometheus查询语义 | 精确1通过，包含两个容量gauge、缺测、时间戳及HA分离 |
| 采集配置、实际Prometheus协议链、告警 | 17配置测试通过；实际mTLS抓取/远程写入/双副本/过滤/恢复通过；38个声明的告警故障场景通过 |
| 独立TLS PostgreSQL/签名身份/指标HTTP | 精确1通过；两容量选择项、租户隔离、IO期间撤权/epoch、正式迁移账本核对；源码/产物不变及自有资源清理确认 |
| SDK、控制台、真实浏览器指标合同 | 71、66、4通过；后者使用明确HTTP合同fixture，保留原值、空缺和撤权清理 |
| 原生响应观测合同 | 10通过、零跳过，使用锁定Chromium |
| 完整真实Chrome/Keycloak/BFF/API/TLS-PG | 精确1通过；真实账号/授权、诊断/事件、未来策略、通知失ACK及重放、停止受理、撤权；9张截图、业务事实不变、临时realm/进程/PG容器清理确认 |

非root Linux CI入口`scripts/test-nodeguard-capacity.py`消费普通Cargo产物，检查精确忽略用例、ELF/UID/metadata/路径、固定镜像与容器限额，只挂载二进制。创建失ACK按精确随机名字/标签/镜像恢复清理所有权；主失败和清理失败分别保留，未确认不存在不能通过。macOS本地的上述内核用例不等于这个Linux入口已经通过；最终入口与整套远端结果以新提交CI收据为准。

发布后复核发现Docker CLI29.6.2对不存在对象返回小写`no such object`，清理判断已改为大小写无关；实际不存在随机对象的inspect和精确名字空列表通过，权限或daemon连接错误不被当成不存在。该修正只影响验收收尾，不改变内核采集和生产运行。当前Docker Desktop的Cargo产物位于构建容器的named-volume路径且属root，不能满足该入口的普通Linux UID/宿主路径合同；未通过改属主、重写Cargo消息或构造宿主路径别名绕过，由真实Ubuntu非root CI执行入口。

随后`b7b89f7`的[CI运行38402086901](https://github.com/StateKnot/knotsandbox/actions/runs/38402086901)四个独立作业通过，但verify的普通测试步骤中，新增真实容量入口返回内核用例退出101、`GuardError::Invalid`；原宿主观察用例通过，自有容量容器清理确认，真实浏览器步骤尚未执行。原日志缺少内部阶段，不能直接推断失败原因。

预研确认[Linux内核rstat.c](https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/b91872c56940950a6a0852e499d249c3091d4284/kernel/cgroup/rstat.c)在CONFIG_SCHED_CORE时输出`core_sched.force_idle_usec`。原基础stats解析器确实拒绝这个合法字段；固定输入回归先失败再通过。现仅增加此字面字段兼容，任意其他点号字段、重复键、非法/溢出数字继续拒绝。该字段不产生新的公开指标，也不改变已有usage或throttle值。

真实内核用例增加固定读取/解析/断言阶段Context，实际CPU文件只打印上述字段存在与否的布尔标记；wrapper记录白名单错误码、阶段和布尔证据，无原始路径/控制器正文/凭据。所有容量、PID/inode、精确用例、产物和清理门禁保持。最新本地内核容量仍通过，当前Docker Desktop内核的字段存在标记为false；此环境不能替代Ubuntu的字段现场。最新远端CI仍需验收，不能把已证实的解析缺陷当作上一运行已被证明的唯一根因。

本地证据在忽略的`.local/resource-faststart-20261013/`，包含源指纹、普通产物SHA、原失败日志和清理回执；不提交PKI、身份凭据、临时数据库或构建缓存。

## 下一交付与发布门

按表继续有效期request/limit/overhead和归属账本、PSI/峰值画像，建立可解释的利用率/浪费原因；再做受预算与撤销/GC约束的镜像和节点预准备。GPU先完成独占设备租约、真实归属/显存/计算利用率采集、故障回收和数据残留验收，再评估MIG等共享模式。

真实Kata、Cilium、CSI、GPU、目标公有云和发布安全认证尚未通过；不得启用未认证模板/GPU或将本轮本地验证计为正式上线验收。
