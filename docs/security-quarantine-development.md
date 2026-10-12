# 隔离与解除隔离生产开发合同（尚未实现）

当前正式功能只有 [实例安全详情只读 API](instance-security.md)。本文是后续开发和验收合同，未提供隔离、解除隔离 API、调度器或新迁移，也不表示运行时已通过独立认证。正式迁移目前为 0001–0037；恢复、自动化等草案不得被伪装为正式迁移。新状态操作必须在完整实现、实际验收和按序正式迁移后启用。

## 产品语义与现有证据

第一阶段隔离应定义为：为目标实例建立持久安全 hold，立即禁止新的运行受理，再通过已有 STOP 流程结束该实例的实际 VM。接受请求只表示意图持久化；只有准确匹配目标代次的可信终止与清理证据才能报告 `COMPUTE_TERMINATED`。未得到证明时保留 pending/unknown，不释放计算配额、活动槽或工作区归属。

这不是“Cilium 策略已生效”的承诺。策略对象存在、Pod 不存在、进程退出、租约到期、超时或 STOP 请求被接受都不能证明 VM 死亡，更不能证明独立网络隔离。隔离状态与 applied policy、镜像验证、宿主认证必须分开报告；没有独立证据时继续使用 UNKNOWN/NOT_ASSERTED。

已有 `observed_state=QUARANTINED` 只是观测枚举，不能代替持久意图：终止流程完成后会写 STOPPED。`nodeguard` 本地 `guard_meta.quarantined` 是宿主级故障闭锁，会影响该宿主上的所有租户，禁止由租户实例 API 清除或重用为产品隔离。

解除隔离只移除 hold，并保持实例 STOPPED。它不重启旧 VM、不继续原命令、不恢复旧 CONNECT、不续租，也不自动修改策略或目录批准状态。之后的 START 必须重新经过当前权限、模板/策略批准、节点认证、配额、租约、新 launch identity 和准入校验。

实例 hold 只保证该实例不能继续执行，不自动保证数据谱系隔离。已授权的冷备或已有对象读取可作为取证保留，但不得为读取启动被 hold 的 VM。若产品要求阻止备份恢复或复制传播，还须设计 workspace/source lineage hold 与独立释放授权，并在恢复和首次 START 路径验证；不能用实例 hold 暗示已实现这种能力。工作区、备份和文件不得因隔离被自动删除。

## 持久状态与事务

新增租户/项目 RLS 的安全 hold 与不可变请求账本，保存目标实例、工作区、spec version、generation、launch、pod/epoch、请求者身份、批准范围、固定请求摘要/If-Match/幂等 key、STOP operation 绑定、接受时间、公开原因代码及解除引用。历史不能被原地改写为新的请求。公开视图只返回实例绑定摘要和固定原因；宿主、云资源标识、原始证据及任意脚本不进入租户响应。

hold 与真实 STOP 受理必须在同一事务完成；不能先提交 hold 再用新 key 启动 STOP，也不能先 STOP 再异步补 hold。复用现有业务受理与终止控制器，增加窄的安全受理上下文，避免复制第二套生命周期 SQL。幂等重放使用原请求、原资源、原 key 和原 If-Match；未知 ACK 只查询或重放原意图，不能创建第二次停止或解除。

统一锁序为 workspace → instance → operation → quota → event-stream head。安全意图的额外锁不得在持有它时逆序等待资源锁。新增 START/EXEC 与 hold 同时发生时，必须只有一个合法事务结果。最终事件头等待后重新验证当前 issuer/subject、主体、成员、租户、项目、权限、期限、版本和 epoch；所有期限以完成授权读取后的同一数据库时钟比较。

安全 STOP 可以在 safe mode、历史 epoch 和原创建者权限撤销后继续处理已接受意图的安全收尾。接受与解除仍要求当前授权；不能把 SYSTEM 身份当作租户请求者绕过。控制器超时、租约丢失、重启或结果不明不移除 hold。已关闭 launch 的 tombstone 和未知执行/文件写者继续遵守现有不可重放、配额保留规则。

解除需在资源锁内通过窄、租户作用域的证据函数验证：末代 launch 的可信 VM 终止与 cleanup，或合法 never-authorized 证明；没有未解决活动、计算配额归属或新并发受理；工作区与目标绑定仍相同。STOPPED 标签、Pod 404、执行进程退出、计算租约过期和任意“成功操作”标签都不足以替代该证明。API 角色不应获得原始终止 receipt 的 SELECT 权限。

## 权限与迁移

建议新增明确的 `instances:quarantine`、`instances:unquarantine`，不可由 instances:read 或已有 hard_stop 自动推导永久 hold/解除权限。隔离受理另与当前 `instances:stop`、`instances:hard_stop` 取交集，说明其实际会结束 VM；解除需要独立显式授予的权限。最终动作名称需和 API/OAS/SDK、bootstrap、项目委派允许列表一致，并测试有限授权的 ceiling 与撤销。

不修改冻结的 0036。新有序迁移应复制届时最新的 grant-definer 合同，只增加所需动作，保留恢复和自动化迁移已加入的动作及原锁序、期限、live-authority 检查。迁移编号由正式迁移顺序确定。新表/函数坚持最小角色、RLS、不可变身份、精确外键和原证据保护，不允许调度角色任意改队列或绕过接受角色。

草案验收用独立测试库：先正常应用正式迁移并验证角色，再显式应用受跟踪草案；生产启动必须仍拒绝草案，禁止写伪造的 SQLx 版本、忽略失败的角色校验或自动 fallback。公开动作与能力标志在正式迁移和完整验收前关闭。

## 必须修改并验收的守卫

| 路径 | 生产要求 |
|---|---|
| `lifecycle` START/RESTART/RENEW | 在统一资源锁内检查 hold；不能通过续租、重启或现有幂等资源重新开机 |
| `execution`、文件 transfer 接受 | 阻止新的执行与需要运行 VM 的传输；已有 UNKNOWN 意图只按原身份安全收尾 |
| 普通 worker、termination 的 RESTART 后半段 | 终止旧 VM 后创建新 launch 前再次检查 hold；隔离与 restart race 不能产生第二个 VM |
| admission（Pod/运行资源/执行 CONNECT/固定文件 runner CONNECT） | 使用当前持久 hold 与精确目标绑定拒绝新的运行；不能只检查 API 层 |
| gateway / file gateway 的 claim、dispatch、完成 | 领取任务不等于可派发；真正 I/O 前重验 hold/身份/当前授权，不重发 DISPATCHING/UNKNOWN |
| STOP、可信终止、never-authorized GC、安全清理 | hold 不阻止已接受意图的收尾；仍需物理证据才能释放计算与活动归属 |
| backup / restore / restored workspace 首次 START | 明确冷备取证与传播限制；不得绕过 hold 启动 VM；数据隔离模式还须检查来源谱系 |
| automation 的持久委托与实际业务受理 | 无调度 SYSTEM 绕过；每次经同一业务守卫，结果不明阻塞替代 run |
| GET 安全详情、操作/事件/审计、控制台 | 区分 ACCEPTED、终止 pending、未知、已证明计算结束和解除；保持权限脱敏与 no-store |

## 真实验收矩阵

| 场景 | 必须证明的结果 / 证据 |
|---|---|
| 12 个并发相同 key / 请求 | 一个持久 hold 和真实 STOP operation；不同 body/If-Match 不被同 key 接受 |
| quarantine 与 START / EXEC / FILE 并发 | 实际 PG 资源锁竞争，只有合法结果；hold 提交后无新派发/CONNECT |
| restart 已接受、旧 VM 已结束时隔离 | 新 launch 出生前再次阻断；真实 mTLS/VM 流程不产生替代运行 |
| API ACK 丢失、worker 重启、claim 被接管 | 只原 key/原绑定 reconcile；旧 claim、旧 epoch 与旧请求不得新受理 |
| 事件头锁等待期间撤权、成员/身份禁用、JWT/grant 到期 | 最终 DB clock/live-authority 拒绝新接受或解除；不泄露其他租户信息 |
| 已接受隔离后原权限撤销 | 继续安全 STOP/cleanup；没有自动解除或自动重启 |
| VM 死亡不明、仅进程退出、Pod 删除、网络断开、租约过期 | hold 保留；计算、槽位、卷和配额未提前释放；公开结果 UNKNOWN/pending |
| 可信终止 + 精确 cleanup / never-authorized 证据 | 仅正确末代目标可成为 COMPUTE_TERMINATED；错误 UID/boot/generation/epoch 不生效 |
| 解除与并发 START/新隔离竞争 | 资源锁下线性化；解除保持 STOPPED；重复解除不启动 VM、不继续旧执行 |
| 跨租户/跨项目、只读或 hard_stop 权限、超授权 ceiling | 实际 PG RLS + 签名 HTTP/Node SDK 拒绝越权，审计只保存公开原因 |
| 安全模式、历史 epoch、Cilium 额外 allow、CEP/策略对象存在 | 不被误报告为独立隔离认证；真实数据面认证单独验收 |
| 冷备取证、对象清理与未知 OSS 写者 | 不为取证开机、不删除持久数据；bytes 只在既有可信清理条件后释放 |
| 数据隔离模式下恢复/复制谱系 | 不可通过新实例绕过来源 hold；未开发此模式时明确不声称已限制传播 |

上线证据必须记录源/二进制 SHA、真实正常迁移账本、各角色权限、实际 PG/HTTP/Node SDK/可信终止结果及目标云的数据面认证。合同测试、历史假节点 fixture、CLI 返回成功和只读策略 discovery 不替代真实 VM、宿主、网络或存储认证。
