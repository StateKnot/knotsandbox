# 生命周期队列调度与控制面调用观测

正式迁移0044新增私有dispatch trigger。领取操作仍使用原`sandbox_claim_operation`和专用`sandbox_worker`登录；SQL继续校验路由、kind、due time、租约及token，租户RLS、审计、当前运行许可、UID与外部准入合同保持生效。既有1..37加39..43库通过正常migrate升级到44，不回填永久未发布的38，也不重写历史操作或路由行。

## 执行与恢复

Worker启动立即扫描积压操作。每个select轮次最多领取一个，成功后继续填充到`SANDBOX_WORKER_CONCURRENCY`上限；关闭、timer故障及阶段完成优先。槽满时不继续领取或创建内存任务队列。空队列后，提示只申请重新扫描，最早下一次空扫描距离上次至少50ms；提示不会延后该期限。数据库暂时领取错误保留2秒退避，提示、槽释放及恢复tick均不能绕过。永久合同错误仍停止父任务。

固定500ms interval使用Skip处理漏tick，不随任务完成重置。它恢复启动前提交、丢/重复提示、未来WAIT到期以及无人续期的租约。原阶段1秒登记等待、5秒非Ready等待、25秒阶段期限及30秒租约保持；阶段连续推进是后续独立开发。

0044只在WORKER路由的已到期dispatch新行或提前资格变更时发送`sandbox_worker_dispatch`空payload，未来资格和heartbeat不发送。通知在发送事务提交后才可见；回滚不留下提示。任何数据库会话可发送伪提示，所以接收方忽略channel payload，不能从中获取tenant、operation或授权。watch通道只保留一个扫描请求，操作从持久SQL领取。

监听在LISTEN提交后申请新扫描，断线及重订阅均再次扫描；错误后5秒重试，期间固定轮询继续。监听失败日志只输出固定说明。使用直连PostgreSQL或保持会话的代理；transaction-pooling代理不能保证LISTEN会话。单连接配置明确使用poll-only；其他配置常驻占用一个原池连接，业务可用连接为配置上限减一，不能把它当新增免费连接。目标容量应包含claim、阶段、heartbeat与timer的连接竞争。

关闭取消监听任务，显式UNLISTEN最多等待2秒，随后释放监听所有权。SQLx Drop会异步归还连接；只有现有外层`pool.close().await`完成才证明本地物理连接排空，任务返回本身不提供此证明。网络黑洞下该最终排空仍依赖数据库连接/系统网络超时，不声称所有网络故障都有固定退出SLO。

PostgreSQL通知队列满会使发送事务COMMIT失败；空hint不是“零提交成本”的承诺。运维必须监控`pg_notification_queue_usage()`、长事务、监听重连日志和durable积压，保留幂等重试及变更回执恢复。提示容量故障不能伪造业务成功。[PostgreSQL NOTIFY](https://www.postgresql.org/docs/current/sql-notify.html)、[LISTEN提交和初始扫描](https://www.postgresql.org/docs/current/sql-listen.html)。

当前原claim函数只检查最老64个候选并SKIP LOCKED；若这64个操作均被长期锁住，后项仍可能延后。本批只改善唤醒与并发填充，不承诺解决任意锁积压的跨租户公平性；定时器0041公平扫描是另一份合同。

## 调用观测

通过已有受依赖脱敏过滤保护的JSON tracing记录：`scope=CONTROL_PLANE_CALL`、固定`phase`、单调时钟`duration_micros`、`outcome`及可选固定`error_code`。已持租约时附私有日志关联operation_id/lease_token，不转成指标label，不打印tenant、request、provider错误详情、凭证或返回值。

| phase | 实际测量的范围 |
| --- | --- |
| CLAIM_ROUND_TRIP | 连接借用、权威SQL领取及COMMIT ACK的本地往返；包含空领取 |
| RECONCILE_ATTEMPT | 当前一次调谐调用，可能只提交WAITING |
| RUNTIME_CLASS_VERIFY | 当前RuntimeClass读取与校验 |
| NAMESPACE_VERIFY | 当前namespace读取与认证合同校验 |
| NETWORK_POLICY_ENSURE | 策略对象读取/创建/验证调用 |
| WORKSPACE_ENSURE | PVC对象读取/创建/验证调用 |
| POD_ENSURE | Pod对象读取/创建/验证调用 |
| TRUSTED_READY_COMMIT | 当前launch核验及Ready账务/审计/事件提交ACK |

OK表示该调用返回Ok，ERROR表示返回固定错误码，CANCELLED_UNKNOWN表示已经开始的future被取消/丢弃，远程副作用结果未知。未被poll的future不产生假样本。已有阶段返回值与业务等待语义不改变。缺少事件不是零耗时；这些是控制面调用耗时，不是精确queue latency、PVC provisioning、VMM boot或首次正确执行时间。调用时长相互包含，不能直接相加；pending还可能经历多次调谐，统计启动SLO必须按全部尝试和真实可用证据另算。

## 验收边界

`tests/worker_dispatch.rs`使用正式迁移、实际TLS PostgreSQL及独立worker登录，覆盖提交/回滚、空payload、伪/重复hint不能越过due/lease、并发槽、启动积压、物理断线重新LISTEN、禁用测试hint后的未来工作恢复、单连接到期租约和旧token拒绝。原worker崩溃/UID恢复/撤权/可信Ready及实际worker进程ACL漂移、timer竞争和物理连接排空继续回归。Kubernetes是明确的自有传输probe，没有启动真实VM。`worker_observation`四项测试记录真实异步成功、错误、取消及未poll，检查返回值保留和日志脱敏。

本机probe记录首/次任务到达时间供排查，不预填生产启动SLO。真实Kata/Cilium/CSI、HA吞吐、冷暖与高写入、72h稳定性、GPU和单位成功任务成本继续按[开发表第12节](../research/rust-sandbox-development-workbreakdown.md)验收。
