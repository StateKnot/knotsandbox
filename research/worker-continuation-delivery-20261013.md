# 已提交资源阶段连续调谐交付（2026-10-13）

基线为公共提交 `02403cca0bc87ea4c3fe8f04df06bbbe69675628`，范围对应开发表 G2-04/G2-05、G0-07/G0-08/G3-03 的子项。生产调谐复用已有 Worker、OperationEngine、最小权限和正式43条迁移；没有开放新运行时、GPU或缓存开关。

## 实现合同

受监督的 `Worker::run` 在同一claim内最多执行四轮：策略登记、PVC登记、Pod登记、最终观察。只有前三种固定检查点的事务收到成功COMMIT回执才继续；每轮重新核验当前授权、政策/template、lease/token、期望状态、真实计算期限、launch/generation/epoch、UID/spec和运行环境。共用原25秒总超时及每10秒heartbeat，不给继续阶段重置期限。

`external_resources`、`operations.stage`、`operation.progressed` 同事务提交。Pod同时写UID及清理旧Ready字段；progress版本在已锁定操作内独立递增，payload中的lease_token用于关联同一租约。事件写入之后再次检查owner/token/RUNNING/lease期限，失败整事务回滚。未Ready仍WAITING_READY/5秒，错误保持原分类与指数退避。公开 `Worker::reconcile` 仍单阶段成功后wait1释放租约，停止/删除/重启收尾/诊断合同保留。

COMMIT回执未知时停止旧批次，即使其他连接已看见提交事实也不会继续。后继领取按固定对象与已登记UID恢复，不能把对象登记当可信Ready、创建替代卷或释放PENDING配额。现有可信Ready与可信VM终止仍各有独立证据门。

新增 `RESOURCE_CHECKPOINT_COMMIT` 固定观测；当前九种观测都是控制面调用范围。OK/ERROR/CANCELLED_UNKNOWN与原返回值保留，不输出provider错误正文，不承诺精确队列延迟或真实VMM/GPU可用时间。详见[运行合同](../docs/worker-runtime.md)与[观测合同](../docs/worker-dispatch.md)。

## 本机实际验收

最终普通Cargo制品来自 `.local/worker-continuation-20261013/build-final.jsonl`。隔离Docker、verify-full TLS PostgreSQL、十个独立LOGIN及正式正常迁移下，`pg-final/record.json` 核对源码/制品/SDK前后不变、迁移SHA384完整、自有测试进程与容器清理确认。

| 验收 | 数量 | 结果/关键事实 |
| --- | --- | --- |
| 连续调谐 | 6 | 全通过；同claim/token1三次独立事件版本；后继创建只能读取已提交前置UID/事件；可信launch登记前PENDING |
| 撤权/失租约/政策/epoch | 包含在6项中 | 四种独立故障不创建PVC/Pod，保留原检查点及PENDING |
| 未Ready与总预算 | 包含在6项中 | 精确5秒资格、不提前claim；慢前两阶段后共同25秒到期，原heartbeat续约，无Pod |
| COMMIT前失败 | 包含在6项中 | 真实domain_events表锁，UID/阶段/进度事件全部回滚，无下一资源；不当作ACK丢失 |
| 已提交ACK丢失 | 包含在6项中 | 双端TLS均验证同测试CA/hostname；截获真实COMMIT CommandComplete并暂留回执；独立owner看见UID/阶段/事件提交后断开该socket；token2复用原UID且每类POST一次，最终可信Ready，原PID/backend_start退役及全部代理backend收尾 |
| 原Worker恢复 | 4 | 崩溃UID恢复、缺卷拒绝、安全模式/撤权、100锁timer公平 |
| 队列调度 | 3 | 通知/自然扫描/重连/并发槽/单连接旧token合同 |
| 独立Worker进程 | 1 | ACL漂移非零退出、真实锁退避恢复、SIGTERM及物理连接缺席 |
| 非空历史升级 | 1 | ≤41真实历史schema→当前43条正常迁移，原来源/回执/已阅/权限合同 |
| 异步观测 | 4 | 成功/错误/已poll取消/未poll；日志脱敏和返回值保留 |

真实PG合计15项全部通过（新6+原4+调度3+进程1+升级1），原生严格all-target Clippy/fmt通过。六项纳入正式 `test-review-fixes.py` 与 `test-local-acceptance.py`，固定数量及必需ACK用例防止零测试假通过。

## 失败与CI状态

第一次容器创建因本机Docker Desktop停止而失败，没有运行测试；启动现有Docker后确认该随机容器从未存在，原记录保留。首次矩阵5/6通过，ACK用例在代理前置检查超时；精确诊断确认测试TLS转发需显式flush。随后故障业务断言全部完成但代理/池关闭顺序触发45秒连接上限；调整为先join业务、再关闭/await自有代理socket子任务、最后pool close。最终原完整矩阵15项通过，未放宽5秒前置校验、45秒I/O上限、生产25秒预算或TLS/角色规则。临时DEBUG步骤已移除，早期失败记录均保留。

上一公共提交GitHub run `38364068026` 的verify job在 `bff::tests::browser_http_login_csrf_refresh_revocation_and_stream_close` 业务断言之后的Fixture清理安全检查失败；其余console/SDK/云/安装jobs通过，browser未执行。本机原始exact5、完整BFF三轮9、0.2CPU/512MiB独立TLS PG3，以及诊断版3项共20项通过，根因未复现。`src/bff_tests.rs`仅增加失败时固定连接分类/state/wait/xact诊断，原owner/idle/ClientRead、普通DROP、55006记录行为均保留。新CI需要以实际新提交核对，不能由本机PASS推定旧故障修复。

## 未覆盖与下一步

本机Kubernetes/host是明确自有夹具，没有真实Kata/CSI/Cilium/GPU隔离或节省成本证据。原claim最老64候选的锁积压公平性、实际HA吞吐与72h持续负载仍未交付。exact accepted/queue/placement/artifact/VM/route/首次正确执行、有效期容量分母、镜像与节点warm预算/撤销/GC是后续P0。模板与GPU继续使用独立完整认证链；当前过期发行安全评估、Linux发行签名和实云部署尚未满足，不称生产上线完成。

本机Rust缓存复用 `target/review-low-debug`，命令限定2个编译job、关闭增量及dev/test调试符号，保留断言/溢出检查；最终约4.1GiB，小于20GiB。日志/证据保存在缓存外。当前磁盘超过50GB余量，无需清理共享缓存、已有Docker数据卷或用户文件。
