# 非空历史与升级后ACK交付 — 2026-10-11

本轮推进G4-06的历史schema升级验收，补齐非空账务、幂等/授权回执、法律保护和42已阅通知历史，并实际验证43后的当前签名身份ACK恢复与撤权。新增两个测试内部模块并接入既有runner；没有新增生产迁移、放宽角色或改动运行实现，工作保留在当前工作区。

## 实现与证明范围

`tests/automation_upgrade.rs` 仍只在runner本次新建、确认0个用户relation的TLS数据库运行。按真实迁移源码前缀1..37+39..41、冻结旧ACL、正常42、正常43的顺序推进，没有删迁移行、篡改checksum或先装当前schema再伪装历史。冻结ACL来源及SHA保护未变。

| 阶段 | 新增事实与验收 |
| --- | --- |
| 41历史 | 两租户各8个配额账户与8条预约（PENDING 2、ALLOCATED 4、RELEASED 2），余额精确等于预约聚合；真实 `reserve_quota`、`Idempotency.persist` 和typed Accepted生成创建受理回执；typed GrantReceipt关联既存授权；每租户2条LEGAL hold、1条release。 |
| 正常42 | 比较32类租户表及全局身份/平台配置/既有RLS、policy、触发器与函数安全属性，完整41账本保持；历史异常不回填通知。旧API/coordinator LOGIN仍按原ACL插入合法异常来源，由正常触发器派生通知。 |
| 42已阅历史 | owner对真实派生通知执行合法单向ACK UPDATE，同事务记录原键、原ETag摘要、typed响应、请求关联审计和run关联因果事件。只表示合法已提交历史夹具，没有运行旧发行包。 |
| 正常43和权限 | 全部历史事实、通知全部列和42完整迁移账本逐列不变；原正常角色脚本安装后再次比较，当前API/coordinator角色及完整schema检查通过。 |
| 当前ACK | RS256签名JWT经本地真实JWKS验证，再经 `resolve_actor` 解析当前主体；直接调用产品当前数据库Interface。历史原key/原ETag恢复完全相同body且不增事实，同key改摘要409，新key陈旧ETag412。读撤权使get/list404，写撤权使ACK重放404，身份绑定或主体禁用使重放401。 |
| ACK去重与隔离 | 未读通知首次ACK与同key重放只有一份回执/审计/因果event；已阅通知用独立key和当前ETag可另建回执，审计/event仍各一次。同key再次重放不变；原始来源、run、幂等创建记录、账务/业务事实与另租户全部历史保持原样，另租户仍存在未读通知。 |
| 原回归保留 | 非法来源版本/状态/请求关联精确23514整事务回滚；正常0043延迟COMMIT及孤立活动COMMIT拒绝、事务内上下文恢复；重复正式迁移/角色不变、旧Migrator返回VersionMissing且关闭专用连接释放锁；池复用无租户上下文遗留。 |

配额状态是owner账务历史夹具，同一CREATE的不同维度有不同状态；没有经过完整worker/termination生命周期，不能证明guest启动或物理资源释放。LEGAL保护不能当作BACKUP/RESTORE保护。执行、launch permit、backups、backup_attempts及backup_resource_intents在该夹具中仍为空：没有满足冷备份的真实关闭证明和已认证配置，不制造VM或存储证明填满这些表。

runner现在要求同一个实际通过的ignored用例同时给出两项完成marker，并将两项写入 `record.json`：

- `AUTO_UPGRADE_V41_CURRENT_FACTS_OLD_MIGRATOR_REFUSAL_VERIFIED`
- `AUTO_UPGRADE_NONEMPTY_HISTORY_SCHEMA42_ACK_CURRENT_REPLAY_REVOKE_VERIFIED`

完整34组本地入口继承相同约束，CI已有all-target构建和review入口自动覆盖；本轮实际运行14组review，未执行完整34组或远端CI。

## 实际验证

| 验收 | 结果 |
| --- | --- |
| 独立Docker TLS PostgreSQL | 14组64项实际执行，0失败、0ignored；扩展升级用例1/1，1.88秒。 |
| 迁移与输入绑定 | 每组最终42条迁移1..37+39..43，success/SHA384逐项匹配、无38；819文件公开源码、普通二进制及真实生成SDK运行前后不变。普通验收结束后再次核对相同摘要。 |
| 普通Rust全部目标 | 56个程序，427通过、0失败、246环境专项明确ignored；ignored不计入实际数据库通过。 |
| Lint与格式 | 锁文件构建、all-target Clippy `-D warnings` 和fmt检查通过。 |
| SDK与runner | 正常SDK构建、Python语法及14/34矩阵/双marker静态核对通过；没有改SDK或控制台行为，不重计旧浏览器结果。 |
| 清理 | 本次自有临时容器和进程确认清理，无输入漂移或清理错误；没有选择或修改既有数据库。 |

本轮第一次实际数据库验收通过，没有追加失败重试，也未放宽生产超时、资源限额、身份或约束。

## 证据与缓存

证据位于 `.local/progress-20261011-upgrade-state/`，保存于Cargo缓存之外：

- `pg-v1/record.json` SHA256：`9a84950461866ce10b5bbaa010d73fe484535a3c971330d4e6bad384ed7a077d`。
- `pg-v1/source.json`文件序列化SHA256：`fcb0a176c627b4c620d558ed7679cdbbd70d74d1737c16a9e387aa02a4aee67f`；runner规范化source绑定SHA256：`828ae132dad8c466e3745707c89e9854b5892d9224662dd7e2cbaabf0919ecec`。两种序列化摘要分别标注，不混用。
- `artifacts-v1.jsonl`、`rust-tests-final.log`、`clippy-final.log`、`fmt-final.log`、`sdk-build.log`、各PG日志、`pg-summary.json`及 `final-validation-record.json`保存实际结果和摘要；交付记录另比较验证之后仅Markdown说明变化。私有TLS密钥不作为公开交付物。

复用当前仓库 `target/review-low-debug`，普通Rust环境为 `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`；未复制target或创建隔离缓存。验证结束df可用234.19GiB，缓存3.68GiB，仍低于20GiB缓存/50GiB空闲阈值。缓存保留供同工具链后续验收；本轮没有回收缓存，不宣称释放空间。

## 后续退出条件

G4-06保持开发中。继续补齐UNKNOWN→FAILED双状态、非空执行/备份及真实完整生命周期历史；再用有来源的旧/新已签名发行包验证API、worker、automation混跑、升级恢复、应用回退和滚动排空。旧SQLx Migrator拒绝未知版本只证明迁移器行为，不能推导旧进程拒绝启动或回退安全；当前runtime仍允许自身所需checksum完整的成功较新schema。

生产PKI/身份/存储轮换、实云Kata/CSI/Cilium、灾备、HA/容量和同源Linux八ELF/四OCI安全签名发布仍需独立证据。整产品未完成生产验收，本轮未Git提交/推送或云端上线。正常生产升级步骤见[数据库升级说明](../docs/database-upgrade.md)，前一轮证据保留在[基础升级记录](database-upgrade-delivery-20261011.md)。
