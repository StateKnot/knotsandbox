# 升级后同一运行双状态通知交付 — 2026-10-11

本轮继续推进G4-06，在既有41→42→43升级测试中补齐同一个run的OUTCOME_UNKNOWN→FAILED持久状态与通知合同。保留非空账务/回执/LEGAL保护、42已阅及当前ACK历史验收，新增合法来源转换、跨目标回执、独立已阅和重复来源回滚。没有修改生产Rust实现、正式迁移或角色权限，没有Git提交/推送或云端上线。

## 完成的合同

`tests/automation_upgrade/ack.rs::verify_dual_status_progression` 通过实际 `sandbox_automation` LOGIN、强制RLS及生产连接期限写入来源；当前通知Interface使用真实RS256 JWT/JWKS与 `resolve_actor`。这是合法持久状态/source-writer测试，没有运行完整 `AutomationCoordinator::run_claim`，不证明真实远端派发已被协调器恢复或policy已经EXHAUSTED。

| 场景 | 实际验证 |
| --- | --- |
| 合法结果转换 | UNKNOWN run v5在coordinator事务中变FAILED v6，version由正式guard生成；completed_at合法，原意图/dispatch/资源链接不变。同事务一条转换审计及严格匹配run/version/request的源事件。除目标run允许字段和目标claim.eligible_at外，全部业务事实不变；正常queue将其路由到委派到期。 |
| 两条独立通知 | 同一run恰有UNKNOWN与FAILED两条通知。原UNKNOWN首来源v4、通知v2及已阅主体/时间完整保留；FAILED独立通知v1、未读，没有继承旧ACK。两条源事件始终完整不变。 |
| 终态重复来源 | FAILED不可通过UPDATE制造新版本。同版本/类型的新源事件被基础domain_events唯一约束精确23505拒绝；先插入的正常审计、事件头/位置、通知、回执和全部业务事实整事务回滚。原FAILED来源和转换审计各一条。既有非终态UNKNOWN v4/v5的合法来源去重继续通过。 |
| 分页与隔离 | limit=1遍历实际项目3条通知，固定原cutoff，无漏读/重复，其中目标run恰两条；同租户兄弟项目为空。签名游标跨项目/租户400 INVALID_CURSOR；当前签名另一租户读及ACK404，其32类历史及通知/事件全量保持。 |
| 原键与目标隔离 | run后来FAILED后，原UNKNOWN ID/key/ETag1仍恢复相同有效回执。FAILED首次ACK复用完全相同文本key但不同target，产生自己的回执；两个target分别以原ETag1重放返回各自body，互不串用、不增事实。 |
| ACK与撤权 | FAILED首次ACK后通知v2，receipt、请求关联审计和run关联因果事件各一次；不改变完成run、claim、旧UNKNOWN、预算/配额/操作/保护等业务事实。当前写grant禁用后旧FAILED回执重放404，拒绝不修改历史；恢复后权限与历史符合当前合同。 |
| 升级回归保留 | 原非法来源整事务回滚/0043正常COMMIT及调用方上下文恢复在转换前执行，随后重新冻结稳定事实。重复正式迁移/角色和旧Migrator拒绝均保持新旧事实与完整账本，池复用无租户上下文遗留。 |

runner现在强制同一个实际通过的历史升级用例同时输出并记录三个marker：

- `AUTO_UPGRADE_V41_CURRENT_FACTS_OLD_MIGRATOR_REFUSAL_VERIFIED`
- `AUTO_UPGRADE_NONEMPTY_HISTORY_SCHEMA42_ACK_CURRENT_REPLAY_REVOKE_VERIFIED`
- `AUTO_UPGRADE_UNKNOWN_FAILED_DISTINCT_SOURCES_ACK_REPLAY_ISOLATION_VERIFIED`

14组review及34组完整本地入口共享这项约束；已有CI all-target构建及review入口覆盖。本轮实际运行14组，34组只做配置静态核对，未执行远端CI。新合同扩展原用例，独立测试数保持64，没有把内部断言虚计为新增用例。

## 实际结果和首轮失败

最终候选820文件下，14组64项实际Docker TLS PostgreSQL/HTTP/worker回归通过，0失败、0ignored；升级用例1/1，1.70秒。每组最终正式迁移42条1..37+39..43，success及SHA384逐项相同、无38。公开源码、普通二进制和真实生成SDK运行前后无漂移，普通检查结束再次核对相同摘要；本次自有容器/进程确认清理。

普通Rust全部目标56个程序、427通过/0失败/246环境专项明确ignored，严格all-target Clippy `-D warnings`、fmt、正常SDK构建及Python语法/矩阵/marker检查通过。ignored不计入数据库通过，本轮不改SDK/控制台行为，不重计以前的浏览器验收。

首轮`pg-v1`在新用例失败：测试错误地期望终态FAILED同版本重复事件正常提交，实际 `domain_events_tenant_id_aggregate_id_aggregate_version_even_key` 正确拒绝。仅修正测试为精确23505/约束名、完整事务回滚和一个已提交FAILED来源；未修改生产唯一约束、终态guard、角色、超时或资源限额。首轮源码、二进制/SDK绑定、日志与清理记录保留；最终在新的`pg-v2`完整重跑，首轮已通过的组不重复累计。

## 证据与本机空间

证据目录为 `.local/progress-20261011-upgrade-progression/`，位于Cargo缓存之外：

- `pg-v2/record.json` SHA256：`0d6a9a78df526e2041fbd059fdc8a78d6af832564a5ad43a965077a683884b4b`。
- `pg-v2/source.json`文件序列化SHA256：`d01b24a3ccb378ed7ba760755627174b767601bc25c9d57ada5c8d37dbce3ad6`；runner规范化source绑定SHA256：`3882b0e8e366f1f88d2a933479c6f634ec05e545af7f366faf2d070ba55fa979`。两种序列化摘要分别标注。
- `artifacts-v2.jsonl`、`rust-tests-final.log`、Clippy/fmt/SDK日志、`pg-summary.json`、`python-static-final.json`及`final-validation-record.json`保存实际结果；`pg-v1`与 `failure-v1.json`保留失败，交付记录单列验收后Markdown变化。私有TLS密钥不作为公开交付物。

复用 `target/review-low-debug`，缓存3.68GiB。普通Rust环境仍为 `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`，保留原断言/溢出检查，没有复制target、修改发布配置或清理其他数据。验证结束实际df可用234.17GiB，未触发50GiB空闲/20GiB缓存阈值；缓存保留供同仓库/工具链验收复用。本轮未回收缓存，不宣称释放空间。

## 下一项的落地前置

非空备份历史需单独准备，不能把本轮PENDING工作区的空集合算作通过。冷备份约束要求AVAILABLE工作区、精确关闭的同epoch启动许可、关闭/清理证明、无活动slot/操作，以及认证覆盖deadline的已启用配置。LEGAL保护不代替BACKUP保护。

已有协议夹具可复用正常STOP、mTLS nodeguard关闭与 `complete_termination`，再经正常profile注册、实时Kubernetes/TLS vault验证和激活，最后正常 `create_backup`。首次受理即可产生非空backup、CAPTURE/SEAL两attempt、SOURCE_SNAPSHOT intent、BACKUP hold、配额和typed回执，无须先跑完整Job流水线；这些宿主/Kubernetes/OSS观察仍是协议夹具，不能宣称实云VM或存储认证。

现有组合示例位于 `src/restore_raw_vendor_report_matched_tests.rs`，helper仅为lib内测试能力，连接前置会安装全部当前迁移并验证当前schema。后续需独立历史harness或有来源的旧源码seeder，保存许可/登记/关闭/清理/节点及backup_profiles/actions证明快照，不能把当前已验证连接伪装成41连接。HEAD正式源码前缀只到39，不是已签名41发行包。

G4-06保持开发中。非空备份/执行与完整生命周期、完整controller未知结果恢复、真实旧/新发行包N/N−1混跑和应用回退、滚动排空、实云身份/PKI/存储轮换、HA/容量及同源签名发布仍需独立验收。旧Migrator拒绝不证明应用回退安全；整产品未完成生产验收。复现和生产升级步骤见[数据库升级](../docs/database-upgrade.md)，前一轮记录见[非空历史与ACK](database-upgrade-state-delivery-20261011.md)。
