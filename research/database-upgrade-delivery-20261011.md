# 历史数据库升级交付 — 2026-10-11

本轮完成开发表 G4-06 的历史schema升级子项：新增实际升级测试、固定历史权限夹具、必跑runner与可执行升级说明。正式迁移和运行代码保持原有实现，工作保留在当前工作区。

## 已实现的升级验收

`tests/automation_upgrade.rs` 在runner新建的空库安装正式SQL源码前缀 `1..37,39..41`，先执行从真实 HEAD `d5f7a70afadde40e30ca01a2e9871a5312153d57` 冻结的旧ACL，然后种历史数据。不会先安装最新版再删除迁移行，也不会使用管理员运行被测writer。该schema前缀不是一个已经发布的“v41产品版本”。

- 两个租户、四个项目；两个实例与工作区、两个排队DOWNLOAD文件意图；每租户FAILED及OUTCOME_UNKNOWN历史run各一个，关联策略、委派、来源事件和审计。
- 29类租户表逐字段 `to_jsonb` 比较，另保留全局principal／identity、平台配置及原迁移账本每列；既有RLS／policy、触发器启用和延迟属性、函数安全属性精确比较。执行、配额、hold、备份和回执集合在本夹具中为空，只有空集合不被误造的证据。
- 正常当前迁移后，历史业务和安全事实不变，不回填历史异常通知。旧API与coordinator分别使用独立LOGIN、原有权限真实插入合法异常来源；没有新通知表直接权限仍由正常触发器派生。
- 当前角色原样安装后，正常数据库Interface的读取、项目和租户隔离、首个UNKNOWN通知去重、旧无status事件正常提交通过。运行连接保持生产10秒语句／3秒锁等待／15秒闲置事务期限。
- 三种非法来源分别错绑version／status／request_id，均精确返回23514；同事务run变更、来源事件、事件序号、审计与通知全部回滚。
- 0043通过实际正常延迟COMMIT正例和孤立FILE_WRITE的COMMIT拒绝；另在真实事务内执行约束后检查调用方租户上下文恢复，固定search_path和无公共EXECUTE继续保持。
- 重放当前迁移和全部正常角色脚本不改变已提交事实及完整迁移账本。旧prefix Migrator返回VersionMissing，关闭专用物理连接释放其迁移锁，再核对全部事实未改变；不会设置ignore_missing绕过拒绝。

runner只有精确`automation_upgrade`用例跳过预迁移；其余组仍由正常`sandboxd --role migrate`准备。它先确认新库0个用户relation，固定必需发现一个ignored用例、实际执行一个PASS、完整完成marker和最终42项SHA384；没有选择已有库或通用跳过校验的参数。原有CI的all-target构建和review入口自动覆盖新增用例。完整本地验收入口相应由33组增为34组，本轮实际运行的是14组review矩阵。

## 实际验证结果

| Docker TLS PostgreSQL组 | 实际用例数 | 结果 |
| --- | ---: | --- |
| service_clients | 7 | PASS |
| tenant_audit | 5 | PASS |
| automation_upgrade | 1 | PASS，1.93秒 |
| timers | 8 | PASS |
| timer_worker | 4 | PASS |
| worker_process | 1 | PASS |
| output_identity | 1 | PASS |
| action_scope | 1 | PASS |
| bootstrap_prerequisite | 1 | PASS |
| bootstrap | 4 | PASS |
| grants | 4 | PASS |
| capabilities | 1 | PASS |
| executions | 14 | PASS |
| file_transfers | 12 | PASS |

合计14组64项实际执行、0失败、0ignored。每组最终账本42条（1..37+39..43），成功标志与源码SHA384逐项一致，0038永久保留。本次自有临时容器、进程确认清理，公开源码、普通二进制及实际生成SDK摘要前后未漂移。

| 最终源码检查 | 结果 |
| --- | --- |
| 普通Rust全部目标 | 56个程序，427通过／0失败／246环境专项明确ignored；ignored不算实际PG通过 |
| 新普通保护用例 | 3项通过：字面loopback／TLS目标保护、owner与runtime的数据库／端口／CA匹配、冻结ACL字节SHA校验 |
| 严格lint／格式 | all-target Clippy `-D warnings`及fmt通过 |
| Python／runner | 两入口语法、14组review／34组完整矩阵及新marker核对通过 |
| SDK | 正常构建，实际制品与PG验收绑定；本轮没有改SDK或控制台行为，不重计以前的浏览器验收 |
| 发布与环境 | 本地Docker TLS结果；未执行远端CI或实云发布 |

证据保存在 `.local/progress-20261011-upgrade/`，不位于Cargo缓存内：

- `pg-v2/record.json` SHA256：`b86d1c0991d87c77311375654616fc82fc8b42d62143daec53565a12f4411e89`。
- 816文件公开源码索引 `pg-v2/source.json` SHA256：`0c67f9fbee2161d3011ecddb661573cf4ffda49e22c11eeac0bfbd45256b7e07`；runner内部规范化source绑定摘要为`956ba06d78b4861a6e82c0b07be19bc7d694aac96f56cb67749bfdd1f9f67db0`，两种序列化摘要不混用。
- `artifacts-v2.jsonl`、普通测试、Clippy／fmt、SDK构建及数据库驱动日志与`final-validation-record.json`分别保存；后续交付记录单列仅文档变化。

首轮`pg-v1`的升级用例被真实`projects_tenant_id_name_key`约束拒绝：夹具的同租户两个项目误用同名。只将项目名称改为参数绑定的唯一名称，未放宽产品约束；该失败日志、源码和清理记录保留。最终新库完整14组通过，首轮通过的其他组不与最终数量重复累计。

复用`target/review-low-debug`，本次约3.67GiB；普通Rust使用`CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`，没有复制target、创建独立缓存或删除数据库卷。验证结束实际df可用235.94GiB。缓存保留供同仓库／工具链验收复用，仍按20GiB容量与50GiB空闲阈值管理；本轮没有回收缓存，不宣称释放空间。

## G4-06仍需完成的范围

旧Migrator拒绝未知版本只证明迁移器行为；当前runtime校验明确允许完整成功的较新schema，不据此推导旧二进制拒绝启动或安全回退。本轮未运行真实旧发行包、未验UNKNOWN→FAILED双状态、升级后ACK或非空配额／备份／回执历史。

下一步补齐这些历史数据和提交合同，再用具备来源的真实旧／新发行包验证API、worker与automation混跑、原幂等键恢复、撤权和滚动排空。生产PKI／身份／持久存储轮换、实云Kata/CSI/Cilium、灾备、HA／容量与同源Linux八ELF／四OCI签名发布仍需独立证据。G4-06保持开发中，整产品仍未完成生产验收。

复现命令、正常生产迁移顺序及回退限制见[升级说明](../docs/database-upgrade.md)。数据库扩展和已提交事实保留；应用只能回到已经证明兼容的发行包，不能下迁移、删成功账本或执行旧ACL脚本替代回退。
