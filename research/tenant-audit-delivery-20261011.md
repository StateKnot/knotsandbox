# 租户账户审计与备份能力交付 — 2026-10-11

本轮按开发表 G2-10/G3-09/G3-10 完成独立租户账户审计；同时修复 G3-08 的备份页面能力约束。工作保留在当前工作区，未提交或推送Git，未连接云端。

## 已完成的实现

- 新增 `GET /v1/tenant-audit-records`，OpenAPI、生成SDK类型及控制台一致；独立 `tenant_audit:read` 租户权限，项目授权不能跨入该范围。
- 查询只返回当前租户 `project_id IS NULL` 的固定元数据，不返回details。沿用真实审计记录与现有索引，无迁移、无新SQL权限或特权函数。
- 查询前后在新语句快照中核验身份、成员、当前授权和最后数据库时间；签名游标绑定租户、主体、动作和页大小。
- 引导支持显式新权限，重复引导严格比较旧集合；现有授权不自动提升。现有租户级通配授权仍遵循原语义。
- 账户页无需项目即可显式查询；切换页大小／刷新／拒绝读取清空旧结果，迟到响应不能覆盖新页。
- 备份面板仅接收当前项目明确为true的能力：关闭、缺失、畸形值不查询／提交，开启时仍使用原权限与404语义。
- 必跑review runner加入新tenant_audit suite，并校验实际生成SDK制品运行前后摘要，防止只绑定源码却调用漂移制品。

使用与上线授权步骤见[模块说明](../docs/tenant-audit.md)。

## 本地实际验收

| Docker TLS PostgreSQL 组 | 实际用例数 | 结果 |
| --- | ---: | --- |
| service_clients | 7 | PASS |
| tenant_audit | 5 | PASS |
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

合计13组63项，所有用例实际执行、0失败、0ignored。正常迁移42条（1..37+39..43）、逐条SHA384匹配，没有0038；使用独立角色登录，不使用owner运行被测API。新账户审计5项包括正常登记／变更生成的记录、脱敏、跨项目／租户隔离、全部当前授权、实际双向账户游标错绑、四种真实表锁等待和签名JWT/JWKS→真实Node SDK→Rust TCP接口。

`pg-final/record.json` SHA256：`f75385832a2da5a2500cd76c4fb04fcce17eb67df6595411226b2457ee02c914`。
验收公开源码索引 SHA256：`c3ee9d1c9360f8bf4d3f6623a70a3acc011eaba6720a55e0e9a79ec7d064818e`。
source、被测二进制和实际SDK制品未漂移，均由最终记录确认；本次自有临时容器与测试进程清理确认。验收之后只补文档，交付记录单独列出这些变化。

| 其他检查 | 结果／边界 |
| --- | --- |
| 普通Rust全部目标 | 55个测试程序，424通过／0失败／245环境专项明确ignored；ignored不计实际PG通过 |
| 严格lint | all-target Clippy `-D warnings`、fmt通过 |
| SDK | 69通过，含新增2条客户端合同；与PG组真实SDK用例分别记录 |
| 控制台单元／构建／格式 | 66通过，tsc+Vite生产构建及完整Prettier检查通过 |
| OpenAPI合同 | 12通过，要求显式null项目且拒绝details扩展 |
| 编译Chrome合同 | 全矩阵首跑23通过；最终新增专项9通过（账户5+备份4，重叠不累计），含新增迟到响应否例 |
| Python runner语法／Git whitespace | 通过 |

证据目录：`.local/progress-20261011-tenant-audit/`，日志与汇总保存在Cargo缓存外。普通SDK首跑受本机沙箱回环监听EPERM阻断，允许本机测试后69项通过；没有放宽产品HTTPS／身份／数据库权限。初次控制台编译发现依赖Readable类型剔除pure-null字段，现先核验实际JSON项目值为null，再恢复typed投影；失败不能通过类型强转掩盖。

备份错误的原始red记录在 `.local/backup-capability-20261011/red/`：能力false时实际发送了1次workspace GET，导致预期零请求断言失败。修复后同路径与缺失／畸形能力的4项合同通过。未扩大权限或改变隐藏404，也未宣称真实备份服务已启用。

独立只读审查未发现本轮可定位越权问题；指出的实际账户游标和迟到响应测试缺口均已补齐并运行。SYSTEM用例只证明正常未注册SYSTEM被拒；可信 `authorization=None` 的内部调用不宣称按kind绝对拒绝owner手工注册的SYSTEM。正常HTTP身份解析仍限制USER/SERVICE。

本轮复用 `target/review-low-debug`（约3.7GiB），Rust普通验收使用 `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`。没有复制target或创建独立编译缓存，没有删除数据库卷；本次缓存保留供后续同工具链验收复用。实际df始终高于50GiB，后续仍按年龄／容量管理保留。

## 下一开发项与退出条件

G4-06 的历史0041→0042→0043数据升级仍未实施。下一项应在独立空库安装≤41正常版本，种两租户真实历史策略／委派／FAILED和UNKNOWN运行／来源事件及审计／定时器，再正常迁移到当前版本，逐字段验证事实、epoch和原checksum不变。0042不回填历史通知；升级后新合法异常才派生，旧无status事件保持旧语义，错误版本／status／request_id整事务回滚。重复迁移无变化，旧≤41 migrator遇较新版本明确拒绝，不删除新账本或设置ignore_missing绕过。

该测试需要历史模式库，不能先全迁移再删除42/43。可复用当前本地Unix Docker/TLS/角色/清理工具，但现有旧migrations test的固定管理员、无query且关闭TLS连接要求与当前runner不同，需新专用接口测试或明确改造。没有真实旧发布二进制时只认证schema升级／旧事件格式／旧migration拒绝，不将其标记为完整N/N−1 API和worker兼容。

本轮Chrome属于HTTP合同夹具，新账户审计还没有单独的Keycloak/BFF全链验收。审计归档、tenant授权自助管理、人类账户、实云Kata/CSI/Cilium、生产PKI、HA／容量和统一Linux签名发布仍待完成。整产品保持未完成生产验收，既有过期的发布安全审阅不因本轮局部通过而改变。
