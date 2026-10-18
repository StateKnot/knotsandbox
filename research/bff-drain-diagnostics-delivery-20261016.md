# BFF 测试库关闭超时诊断：交付记录（2026-10-16—18）

当前结论：已补齐测试夹具的关闭诊断，并在 Mac 与 Linux arm64 的独立 TLS PostgreSQL 各完成 5 项 BFF 验收。公开基线 `4e517ab061ab7d4a796731c00e3d70426a3380fb` 的 [CI run 38871811699](https://github.com/StateKnot/knotsandbox/actions/runs/38871811699) 仍是失败状态；原 BFF 超时根因仍为 UNKNOWN。Mac 共享 PostgreSQL 整轮在备份账本组失败，尚未到达 BFF；后续同一 Linux VM 时钟域的末五组 20 项通过。这些限定结果不能将本片写成 CI 修复完成。

## 已确认的问题与实现

原 CI 共 5 个 job、73 个 step，4 个 job 成功；`verify` 首个失败为第 22 步 PostgreSQL 集成，`browser_session_idle_abandoned_refresh_and_retention_cleanup` 在业务断言完成后的 `Fixture::close` 返回 `fixture backend drain deadline exceeded`。第 14 步独立隔离 BFF 及之前的原生镜像门已通过；后续三个上传步骤因前置验收未执行而缺产物，不能通过放宽上传条件掩盖。

原超时同时覆盖 admin 连接取得、连接检查和查询完成，却没有保存正在执行的阶段与最后一次可信观察，无法区分“尚未完成连接观察”与“已观察到连接尾部仍存在”。本片只修改 `src/bff_tests.rs` 和 `scripts/test-review-fixes.py`：超时保留原错误链，追加固定阶段、完成轮次、单调时间预算及最后一次 peers/owner 样本的独立年龄。未完成的观察为 UNKNOWN；成功查询的 peers 先保存，再查询 owner，避免后一个查询超时抹掉已知事实。

不记录角色、application_name、PID、SQL、路径、URI、凭据或远端原始错误。正常轮询不增加日志、查询或任务。`Fixture::close` 原 2 秒总预算、peers→owner 顺序、100ms 睡眠、精确角色/标签与 idle/no transaction/wait 谓词、零连接后普通 DROP 及 `55006` 拒绝保持；未调用 `pg_terminate_backend` 或 `DROP ... FORCE`。普通客户端关闭仍使用驱动既有协议，不把本机连接句柄关闭等同于服务端 backend 已消失。

## 真实故障回归

新增一个必跑 ignored PostgreSQL 用例，从现有 `Fixture::close` Interface 验证两个情形：

| 情形 | 实际注入与独立核对 | 必须得到的结果 |
| --- | --- | --- |
| 观察未完成 | 占满原 admin 池的两个许可；独立 admin 确认子库存在且真实 peers 为零 | 原 2 秒超时；阶段为 PEERS_QUERY、完成轮次为零、peers/owner 为 UNKNOWN。释放本测试连接后普通 DROP，并独立确认库不存在 |
| 已观察到空闲尾连接 | 在池外保留精确 owner/标签、idle 且无事务的连接 | 原 2 秒拒绝；库与该连接仍可用，最后样本为 1 条 owner idle、无 runtime/unknown peer，owner/样本年龄/睡眠预算可读。明确释放后，单独的有界清理阶段确认真实零 peers、普通 DROP 和库缺席 |

第二行的手工清理使用新的独立 2 秒预算，只在被测关闭已经失败、测试持有的连接已显式释放后开始；查询与睡眠共用该清理预算。它不延长被测关闭期限，也不把延后清理当成首次关闭成功。默认 runner 的 BFF 精确计数由 4 改为 5，缺项或失败不能通过。

## 验收与保留失败

证据均位于本机 `.local/ci-repair-20261016/`，目录不进入公开仓库；本记录只引用既有回执，不把未执行的步骤写成通过。

| 证据 | 结果与范围 |
| --- | --- |
| `red-record.json`、`red-diagnostic/bff_pg.log` | 原关闭实现加新增回归真实 RED：独立确认零 peers、普通 DROP 与库缺席后，因缺少阶段诊断而失败。只证明诊断缺口 |
| `host-final-bff/record.json`、`host-final-bff/bff_pg.log` | 最终 Mac TLS PG，5 通过/0 失败/0 ignored；正常 47 条迁移、源码/制品/SDK 稳定与自有清理确认 |
| `linux-final/record.json`、`linux-final/tls-final/bff.log` | 最终 Linux arm64 同一冻结源码/普通 Cargo ELF，5 通过/0 失败/0 ignored；TLS、原期限、源码/ELF 稳定及自有清理确认。不是 Linux amd64 CI 的等价复现 |
| `ordinary-tests-final-v2.log` | 最终普通 Rust 65 个程序、520 通过/0 失败/292 环境 ignored；ignored 不计作环境验收 |
| `clippy-host-final-v2.log`、`linux-build-v2/clippy.log`、`fmt-final-v2.log` | Mac/Linux 严格 all-target Clippy 与格式检查通过 |
| `shared-final-v2-attempt-summary.json`、`shared-final-v2/record.json` | 计划 31 组/190 项，实际 23 组通过/149 项通过、备份账本 1 组/4 项失败、7 组/37 项未执行；BFF 未执行。已完成组的正常 47 迁移 checksum、自有清理和稳定性守卫通过，不构成全矩阵通过 |

共享批次的四项备份失败为 `LAUNCH_RESOURCE_OBSERVATION_STALE`（409）。随后最小 fresh 备份四例在更早阶段出现 `nodeguard registration or challenge has expired`，当时测得 PostgreSQL 比 host 慢约 1379 秒；后续全新纯读时钟 probe 又在未调钟情况下对齐，偏差范围约 -6.37ms 至 +55.94ms。原共享 409 发生时没有配对时钟读数，不能把原 409 归因为已证实的时钟偏差；这些失败均保留，不能相互替代。

Linux 同一最终 ELF、同一 VM 时钟与共享 TLS PG 的末五组按原 CI 顺序一次通过：backup 4、pipeline 8、profile 2、metrics 1、BFF 5，共 20 项。新空库由原 `test_support_db::Fixture` 正常迁移，随后按普通 migrator 原顺序以 owner 应用组件授权 SQL；未手工写迁移账本。每组正常 47 条 checksum、实际用例集合、源码/ELF 不变与全部 7 个自有容器清理确认。回执为 `linux-shared-tail/record.json`，原始日志分别位于该目录的五组 `tests.log`。该次记录再次出现墙钟变化：pipeline 后至 BFF 前，VM/PG 比 Mac 慢约 891 秒；BFF 后又对齐。BFF 容器自身实时时钟前后相差约 910.302 秒，而 host 单调耗时仅 19.143 秒，不能声称全程墙钟稳定或据此作性能结论。应用与 PG 均在同一 VM 执行，验收程序未调钟，也未认定系统调钟主体；这证明该限定序列通过，不能倒推先前 409 根因、改写 31 组整轮失败，或声称原 Linux amd64 CI 超时已复现/修复。

原 BFF 在未改代码下的 Mac TLS 与 Linux arm64 TLS 2CPU/TLS 0.5CPU/plaintext 2CPU 控制均通过，未复现原 CI；它们只是定位控制。首个 GREEN 中新测试解析完整 anyhow 错误链时把分隔冒号当作数字，已只改为解析固定诊断 context。另一次业务断言通过但并发 Cargo 改变 `sandboxd` 摘要，整体回执仍判失败；最终采用完成构建后再冻结制品、串行验收。默认本机受限调用的 109 个 localhost bind 权限失败也保留，未改产品策略，具备既有本机验证权限的相同测试重新通过。相关记录为 `green-parser-failure-record.json`、`host-validation-environment-failure-record.json` 和原日志。

独立审查：Standards 0 项违反/0 项有实质影响的 smell；Spec 累计发现 1 项新增手工清理竞态，已通过独立有界观察修正，静态剩余 0 项。最终文档及实际回执另由两轴独立复核，不以静态审查代替验收。

## 源码绑定与下一门

冻结代码见 `code-manifest-v2.json`：`src/bff_tests.rs` SHA-256 为 `1125ae16dc6d097eeea9132c6cc4199da41bcdf873c5bd644822d45ed8f95ea8`；`scripts/test-review-fixes.py` 为 `1b4901a9eefc4e5e2dbcab7dab9bb51fa769db9bee46add98a9af8aa02af113d`。原生产 BFF、数据库模块、驱动、锁文件及 47 条正常迁移未改。本机缓存保留且分别小于 20GiB；磁盘与仅本任务自有容器清理记录见 `cleanup/record.json`，不以目录累计大小声称释放量。

本批开始核对的公开 main 为 `4e517ab`，远端完整 1116 文件树、Git mode、checkout 字节一致。本次只同步经审查并验收的文件，保留主工作树及四项历史文档差异。本记录在提交前形成，不自证新提交或 CI 成功；发布后的精确 head、完整树与 CI 结果须由独立回执核对，不沿用旧提交成功，不强推或自动创建 release。

优先闭合当前失败与观测，再推进 P1 的受限准备执行者、真实硬限、pull 选择和 lease/content/snapshot/GC 保护闭包。pre-pull 保持关闭；GPU、云、Kata、CSI、冷暖性能收益和生产上线认证均未完成。
