# 身份与生命周期必跑回归

对应开发表 G4-01（权限与攻击面）、G4-02（状态与生命周期故障）及 G4-06 的历史自动化 schema 升级子项。必跑矩阵现为24组；覆盖审查修复的实际调用链、BFF连接收尾和一个历史schema前缀升级用例，不能替代实云运行时、灾备、容量或完整发布认证。

## 本地运行

前置条件：仓库锁定的 Rust 工具链、可用的本地 Docker Unix socket、锁定 PostgreSQL 镜像、OpenSSL。先按 AGENTS.md 检查磁盘；构建目录复用当前仓库缓存，不复制已有 target。证据目录必须尚不存在。

```bash
df -h .
mkdir -p .local
npm --prefix sdk/typescript ci --ignore-scripts --no-fund --no-audit
npm --prefix sdk/typescript run build
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked --all-targets --no-run --message-format=json \
  > .local/review-artifacts.jsonl
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo build --locked --bin sandboxd --message-format=json \
  >> .local/review-artifacts.jsonl
python3 scripts/test-review-fixes.py \
  --artifacts .local/review-artifacts.jsonl \
  --evidence-dir .local/review-regressions
```

runner 只接受本地 Docker；允许显式设置本机 `DOCKER_HOST=unix:///绝对路径/docker.sock`，不接受远端 daemon。它新建带随机名称与所有权标签的容器，数据仅存内存盘，数据库端口只绑定 `127.0.0.1`。正常组使用独立当前迁移库及十个独立最小权限登录角色；bootstrap 先在自己的新库运行既有 database 初始化/RLS 测试，再在同库验证引导的重复性。

`bff_pg`精确执行5项BFF用例；仅此组获得同一临时TLS-PG容器的admin URI，用于创建各自随机子测试库。BFF业务始终使用普通runtime登录，其他接口组不接收admin权限。owner/runtime pool的唯一application_name在真实PG核对；关闭后最多2秒等待匹配角色/标签的空闲无事务尾连接，只有零连接才普通DROP。活动、外来、隐藏状态拒绝，不调用`pg_terminate_backend`或`DROP ... FORCE`。超时追加固定阶段、完成轮次、最后一次peers/owner观察与独立样本年龄，尚未观察保持UNKNOWN；阶段覆盖连接取得、检查与查询完成，不能仅凭PEERS_QUERY断言SQL执行阻塞。原2秒总预算、100ms轮询及安全谓词保持。

新增真实故障用例先占满两个admin许可，独立确认子库零peers但观察未完成；另用精确owner/标签的池外idle连接验证实际尾连接仍存在时原期限拒绝且连接可用。两种情形均在明确释放本测试连接、实际零peers后普通DROP，并由独立admin确认库消失。后者的手工清理另有2秒总预算，只在被测关闭已失败且持有连接已释放后启动，不能将其当成被测关闭成功或扩大原期限。详见[BFF诊断记录](../research/bff-drain-diagnostics-delivery-20261016.md)。

唯一例外是精确元组 `automation_upgrade / automation_upgrade / upgrade_from_v41_preserves_historical_automation_and_rejects_invalid_source_events`：runner 先确认本次新库用户关系数为零，不运行当前 `sandboxd` 预迁移，由被测用例安装真实迁移源码中版本 ≤41 的历史前缀，再升级到当前版本。相同名称、不同 target/filter/required 会失败；没有通用跳过迁移或选择已有库的选项。测试连接启用 `verify-full` 并验证专用测试 CA。它不会读取或修改已有数据库，也不会通过超级用户连接运行被测 API/worker；历史 schema 由无 `CREATEDB` 权限的 owner 登录安装。

## 覆盖与通过条件

| 验收组 | 真实 Interface / 条件 | 关键断言 |
| --- | --- | --- |
| fresh_database_setup | 本次自有空库，由共享initializer直接安装正常迁移与角色，取消runner预迁移 | 1项；空库初始化、正常schema与RLS检查不能被sandboxd预迁移掩盖 |
| resource_accounting | 正常TLS PG与精确普通runtime凭据 | 9项；逐次launch请求与PENDING/ALLOCATED/RELEASED事实、不可变归属、真实COMMIT回滚、跨tenant上下文与原launch释放证据 |
| resource_accounting_http | 正常TLS PG、签名JWT/HTTP及实际Node SDK | 3项；十进制数量/分页/撤权、真实锁后复查，关闭trigger/同名替换/列写权漂移拒绝 |
| pod_observation | 正常TLS PG、普通termination登录与认证nodeguard | 8项；原子ACK与观察、同内容重放/冲突拒绝、真实COMMIT ACK丢失、过期旧ACK及最小权限/schema漂移 |
| pod_observation_http | 正常TLS PG、签名资源分页及真实事务顺序 | 1项；第一页固定“无观察”，并发先INSERT后COMMIT不能改变既有分页证据，读取后重查撤权 |
| db_cancellation | 实际TLS PostgreSQL、正式runtime池与取消中的begin | 1项；取消后归还连接处于idle/autocommit安全状态，要求DB_BEGIN_CANCEL_RUNTIME_TLS_POOL_CLEAN_VERIFIED |
| bff_pg | 独立TLS PG、实际owner/runtime标签及既有BFF HTTP/会话 | 5项精确用例；登录/CSRF/刷新/撤权/流关闭、真实锁到期、保留清理及普通删除；新增观察未完成与已观察idle尾连接的区分，安全反例保留active/xact/foreign拒绝 |
| service_clients | 正常 PostgreSQL 服务身份管理与授权 | 相同 issuer/sub 的错误 client 被拒；owner CAS 轮换后旧持久委派不能复活 |
| tenant_audit | 独立租户审计、签名JWT/JWKS及真实Node SDK | NULL-project脱敏投影、项目和租户隔离、双向动作游标隔离；真实锁等待期间撤权／身份禁用／token和grant到期拒绝返回 |
| automation_upgrade | 本次自有空库，真实 ≤41 schema 前缀、冻结历史 ACL，按41→42→43正常迁移；当前JWT/JWKS与身份映射 | 非空账务/回执/LEGAL及42已阅保留；同run UNKNOWN→FAILED独立来源和已阅状态、同文本key跨目标原回执恢复；终态重复源23505整事务回滚、分页/游标/撤权/租户隔离；旧writer及旧Migrator合同保留 |
| timers | 正常数据库到期扫描与停止受理 | 前100项受阻仍扫描后续到期项；副本最多受理一条 STOP；真实到期时间不变 |
| timer_worker | 实际 `Worker.run`，持有100个 workspace 行锁 | 后续实例在原15秒期限内受理 STOP；取消后有界 join / pool close；受阻实例未被改写 |
| worker_process | 独立 `sandboxd --role worker` 进程，运行后撤销 SQL 权限或持有表锁 | 永久故障非零退出并确认物理数据库连接缺席；锁超时退避后同进程恢复；SIGTERM 正常收尾 |
| worker_dispatch | 正式0044迁移、TLS PG与实际 Worker.run | hint只触发权威领取；缺提示/重连/到期恢复及池预算不改变 |
| worker_continuation | 实际 Worker.run、TLS PG与自有Kubernetes transport；6项用例 | 同租约三次UID/阶段/事件提交，可信Ready才完成；未Ready等待5秒；撤权/失租约/政策/epoch拒绝下一资源；单25秒预算/heartbeat；COMMIT前回滚及真实双端TLS已提交ACK丢失分别验收 |
| output_identity | 真实 HTTP / 签名 JWT / 延迟对象读取 | 读取期间仅禁用身份映射，或原 JWT 到期，均不能返回输出内容 |
| output_startup | 真实PG锁等待、生产启动schema预检与签名JWT/HTTP | 1项；短期token在启动预检完成后签发；原锁等待预算、token期限及I/O后过期拒绝保持 |
| action_scope | 正常 HTTP 路由、细分 scope 与本地 grant | 当前令牌动作上限不能被写入、输出流或自动化持久委派放大；通用 profile 兼容合同另保留 |
| capabilities | 正常 PostgreSQL / 签名 JWT / HTTP 能力查询 | 未挂载自动化时明确返回 `automation: null`；项目/租户隔离及实时撤权继续生效；能力查询不授变更权限 |
| bootstrap_prerequisite | 既有 database 初始化与 RLS 集成，在新建 bootstrap 专用库运行 | 正常初始化集群配置；强制 RLS 隔离和事务上下文清理通过，才允许继续引导回归 |
| bootstrap / grants / executions / file_transfers | 受本次共享授权改动影响的既有 PostgreSQL / HTTP 集成 | 正常引导、撤权/版本/幂等、执行账本与文件传输合同继续通过；不是只跑新增测试 |

runner从普通Cargo JSON定位本次可执行文件，拒绝缺失、多个候选、符号链接和不一致target布局。必需测试必须实际发现；精确匹配通过数与完成标志，零项测试不算成功。历史升级组必须且只能执行一个ignored用例，同时输出 `AUTO_UPGRADE_V41_CURRENT_FACTS_OLD_MIGRATOR_REFUSAL_VERIFIED`、`AUTO_UPGRADE_NONEMPTY_HISTORY_SCHEMA42_ACK_CURRENT_REPLAY_REVOKE_VERIFIED` 和 `AUTO_UPGRADE_UNKNOWN_FAILED_DISTINCT_SOURCES_ACK_REPLAY_ISOLATION_VERIFIED`；缺失任一marker、异常用例数或失败状态均不能通过。每组测试后核对正式迁移账本版本与源码SHA384；当前要求47条1..37加39..48，0038永久保留；本轮未新增迁移。

升级组的 `record.json` 记录 `schema_preparation.mode=TEST_INSTALLS_V41_THEN_CURRENT`、`pre_run_user_relation_count=0` 和三个完成marker。它验证真实schema前缀、42 owner已阅历史及当前独立LOGIN合法来源转换，未使用已签名旧发行包或运行完整controller未知结果恢复。配额状态是合法账务夹具，LEGAL保护不是备份保护；本轮不覆盖非空备份及真实worker资源释放。旧Migrator的 `VersionMissing` 拒绝不是旧API/worker二进制拒绝启动，也不是完整回退验收；当前runtime迁移检查允许自身所需checksum完整的成功较新schema。详细语义和生产升级步骤见[数据库升级](database-upgrade.md)。

运行前后绑定全部公开源码的字节与模式、被测二进制及实际生成SDK制品摘要；SDK不存在、含符号链接或运行期间漂移均失败。任一漂移、测试失败、遗留子进程或未确认容器清理均失败。清理仅针对本次拥有的进程组和名称/标签/ID一致的容器。原始测试日志、源码摘要和 `record.json` 保存在构建缓存之外；测试 CA 私钥不作为公开交付物。

## CI 与生产边界

上述24组描述默认runner的必跑选择，不是本轮全部24组已通过的声明；具体执行范围、源码/制品摘要和失败见每次回执。

`.github/workflows/ci.yml` 将本组验收作为必跑步骤，并保留 JSON/日志证据；不会上传 TLS 私钥。安装合同 job 另必跑自动化节点池组合测试与正式 schema 验证。原自动化实际进程验收仍由 `scripts/test-automation.py` 独立执行，不被本组替换。

本地 HTTPS Kubernetes / 对象存储夹具只用于限定的故障与授权条件。结果不证明 Kata/CSI、物理 fencing、实际云存储恢复、生产身份和 PKI、跨区 HA、72小时容量或 Linux 制品统一签名发布已完成。G4-01/G4-02 只有全部工作包退出条件通过后才能标为完成。
