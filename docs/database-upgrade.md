# 数据库升级与历史自动化验收

当前仓库在一次性真实 PostgreSQL TLS 数据库中安装版本 ≤41 的真实迁移源码，写入历史自动化、非空账务与回执，再按41→42→43分阶段升级。42阶段保存合法已阅通知历史，43后通过当前签名身份验证原键恢复、当前ACK和撤权；新增同一run的UNKNOWN→FAILED独立通知及跨目标回执验收。2026-10-11局部结果分别见[基础升级](../research/database-upgrade-delivery-20261011.md)、[非空历史与ACK](../research/database-upgrade-state-delivery-20261011.md)和[双状态通知](../research/database-upgrade-progression-delivery-20261011.md)。这份说明定义可复现验收和生产升级顺序；局部结果不代表完整 N/N−1 升级或生产发布已经通过。

## 验收对象与版本来源

| 对象 | 来源与含义 |
|---|---|
| 历史 schema | 当前正式迁移目录中版本 ≤41 的实际源码前缀，即 1..37、39、40、41；0038 永久保留，没有占位或伪造账本。这是 schema 来源，不能命名为一个已发布的 v41 产品版本。 |
| 历史基础 ACL | `tests/fixtures/upgrade/v41-roles.sql`，冻结自真实 Git HEAD `d5f7a70afadde40e30ca01a2e9871a5312153d57` 的 `scripts/sql/roles.sql`。 |
| 历史自动化 ACL | `tests/fixtures/upgrade/v41-automation-role.sql`，冻结自同一 HEAD 的 `scripts/sql/automation-role.sql`。它表示该源码时点的权限合同，不能代替真实旧发行包。 |
| 当前 schema | 全部正式迁移 1..37 加39..43，共42条；逐项成功标志和 SHA384 必须与源码一致。 |
| 当前调用链 | 普通 Cargo 构建的 `automation_upgrade` 测试产物、正式 Migrator 和最小权限角色；其他必跑组继续使用正常 `sandboxd --role migrate`。 |

历史权限脚本只用于一次性测试库，先于当前权限安装；不得在生产新 schema 上运行这些旧脚本来“恢复权限”。测试不修改已冻结正式迁移、不重写 `_sqlx_migrations`、不通过管理员连接执行被测 writer，也不给 owner 或运行身份 `CREATEDB` 权限。

两份冻结 ACL 的 SHA256 和来源说明见[夹具来源](../tests/fixtures/upgrade/README.md)。历史 schema 仍使用正式迁移源码前缀；每次 runner 绑定其当前字节，不把一个未发布的 schema 序号包装成产品版本。

## 必须保留的兼容性语义

升级必须保留历史策略、委派、run 及其已有授权和事件事实。迁移 0042 新增的通知捕获针对升级后写入的真实异常源事件：新通知关联持久化 run 的范围、版本和状态，事件请求身份必须匹配；不能根据任意 payload 制造通知。历史事件保留原样，不由迁移回放成新通知。

旧字段集合、旧 ACL 下的合法事件 writer 应在当前 schema 中继续工作。新通知由受限 `SECURITY DEFINER` 触发器派生，旧 writer 不需要新通知表的直接写权限。非法或错绑的源事件应被拒绝并回滚，不能先承诺“所有旧 writer 都会被拒绝”。这一 SQL／权限兼容性检查没有运行旧发行包的 API 或 worker 进程。

SQLx 的历史 Migrator 在当前数据库上重新运行时，不认识已安装的新迁移版本，必须返回 `VersionMissing`，且保持账本和业务事实。这条断言只证明旧迁移器拒绝未知版本。它不证明旧应用拒绝监听、不证明旧 worker 拒绝执行，也不证明应用回退安全。

当前 `Database::verify_runtime_role` 会检查登录和当前角色不拥有表、不带超级用户／RLS 绕过／建库建角色能力、不跨组件继承；其迁移检查要求自身所有 embedded 迁移均成功且 checksum 相同，并拒绝失败迁移。成功的较新 schema 版本可以存在，这一点已有普通测试明确允许。不能把该合同解释为“数据库版本比二进制新就一律拒绝启动”；真实旧二进制与新 schema 的兼容性仍须独立验收。

| 本用例范围 | 具体检查 |
|---|---|
| 历史事实 | 两个租户、各自业务项目和同租户兄弟项目；每租户保留 FAILED／OUTCOME_UNKNOWN 各一个历史 run、相应策略／委派／事件／审计。逐列快照比较32类租户表、全局 principal／identity 及平台配置；核对既有 RLS／policy、触发器启用与延迟属性、函数安全属性不变。每租户新增8个配额账户、8条预约（PENDING 2／ALLOCATED 4／RELEASED 2）且余额精确匹配、1条typed Accepted幂等回执、1条typed GrantReceipt、2条LEGAL hold及1条release；实例、工作区、文件意图、定时和派发路由仍非空。 |
| 新旧 writer 合同 | 先正常执行至42，比较41全部既存事实与完整旧账本，确认没有回填通知。42 DDL后、当前权限脚本之前，以历史权限的 API 和 coordinator 独立 LOGIN 分别写入真实合法 FAILED 源事件并派生通知；当前角色安装后检查 UNKNOWN 重复来源仅保留首条通知。无 status 的旧格式事件仍正常提交且不产生通知。运行连接使用生产10秒语句／3秒锁等待／15秒闲置事务限制。 |
| 42已阅历史 | owner仅在正常源事件派生的通知上执行合法单向ACK UPDATE，同事务保存typed回执、HTTP请求关联审计与run关联因果事件。再执行正常43迁移及原权限脚本，完整历史、通知全部列和42账本全部列保持一致；这表示提交历史夹具，没有运行一个真实旧发行包。 |
| 当前ACK与隔离 | 完整当前schema/角色验证后，通过真实RS256 JWT／本地JWKS和 `resolve_actor` 调用当前数据库Interface。42原key/原ETag恢复原body，无新增事实；同key改摘要409，新key陈旧ETag412；撤销读权限使get/list404，撤销写权限使ACK重放404，身份绑定或主体禁用使重放401。新通知ACK及同key重放只记录一次ACK；已阅通知用新key和当前ETag可产生独立回执，审计/因果事件仍各一次。原始来源、run、业务账务及另租户全部事实不变，池复用没有遗留租户上下文。本用例没有浏览器演示或旧API进程。 |
| 同run双状态 | 当前coordinator独立LOGIN按正常约束将UNKNOWN v5合法更新FAILED v6，同事务写一条转换审计与匹配源事件。UNKNOWN首来源仍v4、通知已阅v2，FAILED是独立未读v1；同run恰两通知。终态同版本重复源受真实唯一约束23505拒绝，先写的审计、事件头/位置及全部业务事实整事务回滚。limit=1固定cutoff分页恰读项目3条记录，其中目标run两条；跨项目/租户游标400、跨租户读与ACK404。相同文本key在两个通知target上各自返回原回执，FAILED ACK与撤权重放不改变UNKNOWN和已完成run。该用例证明合法持久状态/source-writer合同，没有运行完整controller恢复或policy exhaust。 |
| 非法源事件 | 在同一事务先更新 run，再分别写入错版本、错状态、错请求关联的事件；精确约束错误 `23514` 后回滚，run、事件、序号、审计和通知事实均不变。 |
| 重放与拒绝 | 当前正式迁移／角色脚本重放不改变账本与事实；历史 Migrator 返回 `VersionMissing(42/43)`，关闭专用物理连接后账本与事实不变。0043 的延迟文件活动 scope 验证正常换租户提交和孤立活动在 COMMIT 拒绝；另在事务内执行正常约束并直接检查调用方租户上下文恢复，函数保持固定 search_path 与无公共执行权限。 |

配额ALLOCATED／RELEASED行是owner准备的合法账务历史夹具：同一CREATE操作的不同维度有不同状态，仅用于schema、余额及字节保留验收，未经过完整worker／termination生命周期。不能据此声称guest已启动或资源已释放。LEGAL保护也不等于BACKUP／RESTORE保护。执行、launch permit、backup及attempt集合仍为空；当前夹具没有满足冷备份所需的真实关闭证明和已认证配置，不插入伪造证明来制造非空备份。

## 本地复现与通过条件

依赖为仓库锁定 Rust 工具链、本机 Docker Unix socket、锁定 PostgreSQL 镜像、Python、OpenSSL 和真实构建后的 TypeScript SDK。使用当前仓库缓存，保留普通断言和溢出检查；证据保存于 `target` 之外。每次使用新的私有证据目录，不选择已有或生产数据库。

```bash
df -h .
export CARGO_TARGET_DIR="$PWD/target/review-low-debug"
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
umask 077
sandbox_upgrade_out="$PWD/.local/upgrade-$(date +%Y%m%dT%H%M%S)"
mkdir -p "$sandbox_upgrade_out"
npm --prefix sdk/typescript ci --ignore-scripts --no-fund --no-audit
npm --prefix sdk/typescript run build
cargo test --locked --all-targets --no-run --message-format=json \
  > "$sandbox_upgrade_out/cargo-artifacts.jsonl"
python3 scripts/test-review-fixes.py \
  --artifacts "$sandbox_upgrade_out/cargo-artifacts.jsonl" \
  --evidence-dir "$sandbox_upgrade_out/review"
```

剩余磁盘低于50 GiB或本任务缓存超过20 GiB时，先按本机规则评估可安全回收产物，不删除数据库或复制整个 `target`。离线构建可在依赖缓存完整时加 `--offline`；缺少依赖时不得用不同版本替代锁文件。

复用同一 runner，避免单独手工建库形成另一套夹具。14组 review 中，只有完整精确元组 `automation_upgrade / automation_upgrade / upgrade_from_v41_preserves_historical_automation_and_rejects_invalid_source_events` 不预迁移；runner 管理员只新建并确认自有空库，测试 owner 自行安装历史前缀。其他组保留当前全量预迁移。没有用户可选的“跳过 schema 校验”或“已有库升级测试”选项。需要完整控制面验收时，使用[本地验收](local-acceptance.md)的34组入口；它继承同一个历史用例。

本用例必须实际发现且仅有一个ignored测试，日志最终同时输出以下三项marker，实际通过数与失败数满足runner条件：

- `AUTO_UPGRADE_V41_CURRENT_FACTS_OLD_MIGRATOR_REFUSAL_VERIFIED`
- `AUTO_UPGRADE_NONEMPTY_HISTORY_SCHEMA42_ACK_CURRENT_REPLAY_REVOKE_VERIFIED`
- `AUTO_UPGRADE_UNKNOWN_FAILED_DISTINCT_SOURCES_ACK_REPLAY_ISOLATION_VERIFIED`

最终账本须为42条且SHA384相同、无0038。`record.json` 必须含 `schema_preparation.mode=TEST_INSTALLS_V41_THEN_CURRENT`、`pre_run_user_relation_count=0`，以及 `historical_upgrade_completion_marker`、`historical_state_completion_marker`、`historical_progression_completion_marker`。全部公开源码、普通二进制、SDK制品运行前后摘要不变，14组全部通过并确认本次进程/容器清理后，review runner才返回成功；缺任一marker或零测试均不能通过。

非空执行/备份、完整生命周期及controller未知结果恢复、真实旧发行包进程仍需相应独立用例；不能从这一个历史升级用例推断它们已经通过。

## 生产升级执行顺序

生产部署继续通过正常 `sandboxd --role migrate` 安装当前迁移与权限，没有新增 dry-run、safe-mode、自动降级或修复账本的 CLI。以下操作由部署流水线和运维职责执行，不能将本地空库脚本直接指向生产。

1. **固定发布输入。** 保存当前／目标发行包版本、源码和镜像摘要、迁移 checksum、组件角色与权限清单。生产 runtime 与迁移 owner 使用不同凭据；DBA 预先提供各组件独立、无特权 LOGIN，正常迁移只安装已经存在角色的权限，不创建账号或替代身份服务。
2. **完成恢复与兼容性前置。** 备份生产数据库并记录恢复点、保留期和依赖；在独立环境实际恢复，核对 schema、授权、幂等账本和业务事实。用真实当前与目标发行包在该环境完成升级、兼容性及应用回退试验。未通过时不进入生产变更窗口；本地 schema 前缀通过不满足这个条件。
3. **先扩展 schema。** 根据已验证的发布计划控制写流量和自动化调度，确认需要停止的进程完成排空、没有遗留本次事务与锁，再由单一受控迁移任务使用 owner 凭据运行目标版本：

   ```bash
   SANDBOX_DATABASE_URL="$MIGRATION_DATABASE_URL" /opt/sandbox/bin/sandboxd --role migrate
   ```

   二进制路径须对应已验证目标发行包，数据库地址由生产秘密管理注入。现有迁移固定一条 owner 连接，使用有界5分钟 statement timeout；运行身份仍保持10秒语句、3秒锁等待限制。权限安装失败会使任务失败，已经完成的正式迁移不能因此被当作未发生。
4. **核对再发布应用。** 用维护身份确认每项迁移的成功标志／checksum、权限和强制 RLS；部署目标 API、worker、automation 等实际启用组件。确认 readiness、身份解析、授权实时撤回、持久 run 和幂等恢复、事件／通知、未知结果不自动重复执行、进程正常退出后，再按已验证方案恢复流量和调度。真实旧进程与新 schema 的滚动共存顺序必须由发行包验收决定，不能从 `VersionMissing` 推导。
5. **保留证据与数据库事实。** 记录变更前后版本、每阶段结果、实际排空与恢复事实、异常及处理人。锁竞争或超时失败时停止后续发布，保留日志和账本，排除已确认竞争后重试同一目标迁移任务；不改 checksum、不删成功迁移行、不运行下迁移。生产滚动排空、故障恢复和流量恢复仍需独立演练。

应用发布失败时，只能回退到已经通过新 schema 兼容性验收的发行包，数据库保持已安装的扩展和事实。不得运行旧 Migrator／旧 ACL 脚本来回退数据库；默认 SQLx 拒绝未知版本应作为停止信号。若必须数据库恢复，应执行已演练的独立恢复／切换流程，核对恢复点之后的操作、幂等键、授权、任务与外部资源，不能将备份覆盖视为无损回退。

## 仍需完成的生产退出条件

| 剩余项 | 必须提供的证据 |
|---|---|
| 真实 N/N−1 发行包 | 已签名旧／新 Linux二进制和 OCI 产物、固定版本来源及完整升级／回退结果；当前 schema 前缀和冻结 ACL 不代替发行包。 |
| 旧／新进程共存 | 实际 API、worker、automation 在新 schema 下的读取、写入、撤权、幂等、未知结果、流和排空；旧 Migrator 拒绝本身不覆盖这些事实。 |
| 生产维护与滚动发布 | 写受理和调度控制、实际 Pod/进程逐个排空、数据库连接／锁确认、恢复流量和失败处理，全过程有独立观测证据。 |
| 实云升级／恢复 | 公有云数据库、PKI、身份、Kata/CSI/Cilium、持久存储与实际外部资源在升级／切换过程的结果，含恢复点后的事实核对。 |
| 完整发布门 | 当前有效安全审查、签名产物、HA／容量／稳定性与恢复验收。不得延长旧审查、改变时钟或将局部回归当作整产品认证。 |
