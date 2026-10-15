# 启动申请与配额释放账本：开发与验收记录

状态：**账本子项已实现并完成本地整轮验收**。最终50文件冻结候选单轮27组164项、0失败、0ignored，汇总PASS_FULL_ACCEPTANCE；44条正式迁移逐项字节/checksum匹配，source/bin/SDK前后不变及自有清理确认。此前27组分批验收作为历史保留，最终状态以本次完整单轮为准。v2/v3及49候选失败仍保留：历史metadata测试边界与precommit注入阶段已分别修正并实际GREEN；早期其他并发503/timer原因仍UNKNOWN，此次数据库20/timers8/timer_worker4通过不等于修复未知原因。完成范围为[方案](launch-resource-accounting-plan-20261014.md)第2/5步及相关6/7/8账本子项，真实44→45维护门独立通过；第3/4步实际Pod/RuntimeClass观察待开发，新GitHub CI待上传触发。

第3/4步实际Pod/RuntimeClass可信观察尚未开发。`REQUESTED_COMPUTE_QUOTA`记录控制面受理的普通CPU/内存申请，`pod_resource_evidence`固定为`NOT_CAPTURED`；旧launch缺合同为`HISTORY_START_NOT_CAPTURED`，旧预约真实后续变化保留`LEGACY_UNBOUND`。申请、配额、Pod配置、宿主采样与宿主共享容量各自保留来源，不能直接相除计算利用率，也不提供节省比例、自动调档、warm pool或GPU。

## 生产实现

0045新增`launch_resource_contracts`、`quota_resource_receipts`、`launch_quota_bindings`与`quota_resource_legacy_baseline`四张append-only/FORCE RLS表。真实quota INSERT和status UPDATE在原业务事务内立即捕获NEW/OLD状态、原预约/账户/操作/资源、用途、单位、scope、数量及账户版本/余额/limit快照；延迟约束只检查普通新启动的精确身份与两scope各CPU/MEM共四条预约，不从最终账户余额重建PENDING。延迟校验使用行绑定tenant上下文，普通调用者在COMMIT前切换上下文不能绕过归属或金额完整性。

CREATE/START在真实新启动身份提交时捕获合同，RESTART不在受理时提前记新合同；可信关闭后同事务分别保留旧launch的RELEASED和新generation/launch的PENDING及归属。renew不新增合同。预约身份、数量、账户、origin operation不可漂移，只允许PENDING→ALLOCATED/RELEASED及ALLOCATED→RELEASED，状态不得回退。

普通计算、实例存续、工作区存储、执行、文件过程/内容、备份隔离计算/保留及临时存储、恢复隔离计算/临时存储用途独立捕获。租户和项目是同一申请的两层约束，逐条列示不能相加；同预约的状态历史也不能求和为消耗。新ordinary释放须关联原launch可信终止proof+cleanup或已持久never-authorized关闭；never-authorized先关闭、后独立事务实际释放。其他用途保留原执行/文件/volume/backup证据保护，`RELEASED`仅代表该用途的配额账务，不能概括为VM死亡或所有资源均释放。

旧预约基线只在迁移owner持锁时精确冻结一次，runtime不能读写；旧预约没有合同也不会被按今天规格回填。新预约缺普通合同拒绝整事务，不能以缺合同或客户端时间冒充legacy。迁移不补造历史PENDING、Pod资源或释放起点。

API普通角色只得到合同、状态记录和启动绑定表SELECT；八种非API组件不新增账本读取，所有runtime禁写新增表。启动时和`sandboxd resource-accounting-check`检查正式迁移checksum、实际表形状/FORCE RLS、精确函数体/安全属性、trigger与grants，缺失/停用/替换在bind/claim前拒绝。

只读`GET /v1/instances/{id}/resource-accounting`需要当前`instances:read`，读取前后新事务复核授权，返回前复查身份和token期限。默认当前合同+实例关联全部purpose/history；显式launch仅精确绑定ordinary CPU/MEM。签名24小时游标绑定主体/tenant/project/instance/选中launch/epoch/筛选方式/limit，倒序固定cutoff分页。数量、account version和generation均保留最多19位十进制字符串。SDK新增`getResourceAccounting`；实例页面只读并在scope/撤权/失败时清旧数据，缺合同/未绑定/未捕获Pod均显示UNKNOWN。使用合同见[资源账本](../docs/resource-accounting.md)。

## 实际维护升级证据

首发使用[维护升级门](../deploy/resource-accounting-upgrade/README.md)，不承诺旧0044 writer与新schema滚动共存。固定已审plan和镜像摘要，实际ValidatingAdmissionPolicy保护普通/init/sidecar/更新及ephemeral入口；全操作create-only ConfigMap锁按namespace互斥，不用TTL自动接管，释放带真实UID precondition。真实第二maintain冲突被拒绝。CLOSED后核对实际writer Pod、准确数据库runtime会话与活动租约均为零，才运行owner正常迁移；普通身份预检后恢复批准目标并等实际rollout。失败保持CLOSED/零writer；完成后清理失败独立为`COMPLETED_WITH_CLEANUP_FAILURE`/exit2，不能在无锁状态重新封闭其他维护操作。

最终全门证据为`.local/resource-upgrade-admission-20261015/full-final-v1/record.json`，status=PASS，绑定普通`sandboxd` SHA256 `09ca3005dcb1e874799128b7277ea72c63892995cffc01264bbe23a187fa5e10`和最终门脚本SHA256 `3c0f505fe174189ed590fcb0ff35d2129ded81c69454f8e3b557bb058bbd17ca`。真实本地Kubernetes v1.36.4/Alpine进程与独立TLS PostgreSQL执行44→45迁移、普通身份preflight、旧Pod排空及新Pod实际Ready；新UID `791cad11-e67b-4d87-9c1d-b7c08ecbb749`与旧UID `5e986de4-c5d1-4c84-91a5-4d366f27fc0a`不同。

同目录`data-before.json`/`data-after.json`核对quota_accounts、quota_reservations、instances、operations、workspaces五类原表逐行JSON摘要和行数完全相同。两个租户各8条共16条旧预约与baseline精确匹配；contracts/receipts/bindings均为0，没有补造历史。四张新表均FORCE RLS，实际SQLx45 SHA384 `d93790f3b18d8c6a0f9895eb3b5bcba17066c7cd69fcd798cac336bea4208b1146761fb5dd68a66660ff3742df9790a5`与最终源相同。`postgres-cleanup.json`确认只清理自有一次性PG；全门记录确认自有K3s、探针和操作锁清理。

最终源实际准入失败矩阵为`.local/resource-upgrade-admission-20261015/actual-v8/record.json`，status=PASS：无策略旧image可接受的RED、APPROVED11与CLOSED拒绝、普通/init/sidecar/更新/ephemeral拒绝、未配置writer默认拒绝及其他namespace不误封、实际第二maintain冲突与UID释放、真实Docker create ACK丢失后的自有清理、缺凭据维护失败保持CLOSED且零writer。该矩阵自身不执行数据库迁移，不能与全门范围混写。

本地维护验收证明真实Kubernetes编排和正常数据库迁移行为；Alpine进程是明确fixture，不能认证正式产品OCI、Kata/guest、CSI/Cilium、目标云、生产PKI/身份、HA容量或备份恢复。完整发行签名、安全审查与现网变更审批仍属独立发布门。

## 本轮测试与失败记录

| 证据 | 真实结果与范围 |
| --- | --- |
| `.local/launch-resource-20261015/public-sdk-unrestricted.log` | SDK75/75，通过构建及实际本地HTTP合同，数量精度、默认/显式launch、分页/撤权/取消保持只读。 |
| `.local/launch-resource-20261015/maintenance-unit.log` | 维护单元18/18，包括并发锁、原UID删除、完成后的丢ACK/回执写入失败和保持关闭。 |
| `.local/launch-resource-20261015/final-api-contract-python311.log` | OpenAPI合同13/13。 |
| `.local/launch-resource-20261015/final-fmt-v4.log`、`final-clippy-v3.log` | post-policy barrier修订后的fmt及严格`cargo clippy --all-targets -- -D warnings`均实际exit0，Clippy3.45秒。之前各轮结果保留；不把空fmt日志作为其他检查证据。 |
| `.local/launch-resource-20261015/public-browser.log`、`public-console-build.log` | 当前public控制台生产build通过；真实Chrome HTTP合同34/34、2.4分钟，含新增账本6项。它是明确HTTP合同fixture，不等于真实IdP/Kata/云产品链认证。 |
| `.local/launch-resource-20261015/native-final/record.json` | Cargo JSON定位的60个普通程序直接运行，453 PASS、0 FAIL、269环境专项明确ignored，binary前后不变，没有重编译或继承外部TEST环境。该轮在automation_upgrade和worker_support两处integration修订前；automation_upgrade target当时四项均ignored，修订后用例分别由v3和诊断批次真实执行，不从普通ignored推导PG/节点证明。 |
| `.local/launch-resource-20261015/final-docker-v2/record.json` | **未通过**，runner exit1；账本9、HTTP3、DB取消1、BFF PG4、服务身份7、租户审计5共6套29项PASS；第7套automation_upgrade 0/1失败，之后套件未运行。该点source/artifacts/SDK前后均稳定，自有容器/进程清理确认。 |
| `.local/launch-resource-20261015/acceptance-summary.json` | **历史分批结果**PASS_BATCHED_ACCEPTANCE：选中27组164项、0ignored；457生产输入一致、09ca未变及逐批稳定/清理确认。该收据`single_27_suite_run_passed=false`，不作为当前最终状态。 |
| `.local/launch-resource-20261015/final-docker-v3/record.json` | 选中前11组46项PASS，含历史升级1/1/三个marker、timers8和timer_worker4；第12组continuation为5/6，runner exit1保留，没有作为整轮PASS。 |
| `.local/launch-resource-20261015/checkpoint-diagnostic-v1/record.json`、`checkpoint-diagnostic-v2/record.json` | 只增加测试故障诊断后exact1实际7.28秒PASS，再按原顺序完整6项45.46秒PASS，不再重试；汇总164只计完整6项，exact1不重复加总。 |
| `.local/launch-resource-20261015/remaining-docker-v1/record.json` | 后15组112项PASS，含database20、termination16、never-authorized10、gateway6、volume10、backup4+8；source/bin/SDK稳定与自有清理确认。 |
| `.local/launch-resource-20261015/final-candidate-docker/record.json` | 冻结49候选的单轮再次失败：前11组46项PASS，continuation5/6 FAIL，exit1；source/bin/SDK稳定与自有清理确认。新增诊断捕获真实SQLx LOCK_TIMEOUT，详见下文。 |
| `.local/launch-resource-20261015/checkpoint-barrier-v1/record.json` | 修正测试注入阶段后timer_worker4+continuation6，两组10项实际PASS；source/bin/SDK稳定与自有清理均true。与之前164项分别记录，不重复加总。 |
| `.local/launch-resource-20261015/final-acceptance-summary.json`、`final-candidate-docker-v2/record.json` | **最终PASS_FULL_ACCEPTANCE**：冻结50文件候选完整单轮27组164项、0失败/0ignored，原runner exit0。source SHA256 `98ceede163da557bed8b567eb9623163bdec271f819977cf45484e529d134205`；source/bin/SDK前后不变、自有容器/进程清理全部确认，sandboxd09ca未变。44条正式迁移逐项字节/checksum匹配，含0045 SHA384 `d93790f3b18d8c6a0f9895eb3b5bcba17066c7cd69fcd798cac336bea4208b1146761fb5dd68a66660ff3742df9790a5`。 |
| `.local/launch-resource-20261015/probe-v1/record.json`、`probe-v2/record.json` | 早期核心6项首轮失败、后续6+HTTP3观察到通过，但source_unchanged=false、runner exit1，均不计最终源码aggregate PASS。 |
| `.local/launch-resource-20261015/writers-probe-v3/record.json` | termination16、never_authorized10、gateway6、volume10、backup4+8共6套54项观察到通过；source_unchanged=false、runner exit1，不计最终汇总。对应writer后在remaining-docker-v1真实重验，不与早期数字重复加总。 |

最终Docker v2的`automation_upgrade.log`保留原失败：`Current migrations changed historical quota, holds, receipts, ACK, source events or authority`。该失败已定位为历史metadata对象集合把0045新增四表、五函数和新增trigger纳入了旧对象比较；只修改`tests/automation_upgrade.rs`（SHA256 `2efbde0bbead2a4f0612acf0e9ac1d1a8c98a8c07e6f516e708de39ab8061d37`），精确排除新对象，保留旧32类业务表和全部旧安全metadata比较，同时独立严格验证16条旧预约ID基线、四表FORCE RLS、三类新账本零行及两个runtime当前guard。定向正常编译8.84秒后，v3实际1/1 GREEN且三个原marker齐全。生产0045 SQL与09ca普通二进制未改变；v2失败保留，GREEN证明修复后的精确用例，后续27组164项分批汇总不改写v2或v3整轮失败。

v3连续worker组初轮5/6，precommit用例报`owned worker stopped before checkpoint fault`。第一次仅增加安全drain后的真实worker错误优先诊断，未改生产、锁、时序、预算和断言；诊断版exact1/原序6项通过并不能确定原因。随后冻结49候选单轮再次在同用例失败，新诊断真实报`WORKER_PRECOMMIT_WORKER_EXIT_FAILED`，内层为SQLx `canceling statement due to lock timeout`。结合源码错误路径，raw SQLx错误发生在`Worker::run`启动检查，循环后的fatal已有固定包装；helper在启动前持`domain_events ACCESS EXCLUSIVE`击中了启动检查，而不是预期checkpoint写入。这项故障注入时序原因已有实际错误与源码因果证据，不再统称UNKNOWN。

修复仅在测试增加post-policy响应barrier：等真实Worker通过startup/claim并完成policy POST远端创建，暂不交付响应UID，确认尚未写checkpoint；此时取得domain_events故障锁，再放行POST响应，令原checkpoint写入遇到真实锁等待。独立startup barrier为5秒，原5秒观察、12秒drain、35秒测试预算、原锁超时及完整断言保持。最终helper SHA256分别为`checkpoint_faults.rs=8b7855dccac4172fcd947a4caf499c16316383452f90b1b0c3289e429fa86ab6`、`mod.rs=8d8c2202f6012a028b3c432a93ea9a1c40be8a705cd35fdb4ab3d7adce6e12df`；生产SQL和09ca二进制未改。真实checkpoint-barrier-v1两组10项及最终50候选完整单轮内continuation6项均GREEN，独立审查通过；旧候选FAIL与早期诊断结果保留。

早期`writers-probe-v1/database.log`有两项并发503/DEPENDENCY_UNAVAILABLE；`writers-probe-v2/worker_lifecycle.log`有timer公平到期检查失败。同一早期账本构建的相同二进制，设置未变，重复结果有成功也有失败；503的根因仍UNKNOWN，不能归因为账本或宣称已修复。这里没有不含本特性的旧生产基线对照证据。原生产超时、严格断言和等待预算不变；后续通过只能按实际源码/制品与精确日志记录，不能抹除此前失败。

本轮两项维护P2和延迟tenant上下文审查反馈已处理，无未关闭项；该结论只限本轮审查范围。基线Git提交`5086b28bd586e9ee114651f492a5e7cce7b5c791`的GitHub CI run`38464971503`已实际completed/success，属于本轮之前的基线。本轮新提交CI待上传后触发，实际状态另存本机交付回执，不用基线成功代替新结果，也不循环修改此提交文档填写自身提交hash。

## 本地验收结论与后续门

| 待补项 | 当前状态与通过要求 |
| --- | --- |
| 历史升级metadata边界修复 | 已通过v3真实1/1及三个marker，详见上文；不据此替代剩余完整矩阵。 |
| 账本相关本地Docker验收 | 最终50候选完整单轮27组164项、0失败/0ignored，44条迁移、source/bin/SDK稳定及自有清理通过。先前分批为历史，v2/v3/49候选FAIL保留。 |
| precommit故障注入与其他早期失败 | 49候选SQLx锁超时已定位为测试注入过早；post-policy barrier专项10项及最终整轮6项GREEN。早期其他503/timer原因仍UNKNOWN；此次database20/timers8/timer_worker4通过不证明未知原因已修复。 |
| 本轮严格Clippy/Chrome最终绑定 | 已通过：最新严格all-target Clippy-v3/fmt-v4、当前public Chrome34及console生产build；普通453/0/269与integration修订后的真实PG范围分别记录，不能相互替代。 |
| 新提交GitHub CI与上传 | 本地账本整轮验收完成，新提交CI待上传后触发；实际状态由本机交付回执和最终答复报告，基线成功不代替新结果。 |
| 实际Pod/RuntimeClass可信观察 | 待开发，仍属方案第3/4步；普通请求/配额账本不能替代Pod UID/Node/boot/许可绑定和版本回读。 |
| 生产与资源效率认证 | 真实Kata/CSI/Cilium/云恢复、GPU、预热、利用率/成本与HA/72h仍为后续独立工作，不由本轮账本或Docker结果推出。 |

账本子项已有上述完整单轮验收；新提交CI和发布状态仅按实际收据记录。保留分批、v2/v3、49候选及早期失败，不通过放宽断言、超时或删除迁移历史换取通过。
