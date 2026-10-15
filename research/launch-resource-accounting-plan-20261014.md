# 逐次启动资源账本：下一完整交付方案

状态：**进行中；第2/5账本和第3普通CPU实时回读子项已完成本地验收。** 原0045账本50文件单轮27组164项记录保留。本轮新增实际RuntimeClass守卫、Pod资源前后复核和最小RBAC，35组192项按最终二进制分批通过，459项原生及严格Clippy/fmt通过；恢复草稿在原有backups:restore关闭处阻断，未计通过。93954fd的CI准入fixture漏配额已修正并本地4项通过，新CI待同步后核对。第4步持久观察、利用率、自动调档、预热和GPU仍未完成，公开Pod证据继续NOT_CAPTURED。详见[本轮回读交付](runtime-class-resource-readback-20261015.md)与[原账本交付](launch-resource-accounting-delivery-20261015.md)。

## 数据与身份合同

必须分别保存四种来源：受理时的用户规格；每次launch实际请求合同；经可信登记方回读的Pod request/limit/overhead；现有配额账的PENDING、ALLOCATED、RELEASED回执。宿主cgroup共享祖先的容量上界仍是独立观测，不能与其中任何一项直接等同。

合同绑定tenant、project、instance、workspace、generation、launch与安装epoch。实际Pod观察再绑定Pod UID、Node UID、节点boot身份和登记许可。RuntimeClass的UID、resourceVersion及overhead保存为配置观察；Pod自身的资源值来自其实际UID回读。跨对象读取不是原子快照，不伪造Pod采用了某一RuntimeClass版本的证明。本轮采用固定kata-qemu和真实VAP/Binding保护受控配置，当前配置身份是Class UID加规范化受控内容SHA-256；resourceVersion仅表示本次回读元数据。创建/回读前后核对守卫、Class及完整Pod UID/spec/resources，纯RV或status变化不等于资源漂移。配置变化、UID替换或证据冲突拒绝验证；第4步完成前不持久登记为历史观察。停止和清理仍允许依据原可信终止证据进行，不能被当前RuntimeClass变化卡住。Kubernetes v1.35并未天然将整个Class配置设为不可变，缓存admission也不提供adopted RV证明，官方源码依据见[本轮设计](runtime-class-resource-readback-20261015.md#官方行为与实现依据)。

0045已新增append-only请求合同、配额状态回执、精确普通启动绑定与冻结旧预约基线，使用复合FK、有界数量和FORCE RLS；实际Pod观察表及其UID/Node/boot身份模型仍属于第3/4步。原迁移字节保持，当前正式迁移为1..37加39..45，共44条。旧launch没有足够证据时返回明确缺证据；不能按今天的Flavor、overhead或更新时间补造历史。

## 实现与开发验收表

| 顺序 | 需要开发什么 | 技术落点与完成条件 |
| --- | --- | --- |
| 1 | 确定可归一化的CPU/内存数量、来源与缺证据状态 | **数量/provision校验保持原已实现检查点，完整来源观察模型仍待第3/4步。** `runtime_resource_contract`接入实际生成、创建前/回读后和RuntimeClass入口；工作负载支持原CPU、memory、ephemeral-storage三个键，overhead只允许CPU/memory，拒绝负数、溢出、额外设备和sidecar。第2步申请标为`REQUESTED_COMPUTE_QUOTA`，实际Pod明确`NOT_CAPTURED`，不能把当前校验值当历史观察。 |
| 2 | 不可变launch请求与配额回执 | **已实现并完成本地整轮验收。** 0045真实quota INSERT/status UPDATE同事务捕获全部purpose。CREATE/START在真实新身份提交时记录合同；RESTART受理时不提前记录，旧release后新generation/launch延迟精确归属；renew不新增。PENDING和申请同提交，tenant/project scope分列不相加。已验真实0044→0045维护切换，相关用例纳入最终50候选单轮27组164项PASS；旧候选失败保留。 |
| 3 | 受控RuntimeClass配置与Pod资源回读 | **普通CPU实时校验子项已开发并本地验收。** 真实VAP/Binding锁住kata-qemu配置更新/删除；逐字段GET核对、UID与配置摘要前后复核，创建后独立GET实际Pod，完整request/limit/overhead与总和溢出校验；provision允许首次调度、gateway固定节点。35组192项分批、真实本地Kubernetes及459原生通过；恢复草稿未到restored START，兼容性未计通过。持久观察属于第4步。 |
| 4 | 可信观察登记 | **下一步待开发。** gateway_runtime、termination_runtime带入经校验资源能力，授权ACK与观察原子提交；保存Node/boot/epoch/permit与Class独立观察，沿用原锁序和实时权限/期限。冻结旧基线、同内容幂等/冲突拒绝、COMMIT ACK丢失复用；只读API/SDK/UI及签名分页固定观察ID或首次缺失状态。API与普通调用者不能伪造登记。 |
| 5 | 完整释放历史 | **账本子项已实现并完成本地整轮验收。** `mark_ready`与原ALLOCATED同事务捕获，可信cleanup的RELEASED变化和回执同提交。新ordinary释放校验原launch proof+cleanup或持久never-authorized关闭；never-authorized两事务不提前释放。TTL、Pod缺失、CRI返回、API退出、节点失联不能直接结束预留。 |
| 6 | 最小权限与启动门禁 | **账本子项已实现并完成本地整轮验收。** 只有API获得三张查询表SELECT，八种非API组件不新增账本读取，遗留基线runtime禁读；所有新表runtime禁写。缺迁移/checksum、表形状/RLS/trigger/function/grants漂移在bind/claim前拒绝。维护门执行真实准入/停写/排空/迁移/普通身份预检/目标恢复，不承诺N−1/N混跑。 |
| 7 | 对外只读API、SDK与实例页面 | **账本子项已实现并完成本地整轮验收。** `instances:read`前后撤权/epoch核验、签名有界分页；默认当前合同+实例全部purpose/history，显式launch仅精确绑定ordinary CPU/MEM。数量/version/generation全为十进制字符串；SDK75项通过。UI只读并在切scope/撤权/失败后清空；Pod固定`NOT_CAPTURED`，没有Pod观察时间或利用率。 |
| 8 | 真实事务和HTTP验收 | **最终50候选单轮27组164项、0失败、0ignored及真实维护门通过，汇总PASS_FULL_ACCEPTANCE。** 独立TLS PostgreSQL、正常迁移、普通角色和实际JWT/HTTP/Node SDK覆盖合同/状态/撤权/游标/整数精度。最终source/bin/SDK前后不变、44条迁移一致及自有清理确认，sandboxd09ca保持。v2/v3/49候选FAIL保留，历史分批及source changed不冒充本次整轮结果。第3/4步的Pod登记、真实Kata/Node/boot资源对应仍待开发与实机验收。 |

每一步仅在其事务、不变式和失败验收通过后完成；不能只凭schema存在、HTTP 200或控制台展示标记整个工作包完成。发布走源码绑定CI及既有签名、安全、回滚和离线安装门禁。

## 第2步的事务时序与升级合同

当前代码的RESTART在写入新generation/launch之前申请配额（`src/termination_ledger.rs`）；捕获PENDING时不能绑定instance当时的旧launch。CREATE先插入instance，再插operation及配额，birth也不能作为合同的必需先决记录。普通CPU请求、隔离备份CPU/MEM、执行/文件及工作区配额要分别保存purpose；仅凭dimension或resource_id不能判断是普通VM申请。

已保留原业务写法和锁顺序，在真实quota INSERT及status UPDATE安装同事务捕获。普通新申请的完整性与新launch归属延迟到COMMIT前检查；使用该次INSERT的NEW身份、金额及origin operation，核对最终新generation/launch和四条CPU/MEM scope记录。每次INSERT/状态变化立即保留当次NEW/OLD、account version及limit快照，延迟检查只负责归属与完整性，不只读最终account/status而丢PENDING。RESTART同一COMMIT分别得到旧合同的RELEASED与新合同的PENDING，旧释放按原reservation合同及可信证据关联。该延迟触发器已在普通角色的真实PostgreSQL专项验收；等待延迟检查时调用者切换tenant上下文也不能绕过归属完整性。

所有quota purpose的回执保留实际reservation/account/origin operation及单位、scope、金额、limit和account version。request合同只绑定有准确普通CPU申请来源的记录；backup等保持独立purpose。新ordinary申请缺合同应拒绝事务，不能当旧历史放过。升级不补造旧PENDING、开始时间或launch配置；旧row升级后实际发生的ALLOCATED/RELEASED可记当前事实，并明确HISTORY_START_NOT_CAPTURED/LEGACY_UNBOUND。合同不FK到instance可变的当前generation/launch。迁移必须冻结不可由runtime改写的原reservation ID基线来识别旧历史，不能按缺合同、客户端时间或当前created_at把新申请放行为LEGACY。reservation身份、金额、origin operation及account一经申请不得漂移，状态图限PENDING→ALLOCATED/RELEASED及ALLOCATED→RELEASED，RELEASED终态；保持status不变的非法字段改写也必须拒绝。

never-authorized的永久关闭和实际释放是两个事务：第一事务仅有closure，第二事务真实完成状态变化后才产生RELEASED。STOP/RESTART、执行完成、文件退出、volume删除和backup完成的真实writer都必须覆盖，且保留各自原证据规则。触发器固定search_path、使用schema限定对象，PUBLIC不可任意执行；回执append-only、FORCE RLS，API等普通角色对新增账本表只读，保留原quota业务写权限。新增检查不能在quota锁之后反向取得workspace/instance锁，也不能靠自报GUC伪造租户或释放证明。

SQL自动捕获须覆盖所有真实writer，但原0044版本的Rust启动检查允许额外迁移，也不认识新增trigger，不能承诺未升级binary能发现未来trigger停用。第2步首发采用受控维护窗口，禁止未经兼容认证的旧writer混跑：暂停写入口和claim，停止旧writer并核实自有进程、活动租约及数据库会话收尾；正常owner应用新迁移及grants；由新版本preflight核对schema、trigger、校验和及权限；部署入口只允许对应已审核发行摘要并防止旧writer重新启动，再恢复写入口。部署门须真实执行并验收，不能只写操作说明。任何一步失败保持维护状态，不回退运行不具备资源guard的旧binary。若以后采用滚动升级，须先发布兼容guard或强制部署启动门，并单独验证N−1/N混跑及trigger停用拒绝；本次不提前承诺。

新版本缺迁移、校验和错误、trigger停用/替换、部分schema或缺权限时在bind/claim前拒绝启动。新API/SDK/outbox数量字段使用十进制字符串，保留超过JavaScript安全整数的精度；不把BIGINT直接转Number。旧三Flavor接口保持兼容。

落地验收使用正常迁移及普通角色的独立TLS PostgreSQL，覆盖CREATE/START/RESTART queued与blocked、renew、ready/STOP、already-STOPPED DELETE仅释放INSTANCES而不重复CPU/MEM、never-authorized两事务崩溃、exec/file/volume/backup实际释放、锁等待回滚、真实COMMIT ACK丢失与原键重放、并发旧代/epoch撤销及0044历史升级、维护窗口内旧writer排空与拒绝重启；同时核对跨租户FK/RLS与禁写、缺scope或冲突金额拒绝、禁用/替换trigger启动拒绝，以及9007199254740993和i64_MAX的JSON逐字往返。选中批次、v2/v3/49候选失败及test-only注入阶段修复见[本轮交付记录](launch-resource-accounting-delivery-20261015.md)。第2/5步与相关6/7/8账本子项完成本地整轮验收；post-policy barrier两组10项及最终50候选单轮27组164项均实际通过，旧分批与失败记录保留。早期并发503/timer原因仍UNKNOWN，新提交CI和实际Pod来源/历史利用率/自动调档仍属后续门。

## 随后推进快速启动和GPU

资源账本交付后，再开发有预算、到期、撤销和GC合同的镜像/节点预准备。分开观测accepted、queue、placement、镜像准备、CRI调用、VM readiness、route及首次正确执行；以端到端成功任务测冷暖p50/p95/p99、峰值并发、失败率和单位成功任务成本。预准备本身的空闲占用、镜像体积、实际释放证明须可计量；没有节点实测前不承诺启动毫秒数或资源节省比例。

GPU先开发真实设备身份、独占租约、Pod/VM/租户归属、显存与计算利用率采集及可信回收。不得把显存占用率当计算利用率；设备未运行、采集失败及归属丢失用UNKNOWN。随后在实际支持的硬件/驱动上验MIG、时间共享等隔离与资源合同，覆盖撤权、节点重启、故障恢复和数据残留。没有本机GPU不能用CPU fixture签发GPU性能、隔离或成本认证。
