# 逐次启动资源账本：下一完整交付方案

状态：**进行中**。宿主CPU/内存容量上界和CRI调用往返耗时已经实现；2026-10-14已开发有界数量类型及实际provision校验，见[数量子项交付记录](runtime-resource-contract-delivery-20261014.md)。来源/缺证据状态、不可变launch合同、配额回执和有效期账本仍待开发。本方案补齐解释浪费所需的配置与授权账。实施与验收完成前，不开放利用率百分比、自动调档、预热池或GPU共享。首批保留普通CPU三种Flavor及request=limit，不改变已有配额政策。

## 数据与身份合同

必须分别保存四种来源：受理时的用户规格；每次launch实际请求合同；经可信登记方回读的Pod request/limit/overhead；现有配额账的PENDING、ALLOCATED、RELEASED回执。宿主cgroup共享祖先的容量上界仍是独立观测，不能与其中任何一项直接等同。

合同绑定tenant、project、instance、workspace、generation、launch与安装epoch。实际Pod观察再绑定Pod UID、Node UID、节点boot身份和登记许可。RuntimeClass的UID、resourceVersion及overhead保存为配置观察；Pod自身的资源值来自其实际UID回读。跨对象读取不是原子快照，不伪造Pod采用了某一RuntimeClass版本的证明。采用受管理的不可变版本配置和创建/回读复核；配置变化、UID替换或证据冲突拒绝登记或保持UNKNOWN。停止和清理仍允许依据原可信终止证据进行，不能被当前RuntimeClass变化卡住。

数据库新增append-only合同、Pod观察和配额状态回执，使用复合FK、唯一launch/Pod及有界数量约束，FORCE RLS。原迁移字节保持，当前0044后的新迁移编号在实施时重新核对。旧launch没有足够证据时返回明确缺证据；不能按今天的Flavor、overhead或更新时间补造历史。

## 实现与开发验收表

| 顺序 | 需要开发什么 | 技术落点与完成条件 |
| --- | --- | --- |
| 1 | 确定可归一化的CPU/内存数量、来源与缺证据状态 | **数量/provision校验已实现，来源与缺证据模型待开发。** 新`runtime_resource_contract`深模块接入实际生成、创建前/回读后和RuntimeClass入口；工作负载支持原CPU、memory、ephemeral-storage三个键，overhead只允许CPU/memory，拒绝负数、溢出、额外设备和sidecar。后续用户请求、实际调度资源、配额授权额和宿主上界用不同类型/字段表示，不能把当前校验值当历史证据。 |
| 2 | 不可变launch请求与配额回执 | 新迁移、真实quota INSERT/status UPDATE的同事务捕获。CREATE/START在实际资源申请时记录新合同；RESTART受理时不提前记录，新合同属于可信终止后真正申请的新generation/launch，renew不新增。PENDING和资源申请同提交，tenant/project scope分列不相加。详见下方时序与升级合同。 |
| 3 | 受控RuntimeClass配置与Pod资源回读 | `runtime`/`runtime_manifest`/`worker`保存版本配置观察并校验实际Pod资源。UID或值冲突拒绝；无法建立一致证据时UNKNOWN，不回填当前值。保持原CRI许可、节点/卷归属和期限。 |
| 4 | 可信观察登记 | `gateway_runtime`、`termination_runtime`把已校验的Pod资源带入原许可登记事务；沿用workspace→instance→operation/node fence顺序。同UID相同内容幂等，冲突拒绝，COMMIT ACK丢失复用原登记。API/普通调用者不能伪造登记。 |
| 5 | 完整释放历史 | `mark_ready`与原ALLOCATED事务同提交；可信cleanup的真实RELEASED状态变化和回执同提交。never-authorized先永久关闭、后独立事务实际释放，只有关闭证据时不提前写RELEASED。TTL、Pod缺失、CRI返回、API退出、节点失联不能直接结束预留。 |
| 6 | 最小权限与启动门禁 | 各角色SQL仅增实际调用所需权限；API只读，admission仍只读。缺迁移、旧校验和不符、缺grants或部分部署均启动拒绝；不能捕获启动失败后降级成成功。 |
| 7 | 对外只读API、SDK与实例页面 | 按实例/launch有界分页，以`instances:read`检查租户/项目及查询前后撤权/epoch。返回请求来源、Pod观察时间、配额状态和UNKNOWN。SDK生成与正式OpenAPI一致；切scope、撤权、缺测后清除旧数据。 |
| 8 | 真实事务和HTTP验收 | 独立TLS PostgreSQL、正常迁移及普通角色；测试CREATE/START/RESTART/renew/stop/delete、未授权launch删除、并发登记/回滚/丢ACK、旧generation/epoch/boot、慢查询期间撤权与升级旧历史。Kubernetes响应可用明确合同fixture验失败边界，真实Kata资源对应仍须节点实机验收。 |

每一步仅在其事务、不变式和失败验收通过后完成；不能只凭schema存在、HTTP 200或控制台展示标记整个工作包完成。发布走源码绑定CI及既有签名、安全、回滚和离线安装门禁。

## 第2步的事务时序与升级合同

当前代码的RESTART在写入新generation/launch之前申请配额（`src/termination_ledger.rs`）；捕获PENDING时不能绑定instance当时的旧launch。CREATE先插入instance，再插operation及配额，birth也不能作为合同的必需先决记录。普通CPU请求、隔离备份CPU/MEM、执行/文件及工作区配额要分别保存purpose；仅凭dimension或resource_id不能判断是普通VM申请。

推荐保留原业务写法和锁顺序，在真实quota INSERT及status UPDATE安装同事务捕获。普通新申请的完整性与新launch归属用有界、延迟到COMMIT前的约束检查；使用该次INSERT的NEW身份、金额及origin operation，核对最终新generation/launch和四条CPU/MEM scope记录。每次INSERT/状态变化立即保留当次NEW/OLD、account version及limit快照，延迟检查只负责归属与完整性，不能只读最终account/status而丢PENDING。RESTART同一COMMIT要分别得到旧合同的RELEASED与新合同的PENDING，旧释放按原reservation合同及可信证据关联。延迟触发器方案仍需真实PostgreSQL验收，尚未实现。

所有quota purpose的回执保留实际reservation/account/origin operation及单位、scope、金额、limit和account version。request合同只绑定有准确普通CPU申请来源的记录；backup等保持独立purpose。新ordinary申请缺合同应拒绝事务，不能当旧历史放过。升级不补造旧PENDING、开始时间或launch配置；旧row升级后实际发生的ALLOCATED/RELEASED可记当前事实，并明确HISTORY_START_NOT_CAPTURED/LEGACY_UNBOUND。合同不FK到instance可变的当前generation/launch。迁移必须冻结不可由runtime改写的原reservation ID基线来识别旧历史，不能按缺合同、客户端时间或当前created_at把新申请放行为LEGACY。reservation身份、金额、origin operation及account一经申请不得漂移，状态图限PENDING→ALLOCATED/RELEASED及ALLOCATED→RELEASED，RELEASED终态；保持status不变的非法字段改写也必须拒绝。

never-authorized的永久关闭和实际释放是两个事务：第一事务仅有closure，第二事务真实完成状态变化后才产生RELEASED。STOP/RESTART、执行完成、文件退出、volume删除和backup完成的真实writer都必须覆盖，且保留各自原证据规则。触发器固定search_path、使用schema限定对象，PUBLIC不可任意执行；回执append-only、FORCE RLS，API等普通角色对新增账本表只读，保留原quota业务写权限。新增检查不能在quota锁之后反向取得workspace/instance锁，也不能靠自报GUC伪造租户或释放证明。

SQL自动捕获须覆盖所有真实writer，但原0044版本的Rust启动检查允许额外迁移，也不认识新增trigger，不能承诺未升级binary能发现未来trigger停用。第2步首发采用受控维护窗口，禁止未经兼容认证的旧writer混跑：暂停写入口和claim，停止旧writer并核实自有进程、活动租约及数据库会话收尾；正常owner应用新迁移及grants；由新版本preflight核对schema、trigger、校验和及权限；部署入口只允许对应已审核发行摘要并防止旧writer重新启动，再恢复写入口。部署门须真实执行并验收，不能只写操作说明。任何一步失败保持维护状态，不回退运行不具备资源guard的旧binary。若以后采用滚动升级，须先发布兼容guard或强制部署启动门，并单独验证N−1/N混跑及trigger停用拒绝；本次不提前承诺。

新版本缺迁移、校验和错误、trigger停用/替换、部分schema或缺权限时在bind/claim前拒绝启动。新API/SDK/outbox数量字段使用十进制字符串，保留超过JavaScript安全整数的精度；不把BIGINT直接转Number。旧三Flavor接口保持兼容。

落地验收必须使用正常迁移及普通角色的独立TLS PostgreSQL，覆盖CREATE/START/RESTART queued与blocked、renew、ready/STOP、already-STOPPED DELETE仅释放INSTANCES而不重复CPU/MEM、never-authorized两事务崩溃、exec/file/volume/backup实际释放、锁等待回滚、真实COMMIT ACK丢失与原键重放、并发旧代/epoch撤销及0044历史升级、维护窗口内旧writer排空与拒绝重启。再验证跨租户FK/RLS与禁写、缺scope或冲突金额拒绝、禁用trigger启动拒绝，以及9007199254740993和i64_MAX的JSON逐字往返。这些检查通过前，第2步仍为未交付，不能展示历史利用率或开启自动调档。

## 随后推进快速启动和GPU

资源账本交付后，再开发有预算、到期、撤销和GC合同的镜像/节点预准备。分开观测accepted、queue、placement、镜像准备、CRI调用、VM readiness、route及首次正确执行；以端到端成功任务测冷暖p50/p95/p99、峰值并发、失败率和单位成功任务成本。预准备本身的空闲占用、镜像体积、实际释放证明须可计量；没有节点实测前不承诺启动毫秒数或资源节省比例。

GPU先开发真实设备身份、独占租约、Pod/VM/租户归属、显存与计算利用率采集及可信回收。不得把显存占用率当计算利用率；设备未运行、采集失败及归属丢失用UNKNOWN。随后在实际支持的硬件/驱动上验MIG、时间共享等隔离与资源合同，覆盖撤权、节点重启、故障恢复和数据残留。没有本机GPU不能用CPU fixture签发GPU性能、隔离或成本认证。
