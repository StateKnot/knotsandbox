# 逐次启动资源账本：下一完整交付方案

最新开发检查点（2026-10-16，P1b6快照与配置引用元数据）：新增公共inspect_snapshot／本机admin inspect-snapshot，认证DiffID派生ChainID／直接父链，固定overlayfs的Stat与config引用标签前后核对；原固定UDS／k8s.io及5秒总预算保持。最终普通Rust65程序520通过／0失败／291环境ignored、两平台严格Clippy／fmt、新快照加五项原生回归、离线Docker CLI七场景通过；release104及协议重生成、实际Linux许可producer／四Docker COPY路径56文件通过。首轮CLI格式失败保留，格式修正后最终制品已重新构建并完整回归。基线ee3eeac精确CI五job／72step全绿，新提交CI独立核对。空committed快照也可通过本检查，故不证明真实层apply、GC保护、pull选择或准备许可。下一完整门为受限准备执行者／硬限、实际pull及原生保护闭包；pre-pull仍关闭，云／Kata／CSI／GPU／性能未认证。见[本批交付](snapshot-reference-metadata-delivery-20261016.md)。

前序开发检查点（2026-10-16，P1b5 CRI当前索引身份）：新增root本机 `image-artifact inspect-cri`，同一固定UDS／k8s.io／原5秒总预算核对前后CRI精确引用、已验OCI config摘要及最终原生根；回执仅为CRI索引配置身份，所有审批／pull选择／handler／snapshotter／unpack／GC／准备标志为false。普通Rust65程序513通过／0失败／291环境ignored，两平台严格Clippy／fmt、Python11、实际新CRI及四项原生回归、旧Docker CLI七场景通过。真实测试发现的本地超时分类缺陷已按typed TimeoutExpired修复，精确RED／GREEN及远端同文案Cancelled反例保留；首轮编译OOM已恢复前轮原swap配置并降编译并发后通过，不扩大功能期限／权限／栈。基线e3debc5精确CI五job／71step全绿，本片提交CI独立核对。完整P1的实际pull选择／snapshotter、原生引用／GC及准备硬限与P2—P6仍待完成，pre-pull关闭；云／Kata／CSI／GPU／性能未认证。见[本批交付](cri-image-identity-delivery-20261016.md)。

前序开发检查点（2026-10-16，P1b4原生已存元数据）：新增root本机 `image-artifact inspect-native`，固定UDS／k8s.io，原生Get／Info／Read与原离线命令共享OCI验证，5秒I/O预算、1MiB单块／3MiB元数据，前后根身份核对；不读层、不pull／unpack／写lease或签发准备许可。普通Rust65程序509通过／0失败／291环境ignored、两平台strict Clippy／fmt、最终真实native CLI及三项原生回归、旧Docker CLI七场景均通过。新增协议许可已接当前manifest v4／原签名与安装链，历史v3含义保持；release100项及实际Linux producer／Docker四路径48文件通过，独立最终审查Standards累计1项P2已修复／遗留0项，Spec发现0项。基线32910f0精确CI五job／69step全绿，新提交CI独立核对。实际CRI pull选择、引用／GC和硬限、P2—P6及云／Kata／CSI／GPU／性能仍待完成，pre-pull关闭。见[本批交付](native-image-metadata-delivery-20261016.md)。

前序开发检查点（2026-10-16，P1b3重连身份与请求排空）：固定root UDS以目录／socket对象FD及SO_PEERCRED的PID／start绑定，CRI与镜像观察复用算法、各自持有身份。CRI重连冲突进入永久拒绝，沿既有任务门阻止新CRI／CONTROL并取消纯读；不清SQLite coverage或释放资源／配额。普通Rust65程序501通过／0失败／291环境ignored、Python11、两平台严格all-target Clippy／fmt通过；最终Linux制品的重连、启动配置和原生镜像mTLS三个case各1项通过，自有资源清理及源码／制品稳定已核。0755夹具失败、计数断言缺口与ready发布竞态均修复并保留事实。基线cb47bc9精确CI五job／68step全绿，新提交CI独立核对。该片不证明daemon二进制／持续配置或真实PID复用，不产生准备许可；完整P1硬限／引用、P2—P6及云／Kata／CSI／GPU／性能仍待完成，pre-pull关闭。见[本批交付](runtime-peer-binding-delivery-20261016.md)。

状态：**第4步普通CPU可信观察已完成本地验收；37组201项按最终制品分两批通过，已公开；基线18ad317的CI 5 job/62 step已通过。** 当前对外支持可信 `KUBERNETES_API_READBACK` 加非空观察，缺证据保持 `NOT_CAPTURED` 加null。普通原生461项、SDK77项、资源账本Chrome8项、新DB8项＋HTTP组合1项、实际维护及生产镜像各自通过；分批结果不称单轮全跑，也不等于生产上线认证。前轮0045账本单轮27组164项、第3步35组192项分批记录均保留其原范围；恢复草稿仍未计验收。当前实现与最终本地验收范围见[可信观察交付](trusted-launch-resource-observation-20261015.md)，原回读及账本记录分别见[第3步](runtime-class-resource-readback-20261015.md)与[第2/5步](launch-resource-accounting-delivery-20261015.md)。利用率、自动调档、预热和GPU仍未完成。

后续进展（2026-10-16）：节点镜像P0b的发布dcb7554精确CI 5 job/62 step已通过；本轮P0c1持久安装读授权／永久撤权、owner CLI、普通app/JWT授权检查完成本地验收。46条正常迁移及原45条不变、6专项、6组29 PG、正式自动化25、普通Rust475、SDK77均已验。它不代表启动利用率或完整节点查询已完成，P0c2及同一原生整链继续待开发。见[本批交付](installation-operator-access-delivery-20261016.md)。

后续进展（2026-10-16，P0c2b）：同一原生containerd→scraper mTLS→双Agent remote-write→实际receiver→operator API／admin八阶段整链已本地验收，最终v5主链82.876秒；原始scrape时间／collector报告推进、RPC失败／失联清旧、在途撤权与新grant原期限均通过。基线8e1fbbc的精确CI 5 job／62 step已通过，新提交CI另核；下一项为P1平台／原生引用和硬限组合，pre-pull／GPU／物理缓存与收益认证仍未完成。早期失败及匿名卷归属限制见[本批交付](native-image-chain-delivery-20261016.md)。

最新后续检查点（2026-10-16，P1a）：离线OCI元数据公共模块与实际admin CLI已完成11项真实进程测试、Linux Docker七场景验收。固定expected digest／精确平台及元数据描述符一致性已实现，回执明确不查审批、不验层载荷、不授权准备；三项审查缺陷已修复并保留失败证据。基线57d1689精确CI 5 job／64 step全通过，本批CI独立核对。下一项是P1b运行时绑定／原生引用与硬限；pre-pull、GPU、物理容量与性能收益仍未认证，见[本批交付](image-artifact-delivery-20261016.md)。

最新后续检查点（2026-10-16，P1b1）：实际安装plan／collect的受支持镜像运行时组合与相同读取字节认证已完成本地验收。14项Python、原版上游完整模板和默认Docker入口20实际CLI／40日志通过；配置换档真实FD屏障拒绝登记、目录FD输出及自有清理已核。基线0721699精确CI 5 job／65 step成功，本批CI另核。它仅证明配置与身份，实际daemon读回、pull／unpack、原生引用和硬限仍待推进，不增加VM或GPU配额、容量和收益声称。见[本批交付](host-image-runtime-profile-delivery-20261016.md)。


前序开发检查点（2026-10-16，P1b2启动时runtime读回）：`CriProxy::verify_startup` 在版本核对后、原sandbox／进程覆盖恢复及开放登记前，沿原固定UDS执行有界 `Status(verbose=true)`。固定目录／endpoint、默认runc／两个handler、Kata ConfigPath／类型与安全选项冲突或缺失保持Closed，不输出原配置。普通Rust 65程序501通过／0失败／291环境ignored，其中新增4项含真实gRPC与原5秒deadline；Python runner 11项、Mac／Linux严格all-target Clippy及fmt通过。真正containerd 2.3.5的本地Linux arm64正反例与原生镜像mTLS回归各1项通过，源码／制品不变及自有容器／镜像清理确认。基线686b9b8精确CI 5 job／67 step全通过，本批CI另核。该片仅验证本次启动的runtime配置子集，沿用受控root UDS信任，不证明daemon PID／二进制、持续漂移、images／NRI状态或Kata能力；pull／unpack、原生引用／GC、硬限和GPU／云／CSI／性能仍待验收。见[本批交付](runtime-profile-startup-delivery-20261016.md)。

## 数据与身份合同

必须分别保存四种来源：受理时的用户规格；每次launch实际请求合同；经可信登记方回读的Pod request/limit/overhead；现有配额账的PENDING、ALLOCATED、RELEASED回执。宿主cgroup共享祖先的容量上界仍是独立观测，不能与其中任何一项直接等同。

合同绑定tenant、project、instance、workspace、generation、launch与安装epoch。实际Pod观察再绑定Pod UID、Node UID、节点boot身份和登记许可。RuntimeClass的UID、resourceVersion及overhead保存为配置观察；Pod自身的资源值来自其实际UID回读。跨对象读取不是原子快照，不伪造Pod采用了某一RuntimeClass版本的证明。采用固定kata-qemu和真实VAP/Binding保护受控配置，当前配置身份是Class UID加规范化受控内容SHA-256；resourceVersion仅表示本次回读元数据。创建/回读前后核对守卫、Class及完整Pod UID/spec/resources，纯RV或status变化不等于资源漂移。配置变化、UID替换或证据冲突拒绝验证；只有通过原子可信登记的回读才成为历史观察，缺观察旧launch不由当前配置回填。停止和清理仍允许依据原可信终止证据进行，不能被当前RuntimeClass变化卡住。Kubernetes v1.35并未天然将整个Class配置设为不可变，缓存admission也不提供adopted RV证明，官方源码依据见[回读设计](runtime-class-resource-readback-20261015.md#官方行为与实现依据)。

0045已新增append-only请求合同、配额状态回执、精确普通启动绑定与冻结旧预约基线；0046再增加不可变Pod观察及封闭旧授权ACK基线，复合FK、有界数量和FORCE RLS保持。原44条迁移字节不变，第4步当时正式迁移为1..37加39..46，共45条，0038仍未发布。只有切换前真实提交的base/extension ACK能进入新冻结基线，旧permit或缺观察本身不能获得历史豁免。旧launch没有足够证据时返回明确缺证据；不能按今天的Flavor、overhead或更新时间补造历史。

## 实现与开发验收表

| 顺序 | 需要开发什么 | 技术落点与完成条件 |
| --- | --- | --- |
| 1 | 确定可归一化的CPU/内存数量、来源与缺证据状态 | **数量、来源及缺证据模型已实现，并随第4步完成本地验收。** `runtime_resource_contract`接入实际生成、创建前/回读后和RuntimeClass入口；工作负载支持CPU、memory、ephemeral-storage，overhead只允许CPU/memory，拒绝负数、溢出、额外设备和sidecar。申请为`REQUESTED_COMPUTE_QUOTA`，持久可信观察为`KUBERNETES_API_READBACK`，缺观察为`NOT_CAPTURED`+null；当前值不能替代历史。 |
| 2 | 不可变launch请求与配额回执 | **已实现并完成本地整轮验收。** 0045真实quota INSERT/status UPDATE同事务捕获全部purpose。CREATE/START在真实新身份提交时记录合同；RESTART受理时不提前记录，旧release后新generation/launch延迟精确归属；renew不新增。PENDING和申请同提交，tenant/project scope分列不相加。已验真实0044→0045维护切换，相关用例纳入最终50候选单轮27组164项PASS；旧候选失败保留。 |
| 3 | 受控RuntimeClass配置与Pod资源回读 | **普通CPU实时校验子项已开发并本地验收。** 真实VAP/Binding锁住kata-qemu配置更新/删除；逐字段GET核对、UID与配置摘要前后复核，创建后独立GET实际Pod，完整request/limit/overhead与总和溢出校验；provision允许首次调度、gateway固定节点。35组192项分批、真实本地Kubernetes及459原生通过；恢复草稿未到restored START，兼容性未计通过。持久观察属于第4步。 |
| 4 | 可信观察登记 | **已实现并完成本地验收；37组201项分两批、专项、维护及生产镜像门通过。** runtime内部校验能力进入正式mTLS授权登记，ACK与观察原子提交；精确Node/boot/epoch/permit、Class配置与Pod资源独立保存。冻结旧ACK基线、同内容幂等／冲突拒绝、真实COMMIT ACK丢失重放、过期旧ACK拒绝均已验；签名分页固定观察ID或首次缺失状态。普通API不能伪造登记。见[本轮交付](trusted-launch-resource-observation-20261015.md)。 |
| 5 | 完整释放历史 | **账本子项已实现并完成本地整轮验收。** `mark_ready`与原ALLOCATED同事务捕获，可信cleanup的RELEASED变化和回执同提交。新ordinary释放校验原launch proof+cleanup或持久never-authorized关闭；never-authorized两事务不提前释放。TTL、Pod缺失、CRI返回、API退出、节点失联不能直接结束预留。 |
| 6 | 最小权限与启动门禁 | **0045整轮证据保留；0046新表／函数／维护专项和本轮完整分批矩阵通过。** API只读合同、回执、绑定和观察；runtime禁写观察表、禁读遗留基线，只有termination经窄入口原子登记。缺迁移/checksum、表形状/RLS/trigger/function/grants漂移在bind/claim前拒绝。真实0045→0046维护门已通过准入封闭、排空、正常迁移、普通app预检和新进程恢复，不承诺N−1/N混跑。 |
| 7 | 对外只读API、SDK与实例页面 | **可信观察展示已实现并通过SDK77项、资源账本Chrome8项及真实HTTP组合专项。** 原`instances:read`前后撤权／身份复核保持；签名页固定观察ID／首次缺失和current launch/generation。十进制字符串保19位，bytes与MiB分列；失败／撤权／scope变化清空，未知不填零。API／SDK／UI协同升级，旧资源游标丢弃并从第一页重读；无利用率／GPU声称。 |
| 8 | 真实事务和HTTP验收 | **PASS_BATCHED_FINAL_ARTIFACTS：37组201通过／0失败／0ignored，明确分两批。** 独立TLS PostgreSQL、正常迁移、普通角色、真实mTLS／JWT／HTTP／Node SDK与非空旧ACK冻结已覆盖核心合同；前9组42项加后28组159项，两批间仅历史升级测试及其独立程序变化，其他源码／制品／SDK逐SHA稳定、各批自有清理确认；原生461、新8＋1、维护和生产镜像另行通过。45条正常迁移及具体摘要见最终回执。原0045的50候选单轮27组164项是前轮证据，不冒充本轮完整结果；真实Kata／云／GPU仍需实机认证。 |

每一步仅在其事务、不变式和失败验收通过后完成；不能只凭schema存在、HTTP 200或控制台展示标记整个工作包完成。发布走源码绑定CI及既有签名、安全、回滚和离线安装门禁。

## 第2步的事务时序与升级合同

当前代码的RESTART在写入新generation/launch之前申请配额（`src/termination_ledger.rs`）；捕获PENDING时不能绑定instance当时的旧launch。CREATE先插入instance，再插operation及配额，birth也不能作为合同的必需先决记录。普通CPU请求、隔离备份CPU/MEM、执行/文件及工作区配额要分别保存purpose；仅凭dimension或resource_id不能判断是普通VM申请。

已保留原业务写法和锁顺序，在真实quota INSERT及status UPDATE安装同事务捕获。普通新申请的完整性与新launch归属延迟到COMMIT前检查；使用该次INSERT的NEW身份、金额及origin operation，核对最终新generation/launch和四条CPU/MEM scope记录。每次INSERT/状态变化立即保留当次NEW/OLD、account version及limit快照，延迟检查只负责归属与完整性，不只读最终account/status而丢PENDING。RESTART同一COMMIT分别得到旧合同的RELEASED与新合同的PENDING，旧释放按原reservation合同及可信证据关联。该延迟触发器已在普通角色的真实PostgreSQL专项验收；等待延迟检查时调用者切换tenant上下文也不能绕过归属完整性。

所有quota purpose的回执保留实际reservation/account/origin operation及单位、scope、金额、limit和account version。request合同只绑定有准确普通CPU申请来源的记录；backup等保持独立purpose。新ordinary申请缺合同应拒绝事务，不能当旧历史放过。升级不补造旧PENDING、开始时间或launch配置；旧row升级后实际发生的ALLOCATED/RELEASED可记当前事实，并明确HISTORY_START_NOT_CAPTURED/LEGACY_UNBOUND。合同不FK到instance可变的当前generation/launch。迁移必须冻结不可由runtime改写的原reservation ID基线来识别旧历史，不能按缺合同、客户端时间或当前created_at把新申请放行为LEGACY。reservation身份、金额、origin operation及account一经申请不得漂移，状态图限PENDING→ALLOCATED/RELEASED及ALLOCATED→RELEASED，RELEASED终态；保持status不变的非法字段改写也必须拒绝。

never-authorized的永久关闭和实际释放是两个事务：第一事务仅有closure，第二事务真实完成状态变化后才产生RELEASED。STOP/RESTART、执行完成、文件退出、volume删除和backup完成的真实writer都必须覆盖，且保留各自原证据规则。触发器固定search_path、使用schema限定对象，PUBLIC不可任意执行；回执append-only、FORCE RLS，API等普通角色对新增账本表只读，保留原quota业务写权限。新增检查不能在quota锁之后反向取得workspace/instance锁，也不能靠自报GUC伪造租户或释放证明。

SQL自动捕获须覆盖所有真实writer，但原0044版本的Rust启动检查允许额外迁移，也不认识新增trigger，不能承诺未升级binary能发现未来trigger停用。第2步首发采用受控维护窗口，禁止未经兼容认证的旧writer混跑：暂停写入口和claim，停止旧writer并核实自有进程、活动租约及数据库会话收尾；正常owner应用新迁移及grants；由新版本preflight核对schema、trigger、校验和及权限；部署入口只允许对应已审核发行摘要并防止旧writer重新启动，再恢复写入口。部署门须真实执行并验收，不能只写操作说明。任何一步失败保持维护状态，不回退运行不具备资源guard的旧binary。若以后采用滚动升级，须先发布兼容guard或强制部署启动门，并单独验证N−1/N混跑及trigger停用拒绝；本次不提前承诺。

新版本缺迁移、校验和错误、trigger停用/替换、部分schema或缺权限时在bind/claim前拒绝启动。新API/SDK/outbox数量字段使用十进制字符串，保留超过JavaScript安全整数的精度；不把BIGINT直接转Number。旧三Flavor接口保持兼容。

落地验收使用正常迁移及普通角色的独立TLS PostgreSQL，覆盖CREATE/START/RESTART queued与blocked、renew、ready/STOP、already-STOPPED DELETE仅释放INSTANCES而不重复CPU/MEM、never-authorized两事务崩溃、exec/file/volume/backup实际释放、锁等待回滚、真实COMMIT ACK丢失与原键重放、并发旧代/epoch撤销及0044历史升级、维护窗口内旧writer排空与拒绝重启；同时核对跨租户FK/RLS与禁写、缺scope或冲突金额拒绝、禁用/替换trigger启动拒绝，以及9007199254740993和i64_MAX的JSON逐字往返。原0045选中批次、v2/v3/49候选失败及test-only注入阶段修复见[账本交付记录](launch-resource-accounting-delivery-20261015.md)。第2/5步与相关6/7/8账本子项的前轮整体验收及其27组164项保留；本轮第4步专项、0045→0046维护、生产镜像及37组201项最终制品分批通过，具体回执见[可信观察交付](trusted-launch-resource-observation-20261015.md)。早期并发503/timer原因仍UNKNOWN，新提交CI、历史利用率／自动调档及真实Kata／云／GPU仍为独立后续门。

## 随后推进快速启动和GPU

资源账本交付后，再开发有预算、到期、撤销和GC合同的镜像/节点预准备。分开观测accepted、queue、placement、镜像准备、CRI调用、VM readiness、route及首次正确执行；以端到端成功任务测冷暖p50/p95/p99、峰值并发、失败率和单位成功任务成本。预准备本身的空闲占用、镜像体积、实际释放证明须可计量；没有节点实测前不承诺启动毫秒数或资源节省比例。

GPU先开发真实设备身份、独占租约、Pod/VM/租户归属、显存与计算利用率采集及可信回收。不得把显存占用率当计算利用率；设备未运行、采集失败及归属丢失用UNKNOWN。随后在实际支持的硬件/驱动上验MIG、时间共享等隔离与资源合同，覆盖撤权、节点重启、故障恢复和数据残留。没有本机GPU不能用CPU fixture签发GPU性能、隔离或成本认证。

后续进展（2026-10-16，P0c2a）：当前安装授权下的单节点镜像固定查询／HTTPS admin读消费者已完成本地验收；原始报告新鲜度、最新单副本整cohort和失败清旧保持，独立两个查询槽不占VM八槽。真实Prom四场景、真实PG／OIDC／HTTPS十项及既有账本／历史升级回归通过；不把node运行时报告作为VM利用率分母或物理缓存容量。该子项交付时P0c2b同一原生整链待验；随后已通过，见上方P0c2b进展与[P0c2a交付](node-image-query-delivery-20261016.md)。
