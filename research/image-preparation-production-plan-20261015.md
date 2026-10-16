# 批准OCI镜像的节点预准备：生产实施计划

状态：**P0a—P0c2b只读观察及同一原生整链、P1a元数据校验、P1b1宿主配置准入、P1b2启动时runtime读回已完成本地验收；完整P1及P2—P6仍未完成／未认证。** 本文件承接[开发表12.7](rust-sandbox-development-workbreakdown.md#127-可信启动资源观察与原子登记2026-10-15)的可信资源账本；基线686b9b8的精确CI run38830234782，5 job/67 step已通过，当前按以下依赖推进；新源码CI单独核对。
范围仅为批准OCI镜像在准确节点／运行时中的有预算准备，不创建CPU／GPU VM池，不产生用户进程、工作区或普通launch许可。
每90分钟是触发间隔，不是开发或验证超时；先接续已有在途工作，再持续完成选中的可验证切片，不因下一次触发重复启动。
失败保存原现场并继续闭合该切片，不能因触发次数或时间到而标记通过，也不能跳过前置门开放拉取。


最新开发检查点（2026-10-16，P1b2启动时runtime读回）：`CriProxy::verify_startup` 在版本核对后、原sandbox／进程覆盖恢复及开放登记前，沿原固定UDS执行有界 `Status(verbose=true)`。固定目录／endpoint、默认runc／两个handler、Kata ConfigPath／类型与安全选项冲突或缺失保持Closed，不输出原配置。普通Rust 65程序501通过／0失败／291环境ignored，其中新增4项含真实gRPC与原5秒deadline；Python runner 11项、Mac／Linux严格all-target Clippy及fmt通过。真正containerd 2.3.5的本地Linux arm64正反例与原生镜像mTLS回归各1项通过，源码／制品不变及自有容器／镜像清理确认。基线686b9b8精确CI 5 job／67 step全通过，本批CI另核。该片仅验证本次启动的runtime配置子集，沿用受控root UDS信任，不证明daemon PID／二进制、持续漂移、images／NRI状态或Kata能力；pull／unpack、原生引用／GC、硬限和GPU／云／CSI／性能仍待验收。见[本批交付](runtime-profile-startup-delivery-20261016.md)。

## 当前事实与来源门

当前nodeguard已有独立scraper-client CA保护的`/metrics`及固定containerd UDS配置，原有VM指标从可信journal绑定launch。
原VM job的Prometheus重标记要求tenant／instance／generation，节点样本须走已新增的独立job；不能给每台VM复制同一份节点镜像占用。
模板审批保存repository与SHA-256 digest。P1a已提供离线expected index→唯一精确平台manifest→config元数据校验，独立CLI不查询审批、不读取层载荷，也不产生准备权限。审批与运行时闭包绑定、准备租约、物理存储预算和回收账本仍未完成。
相关真实源码为[`metrics_server.rs`](../src/nodeguard/metrics_server.rs)、[`CRI模块`](../src/nodeguard/cri.rs)、[`观测部署`](../deploy/observability/observability.py)、[`模板入口`](../src/admin.rs)和[`版本锁`](../deploy/cluster/versions.lock.json)。

第一切片准确称为“CRI snapshotter报告使用量／镜像库存基线”，不能称完整镜像缓存物理采样。
固定containerd2.3.5源码的`ImageFsInfo`只聚合snapshotStore统计，content store占用仍为TODO；不能据此得到总imagefs使用量、capacity或available。
其snapshot统计包含active对象，也存在复用旧Usage、失败跳过及缺省零记录的行为；返回timestamp不是完整性证明，协议没有completeness字段。
`ListImages`来自runtime内存索引，存在snapshot是否仍在的检查缺口；size是平台选择后的压缩镜像逻辑量，共享层不能重复计物理用量，`pinned`也不是本产品GC证明。
基线只输出明确标注runtime-reported的聚合值及不透明FS身份，完整性、cache total、capacity、available、reclaimable和实际释放量保持UNKNOWN。
接口来源固定为`RUNTIME_REPORTED`，并单独注明snapshotter报告范围和完整性UNKNOWN，不与普通launch的`KUBERNETES_API_READBACK`配置证据混用。
`observation_success`仅表示RPC／形状／绑定身份校验成功，不能解释为存储全量采样成功，更不能直接用作硬预算准入。
固定版本的官方来源与待核实项见[原生镜像来源调查](image-preparation-native-sources-20261015.md)；P0c1授权基础见[本批交付](installation-operator-access-delivery-20261016.md)；P0c2a固定查询／admin消费者见[交付](node-image-query-delivery-20261016.md)，同一原生整链仍待验；后续准备接口仍为方案。
目标版本取仓库锁定的containerd／Kubernetes／snapshotter组合；锁版本、实际backend配置及官方来源三者不符时停止，不猜测某个RPC或插件支持。

## 端到端接口与身份

只读链路：nodeguard固定后端→有界节点观察→原scraper CA／同Prometheus双Agent→独立节点allowlist与查询→安装级operator消费者。
准备链路：operator授权的批准策略→PG持久准备意图与预算→精确node／boot的可信宿主代理→原生内容／快照引用→确认回执→调度后命中观察。
回收链路：到期／撤销停止新引用→排空本产品准备任务→复核引用与lease→释放自己的保护引用→原生GC及物理回读→结清可证实的预算。

准备身份固定installation／cluster epoch、Node UID、boot ID、runtime profile摘要、containerd namespace、snapshotter及平台；名字或IP不作为所有权。
制品身份固定审批版本、registry repository、批准index digest（单manifest时明确无index）、选中manifest digest、config／layer descriptor闭包及`os/architecture/variant`。
拒绝tag作为执行身份、平台不匹配、歧义选择、摘要／长度冲突及超限descriptor；registry返回同名内容不能替换批准摘要。
凭据只以短时、最小repository权限的引用进入可信宿主路径；token、Docker config、认证头及registry原始错误不进SQL普通字段、日志、metrics或API。

新增`ImagePreparationAuthorization`为独立、短时、可撤销能力，绑定策略版本／节点身份／制品／预算／动作／request ID与fencing token。
它不能转换为`LaunchPermit`，不能放行CRI RunPodSandbox、CreateContainer或执行；公开API也不能组合出普通启动许可。
准备任务和用户启动分别授权；撤销缓存准备不自动停止已合法运行的实例，镜像安全撤销仍经既有模板／策略与安全停止流程。

安装级operator身份必须由可信issuer／subject和显式持久授权确定，普通租户不能通过传一个installation ID变成安装管理员。
operator读／管理权限分开，授权变更可审计且每次读取前后重新核对；API采用正常非owner数据库角色和窄查询，不复用迁移登录。
公开租户视图若以后需要，只显示该租户自己的策略／账务；全节点库存汇总和其他租户存在性不能沿实例接口泄露。
P0c1安装授权、P0c2a固定单节点查询／admin和P0c2b同一原生整链已本地验收；不开放节点枚举或任意查询。

## 第一个完整切片：节点只读基线

1. 在nodeguard同一进程中增加只读collector，使用固定受控containerd UDS，不接受远端地址或调用者指定socket。
2. 对`ImageFsInfo`与`ListImages`设置独立超时、并发槽、解码字节／镜像数上限和取消收尾；到上限返回明确不完整，不能将截断值当全集。
3. 文件系统路径仅供宿主内部核验；同FD、device／inode、mount identity前后复核，并绑定Node UID／boot／profile／epoch；对外仅稳定不透明ID。
4. 固定输出RPC／身份观察成功、原报告时间、runtime-reported镜像条目数／逻辑大小及snapshotter报告bytes／inodes；每项独立缺测，完整性UNKNOWN，无VM时也可读，不能拿路径或repository作label。
5. 新增独立node metric allowlist／relabel，保留原VM身份过滤；同一Prometheus与双Agent复用，不新建TSDB，不把HA副本相加。
6. 重新计算每节点／全安装样本、响应正文、抓取、remote-write及WAL预算；计入原磁盘阈值和失联告警，不挤掉已有VM必需样本。
7. 固定operator查询或`sandbox-admin node-image-status`消费正常服务读接口；安装级OIDC机器身份加持久授权／实时撤销，不能借`instances:read`读取全节点。
8. operator响应保留原样本时间／boot／profile和UNKNOWN；失败、撤权、scope／epoch变化清除旧值，不展示“可释放空间”或利用率百分比。

本切片只有读，不拉取或删镜像；必须连同真实operator消费者、安装授权、部署配置和失败验收一起交付，不能止于无消费者的指标。
容量／硬预算还没建立之前，部署不得启用后台pre-pull；只读基线不是准备成功或物理回收证明。
原VM抓取deadline和必需样本不能因节点collector而放宽；后台采集使用独立有界槽、取消和缓存，scrape只输出原观察时间与当前有效性。
失败不能继续发布旧成功标记；collector重启、boot／profile切换及超龄都使原基线失效，Prometheus旧样本仍须被查询端新鲜度门排除。
不透明FS身份从受控节点／boot／mount身份派生，原路径只在宿主内部使用；数量上限与允许的snapshotter来自受控profile，不能无限增label。

## 后续实施顺序与退出门

以下文件名为拟新增落点，正式命名在实现前按领域词汇核对；已有模块保持深接口，不为每种backend先造通用框架。

| 顺序／依赖 | 开发文件与接口 | 必须验收 | 退出门 |
| --- | --- | --- | --- |
| P0a宿主子项已本地验收；后续P0c2b同链也已通过 | `src/nodeguard/image_observation.rs`；接`metrics_server.rs`／固定UDS，只读有界collector及scraper mTLS诊断；见[本批交付](node-image-observation-delivery-20261015.md) | 正常／空镜像／无VM、超大响应、超时、取消、身份／mount切换、部分缺测；真实containerd与FS观察 | RPC／形状成功与统计完整性UNKNOWN分开，逻辑数不冒充容量；无写RPC或任意socket入口 |
| P0b已完成本地验收，依赖P0a | `deploy/observability/observability.py`、对应verify／pipeline／tests；独立node allowlist、同Prom双Agent预算 | 实际抓取／remote-write、节点样本不被tenant过滤丢弃、旧VM样本保持、HA不累加、恶意label被剥离、WAL与样本上界 | 新旧两类样本在真实协议管线闭合；原生containerd另验，尚非同一原生整链；见[本批交付](node-image-pipeline-delivery-20261016.md) |
| P0c1已本地验收，依赖P0a/P0b | `src/operator_access.rs`、正常0047／角色与schema预检、owner CLI和JWT授权检查 | 真实Keycloak/普通PG登录/CLI/TCP、永久撤权与ABA、锁后到期、写权漂移、历史升级；6专项及6组29/自动化25通过 | 安装授权基础可独立使用；仅授权元数据，无节点查询；见[交付](installation-operator-access-delivery-20261016.md) |
| P0c2a已本地验收，依赖P0c1 | `src/node_image_query.rs`、`src/node_image_metrics.rs`、0048和HTTPS admin读消费者 | 真实JWT／PG／HTTPS十项，真实Prom四场景；固定预算、最新完整单副本cohort、原时间与I/O后重授权 | 普通app窄EXEC，私有认证／写ACL漂移拒绝；仅本子片完成，见[交付](node-image-query-delivery-20261016.md) |
| P0c2b已本地验收，完整P0c只读退出门 | 同一原生CRI→mTLS→双Agent remote-write→operator API/admin | 最终v5主链82.876秒，八阶段及真实原始scrape时间、报告推进／撤权清值通过；正常47迁移、旧native回归及本次资源清理通过 | [完整交付](native-image-chain-delivery-20261016.md)明确本地／合成认证边界与早期匿名卷归属限制；P1—P4前不开放准备操作 |
| P1a已本地验收，依赖P0 | `src/image_artifact.rs`、实际admin CLI、[使用合同](../docs/image-artifact-metadata.md) | 固定expected digest，实际CLI 11项及Linux Docker七场景；平台精确匹配、同FD／摘要／大小、描述符和rootfs关系、未知扩展／预算／FIFO拒绝 | 仅元数据回执，不授权审批、完整内容或准备；[本批交付](image-artifact-delivery-20261016.md)保留失败与独立预期 |
| P1b1已本地验收，依赖P1a | 既有`deploy/nodeguard/host_profile.py`／安装plan与锁定上游完整模板；不新增profile协议字段 | v4／overlayfs／明确kata-qemu映射、NRI显式关闭与扩展拒绝；七输入同次语义／SHA、FD／路径／输出目录身份；14项Python与默认Docker20实际CLI／40日志通过 | 仅配置准入与身份绑定；[交付](host-image-runtime-profile-delivery-20261016.md)保留竞态、失败与平台边界；不是daemon loaded config或实际pull证明 |
| P1b2已本地验收，依赖P1b1 | `runtime_profile`深模块接既有`CriProxy::verify_startup`，期望路径只读、原固定UDS | 真正2.3.5的Status匹配／ConfigPath错配后登记Closed；4合同测试含实际gRPC／decode／5秒timeout、普通501及Python11、两平台strict Clippy／fmt，原native镜像回归和自有清理通过 | [本批交付](runtime-profile-startup-delivery-20261016.md)仅证明此次启动runtime子集，不证明images／NRI、持续漂移、peer二进制或准备硬限；无新许可／schema |
| P1b后续待开发，依赖P1b2 | 固定版本原生adapter、实际image选择／引用和部署硬限合同 | 完整image选择证据、lease／content／snapshot引用、namespace／snapshotter、CRI GC交互、存储／内存／FD／专用网络槽的硬限与临时目录逐项源码及实测；持续身份绑定另补 | 官方来源＋真实backend证据确定一套受支持组合；共享daemon不能隔离准备开销时不开放该组合，P1a／P1b1／P1b2成功不替代本门 |
| P2，依赖P1 | `src/image_preparation.rs`、`src/image_preparation_budget.rs`、正常新迁移／角色／preflight | 并发预算预留／拒绝、跨租户归因、同键重放、撤权／epoch／节点换代、schema／列授权漂移 | PG意图／预算／身份持久且不可伪造，未派发任务也可安全关闭；没有直接runtime表写权 |
| P3，依赖P1/P2 | `src/nodeguard/image_preparation.rs`、独立宿主协议／journal及controller adapter | 本地registry实际descriptor与平台选择、凭据隔离、摘要校验、受限下载／解包、native保护引用、内存／FD／网络槽耗尽与取消／崩溃 | 每任务和每节点真实硬限、瞬态headroom及原VM链路保留量守住；只有精确当前授权任务能产生准备回执 |
| P4，依赖P3 | `src/image_preparation_reconcile.rs`、GC／升级与运维工具 | 实际lost ACK、daemon／controller重启、boot变化、到期／撤销、活动共享引用、GC竞争／回收延迟及内存／FD／网络槽实际退役 | UNKNOWN保留必要预算与引用；确认副作用结束后再释放临时资源槽，只删本产品确定所有权，物理释放单独核验 |
| P5，依赖P3/P4 | `src/worker.rs`／runtime的只读命中观察、固定metrics／operator查询及文档 | placement之后精确节点／制品／snapshotter验证，驱逐／撤销竞争、cold路径、启动许可回归 | HIT／MISS／UNKNOWN可审计，缓存观察不能改变原调度、准入或Ready含义 |
| P6，依赖P0—P5 | `scripts/test-image-preparation.py`、Docker registry／PG／containerd验收，生产节点演练 | 全生命周期与故障、迁移／preflight、真实统计；随后目标Kata／云冷暖p50/p95/p99、成功率和成本 | 本地证据和目标平台认证分列；未过生产认证不开默认预准备或承诺加速收益 |

P1必须单独闭合Kata使用的snapshotter选择：已核实的固定版本pull实现会在`sandboxConfig=nil`时直接选default snapshotter，仅设置image runtimeHandler不足以证明Kata准备完成。
P1b1已约束的`runtime_platforms`只表示配置意图。固定2.3.5的Status(verbose)只读回runtime配置，不包含独立images配置；实际PullImage的local／transfer路径仍须核实其使用的宿主平台与所选manifest，不能从映射声明推断。NRI缺省启用，安装器已显式禁用，但这不代替daemon实际读回，具体官方来源与本批边界见[交付](host-image-runtime-profile-delivery-20261016.md)。
非nil受控sandbox配置、runtime handler／profile和实际native snapshotter证据须一起验证；不通过就保持该组合不支持，不回退成default后报READY。
lease API存在不等于完整生命周期已经接好；content／snapshot标签引用、根对象、GC调度及CRI自身删除／解包行为都在P1逐项追源码、P3/P4真实故障测试。
准备须落在真实CRI使用的namespace；固定版本默认`k8s.io`，不能在独立namespace写完内容后直接声称kubelet会命中。
固定版本`RemoveImage`会处理该镜像的全部references；本产品不能按自己提交过一个alias就调用删除来证明只清理了自己的对象。

## 多维硬预算与引用保护

PG预算只做准入、归因和状态记录；containerd namespace、镜像logical size和native lease都不能代替物理存储硬限。
部署须选择可强制限制的专用存储／文件系统配额方案，覆盖内容、snapshot、ingest／解压临时目录、metadata及并发峰值；具体backend支持在P1定型。
只限制最终压缩blob总量不合格；必须预留解包放大、并发下载、重复临时写、重试残留、共享对象和常驻系统空间的瞬态headroom。
没有可信展开上界时，只允许在真实受硬限的隔离暂存区验证；若不能保证原生准备阶段也受硬限，拒绝pre-pull，不靠软预估下注。
在真实存储可用量、硬限制余量及保留水位三者中取保守预算；读取失败／身份变化立即停止新准备，UNKNOWN不能当空盘。
准入在PG原子预留节点／策略／租户归因预算，宿主再核对当前物理门；两者间的竞争仍由硬限兜底，不能承诺跨PG／文件系统分布式原子提交。

批准闭包必须建立可追踪的原生保护引用，覆盖实际需要的content和目标snapshotter解包产物；具体lease／引用操作待P1核实，不能仅设置镜像pinned标记。
准备任务所有权、活跃启动引用、共享内容和宿主GC分别建模；不得按repository字符串或扫描到文件就当作本产品所有。
共享blob物理使用只计一次，租户分摊是独立计费政策；归因额、预留额、逻辑大小和物理占用分别返回，不能混加。
metadata大小和任务数／descriptor数／并发数也需硬上界，防止零字节大量对象或解压炸弹绕过bytes预算。
预算策略须同时固定每任务／每节点的磁盘和内存上界、FD限额、专用准备网络连接槽／并发下载槽、带宽、每任务deadline、最大重试／保留期限及节点最低保留量；min默认为0、max和在途任务数必须显式有界。未获各维预算不能先创建ingest、解包目录或registry连接。
内存预算覆盖resolver、下载缓冲、transfer、解压及共享containerd的实际开销，并为正常VM／CRI／控制面保留余量；只给请求客户端加cgroup限额不能限制daemon内的解压。P1必须证明真实执行者的限制覆盖与故障隔离，缺可信上界或不能避免影响正常runtime时拒绝该profile的准备能力。
FD预算覆盖实际worker／daemon打开的内容、snapshot、管道和registry socket，网络槽只属于准备路径，不能借用用户执行／DNS／控制面保留槽。仅限制RPC并发或client的RLIMIT_NOFILE不等于限制daemon资源；P1须实测受控执行者和后端限流／隔离，无法覆盖则不开放。
各维度独立保存保留额、实际来源及UNKNOWN；缺测、节点保留量不足或任一维硬限不可建立时停止新准备，不能把缺测当零用量。到期／取消只停止新准入，必须等真实副作用owner退役并核对句柄／socket／内存及网络槽归属后释放临时预算；进程崩溃或ACK丢失先对账，未知槽不提前复用。
软归因账与部署硬配额必须分别验到实际写失败；空间不足仅中止自己的准备，不删除其他镜像、不触发节点重启来“回收”。

## 状态机、撤销与恢复

建议状态为`REQUESTED→BUDGET_RESERVED→PREPARING→READY`，异常为`UNKNOWN／FAILED`，终结为`REVOKED／EXPIRED→DRAINING→REFERENCES_RELEASED→GC_PENDING→RECONCILED`。
每次转移绑定原request ID、attempt及fencing token；PG事务先保存意图，再派发宿主副作用，以不可变回执完成，不把网络ACK当持久事实。
宿主实际完成而ACK丢失时，同键查询原journal及精确native引用；内容相同复用，冲突拒绝，不能重新下载后假称第一次成功。
controller或daemon重启先重建本产品引用与预算，未知任务不释放预算；node reboot／profile／epoch变更后旧READY失效，重新验证而不是沿用缓存布尔值。
expiry／revocation先阻止新引用；已有合法实例引用继续保护。GC只有在确认自己的任务无活跃引用后才释放自己的native保护，不删除他人image／snapshot或手工清全局content目录。
原生GC完成可能滞后于引用释放；`REFERENCES_RELEASED`不等于物理bytes归还，删除RPC成功也不是预算释放证明。
物理对账使用同一受控FS身份下的新鲜读回，考虑共享引用、异步GC、其他writer及计量粒度；不能将文件系统差额全归因本任务。
准备准入额度可在证明不再有未来写入且残留有归属后转换为残留占用账，不得无证据归零；无法核对则隔离新准备并保留UNKNOWN及告警。

## 必跑故障矩阵

| 场景 | 验证结果 |
| --- | --- |
| shared layer／并发同digest／跨租户引用 | 单一物理对象、多条明确归因，不重复下载／重复记释放；活动引用不被到期GC破坏 |
| manifest／platform／snapshotter错配、index有歧义 | 在副作用前拒绝；没有tag或default snapshotter静默回退 |
| 下载／解压中断、disk/inode配额、daemon重启 | 硬限和保留水位守住；暂存残留可归属，UNKNOWN预算不归零，重放不换request ID |
| 内存／FD／准备网络槽耗尽，取消／kill后重启 | 每任务与节点硬限真实生效，正常VM／CRI保留量不被挤占；证明副作用退出及实际资源退役后才归还槽，缺测／未知不复用 |
| native完成后丢ACK、控制面失租约、撤销竞争 | 原journal／引用只复用原任务，旧fencing token不能提交新成功；撤销后不能新增引用 |
| GC后共享引用仍在／文件系统无可归因下降 | 只记自己的引用已释放，物理释放仍UNKNOWN或为零；不能据删除成功结清全部物理账 |
| exporter空值／部分统计／失联／跨boot旧样本 | 不用零补全、不按新timestamp声称完整；固定operator查询清除旧证据 |

## 命中、加速与生产认证

placement之前只能记录“候选节点有缓存观察”，不能发布本次launch的HIT；禁止为提高命中率绕过现有亲和、存储、隔离与节点认证。
placement后按选中节点／boot／profile、批准制品闭包、platform／snapshotter及仍有效的保护引用复核，再记HIT／MISS／UNKNOWN。
准备成功不能代替后续原生runtime实际使用证明；普通启动许可、精确Pod资源、宿主登记、Kubernetes Ready和首次正确执行仍各自成立。
冷路径沿原授权流程执行；准备失败不触发无限重试或隐藏资源开销，记录accepted／queue／placement／pull／unpack／VM／route／first-correct-exec各段实际证据。
benchmark按相同SKU／安全配置／成功任务统计冷暖p50/p95/p99、失败／取消／UNKNOWN、带宽、保留空间、准备空闲成本和单位成功任务成本。
本机Docker可验真实PG／registry／containerd协议、硬限与回收反例；不能由此认证Kata、GPU、云存储、生产调度尾延迟或实际省钱比例。

验收证据区分三层：源码／规格确认“接口存在”，本地真实服务确认“该固定组合行为”，目标节点确认“生产约束与收益”；下层不能自动替上层签字。
第一次可上线只读slice不以加速数值验收，而以真实operator可用、授权撤销、数据来源不误导及预算不破坏原VM链路验收。
第一次可上线pre-pull须同时满足P1—P4；只有数据库任务API或一次registry下载通过时仍不开放后台准备策略。
首批部署仅受控批准节点与制品，保留停用开关和可审计策略；停用必须停止新准备并依合同处理原引用，不强行删缓存或关节点。

## 每90分钟触发后的执行合同

先核对当前CI与上次失败／未完成切片；CI未闭合时优先修复已发布变更，不并行扩大产品写能力。
开始编译或Docker验证前读取`df`；复用受控Rust缓存，不复制target，不清用户数据库／卷或其他任务容器。
先检查当前编译／测试／镜像任务及实际进程状态，接续已有任务；没有在途工作时，再选最靠前且依赖满足的切片，冻结输入与验收接口后持续开发、检查、真实本地验收及两轴审查。
触发间隔不修改原有生产或验收deadline，不截断正在正常推进的工作，也不创建重复runner；长任务保存明确阶段与真实进程状态。
收尾更新开发表与证据，只将退出门已满足的切片记为通过；未完成记录剩余工作、失败原文所在私有路径及后续起点，不能因90分钟到时标完成。
同步GitHub须对应具体已验收源码并核对CI；自动跟进仅在完成、失败、需用户决定或有实际新进展时通知，不发送空进度。

## P0c2a只读消费者进展（2026-10-16）

0048不新增库存或写权限，绑定当前登记节点与认证；普通 app 只获窄EXEC。`GET /v1/operator/nodes/{id}/image-status` 与 `sandbox-admin node-image-status` 已接实际安装授权，I/O后包括失败路径再次检查原grant及当前节点。固定查询／独立两个槽／256KiB／216行，原VM八槽不变。先选最新健康scrape，再检查同cohort字段；部分remote-write不能借另副本旧成功补齐。原始报告严格60秒，UNKNOWN／f64近似／完整性UNKNOWN保持。

真实Prometheus3.13.4经HTTPS代理的四场景与PG／Keycloak／HTTPS／CLI十项已通过；其中是标准Prom实际scrape和query，未经过原生CRI／mTLS scraper／双Agent remote-write同一链。P0c2b随后已用同一原生整链完成本地验收，见[最终v5交付](native-image-chain-delivery-20261016.md)；P1a离线元数据校验也已本地验收，下一步为P1b运行时绑定／原生引用与硬限组合定型，完整P1—P4未验前仍不开放pre-pull。详见[消费说明](../docs/node-image-query.md)与[P0c2a交付证据](node-image-query-delivery-20261016.md)。
