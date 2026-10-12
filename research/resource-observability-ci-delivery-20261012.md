# 资源观测交付的 Linux CI 补验

日期：2026-10-12。对应[六项资源指标首批交付](resource-observability-delivery-20261012.md)的验收收尾，不新增产品动作或数据库迁移。

## 1. 实际发现与修复

公开提交 `4cdb090` 的[首次 CI](https://github.com/StateKnot/knotsandbox/actions/runs/38225606682)中，SDK和控制台通过，采集安装、Linux lint、基础设施检查失败。读取实际日志后修复三类跨平台问题：

| 问题 | 窄修复 | 保持的门槛 |
| --- | --- | --- |
| Python临时目录默认0700；Linux bind mount下Prometheus默认非root用户不能读取配置 | 两个本地验收脚本仅将临时夹具根目录设为0755，与已有告警检查一致 | 镜像默认用户、生产Secret配置、凭据源文件权限、断言与超时不变 |
| Linux专属句柄锁测试中四个既有unwrap被严格Clippy拒绝 | 测试内使用有上下文的Result传播；两个线程先join后传播错误 | 不屏蔽lint、不修改生产采集/生命周期代码；证据上传仍要求文件存在 |
| 三个Terraform模块只锁定本机平台的内容校验值，Linux解包缓存校验失败 | 固定版本的provider补齐Linux/macOS两种架构的h1 | 原版本/约束、11个zh和已有native h1保留；CI继续lockfile=readonly |

Linux权限原因由独立Linux Docker volume对照确认：root拥有的0700目录、0644普通文件在Prometheus默认65534用户下不可读；仅改根目录0755后相同命令成功。没有覆盖容器用户或放宽生产权限。该实测为Linux arm64，不冒充amd64运行证据；临时专用volume已删除并核对不存在。

## 2. provider校验来源

Terraform CLI仍固定1.14.7，其本机官方ZIP摘要与工具链锁文件一致。三个非native平台包从官方release asset API取得，并逐一匹配原工作区和公开 `4cdb090` 已冻结的zh：

| 平台 | 受信原包或内容校验 | 固定Terraform计算的h1 |
| --- | --- | --- |
| darwin_arm64 | 现有完整解包内容严格匹配原h1 | `m5+QKYJuA+UE2TJZfm5SIwyCKaI9nRMFs42bykK2FRE=` |
| darwin_amd64 | 官方ZIP匹配原zh | 见三份已提交锁文件与私有逐平台验证回执 |
| linux_arm64 | 官方ZIP匹配原zh | 见三份已提交锁文件与私有逐平台验证回执 |
| linux_amd64 | 官方ZIP匹配原zh | 见三份已提交锁文件与私有逐平台验证回执 |

直接下载官方release超时的失败记录保留。任务级mirror只用于从已验证内容计算h1及本机复验，没有引入新的包信任来源。native ZIP未完整下载，复用了内容校验一致的现有native包；本轮保存了官方签名元数据和签名文件，但没有重新执行PGP验签，不将其记为通过。每个模块只增加三个h1，旧校验值和固定版本没有替换。维护流程与官方说明见[基础设施手册](../docs/alicloud-infrastructure.md#跨平台-provider-锁文件维护)。

## 3. 补验结果

| 检查 | 结果 | 证明范围 |
| --- | --- | --- |
| Linux全目标严格Clippy | PASS，5分52秒 | 固定1.98.1、离线缓存、不可变源码快照，`-D warnings` |
| Linux真实句柄锁回归 | 1通过/0失败，运行0.01秒 | 实际阻塞FIFO采集与并发release，原期限/断言保持 |
| Linux目录权限对照 | 两种权限结果均符合预期 | 原默认非root用户、独立Linux volume，不经过macOS bind mount |
| 采集部署单测 | 13通过/0失败 | 精确白名单、身份过滤、3072样本和容量模型 |
| 锁定Prometheus镜像 | PASS，11.51秒 | 实际配置/TLS读取、启动、样本WAL跨重启保留与回放 |
| 双节点双副本协议链 | PASS，21.07秒 | mTLS采集、BasicAuth写入、六项新增序列及原身份/失败恢复合同 |
| 原告警回放 | 38场景PASS，31.94秒 | 实际固定promtool，无云规则激活或外发通知 |
| Terraform三模块 | fmt/只读init/validate PASS；mock 15通过/0失败 | 实际darwin_arm64，主模块10+state2+publisher3；backend=false，无真实云plan/apply |

首轮本机Prometheus readiness在冷编译并发期间超过原3秒期限，日志与诊断保留；冷编译结束后原脚本串行通过，不推断未确认的底层调度根因。Terraform native插件首次在受限环境中握手失败，允许本机进程通信后按原配置通过；没有调整产品权限或测试断言。首次基础镜像未安装Clippy，另外准备了固定官方Rust镜像+同版本官方Clippy的任务验收镜像，未发布产品镜像。

本次没有重复执行与窄修复无关的429项普通Rust、真实PG/API、SDK和浏览器测试；这些首批结果按原源码检查点保存。当前295项Rust源码/锁文件/工具链输入与Linux补验快照逐一匹配。独立只读复核未发现六项指标的计数/单位、前后授权、null、HA、采集白名单或容量模型的具体阻断错误。

公开修复后的远端整套CI以对应新提交运行记录为准；本地通过不代替远端通过，也不代替目标云认证。GPU、利用率容量分母、峰值/成本归因、公开idle策略、真实Kata/CSI、72小时容量和统一签名发行仍有独立开发或发布门。G0-08/G3-12仍为开发中。

## 4. 远端复核追加

修复提交 `5f95e6a` 的[远端CI](https://github.com/StateKnot/knotsandbox/actions/runs/38234227595)确认云只读锁文件、SDK、控制台及Linux fmt/Clippy通过。采集仍在镜像检查阶段失败，协议链尚未执行；旧通用错误未直接说明新失败原因，已增加仅合成离线夹具的有界诊断，不把推测当成该次CI根因。

后续独立Linux volume实测另确认真实WAL清理缺陷：Prometheus默认65534创建的WAL子目录0755，普通runner UID1001无权删除子目录中的段；相同固定镜像默认数据owner清理自己的WAL后，runner可完整清理夹具。该实测仍为Linux arm64，不代替完整amd64 CI。

同一次Linux检查的后续release单测出现2失败/6错误，原因是实际日期使历史冻结安全fixture到期。仅测试从两份已记录review窗口的交集中点选择参考时刻，无交集拒绝，并补齐一个未控时调用；合法刷新review后会随输入变化，原63项在当前系统日期执行通过。真实生产校验器、风险/扫描/签名与安全锁未修改，默认时钟仍拒绝过期安全快照。当前发行阻断及后续原流程见[安全状态](../docs/release-security-status.md)。

夹具清理后续修复：两脚本仅使用固定临时prefix和五个store白名单，在原容器停止及所有断言完成后，由同一固定镜像的默认数据owner移除自有`wal`/`chunks_head`，再由host清理父目录。没有覆盖被测用户、提高capability、chmod生产WAL或挂载部署路径；symlink/未知profile拒绝，原失败不被清理错误掩盖，成功路径清理失败也会使门禁失败。新增四项对应回归，部署单测现17/17；本机完整镜像/TLS/WAL16.84秒、双节点双副本协议20.71秒、原38告警32.57秒再次通过。后续远端CI以新提交实际结果为准。

## 5. 身份证书与宿主专项收尾

提交 `2758c3a` 的[实际Linux CI](https://github.com/StateKnot/knotsandbox/actions/runs/38237471440)已通过完整采集门禁：17项单测、14个schema对象、真实镜像/TLS/WAL重启回放、38告警场景及双节点双副本协议链；云只读检查、SDK、控制台和Linux fmt/Clippy/release单测也通过。整套CI仍失败，日志确认另有以下两项基线问题，分别复现和窄修复：

| 问题 | 实际证据与修复 | 保留的合同 |
| --- | --- | --- |
| OpenSSL 3.0对证书主机名不匹配仍返回0，原验证只检查退出码 | 实测3.0.20不匹配exit0、3.6.3不匹配exit1，均输出否定结果；每个public/admin主机名现在必须获得对应的完整肯定结果，未知输出拒绝 | 继续使用OpenSSL的SAN/通配符规则；原密钥匹配、叶证书与信任材料七天有效期检查保留；不把本地合成证书当公有CA认证 |
| 普通CI用户无权stat PID1的mount namespace，实际guard返回503 | 同一只读容器/二进制下UID1001得到EACCES/503，root得到200且原断言通过；该用例明确标为宿主权限专项，新增CI必跑gate | 普通all-targets仍以runner身份执行；Cargo不经sudo；只有指定的已编译用例以sudo执行；生产root/PID1守卫未修改 |

宿主gate从普通调用方的Cargo metadata与lib test JSON选择唯一原生ELF，核对package/source、owner、target布局及symlink边界；预检root和PID1 mount namespace的device/inode，再核对唯一ignored用例库存。实际运行必须恰好1通过/0失败/0忽略并产生唯一完成marker，零测试或缺marker不能通过；执行前后指纹核对，权限/namespace/用例失败、二进制消失都保存FAILED回执且保留原失败。CI无continue-on-error或可选跳过，always上传JSON/log并保持缺文件失败。

| 本批补验 | 结果与范围 |
| --- | --- |
| 身份安装单测与schema | 27/27通过、37个官方schema对象通过；真实证书覆盖缺任一SAN、CN/SAN冲突、错密钥、短有效期、通配符及安装前零集群写入 |
| 旧版OpenSSL实际匹配 | Linux arm64的3.0.20 hostname CLI红→绿；生成/key/expiry使用本机CLI，完整Linux amd64身份流程由远端CI核验 |
| 宿主gate合同 | 固定Python3.12下11/11通过；含sudo拒绝、device不同但inode相同、零测试/缺marker、binary消失及primary错误保留 |
| 最终Linux严格Clippy/fmt | 不可变824文件源码、296项Rust输入逐一匹配；all-targets -D warnings通过，fmt通过 |
| 最终Linux Nodeguard | 38通过/0失败/2明确ignored；宿主专项另以root真实执行1通过/0失败/0忽略，唯一marker且binary摘要不变 |
| 清理与边界 | 自有容器删除并确认不存在；复用下载/编译缓存，不复制target，不删除共享volume；不使用本机sudo，不操作实云 |

首轮使用本机默认Python3.9跑新合同测试时因缺少标准库file_digest报错，记录保留；仓库CI约定的3.12下原11项通过。binary消失收尾负例也经历红→绿，没有屏蔽失败或移除断言。本批未重复无关的429项首批普通Rust、PG/API与浏览器回归；此前数据保留为各自源码检查点。

新增公开文件为宿主gate及其测试；生产Rust改动仅test-only两行，身份校验为上述窄修复。42条正式迁移逐项保持、无0038，生产安全锁和真实时钟未变，过期Debian快照继续阻断发行。最终普通UID→sudo链和整套远端结果按新提交实际CI记录确认，不将本机root专项当成云/Kata认证。容量分母、峰值/成本、GPU、idle策略与生产验收仍按开发表推进。

## 6. 远端回执与后续数据库精度

公开 `9b23f15` 的[实际CI](https://github.com/StateKnot/knotsandbox/actions/runs/38242963756)确认完整采集、身份/TLS/schema、云只读检查、SDK、控制台、fmt/Clippy/release单测、普通Rust与宿主必跑gate及隔离review回归通过。已上传宿主回执实际caller UID1001，精确1通过/0失败/0忽略、唯一marker、binary前后相同；sudo仅执行id/stat/该已编译ELF，没有sudo Cargo或target写入。仅读取两项指定附件成员并核SHA，未任意解包。

同次整套CI随后在PostgreSQL终止认证组失败：15通过、1失败。Linux请求时间`12:44:38.624670844Z`经数据库读取为`12:44:38.624670Z`，原exact比较相差844ns；这是测试fixture未遵循timestamptz微秒精度。只在该case局部以`trunc_subsecs(6)`构造horizon，认证/request/ACK继续由同一值派生；两个exact断言、生产时钟/有效期边界、权限/关闭守卫未修改，未扩大其他时间fixture。

该窄修复已用现有独立TLS PostgreSQL夹具完整执行原16项终止认证回归：16/16通过，42条正常迁移逐项核对，无0038；输入/测试二进制/SDK未漂移、自有容器和进程清理确认。本机与新826文件Linux源码快照的全目标严格Clippy、fmt均通过，296项Rust输入逐项相同。失败记录仍保留；未放宽断言、精度比较或期限。

`9b23f15`整套结果明确为failure，浏览器验收及后续镜像没有执行，缺浏览器回执的上传门槛仍保留。此修复后的远端结果须由新提交实际重验；本批资源观测及宿主门禁通过不能替代整套CI、实云/Kata、持续容量或安全签名发行验收。
