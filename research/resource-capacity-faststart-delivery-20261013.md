# 宿主容量与启动调用观测交付（2026-10-13）

本轮推进开发表12.3的两个子项：宿主真实CPU/内存容量上界，以及实际CRI启动调用耗时。G0-08/G3-12和快速启动工作包仍进行中；本轮没有交付节点整体利用率、自动调档、预热池或GPU共享。

## 上一提交CI

基线提交`3a6752eb31a979baf9b770e7e730d87b4e965812`的[CI运行38386853730](https://github.com/StateKnot/knotsandbox/actions/runs/38386853730)失败。production-console、typescript-sdk、cloud-infrastructure-contract和cluster-installation-contract通过；verify在真实Keycloak浏览器账号流程读取重新启用PATCH响应体时出现`RESPONSE_BODY_UNAVAILABLE`/`net::ERR_ABORTED`。此前独立PG回归通过，不能把更早的BFF清理失败当作本次原因。

本地原场景三次通过、一次出现另一种刷新定位器超时；没有稳定复现远端缺响应体错误，底层原因仍未证实。测试观测入口现使用**同一次原生fetch的Response clone**，在SDK绑定fetch之前安装。原Promise、Request/signal和Response原样返回；无重试、替代GET、合成响应或弱化版本断言。限定同源服务身份POST/PATCH，真实Idempotency-Key、状态和ETag匹配；最多16条、每条256KiB，消费后删除，异常和超预算失败。生产SDK与控制台请求实现未改。

新增真实浏览器合同10/10通过，包括原生身份保留、CDP单独读取失败、正文截断/取消/非法/超限、重复/容量限制、错误匹配、认证路径排除和页面重新加载。CI在完整真实场景前执行精确10项、零失败、零跳过检查，并保留日志；不能仅凭此宣称远端底层故障已根治。

## 宿主容量

新增`VM_CPU_CAPACITY_CORES`、`VM_MEMORY_CAPACITY_BYTES`两项gauge，贯通nodeguard、采集/写入白名单、固定查询、API/OpenAPI、TypeScript SDK和控制台。共13项公开资源指标、14条原始序列（含观察标记）、每节点3584样本预算，WAL容量校验仍保留原70%磁盘门槛。

CPU读取叶级有效cpuset，并取叶级和全部非根祖先有限`cpu.max`最紧quota/period。内存取完整同一路径有限`memory.max`最小值。父级可能共享；这些是实际采样的上界，不能当作专属预留、剩余容量或节点利用率。CPU是名义CFS/fair class带宽约束，burst、周期与其他调度类别使其不构成瞬时上限。

固定FD、device/inode、pidfd、完整宿主cgroup2挂载和祖先链接前后复核；限制前后双读只能证明观测期间未发现变化，并非原子快照。CPU/内存独立缺测，可选容量失败不抹掉原基础计数。全无限内存、非法/缺失文件、无法证明完整路径或观测失效保持缺测；真实内核零限制保留零。无Flavor、guest或宿主总RAM补值，无百分比或clamp。

## 启动调用

在现有受管`RunPodSandbox`调用周围记录单调`duration_micros`，固定`HOST_RUNTIME_CALL`/`CRI_RUN_SANDBOX_ROUND_TRIP`与launch关联。`OK`、`ERROR`与`CANCELLED_UNKNOWN`分列；返回Cancelled/DeadlineExceeded或已开始future被drop都保留未知。原Status、响应、所有权许可、120秒deadline及UNKNOWN处理保持，无请求/响应正文或provider错误消息日志。

此间隔不含走独立containerd端点的镜像拉取，不是VM Ready、端到端首次正确执行或VM死亡证据。未被poll的future不生成耗时。下一步须把accepted、排队、资源就绪、路由和首次正确执行按同一launch关联，并在真实Kata节点测量冷暖启动；不能拿本轮测试用例耗时代替产品启动基线。

## 当前源码本地验收

| 验收 | 结果及边界 |
| --- | --- |
| Rust普通库、严格native Clippy/fmt | BFF收尾补验后290通过，121个环境专用用例未执行；lint/format通过 |
| 严格Linux全target Clippy | 锁定工具链镜像通过 |
| Linux nodeguard普通合同 | 内核兼容补验后49通过，3个环境专用用例未执行 |
| 真实Linux内核容量精确用例 | 1通过；固定Docker运行镜像、0.75 CPU/256MiB、完整cgroup层级、inode变化和PID退出拒绝；不是Kata认证 |
| 锁定官方Prometheus查询语义 | 精确1通过，包含两个容量gauge、缺测、时间戳及HA分离 |
| 采集配置、实际Prometheus协议链、告警 | 17配置测试通过；实际mTLS抓取/远程写入/双副本/过滤/恢复通过；38个声明的告警故障场景通过 |
| 独立TLS PostgreSQL/签名身份/指标HTTP | 精确1通过；两容量选择项、租户隔离、IO期间撤权/epoch、正式迁移账本核对；源码/产物不变及自有资源清理确认 |
| 独立TLS PostgreSQL/BFF收尾 | 4通过；真实连接角色/唯一标签核对、原登录/撤权/流关闭、会话锁及保留清理；新增用例要求实际普通DROP，不能延期冒充成功 |
| SDK、控制台、真实浏览器HTTP合同 | 71、66、完整28通过；后者包含4项资源指标合同，使用明确HTTP fixture，保留原值、空缺和撤权清理 |
| 原生响应观测合同 | 原账户10项、原诊断12项及共享模块15项通过、零跳过，使用锁定Chromium；旧合同未修改，共享总预算 |
| 完整真实Chrome/Keycloak/BFF/API/TLS-PG | 精确1通过；真实账号/授权、诊断/事件、未来策略、通知失ACK及重放、停止受理、撤权；9张截图、业务事实不变、临时realm/进程/PG容器清理确认 |

非root Linux CI入口`scripts/test-nodeguard-capacity.py`消费普通Cargo产物，检查精确忽略用例、ELF/UID/metadata/路径、固定镜像与容器限额，只挂载二进制。创建失ACK按精确随机名字/标签/镜像恢复清理所有权；主失败和清理失败分别保留，未确认不存在不能通过。macOS本地的上述内核用例不等于这个Linux入口已经通过；最终入口与整套远端结果以新提交CI收据为准。

发布后复核发现Docker CLI29.6.2对不存在对象返回小写`no such object`，清理判断已改为大小写无关；实际不存在随机对象的inspect和精确名字空列表通过，权限或daemon连接错误不被当成不存在。该修正只影响验收收尾，不改变内核采集和生产运行。当前Docker Desktop的Cargo产物位于构建容器的named-volume路径且属root，不能满足该入口的普通Linux UID/宿主路径合同；未通过改属主、重写Cargo消息或构造宿主路径别名绕过，由真实Ubuntu非root CI执行入口。

随后`b7b89f7`的[CI运行38402086901](https://github.com/StateKnot/knotsandbox/actions/runs/38402086901)四个独立作业通过，但verify的普通测试步骤中，新增真实容量入口返回内核用例退出101、`GuardError::Invalid`；原宿主观察用例通过，自有容量容器清理确认，真实浏览器步骤尚未执行。原日志缺少内部阶段，不能直接推断失败原因。

预研确认[Linux内核rstat.c](https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/b91872c56940950a6a0852e499d249c3091d4284/kernel/cgroup/rstat.c)在CONFIG_SCHED_CORE时输出`core_sched.force_idle_usec`。原基础stats解析器确实拒绝这个合法字段；固定输入回归先失败再通过。现仅增加此字面字段兼容，任意其他点号字段、重复键、非法/溢出数字继续拒绝。该字段不产生新的公开指标，也不改变已有usage或throttle值。

真实内核用例增加固定读取/解析/断言阶段Context，实际CPU文件只打印上述字段存在与否的布尔标记；wrapper记录白名单错误码、阶段和布尔证据，无原始路径/控制器正文/凭据。所有容量、PID/inode、精确用例、产物和清理门禁保持。最新本地内核容量仍通过，当前Docker Desktop内核的字段存在标记为false；此环境不能替代Ubuntu的字段现场。最新远端CI仍需验收，不能把已证实的解析缺陷当作上一运行已被证明的唯一根因。

`967f705`的[Ubuntu CI运行38406154806](https://github.com/StateKnot/knotsandbox/actions/runs/38406154806)已通过真实容量入口：实际core字段存在为true、退出0、所有容量/身份断言及自有清理通过。随后PG集成在BFF业务完成后的fixture收尾拒绝：两个已关闭runtime pool的服务端socket仍短时idle，另一个owner的wait为空；原逻辑只允许owner/ClientRead，错误地把这些关闭尾连接视为异常。

BFF修改仅位于测试fixture：为owner/runtime配置与唯一临时库绑定的application_name，保留TLS和其他URI参数；每轮admin独立autocommit查询，只有准确角色/标签、idle、无事务、wait空或ClientRead的尾连接可在2秒总预算内等待。**只有真实零连接才普通DROP**；active、foreign或隐藏状态拒绝。55006竞态复核要求非空且全部为本fixture的空闲OWNER才允许原owner-only延期，runtime不能转为owner记录。application_name用于来源匹配，不是数据库授权；没有terminate、FORCE或生产身份权限变更。[PG17明确state与wait_event相互独立，并说明事务内统计快照缓存](https://www.postgresql.org/docs/17/monitoring-stats.html)。

新增独立TLS-PG的4项BFF验收在既有review入口成为必需套件；只有此套件获得本容器临时admin URI以创建自有随机数据库，其他接口测试仍只获得各自普通登录。新用例从真实PG验证owner/runtime身份与标签，并在close后用新独立admin连接确认数据库消失。最新完整远端CI仍以之后提交为准，不能把容量PASS等同于整个流水线通过。

`d59ea163`的[CI运行38413320610](https://github.com/StateKnot/knotsandbox/actions/runs/38413320610)完成为failure。真实Linux容量入口再次通过（实际core字段存在、退出0和自有清理确认），17组独立PG回归共77项全部通过，包含BFF精确4项；随后PG全套和Keycloak到API集成也通过。两处浏览器失败分别处理，不能把这些成功步骤等同于完整CI通过。

控制台HTTP合同的自动化撤权断言在中间渲染同时匹配两个`RESOURCE_NOT_FOUND`警报。原用例本地普通20次全部通过；相同真实React/HTTP在CDP CPU降速6倍的独立诊断实验中复现strict2，继续观察并保留原错误后，最终警报恰好一个且可见，策略详情/运行详情/创建表单均为零。修正只把这三项已有清除断言移到原严格唯一警报断言之前，没有修改组件、请求、期限或断言。相同降速实验修后20/20通过，正常全套Chromium HTTP合同28/28及format通过；限速/诊断源码仅留在私有证据中。

同次真实身份浏览器已通过服务身份重新启用的200、完成及正文读取，随后在诊断提交故意丢失ACK、页面reload、显式原键重放的202响应读取处发生`RESPONSE_BODY_UNAVAILABLE`。其固定阶段为`diagnosis_management`/`RELOAD_ORIGINAL_REPLAY`；临时进程和fixture清理全部确认。这定位到外部响应观察失败，不能把先前累计的`net::ERR_ABORTED`当成新的业务请求被证明失败，也不能宣称所有CDP留存问题已根治。

诊断补验增加独立的原生响应观察器，仅匹配同origin、UUID实例路径、UUID幂等键的诊断POST 202，在控制台捕获fetch之前初始化。最多16条、每条256KiB原始JSON；来源/status/ETag错误、重复/容量耗尽、非法/截断/取消、凭据字段均拒绝，消费后删除。调用者继续获得原Promise、Request/signal及Response；原202、原键/正文/CSRF、同resource/operation以及journal ACCEPTED断言全部保留，不发替代GET或第二个提交。

新增12项真实Chromium合同通过。有效RED来自同一真实POST的实际CDP requestId：先确认原生SDK与CDP读取同一202，再清除独立观察session的Network状态，实际getResponseBody报错；GREEN仅改外部reader读取原生clone。先前手写throw的探索单独保留且不计有效RED；该实验验证同类外部观察失效的处理，不证明线上CDP留存失效的具体底层原因。两个观察器实际叠加、重载和单请求身份均覆盖；诊断GET及其他业务响应继续走原观察渠道，未宣称覆盖所有CDP问题。

此补验后的完整Chrome/Keycloak/BFF/API/TLS-PG本地流程再次通过：精确1项、两种业务marker、9张截图、通知业务事实一致、源码/产物不变及全部自有资源清理确认。最新完整GitHub CI仍待后续补验提交的独立结果，真实Kata、GPU、云发行安全门禁仍未认证。

`9c42b2dc`的[CI运行38419701643](https://github.com/StateKnot/knotsandbox/actions/runs/38419701643)四个独立作业全部通过；verify的真实容量、17组77项独立PG、PG全套及Keycloak/API也通过，真实浏览器已到诊断/事件VERIFIED，随后自动化创建失ACK后的原键重放再次遇到外部正文不可用。临时资源清理全部成功。该结果说明问题不只限于前两种提交回执，不能把本地通过等同于完整CI已通过。

本次收敛为共享`mutation-response-observer.mjs`：一个原生fetch包装、一个全局16条/每条256KiB原始JSON预算，仅显式注册的闭合业务profile可捕获。服务身份、诊断、自动化、项目授权、通知ACK和本流程STOP分别固定method/UUID路径/status；仅通知ACK明确接受真实200及404，其余没有开放任意4xx。方法/路径已匹配但status属于同profile另一路由时立即MISMATCH，未知scope/status为SCOPE；仍以原origin、幂等键、实际status及ETag配对，跨profile消费不能取走其他回执。原两个模块只保留兼容导出/slot/error分类；多次初始化和reload合并注册，不能重复包装fetch。

已知浏览器mutation正文统一从同原生响应读取，包括通知拒绝写入后保持UNKNOWN、恢复权限后同键200重放。原44/94/101项业务断言及全部请求调用保持；route.fetch/APIRequestContext的真实提交证据、GET及auth仍走原渠道，不重发、不替代GET或自动重试。原账户10/诊断12合同未经修改仍通过，新15项覆盖全部闭合路由、实际CDP观察状态失效、全局预算、隔离/初始化/同键404后200、原生身份及安全负例。共有37项、零失败/零跳过；完整产品链路与远端CI须继续按最终提交分别核验。

本地证据在忽略的`.local/resource-faststart-20261013/`，包含源指纹、普通产物SHA、原失败日志和清理回执；不提交PKI、身份凭据、临时数据库或构建缓存。

### 2026-10-14：真实数据库取消缺陷补验

共享观察器后的真实业务链另行复现数据库503。固定页面码为`DEPENDENCY_UNAVAILABLE`；后续真实Chrome锁快照记录到`SESSION_READ`被另一个`IDLE_IN_TRANSACTION`/`ClientRead`会话阻塞，并返回SQLSTATE `55P03`。独立检查没有发现fixture跨浏览器协调阶段持事务；不把它归为UI渲染等待或外部CDP正文失留存。

锁定SQLx Postgres 0.8.6在BEGIN往返期间被取消时，客户端深度尚未增加，drop不能排入ROLLBACK。真实TLS PostgreSQL最小回归先确认服务端进入BEGIN，再取消原future；未修复的同一物理连接仍在事务内，后续普通写入不可见、事务advisory锁未释放，2.27秒精确失败。采用[上游已合并修复](https://github.com/transact-rs/sqlx/commit/f1e94ec34dd5f11ad6488a3a8ac7988439a3f757)后，同一测试2.31秒通过，三项独立事实均正常。该回归进入默认独立TLS-PG矩阵，要求精确一项和完成marker；没有改变业务重试、锁、应用期限或成功响应。

使用原0.8.6发布包的有限回移：原archive SHA256为`db58fcd5a53cf07c184b154801ff91347e4c30d17a3562a635ff028ad5deda46`，116个原文件只改变`transaction.rs`中的三处深度操作，保留双许可证和原版本。Cargo.lock如实显示path dependency。固定校验器验证全部原文件、唯一补丁、Cargo覆盖与Docker上下文，十项实际篡改负例通过；不修改其他依赖版本或把本地补丁伪装为registry checksum。所有临时SQL/DOM探针已按原字节恢复。

普通Rust290项通过，122项环境专用用例保持独立门禁；严格本机all-targets clippy与格式检查通过。默认文件沙箱下的82项本地socket拒绝日志保留，改用已授权loopback验证权限后，同一测试集合全部通过，未改测试内容。新增十项SBOM path依赖合同通过；锁定Syft 1.54.0在无网络只读Linux容器中实际从新Cargo.lock识别出`sqlx-postgres 0.8.6`/`rust-crate`。该条目没有PURL，不能据此宣称完整镜像扫描或正式发行已认证。完整产品链和远端全部CI继续以最终源码绑定收据核对。

该修复是资源与快启子项的验收依赖；不会把预留分母、预准备预算或GPU状态提前标为完成。下一资源交付的身份、事务及查询合同见[逐次启动资源账本方案](launch-resource-accounting-plan-20261014.md)。

版权与出处贯穿实际交付链：当前manifest v3强制签名`sqlx-postgres-notices.json`，包含原双许可证全文和补丁来源；v1/v2只保留历史读取。OCI/宿主导出和离线安装均保留通知，只有原八ELF执行集合；发布合同87项通过，包含真正本地文件复制、改字节拒绝、旧版下载名单和许可证截短负例。该结果没有签发本项目正式发布，签名、镜像扫描和云验收仍是各自独立的发布门。

## b66177be 完整CI：诊断读权限恢复后的GET正文观察失败

精确提交`b66177be3475e161e7a4b33625096759f8cf57bc`的[CI 38435165070](https://github.com/StateKnot/knotsandbox/actions/runs/38435165070)最终失败。四个独立作业通过；verify的普通Rust、18组78项独立PG回归（含真实BEGIN取消归池）、真实Linux容量、全部PG与OIDC/API链均通过。第16步的原10/12与新15项Chromium observer合同全部通过、零失败/零跳过，但实际产品浏览器在诊断读权限恢复后失败。

最后完成标记为`READ_RESTORED_HTTP_200`，未达到`READ_RESTORED_BODY_CHECKED`；实际失败入口为`browser-diagnoses-live.mjs`的原`restoredResponse.json()`，固定分类`RESPONSE_BODY_UNAVAILABLE`。此时账号恢复、诊断原键202重放、首次结构化GET和撤权GET 404均已通过。不能将本次失败归为早先的账号数据库503或mutation回执。977个源文件逐一匹配该提交，浏览器源码经过Cargo校验，自有进程与数据库清理成功。

后续正式自动化验收、Prometheus、服务镜像、Linux host导出与投射凭证门均实际跳过；always-upload成功不代表这些验收通过。第25步依赖停止成功。固定报告与原失败日志保留在本机`.local/resource-faststart-20261013/publication-shared-native/ci-private/`，修复不重跑此失败提交，不加入业务重试或移除原断言。

## 显式一次性GET观察与资源数量子项

针对上述GET失败，观察深模块新增`observeReadResponse`，使用原单fetch包装和16条/每条256KiB raw JSON预算。仅显式一次性票据的闭合业务GET能捕获；实际请求/响应完整URL、租户、status、ETag及实例详情的instance ETag必须一致。第二调用、重入、匹配两个GET、导航、请求失败、坏JSON、超界、认证字段和期限均失败关闭，消费与finally清理只取消clone分支。没有新增GET、网络关联header、retry或替代正文。

机器身份分页的opaque cursor由原SDK请求生成，因此只有这个list可显式按path arm，仍保存实际完整URL并逐字核对；其他query精确匹配。认证、未arming及其他路由不读关联头或正文。一个真实GET首先证明原生与CDP正文一致，实际清除该CDP会话状态后原外部正文读取精确失败；随后独立副本仍来自同一请求。该回归不推定GitHub底层为何失去正文。原25项首次运行24通过/1失败捕获真实fetch失败不产生response事件的问题；已监听实际`requestfailed`，不follow或重试。fixture和入口错误分别保留，未当有效RED。

新增28项与原37项共65项真实Chromium合同通过，零失败/取消/跳过，原三个合同源字节不变。五消费者原断言均保留，账户多一项cursor检查；route.fetch、APIRequestContext和原生页面内读取保持。CI强制新增28项门禁及日志保留，原完整产品链继续独立执行。Standards与Spec静态审查分别零阻断；这不是本项目云运行或正式发布认证。

按资源开发表同时实现数量/provision校验，见[资源数量交付记录](runtime-resource-contract-delivery-20261014.md)。本轮最终普通Rust all-targets 453项通过，257项环境专用用例保留独立门；严格all-targets Clippy和完整格式检查通过。launch来源、有效期配额账本、利用率分母、warm和GPU仍待开发，新提交远端完整CI必须单独核对。

## 72754128 完整CI：浏览器通过，正式自动化进程门失败

精确提交`7275412890a08acd83bf39c2527b5f8551ce3c3f`的[CI 38444257078](https://github.com/StateKnot/knotsandbox/actions/runs/38444257078)最终失败。四个独立作业通过；verify的资源数量回归、真实Linux容量、18组78项独立PG、全部PG及OIDC/API门通过。第16步65项Chromium观察合同和完整真实Keycloak→BFF→API→TLS PostgreSQL产品链均通过；9份截图、980个逐文件源码SHA、产物保持及自有清理已核对。

首个失败为第18步正式自动化的`worker_process`。原上传内容只有`evidence.json`，没有`process.log`，因此无法直接确定该次CI的具体失败断言。后续Prometheus、镜像、Linux host导出及投射凭证第20–24步实际跳过；第25步依赖停止成功。不能把前置门或always-upload成功计为完整CI成功。

本地用同一原进程测试源码及正常迁移到0044的独立TLS PostgreSQL两次复现：测试严格期待正式1..37+39..43，数据库实际为1..37+39..44，均在进程场景之前失败。源码及迁移校验匹配，支持清单过期这一判断；不把本地断言冒充缺日志的原CI断言。修复只更新完整版本集合、固定错误说明及ignore的环境说明，0038继续不存在，原进程、角色、租约、业务和期限断言全部保留。

正式runner新增现有`evidence.json`内的派生诊断：每组精确选择/计数、退出码、日志SHA及大小、固定分类/源位置和闭集阶段标记。原始错误、连接串、密码、请求/响应正文继续留在本地私有日志；未知输出与超界、超时、错测试或非零退出不能形成成功回执。新增9项诊断检查涵盖敏感文本污染、超长/非ASCII计数及失败关闭，CI强制执行；不额外上传原始进程日志。

## 同URL旧在途GET的真实Request归属修复

原观察票只按URL/method监听外部response/requestfailed时，arm之前已经发出的同URL GET可能抢先到达。本地实际Chromium/HTTP两项RED证明：旧response与新原生clone正文错误配对，或旧请求失败错误终止新GET。每项都保留两次原生GET、一条clone与原生对象身份；没有伪造Response、CDP异常或额外业务重试。

修复绑定arm之后唯一匹配的实际Playwright `Request`，response与requestfailed必须归属于这个对象；第二匹配请求仍严格拒绝，消费前后及finally保持清理。新增两项合同各自通过；原28项合同字节前缀及原37项合同源保持不变。新fixture等待真实HTTP处理方的首次到达回执，再检查原请求计数，不假定Playwright事件与HTTP处理顺序；30秒期限保持，无sleep、retry或额外请求。最终30+37共67项真实Chromium合同通过，零失败/跳过/取消，CI强制30项新计数。完整产品链、独立审查及下一精确提交CI仍须单独核验。

补验收尾：两轴复核发现并修复了GET fixture到达等待的取消清理缺口与诊断超长数字解析缺口。真实首GET已发起但尚未到HTTP handler的受控取消实验，修前自有browser/server仍开放，修后确认全部关闭；预期cancelled实验不计业务PASS。最终受影响30项全部通过，原37项引用未变core及合同源码的已通过记录。正式自动化完整runner的18项业务、5项通知PG、1项真实签名HTTP/SDK和1项原完整进程矩阵全部精确通过，零失败/零忽略；正常43个正式迁移（1..37+39..44）的SHA384、自有进程/容器清理、源码/SDK/制品前后绑定另有收据核对。新提交的完整浏览器链和远端全部CI仍单独核验。

## eeb6c6ec 完整CI：后置投射凭证入口失败

精确提交`eeb6c6ece164fa293e773a917fcd0abc9acee37d`的[CI 38451451190](https://github.com/StateKnot/knotsandbox/actions/runs/38451451190)结束，四个独立作业成功、verify失败。真实Linux容量、18组78项独立PG（含BEGIN取消）、9项安全诊断、完整PG/OIDC、67项Chromium合同及27.137秒完整产品链通过；981个逐文件SHA与Git执行权限匹配，普通文件的600/644权限差异单列，不能声称全物理mode一致。产品链9截图已由原runner验证并保留收据；该CI artifact不含这9份PNG。正式自动化18+5+1+1全部EXACT_PASS，两数据库各43项正常迁移，源码及清理收据已核对。

此前跳过的第20步官方Prometheus（1项实际通过）、第21步非root服务/runner镜像及第22步Linux amd64宿主ELF导出/帮助/校验和均实际成功。首次失败为第23步投射凭证wrapper返回1；父调用`capture_output=True`与`check=True`只留下CalledProcessError，丢失子stderr。现有四份artifact没有该失败回执或测试ELF，原内部分类和是否执行了信任测试仍UNKNOWN。第24步unsigned宿主上传实际跳过，第25步依赖停止成功。

[该runner软件清单](https://github.com/actions/runner-images/blob/ubuntu24/20261004.327/images/ubuntu/Ubuntu2404-Readme.md)声明Docker Client/Server28.0.4；[官方API版本表](https://docs.docker.com/reference/api/engine/)对应API1.48，而[`image inspect --platform`](https://docs.docker.com/reference/cli/docker/image/inspect/)要求API1.49。本地以同一原wrapper和真正普通Cargo编译的AMD64 ELF，单命令强制API1.48，精确复现LOCAL_DOCKER_IMAGE_FAILED；这里证明的是入口兼容缺陷，不倒填原CI丢失的具体错误。

直接删除platform参数会在多平台存储中读到宿主默认ARM元数据，不能拿它证明实际AMD容器。修复依据[官方API1.48存储合同](https://docs.docker.com/reference/api/engine/version-history/)：先核唯一approved repo digest及image ID，create固定linux/amd64且不pull，在start之前核实际Config.Image和Image ID；多平台存储必须有严格合法的platform-specific ImageManifestDescriptor，经典存储只有在descriptor确实不存在且实际image元数据严格为Linux/AMD64时才可通过。空/坏descriptor、错误平台、Image ID、Config.Image或repo digest全部拒绝，不捕获失败后降级。image ID与selected manifest digest分开记录，不把清单digest冒充image ID。

原Rust信任测试与固定staging脚本保持：真实10001主UID/GID、补充组10002、所有capability集合清零、NoNewPrivs、root:10001的0440身份和投射symlink通过，可读但错误补充组/组可写/公开身份/非root组身份及可写CA均拒绝。原失败、修复后的API1.48和当前API均绑定同一AMD64 ELF和三个公开PEM的前后SHA；两次修后各精确1项实际PASS。两次本地验收使用多平台存储，经典分支仅有严格协议fixture及负例，其真实执行仍待下一CI。10项静态协议与负例通过，真实非零子进程及敏感文本污染证明派生FAIL回执不复制原stdout/stderr，只输出闭集分类、大小和SHA；未知不变成成功。

CI新增强制静态协议门；子进程失败先写projected-trust.json再以固定分类失败退出，always保留失败收据。实际凭证门移至昂贵发行镜像构建之前，仍独立执行完整原测试；成功回执在宿主导出后复制入原交付目录。没有跳过、重试、放宽真实身份规则或更改生产信任代码。普通AMD64编译复用原Linux目标卷的独立架构目录，不复制target，保留9.1GiB缓存，剩余空间359GiB；自有测试容器确认清空。新精确提交仍须全部CI门通过，不能以本地通过签发云/Kata/GPU认证。

## 下一交付与发布门

按表继续有效期request/limit/overhead和归属账本、PSI/峰值画像，建立可解释的利用率/浪费原因；再做受预算与撤销/GC约束的镜像和节点预准备。GPU先完成独占设备租约、真实归属/显存/计算利用率采集、故障回收和数据残留验收，再评估MIG等共享模式。

真实Kata、Cilium、CSI、GPU、目标公有云和发布安全认证尚未通过；不得启用未认证模板/GPU或将本轮本地验证计为正式上线验收。
