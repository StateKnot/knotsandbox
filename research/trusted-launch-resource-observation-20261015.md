# 可信启动资源观察：原子登记与固定分页

状态：**第4步普通CPU可信观察已实现并完成本地验收；待同步及新提交GitHub CI。** 公开比较基线为 `5b668d5fb3b5b15be8f65d89b67a0f9a7860cf83`。本轮37组201项按最终制品分两批通过，汇总 `PASS_BATCHED_FINAL_ARTIFACTS`；专项、维护升级门及本地生产镜像验收分别通过。本交付对应[逐次启动资源账本开发表](launch-resource-accounting-plan-20261014.md)第4步，不能据此宣称完整产品、生产上线或目标云认证完成。

## 交付合同

Kubernetes 逐字段回读产生不可从外部 JSON 构造的能力，经现有 scheduled launch 路径带入 nodeguard 双向 TLS 授权登记。资源来源是 `KUBERNETES_API_READBACK`，nodeguard 只认证 launch、节点和许可身份，不承担 Kubernetes 资源测量。Class UID、回读 RV、配置摘要及独立 overhead 是当前配置观察，不是 adopted RuntimeClass RV 证明。实际 Pod request、limit、overhead 和有效资源取自精确 Pod UID。

授权 ACK 与观察共同提交。事务遵守 workspace → instance → 活动执行 → operation → 节点防护的锁序，重新核对当前 launch、generation、epoch、权限、期限、节点与认证。身份或内容冲突整体回滚；同内容重放和纯 RV 变化复用原观察，续租不覆盖历史。

0046保留1..37及39..45原文件字节，当前正式集合为1..37加39..46，共45条；0038继续未发布。新迁移冻结升级前已提交 base/extension ACK 的精确归属。未提交的 permit 不享受旧数据豁免；旧基线 ACK 复用时保持缺观察，不从当前对象补造过去的资源值。观察与新 ACK 双向要求同事务完整；追加保护、FORCE RLS、复合身份关联和最小权限同时成立。普通 API/SDK 没有观察写入口，runtime 没有观察表直接写权限。启动及 preflight 核验迁移、schema、函数、触发器和 grants。

只读接口继续受 `instances:read` 和返回前身份复核保护。签名游标固定所选观察 ID 或第一页缺失状态；后续页不选择“最新观察”，不只靠写入时间上界处理未提交行。数量和 generation 采用有界十进制字符串，单位明确为 millicores/bytes，未知不用零值替代。页面在失败、撤权或范围切换后清除原视图。

## 验收接口与证据

沿用开发表和现有验收接口：可信授权登记、正常迁移与普通数据库角色、只读 JWT/HTTP、真实 Node SDK、浏览器页面。Kubernetes/宿主测试替身仅用于明确的身份与事务测试；本地真实控制面验证防护安装，不能签发 Kata、云或 GPU 认证。

必验行为：原子回滚；相同键与冲突重放；真实双跳 TLS COMMIT ACK 丢失；撤权、换代、epoch、permit过期及节点 fence；冻结非空旧 ACK 基线；RLS与表禁写；schema漂移在入口前拒绝；分页固定观察与缺失；超过 JS 安全整数的数量逐字往返；UI清旧证据。维护升级须正常 owner 迁移、普通身份 preflight、排空与镜像门禁。

## 实现落点与不变式

| 落点 | 本轮行为 |
| --- | --- |
| `termination_runtime`、`runtime`及受控资源模块 | 真实 GET 验证后内部构造不可反序列化的 `VerifiedLaunchResources`；绑定完整 launch/node/boot，保留实际 Pod 与独立 Class 配置；不接受普通调用者的观察 JSON。 |
| `record_launch_authorization` | 原锁序、实时权限、节点 fence 和认证覆盖继续成立；ACK、不可变观察及 journal 水位同事务提交，任一失败共同回滚。入口与最终可能阻塞写入之后均以数据库 `clock_timestamp()` 检查观察新鲜度及本次请求／ACK有效期限。 |
| `0046_launch_pod_resource_observations.sql` | 新观察表、封闭旧 ACK 基线、精确复合外键、双向 deferred 完整性约束、append-only 和 FORCE RLS；只有独立 termination 身份经窄入口写入，普通角色不能直接写表或调用该入口。 |
| 启动与独立 preflight | 核对正式 checksum、表形状、列权限、RLS、精确函数及触发器；同名 no-op、禁用 guard、额外写授权均失败关闭。 |
| `resource_accounting`及签名游标 | 固定不可变观察 ID 或首次缺失；当前 generation/launch、所选历史 launch、epoch、主体、项目、筛选方式和 limit 均绑定。每页仍前后新事务鉴权，返回前复核原身份和 token。 |
| OpenAPI、TypeScript SDK、控制台 | `KUBERNETES_API_READBACK` 配非空观察，`NOT_CAPTURED` 配 null；固定 request/limit/overhead/effective 键，CPU millicores、内存和临时盘 bytes。19位十进制字符串不转 Number，检查正量、已知 Flavor、request=limit、合同单位换算及有效量加法。 |

观察时间允许的当前窗口为数据库时间之前30秒至之后2秒，入口及最终 fence 各检查一次；它限制本次资源能力的使用，不把历史观察改造成每次查询都需重新采样。纯 Pod/Class RV 变化及相同规范化内容重放复用原观察 ID、原时间和原 RV。内容冲突拒绝覆盖；真实 COMMIT ACK 丢失后仍使用原注册键及已提交观察。

## 已完成验收与保留门禁

私有证据在 `.local/trusted-observation-20261015/`；下面各行是各自的验收范围，不能相加为一轮完整验收。Kubernetes／宿主替身不是 Kata 或云实机证明。

| 验收范围 | 当前结果 | 证据与边界 |
| --- | --- | --- |
| 新可信登记数据库专项 | **8项通过** | 正常迁移、普通 termination 登录、真实 mTLS；原子回滚、内容／RV重放、真实双跳TLS已提交 ACK 丢失、撤权锁等待、过期旧 ACK、RLS／禁写／preflight 漂移及跨租户非空旧基线。`docker-probe-v2/`；初轮失败保留。 |
| 新观察 HTTP／独立 Node SDK | **1项组合专项通过** | 真实 JWT/JWKS、普通 API 角色和正式可信登记；实际 INSERT 后阻塞高水位写入，第一页缺失后才 COMMIT，且 `recorded_at<=cutoff`，后页仍 null，重新第一页才捕获；精确19位 bytes 往返和撤权拒绝。 |
| 普通原生检查点 | **461通过／0失败／278环境专项 ignored** | `native-final-upgrade/record.json`；三批按未变程序SHA复用结果，变更目标单独重建重验，不称单轮全跑。ignored 不计通过，完整候选绑定以最终回执为准。 |
| SDK／控制台 | **SDK 77项、资源账本 Chrome 8项通过；控制台构建通过** | 固定键与精度、请求参数、错误／撤权清旧、缺失UNKNOWN、取消旧请求及实例切换；浏览器 HTTP 合同替身不替代真实产品全链。 |
| 0045→0046维护门 | **PASS** | `maintenance-v1/record.json`：真实K3s1.36.4、独立TLS PG、普通owner正常SQLx prefix45与从公开基线取得的10份正常角色脚本；封闭、排空、正常迁移46、普通app预检、新Pod UID恢复和操作锁释放。空prefix45维护机制与上面的非空基线专项分别证明；Alpine真实进程不是生产服务OCI。 |
| 完整Docker数据库矩阵 | **PASS_BATCHED_FINAL_ARTIFACTS：37组／201通过／0失败／0ignored** | `acceptance-summary.json`：`docker-full-v2`前9组42项与`docker-remaining-v2`全部28组159项。两批间仅`tests/automation_upgrade.rs`及其独立测试程序变化，其余公开源码、二进制和SDK逐SHA不变；变更后的升级用例在第二批通过。每批运行前后source／制品／SDK一致及自有清理确认，当前源码与最终快照核对。不是单轮全跑，旧失败保留。 |
| 普通生产Docker镜像 | **PASS** | `docker-production-ci-final/record.json`：535个冻结输入前后SHA一致，实际linux/amd64 runtime正常release构建1013.76秒，runner复用同context构建3.827秒；锁定SQLite实际构建／链接、4项nonroot/read-only/network-none/drop-caps smoke，以及真实secrets-init三个profile、幂等和权限反例通过。与当前根目录仅有明确cfg(test) BFF夹具差异；自有2个标签和源码副本清理确认，共享builder/cache保留。 |
| 新提交与GitHub CI | **本地门通过，待同步后核对** | 发布回执按精确提交核对远端树及各CI作业；旧提交结果不能替代本候选，本地验收不提前声称新CI成功。 |

维护验收38.01秒，16次Docker VM真实 `MemAvailable` 采样最低4.588GiB；自有PG启动后4.775GiB，未触发3GiB停止门。本机最终 `sandboxd` SHA-256为 `0a2e1094ae7c65558a19905b92e3906205735a026fd885d19a252195469df04f`，维护前后源码及二进制不变，自有PG和K3s精确身份清理确认。Gate保留两次有界实际dry-run重试的 `CHILD_FAILURE` 记录，随后真实准入验证通过，没有删除失败记录。这些内存采样用于本次测试资源预算，不是沙箱资源节省率。

## Standards

独立规范轴审查未发现需要修改的问题，**0项发现、0项未关闭**。代码审查、分批本地验收与新提交CI分别记录，不替代生产上线认证。

## Spec

独立规格轴发现并修复 **1项，0项未关闭**：仅增大数据库 compute lease、尚未得到宿主延期 ACK 时，已过期的旧注册请求与旧 ACK 原来仍可能因当前 lease 更长而被接受。现在登记入口及所有可能阻塞的写入后的最终 fence，都用数据库当前时钟要求本次请求期限和 ACK 的有效期限仍在未来；观察新鲜度另行检查。真实旧许可自然到期、数据库已续期但 extension 未 ACK 的反例拒绝，ACK／观察／水位不产生半提交；不放宽数据库或宿主期限。

## 初始失败、构建与夹具修正

1. 基线GitHub CI `38720653809` 的正式Docker SQLite阶段报 `ModuleNotFoundError: common`。严格context包含 `sqlite_build.py`，遗漏其唯一仓库本地导入 `scripts/release/common.py`；补精确白名单项，继续最终排除私有目录及生成依赖，没有扩大成整个release目录。真实构建及smoke仍以上表最终结果为准。
2. BFF自建临时数据库原先未安装正常 termination 角色入口；0046正确拒绝缺失执行授权。夹具补正常 `termination-role.sql` 初始化，不给API调用观察入口，也不绕过生产guard。
3. 历史自动化升级测试原 metadata 快照未区分0046的新增表、触发器和函数。修正只排除精确新增对象，并独立核对0046两个FORCE RLS表、六个精确触发器及函数签名／正文／安全属性；原历史对象的严格不变断言继续成立，不使用宽泛名称过滤。
4. 旧源码release构建在过期ACK生产修复后仅取消自有构建进程，重新从冻结context正常构建；旧构建不能计作修复后制品。初始专项、完整矩阵及构建失败的原日志／回执保留，修复后结果单独登记。

没有靠调大线程栈、放宽业务期限、禁用约束、修改旧迁移、伪造观察或把UNKNOWN填零取得通过。完整矩阵以两批最终制品核对的实际37组201项为依据，未把初轮失败或仅专项成功计为整轮通过。

## 协同升级与后续顺序

服务端0046、对应二进制、OpenAPI生成SDK和控制台作为同一资源证据合同升级。先封闭并排空旧writer，正常owner迁移和组件grants，再用普通身份preflight，部署批准摘要后恢复。旧程序不能与新schema未经认证混跑，也不承诺直接应用回退。API新增必需的 nullable `pod_resource_observation` 及新的证据枚举；严格校验的旧客户端应随服务端升级。旧资源账本游标没有本轮固定观察选择，升级后按 `INVALID_CURSOR` 丢弃并从第一页读取，不通过兼容回退再查最新观察。

本轮交付普通CPU启动配置事实与可信归属，不是实测利用率、物理独占容量、GPU或恢复实机认证。缺观察的旧launch继续UNKNOWN；停止和释放仍依赖原本地可信终止与清理证明，不依赖当前Class是否可读。本地矩阵、维护及镜像已通过，新提交CI单独核对；随后按开发表推进有预算／期限／撤销／GC的镜像和节点预准备、端到端冷暖启动实测。GPU设备身份、独占租约、真实采集和回收继续单独实施认证。
