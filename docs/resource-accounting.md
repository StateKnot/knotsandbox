# 启动资源与释放账本

`GET /v1/instances/{id}/resource-accounting` 读取实例的启动申请合同、可信Pod配置观察和不可变配额状态记录。合同来源为 `REQUESTED_COMPUTE_QUOTA`，记录控制面受理的普通 CPU／内存申请；配额记录说明各用途何时进入 `PENDING`、`ALLOCATED`、`RELEASED`，以及该次变化的账户快照。接口需要当前项目的 `instances:read`，只读，不续期、不启动实例，也不触发配额释放。

受信任登记路径将精确 Pod UID 的实际 request、limit、Pod overhead 和有效 request／limit 与启动授权同事务保存。`pod_resource_evidence=KUBERNETES_API_READBACK` 时 `pod_resource_observation` 非空；缺观察为 `NOT_CAPTURED` 加 null，界面显示 UNKNOWN。宿主 CPU、内存、I/O 采样由[实例运行指标](runtime-metrics.md)提供；启动申请、Pod 配置、宿主用量和宿主容量分别表达不同事实，不能用申请数或配额数作为利用率分母，也不能据此计算节省比例、专属容量或剩余资源。

## 查询与分页

请求使用正常 OIDC 身份及 `X-Tenant-ID`。API 在读取前、读取后分别以新的事务检查当前项目授权，并在返回前重新解析身份及检查 token 到期。查询期间撤权、主体禁用、身份绑定变化或 launch／恢复纪元变化时，旧页面不能作为成功结果返回。客户端收到权限拒绝后应清除旧视图。

| 查询参数 | 合同 |
| --- | --- |
| `launch_id` | 可选 UUID。省略时选取当前启动合同，账本页包含与该实例关联的全部用途和历史。显式指定时仅返回精确绑定该 launch 的普通 CPU／内存配额记录。历史 launch 必须属于此实例，并有当前平台恢复纪元中的合同。 |
| `limit` | 1–100，默认 50。 |
| `cursor` | 上页返回的非空签名游标，最长 2048 字符；第一页省略。 |

省略 `launch_id` 与显式传入当前 `launch_id` 的结果范围不同。默认页可以包含实例操作和同工作区关联操作的生命周期、执行、文件、备份与恢复记录；显式 launch 页不会包含没有普通启动绑定的用途和历史。`selected_launch_id` 说明响应中的合同选择，不表示默认账本页的每条记录都归属该 launch。

`receipts.items` 按 `(captured_at, id)` 倒序排列；`cutoff` 固定本次分页上界，`next_cursor=null` 表示该快照没有下一页。签名游标有效期为 24 小时，绑定主体、租户、项目、实例、当前代次和 launch、选中 launch、显式或省略的 launch 筛选方式、恢复纪元、页大小，以及第一页选择的不可变观察 ID 或明确的缺观察事实。只按时间过滤不足以固定证据：cutoff 前 INSERT、第一页之后 COMMIT 的观察也不能突然出现在后页。新观察只能重新读取第一页纳入。翻页须保留原筛选与 `limit`，只替换 `cursor`；改变筛选、页大小或作用域时重新读第一页。实例换代后，默认页和显式历史页的旧游标均失效。每页仍实时撤权检查，快照不维持已撤销的访问资格。

| 响应或错误 | 处理方式 |
| --- | --- |
| `200` | 同时检查 `request_evidence`、`contract`、每条记录的 `history_start` 与启动绑定。空页不表示实际用量为零或资源已释放。 |
| `400` | 查询字段、UUID、范围或游标无效；游标失效或作用域变化后重新读第一页。未知字段和重复参数被拒绝。 |
| `401` | 身份无效、失效或到期；清除旧视图并重新取得有效身份。 |
| `404` | 实例／指定历史 launch 不可见或当前授权已撤回；不能解释为零用量。 |
| `409 RESOURCE_ACCOUNTING_EPOCH_CHANGED` | 实例仍属于旧平台恢复纪元；先核对恢复与实例状态。 |
| `409 RESOURCE_ACCOUNTING_BINDING_CHANGED` | 读取期间实例绑定发生变化；重新选择启动并读第一页。 |
| `409 RESOURCE_ACCOUNTING_OBSERVATION_CHANGED` | 已固定的不可变证据不可用；保留错误并重新读取第一页，不能改选“最新值”。 |
| `503` | 服务不可用；保留错误状态，不能补造账本或零值。 |

响应禁止缓存。精确字段和类型以[正式 OpenAPI](../openapi/sandbox-api.yaml)为准，TypeScript 用法见[SDK](../sdk/typescript/README.md#resource-accounting)。

0046对应的服务端、生成SDK和控制台需协同升级：响应新增必需的nullable `pod_resource_observation` 和 `KUBERNETES_API_READBACK` 枚举，严格客户端不能沿用仅支持NOT_CAPTURED的旧合同。旧资源游标没有固定观察选择，升级后返回 `INVALID_CURSOR`；丢弃旧cursor、清除原明细并重读第一页，不回退到按当前最新观察查询。

## 合同、用途与账户快照

`contract` 包含实例、工作区、启动代次 `generation`、`launch_id`、`cluster_epoch`、原操作 `operation_id`、申请 `cpu_millis`／`memory_mib` 及捕获时间。CREATE 和 STOPPED→START 在真实新启动身份提交时捕获合同；RESTART 先完成旧启动释放，再为新身份捕获合同及归属。续期不产生新合同，停止、删除或读取也不会根据当前规格回填历史合同。RESTORE 的隔离计算使用独立用途，不作为普通运行启动合同。

每条记录保留 `reservation_id`、`quota_account_id`、`operation_id`、`resource_id`、`operation_kind`、用途、维度、单位和账户范围。只有精确绑定普通启动的记录才有 `contract_id`、`generation`、`launch_id`、`cluster_epoch`；其余为 null，不能从当前实例补齐。

| `purpose` | 范围 |
| --- | --- |
| `ORDINARY_COMPUTE` | CREATE／START／RESTART 的普通 CPU 和内存配额。 |
| `INSTANCE_LIFETIME` | CREATE／RESTORE 的实例数配额。 |
| `WORKSPACE_STORAGE` | 工作区容量配额。 |
| `EXECUTION` | 命令执行槽位。 |
| `FILE_PROCESS`、`FILE_CONTENT` | 文件传输过程与内容字节配额。 |
| `BACKUP_ISOLATED_COMPUTE`、`BACKUP_RETAINED_STORAGE`、`BACKUP_TEMP_STORAGE` | 备份隔离计算、保留存储与临时存储配额。 |
| `RESTORE_ISOLATED_COMPUTE`、`RESTORE_TEMP_STORAGE` | 恢复隔离计算与临时存储配额。 |
| `LEGACY_UNBOUND` | 升级前已有预约的来源无法归入上述用途，保留未绑定事实。 |

`account_scope=TENANT` 时 `account_project_id=null`；`PROJECT` 时该字段为当前项目。租户与项目是同一申请的两层独立准入约束，不能相加为消耗量。新普通启动在两层各有一条 CPU 和内存预约，共四条预约；同一预约的多条状态记录也不能相加为资源量。

`amount` 是该预约的数量；`limit_value`、`pending_value`、`allocated_value` 和 `account_version` 是捕获这次变化时的账户快照，不是整个分页截止时间的账户当前余额。状态记录和原配额变化在同一事务中产生，包含同一事务内发生的中间状态；事务失败时共同回滚，不从最后余额重建过程。各维度仅按自身 `unit` 解释，不能跨单位汇总。

所有新增数量、账户版本和代次以十进制字符串传输，最多 19 位且不超过 `9223372036854775807`。客户端保留字符串；需要整数运算时使用 `BigInt` 或精确整数库，不能转成 JavaScript `Number`。

## 可信 Pod 配置观察

`pod_resource_observation` 固定实例、工作区、代次、launch、平台 epoch、Pod UID、Node UID 和 boot ID，并保存实际 Pod GET 的不透明 resourceVersion。`source=KUBERNETES_API_READBACK` 表示来自 runtime 内部验证的 Kubernetes 回读；nodeguard 认证启动及节点身份，不宣称测量这些配置值。观察记录与真实授权回执共同提交并不可变；续期或纯 RV 变化复用初始观察，不回填旧历史。

`workload_request`、`workload_limit`、`effective_request`、`effective_limit` 各自使用固定键 `cpu_millis`、`memory_bytes`、`ephemeral_storage_bytes`。`pod_overhead` 仅有 CPU 和 memory；完整对象明确没有 overhead 时零值是已确认配置，缺对象或读取失败不能补零。内存和临时存储的 bytes 与申请合同的 memory_mib、配额的 MIB 单位分开列示，不跨单位直接相加。

`runtime_class` 是同次可信验证中读到的受守卫 Class 配置：UID 加受控内容 SHA-256 标识配置，overhead 单独保存。Class RV 仅为 GET 的不透明元数据，不证明 Pod 创建时采用该 Class RV；Pod 自身 overhead 不能用 Class 值替代。响应不暴露原始 Pod JSON、任意 metadata、内部登记能力或无限资源字典。SDK 与控制台独立校验固定键、作用域、i64 精度和有效量加法，错误、撤权和作用域变化清除旧证据。

## 历史与释放语义

迁移 0045 在受锁保护下固定升级前已存在的预约 ID 基线，随后只捕获真实写入的状态变化。迁移不为历史预约制造 `PENDING`、旧合同或 Pod 观察，不更改既有配额余额。旧启动没有合同则 `request_evidence=HISTORY_START_NOT_CAPTURED`、`contract=null`；即使当前实例仍有规格，也保持 UNKNOWN。旧预约升级后的真实变化可产生 `history_start=LEGACY_UNBOUND` 的记录；用途可从原操作识别时仍保留其用途，但普通启动绑定保持未知。

0046另行冻结维护切换前已提交的base／extension授权ACK及精确归属，旧基线ACK复用仍保持缺Pod观察。没有提交ACK的旧permit不进入基线；不能用缺观察、旧时间或调用者GUC获得历史豁免。新ACK必须与可信观察或合法复用的已有观察同事务成立，旧记录不能由今天的Pod／Class回填。

新预约从 `PENDING` 开始，只允许 `PENDING→ALLOCATED`、`PENDING→RELEASED` 或 `ALLOCATED→RELEASED`，每个状态最多一条不可变记录。预约的原账户、操作、资源和数量不能在后续变化中替换。

新普通计算预约的释放绑定原 launch 的可信关闭事实：已授权启动需要匹配原身份的本地终止证明与清理回执；从未授权启动需要持久的 never-authorized 关闭及精确身份验证。never-authorized 流程先提交关闭事实，再在后续事务释放，不能在关闭证据提交前释放。RESTART 的旧预约持续归属旧 launch。STOP 的受理、Pod 不可见、TTL 到期、指标缺失或一次控制器重试均不能替代这些证明。

其他用途保留各自原有的执行、文件、工作区、备份和恢复保护条件。它们的 `RELEASED` 仅说明对应配额账务已释放，不能据此断言普通 VM 死亡、卷卸载、数据销毁或所有用途都已释放。旧预约仍受原有生命周期保护；其基线标记不构成后来新预约逃避精确绑定的通道。

## 安装与运维

正常 `sandboxd --role migrate` 安装正式迁移和组件权限。0045四表及0046观察／旧ACK基线两表均强制租户RLS、不可变，受限函数固定 `search_path` 且不向PUBLIC开放执行。普通API只取得合同、状态记录、启动绑定和Pod观察表SELECT；runtime不能直接插入、修改或删除观察，也不能读取两类迁移遗留基线。现有配额写入仍通过受限触发器捕获，可信观察只有独立termination身份经正式内部登记入口同ACK写入，不向worker／gateway授予该能力。运行时启动检查及 `sandboxd resource-accounting-check` 核对本模块的schema、迁移checksum、精确函数／trigger、列权限与RLS；额外写授权、缺失或同名替换都拒绝。

升级使用[启动资源账本维护升级门](../deploy/resource-accounting-upgrade/README.md)：固定目标制品与writer身份，实际阻止旧摘要进入，停写并核对Pod、数据库会话及活动租约排空，再执行owner迁移、普通应用身份预检与目标恢复。失败保持维护封闭并保留证据。旧程序允许额外成功迁移不等于已认证0045／0046语义；本模块不承诺N/N−1滚动混跑或旧程序直接回退。正常0045→0046本地维护机制已通过，具体范围、完整回归及新CI状态见[可信观察交付](../research/trusted-launch-resource-observation-20261015.md)。通用数据库备份、恢复与发布顺序见[数据库升级](database-upgrade.md)。

本模块提供控制面申请、配额归属和可信 Kubernetes 配置事实。GPU、预热、利用率与节省比例，以及目标云 Kata、CSI 和生产恢复验收仍需各自完成，不能由此账本推断已通过。
