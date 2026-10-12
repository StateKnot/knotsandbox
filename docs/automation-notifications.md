# 项目自动化异常收件箱

该模块持久记录项目内自动化运行的 `FAILED` 和 `OUTCOME_UNKNOWN` 异常事实，供控制台和其他微服务通过正常身份认证接口读取、确认。收件箱属于项目，未绑定原规则创建者；具有当前项目权限的另一位管理员可以处理原创建者停用后留下的通知。

确认只表示某位管理员已经看到这条历史异常。它不表示原运行已经恢复、影响已经关闭，也不暂停、恢复、撤销、重试或创建自动化任务。处理实际故障时，应另外读取原运行及其关联操作，再使用各自正常的授权接口。

同一个运行先产生 `OUTCOME_UNKNOWN`、后来确定为 `FAILED` 时，收件箱保留两条独立通知。UNKNOWN已阅不会自动确认后来的FAILED；每条通知分别读取自己的ETag并确认。其他微服务应以通知 `id` 处理收件项，不能只按 `run_id` 合并或覆盖历史来源。运行状态改变后，当前仍有权限的调用方仍可用原通知ID、原key和原ETag恢复该通知的有效原回执。

2026-10-11的升级后双状态合同已在独立Docker TLS PostgreSQL验收：来源和已阅状态各自保留、同文本key跨通知目标的回执隔离、重复终态来源整事务回滚及分页/撤权通过。该用例使用正常coordinator LOGIN持久来源写入和当前签名身份Interface，没有执行完整controller未知结果恢复或重计浏览器全链。详见[双状态交付](../research/database-upgrade-progression-delivery-20261011.md)。

2026-10-11 已补齐真实 Chrome/Keycloak/BFF/API/TLS PostgreSQL 异常确认全链：实际专用 coordinator 产生 FAILED 通知，真实 ACK 提交后丢失回执，重载及当前读写撤权期间保留 UNKNOWN，恢复权限后原 key、空对象和旧 ETag 重放得到完全相同回执。完整业务记录不变，回执、审计与因果事件各一条；原账户、诊断、事件、未来自动化、最终停止与撤权链全部保留。该链 1/1 通过，Rust 普通库 270 通过、118 明确 ignored，严格 all-target Clippy/fmt 与控制台构建通过。此前通知 PG、签名 API/SDK 和 UI 合同证据保留，范围分别记载。详见[真实 BFF 验收](../research/automation-notification-bff-20261011.md)和[功能开发验收](../research/automation-notification-inbox-20261011.md)。云环境、HA、容量和签名发布尚未认证。

## 安装与升级

使用包含正式 `0042_automation_notifications.sql` 与 `0043_deferred_file_activity_scope.sql` 的同一发布版本，通过正常 `sandboxd --role migrate` 完成迁移和角色安装。该命令使用操作者按现有部署流程提供的受限迁移凭据，不在 API 启动期间自动迁移。当前正式迁移账本为 1..37、39、40、41、42、43，共 42 条；38 永久保留且从未发布。0043 修复受限组件提交时延迟文件活动检查的身份与范围，不改变收件箱来源合同。不要手工填造 SQLx 账本、给组件扩展宽表权限或修改此前迁移的 checksum。

迁移角色先应用新表、RLS 和触发器，再按正常流程执行 `scripts/sql/roles.sql`、`scripts/sql/automation-role.sql`。正常迁移命令已经包含这两份脚本。`sandbox_app` LOGIN 由 DBA 独立配置；脚本不创建账号、口令或修复错误账本。API 安装不依赖可选 `sandbox_automation` LOGIN 是否存在。

角色权限固定为：

| 身份 | 新收件箱权限 |
| --- | --- |
| `sandbox_app` | SELECT；仅 UPDATE `acknowledged_at`、`acknowledged_by`、`version`；仅 EXECUTE 项目事件头的窄加锁函数 |
| `sandbox_automation` | 无通知表读写权限，不调用 ACK 加锁函数；继续写原运行及其正式事件 |
| PUBLIC | 无通知表权限；不可直接执行来源派生和事件头加锁函数 |

来源派生函数以固定 `pg_catalog` search path 和当前租户上下文运行，只接受已持久化运行的匹配异常事件。API 没有通知 INSERT、DELETE、TRUNCATE 或来源列 UPDATE 权限，也没有事件头 UPDATE 权限。窄加锁函数只锁当前租户指定项目的既有事件头，不创建或改写事件序列。

API 的 `check_automation_api_schema` 包含新表的检查：正式迁移、FORCE RLS、启用触发器、必要列权限、窄函数 EXECUTE，以及禁止伪造来源的权限必须满足。检查失败会使 API 启动失败，不绑定业务监听端口。可关闭自动化路由的嵌入式路由配置返回 `api_features.automation_notifications=false`；正常 `sandboxd` 安装在检查通过后提供该能力。该字段只描述已配置的接口，不证明调度 worker 正常、个人有权限或原故障已经恢复。

先迁移和安装权限，再部署依赖此接口的 API、SDK 调用方和控制台。旧调用方继续使用原有自动化接口。旧 worker 写入兼容的正式运行事件时，来源通知由数据库触发器产生，不需要它新增通知表权限或升级专用通知 worker。新 API 不能在仅有旧 schema 的数据库上降级运行。回退应用前必须核验实际旧二进制对较新迁移账本的兼容性；当前完整 N/N−1 发布仍未认证。回退不能执行旧迁移器或手工重放旧角色脚本；旧角色脚本可能撤销新表/函数权限。该模块不提供删除新迁移、修改 checksum 或删除通知历史的自动回退路径。

只派生迁移生效后新提交的异常事件。迁移不扫描或回填旧事件，也不为已有 FAILED 历史凭空建立通知。已有运行历史仍通过原自动化运行查询接口访问。OUTCOME_UNKNOWN 后续合法版本的异常事件可以产生首条通知，但不会覆盖已经存在的首条历史来源。

## 认证和权限

机器调用复用已配置的 OAuth2/OIDC access token 校验、身份解析及 `X-Tenant-ID` 请求上下文。使用 access token，不能使用 OIDC ID token。独立身份服务和对接统一身份服务使用同一产品权限模型。`action-scopes` 模式下还须具备对应 token action scope；`generic-access` 模式遵循该配置的 access scope 合同。两种模式都必须满足数据库中的当前租户、项目、主体和 grant 权限。

| 操作 | 产品权限 |
| --- | --- |
| 项目分页和单条读取 | `automations:read` |
| 确认，包括原 key 回执重放 | `automations:write`；该接口不额外要求 `automations:read` |

ACK 不要求原规则的执行动作权限、原创建者仍可委派或剩余运行预算。它只更新收件箱事实。读取不要求 `operations:read`；查询关联操作时仍须满足操作接口本身的权限。

每次请求都使用当前身份和 live grant；签名游标和已有回执都不能代替授权。读取在查询完成后复核权限。ACK 在锁等待后、保存回执前和提交前复核身份、token 到期时间、主体和租户/项目 grant。资源或项目不可访问时按现有资源隐匿合同返回 404；无效或到期身份按正常认证合同拒绝。浏览器经现有 BFF 会话代理调用，确认仍要求既有 Origin 和 CSRF 校验。

## 三个接口

完整机器合同见 [OpenAPI](../openapi/sandbox-api.yaml)。请求携带 `Authorization: Bearer <access-token>` 和 `X-Tenant-ID: <tenant-uuid>`；URL 中的 ID 均为 UUID。

| 方法与路径 | 输入与响应 |
| --- | --- |
| `GET /v1/automation-notifications` | 必填 `project_id`，可选 `instance_id`、`limit`、`cursor`；200 返回 `{items,next_cursor,cutoff}` |
| `GET /v1/automation-notifications/{id}` | 200 返回单条通知及强数字 ETag，例如 `"1"` |
| `POST /v1/automation-notifications/{id}/actions/acknowledge` | 严格空 JSON 对象 `{}`、`Content-Type: application/json`、`Idempotency-Key` 和该通知的 `If-Match`；200 返回 `{resource,idempotency_expires_at}` 及 ETag |

分页默认 50 条，范围 1..100，按 `created_at DESC,id DESC` 排序。`cutoff` 是数据库时钟确定的 UTC 截止时间，后续页沿用。游标签名绑定通知历史类型、租户、调用主体、项目、实例过滤条件、实际 limit 和 cutoff，24 小时到期。翻页时保留相同过滤条件和 limit；不要跨账号、项目或历史类型复用游标。`next_cursor=null` 表示本次窗口结束。查询中新提交的通知须开始新一轮分页才能纳入；确认状态不是全表快照，翻页过程中另一位管理员可以确认已有记录。

公开通知精确包含以下字段：

| 字段 | 含义 |
| --- | --- |
| `id`、`tenant_id`、`project_id` | 通知及其固定产品范围；`id` 等于首来源事件 ID |
| `instance_id`、`automation_id`、`run_id` | 来源的固定实例、规则和原运行 ID |
| `source_event_id`、`source_run_version` | 首来源事件及产生异常事实时的原运行版本，确认后不变 |
| `source_status` | 仅 `FAILED` 或 `OUTCOME_UNKNOWN`，是历史状态而非当前运行状态 |
| `created_at` | 通知生成时的 UTC 时间 |
| `acknowledged_at`、`acknowledged_by` | 初始均为 null；首次确认后为 UTC 时间及确认主体 UUID |
| `version` | 初始为 1；首次确认后为 2，覆盖通知自身状态 |

响应不含原事件 payload、命令、环境变量、备份参数、内部错误字符串、issuer/subject、委派凭据或个人收件人。即使原运行后来恢复、完成或失败，通知的历史来源也保持不变。应通过 `GET /v1/automation-runs/{run_id}` 查询原运行当前状态。

## ETag、丢失回执和并发确认

ACK 的 `If-Match` 使用通知详情 GET 的 ETag，不能使用实例、规则或运行版本。只接受一个带双引号的正整数强 ETag；缺少返回 428，`*`、弱 ETag、多个值或非正整数拒绝。key 按现有协议为 1..128 个 ASCII 字母、数字或 `-_.:`。

首次确认以通知 ID、调用主体和 key 固定请求，原空对象及原 `If-Match` 一起参与摘要。成功后版本从 1 变为 2，写入一次 ACK 审计、一次域事件和七天有效回执。接收方应保留原 key、通知 ID、原 ETag 与空请求体，用于连接中断或响应丢失后的核对：

| 情况 | 结果及调用方处理 |
| --- | --- |
| 同主体、同 key、同请求及原 ETag，回执有效且当前仍有权限 | 返回原 200 回执；不重复确认、审计或事件。即使通知已是版本 2，重放仍使用原 `"1"` |
| 同 key 换成另一 ETag | 409 `IDEMPOTENCY_CONFLICT`；读取并处理原提案，不自动换 key |
| 新 key 携带旧版本 | 412 `VERSION_MISMATCH`；重新读取通知，再由调用方明确决定下一步 |
| 原回执超过七天 | 410 `IDEMPOTENCY_EXPIRED`；先读当前通知，不把过期当作确认未发生 |
| 已确认通知，使用新 key 和当前版本 2 | 返回 200 当前通知和新回执；不再写第二次 ACK 审计或域事件 |
| 当前 token、身份或 grant 不再允许 ACK | 拒绝，包括已有回执的重放；旧回执不能恢复权限 |

空对象之外的字段和 JSON 类型拒绝。非法 body 在摘要和业务写入之前失败。七天回执窗口及其后 90 天过期 key tombstone 沿用现有 management receipt 协议；调用方不可依赖无限期回执保留。不会自动换 key、自动确认下一条通知或重新提交原自动化运行。

使用现有 TypeScript 客户端的 ACK 调用形态为：

```ts
const result = await client.POST(
  "/v1/automation-notifications/{id}/actions/acknowledge",
  {
    params: {
      path: { id: notificationId },
      header: {
        "X-Tenant-ID": tenantId,
        "Idempotency-Key": originalKey,
        "If-Match": originalNotificationETag,
      },
    },
    body: {},
  },
);
```

`client` 由既有 `createSandboxClient` 配置 HTTPS base URL、当前 token provider 和租户。读取及重放也经过正常 HTTP，不使用绕过授权的通知专用客户端。SDK 传输重试保留同一提案；409、410、412 或权限拒绝不是新建 key 的信号。

## 事务、安全和运维

通知由 `domain_events` 的 AFTER INSERT 触发器在原事务中派生。触发器核对真实运行的租户、项目、聚合 ID、版本、状态和运行因果 request ID，并从运行行读取实例/规则范围。唯一键 `(tenant_id,run_id,source_status)` 保留首次同类异常；原事件回滚时通知一起回滚。正常 SKIPPED、CANCELLED、SUCCEEDED 和没有异常状态的事件不生成通知。

同类 PostgreSQL 触发器按名称执行；来源派生排在原事件序列分配之后。来源写入和 ACK 都采用项目事件头 → 通知行的锁序。API 的窄加锁函数不修改事件头，锁等待后重新检查完整权限，避免反向锁序及等待期间授权过期。原数据库的 3 秒 lock timeout、10 秒 statement timeout 和 15 秒事务空闲超时保留；依赖超时不代表确认是否已经提交，仍按原 key 核对。

ACK 的审计 `request_id` 是本次真实 HTTP 请求 ID。ACK 域事件的 `request_id` 保留原运行 UUID 作为因果来源，使已有与当前事件自动化来源识别都将其排除，不因确认再次触发规则。它不是重新执行原请求。通知、审计、域事件和回执在一个事务提交；不修改原 run、delegation、预算、operation、执行活动或备份 hold。

收件箱使用租户 FORCE RLS、项目历史索引和项目/实例历史索引，采用键集分页，不执行大 offset 扫描。读取历史不需要启动另一个 worker。该版本通过查询和显式确认提供持久收件箱，没有邮件、短信、Webhook、后台外发重试、推送成功或送达状态。

没有自动历史删除、归档或用户可调用的删除接口。部署容量应包含通知、原事件、审计、回执及索引的持续增长，并监控数据库存储、连接数、查询耗时与异常数量；不能把有限规则预算等同于整个平台历史容量有限。备份继续使用现有数据库备份与恢复流程。目标云、容量基线、保留归档政策和恢复演练应进入各自正式验收，当前本地功能验收不代替这些结果。

## 验收入口

新增真实 PostgreSQL 用例独立放在 `automation::notification_tests::`，保留原 18 个自动化验收用例不变。新增用例覆盖：真实 FAILED 事件与确认幂等/撤权、合法 UNKNOWN 版本去重和事务回滚、事件头等待期间 grant 撤销/token 到期、UNKNOWN 来源与 ACK 并发锁序、普通及缺状态事件兼容和伪造异常来源拒绝。`automation::notification_http_tests::` 使用正常签名创建/手工续期产生真实版本拒绝，由 Node SDK 在真实确认提交后丢弃首响应并重放原请求。Chrome HTTP 合同验证 UI 异常确认及重载；真实 OIDC/BFF 回归另验证当前能力、收件箱空列表及既有完整管理链，二者的范围分别记录。

统一验收记录保存在 `.local/notification-inbox-20261011/delivery-record.json`，绑定源文件 hash、正式迁移 checksum、真实角色、原 18 个与新增用例各自计数、实际命令及清理结果。未运行的 ignored tests、mock HTTP 响应或界面截图不作为真实数据库或生产环境通过证据。
