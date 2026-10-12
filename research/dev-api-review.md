# 生产开发补充：微服务调用契约与 Rust / PostgreSQL 领域设计

本文用于并入《Rust 企业多租户沙箱平台详细开发方案》，只给开发设计，不代表已经实现或通过验收。范围按用户最新确认：公有云从零部署，企业多租户运行非可信代码；产品既能独立部署并自带成熟身份组件，也可接入已有 OAuth2/OIDC；一个 Kata 生产运行时；其他微服务通过公开 API 调用。采用 Ponytail full：一个 Rust workspace、API / worker / gateway 三个部署角色，PostgreSQL 持久操作账本，不引入第二套 gRPC API、Redis、消息总线或通用工作流引擎。

## 1. 对外协议冻结

- 管理接口：HTTPS + REST + JSON，前缀 `/v1`；OpenAPI 是唯一外部契约，控制台和内部业务服务使用同一契约。
- 命令输出和领域事件订阅：SSE；交互终端：WebSocket；大文件：受授权文件会话/对象传输。不得把 shell 命令塞入 URL、标签或监控标签。
- `/health/live` 只证明进程存活；`/health/ready` 说明当前角色是否可接流量。管理 API readiness 不依赖所有工作节点在线。内部运维端点不对租户开放。
- UTC 时间使用 RFC3339，字节数/资源大小命名含单位；外部 ID 是不可解释的 UUID 字符串。租户不能依据 ID、Pod 名称、节点 IP 获得权限。
- 管理 JSON 默认 1 MiB 上限；命令文本默认 64 KiB；列表默认 50、最大 200；每实例最多一个活动执行。大脚本作为经授权文件上传后执行。
- 只公开预定义筛选字段与排序；不允许任意 SQL、PromQL、日志查询表达式、Kubernetes spec 或云厂商资源参数透传。
- 客户端应容忍响应新增字段；请求未知字段拒绝并指出路径。破坏性修改进入 `/v2`，不能通过改变既有枚举含义、默认删除行为或默认网络访问实现。

## 2. S2S 身份、租户与授权

产品提供两个部署配置，业务授权与 API 完全相同：

| 模式 | 身份组件 | 产品责任 |
| --- | --- | --- |
| `standalone` | 随安装包提供固定版本 Keycloak、独立数据库/账号、TLS、邮件和备份配置 | 独立用户登录、账户管理、MFA、服务 client、bootstrap 运维流程；产品库保存租户/项目/grant |
| `external_oidc` | 已有企业 OAuth2/OIDC，不部署 Keycloak | 配置可信issuer/audience/JWKS，验证服务身份、用户登录、claims与撤权能力；同样由产品库保存业务grant |

这两种模式使用同一 JWT validator 和授权代码，仅issuer/client配置与部署依赖不同；不自建密码库、MFA、签发JWT或动态认证插件框架。每次部署默认一个明确的活动issuer；迁移窗口才显式同时允许新旧issuer，不能根据用户任意输入issuer自动发现并信任。

独立版复用 Keycloak 登录/账户页面，Web 使用 Authorization Code + PKCE；用户密码、OTP 与恢复码只交给 Keycloak。初始管理员经一次性运维 bootstrap 创建，启用 MFA 后关闭 bootstrap，禁止长期保留安装默认管理员密码。邀请默认管理员在 Keycloak 创建账户并发送验证邮箱/设置密码等 required action 邮件，再在产品侧为该主体分配项目grant；不另写邮件验证码登录体系。API Client 由管理员在 Keycloak 建立 service account，产品添加对应TenantGrant；支持凭据轮换与立即禁用本地grant。外部模式的用户/凭据创建与轮换由现有 IdP 完成，产品界面清楚跳转到身份管理员流程，不承诺可跨任意IdP远程改密码。[Keycloak管理文档](https://www.keycloak.org/docs/latest/server_admin/)

Keycloak生产数据库与产品数据库逻辑分离、账号分离；可使用同一托管PostgreSQL实例中的独立database，备份/PITR和升级仍分别验证，不直接读写Keycloak内部表。不能使用其仅面向开发的dev-file数据库。[Keycloak数据库](https://www.keycloak.org/server/db)

上线前仍需确认所选提供商支持服务身份、服务凭据轮换与正确audience。OIDC用户登录接口不能直接替代微服务认证。产品主体唯一键固定为`(issuer, subject)`，email、username和display_name都不是身份主键，也不能自动用于合并账户。更换IdP需要受审计的显式主体绑定迁移、冲突检查、grant验证、会话撤销和回滚窗口；禁止同邮箱自动继承管理员权限。

**默认生产接入：**每个调用微服务独立 OAuth client，使用所选提供商支持的 `client_credentials` 获得短时 access token，audience 固定为 sandbox API；采用提供商已支持的非共享静态密码认证方式（工作负载身份、证书或 `private_key_jwt`）。一期不自研授权服务器或 token exchange；standalone 使用随包部署的 Keycloak 提供标准OAuth服务。API 校验 issuer、签名算法白名单、audience、expiry、not-before、subject 和客户端标识；不接受 ID token。Keycloak官方提供OIDC端点、JWKS与client credentials，独立模式复用这些能力。[Keycloak OIDC与服务调用](https://www.keycloak.org/securing-apps/oidc-layers)JWKS 仅取配置的 issuer，不从 token 的任意 URL 取密钥。未知 kid 可以限频刷新，不能 fail-open。

如果已有平台支持证书绑定 access token，可直接复用；OAuth 客户端 mTLS 认证和资源服务验证证书绑定 token 是不同机制，不能只在 token endpoint 使用 mTLS 就宣称 API 防 token 盗用。[RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html)

**租户上下文不得由请求头自行决定。**默认服务身份在平台数据库中绑定一个或若干明确的租户/项目 grant；请求的 `project_id` 仅为授权目标，API 查 grant 后得出 tenant。一个租户专用微服务不需要在每个请求新增 tenant 字段。确需为多个租户代调的聚合服务，采用已有 IAM 签发的单租户 token 或由平台显式配置该 client 的精确 tenant/project allowlist；不提供“任意 X-Tenant-ID + 全租户 scope”捷径。代表用户执行时，只有可信 IAM 明确签发并绑定调用服务的委托上下文可作为 `on_behalf_of`；调用方传入的 user_id 只能是业务标签，不能提升权限。

审计同时记录 `actor_client_id`、`actor_subject`、可选 `on_behalf_of_subject`、tenant/project、授权规则版本与 request_id。token、客户端密钥、命令中的秘密和文件内容不写审计。

权限使用简单固定动作清单与项目级 grants，无需先上通用策略 DSL：

| 权限 | 允许的操作 |
| --- | --- |
| `instances:read` | 实例、Operation 和基本运行信息 |
| `instances:write` | 创建、规格/标签等允许字段变更、启停、删除计算资源 |
| `executions:create/read/cancel` | 分别提交、读输出、请求取消命令 |
| `instances:hard_stop` | 强终止实例上的全部进程，影响终端与后台任务 |
| `workspaces:delete` | 单独删除持久工作区；实例删除权限不包含它 |
| `sessions:create` | 文件/终端/端口会话，继续限制用途、端口和路径 |
| `observability:read`、`audit:read` | 可观测数据和权威审计分权 |
| `security:read/write` | 查看或变更安全策略；弱化策略需额外批准规则 |
| `backups:create/read/delete/restore` | 分别控制备份、删除和恢复能力 |
| `automation:write`、`diagnoses:create/read` | 定时自动化和诊断 |

每次请求都重新校验本地 grant 和 principal enabled 状态；不要把完整租户权限只固化在十几分钟有效的 JWT 中。已有长连接每 30 秒检查撤权版本，检测后立即关闭；上线验证撤权到关闭不超过 60 秒。DB/授权检查不可用时新会话拒绝，既有会话最多到重检边界后关闭。worker 在新副作用前重新校验身份/grant，已失效的历史 schedule 不再启动。可用的本地权限缓存必须具有不超过上述窗口的 TTL，不需要 Redis。

针对未知和无权访问的资源，统一 `404 RESOURCE_NOT_FOUND`，避免跨租户枚举；对当前授权资源上缺少某个动作权限返回 `403 PERMISSION_DENIED`。

## 3. 生命周期 API 与统一 Operation

| 路径 | 成功响应 | 必要条件 |
| --- | --- | --- |
| `POST /v1/instances` | 202，instance + operation 标识 | Idempotency-Key，project、固定 template version、规格、工作区策略 |
| `GET /v1/instances`、`GET /v1/instances/{id}` | 200 | 项目授权；分页；详情返回 ETag |
| `PATCH /v1/instances/{id}` | 202 + operation | If-Match；只允许已声明字段；禁止直接改 observed state |
| `POST /v1/instances/{id}/actions/start`、`stop`、`restart` | 202 + operation | Idempotency-Key、If-Match、实例操作互斥 |
| `DELETE /v1/instances/{id}` | 202 + operation | Idempotency-Key、If-Match；默认保留工作区；已不存在/已删除的重复请求稳定可识别 |
| `DELETE /v1/workspaces/{id}` | 202 + operation | 单独数据删除权限；无有效挂载；显式确认 scope，不与实例删除捆绑 |
| `GET /v1/operations/{id}` | 200 | 相应资源权限 |
| `POST /v1/operations/{id}/cancel` | 202 + 原 operation 的取消请求状态 | Idempotency-Key；只允许可取消阶段；取消不是回滚承诺 |

每个**已接受的变更**有 Operation；权限/校验拒绝只有审计与 request_id，不创建虚假的成功 Operation。Operation 状态固定为 `QUEUED/RUNNING/WAITING/SUCCEEDED/FAILED/CANCELLED`，`WAITING` 必须含稳定 reason 和下次检查时间，不能无限悬挂。超过最长等待需失败或转入需要运维介入的 WAITING，写告警并继续被监控。`cancel_requested_at` 独立字段，只有确认终止并完成必须的清理才进入 CANCELLED。

返回示例：

```http
HTTP/1.1 202 Accepted
Location: /v1/operations/0198f611-41c0-70ee-8201-d7d565ee93b1
Retry-After: 1
X-Request-ID: req_7a62
Content-Type: application/json
```

```json
{
  "operation": {
    "id": "0198f611-41c0-70ee-8201-d7d565ee93b1",
    "kind": "INSTANCE_CREATE",
    "status": "QUEUED",
    "resource_id": "0198f611-4200-7ac1-bf73-2f709d690b00",
    "stage": "ACCEPTED",
    "created_at": "2026-10-03T09:00:00Z"
  },
  "resource": {
    "id": "0198f611-4200-7ac1-bf73-2f709d690b00",
    "desired_state": "RUNNING",
    "observed_state": "PENDING",
    "spec_version": 1
  }
}
```

Operation 完成条件必须以资源实际状态为准：创建完成 = 持久卷可用、隔离运行时正确、强制策略已应用、Pod/目标应用 readiness 通过、观测到本次 generation；受理或 Pod Created 都不等于可执行。失败的 Operation 不覆盖实例真实状态；例如重启超时后实例可能 UNKNOWN，不能伪造 STOPPED。接口返回 `observed_at`、`observed_generation` 和 `spec_version`，监控过期时明确显示未知/陈旧。

实例 ETag 只表示客户可修改配置的 `spec_version`，不要因心跳、指标和 observed state 改变而使写入频繁 412。同一实例的 start/stop/restart/delete/restore-switch 互斥；备份是否阻断 exec 取决于实际冻结窗口并在契约列明。已有冲突操作返回 409 及调用者可访问的 blocking_operation_id，首版不做隐形命令队列。

## 4. 幂等提交与重试契约

所有产生副作用的 POST/PATCH/DELETE 强制 Idempotency-Key，128 字节以内，SDK 使用随机 UUID。作用域：`tenant_id + principal_id + operation_route + target_resource_id + key`；route 使用稳定操作名而非未经规范化 URL。创建目标为项目。调用身份仍有权限时，同 scope + 相同 payload 返回最初的 resource/operation 和原接受状态；不根据资源后来完成状态另建操作。相同 key 不同 payload 返回 `409 IDEMPOTENCY_KEY_REUSED`。

请求指纹由已校验、稳定序列化的请求字段、route、资源 ID 和影响语义的条件头（如 If-Match）生成。排除 Authorization、traceparent、request_id；不要用动态默认值参与重试比较，首次接受时解析出的模板/安全策略版本单独保存到 Operation。收到重复 key 时先做当前权限检查，再重放最初受理结果；不重新做旧 If-Match 的状态比较。

幂等记录与业务变更同事务提交，唯一索引解决并发同 key 竞争；API 不先插一条永久 IN_PROGRESS 然后在进程内做事。若提交成功但响应丢失，重试会命中记录；DB commit 结果不明则返回可重试错误，SDK仍使用同 key。HTTP超时不得自动换key。

默认保证受理结果可重放 7 天，保留过期 key 的 tombstone 90 天，已存在但过期的 key 返回 `410 IDEMPOTENCY_WINDOW_EXPIRED` 和可公开的原资源/operation 标识。响应给出 `idempotency_expires_at`。不能承诺无限期去重；超过保证窗口后 SDK 必须停止自动重提，调用方按存储的 operation_id 或 client_reference 业务记录对账。长于 7 天的未完成 Operation 的 key 不能提前清理。关键非幂等脚本的业务系统必须持久保存 execution_id，不把七天 API 幂等当成外部副作用“恰好一次”。

重试规则：GET 可退避重试；提交只在同 key 下重试连接失败、408/429/502/503/504，遵守 Retry-After；401 只刷新 token 后再试一次；403/404/409/412/422 不自动重试。最大 4 次、单次管理请求 5 秒、总受理预算 20 秒是 SDK 初始默认值，可由调用方缩短。Operation 的等待预算与 HTTP 提交预算分开；等待超时返回 operation_id，并不取消服务端任务。

## 5. 非幂等命令执行：单次派发与结果未知

生产首版复用 Kubernetes exec，通过批准模板内的一次性 Rust runner 执行，不部署额外常驻命令 daemon。每实例最多一个活动执行，交互终端不在此 API 下伪装成有确定结果的执行。

`POST /v1/instances/{id}/executions`：

```json
{
  "argv": ["python3", "/workspace/jobs/task.py", "--job-id", "job_801"],
  "cwd": "/workspace/jobs",
  "env": {"TASK_MODE": "batch"},
  "timeout_seconds": 300,
  "on_timeout": "HARD_STOP_INSTANCE",
  "client_reference": "billing-import-20261003-801"
}
```

默认用 argv，不经过 shell；确需 shell 时显式 `argv:["/bin/sh","-lc","..."]`，调用方承认字符串的解释边界。secret 使用经授权的引用，禁止 API/审计回显值。超时不得为无限；建议默认 300 秒、最大 3600 秒，具体项目规格可限制得更短。`HARD_STOP_INSTANCE` 需要 `instances:hard_stop`，会终止此实例上全部进程、终端与后台服务但保留工作区。服务账号没有该权限时拒绝这种提交，不能执行到超时后再悄悄强杀。若提供软取消模式，必须明示其不能保证所有子孙进程退出，不能把软模式称作强超时保障。

返回 202 包含 execution_id 与 operation_id。Operation 描述派发/终止编排；Execution 描述命令自身进程结果。Execution 状态为 `QUEUED/DISPATCHING/RUNNING/SUCCEEDED/FAILED/TIMED_OUT/CANCELLED/OUTCOME_UNKNOWN`。`exit_code` 仅在确有进程退出结果时提供。0 只表示工作负载报告成功，不能证明业务数据库提交、外部请求或输出可信。

最关键的崩溃规则：

1. 同事务创建 Execution、派发 Operation、幂等与审计。worker 领取后先持久化 DISPATCHING，才发一次 Kubernetes exec。
2. 禁用 exec 的 SDK/HTTP代理自动重发；DISPATCHING 之后 worker、进程、流或节点失联，接任 worker **不能再次 exec**。Kubernetes exec 返回连接失败也不证明命令未启动。
3. 发生不确定状态，标记 OUTCOME_UNKNOWN，保留运行隔离与活跃执行占位，记录最后确认时间。只有证据表明“尚未派发”时可恢复 QUEUED；只因超时、租约失效或 guest 回执缺失不能重试。
4. runner 输出和回执属于不可信工作负载数据，不用它证明 VM 已关闭、身份授权或计费事实；宿主/运行时观测用于确定强终止。确认旧 Pod/VM 已终止并完成 fencing 后才释放执行占位；节点分区时不能根据已请求删除就释放。
5. OUTCOME_UNKNOWN 可最终补录迟到的进程结果，但不触发自动重跑。即便确认命令已死，也不能确定它此前是否已调用外部服务成功。调用微服务必须凭自己的业务幂等键/账本核对；人工选择新的 execution 是新授权动作。

`POST /v1/executions/{id}/cancel` 请求取消；默认强取消接口要求 `mode:HARD_STOP_INSTANCE` 及对应权限。返回 202 仅表示接受。只有终止确认后才可标记 CANCELLED/TIMED_OUT；终止不明仍为 OUTCOME_UNKNOWN，独立返回 `termination_status:PENDING/CONFIRMED/UNKNOWN`。客户端断连、SSE 超时和等待超时不自动取消执行。

执行输出状态与命令结果分开：`output_status:COMPLETE/TRUNCATED/PARTIAL/LOST`、`output_bytes`、`last_sequence`。日志上传失败不能被偷换成命令失败后重试。默认输出总量上限建议 16 MiB/次，超过后继续读并丢弃超额部分或在runner安全截断，标记 TRUNCATED；不得停止读管道把租户进程堵死。用户需要大结果应写工作区或制品存储。

## 6. 查询、分页、流式输出与 Webhook

列表返回 `{items,next_cursor,has_more}`。使用 `(created_at,id)` keyset pagination；游标包含查询摘要、tenant/project、last key、截止创建时间和版本，以服务端密钥签名，短期有效。续页不能换筛选或项目；默认 24 小时过期。首版保证固定排序与不重复跨页，不承诺列表在并发修改下的完整历史快照。审计检索使用同样边界且限定时间窗；不使用 offset 扫描全租户大表。

`GET /v1/executions/{id}/output?after_sequence=...&limit_bytes=...` 提供补读。`GET .../output/stream` 返回 SSE，id 是该 execution 内递增序号，支持 Last-Event-ID；心跳 15 秒，输出分块包含 `sequence/stream/data_base64/observed_at`。字节输出用 base64 避免截断 UTF-8 产生隐含数据损坏，SDK负责增量解码。读取授权在每次重连重做。已经丢失或超出保留期的游标返回 410 及最早可读序号；不能假装无缝回放。多个 stdout/stderr 管道只保证平台接收顺序，不保证严格源进程时序。

慢消费者每连接内存缓冲上限建议 256 KiB；超过后断开并允许从持久块补读，不无限积压。活动输出写受限 spool/对象块；块完成持久化后再宣称可回放。可先展示未落盘实时输出，但必须标记临时数据；生产首版更简单的是只推送已持久化的块。SSE 永久断线不等于执行终止。

Webhook 是可选通知方式，轮询 Operation 永远可用。订阅固定 event_types、项目和已验证 HTTPS 回调地址；不允许每次任务任意指定 callback_url。平台按至少一次投递，消费方先将 `event_id` 唯一键落库再返回 2xx；不承诺有序。回调体含 `schema_version/event_id/tenant_id/project_id/resource_id/type/occurred_at/operation_id/resource_version`，只传必要信息，不传脚本全文、密钥或输出。

回调签名 `HMAC-SHA256(secret, timestamp + "." + raw_body)`，头包含 key_id、timestamp、signature；每次重试使用新 timestamp、相同 event_id。消费者允许 5 分钟时钟窗，常量时间验证签名并做 event_id 去重；双密钥轮换窗口支持更新。SDK提供验证函数。5秒连接/响应总预算，禁止重定向，限制响应体；仅2xx视为确认，429/5xx/超时指数退避加抖动，最长24小时后FAILED并告警；永久4xx直接停投，允许授权重新投递原event_id。

从 DNS 到实际连接均阻止回环、私网、链路本地、云元数据和控制面地址；公有云从零部署默认只接受公网 HTTPS webhook。确需内部回调须走预先批准的网络端点/独立外联策略，不对任意私网 URL 开洞。重复投递还需做目标级并发和流量限额，防回调故障拖垮管理面。

## 7. 错误模型

采用 `application/problem+json`，以 RFC 9457 的 type/title/status/detail/instance 结构加业务扩展 `code/request_id/retryable/operation_id/violations`；detail 可读，客户端只按稳定 code 处理，不解析中文/英文文本。[RFC 9457](https://www.rfc-editor.org/rfc/rfc9457.html)

| HTTP | code | 语义与客户端动作 |
| --- | --- | --- |
| 400 | INVALID_ARGUMENT | 语法、类型、未知字段、非法路径；修复请求 |
| 401 | UNAUTHENTICATED | token 不合法；refresh 一次 |
| 403 | PERMISSION_DENIED | 当前项目或动作授权不足；不自动重试 |
| 404 | RESOURCE_NOT_FOUND | 不存在或无权见；不自动枚举/重试 |
| 409 | OPERATION_CONFLICT | 现有操作/执行占用；先查阻塞任务 |
| 409 | IDEMPOTENCY_KEY_REUSED | 同 key 不同请求；不可自动换 key 重试 |
| 409 | QUOTA_EXCEEDED | 配额预算不足；不与底层容量不足混同 |
| 410 | CURSOR_EXPIRED / IDEMPOTENCY_WINDOW_EXPIRED | 按返回信息对账/重查，禁止盲目重新执行 |
| 412 | VERSION_MISMATCH | If-Match不匹配；读取新版本后由业务重新决策 |
| 422 | CAPABILITY_UNSUPPORTED | 合法请求但当前规格不支持；例如内存恢复 |
| 429 | RATE_LIMITED | API/并发预算；遵守Retry-After |
| 503 | CAPACITY_UNAVAILABLE | 确认没有接受的容量不足；给Retry-After |
| 503 | DEPENDENCY_UNAVAILABLE | DB/运行控制依赖不可用；同key重试提交 |
| 500 | INTERNAL | 未分类平台失败；关联request_id排查，不暴露堆栈 |

`retryable:true` 仅表示可以重新请求查询或用**原 key**重新确认受理，不表示可以新建 Operation 或重新执行 shell。查询 Operation 本身成功但任务失败，HTTP 返回200，失败原因在 Operation.error；不得给GET返回500导致无限盲重试。

## 8. PostgreSQL 最小领域模型与约束

首版只有一个 PostgreSQL 业务数据库。所有租户数据表必须含 tenant_id，资源归属项目也有 project_id；主键/外键使用 `(tenant_id,id)` 或等价复合唯一约束，阻止引用其他租户资源。时间全部 timestamptz；可筛选、可约束和参与状态转换的字段单独列，只有可变快照和错误细节用受大小限制 jsonb。

| 表/表组 | 必需字段与关键约束 |
| --- | --- |
| tenants / projects | enabled、quota profile；project含tenant；项目不能跨租户移动 |
| principals / grants | `(issuer,subject)`唯一；client_id是受信claim映射后的附加标识，不与email合并；enabled、role/actions、project_id、authz_version；同授权唯一 |
| template_versions | immutable image_digest、runner版本、审批状态、资源约束；引用中的版本不能物理删除 |
| security_policy_versions | immutable policy_version、规则摘要；活动引用与变更操作分开 |
| instances | tenant/project/id、name、template_version、flavor、workspace_id、desired_state、observed_state、spec_version、runtime_generation、observed_generation、observed_at、active_operation_id、deleted_at |
| workspaces | size_gib、storage_ref、zone、encryption_key_ref、status、attached_generation、retention、deleted_at；单实例单卷为首版边界 |
| operations | kind、resource_id、status、stage、immutable request snapshot、actor、deadline、lease_owner/expires_at、lease_token、attempts、next_attempt_at、cancel_requested_at、error、timestamps |
| executions | instance_id、runtime_generation、operation_id、argv/cwd受保护配置、timeout、on_timeout、status、dispatch_attempted_at、exit_code、termination_status、output_manifest_ref、output_status、client_reference；每实例活动状态部分唯一索引 |
| idempotency_keys | scope字段、key_hash、request_hash、operation_id、resource_id、原status与必要response、created_at、expires_at、tombstone_until；scope唯一 |
| quota_accounts / quota_reservations | tenant/project、resource dimensions、allocated和pending计数；reservation含operation/resource与状态；维度非负，unique避免重复扣账 |
| audit_events | append-only actor/action/result/resource/request/operation+脱敏diff；时间分区；API账号无UPDATE/DELETE |
| domain_events | event_id、schema_version、aggregate_id/version、type、payload、occurred_at；受理或结果事务内写入 |
| webhook_subscriptions / webhook_deliveries | secret_ref、授权项目、目标URL；event_id+subscription_id唯一；attempt/lease/next_attempt/status；不把消费状态混入事件事实 |
| schedules / task_runs | tz、规则、目标、actor、spec_version、next_run；schedule_id+version+scheduled_at唯一；补跑/并发/预算策略 |
| backups / backup_policies | source generation、volume与template refs、data_time、required/achieved_consistency、manifest_ref、verify_status、保留期限和删除状态 |
| diagnoses | rule_version、observed_at、evidence_refs、findings、operation_id；诊断不会直接修改隔离策略 |

恢复记录可先使用 `operations(kind=RESTORE)` + 新实例 + backup引用，不为同一事实重复新建一个通用“工作流执行”体系。`domain_events` 就是 durable event outbox；worker 任务直接来自 operations，不另造冗余 job/event/message 三张表保存相同任务。webhook_deliveries 管投递，事件事实不可变。使用量按资源分配/释放事件与采样聚合，不用高频INSERT污染实例行。

索引至少包含每租户项目的实例列表 `(tenant_id,project_id,created_at,id)`，任务领取 `(next_attempt_at,created_at)` 的非终态部分索引，operation resource history，execution instance history，事件/审计的 tenant+time，以及必要唯一约束。全库避免对未约束jsonb随意上GIN索引。审计/事件按时间分区，分区清理受留存与归档确认约束；其它表先不为1000运行实例预分片。

RLS 是防程序漏条件的第二道防线：API角色不是owner、不是superuser、没有BYPASSRLS；租户表启用且FORCE ROW LEVEL SECURITY。每个请求在事务中以 `set_config('app.tenant_id', authenticated_tenant, true)` 设置上下文，查询也在该事务内；绝不在连接池会话级保留tenant setting。SQL同时保留显式tenant过滤、bind参数和复合外键。worker领取跨租户operation使用最小权限的独立角色，后续租户操作切入租户事务；迁移角色分离。RLS不代替动作授权，也不能抵御拥有可执行任意SQL能力的应用角色。[PostgreSQL RLS](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)、[事务局部SET](https://www.postgresql.org/docs/current/sql-set.html)

## 9. 事务与worker调谐细节

API接受创建的单个短事务顺序为：设置tenant上下文 → 校验principal/grant及目标项目 → 幂等唯一记录查找/竞争 → 锁项目quota行 → 验证/预留限额 → 插入instance/workspace元数据及operation → 写accepted audit和domain event → 完成幂等回执 → COMMIT → 202。任何一步失败全部回滚。事务期间不调用Kubernetes、云API、IAM外部网络、对象存储或webhook。

READ COMMITTED + 明确行锁/唯一约束即可作为初始隔离级别；不要靠全局SERIALIZABLE解决所有业务竞态。固定锁顺序：授权版本/项目配额 → 实例 → 操作/执行，以降低死锁；死锁最多少量同事务重试且不夹外部副作用。配额是pending+allocated预算，不只count当前Running实例；创建失败和删除完成后的回收与终态同事务，后台定期对账查漏。

worker使用短事务 `SELECT ... FOR UPDATE SKIP LOCKED` 领取到期operation，更新lease_owner/lease_until并递增lease_token后提交；执行外部调用不持有DB行锁。SKIP LOCKED适用于队列表，不用于要求完整业务视图的普通资源查询。PostgreSQL官方明确其跳过锁行带来不一致视图，适合多个消费者访问队列表这一用途。[PostgreSQL SELECT](https://www.postgresql.org/docs/current/sql-select.html)

建议lease 30秒、10秒续期，外部请求有小于lease的明确截止时间；失租后停止新的副作用。DB提交条件始终包含operation_id、lease_token、预期状态。这里的token只挡旧worker写DB，不能撤回在途Kubernetes exec或云调用；执行命令遵从上一节“派发后不重发”，生命周期创建使用确定名称+generation发现已有对象，更新/删除使用实际对象UID和resourceVersion前置条件。

数据库lease不是存储fencing。旧VM是否仍在写盘必须由运行时/云/存储证据裁定；外部结果不明时保持操作等待与实例隔离。数据库故障恢复后先暂停exec和自动化，完成epoch提升与实际资源对账，旧操作不能无条件重放。

## 10. Rust 模块、SDK与测试交付

一个workspace即可，建议3个bin共享domain/db/auth模块；不要为单一实现建立一层trait/factory/repository/service重复转发。领域状态使用Rust enum，转换函数集中在domain；DB表示采用CHECK约束的text以方便滚动迁移。API DTO 与持久模型分开，防止新增内部字段自动暴露给租户。数据库写入显式sqlx事务，不用动态ORM生成租户条件；错误转换集中映射稳定code。任何后台循环都有取消信号、并发上限、deadline和日志关联ID。

OpenAPI源文件与实现同仓库，CI检查路由/DTO与文档契约一致。首版交付通用curl示例、Rust与TypeScript/Python基础客户端中实际需要的语言；如果调用方是Java/Go，通过相同OpenAPI生成并完成至少一门实际调用方语言验收，不为展示同时维护六套手写SDK。

SDK少量手写增强：TokenProvider接入所选标准OAuth、幂等key生成与复用、Operation.wait、execution output补读、SSE重连、标准错误类型、webhook验签。SDK不把调用超时当取消，不把未知执行自动重跑，不在日志记录token/script/env secret。给调用方的完整示例必须覆盖“受理→持久保存operation/execution ID→等待→读取输出→处理UNKNOWN→清理实例/保留卷”。

上线前必须通过以下可自动重现的契约/故障测试：

1. 两租户以及同租户不同项目，对实例、operation、输出、审计、备份、cursor/session进行ID替换，均无越权；跨租户复合外键写入失败。
2. 并发100个相同key只创建1个Operation/实例/配额reservation；不同body同key返回409；commit后断网重试仍返回原ID；过期key不被SDK自动换新。
3. 同实例stop/delete/backup/exec竞态符合冲突矩阵；ETag不被心跳改变；真正修改配置产生412。
4. DISPATCHING写入后任一点kill worker/断exec链路，不产生第二次exec；UNKNOWN不会自动变成功、失败或释放写者约束。
5. timeout/cancel断开API连接不影响状态准确性；未确认VM终止不报告强取消完成；强终止影响全部进程在契约中可见。
6. 输出包含二进制、分割UTF-8、超限、消费者停读、spool故障；内存有界并给出partial/truncated/lost状态。
7. webhook重复、乱序、超时、目标DNS变化、重定向、证书过期、密钥轮换都可预测；同event最多一个消费业务效果由消费者去重测试证明。
8. DB连接池复用10000次交错租户请求，事务回滚/异常退出后不残留tenant context；API DB角色不能修改历史审计。
9. IAM撤权与worker任务派发、长连接重检竞态在承诺窗口内收敛；身份库/DB不可用不会授权新执行。
10. SDK针对网络中断/429/503/未知Operation状态的行为可复现，至少一个真实微服务完成端到端调用验收。
11. standalone与external_oidc运行相同API/授权套件；测试两个issuer相同email不能串号，IdP迁移只按显式映射迁移grants；独立Keycloak升级、PITR、密钥轮换、SMTP失败和管理员账户恢复均有演练。

以上是开发合同与验收标准，仍需在目标公有云、固定Kubernetes/Kata/CSI版本上跑出证据后才能宣布可上线。合同不承诺任意用户代码的业务副作用“恰好一次”，也不把API已接受当成沙箱已经就绪。
