# 微服务事件流调用

`GET /v1/events/stream` 提供项目领域事件的元数据 SSE 流。使用已授权服务主体的 OAuth access token 与 `X-Tenant-ID`；项目需要 `events:read`。它不包含命令参数、环境变量、输出内容或完整审计 payload。服务端事务顺序、实时撤权与保留规则见 [事件流服务端合同](event-stream.md)，请求和帧结构见 [OpenAPI](../openapi/sandbox-api.yaml)。

## TypeScript

Node.js 22+ 使用 `subscribeEvents`，它复用既有 `TransportOptions` 和 `TokenProvider`。普通 `client.GET` 是限长 JSON 传输，调用这个路径会在发请求前报 `STREAMING_TRANSPORT_REQUIRED`。

```ts
import { subscribeEvents, EventStreamError } from '@sandbox-platform/client';

const transport = {
  baseUrl: config.apiUrl,
  tenantId: config.tenantId,
  tokenProvider: {
    getToken: ({ forceRefresh, signal }) => oauth.getAccessToken({ forceRefresh, signal }),
  },
};
const saved = await subscriptions.readCursor(subscriptionId);
const shutdown = new AbortController();
const stream = subscribeEvents(transport, {
  projectId: config.projectId,
  // instanceId: instance.id,  // 若设置，恢复时必须保持相同筛选条件。
  replay: 'all',              // 首次可选 latest（默认）或 all。
  ...(saved ? { lastEventId: saved } : {}),
  signal: shutdown.signal,
  totalTimeoutMs: 3_600_000,
  maxReconnects: 8,
  // 此回调在调用方处理完当前帧并请求下一帧时执行。
  // 只使用同一个串行订阅者；写失败立即结束流，不能忽略错误。
  onCursor: cursor => subscriptions.saveCursor(subscriptionId, cursor),
});
try {
  for await (const item of stream) {
    if (item.type === 'domain.event') {
      // event.id 去重与业务副作用须在本服务同一事务提交。
      // 外部副作用请使用本服务自己的事务 outbox，不能仅记录内存 Set。
      await db.transaction(tx => consumeEventOnce(tx, item.event.id, item.event));
    }
    // checkpoint 没有业务事件，但仍必须推进位置。
    // 下一次循环 next() 才会调用 onCursor；SDK 不提前确认预读数据。
  }
} catch (error) {
  if (error instanceof EventStreamError) {
    // 只记录固定 code/status/requestId；不要记录 bearer token 或完整 cursor。
    await subscriptions.recordFailure(subscriptionId, error.code);
  }
  throw error;
}
```

只要调用方在处理完成后才推进 iterator，事件处理失败、`break`、`return()` 或取消均不会自动保存当前帧 cursor。处理成功但保存 cursor 前宕机会重放事件，必须以 `event.id` 做持久去重。游标不是事件 ID，同一位置重新连接可以获得不同签名值；`sequence` 是十进制字符串，不能转成 JavaScript `number`。单订阅内可用 `BigInt` 比较，但不可跨项目/epoch 比较。

初始流以带 `id` 的 `stream.checkpoint` 建立恢复点。领域帧为 `domain.event`，实例筛选跳过的进度也会通过 checkpoint 更新。心跳仅注释，无 `id`，SDK 忽略。`stream.error` 没有 `id`，不会保存断点；`code/retryable/request_id` 会转换成 `EventStreamError`。未知帧、错误 UTF-8、跨租户事件与倒退序号都失败关闭。

## 重连与期限

默认整体订阅期限 1 小时，连接建立 10 秒，挂起网络读取 45 秒，最多 8 次重连。调用方处理事件的时间不算网络 idle，但计入整体期限。整体期限最多 24 小时、重连最多 100 次；需要长期运行时，应用调度新一轮有限订阅并加载持久 cursor，不要清空位置。单 SSE 帧最多 256 KiB。服务端单连接到 JWT 到期、300 秒或进程关闭即结束；SDK 重新获取 token（`forceRefresh: true`）后使用已确认游标重连。

网络中断、可重试服务错误与正常 EOF 使用有上限的指数退避和随机抖动；遵守 `Retry-After`，超出本次总预算则退出。401 只自动强刷重试一次。SDK 不接受重定向，不发送 cookies，不把 token 写进 URL；自定义 `fetch` 与 `TokenProvider` 应遵守 AbortSignal，SDK 同时对忽略信号的 Promise 加截止时间。

以下错误须应用明确处理，禁止自动删掉游标继续 latest：

| 情形 | 行为 |
| --- | --- |
| HTTP 400 `INVALID_CURSOR` | 排查主体/租户/项目/实例筛选不一致或损坏值 |
| HTTP 409 `EVENT_CURSOR_AHEAD` | 对照恢复过程，显式核对业务状态与历史 |
| HTTP 410 `EVENT_CURSOR_EXPIRED` / `EVENT_HISTORY_UNAVAILABLE` | 游标超过 24 小时、保留历史缺失或恢复 epoch 改变；显式重新同步业务状态，再由业务决定 replay |
| 403/404 或流内撤权错误 | 停止订阅；重新授权前不继续读取 |
| `EVENT_CHECKPOINT_MISSING` | 初始 HTTP200 后在第一个可靠恢复点前中断；SDK 不自动 latest 重连，避免跳过中间提交 |
| `EVENT_CURSOR_PERSIST_FAILED` | 修复调用方断点存储，从最后持久位置恢复 |
| `EVENT_RECONNECT_LIMIT` / `EVENT_STREAM_TIMEOUT` | 本轮本地预算用尽；按服务调度策略从持久位置开启下一轮 |

有限订阅的结束不代表平台操作完成，也不发送执行取消。事件为至少一次传输，`occurred_at` 不是提交顺序；事件列表 API 的时间排序 cursor 与 SSE cursor 互不兼容。

## curl 排障

先由组织的 OAuth 客户端安全取得 token。以下命令从已受控权限为 `0600` 的 header 文件读取认证，避免 token 出现在进程参数；该文件由现有凭据管理器生成，内容为 `Authorization: Bearer ...` 与 `X-Tenant-ID: ...`，不放进 Git。恢复时 `RESUME_HEADER_FILE` 只含一条 `Last-Event-ID: ...`，同样使用受控文件。

```sh
curl --no-buffer --silent --show-error --fail-with-body \
  --max-time 320 --proto '=https' --request GET \
  --header @"$AUTH_HEADER_FILE" \
  --header 'Accept: text/event-stream' \
  --get --data-urlencode "project_id=$PROJECT_ID" \
  --data-urlencode 'replay=all' \
  "$SANDBOX_API_URL/v1/events/stream"

# 恢复：该文件必须来自已完成业务消费的 id，不能从未处理帧预先抽取。
curl --no-buffer --silent --show-error --fail-with-body \
  --max-time 320 --proto '=https' --request GET \
  --header @"$AUTH_HEADER_FILE" --header @"$RESUME_HEADER_FILE" \
  --header 'Accept: text/event-stream' \
  --get --data-urlencode "project_id=$PROJECT_ID" \
  "$SANDBOX_API_URL/v1/events/stream"
```

不要使用 `-L`、query token 或 `--retry-all-errors`，不要把 curl 展示当作持久消费器。HTTP200 后的 `stream.error` 不会改变 HTTP 状态，必须读取 SSE 事件。Ingress/反向代理须关闭响应缓存与缓冲，允许至少 45 秒无字节间隔；请求仍有鉴权和连接上限，不能为 SSE 放开整个 API 的响应体限制。

## 已验证与尚待验证

SDK 单测覆盖分块 UTF-8/CRLF、部分帧断连、保存断点时机、正常 EOF/token刷新、有界 401/503/重连、过期游标不重置、错误帧、帧限长、错误租户、超时/取消及真实本地 HTTP 重定向。OpenAPI 类型已重新生成。`src/event_stream_sdk_test.rs` 已通过真实 TCP Rust API→PostgreSQL→Node SDK 联调：首次收到事件、按原 cursor 重连取得新事件、提交撤权后流内拒绝。测试令牌只经 stdin 管道传入。目标代理环境的长连接、容量与故障切换验收仍须单独完成。

## 执行输出流

`subscribeExecutionOutput(transport, { executionId, ... })` 使用
`GET /v1/executions/{id}/output/stream`，需要独立的 `executions:output:read`。
它不接受任何 query 参数。首次从 segment 0 前的位置开始，恢复只使用
`Last-Event-ID`；不要把项目事件 cursor 与输出 cursor 混用。

```ts
import { subscribeExecutionOutput } from '@sandbox-platform/client';

for await (const item of subscribeExecutionOutput(transport, {
  executionId,
  ...(savedOutputCursor ? { lastEventId: savedOutputCursor } : {}),
  signal: shutdown.signal,
  onCursor: cursor => outputSubscriptions.saveCursor(executionId, cursor),
})) {
  if (item.type === 'output.segment') {
    // 对 executionId + segment.sequence 做持久去重后处理 frames。
    // frame.data 是原始字节的 Base64，不能当 HTML、命令或可信日志格式执行。
    await outputStore.persistSegmentOnce(executionId, item.segment);
  } else if (item.type === 'output.end') {
    await outputStore.recordReadEnd(executionId, {
      status: item.outputStatus,
      manifestVerified: item.manifestVerified,
      finalSegmentSequence: item.finalSegmentSequence,
    });
    // 继续下一次 next()，才能持久化这个 end cursor；随后 iterator 正常结束。
    // 不在此处自动取消执行、释放配额或认为 VM 已终止。
  }
}
```

首帧为 `output.checkpoint`，SDK 将 wire 的 `after_segment` 转为
`afterSegment`，范围 `-1..4095`；`-1` 表示尚未消费任何 segment。
`output.segment` 原样保留 `segment.sequence/frames`，后续 segment 必须连续。
SDK检查执行 ID、帧整数精度、严格 Base64 和 segment 顺序，使用与领域事件相同的
UTF-8/CRLF 流解析器，但输出的单帧上限为 1 MiB（服务端 data 上限 768 KiB）。

`output.end` 是可消费、可确认的最后一帧，然后 iterator 结束，不自动重连。
`COMPLETE` / `TRUNCATED` 必须有匹配最终位置的已验证 manifest；`PARTIAL` /
`LOST` 保留不完整状态。无论哪个状态，end 都只说明当前可提交输出已读完，不能说明
VM 或恶意后台进程停止。没有最终证明的 `PENDING` 不产生 end。

使用同一个 `EventStreamError` 类型与有界超时/重连策略。300 秒正常轮换或 token
到期后重新取 token，使用最后已消费的 cursor；`break`、`return()`、处理失败不会
确认当前帧。`OUTPUT_CHECKPOINT_MISSING`、`OUTPUT_CURSOR_PERSIST_FAILED`、
`OUTPUT_INTEGRITY_FAILED` 和 `OUTPUT_HISTORY_UNAVAILABLE` 要求显式处理。
HTTP 409/410 永不自动清 cursor，完整性错误即使误标 retryable 也不重试。

curl 使用同样的受控 header 文件，输出流没有 query：

```sh
curl --no-buffer --silent --show-error --fail-with-body \
  --max-time 320 --proto '=https' --request GET \
  --header @"$AUTH_HEADER_FILE" --header @"$RESUME_HEADER_FILE" \
  --header 'Accept: text/event-stream' \
  "$SANDBOX_API_URL/v1/executions/$EXECUTION_ID/output/stream"
```

首次订阅去掉 `RESUME_HEADER_FILE`。SDK 故障测试已覆盖大分段、错误字节、丢失
checkpoint、partial/lost end、断线恢复、撤权/epoch错误、确认时机与普通 JSON 客户端
误用拒绝。真实 Node→TCP API→PostgreSQL 的输出链路由集成测试独立验收，测试通过
前不把它算作本节已验证结果。
