# 执行输出流与断点恢复

`GET /v1/executions/{id}/output/stream` 返回 `text/event-stream`。它读取账本已提交且通过完整性核验的 OSS 输出段，与分页输出 API 共用 `executions:output:read` 权限及读取器。端点不接受查询参数；凭据放在 Authorization 请求头，重连位置放在 `Last-Event-ID`。首次从段 0 读取。

## 协议

| SSE event | data | 语义 |
|---|---|---|
| `output.checkpoint` | `execution_id, after_segment` | 首帧确认恢复位置；-1 表示尚未交付任何段 |
| `output.segment` | `execution_id, segment` | 一个连续的已核验输出段，包含 sequence 与 frames；frame 保留 sequence、stream、offset、data（Base64） |
| `output.end` | `execution_id, after_segment, output_status, manifest_verified, final_segment_sequence` | 输出写入者已关闭且当前可读段已交付完毕 |
| `stream.error` | `code, retryable, request_id` | 流开始后的失败；没有 id，发送后关闭 |

前三类事件的 id 是签名游标。客户端必须在消费成功后保存 id；进程崩溃后可重放最后一段，应按 execution/段 sequence 去重。SDK 的内存游标不替代业务持久化。心跳是注释，没有输出数据和游标。

`COMPLETE` 与 `TRUNCATED` 的结束要求完整清单验证通过且最终段序号一致。`PARTIAL` 与 `LOST` 可以结束，但必须保留不完整状态。`PENDING` 不会因为一次空查询而被当成空输出完成。输出流结束不表示命令成功或整个沙箱 VM 已终止；执行状态和可信终止证明分别查询。

## 安全与资源界限

游标绑定租户、主体、execution、集群恢复纪元、dispatch attempt 和段序号，有效期 24 小时。首个派发前的 -1 游标可以绑定第一次 attempt，已有 attempt 不可切换。失效返回 `410 OUTPUT_CURSOR_EXPIRED`，纪元或 attempt 变化返回 `410 OUTPUT_HISTORY_UNAVAILABLE`，超出账本返回 `409 OUTPUT_CURSOR_AHEAD`，不能静默从最新位置或头部重置。

签发与校验 API 副本可能存在时钟偏差。已通过签名验证的游标，其 `issued_at` 最多可以领先校验端当前时间60秒；超过60秒返回 `400 INVALID_CURSOR`。与项目事件流相同，这一容差仅用于未来签发时间：`expires_at` 小于或等于当前校验时间仍立即返回 `410 OUTPUT_CURSOR_EXPIRED`，不增加过期宽限，签发到过期的期限仍不得超过24小时。签名、身份、attempt、代次、序号及实时权限检查保持原合同。

每次输出前重新检查 JWT、本地身份、项目授权和恢复纪元；对象读取后也再次检查。OSS I/O 不持有数据库事务。段对象与 manifest 必须匹配不可变索引、校验和、帧顺序和大小边界，读取失败不发送半段。

每连接最多缓存一个段，SSE data 上限 768 KiB；客户端解析器可采用 1 MiB 上限并拒绝超限数据。分页与流式 API 共用每进程 16 个对象读取并发。输出流与项目事件流共用连接额度：每 API 副本总计 64、每租户 16、每主体 4。额度跟随 HTTP Body 完整生命周期，断开即释放；这是每副本限制，不是集群全局配额。

无新输出时 5 秒轮询、15 秒心跳。连接最长 300 秒，并受 JWT 到期和服务关闭限制。客户端须重新取得可用 token 后携带已确认游标重连。应用背压限制了待发送内容，真实负载均衡器的写超时、连接回收和慢消费者容量仍需要部署环境测试。

## 验证证据

3 项普通测试覆盖游标、身份/纪元及结束语义；5 项真实 PostgreSQL、回环 JWKS、HTTP Body 与原生 OSS 签名传输测试覆盖：两段断点重连、UNKNOWN 执行仍持有 VM 活动槽、完整 manifest、损坏对象、读取期间撤权/恢复纪元变化、连接上限/释放、JWT 到期和服务关闭；还执行真实 Node SDK→TCP Rust API→PG 的断点续读、游标确认、完整输出结束与撤权验证。数据库 fixture 只构造输出账本，不声称运行真实 guest。

```sh
set -a
source .local/dev.env
set +a
cargo test --locked --lib execution_output_stream::tests -- --ignored --test-threads=1
```

真实 OSS、云入口背压、跨副本重连和容量验收需在目标环境执行。API 能力字段表示当前已配置读取器，不表示目标环境认证已通过。
