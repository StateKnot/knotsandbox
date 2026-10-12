# 执行输出分页

`GET /v1/executions/{execution_id}/output?after_segment=-1&limit=1` 返回已持久索引的输出段。`after_segment` 是 segment sequence（范围 -1..4095），不是 guest frame sequence；`limit` 只接受 1 或 2，默认 1。客户端不能传 bucket、对象路径、URL 或凭据。

访问需要 `executions:output:read`，与执行元数据读取权限分离。查询、索引和执行所属项目均受 tenant RLS 约束。存储 I/O 后再用新事务检查原身份映射、client 绑定、主体、token 期限、动作 scope 和实时 grant；读取期间禁用/重映射身份、轮换 client 或 token 到期均不返回输出内容。网关在数据面未产生输出时，查询结果可能为空；这不释放活动槽，也不改变任务状态。

API 必须独立配置 `SANDBOX_OUTPUT_READ_STS_FILE`，使用专用 GET/HEAD 权限的 STS 身份和 KMS 解密权限，不回退使用写入网关凭据。endpoint、bucket 与 KMS 配置必须和输出存储一致。凭据有效期、原子轮换、TLS 和文件权限要求见 [网关运行合同](gateway-runtime.md)。未配置读取能力时接口返回 `503 OUTPUT_STORAGE_UNAVAILABLE`，能力发现标记不可用。

响应字段：

| 字段 | 含义 |
|---|---|
| `execution_id` | 当前租户授权的执行 |
| `snapshot_at` | 获取数据库一致性快照时的服务端时间 |
| `output_status` | PENDING / COMPLETE / TRUNCATED / PARTIAL / LOST |
| `manifest_verified` | manifest 的长度、SHA256、执行身份与全部数据库索引一致；不表示未下载对象的字节已经校验 |
| `has_more` | 此次快照内还有当前页之后的 segment；PENDING 时 false 不表示以后没有输出 |
| `final_segment_sequence` | 仅 manifest 已验证时确定；空输出为 -1，尚未确定为 null |
| `segments` | 每段包含 segment `sequence` 和 `frames` |
| `next_after_segment` | 本页最后返回的 segment sequence；空页为 null，调用方继续保留原 cursor |

frame 包含全局 `sequence`、`stream`（stdout/stderr）、原始流 `offset` 和 base64 `data`。offset 分流累计，单位是字节，不按截断后输出重新编号；不能直接把二进制输出当作 UTF-8。API 只返回经验证的该页对象，不返回私有 OSS key 或签名 URL。

每个 segment 最大 512 KiB，本页最多两段。数据库索引必须连续且符合固定路径与原始输出总额上限；COMPLETE/TRUNCATED 必须存在有效 manifest。读取 manifest 和本页对象最多三个并发请求，共用单对象 20 秒截止；取消 HTTP 请求会直接丢弃读取 futures，不启动脱离请求的后台取数任务。

对象 GET 使用成熟 OSS 客户端，但内存上限不依赖服务端诚实遵守 Range 或 Content-Length：读取流在每次追加前检查已知大小，响应体还有独立限制；缺块、长度/哈希错误、非法 NDJSON、未知字段、帧序号或 offset 冲突均拒绝返回该页。`OUTPUT_INTEGRITY_FAILED` 表示索引/对象不一致，不能把部分内容伪装为完整结果；暂时的对象存储或短期凭据故障返回 `OUTPUT_STORAGE_UNAVAILABLE`。

PARTIAL 可以读取已提交的对象段，即使没有最终 manifest；此时 `manifest_verified=false`、`final_segment_sequence=null`。PUT 已成功但尚未提交索引的孤儿对象不对客户端可见。

本地整合测试使用真实 PostgreSQL 和 HTTP/WebSocket，以及原生 OSS 签名 transport 替身，验证正常/截断/未知结果读取、跨租户拒绝、同尺寸对象篡改、缺失 manifest 与 I/O 期间即时撤权。真实 RAM/KMS/OSS、生产网络与请求容量仍需云环境验收。

每个 API 副本最多同时进行 16 个输出读取、校验及 JSON 编码请求，超出返回 `503 OUTPUT_READ_OVERLOADED`；HTTP 连接与响应体超时、按调用方限流仍需生产入口配置及压测。`502 OUTPUT_INTEGRITY_FAILED` 明确标记 `retryable=false`，SDK不会仅因为状态码为502而重试。调用方须保存消费位置并去重，输出是非可信二进制内容，显示前处理终端控制字符或HTML转义；不得通过重新执行命令补回缺失输出。
