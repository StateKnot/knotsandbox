# 单文件传输

文件通道使用 Rust API、PostgreSQL 持久意图、gateway 的单次 Kubernetes exec 和 Linux `openat2` helper。每文件最多 100 MiB，每分片 1 MiB；不接收任意宿主路径、客供云密钥或归档解压请求。

## 部署

通过正常 `sandboxd --role migrate` 应用正式 0036 和组件数据库权限。API、gateway、worker 文件入口检查 SQLx 正式迁移记录；在独立库执行草案不能启用生产入口。实例须有当前 epoch、准确 generation/launch/Pod UID 的 Ready 证明、有效部署认证和计算租约。

`SANDBOX_FILES_CONFIG_FILE` 指向最多 8 KiB 的绝对路径 JSON 文件：

```json
{
  "endpoint": "https://oss-cn-hangzhou-internal.aliyuncs.com",
  "bucket": "部署的-temporary-bucket",
  "kms_key_id": "临时存储KMS密钥ID",
  "api_upload_sts_file": "/run/sandbox-cloud/file-upload/private/sts.json",
  "gateway_sts_file": "/run/sandbox-cloud/file-gateway/private/sts.json",
  "read_sts_file": "/run/sandbox-cloud/file-reader/private/sts.json",
  "cleanup_sts_file": "/run/sandbox-cloud/file-cleaner/private/sts.json",
  "max_file_bytes": 104857600
}
```

四路径必须不同。API 仅打开 upload/reader，gateway 仅打开 gateway，worker 仅打开 cleaner。凭据格式沿用输出存储的短期 STS 格式，每次操作重新校验文件权限、普通文件类型和剩余有效期；过期不复用缓存，也不回退到环境变量或宿主身份。投射 Secret 的轮换链接可以使用；FIFO 不得阻塞读取。全部 OSS 请求使用官方 reqsign V4 及实际 payload SHA-256。

IaC 的 `file-upload` / `file-reader` / `file-gateway` / `file-cleaner` 独立角色绑定准确 service-account subject，限 temporary bucket 的 `tenants/*/file-transfers/*/content/*/parts/*`。上传/gateway 为 PUT/GET，reader 为 GET，cleaner 为 DELETE/GET；无 List、Multipart、ACL 或保留管理权限。[STS轮换进程与原生sidecar组合器](storage-credentials.md)已实现；完整产品安装、出口与实云验收仍待完成。

租户及项目都必须配置 `FILE_TRANSFERS` 和 `FILE_TRANSFER_BYTES` 配额；缺少账户不会获得无限额度。空文件最少预留 1 字节。`SANDBOX_FILE_GATEWAY_CONCURRENCY` 默认 2，范围 1..16。

## 调用

1. GET 实例取得 ETag。POST `/v1/instances/{id}/file-transfers`，带持久 `Idempotency-Key` 和实例 `If-Match`。UPLOAD 声明相对 `path`、总 `byte_length`、小写 SHA-256、可选 `replace` 和 1..300 秒 `timeout_seconds`；DOWNLOAD 声明相对路径、`max_bytes` 和截止时间。
2. UPLOAD 按准确的 1 MiB 分片，末片为剩余长度。PUT `/v1/file-transfers/{id}/content/{index}`，带 transfer ETag、`application/octet-stream`、准确 Content-Length 和 `X-Content-SHA256`。意图在唯一云 PUT 前落库。已 ACK 的原样分片可以返回收据；PUTTING/UNKNOWN 不会发第二次 PUT。分片可在同一 ETag 并发暂存，不改变父资源版本。中断后先查询状态，禁止自动重试数据 PUT。
3. POST `/v1/file-transfers/{id}/content/commit`，body `{}`，带 transfer `If-Match` 和新的持久 key。独立读取各分片并核对完整长度/SHA，云读取及事务等待后重查权限、身份和期限，再冻结内容允许派发。空文件无需分片。
4. gateway 只建立一个受准入控制的 exec 连接。helper 核对绑定身份，以原子方式上传或有界读取下载。父级、空组件、符号链接、magic link、硬链接和特殊文件被拒绝。覆盖须显式 `replace=true`。
5. GET transfer / operation 读取结果。FROZEN DOWNLOAD 使用 GET `/v1/file-transfers/{id}/content`；每个云分片读取前后重查身份、权限和版本，流受 JWT 到期和 300 秒寿命限制。调用者必须验证完整长度与 SHA 后才能使用数据。

UPLOAD 需要 `files:write`，DOWNLOAD 需要 `files:read`；两者受理和派发均需当前 `instances:read`、`instances:hard_stop`。截止包括暂存，不能超过计算租约，超时停止整个实例。上传持唯一写槽；多个下载可以并发，期间不能闲置停止。创建及 commit 管理请求可用原 key/body/If-Match 查原收据。

SDK `uploadFilePart` 首个 await 前复制字节，只发一次 PUT；断流或无效收据返回 `outcomeUnknown=true`。`downloadFile` 最多缓存 100 MiB，核对元数据版本、长度和完整 SHA 后返回。普通 JSON SDK 拒绝这些数据端点，防止错误重试或管理体限制误用。

## 回收与不确定结果

`process_status` 与 `storage_writer_status` 分开：准确 helper 进程结束不是 VM 死亡证明。正常进程结束可释放计数和写槽；UNKNOWN、超时及中断保留相关限制并请求整个实例安全关闭。存储状态 PENDING / ACKNOWLEDGED / OUTCOME_UNKNOWN 不得根据进程状态推断。

暂存保留 24 小时。worker 公平扫描，以准确身份 DELETE，再 HEAD 确认缺失并提交不可变清理收据。仅全部对象清理且所有 PUT 已 ACK 才释放字节额度。DELETE、HEAD 缺失、租约/STS 到期或 VM 死亡不能证明已送出的未知 OSS PUT 不会迟到；此类字节预算持续占用。当前没有自动导入云写入 fencing 证明的管理入口，不得手改账本释放额度。

## 阶段证据

2026-10-08：文件存储真实 TCP 请求 4 项、配置 5 项、原样 Linux 路径/helper 11 项（含真实 100 MiB 有界下载）、WebSocket 协议 4 项、含文件 TCP 测试的 SDK 55 项及 Terraform 官方 schema/10 项主计划/2 项状态后端计划通过。正式 0036 后文件账本/HTTP/OSS链路 11 项和 mTLS可信关闭 1 项通过，文件配置能力发现另在同一真实HTTP专项验证。云、Kubernetes、宿主接口有明确测试替身；Linux 专项运行于固定 Rust 镜像的真实 Linux 内核，未代表完整发布二进制或 Kata 云验收。安装器、云入口慢消费者及实云隔离仍需补全；不能作为全产品上线证据。
