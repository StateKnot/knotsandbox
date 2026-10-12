# 备份封存清单与控制面验证

本模块实际实现了 v2 Ed25519 签名清单、完整对象库存、独立 OSS 只读校验和专用 OIDC→STS 刷新。它不是产品 `AVAILABLE` 的单独判据。备份控制器还必须确认可信 SEAL VM 终止与清理、持久 backup/attempt/epoch 身份、有效且已经过真实云验收的 WORM/RAM 隔离 profile。未完成这些门禁的 profile 必须保持 disabled；当前本地测试不能充当 OSS、CSI、Kata 或云恢复认证。

## 对象和签名合同

唯一目录固定为 `tenants/{tenant_id}/backups/{backup_id}/`。客户不能提供任意 bucket、endpoint、repo URL 或 object key。`repository/` 中只接受 Restic 当前布局的 `config`、`keys/{sha256}`、`index/{sha256}`、`data/{sha256前两位}/{sha256}`、唯一 `snapshots/{capture_snapshot_id}`；出现锁文件、额外快照、临时文件、目录标记或非法路径均拒绝封存。Restic 除 config 外的对象名是密文字节 SHA256，SEAL 使用一个长驻 `rclone hashsum SHA256 --download --checkers 2` 进程实际逐对象流式读取并核对，控制面不自行实现仓库解密。[Restic 官方格式](https://restic.readthedocs.io/en/stable/100_references.html#repository-format)。

`inventory/000000.json` 开始顺序编号。每片字段固定为 `protocol=1`、`tenant_id`、`backup_id`、`seal_attempt_id`、`cluster_epoch` 和 `objects`；每条 object 为 `{key,size_bytes,sha256}`，key 相对 repository，整个库存按 ASCII key 严格递增、无重复。每片不超过 1 MiB，总库存不超过 512 MiB、1,024 片、2,000,000 个对象。单对象不超过 128 MiB，仓库合计不超过 32 TiB；config 和唯一 snapshot 各不超过 1 MiB。超限报错，不截断库存或宣告成功。这是当前经批准的 Restic profile 上限；扩容必须修改版本合同和测试。

最终 `manifest.json` 是 `protocol=2`、`format=restic-raw-disk-v2`。原数据身份 `backup` 新增固定 `seal_attempt_id` 和原 `cluster_epoch`，恢复保留原值；它同时绑定源实例 generation、PVC/snapshot/clone UID、模板 digest、原始盘大小、SHA256、snapshot ID、保留时间、云账户/地域/桶/KMS/key_ref。`inventory` 固定 `{format:"restic-object-inventory-v1",object_count,total_bytes,shards:[{key,size_bytes,sha256,object_count}]}`。两个完整仓库/原始流校验声明必须为 true，`cloud_restore_tested_at` 必须为 null。v1 清单不被新验证器接受为可用依据。

所有清单/库存采用 Python `json.dumps(sort_keys=True,separators=(',',':'),ensure_ascii=True)` 的 ASCII JSON 字节、无末尾换行。严格字段结构禁止浮点代替整数、重复/未知字段、非规范编码。`manifest.sig` 为这些 manifest 原始字节的 64 字节 Ed25519 签名；控制面只接受已登记的 44 字节 Ed25519 SPKI DER 公钥，不接受文件中的自带新公钥。签名使用已锁定 OpenSSL，Rust 使用已锁定 rustls/ring 原始签名校验。

SEAL 先完成独立 vault 的 `restic check --read-data`、原始盘 dump SHA256，以及全部库存哈希；上传库存后写 `manifest.pending.json`，再写 signature，最后发布 `manifest.json` 指针。pending 不是完成指针。中断恢复重用原始规范 pending 字节，并重新核对当前完整库存，避免 WORM 下新时间戳产生不一致签名。不能通过重新初始化仓库或覆盖旧清单恢复失败。

库存排序采用受限 SQLite scratch（最多 512 MiB，缓存 4 MiB），逐片写出 JSON。SEAL 使用 1 GiB 磁盘 emptyDir 和 2 GiB ephemeral-storage limit，不将全盘或完整库存放进 Python/Rust 内存；容量不足保持失败/hold。hashsum 明确启用 download，不使用远端声明的 hash；前后两次列表与哈希结果必须是同一闭合集合和大小。SQLite 只是可丢弃排序索引，不是备份数据库或提交证据。

## 控制面实际验证范围

`BackupVaultVerifier::verify` 要求来自账本的完整 `BackupVaultExpectation`、capture snapshot/disk SHA256、可选受控 SEAL report manifest SHA256，以及部署预登记的 bucket、region、account、签名公钥。即使报告丢失，也可以根据签名和持久身份恢复验证。

验证器先 GET manifest/signature，再按签名描述逐片 GET 库存；通过有界分页 LIST 与排序库存合并比较整个仓库的 key/size 集合，拒绝缺失、额外、重复、错序或大小变化。config 和 snapshot 另做 HEAD/GET 和 SHA256；末尾重新读取 manifest 检查提交指针未变化。不会把 ETag 当 SHA256，也不让控制面再下载最多 16 TiB 原始盘数据。全部 pack 哈希属于可信 SEAL 签名声明，**同大小对象替换的防护另依赖已验证的 WORM 和独占写入策略**。任何恢复仍必须重新验证全部 pack、原始流及落盘后的 SHA256。

返回的 `VerifiedBackupVault` 私有字段、无 Deserialize/公共构造。它只证明上述范围，不能用其代替节点停止证明、保留配置或恢复演练。控制器消费时必须再核对当前 profile、实际验签公钥 SPKI SHA256、实际访问 endpoint、全量身份、capture 收据和 fresh `verified_at`；建议不接受超过 5 分钟的验证结果。有效保留及法律 hold 仍从平台状态和云保留证据判定，不能只相信签名中的时间。

同一 verifier 实例及其 clones 最多并发 2 个验证，每次总体最多 1 小时；每个 HTTP 请求连接最多 3 秒、请求 20 秒、逻辑对象/LIST 操作 30 秒。只准 HTTPS 精确地域 bucket origin、GET/HEAD 和精确 repository-prefix LIST。禁用代理、重定向、自动重试和任何凭据链 fallback。HTTP 响应体有独立上限，库存处理不累积完整对象数组。临时失败只能从验证流程重新开始，不能生成部分成功 token。

## 专属读取身份与可部署刷新进程

IaC 新增 `backup-reader` RAM role，trust 只允许 `system:serviceaccount:sandbox-system:sandbox-backup-controller`、指定 Kubernetes issuer、audience `sts.aliyuncs.com`。权限限独立 backup-vault `tenants/*/backups/*/*` 的 GetObject、repository-prefix 的 ListObjects、该 vault KMS key Decrypt；没有 Put/Delete/GetObjectVersion/ListMultipartUploads，也没有保留策略管理权限。运行时 HTTP 还会收窄到当前单个 tenant/backup 前缀。

从已审阅的 Terraform 输出生成无密钥配置：

```bash
python3 deploy/backup/reader_config.py --terraform-output reviewed-terraform-output.json --output reviewed-backup-reader.json
```

配置固定七个字段：`region/account_id/vault_bucket/vault_kms_key_id/issuer/oidc_provider_arn/role_arn`。工具核对 account、固定 SA subject/audience 和专属 role 名，不输出 token、不访问云。该文件以 `reader.json` 挂入只读 ConfigMap `/run/backup-reader-config`。

同一备份控制器 Pod 中的凭据 sidecar 使用已构建并签名的 backup 镜像，覆盖入口：

```text
/usr/local/bin/python3 /app/reader_credentials.py --config /run/backup-reader-config/reader.json
```

Pod SA 必须为上述 `sandbox-backup-controller`，`automountServiceAccountToken=false`、`fsGroup=10001`。sidecar UID/GID 10001、drop ALL、只读根、禁止提权；只给它投射到 `/var/run/backup-reader-oidc/token` 的 600 秒、`sts.aliyuncs.com` audience token。共享 16 MiB Memory emptyDir 挂 `/run/backup-reader`；sidecar 创建 owner-only `private` 子目录，控制器以相同 UID 只读挂载该卷。控制器配置 `SANDBOX_BACKUP_READ_STS_FILE=/run/backup-reader/private/credentials.json`，不挂投射云 token，也不挂 capture/export/restore 签名私钥或仓库密码。精确 STS HTTPS 和 vault OSS HTTPS 的网络出口需要在控制器部署策略中放行。

刷新进程向固定地域 STS 交换 900 秒凭据，核对返回的 issuer/subject/audience、角色完整 ARN、STS 类型和期限，并附加同等只读 session policy。每 300 秒刷新；写入采用 0600 临时文件、fsync 和原子替换，输出格式为 `{access_key_id,access_key_secret,security_token,expires_at}`。失败立即移除旧文件，5–60 秒有界退避；不会读取环境 AK、节点身份或其他组件的 STS 文件。正常退出删凭据。Rust 每次获取 operator 都重新检查 regular file、0400/0600 权限以及剩余期限超过 120 秒，不缓存过期 operator。

侧车/控制器实际 Deployment 接线及网络策略属于备份控制器交付，不会因本目录出现脚本就自动部署。所有真实 OIDC STS 交换、OSS WORM/RAM、独立恢复验收仍需在目标云账户进行；本次没有执行云写入或发布镜像。

## 已执行验证

Python 单测覆盖完整排序库存、分片/数量/路径上限、重复列表、大小漂移、密文哈希、STS 精确角色/主体/audience/到期、超长 token、原子 0600 输出和失败撤销；真实 Restic 0.19.1/rclone 1.75.1 本地仓库覆盖逐对象哈希、删除源和 mutable 后独立恢复、错误密钥和损坏 pack。Rust 使用 Python/OpenSSL 生成的真实签名 fixture 经过 OSS 签名请求适配器 mock，覆盖正向验签和身份、集合、哈希、凭据负例。Terraform provider validate 和 mock 权限测试已通过；这些都不声称真实 OSS 或云恢复已经验收。
