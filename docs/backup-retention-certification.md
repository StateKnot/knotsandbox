# 备份 vault 的只读保留认证

此包交付可执行的现场认证工具，不包含已经通过的云认证。仓库测试只连接本机 TLS 模拟 OSS；尚未读取实际阿里云 bucket、创建 anchor、发布 RAM 策略或启用生产 backup profile。

`sandbox-backup-worm` 顺序调用两轮 GetBucketInfo、GetBucketWorm、GetBucketVersioning、HEAD anchor，两轮至少间隔 1 秒。生产入口固定为 `https://{bucket}.oss-{region}-internal.aliyuncs.com`，不接受自定义 URL、代理或跳转。部署在对应地域、具备该内网域名解析和网络访问的受控平台主机。TLS 使用系统受信 CA；工具没有关闭校验开关。

## 成功条件

| 检查 | 必须满足 |
| --- | --- |
| 身份绑定 | account ID、region、bucket、KMS key ID 与审核输入完全相等；桶 ACL 为 private；默认加密为 KMS/AES256 |
| 锁定 | GetBucketWorm 返回 `Locked`；实际 days≥profile `vault_retention_days`，profile days 范围 31–3650 |
| 版本控制 | GetBucketVersioning 的 Status 不存在，即从未启用；Enabled、Suspended 和伪造的 Disabled 文本均拒绝 |
| anchor | 精确 `certification/{cluster_epoch}/{profile_id}/{name}`，普通对象、匹配 ETag/size/KMS、无 version ID；Last-Modified 不早于 WORM 创建时间 |
| 保留窗口 | anchor 的 `Last-Modified + 实际 days` 至少覆盖 `certified_until + 6 小时最大作业时间 + 60 秒` |
| 时间与一致性 | 每次响应唯一 Date 和 request ID；云 Date 与本机偏差≤30秒；两轮关键 bucket/anchor 属性相同 |
| 可激活期限 | `certified_until` 在本机当前时间之后 10 分钟至 30 天；验收 token 只在最后观测后 5 分钟内用于激活 |

每次请求最多重试三次，仅网络错误、429、5xx 可重试；其他错误立即失败。单次 HTTP 超时 10 秒，整个认证 90 秒。XML 最大 64 KiB、深度 8、单值 4 KiB；拒绝重复路径、DTD、实体、CDATA、混合内容。日志和错误不返回响应体、授权头或 STS 内容。报告保存请求 ID、云时间及响应 SHA256，便于另行云审计。

OSS 锁定策略按对象最后修改时间计算，而不是按认证时间计算。Locked 策略不能缩短，但空桶或全部对象都过期后仍可被删除；独立受保护 anchor 用于固定认证期间的桶身份。[阿里云 BucketWorm 规则](https://www.alibabacloud.com/help/en/oss/user-guide/oss-retention-policies)。API 返回字段和权限分别参照 [GetBucketWorm](https://help.aliyun.com/zh/oss/developer-reference/getbucketworm)、[GetBucketInfo](https://www.alibabacloud.com/help/en/oss/developer-reference/getbucketinfo)、[GetBucketVersioning](https://www.alibabacloud.com/help/en/oss/developer-reference/getbucketversioning)、[HeadObject](https://www.alibabacloud.com/help/en/oss/developer-reference/headobject)。

## 权限和不能省略的独立门槛

独立 `sandbox-backup-certifier` service account 的投射 token audience 必须为 `sts.aliyuncs.com`；信任声明固定 issuer、subject、audience。角色名以 `-backup-certifier` 结尾，账号必须与 bucket 审核账号一致。凭据工具复用已有官方 AssumeRoleWithOIDC 流程，返回 900 秒 STS，校验回包 role ARN、issuer、subject、audience 和期限。它不使用长期 AK、环境变量或实例元数据。

精确权限只有：

- bucket 级 `oss:GetBucketInfo`、`oss:GetBucketWorm`、`oss:GetBucketVersioning`。
- 单个 anchor key 的 `oss:GetObject`，仅用于 HEAD。无需 LIST、业务对象读取、`kms:Decrypt`、Put、Delete 或 WORM 管理权限。

RAM 策略可由 `deploy/backup-certification/credentials.py policy` 生成；这只生成审核文本，不创建角色或绑定策略。安装人员必须另外创建独立角色、投射该 SA token 并挂载匹配的公钥 OIDC 信任；此工具不会代办。

当前快照不是整个保留期的权限证明。**官方允许在 Locked 后启用版本控制**，之后同名对象可以写入新版本。现有备份 manifest 没有绑定所有对象 version ID，所以生产启用必须有独立审查/故障验证证明：备份运行角色和所有共享写入主体都不能执行 `PutBucketVersioning`、改 bucket policy、改 WORM/ACL/加密、销毁 KMS 密钥或接管其他备份前缀；管理变更须先禁用 profile 并重新认证。不能仅凭策略 hash、一个 `true` 或本工具报告断言这一门槛已完成。账户欠费、平台管理员变更、未来 KMS 可用性和实际恢复结果也不由这组只读 API 证明。保留策略与版本控制关系见上述官方 BucketWorm 文档。

每个备份使用全新独占前缀；仓库对象须在受理之后创建。控制面受理时要求 `request.retention_days <= settings.vault_retention_days`，才能从对象时间推导出不少于受理时承诺的 `retention_until`。每次恢复仍必须验证签名、库存对象哈希和最终原始磁盘哈希；本认证不读取仓库数据。

## 现场运行

准备严格 JSON expectation（字段见 `deploy/backup-certification/expectation.schema.json`）。`profile_settings_sha256` 是**最终入库的准确 profile settings JSON** 的 SHA256，按控制面的规范序列化计算，不是人工填写的“审核已过”标签。epoch、profile UUID、account/bucket/KMS 必须来自同一部署的受控配置。anchor 需要安装阶段另行经授权创建为非敏感普通对象，记录 ETag/size；此命令只 HEAD，缺失或剩余保护期不足即失败，不自动创建/续期。

先以受控流程为角色和 SA 配置专用信任。把已投射 token 挂载为只读文件，期限不超过 3600 秒；将凭据输出目录创建为当前 UID 所有的 0700 目录。公共配置形状见 `deploy/backup-certification/README.md`。

```sh
python3 deploy/backup-certification/credentials.py --config certifier.json policy --kind permission
python3 deploy/backup-certification/credentials.py --config certifier.json policy --kind trust
python3 deploy/backup-certification/credentials.py --config certifier.json refresh \
  --token-file /var/run/backup-certifier-oidc/token \
  --output /run/backup-certifier/private/credentials.json
sandbox-backup-worm --expectation expected-retention.json \
  --sts-file /run/backup-certifier/private/credentials.json \
  --output retention-observation.json
```

不要把 token 或 STS 放进命令参数、shell 变量、环境变量或工单。命令参数只有文件路径和公共配置。STS 文件必须 0400/0600、普通文件、≤16 KiB、剩余有效期>120秒且总剩余≤1小时；支持 Kubernetes 原子投射 symlink，检查打开后的文件；FIFO/设备立即拒绝。刷新失败会删除旧输出，不继续使用残留凭据。工具只读 OSS，但调用 STS 会产生临时凭据。

JSON 报告 `protocol=oss-bucket-retention/v1`，含完整 expectation、固定 endpoint、开始/观测/激活截止时间、bucket/anchor 事实和八个请求证据。`evidence_kind=LIVE_AUTHENTICATED_OSS_READS_NOT_PROVIDER_SIGNED_ARTIFACT` 表示经验证 HTTPS 观察；报告本身不是阿里云签名证明。它可用于审核归档，不能导入为授权 token。命令拒绝覆盖已有输出文件。

owner 激活入口必须在当前进程调用 `BucketRetentionVerifier::new(expected, sts_file)?.verify().await?`，接收没有公开构造器、没有 Deserialize 的 `VerifiedBucketRetention`；最后入库事务里复核 `proof.check_current(&expected)`、profile settings hash 和当前 epoch，保留其他独立认证要求。不能把磁盘报告反序列化成此 token。库 API 不接收用户提交的“proof JSON”。

`object_retention_days.backup_vault` 是 Terraform 显式参数，没有默认值；现在小于 31 天的 plan 会失败，其他对象期限规则不变。已有 30 天桶须由运维按正常变更流程显式扩展并重新读验；本工具不会执行扩展或把 31 天承诺降为 30 天。

## 本地验证

```sh
deploy/backup-certification/check.sh
cargo test --locked --offline --lib bucket_retention
```

Rust 测试使用真实回环 TLS 与实际锁定版本 OSS V4 signer，覆盖两轮一致性、身份/期限/版本状态拒绝、签名头、重定向拒绝、错误正文脱敏、XML 限额、云时间偏差、短期凭据和有限重试。它不证明真实 OSS 服务、RAM policy、WORM 锁定或灾备恢复；生产认证前必须在目标账号/地域实际运行。
