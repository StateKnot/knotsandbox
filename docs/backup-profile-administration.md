# 备份配置注册、启用和撤销

生产备份配置通过 `sandbox-admin backup-profile` 管理。该命令不对外提供 HTTP owner 接口，数据库连接使用独立安装 owner；API、worker、backup、admission 等运行角色不能启用配置。注册、激活和撤销均记录不可变的 `backup_profile_actions`，每个请求必须有 UUID 和审批引用，相同 UUID 只能重放相同动作。重放旧激活请求不会重新启用后来撤销的配置。

## 制品和密钥准备

先执行 `deploy/backup/controller.py install-protection --config <配置路径> --context <受审集群context>`，安装最小 RBAC、FailClosed 准入以及精确存储类。创建三份受保护密钥后，再执行同工具的 `install` 启动专用控制器；两个安装动作都必须指定 context。密钥使用 `sandbox-system` 内的 `sbx-bkey-` 保留前缀；创建者属于专用 Kubernetes 组 `sandbox:backup-key-installers`，不能是 ServiceAccount。三份 Secret 分别只有 `password`、`private.pem`、`public.pem` 一个 data 项，必须是 immutable Opaque，且没有 ownerReferences 或 finalizers。准入永久拒绝这些名称的更新和删除；轮换使用新名称，旧备份所需密钥继续保留。先部署保护再创建密钥，不能通过停用配置解除保护。

`settings.secret_bindings` 分别记录 password、signing_private、signing_public 的名称、Kubernetes UID 和原始单一 data 字节的 SHA-256；不是 base64 字符串的哈希。公钥另以 Ed25519 SPKI DER 的 SHA-256 绑定签名身份。数据库及审计保存名称和摘要，不保存明文密码或私钥。控制器使用同一公钥 Secret 的 `public.pem`，配置读取器也兼容严格的 44 字节 Ed25519 SPKI DER。

配置和认证报告采用 `deploy/backup/backup.py` 的 canonical JSON：ASCII、键排序、紧凑编码、无尾部换行。配置大小不超过 64 KiB，报告不超过 128 KiB，`enabled` 必须为 false。报告绑定完整配置摘要（计算时仅去掉 certification_report_sha256），并绑定工具版本锁、镜像 digest、云账户、地域、独立仓库、KMS、密钥身份和存储类。

九项认证检查必须齐全，证据观测时间在审阅前七天内，报告有效期最多三十天。PASS 和 evidence_sha256 是审阅者对真实验收材料的签署记录；软件不会把手写 PASS 视为已经执行过云端隔离、KMS 恢复或独立恢复演练。审批引用应关联可复核的实际材料。

## 命令

以下路径和 UUID 由部署者填入实际制品。`SANDBOX_ADMIN_DATABASE_URL` 通过受控运行环境提供，不放入命令行、日志或历史记录。

```sh
sandbox-admin backup-profile register \
  --file /run/review/profile.json \
  --certification-report /run/review/report.json \
  --request-id "$REGISTER_REQUEST_ID" \
  --approval-reference "$CHANGE_REFERENCE" \
  --validate-only
```

`--validate-only` 只做本地结构、摘要和认证时间检查，输出 registration_enabled=false、live_activation_verified=false。把它替换为 `--apply` 才执行原子注册；注册仍然保持禁用。重复名称、不同配置内容不能覆盖原 UUID，需注册新的不可变配置版本。

激活前启用平台 safe_mode，并准备独立的 backup-certifier 短时只读 STS 身份，以及 `deploy/backup-certification/expectation.schema.json` 对应的目标文件：

```sh
sandbox-admin backup-profile activate \
  --file /run/review/profile.json \
  --certification-report /run/review/report.json \
  --retention-expectation /run/review/vault-expectation.json \
  --retention-sts-file /run/backup-certifier/private/credentials.json \
  --request-id "$ACTIVATE_REQUEST_ID" \
  --approval-reference "$CHANGE_REFERENCE" \
  --apply
```

激活执行实时 Kubernetes 检查：网络策略、Kata RuntimeClass、Retain 加密块克隆存储类、Retain CSI 快照类、备份密钥保护 webhook 和三份精确 Secret，以及 Ed25519 公私钥配对。随后直接访问目标 OSS，验证 Locked WORM、保留期、归属、加密、版本控制和锚点。不能用保存在磁盘上的旧验证 receipt 替代这些读取。

数据库提交再次检查当前恢复 epoch、safe_mode、配置内容和证据新鲜度；外部证据最长五分钟有效，配置有效期必须覆盖完整六小时备份截止时间。owner 事务采用五秒锁等待和三十秒语句上限。激活不会自动解除 safe_mode，也不会创建云资源或修改 WORM。

```sh
sandbox-admin backup-profile revoke \
  --profile-id "$PROFILE_ID" \
  --request-id "$REVOKE_REQUEST_ID" \
  --approval-reference "$CHANGE_REFERENCE" \
  --apply
```

撤销不要求旧报告仍有效，也不要求其 epoch 仍然是当前值。它阻止新活动继续取得授权；已有活动仍须经过可信终止和资源清理。配置、密钥、审计、工作区保护和已备份数据不会因此被删除。

## 证据边界

OSS 实时读取验证当前状态，不能证明未来 IAM 永远不会允许打开版本控制、替换策略或破坏 KMS。独立账户/角色隔离、禁止变更的 RAM 约束、密钥恢复及实际独立恢复演练仍是认证材料的必要部分。详见 [保留期认证](backup-retention-certification.md) 和 [独立库存核验](backup-vault-verification.md)。本地 TLS、合成 Kubernetes API 和真实 PostgreSQL 测试用于验证程序行为；它们不替代真实阿里云/Kata 验收。
