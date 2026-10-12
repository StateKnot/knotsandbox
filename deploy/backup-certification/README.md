# 只读 OSS 保留认证

入口和完整边界见 [认证运行手册](../../docs/backup-retention-certification.md)。此目录只生成审核策略和短期凭据；`sandbox-backup-worm` 实际调用固定内网 OSS endpoint，不执行云写操作。

`credentials.py --config certifier.json` 接收以下**公共配置**，所有字段必填、拒绝未知字段：

| 字段 | 来源 |
| --- | --- |
| account_id / region / bucket | 精确部署账号、地域、vault bucket |
| cluster_epoch / profile_id | 当前部署 epoch、待激活 profile UUID |
| anchor_key | `certification/{cluster_epoch}/{profile_id}/{受控名称}` |
| issuer / oidc_provider_arn | workload identity issuer，不能复用用户登录 Keycloak issuer |
| role_arn | 同账号专属、以 `-backup-certifier` 结尾的角色 |

固定 subject 是 `system:serviceaccount:sandbox-system:sandbox-backup-certifier`，audience 是 `sts.aliyuncs.com`。使用 `policy --kind permission` 和 `policy --kind trust` 导出两份可审查 RAM JSON；它们不进行 apply，不能扩大为桶通配符或复用 backup writer/reader 的角色。`refresh` 只写指定 0700 目录中的 0600 STS 文件，失败删除旧文件。

部署现场仍需创建/审核上述角色、独立 SA 和已有 anchor；本目录没有伪造一份已经部署的 IAM、WORM 或恢复证书。测试：`./check.sh`，无需网络或云凭据。
