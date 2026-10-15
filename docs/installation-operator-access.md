# 安装级节点镜像读授权

本接口供独立产品或组合部署的微服务核验安装级权限。它使用产品现有独立 Keycloak／外部 OIDC 配置，复用真实 access-token 验证；没有第二套密码库。
本批交付 P0c1：持久授权、永久撤权、管理命令和授权检查。节点库存查询、Prometheus 查询消费者和原生整链仍待 P0c 后续，不因授权成功而开放节点数据或镜像预拉取。

## 部署与权限

先用独立 owner 登录执行正常 `sandboxd --role migrate`。正式迁移为 `1..37 + 39..47`，共 46 条；没有 0038。旧迁移逐字保留。
0047 为现有配置单例新增持久 `installation_id`，升级不预授予任何身份；SQLx 重跑保持该 ID。
灾备恢复应保留原数据库安装身份，并按现有流程切换 `cluster_epoch`。不能靠传一个安装 ID 选择安装。

正常 API 登录仍是无 owner／跨模块角色成员关系的 `sandbox_app`。它只获得 `sandbox_node_image_access(text,text,text,bigint)` 的 EXECUTE，无授权表、安装审计表或管理函数权限。
通用 `verify_runtime_role`（API 监听及 `resource-accounting-check` 维护预检共同使用）会核对正式迁移 checksum、两张私表及单例表的列／约束／索引、六个函数的正文／参数／返回值／语言／owner／search_path／ACL、六个触发器及实际 runtime 权限。漂移必须由管理员审查，启动检查不自动补权限。

创建／撤权通过 `sandbox-admin node-image-reader`，使用独立 `SANDBOX_ADMIN_DATABASE_URL`。读授权不包含管理能力；普通 tenant 的 `instances:read` 或 `*` 都不能授予安装级读权限。
目前只授予已有、启用且精确绑定的 SERVICE 身份。issuer、subject、client_id 应来自可信 IdP 登记，不能从未经验证的 JWT 或名称推断。已有身份登记和 client 绑定保持原管理流程。

## 显式授权

管理员在受控 owner 会话读取当前范围：

```sql
SELECT installation_id, cluster_epoch FROM platform_configuration WHERE singleton;
```

准备不超过 16 KiB 的 JSON 文件（文件不含密码或令牌）：

```json
{
  "grant_id": "00000000-0000-4000-8000-000000000001",
  "installation_id": "00000000-0000-4000-8000-000000000002",
  "cluster_epoch": "00000000-0000-4000-8000-000000000003",
  "issuer": "https://identity.example.test/realms/sandbox",
  "subject": "reviewed-service-subject",
  "client_id": "reviewed-service-client",
  "expires_at": "2026-10-17T00:00:00Z",
  "reason": "Approved installation node image diagnosis"
}
```

例中 UUID、身份和期限必须替换。每次新授权使用新 grant_id；期限由数据库在锁等待后检查，必须大于当前时间且不超过 24 小时，不能省略或设置无限期。期限返回值使用实际持久的 PostgreSQL 微秒精度。

```sh
sandbox-admin node-image-reader --file reader.json --validate-only
sandbox-admin node-image-reader --file reader.json --apply
```

`validate-only` 只检查格式与字段，不连接数据库，不证明身份、期限或授权已生效。同 ID、同字段、未撤销的重试复用原授权；换字段或复用已撤销 ID 失败。
同身份／安装／epoch 只允许一份未撤销授权，过期后要显式撤销旧项再创建新项。授权和安装审计在同一事务提交。
HTTPS 为默认。与既有本机开发认证配置一致，只有显式 `--allow-loopback-http` 才接受 HTTP literal loopback IP；不接受 HTTP hostname 或私网 IP。生产部署继续使用 HTTPS。

## 微服务核验

```http
GET /v1/operator/access
Authorization: Bearer <access-token>
```

不需要 `X-Tenant-ID`，不接受任何查询参数。token 的 issuer、audience、签名、期限、client 和部署必需 scope 按现有验证；`ACTION_SCOPES` 模式还需精确 `node_images:read`，OAuth `*` 不替代该 scope。

200 正文只有 `installation_id`、`cluster_epoch`、`grant_id`、固定 `action: node_images:read` 和 `expires_at`。无有效 token 返回 401，无当前安装授权返回 403；身份服务／数据库不可用按既有 503 分类。无节点、tenant、路径、repository 或 PromQL 字段。

每次请求新查当前单例和持久授权，不缓存上次成功；所有响应 `Cache-Control: no-store`，带服务器生成的请求 ID。
成功是该次数据库语句快照上的权限观察，不是可以转交、缓存或延长 JWT 的能力令牌，也不保证后续外部 I/O 仍有授权。
后续节点消费者必须在外部 I/O 前后重新核验，并比较包含原 grant_id 的许可及当前节点／boot／profile，拒绝撤旧授权后重发新授权的 ABA；不能只比较两次 `allowed=true`。

## 永久撤权与身份变化

撤权文件只含原 `grant_id`、`installation_id`、`cluster_epoch`、非空 `reason`，同样严格拒绝未知／重复字段和 nil UUID。

```sh
sandbox-admin node-image-reader --file revoke-reader.json --revoke --validate-only
sandbox-admin node-image-reader --file revoke-reader.json --revoke --apply
```

重复撤权幂等且保留第一次撤权审计；不能恢复旧授权、修改范围、期限或删除历史。需要再次授权必须创建新 ID。
身份／主体禁用、principal kind／authz_version 改变、issuer／subject／principal 绑定改变、client 或 binding generation 改变、installation／epoch 改变时，数据库触发器在同事务永久撤销对应授权。因此 disable→enable、client A→B→A、epoch A→B→A 不会恢复旧授权。
撤销原 epoch 的授权仍可用其原范围执行，便于换代后关闭历史记录。到期独立检查，不因幂等重试延长。
这些只撤销安装读权，不停止已有合法实例，也不更改租户授权或节点运行状态。
