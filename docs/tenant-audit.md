# 租户账户审计

对应开发表 G2-10、G3-09、G3-10。机器身份登记和变更原本已同事务写入租户审计，现提供独立只读 Interface，供微服务与控制台查询。项目审计仍保持原项目范围。

## 调用和授权

`GET /v1/tenant-audit-records` 使用正常 OAuth/OIDC Bearer 身份和 `X-Tenant-ID`；浏览器通过现有同域 BFF 会话调用。参数仅接受 `limit`（1..100，默认50）和 `cursor`（最多2048字符），不接受项目、实例或其他过滤字段。返回 `{items,next_cursor,cutoff}`。

调用者须具有本租户、`project_id=null` 的 `tenant_audit:read` 授权；现有租户级 `*` 按既有通配语义同样有效。项目授权及项目 `*` 不赋予租户审计权限。ACTION_SCOPES 身份配置还要求当前令牌包含该动作；GENERIC_ACCESS 继续遵循原通用 access profile，产品授权仍独立检查。

新租户可以在已审阅的 bootstrap `initial_principal.tenant_actions` 中显式列出 `tenant_audit:read`。旧租户需要平台 owner 使用受控 owner 数据库连接执行已审阅的租户 grant 变更；当前没有租户授权变更 HTTP／CLI 入口；重复 bootstrap 会严格比较原授权集合，不能改文件后静默提升权限。项目 grant HTTP Interface 不能授予此动作。本次没有新增迁移或数据库角色权限。

授权读取同时核验当前租户、主体、租户成员、身份映射／SERVICE client 绑定、grant启停／撤销／到期和数据库时间。查询前后都重新核验，避免表锁等待期间已撤权或到期的读返回内容。缺少产品权限返回404，缺少 OAuth action scope 返回403；身份和令牌失效沿用正常认证入口的401／403。接口不返回资源是否属于其他租户的信息。

SDK 使用生成的普通 GET，不需要另外一套认证或重试机制：

```ts
const page = await client.GET('/v1/tenant-audit-records', {
  params: {
    header: { 'X-Tenant-ID': tenantId },
    query: { limit: 20, ...(nextCursor ? { cursor: nextCursor } : {}) },
  },
  signal,
});
if (page.error) throw new Error(page.error.code);
if (!page.data) throw new Error('MISSING_TENANT_AUDIT_PAGE');
```

`client` 使用调用方现有 token provider；生产必须使用 HTTPS。不要将 access token、客户端密码、命令内容放入请求记录或业务日志。

## 数据和分页语义

只读取当前租户且 `project_id IS NULL` 的记录。固定投影包括记录、租户、操作者、请求、操作、资源标识，动作、结果和时间；`project_id` 显式返回 null。原始 `details`、变更 body、主体字符串及凭据均不返回。owner 全局 SERVICE client 轮换的独立 `service_identity_binding_audit` 不由此接口公开。记录只作查询，不制造项目事件或补写操作。

按 `(occurred_at,id)` 降序分页，沿用已有审计索引。HMAC cursor 绑定租户、调用主体、独立动作、页大小及首轮 cutoff，24小时到期。不能混用账户登记、项目审计或其他主体的游标；每一页仍检查当前授权。非法、过期或错绑游标返回400 `INVALID_CURSOR`。cutoff 是首轮时间上界；并发迟提交和保留策略可能改变跨页成员，不承诺一致性快照或事件送达确认。

控制台“账户与授权”中的“租户账户审计”可以不选择项目使用。用户显式读取后才发送请求；切换页大小、刷新、身份变化或拒绝读取时隐藏旧数据并取消旧请求，迟到响应不能恢复旧内容。元数据只留在页面内存，不写本地持久缓存。

## 本轮验证与剩余工作

2026-10-11，本地固定镜像 TLS PostgreSQL、正常42条迁移及独立 owner/app 登录下，新增5项实际测试全部执行通过：正常登记／变更审计、脱敏与项目／租户隔离、当前身份及scope授权、双向游标隔离、四种真实表锁等待后的撤权／期限，以及签名JWT/JWKS→真实Node SDK→Rust TCP Interface。完整受影响回归13组63项通过；普通 Rust 424通过、245项环境专项明确ignored，严格Clippy/fmt通过。SDK69、控制台单测66、OpenAPI合同12通过；新增账户浏览器合同5项与备份能力合同4项通过。

证据在 `.local/progress-20261011-tenant-audit/pg-final/record.json`；完整交付索引见[本轮记录](../research/tenant-audit-delivery-20261011.md)。控制台测试使用编译后的真实React页面和HTTP合同夹具，未将其计作新的Keycloak/BFF全链验收。本次没有连接云端或提交Git。

审计归档／导出／保留策略产品化、人类账户管理、目标环境身份与TLS、实云隔离、HA／容量和签名发布仍按开发表继续完成；本模块的局部通过不表示整产品已完成上线验收。
