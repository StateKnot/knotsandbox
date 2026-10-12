# 实例安全防护详情

`GET /v1/instances/{id}/security` 提供实例作用域的只读安全视图，供微服务和控制台使用。它使用正式迁移 0001–0037，不依赖恢复或自动化草案；`api_features.instance_security` 表示该读取接口已安装。隔离、解除隔离和独立运行时认证还需要单独实现和验收，不能由这个标志推断已启用。

请求必须携带有效的 access token 和 `X-Tenant-ID`，并拥有实例所在项目的当前 `instances:read`。接口再次核对 issuer/subject 映射、主体、租户成员、租户、项目、grant 和数据库时钟下的有效期限。必需权限撤销返回 404；token 到期返回 401。可选操作摘要要求 `operations:read`，缺失或撤销时返回 `REDACTED` 和 `resource: null`，其余实例视图仍可读取。无需额外申请模板或策略全局读取权限，也不会因此获得原始策略或其他实例的信息。

| 字段 | 可以说明什么 | 不能说明什么 |
|---|---|---|
| `desired` | 实例绑定的模板、策略版本、资源额度和受控 manifest 期望配置 | 配置已在当前 VM 生效 |
| `observations.policy_object` | 控制面保存过策略对象记录 | Cilium 已执行策略、没有重叠放行策略 |
| `observations.launch_validation` | 历史生命周期校验及其代次、epoch 是否匹配 | 当前 VM 仍存活或已经通过安全认证 |
| `observations.node_authorization` | 已有节点授权期限是否覆盖计算租约 | 当前内核、网络或存储隔离已独立验证 |
| `applied_policy`、`runtime_isolation`、`image_verification` | 当前缺少相应独立证据，状态为 `UNKNOWN` | 隔离失败、镜像安全、没有漏洞 |
| `findings` | 固定控制面守卫的当前阻断项 | 漏洞扫描结论或历史准入拒绝次数 |
| `denial_history` | `NOT_CAPTURED` 表明尚未采集拒绝历史 | 拒绝次数为零 |

控制台的“安全防护”页显示这些不同来源，缺少证据时保留未知。权限撤销后清除旧视图，不使用缓存结果替代 404。控制台使用 BFF session；微服务通过已有 OAuth token provider 调用生成的 TypeScript `GET` 方法，参见 [SDK 示例](../sdk/typescript/README.md)。

读取事务为 READ COMMITTED、只读。聚合内容来自同一 SQL statement snapshot，再按相同绑定重读；实例、模板、策略、对象或历史认证记录变化时返回 409 `SECURITY_TARGET_CHANGED`。最终必需权限检查优先于版本冲突，并按全部授权读取完成后的数据库时间比较 JWT 和 grant 截止时间。可选操作权限撤销只导致脱敏。`as_of` 是本次授权的数据库时间，不是实时云观测时间；接口不承诺返回后状态不会变化。

所有可空字段仍保留键名。无记录与零值不同，时间新鲜度与安全认证不同。`rules_sha256` 对 PostgreSQL 返回的 JSONB UTF-8 文本进行 SHA-256，保留数据库中的整数和小数精度。输入限制为 65,536 个展开后的 UTF-8 字节，与 TOAST 压缩无关；超限时 digest/profile 为 null。它不是 RFC 8785、跨 PostgreSQL 版本的规范格式、签名或审批证明。策略 profile 仅在 JSONB 精确等于 `{"profile":"deny-all","dns":true}` 时识别；任意规则内容不返回给客户端。

响应使用 `Cache-Control: no-store`。`X-Instance-ETag` 仅描述实例的变更版本，安全视图不提供可用于长期缓存的强 ETag。操作错误使用已有公开分类器，移除命令、日志、host、存储标识和原始内部错误。

当前验收包括实际 PostgreSQL RLS、签名 JWT/JWKS HTTP、锁等待后的授权撤销/期限、压缩 JSON 展开上限、数值精度、历史证据和可选错误脱敏；SDK 与真实 Chrome 合同测试覆盖未知状态和撤权后清除视图。可复现命令及 DTO 位于 [安全读取测试包](../tests/fixtures/security/README.md)。这些验证针对控制面和接口合同，不替代目标云上的 Kata/KVM、Cilium 首包、镜像签名或存储隔离认证。
