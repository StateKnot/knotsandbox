# 浏览器 OIDC 与服务端会话

浏览器以同一个 HTTPS origin 访问控制台和 `/auth/*`、`/v1/*`。BFF 使用 confidential client 的 Authorization Code + PKCE S256；固定回调为 `https://控制台域名/auth/callback`。机器服务继续使用原有 bearer API。独立身份模式使用部署包的 Keycloak；企业模式使用固定的企业 issuer，或由 Keycloak broker 对接企业 OIDC。产品身份始终按 `(issuer, sub)` 绑定，登录不创建、合并或按邮箱匹配产品账户。

本包要求正式应用 migration 0037 及 `scripts/sql/browser-role.sql` 的窄函数权限。配置启用时会在监听端口前核验；未配置时 `/auth/*` 不开放。迁移按 0036、0037 的正式版本顺序执行；不得手工填充迁移台账或跳过角色脚本。

## 配置与身份客户端

设置 `SANDBOX_BROWSER_CONFIG_FILE` 为绝对路径 JSON，配置引用两个绝对路径私有文件，权限必须为 `0400` 或 `0600`。客户端 secret 文件只包含 secret，可有末尾换行；使用密码管理器生成至少 32 字节的新随机值。BFF 所有副本共享同一组服务端 AES256GCM keys；密钥存放在 KMS/Secret 挂载中，独立于数据库备份，不放入 Terraform state、镜像、环境变量或 Git。

```json
{
  "oidc": {
    "issuer": "https://identity.example.com/realms/sandbox",
    "authorization_url": "https://identity.example.com/realms/sandbox/protocol/openid-connect/auth",
    "token_url": "https://identity.example.com/realms/sandbox/protocol/openid-connect/token",
    "jwks_url": "https://identity.example.com/realms/sandbox/protocol/openid-connect/certs",
    "client_id": "sandbox-browser",
    "public_origin": "https://sandbox.example.com",
    "scopes": ["openid", "sandbox:access"]
  },
  "client_secret_file": "/run/secrets/browser/client-secret",
  "session_key_file": "/run/secrets/browser/session-keys.json"
}
```

Key 文件格式为 `{"active":"k202610","keys":[{"id":"k202610","key":"BASE64URL_NO_PADDING_OF_32_RANDOM_BYTES"}]}`。最多保留 8 个不同 key id。切换 active 前先给全部副本部署包含新旧 key 的文件，再滚动重启切换 active；旧 key 最早在最后一个旧副本退出后 8 小时 5 分钟移除。移除旧 key 会使剩余旧会话要求重新登录。DR 恢复必须生成新 `cluster_epoch`；旧数据库中的挑战和会话随即失效。

Keycloak 26.8 客户端可通过 `deploy/identity/browser_client.py render --client-id sandbox-browser --public-origin https://sandbox.example.com` 生成原生 Admin API representation；按既有私网 Admin 运维流程创建客户端及从 secret manager 配置 secret，禁止将密钥写入此生成文件。其 `verify` 模式使用私网 Admin TLS origin 和私有 token 文件，只读核验实时配置。服务端 token 请求使用 HTTP Basic，API access token audience 为 `sandbox-api`，scope 为 `sandbox:access`；浏览器客户端不启用 service accounts、password grant、implicit、offline_access 或 wildcard redirect。realm 设置 RS256、300 秒 access token、refresh rotation/max reuse 0、MFA。企业 issuer 需要提供等价能力。

客户端显式限定 default scope 为 `sandbox:access`，因此在客户端自身固定一个 `oidc-sub-mapper`，启用 `access.token.claim` 和 `introspection.token.claim`，不用隐含的 realm 默认 scope 提供 subject。[Keycloak 26.8 的默认 `basic` scope 注册 subject mapper](https://github.com/keycloak/keycloak/blob/26.8.0/services/src/main/java/org/keycloak/protocol/oidc/OIDCLoginProtocolFactory.java)，[原生 SubMapper](https://github.com/keycloak/keycloak/blob/26.8.0/services/src/main/java/org/keycloak/protocol/oidc/mappers/SubMapper.java) 的 access token subject 来源为用户 ID。替换默认 scope 链接可能漏掉该 mapper。部署实时核验会拒绝缺失、停用、替换为 pairwise 或额外 mapper；Admin API 自动生成的 mapper `id` 仅视为元数据。企业 IdP 同样必须提供 access/ID token 中一致、非空、稳定的 subject；缺失 subject 不能通过放松 JWT 校验解决。

上述 PKCE S256、客户端 session timeout 和 refresh rotation 设置使用 [Keycloak 26.8 官方管理文档](https://www.keycloak.org/docs/26.8.0/server_admin/) 的原生能力；renderer 的字段名称与 [官方 OIDCConfigAttributes](https://github.com/keycloak/keycloak/blob/main/server-spi-private/src/main/java/org/keycloak/protocol/oidc/OIDCConfigAttributes.java) 一致，部署时再读取实时客户端配置核验。

## HTTP 契约

| 请求 | 行为 |
| --- | --- |
| `POST /auth/login`，JSON `{"tenant_id":"UUID"}`，Origin 为配置 origin | 返回 `authorization_url`；浏览器导航该 URL；设置 5 分钟 `__Host-sandbox-login` Secure/HttpOnly/SameSite=Lax 绑定 cookie |
| `GET /auth/callback?state=…&code=…` | 消耗并提交 state+绑定挑战，再调用 IdP 一次；验证 nonce、签名、issuer、audience、subject；成功后 303 到 `/` 并设置 `__Host-sandbox-session` Secure/HttpOnly/SameSite=Strict；清除绑定 cookie |
| `GET /auth/session` | 返回当前 tenant/principal UUID、CSRF token、绝对/空闲过期时间；无 access/refresh token |
| `POST /auth/logout`，Origin + `X-CSRF-Token` | 撤销本产品会话，清除 cookie；现有 SSE/二进制下载长流在 10 秒检查周期内停止；IdP SSO 会话仍按其原生登出策略管理 |
| cookie 方式调用 `/v1/*` | 必须 `X-Tenant-ID` 与会话一致；写请求还必须精确 Origin + `X-CSRF-Token`；CSRF token 保存在页面内存，不放 URL |

一个会话固定一个 tenant，最长 8 小时、空闲 30 分钟；切换 tenant 从 `/auth/login` 重新选择目标 tenant。已有 SSO 可复用 IdP 登录，但产品必须验证该 tenant 的有效 USER membership。每个 principal/tenant 最多 20 个未过期会话。challenge 全局最多 5000 条、TTL 5 分钟。公共代理必须对登录入口设置 IP 频率限制并只开放明确业务路径；应用自身有固定并发/请求期限。BFF 不读取 caller Host/X-Forwarded-* 推导回调或 Origin，也不接受任意 return URL。

access/refresh token 与 CSRF 值以 AEAD ciphertext 持久化，AAD 包含记录 UUID、用途与 epoch。Cookie/CSRF capability 只存 SHA256。每次请求实时检查产品 principal、identity mapping、tenant、membership 和 epoch；JWKS/IdP 网络验证后再复验当前会话版本。Cookie 与 bearer 同时提交会拒绝。长流的 guard 独立于 SSE 业务鉴权，在空闲等待时也检查本产品 session；长流保持当前 access token，过期后重新连接触发新的会话鉴权/刷新。

IdP 签名密钥轮换应提前至少 5 分钟发布新公钥，再开始签发新 `kid`；旧公钥保留到旧 access/ID token 与 key cache 全部到期。未知或不可验证的 signer 会拒绝该次已消费的登录并要求重新登录，不重新兑换 code。

refresh 先提交 `REFRESHING` 单次尝试和版本，再调用 IdP；其他并发请求暂时返回 503。成功仅能以同一个尝试版本发布；退出、禁用身份、DR、过期或 subject 改变使发布失败。网络错误或不确定结果撤销会话并要求新登录，禁止重试可能已被轮换的 refresh token。崩溃遗留的 `REFRESHING` 超过 15 秒后，在下一次会话检查时撤销。每 60 秒最多清理 100 条到达绝对/空闲期限的会话，先清除 encrypted payload，30 天后删除会话/路由元数据；业务 audit 记录按独立审计保留策略保留。

反向代理和 APM 必须关闭 `/auth/callback` 查询串、Cookie、Authorization、token endpoint body 记录；响应均 `Cache-Control: no-store`，回调 `Referrer-Policy: no-referrer`。已有应用 request 日志只含 request id、status、耗时。TLS、secret manager/密钥轮换、实际 Keycloak/企业 IdP 用户登录、MFA、代理限流与跨副本/故障恢复均需在目标环境验收；本地签名 OIDC + PostgreSQL + HTTP 测试不替代这些部署证据。

2026-10-08 实际执行 `src/bff_live_tests.rs` 的独立随机 realm 联调：真实 Chrome → 已构建控制台 → Rust BFF/API → 本地真实 Keycloak 26.8/PostgreSQL，使用上述 production browser client renderer（只把回调替换为测试随机回环端口）。跨浏览器 site 的 Code + PKCE 登录、opaque Secure/HttpOnly/Strict cookie、真实 `/actions/stop` 202、撤销项目 grant 后 404、禁用 membership 后回到登录及无浏览器 bearer/token 存储均通过，记录为 `.local/bff-keycloak-browser-live-20261008.log`，1/1、10.34 秒。这个链路未 mock HTTP/身份。HTTPS 入口用公开 fixture，Chrome 明确忽略该测试证书错误，本地 IdP HTTP 仅限字面回环 test transport，因此它证明真实身份与产品会话行为，**不证明生产 TLS 信任、真实云 HA、MFA 或企业联邦**。API/代理 TLS 正负验证另有独立严格 CA/SAN 测试，不能混为同一生产部署验收。
