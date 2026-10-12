# API 的直接 HTTPS 服务

生产 API 由 Rust `sandboxd --role api` 直接终止 TLS；控制台的 Nginx 用 HTTPS 访问 API Service，不需要另一个 API 反向代理。其他微服务同样用 HTTPS API 与 OAuth2 bearer 调用。身份认证和租户权限继续由 API 处理，TLS 不赋予调用权限。

非回环监听必须同时配置以下四项，缺失、相对路径、证书或私钥无效时启动失败，不创建 HTTP 备用端口：

| 环境变量 | 内容 |
| --- | --- |
| `SANDBOX_API_TLS_CERT_FILE` | 绝对路径，PEM leaf 在前、必要中间证书在后，最多 96 KiB / 8 张证书 |
| `SANDBOX_API_TLS_KEY_FILE` | 绝对路径，与 leaf 匹配的 PEM 私钥，最多 16 KiB |
| `SANDBOX_API_TLS_CA_FILE` | 绝对路径，独立审阅的签发 CA bundle，最多 64 KiB / 16 个 trust anchors |
| `SANDBOX_API_TLS_SERVER_NAME` | 要验证的规范小写 DNS 名称或 IPv4 SAN，例如 `api.sandbox-system.svc.cluster.local` |

例如监听 `0.0.0.0:8443`，API 证书必须覆盖实际客户端及控制台访问的 API Service DNS，控制台使用同一 CA 验证上游。CA bundle 由安装操作者提供；不会从浏览器、JWT、请求 Host 或待验证服务器响应取信任根。使用 Rustls 的标准证书链、serverAuth/SAN、leaf 和中间证书有效期验证，不用关闭验证的客户端选项。启用 TLS 1.2 / 1.3 和 ALPN h2/http1.1；不启用旧版本协议或 TLS 会话票据恢复。

仅本机开发允许全部 TLS 字段不配置，此时必须同时设置 `SANDBOX_ALLOW_LOOPBACK_HTTP=true` 并绑定字面回环 IP。这个现有开发开关也只允许 IdP HTTP 使用字面回环地址；即使开启也不能绑定 `0.0.0.0`、私网 IP 或 IPv6 wildcard。生产安装不得使用它。

TLS 私钥的目标文件必须是普通文件，可以是 Kubernetes projected Secret 的链接目标。允许 API 用户或 root 所有的 `0400` / `0600`，也允许 **root 所有、gid 等于 API 主运行组且非 0 的 `0440`**；其他组、组写、任何 other 权限和特殊权限位均拒绝。证书/CA 不可被组或 other 写入。读取对 FIFO 使用 nonblocking 且检查目标类型，文件大小严格有界，错误不输出 PEM、密钥或其他文件内容。

生产 Deployment 使用 `runAsUser: 10001`、`runAsGroup: 10001`、`fsGroup: 10001`、`fsGroupChangePolicy: OnRootMismatch`，TLS Secret volume 的 `defaultMode: 0440`，只读挂载至 `/run/api-tls/`。Secret 投影由 root 持有、API 主组只读，因此无需让主容器以 root 运行。不要把 TLS key 与 BFF、cursor、OIDC client secret、会话加密 key 混在一个共享权限目录；后几类现有文件仍要求 `0400` / `0600`，安装器必须以受控 init container 把其独立 Secret 复制到 owner 为 API UID 的专属内存卷、固定私有文件名，再让主容器只读挂载。初始化不打印秘密，不用 `chmod 0444` 或放松 BFF 检查来解决读取权限。

API 在启动和运行每秒复查已加载证书。有效期检查包含未来 34 秒，覆盖 30 秒退出期、定时器和整秒时钟取整；leaf 或中间证书即将失效、时钟变化导致验证失败时，共享 cancellation token 立即触发，就绪及新业务请求返回 503，停止接受连接并在 30 秒内完成或终止传输。SSE、执行输出和文件流使用相同取消原语；反压不能无限阻塞退出。正常 SIGTERM/SIGINT 使用同一路径。TLS handshake 最多 3 秒，HTTP1 headers 最多 5 秒且 32 KiB，HTTP2 header list 32 KiB、每连接最多 128 并发流并有 keepalive 期限；应用原有 256 请求并发和 20 秒请求期限继续生效。

证书轮换用新的版本化 Secret 名字并更新 Deployment，滚动启动完成校验的新副本。单独覆盖文件不会热加载证书；没有自动重读未审阅文件或失败后保留过期证书的模式。readiness/liveness 应以 HTTPS 请求 `/health/ready` 和 `/health/live`；安装器还须验证实际证书链、DNS、LB 转发、网络策略、轮换及跨副本退出。普通 Kubernetes HTTPS probe 不提供客户端 CA 信任验收，独立真实客户端必须验证证书和 SAN。

本模块测试使用仓库中明确标记的**公开测试证书/私钥**：真实 HTTPS TLS1.2/1.3、错误信任根/明文拒绝、TLS handshake 限时、共享流取消、readiness 拒绝和文件权限负例。真实 PG smoke 用公开 RSA fixture 签名的访问令牌、真实回环 JWKS HTTP fixture、真实 API HTTPS 及真实身份/租户/grant 查询；它不模拟 API 路由，也不证明真实 IdP、云 CA、HA 或云部署。禁止将这些 fixture 安装到任何部署。

所有 runtime role 的 `Config` 在连接数据库前校验 PostgreSQL URL。生产 URL 只允许 `postgres` / `postgresql`、唯一的 `sslmode=verify-full`、绝对 `sslrootcert` 路径，以及可选的规范 `application_name`；拒绝重复参数、别名、`options`、host 覆盖和未知参数。实际 SQLx 连接继续验证证书链及主机名。只有显式开发开关与字面回环 DB 地址同时成立时才能省略 TLS。秘密 URL 不进入日志。API 清单挂载的 DB CA 固定为 `/run/api-trust/db-ca.pem`，Secret 中的 URL 必须引用该路径；环境变量中的 URL 不能反向覆盖安装清单的目标。安装配置、私有文件初始化与网络激活检查参见 [API 生产安装](api-installation.md)。
