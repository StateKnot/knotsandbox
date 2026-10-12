# 生产身份底座与安装合同

本包把用户身份服务与产品资源授权分开：身份服务验证人和机器，产品仍用 `(issuer, sub)` 对应内部主体，并在每次资源请求检查租户/项目 grant。Keycloak 角色、邮箱和企业 group 不自动变成产品权限。实现位于 `deploy/identity`，Rust 共享授权上下文同时落实 token 动作上限、SERVICE client 绑定和外部 I/O 后身份复查。

本次已交付官方 Operator 的可安装资源、两种身份配置、受控安装器、真实 TLS/realm 配置验证及运维步骤。**尚未在阿里云执行安装或验证 HA、RDS 切换、真实 SMTP、企业 IdP 和公网入口隔离；这不是整套生产环境已验收。** 安装器从零创建受控入口代理，再安装Keycloak；已有代理对象必须符合相同归属和配置合同，否则拒绝接管或覆盖。云侧DNS、双入口LB/私网接入及RDS仍按基础设施安装步骤准备。

## 1. 两种模式

| 模式 | 产品信任的 issuer | 用户与机器身份管理 | 本包行为 |
|---|---|---|---|
| `standalone` | 固定 Keycloak 应用 realm URL | Keycloak 原生账户、MFA、恢复、服务客户端 | 安装官方 Operator 与三副本 Keycloak，初次创建 realm |
| `external` | 固定企业 OAuth2/OIDC issuer | 企业 IdP 负责 MFA、账户和 OAuth client 生命周期 | 仅生成产品鉴权配置，不部署或假装管理外部 IdP |

独立模式可选 Keycloak 原生 OIDC broker：人类使用企业登录，但产品始终只信任 Keycloak issuer；不因此接受上游 token。首次 broker 登录只能创建唯一账户，用户名/邮箱冲突拒绝，不能自动链接已有用户；登录后还要完成本地强制 OTP。产品主体保持 Keycloak 的 `(issuer, sub)`，显式账户迁移必须走受审计的身份绑定流程。这里没有任意认证插件或按请求动态 issuer。官方行为参考 [Keycloak 26.8 管理文档](https://www.keycloak.org/docs/26.8.0/server_admin/)。

企业直连使用 `external.example.json`，必须满足现有 API 的实际合同：

- HTTPS 固定 issuer 和 JWKS；RS256；正确 API audience、签名、`exp`/`nbf`/`iat`/`sub`、`sandbox:access` scope。
- RFC 9068：JWT header `typ=at+jwt`、`client_id` 和 `jti`；或现有 Keycloak access-token profile：header `typ=JWT`、签名 payload `typ=Bearer` 和 `azp`。ID token 不可当 API access token。`token_profile` 是部署验收声明，运行时仍按现有两种明确 profile 校验，不能配置成任意 JWT。
- 每个微服务独立 client；机器的 `client_id`/`azp` 与登记身份匹配。浏览器 Code + PKCE S256 客户端与机器 client credentials 分开，禁用 implicit/password grant。不存在由本文自动创建的产品前端或 BFF。
- 最长 token 300 秒、允许偏差 30 秒。JWKS 正常缓存 300 秒，未知 kid 受限刷新；网络/签名错误不放行。轮换必须保留旧公钥至旧 token 最长期限结束，先发布新 key 再签发；立刻撤 Key 的影响不能伪称实时。
- 本地禁用主体/撤 grant 立即作用于后续授权；只在 IdP 禁用账户，离线 JWT 最迟在有效期加偏差后失效，除非另有已验收的事件/introspection 集成。本包没有增加该同步通道。

生成的 `auth.json` 是部署输入合同；当前 `sandboxd` 通过 `SANDBOX_OIDC_ISSUER`、`SANDBOX_OIDC_AUDIENCE`、`SANDBOX_OIDC_JWKS_URL`、`SANDBOX_OIDC_REQUIRED_SCOPE`、`SANDBOX_OIDC_SCOPE_PROFILE` 读取对应值。生产必须保持 `SANDBOX_ALLOW_LOOPBACK_HTTP=false`，不能误称服务会自动读取 `auth.json`。其余固定期限与现有 Rust 配置保持一致。外部 IdP 不满足上述 access-token 形状时，应修改受支持的 IdP 配置，或用 Keycloak broker；不能关闭 API 的签名/profile 校验。

**与云工作负载身份完全独立：** 此处 issuer 用于产品用户/微服务。Kubernetes ServiceAccount issuer/JWKS、投射 token、阿里云 RAM OIDC→STS 刷新用于 CSI/OSS/fencing；不能把 Keycloak issuer 填入该信任关系。K8s 公钥发布/轮换和 STS 端到端验证属于另一交付项，本包不宣称已经完成。

## 2. 固定依赖与 HA 形态

采用 Keycloak **26.8.0** 与同版本官方 Operator。应用镜像沿用已验证的 `b0f60d48…352bcc` digest，Operator 为 `3e7c09e6…e6d4f2d5`，完整值在 `versions.lock.json`。四个 CRD 和单 namespace Operator 清单原样入仓并固定 SHA256；渲染时替换 namespace、两个应用镜像环境值、Operator 镜像及平台节点选择器。无 Helm 实验 chart、无 cluster-wide preview，也不让在线构建追踪 latest。[官方 Operator 安装](https://www.keycloak.org/operator/installation)

三个 Keycloak 副本固定调度到平台节点、三个可用区，不容忍 untrusted 工作节点 taint；同节点强反亲和、zone DoNotSchedule、PDB 至少两个可用。资源每副本 requests 2CPU/2Gi、limits 4CPU/3Gi，初始/最小/最大连接池各20，总常驻池60连接，另为导入/升级留数据库连接余量；必须按目标登录和机器换 token 负载重新压测。原生 JDBC_PING、内嵌集群 mTLS，无新建外部缓存层。

RDS PostgreSQL 必须为独立 `keycloak_prod` database 和同名非 superuser/非 CREATEDB/非 CREATEROLE/非 BYPASSRLS role，禁止复用产品 owner/runtime role。`db-bootstrap.sql` 只用于第一次受审计引导，psql `\password` 私下输入新随机口令，不在 SQL/argv/Terraform state 放口令；`db-verify.sql` 由该登录通过 `sslmode=verify-full` 验证隔离与 TLS。服务配置 `db-tls-mode=verify-server` 和显式 RDS CA，不能只开启加密却跳过服务端身份核对。[数据库 TLS](https://www.keycloak.org/server/db)

跨区 HA 还依赖支持区域故障的同步高可用数据库、三个故障域与低延迟网络；官方要求节点间 RTT 小于10ms，阿里云组合需独立验证。三副本不等于零停机升级、零 RPO 或云厂商 SLA。[单集群 HA 前提](https://www.keycloak.org/high-availability/single-cluster/introduction)

## 3. TLS 入口、管理面与网络

Keycloak 只监听 HTTPS 8443，应用 `hostname` 与 `hostname-admin` 为不同固定 HTTPS origin，`strict=true`；不会自动创建公开 Ingress。管理 health/metrics 9000 不经业务代理。默认关闭 Operator 自动生成的 NetworkPolicy，避免其默认开放 HTTP(S)/management 与自定义规则叠加形成放行；本包使用独立 default-deny 和精确 ingress/egress。[官方网络及 Secret 配置](https://www.keycloak.org/operator/advanced-configuration)

平台入口部署 **HAProxy 3.2.25** 的 `haproxy.cfg`，两个独立 listener：public 8443 只转发应用 realm 和 `/resources/`；admin 9443 只接受显式私网源 CIDR。源地址必须真实保留，不能把公共连接 SNAT 成获准的管理员 IP。两个 ClusterIP Service 分别映射443→8443及443→9443；public LB 只能指向前者，后者只能经企业私网/VPN管理路径。Keycloak 后端 TLS 同时验证 CA 和固定 hostname，前端证书覆盖 public/admin SAN。代理不记录 URI/query、Authorization、Cookie；日志只记录连接来源、前后端、状态、字节和方法。

代理覆盖全部使用的转发头并去除原始 URL、透传 access token 和 tracing 输入；固定 Host 检查及拒绝歧义路径，公共接口不暴露 `/admin/` 或 master realm。`proxy-trusted-addresses` 只包含实际代理 Pod 地址段，Kubernetes 策略还同时要求确切 namespace+Pod labels；namespace 管理员为受信身份，不向租户授予创建代理 Pod、Ingress 或 identity CR 的权限。仅有 hostname-admin **不能隔离管理入口**。[官方反向代理约束](https://www.keycloak.org/server/reverseproxy)、[HAProxy 3.2.25 配置](https://docs.haproxy.org/3.2/configuration.html)

安装器先创建独立代理namespace、无token的SA、只读根文件系统的非root三副本Deployment、不可变ConfigMap、独立TLS Secret、双ClusterIP Service、PDB和默认拒绝NetworkPolicy。公开listener的可达源由 `public_client_cidrs` 显式配置（可有意开放0.0.0.0/0）；admin仍只接受私网CIDR。Deployment只能调度指定三个zone的可信platform节点，探针只检查代理listener，从而不与尚未启动的Keycloak形成循环依赖。所有既有对象先检查managed-by归属与目标spec，漂移拒绝；此路径不强制apply覆盖或自动轮换Secret。创建后的代理前置校验会实际读取 Deployment、Pods、不可变 ConfigMap 和两项 Service：镜像必须与受审阅 digest 一致，配置内容必须逐字匹配，容器必须以固定参数加载配置、无 command/env 覆盖；至少两个已观测 Available/Ready 副本且 PodIP 落在 trusted CIDR，不得 hostNetwork；admin Service 不得为 LB/NodePort 或带 externalIPs。安装后通过显式 CA 实际访问 public discovery/private master discovery，核对 issuer/JWKS；公共 `/admin`、master、编码穿越及伪造 admin Host 必须拒绝。任一步失败安装命令返回非零，不输出身份服务就绪。

官方 HAProxy 镜像 registry 本轮访问超时，因此采用已锁定SHA256的官方3.2.25源码构建镜像：`Dockerfile.proxy` 固定Rust-bookworm构建基镜像和Debian-bookworm运行基镜像，构建时无apt或网络下载；OpenSSL动态库来自同一锁定builder。仅将非rootHAProxy二进制及运行库放入runtime。本机已完成Linux ARM64镜像构建和只读/nonroot/无capability TLS配置检查；生产Linux AMD64镜像仍需CI构建、扫描、SBOM/签名、推送受控仓库并将真实registry digest写入 `proxy.image`，不得拿本机未发布镜像摘要当已存在的生产仓库制品。

```bash
# SOURCE_ARCHIVE 来自 versions.lock.json 中的官方 URL；prepare_proxy.py 先强制校验其 SHA256。
.local/cluster-venv/bin/python deploy/identity/prepare_proxy.py \
  --source-archive /secure/artifacts/haproxy-3.2.25.tar.gz --output .local/identity-proxy-build
docker build --network=none -t sandbox-identity-proxy:verification .local/identity-proxy-build
IDENTITY_PYTHON=.local/cluster-venv/bin/python IDENTITY_PROXY_IMAGE=sandbox-identity-proxy:verification \
  deploy/identity/check-proxy-image.sh
```

发布流水线使用 `docker buildx build --platform linux/amd64`（或已认证的多架构）构建同一context，验证后签名发布。常规构建无需联网生成源文件；基础镜像缓存/预取以及最终registry发布按发布身份办理。本包不会自动发布镜像或创建云LB。

网络只允许：指定代理与 Operator→8443、监控 namespace 与 Operator→9000、Keycloak 同 namespace→7800/57800；DNS 指定 kube-dns；Cilium FQDN 规则仅放 RDS5432、SMTP587、可选 broker token/JWKS 主机443。Operator API egress 只能使用配置的 Service/控制节点地址，须匹配实际 Cilium service translation 行为；不同出口、主机探针、DNS缓存、RDS故障切换地址变化都需实云负测。普通租户没有上述放行。

## 4. 初次安装

1. 使用既有 `deploy/cluster/requirements.lock.txt` 的哈希锁定 Python 环境；准备 locked Kubernetes schema cache（`cluster.py prepare`），运行身份包离线检查。准备受控 RDS、真实 DNS/SMTP、CA/TLS、已构建并审查的代理镜像和双入口LB/私网管理路由。无需预先安装HAProxy，安装器按固定合同创建代理，其readiness只检查listener。
2. 复制 `settings.example.json` 到受限工作目录，填真实 namespace/三个zone/平台标签、RDS/SMTP、代理资源名称和已审阅镜像digest、精确来源CIDR及 API IP。可选 `broker` 需 issuer/authorization_url/token_url/jwks_url/client_id 与独立 Secret。没有默认密码或假 SMTP fallback。
3. 密钥管理器把独立 DB 口令、一次性随机 bootstrap 用户及≥24字节随机口令、SMTP口令、TLS证书私钥、RDS CA投递到指定的绝对文件路径。每个文件0600/0400、非symlink；私钥不写入渲染目录。`proxy_ca_file` 是前端验证CA，`proxy_backend_ca_file` 是代理验证Keycloak后端的CA；安装器从同一受控TLS文件生成代理frontend.pem，私钥只进入对应Kubernetes Secret。安装前验证 TLS 双 SAN、剩余至少7天、证书/私钥匹配、RDS CA有效期；DB身份不得为产品或数据库管理员。
4. 渲染、审核，再执行安装；渲染不联网、不读取秘密，产生 Operator/CRD、Keycloak/PDB、网络策略、首次 realm 和 API 身份合同。示例本身因代理镜像占位故意不可直接安装。

```bash
IDENTITY_PYTHON=.local/cluster-venv/bin/python deploy/identity/check.sh
.local/cluster-venv/bin/python deploy/identity/identity.py render \
  --settings /secure/identity/settings.json --output /secure/review/identity-v1
.local/cluster-venv/bin/python deploy/identity/identity.py install \
  --settings /secure/identity/settings.json --initialize-realm --execute
```

安装身份需要 CRD 和官方 Operator 集群资源权限，只用于这一受控操作，运行 Operator 仅 watch自己的 namespace。工具检查 identity namespace RoleBinding，只接受固定官方绑定，不把租户主体加入其中；集群级 cluster-admin 仍是外部可信根，不能由 namespace 检查证明其不存在。namespace 建立后先装 deny网络策略和 Secret，再启动 Operator/Keycloak。所有 Secret **create-only**：发现已有值不一致拒绝，不能用旧文件悄悄轮换线上密钥。kubectl错误正文不打印，避免服务端回显Secret。

首次 `--initialize-realm` 在私网TLS入口使用一次性bootstrap凭据调用原生Admin API，先读取master realm的attributes，仅补入 `frontendUrl=admin_url` 并保留其他属性。该值已相同则不再写入；已存在不同值则拒绝，要求显式身份URL迁移。没有这个配置，`hostname-admin` 只改变管理页面地址，master的授权/换token/JWKS可能仍指向被公共代理禁止的master路径。常规升级不登录bootstrap账户、不修改master，仅实际验证私网discovery中的issuer、authorization、token与JWKS全部指向私网origin。整个过程不直写Keycloak数据库、不覆盖master用户或其他realm设置。[26.8.0 URL实现](https://github.com/keycloak/keycloak/blob/26.8.0/services/src/main/java/org/keycloak/url/HostnameV2Provider.java)

初次导入用原生 KeycloakRealmImport 的 Secret placeholders 注入 SMTP/broker秘密，完成后删 Import CR/Job。已有 realm 不会被覆盖；后续常规 install不提交realm导入。初次重复或部分失败需要读取实时 realm 状态后继续，不能删除DB强行重来。[官方 realm 导入边界](https://www.keycloak.org/operator/realm-import)

## 5. 人员、机器和 bootstrap 收尾

应用 realm 默认禁止自助注册，启用邮箱验证、密码恢复、14位密码策略、暴力攻击防护、强制OTP；浏览器表单为 Password REQUIRED + OTP REQUIRED，不是默认“已配置才要求OTP”。初次broker只能创建唯一主体，后置MFA继续强制；内置应用realm `admin-cli` 已禁用。初始包不生成默认人员、产品管理员或共享机器客户端。

正式运维管理员需要在 **master realm** 经私网管理入口建立实名账户，配置MFA并验证第二名恢复管理员。应用realm的MFA策略不会自动保护master。完成至少两人真实登录、恢复与审计验证后，在Keycloak里删除一次性bootstrap用户，并撤销其活动session；随后删除/封存密钥管理器中的一次性明文。CR中的bootstrap字段在已有master时无创建作用，升级不会恢复旧用户；需要保留配置Secret作为无权残留输入时仍按秘密管理，禁止以空密码替换造成新的冷启动隐患。恢复管理员只能按官方离线受审计 bootstrap-admin 流程，并确保所有实例停机，不能上线常驻“万能恢复账户”。[官方 bootstrap](https://www.keycloak.org/server/bootstrap-admin-recovery)

机器按一个微服务一个client创建。`machine-client.template.json` 默认采用 Keycloak `private_key_jwt`（`client-jwt` + 经核对的客户端公钥证书），只启用 serviceAccounts；调用者保管私钥，IdP保存公钥，需要把 `jwt.credential.certificate` 占位符替换成客户端 X.509 证书的 DER Base64；Keycloak 不需要出网下载机器JWKS。若企业决定用client secret，需通过IdP原生管理流程生成并保管/轮换，不写产品数据库。API登记其 issuer/sub/client_id，再赋具体项目动作；没有grant的有效token仍不能创建实例。只有浏览器客户端使用Code+PKCE并严格列出回调，不给机器开浏览器或密码直授。

运行只读校验（短期 admin access token 由私网登录取得，写0600文件；工具不负责取密码或发送邮件）：

```bash
.local/cluster-venv/bin/python deploy/identity/verify.py \
  --settings /secure/identity/settings.json \
  --admin-token-file /secure/identity/audit-admin-token --ca-file /secure/identity/frontend-ca.pem
```

它核对应用realm、SMTP配置、OTP执行要求、broker不自动链接、机器客户端不混入人类流程和所有client禁用implicit/password；返回中明确 `interactive_mfa_tested=false`、`email_delivery_tested=false`、`ha_tested=false`。上线还需实际测试用户首次OTP配置、错误OTP、恢复、邮箱验证、邀请/密码恢复邮件及SMTP失败行为；本轮没有向任何真实地址发信。

## 6. 轮换、备份、升级与失败处理

- **证书/DB口令：** 通过密钥管理器建立新版本，先验证SAN/CA/有效期及新DB登录，再以专门轮换操作更新现有Secret；官方Operator约一分钟发现引用变化并滚动更新。检查三个副本的实际TLS/DB连接，不以Secret更新成功当验证成功。原 install拒绝不一致Secret，不是轮换工具。
- **SMTP/broker凭据：** 已存在realm中的配置不随首次导入placeholder Secret变动；必须走Keycloak原生Admin REST/UI更新、验真和审计。禁止重复导入覆盖用户来“轮换”。
- **签名key：** 先发布新JWKS，后切active key，保留旧key直到最大token寿命+偏差结束并通过现有API验证。紧急禁用同时撤产品本地授权；仅删除IdP key不能宣称旧缓存立刻失效。
- **备份恢复：** 使用独立RDS自动备份/PITR、单独保留策略、加密、恢复权限和定期演练；另备份realm配置、TLS/RDS CA、签名/客户端秘密的密钥管理器版本及版本锁。realm JSON导出不等于完整数据库/用户session/凭据备份。恢复先隔离流量，恢复一致的DB和秘密，在同issuer域名验证签名、MFA、机器换token、产品身份绑定后开放。
- **升级：** 先在隔离恢复库升级相同配置，验证schema变化、备份恢复、realm diff和客户端兼容；人工更新Operator/Keycloak同一版本及digest/CRD哈希，审核官方迁移说明。默认 `RecreateOnImageChange`，明确安排维护窗口；不能把原版本镜像直接滚回已升级DB。回滚采用升级前DB快照与对应版本秘密、旧应用版本组合，先恢复演练再执行。升级从不删除CRD/realm/DB或重置账户。
- **故障：** Secret/CA/DNS/代理合同缺失立即拒绝安装；DB故障/证书错/IdP断联时鉴权失败关闭，不能临时关TLS或接受无签名token。副本不足或zone不足保持Pending并告警，不放宽到untrusted节点；RDS恢复必须确认写主身份与TLS。SMTP失败不能跳过邮箱验证/MFA。

## 7. 已验证与发布门槛

本机已通过：19条离线正负测试；37项官方 Kubernetes/Keycloak/Cilium schema检查；真实 OpenSSL SAN/密钥配对；隔离 Keycloak **26.8.0** 原生TLS下实际导入独立/broker realm，Admin REST读回策略，真实 `private_key_jwt` 机器换取符合API audience/scope/300秒期限的access token、重复创建409不覆盖；官方SHA256源码构建的 **HAProxy3.2.25** 真实双跳TLS、private admin成功、public admin/master/路径穿越拒绝、伪造Host/转发头拒绝。另已联合运行真实Keycloak+HAProxy：Console HTML的服务地址、登录form action、master issuer/token/JWKS全部留在私网origin，公共master/admin被拒，原生frontendUrl初始化可重复且不覆盖其他属性。临时Keycloak使用测试专用数据库，不使用共享PostgreSQL，没有邮件/用户邀请/企业IdP外部操作；不能把此结果称为RDS HA或交互MFA验收。

发布仍要求真实环境验证：三个zone落位与故障恢复、数据库主切/连接恢复、负载容量、隔离备份恢复、TLS轮换、从公网来源拒绝private管理listener、直接Pod8443/9000被拒、header与URL变体负测、TLS/CA错误失败关闭、实际MFA/SMTP/恢复、真实机器JWT签名和grant联调、OIDC key轮换及禁用传播上限。缺失任何证据都不应签发本环境的生产发布验收。

2026-10-09 机器身份接入补齐显式 `oidc-sub-mapper`，不依赖默认 basic scope；验收器核对客户端仅分配 `sandbox:access`、无 optional scope、直接 subject mapper 及实际 scope mapper 的完整配置，只允许 Admin 分配的有界 ID 元数据。正常和开发 audience 模板显式固定 Keycloak 导入后的 `userinfo.token.claim=false`、`introspection.token.claim=true`，未知/遗漏/改值仍拒绝。旧开发 token 此前已通过 Rust 验签，因此这是安装合同与漂移防护，不是已证实的旧认证故障修复。

本次27项身份离线测试通过；独立本地 Docker Keycloak26.8.0 使用正常生产配置，实际创建 standalone/broker 两种 realm、`private_key_jwt` 换取机器 access token、经可信测试 TLS 获取 JWKS 并用 OpenSSL 验证签名，核对 `iss/sub` 与 Admin 原生 service-account ID 精确一致，以及 audience/scope/azp/期限和重复创建拒绝。原生通过日志 `.local/account-console-20261009/identity-live-release.log`，首次严格 mapper 差异及非敏感默认值诊断失败另存保留。它未调用企业上游、SMTP或执行交互MFA，不替代生产PKI/RDS/HA验收。


## 2026-10-10 动作 scope 与机器 client 绑定

scope profile 由 API 操作者固定配置，不能由请求或 token 自选。独立 Keycloak
基线使用 `SANDBOX_OIDC_SCOPE_PROFILE=generic-access`：`sandbox:access` 表示接入，
每个动作仍需实时本地 grant。企业 issuer 可选 `action-scopes`，企业示例默认采用
该模式：有效权限为精确 OAuth 动作 scope 与本地实时 grant 的交集，例如
`sandbox:access instances:read` 不允许创建、启停、输出或自动化委派。没有 wildcard
scope 或 group 自动映射；新动作在该模式下缺少同名 scope 即拒绝。不存在开启
`action-scopes` 后拿本地 `*` 绕过 token 上限的行为。

`deploy/api` 正常安装输入的 `oidc.scope_profile` 必填，允许 `generic-access` 或
`action-scopes` 并生成相同 env。`deploy/identity` 外部输入也须显式选择 profile；
生成 auth.json 的 `GENERIC_ACCESS` / `ACTION_SCOPES` 分别对应上述 CLI/env 值。
BFF 在企业模式下须请求经 IdP 批准的具体动作 scopes，最多 64 项，包括 openid 和
sandbox:access；不能借刷新 token 自动扩大权限。

HTTP 身份保留原 issuer/sub/client_id/principal/期限；共享授权入口和输出 I/O 后
新事务核对当前绑定、token 期限以及动作 grant。SERVICE 请求必须匹配注册 client_id；
USER 不登记 SERVICE client_id，仍允许同一用户通过批准的不同登录客户端请求。

自动化创建须同时满足 token 对 automations:write 和所有委派动作的上限，记录精确
允许动作及 SERVICE 绑定 generation，不保存 bearer/refresh token。持久委派使用
独立明确的 expires_at 和实时 grant/身份检查，可按已授权计划跨越短期 access-token
期限；token 过期不扩大或延长已记录的动作集合。client 绑定改变后旧委派永久失效。
历史 SERVICE 身份升级和安全轮换必须按 [机器身份 owner 迁移步骤](service-clients.md)
完成；0038 仍永久保留，本变更是正常正式迁移 0040。
