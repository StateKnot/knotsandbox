# 控制台开发与生产交付

2026-10-11新增：账户与授权页提供独立租户账户审计，无需项目选择，显式读取后分页；当前撤权与异租户／非NULL项目响应清空、迟到响应拒绝已测。见[账户审计](tenant-audit.md)。备份页仅在当前项目明确 `backup_restore=true` 时查询／提交；false、缺失或畸形能力不发送工作区或备份请求，开启时仍保持原404权限语义。新增9项编译Chrome HTTP合同通过，完整构建与格式检查通过；这些测试不替代真实OIDC/BFF全链和实云备份验收。

`console/` 是独立静态控制台，可与产品 API 同源组合部署。生产只使用 HTTPS，浏览器不能配置其他 API base URL，不持有 OAuth access/refresh token，不读会话 cookie。它读取 `/auth/session` 的租户、主体和 CSRF 值，CSRF 只保留在内存。独立或企业登录方式由服务端 BFF issuer 配置决定，详见 [浏览器身份方案](browser-bff.md)。未启用 BFF 时，控制台不能用机器 token 代替登录。

页面对接正式 OpenAPI 契约，包含实例列表与详情、启动/停止/重启/删除/续期、工作区独立删除、真实指标、执行提交/强制取消/验证输出分页、操作/事件/审计历史、控制面诊断、有限定时与事件自动化管理、冷备份、文件上传/下载、部署能力查询与请求核对。模板版本、已批准安全策略、备份配置和项目 ID 目前由管理员提供；对应枚举端点尚未提供，页面不伪造选项。没有可用 API 的终端与恢复不显示可执行按钮。定时和事件自动化仅按正式能力、当前授权及有限委派开放。

`202` 只显示“已受理”。操作是否成功须查询操作、资源观测和可信终止状态。指标 `STALE`/`MISSING` 不补零，持续健康 `UNKNOWN` 不显示健康绿灯。诊断与备份 ID 可单独查询，底层失败和权限撤销以服务端响应为准。403 不表示产品数据为空，页面保留明确错误；401 会清除当前页面资源并进入重新登录。

控制面诊断由 `control_plane_diagnoses` 能力开启，完整运行健康能力仍关闭。实例页默认只请求实例证据，报告直接 GET 查询进度，不要求读取 Operation；按原截止时间及60次上限自动刷新，终态/失败/截止后只允许显式读取同一报告。结构化展示规则、证据来源/时间/期限、UNKNOWN/REDACTED 和历史启动代；撤权后清除内容。“请求记录”可以重新打开已受理报告；未知创建仍沿原 body/键显式重放。见 [诊断语义与授权](diagnostics.md)。

## 定时与自动化管理

实例页支持有限7动作/3触发器预览和UUID确认，以及按真实ETag暂停、恢复与永久撤销；能力开启不授予权限。运行视图只显示当前作用域元数据，SUBMITTED不表示完成，OUTCOME_UNKNOWN只可核对原运行；暂停不取消已受理操作。授权撤销、作用域变化及非法/成功空能力响应清空旧明细、草稿和内存参数。未知创建须恢复相同原JSON并显式重放原键，不生成替代请求。

本批59单测、8Chrome HTTP合同及真实Chrome/Keycloak/BFF/API/PG完整管理链通过，原生arm64候选 `sha256:8348e298b2810ea24c3b5f384b99e3160d68e08a617d8a69feba09422797da86` 的非root/只读TLS检查另列。真实管理只创建未来单次RENEW，未运行自动化调度器；独立Nginx传输夹具不认证生产身份/TLS组合、实云、HA或签名发布。源码摘要和完整记录见[当前验收](development.md#自动化控制台真实管理验收)。

## 实时事件提示

历史页的事件模式保留正常分页，另提供“开启实时提示”的明确操作。实时连接使用同源 BFF cookie GET，浏览器不保存或发送 bearer，不借健康/通知能力标志授予访问；服务端检查当前项目的 `events:read`。首个 checkpoint 建立基线，独立面板只保留当前页面内存中的断点和最近50条去重元数据，展示观察时间与连接状态，不自动刷新或管理业务资源。快照查询失败或普通刷新不影响断点，也不触发连接。

连接头等待10秒、单次读进展等待45秒、单连接总期限300秒。停止、EOF、网络故障或到期后，明确“从原断点重连”沿用原游标；400/409/410清除旧游标及缓存，只能明确“重建实时基线”。权限拒绝清除证据，401重新登录；租户、主体、项目、实例、记录类型切换和退出取消并清空。页面重载不保留实时游标，实时缓存不替代完整历史。此功能不启用 webhook、通知或未完成的健康能力，详见[事件流合同](event-stream.md#控制台实时提示)。

此前事件控制台检查点47项控制台单测、61项SDK测试和5项Chrome HTTP合同通过。750文件不可变源 `682dc562cbdd5289be6a31870dc0ae9f7a6dabe9caaaa5fd39e16b5516fef2b2` 下，真实 Chrome/Keycloak/BFF/API/PostgreSQL/正常 worker 完整链1/1通过（测试运行18.65秒，含编译命令158.711秒），记录 `.local/evidence/console-events/1791545305718527000/record.json`。真实 CSRF 诊断受理产生事件，停止保留原游标，正常 worker 完成后按原 Last-Event-ID 补读；真实 events:read 撤销清空提示，恢复授权不会自动连接，只有显式重建建立最新基线。事件位置/审计唯一，完整实例/工作区/活动执行事实不变，原账户/诊断/停止撤权链保留。 从正式 stage_context 的22文件最小上下文构建当前 arm64 候选镜像 `sha256:30d822081570ca071b098918ce9af23a0e0d3c516979c74f23e458d2ff659a74`，非root/只读、TLS/CA/SAN/SNI正负检查及原生Nginx在上游未结束前送达checkpoint、显式释放后送达后续事件均通过；记录 `.local/events-console-20261009/native-final.json`。该原生代理测试采用明确 TLS 上游夹具，与上述真实 BFF/API 事件链分别取证，不证明两者组合后的生产PKI或云入口。 首轮实际链因新增验收SELECT多一个右括号失败；仅删除这一字符后重跑，生产代码、断言及期限保持，失败与差异收据保留。首轮离线镜像构建因缺npm缓存/DNS失败；相同上下文按原锁文件联网安装后构建通过，原失败保留。 G3-04/G3-10仍开发中：webhook/通知、生产身份/TLS、云入口慢消费者、实云Kata/CSI、HA/容量与统一签名发布安全门尚未完成。

## 自动化异常通知

项目导航提供异常收件箱，使用正常能力 `api_features.automation_notifications` 和当前项目权限。可显式刷新、按实例筛选、分页、读取历史来源，并输入通知 ID 确认已阅；确认不恢复或重新执行任务。UNKNOWN 原键/空对象/旧 ETag 保留在请求记录，资源已显示已阅仍不能替代原请求回执；撤权清除旧视图，恢复权限后须显式原键重放。

2026-10-11 的791文件候选下，真实 Chrome/Keycloak/BFF/API/TLS PostgreSQL 完整管理链1/1通过（25.68秒）：专用 coordinator 真实 FAILED 来源、ACK 提交后回执丢失、重载、当前写/读撤权、完全相同回执重放、唯一审计/事件和完整业务事实不变，最后 STOP 使用 UI 实际 `/details` 新版本。原账户、诊断、事件、未来策略和最终撤权回归保留。源码、二进制、实际静态构建文件及0600事实报告绑定；必跑CI采用专属临时TLS数据库，远端CI尚未执行。没有认证生产身份/PKI/Nginx组合、企业MFA/联邦、云隔离、HA、容量或签名发布。见[完整证据与失败记录](../research/automation-notification-bff-20261011.md)。

## 请求、文件与浏览器边界

普通管理写请求在发起 HTTP 前把原始 body、ETag、幂等键及租户/主体写入同源共享的 `localStorage`；自动化创建仅持久保存摘要和核对依据，原参数限当前身份/CSRF内存，重载后须相同原JSON摘要校验和显式原键确认；不保存 cookie、CSRF 或 OAuth 凭证。argv 只允许明确非敏感参数，不能输入秘密。浏览器存储或原生 Web Locks 不可用则写请求不发送。同源 Web Lock 内重新读取台账后创建/更新，锁贯穿一次 HTTP，多个标签页不能以旧缓存绕过未知请求或同时重放同一个键；忙锁立即拒绝，不把重叠调用排队为丢失回执后的隐式重试。创建前复制原 body，调用方后续修改不会改变已记录请求；ACK 与本地保存错误分开处理，迟到失败不能把已保存受理回执降为未知。新请求先持久化为 `READY`，HTTP 前持久化为 `PENDING`，崩溃遗留 PENDING 按可能已派发处理。只有首次 READY 尝试获得确定未受理的 4xx 才标拒绝；幂等冲突/过期保守保留 UNKNOWN。已尝试请求的再次 401/403/404/409 或 CSRF 拒绝不能证明原请求没有提交，必须保留原 body/key/ETag 并阻止新键。断网或模糊 5xx 标为 `UNKNOWN`，恢复页面后沿用同一个键，禁止同一路径直接生成新请求绕过待核对结果。只有用户显式选择“重试原请求”才重发原 body/ETag/键。已受理操作 ID 保留作查询依据，已受理/明确拒绝的 body 清空；UNKNOWN 的原 body 持续保留作原键回放，可能包含非敏感 argv 与文件路径等本地业务信息。清除浏览器存储后必须先由管理员核对服务端记录，不得生成新请求重复执行。记录上限 40 个，未核对请求达到 20 个则必须先处理；不删除未核对请求腾出位置。浏览器记录用于恢复同源标签页操作，不取代服务端审计与幂等台账。客户端 actor 检查只用于防止本页面缓存混用；服务端使用当前 cookie 会话及绑定 CSRF 哈希做真实身份/权限验证，跨标签页换登录时旧 CSRF 的写请求会被拒绝。

JSON 单次请求 20 秒、64 KiB 请求体和 4 MiB 响应体，不重试写入，禁止重定向、Cookie 与 bearer 混用、跨 origin/tenant 目标。退出会取消全部本地读请求和文件流；后端独立撤销周期也覆盖 SSE 和二进制流。

文件限制 100 MiB，每片最多 1 MiB。上传先核对完整文件 SHA-256，再逐片核对服务端 receipt。任何失败不会自动重传；通过明确的传输 ID、版本和相同文件摘要继续时才允许显式重传同一个不可变分片。空文件直接提交清单。浏览器负责生成 Content-Length，代码不能设置浏览器禁止的该请求头。下载须 `SUCCEEDED/FROZEN`，并同时核对快照版本、Content-Length、SHA 头和完整实际内容摘要。校验失败不创建下载链接。输出只按文本显示，终端控制序列和 HTML 不执行，页面最多保留最近 1 MiB 文本。

## 账户与微服务授权

“账户与授权”入口管理本产品的租户机器主体和项目权限。机器客户端列表不要求选择项目，须有当前租户范围的 `service_clients:read`；登记、改名和启停须 `service_clients:write`。项目授权列表须 `grants:read`，创建、修改和撤销须 `grants:write` 及所委派操作本身的权限。服务端限制委派期限为这两项当前权限的交集，不允许通过页面提升权限。

接入一个微服务时，先在独立 Keycloak 或企业 IdP 创建专用 OAuth 客户端，将凭据保存在微服务的 secret manager 中。取得该服务账户稳定的 `(issuer, sub)` 后在页面登记；`sub` 不能用邮箱、客户端名称或 secret 代替，issuer 必须是部署信任的那个。登记只建立产品身份和租户成员关系，不生成 token、不创建 IdP 账户，也不自动授予项目权限。再选择目标项目，用登记返回的主体 UUID 创建需要的具体操作授权。微服务通过现有 OAuth 流程取得 API audience/scope 的短期 access token，以 bearer 和 `X-Tenant-ID` 调用 API；网络允许访问不等于拥有业务权限。

编辑从独立详情 GET 取得 ETag，提交使用这个编辑版本；412 时先核对最新详情，再明确创建新的修改。客户端启停不改变 IdP/global 身份：禁用立即阻断本租户的旧 token 权限，其他租户保持各自状态；重新启用仍需满足当前委派权限，只恢复仍有效的授权。授权 DELETE 保留历史记录并撤销权限，无请求体。任何未知结果都在“请求记录”中沿用原方法、键、body 和 ETag 重试，不生成替代请求。

未确认的账户操作会在本机浏览器保存 issuer、subject、名称和授权内容，用于恢复原请求；成功或确定拒绝后清除 body。页面不接受或保存 OAuth 密钥和 token。应使用受控浏览器处理这些身份资料，未核对结果先查服务端审计再清除浏览器存储。

## 构建和验证

依赖按精确版本和 npm integrity 锁定，Node `24.19.0`，React `19.3.0`，Vite `8.3.3`。构建方式参照 [Vite 官方生产构建说明](https://vite.dev/guide/build)。

```sh
npm --prefix console ci --ignore-scripts --no-audit --no-fund
npm --prefix console run format:check
npm --prefix console run build
npm --prefix console test
PLAYWRIGHT_BROWSERS_PATH="$PWD/.local/playwright" npm --prefix console exec -- playwright install chromium
PLAYWRIGHT_BROWSERS_PATH="$PWD/.local/playwright" npm --prefix console run test:browser
python3 -m unittest discover -s deploy/console/tests -v
```

本地已安装 Chrome 可设置 `SANDBOX_TEST_CHROME` 为其绝对可执行路径，测试代码会启动独立浏览器实例。`vite preview` 仅用于本地/CI 验证，不是生产服务。当前 Chrome UI 测试使用明确的 HTTP 契约替身来验证渲染、CSRF、确认、退出、未知状态与禁用能力，不宣称真实 IdP/云端运行验收。真实 PG + 签名 OIDC HTTP BFF 测试另见 `src/bff_tests.rs`，正常迁移 0037 后运行；不能用 UI 替身替代该证据。

2026-10-08 另执行真实 Chrome → 当前编译控制台 → 正式迁移 0037 的 Rust BFF/API → 本地真实 Keycloak/PostgreSQL，1/1、10.34 秒，记录 `.local/bff-keycloak-browser-live-20261008.log`。无 HTTP/身份 mock，生产 browser client renderer 固定 subject mapper；覆盖跨 site 登录、真实停止受理、grant 撤销、membership 禁用和浏览器不保存 bearer。测试 HTTPS 入口使用公开 fixture，Chrome 显式忽略 fixture 证书错误，IdP 后端用回环 test transport；它不验证生产 CA/SAN、MFA/企业联邦、云 HA，也不包含生产 Nginx。下述真实 Nginx→TLS transport fixture 的严格 CA/SAN/SNI 正负验证属于另一项证据。

## 本地真实账户与授权验收

`src/bff_live_tests.rs` 的 `bff::live_tests::real_keycloak_chrome_console_bff_and_api_enforce_live_revocation` 使用真实 Chrome、当前 `console/dist`、本地 Keycloak、正式 BFF/API 与 PostgreSQL。它通过界面登记机器身份、管理项目授权，用真实签名 token 验证启停/撤销效果，并在一个实际已提交 PATCH 后丢失浏览器回执，再从重载后的请求记录重放原键、body 和 ETag；不制造 HTTP 成功结果。

执行前构建控制台，显式设置本次审阅的 canonical 绝对源码根目录 `SANDBOX_TEST_SOURCE_ROOT`、Node 24 绝对可执行路径 `SANDBOX_TEST_NODE`、Chrome 绝对可执行路径 `SANDBOX_TEST_CHROME`。还需现有 literal-loopback Keycloak 的 issuer/管理凭据、独立新 `_test` PostgreSQL 库及分离的迁移 owner/API 最小权限登录。由受审启动器读取受保护输入并向子进程注入私密值，不 `source .local/dev.env`、打印环境或在命令行放凭据。完整输入及精确命令见 [本地开发验收](development.md#真实账户控制台专项)。

2026-10-09 最终源码 `51f7dda624fc5c116482f4e76801be89cdaeffc4bdb99d8f693be30c127da574` 在全新本地 Docker 数据库下，5 项机器身份、4 项项目授权和 1 项真实浏览器全链全部通过，记录 `.local/evidence/accounts/1791535700763985000/record.json`。控制台 32 项单测、2 项 Chrome 合同回归及严格 Clippy/fmt 通过；Chrome 合同使用显式 HTTP fixture，与上述真实全链分别记录。先前缺 Node 输入、缓存源码路径、字段可访问名称、旧提示断言及身份配置默认值差异的失败记录保留。随后只补验收文档。公开用途 TLS fixture、Chrome 忽略 fixture 证书错误和回环 IdP transport 只用于本地测试；不覆盖生产 CA/SAN/Nginx、企业登录/MFA、Kubernetes/Kata/CSI、实云、HA 发布或数据库容量认证。

诊断验收扩展复用上述真实浏览器链与独立 worker 登录，不写入伪造报告。2026-10-09 的747文件源 `d15d90759dc79dc149160c805afd6174b554cf4baaabe00d6c3f0eb674ab2bfc` 两次完整浏览器链1/1通过（5.79/5.24秒测试运行）；包含原账户/停止/撤权链和新诊断回执故障、正常 worker 发布、无操作读取权限、真实诊断读取撤权及恢复。控制台32项单测与4项 Chrome HTTP合同通过；迟到响应合同在修复前确实失败，修复后通过，不通过延长截止掩盖。记录 `.local/evidence/health/1791542835360872000/record.json`、`.local/evidence/health/1791542898336747000/record.json` 和 `.local/health-console-20261009/final.json`。另一次实际浏览器 Error 失败保留且根因未确认；固定阶段诊断后两次同源码通过不等同于确认修复。测试 TLS/IdP 和云部署边界与前段一致。


## 同源 TLS 与只读镜像

[部署 Dockerfile](../deploy/console/Dockerfile) 使用官方 OCI digest 固定 Node 构建镜像和 NGINX nonroot Slim 镜像；摘要记录在 [版本锁](../deploy/console/versions.lock.json)。NGINX 选择 [官方当前稳定安全修复版本](https://nginx.org/en/download.html) 1.30.5，固定官方签名的 `zlib 1.3.2-r1` 安全更新由 [补丁锁](../scripts/release/console-security.lock.json) 管理，下载 SHA、签名和实际安装版本都要验证，详见 [发布流程](release.md)。镜像运行 UID/GID 101，只读根目录，仅 `/tmp` 是 32 MiB tmpfs。TLS 私钥来自独立 Secret 只读挂载，不进入镜像。副本数 2，固定 platform 节点池并跨节点分布；HTTPS health probe 带准确公共 Host；PDB 保留 1 个可用副本，运行身份不挂载 Kubernetes token。

```sh
docker build --file deploy/console/Dockerfile --build-arg SANDBOX_CONSOLE_FIRST_RELEASE=true --tag sandbox-console:reviewed .
python3 deploy/console/render.py \
  --public-origin "$REVIEWED_CONSOLE_HTTPS_ORIGIN" \
  --api-upstream sandbox-api.sandbox-system.svc.cluster.local:8443 \
  --api-ca-file "$REVIEWED_API_CA_FILE" \
  --image "$VERIFIED_CONSOLE_IMAGE_REF" \
  --namespace sandbox-system --tls-secret "$VERSIONED_CONSOLE_TLS_SECRET" \
  --ingress-cidr "$REVIEWED_INGRESS_CIDR" > "$NEW_CONSOLE_MANIFEST_FILE"
```

渲染器不会创建云资源、上传镜像或 apply。以上变量必须已绑定操作者真实审阅的输入；镜像引用必须是已独立核验的完整 registry/repository@sha256 digest，格式正确不能代替验签。入口 CIDR 必须对应 LB/入口实际保留的源地址，IPv4 不得宽于 /24、IPv6 不得宽于 /64；也可用一个或多个 `--ingress-proxy namespace/app` 精确允许受审入口 Pod，至少一种入口必填。安装器把清单接入已有集群、独立控制平面 API Service 与已签发给**完全相同 hostname**的 TLS Secret，再让公有云 LB 的 443 TCP/TLS 透传到该 `ClusterIP` 服务的 443。禁止将 8443 明文 HTTP 对公网开放，禁止用关闭证书验证来连接代理。API 集群内 upstream 是固定 Service，强制 HTTPS；`proxy_ssl_verify on` 用独立、只读、版本化 immutable ConfigMap 的 CA 验证证书链，SNI/验证名称固定为同一个 Service DNS，TLS 1.2/1.3，无明文后备或 skip-verify。CA 轮换与配置均触发 Deployment 更新；不使用浏览器输入或 URL 参数选目标；应用权限边界仍在 BFF/API。部署网络策略仅允许入口 LB/控制面访问 console，console 只可访问明确 API Service 与集群 DNS；禁止沙箱工作负载直达 API/数据库。具体 LB、DNS、Secret 和网络策略由主产品安装器根据真实云/VPC 参数组合；本模块不猜测账号、域名和证书。

console 使用 `console-v1` 网络标签；实际 bootstrap CCNP 必须排除该组件。安装激活前先对经过验签、审阅的清单运行 [共享网络配置门禁](policy-boundary.md)，发现重叠宽允许就停止。它读取实际 Pod/CiliumEndpoint identity 和全部 CNP/CCNP/KNP，报告 `configuration_overlap: PASS` 仍带 `runtime_enforcement: NOT_VERIFIED`；随后还须单独做实际入口/API允许与 metadata、IdP、其他服务拒绝的数据包验收，不能把 desired CNP 或 schema 通过称为隔离认证。

```sh
.local/cluster-venv/bin/python deploy/policy_boundary.py \
  --manifest "$NEW_CONSOLE_MANIFEST_FILE" \
  --kubeconfig "$SCOPED_READ_ONLY_KUBECONFIG" \
  --context "$EXPLICIT_PRODUCTION_CONTEXT" \
  --out "$NEW_CONSOLE_POLICY_REPORT_FILE"
```

代理只开放 `/`、内容哈希 `/assets/`、四个 `/auth/` 路由与 `/v1/`。固定 Host 拒绝其他主机，TLS 1.2/1.3，CSP 只允许同源脚本、样式、连接，拒绝 frame/object/base 与外站表单。JSON body 64 KiB，上传片 1 MiB；SSE/文件不缓冲，代理不会重试已可能写入的请求。访问日志只记录 method、路径（不含 query）、状态与后端 request ID；不会记录 code/state、cookie、token、CSRF 和 body。NGINX 原始 error log 不能自定义清除 query，故关闭该流，排障使用安全 access status 与 API request ID。安装必须核对 LB、CDN、WAF 的独立日志同样不记录回调 query。

`index.html` 和 API `no-store`，哈希 assets `immutable`。首次发布显式设置 `SANDBOX_CONSOLE_FIRST_RELEASE=true`，且 prior manifest 必须为空。后续发布默认 false；正式 release job 按指定前一 tag/commit 验签后，从经过完整校验的前版 console OCI 提取 `assets/` 和 `bundle-manifest.json` 到独立临时 context；本地手动 build 使用的 `console/release-assets/` 目录不构成正式发布信任输入，构建脚本核对全部 SHA-256 后合并新旧内容哈希文件。缺少前一 manifest、摘要不匹配、符号链接或相同哈希文件名内容冲突都会使构建失败。保留至少 24 小时及回滚所需资产，当前构建上限 200 个文件/40 MiB；正式流程保守保留前版全部资产及其 npm 库存，达到界限就拒绝，须完成受审资产保留政策调整才能改变该规则。这样滚动发布的新副本仍可响应旧 HTML 所引用的资产。当前 bundle 无延迟加载和 source map。运行镜像另保留 npm package.json/package-lock.json 到 `/usr/share/sandbox-console/` 供发布 SBOM/scanner 枚举，路径不在 HTTP public root；正式 release pipeline 与其他产品镜像一起扫描、审查、签名及验证 digest；完整 npm 与 retained 库存对照镜像图层逐项核对，详见 [发布流程](release.md)。TLS 轮换使用新的版本化 Secret 名字并重新渲染 Deployment，触发滚动加载新证书；仅原地更新 Secret 不会让 NGINX 自动重载。证书签发与到期监控由安装器的证书流程承担。 正式 stage_context、Docker COPY及.dockerignore均包含共享SDK的 schema/event-message/events/sse/transport 五源；新构建不依赖宿主 dist 或秘密文件。源码闭包检查不替代制品扫描、验签或云验收。

本地镜像真实验证使用 `deploy/console/check_image.py --image sha256:本地镜像ID`。脚本创建唯一命名的本地 bridge 和测试容器，端口仅绑定 127.0.0.1；以临时生成的公开用途证书，验证浏览器入口 TLS/Host/CSP/no-store/404、UID101/只读运行，并实际测试 Nginx→HTTPS transport fixture：受信任 CA 与正确 Service SAN/SNI 成功，错误 CA、错误 SAN 和明文上游均返回 502。这些测试使用明确标记的传输 fixture，不替代真实 Rust API/IdP 验收。所有测试资源完成后清理；测试证书不代表公网签发或生产证书。生产验收仍需真实 HTTPS origin 上的人工/自动化 IdP 登录、MFA/企业联邦策略、实际租户权限、CSRF负例、长流撤销、云运行/对象存储和 HA 发布回滚。缺少真实云环境不能宣称这些已完成。

2026-10-08 已对本地不可变 console 镜像 `sha256:574604b8da8ce3189739679771c8510538f1d847a18203956c8ac4267070b7f5` 实际执行上述上游 TLS 正负测试，记录在 `.local/console-api-tls-image-check.log`。此前静态入口 TLS 证据仅覆盖浏览器→Nginx，不能证明 Nginx→API 的 TLS；本次新证据仍不是统一签名发布或云验收。
