# Rust API 生产安装

`deploy/api` 提供独立 API 服务的生产清单，供其他微服务通过 HTTPS + bearer 调用，也可以启用 BFF 后与控制台组合。API 自身终止 TLS，不需要给 API 加 Nginx 代理。安装目标固定为 `sandbox-system` namespace、`sandbox-api` Service、8443 TLS 端口和 `sandbox-api.sandbox-system.svc.cluster.local` SAN；控制台使用完全相同的 upstream 与独立 API CA。当前部署基线是阿里云私网 PostgreSQL、私网 OSS、HTTPS IdP、HTTPS 指标查询端点和 Kubernetes/Cilium。此目录不 apply、创建 Secret、签发证书或上传镜像。

## 安装输入与发布信任

先按 [发布流程](release.md) 独立核验统一 release manifest、签名和安全扫描有效期，再把经过核验的 **service** OCI digest 放入设置中的 `image`。digest 格式正确只证明内容寻址，渲染器不替代发布验签。init 和 STS sidecar 与主 API 使用同一个 digest；候选必须确实包含 `sandboxd secrets-init` 与 `sandbox-credentials`，旧版本镜像不能提供新增能力。未知字段、重复 JSON key、超过 256 KiB 的输入、tag 镜像及 draft restore/automation 配置均拒绝。

`prepare.py` 输入两个私下审阅的 JSON 文件：非秘密 `settings` 和实际 `terraform output -json`。它从 outputs 绑定 deployment、平台节点可用区、RDS endpoint、OSS buckets/KMS、三个 API RAM roles；不会根据示例猜测云资源。outputs 必须来自同一次已审阅的基础设施实例。平台池至少两个可用区，实际独立主机数至少 `replicas + 1`，还须满足 surge 副本在各区 `maxSkew=1` 的实际容量；多余主机集中在一个区也会拒绝，以避免 hostname anti-affinity 与零不可用滚动更新死锁。控制平面节点不作为 API 调度容量。

| settings 字段 | 必须提供的值 |
| --- | --- |
| `schema_version`, `namespace`, `service_name` | `1`、`sandbox-system`、`sandbox-api` |
| `image`, `replicas` | 已核验 registry/repository@sha256 digest，整数 2–8 |
| `tls` | `secret_name`、Secret 中的 `certificate_key` / `private_key_key`、独立公开 `ca_pem` |
| `cursor_secret` | 精确 `{"name":"版本化Secret名","key":"键名"}` 引用 |
| `database` | `secret` URL 引用、公开 `ca_pem`；host/port 从真实 RDS output 取得 |
| `oidc` | HTTPS `issuer`、`jwks_url`、`audience`、`required_scope`、显式 `scope_profile`（generic-access/action-scopes） |
| `browser` | `null` 或固定 `public_origin`、`authorization_url`、`token_url`、`client_id`、`scopes`、独立 `client_secret` / `session_key_secret` 引用 |
| `metrics` | `null` 或 HTTPS `endpoint`、`ca_pem`、两个明确 HA `replicas` 标签、`auth`；auth 为 BEARER + `token_secret`，或 BASIC + 独立 `username_secret` / `password_secret` |
| `storage_enabled`, `max_file_bytes` | 明确布尔值；启用时整数 1–104857600，停用时 `null` |
| `callers` | 1–16 个允许的机器调用方，每个为精确 `namespace` + `app_name` Pod 标签；禁止沙箱 runtime namespace |
| `default_ttl_seconds`, `max_ttl_seconds` | 整数 60–604800，默认不超过最大值 |
| `db_max_connections` | 每 API 副本整数 1–200，须纳入 RDS 全角色连接预算 |

`browser`、`metrics` 即使关闭也必须显式写 `null`。启用浏览器模式必须按 [BFF 身份方案](browser-bff.md) 配置 confidential Code + PKCE 客户端、subject mapper、产品 `(issuer, sub)` identity 和 USER membership。独立身份使用本产品 Keycloak，企业身份可对接等价 issuer；浏览器只拿 opaque cookie，不接触 OAuth token。机器 caller 的网络允许标签不授予业务权限，仍需有效 JWT、本地主体映射和项目 grant。

正常 API 的自动化异常收件箱需要正式迁移 0042 和同版本
`automation-role.sql` 的最小权限；安装检查不通过时服务不绑定监听端口。
先迁移及安装权限，再更新 API/SDK/控制台。微服务使用现有 OIDC 调用
分页、详情和幂等确认接口，具体升级顺序和错误处理见
[自动化异常收件箱](automation-notifications.md)。

文件/输出组合使用实际 outputs 中的 `file-upload`、`file-reader`、`output-reader` 三个不同 RAM role，由 API ServiceAccount 的精确 subject 换取短期凭证。API 不挂载 gateway 或 cleanup role，不获得备份对象读写角色。文件与输出 buckets 独立；STS daemon 在发布完整新凭证前核验 identity、scope、region、时间和私有文件，主服务只读对应内存卷，详见 [存储凭证](storage-credentials.md)。关闭组合不声明文件能力可用。

以下变量指向操作者已有的真实文件，不包含 Secret 值；输出文件必须尚不存在。

```sh
python3 deploy/api/prepare.py \
  --settings "$API_SETTINGS_FILE" \
  --terraform-output "$REVIEWED_TERRAFORM_OUTPUT_FILE" \
  --output "$NEW_API_INPUT_FILE"
python3 deploy/api/render.py --inputs "$NEW_API_INPUT_FILE" --output "$NEW_API_MANIFEST_FILE"
```

## 私有文件与证书

TLS、cursor、DB、BFF client、BFF session 和 metrics 凭证分别使用不同的版本化 Secret。清单只引用 Secret 名字和键，不把凭证写入 ConfigMap、Terraform state 或生成输出。公开 API/DB/metrics CA 和非秘密 runtime config 分别生成内容寻址的 immutable ConfigMap，改动会触发 Deployment 更新。

Pod 固定 UID/GID/fsGroup `10001`、只读 root、drop ALL capabilities、RuntimeDefault、无自动 Kubernetes token。API TLS Secret root-owned `0440` 且 group 为 API 主 GID，直接只读挂载；leaf 与必要中间证书按顺序组成 PEM，必须覆盖固定 Service SAN，权限/日期/链/私钥匹配校验见 [API TLS](api-tls.md)。API CA 同时供 console 上游验证；标准 Kubernetes HTTPS probe 不校验客户端 CA，不能用 probe 通过证明证书可信。

严格 `0400` / `0600` 的 cursor/BFF/metrics 文件由同一 service 镜像的窄命令初始化：

```text
/usr/local/bin/sandboxd secrets-init --profile browser --metrics-auth bearer
```

renderer 按启用功能固定选择 `browser|bearer` 与 `none|bearer|basic`。该命令在 Config、日志、数据库连接之前执行，拒绝未知参数，要求真实 UID/GID10001；不依赖镜像中的 shell、cp、chmod、chown。它只读 `/var/run/api-secret-source` 的固定文件清单，先验证全部来源的类型、权限和大小，再在 `/run/api-private` 的 1 MiB memory emptyDir 中创建 UID10001 / mode0600 文件并 fsync、原子发布整组 `private/`。已有完整相同组可幂等通过；差异或非预期文件拒绝，不覆盖可能已被主服务使用的文件。主 API 只读该内存卷。cursor、session keyring 格式与轮换分别遵循历史游标和 BFF 协议；初始化不生成、解释或打印密钥。

DB Secret 的 URL 必须私下核对为实际 RDS host/5432、API 窄数据库 role、`sslmode=verify-full&sslrootcert=/run/api-trust/db-ca.pem`，可选唯一规范 `application_name`。用户、口令等 URL 分量必须正确 percent-encode。渲染器只读取 Secret 引用，不读取 URL 值，不能替操作者完成这项核对。所有 runtime Config 在连接前拒绝无 TLS、重复/未知 query、host 覆盖、非绝对 CA；实际 SQLx 继续验证证书/SAN。正式 migration 0001–0037 与角色脚本必须已按顺序应用，API 不在启动时自动迁移。BFF/file 配置缺字段、私有文件不可读、对应正式 schema 不存在会启动失败，不能“先启动再补”。

Secret/CA/客户端 key 轮换用新的版本化名字重新准备/渲染并执行经审阅的滚动更新。TLS 每秒验证已加载证书，接近到期共享取消 token 立即拒绝新业务并在 30 秒内退出；Deployment 35 秒 grace 保留退出窗口。SSE/输出/文件同用取消原语。替换原 Secret 的内容不会触发热加载，不能充当正式轮换流程。

## 网络与激活门禁

API 调度至实际 platform 节点池并跨可用区、跨 hostname；readiness/liveness/startup 均为真实 HTTPS 路径，PDB 保留 `replicas - 1`。专用 CNP 选中 `api-v1` 标签，仅允许已审阅 console/caller 的 8443 ingress、host probes、明确 DNS 和 DB/IdP/metrics/OSS/STS HTTPS 目标。没有 metadata、整 service CIDR、通用 world egress 或 Kubernetes API 允许。基线外部依赖使用 exact FQDN；不能把内部 Pod 域名塞进外部 FQDN 设置来代替经审阅的 Pod identity 策略。

安装器必须先核验实际 cluster bootstrap CCNP 已排除带 `sandbox.platform/network-policy` 的组件，然后在激活前执行共享只读检查。它会核对实际 Pod/CiliumEndpoint identities 和全部策略，不接受另一个重叠宽允许。输入必须是已经验签、审阅的安装清单，kubeconfig 为直接受限只读凭据且保留 HTTPS 验证。

```sh
.local/cluster-venv/bin/python deploy/policy_boundary.py \
  --manifest "$NEW_API_MANIFEST_FILE" \
  --kubeconfig "$SCOPED_READ_ONLY_KUBECONFIG" \
  --context "$EXPLICIT_PRODUCTION_CONTEXT" \
  --out "$NEW_API_POLICY_REPORT_FILE"
```

只有 `configuration_overlap: PASS` 才可继续数据平面验收；报告中的 `runtime_enforcement: NOT_VERIFIED` 必须保持其原意。随后须从实际允许/禁止的 Pod 身份做真实 HTTPS、第一包、metadata、跨租户、旁路、重启和发布期间拒绝测试，并持续检测策略漂移，详见 [共享策略门禁](policy-boundary.md)。API/console 任一组件单独 CNP 的 desired spec 不能证明实际隔离。

最终还必须有真实云证书链/SAN、OIDC 机器及浏览器授权、MFA/联邦、实时禁用与 CSRF、PG 最小权限、OSS 短期 role 和权限拒绝、CA/Secret/STS 轮换、跨副本登录/退出长流、跨区故障与 30 秒退出、滚动发布/回滚的验收记录。按真实云资源完成这些验收后才能激活公共入口；当前未执行 apply，不能宣称服务已上线。

## 本地开发证据

当前 API renderer/preparer 严格字段与 HA/权限/策略负例、官方 Kubernetes/Cilium schema，以及通过实际 Rust `Config` 的跨语言原生配置测试均已执行。Rust TLS 测试实际覆盖 TLS1.2/1.3、CA/SAN/日期/权限、明文拒绝、handshake 期限和流取消；独立 PG smoke 用公开 RSA 签名 fixture 经真实 HTTPS API 核验身份和拒绝错误签名。console 镜像另实际验证 Nginx → HTTPS transport fixture 的 CA/SAN/SNI/明文正负。上述证据不替代统一签名候选、真实 IdP/云 HA 和数据平面验收。公开 fixtures 禁止用于任何部署。

`deploy/api/check_image.py` 可对已构建的不可变 Linux service candidate 运行真实 UID/GID10001、readonly root、无网络/无 shell init 检查。它通过 Docker archive API 设置公开 fixture 的 root:GID10001/0440，不依赖 helper image；检查三种组合的精确 bundle owner/mode/content、同组幂等、变更 Secret 失败保持原组、644/root/未知参数拒绝。只操作唯一命名的本地容器与 volumes，并逐项清理。测试 output 是 disposable named volume，报告明确 `output_volume_is_memory: false`；它检验 Linux owner/权限/原子 bundle 行为，不声称实际 Kubernetes memory emptyDir、云安装或发布签名已验证。

2026-10-08 已对新增命令的真实 Linux amd64 unsigned candidate `sha256:99a400830f55882593b75a72bd4c6237ebdb5ef94a52ae62ffdce9b69341a927` 执行上述检查并通过，记录 `.local/api-secrets-init-linux-smoke.log`。编译输入是 226 文件的固定普通 Cargo 工作树快照，manifest SHA256 `1f7d4fbda04808284decc1bec33b2bb1421d0fa2d96e7023cf536dcb9e16f7f8`，构建后逐文件复核相同；这不是 Git 发布 commit。测试中 Docker archive API 的 staging 容器绝不启动，仅用于公开 fixture 元数据恢复，实际测试的 init 是 UID/GID10001；私有目标目录用 owned volume subpath 模拟 Kubelet 提供的 group root。初始化输出逐文件核验 UID/GID10001、0600、目录0700 与原字节，不以进程 exit0 代替核验。

```sh
python3 deploy/api/check_image.py --image "$IMMUTABLE_LOCAL_SERVICE_IMAGE_ID" \
  --docker-host "$LOCAL_DOCKER_SOCKET" --docker-config "$LOCAL_DOCKER_CONFIG_DIR"
```
