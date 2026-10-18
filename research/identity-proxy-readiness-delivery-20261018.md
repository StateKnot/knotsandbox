# 私网身份代理就绪诊断（2026-10-18）

本批完成测试就绪诊断的实际 RED→GREEN 与最终本地验收；未确认原 CI 故障原因。公开基线 `d30913ad7e63dd1b76257255a85c50a2c2f6ca3a` 的精确 [CI39113057651](https://github.com/StateKnot/knotsandbox/actions/runs/39113057651) 为 4 job 通过、1 job 失败、73 step。`verify` 全部门通过，包括 BFF 关闭门；原 `4e517ab` 超时原因仍 UNKNOWN。新失败仅在安装合同的 `live_admin.py` 私网代理发现就绪阶段，错误为 `Proxy TLS not ready`。身份源码和整个安装合同 job 与 ee3eeac/4e517ab 逐字相同，不能据此推断新提交引入了身份代码回归。

## 观察缺口与实现

失败 CI 已通过真实 HAProxy 两跳经校验的 TLS/公共过滤、独立 Keycloak standalone/broker 与机器 token 链；第二个 Keycloak 的直接 TLS 发现和 HAProxy 语法检查也通过。但私网发现未获 200，后续登录、初始化、console、PKCE 与公共拒绝断言尚未执行。原就绪循环丢弃非 200 状态、OSError 和子进程状态，日志无法区分客户端 TLS 失败、HTTP 拒绝/后端不可用或代理退出。本地未经修改的完整管理链随后通过，不能把它写成原 CI 的复现或修复。

本片仅修改 `deploy/identity/tests/live_proxy.py`、`live_admin.py`，新增同目录 `proxy_readiness.py`，两个原调用方共用原就绪循环。保留 50 次、每次一次原 GET、100ms 睡眠、各自原请求超时（admin 10 秒、native proxy 5 秒）及仅 HTTP 200 成功。原循环没有严格 5 秒总预算，本片不增加总期限或整测重试。TLS/CA/hostname、Host/ACL、转发头、Origin、真实登录、console、PKCE、幂等初始化及公开路径拒绝断言均保留。

只在原尝试耗尽时附加固定诊断：实际尝试数、HTTP/传输计数、最后一次 HTTP 状态或 UNKNOWN、固定传输分类和 `process.poll()` 的 RUNNING/数字退出码。发生传输失败时重置状态为 UNKNOWN，不把旧 HTTP 样本当当前事实。证书验证、其他 TLS、timeout、连接拒绝、其他 I/O 使用固定分类；不输出异常文本、响应正文/头、URI/query、认证票据、配置或 PID。成功路径不增加日志、请求或后台任务，进程观察只在失败时进行。HTTP 状态和进程状态只是客户端观察，不能自行认定后端原因。

## 实际回归与证据

证据位于本机 `.local/tls-ci-repair-20261018/`，不随源码公开；所有测试 CA、bootstrap 密码及运行凭据均留在私有临时夹具。

| 证据 | 实际结果与范围 |
| --- | --- |
| `baseline-contract.json`、`contract-audit.md`、`identity-contract-baseline-proof.json` | 精确失败、调用链和既有源码/job 不变；未扩大原门限或策略 |
| `linux-original-1/record.json` | 首轮 Python3.11 缺 jsonschema，导入即失败，未到网络/CI 故障点；原失败及 5 容器清理保留 |
| `linux-original-2/record.json` | 补齐锁定依赖，Python3.12 下未经修改的 live_proxy 与真实 Keycloak live_admin 通过；不是原 CI 复现 |
| `linux-readiness-red-1/record.json`、`live-proxy.log` | 等价抽出原 generic 循环后，全部原正向安全断言通过，实际不可信 Host 返回 400、进程仍活；因缺少固定诊断字段真实 RED。不是缺依赖或初始化失败 |
| `linux-readiness-green-1/record.json` | 仅更换诊断实现，原正断言及三种真实故障全部通过；真实 Keycloak 管理链通过 |
| `identity-unit-schema.log` | 最终 ROOT 的 27 项身份测试通过，37 个对象通过锁定 Kubernetes/Keycloak/Cilium 官方 schema 离线校验 |
| `linux-final-readiness/record.json` | 直接冻结最终 ROOT，原 HAProxy 正向安全断言、三种故障及真实 Keycloak 管理链通过；全部必需 marker、源码/ELF/库/依赖稳定和 5 个自有容器清理确认 |
| `linux-final-realm/record.json` | 另建全新 Keycloak，默认 hostname 的原 standalone/broker realm 与实际 private_key_jwt/JWKS/服务主体检查通过；全部必需 marker、源码/制品/依赖稳定和 4 个自有容器清理确认 |

三个新增反例都使用原夹具的真实 TLS 和已审阅 HAProxy：不可信 Host 确认实际 HTTP 400、严格默认 CA 确认客户端证书验证失败、显式终止并 wait 后确认真实连接拒绝及实际数字退出码。前两种故障中进程必须仍运行。每种都执行原 50 次循环并核对完整固定诊断，不伪造 HTTP 或退出状态；带有 opaque query/Host 的输入不得出现在错误中。三项完成 marker 缺失、非零退出或 OOM 均不能通过；原正常断言位于这些反例之前。

早期 adapter 的 `readiness_contract` 标签未区分两个 getter，把它们统称为 10 秒；原记录保留，`adapter-contract-facts.json` 明确纠正。最终两份收据已准确区分 10/5 秒；实际源码一直保留原值，没有为了通过放宽 native 的 5 秒超时。

## 制品、范围与后续门

固定运行时为 Linux arm64 Python3.12.10 镜像 `sha256:fd95fa221297a88e1cf49c55ec1828edd7c5a428187e67b5d1805692d11588db`，HAProxy3.2.25 实际 ELF SHA256 为 `229f30accd5f3627981419e14b1be669b438359ef19b0f2667036a6b17c72571`，SSL 库和 7 个 Linux wheel 绑定 SHA；wheel 版本和哈希来自仓库既有锁文件。新空任务依赖目录，不复制 Mac 虚拟环境、target 或其他生成缓存。最终源码摘要见本机 `proposal/manifest.json` 与交付冻结清单，审查报告独立绑定该清单。

本地把 Keycloak 内部 HTTPS 8443 改为 58443，以对应原 CI 的宿主端口映射；测试容器共享本次自有 Keycloak 的网络 namespace，无宿主端口发布、不触及现有服务/数据库。证书在同一 Linux VM 按原 1 天有效期生成；没有调系统时钟或放宽证书验证。两份最终收据各自绑定源码、实际制品和依赖稳定性及精确自有清理，结果不合并成一次整套 CI。它们也不证明 Linux amd64 CI 原因、生产 PKI、MFA、HA 或云身份部署完成。

本批没有修改 Rust、API、迁移、生产代理配置、身份策略、锁定版本或权限，未重跑并冒称本轮 Rust/云/Kata/GPU 验收。两轴审查分别核对 Standards 与 Spec；最终 8 文件字节、模式和回执另由独立清单绑定。此记录在提交前形成，不自证新提交或 CI 成功；发布后须独立核对精确 head、完整远端树与 CI，保留旧失败，不靠文档回填反复触发 CI。

下一生产开发仍为 P1 受限准备执行者、真实硬限及 lease/content/snapshot/GC 保护闭包。pre-pull 关闭，GPU、云、Kata、CSI、性能收益及生产上线认证继续待完成。主工作区与四项历史文档差异保留；只同步本轮审查/验收文件，不强推、不创建 release。
