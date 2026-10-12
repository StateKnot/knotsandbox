# 本地逐项验收与演示

验收对象是已经实现的子功能，开发任务整包的完成状态仍以实施表为准。控制面使用真实 PostgreSQL、OAuth/JWT、HTTP、Node SDK 和编译后的控制台。Kube、云 API、OSS 和节点服务的本地协议夹具必须单独标记，不能代替 Kata/CSI/Cilium、HA、容量和正式发布认证。

| 顺序 | 子功能 | 可观察结果 | 本地边界 |
|---|---|---|---|
| 1 | 身份、服务身份、项目授权 | 真实 Keycloak/JWKS；注册、启停、ETag、撤权；原令牌即时失去资源读取权 | 本地 TLS/OIDC，不含生产 IdP HA、邮件和上游认证 |
| 2 | 详情、生命周期、TTL | 工作区、模板、策略与租约；创建/停止受理；幂等、配额、公平扫描、可信关闭 | 演示实例真实创建排队，不能宣称 VM 已启动或停止 |
| 3 | 操作记录、审计、事件 | 实际变更记录、签名分页、权限脱敏、SSE 断点恢复及撤权 | 运行事件有明确协议夹具 |
| 4 | 执行与输出 | 执行账本、单次 WebSocket、完整性、分页/SSE、UNKNOWN 不重发 | Kube exec/存储协议，不执行本地非可信租户代码 |
| 5 | 文件 | 分片上传、提交、下载、路径与字节校验、原键重放和额度保护 | 本地 PG/JWT/HTTP/OSS；Linux helper 另需 Linux |
| 6 | 安全、监控 | 期望/历史/UNKNOWN 分开；范围和撤权；双 agent WAL/503 恢复与告警回放 | 云数据、实际隔离未配置时界面显示未开启/未知 |
| 7 | 诊断 | 正常受理与 worker claim、只读报告、权限和超时 | 不含 guest 探测或自动修复 |
| 8 | 定时、自动化、通知 | 有界授权、独立进程、暂停/恢复/撤销、真实失败来源和 ACK 原键重放 | 正式迁移；云动作最终效果另验收 |
| 9 | 冷备份 | 账本、保护、可信关闭、签名库存和配置激活；删除自有源/可变仓库后独立完整恢复及 SHA 校验 | 不含公开恢复 API、真实 OSS/CSI/Kata 恢复 |
| 10 | 安装、发布工具 | 配置、固定 schema、原生协议负例及发布门拒绝原因 | renderer/协议通过不等于云 apply 或已签名发布 |

## 普通构建与控制面验收

先读取 `df -h`；不足 50 GiB 时先评估本任务可重建缓存。复用缓存，不复制已有 `target`。下列环境设置只作用于当前命令，保留调试断言和溢出检查。`OUT` 须是本次全新私有目录，位于 `target` 之外。

```bash
export CARGO_TARGET_DIR="$PWD/target/review-low-debug"
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
umask 077
mkdir -p "$OUT"
cargo test --locked --offline --all-targets --no-run --message-format=json > "$OUT/cargo-artifacts.jsonl"
cargo build --locked --offline --bin sandboxd --bin sandbox-automation --message-format=json >> "$OUT/cargo-artifacts.jsonl"
npm --prefix sdk/typescript test
.local/cluster-venv/bin/python scripts/test-local-acceptance.py \
  --artifacts "$OUT/cargo-artifacts.jsonl" --evidence-dir "$OUT/control-plane" \
  --node /absolute/path/to/node --openssl /absolute/path/to/openssl3
```

新入口串行运行 34 组，其中 14 组继承必跑 review 矩阵，20 组补充已实现 Interface。各组使用本次自有 TLS 数据库和十个独立组件角色；正常组由 `sandboxd --role migrate` 安装当前 schema，bootstrap 只共享已通过的初始化前置库。

只有精确 `automation_upgrade` 用例从本次新建空库安装真实版本≤41的schema前缀及冻结ACL，再按41→42→43正常迁移。runner禁止预装当前schema，确认前置用户关系数为零，必须发现并通过一个指定ignored用例，同时输出基础升级、非空历史/ACK、双状态通知三个完成marker，名称及记录字段见[数据库升级](database-upgrade.md)。该用例覆盖非空账务/typed回执/LEGAL、42已阅、同run UNKNOWN→FAILED独立通知、跨目标相同文本key回执与当前撤权、分页/租户隔离、终态重复源整事务回滚、旧writer及旧Migrator合同。账务/42已阅为合法owner夹具，后续来源转换使用当前coordinator独立LOGIN；未运行完整controller恢复、非空备份、完整worker生命周期、旧发行包或滚动发布。

当前正常账本为1..37、39..43，共42条；0038仍永久未发布，旧 checksum 必须逐项保持。每组最终均保存并核对正式迁移 SHA384；另绑定源码、普通产物、SDK 和工具 SHA256，保存实际测试数及清理事实。完整执行、绑定不变且清理确认才通过。不选恢复私有草案、硬编码开发管理员的用例或全部 ignored 库测试。实际自动化执行另用 `scripts/test-automation.py` 正式数据库入口。完整历史升级／回退、旧发行包、滚动发布及实云验收仍为未完成项，不能由这一个 schema 回归推导生产门通过。

## 浏览器验收和手工演示

`scripts/test-console-browser.py` 默认运行完整真实 Chrome → Keycloak → cookie BFF → API → TLS PG。现有本地开发 Keycloak 必须就绪；只读取其本地管理员凭据，创建和删除随机 realm，不改旧身份/口令。原浏览器矩阵与真实通知来源、ACK、撤权、原键重放事实全部必须通过。

普通自动路径必须另外保存九张真实控制台检查点截图及 `browser-screenshots/manifest.json`。wrapper 独立验证 canonical 0700 目录、0600文件、固定九图及顺序、PNG包络、实际字节数和SHA256，记录 `screenshot_evidence.validated=true/count=9` 后报告才可引用。不会截图IdP登录、密码、token或cookie；图片只包含本次夹具的控制台结果。缺失图片不能获得本轮PASS，截图也不能替代真实HTTP/PG业务事实检查。此证据仍属自动化浏览器验收，手工交互状态单独记载。

`--manual-demo --demo-seconds 1800` 使用独立 ignored 入口，最多 7200 秒，不要求 `--chrome`。只发布 `READY_NOT_ACCEPTANCE` 和停止状态，不产生自动验收 PASS。私有 `demo-ready.json` 给出 URL、租户/项目/实例及到期时间；`demo-login.json` 为 0600，保存本次随机用户凭据。浏览器安全提示须由用户完成，不修改系统信任或生产 TLS 校验。

实例来自正常创建受理，仅 DIAGNOSE 由正常 worker 调谐。短事务调度屏障使算力操作保持排队，不改状态或伪造运行成功。未配置能力按真实 capability 禁用。创建环境中的 `demo-stop` 普通文件或发 SIGTERM/SIGINT，等待服务关闭、删除本次随机 realm/PG、销毁登录凭据。只清理已确认本次所有权的资源。

每次保留失败日志并使用新证据目录。报告分开记录可见演示、自动验收、协议夹具、未完成和未配置能力。因本机工具/证书策略未能展示的步骤列为待用户操作，不能仅凭 READY 或后台测试宣称已经演示。发布审查过期、扫描未通过或升级/HA/恢复未验证时保持生产门关闭，不修改时钟或延长旧审查来显示通过。
