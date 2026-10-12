# 整仓审查修复与下一阶段验收

日期：2026-10-10。基于 `d5f7a70afadde40e30ca01a2e9871a5312153d57` 的整仓审查，7项已确认问题均已修复，并完成相应本地回归。本轮同时推进开发表 G4-01/G4-02，将关键真实调用链接入必跑 CI；这些工作包仍为开发中，整个产品尚未通过生产上线验收。

采用 mattpocock-skills 的 codebase-design 与 Standards/Spec 审查原则：身份约束归入共享授权边界，公平领取归入 timer 模块，永久故障分类由后台控制器共享，安装快照由各安装入口统一核验。原始问题与触发证据保留在[整仓审查报告](architecture-code-review-20261010.md)，不将历史结论改写为修复后现状。

## 修复与验收对应

| 编号 | 最终实现 | 实际验证及边界 |
| --- | --- | --- |
| S1 | 自动化副本改为可信 platform 池，保持 control 污点及窄数据库来源 | 从正常 IaC/inventory 与自动化清单组合核对可调度节点、跨区副本条件和数据库来源；未做实云调度认证 |
| S2 | 完整 installation 快照绑定输入、inventory、版本锁和派生资源；执行前重新业务校验，Ansible 使用私有冻结副本 | inputs 漂移、world 出口、派生资源替换及符号链接被拒；缓存真实 Helm/官方 schema 与7个 Ansible playbook syntax 通过；摘要用于漂移检测，不充当发行者签名 |
| S3 | HTTP Actor 保留原 VerifiedIdentity；外部输出读取后经共享授权重核映射、client、scope、本地权限与原 token 期限 | 真实签名 JWT/HTTP/延迟对象读取下，仅禁用 identity mapping 或令原 token 到期均不能返回内容 |
| S4 | 生命周期 worker 监督 timer 和在途任务；永久权限/schema/程序故障有界收尾后非零退出，临时故障退避恢复 | 独立正常 worker 进程运行后撤销 claim/timer 权限，确认非零退出及物理 PG 后端缺席；临时表锁超时后同进程恢复、唯一 STOP，SIGTERM 正常收尾 |
| S5 | 0041 原子领取公平扫描资格；SKIP LOCKED、副本分工、NOWAIT 与单项局部100ms锁超时 | 前100项真实 workspace 行锁仍允许后续实例在原15秒期限内唯一受理 STOP；续期竞争继续通过，真实 TTL/idle 截止时间不变 |
| C1 | 部署显式选择 generic-access 或 action-scopes；适用动作 scope 与当前本地 grant 相交 | 正常 HTTP 的读取、写入、流、自动化 create/resume/幂等重放不能扩大权限；pause/revoke 保留管理合同；持久委派按自己的有限期限运行，不保留 bearer token |
| C2 | SERVICE 登记并精确核对 client_id；0040 为历史身份保留未绑定状态并拒绝认证；owner CAS 绑定/轮换、审计和单调 generation | 错 client 被拒，轮换后旧委派不能复活；Rust/SQL/DTO/控制台统一256 UTF-8字节及空白/控制字符约束；USER 身份保留既有合同 |

## 本轮验收

主要最终候选为766个公开文件，字节/模式摘要 `bc55444605b86e25822019098a8eca6243fa7f212af66b71cd88e01792ee9107`。本文件与进度更新在验收结束后补入，交付回执单独记录文档差异，不将它们冒称为先前测试输入。

| 验收 | 结果 | 证据 |
| --- | --- | --- |
| Rust 普通全目标 | 53个程序，419通过、0失败、231明确 ignored；ignored 不计通过 | `.local/review-fixes-20261010/rust-all-targets-4-local-ports.log` |
| 格式与严格 Clippy | 全目标通过，`-D warnings` | `clippy-4.log`、`candidate-validation.json` |
| 必跑真实数据库/HTTP/进程回归 | 11组共56通过，0失败；包含既有 service_clients、bootstrap、grants、executions、file_transfers | `actual-4/record.json` 与各组日志 |
| 既有自动化实际验收 | 原18项及独立进程1项通过；两库各40条正式迁移逐项核 SHA384 | `automation-3/evidence.json` 与日志 |
| 安装/身份/API Python | cluster18、automation5、nodeguard10、workload-identity19、api14、identity27，共93通过 | `python-final-venv.json` 前三组、`python-final-local-ports.json` 三组 |
| SDK与控制台 | SDK61、控制台59单测通过；Node24.19构建与8项实际 Chromium HTTP合同通过 | `sdk-test-locked-node.log`、`console-test-locked-node.log`、`console-build-locked-node.log`、`console-browser-locked-node-final.log` |

以上相对证据路径均位于 `.local/review-fixes-20261010/`。原自动化验收的输入和全部被测二进制 fingerprints 已与最终候选重新比较，完全相同；最终两轮之间仅修正本组 timers/bootstrap 测试夹具及回归脚本/说明，没有修改自动化生产链。全部公开源码在最终 Docker 验收前后不变，被测二进制摘要不变，所有本轮临时测试进程组和容器清理已确认。各正式库为正常 migrate 的1..37加39、40、41，共40条；0038永久保留，无伪迁移账本。

失败日志保留：初轮重复已有 grant、旧 FILE_WRITE 测试缺真实 held 槽、配额参数 i32/bigint 不匹配、bootstrap 缺初始化及误用未发布恢复权限均只修测试前置条件，保留或加强业务断言；恢复权限生产门禁未开放。受限环境的 loopback EPERM 与误将 venv Python 解析为全局解释器导致的依赖缺失也保留，分别以本地端口权限和正确 venv 重跑通过。未扩大生产权限、测试期限、worker 资源或将进程退出视为 guest 已停止。

## 升级与交付

1. 先按[服务身份迁移](../docs/service-clients.md#owner-binding-and-migration-0040)盘点可信 IdP client 元数据，经 owner 专用连接执行明确 CAS 绑定，再滚动 API/worker。历史 SERVICE 未绑定时保持拒绝；轮换导致旧持久委派失效，必须重新创建。正常迁移与角色安装包括0040/0041。
2. 企业 OIDC 明确配置 scope profile；独立 Keycloak 使用既有通用 profile。不得由请求自选 profile，也不得依靠 scope 补足本地 grant。
3. 旧 inventory-only 安装目录需要按已审输入重新生成完整 installation；校验后执行，各入口使用冻结输入。artifacts/credentials/backups 输出仍写到持久部署目录。
4. `scripts/test-review-fixes.py` 接收普通 Cargo JSON，运行本机临时 loopback TLS PG 与最小权限角色；bootstrap 先在自己的新库运行既有初始化/RLS前置测试。缺必需测试、零项通过、迁移不匹配、源码/制品漂移或清理不确认均失败。CI只上传顶层 JSON/日志，不上传测试 TLS 私钥。见[复现说明](../docs/review-regressions.md)。

本机低调试验证使用 `target/review-low-debug`，约3.24 GiB，保留用于同仓后续验证；未复制已有 target。编译前已安全回收本任务旧可重建 debug 缓存，实际可用空间增加75.65 GiB，回执 `cache-cleanup.json`，不以 du 累加推算释放量。证据保存于构建缓存之外，源码、Git历史、数据库和既有 Docker 数据卷保留。

## 仍需完成的生产门

下一阶段沿 G4 开发表继续推进完整攻击面与生命周期故障矩阵、当前 Linux 八制品同源构建/漏洞处置/统一签名发布，以及安装组件组合验收。真实云 Kata/CSI、物理 fencing、恢复 listener/供应商 gate/完整失败收口、生产身份/PKI、跨区 HA 与灾备、72小时容量和正式微服务接入尚未验收，生产恢复入口保持关闭。G4-01/G4-02及正式发布均不能因本轮本地通过而标为完成。

本轮没有 commit 或 push；当前仓库未配置 Git remote。代码、方案和证据均在本地工作区。
