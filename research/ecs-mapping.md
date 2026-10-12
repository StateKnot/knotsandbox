# 阿里云 ECS 能力向容器沙箱的映射预研

检索日期：2026-10-03。以下事实来源均为阿里云官方文档；“沙箱设计建议”为工程推导，并非阿里云产品声明。

## 核心结论

ECS 实例详情页呈现的是一个云产品体系的组合能力：ECS 资源管理、CloudMonitor 监控告警、ActionTrail 操作审计、Security Center/Cloud Firewall/WAF/Anti-DDoS 安全、Cloud Assistant 命令执行、OOS 运维编排、Cloud Backup 备份。实现类似体验可行，但不能估算成“Rust 封装容器 CRUD + 八个页面”。官方总览可作直接依据：[监控与日志服务分工](https://www.alibabacloud.com/help/en/ecs/user-guide/monitoring-and-logging)、[应用安全服务分工](https://www.alibabacloud.com/help/en/ecs/user-guide/application-security)、[备份与恢复方案分工](https://www.alibabacloud.com/help/en/ecs/user-guide/disaster-recovery-solutions)。

## 八项能力映射

| 用户要求 | ECS 官方语义/产品边界 | 沙箱产品建议 | 不可直接等价的部分 |
|---|---|---|---|
| 实例详情 | 标识、配置、镜像、网络、标签、计费、维护、释放保护等；[官方](https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-information) | 稳定 sandbox ID、租户/项目、镜像 digest、runtime/隔离档位、资源限制、调度位置、网络策略、持久卷、TTL、desired/observed state、当前 operation、健康状态 | Pod/container UID 不应当作稳定业务实例 ID；实例重建可能更换 IP/底层对象。容器重启不等于 VM OS 重启。暂停、停止、休眠不能混称 |
| 监控 | 主机侧基础监控和 guest agent 的 OS 监控独立；[基础/OS 监控](https://www.alibabacloud.com/help/en/cms/cloudmonitor-1-0/user-guide/overview-of-basic-and-operating-system-monitoring) | 平台观测 cgroup CPU/节流、内存 working set/limit/OOM、磁盘用量/IO、网络、重启与执行延迟；可选内部 agent 输出应用健康 | CPU 百分比必须声明分母；guest 内存指标与宿主机指标不等价；网络/卷指标有 runtime 与存储驱动差异。单独给出 source、freshness、unsupported，不能把无数据当 0 |
| 操作记录 | ActionTrail 记录控制台/API/开发工具及主体、IP、资源、结果；默认管理事件保留 90 天，长期交付 SLS/OSS；[官方](https://www.alibabacloud.com/help/en/actiontrail/product-overview/what-is-actiontrail) | 自有 API 入口统一审计 principal/tenant/request_id/action/resource/outcome；敏感字段脱敏；异步 operation 另记执行阶段/重试/取消；长期归档、查询权限与防篡改 | 审计不是 stdout/stderr；记录了 exec API 调用不等于完整记录 shell 内所有行为；数据面文件读写、交互会话需单独审计策略 |
| 事件 | ECS 系统事件覆盖维护、故障、资源异常、生命周期等；有严重度和状态窗口；部分状态变化不显示在 ECS 控制台但推送 CloudMonitor；[官方](https://www.alibabacloud.com/help/en/ecs/user-guide/overview-of-ecs-system-events) | 定义持久化产品领域事件：ProvisionFailed、OOMKilled、NodeLost、TTLExpired、SecurityPolicyDenied、BackupFailed 等；事件 ID/版本、资源 revision、occurrence time、correlation ID；Webhooks 重试和投递状态 | 事件不等于操作日志，不应依赖短期底层事件列表作为业务审计。事件到达可重复/乱序，需要去重与游标；自动修复不能靠“恰好一次投递”假设 |
| 安全防护 | Security Center 管漏洞/主机威胁；安全组/Cloud Firewall 管网络；WAF/Anti-DDoS 管公网攻击；[官方](https://www.alibabacloud.com/help/en/ecs/user-guide/application-security) | 对不可信代码，隔离 runtime + 节点池边界为基础；最小权限、禁止 privileged/host mounts、默认出入站拒绝、metadata/内网阻断、身份密钥隔离、镜像扫描签名、运行时检测、隔离/封禁工作流 | 安全组不是系统调用隔离；镜像扫描不是容器逃逸防护；WAF 不处理任意恶意代码。承诺能力需列检测范围与处置模式，不应笼统宣称 ECS 同级安全 |
| 健康诊断 | ECS 综合诊断为异步诊断任务，检查系统/网络/磁盘，输出严重度、证据与建议，提供诊断 API；[官方](https://www.alibabacloud.com/help/en/ecs/user-guide/diagnose-the-health-status-of-an-instance) | 区分控制面、节点、runtime、沙箱进程、网络/DNS、存储、应用探针；版本化规则引擎输出 finding/evidence/recommendation，自动修复另走授权任务 | Running 不等于健康；应用未提供探针则健康应为 unknown，不是通过。资源被限流可能是配额生效而非平台故障 |
| 定时/自动化任务 | Cloud Assistant 负责 agent 内命令执行；OOS 负责模板、步骤、参数、审批、调度和事件驱动编排；[OOS](https://www.alibabacloud.com/help/en/ecs/user-guide/overview-3)、[执行命令](https://www.alibabacloud.com/help/en/ecs/user-guide/run-a-command) | 控制面持久化 schedule/workflow/run/step，调度租约、并发策略、misfire、时区/DST、deadline、重试、取消、死信、每步幂等键；sandbox exec 是受限执行器 | 容器内 cron 不承担云任务可靠性；沙箱过期/离线时必须有显式策略。控制面任务与租户任意脚本权限分离，禁用“高 CPU 自动重启”之类默认破坏性修复 |
| 备份 | ECS 区分盘快照、镜像、Cloud Backup、异地容灾；一致性组与应用一致性有独立条件；[方案](https://www.alibabacloud.com/help/en/ecs/user-guide/disaster-recovery-solutions)、[应用一致性](https://www.alibabacloud.com/help/en/ecs/user-guide/create-application-consistent-snapshots-in-the-ecs-console/) | durable workspace/volume 为正式备份范围，固定 image digest + sandbox spec + volume backup manifest 形成恢复点；显式一致性等级、加密、保留/删除保护、异地副本、恢复演练；恢复默认创建新实例 | 容器 image/commit 不等于持久卷备份；卷快照不包含内存、TCP 会话及外部服务状态。运行时 checkpoint 应列独立实验能力，不能当通用备份；CSI 快照需另有异地/独立存储策略 |

## 需要写入预研方案的重点边界

1. **备份一致性必须作为 API 返回值，而非模糊勾选项。** 阿里云 Linux 应用一致性依赖 prescript/postscript：暂停应用写入、快照、恢复写入；自定义脚本无法由平台保证应用一致性，脚本不正确可能退化为文件系统一致性。自身产品建议允许 `required_consistency=application`，hook 失败时任务失败，禁止静默降级；若允许降级，必须返回 achieved_consistency 与原因。必须有 thaw 超时兜底与 watchdog。[官方说明](https://www.alibabacloud.com/help/en/ecs/user-guide/create-application-consistent-snapshots-in-the-ecs-console/)
2. **多卷/多实例“同一时间点”不等于分布式应用一致性。** ECS 快照一致性组支持同一可用区的多盘、跨实例崩溃一致性；应用一致性有更严格边界。沙箱应先明确支持的卷驱动和拓扑，再承诺多卷一致性，数据库使用数据库自己的备份/恢复协议。[快照一致性组](https://www.alibabacloud.com/help/en/ecs/user-guide/snapshot-consistency-group-overview/)
3. **必须做三种记录。** AuditEvent 表示“谁请求做什么”，Operation/TaskRun 表示“异步动作现在执行到哪”，DomainEvent 表示“系统实际发生什么”。三者用 resource_id + operation_id + request_id 串联，既服务用户排障，也避免审计受到运行日志清理影响。此条为设计推导。
4. **控制台作为 API 客户端。** ECS 对监控、诊断、命令、事件、快照均提供 API；自研应先定义版本化 OpenAPI 契约，任何控制台动作都走同一鉴权/审计/限流路径，防止形成内部后门。监控、日志、事件按租户过滤不能只靠前端。
5. **安全防护有共同责任边界。** 阿里云也划分底层平台与客户 OS/应用/身份责任。沙箱平台应声明托管节点、隔离内核、runtime、基础镜像和租户自带镜像/依赖的维护分工。[ECS 安全责任](https://www.alibabacloud.com/help/en/ecs/user-guide/security-overview)

## API 资源建议（工程设计）

- `/sandboxes/{id}`：稳定逻辑实例；配置版本与运行实例引用。
- `/operations/{id}`：异步动作、结果、错误、幂等键、取消语义。
- `/audit-events`、`/events`、`/task-runs`：独立分页/筛选/权限/保留。
- `/sandboxes/{id}/metrics`：单位、采样窗口、数据源、时间戳、覆盖情况。
- `/sandboxes/{id}/diagnoses`：异步、版本化 rule-set、证据、修复建议。
- `/security-policies`、`/security-findings`：策略与检测结果分别管理。
- `/schedules`、`/workflows`、`/runs`：调度配置与实际执行分离。
- `/backup-policies`、`/recovery-points`、`/restore-jobs`：保留策略、恢复点、恢复执行分别管理。

以上不是完整 API 规格，只作为资源建模依据；生产验收必须包含跨租户越权、控制面重启恢复、节点故障、重复回调、任务重试幂等、备份恢复和网络策略失效的测试。
