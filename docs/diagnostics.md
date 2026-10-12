# 持久健康诊断

诊断以当前控制面账本为证据生成可保留的历史报告。`POST /v1/instances/{id}/diagnoses` 返回 202 和持久 Operation；`GET /v1/diagnoses/{id}` 读取报告。任务经现有 worker 队列运行，进程崩溃可重算，只有持有当前数据库租约的 worker 能提交结果。

诊断不占实例的生命周期/执行槽，不预留 CPU 或存储，也不修改实例、工作区、Pod、云资源或租期。因此 CREATE 正在进行、执行结果 UNKNOWN、停止等待可信证明和平台 safe mode 都可以请求诊断。整个功能没有自动修复路径。

## API 与授权

创建请求必须带 `Authorization`、`X-Tenant-ID` 和 `Idempotency-Key`，无需 `If-Match`：

```json
{"include_operations": true, "include_executions": true}
```

两个字段默认 true，未知字段拒绝；不接受命令、脚本、探针地址或自定义查询。请求及同键重放要求 `diagnoses:create` 和 `instances:read`；读取要求 `diagnoses:read` 和 `instances:read`。无权限、错误租户和不存在资源统一 404。同键不同选项返回 `IDEMPOTENCY_CONFLICT`。

响应包含 `resource`、`operation` 和 `idempotency_expires_at`；`Location` 指向 Operation，`Content-Location` 指向诊断，ETag 为诊断版本。诊断记录包含请求时 generation/launch/cluster epoch、规则版本、创建时间、截止时间、报告保留截止时间和快照时间。`snapshot_at` 是观测时点，不能当成 GET 时仍然健康。

Operation 和 execution 的附加证据分别要求 `operations:read`、`executions:read`。缺权不阻止基本诊断，对应条目返回 UNKNOWN/EVIDENCE_REDACTED，证据数组为空。GET 每次重新校验并重新计算 overall；后来撤权不能借历史报告获取此前允许的附加数据。开始采集和最终发布均复核原请求主体权限，主体停用/撤权产生失败报告。

部署能力 `api_features.control_plane_diagnoses=true` 表示上述报告 API 已实现，不能代替授权或 worker 可用性检查；旧部署缺少此字段时按不支持处理。完整运行健康能力 `health_diagnostics` 仍为 false。调用方保留受理响应的 `resource.id`，直接 GET 诊断的 `status` 查询进度，只需诊断读取及实例读取权限；无需为此额外授予 `operations:read`。

## 控制台使用

实例页的“健康诊断”支持创建、按 ID 查询和显式刷新。页面默认不附带操作/执行证据；这是控制台的明确请求选项，API 字段默认值仍为 true。报告展示规则集、快照与保留时间、请求时 generation/launch/cluster epoch，以及每条检查的状态、代码、证据来源/观测时间/期限和建议索引。历史报告不能作为当前运行代的健康证明；UNKNOWN、REDACTED、失败和正文已过期分别展示。

PENDING 只自动读取同一报告，每两秒一次，最多60次，受服务器原始 `deadline` 约束；每次自动 GET 的请求和解析后响应均检查该期限。到期限、终态或读取失败停止自动刷新，仍可显式读取原报告。浏览器停止刷新不会擅自将服务端状态改为 FAILED/EXPIRED，也不会自动创建替代报告。读取时切换项目、登出或服务端撤权会取消旧请求并清除旧证据；不显示跨项目返回值。

“请求记录”中已受理的诊断可以直接打开报告。创建已提交但回执丢失时保留 UNKNOWN 原 body/幂等键；重载后只有显式重放原请求，服务端返回原报告与原 Operation，不生成新键绕过未核对结果。详细浏览器边界见 [控制台交付说明](console.md)。

## 已实现证据规则

| 规则 | 数据来源与判定 | 明确限制 |
|---|---|---|
| 计算租期 | 当前数据库租期；desired RUNNING 且到期为 CRITICAL | 不据此声称 VM 已关闭 |
| 生命周期观测 | reconciler `observed_at`；缺失、超过60秒或未来时间为 UNKNOWN | 近期观测也不构成持续存活证明 |
| 启动代与恢复 epoch | 精确当前 generation/launch/epoch 与 Ready 记录 | Ready 是历史启动校验，不是持续健康检查 |
| 工作区 | 持久状态；运行实例引用已删除/正在删除工作区为 CRITICAL | AVAILABLE 不代表 guest 内文件系统可写 |
| 模板与安全策略 | 当前版本是否仍 APPROVED | 不执行扫描或策略更改 |
| 节点认证 | 窄函数核对当前绑定与认证覆盖计算租期 | 无当前授权可含认证过期/撤销/节点停用，不能只诊断成“证书过期” |
| 活动 Operation | 期限、状态、worker lease 是否过期 | 不包含原始 error、wait_reason 或请求体 |
| 活动执行 | 持有槽的执行 UNKNOWN/超过期限 | 仍保留活动槽，不能自动重派或取消 |
| 平台模式 | safe mode 时说明启动受限 | 不阻止报告或到期清理 |

持续运行健康、guest DNS、OOM 和文件系统空间没有在本规则集中采集，显式 UNKNOWN。Pod 消失、没有指标、指标为0、HTTP DELETE ACK 都不构成死亡或销毁证明。报告只有固定规则/结论/建议代码、限定账本状态、UUID 和时间，不包含 token、环境变量、命令、日志、租户名称、节点地址或宿主路径。

overall 优先级是 CRITICAL → WARNING → UNKNOWN → HEALTHY。它只归纳当前可见条目；UNKNOWN 不会被补成0或健康。`recommendation` 是 runbook 索引，不是已授权的操作指令。

## 有界任务、恢复与保留

每个请求固定120秒完成期限、30天报告保留期，规则版本 `control-plane/v1`。同实例最多一个 PENDING；单租户最多32个 PENDING、滚动24小时最多1000次。并发受理在专用租户 advisory lock 下检查限额，不争用实例/工作区锁。返回 `DIAGNOSIS_IN_PROGRESS` 或429 `DIAGNOSIS_QUOTA_EXCEEDED` 时不可通过自动换幂等键绕开限制。

采集采用只读 REPEATABLE READ 事务。请求绑定的启动代或恢复 epoch 改变则失败 `TARGET_CHANGED`；拒绝主体为 `AUTHORITY_REVOKED`；超过任务期限为 `DEADLINE_EXCEEDED`。短暂数据库故障沿用 worker 有界重试，截止维护最终收敛过期任务。报告只提交一次，报告/Operation/audit/domain event 同事务；事件流项目头锁等待后再次校验 worker lease、任务期限和授权，失效则回滚。

worker 每五秒进行有界维护，单次最多128条。过期 PENDING 转失败并释放诊断 admission 配额；受理下一请求也会清理本租户到期任务。报告到期清除 JSON，保留 EXPIRED 身份记录。维护跳过被锁 Operation，并将目标延迟五秒轮转，避免永久挡住其他到期任务。维护失败记录固定错误码，不阻断原有计算租期停止扫描。safe mode 不停止此维护。

GET 在保留截止后立即隐藏报告，不依赖后台清理时机。已完成报告不可重写；EXPIRED 不可复活。幂等受理回执只含原 PENDING 身份和 Operation，不含报告正文；原回执保留7天，过期返回410，现有幂等墓碑政策继续适用。诊断身份/操作/审计元数据不随报告正文一起删除；部署者应将其纳入平台元数据保留和容量政策。

## 运行与验证

先应用0034，再执行现有 app/worker role 脚本，最后部署包含诊断分派的新 worker 和 API。worker 启动检查维护函数和诊断表权限；没有独立诊断服务、消息系统或数据库。app 只能插入/读取诊断；worker 只获最终状态字段更新；全局维护仅返回处理数量，payload-free index 不对 app/worker直接开放。诊断表 FORCE RLS，复合外键限定 tenant/project/instance/workspace/Operation，延迟约束保证 Operation 与报告终态一致。

本地验证命令（依赖真实隔离 PostgreSQL、app/worker/owner 各自身份；缺环境变量失败）：

```sh
cargo test --locked --test diagnostics -- --ignored --test-threads=1
cargo test --locked --lib diagnostics::rules::tests
```

覆盖同键并发、33个并发受理的32槽上限、运行中生命周期不被占用、safe mode、撤权、跨租户隐藏、角色最小写权限、租约失效/重新领取、只提交一次、截止清理、报告到期及防复活，以及真实 TCP/JWT HTTP 请求、事件流头锁等待越过任务期限时原子回滚。真实 K8s/guest 故障注入和生产容量/恢复演练仍须部署验收；本报告不会把未采集的证据当作已通过。

2026-10-09 新隔离 Docker PostgreSQL 库下诊断专项8/8、能力与权限专项1/1通过；真实 Chrome→Keycloak→BFF/API→PostgreSQL→正常 worker 验证已提交丢回执、重载原键重放唯一性、COMPLETE 结构化报告、不具有操作读取权限的报告查询、真实诊断撤权404清除和恢复读取，实例/工作区/活动执行完整行保持不变。最终747文件源 `d15d90759dc79dc149160c805afd6174b554cf4baaabe00d6c3f0eb674ab2bfc` 的两次真实全链分别1/1通过；记录 `.local/evidence/health/1791542835360872000/record.json` 与 `.local/evidence/health/1791542898336747000/record.json`。专项8+1记录于 `.local/evidence/health/1791542218251633000/record.json`，随后只改变报告身份展示与浏览器验收诊断信息，Rust/API/SDK输入相同。另4项 Chrome HTTP合同、32项控制台单测、61项 SDK 测试、严格 Clippy/fmt通过；合同替身与实际链分别记录。一次未定位的浏览器 Error 失败保留，增加固定阶段诊断后同源码连续两次通过，不声称已确认该异常根因。汇总见 `.local/health-console-20261009/final.json`。本地测试证书和回环身份服务不认证生产 TLS、企业联邦、Kata/CSI/实云、HA或容量。
