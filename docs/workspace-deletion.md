# 计算删除、保留数据与独立卷销毁

`DELETE /v1/instances/{id}` 只销毁计算实例。可信终止证明和 Kubernetes 清理完成后，实例变为 `DELETED`，计算/实例配额释放；工作区保持 `AVAILABLE`，存储配额继续计费/占用。旧版本已经写入 `WAITING_VOLUME_DELETION` 的计算操作按相同精确证明恢复，不再永久等待数据销毁。停止过的实例删除也复用不可变的当前 launch 证明，不能把 Pod 不存在当作证明。

真正销毁数据必须另行调用 `DELETE /v1/workspaces/{id}`。调用方需要当前项目的 `workspaces:delete`；查看详情需要 `workspaces:read`。先 GET 取得 `ETag`，DELETE 带该 `If-Match`、`Idempotency-Key` 和 JSON `{"confirm_workspace_id":"同一工作区 UUID"}`。返回 `202`、新的工作区 ETag、操作 `Location` 与 `WorkspaceAccepted`；恢复模糊网络结果必须保持原确认 UUID、原 ETag、原幂等键。每次重放重新核验权限，撤权后不能读回旧回执。跨租户/项目无权限与不存在统一为 404。

## 数据保留门禁

受理与 BACKUP/RESTORE/LEGAL hold 插入共享工作区行锁；只有一方能先提交。只要仍有活动 hold 就拒绝删除，hold 释放必须另写只追加回执。非 LEGAL hold 必须记录关联任务 UUID、源 generation 和精确 PVC UID。删除意图提交后，工作区形成不可撤回的销毁墓碑，不能插入新 hold、改保留期或重新挂载计算。

`retention_until` 在未来会阻止显式删除；为 NULL 表示没有自动到期时间，具备独立权限并明确确认的人工删除仍可受理。当前没有自动回收授权或后台 TTL 数据销毁任务。备份产品控制器尚未完整接线时，不能凭“hold 表为空”宣称备份受保护；其能力必须保持不可用，直到受理、快照不确定状态、仓库封存和恢复接管均真实写入/释放 hold。

所有当前和历史 launch 都必须有精确本地宿主关闭证明及清理回执，所有实例已删除且没有活动执行槽。证明绑定 tenant/project/workspace、generation/launch、Pod/PVC/PV UID、宿主身份与当前 cluster epoch。整机云 `Stopped` 观察不足以通过此门禁。CREATE 失败且从未取得 launch permit 的场景目前保守阻塞，需后续正式的“从未允许启动”封闭协议；这仍是完整生命周期上线验收缺口，不能靠手工制造终止证明解除。

## 控制器与证据顺序

1. 专用 `sandbox_volume_deleter` 数据库身份领取 VOLUME 队列。旧 epoch 的删除意图不会占据候选队首；保留其墓碑，等待数据库恢复审查。每次变更锁工作区再锁操作，校验当前租约、授权、保留期、全部 writer 证明和 hold。
2. Kubernetes fresh GET 校验 namespace 认证、Retain/Filesystem/RWO StorageClass、Deployment/KMS、CSI driver、固定 PV/PVC UID、claimRef、拓扑及原盘 ID；列出并确认无 Pod writer 与 VolumeAttachment。云 DescribeDisks 必须返回同账号/地域、Deployment、zone、KMS、容量和精确 SerialNumber/CreationTime。首个完整身份只追加绑定，后续不允许换盘。
3. 阿里云 CreateDisk 默认 `DeleteAutoSnapshot=true`。独立保留快照意图先持久化，再调用只能设置 `DeleteAutoSnapshot=false` 的受控客户端；记录请求 ID、响应摘要与未知结果。之后独立 DescribeDisks 必须确认 false，才能生成 DELETE_DISK 意图；修改属性 ACK 本身不够。该步骤不会删除任何快照。见 [CreateDisk 官方契约](https://www.alibabacloud.com/help/en/ecs/developer-reference/api-ecs-2014-05-26-createdisk) 与 [ModifyDiskAttribute](https://www.alibabacloud.com/help/en/ecs/developer-reference/api-ecs-2014-05-26-modifydiskattribute)。
4. 先只追加删除 attempt，之后提交固定原盘的 DeleteDisk。云请求前再查同一完整身份、`Available` 且没有任何正向挂载证据，DeleteAutoSnapshot=false。普通非共享盘未返回的共享挂载字段不伪装成隔离证明；`Available` 的原子删除条件还由云 API 执行。独立 RAM角色只获 DescribeDisks 与 Deployment 限制的 DeleteDisk/ModifyDiskAttribute，没有 Stop、Detach、Tag 或快照删除权限；CSI 身份已移除 DeleteDisk。属性修改权限无法由 RAM 限定到单个参数，因此该身份是可信控制器边界，不能交给租户或通用脚本。
5. Accepted/Unknown/拒绝均持久记录。进程在提交 attempt 后崩溃，缺少结果行就是未知，恢复先查询原盘。只有在新的精确身份/状态查询仍允许时才能重试原盘删除；固定盘 ID 的删除重试不会创建第二个数据盘。云返回错误 404 或 DELETE ACK 不是销毁证明。必须随后 DescribeDisks 精确查询原 ID 返回空，并且已有 DELETE_DISK 意图；仅有保留快照意图不够。
6. 云缺盘证据持久化后，准入才允许精确 volume-deleter SA+UID 删除原 PVC/PV。Kubernetes DELETE 带 UID/resourceVersion 前提，受控 storage controller 可以移除合法清理 finalizer；普通 worker、错 UID、换盘/回收策略修改均拒绝。控制器等待实际 PVC/PV 404 且无挂载/writer，不能手工删除 finalizer 来“解卡”。
7. 最后一个事务写清理回执、事件与审计，重新核验租约/epoch/观察新鲜度，再释放租户和项目两份存储预留并标记工作区 DELETED。事件流 head 锁等待期间租约过期会整体回滚，配额不提前释放。全部证据表 FORCE RLS、只追加、复合外键绑定同一工作区/操作。

## 运维恢复

权限或身份永久失败会进入 `WAITING_OPERATOR_REVIEW`，保留存储与墓碑；不会每五秒无限重发。只读诊断使用精确 tenant/operation 查询 `workspace_delete_*` 和 `workspace_snapshot_preserve_*`，核对原账号/地域/盘 ID/SerialNumber/CreationTime、云 request ID、保留快照属性与审计。未知请求不改写成失败成功，不删除 attempt/outcome，不更换原盘绑定。恢复快照或数据库到新 epoch 必须单独认证，不能改旧 intent 的 epoch 强行续跑。

修正权限/部署后，需要已获批准的事故编号、启用的 USER 人类操作者且仍具有该项目 `workspaces:delete`，由 DBA 使用 owner 执行 [定向恢复脚本](../scripts/sql/resume-workspace-deletion.sql)。先在相同租户 GUC 下查询精确绑定与 `encode(sha256(convert_to(cloud_identity::text,'UTF8')),'hex')`，经人工核对后将该 digest 与 tenant_id、operation_id、operator_id、incident_reference 用 psql `--set` 传入脚本。脚本检查 epoch、工作区锁、暂停阶段、无有效租约与全部 writer 证明，只恢复调度并写审计；它不触云、不改绑定/证据/配额。下一轮控制器仍须原调用者权限与所有运行条件通过。DBA URL通过受控凭据渠道注入，不能把密码放在命令历史。

## 已验证与尚待验收

本地真实 PostgreSQL 17.11、独立 API/termination/volume/admission role、真实 mTLS 宿主协议替身与签名 STS/ECS HTTP 替身已用于回归。证据包括崩溃恢复、hold/retention/撤权、物理缺盘无 intent、UID 换绑、受控重试/永久拒绝、提前删 PVC/PV 被拒、七组件的 21 对 membership 隔离。Terraform 使用已锁官方 provider 校验并跑无凭据 mock 测试；部署模板需用实际认证输入渲染。

尚未执行真实云删盘、真实 Kata/CSI 挂载销毁、跨 AZ 故障或备份恢复。上线前必须在隔离演练环境证明默认快照属性真实修正、自动快照保留、RAM 标签条件有效、CSI 不会先行删除盘、AdmissionReview mTLS/准确控制器身份、宿主/Kubernetes/云身份链、晚到写入/响应丢失/故障重启及配额一次释放。不能把上述本地替身测试当作已完成实云认证。
