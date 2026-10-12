# 独立云盘删除传输

`AlibabaCloudVolumeDeletion` 使用独立工作负载身份，只提供精确云盘观察、关闭自动快照随盘删除及删除；它不提供宿主机 Stop、磁盘 Detach、标签修改、快照删除或凭据导出。内部共用已验证的 ACS3/STS 传输，但没有节点 allowlist、公开 fencing 客户端或 Deref。它不把请求受理转成存储已释放。

## 身份与最小权限

`CloudVolumeDeletionConfig` 来自部署输出：账号、地域、独立 RAM role ARN/ID、OIDC provider/issuer/audience、token 绝对路径、Deployment、限速与并发上限。ServiceAccount subject 必须是 `system:serviceaccount:sandbox-system:sandbox-volume-deleter`。新的 STS 会话使用 `volume-` 前缀，仍核验 OIDC 三要素及 GetCallerIdentity 的账号、RoleId 和精确会话 ARN；不回退永久 AK 或宿主身份。凭据、端点、重试和错误脱敏约束与 [云传输](cloud-fencing.md) 相同。

部署角色只应允许 DescribeDisks，以及本账号、目标地域且匹配 Deployment 标签的 ModifyDiskAttribute 和 DeleteDisk。RAM 权限约束到资源，不能声称它能限制 ModifyDiskAttribute 只修改某一个参数；字段限制由独立客户端的封闭方法保证。读取必须允许按精确 ID 看到属性漂移，禁止用授权标签过滤把错误归属隐藏成空结果。DeleteDisk 则约束本账号/地域 `disk/*` 加 `acs:ResourceTag/Deployment`，工作区与 PVC/PV 身份仍由应用校验。阿里云官方系统策略包含 DeleteDisk 配合 `acs:ResourceTag/...` 的实例；目标账号实际 RAM 边界仍须上线认证。[官方 RAM 策略](https://www.alibabacloud.com/help/en/ram/developer-reference/aliyunservicerolepolicyforeskonecs)

## 两阶段身份校验

1. 控制器先从受保护的资源账与实际 PVC/PV UID、claimRef、CSI driver/volumeHandle、地域/zone/KMS/容量取得 `CloudDiskBinding`，不能直接信任租户传入的盘 ID。
2. `observe_disk(binding)` 校验上述云属性及 Deployment、PVC namespace/name、PV name 标签。完整 present 结果的 `identity()` 固定序列号与创建时间，返回 `CloudDiskIdentity`。
3. 调用者在工作区锁内持久化该不可变身份，确认全部历史写入者已可信终止且已清理，没有 hold/新写入许可，工作区已永久封禁写入。
4. 如果 `DeleteAutoSnapshot=true`，先持久化独立快照保留意图，再调用 `preserve_automatic_snapshots(&identity, attempt_id)`，只提交 `ModifyDiskAttribute(DiskId, DeleteAutoSnapshot=false)`。必须重新查询同一盘并观察到 false，才能持久化真正的删除意图。修改成功回执不替代读回验证。
5. 调用 `delete_disk(&identity, attempt_id)`。客户端重新观察，必须是同一序列号/创建时间且身份属性未漂移、Available、没有任一种正向挂载引用、`DeleteAutoSnapshot=false`。
6. 凭据刷新和共享限速等待后再检查观察不超过 5 秒，只发一次 DeleteDisk，参数仅 DiskId。没有自创 Force、ClientToken 或隐含修改属性调用。

这些限制匹配官方语义：DeleteDisk 只释放 Available 的按量数据盘；不存在的盘请求被忽略；手工快照保留，自动快照是否删除取决于盘属性。本产品在删除前显式关闭自动快照级联删除；无法确认已关闭就不删盘。云端状态检查处理观察之后的挂载竞争；它不会替代写入者终止、CSI 解绑与不可复活门禁。[DeleteDisk 规范](https://www.alibabacloud.com/help/en/ecs/developer-reference/api-ecs-2014-05-26-deletedisk)

阿里云 CreateDisk 默认 `DeleteAutoSnapshot=true`，CSI 创建的正常盘不能因默认值而永久无法删除。保留操作不修改其他属性，成功后仍需新鲜观察；`AlreadyPreserved` 仅表示此轮观察已为 false。`AlreadyAbsent` 只给出观察，不能充当 DeleteDisk 意图，不能凭保留尝试释放存储。[CreateDisk 默认值](https://www.alibabacloud.com/help/en/ecs/developer-reference/api-ecs-2014-05-26-createdisk)、[ModifyDiskAttribute 参数](https://www.alibabacloud.com/help/en/ecs/developer-reference/api-ecs-2014-05-26-modifydiskattribute)。

Available 非共享盘可以省略 InstanceId、MountInstances 等不适用字段，因此缺失字段保持 `INCOMPLETE`，不会被伪造为完整空挂载证明，也不会让正常删除永久等待不存在的字段。任一实际实例引用或正 MountInstanceNum 均阻断删除。序列号、创建时间缺失时不允许固定身份和删除。[DescribeDisks 规范](https://www.alibabacloud.com/help/en/ecs/developer-reference/api-ecs-2014-05-26-describedisks)

## 结果与恢复

| 结果 | 语义与后续动作 |
| --- | --- |
| `Accepted` | 请求有有效成功回执；仍须重新查询精确盘 ID，不能释放资源 |
| `AlreadyAbsent` | 本轮精确查询为空，未发 DeleteDisk；只有账本已保存原始 present 身份与有效删除意图时才能作为后续核验输入 |
| `OutcomeUnknown` | 实际发送后发生断流、5xx、正文超限或回执异常；记录 attempt 和云请求证据，进入核验 |
| `CloudError` | 配置/身份/状态/权限等错误；保留可用证据，输出固定错误码。404 本身不生成 absence，仍要重新查询 |

调用者先持久化 DISPATCHING。取消进程、崩溃或外层超时后即使未返回结果，也按未知派发处理。客户端不会自动重发写请求。控制器如要再尝试，必须保留旧记录、再次检查持久删除权限和工作区墓碑，并重新执行完整身份/状态前检；不能拿旧观察跳过查询。所有结果与 request evidence 字段私有且不开放反序列化，输入身份则仅为预期值。

最终存储释放仍需要独立删除账本关联身份、派发意图、新鲜云 absence、精确 PVC/PV UID 清理与配额事务。仅将磁盘列表为空、DeleteDisk 回执或 Pod 消失转换成 `deleted=true` 不符合该协议。实例 DELETE 保留工作区，数据删除由另一个 API 与权限承担。

## 本地证据与云端门槛

新增 14 项真实 loopback HTTP 协议测试，覆盖：独立 SA/RoleId 与签名、精确参数、序列号/创建时间/全部归属漂移、挂载/快照保护、元数据缺失与非法值、空结果与异常分页、错误/断流不重发、显式重试前再校验、错误与回执不泄露令牌；快照保留精确参数、读回未生效拒绝删盘、未知保留结果不重发和已保留幂等读取。另 16 项已有 fencing/云盘观察测试一起回归。测试不调用真实云接口。

上线仍需目标账号验证 STS 与 RAM 标签边界、Kata/CSI 单写者生命周期、状态竞争、真实删盘后的精确 absence 与 PVC/PV 清理、进程崩溃恢复。没有这些证据，不能将本地协议测试记为生产卷删除验收。
