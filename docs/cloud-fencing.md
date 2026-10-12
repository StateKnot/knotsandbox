# Alibaba Cloud 停机传输适配器

`src/cloud_fencing.rs` 实现固定资源范围的 ECS 查询与强制停机调用，以及工作负载 OIDC 换取短期 STS 凭据。它返回可追踪的云请求观察记录，**不生成可信隔离证明，也不连接终止账本、资源释放或对外 HTTP API**。生产终止完成器目前仍使用 [可信终止协议](trusted-termination.md) 的主机与卷清理证据。

## 能证明什么

`StopInstance` 是异步操作，成功响应只表示请求受理；`ForceStop=true` 可能丢失未写入磁盘的数据。本实现显式传 `StoppedMode=KeepCharging`，避免隐含释放计算库存。该操作当前请求规范没有 `ClientToken`，本地 `attempt_id` 仅用于关联记录，不能提供云侧幂等保证。[官方 StopInstance 规范](https://www.alibabacloud.com/help/en/ecs/developer-reference/api-ecs-2014-05-26-stopinstance)

`DescribeInstances=Stopped` 是一次观察，之后仍可以调用 `StartInstance`。其他 RAM 主体、运维自动化或伸缩活动可能重新启动旧宿主机。因此 `Accepted`、`AlreadyStopped`、`OutcomeUnknown` 均不能释放活动槽、计算配额或存储配额，不能把工作区重新交给其他写入者。[官方 StartInstance 规范](https://www.alibabacloud.com/help/zh/ecs/developer-reference/api-ecs-2014-05-26-startinstance)

客户端没有删除实例、启动实例或重启实例的方法。删除实例具有不可逆及关联磁盘删除语义，不能作为停机失败后的自动重试路径；当前部署的删除保护与 RAM 权限也不能被本模块绕过。[官方实例释放说明](https://www.alibabacloud.com/help/en/ecs/user-guide/release-an-instance)

独立的[节点事故控制器](node-fencing.md) 已实现持久节点/云实例墓碑、禁止重新登记、单次云派发及未知结果记录。它仍不能仅凭 `Stopped` 释放资源；完整云隔离完成器还须结合可核验的旧写入者终止与卷清理证据，并认证全部重新启动/自动化入口的约束。仅增加一个 `fenced=true` 或轮询若干次 `Stopped` 不满足这一要求。传输适配器本身不提供资源释放状态或回调。

## 部署输入与身份

一个 `AlibabaCloudFencing` 对象绑定一个云账号、地域和 RAM 角色。配置来源应是经审查的 IaC 输出与节点登记清单，禁止从租户请求直接构造。

| `CloudFencingConfig` 字段 | 来源与约束 |
| --- | --- |
| `account_id`, `region` | `infra/alicloud` 的 `deployment_identity`；全生命周期固定 |
| `role_arn`, `role_id` | `workload_roles.fencing.arn` 与 `.role_id`；账号必须与配置一致 |
| `oidc_provider_arn` | 该账号已创建、已审查的 RAM OIDC provider ARN |
| `oidc_issuer`, `oidc_audience`, `oidc_subject` | 同一 `workload_roles.fencing` 输出；与工作负载 issuer、专用 ServiceAccount 及 projected-token audience 一致 |
| `oidc_token_file` | 绝对路径的短期 projected token；打开后的文件须是普通文件、Unix 权限为 `0400` 或 `0600`；支持原子投射符号链接 |
| `instances` | 固定实例 ID、VPC ID、私网 IP 与 `Deployment` 标签；实例 ID 不允许重复，最多 10,000 个 |
| `requests_per_second` | `1..20`；同对象所有 clone 共用，包括 STS、身份查询、实例查询和停机 |
| `max_in_flight` | `1..16`；超出即时返回 `OVERLOADED` |

`alicloud_ram_role.role_id` 来自锁定的 `aliyun/alicloud 1.293.0` provider 的 computed string 字段，不是 Terraform 资源名称 `id`。机器角色的 Stop 权限仅限该部署 Kata 节点的精确资源 ARN；现有 IaC 查询权限使用 `Resource=*`，客户端进一步强制单个已登记实例范围。本适配器不申请或修改 RAM 权限。

只接受标准地域端点 `https://sts.<region>.aliyuncs.com/` 和 `https://ecs.<region>.aliyuncs.com/`；生产构造函数不接受任意 URL，禁用代理和重定向。专有云、金融云及需要特殊端点映射的地域尚未纳入当前部署支持范围。

凭据通过匿名 `AssumeRoleWithOIDC` 获取，期限请求为 900 秒；响应中的 issuer、subject、单一 audience、验证结果、角色会话 ARN 和有效期都要匹配。随后使用该 STS 凭据签名调用 `GetCallerIdentity`，核对 `IdentityType=AssumedRoleUser`、账号、会话 ARN 与 `RoleId`。`PrincipalId` 不代替角色 ID。缓存进入到期前 90 秒即刷新，多并发只进行一次刷新；失败后不回退到旧凭据、环境变量永久 AK 或宿主机实例角色。[官方 OIDC 换取 STS 规范](https://www.alibabacloud.com/help/en/ram/developer-reference/api-sts-2015-04-01-assumerolewithoidc)、[官方调用者身份规范](https://www.alibabacloud.com/help/en/ram/developer-reference/api-sts-2015-04-01-getcalleridentity)

## 调用与错误契约

`observe(instance_id)` 只查询配置内的实例，使用单个 `InstanceIds`、固定 `RegionId`，不加状态过滤。返回必须恰好一条，不能带后续分页；同时核对实例 ID、地域、VPC 网络类型、VPC ID、预期私网 IP、`Deployment` 与 `Role=kata` 标签。Token分页下的TotalCount按官方合同不作为判定依据。标签不能单独证明实例身份；重复标签键、错绑资源、未知状态均拒绝。[官方 DescribeInstances 规范](https://www.alibabacloud.com/help/en/ecs/developer-reference/api-ecs-2014-05-26-describeinstances)

`observe_disk(binding)` 提供同一身份链下的只读云盘与挂载观察，合同和权限见[云盘观察](cloud-disk-observations.md)。它不执行卸盘、删盘或释放配额。

删盘由[独立卷删除客户端](cloud-volume-deletion.md)承接，使用另一 ServiceAccount、RAM 角色和持久授权链。该能力不添加到 `AlibabaCloudFencing`，也不扩展 fencing 角色的云写权限。

`force_stop(instance_id, attempt_id)` 先完成上述查询和凭据检查，实际发令前再次检查观察年龄不超过 5 秒。它只发一次 `StopInstance`，并关闭 HTTP 客户端的内部自动重试。调用者接入持久完成器时必须先提交 `DISPATCHING` 与固定 `attempt_id`，调用一次；进程崩溃、任务取消或返回未知结果时只进入核验流程，不能按相同或新请求 ID 自动再次发令。

| 返回值 | 含义 |
| --- | --- |
| `Accepted` | 2xx、有效 RequestId 且无错误 Code；仍需后续观察 |
| `AlreadyStopped` | 本次前置查询为 Stopped，本次未发停机请求 |
| `OutcomeUnknown` | 请求已尝试发送后遇到传输失败、服务端错误、正文截断/超限或无有效成功回执；不能自动重发 |
| `CloudError` | 固定错误码与可用的请求证据；不返回云厂商 Message、HTTP URL 或底层异常文本 |

读请求与 OIDC 换取最多尝试 3 次，只对传输失败、429、5xx 或厂商节流码做有界退避。整数秒 `Retry-After` 在 10 秒内被遵守，429 的短期冷却同对象共享；更长延迟返回节流错误，交给上层调度。Stop 从不执行该重试逻辑。连接超时 3 秒，单请求超时 8 秒，完整观察最多 45 秒，响应正文上限 1 MiB。

`CloudRequestEvidence` 包含固定 action、本地请求 UUID、厂商 RequestId、发送/接收时间、HTTP 状态及非凭据响应 SHA-256。厂商 RequestId 按有界无控制字符的 opaque string 保留，不假设 UUID 格式。证据结构字段私有、仅可序列化；它是传输记录，不是可由外部 JSON 构造的可信终止证明。

## 凭据与日志

签名采用 ACS3-HMAC-SHA256，测试使用阿里云完整官方向量校验 canonical request、RFC3986 编码、header 排序及最终签名。[官方 V3 签名规范](https://help.aliyun.com/en/sdk/product-overview/v3-request-structure-and-signature)

OIDC 匿名换取遵循官方 SDK 的 POST RPC query 参数形状；query 中包含 OIDC token。因此生产组件必须使用 `logging::init()` 的不可覆盖依赖过滤：无论 `RUST_LOG` 如何配置，都禁止 reqsign、reqwest、hyper、hyper_util、h2、http_body、http_body_util 的 URL、帧和凭据诊断日志。Authorization 与安全令牌 header 另标记 sensitive，内部凭据及客户端不实现 Debug，错误也不保留底层带 URL 的异常。禁止外部代理或调用方再次打印请求 URL、请求正文与凭据响应。[官方 STS SDK 实现](https://github.com/aliyun/alibabacloud-python-sdk/blob/master/sts-20150401/alibabacloud_sts20150401/client.py)

## 验证边界

本地测试使用真实 HTTP listener 和模拟官方响应，覆盖签名向量、官方 OIDC 时间格式、STS 并发刷新、账号/身份/实例/网络绑定拒绝、节流重试、凭据刷新失败、过期前置观察、响应超限、重定向拒绝、未知停机结果不重发，以及日志敏感 marker 不泄露。未执行真实云停机、启动或删除请求，未申请永久 AK。

上线云隔离完成器前，仍须在受控测试账号完成实际 OIDC 信任、RAM 资源范围与客户端标签校验、区域 API 兼容和云控制面故障演练；完成持久隔离协议及验收后才能让云证据参与释放资源。当前 API 的可用能力声明不包含已完成云隔离。
