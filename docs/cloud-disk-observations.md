# 云盘身份与挂载观察

`src/cloud_disks.rs` 复用 STS 身份校验、固定 ECS 地域端点、ACS3 签名、共享限速、读取重试和响应上限，只实现 `DescribeDisks`。该模块没有卸载、删除或重新挂载方法，不释放存储配额。独立身份的 [卷删除客户端](cloud-volume-deletion.md) 也使用该只读实现；fencing 客户端仍无删盘方法和权限。

`observe_disk` 接受来自可信资源账与部署配置的 `CloudDiskBinding`。账号、地域、部署归属必须匹配客户端配置；精确云盘 ID 来自已持久记录的 CSI volumeHandle，PVC/PV 名称来自同一已核验 launch，不能用租户请求任意替换。调用方仍须验证 PVC/PV UID、claimRef 和 CSI driver；云标签不会替代这些身份。

请求仅发送单个 DiskIds、RegionId 与 MaxResults，不用状态、标签、Zone、加密或实例过滤器，以免把属性漂移隐藏成“没有磁盘”。响应必须没有后续分页，磁盘数组只能包含零项或一项。Token 分页的 TotalCount 不作为判断依据；阿里云明确说明此时其值无意义。[DescribeDisks 官方规范](https://www.alibabacloud.com/help/zh/ecs/developer-reference/api-ecs-2014-05-26-describedisks)

存在的磁盘必须精确匹配 ID、地域、可用区、容量、KMS key、Deployment 标签和三项 PVC/PV 标签，并且为 `data / cloud_essd / PostPaid / Portable / Encrypted`、不随实例删除、未开启 MultiAttach。其他云盘类别不在当前 StorageClass 合同内。PVC/PV 标签由锁定 CSI 版本的 `--extra-create-metadata=true` 与驱动创建逻辑写入；不能仅按磁盘名称猜测工作区。[CSI 标签解析源码](https://github.com/kubernetes-sigs/alibaba-cloud-csi-driver/blob/v1.37.2/pkg/disk/utils.go)、[固定 chart 的 provisioner 配置](https://github.com/kubernetes-sigs/alibaba-cloud-csi-driver/blob/v1.37.2/deploy/charts/alibaba-cloud-csi-driver/templates/controller.yaml)

| 挂载观察 | 判断 |
| --- | --- |
| `PRESENT` | InstanceId、Attachments、MountInstances 任一仍有实例，或 MountInstanceNum 大于0 |
| `EXPLICITLY_EMPTY` | InstanceId 明确为空、两类列表明确为空、MountInstanceNum 明确为0 |
| `INCOMPLETE` | 没有发现引用，但至少一项缺失或为null；不把缺字段补成空列表 |

状态字段独立记录，因此 `Available + PRESENT` 仍然是挂载引用存在，`In_use + EXPLICITLY_EMPTY` 也不能当作可复用卷。正常 Available 非共享盘可以省略不适用的挂载字段，`INCOMPLETE` 不等于可复用或已终止，也不能单独成为删盘资格；独立删盘流程以可信旧 VM 终止/清理、永久工作区墓碑、精确身份、新鲜 Available 观察和云 DeleteDisk 原子状态检查共同约束。目标地域实际响应仍需认证。空查询返回 `ABSENT` 观察记录，缺 Disks/Disk、正文异常、权限失败或未结束分页均不能生成它。

响应可携带 `SerialNumber` 与 `CreationTime`；字段存在时严格解析。`observation.identity()` 只在二者完整时生成 `CloudDiskIdentity`，用于先登记再删除时固定云盘身份。旧版只读观察兼容缺失元数据，但不能据此登记删除身份。Binding/Identity 可从受保护的持久账本反序列化，未知字段拒绝；它们只表示预期值，不是外部提交即可相信的证明。

观察结果只能由客户端构造，不能从外部 JSON 反序列化成可信结果；记录精确绑定、云请求 ID、时间和响应摘要。`Available`、`EXPLICITLY_EMPTY` 与 `ABSENT` 都不是完整终止、永久解绑或删除证明：完成器还必须消费持久删除意图、启动门禁、旧 VM 证据、Kubernetes/CSI 精确身份与清理事实，并防止迟到挂载。该读取模块本身不执行这些完成器。

IaC 为 fencing 角色增加本账号、本地域 `disk/*` 的只读 DescribeDisks，仍不授予 DetachDisk、DeleteDisk 或磁盘修改。API 不支持本模块需要的标签授权过滤，因此读取后仍精确检查归属。实际云盘单写者和删除验收尚未执行。

验证使用本地真实 HTTP 协议替身，覆盖绑定/标签/容量/KMS 漂移、四种挂载表达、字段缺失/null、空结果、分页和非法配置无网络访问；没有调用真实云盘接口。
