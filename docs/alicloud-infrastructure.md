# 阿里云生产基础设施交付说明

本包对应 G1-02。已经实现同一套生产资源定义及离线安全约束测试，**没有执行云端 plan/apply，没有创建收费资源，不能据此认定生产环境已安装或通过认证**。用户尚未选定地域、可用区、主机镜像、SKU、企业网段；这些都是必填输入。

## 交付边界与资源

| 文件 | 具体交付 | 需要下一阶段提供的运行条件 |
|---|---|---|
| `infra/alicloud/network.tf` | 独立资源组/VPC；管理控制、平台、Kata、数据四类子网，每类跨三个 AZ；企业地址重叠拒绝；节点 SG 同组隔离、显式最后拒绝出站、按端口允许必要链路 | 企业网络负责人建立到该 VPC 的专线/CEN/VPN 路由并验证双向可达；不会擅自修改企业现有路由 |
| `nodes.tf` | 三台控制、三台平台、每 AZ 至少一台弹性裸金属；固定镜像、加密 ESSD、无公网 IP/实例密码/实例 RAM 角色、删除保护 | 已审查 x86_64 镜像中的内核/KVM/cloud-init/sudo/SSH；后续 Kubespray 安装与版本认证 |
| `ingress.tf` | Kubernetes 6443、产品 443 两个私网 CLB，双 AZ LB、三 AZ 后端，精确源 ACL、TCP 健康检查；TLS 透传 | 真实地域 CLB 主备组合支持；API server 和产品 ingress 自己校验证书、终止 TLS；32443 仅为固定 ingress NodePort |
| `data.tf` | RDS PostgreSQL 17 HA 双 AZ、固定小版本、磁盘 KMS、SSL 开启、hostssl/SCRAM 和最后拒绝规则、日志/数据备份；五个独立 OSS 桶和七个按用途分开的 KMS key | RDS SKU/小版本可售性、SSL/pg_hba 实际生效、密钥云服务授权、ZRS/WORM支持；数据库账号/CA秘密注入与恢复演练 |
| `identity.tf` | Kubernetes workload OIDC provider；十个精确 SA 主体的 RAM 角色及独立策略；fencing 仅能停止本部署登记的 Kata 主机 | Kubernetes issuer/JWKS HTTPS 发布、证书指纹、投射 token→STS 刷新组件、CSI 与策略实际兼容测试 |
| `state-bootstrap/` | 单独的 KMS 加密/版本化私有 OSS state、TableStore 状态锁、专门 CI state 权限 | 安全负责人一次性引导，随后把引导自身的 state 也迁往远端；CI 运维身份和恢复身份事先登记 |

这些资源定义没有安装 Kubernetes、Kata、Cilium、CSI、Keycloak、业务服务、Prometheus/SLS、镜像仓库、SMTP或证书管理器。它们属于紧接着的 G1 安装与验收工作，不因 IaC 校验成功变为已交付。RDS 数据库/数据库角色由受审计的数据库引导流程建立，产品与 Keycloak 分库分角色；Terraform 不创建或保存任何数据库口令。阿里云 provider 的 account password 字段会写入 state，本包因此不把密码藏在 `sensitive` 标签后声称“没有秘密入 state”。

## 输入合同

所有主模块变量均必须显式传入。实际输入保存在 `.local/<environment>.tfvars` 或独立加密配置库，不能用测试中的 fixture 值部署。`*.tfvars`、plan 和 state 已忽略；输入没有凭据字段。

| 变量 | 提交评审的实际值/证据 |
|---|---|
| `region`、`availability_zones` | 一个地域及三个不同 AZ；ECS/裸金属、CLB、RDS、ZRS 的实际支持矩阵和配额截图/API结果 |
| `environment`、`name_prefix`、`cloud_account_id` | production/preproduction；环境唯一前缀；准确账号 ID。真实 plan 会通过 STS caller identity 拒绝错误账号 |
| `vpc_cidr`、`enterprise_cidrs` | RFC1918 /16–/20 VPC；全部企业现有地址。程序派生 12 个不重叠子网并拒绝企业地址冲突 |
| `management_cidrs`、`api_client_cidrs` | 企业 VPN/堡垒/CI 和微服务来源，均必须落在 enterprise_cidrs 内；拒绝 0.0.0.0/0 |
| `host_image_id`、`node_skus` | 固定镜像；control/platform/kata 三种 SKU。Kata 必须为 ecs.ebm 系列，字符串检查不是 KVM 实测证据 |
| `kata_nodes_per_zone` | 至少 1；仅拓扑下限，容量按实测 VM 规格/过载阈值规划 |
| `ssh_public_key` | 企业运维公钥；cloud-init 建立 `platform-admin`，禁密码和 root SSH；私钥不进入模块 |
| `egress_services` | 每个批准的 DNS/NTP/代理/镜像/云接口出口 CIDR、TCP/UDP 和端口；不会自动放行公网。必须包含启动/安装所需依赖，不能给 tenants 复用此代理权限 |
| `load_balancer_spec`、`load_balancer_health_cidrs` | 地域支持的 CLB 规格与已核实健康检查源；不得把任意大网段当默认管理来源 |
| `database` | PG 17 HA 实例规格、容量≥100GiB、固定 RDS minor、维护窗口和保留天数。`17.0` 是产品基线，SKU/具体 minor 在该地域可用仍需查证 |
| `object_retention_days` | output/audit/backup_vault/temporary 各自保留天数；backup_vault≥31天，临传≤7天。WORM Locked 的期限不能缩短 |
| `workload_oidc` | Kubernetes 服务账号 issuer、专用 STS audience、HTTPS CA SHA-1 fingerprint。与产品独立/外部用户登录 issuer 完全分开 |

ECS IMDS 设为 `http_tokens=required`、`http_endpoint=enabled`，保留 cloud-init/CSI 所需的实例元数据；宿主不挂 RAM 角色，因此元数据不分发云权限。镜像必须能使用 IMDSv2。官方 provider 1.293.0 文档把 hop-limit 字段标为尚不可用，本模块没有假装配置它。租户不可达元数据、宿主服务及平台网段必须通过 Cilium/Kata 首包和绕行测试证明，安全组不能取代虚拟机内网络隔离。

节点之间仅开放 kube-apiserver、控制面到 kubelet/admission、控制节点间 etcd、Cilium VXLAN，以及平台控制器到 Kata 宿主 nodeguard TCP 9444 所需连接；没有 VPC 全端口互通。nodeguard 的另一个入口仅限显式 `management_cidrs`，用于 owner 登记；产品 API 客户端网段和 Kata 节点池没有该专用主机端口授权。宿主依然必须验证独立 mTLS 客户端证书。Cilium 的 Pod→宿主策略及受信平台流量 masquerade/路由效果需要实网验证，不能只看安全组计划。固定 provider 1.293.0 将出站 `source_security_group_id` 映射到云 API 的 `DestGroupId`，已核对[对应官方源码](https://github.com/aliyun/terraform-provider-alicloud/blob/v1.293.0/alicloud/resource_alicloud_security_group_rule.go)。当前网络合同固定 VXLAN UDP 8472，必须与安装配置一致。变为 native routing 或额外观测链路时，应先调整并复核实际端口，不允许临时全放行。受信 Pod 访问 RDS 需由 Cilium 的已认证 masquerade/路由设置呈现为平台节点允许地址；不能把 Kata 子网加入数据库白名单来绕过问题。

## 数据保护与身份权限

五桶分别是 `output`、`backup`、`backup-vault`、`audit`、`temporary`。均使用 ZRS、私有 ACL、阻止公共访问、HTTPS-only bucket policy 和独立 KMS key，禁止 Terraform 强制清空。`output/audit/backup-vault` 使用 Locked WORM；`temporary` 自动过期且清理未完成 multipart。输出、备份和审计不会依据一个粗糙的生命周期规则删除仍被产品引用的数据。

`backup` 是 **Restic 可变仓库**，启用版本化，保留锁/索引维护所需当前对象操作，但不给备份角色 `DeleteObjectVersion`。`backup-vault` 是不同角色控制的不可变归档目的地，不能直接替代运行中的 Restic 仓库。**从可变仓库导出可独立恢复的完整归档、发布清单及校验、回收、从 vault 恢复的业务流程仍待备份开发包实现。建桶和 IAM 不代表已有一份可恢复备份。** 本模块隔离同账号中的权限；若验收要求抵御整个云账号失陷，必须增加不同账号的 vault/密钥及复制授权，不能把本模块描述成跨账号灾备。

| 身份 | 云权限 |
|---|---|
| worker / admission / 租户 Pod | 无 RAM 角色；数据库和 K8s 权限另行最小化 |
| output-reader（API 专用） | 精确绑定 sandbox-system:sandbox-api，只 Get/Head `output/tenants/*` 及该 key 的解密；没有 Put/Delete/List |
| file-upload / file-reader | 精确绑定 sandbox-system:sandbox-api，临时桶文件分片前缀内分别 PUT/GET 与 GET；独立 STS 文件，无 List/Multipart/保留管理权限 |
| file-gateway | 精确绑定 sandbox-system:sandbox-gateway，仅临时桶文件分片 PUT/GET；不复用输出 writer 凭据 |
| file-cleaner | 精确绑定 sandbox-system:sandbox-worker，仅临时桶文件分片 DELETE/GET；缺失观察不替代未知 PUT 结束证明 |
| gateway | 本环境 `output/tenants/*` 的 Put/Get 与该 key 的加解密；无删除、无 bucket 管理 |
| backup | 可变 backup 仓库的对象/list/multipart 操作；不能删除历史版本、不能读写 vault |
| backup-export | 读取 backup，写入独立 vault；无 vault 删除 |
| restore | 只读 vault 及相应解密，不能写备份 |
| audit / upload | 分别只写 audit、操作 temporary；不相互借权 |
| csi-controller / csi-node | 分角色；controller 云盘/快照操作必须带本部署 tag，attach 只允许已登记 Kata 主机；node 仅云盘/实例只读 |
| fencing | StopInstance 精确绑定 IaC 中的 Kata instance ARN；无法停止平台/控制节点、启动节点或删盘；必要 Describe API 是只读通配资源 |

OIDC 信任同时固定 issuer/audience/subject，不接受 namespace 通配或“所有已认证主体”。服务账户名称固定在输出中；安装器应照此创建，不能拿产品用户 token 交换云凭据。投射 token→STS 侧车/刷新器须落地并测过期后失败关闭，环境变量里永久 AK 不是替代方案。当前 CSI 策略是基于官方磁盘驱动权限清单进一步收窄的具体策略，未授与任意资源打标/移除标签、snapshot group、NAS 或 CPFS 权限。**G1 必须验证锁定 CSI 版本在 CreateDisk/CreateSnapshot 时确实提交 Deployment 标签，验证跨环境磁盘操作被拒、合法创建/挂载/快照成功；失败时保留拒绝，修正驱动配置/确切策略后重测，不能把策略扩大为 ecs:*。** IMDS 发现、STS 凭据、加密 key、CSI 节点属性和存储身份都是该验收的一部分。

## 安装、状态与变更流程

1. 安全负责人选择实际账号/地域，确认预算、权限、配额和企业网络接入方案。拿到输入及完整 plan 后才执行云部署。本次没有执行这些步骤。
2. 先在 `state-bootstrap` 使用短期 STS 安全身份创建独立状态基础设施。首次 local state 仅保存在受限加密工作目录，立即备份；引导后把其 state 迁到自己的专用远端 prefix。业务环境与状态基础设施不能共用销毁流程。
3. 将输出填入 `.local/<environment>-backend.hcl`，至少包含 `bucket`、`region`、`prefix`、`key`、`tablestore_endpoint`、`tablestore_table`、`encrypt=false`、`acl="private"`。`encrypt=false` 不代表明文：OSS bucket 的 KMS 默认加密生效；Terraform OSS backend 的 `encrypt=true` 会显式要求 AES256，覆盖该默认，不能误用。创建首个 state 后必须用 HeadObject 证明实际为目标 KMS key。
4. CI 工作负载身份只注入短期凭据，不把 AK/STS 写入 backend HCL、tfvars、plan 注释或日志。生产与预生产分 bucket/prefix、TableStore 锁、CI role 和审批环境；不得只靠 Terraform workspace 名隔离。
5. 用锁定版本执行 `init -backend-config=<path>`、`plan -var-file=<path> -out=<private path>`；保存 plan 的摘要、变更列表、版本、审批和输入摘要。审批后只执行该保存的 plan，禁止临时 `-target` 绕开依赖。
6. 创建云资源后，通过企业管理路径导出节点 inventory 给已锁版本的 Kubespray；完成 TLS/身份/数据库凭据引导及 G1 认证后再安装和放行业务入口。当前 CLB TCP 存活探测不是应用、数据库或隔离健康证明。

已启用 VPC/ECS/RDS/OSS/KMS `prevent_destroy` 及相应云删除保护。镜像变更强制形成替换计划，避免 provider 默认行为直接替换运行节点系统盘。普通 apply 不能完成破坏性升级；节点替换应先扩建已认证节点、排空/确认旧 VM 终止、确认备份，然后执行经过双人审查的精确生命周期调整。账单欠费、账号管理员和云外操作不受 Terraform 的 prevent_destroy 保护。

日常 drift 检查采用只读 plan（`-detailed-exitcode`），退出码 2 进入人工审查，不能自动把未知云侧变更“修回去”。恢复 state 时先冻结所有部署任务、核对锁持有者与任务存活，再用具有历史版本只读权限的独立 break-glass 身份取回已审计的 object version；备份当前 state，核对 lineage/serial/resource IDs，生成修复 plan，审查通过再恢复部署。`force-unlock` 只限证明持有者已终止且记录事件后；不能通过删除锁表或关闭锁来解冲突。WORM 和密钥保留不允许通过 break-glass 提前缩短。

## 本地验证与验收证据

```bash
python3 infra/alicloud/install-terraform.py
TF_BIN="$PWD/.local/tools/terraform-1.14.7/terraform" infra/alicloud/check.sh
```

2026-10-03 实际在 macOS arm64 完成：

- Terraform 1.14.7 官方 archive 与 SHA256SUMS 比对一致；darwin_arm64 SHA256 为 `e9004e245b3e56bff9c7a6c572295d710f6ce4fc72e3910e99519ebdcb46d1bb`。`toolchain.lock.json` 同时固定 Linux/macOS 两种架构的官方包 checksum。此次没有独立 GPG 验证 Terraform CLI 签名。
- `terraform init -backend=false` 从官方 Registry 安装 alicloud 1.293.0，provider 签名验证成功（partner key `47422B4AA9FA381B`）；拒用 Registry 返回的 2.0 beta。`.terraform.lock.hcl` 保存官方完整发布 checksum 与当前平台 h1。版本固定表示可重现，不表示最新版本或云组合已认证。
- 主模块、state-bootstrap 均 `terraform validate` 通过；共 **11 个原生 mock-provider plan 测试通过（9+2）**，包括错误云账号、地址冲突、公共管理入口、非裸金属、错误 AZ、错误 OIDC、数据加密、强制 TLS 配置、可变仓库/WORM 分离及 state 锁结构。检查脚本不调用真实 provider 数据面；mock 使用真实 provider schema，但不会验证云产品业务限制。
- 源码无云凭据、私钥、数据库密码。未执行真实云 plan、apply、destroy、实例启动或付费申请。真实 Linux CI 可使用同一安装/检查命令；本次实际执行平台仅为 macOS arm64。

上线前仍须取得以下证据，任一缺失都不能给环境出具生产认证：

| 验收 | 必须保存的结果 |
|---|---|
| 空账号资源与重跑 | 地域/SKU/三 AZ/KMS/ZRS/CLB兼容及配额；真实 apply 后第二次 plan 无意外变化；VPC企业路由和DNS/NTP/镜像/STS出口均可达 |
| 安全网络 | 非管理源不能 SSH/kube/API；Kata 子网无法访问 DB；无公网IP；租户到IMDS/宿主/平台/其他租户拒绝；所需可信链路成功 |
| RDS | 客户端 verify-full 成功，错误CA/主机名和 `sslmode=disable` 均失败；SCRAM/最小数据库角色；强制故障切换和独立 PITR/备份恢复 |
| 云身份 | 正确 SA 交换 STS；错误 issuer/audience/subject/过期凭据失败；gateway删输出、backup删历史版本、CSI跨环境卷操作、fencing停控制节点均拒绝 |
| OSS/KMS | HeadObject验证SSE-KMS正确key；匿名/HTTP拒绝；WORM期限内删除失败；临传到期清理；恢复身份可读；密钥轮换后旧数据可恢复 |
| 状态恢复 | 两并发plan/apply验证锁互斥；错误账号阻断；从真实历史state version恢复，证明没有依靠直接编辑资源ID或跳过锁 |
| 沙箱底座与备份 | Kata/Cilium/CSI完整组合、分区防双写/可信终止、归档导出与删源独立恢复、容量和72小时稳态测试。均不是本包离线测试覆盖范围 |

## 核对过的官方资料

- [固定 provider 1.293.0 ECS 文档](https://github.com/aliyun/terraform-provider-alicloud/blob/v1.293.0/website/docs/r/instance.html.markdown)：IMDS、镜像替换、加密磁盘、网络字段。
- [固定 provider RDS 文档](https://github.com/aliyun/terraform-provider-alicloud/blob/v1.293.0/website/docs/r/db_instance.html.markdown)与[阿里云 PostgreSQL 强制 SSL](https://www.alibabacloud.com/help/zh/rds/apsaradb-rds-for-postgresql/forcefully-enable-ssl-connections-on-the-client)：启用 SSL 本身不禁止非 SSL，必须配置访问规则。
- [OSS Bucket WORM](https://www.alibabacloud.com/help/en/oss/user-guide/oss-retention-policies)、[OSS 服务端加密](https://www.alibabacloud.com/help/en/oss/user-guide/server-side-encryption-8)：保留与加密真实边界。
- [RAM OIDC 信任条件](https://www.alibabacloud.com/help/en/ram/implement-oidc-based-sso-from-okta)、[资源标签授权](https://www.alibabacloud.com/help/en/resource-management/tag/user-guide/use-tags-to-control-access-to-resources-1)、[StopInstance 资源范围](https://www.alibabacloud.com/help/zh/ecs/developer-reference/api-ecs-2014-05-26-stopinstance)。
- [CSI 磁盘权限源文件（固定提交）](https://github.com/kubernetes-sigs/alibaba-cloud-csi-driver/tree/d340dba7bbd8e3319b16c80e822ecaa7901d2c7c/docs/ram-policies/disk)：本包未照搬其中的所有资源通配写权限，支持子集仍须实机验证。
- [Terraform OSS backend](https://developer.hashicorp.com/terraform/language/backend/oss)、[mock provider](https://developer.hashicorp.com/terraform/language/tests/mocking)、[CLI 固定发布页](https://releases.hashicorp.com/terraform/1.14.7/)：远端锁/加密参数、测试能力及下载来源。

输出读取角色中 `oss:GetObject` 同时授权 GetObject 和 HeadObject；没有虚构 `oss:HeadObject` action。依据[官方 HeadObject 权限表](https://www.alibabacloud.com/help/en/oss/developer-reference/headobject)，读取 SSE-KMS 输出同时需要精确 key 的 `kms:Decrypt`。IAM 的 tenants/ 前缀是组件权限上限，具体租户/项目仍由已认证 API 和数据库授权约束。
