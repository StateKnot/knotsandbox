# 工作区卷销毁控制器

独立进程 `sandboxd --role volume-deleter` 消费平台已受理的工作区删除，不提供租户可调用的云删除代理。数据库身份为 `sandbox_volume_deleter`；云身份与 API、CSI、fencing 完全分离。生产安装使用 [生成器与激活顺序](../../docs/volume-installation.md)；本目录原来的 `workload.yaml`、`rbac.yaml` 和 `config.example.json` 保留为协议参考，不能直接 apply。

1. 应用本版本完整迁移及 `scripts/sql/volume-deleter-role.sql`，分别由 DBA 创建独立 LOGIN、Secret 和验证服务器证书的数据库 URL。Secret `sandbox-volume-deleter-database` 的 `url` 使用 `sslmode=verify-full&sslrootcert=/etc/sandbox-db/ca.crt`，ConfigMap `sandbox-database-ca` 提供实际 CA；不要把凭据写入模板或 Git。
2. 从 Terraform `workload_roles["volume-deleter"]` 输出填写 `config.example.json` 的实际账号/地域/role ARN/role ID。工作负载 OIDC 必须已部署并通过真实 STS 验证；`cloud.oidc_audience` 与 projected token audience 完全一致。StorageClass、区域列表、KMS、Deployment 标签和认证引用必须与已认证的集群配置一致。cloud/storage 两处 Deployment 均为同一精确值。
3. 先创建 ServiceAccount，取得其真实 Kubernetes UID，填入 `deploy/admission/config.example.json` 的 `volume_deleter`，并更新已开启 apiserver mTLS、failurePolicy=Fail 的 admission 配置及 PVC/PV 规则。先确认 worker/CSI 身份不能直接删除受保护卷，再启用控制器。配置中不填该身份会拒绝删除。
4. 为每个已登记项目渲染 `rbac.yaml` 最后一组 Role/RoleBinding 的实际 namespace。ClusterRole 只允许读 StorageClass `sandbox-workspace`；若受控安装更换名字，应同步该唯一 resourceName。控制器无 attach/detach、Pod/Job 创建或 finalizer patch 权限。PV/PVC DELETE 仍必须通过数据库云缺盘证据准入。
5. 创建名为 `sandbox-volume-deleter-config`、键为 `config.json` 的 ConfigMap，填写已扫描/验证镜像 digest 与 audience 后应用 `workload.yaml`。进程仅安排平台节点，没有 workload Kata 节点 toleration；用既有受控平台出口策略连 PostgreSQL、Kubernetes API、区域 STS/ECS。不要用任意互联网出口替代经过认证的网络路径。

此进程不开放健康 HTTP 端口。启动即验证数据库角色/迁移和配置；运行中的依赖故障保留操作与配额并输出固定错误码。进程存活不能作为销毁成功，运维须监控操作 age、WAITING_OPERATOR_REVIEW、云权限/身份错误、实际队列进展。两副本通过数据库租约协调；中断后先查询原盘再恢复。部署 YAML/schema 和 Terraform mock 测试不等于真实云盘销毁验收。

行为、数据保留和人工恢复参见 [完整协议](../../docs/workspace-deletion.md)。此目录不会执行云 apply、真实 DELETE 或申请付费资源。
