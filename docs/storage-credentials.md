# 存储工作负载凭据

`sandbox-credentials` 为 API、gateway、worker 分别轮换短期 STS。它不连接数据库、不使用 Kubernetes 客户端、不读取环境 AccessKey，也不回退到 ECS 元数据身份。组件范围是 API 的 `file-upload`、`file-reader`、`output-reader`，gateway 的 `file-gateway`、`gateway`，worker 的 `file-cleaner`。

## 身份与失效

配置固定部署、账号、地域、purpose、RAM RoleId、集群 issuer、投射 token 路径和输出路径。角色 ARN、OIDC provider、audience 和 service-account subject 由代码按组件派生，不能用配置替换成其他账户或管理员角色。示例：

```json
{
  "deployment": "部署name_prefix",
  "account_id": "真实16位账号ID",
  "region": "cn-hangzhou",
  "purpose": "file-reader",
  "role_id": "Terraform输出的真实RoleId",
  "oidc_issuer": "https://实际集群issuer",
  "oidc_token_file": "/var/run/storage-oidc/token",
  "output_file": "/run/sandbox-cloud/file-reader/private/sts.json"
}
```

输出的父目录必须为 `private`，当前运行 UID 所有、0700、不允许符号链接。整个进程持独占文件锁；竞争进程失败不能删除已有凭据。写入 0600 临时文件、fsync、原子 rename 和目录 fsync，消费者不会读到半个 JSON。投射身份链接可轮换；打开后检查普通文件、权限与长度，FIFO 无法阻塞读取。

每次刷新重新读取投射 token，按官方 [AssumeRoleWithOIDC 协议](https://www.alibabacloud.com/help/en/ram/developer-reference/api-sts-2015-04-01-assumerolewithoidc) 申请 900 秒凭据，再签名调用 GetCallerIdentity。issuer/subject/audience、账号、角色 ARN、RoleId、会话及到期时间全部相符才发布。共享已有受限 cloud transport，不复制签名算法。请求固定地域 STS，HTTPS、无代理/重定向，单次尝试 8 秒、整次刷新 45 秒有界。约 5 分钟轮换；刷新失败立即删除可用文件并有界退避，日志不输出 token 或响应。SIGTERM 后移除凭据；初始化 `--once` 成功会保留文件。`--check` 只读验证文件、权限与剩余至少 120 秒寿命。

失效移除不证明先前发出的 OSS PUT 已停止。未知写入仍按[文件账本合同](file-transfers.md)占用额度，不借 STS 到期释放。

## 组合到部署

`deploy/storage-credentials/credentials.py` 接收经过评审的 trusted Deployment 和来自 IaC 的非秘密身份输出，生成新的 ConfigMap 与 Deployment JSON List。它不调用集群、不覆盖旧输出、不修改云资源。只接受准确 `sandbox-system/sandbox-api|gateway|worker`、platform 节点池、固定镜像 digest、10001 UID/组、只读根文件系统和无默认 API token 的模板；拒绝 guest、管理员角色、重复组合与挂载冲突。

输入字段为 `deployment`、`account_id`、`region`、`workload_roles`；每个角色记录含 IaC 输出的 `arn`、`role_id`、`subject`、`issuer`、`audience`。

```sh
python3 deploy/storage-credentials/credentials.py \
  --deployment /absolute/reviewed-api-deployment.json \
  --inputs /absolute/reviewed-storage-identities.json \
  --component api --output /absolute/new-api-with-storage.json
```

生成 [Kubernetes 原生 sidecar](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/)：位于 initContainers、`restartPolicy: Always`，startup probe 等首次有效凭据后启动应用，readiness 在凭据失效时使 Pod 不就绪，退出顺序使应用先结束。投射 token audience 为 STS、600 秒，仅挂载到凭据进程；每个 purpose 单独 Memory emptyDir，应用只读挂载。配置不可变且名字含摘要，RoleId/issuer 变动产生新部署修订。

API/gateway/worker 的文件配置路径使用 `/run/sandbox-cloud/<purpose>/private/sts.json`。输出 reader 使用 `/run/sandbox-cloud/output-reader/private/sts.json`，输出 writer 使用 `/run/sandbox-cloud/gateway/private/sts.json`。DB/Kubernetes权限、文件 bucket/KMS、私网 DNS/STS/OSS 出口、API/worker可用性探针仍由产品安装器提供；此组合器不伪造这些配置或生产证据。

## 验收

2026-10-08：六项原生 Rust/真实 TCP 验证覆盖签名调用者、错误主体/账号/RoleId/到期拒绝、强制重新换会话、独占写锁、原子替换、投射轮换、世界可读拒绝、FIFO、撤销和清理；四项 renderer 负例、六个原生 Kubernetes 对象的官方 schema 校验、23项发布协议测试通过。真实 RAM/STS、集群 sidecar 启停/节点重启和云密钥轮换尚待目标环境，不计为已完成生产部署。
