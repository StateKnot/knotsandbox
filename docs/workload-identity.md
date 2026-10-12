# Kubernetes 工作负载 OIDC 与阿里云 STS

本包连接自管 Kubernetes ServiceAccount 签名、公网 discovery/JWKS、RAM OIDC 信任与 CSI 工作负载。它不复用产品 Keycloak、不创建永久 AK，也不读取或复制 Kubernetes `sa.key`、用户或客户端私钥。公开源站只提供两个 JSON 路径，没有 Kubernetes 代理、登录、令牌签发或云资源操作接口。

实现已提供工具、独立源站 IaC、离线软件制作入口和安装 playbook；本次只做本地测试、语法与 mock-provider 验证，**没有部署公网源站、修改 DNS、创建真实验收 Pod 或请求真实 STS**。目标域名、证书、云账号及目标集群验收仍需在实际环境完成。

## 身份与发布合同

每个集群固定一个独立根域 issuer，例如 `https://workloads.example.com`；当前工具不接受路径前缀、非 443 端口、IP issuer 或 HTTP。所有 kube-apiserver 都必须实际运行下列参数，导出器从每个控制节点的 mirror Pod 核实，而不是相信配置声明：

```text
--service-account-issuer=https://workloads.example.com
--service-account-jwks-uri=https://workloads.example.com/openid/v1/jwks
--service-account-max-token-expiration=3600s
--service-account-extend-token-expiration=false
```

Kubernetes 官方提供 `/.well-known/openid-configuration` 与 `/openid/v1/jwks`，并支持将 `jwks_uri` 指向公开缓存端点。因此无需开放公网 Kubernetes API。签名与验证仍由 Kubernetes 完成；导出工具只读取公开元数据、Node 状态和 kube-apiserver mirror Pod 的指定参数。[Kubernetes 服务账号发现说明](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#service-account-issuer-discovery)

`extend-token-expiration=false` 防止兼容模式把投射令牌延长到远超请求期限。现存的长期 Secret token 或切换参数前已经签发的长寿命 token 不会因此提前失效；迁移已有集群必须先清理这类使用并核实最长有效期，不能按新配置的 1 小时直接退休旧密钥。[kube-apiserver 参数](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

复制 `deploy/workload-identity/config.example.json` 为受控本地配置并替换全部示例值。`config.schema.json` 拒绝未知字段。账号、地域、OIDC provider ARN、角色 ARN/RoleId、subject、issuer、audience 来自已审批 IaC 输出；`deployment` 与 `cluster_epoch` 来自相同平台初始化记录。工具不会代替数据库 bootstrap 创建或修改 epoch。

`control_plane_contexts` 与 `control_plane_nodes` 一一对应，至少三个；每个 kubeconfig context 必须直接指向该 Terraform 控制节点的私网 IP:6443，使用可信 CA 验证，不能指向同一个负载均衡器或设置 `insecure-skip-tls-verify`。控制节点名称/IP/实例 ID 与已生成的完整 `installation.json` 快照绑定；统一安装校验器复核inputs/inventory/lock及已生成资源摘要、业务约束和确定性库存，拒绝可编辑side file漂移或仅库存摘要的旧目录。导出器逐节点检查 Node UID、Ready、InternalIP、mirror Pod UID、就绪状态和以上四个参数，再要求全部公钥集合与 discovery 完全一致。

导出产物不包含 Pod spec、环境变量、kubeconfig、令牌或私钥。仅允许 RS256、2048–8192 位 RSA 公钥、指数 65537 和固定 JWK 公共字段；任何 `d`/`p`/`q`/未知字段、重复 kid、同 kid 换公钥、错误 issuer 或不一致签发器都被拒绝。

## 独立公网源站，从零准备

`deploy/workload-identity/infra` 是独立 Terraform 根模块，复用主工程固定的 Terraform 1.14.7 与 alicloud 1.293.0。它需要明确账号、地域、VPC、两个不同 AZ 的子网、资源组、实例规格、镜像 ID、KMS key、运维公钥、受限 SSH 网段与可信 NTP IP；没有可直接购买资源的示例 tfvars。模块创建两台独立静态源站，公网仅开放 TCP443，SSH 限定到管理网段，默认拒绝主动出口，NTP 仅访问声明的地址；磁盘加密、实例删除保护及 prevent_destroy 均开启。不挂载 RAM 角色、业务数据、Kubernetes 凭据或共享 OSS 桶。cloud-init 使用 IMDSv2 获取只含运维公钥的 user_data，不授予云访问凭据。

目标基础镜像须是固定 ID 的 Ubuntu 24.04 官方云镜像，带 cloud-init。软件制作入口 `prepare-host.py` 在**隔离的同一基础镜像副本**上执行；它拒绝已有 `/etc/kubernetes` 或活跃 issuer 发布目录的机器。

1. 用 `apt-cache policy` 审核 nginx、python3.12、python3.12-venv、openssl、openssh-server、ca-certificates、chrony 的精确安全更新版本，填写 `package-versions.template.json` 的全部 null 与固定 NTP IP。模板本身不能执行。
2. 在临时制品构建 VM 上运行 `freeze`。APT 强制认证索引与包，不允许不可信仓库；只下载精确版本和所需依赖，不修改已安装包。产出全部 `.deb`、版本与 SHA-256 清单、CPU 架构及原始 dpkg 状态摘要。
3. 在同一基础镜像的干净副本上，以已审阅的清单 SHA-256 运行 `install`。它验证基础包集合、架构和每个包 hash 后离线安装，核对实际版本，设置声明的 NTP 服务器，并停用尚未配置 TLS 的 nginx。构建期间不生成、不复制任何业务或身份签名私钥。
4. 通过正常镜像发布流程创建固定 image ID，记录基础 image ID、软件清单 hash 和测试结果；把这个 ID 输入专属 Terraform 模块。实际云镜像创建与 Terraform apply 不由本次开发运行。

```sh
# 以下是真实构建命令，必须在隔离 Ubuntu 构建 VM 中执行。
sudo python3 prepare-host.py freeze --versions reviewed-package-versions.json \
  --bundle /var/tmp/workload-identity-packages
sudo python3 prepare-host.py install --bundle /var/tmp/workload-identity-packages \
  --lock-sha256 REVIEWED_64_HEX_SHA256
```

镜像快照后重新实例化的包集合、架构必须与清单基线一致；镜像补丁更新应重新制作清单，不允许绕过 hash。`prepare-host.py` 没有冻结一组未知目标环境的假包版本，也不会隐式安装 `latest`。

在同架构 Ubuntu 24.04、Python 3.12 的隔离构建机上预下载 `deploy/workload-identity/requirements.lock.txt` 的 wheels。该文件是集群已锁依赖的原样子集，包含 cryptography/jsonschema 及传递依赖；安装器使用 `--no-index --require-hashes`，不在线回退。部署控制器继续使用完整的 `.local/cluster-venv`。

```sh
python3.12 -m pip download --require-hashes --only-binary=:all: \
  -r deploy/workload-identity/requirements.lock.txt \
  --dest .local/workload-identity-wheels
```

为固定 issuer 域名配置企业公网 DNS 和健康切换；`publisher_origins` 输出实际 IP。源站无 RAM role；仅保留 IMDSv2（required、hop limit 1）供 cloud-init 读取只含 SSH 公钥的 user_data，精确放行 metadata TCP80 /32 与声明的 NTP 出口。两个 A 记录本身不能代替故障摘除，须使用已运营的健康检查 DNS 或负载均衡入口，并将两个源站 IP 填入配置作逐源验证。本包不自动操作企业域名或宣称 DNS 高可用已验收。

证书由企业 PKI/证书服务安装在各源站 `/etc/sandbox-workload-identity/tls/fullchain.pem` 与 `server.key`。证书 SAN 必须包含固定 issuer，私钥为 root 的 `0400/0600` 文件。安装器仅 stat 权限，不读取、计算私钥 checksum 或传输私钥；Nginx 使用该服务器证书完成 TLS。证书链和到期告警由同一证书交付流程负责。

使用 `install.yaml` 安装源站：inventory 的 `[workload_identity]` 恰好两台，运维连接启用 SSH 主机密钥验证；声明 `workload_identity_config`、`workload_identity_wheels`、`workload_identity_nginx_version` 与单独的 `workload_identity_publisher_public_key`。安装器检查精确 nginx 版本和 NTP 同步，离线装 Python wheels，创建无 sudo 的发布账户。SSH 强制固定接收命令，禁 PTY、转发、口令认证及用户 rc；接收器不能选择任意命令或目标路径。

```sh
ANSIBLE_HOST_KEY_CHECKING=True .local/cluster-venv/bin/ansible-playbook \
  -i reviewed-publisher-inventory.yaml deploy/workload-identity/install.yaml \
  -e @reviewed-publisher-install-vars.json
```

## TLS 指纹与公钥发布

RAM 当前官方流程取 `openssl s_client -showcerts` 返回的**最后一张证书**计算 SHA-1 thumbprint。这可能是服务端提供的最高中间 CA，并不一定是根；不能自行把“某个根证书 hash”与它互换。工具使用系统 CA 库验证 HTTPS、主机名与有效期，并核验所提供证书链每一跳签名与 CA 属性，防止拼接无关证书；最后的 CA 指纹还必须精确匹配配置及 RAM 中已审阅的指纹。[阿里云官方指纹步骤](https://help.aliyun.com/en/ram/obtain-oidc-idp-fingerprints-through-openssl)

每个公网入口和源站必须在发布前通过 TLS/SNI/指纹检查。只接收刚从集群导出的 5 分钟内产物；同时绑定 deployment、epoch、配置 hash 和控制节点证据。SSH 仅传校验后的公开 JSON，服务端以 flock 串行处理，在新 release 目录 fsync 两份公有文档及本地 manifest，再原子切换 `current`。Nginx 只允许两个精确路径的 GET/HEAD，其他路径 404，不公开 manifest 或目录列表。

```sh
.local/cluster-venv/bin/python deploy/workload-identity/identity.py export \
  --config .local/production-workload-identity.json \
  --deployment .local/production-cluster-v1 --cluster-epoch ACTUAL_CLUSTER_EPOCH_UUID \
  --output .local/workload-public-v1.json

# 不加 --apply 只检查公开输入；实际 SSH 发布必须显式带 --apply。
.local/cluster-venv/bin/python deploy/workload-identity/identity.py publish \
  --config .local/production-workload-identity.json \
  --bundle .local/workload-public-v1.json --apply
```

两个源站按次序发布。新增密钥时旧公钥自动保留；任一源站失败立即返回失败，不给出“发布成功”结果，也不启动新签名器。成功后重新读取公网入口及全部源站，确认集合一致。失败后修复故障节点再重试公开文档发布，不通过删除旧 key 来“修复一致性”。本地审计 manifest 不是 RAM 接受令牌或云权限生效的证明。

## 首次集群安装闭环

1. 在 `safe_mode=true` 的平台初始化记录中确定 deployment 与 epoch；准备域名、静态源站 TLS、RAM OIDC 配置和精确角色策略。
2. `cluster.py install-control-plane --deployment ... --execute` 安装控制面、CNI 和保持隔离的 Kata 文件，**不安装 CSI addons**。这消除了“先发布真实公钥，却还没有 API server”的首装循环。
3. 直接连接全部控制面导出真实 discovery/JWKS，发布并执行 `verify-public`。不要开放 Kubernetes API 的匿名公网访问。
4. 执行以下 addons 命令。它现场读取经审核 inventory、Kube Node/mirror Pod、公网元数据，创建两个短命且无特权的验收 Pod，分别使用准确的 CSI ServiceAccount 投射令牌，验证签名/kid/iss/aud/sub/期限及 Pod/SA UID，再实际调用 `AssumeRoleWithOIDC` 与签名 `GetCallerIdentity`。任何失败都不会安装 addons。验收 Pod 使用仓库已锁的 Debian 基础镜像，禁用 Kubernetes API token 自动挂载；没有新增任何 Kubernetes RBAC 授权。
5. 验收成功后以 UID 前置条件清理本次 probe Pod，重新核查控制面与公网公钥未变，生成绑定 deployment/epoch/inventory/config 的短期审计 receipt，然后安装 CSI。**安装器不接受上传的成功 receipt 作为授权**，每次都执行现场验收。
6. rollout 后再读取真实 CSI driver 的投射 token，核对其挂载、角色配置和禁止永久 AK/凭据 IMDS 回退，重新验签与 STS 身份。完成记录保存为部署审计文件。失败时保留运行时 quarantine，不能通过填写“验收完成”绕过。

```sh
.local/cluster-venv/bin/python deploy/cluster/cluster.py install-addons \
  --deployment .local/production-cluster-v1 \
  --identity-config .local/production-workload-identity.json \
  --cluster-epoch ACTUAL_CLUSTER_EPOCH_UUID --execute
```

验收读取 token 仅通过固定 `kubectl exec ... -- cat /var/run/sandbox-cloud/token`，原始 token 留在受限进程内存，不写文件、命令行或日志。读取前检查真实投射 volume、容器、SA、namespace；读取后再次检查 Pod/SA UID，防名称复用。响应输出只有 kid、subject、UID、期限和云请求 ID，不含 STS AK/secret/token。子进程 stdout/stderr 在读取过程中限长，所有错误对外使用固定代码。

对已部署的 fencing 等其他组件，可单独运行 `verify-pod --role fencing --context ... --namespace ... --pod ... --container ... --config ...`；只有显式增加 `--exchange` 才请求 STS。这些检查验证“令牌与角色信任链”，管理机发起的交换不能替代驱动容器实际 egress、SDK自动刷新、磁盘操作或云故障演练。完成上述验收也不代表 Kata 首包隔离、可信停止或云 fencing 已认证。

## 密钥与证书轮换

Kubernetes 签名私钥的生成、分发和切换由控制面密钥管理流程负责；本包没有读取它们的路径。先把新**验证公钥**加入所有 apiserver，再一致导出并发布新旧集合。确认 DNS 入口与全部源站均已有新旧 key 后，先切换一台控制面签名器作为 canary，经其直接 API 创建短期试验 Pod，确认实际 token 的 kid 为新 key，并运行 STS 试交换；成功后才继续其余签名器。不要先切签名再等待公开 key 出现。

停止旧 key 签发且旧 token 均已到期后，控制面才移除其验证公钥。公开接收器首次发现所有控制面都已缺失旧 kid 时记录 `missing_since`，继续保留至少本版本支持的最大寿命与缓冲总和 `3600 + 60 + 300 = 3960` 秒（66 分钟）。调低当前 TTL/缓存配置不能缩短已签发令牌的保留窗口。之后必须携带新的完整导出并显式 `--retire-kid OLD_KID` 才能移除；提前退休、签发参数漂移、same-kid 换 key 或源站不一致都失败。没有自动按数量清理旧密钥的路径；达到 32 个公开 key 时要求运维处理，不能删掉未知仍有效 key。

源站缓存合同固定为 `Cache-Control: public,max-age=60,must-revalidate`（可在 30–300 秒内显式配置），不得在上游 CDN 增加未声明的过期缓存。RAM 自身缓存与撤销传播不可由该值证明；改换签名器前须在目标账号完成新 key 实际试交换，紧急泄露时按 RAM 身份撤销与事件响应流程处理，不能声称 JWKS 删除会即时撤销已有 STS 会话。

TLS CA 指纹轮换按官方流程：先将新指纹加入 RAM 与本地配置，等待至少一天，再切证书；新证书实际 STS 验收成功后移除旧指纹。RAM 上限为 5 个指纹。[阿里云 OIDC 管理与证书轮换](https://help.aliyun.com/en/ram/manage-an-oidc-idp)

## 可运行验证

```sh
.local/cluster-venv/bin/python -m unittest discover -s deploy/workload-identity/tests -v
.local/cluster-venv/bin/python -m unittest discover -s deploy/cluster/tests -v
terraform -chdir=deploy/workload-identity/infra init -backend=false -lockfile=readonly
terraform -chdir=deploy/workload-identity/infra validate
terraform -chdir=deploy/workload-identity/infra test
```

测试包含真实 RSA 签名、临时测试 CA 的 loopback HTTPS、重定向与错域名拒绝、证书链末尾拼接攻击、私钥字段拒绝、控制面不一致、实际 projected-token 对象绑定、提前退休、原子发布失败保持旧文件、双源站部分失败、STS 身份错误、子进程输出限长、离线包 hash/基础镜像绑定。测试生成的密钥只用于本地 fixture，不读取用户已有私钥。
