# Admission 服务生产安装

`deploy/admission/render.py` 从经过审阅的非秘密 JSON 生成工作负载清单和**独立的最后启用清单**。生成器不连接集群、不读取 Secret 内容、不产生密码、私钥或服务账户 UID，也不执行 apply。`deploy/admission/workload.yaml` 保留为历史结构参考，生产安装使用生成器输出；`webhook.yaml` 保留全局准入规则的来源。测试里的镜像 digest、节点和公开测试 CA 均不得安装到真实环境。

固定服务为 `sandbox-admission.sandbox-system.svc:443`，目标容器端口为 8443；服务器证书必须同时包含 `sandbox-admission.sandbox-system.svc` 与 `sandbox-admission.sandbox-system.svc.cluster.local` 两个 DNS SAN。API Server 负责验证服务器链、SAN 与有效期；服务仅信任专门给 API Server webhook 客户端签发证书的另一套 CA。该客户端 CA 不能使用 Kubernetes 通用用户/节点 CA、数据库 CA、服务端 CA 或企业通用客户端 CA。拥有其客户端私钥即拥有提交 `AdmissionReview.userInfo` 的权威，私钥只能留在各控制平面主机的秘密存储中。

## 输入与生成

使用 `deploy/cluster/requirements.lock.txt` 的 hash 锁定 Python 环境。离线 schema 检查使用 `deploy/cluster/versions.lock.json` 中锁定的 Kubernetes OpenAPI 和 `deploy/identity/versions.lock.json` 中锁定的 Cilium CRD，缓存缺失或 hash 不符会失败，不以安装成功或运行隔离认证代替。

输入严格只允许下列字段；重复 JSON 键、非有限数字、未知字段、超过 256 KiB 的输入均拒绝。

| 字段 | 生产来源与要求 |
| --- | --- |
| `schema_version` | 整数 `1`。 |
| `image` | 已通过当前发布签名、来源、漏洞与功能审查的完整 `registry/repository@sha256:…`。格式检查不代替发布审查。镜像必须包含当前真实 `--probe-local` CLI。 |
| `replicas` | 整数 2–8；推荐三个副本，两个副本无法同时在三个 AZ 各驻留一个副本。 |
| `platform_nodes` | 实际 Kubernetes `kubernetes.io/hostname` 与 `topology.kubernetes.io/zone` 的 `{hostname, zone}` 数组。恰好三个 AZ，节点不重复，3–32 个；每 AZ 容量支持 maxSkew=1，合计至少 `replicas+1`，包括滚动升级的独立空闲节点。 |
| `config` | 已安装、`immutable: true`、版本化 AdmissionConfig ConfigMap 的 `{name, key, sha256}`。SHA 是实际 `config.json` UTF-8 字节的摘要；生成器仅挂载引用并记录审阅摘要，不从注解推断实际内容已经通过验证。 |
| `database` | `{secret:{name,key},host,port:5432,ca_pem}`。`host` 是规范小写、外部数据库 FQDN，禁止 IP、通配符、集群 Service DNS 和 localhost。Secret 由秘密管理系统供应。 |
| `server_tls` | `{secret_name,certificate_key,private_key_key,server_ca_pem}`。引用现有版本化 TLS Secret，证书和私钥 key 不同；与数据库 Secret 独立。只提供服务端**公开 CA**给生成器，私钥不进入输入。 |
| `apiserver_client_ca_pem` | 有效的专用 API Server 客户端公开 CA bundle；生成器检查 CA 属性、证书期限、重复证书，以及其签名公钥与服务端/数据库 CA 无交集。不同证书名称、不同 PEM 文本并不能证明不同签名密钥。 |

平台节点必须实际 Ready、可调度、仅用于可信控制服务，并有 `sandbox.platform/node-pool=platform` 标签。先核对真实 hostname/AZ 标签和剩余 CPU、内存、Pod 数额及 taint，才能提交上述清单。生成器固定节点池、经过审阅的 hostname/AZ 约束、zone 与 hostname 两层硬 spread，以及 hostname 硬反亲和；不会通过 `ScheduleAnyway`、自动增加 toleration 或借用 Kata 节点解决容量不足。2–8 个副本各自有 20 条数据库连接的上限，还须为 `replicas+1` 个 Pod 和其他组件预留数据库连接预算。

```sh
.local/cluster-venv/bin/python -m unittest discover -s deploy/admission/tests -v
.local/cluster-venv/bin/python deploy/admission/schema_check.py
.local/cluster-venv/bin/python deploy/admission/render.py \
  --input /absolute/reviewed/admission-settings.json \
  --out /absolute/reviewed/admission-workload.json \
  --webhook-out /absolute/reviewed/admission-activate-last.json
```

输出文件必须尚不存在。工作负载包含固定 ServiceAccount、两条 get-only ClusterRole 规则、其绑定、内容寻址且 immutable 的公开 trust ConfigMap、Deployment、Service、PDB 和专属 CiliumNetworkPolicy；不包含 Secret、云权限、Webhook 激活对象。`admission-activate-last.json` 使用原 webhook 规则，仅填入审阅过的服务端 CA，不包含占位 CA。

## 身份、数据库与文件契约

1. **先准备真实身份。** 在 compute 仍关闭时创建固定准入 SA/get-only RBAC，以及 worker、gateway、termination、namespace provisioner、CSI/Cilium 等独立 SA。通过可信管理连接读取 API 返回的每个 SA 的 `metadata.uid`，将实际 username/UID 写入经过审阅的 AdmissionConfig。不得填写生成 UUID、从示例复制 UID 或靠创建顺序推断 UID。调度器/控制器证书身份必须满足当前 `AdmissionConfig::validate` 的精确 username/group 契约。新增备份或卷删除身份使用各自独立账户；不授予准入账户对应写权限。
2. 将有效 AdmissionConfig 保存为 immutable 的版本化 ConfigMap，记录实际字节 SHA。配置最多 1 MiB；Rust 启动时仍验证完整内容、真实身份形式和限制，引用及摘要不绕过这些验证。SA 删除重建后 UID 会改变，须经过审阅重建配置和滚动更新；不得忽略 UID 匹配。
3. 完成正常 SQLx migration，并以迁移所有者执行当前 `scripts/sql/admission-role.sql`。数据库 LOGIN 必须是 `sandbox_admission`，不能有 SUPERUSER/BYPASSRLS、迁移所有者或其他运行角色的成员关系；真正启动时执行 `verify_runtime_role`。角色仅有受限读取与窄的 consume-once 准入函数，不获得普通写表、claim 或云 fencing 权限。
4. 秘密管理系统供应固定数据库 URL：用户名 `sandbox_admission`、输入的外部 FQDN、显式端口 5432、`sslmode=verify-full` 和 `sslrootcert=/etc/sandbox-admission-db-ca/ca.crt`；不得使用 IP 替代服务器名、重复 SSL 参数、disable/require/prefer 或客户端 skip-TLS。密码只进入现有 Secret，renderer 不接收 URL。运行入口的共享严格 URL validator 和数据库角色验证仍是权威检查。
5. PKI 供应与两个固定 SAN 匹配的服务端 leaf/chain 和私钥，部署到独立 TLS Secret；专用 API Server 客户端 CA 的**公钥证书**与数据库 CA 由 renderer 写入公开 trust ConfigMap。API Server 客户端 leaf/key 不得出现在 webhook Pod、AdmissionConfig 或 API 服务中。

Pod 固定 UID/GID/fsGroup=10001、非 root、RuntimeDefault seccomp、只读根目录、禁权限提升、丢弃全部 capabilities。TLS Secret、ConfigMap 和显式 Kubernetes API token 投射均使用 `0440`；私钥必须实际为 `root:10001 0440`（或运行入口认可的当前 UID/root 私有 0400/0600），既不能组/全局可写，也不能随意换成世界可读。Kubernetes 的投射符号链接属于受支持的读取形式；运行入口打开实际有界 regular file 验证权限，禁止用普通 `stat` 检查替代。安装后检查实际投射的 metadata 与读取结果，不能由 YAML 的 defaultMode 推断成功。[Kubernetes projected volumes](https://kubernetes.io/docs/concepts/storage/projected-volumes/)

默认 SA token 自动挂载关闭；仅显式投射绑定 Pod 的一小时 Kubernetes API token、集群根 CA 和 namespace 到标准 kube 客户端路径，使用默认 API Server audience。没有 STS/cloud audience、云角色注解、hostPath、通用 kubeconfig、额外容器或任意 env 注入。ClusterRole 只允许 `get namespaces/nodes/pods/persistentvolumes/persistentvolumeclaims` 和 `get ciliumnetworkpolicies`，不包含 list/watch、写入、secrets、exec、impersonate、CSR 或 RBAC 修改。

## 安装顺序与网络验收

1. 完成锁定集群基线及对应版本的真实 G1 验收，保持产品 compute admission 关闭。先供应身份/RBAC、实际 ConfigMap/Secret；确认数据库完整角色验证和跨网络 `verify-full`，保留错误角色、错误 CA、过期证书、错误服务器名与不安全 URL 会拒绝启动的证据。
2. 在**每个** API Server 上合并现有 `deploy/admission/apiserver-admission.yaml` 与私有客户端 kubeconfig，保留原有 admission 插件配置。服务访问项必须匹配固定 Service DNS 与 443；服务器 CA 与客户端 CA 不同。逐台滚动，不把客户端私钥复制到 Pod。此时尚不安装 webhook 激活对象。
3. 审阅并由授权运维安装工作负载清单，确认三个 AZ 实际容量和滚动 `maxUnavailable=0/maxSurge=1`。PDB 要求 `replicas-1` 个健康副本；不能用修改 PDB、改 failurePolicy 或增加宽网络策略掩盖不可达。
4. 固定 Pod/CNP 标签 `sandbox.platform/network-policy=admission-v1`，使当前 `sandbox-trusted-bootstrap` 不选择这些 Pod。CNP 仅允许 `kube-apiserver` 实体入站 TCP8443；出站仅为 kube-system/kube-dns 的 DNS53（只解析数据库准确 FQDN）、该外部 FQDN 的 TCP5432，以及 `kube-apiserver` TCP443/6443。Pod 固定 `ndots=1`，使多标签外部 FQDN 优先作准确 DNS 查询。Kubernetes 客户端使用已验证的 in-cluster HTTPS，不需要再解析集群 Service 名称。禁止增加 world/cluster/host/remote-node、通配 DNS、任意 CIDR 或额外选中政策。
5. 对实际安装运行共享**只读**重叠检查；使用绝对路径、当前用户/root 所有的私有 kubeconfig，明确 context，不允许 exec/auth-provider、外部凭据文件、代理或跳过 TLS。它从不可变快照读取完整 discovery/策略/真实 Cilium identity，两次观察改变即拒绝。权限不足或未知 policy engine 也拒绝。

```sh
.local/cluster-venv/bin/python deploy/policy_boundary.py \
  --manifest /absolute/reviewed/admission-workload.json \
  --kubeconfig /absolute/private/installation-readonly.kubeconfig \
  --context reviewed-installation \
  --out /absolute/evidence/admission-policy-overlap.json
```

检查通过仅返回 `configuration_overlap=PASS` 和 `runtime_enforcement=NOT_VERIFIED`。还必须真实验证每个控制平面到每个副本的 8443 与 Service443、DNS53、指定数据库5432、Kubernetes API443/6443；验证租户 Pod、其他平台 Pod、其他主机/本机宿主、任意外网及云 metadata 被阻止并保留实际流量身份/丢弃证据。Cilium 默认对本机宿主有额外允许，精确主机网络隔离要求真实 `allow-localhost=policy` 和基线兼容性验证，不能由唯一 `fromEntities` 或重叠检查推断。控制平面隧道可能丢失 API Server 源身份，此安装基线在这种拓扑下不可激活；不得改成 `fromEntities: cluster`。[Cilium 1.20.2 layer 3 policy semantics](https://docs.cilium.io/en/stable/security/policy/layer3/)

6. 在每个 API Server 使用其实际客户端证书发送有效 `/validate` AdmissionReview，核对返回 UID/decision。缺客户端、错误客户端 CA、过期客户端、错误服务端 SAN/CA 必须失败；验证 H2/H1、实际超时边界与未授权 CONNECT、重复 consume、身份撤销、节点/Pod/PV UID 替换以及禁止变更网络政策。进程本地 `--probe-local` 只连接固定 127.0.0.1:8443、总期限 1 秒，启动 listener 在 config/角色/TLS/KubeConfig 检查之后；exec 探针不穿过 kubelet→Pod 网络，也不接触 API Server 客户端私钥。它只证明本地 listener 可用，不证明数据库/KubeAPI实时健康、mTLS 成功或网络隔离。
7. 在全部节点、全部控制平面与依赖故障演练通过后，最后由授权运维安装单独 `admission-activate-last.json`。保持 `Fail`、全局匹配且无可移除 selector、5 秒 API Server timeout 与4 秒业务 decision期限。真实探测 DB/KubeAPI/DNS 断连、副本/单AZ丢失、滚动升级、连接耗尽和慢客户端，并观察错误拒绝。Webhook 故障会阻塞全局匹配的资源写入，含其他 namespace；此故障域须由隔离集群的发布验收明确接受。
8. 再以固定真实 provisioner 身份创建绑定租户/项目的受保护 namespace 和受控策略，通过实际产品 START/CONNECT/STOP 与 CSI 流程验证。仅在真实验收完成后开放 compute；CA/SAN、CNP schema、SA UID、镜像注解、Ready 及 API capabilities 均不能作为独立运行认证。

## 更新、轮换与故障恢复

配置、TLS Secret、公开 trust CM 使用新版本名称并重新 render/review；不修改 immutable 对象原地内容。该服务在启动读取 config 与证书，投射更新不会自动重新载入。客户端 CA 轮换先安装新旧 CA 交叠的专用信任 bundle并滚动所有副本，再逐台更新 API Server 客户端，全部验证后才退役旧 CA；服务端 CA 同样先更新所有 API Server 信任，再滚动服务端证书，最终收窄 webhook caBundle。不可复用新旧服务端/数据库签名 key 冒充客户端专用 CA。

保留上一份审阅通过的镜像/config/TLS版本与非秘密证据，恢复时回滚到对应的一整组绑定版本，再重复实际 mTLS/权限/网络检查。启用后的 outage 优先修复 DNS、数据库、PKI、身份或已审查工作负载，保持 `Fail`；准入校验账户不获得删除 webhook 或修改自身角色的权限。退役秘密和旧对象须等待所有副本与 API Server 验证完成，不把 Pod 删除当成所有连接或 VM 已死亡。

当前仓库证据：10 个离线 renderer/负例测试通过；2–8 副本共64个物件通过锁定官方 schema。真实公有云安装、实际策略包执行、三 AZ 失效、每个 API Server mTLS 与上述 G1 验收尚未执行，不能标记生产已上线。
