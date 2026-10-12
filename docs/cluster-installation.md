# 阿里云自管集群安装与维护

本包提供 G1-03 的实际执行工具，使用已锁定的上游 Kubespray 安装三个控制/etcd节点、三个平台节点和跨三AZ的Kata节点；同时生成磁盘CSI和受信网络策略。**源码可验证不等于云环境已认证。nodeguard 源码和后续独立宿主安装包已提供，见 [门禁安装与登记](../deploy/nodeguard/README.md)；目标裸金属环境及云 fencing 完整路径尚未认证，因此安装完成后仍禁止承载非可信沙箱。** 不创建沙箱RuntimeClass、不配置Kata handler、保留 `sandbox.platform/unverified=true:NoSchedule`，`enable-sandboxes` 明确失败。不能人工删除taint来跳过这一门槛。

## 固定组合与证据

| 组件 | 锁定内容 | 已验证 | 仍待目标云验证 |
| --- | --- | --- | --- |
| Kubespray | 2.32.0官方源码SHA256 | 原版与派生安装playbook、升级playbook实际Ansible语法检查 | SSH到目标九台以上机器安装、扩容、滚动维护 |
| Kubernetes/etcd/containerd/runc | 1.36.4 / 3.6.14 / 2.3.5 / 1.4.3；上游源码内置下载hash | 使用上游实际变量；containerd config v4、systemd cgroup设置 | 节点、证书、三AZ仲裁、恢复演练；所有最终镜像身份纳入实云release证据 |
| Cilium | 1.20.2 chart及CCNP CRD SHA256；官方chart默认镜像digest | 先策略后CNI的插入顺序；CCNP官方schema | Kata首包、重启、策略溢出、host firewall、MTU、IMDS隔离 |
| Kata | 4.2.0 `kata-go-static` amd64官方asset SHA256 | 配置硬化工具与安装语法；不会发布未受控handler | 完整1.26GB制品的目标机安装、KVM、guest/VMM身份、资源开销、nodeguard门禁 |
| CSI | v1.37.2源码SHA256；其中chart元数据仍为1.36.2；八个driver/sidecar镜像digest | 实际chart渲染、结构化身份修改、24个资源的K8s/CRD schema检查 | OIDC到STS刷新、标签权限、跨AZ拓扑、卷挂载、快照、分区不双写 |
| 工具 | Python3.12、Ansible12.3.0/core2.19.8、Helm3.22.0 | 真实工具运行与完整hash锁 | 企业受控制品镜像与离线包复制验证 |

Kata Go runtime在4.2仍受官方支持，但已弃用且未承诺支持结束日期。该选择服务于当前可信终止设计，不代表其未来支持不变；升级到runtime-rs必须重新审查其配置、cgroup和进程身份模型，不能换一个镜像名。

## 输入与准备

在企业管理网中的受控Linux安装主机运行；开发检查也支持macOS arm64。只需本地安装Python虚拟环境，不修改系统Python。使用 `deploy/cluster/README.md` 中的哈希安装命令。`prepare` 只下载官方公开制品；`check`不会SSH，不访问云账号，不运行真实kubectl。

从已经审批并应用的本环境IaC导出 **output而非state**：

```sh
umask 077
terraform -chdir=infra/alicloud output -json > .local/production-infra-output.json
cp deploy/cluster/settings.template.json .local/production-cluster-settings.json
```

填写模板中的全部null；模板没有可直接花钱或连接主机的默认配置。

| 输入 | 要求 |
| --- | --- |
| deployment/region | 与该环境IaC一致；不能复用其他环境输出 |
| host_image_id/host_kernel | 已审查Ubuntu24.04 x86_64固定镜像与**完整**内核版本；裸金属具备`/dev/kvm`，swap关闭，cloud-init/IMDSv2可用 |
| host_image_evidence_sha256/network_evidence_sha256 | 外部审批与实际认证报告的SHA256；安装器记录引用，**不因收到字符串就认证报告真实性** |
| mtu | 根据目标裸金属及VXLAN路径测试，1280–1450范围内的明确值；不能直接照抄测试fixture |
| pod_cidr/service_cidr/enterprise_cidrs | IPv4企业网络规划；Pod/Service网段互不重叠且不与IaC子网/企业地址相交 |
| ntp_servers | 管理网内可信时间服务器，安装前系统时钟已同步；放通IaC中对应UDP123 |
| api_dns_name | 解析到IaC私网Kubernetes CLB，加入API服务端证书SAN |
| oidc_provider_arn | IaC创建的Kubernetes工作负载OIDC provider，非产品用户IdP；精确绑定CSI控制器与节点SA |
| ssh_known_hosts_file | 通过云管理/机器交付渠道核对的绝对路径；不接受运行时自动`ssh-keyscan`后即信任；SSH私钥由安装用户/agent提供 |
| download_proxy/trusted_egress_cidrs | 已审批的无嵌入口令代理URL（私有镜像环境可空字符串）及具体出口CIDR；与IaC安全组、DNS、NTP、镜像仓库、STS/ECS/KMS访问一致，禁止0/0 |
| backup_recipient_certificate | 离线恢复负责人持有私钥的RSA CMS加密公钥证书绝对路径；私钥不上控制节点、不进inventory |

私有集群的工作负载issuer还需要企业HTTPS域名提供 **真实集群公钥** 的OIDC discovery/JWKS；签名私钥只留控制面。[工作负载身份部署包](workload-identity.md)提供双源站 Terraform、固定软件构建、公开元数据导出/发布与实时 STS 验收；企业域名、TLS 交付及目标云执行仍需运维实际完成。不能把私有API地址直接当公网可发现issuer，也不能塞永久AK绕过。

```sh
.local/cluster-venv/bin/python deploy/cluster/cluster.py prepare --include-kata
.local/cluster-venv/bin/python deploy/cluster/cluster.py generate \
  --terraform-output .local/production-infra-output.json \
  --settings .local/production-cluster-settings.json \
  --out .local/production-cluster-v1
.local/cluster-venv/bin/python deploy/cluster/cluster.py check \
  --deployment .local/production-cluster-v1
```

生成inventory、其兼容SHA256文件和完整 `installation.json`，不覆盖已有版本。清单同时绑定 `inputs.json`、inventory和当前artifact lock；`check/render` 重新执行业务校验并核对由输入确定生成的库存，成功后绑定实际 `csi-values.yaml`、`csi-crds.yaml`、`csi.yaml`、`trusted-policies.yaml`。修改输入、库存、任一派生制品或lock均会拒绝；重写单个摘要也不能绕过出口/拓扑校验。所有非敏感文件为0600普通文件，不接受符号链接或部分发布。

修改配置应生成新的部署目录并评审。旧目录只有inventory摘要时，或第一次渲染中途退出而留下未绑定资源时，也必须从原始审批过的Terraform output与settings生成新版本，不能直接补清单或删除策略恢复流程。每条Ansible命令在网络访问前核验相同输入基线，把库存及copy/apply源文件固定到独立0700临时快照；命令结束后复核源目录，漂移会中止后续步骤。Kubespray的 `artifacts`、`credentials` 和加密etcd备份明确写回持久部署目录，不能随临时输入快照删除；这些含敏感信息的输出不进非敏感安装清单，也不复制到代码仓库。摘要用于防止部署配置漂移，不能证明外部审批或替代签名。

核对节点ID/IP/AZ、认证报告、已生成CSI权限/网络策略和证书负责人后，运维才能执行下面真实主机命令；本次开发没有运行它。

```sh
.local/cluster-venv/bin/python deploy/cluster/cluster.py install-control-plane \
  --deployment .local/production-cluster-v1 --execute
```

控制面安装完成后，按工作负载身份手册完成真实 discovery/JWKS 发布、RAM 指纹配置与逐源验证，再运行独立的 addons 安装命令。它从当前控制面采集真实投射 token 并完成 STS 交换，成功才安装 CSI；安装后再次验证实际 CSI Pod 的 token 与角色。

```sh
.local/cluster-venv/bin/python deploy/cluster/cluster.py install-addons \
  --deployment .local/production-cluster-v1 \
  --identity-config .local/workload-identity.json \
  --cluster-epoch ACTUAL_PLATFORM_EPOCH --execute
```

安装先验证实际ECS instance ID/image ID、操作系统/kernel、cgroup v2、NTP、KVM；Kubespray独占containerd与Cilium配置。安装器对锁定的上游playbook做结构化派生，只插入“控制面已建立、CNI尚未开始”阶段的官方Cilium CRD和受信策略，锚点变化立即失败。Cilium CLI使用本地已验hash的chart。策略不全放行 `reserved:init` 或租户namespace；管理来源还受IaC安全组限制。API、gateway、admission等业务和身份服务不由本包安装。

CSI仅磁盘驱动开启；WFFC、加密KMS、Retain、创建盘和快照时带Deployment标签。controller固定平台池，node固定Kata池。两者使用不同精确SA投射600秒token；只有实际cloud driver挂载该token，sidecar不继承RAM凭据。Kubernetes API token仍用于CSI正常控制器权限。移除上游通用chart中未使用的Secret创建/读取、NAS/OSS/CNFS和group-snapshot权限，node不具备PV/PVC/VolumeAttachment写权限，只保留磁盘发现需要的节点patch和事件。关闭ACK托管token/长期AK/凭据IMDS回退；实例地域和ID的只读元数据发现仍保留。controller/节点RAM权限来自IaC；收紧后的合法磁盘操作同样须在目标云实测，拒绝时不自动扩大权限。

## 升级及恢复

本版本 `upgrade` 是**相同候选版本的受信bootstrap集群重配置/维护入口**，不是任意N→N+1升级器。准备新版本时先更新lock、镜像和上游变量适配，重跑离线检查与预生产升级/回退演练，再交付对应版本。存在任何RuntimeClass或已安装 guarded-plan 所有权标记时该入口拒绝，避免旧流程重写 kubelet 前门或 drain/delete 影响已有VM；必须由后续nodeguard感知的维护流程接管。

```sh
.local/cluster-venv/bin/python deploy/cluster/cluster.py upgrade \
  --deployment .local/production-cluster-v2 --execute
.local/cluster-venv/bin/python deploy/cluster/cluster.py backup-etcd \
  --deployment .local/production-cluster-v2 --execute
```

备份对每个控制节点保存一致性etcd snapshot，执行etcdutl校验，并把本节点`/etc/kubernetes`（含CA、SA签名key、Secret加密配置）、`/etc/ssl/etcd`及环境文件一起CMS加密。只取回加密产物；成功取回后删除宿主的明文暂存。中途失败仍为失败，暂存只在root0700目录，值班人员须排查和清理。**这不是已接通OSS定时归档/PITR**：运维须把加密包和SHA清单存到独立受控恢复域并实际试解密，自动归档与保留业务另行交付。

恢复负责人在受控恢复主机解密各节点包，核验外部保存的hash及备份来源。先恢复匹配的CA/SA密钥、各成员TLS证书和Secret加密配置；这些身份缺失时，仅恢复etcd数据会造成不可解密或身份错配，本工具会拒绝。云账号/业务数据库与集群数据库epoch的恢复也必须协调，不能单独“恢复etcd后立即放流”。

```sh
# 输出是含秘密的本地文件；仅恢复负责人操作，目录0700/umask077。
openssl cms -decrypt -inform DER -in control-0.cms \
  -recip recovery-recipient.pem -inkey recovery-private-key.pem \
  -out recovery.tar.gz
```

从**同一份选定snapshot**提取`recovery_snapshot`，准备不含私钥的恢复变量JSON：`recovery_id`（新唯一标识）、`recovery_snapshot`绝对路径、`recovery_snapshot_sha256`、`recovery_ca_sha256`、`recovery_encryption_config_sha256`、`recovery_all_api_writers_fenced: true`。最后一项必须来自已执行的API入口隔离/自动化停用/所有控制成员停写流程；不是仅改布尔字段。替换主机需先用备份身份完成机器引导且验证成员清单，禁止遗漏旧活跃成员。

```sh
.local/cluster-venv/bin/python deploy/cluster/cluster.py restore-etcd \
  --deployment .local/production-cluster-v2 \
  --recovery-vars /secure/recovery/verified-inputs.json --execute
```

流程在任何恢复前验证三个成员相同snapshot与原CA/加密配置，停止全部控制节点kubelet、控制容器、etcd，保留原data目录，再用 **etcdutl3.6** restore重建三个成员，并执行revision bump和mark-compacted。恢复仲裁健康后才启动kubelet。该脚本没有在目标三节点运行过，恢复演练仍是发布阻断项；不会将Ansible syntax通过记作恢复成功。

## 上线门槛

| 门槛 | 当前状态与证据 |
| --- | --- |
| 离线确定性 | 官方下载hash、真实Helm渲染、官方Kubernetes/CRD schema、Ansible syntax及拒绝输入回归已执行；测试脚本不接触集群 |
| 硬件/网络/CSI | 待目标地域、镜像、SKU和至少三台裸金属实测；MTU/IMDS首包、STS到期与跨scope拒绝、卷重挂/分区均须留原始证据 |
| 可信终止 | nodeguard源码已提供，主机安装与目标环境认证未完成；要求kubelet→`/run/sandbox-nodeguard/cri.sock`→`/run/containerd/containerd.sock`，native host进程、root0700目录/0600 socket、持久状态、mTLS9444；原子启动门禁、cgroup证据、云fencing全部验收前不放行 |
| 灾备与升级 | 需运行三节点故障恢复、证书/加密配置恢复、数据库/epoch联动及维护演练；目前只有可执行流程和离线检查 |
| 产品上线 | 本包不安装业务服务、独立Keycloak、观测或备份搬运，也未运行72小时容量验收 |

官方依据：[Kubespray2.32组件矩阵](https://github.com/kubernetes-sigs/kubespray/releases/tag/v2.32.0)、[Kata4.2安装与Go支持边界](https://github.com/kata-containers/kata-containers/blob/4.2.0/docs/installation.md)、[Cilium/Kata限制](https://docs.cilium.io/en/v1.20/network/kubernetes/kata/)、[CSI1.37.2源码](https://github.com/kubernetes-sigs/alibaba-cloud-csi-driver/tree/v1.37.2)、[Kubernetes1.36.4 OpenAPI](https://github.com/kubernetes/kubernetes/blob/v1.36.4/api/openapi-spec/swagger.json)。
