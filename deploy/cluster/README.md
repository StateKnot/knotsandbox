# 固定版本的集群安装工具

交付范围是 G1-03 的可执行安装与离线验证工具，运行说明见 [集群安装手册](../../docs/cluster-installation.md)。当前安装 **不放行非可信沙箱**：Kata 节点保留 `unverified` taint，未创建 RuntimeClass，也未配置可绕过 nodeguard 的 Kata handler。宿主门禁安装和登记工具见 [nodeguard](../nodeguard/README.md)；它同样保留隔离，只有云 fencing 完整路径交付并通过目标云认证后才能放行。

本目录不接受云 AK，不执行 Terraform；任何 SSH 操作均须调用独立的 `install-control-plane/install-addons/upgrade/backup-etcd/restore-etcd --execute` 命令。本次开发只运行 `prepare/check` 和离线测试。

```sh
python3.12 -m venv .local/cluster-venv
.local/cluster-venv/bin/python -m pip install --require-hashes -r deploy/cluster/requirements.lock.txt
CLUSTER_PYTHON=.local/cluster-venv/bin/python bash deploy/cluster/check.sh
```

`versions.lock.json` 固定 Kubespray 源码、Kata Go 制品、Cilium chart/CRD、CSI 源码/驱动镜像和官方 API schema。Python 依赖逐包固定版本与 PyPI SHA256。下载器核对整包校验和；不执行远端脚本。默认不下载 1.26 GB 的 Kata 运行制品，实际安装前须 `prepare --include-kata` 完整下载校验。

工作负载身份按[部署手册](../../docs/workload-identity.md)先发布真实公钥；`install-addons` 会实时核验全部签发器、公开 JWKS 与 CSI 角色 STS 交换，拒绝使用导入的成功 receipt 绕过验收。

`generate` 生成完整 `installation.json` 快照，绑定全部非敏感 inputs、inventory、其兼容 SHA 文件和版本 lock。`render/check` 重新执行业务校验并核对确定性库存，成功后把实际 CSI values/CRD/资源和网络策略的 SHA 一并绑定。任何执行入口都拒绝缺失、被修改、部分发布或符号链接文件；旧的仅 inventory.sha256 目录必须从原始已审批输出重新生成新版本，不能手工补摘要。每条 Ansible 命令读取私有冻结副本中的库存和 apply/copy 制品；源目录在执行期间漂移会阻止下一步。这个摘要清单用于配置一致性，不代替受控评审、签名或云认证。
