# Nodeguard 主机安装与验真

这是现有 `deploy/cluster` 引导之后的宿主安装步骤，使用同一份固定 Kubespray 源码和官方 containerd/kubelet roles。需要已经完成基础安装、仍带 `sandbox.platform/unverified=true:NoSchedule` 的专用节点；集群中不能存在 RuntimeClass。它不会删除隔离 taint，也不会创建 RuntimeClass。

源码、协议和当前测试范围见 [docs/nodeguard.md](../../docs/nodeguard.md)。真实裸金属/Kata/CSI/云 fencing 认证尚未完成；当前 release 的 `enable` 会明确拒绝，因为没有可用于生产启用的云 fencing 完整路径。填写 PASS 报告不能解除该能力限制。

## 安装资料

在私有目录准备 nodeguard settings JSON，字段为：

```json
{
  "cluster_epoch": "<控制面当前 epoch UUID>",
  "certification_id": "<受审阅的认证引用>",
  "binary_file": "/absolute/path/sandbox-nodeguard-linux-amd64",
  "binary_sha256": "<已发布 CI 产物的 SHA256>",
  "nodeguard_server_ca_file": "/absolute/path/nodeguard-server-ca.pem",
  "controller_client_ca_file": "/absolute/path/controller-client-ca.pem",
  "nodes": {
    "<真实 Kata Node 名称>": {
      "node_uid": "<从当前 Kubernetes Node 取得的 UID>",
      "server_certificate_file": "/absolute/path/node-server.pem",
      "server_key_file": "/absolute/path/node-server-key.pem"
    }
  }
}
```

`nodes` 必须精确覆盖 Terraform 输出中的 Kata 池。使用发布流水线产生的 Linux amd64 ELF；安装前和复制到宿主后均校验 SHA256。这里没有占位二进制、临时下载地址或自建 CA 命令。

专用服务端 CA 仅签发 `<NodeUID>.nodeguard.sandbox.internal` 证书，必须带服务端用途且至少还有一天有效期；每节点独立密钥。控制器客户端 CA 必须与服务端 CA 不同，由组织受控 PKI 签发独立客户端用途证书。nodeguard 不接受统一 OIDC token 代替此 mTLS。私钥文件 0600，其余输入不可被 group/other 写入。

```bash
.local/cluster-venv/bin/python deploy/nodeguard/nodeguard.py plan \
  --deployment /absolute/private/bootstrap-deployment \
  --settings /absolute/private/nodeguard-settings.json \
  --out /absolute/private/guarded-deployment

.local/cluster-venv/bin/python deploy/nodeguard/nodeguard.py check \
  --plan /absolute/private/guarded-deployment

.local/cluster-venv/bin/python deploy/nodeguard/nodeguard.py install \
  --plan /absolute/private/guarded-deployment --execute
```

`plan` 只操作本地文件，拒绝覆盖已有计划；`check` 执行固定上游的 Ansible 语法检查，不连接主机；只有 `install --execute` 连接 inventory 已配置且验证 host key 的主机。它逐节点验证实际 Node UID、InternalIP、boot ID 和隔离状态，安装校验后的二进制与证书，以固定上游重写受控 handler/两个 kubelet endpoint，再从实际配置读取 QEMU/virtiofs 路径并计算七个文件摘要。

CRI runtime 前门为 `/run/sandbox-nodeguard/cri.sock`，image endpoint 仍直接使用 `/run/containerd/containerd.sock`。host profile 验证没有其他 runtime handler、默认系统 runc、显式 systemd cgroups、禁用 Kata VM cache/template/annotation，以及 kubelet 无旁路 endpoint。任何不匹配、符号链接二进制或额外 handler 都拒绝安装，需要按认证配置处理，不能忽略。

当前安装组合固定 Linux amd64、containerd 2.3.5 的 v4 配置、`/var/lib/containerd`、`/run/containerd` 和本地 Unix socket。生成器显式配置默认 `overlayfs`，并通过锁定上游模板生成以下 image handler 映射；collector 要求唯一的 `kata-qemu` 映射，拒绝缺失、旧拼写、其他平台或 snapshotter 冲突：

```toml
[plugins."io.containerd.cri.v1.images".runtime_platforms."kata-qemu"]
platform = "linux/amd64"
snapshotter = "overlayfs"
```

runtime handler 的 legacy `snapshotter` 可缺省、为空或同为 `overlayfs`；非空冲突拒绝。Kata 表仅接受类型、options 和该兼容字段，额外 `runtime_path`／`base_runtime_spec` 不能引入未认证 shim 或规格。额外 imports、动态插件目录、proxy plugins、stream processors、server／snapshotter 插件覆盖也不进入该档案。NRI 须显式为 `disable = true` 且无额外配置；生成器同时关闭它。配置 v4 与 `runtime_platforms` 的含义以 [固定 containerd 配置结构](https://github.com/containerd/containerd/blob/v2.3.5/internal/cri/config/config.go)为准，v4 server 插件覆盖见[实际服务端配置](https://github.com/containerd/containerd/blob/v2.3.5/cmd/containerd/server/config/config.go)，NRI 不能依赖缺省关闭，见[默认配置](https://github.com/containerd/containerd/blob/v2.3.5/internal/nri/config.go)。这只是受支持配置的准入，不能证明运行中 daemon 已加载它、实际 pull 平台或 unpack snapshotter 已正确绑定；后续原生读回、引用、GC 与硬限仍须独立验收。

采集从可信目录逐级打开，不跟随符号链接，拒绝 FIFO 和可由 group/other 修改的输入或祖先。配置上限 1 MiB，二进制上限 512 MiB；语义解析与 SHA256 使用同一次读取的字节，七份输入保留原 FD，发布前再检查内容元信息、路径和目录身份。输出目录须 root 所有、group/other 无权限且全部祖先可信，安装流程创建为 0700；三份文件通过目录 FD 排他写入为 0600 并 fsync，`enrollment.json` 最后发布。失败可能留下本次较早写出的 profile/config，节点继续隔离，按原部分安装流程复核；不自动删除或覆盖资料。该检查不承诺跨文件原子快照，后续 HostObserver 仍重新验证当前文件。

已有登记节点继续使用其原档案；采用本组合需走隔离、维护和重新认证流程，不能覆盖原 profile 或 journal。生产档案协议和 Rust HostProfile 字段保持不变；P1a 能解析 arm64 元数据不扩大当前安装器的 amd64 宿主支持范围。

首次初始化记录永久 marker 和 FULL-sync SQLite。只允许尚未登记的新节点；已有 marker/config 的节点拒绝重装，防止销毁旧实例证据。部分安装失败后保持隔离，先检查已修改的文件和 journal；不要自动删除 marker 或重建数据库。bootstrap 工具也会记录 guarded-plan 所有权，阻止原 `install/upgrade` 将 kubelet 悄悄改回直连运行时。当前不能对承载租户实例的节点做无损滚动替换。

## 登记与认证材料

每节点 `/etc/sandbox-nodeguard/enrollment.json` 会复制到计划目录 `artifacts/<node-name>.json`，包含精确 NodeBinding、云 account/region/instance ID、private IP、9444 和 certification ID；不含私钥。cloud account 的安装输入来自受控 IaC/settings，最终登记还必须用独立 Terraform 输出再次比对。

通过控制面的 `sandbox-admin enroll-node --apply` 进行正式登记；该入口执行实时 Kubernetes + mTLS 核对，返回受审计的登记回执。安装完成不等于登记完成。登记也不会清除节点 taint。需要的参数及部署数据库身份见该命令的 `--help`，不要手写 INSERT。

认证报告与独立 reviewed cluster settings 必须绑定以下字段：`certification_report_sha256`、`cluster_epoch`、`certification_id`、`nodeguard_binary_sha256`、`versions_lock_sha256`。后者是当前 `deploy/cluster/versions.lock.json` 原始字节摘要。报告严格字段如下：

- `protocol:1`、同名 certification/epoch/两个 release 摘要、带时区 `reviewed_at` / `expires_at`。
- `nodes`: 每项 `{node:NodeBinding,cloud_instance_id,private_ip}`，每个 Node UID、boot ID 和地址唯一。
- `checks`: 固定九项，每项 `{status:"PASS",evidence_sha256:"<审阅证据摘要>"}`。

九项是 `kata_process_coverage`、`cri_start_fencing`、`crash_recovery_unknown`、`workspace_single_writer`、`csi_late_publish_unmount`、`first_packet_network_isolation`、`node_boot_reenrollment`、`cloud_fence_prevents_revival`、`cloud_volume_detach_safety`。报告验证的是受审阅材料身份与完整性，不会从字段本身推导测试实际通过。

```bash
.local/cluster-venv/bin/python deploy/nodeguard/nodeguard.py verify-enrollment \
  --artifact /absolute/private/guarded-deployment/artifacts/kata-node.json \
  --receipt /absolute/private/enrollment-receipt.json \
  --terraform-output /absolute/private/verified-terraform-output.json \
  --cluster-settings /absolute/private/reviewed-cluster-settings.json \
  --certification-report /absolute/private/certification-report.json
```

该命令只校验报告/登记回执/原始文件摘要/精确节点身份，不宣称节点仍在线；上线前必须重新执行实时登记核验。当前 `enable` 接受同样参数并完成这些校验后，因缺少云 fencing release capability 而拒绝；输入里没有 `skip_verify`、`force` 或绕过开关。

验证命令：`.local/cluster-venv/bin/python -m unittest discover -s deploy/nodeguard/tests -v`。当前已完成离线配置/证书/证据负测、Ansible 语法和 Rust Linux nodeguard 测试；尚未执行任何公有云主机安装。
