# 恢复存储类安装与认证边界

恢复服务尚未开放。本工具准备两类存储资源与可审阅观测结果；完整 CSI、云盘、Kata 和数据读回验收通过前，不生成恢复认证、不启用 profile、不执行正式 0038 迁移。

## 固定用途

| 用途 | 模式 | 绑定策略 | 关键约束 |
| --- | --- | --- | --- |
| 项目 normal | Filesystem | WFFC | 已安装 normal 类，保留现扩容策略 |
| restore raw | Block | WFFC | 独立新类，不扩容，无 fsType |
| restore delivery | Filesystem | Immediate | 独立新类，不扩容，ext4 |
| restore snapshot | Block 来源快照 | 不适用 | 已安装 SnapshotClass，Retain |

三类盘 SC 的 name/UID 两两不同，统一使用审核过的 workspace compute KMS、cloud_essd、encrypted=true 和 diskTags/Deployment；SnapshotClass 固定 snapshotTags/Deployment。raw/delivery allowedTopologies 来自同次 Terraform node/subnet inventory 的三个排序可用区。所有类须为 Retain、准确 Ali CSI driver，无未知行为字段/default annotation/secret/fallback 参数。允许的三个可用区只约束可选范围，不能证明实际盘所在可用区。

## 准备与执行

复制 deploy/restore/storage.example.json 到部署目录，填写审核过的真实类名、账号、地域、Deployment 和 compute Key。保留严格字段，不添加自报认证或任意 zone 参数。所有动作必须提供真实 terraform output -json 文件；使用的 deployment_identity/workspace_kms_key_id/node_inventory/subnets wrapper 必须 sensitive=false，身份和节点/子网与配置相符。工具另检查仓库固定 Kubernetes/CSI 版本与镜像摘要。

```sh
python3 deploy/restore/storage.py render \
  --config .local/production/restore-storage.json \
  --terraform-output .local/production/terraform-output.json

python3 deploy/restore/storage.py install \
  --config .local/production/restore-storage.json \
  --terraform-output .local/production/terraform-output.json \
  --context REVIEWED_CONTEXT

python3 deploy/restore/storage.py probe \
  --config .local/production/restore-storage.json \
  --terraform-output .local/production/terraform-output.json \
  --context REVIEWED_CONTEXT
```

render 不连接集群；install/probe 必须显式指定已审核 context。install 先校验四类现有对象，再仅创建缺失的 raw/delivery SC；已有同名漂移或 deleting 立即拒绝，不 patch/delete 旧类。部分安装不会回滚删除已创建类，可修复依赖后以相同配置重试。probe 两次读取 name/UID/spec，返回候选 mapping、观测时间、context、Terraform 摘要与版本锁；结果固定 production_activation=false、csi_restore_certification=NOT_VERIFIED。

probe 输出不构成认证 INSERT 的依据。后续还须验证真实控制器身份、PV/content 生成与状态转换、源/目标云资源与单可用区、关闭后 Block→Filesystem、普通 Kata START/数据摘要以及故障和升级演练。当前候选和本机协议夹具都不证明上述门槛。

## 本地复验

```sh
python3 -m unittest discover -s deploy/restore/tests -v
python3 deploy/restore/schema_check.py
bash scripts/test-restore.sh PRIVATE_ENV_FILE storage_mapping
bash scripts/test-restore.sh PRIVATE_ENV_FILE raw_parent
bash scripts/test-restore.sh PRIVATE_ENV_FILE node_topology
```

schema check 使用按版本锁下载的官方 schema 及 SHA256，需要仓库既有 cluster 工具依赖。storage_mapping 使用专用 loopback PostgreSQL、真实 HTTP/mTLS、新唯一数据库和不可变 Git 公开源码快照；保护环境文件中的凭据不输出。正式 0001–0037 迁移账本保持原样，草案安装后正常生产 startup 必须拒绝。验收范围和失败证据见 docs/restore-development.md。

raw_parent 独立验证初始 raw PVC 当前授权、实际 CREATE/双 Pending GET、原子父 UID/早期 PV 意图和无父 Bound 拒绝；不依赖未来 Job/PV/permit。它没有授权 selected-node/生成 PV/CSI 状态，也不构成单可用区、Kata 或云盘认证。后续必须通过这些链路的真实验收后再开放恢复服务。

node_topology 使用原正常 enrollment 与真实 mTLS、签名只读云协议夹具、Node/CSINode 和新库 owner 收据发布；完整 raw/canonical Terraform 摘要与原身份固定。它只验证私有安装事实流程，不执行生产 owner 安装，不授予 selected-node/PV/CSI 或普通 START 权限；具体实际覆盖和故障验收缺口见 docs/restore-development.md。
