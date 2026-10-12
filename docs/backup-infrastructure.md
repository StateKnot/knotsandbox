# 工作区独立备份部署与恢复合同

此包已接入实际冷备份 API、PostgreSQL 持久状态机、常驻 `sandboxd --role backup`、CSI 快照/Block clone、一次性 Job 准入、nodeguard 启动许可与可信终止/清理、独立签名库存验证。**当前仍未完成真实 OSS/CSI/Kata 组合验收，备份 capability 保持 false**。本地数据库、TLS、模拟 apiserver/OSS 与真实 Restic 工具验证分别记录，不把它们当成云端恢复认证。

## 1. 固定选型与证据

采用 `CSI VolumeSnapshot → 派生原始块卷 → Kata 中的标准 Restic 0.19.1 仓库 → 独立 OSS backup-vault → 新原始块卷`。对象传输用 **rclone 1.75.1 Alibaba S3 provider**，明确使用 OSS 的 S3 兼容接口，不声称原生 OSS SDK。工具正式发布 SHA256、基础镜像 digest 均在 [versions.lock.json](../deploy/backup/versions.lock.json)。

这修订生产方案 §13 原定的 Velero/Kopia 数据搬运实现，保留独立数据副本、加密、保留及恢复语义。Velero 1.18.2 的实际 backend 只有 Azure/GCS/S3/filesystem，Alibaba BLS 插件不自动提供 Kopia 原生 OSS 数据驱动；Kopia rclone backend 仍标 experimental。Restic 的 rclone stdio backend 已是正式支持的仓库路径，不引入自己的块存储格式。[Velero 固定源](https://github.com/velero-io/velero/tree/v1.18.2/pkg/repository/udmrepo/kopialib/backend)、[Restic rclone](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html#other-services-via-rclone)、[rclone serve restic](https://rclone.org/commands/rclone_serve_restic/)、[Alibaba provider](https://github.com/rclone/rclone/blob/v1.75.1/backend/s3/provider/Alibaba.yaml)。

每个 backup_id 使用一个独立 Restic v2 仓库。这避免运行中的索引/锁/GC 与 WORM 相互破坏，也使单份备份可独立验证、保留和回收。代价是每次读取整块盘、无跨备份 dedup；仓库内仍有标准分块、去重、压缩与认证加密。容量/吞吐不能按已用文件大小估算：例如 1 TiB 云盘每轮至少读取 1 TiB，capture 校验与 seal 又会完整读取仓库。首版容量上限应由实测的 ≤2h 导出和恢复 SLO 确定，不能直接按工具的 16 TiB 防溢出上限销售。

## 2. 不可信磁盘处理边界

备份只读取 **snapshot 派生的 Block PVC**，从不挂载运行实例原始 PVC；恢复只写全新、独占的 Block PVC。容器固定使用 `/dev/sandbox-data`，开盘验证 block 类型及 `BLKGETSIZE64`，限定精确字节数，不运行 tenant shell、tar 解包、目录遍历、mount、fsck、文件钩子或分区工具。恢复先验证仓库和预期 SHA256，再写新盘、fsync、重新全盘读取比对。保留分区表、文件数据、权限、xattr 等是原始字节复制的结果；“字节一致”不代表应用数据库能够恢复。

CSI 1.37.2 的 `NodeStageVolume` 只对 Mount capability 适配分区，`setupDisk` 的 Block 分支走设备 bind，提前返回，不进入格式化/fsck；Kata 4.2.0 Go 的 `appendBlockDevice`/`appendDevices` 把 block device 作为 virtio block/SCSI 设备交给 guest。[CSI 固定代码](https://github.com/kubernetes-sigs/alibaba-cloud-csi-driver/blob/v1.37.2/pkg/disk/nodeserver.go)、[Kata 固定代码](https://github.com/kata-containers/kata-containers/blob/4.2.0/src/runtime/virtcontainers/kata_agent.go)。

上述源代码是可行性证据，**不等于这套集群组合已认证**。Kubernetes volumeDevices → containerd → Kata 的整条实际路径还要核对 OCI device major/minor、QEMU raw block 参数、guest 设备大小，以及宿主 mountinfo/进程执行审计：不得出现对该租户卷的 mount/fsck/blkid/格式化。宿主内核仍会接触块设备/可能进行分区探测，不能宣传“宿主从不解析任何租户字节”；任务只能在沙箱处理节点上运行，不能迁移到控制平面/普通控制服务节点。禁止为使 Job 跑起来切换 runc、hostPath、privileged、SYS_ADMIN 或使用普通 Velero root datamover。

Job 使用新的受控 RuntimeClass **`kata-backup-qemu`，底层 handler 仍 `kata-qemu`**；所以现有 nodeguard 默认拒绝未登记启动，不新增透明 CRI 绕行 handler。Kata guest 内固定可信备份镜像用 UID 0 仅为访问原始设备，drop ALL、只读根、无 host namespaces、无 K8s API token；投射的 token 只有 `sts.aliyuncs.com` audience。seal Job 不接触任何数据卷，私有签名钥只提供给 seal。Job `backoffLimit=0`，不允许控制器在无法证明旧 VM 已停止时自动重复启动写盘。固定 Job 名为 `sbx-bkp-{attempt_id}-{stage}`；每个持久 stage attempt 只允许一个 Job/Pod。第二次恢复需先由控制面确认上一次 VM 终止、归档旧 Job/Pod UID 后重新受理新 attempt。`backoffLimit=0` 本身不能证明没有第二 Pod；新的 consume-once 准入计划和 nodeguard 单 attempt→Pod 永久绑定共同阻止重复任务。

## 3. CSI 转换和资源所有权

源 Filesystem snapshot 恢复为 Block PVC 必须由可信控制面在**精确派生 VolumeSnapshotContent**上设置 `snapshot.storage.kubernetes.io/allow-volume-mode-change=true`；不能给租户广泛修改 VSC 的权限。[Kubernetes 卷模式转换](https://kubernetes.io/docs/concepts/storage/volume-snapshots/#converting-the-volume-mode-of-a-snapshot)。

跨命名空间不能直接拿租户 VolumeSnapshot 作 `sandbox-system` PVC dataSource。`deploy.py plan-clone` 会读取实时源 PVC/PV/snapshot/content，核对 PVC UID、snapshot UID、CSI driver、源云盘 handle 和 ready 状态，输出同一云快照 handle 的 **Retain 静态 VSC + sandbox-system VolumeSnapshot + Block PVC**。静态引用的创建只能由专用控制面权限执行；不向 Job 授予 CSI/Kubernetes API 权限。创建后将静态 VSC UID、派生 PVC/PV UID 和云盘 handle 记录到资源账本，再运行 `preflight`。原始 snapshot 与静态引用共用云快照，所有引用未释放前不得删云快照。 恢复预检独立使用 `--stage restore --target-pvc-uid ... --target-pv-uid ... --target-cloud-disk ...`，期待值取自新建目标盘的控制面账本，不依赖已经删除的源 PVC/snapshot；拒绝有 dataSource 的目标、错误盘 handle 或异 UID。

`preflight` 拒绝 Filesystem clone、原卷 UID、其他 snapshot、错误 PV claimRef、Delete reclaim、runc 或正在删除的对象。它不提供伪造的“已完成宿主认证”开关。WaitForFirstConsumer 的 PVC 需要先让受门禁的 Pod 完成调度才能绑定；控制面先创建 Pod，但 **CRI Run 许可在 PVC/PV/节点身份确定后才登记**，不能要求所有卷已绑定才创建 Pod，也不能因此跳过启动门禁。

## 4. 三个真实数据阶段

| 阶段 | 输入与身份 | 实际完成条件 |
|---|---|---|
| capture | 只读派生 Block PVC；`sandbox-backup` | `restic init` 新仓库；`backup --stdin-from-command` 固定原始盘读取器，非零退出不建立成功 snapshot；`check --read-data`；dump 全盘 SHA256 等于采集 SHA256 |
| seal | 可信控制面交接的 capture report；`sandbox-backup-export`；无数据盘 | 源 VM 终止/写入冻结后，唯一 snapshot 检查；rclone immutable copy；download 全量比较；vault 仓库 `check --read-data` 和 dump SHA256；最后上传 Ed25519 manifest/signature |
| restore | 受授权 backup_id、平台账本保存的 manifest SHA256 与公钥版本；`sandbox-restore` | 限定路径下载有界 manifest、SHA256+签名+租户身份；全 read-data/dump 校验；精确大小新块盘写入、fsync、全盘 readback SHA256；不挂载文件系统、不自动启动租户代码 |

产品首版只受理 STOPPED_CONSISTENT：在 CSI 请求前必须取得源 VM 及所有历史 launch 的可信终止和清理证据。底层工具保留 CRASH_CONSISTENT 格式兼容，但当前产品 API 不接受热备份。工具不从 `Job Complete`、guest report 或 Pod 删除猜测 VM 已死。捕获结果经固定 `terminationMessagePath` 交给控制面，仍是受精确 Pod/launch 绑定的任务报告，不是终止证据。部分恢复失败后目标盘保持不可用；只有新受理、独占且已确认无旧 writer 的尝试才能重写。

对象路径由 `tenant_id/backup_id` 派生：`tenants/{tenant}/backups/{backup}/repository/`，同级是 `manifest.json` 和 `manifest.sig`。不能在 API 中接受任意 repo URL、object key、rclone config、shell 参数或客户指定 snapshot handle。manifest 固定数据身份、原实例 generation、源 PVC/静态 snapshot/clone UID、原 template digest、requested consistency、原始盘大小与 SHA256、Restic snapshot ID、key_ref、保留时间。请求截止期限、当前云身份和当前 runtime 认证不是历史数据身份，恢复可使用新值；历史主体授权、token、WebHook、调度计划不会恢复。

`SEALED_REPOSITORY` 表示这一个工具任务已完成仓库校验；产品 `AVAILABLE` 还必须同事务确认所有 stage/UID/lease/hold 和签名清单已持久保存。`cloud_restore_tested_at` 初始明确为 null，不能由局部校验填时间。

清单现使用 v2，新增与 seal attempt/epoch 绑定的完整对象库存及独立只读验证器。规范化签名、分片上限、不可变性前提和专属 backup-reader STS 部署合同见 [备份封存清单与控制面验证](backup-vault-verification.md)。旧 v1 清单不能单独转为 AVAILABLE。

## 5. OSS、密钥、STS 与保留

复用现有 IaC 的三个**分离 RAM role**和 backup/backup-vault 分离桶、分离 KMS key。当前 IaC 两桶仍在同一云账户，不能宣称已实现跨账户灾备；若要防御整个源账户失陷，需另行部署备份账户、跨账户 bucket/KMS 授权及独立恢复身份并完成认证。backup 可变仓库有 versioning；vault 有 WORM。每个任务的 `AssumeRoleWithOIDC` 另传 session policy，限制到当前 tenant/backup 前缀及精确 KMS key；restore 只有读，export 不能删除。当前 vault 与源在同地域，是独立对象副本而非已交付跨地域灾备。runtime 不读节点 RAM role、shared home credentials 或环境 AK。

固定的 AWS profile `credential_process` 调用本包 `credentials`，使用投射 token 向固定地域 STS HTTPS endpoint 交换 900 秒凭据，核对 issuer/subject/audience/assumed role/expiry，只向 rclone 的私有 stdio 返回。rclone 1.75.1 的 `shared_credentials_file` 实际传给 AWS SDK `WithSharedConfigFiles`，故文件是 **`[profile sandbox-backup]`** 格式。本地已实测同一长驻进程超期后重新执行 provider，失败不会向对象服务发请求。`env_auth=true` 是为了启用这个明确 profile，不等于允许环境 fallback；supervisor 清空环境凭据/代理，设置 metadata disabled 和空 AWS_CONFIG_FILE。[固定 credential 源代码](https://github.com/rclone/rclone/blob/v1.75.1/backend/s3/s3.go)。

采用虚拟主机式 HTTPS OSS endpoint、禁建桶检查、8 MiB part/2 并发，Alibaba provider 禁用 AWS multipart ETag 假设。不通过添加长期 AK、节点角色或匿名读取绕过 STS 失败。真实云门禁必须验证 SigV4+STS、分片、刷新、KMS、WORM，并以错误 scope/过期 token 的请求失败为负测；本地 TLS 记录器不代表 OSS 兼容性已通过。[OSS S3 差异](https://help.aliyun.com/zh/oss/developer-reference/compatibility-with-amazon-s3)。

仓库密码是随机至少 32 字节的独立 Secret，版本和备份 key_ref 进入受保护清单；Ed25519 私钥与仓库密码分开保存，旧公钥/密码版本必须保留至最后引用销毁。不要将私钥提供给 capture/restore VM。KMS 删除保护和恢复密钥的独立受控备份是上线前提，不能只备份密文。

WORM 禁止正在使用的 mutable repo 上锁。封存使用新备份的独占前缀，先完整验证，再发布 signed manifest；复制只用 copy，禁止 sync/delete。单份 repo 不做 forget/prune。产品保留期为 31–3650 天，并在同一受理事务中限制为不超过审批 profile 的 `vault_retention_days`。这个值必须来自真实 Locked WORM 观察；对象保护期按每个对象的 LastModified 加 Locked days 计算。对象均在备份受理后创建，故审批天数必须覆盖请求的逻辑 `retention_until`，不能用“平台引用存在”替代物理 WORM。

认证读取也核查 versioning 为从未启用（Disabled）。Locked WORM 本身不禁止后续开启版本控制；持续 RAM 隔离还必须拒绝 `PutBucketVersioning`、修改桶/KMS安全配置以及跨 prefix 写入。独立只读现场工具观察现有 anchor、Owner/KMS/ACL/WORM，不能证明 IAM 永远不变、不会欠费或 KMS 永远可用。profile 的有效期与检查证据只构成受控审批窗口，不是这些能力的永久保证。

最终 GC 必须经过独立资源账本，核对 retention、引用、BACKUP/RESTORE/LEGAL hold、云盘身份与可信卸载/闭锁，再由专用身份回收。现控制器完成后只释放计算配额与源 workspace hold；派生盘与对象仓库继续 Retain、继续计入 BACKUP_TEMP_GIB/BACKUP_GIB。它没有 CSI DeleteDisk 或 vault 删除权限。

## 6. 构建、安装与本地验证

生产构建不联网下载依赖。按 versions.lock.json 下载两个官方 linux/amd64 archive 到受控目录；prepare 校验 SHA256 和 ELF 架构，仅提取固定命名二进制。镜像从已锁定 Debian 包复制 Python/OpenSSL 及依赖，没有 apt/pip，镜像需要签名与漏洞评审后填写设置中的最终 registry digest。本文不宣称已经发布或完成生产 linux/amd64 镜像认证；离线构建脚本会在缺少官方校验产物时拒绝继续。 `verify_image.py --image REGISTRY@sha256:DIGEST --report image-evidence.json` 检查真实镜像架构/入口/digest，并在无网络、只读根、drop ALL 的容器内重跑真实 Restic 恢复和 STS 刷新模拟。可用本地 image ID 做发布前检查，此时报告明确 registry_distribution_verified=false；报告始终 UNSIGNED/cloud_verified=false/Kata=false，不能作生产认证。

```bash
python3 deploy/backup/prepare.py --artifacts /secure/artifacts --output .local/backup-build
docker build --platform linux/amd64 --network=none -t reviewed-backup:local .local/backup-build
# 发布签名后的 digest 写入 settings；示例的占位值故意无法通过校验。
python3 deploy/backup/deploy.py install-foundations --context approved-cluster --settings reviewed-settings.json --job reviewed-job.json --volume unused
python3 deploy/backup/deploy.py render --settings reviewed-settings.json --job reviewed-job.json --stage capture --volume sbx-bvol-ATTEMPT_UUID --attempt-id ATTEMPT_UUID --cluster-epoch CLUSTER_EPOCH_UUID > review.json
```

安装只建立专用无 API 权限 SA 与 default-deny/Cilium FQDN 限定策略，既有不属于本包或漂移对象拒绝覆盖。 现有 sandbox-trusted-bootstrap 的 selector 已增加 `k8s:sandbox.platform/backup-id DoesNotExist`；安装器读取实时 CCNP，缺少该排除项直接失败，避免 namespace 的宽泛 Allow 抵消备份限制。备份 CNP 另外拒绝所有主动 ingress 和 metadata/host/API egress。Job 一律输出 `suspend:true`；只能由接入下面生产合同的控制面解锁，不提供 `--skip-gate`。命名空间为现有 sandbox-system，使用 namespace admin 部署基础资源；Job SA 没有 get Secret、exec、创建 Pod 或修改策略权限。禁止把部署账号 kubeconfig 放进 Job。

`reviewed-job.json` 必须由控制面生成，精确字段见 `backup.config()` 和单测 fixture；其中 ID、角色 ARN、桶、key_ref、data_timestamp、consistency、卷大小、截止时间都不是租户可覆盖参数。keys Secret 通过独立 Secret 管理投递，data key 为 `password`、`private.pem`/`public.pem`，文件 0400，以 subPath 只读挂载；新 key 用新 Secret 名，不热换正在运行仓库的密码。

```bash
BACKUP_PYTHON=.local/cluster-venv/bin/python \
BACKUP_RESTIC_BIN=/absolute/path/restic \
BACKUP_RCLONE_BIN=/absolute/path/rclone \
BACKUP_OPENSSL_BIN=/absolute/path/openssl \
deploy/backup/check.sh
```

基础检查包含配置/凭据/权限/隔离负测与官方 Kubernetes/Cilium schema。真实本地测试覆盖 Restic-rclone stdio、新仓库加密、全部数据读取、删除源+mutable 后从独立副本恢复、错误密码、坏 pack、超长流及签名篡改。另一个 TLS 记录器检查真实 rclone AWS4/STS header、单进程刷新与 provider 失败无 fallback。没有真实 OSS 写入、CSI 快照、KVM VM 或云盘恢复测试冒充这些本地结果。

## 7. 常驻控制器、API 与部署顺序

`POST /v1/workspaces/{id}/backups` 要求 `backups:create`、工作区 `If-Match` 与幂等键，返回 202、operation Location 和新的 X-Workspace-ETag。`GET /v1/backups/{id}` 使用独立 `backups:read` 与 tenant/project 范围。请求只有审批 profile 和保留天数；不能带任意云盘、Job 模板、对象路径、角色或 key。

事务受理先锁 workspace，再验实例 STOPPED、所有历史普通 VM 已可信终止且清理、无 execution/active lifecycle/其他数据 hold；原子写入备份 operation、BACKUP hold、八项 tenant/project 计算与存储预留、固定 CAPTURE/SEAL attempt、审计、commit-ordered 项目事件和幂等记录。状态顺序为：

`QUEUED → SNAPSHOT_PENDING → SNAPSHOT_READY → CLONE_PENDING → CAPTURE_PENDING/RUNNING/CLOSING → SEAL_PENDING/RUNNING/CLOSING → AVAILABLE`。

Job 成功只提供数据报告。每个 CLOSING 都永久禁止新 Run，须取得 fresh challenge 对应 mTLS host 证明、实际 Pod 消失及 CAPTURE 精确块卷 detach，才允许下一阶段。AVAILABLE 还要求两阶段清理齐全、独立只读 verifier 的签名/库存/关键对象证据、完整固定身份、公钥指纹和 endpoint 匹配当前有效 profile。同事务发布 AVAILABLE、释放源 hold/计算、保留存储计账。

撤权、到期和明确非零退出不会把残留写者变成“失败即已停止”。尚未有 Pod 准入的操作可原子取消并封闭后续准入；已有准入/许可必须先可信清理。SEAL 成功但一次 OSS 503 会重试到总截止，不能按一次读失败抛弃备份；总截止后仅在无剩余写者时取消。未知宿主/旧 lease/无法卸载继续持有 hold，并保留明确诊断。当前备份分支不把缺 permit/节点失联当成已停止，也未接入备份 purpose 的云 fencing/物理 GC；出现此类故障需要后续精确证据路径，不能手工删 hold 解锁。

部署使用 [controller.py](../deploy/backup/controller.py) 与 [controller.example.json](../deploy/backup/controller.example.json)。示例故意含不能通过校验的占位值。先按 §6 安装独立数据域 SA/网络，准备控制面连接 Secret；三种备份数据密钥必须在下面安装器建立 Secret 保护 webhook 后才创建：

- `database_secret` 的 `url`：只属于 sandbox_backup，RDS TLS `sslmode=verify-full`，`sslrootcert=/run/database-ca/ca.pem`；数据库 CA Secret 含 `ca.pem`。
- nodeguard server CA 的 `ca.pem` 与专用 backup-controller client identity 的 `identity.pem`；不能复用公开 API JWT 或租户 kubeconfig。
- 三种数据密钥 Secret 的名称必须以 `sbx-bkey-` 开头，均必须 `immutable:true`、`type:Opaque`、每份仅一项：仓库密码为 `password`、私钥为 `private.pem`、公钥为 `public.pem`。controller 与 Job 共享同一公钥 Secret；Config 将受限 PEM 转换为固定 44 字节 Ed25519 SPKI DER 核验。私钥只挂到 SEAL Job。

controller 配置中的 reader 由 `reader_config.py --terraform-output ... --output ...` 导出，工作负载 issuer 是 Kubernetes SA issuer，不能换成人类登录的 Keycloak issuer。`deployment` 必须等于同次 Terraform 输出中的部署名称，`clone_kms_key_id` 必须等于 `workspace_kms_key_id`；现有 CSI RAM 只授予该 compute key。render、install-protection 和 install 都要求同一份已审阅的非敏感 `terraform output -json`，并交叉核验账号、region、reader 身份和这两个字段。

```bash
python3 deploy/backup/controller.py render --config reviewed-controller.json --terraform-output reviewed-terraform-output.json > controller-review.json
# 在审批集群上下文执行；此开发任务没有运行该命令或进行云写操作。
python3 deploy/backup/controller.py install --context reviewed-production --config reviewed-controller.json --terraform-output reviewed-terraform-output.json
```

安装器先创建专用 SA、读写范围有限的 RBAC、配置、Retain snapshot class、加密 Block clone StorageClass 和 Kata RuntimeClass；读取真实 SA UID，只添加 admission 配置的 backup 部分并等待 webhook rollout；保留现有 mTLS clientConfig 和 Fail 策略，增加 Job/ConfigMap/snapshot/VSC/PV CREATE 的规则后才部署控制器。已存在但归属或 desired fields 漂移的对象拒绝覆盖。它不激活 profile。Job controller 可配置为精确 `system:kube-controller-manager` 证书主体，或精确 Job SA username/UID；不会对任意 system 身份放行。

初始 backup-reader STS 由同 UID 的独立 init container `--once` 先交换到 memory emptyDir；有有效凭据后才启动 controller 和定期刷新 sidecar，避免启动时凭据文件未出现的竞态。交换失败阻止启动，不能退回节点或环境身份。两个控制器副本使用 PostgreSQL claim/heartbeat 租约；实际 I/O 与账本阶段可重入，已知 UID 丢失不会创建替代卷/Job。mutation 并发 1–8，独立只读 vault 验证额外最多一个，以免长库存验证占满及时停止通道。优雅退出取消当前 I/O、保留持久阶段，重启重新核对；无自动重复 VM attempt。

## 8. Profile 注册与持续现场验真

[profile.py](../deploy/backup/profile.py) 固定 artifact/report schema，静态校验永远输出 `registration_enabled=false`、`live_activation_verified=false`。artifact 的 `enabled` 必须 false；profile/report 均使用 `backup.canonical()` 生成的 ASCII、排序 key、无空白 JSON。报告 `bindings.profile_spec_sha256` 是完整 artifact 排除 `certification_report_sha256` 后的 canonical SHA256；这样更换 issuer/role/key_ref/Secret 版本也必须重新审批，不产生 report hash 循环。

报告须精确绑定 deployment、epoch、镜像 digest、工具 lock hash、账户/地域、两桶、三种 KMS、公钥 SPKI SHA、Locked retention、snapshot/clone class；九项现场测试都附不可替换的证据 SHA 和观测时刻。报告最长 30 天，检查不早于审批前 7 天。静态 PASS JSON 不是运行时权限：owner 注册保持 disabled；激活入口必须自己执行 fresh Kube 网络/Secret/StorageClass/runtime/CSI检查和真实 OSS BucketInfo/WORM/versioning/anchor 读取，再在提交事务前核对私有 verified token、当前 epoch 和资料 hash。撤销只关闭新工作，不阻断已接收任务的安全停机。

CNP/CCNP 只允许固定单 `spec` 合同，任何 `specs` 多规则字段拒绝，以免 union-Allow 绕过限制。额外原生 NetworkPolicy 或未知 cluster policy 拒绝；唯一额外例外是严格 host-only 的 observability TCP 9445 规则，不允许它覆盖备份 endpoint。克隆 StorageClass 每次创建与启动前重新读取：固定 CSI driver、cloud_essd、encrypted=true、审批 kmsKeyId、diskTags/Deployment、Retain、WaitForFirstConsumer、禁止扩容，参数仅允许这四项。VolumeSnapshotClass 在 profile 激活、快照创建及 storage 准入时重新读取，固定 driver、Retain 及唯一参数 snapshotTags/Deployment。标签必须匹配 profile 的 deployment，满足原有 RAM RequestTag/ResourceTag 条件；不放宽 RAM 来补偿缺失标签。PVC 云参数覆盖 annotation 拒绝。

旧 artifact/report 缺 deployment 时禁止注册、激活和新 CREATE，包括 CAPTURE_REPORT、Pod 与 scheduler binding；已经接收的旧 CLOSING 任务仍从固定 permit、Job context 和独立 host proof 收口，不依赖新增标签。上线升级前先通过 owner 撤销旧 profile，并完成旧 writer 的可信关闭；使用新 profile ID、新 SC/SnapshotClass 名称和新现场认证重新注册。安装器拒绝覆盖旧 SC/VSC，不能手工改旧报告或不可变 profile。新增标签的本地合同测试不能替代实际 RAM/KMS、快照克隆或完整 CSI 故障认证。

2026-10-08已完成两个新独立PG数据库的升级回归：旧accepted Job的新增权限拒绝、撤权/失败后的独立mTLS关闭及精确清理通过；持久source身份、克隆PVC/PV、hold和配额预留记录保持，缺proof或错误PodUID不能清理。owner旧artifact/report在正确重算hash后仍被当前部署校验拒绝，现有不可变旧tuple无法注册覆盖或激活；新profile有合法deployment时经真实TLS及Kube协议夹具可正常注册disabled再激活。源码快照 `836f731ae5e95b210602fa4bea1083ebd3e8ea9c37dfea4d5f5ba62592e1b76d` 与详细收据 `.local/backup-legacy-deployment-scratch-20261008/receipt.json` 分列两项。此证据验证实际生产函数与数据库信任边界，Kubernetes/宿主仍是明确夹具，不代表真实云升级或Kata执行认证。

`src/backup_admission_service.rs` 现已连接真实持久授权/一次性 Pod gate、CSI/status/scheduler/Job/Pod/finalizer 分流；Pod 的 Priority admission 默认值只接受精确 `priority=0`/`PreemptLowerPriority`，不接受额外优先级。删除保护只凭新鲜 exact host proof 移除，之后状态清理仍要求该 Pod 的历史证据。调度在 fresh Node UID/boot/profile 上调用独立窄 DB 授权函数，不凭节点标签或 Job SA 猜认证。

宿主 `LaunchBinding.purpose` 已支持 `WORKLOAD` 与 `BACKUP {backup_id,attempt_id,job_uid,stage,image_ref,source_pvc_uid}`；旧 journal 缺该字段只解释为 WORKLOAD，且仍要求原 `sbx-ws-{workspace}` 名称，历史 backup 名不会误归普通实例。备份必须绑定真实源 workspace/instance/generation、实际目标 PVC/PV/云盘和 exact Pod/Node/boot/epoch；SEAL 仅在该 purpose 下允许卷字段为空。`attempt_id=launch_id` 且 Job 名/Pod 后缀精确受限，unknown purpose 拒绝。

SQLite FULL journal 已实现单 launch_id 永久绑定单 Pod，BACKUP 只允许一次有序 RUN→CREATE→START；注册续期不改身份，不重开 CLOSED/UNKNOWN。CRI 对 BACKUP 校验固定容器名、argv、无交互 stdin/TTY、受控 image user-specified digest、唯一 Pod/PV 原始设备路径以及 capture 只读权限，禁止 exec/attach/port-forward。可信 kubelet 将 ImageSpec.image 设为已解析 image ID，而 userSpecifiedImage 保留原 digest，因此不能把两者当同一字符串。[Kubernetes 1.36.4 容器配置](https://github.com/kubernetes/kubernetes/blob/v1.36.4/pkg/kubelet/kuberuntime/kuberuntime_container.go)。

关闭门禁后的进程死亡证明沿用原可信 host observer；raw block 额外检查 Pod 专用 symlink 和全局 `volumeDevices/publish/{PV}/{PodUID}` 实际不存在，mountinfo 检查也覆盖该全局路径。每次 challenge（含 cached death）重新检查，不把某次 CRI Stop 或旧 unmount 时间作为当前证明。[固定 CSI raw 路径](https://github.com/kubernetes/kubernetes/blob/v1.36.4/pkg/volume/csi/csi_block.go)、[kubelet device 权限](https://github.com/kubernetes/kubernetes/blob/v1.36.4/pkg/kubelet/kubelet_pods.go)。这些是源码约束及本地协议/内核测试，仍需真实 Kata/CSI 组合核对。

工作区物理删除服务当前只处理普通工作区 purpose；临时 clone/失败 restore target **不能借用 CSI DeleteDisk 权限或此服务冒充已授权清理**。所有派生盘 Retain，需下一包在独立资源账本中接入 purpose、hold、云盘 exact identity、可信终止/attachment absence 和 tombstone。没有该账本时保留资源并显式告警，不自动删原盘、共享云快照或 vault。

备份密钥的长期身份受同一准入服务保护。安装器建立 `sandbox:backup-key-installers` Kubernetes 用户组的 namespace 内 create 权限；只有该组的非系统用户可创建 `sbx-bkey-*`，Secret 必须无 ownerReferences/finalizers。该组应由独立受控短期 Kubernetes 管理身份获得，不授予任务 SA。专属前缀从首次创建起拒绝 UPDATE/DELETE；任何历史 profile 引用的旧名字也永久保护，即使 profile 已 disabled/过期。不提供通用管理员或 GC 豁免，轮换创建新名字并保留旧钥。

profile.settings.secret_bindings 固定为 password/signing_private/signing_public 三项，各项只有 name、非空唯一 UID 和 content_sha256。摘要针对对应 sole data 原始字节，分别是 password/private.pem/public.pem，不是 base64 文本或 DER 转换结果。完整 profile_spec_sha256 同时覆盖这些绑定；数据库和审计均不保存明文密钥，guest config 不包含绑定。每阶段 Job 创建、Pod CREATE 和 nodeguard 启动登记前重新读取三份 Secret 的 UID/内容摘要，并实时核验 sandbox-runtime-protection webhook 的 Fail、无 selector/matchConditions、精确服务和完整 Secret CREATE/UPDATE/DELETE 规则。控制器和准入仅获得这三个 resourceNames 的 GET 与该一个 webhook 的 GET，不获得 Secret LIST 或修改权限；任务 SA 无 API 权限。

首次运行 `controller.py install-protection --context reviewed-production --config reviewed-controller.json` 建立 RBAC、准入配置和 webhook，不启动备份 controller。受控 key-installer 在该保护下创建三份密钥后，再运行 `install` 启动 controller；不关闭 webhook，也不以启动失败作为安装流程。profile 激活还必须通过 fresh 保护规则检查，单独提交静态报告不能绕过这一步。
