# 恢复流水线开发与生产激活边界

恢复 API 尚未开放，`src/restore.rs` 仅由正常 Cargo 的私有 `cfg(test)` 编译，未导出生产路由或能力。可复现的非秘密 SQL 草案在 `tests/fixtures/restore/0038_restores.sql`，GC companion 在 `0038_restore_gc.sql`，临时元数据准入在 `0038_restore_gc_admission.sql`，历史控制/Job状态在 `0038_restore_control_admission.sql`，初始 raw PVC 准入在 `0038_restore_raw_parent_admission.sql`，owner 节点拓扑收据在 `0038_restore_node_topology.sql`，均不属于正式迁移目录。正常部署仍按 0001–0037 顺序迁移；出现任一恢复 schema 标记后，所有运行角色都必须检查完整 schema 和真实成功的 SQLx 0038 记录。仅应用草案会拒绝生产启动，不能把本地测试或伪造迁移记录当作生产认证。

| 部分 | 实现与当前验收 |
| --- | --- |
| 原子受理 | 同租户跨项目，源 `backups:read` / `backups:restore` 与目标 `instances:create` 同时满足集成作用域、当前项目授权；If-Match 与幂等一起检查。新 workspace、STOPPED instance、RESTORE hold、两级五维配额与源引用同一事务建立。 |
| 源数据身份 | 保留源备份原 tenant/project/epoch/template/key 签名身份。通过独立 OSS 验签与完整库存验证后才推进 VERIFIED；恢复到目标项目不改写原签名。 |
| 当前运行权限 | 重验当前 profile、epoch、独立恢复认证、Secret UID/内容摘要、网络和存储加密。历史 profile 可以停用，密码、公钥、账户、地域、仓库与 KMS 身份仍须兼容。 |
| 初始 raw PVC | 精确 backup SA 的 CREATE 使用独立窄 reader 与完整当前授权，不依赖未来 Job/Pod/PV/permit。实际 API 两次读回相同 Pending UID、完整原始 JSON 和固定规格后，同一事务记录父 PVC UID 与预期生成 PV 名称的早期意图。无已记录父 UID 的 Bound 对象在任何 PV GET 前拒绝；Pending selected-node 元数据的私有链路已有独立 PG/HTTP 验收，正常生成 PV、Bound/binder/CSI 状态准入仍待完成。 |
| owner 节点拓扑事实 | 独立 sealed collector 对照真实节点 enrollment、一次完整 Terraform 文件的双摘要、Node/CSINode 双读、mTLS 和精确实例签名只读云查询。owner-only append-only 收据固定身份、三类独立认证的最短期限与原观测时间。私有 selected-node 消费重新核当前登记、认证和新鲜观测，不凭历史收据年龄自授权限；生产 collector 安装、实云事实认证及 listener 仍未接入。 |
| raw WFFC selected-node | 私有窄 reader/准入已接 Pending PVC 的 SELECT、PROVISIONER 与 RESET。正常父 PVC 双 GET/记录→实际 Job CREATE/GET/记录/unsuspend→一次 Pod CREATE/GET/记录→正常节点 enrollment/owner 收据之后，以独立 admission 只读云身份核实际 Pod/Node/CSINode 与当前完整 pin，再在最终 COMMIT ACK 后复查原有限预算。三次原始失败保留；700 文件原源 `f60c4ece…` 在本地 PG 运行内存 2GiB、swap 上限 3GiB 下新库 1/1 通过（30.88 秒）。当前只证明明确协议夹具的 Pending 元数据路径；正常 Bound/PV、并发节点/claim 漂移扩展、真实 CSI/云及生产容量认证未完成。 |
| 数据搬运 | 实际数据程序先完整 Restic check，写新 rawBlock，fsync，整盘读回 SHA。资源意图与新 raw PVC/PV/云盘身份固定；唯一 Pod admission 与 host permit，实际 mTLS 注册/永久关闭，不把容器报告当主机关闭证明。 |
| RESTORE 专用准入 | 私有服务实际读取恢复 Job/config/raw 意图和固定 UID，校验完整 Job/Pod 形状、控制器身份、当前网络/Secret/StorageClass，并在 workspace→instance→operation→restore 锁内重验授权与租约。单调时钟限制远程观察窗口，pin 包含完整用途映射、四类 UID/spec 摘要和认证元组。独立新库实际业务方法通过；生产 apiserver listener/CSI/删除分支仍未接入。 |
| RESTORE 调度与节点状态 | 私有 `decide` 已接入 `pods/binding` 与 `pods/status`。binding 从真实 GET Pod 取租户/restore，固定已记录 Pod UID、Job owner、完整规格，真实 GET Node 核验专用 Kata pool/taint/Ready/UID/boot/profile，再读 Pod、锁内重验当前授权。Binding metadata 不允许注解/标签被合并进 Pod。历史 status 走独立 closure 锁，固定真实 GET、old/new 与不可变 permit 的 Pod/Node/namespace/spec；撤权、profile/node 禁用及租约过期后仍可关闭。最终 reader 返回后检查单调 10 秒窗口，包含 node 行等锁。真实 loopback HTTP/PG/mTLS 通过，生产 listener 接入仍待完成。 |
| RESTORE 节点授权 | 独立 binding reader 在上述锁后锁定确切 runtime node，重验当前认证、节点启用和认证期限；独立 observation reader 识别已有不可变 RESTORE host permit/raw receipt/Pod UID/name/namespace，撤销后仍可可信关闭。错误 tenant/restore/source backup/node UID/name/boot/profile 和旧 backup/普通 START 借用均拒绝。真实锁等待期间提交节点停用后，binding 拒绝且历史 observation 保留。 |
| 受控 CSI 转换 | rawBlock 可信关闭后创建实际 API 快照，再用共享同一云 handle 的受控 static VolumeSnapshotContent 和目标命名空间 VolumeSnapshot，交付全新 Filesystem PVC/PV/云盘。禁止 patch 原 volumeMode。Raw 使用专用 WFFC，目标 Filesystem 使用专用 Immediate；任何未绑定状态都不能发布交付收据。 |
| 成功发布 | 实际 Job/config UID 清理和缺席收据、raw 写入关闭及新 FS 交付收据全部满足后，窄数据库函数发布默认 STOPPED，固定 external_resources 的目标 PVC UID；归还已关闭恢复 VM 的 CPU/MEMORY，释放目标 RESTORE hold。 |
| 普通首次 START | 六条运行上下文读取独立恢复收据，固定 PVC UID/PV UID/PV name/disk，worker/admission/permit 在锁内重查。真实私有工作线程、准入服务、普通 permit 与 mTLS 注册组合测试已通过；替换 PVC、PV、云盘 handle 均拒绝。 |
| 从未普通 START 的 DELETE | 实现独立恢复交付来源，要求当前永久 never-authorized birth closure、无任何普通 admission/permit/START 历史、恢复 writer 独立关闭和实际清理；仅归还仍持有的实例额度。删除来源为 ordinary permit 或 restore delivery 二选一的复合外键。独立新库真实 PG/mTLS/signed TCP 组合通过，并发幂等、固定 UID/PV/disk 拒绝、实际缺席后一次存储结算，源与临时额度保留。 |
| 临时资源 GC | 独立 OIDC/STS 精确资源传输、独立 SCRAM 数据库角色、持久审阅/调度/租约/单次 dispatch/UNKNOWN 查询调谐、两个物理缺席证据、六个 UID 元数据清理与两级 TEMP 一次结算已实现私有闭环。窄 UPDATE/DELETE 准入的最新真实 PG/HTTP/mTLS 专项通过，逐一核验三个受保护 kind/path/UID 的 PATCH、六个固定 path/UID 的 DELETE、全部临时 UID 缺席和源目标保留。云/CSI 状态仍是夹具；正式认证和 apiserver/RBAC/调度器接入前继续关闭。 |

恢复新 writer 的有限授权预算必须与完整授权谓词共享同一 SQL statement：在六个必要的租户/精确项目权限范围内分别取仍有效替代 grant 的最长有效期（永久授权为 infinity），跨范围取最短值，再与 restore/job/operation/lease/profile 截止相交。预算与稳定身份 pin 分开保存。读 SQL 前的单调 Instant 同时扣除查询、锁等待、外部 GET 与最终 COMMIT ACK 时间；首次 ACK 和最终 ACK 后再次检查。

这个同读点约束依据 [PostgreSQL 17 函数易变性文档](https://www.postgresql.org/docs/17/xfunc-volatility.html)：STABLE 函数沿用调用语句快照，VOLATILE 函数内部的每个查询重新取得快照。不能先在一条查询读取长期替代 grant 的预算，再在另一条查询以剩余短期 grant 得到 true 并组合二者。该文档是实现依据，当前没有声称已复现这种并发转换的利用。真实延期 ACK 专项单独证明 backend 已 COMMIT、事务锁释放而响应尚未返回时，跨过短 lease/source grant 后仍在原 4 秒业务预算内拒绝，并在 pool drain 后 join 代理、确认 backend PID 缺席；它不代替生产 listener、CSI 或云认证。

## 已执行的本地验证

- 源身份/密钥兼容/签名上下文及受控 CSI manifest 测试通过。普通与受控恢复 manifest 都显式覆盖 1024Gi → Kubernetes canonical 1Ti，避免不同容量字符串造成身份误判。
- PostgreSQL 17 的独立数据库正常迁移 0001–0037，再事务应用恢复草案；所有角色生产 startup 仍拒绝草案。未修改其他库的迁移账本。
- 真实 mTLS、Ed25519、OSS 请求签名，与状态化 Kubernetes 服务组合通过：跨项目原子受理、并发幂等、唯一 admission/permit、撤销后永久关闭、CSI 新 FS 固定身份、实际 Job/config 清理、成功 STOPPED 发布。
- 正常 Cargo 的独立新库用真实 lifecycle/worker/admission/permit 业务方法完成首次 START；三类同名资源身份替换拒绝，实际 Nodeguard mTLS 注册，再由状态化服务观察 Ready 进入 RUNNING/SUCCEEDED。真实项目 grant 管理方法覆盖委派期限、过期拒绝、版本续期、撤销与恢复。恢复 HTTP 路由仍未开放。
- 首次 START 后真实文件受理产生元数据行：专用 backup 本租户 SELECT 为 1，外租户为 0，读取 parts、UPDATE file 和 UPDATE instance 的状态均得到 PostgreSQL 42501。私有 publish 的 deferred 文件一致性校验仍实际提交成功。
- GC 快照传输四个实际 TCP 测试覆盖 ACS3/STS scope、Force 默认拒绝、单次写 UNKNOWN、SnapshotSN/来源盘/尺寸/pagination 变化、目标盘 serial/创建时间/SourceSnapshotId 与缺失目标证明拒绝。
- 独立 GC 登录直接 INSERT result 的真实否例覆盖旧 lease、异 tenant/restore、倒填与未来 recorded_at；当前 UNKNOWN 仅作为请求结果，不能生成物理缺席或归还 TEMP。实际 `pg_blocking_pids` 确认 finish 等待 event head，10 秒租约在 11 秒锁等待后过期，数据库 23514 回滚两笔共 80Gi TEMP 结算、settlement、audit 与 event；新 claim 重试仅结算一次，随后普通 START 通过。
- 恢复准入实际读取正常 admission 角色的 RLS 数据，并通过 Job/config 创建、已绑定 Job 的受控 unsuspend、12 个不同 Pod review 仅一个胜出与相同 review 重试。源 scope、控制器、privileged/hostPath/image/spec、Secret UID 替换、profile 停用均拒绝；实际 workspace 锁等待后提交 profile 撤销，再授权拒绝且没有 Pod admission。正式 profile guard 直接拒绝 clone StorageClass 变更 23514，没有禁用不可变约束。
- 专用恢复节点 reader 只给 admission 角色 EXECUTE 权限：未获 Pod admission 时两者拒绝；消费 admission 后允许 binding、尚无 host permit 时拒绝 observation；实际创建不可变 permit 后两者允许。节点停用和项目授权撤销分别使新 binding 拒绝，既有 permit observation 仍允许随后真实 mTLS 关闭。测试用 `pg_blocking_pids` 确认 reader 等待实际 workspace 锁，再提交节点停用；既不把 SQL 超时当授权拒绝，也不借用源备份/普通实例的节点权限。
- 调度与历史状态验收通过实际 loopback HTTP Kubernetes 客户端：scheduler UID/用户名、Binding Pod UID/目标 namespace/Node UID、live Pod UID/spec/Job owner 和真实 Node UID/boot/profile/Ready/pool/阻断 taint 替换均拒绝。真实 workspace 锁等待期间提交 node/profile 禁用、cancel 和 lease 过期分别得到 403；真实 Node GET 延迟 9 秒后等待 node 行 2 秒，最后 reader 返回后因超过单调观察窗口而拒绝，生产 3 秒 lock_timeout、10 秒 statement_timeout 保持原值。
- 已有 immutable permit 的 assigned-node status 在 RESTORE_CLOSING、原 grant 撤销、profile/node 禁用、lease 过期时仍允许；GET/old/new 的 UID/name/namespace/spec/protected metadata/deletion fields 必须一致，原 deleting Pod 可继续状态更新。没有该 permit 的 exact termination proof 时缺失保护拒绝；实际 Nodeguard mTLS proof 入库后，Kubernetes 省略空 finalizers 字段的 late status 通过。正常长套件用真实 controller heartbeat，显式过期否例暂停心跳；没有延长生产 lease 或让失效 claim 复活。
- Kubernetes/CSI/cloud host 状态为明确测试夹具。未执行真实阿里云、CSI 驱动、Kata VM、RAM 角色授权或生产数据读回验收。

最近的针对性验收名称为 `restore::tests::restore_gc_direct_results_and_event_wait_cannot_bypass_current_claim`，独立库 `sandbox_restore_acceptance_179143689089363501_test`，42.94 秒内 1/1 通过。实际捕获源码 SHA256 为 `8a695857f0fb8fcd8cd115ea485fe75f99581454afd5e58863368fbfc4a3d708`，不可变快照 `.local/evidence/restore/source-179143688952588683`，日志 `.local/evidence/restore/gc_guards-179143689089363501.log`。这些本机证据不随版本库分发；下面的 tracked runner 可从干净检出重新产生独立证据。

恢复准入、实际调度 binding/status 与节点 reader 验收名称为 `restore::tests::restore_admission_job_config_pod_current_authority_and_one_shot_creation`，独立库 `sandbox_restore_acceptance_179144288482092546_test`，30.77 秒内 1/1 通过。实际源码 SHA256 `d19584ee2d6d6a0ca8d5050b8e2cb80898aefbb666a1c6b6a81260020806bc12`，快照 `.local/evidence/restore/source-179144288426493653`，日志 `.local/evidence/restore/admission-179144288482092546.log`。它调用真实准入业务方法、loopback HTTP Pod/Node 查询、窄 SQL reader、实际锁等待与最终观察窗口否例、后续 Nodeguard mTLS 和普通 START；未宣称已验证恢复专用 apiserver HTTP/mTLS listener 或真实云 CSI。全目标严格 Clippy 和格式检查通过。曾暴露的大异步帧栈溢出已通过拆分/堆上保存新工作流修复，实际使用默认测试栈通过；未提高栈限制。

同一完整验收随后将 Nodeguard 夹具真正接上生产 `control_mutual_tls` 与 `serve_control`，在新独立库 `sandbox_restore_acceptance_179144360892734592_test` 中再次 1/1 通过，22.98 秒，266 项过滤。该源码 SHA256 为 `a0639dfc74b879fc3066240560cd96c175f5b00b99b3c3b71f14f39dd6dd92ac`，快照 `.local/evidence/restore/source-179144360747357597`，日志 `.local/evidence/restore/admission-179144360892734592.log`。它证明私有恢复业务与真实 control mTLS 监听器的组合兼容；HTTP Pod/Node 和宿主响应仍来自明确夹具，不代替生产 Kubernetes apiserver listener、Linux 内核观察或真实云认证。后续 transport 变更须另存新源码点验证，不回填到这份证据。

GC metadata 准入的最新完整验收为 `restore::tests::restore_gc_metadata_admission_requires_closed_exact_resources_and_live_claim`：独立库 `sandbox_restore_acceptance_179145546899778579_test`，61.62 秒内 1/1 通过、279 项过滤，退出状态为 0。完整普通 Cargo 源码 SHA256 为 `d5ecd2e4764c6e860b005e439648ac5e88b2655eb75c094ec87c9fa8303d850d`，快照 `.local/evidence/restore/source-179145546880180636` 包含根 `build.rs` 和 `rust-toolchain.toml`；日志 `.local/evidence/restore/gc_admission-179145546899778579.log` 的 SHA256 为 `a2edd3b5044e7a7099a6fd97220c65cafcdcf66b476d86c2a864d8f5f8b5be4a`。该源码点包含授权谓词与预算同 statement 修正。实际案例覆盖未设置 tenant 的 resolver、错 UID/跨 scope、窄角色直接访问表的 42501、委派与替代授权、首次及最终 COMMIT ACK 后过期拒绝、scheduler/status、撤权后真实 control mTLS 关闭、GC 的六个固定 UID 与源目标保留。GC 的真实第二次 COMMIT 已释放事务锁，代理仅延迟该次 ACK 3 秒，跨过 2 秒 lease 后仍在 10 秒总观察窗口内得到 403；pool drain 后取消并 join 代理，实际 backend PID 消失。PostgreSQL、HTTP 和 mTLS 是真实传输；云资源、CSI 和宿主观察状态为明确夹具，不代表真实 RAM、CSI 或 Kata 认证，也没有声称已并发复现多 SPI 快照切换的利用。

所有原失败源码、数据库和日志独立保留，不回填为成功。首轮 `f2e83c35a49d4185ff7c21cd856b48973927442bf5e0030b3e49af2da342e52f` 在公共恢复/关闭/交付夹具完成、进入新增 GC 工作流时出现测试栈溢出；原日志 `.local/evidence/restore/gc_admission-179144963175598868.log` 没有精确栈回溯，不能据此认定某条 SQL 已执行。`Box::pin` 只用于夹具的 `gc::run`、`controller.reconcile` / `reconcile_resources`、新增 COMMIT 与收尾 helper 的较大 future，没有改生产业务或提高栈限制；该旧快照漏根构建文件，保留原捕获范围。后续失败包括夹具 503 重试、将无自身 finalizer 的合法 DELETE 误列为否例、代理自然 EOF 未收尾、将三个自身保护对象错计为至少四个（该断言 panic 后另出现栈溢出），以及期限测试更新授权后仍缓存旧 ETag。现在明确预置否例保护、核对精确三个保护 kind/path/UID、cancel→join→实际 PID 缺席，并在真实 API 拒绝旧 ETag 后 GET 当前版本再撤销；没有放宽生产 guard、If-Match 或期限。CREATE DATABASE 前曾被本地 PostgreSQL recovery mode 拒绝的一轮未进入业务，不计为业务成功或失败；未重启、删除或改写旧数据库。

## 普通运行与删除合同

worker、admission、termination、gateway、file gateway、never-authorized GC 统一读取独立恢复交付收据。全无恢复 schema 的正常 0001–0037 部署返回 None；带恢复 lineage 的工作区缺收据、epoch 不匹配或 schema 不完整必须拒绝。持久身份使用 PVC/PV UID 和云盘 handle，resourceVersion 只作为单次 Kubernetes 修改的并发条件。

准入在实际 PVC→PV→PVC 查询之后，重新锁 workspace→instance→当前 operation，重验收据、epoch、权限、当前模板/安全配置和 claim，再允许创建 Pod。普通 launch_permit 插入还有独立固定恢复身份约束，不能凭相同 datasource 名称收养替换对象。新目标采用当前选定 template/security_profile/flavor；默认 STOPPED 不执行源环境的旧模板。

默认 STOPPED 的目标无需先 START 才能删除。它没有普通 launch_permit/last_termination_proof，必须以独立恢复交付和永久普通 birth closure 为来源，严格排除普通 writer 历史，同时保留恢复 writer 的独立可信关闭。已有普通 writer 的目标沿用原有完整终止证明路径。DeleteDisk 响应、404 或 Pod 缺席单独都不能释放存储；先持久写入 intent，后确认确切云资源缺席，再执行 UID/resourceVersion 绑定的 PVC/PV 清理与账本结算。

## 从干净检出重复私有验收

先执行 `scripts/dev-dependencies.sh`，使用它生成的本机独立角色环境文件；需提供 `TEST_DATABASE_URL`、migration、worker、gateway、admission、termination、fencing、volume deleter、backup、restore GC 共十个 `TEST_*_DATABASE_URL`。不得输出连接串。专用 GC 必须使用 host 侧 SCRAM；测试显式要求正确密码通过、错误密码拒绝。

执行 `scripts/test-restore.sh <private-env-file> all`，或选择 `start`、`delete`、`gc`、`gc_guards`、`admission`、`gc_admission`、`control`、`storage_mapping`、`raw_parent`、`node_topology`。Docker socket/config 可用 `RESTORE_TEST_DOCKER_HOST`、`RESTORE_TEST_DOCKER_CONFIG` 指定。每个 case 创建全新唯一数据库，不 DROP/FORCE/reset 旧库；正式迁移始终只有 0001–0037，再显式应用 tracked 草案和角色脚本，最后断言正常 production startup 拒绝草案。正常 37 时可启动、单独残留一个 false-only 恢复 metadata 函数时拒绝、移除 probe 后 37 再通过；该 probe 不授权 writer，不伪造 SQLx 记录或认证。

runner 捕获源码（含根目录 `build.rs`、`rust-toolchain.toml`）、公开测试夹具与编译所需部署合同的不可变快照，使用原名普通 Cargo package、原 `cfg(test)` 和正常 migrations，不使用另名私有 crate 或伪造 SQLx 记录。环境和凭据只在子进程内存中按新 DB 路径重映射。每个日志、数据库、UTC、源码 SHA256 和退出状态独立保存在 `.local/evidence/restore`。GC case 清理临时 snapshot 后继续执行真实普通 START，从已有固定 FS PVC/PV/disk 启动，不读取中间 snapshot 对象。

## 临时资源额度、保留责任与能力声明

恢复在 tenant 与 target project 两级各保留 `BACKUP_TEMP_GIB = 2 × source.size_gib`：新 raw 云盘一份、新 raw 派生云快照一份。static CSI 内容和跨命名空间 VolumeSnapshot 共享同一个云快照，不重复计费量。新 Filesystem 云盘单独计入 WORKSPACE_GIB；源 backup/vault 不重复算本次新临时资源。平台用完整卷容量作为保守配额上界，真实账单仍按云商计费口径核对。

STOPPED 发布保留 raw 云盘和派生快照的 ALLOCATED 额度，source backup FK 仍保留。这些临时资源的 retention owner 是 restore_id。没有显式、审阅过的保留截止和清理策略，或任何身份/关闭证明/账户/地域/KMS/租约不确定时，保持资源与额度。不能把正常成功后的永久积累当作完成产品。

派生快照只用于 Block→Filesystem 交付。**新工作区不支持云厂商重新初始化磁盘**；恢复能力由独立源备份提供。阿里云在快照被用于创建磁盘时，默认 Force=false 拒绝删除；Force=true 删除后该磁盘不能从原创建快照重新初始化。[DeleteSnapshot 官方合同](https://help.aliyun.com/zh/ecs/developer-reference/api-ecs-2014-05-26-deletesnapshot)

因此 GC 默认 Force=false。允许 Force=true 的策略必须一次性持久绑定审阅记录、restore_id、tenant/project/epoch、该派生 snapshot 的 serial/creation/source raw disk、目标 FS PVC/PV/disk 身份，不触及 SourceSnapshot 或源备份。专用 STS 会话在 RAM 角色权限交集内只授权这一个快照的读/删、这一个 raw disk 的读/删与关闭自动快照级联、目标 FS disk 只读；不授权 Stop/Detach/Tag、目标盘删除或其他快照删除。官方 DescribeSnapshots 与 DescribeDisks 都支持相应精确资源 ARN；部署仍必须通过真实 RAM/STS 验收。[DescribeSnapshots](https://help.aliyun.com/zh/ecs/developer-reference/api-ecs-2014-05-26-describesnapshots)，[DescribeDisks](https://help.aliyun.com/zh/ecs/developer-reference/api-ecs-2014-05-26-describedisks)

GC 必须持久追踪 raw disk 与 snapshot 两个独立身份和调度结果。UNKNOWN 先 Describe 调谐，不盲目重放；删除确认仅来自对应 exact-ID 云查询，元数据清理仅来自绑定 UID 的实际缺席。当前配额在每级账户是一笔 2×容量 reservation，因此至少等两个物理资源和全部相应 CSI/raw PVC/PV UID 清理全部确认后，才允许一次释放该笔额度，不能提前释放一半而使账本失真。源 lineage 的解除另需不可变 GC 决定和审计，不能随着临时资源级联释放。

所有 GC definer、dispatch 与证据入口自己按 workspace→instance→相关 ordinary/restore operation→restore/run→资源→quota→event head 顺序锁定并在等待后重验 epoch、writer 与租约。审阅不可变；过期后禁止新的写入，已发出的请求仍允许 exact-ID 调谐。续审只能用指向当前审阅的不可变 successor，保持所有资源身份相同、没有活跃租约且未结算。专用 GC 无权创建审阅、修改实例/工作区/配额或直接改变 run。

Result 插入必须绑定当前 run 的 lease token、审阅和 immutable dispatch 身份，不能让过期请求结果附着到后续 claim。Result 是 intent/outcome 记录，不是 provider absence 证明；生产激活还需真实云查询传输及独立审计的认证。finish 在 audit/event 等待后重新核验 claim、epoch 和 writer，最终 SUCCEEDED 更新触发器再次核验原 RUNNING lease；拒绝会回滚整个结算事务。

Kubernetes 清理保持 `Retain`，只对固定六个临时 UID 操作。私有 `RestoreGcAdmissionService` 只接受固定 `sandbox-restore-gc` ServiceAccount 的实际 UID，且只允许上述六个已绑定 UID 的 UPDATE/DELETE。生成的 CSI 对象不依赖可变 tenant 标签：不可变 routing index 仅保存 UID、scope/name/kind 和记录 IDs；admission 角色仅获得窄 resolver/locked reader EXECUTE，没有索引或云证据表的读写权限。UPDATE 仅移除自身保护 finalizer，完整保留其他 metadata/spec/status，DELETE 必须匹配当前 UID/resourceVersion，拒绝未知删除标志与 Orphan；真实 GET 后再次按完整锁顺序重验 epoch、有效审阅/claim、两个 exact dispatched physical absences 和永久 writer closure。reader 在最后数据库 clock 处返回 lease/review 剩余整数微秒预算，与稳定 pin 分开；每次 reader 调用前的单调 Instant 保守扣除查询、等锁和 COMMIT ACK，提交返回后仍须在预算内。首个 SQL I/O 前开始的单调 10 秒窗口另涵盖全部数据库等锁、HTTP 读取和最终提交。当前属于私有实现，上述完整专项不代表生产 webhook 接入或云认证。

确认两个物理资源缺席后才移除平台自己的 `sandbox.platform/backup-protection`，保留 Kubernetes/CSI finalizer，并继续 DELETE→GET 实际缺席；未知、替换 UID 或 finalizer 未释放都会保留 TEMP。最终 FS PVC/PV/disk 与原 source backup 不在该删除范围。

## 正式开放前的剩余门槛

1. 将已验证的独立 GC admission、专用 RBAC 和调度器与正式 schema gate 一同对接；失败/取消恢复的临时资源清理仍须独立可信关闭，不能借用 AVAILABLE 的成功清理权限。
2. 将已验证的私有 Job/config/Pod RESTORE admission、scheduler binding/status 和独立节点 reader 接入经过认证的 apiserver listener；补齐正常 CSI status 与失败 Job/config/Pod 的 UPDATE/DELETE 历史清理准入、备份控制器恢复分支，以及取消/失联/超时与安全失败清理。
3. 完成独立恢复认证管理、真实委派 grant/期限/撤销、API/OpenAPI/SDK 和产品能力声明。
4. 通过真实阿里云 RAM/CSI Block→Filesystem、Kata/Nodeguard、OSS WORM/KMS、当前模板启动/读回，以及升级/回滚演练。
5. 门槛全部通过后才正常迁移 0038，所有角色完成启动检查，开放恢复能力。

### 历史控制与真实失败专项（2026-10-08）

Job/status独立固定Job UID/context/完整原sourceIdentity，仅允许精确Job controller改变status；不要求未来permit或delivery。Pod DELETE保留产品终止保护，只有固定历史RESTORE permit的独立可信关闭才可移除；Job/config Foreground清理还要求同proof的实际cleanup、Pod GET404及完整空Job-Pod清单。GC与backup SA分离，ControlPlane仅接受实际kube-controller-manager身份；所有更新都真实GET旧对象，且只改变各自允许的finalizer。旧proof/receipt为永久身份，新观察自第一SQL至最后COMMIT ACK共10秒，不能重盖历史时间。

671公开文件的不可变源点 `26d7d953cd447b586969767ef3d81e0e4c011d5340b05a4e63702fe23af61d1e`、独立库下1/1通过（56.83秒）：失败exit1/reportNone、撤权CLOSING、真实mTLSproof、own/tracking PATCH、Foreground DELETE保留/重试、独立GC PATCH和最终404；发布拒绝，源/临时媒体/hold/配额完整保留。延迟COMMIT ACK用真实后端已释放锁的11秒停留证明403，proxy join和PID缺席随后核验。证据 `.local/restore-control-admission-scratch-20261008/receipt.json`；旧编译与栈溢出失败不覆盖，仅测试Future堆分配修复。

生产CSI接线还必须解决delivery WFFC等待普通START的循环：使用认证的同workspaceKMS专用raw WFFC和delivery Immediate SC，固定normal→raw/delivery用途映射、SC/SnapshotClass UID/spec、Deployment标签、云盘single-AZ及普通START的PV topology消费约束；父PVC/Snapshot UID要先记录，再准许无标签的官方生成PV/content，不能要求尚未产生的Bound/Ready receipt。现有fixture直接填Bound对象不证明上述时序。raw WFFC自身目前没有ledger循环，补CSI selected-node、provision/binder/status及finalizer的精确主体和状态准入；正式0038和外部恢复API在完整闭环及实云认证前保持关闭。

### 恢复存储用途与不可变映射（2026-10-08）

storage_mappings 替代仅含名称的认证数组。normal、raw Block WFFC、delivery Filesystem Immediate 和 SnapshotClass 分别固定 name/UID/spec SHA，绑定 compute KMS、账号、地域、Deployment 和 Terraform 三个故障域。API 不接收任意存储类；受理事务按项目 normal 选择唯一认证映射、保存完整 contract，并让新 workspace 使用 delivery 类。SQL INSERT/current authority、不可变 guard、准入 pin 和普通交付 provenance 复核完整元组；normal 漂移使新工作拒绝，幂等重放仍返回原结果，历史关闭继续使用原身份。

初始资源写入前真实读取三类 SC 和 SnapshotClass，后续阶段复核实际用途。class GET 保留原始 JSON，避免客户端丢弃未知 metadata；策略、UID 和摘要都须一致。安装命令见 docs/restore-storage.md，输出只表示候选映射，不生成云认证或开启恢复。

681 个 Git 公开文件的不可变源点 `0326435bc7e8569d248c2334748ee7e3929dd1f5cd0031619bef161397e94185`，新独立数据库下 storage_mapping 1/1 通过（44.28 秒）。真实 PG 验证认证形状/report 绑定、256/257 KMS 长度、最小角色、受理/不可变 contract、normal 漂移/原结果重放、Pending/Available delivery 类固定和普通 provenance。实际 TCP HTTP 覆盖 84 个类漂移拒绝，每项核实目标 GET 到达且全部请求为 GET；合法初始子例真实创建一份 Pending PVC，无伪造 Bound。共享流程中的 Bound/Ready、云和宿主状态仍是明确夹具；真实 mTLS、普通 START 和文件元数据权限通过，不代表 CSI/Kata/云盘认证。restore compute KMS 与 capture clone KMS 特意设为不同，只证明代码消费冻结映射，不认证实云跨 Key。

同一源点另四个新独立数据库的首次 START、从未启动 DELETE、GC metadata admission、失败历史控制分别 1/1 通过（43.60/42.92/64.78/54.98 秒）；receipt 为 .local/restore-storage-contract-verification-20261008/regressions.json。安装器 9 项 Python、两个固定官方 Kubernetes schema 对象通过；另一个独立小库的 35 项 SQL JSON 边界只覆盖三个 shape 函数，不代替角色/事务专项。首轮与后段测试 Future 栈溢出、PG 正则重复上限和列/参数歧义的失败快照、数据库、日志均保留。只调整测试 Future 堆分配，不提高生产栈/期限；SQL 改为显式长度和列名，拒绝范围保持原值。

上述存储映射片的整仓普通 Cargo 检查为 328 项通过、215 项明确 ignored、48 个测试程序、0 失败；严格 all-target Clippy 和 fmt 通过。681 公开文件检查点 .local/evidence/checkpoints/read-gc-1791465674722662000/record.json 的 SHA/mode 在运行前后不变，后续只有验收文档变更，不回填为同一源点。实际专项记录与普通检查点分别保存，不将 ignored 专项合并为普通通过数。

该存储映射检查点尚缺初始 PVC 与早期父 UID 意图；以下开发片已补齐初始阶段。生成 PV、selected-node/CSI 状态准入、真实云资源身份与 single-AZ 收据、普通 START 的拓扑消费约束仍待完成。正式 0038、生产恢复 listener、worker 分流和外部 API 继续关闭。

### 初始 raw PVC 与父 UID 意图（2026-10-08）

独立 raw reader 在 workspace→instance→operation→restore 顺序下锁定当前记录与意图，要求 BLOCK_PENDING、当前 RUNNING 租约、有效 profile/epoch/恢复认证、已独立核验的源库存和源/目标 hold，且尚无父 UID、raw receipt 或 permit。六个必要权限范围的最长替代 grant 与最短整体期限在同一 SQL statement 计算；首次及最终真实 COMMIT ACK 后都检查原单调预算。CREATE 精确绑定 backup SA 用户名/UID、恢复命名空间和完整冻结 manifest。Kubernetes 在 CREATE 准入前已生成的 UID/creationTimestamp 与内建 PVC protection finalizer允许通过；未知字段、行为注解、owner/deleting、非空 status 和未来 PV/UPDATE/DELETE 均拒绝。

写入后用真实 HTTP GET 保留原始 JSON，两次读回 canonical 非零 UUID、server bookkeeping、唯一 PVC protection、完整标签/规格和 Pending phase，不丢弃未知 metadata。HTTP 409 与丢失 ACK 使用同一路径，源 UID 复用或两次 UID 不同拒绝。父 UID 与 `disk-<canonical PVC UUID>` 的 identity-only PV 意图同事务提交，PV 意图不含尚未生成的 UID。无数据库已记录父 UID 的 Bound 对象直接拒绝，不能通过合法 Bound 规格绕过 Pending 父身份记录。生成 PV 名称属于固定 renderer 合同，仍须通过固定 Ali CSI vendor 版本实测；现阶段不授权生成 PV，也不新增宿主 permit。

Kubernetes 的 CREATE status 清空与 GET 默认 Pending 依据固定 [PVC strategy 源码](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.36.4/pkg/registry/core/persistentvolumeclaim/strategy.go) 和 [core defaults 源码](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.36.4/pkg/apis/core/v1/defaults.go)。客户端丢失 ACK 用例保留锁定 kube 客户端默认重试：503 后可以再次 POST，再经 409 与两个稳定 GET 恢复，证明同一资源/账本身份，不宣称只发一次 POST。

686 文件不可变专项源 `1ef88d0f6a31aa24d7e11658396d76026e535c235938ff1694def8dbd0cd24a8` 下，六个新独立数据库的 GC metadata、失败历史控制、raw_parent、storage_mapping、never-started DELETE、GC guards 分别 1/1 通过（59.57/52.31/16.92/40.06/40.04/67.90 秒）。`.local/raw-parent-candidate-20261008/regressions-v3.json` 固定各库、日志 SHA 和运行前后全部公开源码不变。raw_parent 覆盖实际 CREATE/GET、22 个 manifest 和四个主体否例、16 个依赖漂移、身份与原始 JSON 读回否例、无父 Bound 拒绝、409/丢失 ACK、原子意图与 UID 替换拒绝，以及首次/最终租约和最终源 grant 的延期 ACK；后端已 COMMIT/释放锁后仍拒过期授权，代理随后 join 并核验 PID 缺席。源备份原签名 epoch 保持不变；目标新 epoch 的测试节点由既有夹具登记，不声称该子例走了真实节点安装登记。未调用真实 VM birth 验证，只核验没有 permit/关闭证明和源/hold/配额变化。

首次 raw 专项的缺 RuntimeClass 依赖夹具、错误预期默认重试行为，以及较早六项回归的测试栈溢出均保留原日志与快照；测试把一段初始化配置拆为独立盒装阶段，没有提高栈或生产权限/租约/时间预算。修正前的通过点缺少无父 Bound 否例，不能替代上述最终六项结果。该 raw 开发片的整仓普通检查为 331 项通过、216 项明确 ignored、48 个测试程序、0 失败，严格 all-target Clippy/fmt 通过；`.local/evidence/checkpoints/read-gc-1791472186636201000/record.json` 的 686 文件 SHA/mode 在运行前后不变。验收结束后只补三份说明文档，实际专项与普通检查计数分开保留；它们均不构成阿里云/CSI/Kata 认证或上线完成。

### owner 节点拓扑观测与不可变收据（2026-10-08）

安装 owner 的私有 collector 先验证六张权威表的所有权，再读取 exact 当前登记节点/enrollment/backup profile/恢复认证。原始 Terraform 文件只读一次，完整 raw SHA 匹配 enrollment，独立 canonical SHA 匹配恢复报告；支持无重复 key 的完整 JSON，整数限 i64/u64，拒绝 `-0`、浮点、指数、越界和任何敏感 output wrapper。canonical 使用与安装器一致的排序、紧凑 UTF-16 ASCII 转义，未知的非敏感 output 仍参与全文件摘要。UTC 时间限定真实日期、00..23 时/00..59 分秒和最多六位小数，SQL 与 Rust 都拒绝 PG 会归一化的 24:00:00 和闰秒输入。

实际 Node/CSINode 前后双读核对固定 UID、boot/profile、Kata pool/Ready/阻断 taint、精确 driver/nodeID/四个 topology key、Node owner 与三 AZ 认证范围；真实 mTLS client 的配置身份必须与登记 node 完全相同，正常节点 enrollment observer 也在任何 GET 前增加相同校验。签名云查询固定 OIDC subject、调用账户/role ID、单实例 ARN 的 `DescribeInstances` 与 `GetCallerIdentity` 最小 session policy，核对 zone/VPC/vSwitch/private IP/Deployment/Role/Running、唯一实例/标签、无分页和原始响应摘要；没有云写操作或可反序列化的 verified proof 构造器。现 collector/云 wrapper 仍仅由私有测试编译。

sealed proof 固定一次 ID/完整 payload、首读之前的总预算、10 秒实际观测窗口和原认证到期；末读 pin 与首读必须一致，publication 前及真实 COMMIT ACK 后检查同一原预算并验证完整持久 row。SQL publisher 为 SECURITY INVOKER，按 configuration→profile→恢复认证→node→exact enrollment 加锁后才检查当前状态与观测新鲜度，期限严格取 exact enrollment/恢复认证/backup profile/恢复 review+30 天的 LEAST。收据只允许 append，相同 ID/原 payload 重放返回原事实；changed payload 或同一身份换 ID 拒绝。历史事实不刷新时间、不授当前调度权限，后续消费者仍须复核当前认证与实际节点/云状态。

692 个公开文件不可变源 `20b125ff195a3e9fe672ebe076e58621a191a3e2d26e01a06cf8dfc4360337c4` 下，独立库 `sandbox_restore_acceptance_179147276472679604_test` 的 node_topology 1/1 通过（4.59 秒），receipt `.local/raw-selected-node-candidate-20261008/actual-v1.json`。新节点通过原 `observe_node` 的 Node→真实 mTLS→Node 和原 `commit_enrollment` 登记，没有伪造 LiveEnrollment 或正例 receipt INSERT。16 个 Kubernetes、15 个云观测否例逐模式核验实际目标 GET/action 到达；双 SHA、不同源期限的 exact LEAST、七个真实 PG 时间 literal、全 row 重放/不可变和源/vault/hold/配额不变均通过。八个正式组件先在正常 1..37 上取得有效连接证明，草案后实际 SELECT/EXEC 为 42501；第九个私有 restore_gc 仅核验 owner-side effective privilege metadata，不声称已测试其真实连接。STS 夹具验证签名/token/subject/policy 和固定实例查询，未逐字段断言所有 RoleArn/providerArn/version。

该节点拓扑基础片的整仓普通 Cargo 为 334 项通过、217 项明确 ignored、48 个测试程序、0 失败，严格 all-target Clippy/fmt 通过；`.local/evidence/checkpoints/read-gc-1791472903960401000/record.json` 的 692 文件 SHA/mode 运行前后不变。首编译的测试 Url→Uri 类型错误和等价字符范围 Clippy 修正保存于 compile-v1/v2/v3，不豁免警告。此通过点尚未执行 publication ACK 丢失/延期、锁等待跨预算或所有失败路径的进程 drain 专项；同 proof 正常重放不等于提交故障验收。随后只恢复测试脚本原可执行位，内容未变，独立记录于 executable-mode-correction.json。实际阿里云 RAM/CSI/Kata、owner 安装、selected-node/PV/CSI 准入和普通 START 拓扑仍待完成，正式恢复能力继续关闭。

### 原证明预算与真实提交故障（2026-10-08）

693 文件不可变源 `d0349441c2e3a0f797a56bb85e719c1f615260a2231de49a16681ad366394ce8` 的三个新库专项 node_topology/raw_parent/admission 分别 1/1 通过（44.57/16.84/39.71 秒）；`.local/raw-selected-node-candidate-20261008/actual-v2.json` 保存全源码 SHA/mode、各库与日志 SHA。新增测试复用真实 SCRAM/COMMIT 代理，owner 模式只拦固定第一或第二次 COMMIT，原 admission 两次 ACK 规则保留；生产代码、SQL、权限和预算均未修改。

collector 的首次/最终 source reader 分别在真实 COMMIT、锁已释放后把 ACK 留置三秒，跨过独立新认证的两秒期限，业务返回 Expired；逐项验证零 I/O 或完整 Node2/CSI2/mTLS1/三个签名云 action，而非 unrelated 错误或测试外层超时。publication 使用同一真实 sealed proof，先消耗八秒原预算，再持有实际 configuration 行锁并核验 blocking PID；原预算先于固定三秒数据库 lock_timeout 耗尽，结果为 Expired、没有收据，未提高任何 timeout。

另两例确认 publication 的唯一真实 COMMIT 已释放锁、原 ID 收据在独立会话可见：ACK 延迟十一秒时原 proof 过期；直接关闭真实 socket 丢失 ACK 时返回 Database uncertainty，在期限内用同一借用 proof 重放得到原完整 row，未新建 ID/时间/证据。过期后 Rust 发布入口拒绝；owner SQL exact-payload 重放仍只返回原历史事实，不构成公开 reconciliation API 或新调度授权。实际测试代理在 pool close 后 join，并由独立 owner 会话确认 backend PID 缺席；所有场景后 source/vault/hold/配额保持不变。该证据不覆盖所有未测试的 setup/异常 drain 路径。

该节点拓扑专项检查点的整仓普通检查为 334 通过、217 明确 ignored、48 个测试程序、0 失败，严格 all-target Clippy/fmt 通过；`.local/evidence/checkpoints/read-gc-1791474088459908000/record.json` 的 693 文件输入运行前后不变，随后仅更新两份验收文档。真实云/CSI/Kata、owner 安装、selected-node/PV/CSI 状态、普通 START 拓扑与完整失败收口仍待完成；恢复 API 与正式 0038 不开放。

### 首次 Job CREATE 与持久身份分离（2026-10-09）

固定 Kubernetes v1.36.4 的 [registry Store](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.36.4/staging/src/k8s.io/apiserver/pkg/registry/generic/registry/store.go)、[创建路径](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.36.4/staging/src/k8s.io/apiserver/pkg/registry/rest/create.go) 和 [Job strategy](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.36.4/pkg/registry/batch/job/strategy.go) 显示：最终 validating admission 之前已经填充服务器 UID/创建时间、generation=1、空 status，并根据 UID 生成 Job selector 和四个 controller/name 标签。此前裸 manifest 正例遗漏这些字段，共享比较要求尚未记录的 Job UID，因此会拒绝合法首次创建。原始错误在普通 Cargo 下实际复现，保留 `.local/evidence/checkpoints/job-create-original-1791475563782081000/record.json`，不能把旧裸 manifest 正例当首次创建验收。

共享 guard 只在 CREATE、无已记录 Job UID、无 oldObject 时接受 canonical 非零 UUID、合法 UTC-Z 时间、整数 generation=1、空/缺失 resourceVersion、精确 selector/manualSelector 和四个生成标签。候选 UID 仅作本次比较参数，不写 authority、plan 或数据库；完整固定 manifest 和原安全字段继续核验，初始 Job 必须 suspended。时间仅是服务器字段形状，不是新鲜度或授权证明。UPDATE 和 GET 对象比较仍使用正常记录的 UID；标签/selector 同时改成另一 UID 也不能绕过。10 项集成普通测试与 1 项内部观察测试覆盖 Capture/Seal/Restore 三种 stage，内部观察对象是内存夹具，不能替代实际 GET。

恢复专项先删除全部未来 Job/config/Pod 占位，正常 `ensure_job(None,None)` 经 TCP 先 GET404，再 POST 到明确的 API Server 存储夹具。夹具按固定源码准备字段后调用真实私有 RestoreAdmissionService/正常 admission 角色，只在 Allow 后储存对象；正常再次 GET 和额外原始 JSON GET 返回同一 UID。准入本身不创建绑定、Pod admission、permit、proof，也不改变源、hold 或配额。正常 `record_restore_job_objects` 随后记录实际读回 UID，正常 prepare/refetch 和 RLS 查询核实完整 CONFIG/JOB 元组；后续控制、Pod owner、状态与清理保留同一对象。第二个同名合法候选经准入后返回存储冲突 409，不能替换胜出对象；三个显式后准备字段篡改否例分别拒绝。Pod 后续存储仍是明确夹具，不能表示真实 Job controller 或云计算验收。

694 文件不可变专项源 `a991a95debacafb75e8514a745a1706b31cad553667406834d728a522b243110` 下八个新独立数据库均通过：admission 40.39 秒、control 52.65 秒、gc_admission 60.18 秒、storage_mapping 40.60 秒、start 40.23 秒、delete 40.75 秒、gc 54.77 秒、gc_guards 68.41 秒。`.local/job-create-candidate-20261009/root/actual-v3-final.json` 保存库名、全部日志 SHA 和 694 文件 SHA/mode 前后一致的核验。首轮 query 夹具错误保留原失败；固定 kube 4.2 客户端使用带首个 `&` 的 list query，仅修正夹具匹配。第二轮 gc_admission 的原生栈溢出也保留，只把相同正常 refetch/SQL 断言移入独立盒装测试 future；独立等价审查与 macOS 原生反汇编显示主测试帧减少 18,640 字节，不宣称定位了最深崩溃 PC 或认证 Linux 栈。

同片整仓普通 Cargo 340 通过、217 明确 ignored、48 程序、0 失败，严格 all-target Clippy/fmt 通过；`.local/evidence/checkpoints/read-gc-1791478462746353000/record.json` 的 source manifest SHA `212c5f105a0fb562b27f566afe1177f6ef3237f68be3b46386010cf7a109f79d` 与运行后相同。第一次普通检查因本机执行沙箱套接字限制失败，原日志保留，在允许本地回环测试套接字的环境中以同一源码、原命令重跑通过。随后仅更新两份说明文档，专项 flat digest 与普通 JSON manifest digest 分开记录。在该八项专项执行时，备份 Capture/Seal 的独立首次创建仍未验证；后续结果分别记录于下方独立里程碑。生成 PV/CSI 状态、普通 START 拓扑、完整失败收口及真实云/Kata/CSI 认证仍未完成，正式 0038 和恢复产品入口保持关闭。

### Capture 共享服务的独立首次创建（2026-10-09）

新独立 Capture 测试先在正式 1..37 上取得正常角色连接，再经正常 STOP 关闭、备份受理/claim和显式 synthetic CSI snapshot/clone记录进入 CAPTURE_PENDING。Job/config/Pod 没有预先绑定；真实共享 AdmissionService 通过实际 admission 登录读取权威状态和同一 TCP 服务读取网络、RuntimeClass及三份 Secret。API Server 字段准备先于 decide，Allow 后才存储；正常 ensure_job 的 GET404→POST 和再次 GET、额外原始 GET 返回相同 UID，随后 record_backup_job_objects/refetch 和实际 RLS绑定核实精确 CONFIG/JOB。

七次实际准入均核对完整依赖读取到达：合法首次 config/Job、第二个合法同名 Job 存储冲突，以及 nil UID、controller label、selector 和 controller caller UID 四个否例。记录前备份、实际源实例/工作区完整行、hold/releases、reservations/quotas、Pod admission/permit/proof/cleanup 全部不变；身份记录后同样不改变这些事实。记录后 coherently 替换 GET 对象的 UID/标签/selector被拒绝，账本仍保留原 UID。

695 文件不可变源 `dffed1b4ebaf31e90c73280b43d1a5118d865779bea13404f84a95a9e9dea143` 下新库 `sandbox_backup_create_acceptance_179147887126977259_test`，1/1 通过（0.95 秒）；receipt `.local/job-create-backup-candidate-20261009/root-actual-v1.json` 核实源快照与当前文件 SHA/mode 一致。严格 all-target Clippy/fmt 随后通过，checkpoint `.local/evidence/checkpoints/job-create-http-compile-1791478922361049000/record.json` 的 JSON manifest SHA `f66bf7469e62ab85f3519d7daeacc0beb35dc1349d0d42c36c7a8c86611218a8` 前后不变。新增的是独立 cfg(test) 测试和薄模块声明；此后普通全量尚未重跑，340/217 仍是上一共享修复检查点。前置 snapshot/clone、UserInfo和存储服务是明确夹具，未调用真实 CSI/云/Kata 或安装 apiserver mTLS；Seal 正常 trusted closure/handoff与首次创建不由此用例证明。


### 首次 Pod CREATE 的服务器准备状态（2026-10-09）

固定 [Kubernetes 1.36.4 Pod 策略](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.36.4/pkg/registry/core/pod/strategy.go)在最终 validating admission 前，为 Pod 写入 generation=1 和 status={phase:Pending,qosClass:GetPodQOS}；QoS 按[同版固定实现](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.36.4/pkg/apis/core/helper/qos/qos.go)计算。Capture/Seal/Restore 的固定单容器 manifest 无 Pod-level resources、init container 或 scheduling gates，CPU request/limit 为 1/2、内存 request/limit 为 1Gi/2Gi，因此此受控形状的 QoS 为 Burstable。此前共享 guard 只接受空 status，真实原源码复现得到 `capture: Backup Pod differs from controlled Job`、0 通过/1 失败；原 699 文件快照及日志保存于 `.local/evidence/checkpoints/pod-create-original-1791479736941543000/record.json`，输入 SHA/mode 未改变。

窄修复仅处理首次 Pod CREATE：canonical 非零服务器候选 UID、原 UTC-Z 时间校验、整数 generation=1、空/缺失 resourceVersion、无 oldObject、精确 Pending/Burstable 和完整受控 manifest 均须满足。未知状态、注解、标签、安全配置及规格变化继续拒绝；不模拟任意 QoS、不新增持久身份或放宽一次 Pod gate，GET/UPDATE 继续依赖正常记录的 UID。14 项集成普通测试、严格 all-target Clippy/fmt 在同一 699 文件检查点通过，receipt `.local/evidence/checkpoints/pod-create-fix-unit-1791480286581431000/record.json`，manifest SHA `9eaace054559deaeab4fbe6e8f47c3ddee63054161d194ce97634547be2f32f6` 前后相同。这是共享 guard 的本地协议回归，不是已部署 Kubernetes apiserver 的证明。

共享修复随后在700文件不可变源 `f60c4ece82ab1673a9b937f57a8447007c17347eae01a16365c2a13705412c54` 下完成八个新独立数据库回归：准入、历史控制、GC准入、存储映射、首次START、never-started DELETE、GC和GC guards全部1/1通过。receipt `.local/pod-create-admission-candidate-20261009/root-actual-eight-regressions.json`（SHA `87e4017dcb17674c980a02d65315372e5052a80cfe90748eebce51d46b20c249`）核实完整源与快照SHA/mode不变，普通Cargo与默认栈，不提高授权、租约或观察期限。实际PG/HTTP/mTLS仍使用明确的云/CSI协议夹具。

### Seal 正常关闭后独立首次创建（2026-10-09）

独立用例沿正常 Capture Job/Pod 首次 CREATE、实际 GET 与正常 ledger record，完成单次 admission、正常调度/观察、宿主许可及真实 mTLS 注册，再经正常可信关闭、终止证明、受控保护移除、GET404/附件读回和 cleanup 进入 Seal handoff。交接 config 与首次 Seal Job 均通过真实共享 AdmissionService、窄数据库角色及状态化 TCP API，只有 Allow 后存储；实际 GET 返回的 UID 经 `record_backup_job_objects` 正常记录、prepare/refetch 和 RLS 绑定查询核验。没有 SQL seed Job/Pod binding、未来 permit、proof 或 cleanup。源实例/workspace 的完整行、源备份身份、hold 和配额首尾核验保持不变。

700 文件不可变源 `22b11b8d38c99b466784c430b50d74071511247038c3e83db67408e71c7144ae` 下，独立库 `sandbox_backup_seal_acceptance_179148091740537633_test` 的 `backup_ledger::job_create_admission_tests::seal_tests::seal_first_job_create_after_normal_capture_trusted_cleanup_and_handoff` 1/1 通过（1.20 秒），正常 Cargo、默认栈，源与快照 SHA/mode 运行前后一致。receipt `.local/job-create-seal-candidate-20261009/root-actual-v1.json` 的 SHA 为 `3ae8fc9ee859d04dcb7af2cc7066e8df43dfff14e6ebba047b2088b3f37b6ec5`，日志 SHA 为 `9d858318c470fdc46f7fa8eb4405c87895bdad83bd79b08cfb6e92e1c05e5cc5`。验证只到首次 Seal Job CREATE/GET/正常记录；Seal 执行、Seal Pod/vault 上传和 AVAILABLE 备份完成未由此证明。CSI、Node、guest 和控制器状态仍是明确协议夹具，未进行实云/真实 Kata 认证。

### Raw selected-node 当前专项与三次原始失败（2026-10-09）

私有准入从已记录的 Pending raw PVC 父 UID、早期生成 PV 意图、正常 Job/一次 Pod 记录出发；Pod 尚未分配 nodeName 时，读取当前登记、认证与 owner 拓扑历史事实，再以独立 admission 只读云 subject 进行新鲜签名实例查询及 Pod/Node/CSINode 双读。owner token/数据库发布权限不借给 admission。SELECT/PROVISIONER/RESET 分支只允许精确元数据差异，当前 pin 和六个 scope 的替代 grant MAX/MIN 有限预算在首/末 reader 与 COMMIT ACK 后复查；RESET 核两次生成 PV404。正常父流程未提前制造 Bound、raw receipt、VM permit、proof、cleanup 或存储配额释放。

三次失败分别保留原源码、独立数据库和日志，不以重跑结果覆盖：

| 原轮次 | 实际失败与已到达范围 | 本机 receipt |
| --- | --- | --- |
| v1 | 初始 Pending 双 GET 的计数断言失败，未到 Pod CREATE 或 selected-node 矩阵；不能据此宣称 Pod 生产 guard 已复现。 | `.local/raw-selected-node-candidate-20261008/root-selected-actual-v1-failed.json` |
| v2 | 夹具将匿名 STS query 误定为 6 个 key，正常协议实际有 9 个；首 SELECT 得到503，其余矩阵未执行。原 generic finish 未区分 join/协议失败，不能声称其已完整 drain。 | `.local/raw-selected-node-candidate-20261008/root-selected-actual-v2-failed.json` |
| v3 | cloud 请求均200、双 GET 全部到达、HTTP join 与协议检查完成后，首 SELECT 仍503；同一时段本地 PG backend 被 SIGKILL 并进入 recovery，容器限制1GiB、OOMKilled=true、cgroup oom_kill=1。环境 OOM 证据已记录，具体分配根因尚未证明，剩余矩阵未执行。 | `.local/raw-selected-node-candidate-20261008/root-selected-actual-v3-environment-failed.json`（SHA `299687fb7395b8e709d0696a51e817a276fe280703f1369cf5afc6edd5ec9b77`） |

仅调整自有本地 PG 容器的运行内存为2GiB、memory+swap 总限额为3GiB，原 compose/生产源码、guard、租约和期限均未改变。700 文件原源 `f60c4ece82ab1673a9b937f57a8447007c17347eae01a16365c2a13705412c54` 下，新独立库 `sandbox_restore_acceptance_179148185240535607_test` 的 `restore::tests::node_topology::selected::raw_selected_node_metadata_requires_current_authority_and_live_unassigned_pod` 1/1 通过（30.88 秒）。receipt `.local/raw-selected-node-candidate-20261008/root-selected-actual-v4-pass.json`（SHA `c092f2b8720ad4e0db60d1d689711e02b500a7c536460c76d41981d08d3dffd4`）核实源与快照 SHA/mode 未变，日志 SHA `4be99139f1129fb45795a2b00119a807c7531e299d4ec85a3e39b95636cb8aa7`。每2秒采样所得峰值为1339023360字节（约1.247GiB），采样进程已 join，cgroup oom_kill 从1到1、无新增；记录 `.local/raw-selected-node-candidate-20261008/root-selected-memory-1791481852047428000.json`（SHA `9e0ba87f6ac90e22d3178a571c9158d333c4b7c5b3945b892abe1090ff319273`）。这是离散采样最大值，不是内核 lifetime peak，也不是生产容量认证。

此通过点覆盖当前 Pending SELECT/PROVISIONER/RESET 正例、精确目标计数的 Pod/Node/CSINode/cloud 否例、六 scope 有限授权、真实 workspace 锁等待后撤权，以及首/末真实 COMMIT ACK 跨短 lease/source grant 后拒绝、代理 join/锁释放/backend PID 缺席。延迟 ACK 用例验证的是短权威期限，不宣称单独验证所有总10秒过期或丢失 ACK 重放。正常 Bound/PV 生成及记录、并发同名节点/epoch/claim 换代扩展、缓存复用、生产 listener/CSI/RAM/Kata/普通 START 拓扑与完整失败收口仍需独立验收；私有 v8 扩展尚不在本次700文件源中。

本工作树普通全目标 351 通过、220 明确 ignored、48 个测试程序、0 失败，严格 all-target Clippy/fmt 通过；checkpoint `.local/evidence/checkpoints/read-gc-1791482501332273000/record.json` 的 700 文件 JSON manifest SHA `4ede23faf8dd57b860005e690f13e86b30de6f0de749121201093b93be182fa2` 运行前后不变。Compose 的 PostgreSQL 开发内存上限与开发容量说明已包含于此普通检查点；该变化未回填到此前专项源。随后仅更新两份里程碑说明文档。 14项共享 unit、Seal 1项和 selected-node 1项分别按各自源点记录，不与较早340/217/48或334/217/48相加。正式0038、恢复生产 API/listener/worker 分流仍关闭，本里程碑不表示完整备份/恢复产品已上线或获得实云认证。

生产数据库容量还需独立验收：本地夹具的缓存清理可预热47个连接，包含owner连接，采样峰值是整个容器用量，不能当作单个CTE内存或已证明的JIT问题。SQL未调整JIT，只读历史库计划诊断不替代真实授权验收。安装容量门禁必须合计各服务进程pool、滚动新旧副本与terminating旧池、后台/作业/外部及管理保留连接，并与实际RDS普通连接额度、活跃SQL和并发内存实测相符；本地单次2GiB结果不能认证生产规格。


### Selected-node 扩展边界与正常身份换代（2026-10-09）

本片只扩展 cfg(test) 验收与公开测试 TLS 凭据，没有修改生产 reader、SQL、授权、时间预算或正式迁移。父流程仍通过正常 PVC/Job/一次 Pod 创建、GET 和记录取得当前 Pending 意图。

新增实际 HTTP 观察覆盖：首/末 PVC 已 Bound 时拒绝；RESET 第一次生成 PV404、第二次存在时拒绝，包括同名不同 UID。正常登记用独立 NodeUID、boot ID、ECS 实例和 IP，但同名的候选，通过 Node→真实 mTLS→Node 后被精确的 commit inventory 守卫拒绝；仅证明正常登记不允许第二 active 同名身份，不将不可创建的 count2 库存伪造为正例。runtime Node 的真实 FOR UPDATE 锁等待中提交禁用后，reader 返回无当前权威并在外部 I/O 前拒绝。

末轮二次 Node GET 的明确屏障后提交 epoch、principal revision、profile 或 runtime Node 当前权威变化，原 pin 必须拒绝。principal revision 只前进，不回退。平台 epoch/可用标志仅作夹具维护恢复，登记、认证及历史拓扑身份不可修改。同 UID 的首/末 Node boot/profile/Ready/IP/拓扑与 CSINode owner/nodeID/topology keys 变化有精确 GET、云 action 和拒绝类别断言；末轮变化确实经过新鲜签名云查询。最后用普通 wait/claim 队列取得更高 fencing token，旧 heartbeat 失败，新 claim 成功后，旧准入 pin 拒绝；未直接编辑租约或制造成功收据。完整源/目标、hold/quota 和全局 Node/enrollment/topology 事实持续核验。

扩展首轮在 702 文件源 `0300beed25cf0f45a92082e11857a446eb9735548f892146b7c6bf82bc08074f`、独立库下失败（31.14 秒），receipt `.local/raw-selected-node-candidate-20261008/root-selected-boundary-v8-actual-v1-failed.json`（SHA `af7a790c124c9324375057be2f24c37c85082f0e24aba4eaf50683654e8e43d2`）。重复候选随机 UID 与测试服务器固定 UID 证书 SAN 不符，身份校验提前失败，后续节点锁/权威/同 UID/claim 扩展未执行；原错误日志没有输出内层 TLS 错误，静态源码与证书核验定位了该前置缺陷。没有接受提前拒绝作为重复登记通过。第二固定 NodeUID 使用独立公开测试 server CA 和精确签名 DNS SAN，服务端 client CA 保持，生产客户端 hostname/证书验证保持。

705 文件不可变源 `d2227fc0abfa6b6be0723ecd7d1e31a9e49e31ad77dbbed0b91301aefc5f71d9` 下，新独立库 `sandbox_restore_acceptance_179148380432215952_test` 的原 selected-node 专项 1/1 通过（33.90 秒），receipt `.local/raw-selected-node-candidate-20261008/root-selected-expanded-actual-v2-pass.json`（SHA `c60ed83bf3d4d2f511c62fa753ad191736d83c9177a9a5e451ba4cc96bdcc8c6`），日志 SHA `14730a40c60891766c98ad63b9590539bc6a17087181c71d84332f20b5b1c4ae`。原先矩阵和扩展都在同一正常 Cargo 用例中执行；不把各场景分别累加为独立通过项。2 秒采样的容器用量最大值为 1300344832 字节，采样进程已 join，cgroup oom_kill 1→1，memory receipt `.local/raw-selected-node-candidate-20261008/root-selected-memory-1791483804115921000.json`（SHA `7a6c632048beb9065a7824df94e266ccd3b97b3cbf1ff32fb95f0a104bfd26bb`）。本地 2GiB runtime limit/memory+swap 总限额3GiB 不代表生产容量。

普通全目标 351 通过、220 明确 ignored、48 个测试程序、0 失败，严格 all-target Clippy/fmt 通过；checkpoint `.local/evidence/checkpoints/read-gc-1791483937109990000/record.json` 的 705 文件 JSON manifest SHA `cc221ef530c8a215cdfcae4c52db9beb1030917dd275c9a79415f1ac67c7a2ae` 运行前后不变。随后仅更新本文与实现进度说明，测试源码不变。正常 CSI PV CREATE、PV/status 与 PVC binding/status 多方控制序列、业务记录和新鲜 DescribeDisks，raw receipt、VM birth/许可、完整失败排空、真实阿里云/CSI/Kata 和生产容量/发布认证仍待完成，正式 0038 与恢复 API/listener/worker 分流继续关闭。
