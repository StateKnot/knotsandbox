# P0c2b：原生节点镜像只读整链交付

状态：P0c2b 本地同链验收已完成。修复前置 cohort 检查后，`chain-v5/record.json` 实际 PASS，主链 82.876 秒、原生 fixture 及操作员 fixture 各 1 项通过，未扩大原预算。v4 曾记录成功但不能证明原 scrape 对齐的局限仍保留，最终使用 v5 结论。它验证的是镜像只读观察链，不认证生产集群、GPU、物理缓存容量或快速启动收益。P1—P4 的准备与释放门仍未完成，pre-pull 未开放。

本轮比较基线为 `8e1fbbc2b9be815ae38aa4290d628ad98503f6e6`，其 [GitHub CI run 38799480127](https://github.com/StateKnot/knotsandbox/actions/runs/38799480127) 已实际完成 5 个 job、62 个 step，全部成功。该结果只对应基线；本批提交的精确远端完整树、CI 结果须在同步后单独核对。

## 同一条实际数据链

```text
固定 containerd 2.3.5 / CRI
  → 生产 ImageObserver / 原始报告时间
  → 生产 scraper mTLS /metrics/node-images
  → 两个 Prometheus Agent 的生产生成配置
  → HTTPS remote-write / 固定 Prometheus 3.13.4 receiver
  → 只转发实际 receiver 原响应的有界 HTTPS 查询桥
  → 安装级 operator API
  → 实际 sandbox-admin node-image-status
```

原生源只导入独立构造的一个 OCI 镜像，使用实际 CRI 观察；镜像不解包、不执行工作负载。独立 OCI 内容给出压缩逻辑字节预期，当前样本为 1 个镜像、10789 逻辑字节。原生 Rust fixture 在停止前检查没有 snapshot、container、task，不以手写 Prometheus 数值替代 CRI 结果。[原生 fixture](../src/nodeguard/image_chain_fixture.rs)、[原生所有权与故障驱动](../scripts/node_image_chain_native.py)

两 Agent 使用既有生产配置生成器及原采集／队列预算，保留分别命名的副本身份。节点、boot、profile、epoch 与镜像观察标签在同一原生来源贯穿采集、remote-write、receiver 和产品查询。API 与 CLI 消费实际 Prometheus 响应，没有将两个副本相加，也没有把不同字段的最大值拼成报告。stock Prometheus 的 Basic writer／reader 只是 PUBLIC fixture 认证；stock receiver 不认证生产托管 Prometheus 的路径权限，侧车本身则限制为固定 query 路径。[管线 fixture](../scripts/node_image_chain_prometheus.py)、[生产配置生成器](../deploy/observability/observability.py)、[查询合同](../docs/node-image-query.md)

安装权限使用真实本地 Keycloak 机器 JWT；PostgreSQL 为独立新建、loopback、verify-full TLS 的固定摘要 PostgreSQL 17.11。只创建既有十个普通登录角色，业务 schema 由 Rust fixture 正常 SQLx 迁移及既有角色安装产生，不重放一套替代 schema。最终 47 条迁移严格为 `1..37+39..48`，各条 success 和 SHA384 与源码一致，0038 没有加入。[数据库 fixture](../scripts/node_image_chain_postgres.py)、[真实 API／CLI 验收](../tests/operator_access/native_chain.rs)

数据库中的节点云属性和认证收据属于明确的测试数据；身份中的 Node UID／boot／profile 来自同一次实际原生源。profile 所需的 Kata／QEMU 等文件为合成夹具，未启动 Kata、KVM 或云 VM。普通 app 使用既有窄授权接口；本轮没有新增产品权限、迁移、准备操作或 owner 数据库回退。

## 已观察的行为

本机私有证据保存在 `.local/node-image-chain-20261016/`。`chain-v5/record.json`、原生与操作员日志及有界查询原响应保留；成功回执 SHA256 为 `a7f34e6e713ee47991ded4969c1bba323331de600e0402e288e7a12de8017bef`。公开源码不包含身份密钥、数据库口令、OAuth token 或生成 PKI 私钥。

| 阶段 | 实际观察与判定 |
| --- | --- |
| FRESH | 两个 Agent 都完成实际 mTLS 抓取和 remote-write。API 与真实 CLI 返回当前 installation／epoch／grant／node／boot／profile，通过产品的同 scrape cohort 与新鲜度门；数量对应独立 OCI 预期，文件系统观察来自实际 CRI。v5 使用实际原始 selector timestamp 单次查询补验前置 cohort 对齐 |
| RPC_FAILURE | 只向已核对 PID、启动时刻及可执行文件的自有 containerd 发送 STOP；collector 与 mTLS listener 保持运行。receiver 中两副本 `up=1`、两观察 success 为 0；API 和 CLI 的 inventory／filesystem 清空，不继续呈现旧成功数量 |
| 第一次恢复 | 仅恢复同一 containerd；两副本原始 collector 报告时间必须晚于故障观察时刻，再满足完整 cohort 和严格新鲜度。API／CLI 恢复实际报告，不能靠新 scrape 刷新旧报告 |
| TRANSPORT_FAILURE | 暂停自有原生容器，使实际 mTLS 抓取失联；receiver 两副本 `up=0`。API／CLI 返回 UNKNOWN 并清空旧观察对象 |
| 第二次恢复 | 恢复同一原生容器；仍要求两副本原始报告时间推进，并重新核对真实 API 与 CLI |
| 在途撤权 | 查询桥先取得 receiver 的真实结果，再停在有界回包屏障；owner 撤销原 grant 后释放原响应。实际 API 返回 403／`PERMISSION_DENIED`，随后 CLI 读取拒绝，不返回旧数据 |
| 新 grant | 创建不同 ID 的新 grant，保留原到期时间；实际 API 与 CLI 返回新 grant 和当前观察。没有延长授权期限以通过测试 |
| 停止 | IPC 只驱动八个固定验收阶段，不代替业务接口；序号 1 至 8 全部完成，原生与操作员各记录 COMPLETE 和 `1 passed; 0 failed; 0 ignored` |

`chain-v5` 的 receiver 状态序列为 `FRESH → RPC_FAILURE → FRESH → TRANSPORT_FAILURE → FRESH`；操作员八阶段包含两个 UNKNOWN、在途撤权、新 grant 及停止。操作员退出码为 0，实际测试运行 60.80 秒；原生 Rust 测试运行 85.93 秒、含外部退役观察的 native fixture 为 86.129 秒，主链为 82.876 秒。这些时间包含故障注入、固定生产采集间隔和本地验收轮询，不是启动 p95／p99、产品资源收益或性能基准。

原始来源仍为 `RUNTIME_REPORTED`，完整性为 `UNKNOWN`，Prometheus 数值精度为 `APPROXIMATE_F64`。文件系统观察不代表所有镜像内容、snapshotter、共享层的物理总量，也不代表可回收量。双副本只是观测冗余，不增加镜像数量或容量。[既有只读消费定义](../docs/node-image-query.md)

## 本地边界与资源

本次本机实际 internal 网络没有可用宿主发布端口；最终原生源、两 Agent、receiver 和查询 sidecar 只连本次自有 internal bridge，且明确不配置宿主 publish。这里不泛化所有 Docker 环境的 internal 网络实现。为避免将该内部网络改成外部可路由网络，新增的 sidecar 只执行固定 receiver HTTPS 查询：5 秒、256 KiB，校验 CA 和主机名，拒绝代理／跳转，不能调用写接口。宿主本地 HTTPS 查询桥保留原 receiver 正文；它不是生产 sidecar、产品权限或新管理 API。

| 自有组件 | 固定运行边界 |
| --- | --- |
| 原生源 | 768 MiB、1 CPU、128 PID、1024 FD；原有有界 tmpfs、只读 root、drop ALL、no-new-privileges；不挂载宿主 socket 或用户数据 |
| 查询 sidecar | UID/GID `501:20`、128 MiB、1 CPU、64 PID、1024 FD；只读 root、drop ALL、no-new-privileges；只承接固定只读 TLS 查询 |
| 两 Agent 及 receiver，各自 | 256 MiB、1 CPU、64 PID；只读 root、drop ALL、no-new-privileges；仅本次生成配置及专属数据目录 |
| PostgreSQL | 1 GiB、2 CPU、256 PID、1 GiB 数据 tmpfs；仅新建本次数据库，独立凭据和 verify-full TLS |

原生服务固定总预算仍为 180 秒，主链截止仍为原生开始后 160 秒，保留正常退役时间；没有提高生产 RPC、采集、锁、授权、线程栈或测试期限。查询桥在 TLS 握手之前给接收连接设置 5 秒超时，处理器读取也受限，避免失败连接阻塞清理。

v5 回执确认：PostgreSQL、三个 Prometheus 容器、其自有数据、原生源容器、查询容器、COPY 镜像、内部网络和构建暂存目录均已按精确所有权清理，清理错误为空。源码、原生 ELF、host 测试与 CLI 二进制、两份 Cargo artifact 消息及公开原生输入在该次验收前后保持一致。Prometheus 镜像声明的 `/prometheus` 使用明确 bind；停止后 `rm -v` 仅清理该自有容器所附匿名卷，不使用全局 prune。原生 ELF SHA256 为 `00e55cd6cbd6c26eed590ea90edcf6eeda71d05bf9ed8126f7b5c5edf11c62d5`，与旧原生门复验制品一致。

本轮保留 host 构建缓存约 6.59 GiB、Linux 构建缓存约 1.77 GiB，供精确已构建制品和后续验收复用；没有复制 target。`chain-v5` 的 df 实测可用空间由 326064992256 变为 325664292864 字节，差值为 -400699392 字节；该差值包含本机同期活动，不能用目录累计大小声称已释放空间。两缓存均未超过单任务 20 GiB 限制，未删除用户数据库或不确定归属的数据卷。

## 失败与验证记录

| 记录 | 实际结果及处理 |
| --- | --- |
| `chain-v1` | `ACTUAL_NATIVE_PUBLISH_CHANGED`：internal 网络未产生原假设的宿主端口映射。保留失败；改为内部固定只读查询 sidecar，不放宽网络为外部可路由 |
| `chain-v2`、`chain-v3` | `EXACT_OWN_PROMETHEUS_MOUNTS`。先做路径 realpath 核对后，v3 仍然失败；实际根因为固定 Prometheus 镜像声明 `VOLUME /prometheus`，原 `/data` 挂载留下额外匿名卷。最终将存储明确 bind 到 `/prometheus` 并保留精确 mount 断言，没有通过删断言绕过 |
| 早期匿名卷 | v3 的卷根据精确 mount 事件和携带 owner 标签的容器 destroy 事件证明归属，已删除，见 `early-anonymous-volume-cleanup.json`。v2 的对应事件没有留存，无法证明具体卷归属，未依据时间猜测删除；不能声称所有早期匿名卷已清零 |
| `chain-v4` | 实际 API／CLI 八阶段及原生／操作员各 1 项通过，回执记录 PASS。随后 Standards 审查发现前置检查对 `label_replace(...)` 使用 `timestamp` 得到求值时间，cohort 对齐检查恒真；该限制不能被实际产品接口通过掩盖，不作为最终整链退出证据 |
| `chain-v5` | 实际 PASS。前置检查改为单次真实 instant query 的十二个固定分支，分别保留六项指标的 value 与原 selector timestamp，之后再补 metric 名标签；按 metric／kind／replica 显式组合，不生成观察数值。原 160／180 秒预算内完成五个 receiver 状态、八个操作员阶段、两个实际测试及全部自有清理 |
| 普通 host Rust | 已运行 64 个程序，486 通过、0 失败、291 个环境专项明确 ignored；不把 ignored 计为通过。该检查先于内部查询 sidecar 适配，最终 host 二进制对应关系需以最终回执核对 |
| 严格静态检查 | Mac／Linux Clippy 与 fmt 已通过；新增 Linux sidecar case 在适配后重新构建及 Clippy 通过。最终完整输入比较由主交付回执确认 |
| 既有原生门 | `old-native-regression/record.json` 已观察到 PASS：原无网络、45 秒命令预算的 CRI／mTLS 原生专项 1 通过，源码／二进制／artifact 保持，自有容器及镜像清理确认；不以新整链替代旧门 |

前置检查发现并修复查询连接清理可能无界、恢复可能复用暂停前缓存报告的问题；分别补接收连接握手／读取超时，以及故障后原始报告推进。Standards 后续发现上述 v4 timestamp 顺序问题，修复后 v5 已完成完整真实重验。`cohort-review-green.json` 核对两个副本实际 up 原始时间与 query 求值时间不同，第一阶段 API 选中的 `scraped_at_seconds` 精确等于副本 b 的原始 scrape 时间。最终独立两轴审查与精确补丁哈希由主交付记录保存。私有 `failures.json` 和 `cohort-review-red.json` 保留实际失败与限制，不以新成功覆盖旧记录。

## 重现入口与 CI

前提是本机已按锁文件安装观测 Python 依赖、具有本地 Unix Docker socket、真实测试 Keycloak，以及同次普通 Cargo 构建输出的 host operator／CLI 和 Docker 原生架构 Linux lib-test artifact 消息。Mac 制品不能替代 Linux ELF；runner 校验目标、普通用户、SHA、架构及固定官方 containerd archive／checksum。运行前仍须按用户磁盘与缓存约束检查 df。

```sh
.local/cluster-venv/bin/python scripts/test-node-image-chain.py \
  --native-artifacts .local/nodeguard-host-artifacts.jsonl \
  --operator-artifacts .local/review-artifacts.jsonl \
  --identity-env-file .local/dev.env \
  --evidence-dir .local/node-image-chain-local
```

使用全新 evidence 目录；身份文件必须是当前用户所有的常规非符号链接文件、0600、最大 64 KiB，只读取四项 OIDC／机器客户端配置，不执行 shell。也可使用已完整注入的四项环境变量；口令和 token 不放命令行。可选 `--containerd-archive` 与 `--containerd-checksum` 必须成对提供，并同时匹配内置官方摘要。调用脚本见 [test-node-image-chain.py](../scripts/test-node-image-chain.py)。

CI `verify` 增加正常必需步骤 `Native image source through dual Agents, real receiver, operator API and admin`，直接执行同一 runner，不允许失败继续。普通 Keycloak 专项显式排除需要本 runner 完整环境的新 case，由整链步骤单独执行；不是略过它。紧随的 `if: always()` artifact 步骤只上传本次 `record.json`，缺失即失败，保留 14 天；不上传生成私钥或原始身份文件。[CI 配置](../.github/workflows/ci.yml)

## 后续门禁

本地 v5 同链已通过；继续核对最终交付输入、本批精确远端完整树和 CI。P1 仍需先确认原生 lease／content／snapshot 引用、namespace／snapshotter／GC 与严格资源硬限，之后才能开发或开放受授权的镜像准备。真实云、Kata、CSI、GPU 与 GPU 共享／显存回收、物理缓存总量、命中、启动分位数、72 小时资源与费用收益均未在本轮认证。[实施顺序](image-preparation-production-plan-20261015.md)、[开发表](rust-sandbox-development-workbreakdown.md)
