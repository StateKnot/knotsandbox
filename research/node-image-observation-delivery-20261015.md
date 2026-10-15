# 节点镜像只读诊断 P0a 交付记录（2026-10-15）

本轮对应开发表 12.8 的 **P0a 宿主只读 adapter 与真实 scraper 消费者子项**。P0 整体、P0b 的节点 Prometheus 管线、P0c 的安装级授权/API 仍未完成，默认不开放整套节点观测或后台镜像准备。使用合同见[节点镜像诊断](../docs/node-image-observation.md)，完整后续依赖见[生产实施计划](image-preparation-production-plan-20261015.md)。

## 已发布基线

先核对公开 main `ff16330249380468ea95bcbde7edfc9de3c5b524`：GitHub [CI run 38736718731](https://github.com/StateKnot/knotsandbox/actions/runs/38736718731) 的 5 个 job／61 个 step 全部成功，首次运行完成于 2026-10-15 13:29:45 UTC。该结果只证明这个旧提交；本轮新源码的远端完整树和精确提交 CI 另存本机发布回执，不沿用旧成功。

## 交付行为

新增独立深模块 `image_observation`，只访问固定 containerd UDS 上的 ListImages、ImageFsInfo 和身份 Version。受控 overlayfs/profile/config、NodeBinding、boot、root peer PID/start、同 FD/device/inode/mount ID 在读前后复核；不接受调用方 socket/path。独立后台 owner、RPC/解码/并发/缓存上限及实际 I/O 收尾不占用原 VM 抓取槽。

现有独立 scraper CA 的宿主监听器增加 `GET /v1/node-image-status`；无 VM 时也可通过真实 mTLS 消费，不输出未接管线的节点 Prometheus 样本。默认 false／无批准新 profile 时路由关闭；原强制启动检查通过后，独立诊断构造失败关闭路由、后台握手失败保留 UNKNOWN；不放宽原 profile/摘要/boot 启动守卫。没有新迁移、租户授权或安装级管理豁免，安装器暂不启用此能力。

库存是 CRI 索引压缩逻辑数，FS 是 runtime snapshot-store 报告；二者独立缺测，全部整数以字符串传输。来源 `RUNTIME_REPORTED`、完整性 `UNKNOWN` 固定。原 FS timestamp 在每次读缓存时仍须有效；缓存不刷新旧报告。响应无 repo/image ID/原路径，不报告 total cache、capacity、available、reclaimable、HIT 或节省比例。

## 验收与失败记录

本机私有证据目录 `.local/image-observation-20261015/` 不进入公开树。正式 native runner 对照固定官方 containerd 2.3.5 归档及独立 checksum 资产，隔离 runtime 无网络、只读、drop-all-capabilities，无宿主 socket/卷。自生成非空 OCI 的 descriptor 闭包独立计算预期 logical bytes，不 unpack、不创建 sandbox/VM；真实 ImageService→scraper mTLS 接口断言授权、无 VM 库存、FS、时间、隐私、方法及退出清旧，精确清理自有镜像与容器。

本轮最终普通原生62程序472通过／0失败／279环境ignored；最后仅Linux cfg lint改动，重新构建后62个二进制SHA均相同，复用此前完整运行，不重复宣称新一轮全跑。Linux四组61＋5＋3＋1共70通过，普通组8项环境ignored另列；真实containerd专项1／0／0、Python边界11项通过，两平台strict all-target Clippy和fmt通过。mount反例仅在独立自有测试容器使用SYS_ADMIN，真实native门cap-drop ALL；没有改生产权限。

最终结果与制品摘要在本机 `verification-final.json` 收口。普通原生回归、Linux 节点守卫、实际 native 后端、Python 边界和 strict Clippy/fmt 分别记录，不把环境 ignored 算通过或重复计成单轮测试。新 gate 已接入现有 CI，只有非敏感派生 JSON 回执上传；原有检查和生产权限／期限／线程栈保持。

保留真实失败：最初 tracer 真实 gRPC 反例；FS 原报告超龄与构造器在无 backend 时阻断的两项 P2 反例；编译期缺少直接依赖的无效 RED 单独区分；只读容器拒绝 docker cp 后改 COPY-only 夹具镜像；local 日志驱动默认压缩与 max-file=1 冲突后显式 compress=false；预检丢回执和晚中断假 PASS 的独立 Python 反例均修复。普通本机回归一次受工具沙箱回环 bind 拒绝，随后同普通 UID/原二进制在可绑定回环的执行环境验证；没有更改产品权限。Linux 构建首次缺工具链组件触发只读 rustup 同步、新日志目录未挂载、错误使用lib＋bin清单被正式唯一lib检查拒绝、跨平台 lint 的失败也保留，不涂改为通过。

## 审查与后续退出门

独立 Standards 与 Spec 两轴审核固定文件哈希。Spec 原两项 Rust P2（可选握手阻断原启动、缓存掩盖原 FS timestamp 超龄）已用实际 RED/GREEN 修复；runner 两项回执 P2（预检失败无记录、晚中断遗留 PASS）已补真实边界测试。最终审查回执在本机 `review-record.json`，公开文档不以审查替代运行结果。

下一项先交付 P0b：同 Prometheus 双 Agent 的独立 node allowlist、样本/响应/WAL/remote-write 预算与真实管线回归；再交付 P0c 的正常非 owner 数据库角色、安装级 OIDC 授权/撤权和 operator 消费者。P0a 接口不是全局当前 epoch 的证明。P0 完整闭环后才进入 P1 的原生引用、snapshotter 选择和硬限认证，未通过前不开放 pre-pull。

本轮 Docker 证据不认证真实 Kata、CSI、云节点、GPU 或冷暖 p95/p99/72 小时成本；没有 GPU 利用率或资源节省结论。共享层物理占用、GC 后实际释放与下载硬预算仍待后续明确实现。
