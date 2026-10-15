# 节点镜像指标与双 Agent 管线 P0b 交付（2026-10-16）

本轮完成[开发表12.8](rust-sandbox-development-workbreakdown.md#128-批准镜像节点预准备后续有序实施2026-10-15)的P0b本地验收：独立节点exposition、严格抓取/远写过滤、预算和失联/报告告警。P0整体仍待P0c安装级授权、正常数据库角色、固定查询/admin消费者及原生整链；没有开放pre-pull、普通启动许可或GPU功能。

## 基线与行为

先确认公开提交 `18ad317dbe140f4cc7135528abda2f182e348f78` 的[CI run38762694677](https://github.com/StateKnot/knotsandbox/actions/runs/38762694677)首次5 job/62 step全部成功，包含P0a真实native门。该结果只证明旧提交；本轮上传后按精确新提交核对完整树与CI，私有发布回执独立保存，不以旧成功或文档循环重跑冒充新源码验收。

原VM抓取要求tenant/instance/launch，不能承载无VM的节点统计。新增同一scraper CA下的`/metrics/node-images`，只读一次已绑定缓存，不拿VM槽、不查journal数据库或发CRI。真实journal关闭时节点缓存仍可读、VM抓取按原合同503；错NodeBinding拒绝，None保持404。8个固定名最多53样本/64KiB，原时间用gauge值保留，来源RUNTIME_REPORTED/完整性UNKNOWN；近似f64不替代JSON精确整数或预算。

每node只有显式 `image_profile_sha256` 才增加独立job；固定profile/boot/epoch和受控FS ID，node与VM两套allowlist互不借身份。新样本、五个原生报告、响应正文、remote-write及WAL分别规划，原VM3584/2MB、队列、磁盘70%与双Agent保持。远写每秒模型按15秒轮次平均计算，不含重试、传输开销或恢复追赶突发，不是硬带宽/容量认证。现场只读检查核对真实JSON与闭集指标标签，拒绝后缀伪装、重复键及未知形状。

仅opt-in生成每节点9条规则：抓取/库存/FS各有单副本warning与双副本critical，原整体采集失联抑制保留。HTTP200但UNKNOWN、原观察/FS时间过旧、缺同一FS报告时间都可见；合法空FS与真实零值不会被误判。默认规则与基线逐项相同，尚未激活云端规则或通知。

## 最终本地验收

私有目录 `.local/node-image-pipeline-20261016/` 保存源码/制品摘要、原始失败与精确自有清理，未进入公开树。

| 验收 | 实际结果与边界 |
| --- | --- |
| 真实HTTP RED/GREEN | 原Linux路由在scraper mTLS下真实404；新增路径通过无VM/UNKNOWN、错CA/匿名、POST405、跨boot503、None404及journal关闭独立性 |
| Linux Rust | 四组65+5+3+1共74通过，普通组8个环境ignored另列；最终lib/bin逐SHA，root身份/取消/同inode mount反例保持。仅该mount测试沿用隔离自有容器SYS_ADMIN，不改生产或native门权限 |
| 实际containerd | 官方固定2.3.5 ARM64、真实非空OCI/no-unpack、只读/无网络/cap-drop ALL/无宿主卷；原JSON与新增指标的值/原时间/标签分别核对，精确1通过/0失败/0ignored、自有容器与镜像清理确认 |
| 普通macOS | 重新构建后62个程序与已有472通过/0失败/279环境ignored的制品SHA全部相同，复用该证据，不声称重跑全量；两平台strict all-target Clippy和fmt通过 |
| 完整观测入口 | 最终16代码文件冻结，既有check.sh统一PASS，49.658秒、输入前后不变：Python27、固定官方schema28对象、真实promtool默认与opt-in配置/受限启动/WAL跨重启、原38+新38规则、真实双Agent管线全部通过 |
| 真实Prometheus协议 | mTLS→双Agent→BasicAuth remote-write→真实receiver，原35秒共享截止保持；错身份/FS/额外标签拒绝、原时间陈旧及较大旧副本不污染HA、UNKNOWN不补数量、node/VM独立503与恢复通过。合成源夹具不是原生containerd整链，也不是云端认证 |

保留的失败：旧路由404；基线generator在真实receiver已收到VM数据但无node job，新增管线按原35秒失败；可选profile/过滤/预算的真实RED；现场标签后缀假阳性及正文/远写规划缺字段；新告警在锁定promtool中预期告警got[]。第一次HTTP私有wrapper误写诊断片段、新pipeline测试解析label键漏数字、规则夹具中的边界修正均分开记录，不当作产品RED或根因修复。

统一验收首轮Python27通过后，公开checkout缺少本地schema缓存而停止；仅补两个已锁SHA的原始schema资产后同源码通过，没有复制target/虚拟环境或放宽校验。全部失败/修正详见私有回执。两轴审查原告警P2和标签假阳性问题均已修复并独立收口；不以审查替代运行结果。

## 后续退出门

下一项P0c：安装级OIDC主体/持久授权与实时撤销、正常非owner读身份、固定selector/当前epoch与boot/profile的新鲜度门、admin消费者。真实native exporter与真实Prom写入/查询及operator需要组成同一受控链路后，才完成P0完整闭环；当前两段证据分别成立，不混写为原生整链。

P1仍需原生引用、Kata snapshotter选择、物理/内存/FD/网络硬限及后端隔离认证；之后才准备预算/下载/到期/撤销/GC。完整cache/capacity/available/reclaimable/HIT及节省比例仍未知。真实云托管写入、跨区CSI WAL、Kata、GPU、72小时负载、p95/p99和实际成本均未认证。接口与启用合同见[节点诊断](../docs/node-image-observation.md)与[采集部署](../deploy/observability/README.md)。
