# 逐次启动资源账本：下一完整交付方案

状态：**待开发**。宿主CPU/内存容量上界和CRI调用往返耗时已经实现；本方案补齐解释浪费所需的配置与授权账。实施与验收完成前，不开放利用率百分比、自动调档、预热池或GPU共享。首批保留普通CPU三种Flavor及request=limit，不改变已有配额政策。

## 数据与身份合同

必须分别保存四种来源：受理时的用户规格；每次launch实际请求合同；经可信登记方回读的Pod request/limit/overhead；现有配额账的PENDING、ALLOCATED、RELEASED回执。宿主cgroup共享祖先的容量上界仍是独立观测，不能与其中任何一项直接等同。

合同绑定tenant、project、instance、workspace、generation、launch与安装epoch。实际Pod观察再绑定Pod UID、Node UID、节点boot身份和登记许可。RuntimeClass的UID、resourceVersion及overhead保存为配置观察；Pod自身的资源值来自其实际UID回读。跨对象读取不是原子快照，不伪造Pod采用了某一RuntimeClass版本的证明。采用受管理的不可变版本配置和创建/回读复核；配置变化、UID替换或证据冲突拒绝登记或保持UNKNOWN。停止和清理仍允许依据原可信终止证据进行，不能被当前RuntimeClass变化卡住。

数据库新增append-only合同、Pod观察和配额状态回执，使用复合FK、唯一launch/Pod及有界数量约束，FORCE RLS。原迁移字节保持，当前0044后的新迁移编号在实施时重新核对。旧launch没有足够证据时返回明确缺证据；不能按今天的Flavor、overhead或更新时间补造历史。

## 实现与开发验收表

| 顺序 | 需要开发什么 | 技术落点与完成条件 |
| --- | --- | --- |
| 1 | 确定可归一化的CPU/内存数量、来源与缺证据状态 | 新`runtime_resource_contract`深模块。只接受受支持的资源键与有界Quantity，拒绝负数、溢出、额外设备和sidecar。用户请求、实际调度资源、配额授权额和宿主上界用不同类型/字段表示。 |
| 2 | 不可变launch请求与配额回执 | 新迁移、`db`/`lifecycle`受理事务。PENDING与原受理一起提交；START/RESTART有新launch，renew不改资源合同。保存实际受理/观察时间，不伪装精确COMMIT时间。双层租户/项目配额分列，不相加为物理占用。 |
| 3 | 受控RuntimeClass配置与Pod资源回读 | `runtime`/`runtime_manifest`/`worker`保存版本配置观察并校验实际Pod资源。UID或值冲突拒绝；无法建立一致证据时UNKNOWN，不回填当前值。保持原CRI许可、节点/卷归属和期限。 |
| 4 | 可信观察登记 | `gateway_runtime`、`termination_runtime`把已校验的Pod资源带入原许可登记事务；沿用workspace→instance→operation/node fence顺序。同UID相同内容幂等，冲突拒绝，COMMIT ACK丢失复用原登记。API/普通调用者不能伪造登记。 |
| 5 | 完整释放历史 | `mark_ready`与原ALLOCATED事务同提交；可信VM终止和cleanup释放同提交。保留`never_authorized_closures`的独立合法释放路径。TTL、Pod缺失、CRI返回、API退出、节点失联都不能直接结束预留。 |
| 6 | 最小权限与启动门禁 | 各角色SQL仅增实际调用所需权限；API只读，admission仍只读。缺迁移、旧校验和不符、缺grants或部分部署均启动拒绝；不能捕获启动失败后降级成成功。 |
| 7 | 对外只读API、SDK与实例页面 | 按实例/launch有界分页，以`instances:read`检查租户/项目及查询前后撤权/epoch。返回请求来源、Pod观察时间、配额状态和UNKNOWN。SDK生成与正式OpenAPI一致；切scope、撤权、缺测后清除旧数据。 |
| 8 | 真实事务和HTTP验收 | 独立TLS PostgreSQL、正常迁移及普通角色；测试CREATE/START/RESTART/renew/stop/delete、未授权launch删除、并发登记/回滚/丢ACK、旧generation/epoch/boot、慢查询期间撤权与升级旧历史。Kubernetes响应可用明确合同fixture验失败边界，真实Kata资源对应仍须节点实机验收。 |

每一步仅在其事务、不变式和失败验收通过后完成；不能只凭schema存在、HTTP 200或控制台展示标记整个工作包完成。发布走源码绑定CI及既有签名、安全、回滚和离线安装门禁。

## 随后推进快速启动和GPU

资源账本交付后，再开发有预算、到期、撤销和GC合同的镜像/节点预准备。分开观测accepted、queue、placement、镜像准备、CRI调用、VM readiness、route及首次正确执行；以端到端成功任务测冷暖p50/p95/p99、峰值并发、失败率和单位成功任务成本。预准备本身的空闲占用、镜像体积、实际释放证明须可计量；没有节点实测前不承诺启动毫秒数或资源节省比例。

GPU先开发真实设备身份、独占租约、Pod/VM/租户归属、显存与计算利用率采集及可信回收。不得把显存占用率当计算利用率；设备未运行、采集失败及归属丢失用UNKNOWN。随后在实际支持的硬件/驱动上验MIG、时间共享等隔离与资源合同，覆盖撤权、节点重启、故障恢复和数据残留。没有本机GPU不能用CPU fixture签发GPU性能、隔离或成本认证。
