# P0c2a：安装级节点镜像查询与管理读消费者交付

状态：本地验收完成。基线 `eec9106cbfc33cb6f8a9d9c754df7c556a90bbfe` 的 GitHub CI run `38786382406`，5 job／62 step全绿。本批新提交只在实际同步后读取其精确CI；基线结果不证明本批Linux／镜像门。完整P0c仍等待P0c2b同一原生整链，P1—P6未完成。

## 本轮行为

`GET /v1/operator/nodes/{runtime_node_id}/image-status` 无tenant header选择，固定 `node_images:read` 安装SERVICE权限。0048只增加绑定函数：当前installation／epoch／原grant ID及enabled节点、Node UID／boot／profile和未到期owner认证；正常app仅窄EXEC。外部I/O后即使后端失败仍重新授权，换grant不挪用在途读取，节点失效或认证／OAuth／授权过期拒绝旧结果。节点没有VM也可读；无观察不伪造零。

固定 instant POST／独立2槽／256KiB／216行／217行哨兵／最多两个配置副本、16个可见FS；原VM的GET range／八槽／预算保持。先以最新健康 `up` 确定scrape，再检查同cohort flag与字段。remote-write部分到达时最新flag缺失／旧时间为UNKNOWN，不能回退另一副本旧成功；最新0清值，健康副本可独立承接另一副本 `up=0`。每组件使用完整单副本元组，绝不累加或逐字段max。原始scrape／collector／filesystem时间严格新于60秒，报告未来最多5秒；新的scrape时间不能刷新旧报告。

返回固定来源 `RUNTIME_REPORTED`、完整性 `UNKNOWN`、精度 `APPROXIMATE_F64`。两个组件独立，不宣称原子快照；FS的两个数量允许分别缺失，空可见列表不证明总集合为空。重复键／重复序列／未知标签／截断warning／非有限或负数量／超预算拒绝。

`sandbox-admin node-image-status` 实际调用同一HTTPS API，使用私有常规OAuth token文件和可选CA，没有owner数据库回退。每次打开当前inode，支持投射Secret轮换；禁代理／重试／跳转，总请求10秒／连接3秒／256KiB。错误不打印服务正文／token／旧结果。owner `node-image-reader` 管理功能保持独立。用法见[操作说明](../docs/node-image-query.md)。

普通启动／维护预检增加窄函数的正文／参数／结果／owner／search_path／ACL，以及节点登记结构、列权限、不可变trigger／函数正文，拒绝私有认证表直接读取或运行时写权限漂移。0048正常迁移后47条为1..37＋39..48，原46条字节不变，没有0038。精确更新三个正式runner及历史升级函数排除，没有泛化schema豁免或新库存副本。

## 实际验收

验收制品与日志在本机 `.local/node-image-query-20261016/`，公开源码不包含credentials、容器数据库或私有产物。

| 范围 | 已观察结果与限制 |
| --- | --- |
| 普通Rust | 64个程序，486通过／0失败／290环境专项明确ignored；最终64制品逐SHA保持，复用同一已验结果，不把ignored算通过。7个节点backend真实HTTP行为与4个CLI纯测试包含在普通数内 |
| 安装／查询组合专项 | 最终普通PG／真实Keycloak JWT／生产Router实际TCP HTTP、真实HTTPS backend与CLI，共10项通过／0失败／0ignored；查询中撤权（含backend503）、新grant替换、禁用node、原认证1秒到期均拒旧；正常preflight核对函数正文、列级读写ACL、结构和trigger漂移 |
| 最终CLI补验 | 仅CLI let-chain静态修正后补验受影响的HTTPS／CLI与查询后撤权1项；API专项制品SHA与前10项相同，完整64普通制品SHA也不变 |
| 真实Prometheus3.13.4 | 固定摘要镜像、真实双副本scrape、HTTPS query proxy原响应、Rust公开backend，fresh／latest_zero／stale／absent四场景各1项通过；fresh每副本18种name-kind、总36行，结果选择实际最新完整cohort；自有container与数据清理确认 |
| 既有PG回归 | 六组29项：fresh1、资源账本9、真实HTTP／Node SDK3、可信Pod观察8、SERVICE授权7、非空v41正常升级1。新库与历史升级均正常47条checksum；源码、测试及SDK产物保持，精确自有容器／进程清理确认 |
| 正式自动化 | 18业务＋5通知＋1通知HTTP＋1实际进程，共25通过；实际进程117.74秒，未扩大原权限、自然期限、锁窗口或线程栈；正常47条账本、双独立库及自有清理确认 |
| 合同／静态 | SDK77、OpenAPI13、Python诊断10通过；生成类型保持，strict all-target Clippy与fmt通过。既有vendor四条依赖warning仍保留，workspace检查退出0 |

这里的API与CLI是本机Rust程序，PG与Prometheus是真实Docker服务；不是完整 `sandboxd` Linux发行包／生产TLS listener认证。真实Prom这里为固定协议采集端点，不是原生CRI，不经过双Agent remote-write。P0a原生后端、P0b管线与本片不能拼成一次原生整链通过。

## 审查与失败保留

独立Spec审查发现三项P2：最新健康scrape的flag不齐会退旧值；节点不可变函数仅核对关联名称；新CI在固定Prom镜像拉取之前就以pull-never执行。分别先选择最新up再解释完整度、增加旧0014函数完整合同及真实PG否例、提前固定镜像拉取并复用已有锁依赖Python环境。首项通过真实HTTP在修复前重现 `Some(true)` 对比期望 `None`，之后同用例GREEN。Standards及最终增量复审另存具体补丁哈希回执，不以作者自审代替。

原始失败没有覆盖：旧API404而预期403、首backend stub拒绝、上述HA退旧实际RED、首HTTP测试缺Handle泛型编译失败、TLS辅助blocking socket注册panic及同组身份绑定级联失败、全局Python缺PyYAML准备失败、Docker local日志压缩与单文件冲突、CLI collapsible-if静态失败。分别在独立新目录保存后修正重验；TLS设为nonblocking，准备错误正常退役本测试身份；日志保持1MiB单文件并关闭该测试日志压缩，未扩大资源／权限／期限／线程栈。目录／源码快照准备的早期路径错误也保留记录，catalog仅作结构提取，不称功能验收。

编译前可用306GiB，复用本任务 `target/review-low-debug` 约6.6GiB；原Linux缓存约1.8GiB保留。没有复制target、清理用户DB／Docker卷或全局prune；最终磁盘与保留缓存另存回执。

## 下一步

优先完成P0c2b：同一原生containerd→mTLS scraper→双Agent remote-write→当前operator API／admin的整链，包括原生故障、失联恢复和撤权清值。P1原生引用／平台选择、P2／P3预算与有硬限准备、P4安全释放仍未完成，不开放pre-pull。物理缓存总量／可释放量／HIT、GPU、Kata／CSI／目标云与p95／p99／72小时成本均未认证，不能从本轮只读功能推导收益或上线全产品结论。
