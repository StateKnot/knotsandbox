# KnotSandbox 资源效率观测首批交付

日期：2026-10-12。对应G0-08/G3-12的首个观测子项，复用G3-02现有链路。交付可调用的宿主指标扩展、采集安装配置、SDK和控制台；没有新增依赖或数据库迁移，没有开启GPU、闲置公开策略、自动调档或生产部署。本批不等于整个资源优化工作包完成。

## 1. 已实现的完整路径

nodeguard从已固定的cgroup目录FD读取CPU/内存记账，保留采集前后device/inode、pidfd与进程cgroup身份检查。六项新字段加入严格固定指标枚举，通过独立mTLS采集、双副本Prometheus写入、固定查询、现有授权API、生成的TypeScript SDK和控制台提供。

| 新指标 | 内核字段和单位 | 解释边界 |
| --- | --- | --- |
| `VM_CPU_THROTTLED_PERIODS_PER_SECOND` | `cpu.stat nr_throttled`，周期/秒 | 自身CFS限额观察，不能覆盖祖先限额的全部节流 |
| `VM_CPU_THROTTLED_SECONDS_PER_SECOND` | `throttled_usec`转换为秒，秒/秒 | 使用2分钟速率，可大于1，不是利用率百分比 |
| `VM_MEMORY_ANON_BYTES` | `memory.stat anon`，字节 | 宿主匿名映射，不能当guest工作集 |
| `VM_MEMORY_FILE_BYTES` | `memory.stat file`，字节 | 包含tmpfs/共享内存，不能宣称全部可回收 |
| `VM_MEMORY_OOM_EVENTS_PER_SECOND` | `memory.events oom`，事件/秒 | 宿主事件，不保证发生guest OOM或进程终止 |
| `VM_MEMORY_OOM_KILLS_PER_SECOND` | `memory.events oom_kill`，进程/秒 | 宿主被OOM终止的进程数量，不是实例死亡证明 |

字段按实际宿主内核和挂载语义解释。[内核定义](https://docs.kernel.org/admin-guide/cgroup-v2.html)；完整查询与凭据合同见[运行指标说明](../docs/runtime-metrics.md)。原五项用量指标保持兼容，已有身份服务和`instances:read`授权可继续使用，无需新增权限。

## 2. 调用与缺失数据

其他微服务使用同一个Interface：

```http
GET /v1/instances/{id}/metrics?metric=VM_MEMORY_ANON_BYTES&start=<RFC3339>&end=<RFC3339>&step_seconds=15
Authorization: Bearer <access-token>
X-Tenant-ID: <tenant-uuid>
```

OpenAPI与SDK支持11项固定枚举和相应单位；不接受任意PromQL。省略launch时使用当前launch，历史launch仍需该实例/当前恢复纪元授权。查询前后数据库权限、身份与launch绑定复核保持，缺失/过期返回null，真实零值保留，HA不累加。

可选CPU字段缺失、新内存文件读取/解析失败或旧采集器没有新序列时只省略相应数据，不能补零。每个新内存文件最多64KiB；损坏的可选内存文件不抹掉原五项。必需`cpu.stat`继续原严格校验。`sandbox_vm_observation_success=1`只表示五项基础计数成功，不表示六项可选指标完整或运行健康。

控制台提供中文名称、单位、解释及空缺图表；404/撤权后清除旧图表和明细。没有将任何新指标接入自动STOP、续租、释放配额或数据删除。

## 3. 采集部署与资源预算

采集和remote-write白名单精确列出12项原始序列（11项资源加1项基础观察标记），没有开放任意`sandbox_vm_*`。每节点最多256个登记观察体，sample_limit由1536更新到3072；标签限制13、单抓取2MB、15秒周期、独立CA和原有网络/连接限制保留。

WAL规划同时计入新序列、原生抓取记录和自身指标，原70%磁盘预算门槛、6小时规划窗口、checkpoint预留、内存上限和写入队列限制不变。新容量校验会拒绝只按旧六序列容量准备的配置，不以扩大限额掩盖不足。该上界是规划模型，不代表已经完成云容量或无损保证。

上线顺序：

1. 用现有安装身份重新渲染采集配置和capacity报告，按实际节点/登记数量复核WAL、内存、写入速率与配额；容量不够时先取得相应资源变更授权。
2. 发布兼容旧五指标的API/reader、SDK和控制台；旧collector期间新指标明确留空。
3. 在维护窗口更新双采集器配置（白名单与sample_limit一起生效），保留各自持久WAL和节点/boot身份过滤。
4. 按现有nodeguard发布/账本恢复与准入围栏流程更新目标宿主；不得直接跳过宿主二进制和Kata运行组合认证。
5. 检查真实样本、缺失率、采集开销、错误和WAL压力；异常时恢复兼容旧五指标的部署，保留WAL和可信关闭链。

本次只交付安装工具与源码，未应用任何云/Kubernetes资源。

## 4. 实际验收

| 验证范围 | 本批结果 | 证明边界 |
| --- | --- | --- |
| 普通Rust | 56个程序，429通过/0失败/246环境专项明确ignored | 同源码串行完整all-targets；不把ignored算通过 |
| Linux nodeguard | 39通过/0失败/1专项明确ignored；随后该真实cgroup内核专项独立1/1通过 | 当前Rust源码，Linux arm64；实际pidfd/cgroup与锁验证，不是Kata/QEMU认证 |
| 真实PostgreSQL/签名身份/API | 独立TLS Docker库1/1通过 | 六个新枚举、null、实时撤权、身份失效、token期限、恢复纪元；正常42条迁移和最小组件角色，无迁移变更 |
| Prometheus查询语义 | 锁定真实promtool1/1通过，9规则样例/17表达式检查 | 速率、单位、超过1、零值、缺失及旧HA/freshness合同 |
| 双节点/双副本实际采集写入 | 真实Prometheus协议链通过 | 六项新序列各4份绑定正确，24份新样本；mTLS、写入重试、私有标签/无效身份拒绝、失败与恢复；exporter为协议夹具 |
| 采集部署 | 13单测、14对象官方schema、锁定镜像配置/TLS/WAL跨重启、原38告警场景回放通过 | 精确白名单/3072样本、WAL余量拒绝和原身份规则，不是集群安装 |
| SDK/控制台/OpenAPI | SDK70、控制台单测66、Chrome新指标合同2、OpenAPI13项通过 | 控制台/SDK构建与格式检查通过；Chrome为真实浏览器HTTP合同夹具 |
| 代码检查 | macOS all-targets严格Clippy及Rust格式检查通过；Linux补验见下文 | 新增Rust、部署脚本与Interface已独立只读复核 |

保留首轮SDK回环监听权限失败、浏览器控件定位失败、并行Rust网络/计时失败以及冷编译期间PG容器准备超时。SDK在允许回环环境通过；浏览器改用实际combobox角色，不改变产品或断言；Rust同源码/原期限串行通过；PG在冷编译结束后用新库通过。控制台首次npm脚本报告Node选项错误，固定Node24.19.0绝对路径按同参数66项通过；不推断未复现的子进程环境根因。告警回放首轮脚本失败，单独配置/规则/38夹具生成通过后，原脚本串行重跑38项通过；未确认首轮失败根因。没有放宽授权、超时或测试断言。

原始日志、源码/制品摘要、失败和自有清理回执保存在私有验收目录，未发布凭据。自有临时PG、Linux与Prometheus协议容器均已核对清理；仅保留源码快照、日志和可复用编译缓存。

## 5. 仍待开发

G0-08/G3-12均仍开发中。下一步是有有效期的capacity/request/limit/overhead合同、CPU/内存压力与峰值画像、覆盖率、只读利用率/成本归因；不能用名义Flavor给VMM消耗制造百分比，不能用文件内存直接计算可缩容额度。

G2-07需完整闲置策略配置及安全授权：平台活动结束不证明guest无后台工作，启用不能绕过`instances:hard_stop`；独立有界可撤销委派、后台保护、计时重置、CAS/幂等和idle/TTL分离均待实现。现有UNKNOWN执行活动槽保护不能当成通用实例UNKNOWN排除。

GPU版本/实机矩阵、设备租约/分配、安全清理、可信归属、GPU监控和成本核算继续按[资源效率计划](resource-efficiency-audit-and-plan-20261012.md)推进。未开启GPU、调整requests=limits、启用闲置停机或宣称降低了实际云费用。云隔离、72小时容量、真实工作负载SLO和统一签名发行仍有独立发布门。

## 6. 公开CI补验

首批公开CI的SDK/控制台通过；采集夹具目录权限、Linux测试lint和Terraform跨平台锁检查失败。随后完成三类窄修复及实际Linux/Prometheus/native Terraform补验，保留首轮失败与原检查门槛，详见[补验交付](resource-observability-ci-delivery-20261012.md)。远端整套CI需按新提交实际运行核对；不将首批本地通过等同于完整生产上线。
