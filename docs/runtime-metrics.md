# 实例运行指标

`GET /v1/instances/{id}/metrics` 提供已授权实例某一次 launch 的宿主资源时间序列。采集源是 nodeguard 已登记并固定的 VM cgroup，不接受租户提供的 exporter、标签或 PromQL。它用于资源观察，不构成应用健康、VM 死亡、卷卸载或配额释放证据。

2026-10-12首批资源效率开发已将固定指标从5项扩展为11项，补充CPU自身限额节流、匿名/文件内存和宿主OOM观察。尚无有效期request/limit/overhead分母、利用率百分比、规格推荐或节点成本治理，也不包含GPU。idle公开策略配置与安全委派仍待开发，`idle_timeout_seconds` 默认NULL。完整计划见[61项开发表](../research/rust-sandbox-development-workbreakdown.md#11-资源效率与gpu新增交付顺序)，本批实现、上线顺序和实际验收见[交付记录](../research/resource-observability-delivery-20261012.md)。

## 调用合同

调用者须通过产品 OIDC 验证，并持有项目的 `instances:read`。租户头、主体启停和本地 grant 按其他实例查询相同规则校验。后端查询之前和之后分别使用新的数据库事务鉴权；查询过程中撤权或恢复纪元变化不会返回旧数据，JWT 到期也会使请求失败。

| 参数 | 规则 |
| --- | --- |
| `metric` | 以下11个固定枚举之一 |
| `start`、`end` | RFC3339；最近 90 天内，不接受未来时间；内部按整秒计算 |
| `step_seconds` | 15–3600；单次范围不超过 7 天且最多 1441 点 |
| `launch_id` | 可选；省略时查询当前 launch。显式历史 launch 必须属于该实例且仍在当前平台恢复纪元 |

| 指标 | 单位与含义 |
| --- | --- |
| `VM_CPU_CORES` | `cpu.stat usage_usec` 的 2 分钟速率，单位核，包含虚拟化开销；可能大于 1 |
| `VM_MEMORY_BYTES` | `memory.current`，单位字节，包含内核记账的缓存 |
| `VM_IO_READ_BYTES_PER_SECOND` | `io.stat rbytes` 的 2 分钟速率，跨宿主块设备求和 |
| `VM_IO_WRITE_BYTES_PER_SECOND` | `io.stat wbytes` 的 2 分钟速率，跨宿主块设备求和 |
| `VM_TASKS` | `pids.current` 中的宿主任务/线程数，不是 guest 进程数 |
| `VM_CPU_THROTTLED_PERIODS_PER_SECOND` | `cpu.stat nr_throttled` 的2分钟速率，单位周期/秒；观察该cgroup自身CFS限额，不涵盖祖先限额的全部节流 |
| `VM_CPU_THROTTLED_SECONDS_PER_SECOND` | `cpu.stat throttled_usec` 转为秒后的2分钟速率，单位秒/秒；可能大于1，不是CPU利用率百分比 |
| `VM_MEMORY_ANON_BYTES` | `memory.stat anon`，单位字节；宿主匿名映射，不是guest应用工作集 |
| `VM_MEMORY_FILE_BYTES` | `memory.stat file`，单位字节；包括tmpfs和共享内存，不等于可全部回收的缓存 |
| `VM_MEMORY_OOM_EVENTS_PER_SECOND` | `memory.events oom` 的2分钟速率，单位事件/秒；宿主内存不足事件，不等于guest OOM或进程死亡 |
| `VM_MEMORY_OOM_KILLS_PER_SECOND` | `memory.events oom_kill` 的2分钟速率，单位进程/秒（接口单位为`events_per_second`）；不是实例终止数 |

I/O 是宿主 cgroup 记账值；设备层级可能使同一次 I/O 在多个设备记账，不能直接作为 guest 文件读写量或计费量。计数器速率至少需要足够的采样点，启动预热阶段返回缺失。

匿名与文件内存之和不必等于`memory.current`；内核其他记账、并发读取及内核配置均需按实际宿主解释。`memory.events`沿挂载的内核层级语义读取，`memory_localevents`等配置可改变范围。缺少可选CPU字段或内存文件、旧采集器没有新序列、可选内存文件读取/解析失败时，新指标保持`MISSING`/null，不能推断为零或自动宣称硬件不支持。可选内存失败不抹掉原五项；必需`cpu.stat`仍按原严格数值校验，损坏则整次基础观察失败。

结果含 `instance_id`、`generation`、`launch_id`、`cluster_epoch`、`queried_at`，以及 `series`。每个点分开给出查询时间 `evaluated_at` 和原始样本时间 `observed_at`：

- `FRESH`：原始样本距离该查询点不超过 60 秒，`value` 可以是真实的零。
- `STALE`：已知样本超过 60 秒，保留观察时间，但 `value` 为 null。
- `MISSING`：没有原始样本或速率尚未形成，`value` 为 null。

两台采集器的值不会累加。读取器从允许的 `collector_replica` 中选择可用且最新的一份；新副本正在预热时不会遮住仍新鲜的另一副本。Prometheus stale marker 后残留在速率窗口中的旧值被原始序列存在性条件过滤，不会显示成仍在采集。

无可用 launch 绑定返回 `409 METRICS_RUNTIME_UNBOUND`；查询期间当前 launch 改变返回 `409 METRICS_RUNTIME_CHANGED`。配置缺失、凭据错误或后端不可用返回 503；后端数据不完整、越界标签、重复点、非有限值等返回 `502 METRICS_RESPONSE_INVALID`。未知查询字段和重复参数拒绝。响应禁止缓存。

## 后端与凭据

API 通过 `SANDBOX_METRICS_CONFIG_FILE` 指向最多 32 KiB 的 JSON 配置。以下为字段示意，生产必须替换为该云地域实际验证的独立查询地址和凭据：

```json
{
  "endpoint": "https://<已验证的查询服务>/<实例专用 API 前缀>",
  "deployment": "sandbox-production",
  "auth": {
    "type": "BASIC",
    "username_file": "/run/metrics-reader/username",
    "password_file": "/run/metrics-reader/password"
  },
  "ca_file": null,
  "replicas": ["a", "b"]
}
```

也支持 `{"type":"BEARER","token_file":"/run/metrics-reader/token"}`。配置不包含凭据字面值；endpoint 必须 HTTPS，拒绝 userinfo、查询参数和片段。凭据文件必须为绝对路径、普通文件、权限 0400 或 0600、最多 16 KiB，逐次读取以支持原子轮换。启动会检查文件可读性；禁止回退到环境代理或其他组件身份，不跟随 HTTP 重定向，不自动重试查询。

独立 reader 身份只授所需实例查询权限；采集器使用独立写入身份。某个云端 token 不能据其名称推断读写权限已经隔离，部署前须做拒绝写入/拒绝跨实例读取的实际验证。每个 API 副本最多同时 8 次后端请求，每次 10 秒、响应 2 MiB。请求和错误不回传后端 URL、凭据或原始后端错误。

`api_features.runtime_metrics=true` 只表示本副本已配置该查询接口，不代表集群认证通过。完整 `monitoring` 能力仍由全链采集、告警和生产验收决定。

## 宿主采集

nodeguard 可配置独立 `metrics`：同一登记私网 IP、9445 端口、deployment 身份和 `scraper_client_ca`。服务端证书 SAN 保持 `<node_uid>.nodeguard.sandbox.internal`。采集客户端 CA 与控制客户端 CA 分离；同一个 CA 信任根不能同时用于二者。9445 只提供 `/metrics`，控制接口只在 9444；对应网络规则只允许平台采集节点访问。

9445 在接受连接前取得配额，最多 32 条连接；TLS 握手 3 秒、HTTP 头 2 秒、I/O 空闲 5 秒、连续写阻塞 5 秒、连接总寿命 15 秒，关停等待最多 3 秒。只用 HTTP/1.1，每次抓取后关闭连接；禁用 TLS 会话票据和服务端会话缓存，下一次抓取重新验证客户端证书。握手同时按当前时间和由连接期限推导的未来时间验证整条客户端链，证书余期不足 17 秒即拒绝。限额只用于监控入口。

采集 CA 更换或撤销需要在受控维护窗口替换专用信任根并重启 nodeguard；目前没有 CRL/OCSP 或 CA 热重载，不能承诺即时撤销某一张证书。重启仍须遵守宿主账本恢复和隔离流程。超时不产生资源零值或终止证明。

每次读取先按本机 boot 账本选出未完成可信终止的普通工作负载，备份 VM 不进入产品实例指标。读取器核对固定 cgroup FD 的 device/inode，以及各已登记 pidfd 和进程 cgroup 归属，再经固定目录 FD 读内核计数器；读取后重复身份检查。身份不匹配或读取失败时只输出 `sandbox_vm_observation_success=0`，不会制造资源零值。采集不改变启动、终止或配额账本。

`sandbox_vm_observation_success=1`仅表示原五项必需计数读取成功，不保证六项可选指标齐全。新内存文件各限64KiB；每个文件失败仅省略该文件的新序列。采集和写入白名单精确包含11项资源序列及1项基础观察标记，每节点上限为`256 × 12 = 3072`个样本。WAL容量报告同时计入这些序列、原生抓取记录及采集器自身指标；原70%磁盘预算门槛、保留期限和内存上限保持。已有安装须重新渲染并审核容量报告，不能仅手工放宽白名单。

每宿主最多一个并发采集、256 个登记观察体和 2 MiB 输出；批次具有 2 秒处理期限、HTTP 3 秒期限。固定观察锁使用非阻塞取得，仅在锁内复制已有 cgroup 和 pidfd 句柄；实际 proc/cgroup 读取在锁外完成。用户态超时无法解除内核不可中断 I/O；后台任务仍持有唯一槽位，避免超时后不断创建阻塞线程。这是故障限制，不是节点容量认证。

部署与双副本持久 WAL 见 `deploy/observability/`。跨区调度、CSI 挂盘、云查询/写入端点、凭据轮换和网络首包策略必须在目标云集群验证。观测缺失触发的告警也不能作为 VM 已终止的依据。

## 验证边界

普通 Rust 测试覆盖固定查询、HA 合并、原始样本时间、坏标签/数值/响应、凭据轮换、重定向拒绝，以及真实 TLS CA 验证。PromQL 语义使用固定版本的真实 promtool 验证。独立 Linux 测试覆盖双 CA 越权拒绝、SQLite 只读投影、pidfd/cgroup 身份；实际内核子进程采样仍不等于真实 Kata/QEMU 配置认证。数据库/API 集成专项使用隔离 PostgreSQL、实际 JWT/JWKS 和 HTTP 后端；生产集群仍须独立完成验收。

语义参考：[Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)、[Prometheus timestamp](https://prometheus.io/docs/prometheus/latest/querying/functions/#timestamp)、[Prometheus 单元测试格式](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/)。
