# 实例监控采集部署

两份固定 Prometheus 3.13.4 agent，分别运行在不同 platform 节点、不同可用区；每份使用独立、加密 ESSD PVC 保存 WAL。采集 nodeguard 的宿主 VM cgroup 指标、可信目标的原生 `up` 和九项采集器自身指标，写入操作者提供的阿里云托管 Prometheus。没有 Operator、Grafana、查询代理、云凭据默认链或 K8s API 读取权限。API 读取器使用另一套只读身份，不能挂载 writer Secret。

已交付渲染、凭据验证、固定镜像校验、只读现场前置检查。当前仓库没有真实 Managed Prometheus 账号/endpoint/凭据，也没有执行云资源创建、集群 apply 或现场认证；离线测试不能将安装标为生产验收通过。

## 写入入口和身份

当前支持经过[阿里云官方文档](https://www.alibabacloud.com/help/en/cms/cloudmonitor-1-0/user-guide/write-open-source-prometheus-data-to-an-alibaba-cloud-prometheus-instance)记录的 HTTPS BasicAuth 入口：`https://ts-<instance>.hitsdb.rds.aliyuncs.com:3242/api/prom_write`；同主机443端口也可接受，但必须是目标实例控制台实际给出的 HTTPS 入口，不能自行把 HTTP 改成 HTTPS 或假定所有地域/产品版本都提供该入口。关闭 HTTP/2、重定向及环境代理。使用专属 writer 的 username/password 文件；不在配置中内联 AccessKey，不使用主账号凭据，不生成永久 AK。

不支持含凭据的 `/prometheus/{token}/...` 路径、URL query、userinfo、HTTP、任意域名或其他端口。Prometheus 自身错误日志可能输出 endpoint，因此只将文件放 Secret 不能保护 URL 中的 token。若目标产品只有这种入口，本安装器拒绝；需要单独评审该产品提供的受保护写入口，不能绕过校验。路径没有凭据也按私有文件管理。

两个 scraper 使用独立 client CA 签发的证书；该 CA 的公钥必须与控制 RPC client CA、node server CA 都不同。nodeguard9445仅信任 scraper CA；9444继续只信任控制 CA。每个 node 单独 scrape job，TCP目标固定为受审私网 IP，TLS SAN 固定 `<node_uid>.nodeguard.sandbox.internal`，不关闭证书校验。更换证书通过更新 Secret 完成；到期、撤销或错误 CA 会导致采集失败，不会变成零用量。

## 安装顺序

1. 按[集群安装流程](../../docs/cluster-installation.md)准备固定制品并完成真实 workload OIDC→STS 验收。更新后的 CSI node DaemonSet 覆盖 kata 与 platform；CSI controller 的 RAM Attach/Detach 仅新增已知 platform 实例，fencing 仍只覆盖 kata。重新应用前先审阅 Terraform 计划和 CSI 清单；本工具不代替执行这些变更。
2. Cilium 1.20.2 启用 `nodeSelectorLabels: true`、`clustermesh.policyDefaultLocalCluster: true`。不启用 `policyCIDRMatchMode`。采集 Pod 在独立 `sandbox-observability` namespace，不继承 sandbox-system bootstrap 的宽授权；egress 仅受审 node 的 `toNodes` 精确 hostname+kata selector/TCP9445、目标 Managed Prometheus FQDN/TLS端口与该域名的 CoreDNS查询。对应 host policy 仅给这些 node 放行该采集身份9445。网络/安全组仍需按部署计划放行 platform→kata9445及目标HTTPS流量。
3. [nodeguard安装器](../nodeguard/README.md)启用 metrics，安装独立 scraper CA。节点必须完成可信登记，Node UID、boot ID、cluster epoch 与平台一致。扩容、重启后重新登记并更新整个采集清单，不能仅修改标签猜测身份。
4. 从 Terraform 的 `node_inventory` 和实际登记记录准备 `settings.json`。字段如下，UUID/IP/name必须来自本部署；示例中的标记不是可安装凭据：

```json
{
  "protocol": 1,
  "deployment": "<Terraform deployment_identity.deployment>",
  "region": "<Terraform deployment_identity.region>",
  "cluster_epoch": "<current registered cluster epoch UUID>",
  "wal_gib": 40,
  "nodes": [{"name": "<exact inventory/Kubernetes node name>", "node_uid": "<actual Node UID>", "host_boot_id": "<registered current boot ID>", "private_ip": "<Terraform Kata node IP>"}]
}
```

全量 Kata 节点必须列全，最多64；platform至少两个可用区可调度。`wal_gib` 必填且40–1024，每副本独占该容量。渲染器按目标数量计算预算，不满足70%磁盘预算则拒绝；先核对输出 `capacity.json`，不要机械复制40Gi。准备一个0400/0600的 `remote-write-url.txt`，仅包含实际受审HTTPS地址。

```sh
.local/cluster-venv/bin/python deploy/observability/observability.py \
  --settings settings.json --terraform-output terraform-output.json \
  --remote-write-url-file remote-write-url.txt --output rendered-observability

.local/cluster-venv/bin/python deploy/observability/credentials.py \
  --username writer-username --password writer-password \
  --client-cert scraper-chain.pem --client-key scraper.key \
  --scraper-ca scraper-ca.pem --controller-ca controller-ca.pem \
  --server-ca node-server-ca.pem --output rendered-observability/credentials.yaml
```

输入私钥/username/password必须0400/0600；client证书必须与私钥匹配、具备clientAuth、由专属CA验证且至少还有24小时有效。输出目录0700、文件0600，拒覆盖。不要把任何这些生成文件提交 Git、复制到工单或打印到构建日志。

渲染同时生成 `alerts.rules.yaml`，供托管后端的 Prometheus 规则执行器加载。该文件包含固定 deployment/cluster epoch/节点登记身份；不属于 Kubernetes 资源，也不挂入 agent 的 `rule_files`。Prometheus agent [不执行告警规则](https://prometheus.io/blog/2021/11/16/agent/)。部署时必须另行配置后端规则执行、通知路由和抑制策略，并在目标服务中验收；本工具不假定不同版本的阿里云监控产品共享同一导入 API。

5. 用有读取 Nodes/CSINodes/Cilium配置权限的运维身份执行只读检查。它严格比对 Terraform API入口/NodeUID/boot/IP/Ready/CSI节点插件，逐节点真实mTLS抓取；它不调用云写接口，也不把成功文件当成远程写入或CSI持久性证明：

```sh
.local/cluster-venv/bin/python deploy/observability/verify.py \
  --settings settings.json --terraform-output terraform-output.json \
  --remote-write-url-file remote-write-url.txt --context reviewed-cluster \
  --server-ca node-server-ca.pem --client-cert scraper-chain.pem --client-key scraper.key \
  --output observability-private-prerequisites.json
```

6. 人工审阅渲染文件，先创建namespace，再应用凭据和清单。以下是运维执行指令，本次开发未执行。`kubectl apply`不会安全打印Secret内容，但仍不要打开shell tracing。

```sh
kubectl --context reviewed-cluster create namespace sandbox-observability --dry-run=client -o yaml | kubectl --context reviewed-cluster apply -f -
kubectl --context reviewed-cluster apply -f rendered-observability/credentials.yaml
kubectl --context reviewed-cluster apply -f rendered-observability/manifest.yaml
kubectl --context reviewed-cluster -n sandbox-observability rollout status statefulset/sandbox-metrics-agent-a
kubectl --context reviewed-cluster -n sandbox-observability rollout status statefulset/sandbox-metrics-agent-b
```

## 数据合同与容量

15秒抓取；每 nodeguard 目标最多256个实例、14条raw metric/实例（13项资源加1项基础观察标记）、2MB响应、3584 samples、13标签、标签值128字节。精确白名单在[RAW_METRICS](observability.py)中枚举：原五项用量及观察标记，加CPU自身CFS节流周期/时间、匿名/文件内存、宿主OOM事件/终止进程计数和CPU/内存容量上界；不开放任意`sandbox_vm_*`。身份标签验证 node UID/boot/epoch/deployment 和非nil UUID 格式，去除其他标签；不接受guest指定路径或时间戳。资源计数包括 VMM/virtiofs/cgroup page cache，tasks指宿主线程，均不等于guest应用健康或退出证明。六项压力指标和两项容量均可缺失，基础`observation_success=1`不代表它们全部可用，详见[运行指标合同](../../docs/runtime-metrics.md)。

新增`sandbox_vm_cpu_capacity_cores`与`sandbox_vm_memory_capacity_bytes`是宿主真实采样的gauge。CPU取叶级有效cpuset及全祖先有限`cpu.max`的最紧名义CFS/fair class上界；内存取全祖先最紧有限`memory.max`。父级限制可能共享，不能当作实例专属预留、可用余量或节点利用率。内存全为`max`或输入缺失/非法时省略该容量，明确的`memory.max=0`保留零；CPU与内存变化各自缺测，不抹掉基本计数。前后双采样用于检查稳定性，不是原子快照。只读查询和控制台当前提供13个固定资源选择项，不提供利用率百分比或自动调档。

原生 `up` 由 Prometheus 生成；节点目标使用独立 `scrape_node_uid`/`scrape_host_boot_id` 静态标签，不用目标标签覆盖被验证的 exporter 身份。VM 序列继续保持原13标签，剔除这两个目标标签。nodeguard 返回的同名 `up` 或采集器指标会被丢弃。[metric relabel 不处理自动生成的 `up`](https://prometheus.io/docs/prometheus/latest/configuration/configuration/)，因此远程写入白名单单独保留它。

每副本仅增加一个 `127.0.0.1:9090` 自采目标，无新网络授权或 K8s 权限。固定白名单为 `prometheus_remote_storage_samples_pending`、`samples_failed_total`、`samples_retried_total`、`queue_highest_sent_timestamp_seconds`、`shards`、`shard_capacity`（前六项共享 `prometheus_remote_storage_` 前缀），以及 `prometheus_tsdb_wal_storage_size_bytes`、`prometheus_tsdb_wal_writes_failed_total`、`prometheus_agent_corruptions_total`。指标名和类型已在锁定镜像实测；该镜像没有 `prometheus_remote_storage_samples_dropped_total`。自身指标限制64 samples、3标签、2MiB响应，`url`/`remote_name` 在入 WAL 前去掉；不把租户或实例标签加入自身指标。

每项指标的两份序列始终保留 `collector_replica=a|b`。托管后端必须保留这个标签、不能启用移除该标签的HA去重。API按真实原始样本时间选一个新鲜副本，不相加；超过60秒只返回陈旧/缺失，不填0。不把remote write延迟当成采集时刻，也不将重放样本改写为当前时间。CPU/IO及节流/OOM计数器速率在查询侧 `rate(...[2m])` 计算；容量gauge保留原值，不计算rate、用量比率或剩余容量。

每副本队列最多4 shards，每shard10000排队样本、每批2000；429/5xx有界退避，失败回积WAL；HTTP401/403等不可恢复错误不能靠WAL承诺自动补回，需立刻处理并记录数据缺口。WAL压缩，最少保留5分钟，最多6小时强制截断；超过6小时写入故障、磁盘耗尽、损坏、重建/误删PVC都可能丢数据，**不宣称无损**。磁盘硬上限是PVC容量，Prometheus agent没有按字节自动缩减WAL的开关；不能套用server TSDB retention-size。预算包括全部 VM 样本、自采64样本上限及每目标五条原生抓取报告；报告即使被远程写过滤也先进入 WAL。预算以每个采样1KiB包含label/churn再乘2 checkpoint余量建模，预留30%磁盘，需现场测量实际压缩率和实例启动频率；内存限4Gi也需要容量压测，OOM/丢样本必须验收而非忽略。

2026-10-13增加容量gauge后须重新渲染并审核capacity报告，14条raw白名单和3584样本上限一起生效。按旧六条或十二条raw序列准备的WAL配置可能被新预算拒绝；不得单独放宽70%门槛或默认扩容。资源变更、PVC扩容和宿主升级仍需现有运维授权与实际容量/恢复验收，首批安装顺序见[资源观测上线顺序](../../research/resource-observability-delivery-20261012.md#3-采集部署与资源预算)。

两个PVC名字分别 `wal-sandbox-metrics-agent-a-0` 与 `wal-sandbox-metrics-agent-b-0`。缩容或删StatefulSet均保留PVC；删PVC后云盘由StorageClass Retain保留，不自动销毁。相同StatefulSet/PVC名称可重建接原WAL；不得同时给两个进程挂同一WAL、禁用lockfile、删除旧卷再假称续传。单可用区故障时另一副本继续抓取，故障副本等原区/卷安全恢复；不强制多挂载或无证明force-detach。若因升级需要改WAL尺寸，先显式扩各PVC并确认文件系统容量，volumeClaimTemplates变更不可直接通过普通StatefulSet patch完成。卸载后的计费卷由独立受控存储清理流程处置。

## 现场验收与故障演练

真实验收至少保存：两个PVC/PV/cloudDiskUID和加密/KMS证明、agent分布于不同可用区、CSI实际挂载；删除单个Pod重建后WAL续传；滚动升级时旧agent退出后才接管PVC；后端可查询的同一launch两副本序列；可用区单故障；断网/429/401和证书失效；超过六小时/磁盘满/高churn时缺口告警；错tenant/epoch/boot标签被丢弃；API实时撤权与时序陈旧行为。认证材料必须与本部署、镜像digest、配置摘要绑定。

agent HTTP9090无对外入口，只允许宿主探针和容器自身抓取；运维可通过受审 `kubectl port-forward` 读取本地 `/metrics`。还须通过现有集群监控配置 PVC 剩余容量、Pod 重启/OOM 和 CSI 挂载告警。本包不部署告警发送器，不将 agent readiness 当作云端收数成功。实例 `observation_success` 缺失/0、guest 应用健康与修复策略也须单独验收，不能从空闲节点没有 VM 序列推断故障。

## 监控采集链告警

标准规则每15秒评估，只接受本部署和本 epoch 的样本；节点还必须匹配登记的 UID/boot ID。样本年龄必须严格小于60秒，重放旧样本不会延长健康期限。没有 VM 序列的空闲节点仍以真实 `up` 判定。每副本问题为 warning；两个副本同时出现同一问题才提升 critical。双副本问题也保留 warning 供定位，通知路由应抑制重复通知。

| 规则范围 | 触发条件与持续时间 | 运维含义 |
| --- | --- | --- |
| 采集器与节点抓取 | 新鲜成功 `up` 缺失/0持续2分钟；采集器整体失联时抑制逐节点规则 | 排查进程、远程写入、mTLS、登记身份和网络；不代表 VM 已退出 |
| 不可恢复远写失败、WAL写失败/恢复损坏 | 新鲜的本进程累计计数大于0持续1分钟，包含首个样本已为正的情形 | 核验数据缺口与卷；计数表示进程曾记录故障，不表示故障此刻仍发生。进程重启清零可清除告警，故障材料需另行保留 |
| 持续远写重试 | 最近5分钟计数有增量，条件持续5分钟 | 排查网络、429/5xx与后端；重试不等于样本已丢失 |
| 队列接近容量 | 有积压，当前 shards×单 shard 容量为正，使用率大于80%持续5分钟 | 按真实当前 shards 计算，不拿最大4 shards 隐藏饱和 |
| WAL预算超出 | 原生 WAL 字节大于配置卷容量70%持续5分钟 | 预算告警；不能替代实际文件系统剩余容量监控 |
| 送达落后 | 有真实积压且非零最高已送达时间落后15分钟，持续5分钟；两副本都落后4小时提升 critical | 提前排查六小时截断风险；最高送达时间不是最旧未送达时间，不承诺仍有两小时无损窗口 |
| 尚未确认送达 | 有积压但已送达时间为0持续15分钟 | 初始零值不被误称为四小时延迟；空闲且无积压不会告警 |
| 自身遥测不完整 | 新鲜健康 `up` 存在，任一固定自身指标缺失/陈旧持续2分钟 | 检查镜像、白名单与采集配置；缺失不填0 |

规则文件不包含云凭据或通知接收者。上线前须在目标后端完成规则加载、15秒评估、两副本标签保留、故障触发/恢复、分级抑制和通知送达验证；这些步骤尚未在实云执行。采集链规则不替代实例级告警、告警管理 API 或自动修复。

## 离线检查

Python依赖沿用仓库 `deploy/cluster/requirements.lock.txt`；只运行已缓存的digest镜像，检查器不会拉镜像、创建云资源或写入Managed Prometheus。

```sh
OBSERVABILITY_PYTHON=.local/cluster-venv/bin/python bash deploy/observability/check.sh
```

包括配置/权限/身份/指标白名单检查、14个对象的固定官方 Kubernetes/Cilium schema、镜像内实际 `promtool check config --agent`、TLS文件验证、无网络 agent 启动和真实本地采样 WAL 跨重启。`check_rules.py` 在无网络、只读根文件系统和128MiB临时内存盘内运行原生 `promtool check rules` / `test rules`，回放38个独立故障场景，包含首样本已记录故障、清零、严格新鲜度、错 epoch/boot、断流恢复及整体故障抑制。

2026-10-12新增六项raw序列的实际双节点/双副本写入、真实零值、身份与私有标签过滤，以及失败/恢复验证；原35秒截止不变，历史结果见[资源观测交付](../../research/resource-observability-delivery-20261012.md)。本轮容量gauge扩展后的渲染、采样预算、写入与缺测合同须另行保留绑定当前源码的结果，不能用该历史记录代替本轮验收。真实Kata/QEMU、云端收数、跨区WAL/CSI和通知链仍需现场验收；GPU未纳入本采集部署。

另以仅指向本机的 mTLS 夹具连接两个真实 agent 和一个真实 Prometheus 接收端，验证 BasicAuth、503重试、HA副本分离、错身份/额外标签过滤、忽略源端伪造时间戳、原生节点 `up` 的503失败/恢复、自身九项指标和 guest 同名伪造拒绝。故障和恢复共享原35秒截止；失败不产生零用量。该管线需要本机 TCP 监听和 Docker bridge，使用生成的测试证书/合成凭据，不连接外部网络目标。规则回放验证引擎语义，管线验证真实数据合同，两者未组成云端告警通知链。2026-10-09最终本地完整检查通过，输入与日志收据见 `.local/observability-alerts-20261009/final-2/record.json`。该本地协议证据不等于阿里云远程写入、Kata裸金属或 CSI 卷认证。官方配置/队列/agent保留语义见 [Prometheus配置](https://prometheus.io/docs/prometheus/3.13/configuration/configuration/)、[remote write调优](https://prometheus.io/docs/practices/remote_write/)、[Cilium节点策略](https://docs.cilium.io/en/stable/security/policy/layer3/)。

## 节点镜像只读指标（P0b，显式启用）

在已重新认证并开启image_observation的node上，可给该node的settings额外填写 `image_profile_sha256`（实际profile SHA-256的小写64hex）。缺字段保留原行为；不能用占位摘要、当前模板或今天的配置补造认证事实。宿主安装器不自动开启该功能，P0c安装级授权/API和目标宿主认证仍未完成，生产默认关闭。原独立scraper CA与9445网络范围保持，不向普通租户开放全节点指标。

每个opt-in node增加独立 `node-images-<uid>` job，抓取 `/metrics/node-images`：53样本、64KiB、12标签、15秒间隔，精确匹配profile/node/boot/epoch、RUNTIME_REPORTED和UNKNOWN，scalar不能借FS标签，FS必须有受控不透明ID。标签过滤在入WAL前完成；原VM白名单和3584/2MB限额、自采、原队列均保持。

设N为VM节点数、E为opt-in节点数、T=N+E+1：每副本raw上限 `3584N+53E`，加self64及每目标5条原生报告后，WAL每轮为 `3584N+53E+64+5T`；远写只保留原生up，样本规划为 `3584N+53E+64+T`。原六小时、每样本1KiB含churn、2倍checkpoint余量和70%磁盘门不放宽。正文保守规划每轮 `2MiB*(N+1)+64KiB*E`；远写每秒样本/字节模型按15秒一轮的平均准入量规划，不含重试、传输开销及故障后追赶突发，不是硬网络限额或实测压缩率。启用前重新核对capacity.json，预算不足应拒绝或经正常容量流程处理，不能自动扩容或侵占VM额度。

原报告时间以gauge值保留，实际Prometheus样本时间仍由Agent生成。固定查询必须先按success、up、原收集/FS时间及其样本年龄筛选各副本，再去除collector_replica/job/instance取有效值；不要相加。逻辑压缩量和snapshot-store报告不等于物理缓存容量/可回收量；近似f64不能替代JSON精确整数，完整性始终UNKNOWN。接口与字段见[节点诊断合同](../../docs/node-image-observation.md)。

节点镜像job使用独立失联告警；HTTP200但组件长期UNKNOWN或原观察时间超龄也会单独告警。规则仅为显式启用节点生成，绑定profile/boot/epoch和独立副本，整体collector失联时保留原抑制。规则仍需加载到真实后端并完成通知验收；Agent自身不执行规则。新的实际管线、原生containerd、规则回放分别有证据，不宣称三者已组成云端端到端链路。
