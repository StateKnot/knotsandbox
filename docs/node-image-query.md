# 安装级节点镜像只读查询

这是安装操作员接口。其他微服务可以用已登记的 SERVICE OAuth 身份调用，也可以使用独立身份服务；身份来源不代替产品授权。先按[安装授权](installation-operator-access.md)由 owner 为精确 issuer／subject／client 颁发有限期 `node_images:read`，ACTION_SCOPES 模式同时要求令牌携带该 scope。租户、项目及 `instances:read` 不授予节点级数据。

```
GET /v1/operator/nodes/{runtime_node_id}/image-status
Authorization: Bearer <current-service-access-token>
```

`runtime_node_id` 来自已批准的安装登记，不是 Node UID。没有节点枚举、tenant 选择、安装选择、时间范围或自定义 PromQL 参数。节点须属于当前安装 epoch、处于 enabled 且有未过期的 owner 认证；不要求节点上存在 VM。仅观察 opt-in 的节点会有采集数据，授权本身不打开采集。没有数据时返回 UNKNOWN／null，不能据此推导节点没有缓存。

读取先通过普通 app 的窄数据库入口取得安装、原 grant ID 和当前 node／boot／profile，执行一次固定监控查询，再重新取得当前绑定。撤权、JWT／grant 到期、节点失效或授权替换会拒绝该次结果；外部查询失败也必须完成第二次授权检查。认证续期只在同一不可变节点身份仍有效时允许，不延长 OAuth 或 grant 期限。

## 管理命令

`sandbox-admin node-image-status` 使用相同 HTTP API，不读取 owner 数据库。把当前 OAuth access token 写入私有 0400／0600 常规文件；不附换行，不把 token 放到命令行。凭据文件支持投射 Secret 的符号链接轮换，每次调用重新打开当前 inode。

```sh
sandbox-admin node-image-status \
  --endpoint https://sandbox-api.example.com \
  --runtime-node-id 00000000-0000-4000-8000-000000000001 \
  --token-file /run/secrets/operator-access-token \
  --ca-file /run/config/sandbox-api-ca.pem
```

endpoint 可包含 API 前缀，默认 HTTPS；显式 `--allow-loopback-http` 仅允许字面 loopback IP 的本地开发。禁环境代理、重试与跳转；响应至多256 KiB，连接3秒、总请求10秒。失败不输出 token、服务响应正文或旧成功报告。节点绑定必须匹配请求。现有 `node-image-reader` 子命令仍只负责显式 owner 授权／撤权。

## 观测含义与边界

外层返回 installation／epoch／原 grant ID／登记 ID／Node UID／boot ID／profile SHA。`metrics` 的 source 固定 `RUNTIME_REPORTED`、completeness 固定 `UNKNOWN`、accuracy 固定 `APPROXIMATE_F64`。Prometheus 的 f64 近似数不能作为19位精确账务或配额数量。

inventory 与 filesystem 分别按一个健康副本的最新完整 scrape cohort 解释，不相加，也不逐字段挑最大值。更新的 RPC 失败标志会清除另一个副本的旧成功值；更新的成功但原始时间陈旧／字段残缺时保持未知，不能回退旧成功。另一副本 transport `up=0` 不阻止健康副本的当前观察。两个组件独立采集，不能解释成同一原子快照。

所有原始 scrape timestamp、collector observed time 和可见 filesystem reported time必须严格新于当前60秒窗口；原始报告最多容许未来5秒。新 scrape 不刷新旧 runtime 报告。成功 flag 只描述对应 scrape 中的 RPC 状态：可为 true 而报告仍为 null。文件系统 used bytes／inodes 可以分别缺失；`filesystems: []` 仍不证明总集合为空或完整。失败、缺测和陈旧数据不填零。

后端固定 instant POST，受信任 endpoint／deployment／replica 来自服务配置；最多两个预设副本、16个可见 filesystem、216结果行和256 KiB正文，设置217行截断哨兵。未知标签、重复JSON键／序列、截断warning、非有限／负数或超预算整份拒绝。独立两个节点读取槽不占原VM的八个槽；原VM范围查询合同保持。

未配置／不可达后端返回503，非法响应502，无授权403，无效token401，未知／禁用／认证失效节点404，查询期间有效授权替换409。客户端每次从当前授权重新读取，清除旧显示；`/v1/operator/access` 的成功不是可缓存权限。

## 安装与验收

0048仅增加窄的只读绑定函数；没有新库存副本或运行时写权限。普通 owner 正常迁移后应用 roles.sql，按既有维护升级流程停旧进程、迁移／预检、再启动，不能假定 N−1／N 混跑。startup／维护预检核对函数正文／参数／owner／search_path／ACL、既有节点登记结构／不可变trigger和列级写权限。普通 app 仅获该函数 EXECUTE。

本地真实 PostgreSQL／OIDC／HTTPS、真实 Prometheus evaluator 与目标宿主认证分开记录。同一原生 CRI→mTLS→双Agent remote-write→operator 的完整整链、目标云／Kata／CSI／GPU和性能成本仍须独立验收。本查询不提供物理缓存容量、可释放量、命中率、加速收益或任何自动 pre-pull／删除操作。
