# 生命周期队列调度与控制面调用观测交付（2026-10-13）

本批按[开发表第12节](rust-sandbox-development-workbreakdown.md)推进G2-04/G2-05与G0-07/G0-08/G3-03。采用mattpocock codebase-design的小Interface/深Module方法：一个私有监听模块和固定阶段观测接口，复用现有持久操作、角色、租约及Kubernetes adapter，没有引入另一套消息队列、VMM或GPU运行时。

## 已开发行为

- 0044新增事务空hint，只作用于WORKER已到期dispatch；不发送租户、operation、token或请求。领取仍由原SQL的路由/期限/租约守卫决定。
- 启动、LISTEN提交及重订阅后扫描；容量释放后继续填槽，每个select最多领取一个。固定500ms恢复扫描不随完成事件重置，丢提示及未来资格仍可恢复。
- 空队列至少50ms间隔、暂时claim错误2秒退避；提示不能重置或绕过这些界限。监听计入原连接上限，max1明确poll-only；关闭保留外层实际连接池排空。
- 记录领取往返、调谐、RuntimeClass、namespace、策略、PVC、Pod及可信Ready提交八种内部调用耗时。OK/ERROR/CANCELLED_UNKNOWN分列，保留原Result，不打印provider详情或返回值，也不把私有operation关联转成指标label。
- 修复CI验收脚本硬编码58073：只读取固定本地开发Keycloak容器的唯一实际回环发布端口，拒绝非回环、歧义及无效映射；新增mandatory契约测试。

部署、连接预算、通知队列及观测定义见[生产调度合同](../docs/worker-dispatch.md)。所有既有迁移字节保留；正常migrate追加0044，账本为43条1..37+39..44。生产38仍永久未发布。

## 验证与独立证据

| 验收 | 实际结果 | 私有记录 |
| --- | --- | --- |
| 新dispatcher实PG | 3/3：commit/rollback、空/伪hint、due/lease及重复领取、启动积压、有界容量、缺hint/future恢复、物理断线重订阅、max1及旧token拒绝 | `.local/startup-dispatch-20261013/pg-v4/worker_dispatch.log` |
| 原worker恢复与权限 | 4/4：Pod创建崩溃后同UID恢复、可信launch、当前授权及原锁竞争timer | `pg-v4/worker_recovery.log` |
| 实际sandboxd进程 | 1/1：claim/timer ACL漂移非零退出、暂时timer锁竞争恢复、自然截止与物理后端缺席 | `pg-v4/worker_process.log` |
| 非空历史升级 | 1/1：41→42→当前44的账务/保护/回执/ACK与双状态历史完整；旧schema/policy/function/trigger仍精确比较，0044新增元数据另校验固定owner/search_path/trigger类型/无PUBLIC及runtime execute | `pg-v4/automation_upgrade.log` |
| 观测普通单元 | 4/4：成功值/错误保留、脱敏、已开始取消未知、未poll无伪样本 | `observation-final.log` |
| 端口契约 | 3/3；先保存原硬编码红例再窄修；无任选issuer/fallback | `console-contract.log`、`ci-fix/port-fix-final.json` |
| 原生Rust工程检查 | strict all-target Clippy与fmt通过；无unwrap/expect放宽 | `clippy-upgrade-final.log`、`fmt-final.log` |
| 当前源码真实浏览器 | 两轮独立各1/1（31.06s、26.53s），真实Chrome/Keycloak/cookie BFF/API/TLS PG；原权限/失ACK/幂等重放、定时/通知及九检查点保留 | `browser-diagnostic/record.json`、`browser-diagnostic-v2/record.json` |

实PG统一记录`pg-v4/record.json`的9项、43条逐SHA384迁移、source/artifacts/SDK前后不变以及自有进程/容器清理均通过。两轮浏览器来源与产物/console bundle不变、业务事实一致、进程/fixture清理均通过；同一源点SHA256 `c273d472d717abb80c01d94fef849e7a964ca3608074e200f5823217adae7556`。之后交付说明与工作表补充不视为已运行的可执行源码变化。

容量探针在本批v4记录中先后到达250631µs和270538µs，相隔19.907ms；它证明本机两项已领取任务没有固定逐项500ms等待，不是VM启动时间或生产吞吐/SLO。探针没有运行真实Kubernetes、Kata或guest。

## 失败保留与修正边界

`pg-v1`首次测试错用通用API的空策略文档，runtime probe未到达；改为原worker同样的APPROVED deny-all测试策略，生产校验不变。`pg-v2`已通过2项，但重订阅检查只识别不带分号的首次LISTEN；SQLx0.8.6实际重连使用带分号形式，改为同channel这两种精确语句，v3新队列与原恢复/进程全部通过。v3历史snapshot随后发现新增helper/trigger；只把新增元数据单列严格检查，原完整业务事实、旧元数据、账本与权限断言保留，v4全矩阵通过。全部失败记录未回填。

当前统一源码首次浏览器登记响应出现`RESPONSE_BODY_UNAVAILABLE`，原source/bundle与两轮后续测试相同。新增固定POST阶段/201/finished结果诊断，并保留原body精确断言；Playwright内部本来就等待finished，因此显式finished不能被称为根因修复。后续两轮没有复现，仍须通过完整CI；没有增加自动重试、放宽期限或跳过读取/撤权断言。详见`ci-fix/browser-body-diagnostic-final.json`。早期缺显式Docker socket的本机启动拒绝发生在资源创建前，之后使用核对过的本机Unix socket，未修改门禁。

## 后续开发与发布边界

本批不把内部调用耗时当成exact queue、PVC provisioning、VMM boot或首次正确执行。原1/5秒等待、64个claim候选窗口及实际网络故障退出SLO仍按合同记录，已提交安全阶段连续推进与任意锁积压公平调度待开发。NOTIFY队列满可能导致COMMIT失败，必须监控队列使用、长事务、积压和幂等恢复，不能伪造成功。

下一批推进已提交安全阶段的有界连续调谐、完整启动证据和批准artifact/节点预准备预算；CPU暖池、自动资源回收、新认证fast runtime和GPU独占/MIG/可信GPU服务继续按独立工作包落地。模板cache与GPU仍未启用。目标Kata/Cilium/CSI/云/HA/72h和成本验收、更新真实安全证据及统一签名发布尚未完成，当前不是生产环境上线验收证书。生产镜像安全门不因本批本机验证放宽，见[发布安全状态](../docs/release-security-status.md)。
