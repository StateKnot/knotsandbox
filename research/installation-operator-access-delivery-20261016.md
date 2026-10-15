# 安装级节点镜像读授权 P0c1：交付记录

本批完成独立安装授权基础，**完整P0c尚未完成**：固定节点查询、admin读消费者、当前node/boot/profile新鲜度及原生containerd→Rust mTLS→Prometheus→operator同一整链仍待P0c2。没有开放pre-pull、物理缓存容量、可回收量、GPU利用率或加速收益。

先核对发布基线`dcb75546f08705eb9c41a87cd44274687200b9f0`的[CI run38774056967](https://github.com/StateKnot/knotsandbox/actions/runs/38774056967)：5 job／62 step全部成功。本轮新源码上传后按其精确commit核对，不沿用基线结果；上传回执与新CI状态独立保存，不为改验收文档循环触发CI。

## 实现与管理合同

- 正式新增0047，原45条迁移逐字保留；当前正式46条`1..37 + 39..47`，没有0038。持久安装UUID在升级／重放后保持，不预授予任何身份。
- 新`operator_access`模块封装SERVICE精确issuer／subject／client／identity行ID／binding generation／principal version、安装与当前epoch、有限24小时授权及永久撤权；管理和审计同事务，不修改tenant授权。
- `sandbox-admin node-image-reader`通过独立owner连接显式创建／撤销，严格16KiB JSON和UTF8字段上限；相同ID重试不延长期限，撤销ID不能恢复；普通API登录没有管理函数或两张私表权限。
- 新`GET /v1/operator/access`使用现有独立Keycloak／外部OIDC配置，不需tenant头，不接受scope选择器或任意查询参数。只返回当前installation／epoch／原grant ID／固定`node_images:read`／实际持久期限，不返回节点数据。
- tenant `instances:read`／`*`不能获得安装权；ACTION_SCOPES另需精确OAuth scope。授权成功是数据库语句快照上的no-store观察，不是可缓存或转交的能力令牌；未来节点I/O前后必须重核并比较原grant ID。
- 身份／主体禁用与绑定变化、client轮换、installation／epoch变化在同事务永久撤旧授权，A→B→A不复活。锁等待结束后用数据库clock重新核对授权期限；JWT期限独立检查。
- 通用`verify_runtime_role`纳入表结构、约束／索引、owner／函数正文与完整参数返回形状、PUBLIC及runtime ACL、6个触发器、单例scope表写权限检查。API监听和现有维护预检共同覆盖；不自动修权限或重写账本。

完整使用合同见[安装级授权操作文档](../docs/installation-operator-access.md)。OpenAPI和生成的TypeScript类型同步，普通VM／节点镜像采集器及既有预算未变。

## 最终本地验收

以下为同一最终功能源码的独立验收，不把不同轮次相加冒充一次全量测试：

| 入口 | 实际结果与边界 |
| --- | --- |
| 普通macOS Rust | 63程序，475通过／0失败／285环境专项显式ignored；含3个新增解析用例。6个授权专项另以真实依赖执行，不把ignored记通过 |
| 安装授权专项 | 真实Keycloak／签名JWT、隔离Docker PostgreSQL17 TLS、正常SQLx迁移、普通app身份、真实管理CLI和生产Router上的loopback TCP HTTP：6通过／0失败／0ignored |
| 具体授权行为 | 无tenant头；tenant通配拒绝；管理／私表拒绝；精确scope；过期JWT与有限期限；同ID重试／差异冲突；永久撤权与新ID；身份／client／epoch／installation ABA；缺EXEC／私表及scope列写权限漂移拒绝／恢复 |
| 锁等待反例 | `pg_stat_activity`及`pg_blocking_pids`确认实际被目标principal行锁阻塞且当时未过期，再确认数据库时钟跨过期后释放；真实返回P4000、HTTP403，不能将55P03锁超时当通过。保持原3秒DB锁超时 |
| 既有PG回归 | 6组29项通过：空库正常安装、资源账本9、账本HTTP3、可信Pod观察8、服务身份7、v41历史升级1（空库1）；每组独立数据库、正常46条SHA384账本与原历史事实比较，source／binary／SDK不变，自有清理确认 |
| 正式自动化 | 原正式验收18、通知5、通知HTTP1、进程1，共25通过；原权限／生命周期／时限门、精确正式46条账本、实际进程和自有容器退出分别核对 |
| 静态与客户端 | all-target strict Clippy、fmt检查通过；OpenAPI13通过；生成TypeScript类型及SDK77通过。未引入依赖；未为验收放宽既有权限／期限／线程栈 |

本批新授权请求测试为真实loopback HTTP＋生产Router，**不是sandboxd生产TLS整进程部署认证**。PG传输确实verify-full，Keycloak确实本机真实服务；ACTION_SCOPES另用仓库公开测试RSA／JWKS验证签名反例。云／Kata／CSI／GPU和性能／成本仍需各自实机认证。本批没有重跑未改的原生containerd采集器；其基线精确CI已通过，不以分段证据声称完整原生operator链。

## 原失败与独立审查

私有证据目录`.local/operator-access-20261016/`保留全部原现场：旧公开基线的新路由404→预期403真实RED；旧预检误授`UPDATE(installation_id)`仍接受的真实RED；修复后的6项GREEN；首次验证副本缺3个必要编译输入、catalog重放缺SQLx空账本以及SDK工具沙箱EPERM分别记录为准备／环境失败，未当产品RED或假称通过。catalog仅生成结构合同，最终正常SQLx与真实角色仍另验。

双轴独立审查发现并修复：Spec的单例列写权漏检P2、Standards的故障清理kind=USER会阻止身份退休P2。最终两轴未关闭0项，Fowler判断性smell0；测试作者未自审自己的代码，5个升级联动文件另由独立审查者复核。
最终20文件功能补丁SHA-256：`f0170f685af8dea3d9e1a1d1caac4f00c68190f46c11b02ae60172f1a1e0b3c4`。交付文档另行审查，不改变已验功能源码。

## 资源与后续

复用`target/review-low-debug`约6.5GiB，供同仓库同工具链后续普通验收；既有Linux观察缓存`target/image-observation-linux-arm64-low-debug`约1.8GiB继续保留。源码验证副本未复制target／node_modules／venv。日志均在编译缓存外，所有本批Docker临时资源按精确所有权清理，不清用户数据库／卷或共享镜像缓存。编译前后可用盘约307GiB，未声称释放缓存空间。

下一依赖是P0c2：固定有界节点查询、当前epoch／node UID／boot／profile及样本原时间新鲜度，外部I/O前后重新授权、撤权／换代清旧，正常API与admin只读消费者，以及同一原生整链。P1—P6的物理硬预算与预准备仍保持未开放。
