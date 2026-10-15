# RuntimeClass 配置守卫与 Pod 资源回读

状态：**第3步普通CPU实时回读子项已完成本地验收；恢复草稿兼容性尚未验收。** 本轮实现范围是受守卫的固定 `kata-qemu` 配置，以及 provision／gateway 路径对实际 Pod 的完整资源回读。第 4 步的持久观察、可信登记事务和对外 API 尚未实现；用户资源账本继续返回 `pod_resource_evidence=NOT_CAPTURED`，界面继续显示 UNKNOWN。本轮35组192项按分批实际执行、最终二进制摘要核对通过，不是单轮整仓或目标云认证。

## 官方行为与实现依据

Kubernetes v1.35.0 的 `ValidateRuntimeClassUpdate` 对 handler 执行不可变校验，没有对 overhead 或 scheduling 执行同样校验。因此不能仅因 `RuntimeClass` 已创建，就认为它的完整配置天然不可变；本项目需要额外的更新和删除守卫。[v1.35.0 RuntimeClass validation 源码](https://github.com/kubernetes/kubernetes/blob/v1.35.0/pkg/apis/node/validation/validation.go#L40-L47)

同一版本的 RuntimeClass admission 只处理 Pod CREATE。其 `prepareObjects` 优先读取 informer lister，缓存未找到时才进行 live GET；`setOverhead` 将 RuntimeClass 的 `PodFixed` 复制到实际 Pod 的 `spec.overhead`。该流程没有在 Pod 中保存采用的 RuntimeClass UID 或 resourceVersion。因此，控制面随后 GET 到的 RuntimeClass RV 不能作为 Pod 创建时采用该 RV 的证明。[v1.35.0 admission 源码](https://github.com/kubernetes/kubernetes/blob/v1.35.0/plugin/pkg/admission/runtimeclass/admission.go#L121-L167)

ValidatingAdmissionPolicy 的匹配范围、`failurePolicy` 与 Binding 的 `validationActions` 共同决定请求是否拒绝；安装了一个同名对象本身不证明策略正确生效。本项目必须同时核对实际 Policy 与实际 Binding 的完整受控配置，要求失败关闭并执行 Deny。[Kubernetes ValidatingAdmissionPolicy 文档](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)

## 本轮第 3 步实现合同

继续使用固定 RuntimeClass 名 `kata-qemu`。不通过更换名字放宽现有 manifest、handler、专用 Kata 节点或 nodeguard 门禁要求；也不将资源读取功能作为现有隔离或云 fencing 认证完成的依据。

部署交付真实的 `ValidatingAdmissionPolicy` 与 `ValidatingAdmissionPolicyBinding`，对该 Class 的受控配置更新和删除建立拒绝规则。运行组件在继续 provision 或 gateway 验证前，读取并核对实际守卫；缺对象、禁用、匹配条件变窄、表达式或 binding 漂移、读取失败均拒绝。期望守卫配置必须与部署产物使用同一受控来源，不能由调用者提交一个“已经启用”的布尔值替代。

实现使用[共享守卫合同](../deploy/runtime-class-guard/guard.json)、[安装与核验工具](../deploy/runtime-class-guard/guard.py)和[固定名称只读RBAC](../deploy/runtime-class-guard/read-rbac.json)。安装只允许创建缺失对象，并以实际回读确认；同名对象配置不符时拒绝，不自动apply覆盖。verify要求明确的kubeconfig、context和kube-system namespace UID，执行服务端dry-run：metadata更新为正例，overhead／scheduling更新和DELETE为反例，核对拒绝来自该守卫。工具不创建或删除实际Class，也不启动工作负载。生产Docker输入白名单须包含编译时include的guard.json，以及生产SQLite验收所依赖的共享fixture文件。

Policy／Binding 的管理权限属于可信 operator 边界。普通租户和运行组件不能修改这些守卫，也不能修改或删除受保护 Class。具备修改 admission policy、binding、RBAC 或直接管理控制面的 operator 可以改变信任根；前后回读能够发现持续漂移，不能证明这种高权限主体从未进行过瞬时替换。生产安装必须以真实 RBAC、最小权限和受控维护路径维持该边界。

一次 Class 配置观察保存实际 UID、resourceVersion、规范化受控内容的 SHA-256，以及解析后的 overhead。**当前配置身份是 UID 加规范化内容 SHA-256**：UID 标识对象替换，内容摘要标识 handler、scheduling 和 overhead 等受控配置变化。resourceVersion 保留为本次 GET 的不透明诊断元数据；metadata 更新导致的纯 RV 变化不等同于资源配置改变，不能把它转换成整数或声称 Pod 采用了该版本。

provision 路径在创建或采用前检查真实守卫与 Class；创建后必须对实际 Pod 执行 GET，不能仅接受 POST 返回值。gateway 路径同样从真实资源账本中的 Pod UID 出发进行 GET。两条路径都解析实际单容器的 request、limit 和 Pod 自身 `spec.overhead`，比较预期工作负载和当前受守卫 Class overhead，并检查 effective request／limit 的加法溢出。工作负载仅支持 CPU、memory、ephemeral-storage，overhead 仅支持 CPU、memory；额外设备、sidecar、init、Pod-level resources 或缺失必要字段仍拒绝。

代码落点为[`runtime_class_guard`](../src/runtime_class_guard.rs)的内部配置能力、[`runtime_resource_contract`](../src/runtime_resource_contract.rs)的完整资源解析、[`runtime`](../src/runtime.rs)的创建后与前后GET复核，以及[`gateway_runtime`](../src/gateway_runtime.rs)的只读接入。`PodResourceObservation`字段私有且不提供Deserialize；当前固定普通CPU基线要求request等于limit，因此相同workload／effective值同时表达这两个已经独立核对的资源合同。

Class、guard 与 Pod 在验证前后重新读取并复核。Pod 的 UID、完整受控 spec 和规范化资源需要保持一致，原有 namespace、标签、节点、卷和许可身份检查继续成立；纯 resourceVersion 或 status 变化不作为资源冲突。Pod 被删除、名字被其他 UID 复用、spec 或 overhead 漂移、Class UID 或受控内容变化、守卫变化均拒绝。前后读取是有界的一致性复核，不构成 Kubernetes 多对象原子快照，也不签发 adopted RuntimeClass RV 证明。

完整对象明确没有 overhead 时可解析为零 overhead；远端对象不可见、GET 失败或身份不完整保持缺证据并拒绝资源验证，不能用零值补齐。规范化结果是配置事实，不是物理机实测容量。CPU 使用 millicores，内存和 ephemeral-storage 使用 bytes；各维度使用独立类型，值保持非负且不超过 `9223372036854775807`。现有 Quantity 子集继续限制每个输入为至多 64 ASCII 字节，拒绝负数、指数、不支持的精度、舍入和饱和。

停止、清理和释放继续使用原先精确绑定的 UID、可信本地终止证明及清理回执。当前 Class 或 overhead 漂移不能阻止已存在启动的安全停止；本轮新增资源验证不进入 safety-stop 的目标识别条件。Pod 不可见、配置验证失败或一次重试均不构成 VM 已死亡或配额可释放的证明。

## 本轮交付边界

第 3 步产生的是验证路径内的完整资源回读，不是已经提交的历史观察。没有新增观察表，没有从当前 Class、Pod、Flavor 或读时钟回填历史，没有将 API 普通调用者变成观察登记方。现有 `GET /v1/instances/{id}/resource-accounting`、SDK 和 UI 的资源证据语义保持 `NOT_CAPTURED`／UNKNOWN。

本轮不改变申请合同 `REQUESTED_COMPUTE_QUOTA`、配额回执、历史缺证据和释放条件。request、limit、overhead、配额、宿主采样、宿主容量分别表示不同事实；不能据此计算利用率分母、专属容量、剩余资源或节省比例。GPU、预热、自动调档、Kata／CSI／目标云实机认证均不由本轮资源回读完成。

## 下一步第 4 步：原子可信登记与持久读取

新增不可变观察表，绑定 tenant、project、instance、workspace、generation、launch、cluster epoch、Pod UID、Node UID、boot ID 与原登记许可。观察来源应明确为可信登记路径的 `KUBERNETES_API_READBACK`；nodeguard 认证 launch 身份和许可，不声称它测量了 Kubernetes 资源值。Class UID、回读 RV、配置摘要及配置 overhead 单独保存；Pod 自身的 request、limit、overhead、effective request／limit来自精确 Pod UID 的实际回读，不能以 Class 配置替代。

可信观察类型由 runtime 验证内部构造，禁止反序列化外部 JSON 或开放公共布尔构造器。`record_launch_authorization` 在原锁顺序和许可事务中核对该能力与已认证注册响应的精确 launch／node／boot 归属，随后共同提交授权回执和观察。沿用 workspace→instance→operation／node fence 顺序，重新检查当前授权、epoch、许可期限及认证覆盖；不能在外部观察之后跳过事务内 fence。任何一项失败应整体回滚。

同一 launch／Pod UID 的规范化资源内容相同应幂等复用原观察；内容冲突拒绝，不能覆盖旧行。纯 RV／status 改变不重写历史，也不应把相同资源伪装成冲突。真实 COMMIT ACK 丢失时复用原登记键和已提交观察；续期不得根据当前对象改写早期资源事实。

新迁移保持既有 0045 字节不变，另建冻结的升级前登记基线：记录切换前已经持久提交的 base／extension 授权回执及其精确归属，普通 runtime 不能增删改。旧回执可以明确缺观察；新提交的授权回执必须与新观察或合法复用的已有观察同事务成立。不能以“没有观察”、当前实例时间、某个 GUC 或今天仍存在的 permit 作为旧历史例外，也不能把尚未提交登记的旧 permit 自动豁免。维护升级门要排空旧 writer并验证新 guard，不能提前承诺旧 binary 混跑。

新增表使用复合外键、FORCE RLS、有界数量和 append-only保护；API按当前项目只读，其他运行角色只通过既有可信登记入口写入，不新增直接 INSERT／UPDATE／DELETE权限。启动和独立 preflight 同时核对 schema、迁移 checksum、函数、trigger、RLS及列权限。普通 API或 SDK不能提交“观察”来影响许可和释放。

对外读取在原 `instances:read` 前后新事务及返回前身份／token检查内完成。最小状态合同为 `NOT_CAPTURED` 加 nullable观察，以及来源明确的已验证观察；UI将缺证据显示 UNKNOWN且不展示资源零值。若另外引入 `UNKNOWN`，必须明确其持久来源和原因，禁止将服务错误、撤权或缺历史当作成功的零值。新数量、版本和代次为最多 19 位十进制字符串，≤i64_MAX；内存／ephemeral bytes 与申请合同 memory_mib、quota MIB分开标注。RV是有界不透明字符串，模型采用固定资源键，不暴露无限原始 Pod JSON或metadata。

观察与 receipts 必须绑定同一分页视图。签名游标固定所选观察 ID，或固定第一页时“尚无观察”的事实，继续绑定主体、tenant、project、instance、launch、筛选方式、epoch和limit。仅按 `recorded_at <= cutoff` 过滤不足以固定缺失状态：cutoff前插入但第一页之后才COMMIT的观察，否则会在后续页突然出现。新观察只在重新第一页时纳入，游标不读取“最新观察”。快照引用不绕过每页实时授权；撤权、主体禁用、epoch／launch变化继续拒绝并清除旧视图。

完成第 4 步需要正常迁移和普通角色的真实TLS PostgreSQL、实际JWT／HTTP、独立Node SDK及浏览器验收。必须覆盖事务回滚、真实COMMIT ACK丢失重放、并发换代、撤权、冻结旧基线、RLS／禁写、分页观察ID与缺失固定、超过JS安全整数的精度，以及读取失败清旧证据。HTTP 200或UI出现数字不能独立证明本步骤完成。

## 本轮验收记录（2026-10-15）

实际结果见下表及私有目录 .local/runtime-readback-20261015/。35组192项为分批验收，逐组测试程序与最终候选摘要一致；早期失败与未通过的恢复草稿保留。Mock或本地API测试不替代目标云Kata实机认证。

本地真实API验收工具为[`test-runtime-class-guard.py`](../scripts/test-runtime-class-guard.py)，复用checksum固定的Kubernetes v1.36.4 ARM64控制面，使用自有Docker容器、独立kubeconfig、真实admission dry-run及生产TLS客户端示例；以finally核对自有容器清理。其结果须明确记录为1.36.4本地行为，不能替代上述v1.35源码依据或目标生产版本验收。反例已核对明确NOT_FOUND/CONFIGURATION类别，Binding恢复后正例再次通过；没有将TLS/transport失败当成语义拒绝。

| 门 | 必须覆盖 | 本轮真实结果 |
| --- | --- | --- |
| 守卫部署与RBAC | 实际Policy／Binding与期望配置一致；目标Class更新／删除拒绝；非目标Class不被误拦；缺对象、失效或篡改失败关闭；普通运行身份无法改guard | PASS：自有Kubernetes1.36.4实际CEL/DELETE/非目标Class/overhead dry-run、生产TLS回读；24项RBAC允许/拒绝检查，容器清理确认。 |
| Class身份 | 固定name／handler；完整受控配置摘要；UID替换或内容漂移拒绝；纯RV变化保留相同配置身份 | PASS：原生guard身份/漂移/RV合同与真实TLS回读；当前Class观察不作为adopted RV。 |
| Pod真实回读 | 已有与新建Pod均GET；实际UID／受控spec／resources前后相符；POST响应不能替代GET；status／纯RV变化可接受 | PASS：runtime_manifest21项与gateway_runtime3项，含创建后UID替换、前后资源/配置冲突、RV/status变化和首次调度。 |
| 数量与边界 | 三种Flavor；合法Quantity别名和overhead；缺字段、负数、精度、超长、额外设备、sidecar、加法溢出拒绝 | PASS：三Flavor、受控Quantity、溢出和未知资源正负例，纳入459项原生通过；未开放GPU资源键。 |
| provision／gateway闭合 | 两条路径都使用完整资源验证；Class／guard／Pod中途变化拒绝；原节点、卷、网络与许可校验保留 | PASS：普通worker4项、continuation6项、dispatch3项和gateway6项真实PG；原配额/权限/UID合同保持。 |
| 停止回归 | overhead或当前Class漂移时仍按原UID安全停止；没有削弱本地终止与cleanup证据 | PASS：原生安全停止用例与真实PG termination16/never-authorized10/volume10项；停止不依赖新guard读取。 |
| worker／restore兼容 | 共享mock与restore路径支持真实守卫和前后GET；没有fixture特权绕过生产检查 | PARTIAL：worker实际通过；恢复草稿在公开backups:restore授权前置门被拒，未进入restored START/Class路径，不计通过。三个父流程文件与93954fd相同，未开放权限或绕过授权；共享fixture已编译。 |
| 格式及适当回归 | 本轮源码对应的fmt／lint／定向测试，实际磁盘检查与任务缓存清理记录 | PASS：62个最终原生程序对应459通过/269环境ignored；其中变更的两个零普通测试target另验；严格all-target Clippy与fmt通过。df约315GiB，复用review-low-debug约6.5GiB缓存，无大目录复制。实际Docker COPY523文件/7,867,697bytes，无额外或私有/生成输入，清理确认。 |
| 对外证据边界 | ledger仍NOT_CAPTURED；无当前值回填、利用率／节省比例／GPU声称 | PASS：资源账本9项、签名HTTP/实际Node SDK3项；API/SDK/UI继续NOT_CAPTURED，未回填历史或显示利用率/GPU。 |

本轮完成普通CPU的守卫与实时回读子项；恢复草稿兼容项明确未验。第4步持久观察与原子可信登记仍待开发，不能将本轮布尔验证当作历史观察。

## 失败记录与修复范围

93954fd 的 GitHub CI run38712207834 在准入集成测试失败：手工 RESTART 换代没有申请四个 scope 的 CPU/内存配额。测试改用生产 reserve_quota 并核对新合同绑定，实际4项通过；没有放宽0045约束，44条既有迁移逐字保持。

新增未优化 Kubernetes future 嵌套曾使 worker 用例默认线程栈溢出。修复将实际 I/O 状态放入深模块堆状态，没有调大线程栈或期限。ensure_pod 调用者 future 从17,976降至48bytes，verify_runtime_class 从3,752降至128bytes；这只是调用者状态大小，不是VM内存节省率。原崩溃用例、最终worker4项及future大小断言通过。

新增创建后GET使旧Pod GET故障barrier过早暂停。测试改为另一真实连接确认同tenant/op/generation/Pod UID、实例绑定及checkpoint事件/lease已提交才暂停，不按GET次数或sleep跳过。原6项、实际COMMIT ACK丢失重放和25秒总预算/10秒heartbeat等断言保持通过。另修新反例fixture缺席字段的插入方式，未削弱资源验证。

真实Kubernetes最初拒绝了错误的运维探针：scheduling反例先命中baseline消息；kubectl DELETE不支持-o json，尚未到服务器。已分别改为保留合法pool但修改其他配置、移除无效输出参数，核对具体守卫消息及生产客户端失败类别；最终v4通过，前三轮FAIL及自有清理记录保留。

实际Docker COPY发现父目录negation带入约166MB生成依赖，没有发现用户秘密。按父级放行后重置子级、最后排除生成/私有目录修复，实际523个预期输入逐项SHA通过。开发管理员角色与历史升级用例原本要求query-free本地URL；验收fixture按其原连接合同提供独立管理员，正常迁移CLI仍使用显式verify-full，未改测试或生产TLS检查。

私有记录目录包含各次FAIL、分批PASS、实际二进制摘要及清理结果；本轮结论是35组192项适用范围分批通过，不称为一次全仓绿灯。恢复草稿的Unsupported project action另记未验，不能被上述通过覆盖。

## 两轴审查

### Standards

对照93954fd公开基线，独立只读审查实际diff及新增文件，未发现需要修改的生产规范或结构问题。堆分配边界、持久checkpoint测试barrier、RBAC与Docker上下文均纳入，0项未关闭发现。

### Spec

对照本文件及逐次启动方案第3步，未发现范围内缺失、错误实现或未经要求的行为。第4步保持明确待开发；恢复草稿前置门的未验状态保留，代码审查不替代实际验收。0项未关闭发现。
