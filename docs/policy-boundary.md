# 平台组件网络策略的上线前检查

Cilium 的策略允许规则会合并。单独安装窄 CNP 不能撤销另一个选中同一 Pod 的宽允许；命名空间 CNP 只选中自身命名空间，CCNP 则跨命名空间。标签来源和 service account、namespace labels 也参与选择。实现依据固定的 [Cilium 1.20.2 策略说明](https://docs.cilium.io/en/stable/security/policy/kubernetes/)及[标签来源规则](https://docs.cilium.io/en/stable/gettingstarted/terminology/)。

API、控制台和自动化组件使用 `sandbox.platform/network-policy` 标签。集群 bootstrap CCNP 排除任何带此标签的 endpoint，各组件提供自己的双向默认拒绝和明确允许。新增组件必须同时交付这两项，不能只增加标签或单独叠加 CNP。

`deploy/policy_boundary.py` 是安装器可调用的只读检查。输入应来自已经独立验签、审阅的组件 JSON manifest；文件名或任意输入 manifest 不构成信任。操作者提供明确 Kubernetes context、HTTPS CA 及直接、受限的只读凭据。kubeconfig 必须为当前用户或 root 所有的普通私有文件，权限0400/0600，至多1MiB；只接受内嵌 CA，以及内嵌 token 或匹配的 client certificate/key。拒绝路径凭据、exec/auth-provider、代理、身份模拟、TLS 验证关闭和主机名覆盖。检查先从固定文件描述符读取、严格解析并写入0700临时目录中的0600固定副本，之后所有 kubectl 只读该副本；原配置被替换不会改变这次观察输入。检查不会打印 kubeconfig、认证错误正文、token 或原始 API 响应，不执行 apply。

```sh
.local/cluster-venv/bin/python deploy/policy_boundary.py \
  --manifest /absolute/path/verified-api.json \
  --kubeconfig /absolute/path/scoped-read-only.kubeconfig \
  --context production-sandbox \
  --out /absolute/path/new-policy-boundary-report.json
```

检查实际 Ready Pod、service account、namespace labels、Cilium 配置和 CNP/CCNP/Kubernetes NetworkPolicy。策略选择使用实际 `CiliumEndpoint.status.identity.labels`，不会从 Pod 标签推导：Cilium 的 identity label filter 可能排除某个 Pod 标签。CEP 必须通过 ownerReference 绑定当前 Pod UID、处于 ready 并报告双向 enforcing；实际 namespace、service account、cluster 与专用边界标签须一致。旧 UID、缺失边界标签、reserved/未知身份来源都拒绝。字段依据固定的 [Cilium 1.20.2 CEP schema](https://github.com/cilium/cilium/blob/v1.20.2/pkg/k8s/apis/cilium.io/client/crds/v2/ciliumendpoints.yaml)。这些状态仍然不是数据包拒绝证明。

只允许与受审阅 spec 完全相同的组件 CNP；额外选中组件的 Cilium 策略、会增加允许的 Kubernetes 策略、已发现但未审阅的其他 network-policy API、缺失权限、分页截断、读取变化、未知选择器都会使检查失败。纯 Kubernetes default-deny 可共存。全局 host policy 单独作用于节点，仍需对应宿主认证。两次完整输入向量——discovery、额外策略库存、namespace、Pod、CEP、Cilium 配置和三类策略——须一致；它不是原子快照。List集合resourceVersion只是读取观察点，单独变化不作为策略漂移；实体完整UID/resourceVersion/spec/status保留比较，证据同时记录两轮集合版本。这符合[Kubernetes集合与实体版本合同](https://kubernetes.io/docs/reference/using-api/api-concepts/#semantics-for-get-and-list)。整体观察期限45秒，单命令至多8秒/8MiB；discovery至多256个资源，其他策略 API 至多16个，每个库存至多512项。证据记录当前 Pod/CEP UID、identity ID/标签摘要、策略 UID/resourceVersion、spec SHA256 与观察时间，不记录原始身份标签或凭据。

结果明确区分 `configuration_overlap: PASS` 和 `runtime_enforcement: NOT_VERIFIED`。它只是配置重叠检查，不证明 Cilium 已把策略下发到内核，也不保证后续没有配置变化。正式激活仍必须有独立第一包、元数据地址、跨租户、绕路及重启/更新时的数据平面拒绝证据，并持续检测策略漂移。24项本地配置/子进程/整体观察故障测试已通过；安装组合器及真实集群执行目前未验收，没有目标 Kubernetes context，因此没有 live PASS 记录。
