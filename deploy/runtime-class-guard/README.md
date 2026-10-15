# Ordinary RuntimeClass guard

普通 `kata-qemu` 的 provision、gateway 和 launch 登记前回读现在要求这一固定守卫。Kubernetes 原生只将 RuntimeClass 的 handler 设为不可变；overhead 和 scheduling 仍可修改。本组件使用真实 ValidatingAdmissionPolicy/Binding 阻止同名配置修改及删除，并由 Rust 客户端逐次核对完整 spec、UID 和类型检查状态。

集群管理员、API server 和安装配置是信任边界。产品账号只有固定名字的 GET，不能管理这些策略。读取策略不是某次历史 Pod 准入或所有 API server 缓存同步的证明；旧历史继续缺证据。Pod 自身 overhead 必须与当前受保护配置一致，配置、身份冲突或读取失败拒绝本轮操作。停止和可信清理不依赖当前策略。

## 安装与验证

在新服务启动之前，由可信运维使用**明确 kubeconfig、context 和事先核对的 kube-system namespace UID**执行。先在现有维护流程停止新建/登记写入；保留旧实例的可信停止、清理路径。不要混跑绕过新守卫检查的旧 writer。

```sh
python3 deploy/runtime-class-guard/guard.py install \
  --kubeconfig /secure/operator.kubeconfig --context production \
  --cluster-uid REPLACE_WITH_REVIEWED_KUBE_SYSTEM_UID
kubectl --kubeconfig /secure/operator.kubeconfig --context production \
  create -f deploy/runtime-class-guard/read-rbac.json
python3 deploy/runtime-class-guard/guard.py verify \
  --kubeconfig /secure/operator.kubeconfig --context production \
  --cluster-uid REPLACE_WITH_REVIEWED_KUBE_SYSTEM_UID
```

`install` 仅 create，遇到已有对象则逐字段核对；不 apply/replace、不覆盖冲突、不自动撤销保护。丢失创建 ACK 后实际回读确认。类型检查必须完成、代数一致且没有警告。`read-rbac.json` 为 sandbox-system 内 worker/gateway/termination 授固定名字 GET；已有安装应核对同名 RBAC 后纳入自己的受控发布流程。termination renderer 和 gateway/termination 静态 RBAC 也包含同样权限。

守卫安装不创建 RuntimeClass。若集群尚未有普通 Class，`verify` 会拒绝，保持入口关闭；待 Kata、节点认证、网络、fencing 与可信终止链满足原发布条件后，由可信安装方创建原固定 `kata-qemu` 配置，再运行 verify。不能为了演示启动自动移除节点隔离或创建未经认证的生产 RuntimeClass。

`verify` 要求目标 Class 存在，执行服务器 dry-run：元数据修改正例成功，overhead/scheduling 修改和 DELETE 必须被**此守卫的具体拒绝消息**阻断；随后核对对象 UID/配置未变。全部探针不修改 Class、不创建 Pod、不启动 VM。普通产品 GET 账号没有运行这些运维探针的变更权限。

更新 overhead/scheduling 是维护变更：先停止新 launch、完成既有可信终止/释放和发行检查，再由可信运维审核下一套配置及守卫迁移。工具不会提供删策略、改 Class、恢复策略的一键绕过。安全停止仍可执行，不能依赖修改今天的 Class 修复历史证据。

## 本地真实验收

```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo build --locked --example runtime_class_guard_check
DOCKER_HOST=unix:///REPLACE_WITH_LOCAL_DOCKER_SOCKET \
  python3 scripts/test-runtime-class-guard.py \
  --k3s-arm64 /verified/k3s-arm64 \
  --readback-binary target/debug/examples/runtime_class_guard_check \
  --evidence-dir /private/new-runtime-class-evidence
```

脚本只创建、使用和清理带本次唯一身份的 Docker 控制面，沿用已锁定官方 K3s 1.36.4/Alpine 摘要。覆盖实际 CEL 拒绝、服务器 Pod dry-run 注入 overhead、生产 Rust TLS 客户端回读，以及缺 Class、缺 Binding、Audit-only Binding 拒绝；记录源文件与二进制摘要、结果及实际清理。kubeconfig/控制面日志仅在私有验收目录。没有 guest/Kata/云环境/GPU性能或隔离认证。

公开资源账本仍返回 `NOT_CAPTURED`，直到下一步可信登记事务将 Pod/RuntimeClass 观察及节点/boot/permit 身份原子归档并接通只读 API。这里的检查结果不能作为利用率、专属容量或资源释放许可。
