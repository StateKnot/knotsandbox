# 沙箱参考项目核查笔记

核查日期：2026-10-03。本笔记基于官方网页全文及发布说明，不包含部署、性能、安全或恢复实测。

## CubeSandbox

- 官方仓库为 TencentCloud/CubeSandbox，根许可证 Apache-2.0。稳定基准锁定 v0.7.2（2026-09-24）。[版本](https://github.com/TencentCloud/CubeSandbox/releases/tag/v0.7.2)
- v0.7.2 README 明确将 Kubernetes 部署和跨节点 pause/resume 标为 preview；官方启动时间依赖模板、池化和快照克隆，额外内存不等于实例工作负载总内存。[锁定版本 README](https://github.com/TencentCloud/CubeSandbox/blob/v0.7.2/README.md)
- 架构采用 Rust、Go、OpenResty/Lua；不是全 Rust。Rust 覆盖 CubeAPI、Shim、Hypervisor、CubeCoW 等，Go 覆盖 CubeMaster、Cubelet、生命周期管理。[主线架构](https://github.com/TencentCloud/CubeSandbox/blob/master/docs/architecture/overview.md)
- v0.7.2 修复过增量快照数据丢失、删除模板使既有快照失效、ARM 恢复失败等问题，应转化为回归场景，不能据此断言当前仍有缺陷。[发布说明](https://github.com/TencentCloud/CubeSandbox/releases/tag/v0.7.2)
- 当前 roadmap 仍包含自动故障恢复、节点 drain 迁移、剩余 E2B 兼容工作。主线文档不能等同于固定版本已交付能力。[Roadmap](https://github.com/TencentCloud/CubeSandbox#roadmap)

## OpenSandbox

- 生命周期控制面为 Python/FastAPI，执行组件 execd 为 Go；支持 Docker、Kubernetes 及 FastSandbox 等后端，能力需逐后端核实。[主线架构](https://github.com/opensandbox-group/OpenSandbox/blob/main/docs/architecture/index.md)
- 统一稳定发布 release-1.1.0（2026-09-21）包含 Firecracker FastSandbox、PostgreSQL snapshot 元数据 HA、诊断与 OTLP 指标。[发布说明](https://github.com/opensandbox-group/OpenSandbox/releases/tag/release-1.1.0)
- release-1.1.1-rc.1（2026-09-28）仍属预发布；其说明明确指出 1.1.0 PyPI server wheel 导入失败，且 agent-sandbox provider 暂停恢复、共享 namespace 租户隔离为该 RC 新增。不得把 RC 或主线能力算作稳定版本既有能力。[RC 说明](https://github.com/opensandbox-group/OpenSandbox/releases/tag/release-1.1.1-rc.1)
- 诊断 API 明确是尽力而为的日志和事件，不定义结构化审计或完整可观测模型。[API 文档](https://github.com/opensandbox-group/OpenSandbox/blob/main/docs/api/index.md)

## 工程判断

两者均可作为运行时或协议参考，但不能据此证明 ECS 级运营能力已经齐备。Rust 产品控制面配合成熟运行底座合理；为了语言统一而重写 VMM、存储、网络和调度没有必要。若任意进程内存恢复和快速克隆是核心需求，CubeSandbox 值得固定版本对照验证；仅需持久工作区与企业实例管理时，Kubernetes/Kata/CSI 路线应独立评估。没有同硬件同负载测试，不能给出两者的实际生产成本排名。
