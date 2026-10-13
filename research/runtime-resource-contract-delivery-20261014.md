# 受控运行资源数量：开发与验收记录

本轮已实现逐次启动资源账本的数量与provision校验子项，接入实际Pod生成、创建前/回读后以及RuntimeClass读取入口。launch不可变合同、配置来源观察、配额状态回执、释放有效期和对外查询仍待开发；当前没有新增利用率百分比、自动调档、warm pool或GPU配置。

## 生产实现

`runtime_resource_contract`深模块将CPU millicores、内存bytes和临时磁盘bytes分别封装，使用checked整数转换与加法，数量限制至非负`i64::MAX`。工作负载仍只接受原三种Flavor，request=limit，临时磁盘仍为128–32768 MiB。新生成合同保持原规范表示；其他Pod身份、权限、卷和完整spec仍按原方式严格校验。

这是明确受控的Quantity子集：CPU为无符号整数cores、整数`m`或最多三位小数cores；内存和临时磁盘为无符号整数bytes或整数`Ki/Mi/Gi/Ti/k/M/G/T`。输入最多64 ASCII字节；拒绝符号、指数、非支持单位、分数bytes、精度不足、溢出、额外资源、设备claims、sidecar、init/ephemeral容器和Pod级resources。overhead仅允许CPU和memory，明确零合法；缺少完整对象不能由此推导零或历史值。不会默默取整或饱和。

Kubernetes的[Quantity规范表示](https://raw.githubusercontent.com/kubernetes/apimachinery/v0.35.0/pkg/api/resource/quantity.go)会在序列化时调整suffix。模块接受的等值数量不等于完整Pod可被采用：原raw spec严格比较继续有效，非规范实际Pod别名仍可被拒绝。本步没有改PVC、tmp、finalizer或停止协议，也未认证任意Kubernetes数量语法。

provision入口先验证预期资源，再验证实际回读的工作负载及overhead，拒绝CPU/内存总量加法溢出；随后原完整Pod与UID归属检查仍必须通过。`find_stop_target`、`request_stop`和可信终止清理没有引入当前RuntimeClass或新数量解析依赖。资源配置通过不代表VM就绪、资源独占、RuntimeClass版本一致或允许释放预留。

## 验收范围

三条实际调用入口回归分别保留RED和GREEN：原RuntimeClass入口接受负CPU overhead；原Pod provision入口接受非法overhead；原入口未限制工作负载加overhead的整数溢出。修复后均拒绝，且同一坏overhead用例确认既有UID停止路径仍可执行。编译错误和沙箱socket权限失败另存，不作为有效RED。

限定回归共26项通过：RuntimeClass生产HTTP入口5项、manifest及Pod回读19项、原gateway_runtime 2项。包含三Flavor与临时磁盘边界的9种组合、创建前16类拒绝、RuntimeClass合法/拒绝数量、POST返回坏资源、总量溢出、停止及非规范别名约束。随后普通Rust all-targets 453项通过，257项环境专用用例保留独立门；严格all-targets Clippy和完整格式检查通过。Standards与Spec只读静审分别零阻断。本机私有日志和源SHA保存在`.local/runtime-resource-contract-20261014/`；最终完整产品链源码验收和远端CI分别核对，不能由这些限定结果提前填绿。

HTTP回读是明确的Kubernetes响应合同fixture，通过实际客户端和生产Interface；没有真实Kata/Cilium/CSI/GPU或目标公有云认证。下一步按[逐次启动资源账本方案](launch-resource-accounting-plan-20261014.md)持久化launch请求和配额回执，再开发可信Pod来源登记与释放历史，随后进入预准备预算及端到端冷暖实测。
