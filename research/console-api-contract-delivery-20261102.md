# 控制台确认请求与 OpenAPI 合同交付（2026-11-02）

本批关闭视频演示中发现、尚未同步公开仓库的 G3 请求合同缺陷，并将反例加入现有 CI。比较基线为公开提交 `9fb4374c974c42d9702ab2a12ce99c9b313070f2`。不改变后端权限、资源期限、终止及删除状态机。

## 修复后的行为

- 取消执行须先完成既有危险动作确认，向所选 execution 的取消接口发送 `{"hard_stop_instance":true}`，使用 execution 当前版本。
- 删除工作区须先完成既有确认，向所选 workspace 的 DELETE 接口发送该 UUID 的 `confirm_workspace_id`，使用 workspace 当前版本。
- 两者继续经过原 BFF、CSRF、租户、ETag、幂等与请求台账。202 仅为受理：取消结果未知时保留 `OUTCOME_UNKNOWN`、待终止及活动槽；删除受理不表示数据已删除。
- OpenAPI 的 Operation 类别补入后端已使用的 `FILE_TRANSFER`，SDK 类型由正式生成器同步。自动化合同的16处旧 `nullable:true` 改为 OpenAPI 3.1 类型联合，其余 required、format、枚举与数值限制保持。

## 行为验收

已有真实 Chrome 回归在旧编译界面上观察到两按钮实际发送 `{}`，两项均 RED；修复后同一组 GREEN。新增的正式 schema 回归对旧公开 OpenAPI 产生3项 RED，对当前合同17/17 GREEN；覆盖全部16个可空位置、合法非空值、错误格式／类型／下界、必需响应键，以及显式危险请求确认。

本轮重新执行：

| 检查 | 结果与边界 |
| --- | --- |
| 控制台构建、TypeScript检查、格式 | 通过；静态 JS 为 `index-Dm3AxR4E.js` |
| 控制台单测 | 66/66 |
| 完整 Chrome 合同回归 | 38/38；实际编译界面与 HTTP 合同夹具 |
| SDK重新生成与测试 | 77/77；生成差异仅为 FILE_TRANSFER 联合项 |
| 正式 OpenAPI 合同检查 | 17/17；复用 `scripts/tests/api-contract.py` 和原 CI |
| 控制台部署配置检查 | 5/5 |
| 生产 Dockerfile 构建 | 本机 arm64 成功；镜像 `sha256:dfe30a272c9c13d905d418ac5e4fdfeb3333d03b122f74e1b08b74eb3023c880` |
| Docker非root／只读／TLS及路径检查 | 同一不可变镜像通过；CA/SNI/TLS1.3、错误CA／SAN／明文拒绝、CSP／不可变资源及非法路径拒绝均通过 |
| 验收网络参数 | 26项实际CLI边界检查通过；默认行为保持 |

可复现命令沿用 `npm --prefix console run build`、`npm --prefix console test`、`npm --prefix console run test:browser`、`npm --prefix sdk/typescript run generate`、`npm --prefix sdk/typescript test` 和 `scripts/tests/api-contract.py`。Python检查使用已有部署虚拟环境，未增依赖。浏览器使用本机已安装 Chrome；SDK测试仅开启临时本机回环端口。

## 失败记录与发布边界

原始证据保存在本机 `.local/progress-20261102/`；视频期间的真实按钮 RED、修复及两轴审查保存在 `.local/video-demo-20261101/`，这些私有生成目录不上传公开仓库。新增回归最初的虚拟环境解释器解析错误和不完整 Operation 夹具失败保留；修正测试驱动后才进行正式 RED/GREEN。

第一次 Docker 构建曾观察到桌面凭据助手等待，保留原日志并终止精确匹配的本轮构建；相同 Dockerfile 使用项目既有无凭据配置重新构建成功。第一次镜像验收在创建网络前失败：本机默认地址池已耗尽。没有清理其他项目网络、容器或数据卷，也没有把该失败记为 TLS 通过。

因此给既有镜像验收工具增加可选 `--network-subnet`，仅接受严格对齐的 RFC1918 IPv4 `/24` 至 `/28`，默认不传时保持原行为，冲突仍由 Docker 拒绝。核对本机33个现有网络及主机LAN后，本轮使用无重叠的 `10.253.231.0/24`，完整镜像验收成功并清理自有资源；没有改变 Docker daemon 的全局网段配置。可复现运行：

```sh
python3 deploy/console/check_image.py \
  --image sha256:dfe30a272c9c13d905d418ac5e4fdfeb3333d03b122f74e1b08b74eb3023c880 \
  --network-subnet 10.253.231.0/24
```

该镜像ID和网段是本机本轮事实；其他主机应使用其实际新构建的镜像ID，并先核对 Docker 与主机路由是否冲突。工具不会自动挑选／清理网络，且此参数不进入产品实例的网络配置。

发布前重新读取公开 HEAD、原 CI 39221603285 的5作业／75步骤和1148文件完整树，均与基线一致。该旧 CI 只证明基线。本批精确提交的 CI 须另行读取，不能沿用旧绿灯；不会因补验收文档重复触发发布。公开同步仅包含本轮审查文件，不全量提交主工作区。

这是可独立交付的控制台／对外合同修复，不是实际 VM 硬终止、云工作区销毁、完整自动化生产验收或快速启动性能证明。镜像预准备 P1 的权威路径、FD、进度确认与可信原生闭包，以及云、Kata、CSI、GPU与冷暖收益仍单独开发和验收；pre-pull保持关闭。
