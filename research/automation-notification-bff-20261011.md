# 自动化异常通知真实 BFF 验收

2026-10-11，按开发表继续推进 G3-04、G3-07、G3-10，补齐上一轮尚未验收的真实浏览器异常确认链。本轮扩展验收和必跑 CI，不新增产品接口、调度器或身份绕过入口；这些工作包仍为开发中。

## 实际链与模块边界

使用已安装 Chrome、编译后的控制台、本地真实 Keycloak 临时 realm、Rust 正式 BFF/API，以及全新临时 TLS PostgreSQL。数据库通过正常 `sandboxd --role migrate` 安装全部正式迁移与角色权限。自动化使用独立 `sandbox_automation` LOGIN；原开发数据库、卷和账号口令保持原样。

原验收先完整验证未来 ONCE RENEW 的 UI 创建、丢回执重放、暂停/恢复/撤销、当前撤权和零运行事实。随后追加异常阶段：从实际 ACTIVE BFF 会话解密凭据，正常验签 access token 并解析当前 Actor；使用正常域入口创建有限 ONCE RENEW，专用 coordinator 领取并准备运行；正常手工续期增加实例版本，实际 `run_claim` 得到 VERSION_MISMATCH 并提交 FAILED 运行、来源事件和通知。没有直接写失败状态、通知、事件或回执。

异常来源创建与手工续期采用正常数据库域入口和实际 BFF 验证身份，不能称作这两步由 UI 发起。通知的读取、确认、回执故障和重放实际经过 Chrome → cookie BFF → 正式 HTTP API → PostgreSQL。仅测试构建暴露窄的 prepare 布尔入口，调用同一正式实现；生产可见性和执行路径不变。

首次 UI ACK 经 `route.fetch` 获得真实提交的 200、版本 2 和完整回执后，才中断浏览器响应。UNKNOWN 原 key、原 `{}`、原 `"1"` ETag 持久保留；正常 GET 已能看到提交结果，不把资源版本变化当作原请求回执已确认。控制台移除已阅表单，同时继续提示核对原未知请求。

重载后撤销当前写权限，原请求重放真实返回 404，保留 UNKNOWN；随后撤销当前读权限，刷新清除列表/详情，重放预读取被拒绝且不发送 ACK。恢复两项原权限后，用户显式重放同一 key、空对象和旧 ETag，得到与首次提交完全相同的回执。最终请求记录只有一条 ACCEPTED 记录，没有替换 key。

同时验证匿名 401、缺 CSRF/错误 Origin 403、缺 If-Match 428、非空 JSON 400、新 key 携旧版本 412。ACK 期间无工作负载写请求和 Operation 读取；浏览器没有 bearer、access/refresh token 或可读会话 cookie。最后仍通过控制台的实际 `/details` 读取新实例版本，STOP 的 If-Match 与 `x-instance-etag` 精确一致，原停止、grant 撤销和 membership 禁用回归通过。

## 事实与证据

在来源失败提交之后建立 ACK 基线，四个阶段比较完整实例、工作区、执行、文件活动及分片、操作/派发、规则、委派、运行、私有 claim、租户/项目配额、预留与工作区 hold/释放记录。ACK 不改变这些事实。通知来源字段保持不变，正常 management receipt、ACK audit 和因果 domain event 各恰好一条；审计 request ID 与原 run ID 不同且非空，域事件保留原 run 因果 ID，满足现有自动化排除条件。没有声称本轮精确核对审计 ID 与 HTTP 响应头。

实际源码候选为 791 个公开文件，SHA256 为 `ffccd99aee2f23223432996faba6664c5f07a7fa2a2f5eead2700d2aeb89285c`。runner 在捕获后强制由当前源码执行 locked/offline Cargo 构建确认，外部 Cargo JSON 仅作路径核对；Rust 制品及实际提供给 Chrome 的 `console/dist` 清单、SHA 和 mode 在验收前后不变。完整 0600 私有事实报告在编译缓存之外保存，并纳入收据 SHA。

| 检查 | 最终结果 | 边界 |
| --- | --- | --- |
| 真实 Chrome/Keycloak/BFF/API/TLS PG 完整链 | 1/1，测试 25.68 秒，子进程 25.73 秒 | 包含原管理矩阵、实际失败通知故障链及最终停止/撤权 |
| Rust 普通库测试 | 270 通过、0 失败、118 明确 ignored，62.26 秒 | 本轮只重跑库测试；环境专项不计入普通通过数 |
| 严格 all-target Clippy / fmt | 通过 | 正常工具链与锁文件；未改发布配置 |
| 控制台生产构建 | 通过，5.709 秒 | 与实际浏览器读取的构建文件绑定 |
| Node / Python / CI 语法 | 通过 | 两个浏览器脚本、runner AST、工作流 YAML 与变更 Bash；远端 CI 未执行 |
| 迁移账本 | 全部 41 条 SHA384 一致 | 1..37、39..42；无未发布 38，未造账本 |
| 清理 | 四次尝试均确认 | 只移除各自临时容器/进程组，原开发数据保留 |

最终记录为 `.local/bff-notification-20261011/actual-v4/record.json`，聚合交付记录为 `.local/bff-notification-20261011/delivery-record.json`；`notification-facts.json` 保存完整前后业务行及唯一回执/审计/事件，目录 0700、文件 0600，不上传该报告、TLS 密钥或 realm 凭据。CI 仅保留不含身份响应的收据、公开源码清单和受控浏览器日志。

前三次实际尝试均保留 FAIL 收据，不计入最终通过：第一次错误要求已阅通知仍有禁用表单；第二次等待实例响应的注册时间过晚；第三次新增检查监听了普通资源接口，实际 UI 调用的是 `/details`。修正只涉及验收脚本的实际界面/接口断言；没有放宽授权、版本、事实、业务期限或正常测试栈。后两次异常通知链已通过，但停止前检查失败，仍按整链失败记录。

本轮复用 `target/review-low-debug`，普通 Rust 命令设置 `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`，保留调试断言和溢出检查；缓存约 3.6 GiB，完成时可用空间约 247 GiB。没有清理共享缓存或未确认用户文件，日志和报告保存在缓存外。随后仅补交付文档，行为源码保持本次验收版本。

## 剩余生产门

下一项优先推进 G4-06：带历史数据的 0041→0042 添加式升级、迁移重复运行、旧格式事件写入及应用回退限制。要求正常迁移、保留全部历史事实与旧 checksum、不回填旧异常，并确认旧迁移器拒绝较新账本；没有实际旧发布制品时，不能声称完成 N/N−1 二进制兼容认证。禁止手工重放旧角色脚本、删除新迁移或改写 SQLx 账本。

目标集群的滚动升级、HA、72 小时容量与历史保留、控制数据备份恢复、生产身份/TLS、Kata/CSI/Cilium，以及统一 Linux 八 ELF/四 OCI 的安全扫描和签名发布仍未验收。本轮不认证云副作用、企业 MFA/联邦或生产 Nginx/PKI：浏览器 HTTPS 使用公开测试证书，Chrome 只在本地夹具忽略其证书错误；Keycloak 后端使用回环测试 transport。没有 Git 提交、推送或云部署。
