# 自动化能力合同交付记录

日期：2026-10-10。对应开发表 G3-07，并补齐 G2-11/G3-10 的调用与控制台合同。

本轮完成服务端、OpenAPI、TypeScript SDK、控制台之间的自动化能力发现和受理约束一致性。其他微服务可以通过正常 `GET /v1/capabilities?project_id=<uuid>` 获取已安装的自动化协议，不必从控制台参数或 worker 实现推断。G3-07 和整产品继续标为开发中；本地验收不代替生产云环境验收。

## 行为和模块边界

正常自动化路由开启时，顶层 `automation` 发布 `schema_version:1`、7个动作、3个触发器、PostgreSQL/UTC 时钟语义、cron 规则、漏执行和 UNKNOWN 处理规则以及固定限额。未挂载路由时该字段仍存在且为 `null`，两个原能力布尔值同时为 false。

`src/automation_contract.rs` 保存固定合同和同一组验证常量，ledger/rules 消费这些限制；路由决定是否公布合同。没有新增数据库迁移、独立调度逻辑或另一份持久能力状态。API 返回的是接口合同，不是当前调用者权限、剩余额度、worker 健康或云隔离认证。具体字段见[能力说明](../docs/capabilities.md)。

控制台使用已识别合同的限制构造表单。合同缺失、非法或版本未知时禁止新建/恢复，并清未提交草稿；已记录 UNKNOWN 的原请求、键、摘要和回执保留，继续显式核对。读取、暂停、撤销仍按原路由和权限判断。身份、项目和 CSRF 变化仍执行既有敏感内存清理。

## 已核对的语义

- `capabilities:read` 只允许发现。创建和恢复还要检查当前 token 的具体动作 scope、项目 grant 及资源状态；恢复也要确认原创建者的持久委派和身份代次有效。项目管理者可以暂停、撤销别人的规则，不能借恢复接管或延长原委派。本轮只纠正此前 OpenAPI 的“必须同一创建者”错误文字，未改变这些运行行为。
- `minimum_interval_seconds` 是 EVENT 冷却。ONCE/CRON_UTC 也必须提交范围内值，但 cron 频率由表达式决定。冷却内匹配事件记为 SKIPPED 并耗预算，不延后补执行。
- 名称、cron、事件类型上限按 UTF-8 字节判断。委派期限严格大于60秒且最多366天；当前 grant 可缩小允许期限。超过当前授权期限的显式请求被拒绝，服务端不会悄悄修改到期时间。
- 先向所有 API 副本发布新合同，再发布新控制台。旧服务端缺少字段时，新控制台禁止新建/恢复，保留原来可用的读取和安全管理。仓库 SDK 的普通 JSON 读取兼容新增字段；第三方严格解码器需同步 schema，不能笼统承诺全部旧客户端兼容。

## 验收证据

真实链路验收冻结了774个公开文件，字节/模式映射 SHA256 为 `ba5500578b0bfadbae32120e545b914c0b69ca5c670b7ce6bb4d526c74e63f3d`。普通 Rust 验收之后、冻结之前只修正3个文件的授权文字/生成注释，Rust 行为输入未变；验收之后只补本记录、进度、能力/开发语义说明与 OpenAPI/生成SDK字段注释。最终差异及日志摘要保存在 `.local/progress-20261010/delivery-record.json`，不把不同阶段的文档哈希冒充同一次完整源验证。

| 验证 | 结果 | 证据 |
| --- | --- | --- |
| 普通常规 Rust all-targets | 54程序、421通过、0失败、231明确ignored；ignored不计入通过 | `.local/progress-20261010/rust-all-targets.log` |
| 格式与严格 Clippy | 通过；保留原测试断言/溢出检查，关闭本地增量和调试符号 | `.local/progress-20261010/clippy.log` |
| 正式角色/HTTP/worker必跑回归 | 12组57通过，包含关闭路由的能力发现、真实授权和现有审查修复回归 | `.local/progress-20261010/review-actual-1/record.json` |
| 自动化业务及真实 HTTP/SDK | 18通过、0失败，48.48秒；包含版本1能力、授权隔离、撤权、边界拒绝和上界正常受理 | `.local/progress-20261010/automation-actual-1/acceptance.log` |
| 实际独立自动化worker进程 | 1通过、0失败，116.57秒；包括原启动/退出和故障、自然租约恢复场景 | `.local/progress-20261010/automation-actual-1/process.log` |
| 自动化正式迁移和收尾 | 业务/进程各独立库，40条SHA384逐项核对1..37+39..41，无38；两套本轮临时容器/进程已清理 | 上述目录 `evidence.json` 与必跑回归 `record.json` |
| SDK及OpenAPI静态合同 | 64/64与8/8；类型生成和TypeScript编译通过 | `.local/progress-20261010/sdk-final.log`、`api-contract-final.log` |
| 控制台单元及Chrome HTTP合同 | 61/61与9/9；构建和格式通过 | `.local/progress-20261010/console-unit-final.log`、`console-browser.log` |
| 真实Chrome/OIDC/BFF/API/PG | 1/1，浏览器18.201秒；原账户/诊断/事件/停止撤权链保留，新增服务端合同和表单限制核对、丢回执原键重放 | `.local/evidence/console-automations/1791646050007459000/record.json` |

这些测试集合存在覆盖交集，不相加宣称独立用例数。Chrome HTTP合同使用明确替身，最后一行才是实际本地身份与数据库链路。实际浏览器只管理未来 ONCE/RENEW 规则，不把该测试当作所有动作/触发器的云副作用验收。

保留的失败记录：控制台首次4项合同中一个旧断言预期合同失效时清除 UNKNOWN 原参数内存并出现重输JSON框。现已纠正为保留当前身份/CSRF绑定的原参数，允许显式同键重试；浏览器重载仍需恢复参数并核对摘要。原意图、键和摘要始终保留，失败 trace 保存在 `.local/console-automation-contract-20261010/first-failure`。SDK 首次普通沙箱执行遭本地回环监听 EPERM，同一测试在既有本地验证授权下通过。真实浏览器首次因未提供必须的显式本机 Docker Unix socket 在准备前退出；补参数后沿原检查通过，记录 `.local/progress-20261010/browser-first-preflight-failure.json`。这些修正没有放宽生产权限、期限或重放守卫。

本次复用 `target/review-low-debug`，约3.2GB；结束时可用空间约281GiB，无需清理。日志和交付文件位于缓存之外；两套独立临时 Docker 夹具已移除，现有开发容器及数据卷保留，真实浏览器新测试库保留。本轮未配置 Git remote、未提交或推送。

## 尚未通过的上线条件

本轮没有打开生产恢复、认证 Kata/CSI 或证明所有云动作已执行。仍需当前源码的统一 Linux 八ELF/四OCI安全扫描、签名与升级回退验收，真实云环境权限/隔离/存储组合验收，以及 HA、容量、持续故障和运维接管。后续按[完整开发表](../docs/implementation-status.md)及产品路线落地方案（内部规划记录，不随源码发布）推进；具名组织评审和实际生产发布分别留下真实证据。
