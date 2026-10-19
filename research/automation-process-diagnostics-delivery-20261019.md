# 自动化进程验收失败阶段诊断交付（2026-10-19）

本片补齐真实进程验收的安全诊断，生产运行时、API、迁移、权限与启动资源准备功能均未改变。原 CI 故障原因仍 UNKNOWN，不能把本地通过或故障注入验收写成原故障已修。

## 精确基线与证据边界

公开基线 `d53d7b197fb004a4300a2f91540e964de3cb6480` 的 [CI 39120679185](https://github.com/StateKnot/knotsandbox/actions/runs/39120679185) 为五个 job 中四个通过，`verify` 在 Fresh independent PostgreSQL automation acceptance 失败。前轮身份安装合同已通过。本轮失败回执的业务18、通知PG5与通知HTTP/SDK1均为 EXACT_PASS；最终实际进程用例为 EXACT_FAILURE、exit101，最后固定标记为 `ACCEPT_FINAL_SAFE_MODE_FENCE START`，没有已识别断言。缺失后续标记并不证明已经到达最终 SQL 栅栏或产生 P4090。

200项自动化源码、fixture、迁移、锁文件、vendor和CI输入与前提交逐字一致，ROOT 同样匹配；这不能证明间歇故障的原因。原私有进程日志未上传，现有回执只含 SHA256、字节数与有限分类，无法从摘要恢复错误内容。既有 BFF 与身份就绪故障原因也继续保留 UNKNOWN，不合并成同一故障。

未经修改的原进程场景已分别在 Mac→本地TLS PostgreSQL 和同一 Linux VM 时间域通过：各1项、0失败、全部原里程碑，分别120.15秒和115.77秒；正式47迁移及自有夹具清理确认。它们是单场景对照，不是完整25项矩阵或原CI故障复现。更早中断的本地整轮只留有18项业务原始通过日志，没有完整收据；未执行的七项不能补记通过。中断遗留容器已按精确ID、label和TLS挂载核验后清理。

## 实现

`tests/automation_process/acceptance_faults.rs` 对 Owned 资源之前的基线单独附固定上下文；原 outcome 内用静态字符串区分工作者启动、意图创建、配额阻塞器、真实等待与语句年龄、safe-mode及锁释放、拒绝观察、自然恢复和进程释放。仅在全部原清理操作求值并等待后，把失败时的当前阶段附加到原错误链。成功路径不增加网络请求、数据库查询或日志。阶段只是失败返回的位置，不宣称其根因。

`scripts/test-automation.py` 沿用既有回执接口，增加九种固定阶段分类、固定说明和当前源码路径/行号/SHA256。新阶段要求完整行匹配，已知前缀加未知后缀不得冒用分类。原始异常、SQL、HTTP正文、URI、凭据和请求内容继续只留在私有日志；未知错误保持未知。测试选择、数量、退出码和精确 libtest 判定逻辑不变，分类不能制造通过。

原2秒锁窗口、3秒SQL锁超时、5秒观察、10秒就绪/退出、15秒阻塞器观察、自然30秒租约及45秒恢复观察均保持。TLS verify-full、独立LOGIN、正常迁移/角色、不可变意图、恰好一次、物理backend缺失、真实P4090来源及单次连接池drain断言保持；不强行过期租约、改系统时间、扩大权限/线程栈或依赖反复重跑。

## 本地验收

证据根目录 `.local/automation-ci-repair-20261018/` 不随源码公开。测试证书、密码及原始日志留在私有夹具；日志和收据位于编译缓存之外。

| 记录 | 实际结果与范围 |
| --- | --- |
| `ci-artifact/evidence.json`、`automation-input-contract.json`、`phase-analysis.md` | 原CI失败、输入未变与开放故障区间保留，未回填新分类 |
| `host-interruption-record.json` | 中断记录；18项原始通过不是整轮验收；遗留自有资源清理确认 |
| `host-process-original/evidence.json` | 未修改原进程1项通过、47迁移、制品/源码稳定及自有清理；不是25项 |
| `linux-process-original/evidence.json` | 同VM原进程1项通过、47迁移、全部原里程碑及精确自有清理；不是CI修复证明 |
| `diagnostics-red.log`、`diagnostics-green-final.log` | 新分类断言先RED，最终12项receiver合同测试通过，覆盖固定分类/源码绑定、未知后缀拒绝、正文脱敏及原判定门 |
| `linux-process-diagnostic-red/evidence.json` | 仅最终场景期望2→3的受控反例实际exit101；EXACT_FAILURE / ACCEPTANCE_QUOTA_BLOCKER，原私有cause保留；独立backend为0、47迁移及自有清理确认 |
| `linux-process-diagnostic-green/evidence.json` | 恢复最终原条件后，完整原进程序列1项通过、0失败，115.57秒；所有原里程碑、47迁移、独立backend为0及自有清理确认 |

同一份实际反例日志交给旧、新receiver比较：二者精确失败判定均为EXACT_FAILURE，旧版没有分类，新版仅为ACCEPTANCE_QUOTA_BLOCKER；原CI回执保持不变。比较记录为 `producer-red-receiver-comparison.json`，不是对原CI私有日志的重建。

受控反例只在私有源码副本把 FinalSafeMode 的配额账户期望从2改成3，QuotaTimeout和全部前序trial保持原条件；数据库实际仍只锁定原两个账户。单行差异、源码与普通制品摘要保留。该反例用于验证 outcome 内真实断言失败经过原清理后能保留阶段，不能充当原CI复现、产品缺陷或成功自然drain的证据。反例结束后还在移除夹具前独立只读核对该库同一自动化LOGIN的实际backend数为0。最终源码恢复原期望后必须完整通过原场景。

固定运行环境为既有 Rust1.98.1 Linux arm64 镜像、摘要固定PostgreSQL17.11，测试CA在同VM按原1天期限生成。源码副本只含1119项公开路径的源码/锁文件/必要配置，排除target、node_modules、虚拟环境；四项历史未发布文档差异不进入本批。普通低debug/jobs1、原debug assertions/overflow checks和既有缓存复用；编译前df与缓存容量均满足用户限制。首轮只读副本缺空挂载点的容器启动失败已单独保留，未到编译或产品执行，不计作原CI复现。

主机Rust1.98.1的全仓fmt检查与本变更automation_process target严格Clippy通过；固定Linux镜像的同target严格Clippy通过。该镜像未安装rustfmt，首次fmt命令失败保留，格式检查由同版本主机工具完成，未临时联网安装组件。最终冻结源码的Python诊断12项通过。最终正常worker与迁移器的ELF摘要和原对照逐字一致，最终普通制品/源码在验收期间稳定。普通Rust全量用例和完整25项自动化矩阵本片未重新执行，不能合并本地单场景或历史CI结果补成整轮通过。

代码两轴独立审查：Standards 0项，Spec 0项，最严重问题均为无。最终文档/字节/模式和交付清单另行冻结复核。

## 发布与后续门

仅同步本片三项代码/测试、四项进度文档和本记录，保留主工作区其他改动及四项历史差异。固定基线、最终字节/模式与独立两轴审查绑定；提交后单独核对远端完整树和精确head CI，不把旧提交成功当新提交成功，不强推、不创建release或文档自引用触发提交。

下一生产开发仍为P1受限准备执行者、真实硬限与lease/content/snapshot/GC保护闭包。pre-pull保持关闭；云、Kata、CSI、GPU、物理缓存和性能收益均未认证。本片不宣布整套产品可生产上线。
