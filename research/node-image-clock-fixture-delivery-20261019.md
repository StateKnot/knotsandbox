# 节点镜像指标：未来时间夹具修复与 CI 证据

日期：2026-10-19。本片针对公开提交 `0dd7eb7d0003792e70825f296fa88172e65a3b57` 的精确 [CI 39196350609](https://github.com/StateKnot/knotsandbox/actions/runs/39196350609)，不重复运行同一失败提交。

## 已确认的故障与未记录的事实

五个job中四个成功，verify首先在 `Unit and authentication tests` 失败。首个失败为 `metrics::node_image_metrics::tests::stale_or_partial_newest_components_stay_unknown_without_fallback_or_empty_invention`，原文件第518行的第四个返回值没有满足库存与文件系统均UNKNOWN；库测试352通过／1失败／149 ignored，退出101。后续缺收据／制品上传失败是级联结果。原始完整job／失败step、安全摘录和精确head校验保存在 `.local/p1-executor-20261019/ci/failure-summary-39196350609.json`。

失败对应 `future_original`：夹具把原始观察时间设为查询整数秒 `evaluated + 6`。生产代码在HTTP前取整数查询时间，收到正文后重新取毫秒级时间给现有 `decode`；原始观察时间允许到**响应时钟加5秒，含边界**。当解码时钟为 `evaluated + 1` 时，同一夹具恰好在合法边界内，因此原UNKNOWN期望不是恒成立的非法输入。请求开始的取整小数和I/O／调度时间都可能产生该条件；不能把它表述为已证实的“一秒网络延迟”。

原CI没有记录实际evaluated／decode-now，故历史触发原因仍UNKNOWN。这里能确认并修复的是夹具的确定性缺陷；不能从复验通过倒推原CI的真实时序。

## 修复合同

只修改 `src/node_image_metrics_tests.rs`，生产代码保持逐字不变。使用现有真实decoder的显式 `now` 参数复现旧夹具的边界条件；HTTP非法未来夹具改用有限的 `f64::MAX`，原HTTP UNKNOWN断言保留。固定时钟测试覆盖共享原始观察时间及文件系统报告时间在未来5秒的前一浮点值、精确边界、后一浮点值；文件系统时间各案例的整个库存报告均须与正常基线一致。

不放宽未来5秒／陈旧60秒规则、原10秒HTTP总期限／5秒Prometheus查询参数、权限、线程栈、资源或ignored要求。HTTP传输回归与固定时钟边界分开验证，既不靠墙钟碰巧够快，也不把遥远未来案例冒充精确边界覆盖。

## 验收状态

确定性RED已实际执行：旧 `+6` 夹具在固定 `now=evaluated+1` 下有成功来源标志，但原双UNKNOWN断言失败，1项失败／退出101。RED源、命令、摘要与日志保留在 `.local/p1-executor-20261019/ci-future-timestamp/`，不能把它说成原CI真实墙钟时序的复现。

最终源码的两个主机固定时钟测试均通过，严格all-target Clippy和fmt退出0。Linux原节点镜像指标组实际9项通过／0失败／0 ignored，含原HTTP回归；固定镜像、非root、只读、无网络、1GiB内存／无swap、2 CPU、128 PID和256MiB临时空间，源码与ELF前后hash一致。未扩大权限、资源或线程栈。

完整all-targets首次Docker启动因验证源码副本缺少嵌套证据挂载目录而退出128，尚未执行Cargo；保留原始启动失败后，仅给副本补齐空挂载目录，使用相同构建限制继续。随后Linux arm64实际执行 `cargo test --locked --offline --all-targets --no-run`，从Cargo的实际产物清单取得65个测试程序与8个普通二进制，共73个不同ELF。逐一执行全部65个测试程序，外层最终结果合计**566通过／0失败／309原生ignored**，其中库为355／0／149；各进程退出0且无OOM。相比P1b7a前轮默认63程序，增加的是两个example测试程序 `resource_accounting_upgrade_fixture` 与 `runtime_class_guard_check`，各自实际运行0项；不拿编译成功冒充测试执行，也不把嵌套子进程的结果重复计入。

Linux严格all-target Clippy退出0；源码输入、73个ELF及锁定的独立Python依赖前后校验一致。完整测试使用与上述节点指标组相同的测试容器限制，使用既有 `CLUSTER_PYTHON` 与四个锁定wheel包的只读依赖目录；未复制旧虚拟环境。构建仍为原4GiB内存／8GiB内存与swap总额、2 CPU、256 PID和单Cargo job。未另跑doctest；不能称为云、Kata、CSI、GPU或性能认证。完整记录位于 `.local/p1-executor-20261019/ci-future-timestamp/validation-final.json`。

发布范围仅为测试源码、本文、P1b7a后续CI事实及四份开发表／状态文档，共7文件；生产代码、锁文件、权限、时限、ignored与线程栈不变。发布后须按新提交的精确head独立核对CI，不重跑原失败提交、不沿用基线绿灯；本次本地通过不改写原CI失败或UNKNOWN事实。原失败记录、P1b7a的独立本地载荷验收及其权限关闭边界保留。完整准备执行者／硬限、真实pull／原生保护、云／Kata／CSI／GPU／性能仍未认证；pre-pull关闭。

## 新提交精确 CI 的后续事实

以上7文件已发布为 `e9b779c9d9c226ac60e303075a880160591f435c`，远端完整1143文件与已审本地树一致。该提交的精确 [CI 39199647925](https://github.com/StateKnot/knotsandbox/actions/runs/39199647925) 中，原失败的单元与认证步骤已通过，原生运行时／实际OCI与CRI／PG／Keycloak／浏览器／自动化等后续验收也通过；但最终镜像构建首先在许可目录COPY缺失处失败，整轮仍为4个job成功、1个失败。不能将时间夹具步骤通过称为整轮CI成功，原始时钟差仍UNKNOWN。

生产Docker上下文遗漏与前轮scratch许可验收未覆盖实际过滤的范围缺口，见[后续交付](docker-license-context-delivery-20261019.md)。原失败和本片局部通过证据均保留，新修复提交的完整CI仍须独立核对。
