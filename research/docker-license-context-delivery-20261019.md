# OCI 载荷许可：生产 Docker 上下文修复与验收

日期：2026-10-19。基线为公开 `e9b779c9d9c226ac60e303075a880160591f435c`，精确 [CI 39199647925](https://github.com/StateKnot/knotsandbox/actions/runs/39199647925) 为4个job成功、verify失败；不重跑原失败提交。

## 已确认的生产构建失败

verify在单元与认证、原生运行时、实际OCI／CRI／快照CLI、PostgreSQL、Keycloak、浏览器授权撤销及独立自动化验收通过后，首先失败于 `Build and smoke-test non-root service and runner images`。BuildKit在 `Dockerfile:137` 的实际 `COPY licenses/oci-payload/ ...` 无法计算输入校验和，报告 `"/licenses/oci-payload": not found`，退出1。原始183行step、完整job、安全摘录及SHA保留在 `.local/p1-executor-20261019/ci-future-timestamp/ci/first-failure-record-39199647925.json`。后续host制品保留失败不作为首因。

`e9b779c` 的时间夹具修复已通过该提交的真实单元步骤；这不等于整轮CI通过，也不能倒推 `0dd7eb7` 未记录的实际时钟差。

## 前轮许可验收的范围缺口

P1b7a前轮实际Linux许可producer及四条Docker分发路径确实通过；但其scratch夹具使用按需组装的输入上下文，没有覆盖生产根目录 `.dockerignore` 的真实过滤。因此28文件的文本文字／哈希一致不能证明生产构建能取得这些输入，也不能把那份局部绿灯称为完整生产镜像构建成功。原通过记录保留，并在本片补上正确的构建上下文验收接缝。

## 实际 RED 与最小修复

实际RED使用真实ROOT上下文、原生产 `.dockerignore`、stdin Dockerfile和BuildKit的 `FROM scratch`／`COPY .` 本地导出；未拉取外部基础镜像、未编译Rust。导出结果中Cargo.lock与common.py存在，但producer脚本、README及5个固定MIT文件均缺失。允许control存在，12类dummy私有／生成文件canary全部未进入，临时src探针已精确清理。取原Dockerfile四个分发stage的实际许可目录COPY指令执行，各自退出1并报告输入不存在；12个基线文件SHA保持与e9一致。记录保存在 `.local/p1-executor-20261019/docker-context-repair/red/record.json`。

这排除了仅目录拼写或producer额外第三方依赖导致失败的解释：目录在源码中确实存在，producer只依赖已允许的common.py及Python标准库；实际BuildKit过滤删除了7个必要输入。修复仅允许该producer、两级许可祖先目录、README及5个确切版本的MIT文件，保持默认拒绝与末尾私有／生成路径排除。

## 最终本地验收与持久回归

新增 `scripts/test-docker-license-context.py` 使用标准库和真实Docker Buildx，不实现另一套ignore解析器。实际ROOT的过滤导出含完整9项输入且字节／SHA一致；只从导出目录运行和导入原producer／common.py，生成的notice为 `56073b43e1985b66b1fc9c6d4340ff461349929b4d18ebbaedf0084578ad9f2b`。再以该实际输出作为named builder上下文，执行原Dockerfile四stage的8条许可COPY指令；四个目标各7文件、共28文件的完整文本和SHA均一致。最终有界版本GREEN保存在 `.local/p1-executor-20261019/docker-context-repair/green-final/receipt.json`。

三个受控反例仅在私有源码副本实施：只缺producer放行时只报告该脚本缺失；只缺许可放行时只报告6个许可输入缺失；只允许合成探针的.env时实际检测到泄漏并失败。三例BuildKit导出本身均退出0、允许control存在，验证器分别正确退出1；不是拿Docker启动失败充当反例。实际ROOT的12类私有／生成canary均未进入，允许control存在，探针已清理，来源SHA保持。反例及原始日志见 `negative-cases.json`，原始RED与首轮GREEN也保留。

运行方式为 `python3 scripts/test-docker-license-context.py --evidence-dir .local/docker-license-context`，证据目录必须不存在。每次Docker调用最多60秒、producer15秒、df5秒；失败收据保留阶段、已取得的退出状态及清理结果。CI在checkout之后、安装Rust及昂贵构建之前运行该实际预检，新step最多6分钟，原verify job的60分钟上限不变。

独立Standards初审发现1项CI证据持久化缺口：本机有收据不代表CI runner退出后仍能取得。已补紧邻的固定SHA `upload-artifact` 步骤；校验器已生成收据时使用 `always()` 保留仅 `receipt.json` 和各阶段 `.log`，14天、最多2分钟，不上传过滤后的源码或其他私有输入。CI YAML／顺序与白名单重新校验，最终双轴审查按固定文件清单另留回执。

Python AST与CI YAML／调用顺序检查已通过，前轮566个Rust／Cargo／fixture输入仍全部MATCH；本片没有重编Rust或重跑117项release测试，也不将其前轮证据冒充本次重跑。这里认证的是生产过滤与许可分发接缝，不是完整生产镜像、amd64链接或运行时安全扫描；这些仍由新提交的精确CI及原发布门独立核对。

本片不改变Rust生产逻辑、依赖锁、许可原文、产品权限、时限、线程栈或ignored。完整P1受限准备执行者、多维物理硬限、原生保护闭包及云／Kata／CSI／GPU／性能认证仍待完成，pre-pull关闭。
