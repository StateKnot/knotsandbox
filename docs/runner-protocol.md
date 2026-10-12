# Sandbox runner protocol v1

`sandbox-runner` 是工作负载镜像内的 Linux 一次性进程执行器。它不监听端口，不访问 Kubernetes、数据库、对象存储或身份服务，也不提供跨重试的去重保证。平台通过 Kubernetes exec 明确指定本次 launch 的容器，启动固定命令：

```text
/usr/local/bin/sandbox-runner exec --execution-id <UUID> --dispatch-attempt-id <UUID>
```

平台必须先持久保存 dispatch 标记。两个非空 UUID 用于绑定准入检查与此次 exec 连接；命令参数中不放 argv 或环境值。runner 收完 stdin 后核验请求 execution ID 与 CLI 一致，不一致时拒绝启动。attempt UUID 不构成 guest 去重凭据。exec 连接或平台 worker 丢失后，不得根据“没有收到 started”重新派发；这仍可能是 `OUTCOME_UNKNOWN`。任意 guest 事件、文件及退出码都是工作负载报告，不能成为隔离、VM 终止或外部业务动作成功的证明。

## 子命令

| 命令 | 行为 |
| --- | --- |
| `idle` | PID 1 等待 SIGTERM/SIGINT，处理 SIGCHLD 并回收孤儿进程；不读取或自动执行工作区脚本 |
| `health` | 输出一行固定版本 JSON 并退出；只证明 runner 可以响应探针，不证明网络隔离和终止状态 |
| `exec` | 从 stdin 接收一个完整 JSON，在 EOF 后才启动目标命令；stdout 专用于 NDJSON 协议 |

`health` 示例：

```json
{"protocol_version":1,"runner_version":"0.1.0","status":"ok"}
```

## 输入

```json
{
  "execution_id": "00000000-0000-4000-8000-000000000001",
  "argv": ["/usr/bin/printf", "%s", "hello"],
  "env": {"TASK_MODE": "batch"},
  "cwd": "/workspace",
  "timeout_seconds": 300,
  "output_limit_bytes": 1048576
}
```

- stdin 最大 65,536 bytes，10 秒内必须收到 EOF。拒绝第二个 JSON 对象、未知字段、重复字段及重复环境变量名。输入完整前不会执行命令；控制 stdin 不传给子进程。
- `execution_id` 必须是非空 UUID，仅作为相关性标识，不充当执行锁。
- `argv` 长度为 1–64，总计含参数分隔开销不超过 64 KiB，首项非空，不允许 NUL。参数直接传给操作系统；只有调用者明确给出 `/bin/sh -c ...` 才运行 shell。
- `env` 最多 64 项，总计不超过 16 KiB，单个值不超过 4 KiB。名字使用 ASCII 标识符，不允许 NUL。拒绝 `SANDBOX_*`、`PATH`、`HOME`、`TMPDIR`。
- runner 清空继承环境，固定 `PATH=/usr/local/bin:/usr/bin:/bin`、`HOME=/workspace`、`TMPDIR=/tmp`，默认 `LANG=LC_ALL=C.UTF-8`，设置协议及 execution ID 变量，然后加入请求环境。不会把控制平面访问令牌传入工作进程。
- `cwd` 必须是 `/workspace` 或其子目录，不允许 `..`。Linux 使用逐级 `openat(O_NOFOLLOW | O_DIRECTORY)` 和持有的目录 FD 定位，拒绝符号链接组件，不使用有竞态的 `canonicalize → chdir` 安全检查。
- `timeout_seconds` 范围 1–3600，从子进程启动计时。
- `output_limit_bytes` 范围 0–16 MiB，按两个流合计的原始字节数计费；0 表示只丢弃输出。达到额度后仍持续读取两个流，避免子进程因管道写满卡死。

生产执行仅支持 Linux。其他平台明确返回 `UNSUPPORTED_PLATFORM`，不使用安全性较弱的 cwd 处理替代。控制通道要求可注册非阻塞事件的 pipe/socket；平台 Kubernetes exec 满足此形态。CLI 调试时通过管道传输与保存协议，不把 runner 的 stdout 直接重定向为普通文件。

## 输出

stdout 为一行一个 JSON 的 NDJSON。每行都有：

| 字段 | 含义 |
| --- | --- |
| `protocol_version` | 固定为 1 |
| `execution_id` | 已解析请求的 UUID；输入解析失败时为 null |
| `sequence` | 本次调用从 0 连续递增；连接中断时不能推断缺失事件内容 |
| `type` | `started`、`output`、`exited`、`timed_out` 或 `error` |

成功 spawn 后先输出 `started`：

```json
{"protocol_version":1,"execution_id":"00000000-0000-4000-8000-000000000001","sequence":0,"type":"started","pid":42}
```

输出事件使用 base64 保留任意二进制数据；两个流可以交错，各流自身保持顺序。

```json
{"protocol_version":1,"execution_id":"00000000-0000-4000-8000-000000000001","sequence":1,"type":"output","stream":"stdout","data":"aGVsbG8="}
```

每个 chunk 最多 6,144 原始 bytes / 8,192 base64 字符。额外限制最多 4,096 个 output 事件，防止海量单字节写入放大协议头；达到该限制也置 `output_truncated=true` 并继续 drain。最大额度下，base64 和协议头会使传输量高于原始输出额度，最多约 24 MiB。内部传输队列最多 16 个事件，不缓存完整命令输出。

终端 `exited` 或 `timed_out` 带有：

```json
{
  "protocol_version":1,
  "execution_id":"00000000-0000-4000-8000-000000000001",
  "sequence":2,
  "type":"exited",
  "exit_code":0,
  "signal":null,
  "timed_out":false,
  "cancelled":false,
  "output_complete":true,
  "output_truncated":false,
  "bytes_observed":5,
  "bytes_emitted":5,
  "termination_confirmed":false
}
```

`output_complete` 仅在两个流都读到 EOF、没有截断时为 true。`bytes_observed` 为 runner 实际读到的字节数；后代长期持有管道导致超时关闭时，不代表该进程一共曾生成多少字节。`exit_code` 与 `signal` 可以是 null。字段不构成远程停止证明。

## 截止期限与错误

超时或 SIGTERM/SIGINT 会尽力向独立子进程组发送 SIGKILL，同时尝试终止直接子进程。子孙可以通过 `setsid` 等方式离开进程组；guest 可以干扰 runner 或伪造输出，因此所有结果的 `termination_confirmed` 始终为 false。平台的 HARD_STOP 策略必须继续整 VM 停止、可信终止确认和必要的云 fencing。

直接子进程结束后，最多再等待 2 秒读取流尾部。后代不关闭管道时，runner 再尝试本地进程组清理，关闭读取端并返回不完整输出。结果通道写入同样有有界收尾期限；平台停止读取不会关闭子进程计时器。写入失败时可能无法送达最后一个事件，平台必须按传输中断处理。

`error` 只返回稳定错误代码，不回显 argv、环境值、文件路径或底层系统错误。输入错误发生于 spawn 前；`CANCELLED` 和 `CHILD_WAIT_FAILED` 不能说明远端已停止。

```json
{"protocol_version":1,"execution_id":null,"sequence":0,"type":"error","code":"INVALID_JSON","termination_confirmed":false}
```

错误代码包括 `INPUT_TOO_LARGE`、`INPUT_TIMEOUT`、`INVALID_JSON`、`INVALID_REQUEST`、`INVALID_CWD`、`UNSUPPORTED_PLATFORM`、`SPAWN_FAILED`、`INPUT_CHANNEL_FAILED`、`OUTPUT_CHANNEL_FAILED`、`CHILD_WAIT_FAILED`、`CANCELLED`。

runner 进程退出码 0 表示已完成协议输出，包括子命令失败和超时；调用方须解析终端事件。参数或输入错误返回 64，内部/通道错误返回 70。stderr 仅输出固定 runner 错误码，不混入 stdout 协议。

## 镜像与验证

`docker build --target runner -t sandbox-runner:local .` 生成 UID/GID 1000 的基础 runner 镜像，与服务镜像复用同一个锁定工具链的构建阶段。二进制由 root 持有且不可写。运行时使用只读根目录，仅 `/workspace`、`/tmp`、`/run` 可写并有独立额度。基础 runner 不安装 Python；语言、工具链、CA 和业务依赖必须在具体批准模板中固定版本、扫描并锁定镜像 digest。

Linux 上执行：

```sh
cargo test --locked --test runner
```

测试覆盖真实命令退出码、双流二进制输出、显式 argv、stdin 隔离、环境清理、海量输出、超时、后代持管道、慢输出消费者、cwd 链接逃逸及 spawn 失败。它们验证本地 runner 行为，不代替 Kata、Cilium、CSI、节点分区和整 VM 终止验收。
