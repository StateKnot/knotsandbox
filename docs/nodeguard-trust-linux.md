# Linux 投射凭据文件验收

`scripts/test-nodeguard-trust-linux.py` 执行现有 `tests/termination_credentials.rs` 中的 ignored Linux 专项。输入为当前固定源码构建的 `x86_64-unknown-linux-gnu` 测试 ELF，以及本地已有、经审阅的 `repository@sha256` Docker 镜像。镜像须含 `/usr/bin/python3` 和该 ELF 所需的运行库，可使用 Dockerfile 锁定的 `RUST_IMAGE`。脚本不构建、拉取或修改镜像，也不操作部署服务、卷或缓存。Docker 固定连接本地 `unix:///var/run/docker.sock`；其他本地环境可用 `--docker-host unix:///absolute/local/docker.sock` 显式指定真实 socket，拒绝 tcp/ssh/相对地址，不继承远端 DOCKER_HOST/DOCKER_CONTEXT。

先运行纯协议负例，它不会调用 Docker：

```sh
python3 scripts/test-nodeguard-trust-linux.py --self-test
```

Linux 构建环境使用正常 Cargo 编译测试，保留原始构建日志、源码 manifest 和该测试 ELF 的摘要；不能用旧候选二进制或缩减后的替身来替代当前实现：

```sh
CARGO_INCREMENTAL=0 cargo test --locked --offline --release --test termination_credentials --no-run
```

从该次 Cargo 输出取得实际测试 ELF 的绝对路径，镜像参数使用当前已核验的仓库摘要。例如当前 Dockerfile 的编译基线为：

```sh
python3 scripts/test-nodeguard-trust-linux.py \
  --test-binary /absolute/path/to/termination_credentials-actual-build-hash \
  --image rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e
```

路径必须替换为实际产物；此示例不会创建产物。脚本拒绝镜像 tag/local image ID、错误 ELF 架构、链接/FIFO/可写输入、空输入和超限输入。它先从已打开文件描述符复制有界输入，并校验复制期间文件未变化；原文件不挂入容器、不更改 owner。使用的三份 PEM 全部是已提交的公开协议测试证书和测试私钥，不读取生产 Secret。

容器及本地镜像inspect均固定 `linux/amd64`，避免多架构镜像默认选宿主平台；Docker须支持inspect的platform参数。`--pull=never`、`network=none`、只读根文件系统、只读输入和 1 MiB `nosuid,nodev,noexec` tmpfs保持。root Python阶段先chmod再chown，只授予CHOWN/SETUID/SETGID，以及用于清空bounding set的SETPCAP；启用no-new-privileges，不增加FOWNER。它只在tmpfs创建root:10001 0440 identity、投射链接，以及可读但错误补充组、组写、公开mode、本进程UID10001所有但0440的非root identity和可写CA否例。

随后设置补充组 `[10002]`、真实/有效/保存 UID 与主 GID 均为 10001，检查 Inheritable/Permitted/Effective/Bounding/Ambient 五组 capability 全部为零，再以固定、最小环境执行精确 ignored 测试。测试自身核验实际 UID/GID、文件 owner/mode 和补充组可读性；脚本要求恰好一个测试实际通过，零测试或仍 ignored 都失败。Docker 命令有输出与时间限制；已退出容器直接删除，超时后仍运行的独立测试容器先执行有界 stop，再正常 rm，不使用 force rm。清理失败单独给出本次随机容器名称，保留原测试错误；不操作任何服务容器。

实际成功才输出 JSON PASS，包含镜像 ID、测试 ELF 和公开 fixture 摘要。归档此 JSON、原构建源码 manifest 及真实命令日志。`--self-test` 只证明脚本协议与拒绝条件；真实执行证明 Linux 文件权限/FD 契约，仍不证明 Kubernetes 实际投射、Cilium 隔离、Kata/KVM、云 fencing 或运行时认证。本专项未执行前必须保持 `NOT_RUN`，不能计入 Linux 认证通过数。

2026-10-08，冻结v6源点的实际O3测试ELF SHA256 `0c5143238e27bf5d72a181cbba28252f4439052b63ea259778cb181e7e29fabd` 配合独立新harness SHA256 `dfd795b41ba27a66adbd6cf45939f5a1d370f30c7a2e463e65190777524b56c2` 实际1/1通过。UID/GID10001、补充组10002、五组capability均零；原冻结harness在平台检查处失败，尚未进入chmod/chown阶段，不能声称实际重现了权限顺序错误。收据 `.local/sqlite-release-candidate-20261008-v6/projected-trust-v2-summary.json` 保留两次范围，新helper不回填原v6冻结源点。该验收仍不含Kubernetes真实投射或Kata/KVM认证。
