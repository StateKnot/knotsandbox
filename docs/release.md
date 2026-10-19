# Linux AMD64 发布与离线安装

本仓库提供可执行发布流程，但目前没有本项目的线上签名身份、GHCR 发布或生产验收。`validate` 只产出**未签名候选制品**。本地构建成功、协议测试或官方工具签名验签成功，均不等于本产品发布通过。

当前签名制品合同为 manifest v5，必须包含 `sqlx-postgres-notices.json`、`native-protocol-notices.json` 和 `oci-payload-notices.json`。前两者保留原 SQLx 事务修复与固定 containerd／protobuf 协议许可；native notice 当前仍为 schema 2，不因 manifest 升级改写。新增 OCI 载荷 notice 按当前 Cargo.lock 精确绑定 flate2、crc32fast、miniz_oxide、adler2、simd-adler32 的版本、包校验和及所选 MIT 许可证完整正文，并绑定整个锁文件摘要。三份 notice 受原签名 file inventory、内容 hash、64KiB 读取上限与语义校验；离线安装以0444保存，只有八个 ELF 可以执行。缺资产、改字节、重算 hash 后截短许可证均拒绝。历史 v3 只要求 SQLx 资产，v4 另要求固定原生协议资产；仅先验签的历史读取可接受相应固定库存，v4 native notice 仍只允许原 schema 1 或固定 schema 2，不允许混合来源。v1—v4 历史读取均不能绕过当前 v5 安装门。四种 Docker 导出／镜像目标同时携带完整许可证、来源和生成 notice，主项目 MIT 不覆盖第三方许可。

`python3 scripts/verify-sqlx-postgres-patch.py`在CI与正式镜像构建前验证原116文件、唯一事务补丁、Cargo路径覆盖和Docker上下文；既有三份Rust SBOM必须继续覆盖path版`sqlx-postgres 0.8.6`，不能因Cargo.lock没有registry source而把它排除。镜像和宿主导出目录保留两许可证及补丁说明；新增通知协议的本地回归不等于已经签发正式发行。

## 制品与构建边界

`.github/workflows/release.yml` 只接受人工 `workflow_dispatch`，默认 `validate`。指定已存在的 `vX.Y.Z` 或 `vX.Y.Z-rc.N` 标签，且必须在该标签上 dispatch。输入独立审阅的完整 commit；远端标签、Git checkout、GitHub 工作流身份及最新同 commit 的 CI push run 必须一致且 CI 成功。没有 tag、CI 或 GitHub 仓库时不能伪造已发布清单。

Linux AMD64 产物包括 `service`、`runner`、`identity-proxy`、`console` OCI 镜像，以及 `sandboxd`、`sandbox-admin`、`sandbox-admission`、`sandbox-runner`、`sandbox-nodeguard`、`sandbox-backup-worm`、`sandbox-credentials`、`sandbox-automation` ELF 二进制。`nodeguard` 在认证节点宿主运行；把它打包进应用 Pod 不能建立宿主信任。每个镜像由完整 OCI archive 和 digest 标识，部署不使用浮动标签。

所有 Action 使用完整 commit；BuildKit、Cosign、Syft、Grype、crane、GitHub CLI 使用 `scripts/release/tools.lock.json` 中的官方版本、URL 和 SHA-256。`install-tools.py` 只提取锁文件指定的普通文件，不执行下载脚本。BuildKit 是校验后的 `buildkitd/buildctl/buildkit-runc`，在独立 GitHub hosted Ubuntu AMD64 runner 上通过私有 Unix socket 工作，禁用 containerd worker；不继承预先存在或与不可信构建共享的 daemon。GitHub hosted runner 的宿主维护由 GitHub 负责，不能将该限制描述为完整宿主字节复现。

主 Dockerfile 不执行 `apt-get install`。服务采用固定 Distroless Debian 13 nonroot 镜像，移除无需的 shell、Perl、包管理器和登录工具；runner 采用固定 Debian 13 slim，保留调用方明确要求的 `/bin/sh`。runner 的 `libgcc-s1` 版本在构建时检查；服务 HTTPS CA 来自固定 Distroless 镜像，公共 CA 包版本和实测文件 SHA 随运行依赖锁审阅。Rust builder CA 另校验固定 SHA，宿主二进制仍以 Debian 12 glibc 构建，保持 Ubuntu 24.04 节点兼容。Cargo 依赖由 `Cargo.lock` 与 `cargo build --locked` 固定；HAProxy 源码由 `deploy/identity/versions.lock.json` 中的官方压缩包校验和固定。BuildKit 使用 source commit 时间和 `rewrite-timestamp=true`；尚未完成两次独立全量构建的字节一致性验收，不宣称 bit-for-bit reproducible。

## ELF 与原生依赖清单

当前发布清单、正常验证、预检和安装要求 version 5。只有已按固定当前 Cosign 信任根认证的内部 `verify_previous` 可以读取已知 version 1/2/3/4/5，用于控制台历史资产；它不生成安装锁，也不将旧扫描当作本次安全证明。该先验签历史路径仅接受固定旧七个或当前八个完整 ELF 名单，贯穿文件、原生库存与 OCI 校验；当前新候选始终要求完整八个，不按文件是否存在猜测版本。

当前八个 ELF 逐一解析实际 program headers、`PT_INTERP`、dynamic string table 和 `DT_NEEDED`，不执行候选来判断架构。当前 `gnu-dynamic-v1` 固定 AMD64 glibc loader `/lib64/ld-linux-x86-64.so.2`，必须依赖 `libc.so.6`，仅允许该 loader、libc、libm 和 libgcc_s；额外动态库、RPATH/RUNPATH、越界/截断 ELF 均失败。未来 `musl-static-v1` 的解析合同要求完全没有 interpreter 和 dynamic needed，允许静态 PIE；其生产原生收集/构建尚未实现，当前 native contract 会拒绝使用该 profile。

新增签名制品为 `native-security.lock.json`、`native-inputs.tar`、`native-provenance.json`、`native-components.cdx.json`、`native-components.spdx.json`、`native-components.grype.json`。构建器的附加无网络阶段继承同一个实际 Rust builder，导出全部八个二进制、Cargo.lock、checksum 锁定的 libsqlite3-sys/ring `.crate` 和实际展开源文件、实际 rustc/sysroot rlib、GCC CRT 静态对象及其 dpkg 所有者/版本。归档前逐字节核对 crate/checksum/source，拒绝额外源文件或缓存篡改；安装时重新计算整个库存和两个 SBOM，不能只修改版本字段。完整固定 builder Syft 中的 CRT 包版本也必须一致。service/runner OCI 中实际运行二进制的哈希必须与这八个导出二进制匹配。

原生清单是有来源的保守编译输入范围，包含 SQLite C 实现、ring C/assembly、Rust std/unwind/compiler builtins/libc 和实际链接 CRT。它不宣称这些输入的每个文件进入每个二进制，也不把 CPE 命中当作项目可利用性结论；原生组件仍独立执行新鲜 Grype 扫描，High/Critical/Unknown 沿用相同发布阻断规则，原有八份报告全部保留。

2026-10-08 本机实际冻结源快照 `1f7d4fbda04808284decc1bec33b2bb1421d0fa2d96e7023cf536dcb9e16f7f8` 的七个 Linux AMD64 导出及 438 个原生输入已核对一致。实际嵌入的 SQLite 为 3.46.0；固定 Grype 0.120.0、扫描当时不足 24 小时的 v6.1.10 官方 DB 返回 1 Critical、5 High、0 ignored，发布继续阻断。真实证据位于本机 `.local/native-candidate-20261008/candidate-sources/` 和 `scan-summary-final.json`。该源点早于当前开发修改，不是当前 HEAD 或已签名发布。

## SQLite 固定源码静态升级

当前构建固定官方 SQLite **3.53.4**，保留 SQLx 0.8.6 / libsqlite3-sys 0.30.1 的 Rust/C ABI bindings，不更新其它 Cargo 依赖。[SQLx 0.8.6 的官方 SQLite 约束](https://docs.rs/crate/sqlx-sqlite/0.8.6/source/Cargo.toml) 不接受提供更新 SQLite 的 libsqlite3-sys 版本；[SQLx 0.9.0](https://docs.rs/crate/sqlx-sqlite/0.9.0/source/Cargo.toml) 仍限制 `<0.38.0`，直接升级 SQLx 也不能得到需要的 3.53.2 以上 bundled 实现。因此使用现有 [libsqlite3-sys 的官方 external/static 链接入口](https://github.com/rusqlite/rusqlite/blob/v0.32.1/libsqlite3-sys/build.rs)，由同一个固定 Rust builder 编译官方 C 实现。

`native-security.lock.json` version 2 保存官方 autoconf 包 URL、3283177 字节大小、SHA256 `0e9483900e92cd5de8fd48d16bf9200145a61f7fd5be542a5ac81d8a9516eb9c`、[官方下载页](https://www.sqlite.org/download.html) 独立核对的 SHA3-256 `454e45f61c6bd75b7420e7190732dea03ce6639c63ada47bbc592f67fc340338`，以及 C/H 哈希、source ID、完整固定宏。编译时保留原 bundled 的 JSON、WAL、foreign keys、FULL synchronous、threadsafe、unlock notify 等合同；没有删除扩展或忽略漏洞来改变扫描结论。

Dockerfile 的 `ADD --checksum` 和无网络 `sqlite_build.py` 再次核验全部源码；实际静态 probe 检查版本/source ID、JSON 与编译选项。生产 `build.rs` 强制 Linux AMD64、固定私有 static library/include 路径和 3.53.4 头文件；`LIBSQLITE3_SYS_USE_PKG_CONFIG=1` 强制 external branch，`SQLITE3_NO_PKG_CONFIG=1` 禁止探测系统库，`SQLITE3_STATIC=1` 固定静态链接。缺源、缺库、宏漂移、变量或路径漂移立即失败。 C 实现以固定 `sqlite3.c` basename 编译，避免随机临时路径进入 `__FILE__` 和静态对象。每次真正执行新的 builder Cargo 阶段先清理 `libsqlite3-sys` 一个 release package，再构建七个二进制；external build script 不跟踪库内容，此处保证持久 target cache 不能保留前次原生对象。已缓存的同一 builder layer 无需再次执行清理。

同一次七二进制生产 Cargo RUN 使用官方 [JSON build-script 消息](https://doc.rust-lang.org/cargo/reference/external-tools.html#build-script-output)，把完整回执保存为 `native-inputs.tar` 内的 `sqlite/production-cargo.json`。封存工具按 Cargo.lock 的精确 package ID 和该次回执的 `out_dir` 读取生产 host/target 输出，要求七个正常 O3 二进制、成功的 build-finished、每份都链接固定 static archive，并且各输出及 bindings 字节完全一致；不同输出立即失败。成功字段必须是 JSON 布尔值 `true`，数字、字符串和 null 均拒绝。共同字节与回执在该 RUN 结束前固定到镜像层，后续测试及库存阶段仅复制该证据。不能用共享缓存里的 `find/head` 任意挑一个，也不能把测试阶段新产生的 build-script 输出回填成生产证据。没有新增 Cargo 依赖版本或放宽扫描合同；旧候选不含这份回执，必须重新构建，不能补写文件获得验收。

正常发布的 native exporter 必须继承同一个实际 builder，以 `cargo test --release --test nodeguard_journal_native` 链接生产 O3 库，先执行两项固定公开接口回归（关闭 UID 跨重启保持关闭、失败 open 的事务回滚与连接排空），再执行五项明确 ignored 的 Linux 专项：SQLx 实际版本/PRAGMA、真实 writer busy 失败与恢复、约束事务回滚、损坏拒绝、三个真实 `process::exit` 的 WAL 恢复和 START 不重放。五项名称和两个普通回归必须逐一出现成功行，零失败、零 ignored；缺测试就不能导出合格 native 库存。独立临时数据库 SQL 仅用于测试夹具预置可信节点登记状态和核查持久数据，不能冒充生产 pool 的连接设置；版本/source ID/compile options 和 WAL/synchronous/foreign keys/busy timeout 均来自 `GateJournal::storage_diagnostics()` 对实际内部连接执行的固定只读查询。该诊断不暴露 pool、路径或任意 SQL，也没有新增 HTTP 功能声明。归档绑定实际官方 source tar、C/H、ELF object、`libsqlite3.a` 单对象成员、未改动 bindings、Cargo 的真实 static link 输出、运行版本/选项及测试日志。旧 crate 内的 3.46.0 C/H 仍按 checksum 验证并记录为 **unused bundled implementation**，不能假称它们编译成新版 SQLite；新 CPE/SBOM 版本从真正固定源码与执行证据产生。

2026-10-08 固定公共源快照 `c575206ab4bb51e3177aac08253968125940277373c71f6c1693e08c24f97364` 的真实 Linux AMD64 七个生产二进制完成编译，原日志回归 10/10 通过，SQLite 专项 4/5 通过。约束回滚专项在创建测试触发器时因保留的 `sqlite_` 名称前缀返回 code 1，尚未执行回滚断言；该候选失败且没有导出合格原生库存、镜像或扫描。完整失败日志和原 Keycloak 配置不变且恢复 healthy 的结果保存在 `.local/sqlite-release-candidate-20261008-v2/`，后续修复必须使用新的源码清单，不能覆盖该失败源点。该源点也早于后续 CONTROL listener、投射凭据和启动失败排空修复，不能代表当前 HEAD 或完整生产验收。

后续公共源快照 `4fe5f66ade3e3e083251f6735303947024da7ee16b9496562d178cac77ec300a` 的真实 Linux 七二进制、两个普通生产接口回归和五个 SQLite 专项均通过，包含实际 SQLite 3.53.4 pool、WAL 子进程恢复、busy/损坏/回滚断言。两个普通接口回归与旧十项 unit 的计数和覆盖范围分别记录。该候选在库存导出时发现两份正常 host/target 链接输出而失败；只读诊断已保留成功的原测试日志，但没有合格库存、镜像或新版本扫描。原始失败及配置不变且恢复 healthy 的 Keycloak 结果保存在 `.local/sqlite-release-candidate-20261008-v5/`。上述即时封存修复须由更新的独立源点实际验证。

新的不可变668文件v6源点 `7be7c22a0af3765adbd4033f32bfcd18f7658497f8ae4c794246136c2aa41ca3` 已实际完成七个Linux GNU生产ELF、两个O3公开接口回归和五个强制SQLite测试，导出并验证451项输入、两份一致的实际host/target SQLite输出、七个production artifact与真实布尔success。固定新DB下native-components和rust-binaries均零匹配；实际service/runner OCI的二进制SHA与库存一致，非root/只读启动及真实命令检查通过。service的11High、runner的54High仍阻塞，builder原报告也阻塞且含默认内核头文件抑制。原失败报告保留。公共Grype配置现显式match-upstream-kernel-headers=true扩大扫描，不通过忽略规则消除结果；重新扫描与全部发布门禁必须使用实际完整descriptor/configuration/DB证据。v6未包含随后Cargo JSON数值bool拒绝修复、最新恢复控制及备份标签；这是候选阶段证据，不是当前HEAD发布认证。

扩大后的实际builder扫描为206Critical、1144High、1002Unknown，合2352阻断、0ignored；报告SHA256 `94700bcb863871835fcb0443045461757104044fa7ad259b30139b161e0dad23`。新校验器严格核全部effective configuration及官方DB身份，并过滤继承的`GRYPE_*`/`SYFT_*`环境变量；各report的schema/from含checksum/built须与同次`database.json`一致。唯一可变化的cache路径仍须与实际DB路径一致。61项协议测试涵盖隐藏过滤、backend、VEX、EOL、JSON类型和历史报告缺配置；先验签后的历史DB检查使用签名gate时间，风险例外仍按当前时间检查。该实际报告只证明新配置和DB校验已执行；完整新8scope发布报告集尚未完成，不能将其标为正式发布PASS。收据 `.local/release-scanner-strict-evidence-20261008.json`。

本机普通开发 Cargo 未显式启用生产构建环境时仍使用原 bundled 库；上述发布专项刻意不在该路径宣称通过。只能由正式 Linux builder 的实测结果确认生产升级。新源点的八二进制、完整库存、日志验收和新 DB 扫描仍需实际执行；未完成前整个产品仍不可发布。

## Debian 安全补丁锁

runner 的 OpenSSL 与 PCRE2 安全更新保存在 `scripts/release/debian-security.lock.json`。目前固定 `libssl3t64` / `openssl-provider-legacy` 的 `3.5.7-1~deb13u3` 和 `libpcre2-8-0` 的 `10.46-1~deb13u3`；Dockerfile 使用官方 Debian HTTPS URL 和 `ADD --checksum`，随后 `dpkg -i` 安装固定文件，逐包检查实际版本并删除安装包。没有浮动软件源、依赖解析或自动升级，也不删除 dpkg 元数据绕过扫描。

补丁审阅必须先用固定 Debian archive keyring 验证官方 `InRelease` 签名与有效期，再用该 Release 中的 SHA256/大小核验 `Packages.xz`，最后核验目标包的名称、架构、版本、大小和 SHA256。本轮使用 `debian-archive-keyring 2025.1` 中的 trixie-security 公钥，通过 `sqv` 验证可信签名 `5E04A1E3223A19A20706E20F9904613D4CCE68C6`。源索引哈希和实际软件包哈希随锁文件提交，不把未经签名索引验证的 HTTPS 下载当作 Debian 发布证明。更新时由审阅者明确修改锁及 Dockerfile，再做完整构建、运行 smoke 和扫描；工具不自动改锁。

本轮审阅到期为 2026-10-10 08:45:53 UTC，与该索引的 `Valid-Until` 一致。构建和离线安装均要求本地经独立审阅的锁与签名发布内的锁完全相同且仍在有效期；过期阻断，不能临时延长期限来跳过安全审阅。包锁不是漏洞例外，修复包仍接受完整扫描。

## SBOM 与漏洞门禁

构建为四个镜像和宿主二进制生成 Syft JSON、SPDX JSON；另外扫描完整固定 Rust builder（覆盖 HAProxy 复制的 OpenSSL 与构建依赖）、固定 Node builder 和 HAProxy 源码组件 CycloneDX。扫描 builder 有意采用保守范围，不把构建工具风险伪称为运行库风险；报告保留组件来源供评审。

Syft image 默认不会收集声明式 Cargo.lock，因此流程显式启用 `rust-cargo-lock-cataloger`，并要求 service、runner 和二进制 SBOM 包含 `Cargo.lock` 中**每个 registry crate 的精确名称/版本**。这是全工作区依赖的保守上集，不宣称每个 crate 都链接进每个二进制。漏掉 Rust 依赖立即失败。

Grype 首先下载并验证官方 DB；有效构建时间必须在 24 小时内，扫描时禁用自动更新保证同批次一致。九份报告必须齐全、版本正确，无忽略或 EOL 告警。High、Critical、Unknown 均阻断，无论上游是否已有修复。扫描器超时/退出非零、数据库失败、格式变化也阻断，绝不通过 `continue-on-error`、`|| true` 或空报告过门禁。

`risk-exceptions.json` 默认空。确需接受风险时必须经仓库 review，逐条固定 artifact、漏洞 ID、package、version、PURL、severity、责任人、评审链接、原因、批准时间与到期时间，最长 30 天。禁止通配符；过期、未来批准、未被本次扫描实际使用的例外均失败。工具不自动生成批准。离线安装会再次检查例外的当前有效期。原始扫描时间保留在签名清单内；验签证明发布时的检查，不证明后来没有新 CVE，生产还须按当前数据库持续复扫。

本地 2026-10-03 对原固定 Debian bookworm 服务镜像的真实检查，在补齐全部 419 个 registry crate 后仍发现 High 60、Critical 7、Unknown 16；未设置例外，发布应被阻断。证据位于本机 `.local/release-scan-validation/`，该目录不进 Git。随后对官方当前候选只读复扫：Debian 13 slim 为 High 63、Critical/Unknown 0；Distroless cc-debian13 为 High 11、Critical/Unknown 0。服务已选择后者缩小运行依赖，runner 选择前者保持 shell 合同；实际服务应用镜像已完成 non-root/只读/无网络 smoke、loader依赖检查和 Docker离线导出，复扫结果同样为 High 11、Critical/Unknown 0；SBOM为14个deb及420个Rust组件，419个registry crate全覆盖。runner应用镜像也已实际完成非root/只读/无网络的health及`/bin/sh`命令协议验证、导出和包含Rust依赖的复扫，结果为High63、Critical/Unknown0。汇总证据在`.local/release-scan-validation/summary.json`。剩余 High 继续阻断，无豁免。不能用隐藏报告消除风险。

## 首次启用发布

仓库管理员先配置 `production-release` environment，设置 required reviewers、禁止 self review、只允许发布标签。另设生效的 repository tag ruleset，至少禁止匹配标签更新和删除，审阅 bypass actors；组织规则之外，本工具要求等效 repository ruleset 以免错误推断继承规则。发布脚本读取实际 environment 与 ruleset；缺失或 GitHub API 失败就停止。仓库还应通过 CODEOWNERS/保护分支约束 workflow、工具锁、信任根和风险清单变更。

显式选择 `mode=publish` 后，独立 environment 受审作业才取得 `packages:write`、`contents:write`、`id-token:write`；build 作业没有发布权。发布先复查同 commit CI、标签、扫描和清单，再向 `ghcr.io/<owner>/<repo>/{service,runner,identity-proxy,console}` 上传候选摘要并验证远端 digest，一一 keyless 签名。凭据通过受控环境/标准输入传递，不进入 argv、清单或日志。

最终用 GitHub OIDC 对 release-manifest 的 SLSA v1 provenance 做 `cosign attest-blob`，包含固定 workflow identity、源标签/commit、run URL、所有制品哈希及镜像 digest。先在 GitHub Draft Release 上传完整资产；全部成功才公开。任一步失败不产生可安装的完整签名发布；可能留下未公开 draft 或 registry 候选，需人工检查后清理，工具不覆盖旧 release。本文不授予当前会话执行 publish 的权限。

## 断网验证与安装

在可信机器取得本仓库经审阅的 release 工具和工具锁，通过 `install-tools.py` 获取校验过的工具，然后将工具、`trusted-root.json`、发布包一起带入隔离部署环境。校验器与信任根必须来自独立可信渠道，不能执行未验签压缩包自带的脚本。Python 3.12 与 Linux AMD64 是部署工具运行要求；工具目录和安装父目录应由部署操作者独占写权限。

从变更审批记录取得 repository、tag、commit，不能复制不可信清单的自报值作为期望值：

```sh
python3 scripts/release/verify.py \
  --directory /srv/release-download \
  --tools /opt/release-tools \
  --repository "$REVIEWED_REPOSITORY" \
  --tag "$REVIEWED_TAG" --commit "$REVIEWED_COMMIT" \
  --output /srv/reviewed-deployment-lock.json
```

`verify.py` 验证 Sigstore bundle 的证书链、SCT/透明日志证明与本地固定信任根，严格核对 GitHub issuer、workflow URI、workflow trigger、repo、ref、commit，不允许 `insecure-ignore-*`。bundle 已携带全部证明，传入本地根后无需在线查询；网络隔离应由部署环境施加。之后复核 SLSA 源绑定、每个文件哈希、镜像每个 blob、平台/non-root、扫描覆盖及风险期限。任一失败不写 deployment lock。

实际本地制品安装入口：

```sh
python3 scripts/release/install.py \
  --directory /srv/release-download --tools /opt/release-tools \
  --repository "$REVIEWED_REPOSITORY" \
  --tag "$REVIEWED_TAG" --commit "$REVIEWED_COMMIT" \
  --destination /opt/sandbox/releases/approved-release
```

该入口先执行相同验签，再复制二进制和 OCI archives，复制后重算哈希，原子发布到**全新目录**。验签失败或目标已存在则拒绝，不安装未签名候选。不自动启动服务、不改现有部署、不自动执行生产迁移。节点安装器使用该目录的 nodeguard 及已验证 SHA；Kubernetes 配置使用 deployment-lock 中的 digest references，仍须经过该组件的权限、runtime certification 和部署验收。绕过这个入口手工复制二进制不具备发布验证保障。

信任根轮换通过单独 review 更新固定 Sigstore 官方 commit/SHA，并用新旧已发布 bundle 做离线验证；不从待验证包导入新根，不在失败时自动回退在线信任。离线验证失败需补齐正确证据或审核工具/根更新，不能关闭校验。

## 当前可复核证据与限制

本包包含离线结构/故障测试、官方 Cosign 公开签名 fixture 的真实断网验签及三个拒绝用例、临时本地测试密钥的 Statement v1 真实签验往返（篡改与生产身份替换被拒绝）、真实本地服务镜像构建/运行检查和真实 SBOM/扫描。公开 fixture 是 Sigstore 自己的 cosign 二进制签名，只证明工具和离线链可工作，绝不是本项目的发布证明。当前未执行 registry push、GitHub Release、GitHub OIDC signing；完整人工环境规则和发布链必须在实际仓库启用后验收。

官方接口：[Cosign 验签](https://docs.sigstore.dev/cosign/verifying/verify/)、[GitHub environments REST](https://docs.github.com/en/rest/deployments/environments)、[GitHub rulesets REST](https://docs.github.com/en/rest/repos/rules)、[BuildKit](https://github.com/moby/buildkit/tree/v0.33.1)、[Syft cataloger 选择](https://oss.anchore.com/docs/guides/sbom/select-catalogers/)、[Grype 配置](https://oss.anchore.com/docs/reference/grype/configuration/)。工具版本与信任根的实际来源在 tools.lock.json。


## 控制台发布、前版资产和 Node 依赖

Release workflow 的 `console_first_release` 默认 **false**。首次显式设 true，预检与发布复检确认同仓库尚无已公开 `console.oci.tar`；已有控制台的仓库不能用该开关跳过资产校验。后续必须输入最新已公开版本的 `console_previous_tag` 和精确 `console_previous_commit`，两者不可缺省，远端标签必须仍指向该 commit。校验标签/commit 和现有签名都不授予本会话发布权限。

只读 build 作业用 checksum 锁定的 gh 下载既有 release 的 manifest、provenance、Sigstore bundle，再按外部指定 repository/tag/commit 和本地固定 Fulcio/Rekor roots 验签；之后只下载固定制品白名单。build.py 再次验签并验证每个文件、OCI blob、provenance、历史扫描证据后，才从已认证的 console OCI 读取内容哈希 assets 与 npm 清单。旧扫描只说明旧发布当时的证据；旧 JS 的依赖将在新发布重新扫描。调用方任意未认证的 assets 目录不作为正式输入。

历史核验只能由已完成上述验签的 `verify_previous` 内部调用，按前版发布时间核验其签名内的工具版本、补丁审阅期限和扫描证据，允许当前工具或补丁锁已正常更新。该核验不会生成安装 lock；`verify.py`、`install.py`、`preflight.py` 没有历史模式开关，安装新版本仍要求当前独立审阅的工具、Debian 与控制台安全锁完全一致且未过期。前版的过期扫描与补丁不能作为新发布的安全依据。

仅在独立临时 context 中合并被验证的资产，原干净源 checkout 不改动。selected OCI 文件必须是有限 regular file，不接受路径穿越、符号/硬链接、影响受信任目录的 whiteout。console 只允许 UID/GID `101:101`，其他组件不能借该规则使用该身份。首次/前版 manifest hash/console digest 绑定到 release manifest 与 SLSA externalParameters，安装 verifier 也检查该绑定。当前保守保留前版全部资产和依赖，达到 200 文件/40 MiB/30 npm 清单限制时停止构建，必须先完成受审查的资产保留政策调整，不能以首次开关绕过。

运行镜像把当前 `package.json`/`package-lock.json` 及被保留旧 JS 对应 npm 清单放到非 HTTP public root 的 `/usr/share/sandbox-console/`。signed file inventory 的 `console-npm-locks.json` 必须与真实镜像图层逐项一致。显式启用 Syft 的 [JavaScript lock cataloger](https://oss.anchore.com/docs/capabilities/javascript/) 和 `include-dev-dependencies: true`，要求当前/被保留清单的每个 npm 精确名称/版本（含传递、作用域和开发依赖）出现在 console SBOM，否则拒绝。console runtime 及固定 Node builder 都执行新鲜 Grype 扫描；所有 High/Critical/Unknown 使用同一失败关闭风险门禁。console OCI 与其 scan/SBOM/npm 清单一并受 manifest 签名约束，上传后也逐 digest 签名/verify。

控制台使用固定官方 Nginx unprivileged Alpine Slim 镜像，不加载未使用的图像处理模块。`scripts/release/console-security.lock.json` 固定官方 Alpine v3.24 的 `zlib 1.3.2-r1` 两个架构 APK URL、SHA256、大小和官方签名 key；`ADD --checksum` 后，在无网络且无软件源的构建步骤中用 APK 默认签名校验安装所选架构包，再核对实际安装版本、删除安装包。不会使用 `--allow-untrusted`、浮动升级或移除包数据库。最终镜像仍为 `101:101`，只读运行；实际 SBOM 必须包含修复版本，安全锁及 Dockerfile 漂移、审阅过期均阻断发布。

现有真实本机证据包括 Linux amd64 OCI/hash/UID/npm 提取和 native Syft 覆盖，以及实际非 root/只读 TLS/Host/CSP/cache/404 测试；离线协议测试明确使用合成 fixture，不代表项目已发布或真实云验收。项目尚无受审签名的前版 release 时，后续链路的正式成功不能伪造，本地只验证其负例、结构和可信签名工具。

2026-10-08 最新控制台 Linux AMD64 本地 OCI 候选 `sha256:574604b8da8ce3189739679771c8510538f1d847a18203956c8ac4267070b7f5` 已用实际 Syft 1.54.0 和 Grype 0.120.0 复扫：94 个锁定 npm 名称/版本全部覆盖，包含产品根包时为 95 个 npm，另有 21 个 APK；官方 v6.1.10 DB 构建于 2026-10-07 06:31:48 UTC，扫描时有效且不足 24 小时。结果为 3 个 Medium，High/Critical/Unknown、忽略和 EOL 告警均为 0。实际 TLS/Host/健康路由/CSP/只读 UID101 测试通过；仅修改官方 APK 一个 RSA 签名字节的负例以 `BAD signature` 拒绝安装。汇总及各真实制品 SHA 在本机 `.local/console-release-final-evidence-20261008.json`，不进 Git。这只覆盖控制台候选；服务、runner 和其他 builder 的门禁独立执行，整个产品不能因为控制台通过而宣称发布安全或上线验收完成。
