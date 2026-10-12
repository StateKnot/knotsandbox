# 本地镜像安全检查

2026-10-08 的较早本地候选镜像检查已完成。服务和 runner 均通过 Linux amd64、非 root、只读根文件系统、无网络和移除全部 capability 的启动检查；runner 实际执行命令并验证最终退出帧。这些镜像没有发布、签名或部署。下表为较早候选；新的不可变v6候选与扫描证据在文末单列。

| 候选 | 平台 manifest digest | Rust 锁定依赖覆盖 | High 匹配 | 独立 CVE 数 |
|---|---|---|---|---|
| service | `sha256:fb36072712b807a9063cf347db3a956562ca4d4ca678da998f2cda89b728040a` | 446/446 | 11 | 5 |
| runner | `sha256:2a86d7bbd832055f103d1df79709a920dc1d678622959e8d656e56b42152dc43` | 453/453 | 54 | 14 |

固定版本的 Syft/Grype 与 2026-10-07 构建的有效漏洞数据库用于检查；镜像层、平台 manifest、config 和内置 Cargo.lock 分别校验。没有忽略规则，Rust crate 没有 High/Critical/Unknown 匹配。阻塞匹配来自基础系统包，多个二进制包可能映射同一来源包 CVE，因此表中两列不能互换为“已确认可利用漏洞数”。

OpenSSL/PCRE2 的内容寻址 Debian 安全补丁实际安装并进入 runner 镜像，但基础包的其余匹配仍阻止发布。例如，官方 Debian 跟踪页将当前 trixie 的 [glibc DNS 打印函数问题](https://security-tracker.debian.org/tracker/CVE-2026-5435)、[glibc 格式化问题](https://security-tracker.debian.org/tracker/CVE-2026-19499)和 [libstdc++ 分配问题](https://security-tracker.debian.org/tracker/CVE-2026-95619)记录为尚未在该发行版修复；供应商的较低紧急度不自动修改本项目门禁。[zlib 跟踪记录](https://security-tracker.debian.org/tracker/CVE-2026-85091)同时存在受影响范围的讨论，尚需把实际包代码与上游引入/修复提交对照，不能仅凭包名判断可利用性或自行忽略。

当前风险例外表为空。应继续通过受支持基础包更新、移除实际未使用的组件，以及精确的来源/调用路径核验解决匹配；没有将 `not-fixed`、`wont-fix`、只读容器或 Kata 隔离当作豁免。发布门禁继续返回阻止状态。

此处是两个本地候选的证据：构建期间工作树仍在变化，两个镜像的 Cargo.lock 不同，也没有捕获统一不可变源码快照。不能据此声称当前 HEAD、所有组件或整套产品完成发布验收。正式流水线仍须对同一干净 tag/commit 构建全部制品并扫描控制台、身份代理、宿主二进制和构建输入，完成完整性、签名、部署前验证。

本机报告保存在被 Git 忽略的 `.local/release-security-20261008/`：

- `validation-summary.json`：候选 digest、启动检查、依赖覆盖和阻塞状态。
- `service.grype.json`：SHA256 `5dd40266eb77cfc7baf067aa9069a4b8b026ece1eb57629790675d0590bdc757`。
- `runner.grype.json`：SHA256 `95c52d98a1184c9467b7062a0df230f785d11f25fbfc0d45ee78504c805a6390`。

这些扫描报告仅是本地证据；正式发布使用流水线生成、完整签名且可独立验证的制品。

后续v6来自668个公开文件的不可变源点 `7be7c22a0af3765adbd4033f32bfcd18f7658497f8ae4c794246136c2aa41ca3`。实际7个生产ELF、451项原生库存、SQLite 3.53.4的2+5项回归及OCI二进制逐字节校验通过。两个OCI的非root/只读启动通过；当前恢复控制、备份标签及扫描校验器增量不在该冻结点，不能据此认证当前HEAD。

| v6扫描范围 | 实际制品或报告 | 阻断匹配 | 状态 |
|---|---|---|---|
| service | `sha256:e85cc45124b7c0fefebe82be62f59dd6efb9d2b81dec7ffc05375d264a8ed4a8` | 11 High | 阻止发布 |
| runner | `sha256:a1a708ff7eb87f9a60b0edaeae828863c212cd61b47070e037c03fde6d264916` | 54 High | 阻止发布 |
| native-components | 报告SHA `79414ea3d8798aff0f215deca360c2060c67e6484ad6c610c4f896a4f5783519` | 0 | 此范围通过 |
| rust-binaries | 完整v2报告SHA `f2d5feed9e1db6305f45c277edf2c7a105479b8dafa0f5791385d0dc1e744ed1` | 0 | 此范围通过 |
| builder，展开内核头匹配 | 报告SHA `94700bcb863871835fcb0443045461757104044fa7ad259b30139b161e0dad23` | 206 Critical / 1144 High / 1002 Unknown | 阻止发布，0 ignored |

固定Grype 0.120.0与官方v6.1.10 DB（built：2026-10-08 06:33:47 UTC）实际执行上述扫描。原builder报告的默认抑制2466项保留为失败证据；新配置显式展开并复扫，不创建风险例外。匹配数量不表示已确认可利用漏洞数量，不能跨范围相加宣称独立CVE数。新校验器严格检查报告effective configuration、官方DB来源/checksum/时间及独立DB一致性，61项协议通过；尚无完整8scope新报告集，aggregate门禁没有执行通过。详细证据在 `.local/sqlite-release-candidate-20261008-v6/` 和 `.local/release-scanner-strict-evidence-20261008.json`，整体发布继续阻断。
