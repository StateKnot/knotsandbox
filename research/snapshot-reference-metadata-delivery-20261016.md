# Snapshotter 与配置引用元数据读回

日期：2026-10-16。切片 **P1b6**：本机管理消费者只读核对已存OCI的ChainID、固定overlayfs快照及config引用标签。完整P1的实际pull选择、原生保护租约／GC及准备硬限仍未完成；pre-pull保持关闭。

## 生产行为与证明范围

新增公共 `nodeguard::native_image_metadata::inspect_snapshot(reference, expected_digest, platform)` 及实际 `sandbox-admin image-artifact inspect-snapshot`。Linux root、独立expected digest、精确平台、固定root UDS／peer对象绑定、`k8s.io` 和containerd2.3.5沿用。snapshotter固定overlayfs；没有调用方指定key、mount、路径、handler、socket、namespace或凭据参数。旧离线／native／CRI消费者与回执保持。

在原已验OCI闭包上按认证config DiffID顺序推导ChainID／直接父ChainID，首层为该DiffID，后续为sha256(旧ChainID＋ASCII空格＋新DiffID)。不以压缩层摘要代替DiffID；零层返回SNAPSHOT_NOT_APPLICABLE，不查空snapshot key。只验证最终快照与直接父名称，不遍历完整祖先或GC可达闭包。

连接及整个RPC链共用原5秒：Version→原Get/Info/Read闭包→config Info A→Stat A/B→config Info B→最终Get。config digest／size须匹配已验配置，指定 `containerd.io/gc.ref.snapshot.overlayfs` 标签值须为ChainID；Stat名称／父／Committed kind3匹配。核前后创建／更新时间，缺失或protobuf范围／顺序冲突拒绝。每个新unary64KiB，128标签、键值单对4096字节、累计48KiB；原单blob1MiB／累计3MiB／64帧保持。其他标签、目录、mount、物理用量和提供方错误正文不回传。

回执scope=NATIVE_SNAPSHOT_REFERENCE_METADATA_ONLY，含snapshotter、chain_id、可空parent_chain_id、reference_label_matches／snapshot_committed_observed为true及原native回执。approval_checked／pull_selection_checked／runtime_handler_checked／layer_payloads_verified／gc_protection_checked／preparation_allowed全false。新增5个稳定snapshot错误，CLI失败stdout为空、stderr只有固定前缀与code。

多次读取不是原子事务，不取得lease或拥有资源。空的committed snapshot也可能通过检查；层载荷是否正确apply、快照内容完整、实际pull／Kata snapshotter、未来GC保护、Ready／HIT／物理释放都不由本片证明。没有产品pull／unpack／lease／snapshot写RPC，也没有新增HTTP、迁移或OAuth权限。

## 固定官方来源与许可证交付

ChainID依据[OCI身份算法](https://github.com/opencontainers/image-spec/blob/v1.1.1/identity/chainid.go)；固定服务[Snapshots协议](https://github.com/containerd/containerd/blob/v2.3.5/api/services/snapshots/v1/snapshots.proto)的Stat按精确snapshotter/key读Info。[Go IsUnpacked](https://github.com/containerd/containerd/blob/v2.3.5/client/image.go)也依赖ChainID Stat，不能据名称存在推断层apply；相同源码的unpack后流程另写config的snapshotter引用标签。

新增官方Snapshots／Mount两份原始协议保持完整Apache头及固定Git blob／SHA256，与原WKT输入生成私有消息，不生成写客户端。CI重生成核对五个native消息文件及原CRI；无运行时依赖／锁文件变化。[来源与固定摘要](../vendor/containerd/v2.3.5/README.md)

native-protocol-notices当前schema2包含八个协议输入及五个native生成文件、完整Apache/BSD许可证。manifest仍v4；当前生成／验证／安装只接受2，原已认证historical读取仅接受完整固定schema1或2，混合／缺摘要／任意版本拒绝。旧v4的schema1语义保留，不能借历史模式产生安装锁。四个Docker交付目标继续COPY完整vendor／来源／真实producer JSON；项目原创MIT不覆盖第三方许可。没有签名或公开release。

## 实际验收

精确基线 `ee3eeac55a44726aad2d4f8aed8710cd1005d679`，[CI run38861416715](https://github.com/StateKnot/knotsandbox/actions/runs/38861416715) 五job／72step全成功。远端完整1109文件与干净公开副本的blob SHA／mode逐项一致；新提交完整树及CI独立核对，不沿用基线。

| 验收 | 最终结果与证据 |
| --- | --- |
| Rust普通测试 | 65程序，520通过／0失败／291环境专项ignored；ordinary-tests-v2.log，不把ignored计实测 |
| 新行为合同 | 3项typed ChainID＋4项真实HTTP/2测试，包含31类坏路径、直接／index／单层／两层、空rootfs无Stat和原5秒总期限；纳入上述520 |
| 质量门 | Mac与Linux严格all-target Clippy及fmt通过；clippy-host-v2.log、linux-build/clippy-v2.log、fmt-v2.log |
| 最终真实containerd＋CLI | snapshot-final、cri-regression-final、native-regression-final、peer-regression-final、profile-regression-final、image-regression-final各1通过／0失败／0忽略；各record.json核源码／制品／精确清理 |
| 最终离线CLI | offline-cli-regression-final七场景通过，实际最终admin制品／输入稳定及自有清理保持 |
| 分发／历史兼容 | release-tests-root-v1.log：104项通过；当前schema2／历史固定schema1核验，原签名与安装边界保持 |
| 验收脚本与协议生成 | 既有runner Python11项通过，protocol-regeneration-final.log核对原CRI及5个native生成文件 |
| 实际许可输出 | license-copy/record.json：Linux真实producer schema2、四生产Docker路径原COPY行导出56文件，逐项字节／mode匹配；非完整release构建／签名 |


最终源码副本1115文件／16,351,260bytes，只含源码／锁／必要配置；没有复制target、node_modules或Git。Rust使用既有host／Linux低debug、无incremental缓存，单编译并发；Linux编译维持既有4GiB物理／8GiB memory+swap、2CPU／256PID、UID501:20、无网络／只读／cap-drop ALL。编译前df、各缓存20GiB内、可用空间大于50GB。日志及回执在缓存外 `.local/snapshot-identity-20261016/`。

首轮520普通与全部真实行为、两平台Clippy已通过，但root新增CLI一处anyhow!换行未过fmt，原fmt-v1.log保留。只做rustfmt格式修正，冻结v2；重新生成最终Linux lib/admin回执、重跑最终普通与质量门，以及同一最终制品的所有native／CLI场景。最终结果按v2统计，不把旧CLI验收或两轮计数相加；没有权限、期限或线程栈扩展。

真实fixture遵守原networknone、readonly rootfs、cap-drop ALL／no-new-privileges、768MiB memory/swap、1CPU／128PID、nofile1024与45秒case。在自己独有daemon中通过ctr无mount参数的Prepare→Commit创建空单层快照元数据并设置自有config标签；无layer apply操作。case结束精确去标签／删除自有snapshot，原image-not-unpacked、无snapshot/container/task后置门及owned container/image cleanup保持。这个正例专门限制metadata检查的意义，不能计为真实解包或Kata认证。

本轮五个自有已停止编译／许可容器的真实inspect已保存并精确删除，未删除共享镜像或卷。最终df可用307,182,532KiB；保留复用host／Linux／codegen缓存约6.66／2.12／0.13GiB，各小于20GiB，无需缓存回收，缓存清理释放量为0。私有清理回执的Docker错误文本大小写及保留缓存tag假设失败均已留存，最终absence／保留清单已核；不把du合计或背景磁盘变化算成释放量。

## Standards

独立Standards复核最终27文件SHA／mode一致；标准违反0项、有意义Fowler smell 0项。最终520普通、六项原生／离线七场景、release104、Python11、协议生成、两平台质量门及56许可输出原始证据均核对通过；v1→v2仅CLI格式。七份文档的metadata／apply／GC／准备边界准确，原资源／权限／期限／线程栈保持。

## Spec

独立Spec复核最终27文件，新增及剩余发现均0项；1115文件／16,351,260bytes源码副本、最终lib／普通admin、217条命令日志SHA及各receipt一致。最终实际case、否例、原接口回归、历史notice兼容与源码来源符合合同。第三路只读证据核验也通过；空committed快照的正例只验证元数据，未替代真实apply、原生保护闭包或准备硬限。

## 下一依赖

下一完整门转向真实受限准备执行者、存储／inode／临时空间、内存／FD／专用网络槽及正常runtime保留量；限制客户端不足以限制共享daemon下载／解包。结合实际pull manifest／平台／handler／snapshotter、native lease/content/snapshot保护与GC／崩溃对账证明一套受支持组合；无法隔离的profile不开放准备。继续增加布尔诊断不能替代该门。

P2—P6、云／Kata／CSI、真实GPU、冷暖分位数和单位成功任务成本仍未完成／未认证；pre-pull保持关闭。
