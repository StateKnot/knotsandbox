# 沙箱平台方案索引

当前开发基线是 [Rust 沙箱平台生产开发方案](rust-sandbox-production-development.md)，包含独立 Keycloak / 企业 OIDC 双模式、阿里云参考部署、八项产品能力、API、状态和数据模型、安全、恢复、测试及上线验收。

在线文档：[Rust 沙箱平台生产开发方案](https://chatgpt.com/space/page_02a97e1cc7f88191a9012b3fd6475ec4)。已核对页面正文与本地源文档内容一致。

这是设计文档，当前目录尚未包含已实现或通过生产验收的产品代码。

执行拆分见[分阶段开发表](rust-sandbox-development-workbreakdown.md)及[在线开发表](https://chatgpt.com/space/page_7afe87e785388191aa8c665b7270cbb2)，共6个阶段、54个工作包，附TTL、续期、闲置停止及数据保留的专项开发与验收要求。

- [可行性预研](rust-sandbox-feasibility.md)：背景与备选方案，后续冲突以生产开发方案为准。
- `dev-api-review.md`、`dev-runtime-review.md`、`dev-delivery-review.md`：主方案形成过程中的专项评审工作稿，部分细节已由主方案修正，不作为独立开发基线。
- `reference-platforms.md`、`ecs-mapping.md`、`isolation-review.md`：原始调研笔记。
