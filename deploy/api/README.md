# API 生产部署包

`prepare.py` 将经过审阅的非秘密设置与 `infra/alicloud` 的真实 Terraform outputs 绑定，`render.py` 输出原生 Kubernetes List。使用同一个经过发布验证的 service OCI digest 运行 Rust HTTPS API、固定秘密文件初始化和短期 STS credential sidecar；没有 shell 初始化、生成口令或 apply 操作。

完整输入字段、私有文件权限、证书、数据库和上线检查见 [API 生产安装](../../docs/api-installation.md)。控制台上游固定为 `sandbox-api.sandbox-system.svc.cluster.local:8443`，使用同一 API CA 并验证该 SAN。

```sh
PYTHONPYCACHEPREFIX="$PWD/.local/pycache" .local/cluster-venv/bin/python -m unittest discover -s deploy/api/tests -v
.local/cluster-venv/bin/python deploy/api/schema_check.py
CARGO_INCREMENTAL=0 cargo test --locked --test api_deployment
```

测试 fixtures 的账号、证书、密钥和镜像摘要仅供本地契约测试，不是安装输入。部署激活必须运行共享 [网络策略配置预检](../../docs/policy-boundary.md)，随后另行验证实际数据包拒绝、真实 IdP/数据库/OSS、HA、密钥轮换和恢复。当前没有统一签名的安装候选或真实云验收，不可直接发布。
