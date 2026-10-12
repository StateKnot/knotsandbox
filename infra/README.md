# 生产基础设施

`alicloud/` 是阿里云单地域生产资源定义，预生产与生产使用同一份代码、不同账号/凭据/状态和显式输入。没有可直接花钱的地域、可用区、镜像、规格或网段默认值。`alicloud/state-bootstrap/` 仅负责在空环境中先建立远端状态与锁，不是第二套沙箱部署。

本次交付为 **官方 provider 校验通过的 IaC 源码与离线测试**。尚未执行云端 plan/apply，尚无任何地域/SKU/Kata/Cilium/CSI 认证、真实备份恢复或上线证据。安装顺序、输入合同、权限及外部验收见 [阿里云基础设施交付说明](../docs/alicloud-infrastructure.md)。

```bash
python3 infra/alicloud/install-terraform.py
TF_BIN="$PWD/.local/tools/terraform-1.14.7/terraform" infra/alicloud/check.sh
```

安装脚本只从官方固定版本地址下载，校验仓库中的 SHA-256，安装到 `.local/tools`；检查脚本仅做 backend-disabled init、fmt、validate 和 mock-provider tests，不连接云账号，不创建资源。Terraform/Alibaba provider 分别锁为 1.14.7/1.293.0；两份 `.terraform.lock.hcl` 必须提交。升级版本须重跑测试并复核实际云兼容性。
