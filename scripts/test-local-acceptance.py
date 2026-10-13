#!/usr/bin/env python3
"""Sequential local acceptance of implemented public control-plane interfaces.

Runs the existing review matrix plus explicitly scoped interface suites against
fresh PostgreSQL databases with distinct component logins. The exact historical
upgrade case starts empty and installs its own version-41 schema before upgrade;
all other suites use the current normal migrations.
The review fixture owns Docker, TLS, secret redaction, migration verification,
process/container cleanup and source/ordinary Cargo executable binding.

This does not build code or use an existing database. Kubernetes, ECS/STS, OSS,
nodeguard and Prometheus are authenticated local protocol substitutes in these
tests; this is not an installed cloud runtime, guest isolation, restore service
or production certification. Live automation execution and visible OIDC/BFF
demonstrations have their own runners and are intentionally excluded here.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("review_fixture", ROOT / "scripts/test-review-fixes.py")
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)

# (local group, ordinary Cargo target, exact case or complete namespace,
#  ignored test count, visible feature). Counts bind the advertised scope to
#  the ordinary test executable. Never select all ignored library tests.
ADDITIONAL = [
    ("lifecycle_authorization", "lifecycle_authorization", "", 1, "生命周期操作的实时授权"),
    ("gateway_ledger", "gateway_ledger", "", 6, "执行网关、单次连接与输出账本"),
    ("admission", "admission", "", 4, "运行授权与准入检查"),
    ("history", "history", "", 4, "操作记录、审计分页与权限撤回"),
    ("diagnostics", "diagnostics", "", 8, "健康诊断、范围隔离与有界锁等待"),
    ("instance_security", "instance_security", "", 8, "实例安全报告、脱敏与真实 Node SDK 调用"),
    ("http_readiness", "http", "", 1, "服务就绪与安装初始化状态"),
    ("review_regressions", "review_regressions", "", 1, "操作与工作区绑定约束"),
    ("event_stream", "sandbox_platform", "event_stream::tests::", 7, "事件流、断点续传与真实 Node SDK"),
    ("metrics_pg", "sandbox_platform", "metrics::tests::real_pg_metric_binding_is_scoped_and_rechecks_revocation_and_dr_epoch_after_io", 1, "监控查询范围、撤权与灾备代际"),
    ("execution_output_stream", "sandbox_platform", "execution_output_stream::tests::", 7, "执行输出流、完整性与真实 Node SDK"),
    ("termination_ledger", "sandbox_platform", "termination_ledger::tests::", 16, "可信终止证据与计算资源释放"),
    ("node_fencing", "sandbox_platform", "node_fencing::tests::", 9, "节点隔离与云签名协议"),
    ("volume_deletion", "sandbox_platform", "volume_deletion::tests::", 10, "持久卷销毁、保护与独立证据"),
    ("backup_ledger", "sandbox_platform", "backup_ledger::tests::", 4, "冷备份账本与实际 HTTP 契约"),
    ("backup_pipeline", "sandbox_platform", "backup_ledger::pipeline_tests::", 8, "备份流水线、签名清单与可信关闭"),
    ("backup_profile", "sandbox_platform", "backup_profile::integration_tests::", 2, "备份配置认证、注册与激活"),
    ("backup_job_create", "sandbox_platform", "backup_ledger::job_create_admission_tests::", 2, "备份 CAPTURE/SEAL 首次 Job 准入与记录"),
    ("node_enrollment", "sandbox_platform", "node_enrollment::tests::", 1, "节点真实 mTLS 注册与不可替换记录"),
    ("never_authorized", "sandbox_platform", "termination_ledger::never_authorized::tests::", 10, "未获执行授权的关闭、删除与调度准入"),
]
BASE_FEATURES = {
    "service_clients": "服务身份启停、绑定与委托撤销",
    "tenant_audit": "租户账户审计分页、脱敏、实时权限与身份复核",
    "automation_upgrade": "41→42→43 历史非空账务/回执/法律保护与已阅通知保留、UNKNOWN→FAILED 双状态独立来源/已阅/原键恢复、当前签名身份撤权及旧写入兼容",
    "timers": "TTL 到期停止、并发去重与公平扫描",
    "timer_worker": "实际定时器 Worker 监督与有界公平扫描",
    "worker_process": "独立 Worker 进程、启动检查、定时器与退出排空",
    "worker_dispatch": "持久队列提示、并发填充、断线重订阅与缺提示/到期租约恢复",
    "output_identity": "输出读取后重查身份与有效期",
    "action_scope": "OAuth 动作范围对变更、流与委托的限制",
    "bootstrap_prerequisite": "真实数据库 RLS 与事务租户上下文初始化前置",
    "bootstrap": "初始管理员与重复初始化保护",
    "grants": "授权创建、版本控制与实时撤回",
    "capabilities": "实际已实现能力与项目额度查询",
    "executions": "命令执行接受、幂等与状态机",
    "file_transfers": "文件上传下载、路径校验与内容完整性",
}
UNTESTED = [
    "公有云部署、Kata 来宾隔离和真实 CSI/Cilium 运行效果",
    "交互终端与公开恢复 API/listener（尚未交付）",
    "真实云运行结果、完整灾备、72 小时稳定性与容量认证",
    "完整历史升级与回退认证、滚动发布与统一签名发布产物",
    "实际自动化执行与真实 OIDC/BFF 浏览器验收（单独运行）",
]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def executable(path, label):
    require(path is not None, label + " executable is required")
    resolved = Path(path).expanduser().resolve(strict=True)
    require(resolved.is_file() and os.access(resolved, os.X_OK), label + " executable is invalid")
    return resolved


def sdk_fingerprints():
    directory = ROOT / "sdk/typescript/dist"
    require(directory.is_dir() and not directory.is_symlink(), "Build the actual TypeScript SDK first")
    result = {}
    for path in sorted(directory.rglob("*")):
        require(not path.is_symlink(), "SDK build output cannot contain symlinks")
        if path.is_dir():
            continue
        require(path.is_file(), "SDK build output must contain only regular files")
        result[str(path.relative_to(ROOT))] = {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "mode": path.stat().st_mode & 0o777,
        }
    require(all("sdk/typescript/dist/" + name in result for name in ("index.js", "events.js", "output-stream.js")),
            "The built public security/event/output SDK modules are required")
    return result


def preflight(args):
    # The user requires an actual df reading before local validation. Do not
    # equate directory sizes on shared APFS data blocks with available space.
    output = subprocess.check_output(["df", "-k", str(ROOT)], text=True, timeout=15)
    columns = output.splitlines()[-1].split()
    require(len(columns) >= 4 and columns[3].isdigit(), "Cannot establish actual free disk space with df")
    free = int(columns[3]) * 1024
    require(free >= 50 * 1024**3, "Local validation requires at least 50 GiB free; review task-owned rebuildable artifacts first")
    require(not any(os.environ.get(key) for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUST_MIN_STACK", "RUST_TEST_THREADS")),
            "Compiler, stack and test-thread overrides are not accepted for ordinary acceptance")
    binaries = review.artifacts(args.artifacts)
    evidence = args.evidence_dir.resolve()
    require(not evidence.exists(), "Acceptance evidence must use a new directory")
    require(not evidence.is_relative_to(binaries["sandboxd"].parent.parent), "Save acceptance evidence outside the Cargo target")
    node = executable(args.node or shutil.which("node"), "Node.js")
    node_version = subprocess.check_output([str(node), "--version"], text=True, timeout=15).strip()
    require(re.fullmatch(r"v\d+\.\d+\.\d+", node_version) is not None and int(node_version[1:].split(".")[0]) >= 22,
            "Node.js 22 or newer is required for actual SDK TCP tests")
    openssl = executable(args.openssl or os.environ.get("BACKUP_OPENSSL_BIN") or shutil.which("openssl"), "OpenSSL 3")
    openssl_version = subprocess.check_output([str(openssl), "version"], text=True, timeout=15).strip()
    require(re.match(r"OpenSSL 3\.", openssl_version) is not None, "Backup signing fixtures require OpenSSL 3")
    os.environ["PATH"] = str(node.parent) + os.pathsep + os.environ.get("PATH", "")
    os.environ["BACKUP_OPENSSL_BIN"] = str(openssl)
    return {
        "df_available_bytes": free,
        "node": {"path": str(node), "version": node_version, "sha256": hashlib.sha256(node.read_bytes()).hexdigest()},
        "openssl": {"path": str(openssl), "version": openssl_version, "sha256": hashlib.sha256(openssl.read_bytes()).hexdigest()},
        "sdk": sdk_fingerprints(),
    }


def configure_matrix():
    base = list(review.SUITES)
    require({entry[0] for entry in base} == set(BASE_FEATURES), "The inherited review acceptance scope changed")
    additions = [(name, target, selected, "") for name, target, selected, _count, _feature in ADDITIONAL]
    names = [entry[0] for entry in base + additions]
    require(len(names) == len(set(names)), "Acceptance group names must be unique")
    review.SUITES = base + additions
    review.EXPECTED_COUNTS = dict(review.EXPECTED_COUNTS)
    review.EXPECTED_COUNTS.update({name: count for name, _target, _selected, count, _feature in ADDITIONAL})
    features = dict(BASE_FEATURES)
    features.update({name: feature for name, _target, _selected, _count, feature in ADDITIONAL})
    return [{"suite": name, "target": target, "filter": selected, "feature": features[name],
             "expected_ignored_tests": review.EXPECTED_COUNTS.get(name)}
            for name, target, selected, _required in review.SUITES]


def run(args):
    matrix = configure_matrix()
    binding = preflight(args)
    args.fixture_memory_gib = 2
    args.drop_completed_databases = True
    evidence = args.evidence_dir.resolve()
    print(json.dumps({"stage": "LOCAL_ACCEPTANCE_PREFLIGHT", "groups": len(matrix),
                      "df_available_bytes": binding["df_available_bytes"], "fixture_memory_gib": 2,
                      "cloud_certification": False}), flush=True)
    result_code = 1
    try:
        result_code = review.run(args)
    finally:
        # Keep acceptance facts outside the Cargo target. The underlying
        # fixture has already confirmed ownership and cleaned its resources.
        record_path = evidence / "record.json"
        if record_path.is_file() and not record_path.is_symlink():
            record = json.loads(record_path.read_text())
            try:
                sdk_unchanged = sdk_fingerprints() == binding["sdk"]
                tools_unchanged = all(hashlib.sha256(Path(binding[name]["path"]).read_bytes()).hexdigest() == binding[name]["sha256"]
                                      for name in ("node", "openssl"))
            except (OSError, RuntimeError):
                sdk_unchanged = tools_unchanged = False
            complete = (record.get("exit_code") == 0 and len(record.get("suites", [])) == len(matrix)
                        and all(entry.get("status") == "PASS" and entry.get("owned_database_disposal_confirmed") is True
                                for entry in record["suites"]))
            if not complete or not sdk_unchanged or not tools_unchanged:
                result_code = 1
            passed = [entry for entry in record.get("suites", []) if entry.get("status") == "PASS"]
            review.fixture.private_json(evidence / "acceptance.json", {
                "environment": "REAL_LOCAL_PG_JWT_HTTP_SDK_WITH_AUTHENTICATED_CLOUD_PROTOCOL_SUBSTITUTES",
                "exit_code": result_code,
                "fixture_record": "record.json",
                "fixture_record_sha256": hashlib.sha256(record_path.read_bytes()).hexdigest(),
                "plan": matrix,
                "passed_groups": len(passed),
                "passed_tests": sum(len(entry["tests"]) for entry in passed),
                "all_planned_groups_completed": complete,
                "sdk_unchanged": sdk_unchanged,
                "tool_executables_unchanged": tools_unchanged,
                "input_binding": binding,
                "not_certified": UNTESTED,
            })
            print(json.dumps({"stage": "LOCAL_ACCEPTANCE_COMPLETE", "exit_code": result_code,
                              "passed_groups": len(passed), "planned_groups": len(matrix),
                              "passed_tests": sum(len(entry["tests"]) for entry in passed),
                              "record": str(evidence / "acceptance.json")}), flush=True)
    return result_code


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True,
                        help="ordinary current-source Cargo JSON containing all selected test targets and normal sandboxd")
    parser.add_argument("--evidence-dir", type=Path, required=True,
                        help="new private evidence directory outside the Cargo target; must not already exist")
    parser.add_argument("--node", type=Path, help="Node.js 22+ executable; defaults to PATH")
    parser.add_argument("--openssl", type=Path, help="OpenSSL 3 executable; defaults to BACKUP_OPENSSL_BIN then PATH")
    args = parser.parse_args()

    def stop(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    try:
        raise SystemExit(run(args))
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print("local acceptance failed: " + str(error) if isinstance(error, RuntimeError)
              else "local acceptance failed; raw environment/provider output withheld", file=sys.stderr)
        raise SystemExit(1)
