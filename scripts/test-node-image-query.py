#!/usr/bin/env python3
"""Owned Prometheus protocol fixture; does not certify a native CRI chain."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import platform
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/observability"))
from fixture_cleanup import fixture_directory
from observability import LOCK, NODE_IMAGE_LABELS

CASE = "node_image_public_query_through_real_prometheus"
MARKER = "NODE_IMAGE_PROMETHEUS_QUERY_VERIFIED"
TOKEN = "PUBLIC-node-image-query-fixture"
PREFIX = "sandbox_node_image_"
NAMES = [PREFIX + name for name in (
    "inventory_observation_success", "filesystem_observation_success", "observed_at_seconds",
    "inventory_count", "compressed_logical_bytes", "filesystem_reported_at_seconds",
    "filesystem_used_bytes", "filesystem_inodes_used")] + ["up"]
INTERVAL = 20
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def require(value, message):
    if not value:
        raise RuntimeError(message)


def docker(*arguments, check=True):
    return subprocess.run(["docker", *arguments], capture_output=True, text=True, timeout=30, check=check)


def post(port, query, evaluated):
    body = urllib.parse.urlencode({"query": query, "time": evaluated}).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{port}/api/v1/query", data=body)
    with HTTP.open(request, timeout=6) as response:
        data = json.loads(response.read(256 * 1024 + 1))
    require(data["status"] == "success", "PROMETHEUS_QUERY_FAILED")
    return data["data"]["result"]


def run(args, record):
    if args.artifacts:
        messages = [json.loads(line) for line in args.artifacts.read_text().splitlines() if line.strip()]
        candidates = {message["executable"] for message in messages if message.get("reason") == "compiler-artifact"
                      and message.get("target", {}).get("name") == "node_image_prometheus"
                      and message.get("profile", {}).get("test") is True and message.get("executable")}
        require(len(candidates) == 1, "UNIQUE_NODE_IMAGE_TEST_ARTIFACT_REQUIRED")
        args.test_binary = Path(candidates.pop())
    binary = args.test_binary.resolve(strict=True)
    require(binary.is_file() and os.access(binary, os.X_OK), "EXECUTABLE_TEST_BINARY_REQUIRED")
    record["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    require(LOCK["prometheus_version"] == "3.13.4", "PROMETHEUS_VERSION_DRIFT")
    record["image"] = LOCK["prometheus_image"]
    image = json.loads(docker("image", "inspect", record["image"]).stdout)[0]
    record["docker_image"] = {key: image[key] for key in ("Id", "RepoDigests", "Architecture")}
    scrape_bind = "127.0.0.1"
    if platform.system() == "Linux":
        bridge = json.loads(docker("network", "inspect", "bridge").stdout)[0]
        gateways = [item["Gateway"] for item in bridge["IPAM"]["Config"]
                    if item.get("Gateway") and ipaddress.ip_address(item["Gateway"]).version == 4]
        require(bridge["Driver"] == "bridge" and len(gateways) == 1, "UNIQUE_DOCKER_BRIDGE_IPV4_GATEWAY_REQUIRED")
        scrape_bind = gateways[0]
        require(not ipaddress.ip_address(scrape_bind).is_unspecified, "INVALID_DOCKER_BRIDGE_GATEWAY")
    else:
        require(platform.system() == "Darwin", "SUPPORTED_DOCKER_HOST_REQUIRED")
    record["scrape_bind"] = scrape_bind
    bindings = {mode: {"cluster_epoch": str(uuid.uuid4()), "node_uid": str(uuid.uuid4()),
                       "host_boot_id": str(uuid.uuid4()), "profile_sha256": "d" * 64}
                for mode in ("fresh", "latest_zero", "stale", "absent")}
    failure = {"replica": None}
    container = "sandbox-node-image-query-" + uuid.uuid4().hex[:12]
    servers = []
    deadline = time.monotonic() + 90

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if self.server.query_proxy:
                self.send_error(405)
                return
            parts = self.path.strip("/").split("/")
            if len(parts) != 2 or parts[0] not in bindings or parts[1] not in ("a", "b"):
                self.send_error(404)
                return
            mode, replica = parts
            labels = dict(bindings[mode], source="RUNTIME_REPORTED", completeness="UNKNOWN")
            labels.pop("cluster_epoch")  # Deployment/epoch come from fixed target labels.
            text = ",".join(f'{key}="{value}"' for key, value in labels.items())
            success = not (mode == "latest_zero" and failure["replica"] == replica)
            observed = time.time() - (120 if mode == "stale" else 2)
            values = [int(success), int(success), observed, 7 if replica == "a" else 9,
                      200 if replica == "a" else 100, observed - 1,
                      700 if replica == "a" else 900, 3 if replica == "a" else 5]
            body = ""
            for index in range(8 if success else 2):
                extra = f',filesystem_id="{replica * 64}"' if index >= 5 else ""
                body += f"{NAMES[index]}{{{text}{extra}}} {values[index]}\n"
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if not self.server.query_proxy or self.path != "/managed/api/v1/query" or self.headers.get("Authorization") != f"Bearer {TOKEN}":
                self.send_error(403)
                return
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536:
                self.send_error(413)
                return
            body = self.rfile.read(length)
            try:
                request = urllib.request.Request(f"http://127.0.0.1:{port}/api/v1/query", data=body,
                                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
                with HTTP.open(request, timeout=6) as upstream:
                    data = upstream.read(256 * 1024 + 1)
                require(len(data) <= 256 * 1024, "QUERY_RESPONSE_TOO_LARGE")
                query = urllib.parse.parse_qs(body.decode())["query"][0]
                mode = next(mode for mode, binding in bindings.items() if binding["node_uid"] in query)
                (args.output_dir / f"{mode}-request.txt").write_bytes(body)
                (args.output_dir / f"{mode}-vector.json").write_bytes(data)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)  # Preserve the actual Prometheus response unchanged.
            except Exception as error:
                (args.output_dir / "proxy-error.txt").write_text(repr(error))
                self.send_error(502)

    def serve(address, tls=False):
        server = ThreadingHTTPServer(address, Handler)
        server.query_proxy = tls
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(ROOT / "tests/fixtures/admission/server.pem", ROOT / "tests/fixtures/admission/server.key")
            server.socket = context.wrap_socket(server.socket, server_side=True)
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server.server_port

    def probe(mode):
        selector = '{job="node-images-' + bindings[mode]["node_uid"] + '"}'
        evaluated = int(time.time())
        result = {}
        for name in ("up", NAMES[0]):
            for expression in (name + selector, "timestamp(" + name + selector + ")"):
                rows = post(port, expression, evaluated)
                result[expression] = {row["metric"]["collector_replica"]: float(row["value"][1]) for row in rows}
        up, up_time, flags, times = result.values()
        record["probes"][mode] = result
        if all(set(values) == {"a", "b"} for values in result.values()) and up == {"a": 1, "b": 1} and up_time == times:
            return flags, times
        return None

    def wait(check):
        while time.monotonic() < deadline:
            value = check()
            if value:
                return value
            time.sleep(0.2)
        raise RuntimeError("BOUNDED_SCRAPE_WINDOW_TIMEOUT")

    directory = None
    try:
        with fixture_directory("sandbox-prometheus-pipeline-", ("receiver", "agent-a", "agent-b")) as directory:
            directory.chmod(0o755)
            for store in ("receiver", "agent-a", "agent-b"):
                (directory / store).mkdir(mode=0o777)
                (directory / store).chmod(0o777)
            scrape_port, proxy_port = serve((scrape_bind, 0)), serve(("127.0.0.1", 0), tls=True)
            jobs = []
            for mode, binding in bindings.items():
                if mode == "absent":
                    continue
                targets = []
                for replica in ("a", "b"):
                    labels = {"deployment": "production-a", "cluster_epoch": binding["cluster_epoch"],
                              "collector_replica": replica, "__metrics_path__": f"/{mode}/{replica}"}
                    labels.update({"scrape_" + key: binding[key] for key in ("node_uid", "host_boot_id", "profile_sha256")})
                    targets.append({"targets": [f"host.docker.internal:{scrape_port}"], "labels": labels})
                jobs.append({"job_name": "node-images-" + binding["node_uid"], "scrape_interval": f"{INTERVAL}s",
                             "scrape_timeout": "2s", "honor_timestamps": False, "sample_limit": 53,
                             "body_size_limit": "64KiB", "static_configs": targets,
                             "metric_relabel_configs": [{"action": "labelkeep", "regex": "|".join(NODE_IMAGE_LABELS)}]})
            config = directory / "prometheus.json"
            config.write_text(json.dumps({"scrape_configs": jobs}))
            command = ["run", "-d", "--name", container, "--network=bridge", "--pull=never", "--read-only", "--cap-drop=ALL",
                       "--security-opt=no-new-privileges", "--memory=256m", "--cpus=1", "--pids-limit=64",
                       "--log-driver=local", "--log-opt=max-size=1m", "--log-opt=max-file=1", "--log-opt=compress=false", "-p", "127.0.0.1::9090",
                       "--mount", f"type=bind,src={config},dst=/etc/prometheus/prometheus.yml,readonly",
                       "--mount", f"type=bind,src={directory / 'receiver'},dst=/prometheus"]
            if platform.system() == "Linux":
                command += [f"--add-host=host.docker.internal:{scrape_bind}"]
            command += [record["image"], "--config.file=/etc/prometheus/prometheus.yml", "--storage.tsdb.path=/prometheus",
                        "--storage.tsdb.retention.time=2h", "--storage.tsdb.retention.size=32MB", "--query.max-samples=10000"]
            try:
                docker(*command)
                inspection = json.loads(docker("inspect", container).stdout)[0]
                require(inspection["Image"] == image["Id"], "DOCKER_IMAGE_ID_DRIFT")
                port = int(inspection["NetworkSettings"]["Ports"]["9090/tcp"][0]["HostPort"])
                record["container"] = container
                def ready():
                    try:
                        with HTTP.open(f"http://127.0.0.1:{port}/-/ready", timeout=1) as response:
                            return response.status == 200
                    except OSError:
                        return False
                wait(ready)
                for mode in ("fresh", "latest_zero", "stale"):
                    wait(lambda: probe(mode))
                token = directory / "token"
                token.write_text(TOKEN)
                token.chmod(0o600)
                for mode, binding in bindings.items():
                    if mode == "latest_zero":
                        _, times = probe(mode)
                        earlier, later = sorted(times, key=times.get)
                        zero = earlier if times[later] - times[earlier] >= INTERVAL / 2 else later
                        failure["replica"] = zero
                        other = "b" if zero == "a" else "a"
                        def zero_window():
                            current = probe(mode)
                            return current and current[0] == {zero: 0, other: 1} and current[1][zero] > current[1][other] and current[1][other] + INTERVAL - time.time() > 8
                        wait(zero_window)
                    fixture = directory / "fixture.json"
                    fixture.write_text(json.dumps({"backend": {"endpoint": f"https://127.0.0.1:{proxy_port}/managed",
                        "deployment": "production-a", "auth": {"type": "BEARER", "token_file": str(token)},
                        "ca_file": str(ROOT / "tests/fixtures/admission/server-ca.pem"), "replicas": ["a", "b"]},
                        "binding": binding, "expected_mode": mode}))
                    fixture.chmod(0o600)
                    try:
                        completed = subprocess.run([str(binary), "--ignored", "--exact", CASE, "--nocapture", "--test-threads=1"],
                            env=dict(os.environ, SANDBOX_NODE_IMAGE_QUERY_FIXTURE=str(fixture)), capture_output=True, text=True, timeout=8)
                    except subprocess.TimeoutExpired as error:
                        (args.output_dir / f"{mode}-test.log").write_bytes((error.stdout or b"") + (error.stderr or b""))
                        record["modes"][mode] = {"exit": "TIMEOUT", "marker": False}
                        raise
                    output = completed.stdout + completed.stderr
                    (args.output_dir / f"{mode}-test.log").write_text(output)
                    record["modes"][mode] = {"exit": completed.returncode, "marker": f"{MARKER} {mode}" in output}
                    require(completed.returncode == 0 and record["modes"][mode]["marker"] and
                            "test result: ok. 1 passed; 0 failed; 0 ignored;" in output, f"RUST_CASE_FAILED_{mode}")
                    if mode == "fresh":
                        rows = json.loads((args.output_dir / "fresh-vector.json").read_bytes())["data"]["result"]
                        expected = {(name, kind) for name in NAMES for kind in ("value", "sampled_at")}
                        require(len(rows) == 36 and all({(row["metric"]["__name__"], row["metric"]["sandbox_value_kind"])
                            for row in rows if row["metric"]["collector_replica"] == replica} == expected for replica in ("a", "b")), "REAL_PROMQL_UNION_LOST_METRIC_KINDS")
                        times = {row["metric"]["collector_replica"]: float(row["value"][1]) for row in rows
                                 if row["metric"]["__name__"] == NAMES[0] and row["metric"]["sandbox_value_kind"] == "sampled_at"}
                        selected = min(times, key=lambda replica: (-times[replica], replica))
                        results = [json.loads(line.split("NODE_IMAGE_PROMETHEUS_RESULT ", 1)[1]) for line in output.splitlines()
                                   if "NODE_IMAGE_PROMETHEUS_RESULT " in line]
                        require(len(results) == 1 and results[0]["inventory"]["collector_replica"] == selected and
                                results[0]["filesystem"]["collector_replica"] == selected, "HA_DID_NOT_SELECT_LATEST_REAL_COHORT")
                        record["fresh_kind_pairs_per_replica"] = len(expected)
            finally:
                logs = docker("logs", container, check=False)
                record["container_log"] = (logs.stdout + logs.stderr)[-16384:]
                docker("rm", "-f", container, check=False)
                record["container_removed"] = not docker("ps", "-aq", "--filter", f"name=^/{container}$").stdout.strip()
                require(record["container_removed"], "OWN_CONTAINER_CLEANUP_FAILED")
        record["data_removed"] = not directory.exists()
        require(record["data_removed"], "OWN_DATA_CLEANUP_FAILED")
        require(hashlib.sha256(binary.read_bytes()).hexdigest() == record["binary_sha256"], "BINARY_CHANGED")
    finally:
        if directory is not None:
            record["data_removed"] = not directory.exists()
        for server in servers:
            server.shutdown()
            server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--test-binary", type=Path)
    selection.add_argument("--artifacts", type=Path)
    parser.add_argument("--evidence-dir", "--output-dir", dest="output_dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir = args.output_dir.absolute()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    record = {"status": "FAIL", "modes": {}, "probes": {}, "scope": "public Prometheus protocol only"}
    try:
        run(args, record)
        record["status"] = "PASS"
    except Exception as error:
        record["error"] = repr(error)
    (args.output_dir / "record.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))
    return 0 if record["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
