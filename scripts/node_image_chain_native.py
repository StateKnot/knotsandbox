"""Owned native image source for the local, bounded Prometheus/operator chain.

Only the pinned native ELF, containerd and public generated fixture inputs enter
its COPY-only image. Production daemon flags and the existing no-network native
acceptance contract are unchanged. The caller retires its agents before exiting
owned_native, so this module can prove its private internal network is empty.
"""
from contextlib import contextmanager
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import threading
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "native_image_observation_contract", ROOT / "scripts/test-nodeguard-image-observation.py")
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)
CASE = "nodeguard::metrics_server::image_tests::chain::native_image_chain_service_fixture"
QUERY_CASE = "nodeguard::metrics_server::image_tests::chain::native_image_chain_receiver_query"
QUERY_MARKER = "NATIVE_IMAGE_RECEIVER_RESPONSE "
READY = "NATIVE_IMAGE_CHAIN_READY "
COMPLETE = "NATIVE_IMAGE_CHAIN_COMPLETE"
LABEL = "node-image-native-chain"
CHAIN_FILES = {"identity.json", "server.pem", "server.key", "scraper-ca.pem", "server-ca.pem"}
MAX_LOG = 8 * 1024 * 1024
require = CONTRACT.require


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "DUPLICATE_NATIVE_FIXTURE_FIELD")
        value[key] = item
    return value


def canonical_uuid(value):
    require(isinstance(value, str) and str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0,
            "CANONICAL_NON_NIL_NATIVE_UUID_REQUIRED")
    return value


class Native:
    """The exact source identity and fixed owned fault/retirement operations."""

    network_alias = "native-chain"

    def __init__(self, work, docker, env, receipt):
        self.work, self.docker, self.env, self.receipt = work, docker, env, receipt
        self.owner = uuid.uuid4().hex
        self.name = "knotsandbox-native-chain-" + self.owner
        self.network_name = self.name + "-net"
        self.network_id = None
        self.container_id = None
        self.query_name = self.name + "-query"
        self.query_id = None
        self.query_create_attempted = False
        self.query_lock = threading.Lock()
        self.image = {"tag": "knotsandbox-native-chain-fixture:" + self.owner, "id": None}
        self.runtime_pid = None
        self.runtime_start_time = None
        self.host_port = None
        self.node = None
        self.binding = None
        self.expected_compressed_logical_bytes = None
        self.attached = None
        self.attach_log = work / "native-service.log"
        self.attach_stream = None
        self.started_at = None
        self.stopped = False
        self.image_build_attempted = False
        self.create_attempted = False
        self.network_create_attempted = False
        receipt.update(owner=self.owner, native_case=CASE, native_commands=[],
                       native_container_removed=False, native_image_removed=False,
                       native_network_removed=False, native_query_container_removed=False,
                       native_fixture_completed=False, native_receiver_queries=[])

    def _call(self, label, arguments, *, timeout=30, check=True):
        path = self.work / (f"native-{len(self.receipt['native_commands']) + 1:03d}-{label}.log")
        started, failure = time.monotonic(), None
        with path.open("xb") as output:
            path.chmod(0o600)
            process = subprocess.Popen([*self.docker, *arguments], cwd=ROOT, env=self.env,
                                       stdout=output, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            try:
                while process.poll() is None:
                    if time.monotonic() - started > timeout:
                        failure = "NATIVE_DOCKER_COMMAND_TIMEOUT"
                        break
                    if path.stat().st_size > MAX_LOG:
                        failure = "NATIVE_DOCKER_COMMAND_OUTPUT_BOUND"
                        break
                    time.sleep(0.05)
            finally:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.wait()
        if path.stat().st_size > MAX_LOG:
            with path.open("r+b") as output:
                output.truncate(MAX_LOG)
            failure = failure or "NATIVE_DOCKER_COMMAND_OUTPUT_BOUND"
        self.receipt["native_commands"].append({
            "stage": label, "exit_code": process.returncode, "failure": failure,
            "seconds": round(time.monotonic() - started, 3),
            "log": path.name, "sha256": CONTRACT.digest(path)})
        require(failure is None, failure)
        require(path.stat().st_size <= MAX_LOG, "NATIVE_DOCKER_COMMAND_OUTPUT_BOUND")
        require(not check or process.returncode == 0, "OWNED_NATIVE_DOCKER_COMMAND_FAILED")
        return process.returncode, path.read_text(errors="replace")

    def _inspect_container(self, *, check=True):
        code, text = self._call("inspect-container", ["inspect", self.container_id or self.name], check=check)
        if code != 0:
            return None
        value = json.loads(text)[0]
        labels = value["Config"].get("Labels", {})
        require(re.fullmatch(r"[0-9a-f]{64}", value["Id"]) and
                (self.container_id is None or value["Id"] == self.container_id) and
                value["Name"] == "/" + self.name and value["Config"]["Image"] == self.image["tag"] and
                value["Image"] == self.image["id"] and
                labels.get("com.sandbox.fixture") == LABEL and
                labels.get("com.sandbox.owner") == self.owner, "EXACT_OWNED_NATIVE_CONTAINER_REQUIRED")
        self.container_id = value["Id"]
        return value

    def _inspect_network(self, *, check=True):
        code, text = self._call("inspect-network", ["network", "inspect", self.network_id or self.network_name], check=check)
        if code != 0:
            return None
        value = json.loads(text)[0]
        labels = value.get("Labels", {})
        require(re.fullmatch(r"[0-9a-f]{64}", value["Id"]) and
                (self.network_id is None or value["Id"] == self.network_id) and
                value["Name"] == self.network_name and value["Internal"] is True and
                value["Driver"] == "bridge" and value["Scope"] == "local" and
                labels.get("com.sandbox.fixture") == LABEL and
                labels.get("com.sandbox.owner") == self.owner,
                "EXACT_OWNED_INTERNAL_NATIVE_NETWORK_REQUIRED")
        self.network_id = value["Id"]
        return value

    def _verify_container(self, value, *, started=False):
        h = value["HostConfig"]
        require(not value.get("Mounts") and not h.get("Binds") and not h.get("Privileged") and
                not h.get("CapAdd") and h.get("CapDrop") == ["ALL"] and
                h.get("NetworkMode") == self.network_name and h.get("ReadonlyRootfs") is True and
                h.get("PidMode", "") == "" and h.get("CgroupnsMode") == "private" and
                h.get("Memory") == CONTRACT.MEMORY and h.get("MemorySwap") == CONTRACT.MEMORY and
                h.get("NanoCpus") == 1_000_000_000 and h.get("PidsLimit") == 128 and
                h.get("Tmpfs") == CONTRACT.TMPFS and
                "no-new-privileges:true" in h.get("SecurityOpt", []), "NATIVE_RESOURCE_OR_ISOLATION_BOUND_CHANGED")
        require(value["Config"].get("User") == "0:0" and
                value["Config"].get("Entrypoint") == ["/fixture/lib-test"] and
                value["Config"].get("Cmd") == ["--exact", CASE, "--ignored", "--nocapture", "--test-threads=1"] and
                any(item.get("Name") == "nofile" and item.get("Soft") == 1024 and item.get("Hard") == 1024
                    for item in h.get("Ulimits", [])), "NATIVE_UID_FD_OR_TEST_COMMAND_CHANGED")
        require(h.get("LogConfig") == CONTRACT.LOG_CONFIG, "EXACT_NATIVE_BOUNDED_LOG_POLICY_REQUIRED")
        require(not h.get("PortBindings") and not value["NetworkSettings"].get("Ports"),
                "NATIVE_INTERNAL_NETWORK_MUST_NOT_PUBLISH_HOST_PORTS")
        require(set(value["NetworkSettings"]["Networks"]) == {self.network_name},
                "NATIVE_MUST_HAVE_ONLY_ITS_INTERNAL_NETWORK")
        endpoint = value["NetworkSettings"]["Networks"][self.network_name]
        if started:
            require(endpoint["NetworkID"] == self.network_id and
                    self.network_alias in (endpoint.get("Aliases") or []), "NATIVE_NETWORK_ID_OR_ALIAS_CHANGED")

    def _verify_query_container(self, value):
        h, config = value["HostConfig"], value["Config"]
        labels = config.get("Labels", {})
        require(re.fullmatch(r"[0-9a-f]{64}", value["Id"]) and
                (self.query_id is None or self.query_id == value["Id"]) and
                value["Name"] == "/" + self.query_name and config["Image"] == self.image["tag"] and
                value["Image"] == self.image["id"] and labels.get("com.sandbox.fixture") == LABEL and
                labels.get("com.sandbox.owner") == self.owner and labels.get("com.sandbox.role") == "receiver-query",
                "EXACT_OWNED_NATIVE_QUERY_CONTAINER_REQUIRED")
        require(not value.get("Mounts") and not h.get("Binds") and not h.get("Privileged") and
                not h.get("CapAdd") and h.get("CapDrop") == ["ALL"] and not h.get("Tmpfs") and
                h.get("NetworkMode") == self.network_name and h.get("ReadonlyRootfs") is True and
                h.get("PidMode", "") == "" and h.get("CgroupnsMode") == "private" and
                h.get("Memory") == 128 * 1024 * 1024 and h.get("MemorySwap") == 128 * 1024 * 1024 and
                h.get("NanoCpus") == 1_000_000_000 and h.get("PidsLimit") == 64 and
                "no-new-privileges:true" in h.get("SecurityOpt", []), "NATIVE_QUERY_ISOLATION_BOUND_CHANGED")
        require(config.get("User") == "501:20" and config.get("Entrypoint") == ["/usr/bin/sleep"] and
                config.get("Cmd") == ["180"] and h.get("LogConfig") == CONTRACT.LOG_CONFIG and
                any(item.get("Name") == "nofile" and item.get("Soft") == 1024 and item.get("Hard") == 1024
                    for item in h.get("Ulimits", [])), "NATIVE_QUERY_UID_COMMAND_OR_LOG_BOUND_CHANGED")
        require(not h.get("PortBindings") and not value["NetworkSettings"].get("Ports") and
                set(value["NetworkSettings"]["Networks"]) == {self.network_name},
                "NATIVE_QUERY_MUST_ONLY_USE_ITS_INTERNAL_NETWORK_WITHOUT_HOST_PORTS")
        if value["State"]["Running"]:
            require(value["NetworkSettings"]["Networks"][self.network_name]["NetworkID"] == self.network_id,
                    "NATIVE_QUERY_INTERNAL_NETWORK_ID_CHANGED")
        self.query_id = value["Id"]

    def _inspect_query(self, *, check=True):
        code, output = self._call("inspect-query-container", ["inspect", self.query_id or self.query_name], check=check)
        if code != 0:
            return None
        value = json.loads(output)[0]
        self._verify_query_container(value)
        return value

    def _start_query(self, arch):
        self.query_create_attempted = True
        _, output = self._call("create-query-container", ["create", "--name", self.query_name,
            "--label", "com.sandbox.fixture=" + LABEL, "--label", "com.sandbox.owner=" + self.owner,
            "--label", "com.sandbox.role=receiver-query", "--platform", "linux/" + arch,
            "--user", "501:20", "--network", self.network_name, "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true", "--cgroupns=private", "--cpus=1",
            "--memory=134217728", "--memory-swap=134217728", "--pids-limit=64", "--ulimit=nofile=1024:1024",
            "--log-driver=local", "--log-opt=max-size=1m", "--log-opt=max-file=1", "--log-opt=compress=false",
            "--entrypoint", "/usr/bin/sleep", self.image["tag"], "180"])
        self.query_id = output.strip()
        require(re.fullmatch(r"[0-9a-f]{64}", self.query_id), "NATIVE_QUERY_CONTAINER_ID_REQUIRED")
        self._inspect_query()
        self._call("start-query-container", ["start", self.query_id])
        value = self._inspect_query()
        require(value["State"]["Running"] and not value["State"].get("OOMKilled"), "NATIVE_QUERY_SIDECAR_NOT_LIVE")
        self.receipt["native_query_container_id"] = self.query_id

    def query_receiver(self, path: str, data: bytes | None = None) -> tuple[int, bytes]:
        """Transparent, bounded real HTTPS read from the internal non-root sidecar.

        This is called by host HTTP worker threads. No preexec_fn, shell, host
        port, proxy substitution or synthesized receiver response is involved.
        """
        require(path in ("/-/ready", "/api/v1/query"), "FIXED_RECEIVER_QUERY_PATH_REQUIRED")
        require((path == "/-/ready" and data is None) or
                (path == "/api/v1/query" and isinstance(data, bytes) and 0 < len(data) <= 64 * 1024),
                "FIXED_RECEIVER_QUERY_METHOD_AND_BODY_REQUIRED")
        form = data.decode("utf-8") if data is not None else None
        require(form is None or "\0" not in form, "RECEIVER_QUERY_FORM_NUL_FORBIDDEN")
        with self.query_lock:
            require(self.query_id is not None, "OWNED_RECEIVER_QUERY_SIDECAR_REQUIRED")
            # Docker inspect has bounded metadata for this exact immutable image;
            # captured query output is bounded by the Rust 256 KiB body limit.
            inspected = subprocess.run([*self.docker, "inspect", self.query_id], cwd=ROOT, env=self.env,
                                       capture_output=True, timeout=10)
            require(inspected.returncode == 0 and len(inspected.stdout) + len(inspected.stderr) <= 1024 * 1024,
                    "RECEIVER_QUERY_SIDECAR_INSPECTION_FAILED")
            value = json.loads(inspected.stdout)[0]
            self._verify_query_container(value)
            require(value["State"]["Running"] and not value["State"]["Paused"] and not value["State"].get("OOMKilled"),
                    "OWNED_RECEIVER_QUERY_SIDECAR_NOT_RUNNING")
            command = [*self.docker, "exec", "--env", "SANDBOX_NATIVE_CHAIN_QUERY_PATH=" + path]
            if form is not None:
                command += ["--env", "SANDBOX_NATIVE_CHAIN_QUERY_FORM=" + form]
            command += [self.query_id, "/fixture/lib-test", "--exact", QUERY_CASE,
                        "--ignored", "--nocapture", "--test-threads=1"]
            log = self.work / ("native-query-" + uuid.uuid4().hex + ".log")
            started = time.monotonic()
            try:
                result = subprocess.run(command, cwd=ROOT, env=self.env, capture_output=True, timeout=10)
                output = result.stdout + result.stderr
            except subprocess.TimeoutExpired as error:
                output = (error.stdout or b"") + (error.stderr or b"")
                with log.open("xb") as stream:
                    log.chmod(0o600)
                    stream.write(output[:1024 * 1024])
                self.receipt["native_receiver_queries"].append({"path": path, "failure": "TIMEOUT",
                    "log": log.name, "sha256": CONTRACT.digest(log)})
                raise
            with log.open("xb") as stream:
                log.chmod(0o600)
                stream.write(output[:1024 * 1024])
            self.receipt["native_receiver_queries"].append({"path": path, "exit_code": result.returncode,
                "seconds": round(time.monotonic() - started, 3), "log": log.name, "sha256": CONTRACT.digest(log)})
            require(len(output) <= 1024 * 1024, "RECEIVER_QUERY_TEST_OUTPUT_BOUND")
            require(result.returncode == 0, "ACTUAL_INTERNAL_RECEIVER_QUERY_FAILED")
            text = output.decode("utf-8")
            summaries = re.findall(r"(?m)^test result: (.+)$", text)
            require(len(summaries) == 1 and re.fullmatch(
                r"ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s",
                summaries[0]), "EXACT_ONE_RECEIVER_QUERY_TEST_MUST_PASS")
            rows = [line.split(QUERY_MARKER, 1)[1] for line in text.splitlines() if QUERY_MARKER in line]
            require(len(rows) == 1, "EXACT_RECEIVER_RESPONSE_MARKER_REQUIRED")
            result = json.loads(rows[0], object_pairs_hook=unique)
            require(set(result) == {"status", "body_base64"} and type(result["status"]) is int and
                    100 <= result["status"] <= 599 and isinstance(result["body_base64"], str),
                    "FIXED_RECEIVER_RESPONSE_ENVELOPE_REQUIRED")
            body = base64.b64decode(result["body_base64"], validate=True)
            require(len(body) <= 256 * 1024, "ACTUAL_RECEIVER_RESPONSE_BODY_BOUND")
            return result["status"], body

    def _runtime_stat(self):
        require(type(self.runtime_pid) is int and self.runtime_pid > 1, "EXACT_NON_INIT_NATIVE_PID_REQUIRED")
        container = self._inspect_container()
        self._verify_container(container, started=True)
        require(container["State"]["Running"] and not container["State"]["Paused"],
                "NATIVE_CONTAINER_MUST_BE_RUNNING_FOR_RUNTIME_FAULT")
        _, text = self._call("runtime-stat", ["exec", self.container_id, "/bin/cat", f"/proc/{self.runtime_pid}/stat"])
        prefix, _, fields = text.strip().rpartition(") ")
        require(prefix == f"{self.runtime_pid} (containerd", "EXACT_NATIVE_PROCESS_COMM_REQUIRED")
        values = fields.split()
        require(len(values) >= 20 and values[1] == "1" and values[19].isdigit() and int(values[19]) > 0,
                "OWNED_NATIVE_CHILD_AND_START_TIME_REQUIRED")
        start_time = int(values[19])
        require(self.runtime_start_time is None or self.runtime_start_time == start_time,
                "NATIVE_PID_START_TIME_CHANGED")
        _, executable = self._call("runtime-executable", ["exec", self.container_id, "/bin/readlink", f"/proc/{self.runtime_pid}/exe"])
        require(executable.strip() == "/usr/local/bin/containerd", "EXACT_NATIVE_CONTAINERD_EXECUTABLE_REQUIRED")
        self.runtime_start_time = start_time
        return values[0]

    def _runtime_signal(self, name, stopped):
        self._runtime_stat()
        self._call("runtime-" + name.lower(), ["exec", self.container_id, "/bin/sh", "-c",
                   'kill -' + name + ' "$1"', "native-chain", str(self.runtime_pid)])
        deadline = time.monotonic() + 1
        while True:
            state = self._runtime_stat()
            if (state in ("T", "t")) == stopped:
                return
            require(time.monotonic() < deadline, "NATIVE_SIGNAL_STATE_NOT_OBSERVED")
            time.sleep(0.05)

    def pause_runtime(self):
        self._runtime_signal("STOP", True)
        self.receipt["native_runtime_paused"] = True

    def resume_runtime(self):
        self._runtime_signal("CONT", False)
        self.receipt["native_runtime_paused"] = False

    def pause_transport(self):
        value = self._inspect_container()
        self._verify_container(value, started=True)
        require(value["State"]["Running"] and not value["State"]["Paused"], "NATIVE_TRANSPORT_ALREADY_PAUSED")
        self._call("pause-transport", ["pause", self.container_id])
        require(self._inspect_container()["State"]["Paused"], "NATIVE_TRANSPORT_PAUSE_UNCONFIRMED")
        self.receipt["native_transport_paused"] = True

    def resume_transport(self):
        value = self._inspect_container()
        self._verify_container(value, started=True)
        require(value["State"]["Running"], "NATIVE_TRANSPORT_EXITED")
        if value["State"]["Paused"]:
            self._call("resume-transport", ["unpause", self.container_id])
        require(not self._inspect_container()["State"]["Paused"], "NATIVE_TRANSPORT_RESUME_UNCONFIRMED")
        self.receipt["native_transport_paused"] = False

    def _read_service_log(self):
        require(self.attach_log.stat().st_size <= MAX_LOG, "NATIVE_SERVICE_OUTPUT_BOUND")
        return self.attach_log.read_text(errors="replace")

    def _wait_ready(self, expected_node, expected_bytes):
        deadline = self.started_at + 15
        while True:
            require(time.monotonic() < deadline, "NATIVE_READY_15_SECOND_BUDGET_EXCEEDED")
            log = self._read_service_log()
            rows = [line.split(READY, 1)[1] for line in log.splitlines(keepends=True)
                    if line.endswith("\n") and READY in line]
            require(len(rows) <= 1, "NATIVE_READY_MARKER_DUPLICATED")
            if rows:
                result = json.loads(rows[0], object_pairs_hook=unique)
                require(set(result) == {"node", "runtime_pid", "metrics_port", "expected_compressed_logical_bytes"},
                        "NATIVE_READY_FIELDS_CHANGED")
                require(result["node"] == expected_node and type(result["runtime_pid"]) is int and
                        result["runtime_pid"] > 1 and result["metrics_port"] == 9445 and
                        result["expected_compressed_logical_bytes"] == expected_bytes,
                        "NATIVE_READY_INDEPENDENT_BINDING_OR_OCI_ORACLE_MISMATCH")
                self.node, self.runtime_pid = result["node"], result["runtime_pid"]
                self.expected_compressed_logical_bytes = result["expected_compressed_logical_bytes"]
                self.binding = {"cluster_epoch": self.node["cluster_epoch"], "node_uid": self.node["node_uid"],
                    "host_boot_id": self.node["boot_id"], "profile_sha256": self.node["profile_sha256"]}
                value = self._inspect_container()
                self._verify_container(value, started=True)
                require(value["State"]["Running"] and not value["State"].get("OOMKilled"),
                        "NATIVE_SERVICE_MUST_REMAIN_LIVE")
                self._runtime_stat()
                self.receipt.update(native_binding=self.binding, native_node=self.node,
                                    native_runtime_pid=self.runtime_pid,
                                    native_runtime_start_time=self.runtime_start_time,
                                    native_host_port=self.host_port, native_ready=True)
                return
            require(self.attached.poll() is None, "NATIVE_SERVICE_EXITED_BEFORE_READY")
            require(time.monotonic() < deadline, "NATIVE_READY_15_SECOND_BUDGET_EXCEEDED")
            time.sleep(0.05)

    def stop(self):
        if self.stopped:
            return
        self.resume_transport()
        self.resume_runtime()
        self._call("request-native-stop", ["exec", self.container_id, "/usr/bin/touch", "/tmp/native-image-chain-stop"])
        deadline = time.monotonic() + 10
        while True:
            value = self._inspect_container()
            self._read_service_log()
            if not value["State"]["Running"]:
                require(value["State"]["ExitCode"] == 0 and not value["State"].get("OOMKilled"),
                        "NATIVE_SERVICE_FAILED_DURING_RETIREMENT")
                break
            require(time.monotonic() < deadline, "NATIVE_SERVICE_RETIREMENT_10_SECOND_BUDGET_EXCEEDED")
            time.sleep(0.05)
        require(self.attached is not None and self.attached.wait(timeout=1) == 0,
                "NATIVE_ATTACH_EXIT_UNCONFIRMED")
        output = self._read_service_log()
        summaries = re.findall(r"(?m)^test result: (.+)$", output)
        require(len(summaries) == 1 and re.fullmatch(
            r"ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s",
            summaries[0]), "EXACT_ONE_NATIVE_CHAIN_TEST_MUST_PASS")
        require(output.count(READY) == 1 and output.splitlines().count(COMPLETE) == 1,
                "NATIVE_CHAIN_COMPLETION_MARKER_REQUIRED")
        self.stopped = True
        self.receipt.update(native_fixture_completed=True, native_service_log_sha256=CONTRACT.digest(self.attach_log),
                            native_fixture_seconds=round(time.monotonic() - self.started_at, 3))

    def cleanup(self):
        errors = []
        if self.query_create_attempted:
            try:
                value = self._inspect_query(check=False)
                if value is not None:
                    self._call("remove-query-container", ["rm", "--force", self.query_id])
                if self.query_id is not None:
                    _, left = self._call("verify-query-container-absence", ["container", "ls", "--all", "--no-trunc",
                        "--filter", "id=" + self.query_id, "--format", "{{.ID}}"])
                    self.receipt["native_query_container_removed"] = not left.strip()
                require(self.receipt["native_query_container_removed"], "OWNED_NATIVE_QUERY_RETIREMENT_UNCONFIRMED")
            except BaseException as error:
                errors.append(str(error))
        else:
            self.receipt["native_query_container_removed"] = True
        if self.create_attempted:
            try:
                value = self._inspect_container(check=False)
                if value is not None:
                    if value["State"]["Running"]:
                        try:
                            self.stop()
                        except BaseException as error:
                            self.receipt["native_stop_failure"] = str(error)
                            errors.append(str(error))
                    try:
                        self._call("native-daemon-private-log", ["logs", "--tail", "400", self.container_id], check=False)
                    except BaseException as error:
                        errors.append("NATIVE_DIAGNOSTIC_FAILED:" + str(error))
                    self._call("remove-native-container", ["rm", "--force", self.container_id])
                if self.container_id is not None:
                    _, left = self._call("verify-native-container-absence", ["container", "ls", "--all", "--no-trunc",
                        "--filter", "id=" + self.container_id, "--format", "{{.ID}}"])
                    self.receipt["native_container_removed"] = not left.strip()
                require(self.receipt["native_container_removed"], "OWNED_NATIVE_CONTAINER_RETIREMENT_UNCONFIRMED")
            except BaseException as error:
                errors.append(str(error))
        else:
            self.receipt["native_container_removed"] = True
        if self.node is not None and not self.receipt["native_fixture_completed"]:
            errors.append("NATIVE_FIXTURE_COMPLETION_UNCONFIRMED")
        if self.attached is not None and self.attached.poll() is None:
            try:
                os.killpg(self.attached.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.attached.wait()
        if self.attach_stream is not None:
            self.attach_stream.close()
        if self.image_build_attempted:
            try:
                code, text = self._call("inspect-native-image-cleanup", ["image", "inspect", self.image["tag"]], check=False)
                if code == 0:
                    value = json.loads(text)[0]
                    self._verify_image(value)
                    self.image["id"] = value["Id"]
                    require(self.receipt["native_container_removed"] and self.receipt["native_query_container_removed"],
                            "NATIVE_AND_QUERY_CONTAINER_REMOVAL_BEFORE_IMAGE_REQUIRED")
                    self._call("remove-native-image", ["image", "rm", self.image["tag"]])
                if self.image["id"] is not None:
                    _, left = self._call("verify-native-image-absence", ["image", "ls", "--all", "--no-trunc",
                        "--filter", "label=com.sandbox.owner=" + self.owner, "--format", "{{.ID}}"])
                    self.receipt["native_image_removed"] = not left.strip()
                require(self.receipt["native_image_removed"], "OWNED_NATIVE_IMAGE_RETIREMENT_UNCONFIRMED")
            except BaseException as error:
                errors.append(str(error))
        else:
            self.receipt["native_image_removed"] = True
        if self.network_create_attempted:
            try:
                value = self._inspect_network(check=False)
                if value is not None:
                    require(not value.get("Containers"), "OWNED_NATIVE_NETWORK_HAS_LIVE_ENDPOINTS")
                    self._call("remove-native-network", ["network", "rm", self.network_id])
                if self.network_id is not None:
                    _, left = self._call("verify-native-network-absence", ["network", "ls", "--no-trunc",
                        "--filter", "label=com.sandbox.owner=" + self.owner, "--format", "{{.ID}}"])
                    self.receipt["native_network_removed"] = not left.strip()
                require(self.receipt["native_network_removed"], "OWNED_NATIVE_NETWORK_RETIREMENT_UNCONFIRMED")
            except BaseException as error:
                errors.append(str(error))
        else:
            self.receipt["native_network_removed"] = True
        self.receipt["native_cleanup_errors"] = errors
        return errors

    def _verify_image(self, value):
        labels = value.get("Config", {}).get("Labels", {})
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", value.get("Id", "")) and
                (self.image["id"] is None or value["Id"] == self.image["id"]) and
                self.image["tag"] in (value.get("RepoTags") or []) and
                labels.get("com.sandbox.fixture") == LABEL and labels.get("com.sandbox.owner") == self.owner,
                "EXACT_OWNED_NATIVE_IMAGE_REQUIRED")


@contextmanager
def owned_native(args, work: Path, docker: list[str], env: dict, receipt: dict):
    """Yield Native; args supplies native_artifacts and optional official archive/checksum."""
    require(os.geteuid() != 0, "ORDINARY_NATIVE_CHAIN_CALLER_REQUIRED")
    work = CONTRACT.regular(work, directory=True)
    native = Native(work, docker, env, receipt)
    failure, context, before_sources, before_binary, binary, artifacts = None, None, None, None, None, None
    chain, chain_before = None, None
    try:
        artifacts = CONTRACT.regular(args.native_artifacts)
        require(artifacts.stat().st_size <= 32 * 1024 * 1024, "NATIVE_CARGO_MESSAGES_TOO_LARGE")
        before_artifacts = CONTRACT.digest(artifacts)
        metadata = subprocess.run(["cargo", "metadata", "--locked", "--offline", "--no-deps", "--format-version=1"],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
        require(metadata.returncode == 0, "ORDINARY_NATIVE_CARGO_METADATA_FAILED")
        _, engine_text = native._call("docker-engine", ["version", "--format", "{{json .Server}}"])
        engine = json.loads(engine_text)
        arch = engine.get("Arch")
        require(engine.get("Os") == "linux" and arch in CONTRACT.PINS, "NATIVE_AMD64_OR_ARM64_DOCKER_REQUIRED")
        binary, target = CONTRACT.select_artifact(
            [json.loads(line) for line in artifacts.read_text().splitlines() if line.strip()],
            json.loads(metadata.stdout), arch)
        require(work != target and target not in work.parents, "NATIVE_CHAIN_WORK_OUTSIDE_TARGET_REQUIRED")
        before_sources, before_binary = CONTRACT.source_fingerprints(), CONTRACT.fingerprint(binary)
        # Read df before image staging/build; directory sizes are not an APFS
        # free-space oracle, and no generated target is copied into the image.
        disk = subprocess.run(["df", "-Pk", str(ROOT)], cwd=ROOT, env=env,
                              capture_output=True, text=True, timeout=30)
        require(disk.returncode == 0, "NATIVE_CHAIN_DISK_PREFLIGHT_FAILED")
        disk_free = int(disk.stdout.splitlines()[-1].split()[3]) * 1024
        require(disk_free >= 2 * 1024**3, "BOUNDED_NATIVE_CHAIN_DISK_HEADROOM_REQUIRED")
        receipt["native_disk_available_before_bytes"] = disk_free
        receipt["native_below_50gb_assessment"] = (
            "No compile/cache copy; one <=512MiB exact ELF, two <=128MiB pinned binaries, <=64MiB official archive; "
            "owned COPY-only image is removed, no shared cache/data/volume pruning."
            if disk_free < 50 * 1024**3 else None)
        base = re.findall(r"^ARG RUNTIME_IMAGE=(debian:trixie-slim@sha256:[0-9a-f]{64})$",
                          (ROOT / "Dockerfile").read_text(), re.MULTILINE)
        require(len(base) == 1, "PINNED_NATIVE_TRIXIE_IMAGE_REQUIRED")
        chain = CONTRACT.regular(work / "chain", directory=True)
        require({p.name for p in chain.iterdir()} == CHAIN_FILES, "EXACT_FIVE_PUBLIC_NATIVE_CHAIN_INPUTS_REQUIRED")
        chain_before = {}
        for name in sorted(CHAIN_FILES):
            path = CONTRACT.regular(chain / name)
            require(path.stat().st_size <= (1024 if name == "identity.json" else 64 * 1024),
                    "PUBLIC_NATIVE_CHAIN_INPUT_BOUND")
            chain_before[name] = CONTRACT.fingerprint(path)
        identity = json.loads((chain / "identity.json").read_bytes(), object_pairs_hook=unique)
        require(set(identity) == {"epoch", "node_uid"}, "EXACT_NATIVE_IDENTITY_FIELDS_REQUIRED")
        canonical_uuid(identity["epoch"])
        canonical_uuid(identity["node_uid"])
        archive, receipt["native_containerd"] = CONTRACT.verified_archive(args, arch, work)
        context = work / "native-context"
        context.mkdir(mode=0o700)
        files = context / "rootfs"
        fixture = CONTRACT.prepare_files(files, archive, binary, arch)
        (context / "Dockerfile").write_text(CONTRACT.fixture_dockerfile(base[0]))
        (context / "Dockerfile").chmod(0o444)
        original_manifest = CONTRACT.context_manifest(context)
        (files / "fixture").chmod(0o755)
        staged_chain = files / "fixture/chain"
        staged_chain.mkdir(mode=0o755)
        for name in sorted(CHAIN_FILES):
            shutil.copyfile(chain / name, staged_chain / name)
            (staged_chain / name).chmod(0o444)
        staged_chain.chmod(0o555)
        (files / "fixture").chmod(0o555)
        allowed = set(original_manifest) | {"rootfs/fixture/chain/" + name for name in CHAIN_FILES}

        def manifest():
            actual = {str(path.relative_to(context)) for path in context.rglob("*") if path.is_file()}
            require(actual == allowed, "EXACT_EXTENDED_PUBLIC_NATIVE_CONTEXT_REQUIRED")
            return {name: {"sha256": CONTRACT.digest(CONTRACT.regular(context / name)),
                "size": (context / name).stat().st_size, "mode": (context / name).stat().st_mode & 0o777}
                for name in sorted(actual)}

        build_inputs = manifest()
        require(all(build_inputs["rootfs/fixture/chain/" + name]["sha256"] == chain_before[name]["sha256"]
                    for name in CHAIN_FILES), "NATIVE_CHAIN_COPY_IDENTITY_CHANGED")
        receipt.update(native_architecture="linux/" + arch, native_runtime_image=base[0],
                       native_binary_sha256=before_binary["sha256"], native_artifacts_sha256=before_artifacts,
                       native_fixture=fixture, native_build_context=build_inputs)
        native.image_build_attempted = True
        native._call("build-native-image", ["build", "--pull", "--network=none", "--platform", "linux/" + arch,
            "--label", "com.sandbox.fixture=" + LABEL, "--label", "com.sandbox.owner=" + native.owner,
            "--tag", native.image["tag"], "--file", str(context / "Dockerfile"), str(context)], timeout=180)
        require(manifest() == build_inputs, "NATIVE_PUBLIC_BUILD_CONTEXT_CHANGED")
        _, image_text = native._call("inspect-built-native-image", ["image", "inspect", native.image["tag"]])
        image = json.loads(image_text)[0]
        native._verify_image(image)
        require(image.get("Os") == "linux" and image.get("Architecture") == arch, "NATIVE_IMAGE_ARCHITECTURE_DRIFT")
        native.image["id"] = image["Id"]
        native.network_create_attempted = True
        _, network_text = native._call("create-native-network", ["network", "create", "--driver=bridge", "--internal",
            "--label", "com.sandbox.fixture=" + LABEL, "--label", "com.sandbox.owner=" + native.owner,
            native.network_name])
        native.network_id = network_text.strip()
        native._inspect_network()
        command = ["create", "--name", native.name, "--label", "com.sandbox.fixture=" + LABEL,
            "--label", "com.sandbox.owner=" + native.owner, "--platform", "linux/" + arch, "--user", "0:0",
            "--network", native.network_name, "--network-alias", native.network_alias,
            "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
            "--cgroupns=private", "--cpus=1", "--memory", str(CONTRACT.MEMORY),
            "--memory-swap", str(CONTRACT.MEMORY), "--pids-limit=128", "--ulimit=nofile=1024:1024",
            "--log-driver=local", "--log-opt=max-size=1m", "--log-opt=max-file=1", "--log-opt=compress=false"]
        for destination, options in CONTRACT.TMPFS.items():
            command += ["--tmpfs", destination + ":" + options]
        expected_bytes = str(fixture["expected_compressed_logical_bytes"])
        command += ["--env", "SANDBOX_NATIVE_IMAGE_PROFILE=/fixture/host-profile.json",
            "--env", "SANDBOX_NATIVE_IMAGE_LOGICAL_BYTES=" + expected_bytes,
            "--entrypoint", "/fixture/lib-test", native.image["tag"], "--exact", CASE,
            "--ignored", "--nocapture", "--test-threads=1"]
        native.create_attempted = True
        _, container_text = native._call("create-native-container", command)
        native.container_id = container_text.strip()
        require(re.fullmatch(r"[0-9a-f]{64}", native.container_id), "NATIVE_CONTAINER_ID_REQUIRED")
        native._verify_container(native._inspect_container())
        # Start only to obtain the actual kernel boot identity before any READY
        # assertion; Docker exec reads the same owned namespace as the observer.
        native.attach_stream = native.attach_log.open("xb")
        native.attach_log.chmod(0o600)
        native.attached = subprocess.Popen([*docker, "start", "--attach", native.container_id],
            cwd=ROOT, env=env, stdout=native.attach_stream, stderr=subprocess.STDOUT,
            start_new_session=True)
        native.started_at = time.monotonic()
        while not native._inspect_container()["State"]["Running"]:
            require(native.attached.poll() is None, "NATIVE_CONTAINER_FAILED_TO_START")
            require(time.monotonic() - native.started_at < 15, "NATIVE_READY_15_SECOND_BUDGET_EXCEEDED")
            time.sleep(0.05)
        _, boot = native._call("native-kernel-boot", ["exec", native.container_id, "/bin/cat", "/proc/sys/kernel/random/boot_id"])
        _, libc = native._call("native-runtime-sysroot", ["exec", native.container_id, "getconf", "GNU_LIBC_VERSION"])
        require(libc.strip() == "glibc 2.41", "REVIEWED_NATIVE_TRIXIE_SYSROOT_REQUIRED")
        _, copied = native._call("native-actual-test-elf", ["exec", native.container_id, "sha256sum", "/fixture/lib-test"])
        require(copied.split() == [before_binary["sha256"], "/fixture/lib-test"],
                "ACTUAL_NATIVE_LIB_TEST_ARTIFACT_DIGEST_MISMATCH")
        expected_node = {"cluster_epoch": identity["epoch"], "node_uid": identity["node_uid"],
            "node_name": "native-image-chain-fixture", "boot_id": canonical_uuid(boot.strip()),
            "profile_sha256": CONTRACT.digest(files / "fixture/host-profile.json")}
        native._wait_ready(expected_node, expected_bytes)
        native._start_query(arch)
        receipt.update(native_container_id=native.container_id, native_image=native.image,
                       native_network_name=native.network_name, native_network_id=native.network_id)
        yield native
    except BaseException as error:
        failure = error
        raise
    finally:
        cleanup_errors = native.cleanup()
        try:
            receipt["native_source_unchanged"] = before_sources is not None and CONTRACT.source_fingerprints() == before_sources
            receipt["native_binary_unchanged"] = binary is not None and CONTRACT.fingerprint(binary) == before_binary
            receipt["native_artifacts_unchanged"] = artifacts is not None and CONTRACT.digest(artifacts) == receipt.get("native_artifacts_sha256")
            if before_sources is not None:
                require(receipt["native_source_unchanged"], "NATIVE_CHAIN_SOURCE_CHANGED")
                require(receipt["native_binary_unchanged"], "NATIVE_CHAIN_BINARY_CHANGED")
                require(receipt["native_artifacts_unchanged"], "NATIVE_CHAIN_ARTIFACTS_CHANGED")
            if chain_before is not None:
                receipt["native_chain_inputs_unchanged"] = chain_before == {
                    name: CONTRACT.fingerprint(chain / name) for name in sorted(CHAIN_FILES)}
                require(receipt["native_chain_inputs_unchanged"], "NATIVE_CHAIN_PKI_OR_IDENTITY_INPUT_CHANGED")
        except BaseException as error:
            cleanup_errors.append(str(error))
        if context is not None and context.exists():
            # Only this module's just-created COPY staging directory is removed;
            # no target, shared Docker cache, database, volume or source is selected.
            try:
                for path in (context, *context.rglob("*")):
                    if path.is_dir():
                        path.chmod(0o700)
                shutil.rmtree(context)
                receipt["native_build_context_removed"] = not context.exists()
            except BaseException as error:
                cleanup_errors.append(str(error))
        if cleanup_errors and failure is None:
            raise CONTRACT.CheckError("OWNED_NATIVE_CHAIN_CLEANUP_OR_INPUT_VERIFICATION_FAILED")
