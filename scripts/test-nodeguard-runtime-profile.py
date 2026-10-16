#!/usr/bin/env python3
"""Read back a pinned native containerd runtime profile through the production gate.

Reuses the image-observation fixture's exact artifact, provider, isolation,
ownership and retirement checks. The imported image remains inventory only.
No shim, sandbox, VM, pull, unpack, mTLS or image preparation is certified.
"""
import argparse
import importlib.util
from pathlib import Path
import signal
import sys

sys.dont_write_bytecode = True
SOURCE = Path(__file__).with_name("test-nodeguard-image-observation.py")
SPEC = importlib.util.spec_from_file_location("native_runtime_profile_fixture", SOURCE)
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)

FIXTURE.CASE = "nodeguard::runtime_profile::native_tests::native_loaded_runtime_profile_keeps_mismatches_closed"
FIXTURE.MARKER = "NODEGUARD_NATIVE_LOADED_RUNTIME_PROFILE_GATE_VERIFIED"
FIXTURE.ACCEPTANCE_SCOPE = "LOCAL_NATIVE_CONTAINERD_RUNTIME_CONFIG_READBACK_ONLY_NOT_KATA_MTLS_IMAGES_PREPARATION_GPU_OR_CLOUD"
FIXTURE.SUCCESS_MESSAGE = "PASS exact native containerd runtime profile gate; owned daemon retired; no Kata, mTLS or image-preparation certification"

PREPARE_FILES = FIXTURE.prepare_files


def prepare_files(stage, archive, binary, arch):
    FIXTURE.require(arch in ("amd64", "arm64"), "REVIEWED_NATIVE_ARCHITECTURE_REQUIRED")
    FIXTURE.CONFIG = '''version = 4
root = "/var/lib/containerd"
state = "/run/containerd"
[grpc]
  address = "/run/containerd/containerd.sock"
[plugins."io.containerd.cri.v1.runtime".containerd]
  default_runtime_name = "runc"
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runc.options]
  SystemdCgroup = true
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.kata-qemu]
  runtime_type = "io.containerd.kata.v2"
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.kata-qemu.options]
  ConfigPath = "/fixture/profile-files/kata_configuration"
[plugins."io.containerd.cri.v1.images"]
  snapshotter = "overlayfs"
[plugins."io.containerd.cri.v1.images".runtime_platforms.kata-qemu]
  platform = "linux/''' + arch + '''"
  snapshotter = "overlayfs"
[plugins."io.containerd.nri.v1.nri"]
  disable = true
'''
    return PREPARE_FILES(stage, archive, binary, arch)


FIXTURE.prepare_files = prepare_files


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--containerd-archive", type=Path)
    parser.add_argument("--containerd-checksum", type=Path)

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        FIXTURE.run(parser.parse_args())
    except BaseException as error:
        suffix = "private evidence retained" if getattr(error, "evidence_saved", False) else "no completed evidence record was saved; a private evidence destination could not be safely created or written"
        print("Native runtime profile acceptance failed; " + suffix, file=sys.stderr)
        raise SystemExit(1) from None
