#!/usr/bin/env python3
"""Exercise fixed-UDS peer binding and volatile CRI/CONTROL drain.

The existing native runtime-profile fixture supplies the official healthy
containerd, immutable public profile and strict owned Docker runner. The case
temporarily substitutes owned read-only CRI peers, then restores the original
socket for the runner's actual containerd/no-unpack postconditions.
"""
import argparse
import importlib.util
from pathlib import Path
import signal
import sys

sys.dont_write_bytecode = True
SOURCE = Path(__file__).with_name("test-nodeguard-runtime-profile.py")
SPEC = importlib.util.spec_from_file_location("native_runtime_peer_fixture", SOURCE)
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)
FIXTURE = PROFILE.FIXTURE
FIXTURE.CASE = "nodeguard::runtime_endpoint::native_tests::root_reconnect_binding_drains_control_without_forwarding_to_replacements"
FIXTURE.MARKER = "NODEGUARD_NATIVE_RUNTIME_PEER_BINDING_VERIFIED"
FIXTURE.ACCEPTANCE_SCOPE = "LOCAL_FIXED_UDS_PEER_AND_VOLATILE_DRAIN_ONLY_NOT_MTLS_DAEMON_BINARY_CONTINUOUS_CONFIG_KATA_OR_IMAGES_PREPARATION"
FIXTURE.SUCCESS_MESSAGE = "PASS fixed UDS peer binding and volatile CRI/CONTROL drain; official containerd socket restored; no daemon-binary, mTLS or Kata certification"


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
        print("Native runtime peer acceptance failed; " + suffix, file=sys.stderr)
        raise SystemExit(1) from None
