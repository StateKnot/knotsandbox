#!/usr/bin/env python3
"""Verify CRI config identity against independently generated native metadata.

Reuse the existing native metadata fixture's ordinary Cargo ELF selection,
official containerd pins, immutable public OCI inputs, resource bounds and
retirement/input-identity gates. This only adds one public config-digest input
and selects the exact CRI-index acceptance case.
"""
import argparse
import importlib.util
from pathlib import Path
import signal
import sys

sys.dont_write_bytecode = True
SOURCE = Path(__file__).with_name("test-nodeguard-native-metadata.py")
SPEC = importlib.util.spec_from_file_location("cri_metadata_native_fixture", SOURCE)
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)
FIXTURE = NATIVE.FIXTURE
FIXTURE.CASE = "nodeguard::native_image_metadata::cri_cli_tests::cri_metadata_readback_and_admin_cli_remain_index_only"
FIXTURE.MARKER = "NODEGUARD_CRI_METADATA_CLI_VERIFIED"
FIXTURE.ACCEPTANCE_SCOPE = "LOCAL_CRI_INDEX_CONFIG_IDENTITY_AND_ADMIN_CLI_ONLY_NOT_APPROVAL_PULL_SELECTION_HANDLER_SNAPSHOTTER_UNPACK_GC_PREPARATION_GPU_OR_CLOUD"
FIXTURE.SUCCESS_MESSAGE = "PASS exact CRI index/config identity and admin CLI; owned daemon retired; images remain unpacked=false; no pull selection or image preparation certification"
PREPARE_FILES = FIXTURE.prepare_files


def prepare_files(stage, archive, binary, arch):
    image = PREPARE_FILES(stage, archive, binary, arch)
    # This digest comes from the independently generated archive, not a runtime
    # ImageStatus response or the implementation being accepted.
    NATIVE.STATE["environment"]["SANDBOX_NATIVE_METADATA_CONFIG_DIGEST"] = image["config"]["digest"]
    return image


FIXTURE.prepare_files = prepare_files


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--admin-artifacts", type=Path, required=True)
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
        print("CRI metadata acceptance failed; " + suffix, file=sys.stderr)
        raise SystemExit(1) from None
