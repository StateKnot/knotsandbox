#!/usr/bin/env python3
"""Inspect snapshot references without pulling, applying or mounting image layers.

The native runner supplies the exact ordinary admin ELF, independent public OCI
fixture, pinned containerd, original resource bounds, retirement and no-unpack
gates. Only a config digest and the single uncompressed layer's known DiffID are
added; the case creates and retires an empty metadata fixture, never a workload.
"""
import argparse
import importlib.util
from pathlib import Path
import signal
import sys

sys.dont_write_bytecode = True
SOURCE = Path(__file__).with_name("test-nodeguard-native-metadata.py")
SPEC = importlib.util.spec_from_file_location("snapshot_metadata_native_fixture", SOURCE)
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)
FIXTURE = NATIVE.FIXTURE
FIXTURE.CASE = "nodeguard::native_image_metadata::snapshot_cli_tests::snapshot_metadata_readback_and_admin_cli_remain_reference_only"
FIXTURE.MARKER = "NODEGUARD_SNAPSHOT_METADATA_CLI_VERIFIED"
FIXTURE.ACCEPTANCE_SCOPE = "LOCAL_SNAPSHOT_REFERENCE_METADATA_AND_ADMIN_CLI_ONLY_NOT_APPROVAL_PULL_SELECTION_HANDLER_LAYER_APPLY_UNPACK_GC_PREPARATION_GPU_OR_CLOUD"
FIXTURE.SUCCESS_MESSAGE = "PASS exact snapshot reference metadata and admin CLI; empty fixture retired; images remain unpacked=false; no layer application or image preparation certification"
PREPARE_FILES = FIXTURE.prepare_files


def prepare_files(stage, archive, binary, arch):
    image = PREPARE_FILES(stage, archive, binary, arch)
    # The fixture has one uncompressed tar layer. Its independently generated
    # byte digest is the DiffID and, for one layer, the OCI ChainID itself.
    FIXTURE.require(len(image["layers"]) == 1 and
                    image["layers"][0]["mediaType"] == "application/vnd.oci.image.layer.v1.tar",
                    "SINGLE_INDEPENDENT_UNCOMPRESSED_LAYER_REQUIRED")
    NATIVE.STATE["environment"].update({
        "SANDBOX_NATIVE_METADATA_CONFIG_DIGEST": image["config"]["digest"],
        "SANDBOX_NATIVE_METADATA_DIFF_ID": image["layers"][0]["digest"],
    })
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
        print("Snapshot metadata acceptance failed; " + suffix, file=sys.stderr)
        raise SystemExit(1) from None
