#!/usr/bin/env python3
"""Install the checksum-pinned official CLI into .local only; no cloud actions."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import sys
import urllib.request
import zipfile

root = Path(__file__).resolve().parents[2]
lock = json.loads(Path(__file__).with_name("toolchain.lock.json").read_text())
arch = {"x86_64": "amd64", "AMD64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine())
platform_name = f"{sys.platform}_{arch}"
if platform_name not in lock["sha256"]:
    raise SystemExit("Only the pinned Linux/macOS x86_64/arm64 CLI builds are supported")
archive = f"terraform_{lock['terraform_version']}_{platform_name}.zip"
with urllib.request.urlopen(lock["release"] + archive, timeout=120) as response:
    payload = response.read(100 * 1024 * 1024 + 1)
if len(payload) > 100 * 1024 * 1024 or hashlib.sha256(payload).hexdigest() != lock["sha256"][platform_name]:
    raise SystemExit("Terraform download checksum mismatch")
destination = root / ".local" / "tools" / f"terraform-{lock['terraform_version']}"
destination.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(io.BytesIO(payload)) as downloaded:
    executable = downloaded.read("terraform")
temporary = destination / f"terraform.download-{os.getpid()}"
try:
    temporary.write_bytes(executable)
    temporary.chmod(0o755)
    temporary.replace(destination / "terraform")
finally:
    temporary.unlink(missing_ok=True)
print(destination / "terraform")
