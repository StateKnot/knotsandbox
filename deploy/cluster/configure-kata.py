#!/usr/bin/env python3
"""Harden the ORIGINAL installed Go-QEMU config; never synthesize a Rust config."""
import argparse
import os
from pathlib import Path
import re
import tomllib

OVERRIDES = {
    "hypervisor.qemu": {"enable_annotations": "[]", "enable_debug": "false"},
    "runtime": {"sandbox_cgroup_only": "true", "enable_debug": "false", "disable_new_netns": "false"},
    "factory": {"enable_template": "false", "vm_cache_number": "0"},
}


def harden(text):
    original = tomllib.loads(text)
    if "qemu" not in original.get("hypervisor", {}) or "runtime" not in original:
        raise ValueError("expected original Kata Go QEMU configuration")
    lines, section, seen = [], None, set()
    for line in text.splitlines():
        match = re.fullmatch(r"\s*\[([^]]+)\]\s*", line)
        if match:
            section = match.group(1)
        key = re.match(r"\s*([A-Za-z_]+)\s*=", line)
        if key and section in OVERRIDES and key.group(1) in OVERRIDES[section]:
            identity = (section, key.group(1))
            if identity in seen:
                raise ValueError("duplicate runtime security option")
            seen.add(identity)
            line = key.group(1) + " = " + OVERRIDES[section][key.group(1)]
        lines.append(line)
    # Defaulted/commented factory fields still must become explicit. Insert in
    # the matching section, or create the official [factory] section if absent.
    for section, options in OVERRIDES.items():
        missing = [f"{key} = {value}" for key, value in options.items() if (section, key) not in seen]
        if not missing:
            continue
        indexes = [i for i, line in enumerate(lines) if line.strip() == f"[{section}]"]
        if indexes:
            lines[indexes[0] + 1:indexes[0] + 1] = missing
        else:
            lines.extend([f"[{section}]", *missing])
    result = "\n".join(lines) + "\n"
    parsed = tomllib.loads(result)
    assert parsed["runtime"]["sandbox_cgroup_only"] is True
    assert parsed["factory"]["enable_template"] is False
    assert parsed["factory"]["vm_cache_number"] == 0
    assert parsed["hypervisor"]["qemu"]["enable_annotations"] == []
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    result = harden(args.source.read_text())
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.destination.with_suffix(".pending")
    with temporary.open("w") as output:
        output.write(result)
        output.flush()
        os.fsync(output.fileno())
    temporary.chmod(0o644)
    temporary.replace(args.destination)
