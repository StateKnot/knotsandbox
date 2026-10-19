#!/usr/bin/env python3
"""Reproduce small independent fixture/oracle files using Python's stdlib only."""
from pathlib import Path
import gzip
import hashlib
import io
import json
import tarfile

OUT = Path(__file__).resolve().parent


def tar(name: str, data: bytes) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        entry = tarfile.TarInfo(name)
        entry.size = len(data)
        entry.mode = 0o644
        entry.mtime = 0
        entry.uid = entry.gid = 0
        archive.addfile(entry, io.BytesIO(data))
    return output.getvalue()


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def write(name: str, encoded: bytes, decoded: bytes, members: int) -> dict:
    (OUT / name).write_bytes(encoded)
    # Verify the external oracle with the independent stdlib decoder.
    if members:
        assert gzip.decompress(encoded) == decoded
    return {"file": name, "digest": digest(encoded), "encoded_bytes": len(encoded),
            "diff_id": digest(decoded), "decoded_bytes": len(decoded), "gzip_members": members}


a = tar("usr/share/payload.txt", b"PUBLIC_SECRET_SENTINEL\nOCI payload fixture alpha\n")
b = tar("etc/payload.conf", b"OCI payload fixture beta\n")
large = tar("var/lib/expansion", b"x" * (256 * 1024))
empty_gzip = gzip.compress(b"", mtime=0)
items = [
    write("alpha.tar", a, a, 0),
    write("beta.tar.gz", gzip.compress(b, mtime=0), b, 1),
    write("concatenated.tar.gz", gzip.compress(a[:4097], mtime=0) + gzip.compress(a[4097:] + b, mtime=0), a + b, 2),
    write("expansion.tar.gz", gzip.compress(large, mtime=0), large, 1),
    write("empty-members.gz", empty_gzip * 1025, b"", 1025),
    write("exact-empty-members.gz", empty_gzip * 1024, b"", 1024),
    write("split-empty-members-a.gz", empty_gzip * 600, b"", 600),
    write("split-empty-members-b.gz", gzip.compress(b"", mtime=1) * 600, b"", 600),
]
# A legal, large FNAME header forces the verifier's encoded-byte bound to cover
# header processing as well as deflate data. No decoder under test made this.
normal = gzip.compress(b, mtime=0)
long_header = normal[:3] + bytes([normal[3] | 8]) + normal[4:10] + b"n" * (256 * 1024) + b"\0" + normal[10:]
items.append(write("long-header.tar.gz", long_header, b, 1))
(OUT / "oracles.json").write_text(json.dumps(items, indent=2) + "\n")
