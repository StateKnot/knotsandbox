#!/usr/bin/env python3
"""Fetch exact official release archives; extract only the lock's named files."""
import argparse
from pathlib import Path
import tarfile
import urllib.parse
import urllib.request
from common import ROOT, dump, load, require, sha


def download(url, path, limit=300 * 1024 * 1024):
    require(url.startswith('https://github.com/') or url.startswith('https://www.haproxy.org/'), 'DOWNLOAD_SOURCE')
    with urllib.request.urlopen(url, timeout=60) as response, open(path, 'xb') as output:
        require(urllib.parse.urlsplit(response.url).scheme == 'https', 'DOWNLOAD_REDIRECT')
        size = 0
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            require(size <= limit, 'DOWNLOAD_SIZE')
            output.write(chunk)


def install(directory):
    directory = Path(directory)
    require(not directory.exists(), 'FRESH_TOOLS_DIRECTORY_REQUIRED')
    directory.mkdir(parents=True, mode=0o755)
    record = {'lock_sha256': sha(ROOT / 'tools.lock.json'), 'binaries': {}}
    for name, spec in load(ROOT / 'tools.lock.json')['tools'].items():
        archive = directory / (name + '.download')
        download(spec['url'], archive)
        require(sha(archive) == spec['sha256'], 'TOOL_ARCHIVE_HASH')
        if '' in spec['members']:
            archive.rename(directory / spec['members'][''])
        else:
            with tarfile.open(archive, 'r:gz') as source:
                names = source.getnames()
                for member, target in spec['members'].items():
                    require(names.count(member) == 1, 'TOOL_ARCHIVE_MEMBER')
                    entry = source.getmember(member)
                    require(entry.isfile() and 0 < entry.size <= 200 * 1024 * 1024, 'TOOL_ARCHIVE_MEMBER')
                    stream = source.extractfile(entry)
                    require(stream is not None, 'TOOL_ARCHIVE_MEMBER')
                    (directory / target).write_bytes(stream.read())
            archive.unlink()
        for target in spec['members'].values():
            path = directory / target
            path.chmod(0o755)
            record['binaries'][target] = sha(path)
    dump(directory / 'installed.json', record)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    install(args.output)
