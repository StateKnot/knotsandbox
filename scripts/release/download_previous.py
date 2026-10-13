#!/usr/bin/env python3
"""Read-only download of a same-repository previous signed release. Never publishes."""
import argparse
from pathlib import Path
import subprocess
from common import SQLX_POSTGRES_NOTICES, load, require, release_file_names, run, subject, tool
from preflight import github
from verify import cosign_arguments
from sqlx_notices import MAX_BYTES as NOTICES_MAX_BYTES


def download(directory, tools, repository, tag, commit):
    subject(repository,tag,commit)
    require(not directory.exists(),'FRESH_PREVIOUS_RELEASE_DIRECTORY_REQUIRED')
    release=github('repos/'+repository+'/releases/tags/'+tag)
    require(not release.get('draft') and release.get('tag_name')==tag,'PREVIOUS_RELEASE_NOT_PUBLISHED')
    assets={a['name']:a for a in release['assets']}
    require(len(assets)==len(release['assets']),'PREVIOUS_RELEASE_DUPLICATE_ASSETS')
    small={'release-manifest.json','release-manifest.sigstore.json','provenance.json'}
    require(small<=set(assets) and all(0<assets[n]['size']<=4*1024*1024 for n in small),
            'PREVIOUS_RELEASE_METADATA_LIMIT')
    directory.mkdir()
    gh=tool(tools,'gh')
    def fetch(names):
        command=[gh,'release','download',tag,'--repo',repository,'--dir',directory]
        for name in sorted(names):command+=['--pattern',name]
        run(command,timeout=1200,stdout=subprocess.DEVNULL)
    fetch(small)
    run(cosign_arguments(directory,tools,repository,tag,commit),timeout=60,stdout=subprocess.DEVNULL)
    manifest=load(directory/'release-manifest.json',1024*1024)
    require(type(manifest.get('version')) is int and manifest['version'] in (1,2,3),'PREVIOUS_RELEASE_VERSION')
    files=release_file_names(legacy=manifest['version']==1, version=manifest['version'],
                             binary_names=manifest['binaries'], historical=True)
    require(set(manifest['files'])==files and files<=set(assets),'PREVIOUS_RELEASE_FILE_COVERAGE')
    require(all(0<assets[n]['size']<=8*1024**3 for n in files) and sum(assets[n]['size'] for n in files)<=16*1024**3,'PREVIOUS_RELEASE_ASSET_LIMIT')
    require(all(manifest['files'][n]['size']==assets[n]['size'] for n in manifest['files']),'PREVIOUS_RELEASE_FILE_SIZE')
    if manifest['version'] == 3:
        require(assets[SQLX_POSTGRES_NOTICES]['size']<=NOTICES_MAX_BYTES, 'PREVIOUS_RELEASE_NOTICES_LIMIT')
    fetch(files)
    # build.py cryptographically rechecks, verifies every hash/OCI/statement and
    # scanner evidence before it interprets any console asset or npm inventory.


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('repository','tag','commit'):p.add_argument('--'+name,required=True)
    p.add_argument('--tools',type=Path,required=True);p.add_argument('--directory',type=Path,required=True)
    a=p.parse_args();download(a.directory,a.tools,a.repository,a.tag,a.commit)
