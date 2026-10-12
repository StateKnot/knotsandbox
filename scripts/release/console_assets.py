"""Verified console OCI assets and npm inventories. Never trusts an input folder alone."""
import hashlib
import json
import re
import shutil
import tarfile
from common import DIGEST, SHA, TAG, dump, image_digest, load, require, run, timevalue, unique

PUBLIC = 'usr/share/nginx/html/'
PRIVATE = 'usr/share/sandbox-console/'
HEX = re.compile(r'[a-f0-9]{64}\Z')
ASSET = re.compile(r'[A-Za-z0-9_-]+\.(?:js|css)\Z')


def lock_packages(lock):
    require(lock.get('lockfileVersion') == 3 and isinstance(lock.get('packages'), dict), 'NPM_LOCK_FORMAT')
    result = set()
    for path, package in lock['packages'].items():
        if not path: continue
        require(isinstance(path, str) and 'node_modules/' in path and not package.get('link'), 'NPM_LOCK_PACKAGE_PATH')
        name = package.get('name') or path.rsplit('node_modules/', 1)[1]
        require(re.fullmatch(r'(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+', name) and isinstance(package.get('version'), str), 'NPM_LOCK_PACKAGE')
        require(package.get('resolved', '').startswith('https://registry.npmjs.org/') and re.fullmatch(r'sha512-[A-Za-z0-9+/]+={0,2}', package.get('integrity', '')), 'NPM_LOCK_UNPINNED')
        result.add((name, package['version']))
    require(result and len(result) <= 10000, 'NPM_LOCK_EMPTY_OR_LIMIT')
    return result


def selected(name):
    return name == PUBLIC+'bundle-manifest.json' or name.startswith(PUBLIC+'assets/') or name.startswith(PRIVATE)


def image_files(directory):
    """Read only bounded regular console files from hash-verified OCI layers.

    Unknown ancestors, whiteout replacement or selected symlink/hardlink inputs
    fail closed instead of approximating container overlay semantics.
    """
    image_digest(directory, 'console')
    index=load(directory/'index.json')
    manifest=load(directory/'blobs/sha256'/index['manifests'][0]['digest'][7:])
    files={};count=0;total=0
    for layer in manifest['layers']:
        path=directory/'blobs/sha256'/layer['digest'][7:]
        require(layer['mediaType'] in ('application/vnd.oci.image.layer.v1.tar','application/vnd.oci.image.layer.v1.tar+gzip'), 'CONSOLE_LAYER_FORMAT')
        with tarfile.open(path,'r|*') as archive:
            seen=set()
            for member in archive:
                name=member.name.removeprefix('./').rstrip('/')
                if name in ('','.') and member.isdir(): continue
                require(name and not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')) and name not in seen, 'CONSOLE_LAYER_PATH')
                seen.add(name);count+=1;total+=member.size
                require(count <= 200000 and 0 <= member.size <= 1024**3 and total <= 2*1024**3, 'CONSOLE_LAYER_LIMIT')
                basename=name.split('/')[-1]
                if basename.startswith('.wh.'):
                    parent='/'.join(name.split('/')[:-1])
                    affected=parent if basename=='.wh..wh..opq' else '/'.join(filter(None,(parent,basename[4:])))
                    if not affected or any(root.rstrip('/')==affected or root.startswith(affected+'/') or affected.startswith(root) for root in (PUBLIC,PRIVATE)):
                        raise ValueError('CONSOLE_LAYER_WHITEOUT')
                ancestor=any(root.startswith(name+'/') for root in (PUBLIC,PRIVATE))
                if ancestor: require(member.isdir(), 'CONSOLE_LAYER_ANCESTOR_LINK')
                if not selected(name): continue
                if member.isdir(): continue
                require(member.isfile() and member.size <= 8*1024*1024, 'CONSOLE_LAYER_SELECTED_LINK_OR_LIMIT')
                data=archive.extractfile(member).read()
                require(len(data)==member.size,'CONSOLE_LAYER_FILE_SIZE')
                files[name]=data
    require(sum(map(len,files.values()))<=64*1024*1024 and len(files)<=400,'CONSOLE_FILE_LIMIT')
    return files


def inventory(files):
    lock_names=[name for name in files if name.startswith(PRIVATE) and name.endswith('/package-lock.json')]
    require(PRIVATE+'package-lock.json' in lock_names and PRIVATE+'package.json' in files, 'CONSOLE_NPM_INVENTORY_MISSING')
    records={}
    for name in lock_names:
        data=files[name]
        lock=json.loads(data,object_pairs_hook=unique)
        lock_packages(lock)
        digest=hashlib.sha256(data).hexdigest()
        records[digest]={'sha256':digest,'lock':lock}
    require(0 < len(records) <= 30, 'CONSOLE_NPM_INVENTORY_LIMIT')
    return {'version':1,'locks':[records[k] for k in sorted(records)]}


def asset_manifest(files):
    require(PUBLIC+'bundle-manifest.json' in files,'CONSOLE_ASSET_MANIFEST_MISSING')
    manifest=json.loads(files[PUBLIC+'bundle-manifest.json'],object_pairs_hook=unique)
    require(set(manifest)=={'schema','assets'} and manifest['schema']==1 and isinstance(manifest['assets'],dict) and 0 < len(manifest['assets']) <= 200, 'CONSOLE_ASSET_MANIFEST')
    for name, digest in manifest['assets'].items():
        require(ASSET.fullmatch(name) and isinstance(digest,str) and HEX.fullmatch(digest),'CONSOLE_ASSET_IDENTITY')
        require(hashlib.sha256(files.get(PUBLIC+'assets/'+name,b'')).hexdigest()==digest,'CONSOLE_ASSET_HASH')
    require({name.removeprefix(PUBLIC+'assets/') for name in files if name.startswith(PUBLIC+'assets/')}==set(manifest['assets']),'CONSOLE_ASSET_COVERAGE')
    return manifest


def validate_inventory(record):
    require(set(record)=={'version','locks'} and record['version']==1 and isinstance(record['locks'],list) and 0<len(record['locks'])<=30,'CONSOLE_NPM_INVENTORY_FORMAT')
    expected=set();seen=set()
    for entry in record['locks']:
        require(set(entry)=={'sha256','lock'} and HEX.fullmatch(entry['sha256']) and entry['sha256'] not in seen,'CONSOLE_NPM_INVENTORY_HASH')
        seen.add(entry['sha256']);expected.update(lock_packages(entry['lock']))
    return expected


def validate_selection(first, previous_tag, previous_commit, current_tag):
    require(type(first) is bool,'CONSOLE_FIRST_RELEASE_BOOLEAN')
    if first: require(not previous_tag and not previous_commit,'CONSOLE_FIRST_RELEASE_WITH_PREVIOUS')
    else: require(isinstance(previous_tag,str) and TAG.fullmatch(previous_tag) and previous_tag!=current_tag and isinstance(previous_commit,str) and SHA.fullmatch(previous_commit),'VERIFIED_PREVIOUS_CONSOLE_RELEASE_REQUIRED')


def validate_chain(chain, repository, tag, commit):
    require(set(chain)=={'first_release','previous'} and type(chain['first_release']) is bool,'CONSOLE_CHAIN_FORMAT')
    previous=chain['previous']
    validate_selection(chain['first_release'],previous.get('tag') if isinstance(previous,dict) else None,previous.get('commit') if isinstance(previous,dict) else None,tag)
    if chain['first_release']: require(previous is None,'CONSOLE_CHAIN_FIRST_RELEASE');return
    require(set(previous)=={'repository','tag','commit','manifest_sha256','console_digest','created_at'} and previous['repository']==repository and previous['commit']!=commit and HEX.fullmatch(previous['manifest_sha256']) and DIGEST.fullmatch(previous['console_digest']),'CONSOLE_CHAIN_IDENTITY')
    timevalue(previous['created_at'])


def verify_previous(directory, tools, repository, tag, commit):
    from verify import cosign_arguments, verify_candidate, verify_statement
    # No input asset interpretation occurs until the exact external identity is
    # cryptographically authenticated against pinned Fulcio/Rekor roots.
    run(cosign_arguments(directory,tools,repository,tag,commit),timeout=60)
    signed=load(directory/'release-manifest.json')
    manifest=verify_candidate(directory,repository,tag,commit,timevalue(signed['created_at']),historical=True)
    verify_statement(directory,manifest)
    return manifest


def stage_context(source, destination, previous=None):
    require(source.is_dir() and not source.is_symlink(), 'CONSOLE_SOURCE_ROOT')
    require(not destination.exists(),'FRESH_CONSOLE_CONTEXT_REQUIRED')
    destination.mkdir()
    inputs=['.dockerignore','deploy/console/Dockerfile','console/package.json','console/package-lock.json','console/index.html','console/tsconfig.json','console/vite.config.ts','console/scripts/prepare-assets.mjs','sdk/typescript/src/schema.d.ts','sdk/typescript/src/events.ts','sdk/typescript/src/event-message.ts','sdk/typescript/src/sse.ts','sdk/typescript/src/transport.ts']
    for name in inputs:
        original=source/name;require(original.is_file() and not original.is_symlink(),'CONSOLE_SOURCE_FILE')
        for parent in original.parents:
            if parent==source: break
            require(parent.is_dir() and not parent.is_symlink(), 'CONSOLE_SOURCE_ANCESTOR_LINK')
        target=destination/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(original,target)
    require((source/'console/src').is_dir() and not (source/'console/src').is_symlink(), 'CONSOLE_SOURCE_DIRECTORY')
    for original in (source/'console/src').rglob('*'):
        require(not original.is_symlink(),'CONSOLE_SOURCE_LINK')
        if original.is_file():
            target=destination/original.relative_to(source);target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(original,target)
    target=destination/'console/release-assets';target.mkdir(parents=True)
    retained=target/'npm-inventory';retained.mkdir()
    if previous is None:
        dump(target/'bundle-manifest.json',{'schema':1,'assets':{}})
        return
    files=previous;manifest=asset_manifest(files);inventory(files)
    dump(target/'bundle-manifest.json',manifest)
    for name in manifest['assets']:
        out=target/'assets'/name;out.parent.mkdir(exist_ok=True);out.write_bytes(files[PUBLIC+'assets/'+name])
    for name,data in files.items():
        if name.startswith(PRIVATE) and name.endswith('/package-lock.json'):
            package=name.removesuffix('package-lock.json')+'package.json'
            require(package in files,'CONSOLE_PACKAGE_PAIR_MISSING')
            digest=hashlib.sha256(data).hexdigest()
            out=retained/digest;out.mkdir(exist_ok=True)
            (out/'package-lock.json').write_bytes(data);(out/'package.json').write_bytes(files[package])
