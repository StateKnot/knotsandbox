"""Recompute native inventory from actual checksum-locked compiler inputs."""
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import tarfile
import tomllib
from urllib.parse import quote
from common import BINARIES, release_binaries, ROOT, dump, image_digest, load, require, sha
from elf import GNU, validate_file
from sqlite_build import contract as sqlite_contract, validate_inputs as validate_sqlite_inputs

LOCK_FIELDS = {'version','profile','rust_version','target','builder_image','crt_packages','crt_files','sysroot_files'}
MAX_INPUTS = 128 * 1024 * 1024


def contract(value, *, historical=False):
    require(type(value.get('version')) is int and value['version'] in (1,2) and set(value)==(LOCK_FIELDS | {'sqlite'} if value['version']==2 else LOCK_FIELDS), 'NATIVE_CONTRACT_FORMAT')
    current = load(ROOT/'native-security.lock.json')
    require(historical or value == current, 'NATIVE_UNREVIEWED_CONTRACT')
    require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', value['rust_version']) and re.fullmatch(r'rust:'+re.escape(value['rust_version'])+r'-bookworm@sha256:[a-f0-9]{64}',value['builder_image']), 'NATIVE_BUILDER_CONTRACT')
    require(all(value[key] == current[key] for key in ('crt_packages','crt_files','sysroot_files')), 'NATIVE_SOURCE_CONTRACT')
    require(value['profile'] == GNU and value['target'] == 'x86_64-unknown-linux-gnu', 'NATIVE_PROFILE_NOT_IMPLEMENTED')
    if value['version']==2:sqlite_contract(value['sqlite'])
    return value


def crates(lock_bytes):
    packages = tomllib.loads(lock_bytes.decode())['package']
    result = {}
    for name in ('libsqlite3-sys','ring'):
        matches = [p for p in packages if p['name'] == name]
        require(len(matches) == 1, 'NATIVE_CRATE_LOCK')
        p = matches[0]
        require(p.get('source') == 'registry+https://github.com/rust-lang/crates.io-index' and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',p['version']) and re.fullmatch(r'[a-f0-9]{64}',p.get('checksum','')), 'NATIVE_CRATE_SOURCE')
        result[name] = p
    return result


def crate_contents(data, package):
    require(hashlib.sha256(data).hexdigest() == package['checksum'], 'NATIVE_CRATE_CHECKSUM')
    prefix = package['name']+'-'+package['version']+'/'
    result, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
        for member in archive:
            require(member.name.startswith(prefix) and member.isfile() and member.name not in result and len(result)<4096, 'NATIVE_CRATE_MEMBER')
            name=member.name[len(prefix):]
            require(name and all(p not in ('','..','.') for p in name.split('/')), 'NATIVE_CRATE_PATH')
            total += member.size
            require(total <= 48*1024*1024 and member.size <= 16*1024*1024, 'NATIVE_CRATE_BOUND')
            source=archive.extractfile(member);require(source is not None,'NATIVE_CRATE_FILE')
            result[member.name]=source.read(member.size+1)
            require(len(result[member.name]) == member.size,'NATIVE_CRATE_LENGTH')
    manifest=tomllib.loads(result[prefix+'Cargo.toml'].decode())['package']
    require(manifest['name']==package['name'] and manifest['version']==package['version'],'NATIVE_CRATE_MANIFEST')
    return {name[len(prefix):]:data for name,data in result.items()}


def export_dockerfile(source, lock):
    """An extra stage inherits the actual unchanged production builder."""
    lock=contract(lock);packages=crates((source/'Cargo.lock').read_bytes())
    original=(source/'Dockerfile').read_text()
    require('ARG RUST_IMAGE='+lock['builder_image']+'\n' in original,'NATIVE_BUILDER_IMAGE')
    if lock['version']==2:
        sqlite=lock['sqlite']
        required=['ADD --checksum=sha256:'+sqlite['sha256']+' '+sqlite['url']+' /tmp/sqlite-source.tar.gz',
                  'RUN --network=none python3 /build/scripts/release/sqlite_build.py --archive /tmp/sqlite-source.tar.gz --destination /opt/sandbox-sqlite',
                  'ENV SANDBOX_PRODUCTION_NATIVE=1',
                  'ENV LIBSQLITE3_SYS_USE_PKG_CONFIG=1 SQLITE3_NO_PKG_CONFIG=1 SQLITE3_STATIC=1',
                  'ENV SQLITE3_LIB_DIR=/opt/sandbox-sqlite/lib SQLITE3_INCLUDE_DIR=/opt/sandbox-sqlite/include',
                  'cargo clean --locked --offline --release -p libsqlite3-sys',
                  'python3 /build/scripts/release/sqlite_build.py --capture-link-output --destination /opt/sandbox-sqlite/evidence']
        require(all(original.count(line)==1 for line in required),'NATIVE_SQLITE_BUILD_CONTRACT')
        clean_at = original.index(required[-2]); capture_at = original.index(required[-1])
        build_command = ('cargo build --locked --release ' +
                         ' '.join('--bin ' + name for name in BINARIES) +
                         ' --message-format=json-render-diagnostics > /opt/sandbox-sqlite/evidence/production-cargo.json')
        require(original.count(build_command) == 1, 'NATIVE_SQLITE_CARGO_RECEIPT')
        build_at = original.index(build_command)
        require(clean_at < build_at < capture_at and
                original.rfind('\nRUN ', 0, clean_at) == original.rfind('\nRUN ', 0, capture_at),
                'NATIVE_SQLITE_CAPTURE_ORDER')
        require((source/'scripts/release/sqlite_build.py').read_bytes()==(ROOT/'sqlite_build.py').read_bytes(),'NATIVE_SQLITE_BUILD_HELPER')
    commands=['mkdir -p /native-export/bin /native-export/inputs/crates /native-export/inputs/crt /native-export/inputs/sysroot /native-export/inputs/sources',
              'cp /artifacts/* /native-export/bin/', 'cp /build/Cargo.lock /native-export/inputs/Cargo.lock',
              'rustc --version --verbose > /native-export/inputs/rustc.txt',
              'gcc -dumpfullversion > /native-export/inputs/gcc.txt',
              "dpkg-query -W -f='${binary:Package}\\t${Version}\\n' "+' '.join(lock['crt_packages'])+' > /native-export/inputs/packages.tsv']
    for name,p in packages.items():
        commands.append('cp /usr/local/cargo/registry/cache/*/'+name+'-'+p['version']+'.crate /native-export/inputs/crates/'+name+'.crate')
        commands.append('cp -R /usr/local/cargo/registry/src/*/'+name+'-'+p['version']+' /native-export/inputs/sources/'+name)
    for name in lock['crt_files']:
        commands.append('native_path=$(realpath "$(gcc -print-file-name='+name+')") && test -f "$native_path" && cp "$native_path" /native-export/inputs/crt/'+name+' && dpkg-query -S "$native_path" >> /native-export/inputs/owners.txt')
    commands.append('native_sysroot=$(rustc --print sysroot)/lib/rustlib/'+lock['target']+'/lib')
    for name in lock['sysroot_files']:
        commands.append('cp "$native_sysroot"/'+name+'-*.rlib /native-export/inputs/sysroot/'+name+'.rlib')
    if lock['version']==2:
        # The production Cargo RUN sealed the graph's matching host/target
        # outputs before later invocations could alter the shared cache.
        commands+=['mkdir /native-export/inputs/sqlite', 'cp /opt/sandbox-sqlite/evidence/* /native-export/inputs/sqlite/']
    mounts='--network=none --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked --mount=type=cache,target=/build/target,id=sandbox-rust-1.98.1-amd64,sharing=locked '
    acceptance=''
    parent='builder'
    if lock['version']==2:
        acceptance='\nFROM builder AS sqlite-journal-acceptance\nRUN '+mounts+'(cargo test --locked --offline --release --test nodeguard_journal_native nodeguard_journal_regression_ -- --test-threads=1 > /opt/sandbox-sqlite/evidence/journal-tests.txt 2>&1 && cargo test --locked --offline --release --test nodeguard_journal_native sqlite_release_acceptance_ -- --ignored --test-threads=1 > /opt/sandbox-sqlite/evidence/journal-acceptance.txt 2>&1) || { tail -n 80 /opt/sandbox-sqlite/evidence/journal-tests.txt; if test -f /opt/sandbox-sqlite/evidence/journal-acceptance.txt; then tail -n 80 /opt/sandbox-sqlite/evidence/journal-acceptance.txt; fi; exit 1; }\n'
        parent='sqlite-journal-acceptance'
    separator=' '+chr(92)+'\n    && '
    return original+acceptance+'\nFROM '+parent+' AS native-inventory\nRUN '+mounts+separator.join(commands)+'\nFROM scratch AS native-export\nCOPY --from=native-inventory /native-export/ /\n'


def archive_inputs(inputs, target):
    total=0
    with tarfile.open(target,'x') as archive:
        for source in sorted(inputs.rglob('*')):
            require(not source.is_symlink(),'NATIVE_INPUT_LINK')
            if source.is_file():
                total+=source.stat().st_size;require(total<=MAX_INPUTS,'NATIVE_INPUT_BOUND')
                data=source.read_bytes();member=tarfile.TarInfo(source.relative_to(inputs).as_posix());member.size=len(data);member.mode=0o444;member.mtime=0
                archive.addfile(member,io.BytesIO(data))


def directory_inputs(directory):
    values,total={},0
    for path in sorted(directory.rglob('*')):
        require(not path.is_symlink(),'NATIVE_INPUT_LINK')
        if path.is_file():
            total+=path.stat().st_size;require(total<=MAX_INPUTS and len(values)<4096,'NATIVE_INPUT_BOUND')
            values[path.relative_to(directory).as_posix()]=path.read_bytes()
    return values


def read_inputs(archive_path):
    values,total={},0
    with tarfile.open(archive_path,'r:') as archive:
        for member in archive:
            require(member.isfile() and member.name not in values and len(values)<4096 and all(p not in ('','..','.') for p in member.name.split('/')) and not member.name.startswith('/'),'NATIVE_INPUT_MEMBER')
            total+=member.size;require(total<=MAX_INPUTS and member.size<=48*1024*1024,'NATIVE_INPUT_BOUND')
            source=archive.extractfile(member);require(source is not None,'NATIVE_INPUT_FILE')
            values[member.name]=source.read(member.size+1);require(len(values[member.name])==member.size,'NATIVE_INPUT_LENGTH')
    return values


def inventory(values, lock_bytes, lock, binaries, *, historical=False, binary_names=None):
    names=release_binaries(BINARIES if binary_names is None else binary_names,historical=historical)
    lock=contract(lock,historical=historical)
    expected={'Cargo.lock','rustc.txt','gcc.txt','packages.tsv','owners.txt','crates/libsqlite3-sys.crate','crates/ring.crate'}|{'crt/'+n for n in lock['crt_files']}|{'sysroot/'+n+'.rlib' for n in lock['sysroot_files']}
    require(expected<=set(values) and values['Cargo.lock']==lock_bytes,'NATIVE_INPUT_COVERAGE')
    require(all(0<len(values[n])<=48*1024*1024 for n in expected),'NATIVE_INPUT_EMPTY')
    for name in lock['sysroot_files']:
        require(values['sysroot/'+name+'.rlib'].startswith(b'!<arch>\n'),'NATIVE_SYSROOT_ARCHIVE')
    for name in lock['crt_files']:
        data=values['crt/'+name]
        require(data.startswith(b'!<arch>\n') if name.endswith('.a') else len(data)>=64 and data[:7]==b'\x7fELF\x02\x01\x01' and data[16:20]==b'\x01\x00\x3e\x00','NATIVE_CRT_OBJECT')
    lines=values['rustc.txt'].decode().splitlines();compiler={}
    require(lines and lines[0].startswith('rustc '+lock['rust_version']+' '),'NATIVE_RUST_VERSION')
    for line in lines[1:]:
        key,sep,value=line.partition(': ');require(sep and key not in compiler,'NATIVE_RUST_METADATA');compiler[key]=value
    require(compiler.get('release')==lock['rust_version'] and compiler.get('host')==lock['target'] and re.fullmatch(r'[a-f0-9]{40}',compiler.get('commit-hash','')),'NATIVE_RUST_TARGET')
    gcc=values['gcc.txt'].decode().strip();require(re.fullmatch(r'12\.[0-9]+\.[0-9]+',gcc),'NATIVE_GCC_VERSION')
    packages={}
    for line in values['packages.tsv'].decode().splitlines():
        name,version=line.split('\t');name=name.split(':')[0]
        require(name in lock['crt_packages'] and name not in packages and re.fullmatch(r'[A-Za-z0-9.+:~_-]{1,128}',version),'NATIVE_CRT_PACKAGE');packages[name]=version
    require(set(packages)==set(lock['crt_packages']),'NATIVE_CRT_PACKAGE_COVERAGE')
    owners={}
    for line in values['owners.txt'].decode().splitlines():
        name,path=line.rsplit(': ',1);name=name.split(':')[0];filename=Path(path).name
        require(path.startswith('/') and name in packages and filename in lock['crt_files'] and filename not in owners,'NATIVE_CRT_OWNER');owners[filename]=name
    require(set(owners)==set(lock['crt_files']),'NATIVE_CRT_OWNER_COVERAGE')
    locked=crates(lock_bytes);sources={}
    for name in locked:
        members=crate_contents(values['crates/'+name+'.crate'],locked[name]);sources[name]=members
        prefix='sources/'+name+'/'
        for path,data in members.items():
            actual=prefix+path;require(actual in values and values[actual]==data,'NATIVE_COMPILED_SOURCE_MISMATCH');expected.add(actual)
        metadata=prefix+'.cargo-checksum.json'
        if metadata in values:
            expected.add(metadata);checksum=json.loads(values[metadata])
            # New Cargo registry extraction need not generate this vendoring
            # metadata. Every actual source byte was already compared above.
            file_hashes={path:hashlib.sha256(data).hexdigest() for path,data in members.items()}
            require(checksum.get('package')==locked[name]['checksum'] and checksum.get('files') in ({},file_hashes),'NATIVE_SOURCE_CHECKSUM_METADATA')
        marker=prefix+'.cargo-ok'
        if marker in values:
            require(len(values[marker])<=1024,'NATIVE_SOURCE_MARKER_BOUND');expected.add(marker)
    sqlite=sources['libsqlite3-sys']
    matches=[re.findall(rb'^#define SQLITE_VERSION\s+"([0-9]+\.[0-9]+\.[0-9]+)"\s*$',sqlite[n],re.M) for n in ('sqlite3/sqlite3.c','sqlite3/sqlite3.h')]
    require(all(len(m)==1 for m in matches) and matches[0]==matches[1],'NATIVE_SQLITE_VERSION');sqlite_version=matches[0][0].decode()
    parts=list(map(int,sqlite_version.split('.')));number=str(parts[0]*1000000+parts[1]*1000+parts[2]).encode()
    require(all(re.findall(rb'^#define SQLITE_VERSION_NUMBER\s+([0-9]+)\s*$',sqlite[n],re.M)==[number] for n in ('sqlite3/sqlite3.c','sqlite3/sqlite3.h')),'NATIVE_SQLITE_VERSION_NUMBER')
    unused={}
    if lock['version']==2:
        sqlite_inputs={name.removeprefix('sqlite/'):data for name,data in values.items() if name.startswith('sqlite/')}
        validate_sqlite_inputs(sqlite_inputs,lock['sqlite'],sources['libsqlite3-sys']['sqlite3/bindgen_bundled_version.rs'],locked['libsqlite3-sys']['version'])
        expected|={'sqlite/'+name for name in sqlite_inputs}
        unused={'bundled_sqlite_version':sqlite_version,'implementation_used':False,'reason':'fixed_external_static_archive_and_unchanged_bundled_abi_bindings','paths':['sources/libsqlite3-sys/sqlite3/sqlite3.c','sources/libsqlite3-sys/sqlite3/sqlite3.h']}
        sqlite_version=lock['sqlite']['version']
    require(set(values)==expected,'NATIVE_INPUT_COVERAGE')
    evidence={name:hashlib.sha256(data).hexdigest() for name,data in sorted(values.items())}
    components=[]
    def component(name,version,purl,cpe,paths):
        inputs={path:evidence[path] for path in paths};digest=hashlib.sha256(json.dumps(inputs,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        components.append({'name':name,'version':version,'purl':purl,'cpe':cpe,'inputs':inputs,'sha256':digest})
    sqlite_paths=[n for n in evidence if n.startswith('sqlite/')] if lock['version']==2 else ['crates/libsqlite3-sys.crate']+[n for n in evidence if n.startswith('sources/libsqlite3-sys/')]
    component('sqlite',sqlite_version,'pkg:generic/sqlite@'+sqlite_version,'cpe:2.3:a:sqlite:sqlite:'+sqlite_version+':*:*:*:*:*:*:*',sqlite_paths)
    if lock['version']==2:
        component('libsqlite3-sys-bindings',locked['libsqlite3-sys']['version'],'pkg:cargo/libsqlite3-sys@'+locked['libsqlite3-sys']['version'],None,['crates/libsqlite3-sys.crate','sqlite/bindings.rs','sqlite/build-script.txt'])
    component('ring',locked['ring']['version'],'pkg:cargo/ring@'+locked['ring']['version'],None,['crates/ring.crate']+[n for n in evidence if n.startswith('sources/ring/')])
    component('rust-std',lock['rust_version'],'pkg:generic/rust-lang/rust-std@'+lock['rust_version']+'?target='+lock['target'],'cpe:2.3:a:rust-lang:rust:'+lock['rust_version']+':*:*:*:*:*:*:*',['sysroot/'+n+'.rlib' for n in lock['sysroot_files']])
    for name,version in sorted(packages.items()):
        component(name,version,'pkg:deb/debian/'+name+'@'+quote(version,safe='')+'?arch=amd64&distro=debian-12',None,['crt/'+filename for filename in lock['crt_files'] if owners[filename]==name])
    require(set(binaries)==set(names),'NATIVE_BINARY_COVERAGE')
    result={'version':lock['version'],'profile':lock['profile'],'builder_image':lock['builder_image'],'cargo_lock_sha256':hashlib.sha256(lock_bytes).hexdigest(),'rustc':compiler,'gcc_version':gcc,'files':evidence,'binaries':binaries,'components':components,'coverage':'conservative-compiler-inputs'}
    if unused:result['unused_bundled_implementation']=unused
    return result


def documents(provenance):
    components=[];spdx=[]
    for index,value in enumerate(provenance['components']):
        item={'type':'library','bom-ref':value['purl'],'name':value['name'],'version':value['version'],'purl':value['purl'],'hashes':[{'alg':'SHA-256','content':value['sha256']}]}
        references=[{'referenceCategory':'PACKAGE-MANAGER','referenceType':'purl','referenceLocator':value['purl']}]
        if value['cpe']:item['cpe']=value['cpe'];references.append({'referenceCategory':'SECURITY','referenceType':'cpe23Type','referenceLocator':value['cpe']})
        components.append(item)
        spdx.append({'SPDXID':'SPDXRef-Native-'+str(index),'name':value['name'],'versionInfo':value['version'],'downloadLocation':'NOASSERTION','filesAnalyzed':False,'licenseConcluded':'NOASSERTION','licenseDeclared':'NOASSERTION','copyrightText':'NOASSERTION','checksums':[{'algorithm':'SHA256','checksumValue':value['sha256']}],'externalRefs':references})
    digest=hashlib.sha256(json.dumps(provenance,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    cdx={'bomFormat':'CycloneDX','specVersion':'1.6','version':1,'components':components}
    document={'spdxVersion':'SPDX-2.3','dataLicense':'CC0-1.0','SPDXID':'SPDXRef-DOCUMENT','name':'sandbox-native-compiler-inputs','documentNamespace':'https://sandbox.invalid/native/'+digest,'creationInfo':{'created':'1970-01-01T00:00:00Z','creators':['Tool: sandbox-native-inventory-1']},'packages':spdx,'relationships':[{'spdxElementId':'SPDXRef-DOCUMENT','relationshipType':'DESCRIBES','relatedSpdxElement':p['SPDXID']} for p in spdx]}
    return cdx,document


def record(exported, directory):
    lock=contract(load(ROOT/'native-security.lock.json'));binaries={}
    for name in BINARIES:
        require(sha(exported/'bin'/name)==sha(directory/name),'NATIVE_BUILDER_BINARY_MISMATCH')
        binaries[name]={'sha256':sha(directory/name),'elf':validate_file(directory/name,lock['profile'])}
    value=inventory(directory_inputs(exported/'inputs'),(directory/'Cargo.lock').read_bytes(),lock,binaries)
    # Reject unexpected/cache-modified sources before a candidate artifact can
    # be retained or uploaded. Only authenticated compiler inputs are packaged.
    archive_inputs(exported/'inputs',directory/'native-inputs.tar')
    dump(directory/'native-provenance.json',value);cdx,spdx=documents(value)
    dump(directory/'native-components.cdx.json',cdx);dump(directory/'native-components.spdx.json',spdx)
    dump(directory/'native-security.lock.json',lock)
    return value


def validate(directory, *, historical=False, binary_names=None):
    names=release_binaries(BINARIES if binary_names is None else binary_names,historical=historical)
    lock=contract(load(directory/'native-security.lock.json'),historical=historical)
    binaries={name:{'sha256':sha(directory/name),'elf':validate_file(directory/name,lock['profile'])} for name in names}
    expected=inventory(read_inputs(directory/'native-inputs.tar'),(directory/'Cargo.lock').read_bytes(),lock,binaries,historical=historical,binary_names=names)
    require(load(directory/'native-provenance.json')==expected,'NATIVE_PROVENANCE_MISMATCH')
    cdx,spdx=documents(expected)
    require(load(directory/'native-components.cdx.json')==cdx and load(directory/'native-components.spdx.json')==spdx,'NATIVE_SBOM_COVERAGE')
    report=load(directory/'builder.syft.json');metadata=report.get('source',{}).get('metadata',{})
    inputs={lock['builder_image'],'docker.io/library/'+lock['builder_image']}
    require(report.get('source',{}).get('type')=='image' and metadata.get('userInput') in inputs and metadata.get('architecture')=='amd64' and metadata.get('os')=='linux','NATIVE_BUILDER_SBOM_SOURCE')
    builder=report['artifacts'];actual={(p['name'].split(':')[0],p['version']) for p in builder if p.get('type')=='deb'}
    required={(p['name'],p['version']) for p in expected['components'] if p['name'] in lock['crt_packages']}
    require(required<=actual,'NATIVE_CRT_BUILDER_SBOM')
    return expected


def validate_runtime(directory, component, provenance, *, historical=False, binary_names=None):
    names=release_binaries(BINARIES if binary_names is None else binary_names,historical=historical)
    require(set(provenance['binaries'])==set(names),'NATIVE_BINARY_COVERAGE')
    require(component in ('service','runner'), 'NATIVE_RUNTIME_COMPONENT')
    image_digest(directory, component)
    index=load(directory/'index.json');manifest=load(directory/'blobs/sha256'/index['manifests'][0]['digest'][7:])
    expected={'sandbox-runner'} if component=='runner' else {'sandboxd','sandbox-admin','sandbox-admission','sandbox-backup-worm','sandbox-credentials','sandbox-automation'}
    expected &= set(names)
    prefix='usr/local/bin/';values={};total=count=0
    for layer in manifest['layers']:
        require(layer['mediaType'] in ('application/vnd.oci.image.layer.v1.tar','application/vnd.oci.image.layer.v1.tar+gzip'), 'NATIVE_RUNTIME_LAYER_FORMAT')
        with tarfile.open(directory/'blobs/sha256'/layer['digest'][7:],'r|*') as archive:
            seen=set()
            for member in archive:
                name=member.name.removeprefix('./').rstrip('/')
                if name in ('','.') and member.isdir():continue
                require(name and not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')) and name not in seen,'NATIVE_RUNTIME_PATH')
                seen.add(name);count+=1;total+=member.size
                require(count<=200000 and 0<=member.size<=1024**3 and total<=2*1024**3,'NATIVE_RUNTIME_LAYER_BOUND')
                base=name.rsplit('/',1)[-1]
                if base.startswith('.wh.'):
                    parent=name.rsplit('/',1)[0] if '/' in name else ''
                    affected=parent if base=='.wh..wh..opq' else (parent+'/' if parent else '')+base[4:]
                    require(affected and not any((prefix+n)==affected or (prefix+n).startswith(affected+'/') for n in expected),'NATIVE_RUNTIME_WHITEOUT')
                if prefix.startswith(name+'/'):require(member.isdir(),'NATIVE_RUNTIME_ANCESTOR_LINK')
                if name not in {prefix+n for n in expected}:continue
                require(member.isfile() and member.uid==0 and not member.mode&0o022 and member.mode&0o111 and member.size<=512*1024*1024,'NATIVE_RUNTIME_BINARY')
                source=archive.extractfile(member);require(source is not None,'NATIVE_RUNTIME_READ')
                digest=hashlib.sha256();size=0
                while block:=source.read(1024*1024):digest.update(block);size+=len(block)
                require(size==member.size,'NATIVE_RUNTIME_FILE_SIZE');values[name[len(prefix):]]=digest.hexdigest()
    require(set(values)==expected and all(values[n]==provenance['binaries'][n]['sha256'] for n in expected),'NATIVE_RUNTIME_BINARY_MISMATCH')
