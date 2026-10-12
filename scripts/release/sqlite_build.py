"""Fixed official SQLite static input; no package resolver or ambient library fallback."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
from common import BINARIES, unique

FLAGS = ['-O2','-fPIC','-ffunction-sections','-fdata-sections','-DSQLITE_CORE','-DSQLITE_DEFAULT_FOREIGN_KEYS=1','-DSQLITE_ENABLE_API_ARMOR','-DSQLITE_ENABLE_COLUMN_METADATA','-DSQLITE_ENABLE_DBSTAT_VTAB','-DSQLITE_ENABLE_FTS3','-DSQLITE_ENABLE_FTS3_PARENTHESIS','-DSQLITE_ENABLE_FTS5','-DSQLITE_ENABLE_JSON1','-DSQLITE_ENABLE_LOAD_EXTENSION=1','-DSQLITE_ENABLE_MEMORY_MANAGEMENT','-DSQLITE_ENABLE_RTREE','-DSQLITE_ENABLE_STAT4','-DSQLITE_SOUNDEX','-DSQLITE_THREADSAFE=1','-DSQLITE_USE_URI','-DHAVE_USLEEP=1','-DHAVE_ISNAN','-D_POSIX_THREAD_SAFE_FUNCTIONS','-DHAVE_LOCALTIME_R','-DSQLITE_ENABLE_UNLOCK_NOTIFY']
FIELDS = {'version','url','size','sha256','sha3_256','sqlite3_c_sha256','sqlite3_h_sha256','source_id','flags'}
OPTIONS = {'DEFAULT_FOREIGN_KEYS','ENABLE_API_ARMOR','ENABLE_COLUMN_METADATA','ENABLE_DBSTAT_VTAB','ENABLE_FTS3','ENABLE_FTS3_PARENTHESIS','ENABLE_FTS5','ENABLE_LOAD_EXTENSION','ENABLE_MEMORY_MANAGEMENT','ENABLE_RTREE','ENABLE_STAT4','ENABLE_UNLOCK_NOTIFY','SOUNDEX','THREADSAFE=1','USE_URI'}
LINKS = ['cargo:rustc-link-lib=static=sqlite3','cargo:rustc-link-search=/opt/sandbox-sqlite/lib']


def require(condition, code):
    if not condition: raise ValueError(code)


def production_link_directories(data, crate_version):
    """Use this production Cargo invocation's graph, never enumerate cache entries."""
    require(0 < len(data) <= 32 * 1024 * 1024, 'SQLITE_CARGO_RECEIPT_BOUND')
    lines = data.splitlines()
    require(0 < len(lines) <= 20000 and all(len(line) <= 512 * 1024 for line in lines),
            'SQLITE_CARGO_RECEIPT_BOUND')
    messages = [json.loads(line, object_pairs_hook=unique) for line in lines]
    require(all(isinstance(row, dict) for row in messages), 'SQLITE_CARGO_SUCCESS')
    finished = [row for row in messages if row.get('reason') == 'build-finished']
    require(len(finished) == 1 and finished[0] is messages[-1]
            and set(finished[0]) == {'reason', 'success'}
            and finished[0]['success'] is True, 'SQLITE_CARGO_SUCCESS')
    package = 'registry+https://github.com/rust-lang/crates.io-index#libsqlite3-sys@' + crate_version
    directories = []
    binaries = []
    for row in messages:
        if row.get('reason') == 'build-script-executed' and 'libsqlite3-sys' in row.get('package_id', ''):
            require(row.get('package_id') == package and row.get('linked_libs') == ['static=sqlite3']
                    and row.get('linked_paths') == ['/opt/sandbox-sqlite/lib'], 'SQLITE_CARGO_STATIC_LINK')
            directory = row.get('out_dir')
            require(isinstance(directory, str) and re.fullmatch(
                r'/build/target/release/build/libsqlite3-sys-[a-f0-9]{16}/out', directory),
                'SQLITE_CARGO_OUT_DIR')
            require(directory not in directories, 'SQLITE_CARGO_DUPLICATE_OUTPUT')
            directories.append(directory)
        if row.get('reason') == 'compiler-artifact' and row.get('target', {}).get('kind') == ['bin']:
            name = row['target'].get('name')
            require(name in BINARIES and row.get('executable') == '/build/target/release/' + name
                    and row.get('profile', {}).get('test') is False
                    and row['profile'].get('opt_level') == '3', 'SQLITE_CARGO_PRODUCTION_BINARY')
            binaries.append(name)
    require(1 <= len(directories) <= 2 and set(binaries) == set(BINARIES)
            and len(binaries) == len(BINARIES), 'SQLITE_CARGO_PRODUCTION_GRAPH')
    return directories


def capture_link_output(build_root, destination, receipt, crate_version):
    """Seal every actual host/target output before subsequent test Cargo invocations."""
    require(build_root.is_dir() and not build_root.is_symlink()
            and destination.is_dir() and not destination.is_symlink(), 'SQLITE_LINK_CAPTURE_DIRECTORY')
    require(receipt.is_file() and not receipt.is_symlink()
            and 0 < receipt.stat().st_size <= 32 * 1024 * 1024, 'SQLITE_CARGO_RECEIPT_FILE')
    directories = production_link_directories(receipt.read_bytes(), crate_version)
    outputs, bindings = set(), set()
    for directory in directories:
        path = build_root / Path(directory).parent.name / 'output'
        require(path.is_file() and not path.is_symlink() and not path.parent.is_symlink()
                and 0 < path.stat().st_size <= 256 * 1024, 'SQLITE_LINK_CAPTURE_FILE')
        data = path.read_bytes()
        require(len(data) <= 256 * 1024, 'SQLITE_LINK_CAPTURE_BOUND')
        lines = data.decode('ascii').splitlines()
        require([line for line in lines if line.startswith(
            ('cargo:rustc-link-lib=', 'cargo:rustc-link-search='))] == LINKS, 'SQLITE_STATIC_LINK')
        binding_path = path.parent / 'out/bindgen.rs'
        require(binding_path.is_file() and not binding_path.is_symlink()
                and not binding_path.parent.is_symlink()
                and 0 < binding_path.stat().st_size <= 2 * 1024 * 1024, 'SQLITE_BINDINGS_CAPTURE_FILE')
        binding_data = binding_path.read_bytes()
        require(len(binding_data) <= 2 * 1024 * 1024, 'SQLITE_BINDINGS_CAPTURE_BOUND')
        outputs.add(data); bindings.add(binding_data)
    # Host and target can both run the same build script. A differing output is
    # rejected; the sealed bytes are the single common value, not a chosen path.
    require(len(outputs) == len(bindings) == 1, 'SQLITE_PRODUCTION_OUTPUT_DISAGREEMENT')
    require(all(not (destination / name).exists() for name in ('build-script.txt', 'bindings.rs')),
            'SQLITE_LINK_CAPTURE_EXISTS')
    (destination / 'build-script.txt').write_bytes(outputs.pop())
    (destination / 'bindings.rs').write_bytes(bindings.pop())


def contract(value):
    require(isinstance(value,dict) and set(value)==FIELDS,'SQLITE_CONTRACT_FIELDS')
    require(isinstance(value['version'],str) and re.fullmatch(r'3\.[0-9]{1,3}\.[0-9]{1,3}',value['version']),'SQLITE_VERSION')
    version=list(map(int,value['version'].split('.')));number=version[0]*1000000+version[1]*10000+version[2]*100
    require(value['url']=='https://www.sqlite.org/2026/sqlite-autoconf-'+str(number)+'.tar.gz','SQLITE_OFFICIAL_SOURCE')
    require(type(value['size']) is int and 0<value['size']<=8*1024**2,'SQLITE_SOURCE_BOUND')
    require(all(isinstance(value[k],str) and re.fullmatch(r'[a-f0-9]{64}',value[k]) for k in ('sha256','sha3_256','sqlite3_c_sha256','sqlite3_h_sha256')),'SQLITE_SOURCE_HASH')
    require(isinstance(value['source_id'],str) and re.fullmatch(r'2026-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [a-f0-9]{64}',value['source_id']),'SQLITE_SOURCE_ID')
    require(value['flags']==FLAGS,'SQLITE_BUILD_FLAGS')
    return value


def sources(data, value):
    value=contract(value)
    require(len(data)==value['size'] and hashlib.sha256(data).hexdigest()==value['sha256'] and hashlib.sha3_256(data).hexdigest()==value['sha3_256'],'SQLITE_SOURCE_CHECKSUM')
    prefix=Path(value['url']).name.removesuffix('.tar.gz')+'/'
    files={};seen=set();total=0
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
        for member in archive:
            name=member.name.rstrip('/')
            require(name and name not in seen and name.startswith(prefix.rstrip('/')) and all(v not in ('','.','..') for v in name.split('/')) and (member.isfile() or member.isdir()),'SQLITE_SOURCE_MEMBER')
            require(name==prefix.rstrip('/') or name.startswith(prefix),'SQLITE_SOURCE_PATH');seen.add(name);total+=member.size
            require(len(seen)<=4096 and 0<=member.size<=16*1024**2 and total<=64*1024**2,'SQLITE_SOURCE_EXPANSION')
            if name in (prefix+'sqlite3.c',prefix+'sqlite3.h'):
                require(member.isfile(),'SQLITE_SOURCE_FILE');source=archive.extractfile(member);require(source is not None,'SQLITE_SOURCE_READ');files[name[len(prefix):]]=source.read(member.size+1)
                require(len(files[name[len(prefix):]])==member.size,'SQLITE_SOURCE_LENGTH')
    require(set(files)=={'sqlite3.c','sqlite3.h'},'SQLITE_SOURCE_COVERAGE')
    for name,data in files.items():
        require(hashlib.sha256(data).hexdigest()==value['sqlite3_'+('c' if name.endswith('.c') else 'h')+'_sha256'],'SQLITE_SOURCE_FILE_HASH')
        require(re.findall(rb'^#define SQLITE_VERSION\s+"([^"]+)"\s*$',data,re.M)==[value['version'].encode()] and re.findall(rb'^#define SQLITE_SOURCE_ID\s+"([^"]+)"\s*$',data,re.M)==[value['source_id'].encode()],'SQLITE_SOURCE_MACRO')
    return files


def validate_inputs(values, value, bindings, crate_version):
    value=contract(value)
    names={'source.tar.gz','sqlite3.c','sqlite3.h','sqlite3.o','libsqlite3.a','build.json','version.txt','compile-options.txt','build-script.txt','bindings.rs','production-cargo.json','journal-tests.txt','journal-acceptance.txt'}
    require(set(values)==names and all(0<len(data)<=48*1024**2 for data in values.values()),'SQLITE_NATIVE_INPUTS')
    official=sources(values['source.tar.gz'],value)
    require(all(values[name]==data for name,data in official.items()),'SQLITE_COMPILED_SOURCE')
    require(values['bindings.rs']==bindings,'SQLITE_ABI_BINDINGS')
    production_link_directories(values['production-cargo.json'], crate_version)
    metadata={'version':value['version'],'source_id':value['source_id'],'flags':FLAGS,'source_sha256':value['sha256'],'sqlite3_a_sha256':hashlib.sha256(values['libsqlite3.a']).hexdigest(),'sqlite3_o_sha256':hashlib.sha256(values['sqlite3.o']).hexdigest()}
    require(json.loads(values['build.json'])==metadata,'SQLITE_BUILD_EVIDENCE')
    require(values['version.txt']==(value['version']+'\n').encode(),'SQLITE_RUNTIME_VERSION')
    options=values['compile-options.txt'].decode('ascii').splitlines()
    require(len(options)==len(set(options)) and OPTIONS<=set(options),'SQLITE_COMPILE_OPTIONS')
    output=values['build-script.txt'].decode('ascii').splitlines()
    require(len(output)<=256 and all(len(line)<=1024 and line.startswith('cargo:') for line in output),'SQLITE_LINK_OUTPUT')
    links=[line for line in output if line.startswith(('cargo:rustc-link-lib=','cargo:rustc-link-search='))]
    require(links==LINKS,'SQLITE_STATIC_LINK')
    obj=values['sqlite3.o'];require(len(obj)>=64 and obj[:7]==b'\x7fELF\x02\x01\x01' and obj[16:20]==b'\x01\x00\x3e\x00','SQLITE_NATIVE_OBJECT')
    archive=values['libsqlite3.a'];require(archive.startswith(b'!<arch>\n'),'SQLITE_STATIC_ARCHIVE');at=8;objects=[]
    while at<len(archive):
        require(at+60<=len(archive) and archive[at+58:at+60]==b'`\n','SQLITE_AR_HEADER')
        name=archive[at:at+16].decode('ascii').strip();size_text=archive[at+48:at+58].strip();require(size_text.isdigit(),'SQLITE_AR_SIZE');size=int(size_text);at+=60
        require(size<=48*1024**2 and at+size<=len(archive),'SQLITE_AR_BOUND');data=archive[at:at+size];at+=size
        if size%2:require(at<len(archive) and archive[at:at+1]==b'\n','SQLITE_AR_ALIGNMENT');at+=1
        if name=='/':continue
        require(name=='sqlite3.o/','SQLITE_AR_MEMBER');objects.append(data)
    require(objects==[obj],'SQLITE_AR_OBJECT_BINDING')
    ordinary=values['journal-tests.txt'].decode('utf8');acceptance=values['journal-acceptance.txt'].decode('utf8')
    require('running 2 tests\n' in ordinary and 'test result: ok. 2 passed; 0 failed; 0 ignored;' in ordinary,'SQLITE_JOURNAL_REGRESSION')
    for suffix in ('lifecycle_keeps_closed_uid_across_restart','failed_open_rolls_back_and_drains'):
        require('test nodeguard_journal_regression_'+suffix+' ... ok\n' in ordinary,'SQLITE_JOURNAL_REGRESSION_COVERAGE')
    require('running 5 tests\n' in acceptance and 'test result: ok. 5 passed; 0 failed; 0 ignored;' in acceptance,'SQLITE_JOURNAL_ACCEPTANCE')
    for suffix in ('runtime_contract','writer_contention_fails_closed_and_recovers','constraint_failure_rolls_back','corrupt_database_refuses_open','abrupt_process_exit_recovers_durable_wal_without_start_replay'):
        require('test sqlite_release_acceptance_'+suffix+' ... ok\n' in acceptance,'SQLITE_JOURNAL_TEST_COVERAGE')
    return metadata


PROBE = r'''#include "sqlite3.h"
#include <stdio.h>
int main(void) {
  sqlite3 *db = 0;
  if (!sqlite3_threadsafe() || sqlite3_open(":memory:", &db) != SQLITE_OK) return 1;
  if (sqlite3_exec(db, "SELECT json_extract('{\"proof\":1}', '$.proof');", 0, 0, 0) != SQLITE_OK) return 2;
  puts(sqlite3_libversion()); puts(sqlite3_sourceid());
  for (int n=0; sqlite3_compileoption_get(n); ++n) puts(sqlite3_compileoption_get(n));
  return sqlite3_close(db) == SQLITE_OK ? 0 : 3;
}
'''


def build(archive, destination, lock):
    value=contract(lock['sqlite']);require(not destination.exists() and not destination.is_symlink(),'SQLITE_DESTINATION_EXISTS')
    data=archive.read_bytes();files=sources(data,value)
    destination.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='sqlite-static-',dir=destination.parent) as temporary:
        staging=Path(temporary);(staging/'lib').mkdir();(staging/'include').mkdir();(staging/'evidence').mkdir()
        for name,data in files.items():(staging/'evidence'/name).write_bytes(data)
        shutil.copyfile(archive,staging/'evidence/source.tar.gz');shutil.copyfile(staging/'evidence/sqlite3.h',staging/'include/sqlite3.h')
        subprocess.run(['gcc']+FLAGS+['-c','sqlite3.c','-o','sqlite3.o'],cwd=staging/'evidence',check=True,timeout=240)
        subprocess.run(['ar','crsD',str(staging/'lib/libsqlite3.a'),str(staging/'evidence/sqlite3.o')],check=True,timeout=30)
        (staging/'probe.c').write_text(PROBE)
        subprocess.run(['gcc','-O2','-I'+str(staging/'include'),str(staging/'probe.c'),str(staging/'lib/libsqlite3.a'),'-lm','-ldl','-lpthread','-o',str(staging/'probe')],check=True,timeout=60)
        result=subprocess.run([str(staging/'probe')],check=True,capture_output=True,timeout=30).stdout
        require(len(result)<32*1024,'SQLITE_PROBE_BOUND');lines=result.decode('ascii').splitlines()
        require(len(lines)>2 and lines[:2]==[value['version'],value['source_id']] and OPTIONS<=set(lines[2:]),'SQLITE_PROBE_CONTRACT')
        (staging/'evidence/version.txt').write_text(value['version']+'\n');(staging/'evidence/compile-options.txt').write_text('\n'.join(lines[2:])+'\n')
        shutil.copyfile(staging/'lib/libsqlite3.a',staging/'evidence/libsqlite3.a')
        metadata={'version':value['version'],'source_id':value['source_id'],'flags':FLAGS,'source_sha256':value['sha256'],'sqlite3_a_sha256':hashlib.sha256((staging/'lib/libsqlite3.a').read_bytes()).hexdigest(),'sqlite3_o_sha256':hashlib.sha256((staging/'evidence/sqlite3.o').read_bytes()).hexdigest()}
        (staging/'evidence/build.json').write_text(json.dumps(metadata,sort_keys=True,separators=(',',':'))+'\n');(staging/'probe.c').unlink();(staging/'probe').unlink()
        staging.rename(destination)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--archive',type=Path);parser.add_argument('--capture-link-output',action='store_true');parser.add_argument('--destination',type=Path,required=True);parser.add_argument('--lock',type=Path,default=Path(__file__).with_name('native-security.lock.json'));args=parser.parse_args()
    if args.capture_link_output:
        require(args.archive is None, 'SQLITE_LINK_CAPTURE_MODE')
        packages = tomllib.loads(Path('/build/Cargo.lock').read_text())['package']
        sqlite = [package for package in packages if package['name'] == 'libsqlite3-sys']
        require(len(sqlite) == 1 and sqlite[0].get('source') ==
                'registry+https://github.com/rust-lang/crates.io-index', 'SQLITE_CARGO_LOCK')
        capture_link_output(Path('/build/target/release/build'), args.destination,
                            args.destination / 'production-cargo.json', sqlite[0]['version'])
        return
    require(args.archive is not None and args.archive.is_file() and not args.archive.is_symlink() and args.archive.stat().st_size<=8*1024**2,'SQLITE_ARCHIVE_FILE')
    build(args.archive,args.destination,json.loads(args.lock.read_text()))


if __name__=='__main__':main()
