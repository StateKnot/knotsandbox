"""Synthetic source/ELF protocol fixtures. Actual Linux compilation is separate."""
import copy
import hashlib
import gzip
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import ROOT,load,BINARIES
import native
from sqlite_build import contract,sources,validate_inputs,capture_link_output,production_link_directories,LINKS,OPTIONS


def cargo_receipt(directories=('a'*16,)):
    rows = [{'reason':'build-script-executed','package_id':'registry+https://github.com/rust-lang/crates.io-index#libsqlite3-sys@0.30.1','linked_libs':['static=sqlite3'],'linked_paths':['/opt/sandbox-sqlite/lib'],'out_dir':'/build/target/release/build/libsqlite3-sys-'+name+'/out'} for name in directories]
    rows += [{'reason':'compiler-artifact','target':{'kind':['bin'],'name':name},'executable':'/build/target/release/'+name,'profile':{'test':False,'opt_level':'3'}} for name in BINARIES]
    rows.append({'reason':'build-finished','success':True})
    return ('\n'.join(json.dumps(row) for row in rows)+'\n').encode()


def sqlite_fixture():
    lock=copy.deepcopy(load(ROOT/'native-security.lock.json'));value=lock['sqlite']
    body=('#define SQLITE_VERSION "'+value['version']+'"\n#define SQLITE_SOURCE_ID "'+value['source_id']+'"\n').encode()
    archive=io.BytesIO();prefix=Path(value['url']).name.removesuffix('.tar.gz')+'/'
    with gzip.GzipFile(fileobj=archive,mode='wb',mtime=0) as compressed:
        with tarfile.open(fileobj=compressed,mode='w') as target:
            for name in ('sqlite3.c','sqlite3.h'):
                member=tarfile.TarInfo(prefix+name);member.size=len(body);target.addfile(member,io.BytesIO(body))
    data=archive.getvalue();value.update(size=len(data),sha256=hashlib.sha256(data).hexdigest(),sha3_256=hashlib.sha3_256(data).hexdigest(),sqlite3_c_sha256=hashlib.sha256(body).hexdigest(),sqlite3_h_sha256=hashlib.sha256(body).hexdigest())
    obj=bytearray(64);obj[:7]=b'\x7fELF\x02\x01\x01';obj[16:20]=b'\x01\x00\x3e\x00';obj=bytes(obj)
    header=b'sqlite3.o/      '+b'0           '+b'0     '+b'0     '+b'644     '+str(len(obj)).encode().ljust(10)+b'`\n';assert len(header)==60
    library=b'!<arch>\n'+header+obj;bindings=b'PUBLIC ABI FIXTURE'
    metadata={'version':value['version'],'source_id':value['source_id'],'flags':value['flags'],'source_sha256':value['sha256'],'sqlite3_a_sha256':hashlib.sha256(library).hexdigest(),'sqlite3_o_sha256':hashlib.sha256(obj).hexdigest()}
    acceptance='running 5 tests\n'
    for suffix in ('runtime_contract','writer_contention_fails_closed_and_recovers','constraint_failure_rolls_back','corrupt_database_refuses_open','abrupt_process_exit_recovers_durable_wal_without_start_replay'):
        acceptance+='test sqlite_release_acceptance_'+suffix+' ... ok\n'
    acceptance+='test result: ok. 5 passed; 0 failed; 0 ignored;\n'
    ordinary='running 2 tests\n'+''.join('test nodeguard_journal_regression_'+suffix+' ... ok\n' for suffix in ('lifecycle_keeps_closed_uid_across_restart','failed_open_rolls_back_and_drains'))+'test result: ok. 2 passed; 0 failed; 0 ignored;\n'
    values={'source.tar.gz':data,'sqlite3.c':body,'sqlite3.h':body,'sqlite3.o':obj,'libsqlite3.a':library,'build.json':json.dumps(metadata).encode(),'version.txt':(value['version']+'\n').encode(),'compile-options.txt':('\n'.join(sorted(OPTIONS))+'\n').encode(),'build-script.txt':b'cargo:rustc-link-lib=static=sqlite3\ncargo:rustc-link-search=/opt/sandbox-sqlite/lib\n','bindings.rs':bindings,'production-cargo.json':cargo_receipt(),'journal-tests.txt':ordinary.encode(),'journal-acceptance.txt':acceptance.encode()}
    return lock,values


def native_trust_fixture():
    """Explicitly replace only the independent lock in this synthetic test."""
    lock,_=sqlite_fixture();original=load
    return patch('native.load',side_effect=lambda path,*args:copy.deepcopy(lock) if Path(path)==ROOT/'native-security.lock.json' else original(path,*args))


class SQLiteProtocol(unittest.TestCase):
    def setUp(self):self.lock,self.values=sqlite_fixture()
    def test_archive_source_flags_static_link_and_unchanged_bindings(self):
        self.assertEqual(contract(self.lock['sqlite'])['version'],'3.53.4')
        self.assertEqual(set(sources(self.values['source.tar.gz'],self.lock['sqlite'])),{'sqlite3.c','sqlite3.h'})
        self.assertEqual(validate_inputs(self.values,self.lock['sqlite'],self.values['bindings.rs'],'0.30.1')['version'],'3.53.4')
    def test_source_hash_library_object_header_or_bindings_tamper_fails(self):
        for name in self.values:
            changed=copy.deepcopy(self.values);changed[name]=b'TAMPER'
            with self.subTest(name=name),self.assertRaises((ValueError,UnicodeError,json.JSONDecodeError)):
                validate_inputs(changed,self.lock['sqlite'],self.values['bindings.rs'],'0.30.1')
    def test_dynamic_or_ambient_library_fallback_is_rejected(self):
        for output in (b'cargo:rustc-link-lib=dylib=sqlite3\n',b'cargo:rustc-link-lib=static=sqlite3\ncargo:rustc-link-search=/usr/lib\n',self.values['build-script.txt']+b'cargo:rustc-link-lib=static=other\n'):
            changed=copy.deepcopy(self.values);changed['build-script.txt']=output
            with self.assertRaisesRegex(ValueError,'SQLITE_STATIC_LINK'):validate_inputs(changed,self.lock['sqlite'],self.values['bindings.rs'],'0.30.1')
    def test_exact_production_integration_coverage_is_required(self):
        cases=(('journal-tests.txt',b'test result: ok. 10 passed; 0 failed; 0 ignored;\n'),
               ('journal-tests.txt',self.values['journal-tests.txt'].replace(b'failed_open_rolls_back_and_drains',b'unrelated_test')),
               ('journal-acceptance.txt',self.values['journal-acceptance.txt'].replace(b'test sqlite_release_acceptance_',b'test nodeguard::journal::sqlite_release_tests::sqlite_release_acceptance_')),
               ('journal-acceptance.txt',self.values['journal-acceptance.txt'].replace(b'constraint_failure_rolls_back',b'unrelated_test')),
               ('journal-acceptance.txt',self.values['journal-acceptance.txt'].replace(b'5 passed; 0 failed; 0 ignored;',b'4 passed; 0 failed; 1 ignored;')))
        for name,log in cases:
            changed=copy.deepcopy(self.values);changed[name]=log
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'SQLITE_JOURNAL_'):
                validate_inputs(changed,self.lock['sqlite'],self.values['bindings.rs'],'0.30.1')
    def test_unknown_or_disabled_macro_or_unofficial_source_is_rejected(self):
        for change in ('flags','url','extra'):
            value=copy.deepcopy(self.lock['sqlite'])
            if change=='flags':value['flags']=value['flags'][:-1]
            elif change=='url':value['url']='https://mirror.invalid/source.tar.gz'
            else:value['fallback']=True
            with self.assertRaises(ValueError):contract(value)
    def test_actual_host_and_target_graph_is_sealed_and_foreign_cache_is_unused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);build=root/'build';build.mkdir();destination=root/'evidence';destination.mkdir()
            receipt=destination/'production-cargo.json';receipt.write_bytes(cargo_receipt(('a'*16,'b'*16)))
            def output(name,bindings):
                directory=build/('libsqlite3-sys-'+name);(directory/'out').mkdir(parents=True)
                (directory/'output').write_text('\n'.join(LINKS)+'\n')
                (directory/'out/bindgen.rs').write_bytes(bindings)
            output('a'*16,b'PRODUCTION ABI');output('b'*16,b'PRODUCTION ABI')
            output('c'*16,b'FOREIGN TEST FEATURE ABI')
            capture_link_output(build,destination,receipt,'0.30.1')
            self.assertEqual((destination/'bindings.rs').read_bytes(),b'PRODUCTION ABI')
            (build/('libsqlite3-sys-'+'c'*16)/'output').write_text('later cache mutation')
            self.assertEqual((destination/'bindings.rs').read_bytes(),b'PRODUCTION ABI')
            with self.assertRaisesRegex(ValueError,'EXISTS'):capture_link_output(build,destination,receipt,'0.30.1')
            other=root/'unsealed';other.mkdir()
            (build/('libsqlite3-sys-'+'b'*16)/'out/bindgen.rs').write_bytes(b'DIFFERENT ABI')
            with self.assertRaisesRegex(ValueError,'DISAGREEMENT'):capture_link_output(build,other,receipt,'0.30.1')
            self.assertEqual(list(other.iterdir()),[])
    def test_capture_rejects_missing_static_output_symlinks_and_existing_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);build=root/'build';build.mkdir();destination=root/'evidence';destination.mkdir()
            receipt=destination/'production-cargo.json';receipt.write_bytes(cargo_receipt())
            with self.assertRaisesRegex(ValueError,'CAPTURE_FILE'):capture_link_output(build,destination,receipt,'0.30.1')
            directory=build/('libsqlite3-sys-'+'a'*16);(directory/'out').mkdir(parents=True)
            (directory/'output').write_text('\n'.join(LINKS)+'\n')
            (directory/'out/bindgen.rs').write_bytes(b'PRODUCTION ABI')
            (destination/'bindings.rs').write_bytes(b'PRIOR')
            with self.assertRaisesRegex(ValueError,'EXISTS'):capture_link_output(build,destination,receipt,'0.30.1')
            self.assertFalse((destination/'build-script.txt').exists())
            (destination/'bindings.rs').unlink()
            (directory/'output').write_text('\n'.join([LINKS[0].replace('static=','dylib='),LINKS[1]])+'\n')
            with self.assertRaisesRegex(ValueError,'STATIC_LINK'):capture_link_output(build,destination,receipt,'0.30.1')
            (directory/'output').unlink();(directory/'output').symlink_to(root/'untrusted')
            with self.assertRaisesRegex(ValueError,'CAPTURE_FILE'):capture_link_output(build,destination,receipt,'0.30.1')
    def test_cargo_receipt_requires_complete_current_production_graph(self):
        original=[json.loads(line) for line in cargo_receipt().splitlines()]
        mutations=[]
        rows=copy.deepcopy(original);rows[0]['package_id']=rows[0]['package_id'].replace('0.30.1','0.31.0');mutations.append(rows)
        rows=copy.deepcopy(original);rows[0]['linked_libs']=['dylib=sqlite3'];mutations.append(rows)
        rows=copy.deepcopy(original);rows[0]['out_dir']='/build/target/release/build/../foreign/out';mutations.append(rows)
        rows=copy.deepcopy(original);rows[1]['profile']['test']=True;mutations.append(rows)
        rows=copy.deepcopy(original);rows[1]['profile']['opt_level']='0';mutations.append(rows)
        for value in (1,1.0,False,None,'true'):
            rows=copy.deepcopy(original);rows[-1]['success']=value;mutations.append(rows)
        mutations.extend([original[:-1],original[:1]+original[2:],original[:1]+original])
        for rows in mutations:
            with self.subTest(rows=rows),self.assertRaises(ValueError):
                production_link_directories(('\n'.join(json.dumps(row) for row in rows)+'\n').encode(),'0.30.1')


if __name__=='__main__':unittest.main()
