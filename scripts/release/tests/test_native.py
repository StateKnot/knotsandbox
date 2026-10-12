import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tarfile
import unittest
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import BINARIES,HISTORICAL_BINARIES,ROOT,dump,load,sha
from native import archive_inputs,read_inputs,record,validate,export_dockerfile,inventory,documents
from test_elf import fixture as elf_fixture
from test_sqlite_build import native_trust_fixture,sqlite_fixture
import native


def native_fixture(directory):
    """Synthetic protocol inputs, not compiler/runtime certification."""
    directory.mkdir(exist_ok=True);exported=directory/'native-fixture';inputs=exported/'inputs';inputs.mkdir(parents=True)
    (exported/'bin').mkdir();(inputs/'crates').mkdir();(inputs/'crt').mkdir();(inputs/'sysroot').mkdir();(inputs/'sources').mkdir()
    packages=[]
    for name,version in [('libsqlite3-sys','0.30.1'),('ring','0.17.14')]:
        files={'Cargo.toml':('[package]\nname="'+name+'"\nversion="'+version+'"\n').encode()}
        if name=='libsqlite3-sys':
            for path in ('sqlite3/sqlite3.c','sqlite3/sqlite3.h'):files[path]=b'#define SQLITE_VERSION "3.46.0"\n#define SQLITE_VERSION_NUMBER 3046000\n'
            files['sqlite3/bindgen_bundled_version.rs']=b'PUBLIC ABI FIXTURE'
        else:files['crypto/public-fixture.c']=b'PUBLIC PROTOCOL FIXTURE'
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w:gz') as archive:
            for path,value in files.items():
                member=tarfile.TarInfo(name+'-'+version+'/'+path);member.size=len(value);archive.addfile(member,io.BytesIO(value))
        content=data.getvalue();(inputs/'crates'/(name+'.crate')).write_bytes(content)
        source=inputs/'sources'/name;source.mkdir()
        for path,value in files.items():
            target=source/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(value)
        (source/'.cargo-checksum.json').write_text(json.dumps({'package':hashlib.sha256(content).hexdigest(),'files':{path:hashlib.sha256(value).hexdigest() for path,value in files.items()}}))
        packages.append('[[package]]\nname="'+name+'"\nversion="'+version+'"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="'+hashlib.sha256(content).hexdigest()+'"\n')
    lock=''.join(packages);(inputs/'Cargo.lock').write_text(lock);(directory/'Cargo.lock').write_text(lock)
    (inputs/'rustc.txt').write_text('rustc 1.98.1 (public fixture)\nbinary: rustc\ncommit-hash: '+'a'*40+'\ncommit-date: 2026-01-01\nhost: x86_64-unknown-linux-gnu\nrelease: 1.98.1\nLLVM version: 23.0.0\n')
    (inputs/'gcc.txt').write_text('12.2.0\n');(inputs/'packages.tsv').write_text('libc6-dev:amd64\t2.36-public-fixture\nlibgcc-12-dev:amd64\t12.2.0-public-fixture\n')
    contract=native.load(ROOT/'native-security.lock.json');owners=[]
    for name in contract['crt_files']:
        package='libc6-dev' if name in ('Scrt1.o','crti.o','crtn.o') else 'libgcc-12-dev'
        data=bytearray(64);data[:7]=b'\x7fELF\x02\x01\x01';data[16:20]=b'\x01\x00\x3e\x00'
        (inputs/'crt'/name).write_bytes(b'!<arch>\nPUBLIC-FIXTURE' if name.endswith('.a') else bytes(data))
        owners.append(package+':amd64: /public-fixture/'+name)
    (inputs/'owners.txt').write_text('\n'.join(owners)+'\n')
    for name in contract['sysroot_files']:(inputs/'sysroot'/(name+'.rlib')).write_bytes(b'!<arch>\nPUBLIC-FIXTURE')
    for name in BINARIES:
        content=elf_fixture();(exported/'bin'/name).write_bytes(content);(directory/name).write_bytes(content)
    _,sqlite=sqlite_fixture()
    (inputs/'sqlite').mkdir()
    for name,value in sqlite.items():(inputs/'sqlite'/name).write_bytes(value)
    result=record(exported,directory)
    dump(directory/'builder.syft.json',{'source':{'type':'image','metadata':{'userInput':contract['builder_image'],'architecture':'amd64','os':'linux'}},'artifacts':[{'name':'libc6-dev','version':'2.36-public-fixture','type':'deb'},{'name':'libgcc-12-dev','version':'12.2.0-public-fixture','type':'deb'}]})
    return result


def retain_historical_binaries(directory):
    """Reconstruct known seven-ELF synthetic protocol history, not a release signature."""
    lock=load(directory/'native-security.lock.json')
    original=load(directory/'native-provenance.json')
    binaries={name:original['binaries'][name] for name in HISTORICAL_BINARIES}
    value=inventory(read_inputs(directory/'native-inputs.tar'),(directory/'Cargo.lock').read_bytes(),lock,binaries,
                    historical=True,binary_names=HISTORICAL_BINARIES)
    cdx,spdx=documents(value)
    for name,document in [('native-provenance.json',value),('native-components.cdx.json',cdx),('native-components.spdx.json',spdx)]:
        (directory/name).write_text(json.dumps(document))
    (directory/'sandbox-automation').unlink()
    return value


class NativeCoverage(unittest.TestCase):
    def setUp(self):
        self.trust=native_trust_fixture();self.trust.start();self.tmp=tempfile.TemporaryDirectory();self.directory=Path(self.tmp.name);self.value=native_fixture(self.directory)
    def tearDown(self):self.tmp.cleanup();self.trust.stop()
    def test_versions_are_recomputed_from_checksum_locked_source_and_binary_inputs(self):
        value=validate(self.directory)
        self.assertEqual(next(c['version'] for c in value['components'] if c['name']=='sqlite'),'3.53.4')
        self.assertEqual(set(value['binaries']),set(BINARIES));self.assertEqual(len(value['binaries']),8);self.assertEqual(len(value['files']),39)
        self.assertEqual(value['cargo_lock_sha256'],sha(self.directory/'Cargo.lock'))
    def test_known_seven_elf_history_does_not_allow_current_worker_omission(self):
        value=retain_historical_binaries(self.directory)
        self.assertEqual(validate(self.directory,historical=True,binary_names=HISTORICAL_BINARIES),value)
        with self.assertRaisesRegex(ValueError,'RELEASE_BINARY_COVERAGE'):
            validate(self.directory,binary_names=HISTORICAL_BINARIES)
        inputs=read_inputs(self.directory/'native-inputs.tar');lock=load(ROOT/'native-security.lock.json')
        # This protocol fixture pins synthetic native sources. The real lock is
        # unreviewed in that fixture and must fail before inspecting ELF coverage.
        with self.assertRaisesRegex(ValueError,'NATIVE_UNREVIEWED_CONTRACT'):
            inventory(inputs,(self.directory/'Cargo.lock').read_bytes(),lock,value['binaries'])
        # With the actual current fixture contract, seven ELFs reach and fail the
        # separate current eight-ELF coverage gate (no historical flag).
        reviewed=native.load(ROOT/'native-security.lock.json')
        with self.assertRaisesRegex(ValueError,'NATIVE_BINARY_COVERAGE'):
            inventory(inputs,(self.directory/'Cargo.lock').read_bytes(),reviewed,value['binaries'])
        for names in [(*HISTORICAL_BINARIES[:-1],'foreign-worker'),(*BINARIES,'sandbox-automation'),tuple(reversed(BINARIES))]:
            with self.assertRaisesRegex(ValueError,'RELEASE_BINARY_COVERAGE'):
                validate(self.directory,historical=True,binary_names=names)

    def test_sbom_omission_fake_version_provenance_and_builder_coverage_reject(self):
        for filename in ('native-components.cdx.json','native-components.spdx.json','native-provenance.json','builder.syft.json'):
            original=(self.directory/filename).read_bytes();value=load(self.directory/filename)
            if filename.endswith('cdx.json'):value['components'][0]['version']='9.0.0'
            elif filename.endswith('spdx.json'):value['packages'].pop()
            elif filename=='builder.syft.json':value['artifacts'].pop()
            else:value['files'].pop('crt/crti.o')
            (self.directory/filename).write_text(json.dumps(value))
            with self.assertRaises(ValueError):validate(self.directory)
            (self.directory/filename).write_bytes(original)
    def test_archive_tamper_crate_checksum_source_omission_and_dynamic_payload_reject(self):
        values=read_inputs(self.directory/'native-inputs.tar');contract=load(ROOT/'native-security.lock.json');lock=(self.directory/'Cargo.lock').read_bytes()
        for key in ('crates/libsqlite3-sys.crate','crates/ring.crate','sources/libsqlite3-sys/sqlite3/sqlite3.c','sources/ring/crypto/public-fixture.c','sysroot/libstd.rlib','crt/crti.o'):
            changed=copy.deepcopy(values);changed[key]=b'CORRUPT'
            with self.assertRaises(ValueError):inventory(changed,lock,contract,self.value['binaries'])
        changed=copy.deepcopy(values);changed.pop('owners.txt')
        with self.assertRaises(ValueError):inventory(changed,lock,contract,self.value['binaries'])
        original=(self.directory/'sandboxd').read_bytes();(self.directory/'sandboxd').write_bytes(original+b'corrupt')
        with self.assertRaisesRegex(ValueError,'PROVENANCE'):validate(self.directory)
    def test_export_is_fixed_networkless_and_inherits_exact_production_builder(self):
        (self.directory/'Dockerfile').write_text((ROOT.parents[1]/'Dockerfile').read_text())
        (self.directory/'scripts/release').mkdir(parents=True);(self.directory/'scripts/release/sqlite_build.py').write_bytes((ROOT/'sqlite_build.py').read_bytes())
        # The synthetic lock has synthetic source hashes; this test alone uses
        # a corresponding public Dockerfile contract rather than a real build.
        production=load(ROOT/'native-security.lock.json');reviewed=native.load(ROOT/'native-security.lock.json');text=(self.directory/'Dockerfile').read_text().replace(production['sqlite']['sha256'],reviewed['sqlite']['sha256']);(self.directory/'Dockerfile').write_text(text)
        content=export_dockerfile(self.directory,reviewed)
        self.assertIn('FROM builder AS sqlite-journal-acceptance',content);self.assertIn('FROM sqlite-journal-acceptance AS native-inventory',content);self.assertIn('RUN --network=none',content)
        self.assertIn('cargo test --locked --offline --release --test nodeguard_journal_native sqlite_release_acceptance_ -- --ignored',content)
        self.assertIn('cargo test --locked --offline --release --test nodeguard_journal_native nodeguard_journal_regression_',content)
        self.assertNotIn('--lib nodeguard::journal::tests',content)
        self.assertNotIn('curl',content.split('FROM sqlite-journal-acceptance AS native-inventory')[1])
        self.assertIn('libsqlite3-sys-0.30.1.crate',content)
        self.assertIn('cargo clean --locked --offline --release -p libsqlite3-sys',content)
        capture='python3 /build/scripts/release/sqlite_build.py --capture-link-output --destination /opt/sandbox-sqlite/evidence'
        self.assertIn(capture,content)
        self.assertIn('--message-format=json-render-diagnostics > /opt/sandbox-sqlite/evidence/production-cargo.json',content)
        self.assertNotIn('find /build/target/release/build',content.split('FROM sqlite-journal-acceptance AS native-inventory')[1])
        unsafe=text.replace(capture,'python3 /build/scripts/release/sqlite_build.py --destination /untrusted')
        (self.directory/'Dockerfile').write_text(unsafe)
        with self.assertRaisesRegex(ValueError,'NATIVE_SQLITE_BUILD_CONTRACT'):export_dockerfile(self.directory,reviewed)
        unsafe=text.replace('cargo clean --locked --offline --release -p libsqlite3-sys','cargo metadata --locked --offline --no-deps')
        (self.directory/'Dockerfile').write_text(unsafe)
        with self.assertRaisesRegex(ValueError,'NATIVE_SQLITE_BUILD_CONTRACT'):export_dockerfile(self.directory,reviewed)
        unsafe=text.replace('    && '+capture,'RUN '+capture)
        (self.directory/'Dockerfile').write_text(unsafe)
        with self.assertRaisesRegex(ValueError,'NATIVE_SQLITE_CAPTURE_ORDER'):export_dockerfile(self.directory,reviewed)
        unsafe=text.replace(' --bin sandbox-automation','')
        (self.directory/'Dockerfile').write_text(unsafe)
        with self.assertRaisesRegex(ValueError,'NATIVE_SQLITE_CARGO_RECEIPT'):export_dockerfile(self.directory,reviewed)
        unsafe=text.replace(' --message-format=json-render-diagnostics > /opt/sandbox-sqlite/evidence/production-cargo.json','')
        (self.directory/'Dockerfile').write_text(unsafe)
        with self.assertRaisesRegex(ValueError,'NATIVE_SQLITE_CARGO_RECEIPT'):export_dockerfile(self.directory,reviewed)
        (self.directory/'Dockerfile').write_text(text)
        contract=load(ROOT/'native-security.lock.json');contract['profile']='musl-static-v1'
        with self.assertRaisesRegex(ValueError,'UNREVIEWED'):export_dockerfile(self.directory,contract)
    def test_input_archive_paths_links_and_duplicate_are_rejected(self):
        for name,kind in (('../outside','file'),('rustc.txt','link'),('rustc.txt','duplicate')):
            path=self.directory/('bad-'+kind+'.tar')
            with tarfile.open(path,'w') as archive:
                member=tarfile.TarInfo(name)
                if kind=='link':member.type=tarfile.SYMTYPE;member.linkname='/etc/passwd'
                archive.addfile(member,io.BytesIO())
                if kind=='duplicate':archive.addfile(member,io.BytesIO())
            with self.assertRaises(ValueError):read_inputs(path)

if __name__=='__main__':unittest.main()
