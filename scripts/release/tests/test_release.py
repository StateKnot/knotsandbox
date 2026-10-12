import base64
import copy
import datetime as dt
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import ROOT, BINARIES, HISTORICAL_BINARIES, COMPONENTS, SCAN_NAMES, LEGACY_SCAN_NAMES, dump, load, sha, image_digest
from build import create_manifest, build_artifact, verify_docker_config, scanner_environment
from gate import evaluate, exceptions, validate_database, validate_sboms, SCANNER_CONFIGURATION
from verify import extract_oci, verify_candidate, verify_statement, cosign_arguments
from preflight import check, publication_policy, console_policy
from security_packages import validate_lock, validate_dockerfile
from console_security import validate_lock as validate_console_lock, validate_dockerfile as validate_console_dockerfile
from console_assets import lock_packages, inventory, asset_manifest, image_files, stage_context, validate_selection, verify_previous
from common import release_file_names
from download_previous import download
from test_native import native_fixture, retain_historical_binaries
from test_sqlite_build import native_trust_fixture

NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
REPO, TAG, COMMIT = 'test-owner/test-repository', 'v1.2.3', 'a' * 40
NAMES = SCAN_NAMES
VERSIONS = load(ROOT / 'tools.lock.json')['tools']


def database_status(built=None):
    # Synthetic protocol fixture, never a statement of an actual scanner run.
    return {'valid': True, 'schemaVersion': 'v6.1.10',
            'built': (built or NOW-dt.timedelta(hours=1)).isoformat(),
            'from': 'https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.10_2026-10-08T00:00:00Z_1791417600.tar.zst?checksum=sha256%3A'+'a'*64,
            'path': '/scanner/db/6/vulnerability.db'}


def reports(status=None):
    configuration = copy.deepcopy(SCANNER_CONFIGURATION)
    configuration['db']['cache-dir'] = '/scanner/db'
    return {name: {'matches': [], 'descriptor': {'name': 'grype', 'version': VERSIONS['grype']['version'],
            'configuration': copy.deepcopy(configuration), 'db': {'status': copy.deepcopy(status or database_status())}},
            'ignoredMatches': [], 'alertsByPackage': []} for name in NAMES}


def risk():
    return {'artifact': 'service', 'vulnerability': 'CVE-2026-12345', 'package': 'test-package', 'version': '1.0.0', 'purl': 'pkg:cargo/test-package@1.0.0', 'severity': 'High', 'approved_at': (NOW-dt.timedelta(days=1)).isoformat(), 'expires_at': (NOW+dt.timedelta(days=1)).isoformat(), 'owner': 'security-reviewer', 'ticket': 'https://example.test/review/1', 'reason': 'Reviewed exact affected package and compensating control.'}


def finding():
    r = risk()
    return {'vulnerability': {'id': r['vulnerability'], 'severity': r['severity']}, 'artifact': {k: r[k] for k in ('version', 'purl')} | {'name': r['package']}}


def blob(directory, value, media):
    import hashlib
    data = json.dumps(value).encode()
    digest = hashlib.sha256(data).hexdigest()
    target = directory/'blobs'/'sha256'/digest
    target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
    return {'mediaType': media, 'digest': 'sha256:'+digest, 'size': len(data)}


def fixture(directory, *, historical=False):
    # Synthetic protocol fixture. Never used as a signed production artifact.
    native_fixture(directory)
    binaries = HISTORICAL_BINARIES if historical else BINARIES
    if historical: retain_historical_binaries(directory)
    (directory/'builder.syft.json').unlink()
    for name in COMPONENTS:
        d = directory/name; d.mkdir()
        dump(d/'oci-layout', {'imageLayoutVersion':'1.0.0'})
        config = blob(d, {'os':'linux','architecture':'amd64','config':{'User':'101:101' if name=='console' else '1000:1000'}}, 'application/vnd.oci.image.config.v1+json')
        layers=[]
        if name in ('console','service','runner'):
            import hashlib
            package={'name':'fixture-console','version':'1.0.0'}
            lock={'name':'fixture-console','version':'1.0.0','lockfileVersion':3,'packages':{'':package,'node_modules/fixture-npm':{'version':'1.0.0','resolved':'https://registry.npmjs.org/fixture-npm/-/fixture-npm-1.0.0.tgz','integrity':'sha512-'+base64.b64encode(b'a'*64).decode()}}}
            if name=='console':
                files={'usr/share/nginx/html/assets/index-fixture.js':b'fixture', 'usr/share/nginx/html/bundle-manifest.json':json.dumps({'schema':1,'assets':{'index-fixture.js':hashlib.sha256(b'fixture').hexdigest()}}).encode(), 'usr/share/sandbox-console/package.json':json.dumps(package).encode(), 'usr/share/sandbox-console/package-lock.json':json.dumps(lock).encode()}
            else:
                runtime_binaries=('sandbox-runner',) if name=='runner' else tuple(n for n in binaries if n not in ('sandbox-runner','sandbox-nodeguard'))
                files={'usr/local/bin/'+n:(directory/n).read_bytes() for n in runtime_binaries}
            body=io.BytesIO()
            with tarfile.open(fileobj=body,mode='w') as layer:
                for filename,data in files.items():
                    entry=tarfile.TarInfo(filename);entry.size=len(data);entry.mode=0o555;layer.addfile(entry,io.BytesIO(data))
            data=body.getvalue();digest=hashlib.sha256(data).hexdigest()
            (d/'blobs/sha256'/digest).write_bytes(data)
            layers=[{'mediaType':'application/vnd.oci.image.layer.v1.tar','digest':'sha256:'+digest,'size':len(data)}]
        desc = blob(d, {'schemaVersion':2,'config':config,'layers':layers}, 'application/vnd.oci.image.manifest.v1+json')
        dump(d/'index.json', {'schemaVersion':2,'manifests':[desc]})
        with tarfile.open(directory/(name+'.oci.tar'),'w') as archive:
            for path in sorted(d.rglob('*')): archive.add(path, arcname=str(path.relative_to(d)), recursive=False)
    dump(directory/'console-npm-locks.json', inventory(image_files(directory/'console')))
    (directory/'tools.lock.json').write_bytes((ROOT/'tools.lock.json').read_bytes())
    (directory/'debian-security.lock.json').write_bytes((ROOT/'debian-security.lock.json').read_bytes())
    (directory/'console-security.lock.json').write_bytes((ROOT/'console-security.lock.json').read_bytes())
    dump(directory/'risk-exceptions.json', {'version':1,'exceptions':[]})
    for name, report in reports().items():
        dump(directory/(name+'.grype.json'), report)
        if name=='native-components':continue
        sbom={'artifacts':[{'name':'libsqlite3-sys','version':'0.30.1','type':'rust-crate'}, {'name':'ring','version':'0.17.14','type':'rust-crate'}, {'name':'fixture-npm','version':'1.0.0','type':'npm'}, {'name':'zlib','version':'1.3.2-r1','type':'apk'},{'name':'libc6-dev','version':'2.36-public-fixture','type':'deb'},{'name':'libgcc-12-dev','version':'12.2.0-public-fixture','type':'deb'}]}
        if name=='builder':sbom['source']={'type':'image','metadata':{'userInput':load(ROOT/'native-security.lock.json')['builder_image'],'architecture':'amd64','os':'linux'}}
        dump(directory/(name+('.cdx.json' if name=='proxy-source' else '.syft.json')),sbom)
        if name != 'proxy-source': dump(directory/(name+'.spdx.json'), {'fixture':True})
    dump(directory/'database.json', database_status())
    dump(directory/'scan-gate.json', {'version':1,'evaluated_at':NOW.isoformat(),'blocked':[], 'reports':{name:sha(directory/(name+'.grype.json')) for name in NAMES}, 'policy_sha256':sha(directory/'risk-exceptions.json')})
    with patch('build.now',return_value=NOW), patch('build.BINARIES',binaries): create_manifest(directory,REPO,TAG,COMMIT,'42',{'first_release':True,'previous':None})


def rewrite(path, value):
    path.write_text(json.dumps(value))


class RiskGate(unittest.TestCase):
    def test_clean_complete_scan(self): self.assertEqual(evaluate(reports(), {'version':1,'exceptions':[]}, VERSIONS,NOW), [])
    def test_every_high_critical_unknown_blocks(self):
        for severity in ('High','Critical','Unknown'):
            r=reports(); f=finding(); f['vulnerability']['severity']=severity; r['service']['matches']=[f]
            self.assertEqual(len(evaluate(r, {'version':1,'exceptions':[]},VERSIONS,NOW)),1)
    def test_exception_is_exact_and_must_be_used(self):
        p={'version':1,'exceptions':[risk()]}; r=reports();r['service']['matches']=[finding()]
        self.assertEqual(evaluate(r,p,VERSIONS,NOW),[])
        r['service']['matches'][0]['artifact']['version']='1.0.1'
        with self.assertRaisesRegex(ValueError,'UNUSED'):evaluate(r,p,VERSIONS,NOW)
    def test_expired_future_long_and_wildcard_exceptions_rejected(self):
        for key,value in [('expires_at',NOW.isoformat()),('approved_at',(NOW+dt.timedelta(hours=1)).isoformat()),('expires_at',(NOW+dt.timedelta(days=31)).isoformat()),('purl','pkg:cargo/*')]:
            item=risk();item[key]=value
            with self.assertRaises(ValueError):exceptions({'version':1,'exceptions':[item]},NOW)
    def test_missing_scan_wrong_version_ignored_and_eol_reject(self):
        mutations=[lambda r:r.pop('builder'),lambda r:r['service']['descriptor'].update(version='wrong'),lambda r:r['service'].update(ignoredMatches=[{}]),lambda r:r['runner'].update(alertsByPackage=[{}])]
        for mutate in mutations:
            r=reports();mutate(r)
            with self.assertRaises(ValueError):evaluate(r,{'version':1,'exceptions':[]},VERSIONS,NOW)
    def test_database_age_invalid_future_fail_closed(self):
        validate_database({'valid':True,'built':(NOW-dt.timedelta(hours=1)).isoformat()},NOW)
        for status in [{'valid':False}, {'valid':True,'built':(NOW-dt.timedelta(hours=25)).isoformat()}, {'valid':True,'built':(NOW+dt.timedelta(seconds=1)).isoformat()}]:
            with self.assertRaises(ValueError):validate_database(status,NOW)

    def test_scanner_configuration_cannot_hide_findings_or_expand_database_age(self):
        changes = [(['exclude'], ['**']), (['only-fixed'], True), (['only-notfixed'], True),
            (['vex-documents'], ['ignored.vex']), (['vex-add'], ['not_affected']),
            (['ignore'], [{'package': {'name': '*'}}]), (['ignore-wontfix'], 'not-fixed'),
            (['match-upstream-kernel-headers'], False), (['match-upstream-kernel-headers'], 1),
            (['alerts', 'enable-eol-distro-warnings'], False),
            (['match', 'stock', 'using-cpes'], False), (['search', 'scope'], 'all-layers'),
            (['db', 'validate-age'], False), (['db', 'validate-by-hash-on-start'], False),
            (['db', 'auto-update'], True), (['db', 'max-allowed-built-age'], 2*86400000000000),
            (['db', 'update-url'], 'https://untrusted.test/db'),
            (['registry', 'insecure-skip-tls-verify'], True),
            (['externalSources', 'enable'], True),
            (['externalSources', 'maven', 'rateLimit'], 300000000.0),
            (['unknown-field'], False)]
        for path, value in changes:
            with self.subTest(path=path, value=value):
                r = reports(); container = r['service']['descriptor']['configuration']
                for key in path[:-1]: container = container[key]
                container[path[-1]] = value
                with self.assertRaisesRegex(ValueError, 'SCANNER_CONFIGURATION'):
                    evaluate(r, {'version': 1, 'exceptions': []}, VERSIONS, NOW)
        for field in ('configuration', 'db'):
            r=reports();r['service']['descriptor'].pop(field)
            with self.assertRaises(ValueError):evaluate(r, {'version': 1, 'exceptions': []}, VERSIONS, NOW)

    def test_scanner_database_identity_types_source_and_paths_are_bound(self):
        changes = [('schemaVersion', 'v6.1.11'), ('valid', 1), ('path', '/other/vulnerability.db'),
            ('from', 'https://untrusted.test/db?checksum=sha256%3A'+'a'*64),
            ('from', database_status()['from']+'&checksum=sha256%3A'+'a'*64),
            ('from', database_status()['from'].replace('sha256%3A', 'sha1%3A')),
            ('built', (NOW-dt.timedelta(hours=25)).isoformat()),
            ('built', (NOW+dt.timedelta(seconds=1)).isoformat())]
        for field, value in changes:
            with self.subTest(field=field, value=value):
                r=reports();r['service']['descriptor']['db']['status'][field]=value
                with self.assertRaises(ValueError):evaluate(r, {'version': 1, 'exceptions': []}, VERSIONS, NOW)
        r=reports();r['service']['descriptor']['db']['status']['from']=database_status()['from'][:-64]+'b'*64
        with self.assertRaisesRegex(ValueError, 'SCANNER_DATABASE_MISMATCH'):
            evaluate(r, {'version': 1, 'exceptions': []}, VERSIONS, NOW)
        standalone=database_status();standalone['from']=standalone['from'][:-64]+'b'*64
        with self.assertRaisesRegex(ValueError, 'SCANNER_DATABASE_MISMATCH'):
            evaluate(reports(), {'version': 1, 'exceptions': []}, VERSIONS, NOW, database_status=standalone)
        for cache in ('relative', '/db/../other', None):
            r=reports();r['service']['descriptor']['configuration']['db']['cache-dir']=cache
            with self.assertRaisesRegex(ValueError, 'SCANNER_DATABASE_CACHE_PATH'):
                evaluate(r, {'version': 1, 'exceptions': []}, VERSIONS, NOW)

    def test_historical_database_time_does_not_change_current_risk_exception_time(self):
        old=NOW-dt.timedelta(days=2);status=database_status(old-dt.timedelta(hours=1));r=reports(status)
        with self.assertRaisesRegex(ValueError, 'SCANNER_DATABASE_STALE'):
            evaluate(r, {'version': 1, 'exceptions': []}, VERSIONS, NOW)
        self.assertEqual(evaluate(r, {'version': 1, 'exceptions': []}, VERSIONS, NOW,
                                 database_at=old, database_status=status), [])
        r['service']['matches']=[finding()];item=risk();item.update(approved_at=(old-dt.timedelta(hours=1)).isoformat(),expires_at=(old+dt.timedelta(hours=1)).isoformat())
        with self.assertRaisesRegex(ValueError, 'RISK_REVIEW_EXPIRED'):
            evaluate(r, {'version': 1, 'exceptions': [item]}, VERSIONS, NOW, database_at=old, database_status=status)

    def test_scanner_environment_drops_inherited_filters_for_every_scanner(self):
        inherited={'GRYPE_EXCLUDE':'**', 'GRYPE_ONLY_FIXED':'true', 'GRYPE_IGNORE_WONTFIX':'not-fixed',
            'GRYPE_VEX_DOCUMENTS':'ignored.vex', 'GRYPE_DB_CACHE_DIR':'/untrusted',
            'SYFT_EXCLUDE':'**', 'SYFT_PACKAGE_CATALOGER_ENABLED':'false', 'REGISTRY_AUTH':'opaque'}
        with patch.dict('os.environ', inherited, clear=True):
            self.assertEqual(scanner_environment(), {'REGISTRY_AUTH':'opaque'})
            self.assertEqual(scanner_environment(GRYPE_DB_CACHE_DIR='/verified/db',GRYPE_DB_AUTO_UPDATE='false'),
                {'REGISTRY_AUTH':'opaque', 'GRYPE_DB_CACHE_DIR':'/verified/db', 'GRYPE_DB_AUTO_UPDATE':'false'})
            with self.assertRaisesRegex(ValueError, 'SCANNER_ENVIRONMENT'):
                scanner_environment(GRYPE_EXCLUDE='**')


class ArtifactProtocol(unittest.TestCase):
    def setUp(self):
        self.trust=native_trust_fixture();self.trust.start();self.tmp=tempfile.TemporaryDirectory();self.directory=Path(self.tmp.name);fixture(self.directory)
    def tearDown(self):self.tmp.cleanup();self.trust.stop()
    def verify(self):return verify_candidate(self.directory,REPO,TAG,COMMIT,NOW)
    def test_unsigned_candidate_passes_only_structural_checks(self):
        self.assertEqual(self.verify()['commit'],COMMIT)
        self.assertFalse((self.directory/'deployment-lock.json').exists())
    def test_wrong_expected_repository_tag_commit(self):
        for repo,tag,commit in [('other/repo',TAG,COMMIT),(REPO,'v1.2.4',COMMIT),(REPO,TAG,'b'*40)]:
            with self.assertRaises(ValueError):verify_candidate(self.directory,repo,tag,commit,NOW)
    def test_actual_build_helper_local_and_oci_smoke_paths(self):
        # Exercise the real orchestration function, including both exporter paths;
        # subprocesses are mocked, not Python control flow or artifact verification.
        base=['/locked/buildctl','build','--frontend=dockerfile.v0']
        with patch('build.run') as runner:
            build_artifact(base,self.directory,'binaries-export',self.directory/'binary-out',local=True)
            self.assertEqual(runner.call_args.args[0][:3],base)
            self.assertIn('type=local,dest='+str(self.directory/'binary-out'),runner.call_args.args[0])
        d=self.directory/'service';index=load(d/'index.json');m=load(d/'blobs/sha256'/index['manifests'][0]['digest'][7:]);config=m['config']['digest']
        def run_effect(command, **kwargs):
            destination = None
            if command[0] == '/locked/buildctl':
                option = next(v for v in command if isinstance(v, str) and v.startswith('type=docker,'))
                destination = option.split('dest=')[1]
            elif command[:3] == ['docker', 'image', 'save']:
                destination = command[4]
            if destination:
                data = (d/'blobs/sha256'/config[7:]).read_bytes()
                with tarfile.open(destination, 'w') as archive:
                    for name, body in [('manifest.json', json.dumps([{'Config':'config.json'}]).encode()), ('config.json', data)]:
                        entry = tarfile.TarInfo(name); entry.size = len(body)
                        archive.addfile(entry, io.BytesIO(body))
        with patch('build.run', side_effect=run_effect) as runner:
            build_artifact(base,self.directory,'runtime',d,smoke='service')
            calls=[call.args[0] for call in runner.call_args_list]
            self.assertEqual(calls[0][:3],base)
            self.assertTrue(any('type=docker,' in str(value) for value in calls[0]))
            self.assertTrue(any(any(str(v).startswith('sandbox-release-smoke:') for v in call) and '--version' in call for call in calls))
            self.assertTrue(any('/usr/local/bin/sandbox-admission' in call for call in calls))
            self.assertTrue(any('/usr/local/bin/sandbox-automation' in call and '--help' in call for call in calls))
        archive_path=self.directory/'wrong-image.tar'
        with tarfile.open(archive_path,'w') as archive:
            for name, body in [('manifest.json', b'[{"Config":"config.json"}]'), ('config.json', b'{}')]:
                entry=tarfile.TarInfo(name);entry.size=len(body);archive.addfile(entry,io.BytesIO(body))
        with self.assertRaisesRegex(ValueError,'SMOKE_IMAGE_CONFIG'):
            verify_docker_config(archive_path,config)
    def test_blob_tamper_fails(self):
        with (self.directory/'sandboxd').open('ab') as f:f.write(b'tamper')
        with self.assertRaisesRegex(ValueError,'FILE_HASH'):self.verify()
    def test_manifest_cannot_omit_binary_or_sbom(self):
        for field in ['sandboxd','sandbox-automation','proxy-source.cdx.json','native-inputs.tar','native-components.cdx.json','native-components.spdx.json','native-components.grype.json','native-security.lock.json','native-provenance.json']:
            p=self.directory/'release-manifest.json';v=load(p);old=v['files'].pop(field);rewrite(p,v)
            with self.assertRaisesRegex(ValueError,'COVERAGE'):self.verify()
            v['files'][field]=old;rewrite(p,v)
    def test_native_high_and_missing_scanner_coverage_still_blocks(self):
        r=reports();r['native-components']['matches']=[finding()]
        self.assertEqual(len(evaluate(r,{'version':1,'exceptions':[]},VERSIONS,NOW)),1)
        r.pop('native-components')
        with self.assertRaisesRegex(ValueError,'SCAN_COVERAGE'):evaluate(r,{'version':1,'exceptions':[]},VERSIONS,NOW)
    def test_known_seven_binary_previous_history_and_current_rejection(self):
        # Only protocol/signature-orchestration mocks. No real Cosign certification.
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);fixture(directory,historical=True)
            self.assertEqual(verify_candidate(directory,REPO,TAG,COMMIT,NOW,historical=True)['binaries'],list(HISTORICAL_BINARIES))
            with self.assertRaisesRegex(ValueError,'RELEASE_BINARY_COVERAGE'):
                verify_candidate(directory,REPO,TAG,COMMIT,NOW)
            with patch('console_assets.run') as crypto, patch('verify.cosign_arguments',return_value=['current-pinned-cosign']), patch('verify.verify_statement'):
                previous=verify_previous(directory,Path('/tools'),REPO,TAG,COMMIT)
            crypto.assert_called_once_with(['current-pinned-cosign'],timeout=60)
            self.assertEqual(previous['commit'],COMMIT)
            self.assertFalse((directory/'deployment-lock.json').exists())
            original=load(directory/'release-manifest.json')
            for names in [list(HISTORICAL_BINARIES[:-1])+['foreign-worker'],list(BINARIES)+['sandbox-automation'],list(reversed(BINARIES))]:
                changed=copy.deepcopy(original);changed['binaries']=names;rewrite(directory/'release-manifest.json',changed)
                with self.assertRaisesRegex(ValueError,'RELEASE_BINARY_COVERAGE'):
                    verify_candidate(directory,REPO,TAG,COMMIT,NOW,historical=True)

    def test_legacy_v1_is_only_available_for_authenticated_previous_asset_review(self):
        manifest=load(self.directory/'release-manifest.json');manifest['version']=1
        for name in set(manifest['files'])-release_file_names(legacy=True):manifest['files'].pop(name)
        gate=load(self.directory/'scan-gate.json');gate['reports'].pop('native-components');rewrite(self.directory/'scan-gate.json',gate)
        manifest['files']['scan-gate.json']={'sha256':sha(self.directory/'scan-gate.json'),'size':(self.directory/'scan-gate.json').stat().st_size}
        rewrite(self.directory/'release-manifest.json',manifest)
        with self.assertRaisesRegex(ValueError,'RELEASE_IDENTITY'):self.verify()
        self.assertEqual(verify_candidate(self.directory,REPO,TAG,COMMIT,NOW,historical=True)['version'],1)
    def test_native_runtime_hash_links_special_files_and_whiteouts_fail_closed(self):
        import hashlib
        from native import validate_runtime
        original=self.directory/'service';idx=load(original/'index.json');m=load(original/'blobs/sha256'/idx['manifests'][0]['digest'][7:])
        native=load(self.directory/'native-provenance.json');validate_runtime(original,'service',native)
        for filename,kind in [('usr/local/bin/sandboxd','file'),('usr/local/bin/sandbox-automation','file'),('usr/local/bin/sandbox-automation','whiteout'),('usr/local/bin/sandboxd','link'),('usr/local/bin/.wh.sandboxd','whiteout'),('usr/local','ancestor')]:
            body=io.BytesIO()
            with tarfile.open(fileobj=body,mode='w') as archive:
                member=tarfile.TarInfo(filename);member.mode=0o555
                if kind in ('link','ancestor'):member.type=tarfile.SYMTYPE;member.linkname='/tmp/other'
                elif kind=='file':member.size=5
                archive.addfile(member,io.BytesIO(b'WRONG'))
            data=body.getvalue();digest=hashlib.sha256(data).hexdigest();(original/'blobs/sha256'/digest).write_bytes(data)
            m['layers']=[{'mediaType':'application/vnd.oci.image.layer.v1.tar','digest':'sha256:'+digest,'size':len(data)}]
            desc=blob(original,m,'application/vnd.oci.image.manifest.v1+json');rewrite(original/'index.json',{'schemaVersion':2,'manifests':[desc]})
            with self.assertRaisesRegex(ValueError,'NATIVE_RUNTIME_'):validate_runtime(original,'service',native)
    def test_symlink_artifact_and_duplicate_json_fail(self):
        p=self.directory/'sandboxd';p.unlink();p.symlink_to(self.directory/'sandbox-admin')
        with self.assertRaisesRegex(ValueError,'ARTIFACT_MISSING'):self.verify()
        with self.assertRaisesRegex(ValueError,'DUPLICATE'):
            q=self.directory/'duplicate.json';q.write_text('{"a":1,"a":2}');load(q)
    def test_archive_traversal_symlink_and_duplicate_fail(self):
        for kind in ['traversal','link','duplicate']:
            archive=self.directory/(kind+'.tar')
            with tarfile.open(archive,'w') as output:
                entry=tarfile.TarInfo('../outside' if kind=='traversal' else 'file')
                if kind=='link':entry.type=tarfile.SYMTYPE;entry.linkname='/etc/passwd'
                output.addfile(entry,io.BytesIO())
                if kind=='duplicate':output.addfile(entry,io.BytesIO())
            with tempfile.TemporaryDirectory() as d, self.assertRaises(ValueError):extract_oci(archive,Path(d))
    def test_default_image_catalog_must_not_silently_omit_rust_dependencies(self):
        rewrite(self.directory/'service.syft.json',{'artifacts':[]})
        with self.assertRaisesRegex(ValueError,'DEPENDENCIES_MISSING'):validate_sboms(self.directory)
    def test_signature_cli_identity_is_external_not_from_manifest(self):
        (self.directory/'release-manifest.sigstore.json').write_text('{}')
        with patch('verify.tool',return_value=Path('/reviewed/cosign')):
            args=[str(v) for v in cosign_arguments(self.directory,Path('/tools'),REPO,TAG,COMMIT)]
        for flag,value in [('--certificate-github-workflow-sha',COMMIT),('--certificate-github-workflow-ref','refs/tags/'+TAG),('--certificate-github-workflow-trigger','workflow_dispatch'),('--certificate-oidc-issuer','https://token.actions.githubusercontent.com')]:self.assertEqual(args[args.index(flag)+1],value)
        self.assertFalse(any('insecure' in value for value in args))
    def test_unsigned_candidate_cannot_run_production_verify(self):
        proc=subprocess.run([sys.executable,str(ROOT/'verify.py'),'--directory',str(self.directory),'--tools',str(self.directory),'--repository',REPO,'--tag',TAG,'--commit',COMMIT,'--output',str(self.directory/'deployment-lock.json')],capture_output=True)
        self.assertNotEqual(proc.returncode,0);self.assertFalse((self.directory/'deployment-lock.json').exists())
    def test_unsigned_candidate_cannot_install_any_binary(self):
        destination=self.directory/'install-target'
        proc=subprocess.run([sys.executable,str(ROOT/'install.py'),'--directory',str(self.directory),'--tools',str(self.directory),'--repository',REPO,'--tag',TAG,'--commit',COMMIT,'--destination',str(destination)],capture_output=True)
        self.assertNotEqual(proc.returncode,0);self.assertFalse(destination.exists())
    def test_statement_checks_source_and_workflow_after_crypto(self):
        manifest=self.verify()
        statement={'_type':'https://in-toto.io/Statement/v1','predicateType':'https://slsa.dev/provenance/v1','subject':[{'name':'release-manifest.json','digest':{'sha256':sha(self.directory/'release-manifest.json')}}],'predicate':load(self.directory/'provenance.json')}
        def bundle():rewrite(self.directory/'release-manifest.sigstore.json',{'dsseEnvelope':{'payloadType':'application/vnd.in-toto+json','payload':base64.b64encode(json.dumps(statement).encode()).decode()}})
        bundle();verify_statement(self.directory,manifest)
        statement['predicate']['buildDefinition']['externalParameters']['commit']='b'*40;bundle()
        with self.assertRaises(ValueError):verify_statement(self.directory,manifest)


class PublicationGuards(unittest.TestCase):
    def test_manual_and_ci_exact_commit(self):
        env={'GITHUB_REPOSITORY':REPO,'GITHUB_REF':'refs/tags/'+TAG,'GITHUB_SHA':COMMIT,'GITHUB_EVENT_NAME':'workflow_dispatch'}
        good={'head_sha':COMMIT,'path':'.github/workflows/ci.yml','event':'push','run_number':2,'conclusion':'success'}
        with patch.dict('os.environ',env,clear=True), patch('preflight.github',side_effect=[{'sha':COMMIT},{'workflow_runs':[good]}]):check(REPO,TAG,COMMIT)
        for change in [{'GITHUB_REF':'refs/heads/main'},{'GITHUB_EVENT_NAME':'push'}]:
            with patch.dict('os.environ',env|change,clear=True), self.assertRaises(ValueError):check(REPO,TAG,COMMIT)
        with patch.dict('os.environ',env,clear=True), patch('preflight.github',side_effect=[{'sha':COMMIT},{'workflow_runs':[good,good|{'run_number':3,'conclusion':'failure'}]}]),self.assertRaisesRegex(ValueError,'CI_REQUIRED'):check(REPO,TAG,COMMIT)
    def test_environment_without_review_cannot_publish(self):
        with patch('preflight.github',return_value={'protection_rules':[]}),self.assertRaisesRegex(ValueError,'REVIEW_REQUIRED'):publication_policy(REPO,TAG)
    def test_publish_cannot_run_without_explicit_flag(self):
        proc=subprocess.run([sys.executable,str(ROOT/'publish.py'),'--directory','/missing','--tools','/missing','--repository',REPO,'--tag',TAG,'--commit',COMMIT],capture_output=True)
        self.assertNotEqual(proc.returncode,0);self.assertIn(b'EXPLICIT_PUBLICATION_REQUIRED',proc.stderr)



class SecurityPackageLock(unittest.TestCase):
    def test_console_patch_is_signed_offline_pinned_and_installed_in_inventory(self):
        lock = validate_console_lock(load(ROOT/'console-security.lock.json'), NOW)
        dockerfile = (ROOT.parent.parent/'deploy/console/Dockerfile').read_text()
        validate_console_dockerfile(lock, dockerfile)
        for old, new, code in [(lock['packages'][0]['sha256'], '0'*64, 'DOWNLOAD_DRIFT'), ('RUN --network=none case', 'RUN case', 'OFFLINE_INSTALL_MISSING'), ('apk add --no-network', 'apk add --allow-untrusted --no-network', 'OFFLINE_INSTALL_MISSING'), ('zlib-1.3.2-r1" \\', 'zlib-1.3.2-r0" \\', 'INSTALLED_VERSION_UNCHECKED')]:
            with self.assertRaisesRegex(ValueError, code): validate_console_dockerfile(lock, dockerfile.replace(old, new))
        for kind in ('expired', 'url', 'hash', 'architecture', 'signature'):
            changed = copy.deepcopy(lock)
            if kind == 'expired': changed['review_expires_at'] = NOW.isoformat()
            elif kind == 'url': changed['packages'][0]['url'] = 'https://evil.invalid/zlib.apk'
            elif kind == 'hash': changed['packages'][0]['sha256'] = 'missing'
            elif kind == 'architecture': changed['packages'][1]['architecture'] = 'x86_64'
            else: changed['packages'][0]['signature_key'] = 'untrusted.pub'
            with self.assertRaises(ValueError): validate_console_lock(changed, NOW)

    def test_reviewed_security_downloads_match_actual_docker_build_contract(self):
        lock = validate_lock(load(ROOT/'debian-security.lock.json'), NOW)
        dockerfile = (ROOT.parent.parent/'Dockerfile').read_text()
        validate_dockerfile(lock, dockerfile)
        with self.assertRaisesRegex(ValueError, 'DOWNLOAD_DRIFT'):
            validate_dockerfile(lock, dockerfile.replace(lock['packages'][0]['sha256'], '0'*64))
        with self.assertRaisesRegex(ValueError, 'VERSION_UNCHECKED'):
            validate_dockerfile(lock, dockerfile.replace("= '"+lock['packages'][0]['version']+"'", "= 'unreviewed'"))
        with self.assertRaisesRegex(ValueError, 'INSTALL_MISSING'):
            validate_dockerfile(lock, dockerfile.replace('RUN --network=none dpkg', 'RUN dpkg'))
    def test_expired_review_arbitrary_download_and_duplicate_package_fail(self):
        original = load(ROOT/'debian-security.lock.json')
        for change in ('expired', 'origin', 'duplicate', 'index-expired'):
            lock = copy.deepcopy(original)
            if change == 'expired': lock['review_expires_at'] = NOW.isoformat()
            elif change == 'origin': lock['packages'][0]['url'] = 'https://evil.invalid/package.deb'
            elif change == 'index-expired': lock['source']['release_valid_until'] = 'Sat, 03 Oct 2026 00:00:00 UTC'
            else: lock['packages'].append(copy.deepcopy(lock['packages'][0]))
            with self.assertRaises(ValueError): validate_lock(lock, NOW)



class ConsoleReleaseProtocol(unittest.TestCase):
    def setUp(self):
        self.trust=native_trust_fixture();self.trust.start();self.tmp=tempfile.TemporaryDirectory();self.directory=Path(self.tmp.name);fixture(self.directory)
    def tearDown(self):self.tmp.cleanup();self.trust.stop()
    def test_console_is_required_in_every_scan_and_signed_file_inventory(self):
        r=reports();r.pop('console')
        with self.assertRaisesRegex(ValueError,'SCAN_COVERAGE'):evaluate(r,{'version':1,'exceptions':[]},VERSIONS,NOW)
        r=reports();r.pop('console-builder')
        with self.assertRaisesRegex(ValueError,'SCAN_COVERAGE'):evaluate(r,{'version':1,'exceptions':[]},VERSIONS,NOW)
        m=load(self.directory/'release-manifest.json');m['images'].pop('console');rewrite(self.directory/'release-manifest.json',m)
        with self.assertRaisesRegex(ValueError,'RELEASE_COMPONENTS'):verify_candidate(self.directory,REPO,TAG,COMMIT,NOW)
    def test_npm_transitive_dev_scoped_and_retained_packages_cannot_be_omitted(self):
        rewrite(self.directory/'console.syft.json',{'artifacts':[]})
        with self.assertRaisesRegex(ValueError,'NPM_DEPENDENCIES_MISSING'):validate_sboms(self.directory)
        lock=load(self.directory/'console-npm-locks.json')['locks'][0]['lock']
        lock['packages']['node_modules/parent/node_modules/@scope/dev']={'version':'1.2.3','dev':True,'resolved':'https://registry.npmjs.org/@scope/dev/-/dev-1.2.3.tgz','integrity':'sha512-'+base64.b64encode(b'a'*64).decode()}
        self.assertIn(('@scope/dev','1.2.3'),lock_packages(lock))
        lock['packages']['node_modules/parent/node_modules/@scope/dev']['resolved']='https://arbitrary.test/pkg'
        with self.assertRaisesRegex(ValueError,'NPM_LOCK_UNPINNED'):lock_packages(lock)
    def test_uid101_only_allowed_for_console_component(self):
        image_digest(self.directory/'console','console')
        with self.assertRaisesRegex(ValueError,'OCI_NONROOT'):image_digest(self.directory/'console','service')
        with self.assertRaisesRegex(ValueError,'OCI_NONROOT'):image_digest(self.directory/'service','console')
    def test_console_inventory_is_bound_to_actual_image_not_just_scanner_claim(self):
        record=load(self.directory/'console-npm-locks.json')
        record['locks'][0]['lock']['packages']['node_modules/fixture-npm']['version']='9.9.9'
        rewrite(self.directory/'console-npm-locks.json',record)
        manifest=load(self.directory/'release-manifest.json')
        p=self.directory/'console-npm-locks.json'
        manifest['files'][p.name]={'sha256':sha(p),'size':p.stat().st_size}
        rewrite(self.directory/'release-manifest.json',manifest)
        with self.assertRaisesRegex(ValueError,'CONSOLE_IMAGE_INVENTORY_MISMATCH'):
            verify_candidate(self.directory,REPO,TAG,COMMIT,NOW)

    def test_default_cannot_skip_previous_and_first_mode_is_explicit(self):
        with self.assertRaisesRegex(ValueError,'VERIFIED_PREVIOUS'):validate_selection(False,'','',TAG)
        with self.assertRaises(ValueError):validate_selection(True,'v1.2.2','b'*40,TAG)
        validate_selection(True,'','',TAG)
        validate_selection(False,'v1.2.2','b'*40,TAG)
        proc=subprocess.run([sys.executable,str(ROOT/'build.py'),'--tools','/missing','--output','/missing','--repository',REPO,'--tag',TAG,'--commit',COMMIT,'--run-id','42'],capture_output=True)
        self.assertNotEqual(proc.returncode,0);self.assertIn(b'VERIFIED_PREVIOUS_CONSOLE_RELEASE_REQUIRED',proc.stderr)
    def test_first_claim_rejected_if_console_published_and_previous_must_be_latest_exact_commit(self):
        release={'draft':False,'tag_name':'v1.2.2','published_at':NOW.isoformat(),'assets':[{'name':'console.oci.tar'}]}
        with patch('preflight.github',return_value=[release]),self.assertRaisesRegex(ValueError,'ALREADY_EXISTS'):console_policy(REPO,TAG,True,'','')
        with patch('preflight.github',side_effect=[[release],{'sha':'b'*40}]):console_policy(REPO,TAG,False,'v1.2.2','b'*40)
        with patch('preflight.github',return_value=[release]),self.assertRaisesRegex(ValueError,'LATEST_PUBLISHED'):console_policy(REPO,TAG,False,'v1.2.1','b'*40)
        with patch('preflight.github',side_effect=[[release],{'sha':'c'*40}]),self.assertRaisesRegex(ValueError,'COMMIT_MISMATCH'):console_policy(REPO,TAG,False,'v1.2.2','b'*40)
    def test_previous_signature_authentication_precedes_metadata_and_asset_interpretation(self):
        with patch('console_assets.run',side_effect=ValueError('CRYPTO_REJECTED')),patch('verify.cosign_arguments',return_value=['cosign']),patch('console_assets.load') as reader,self.assertRaisesRegex(ValueError,'CRYPTO_REJECTED'):
            verify_previous(self.directory,Path('/tools'),REPO,TAG,COMMIT)
        reader.assert_not_called()
    def test_authenticated_previous_still_requires_actual_scanner_configuration(self):
        # Only signature execution is mocked. Recompute authenticating file
        # hashes so the historical path must reach its real descriptor guard.
        report=load(self.directory/'service.grype.json');report['descriptor'].pop('configuration')
        rewrite(self.directory/'service.grype.json',report)
        gate=load(self.directory/'scan-gate.json');gate['reports']['service']=sha(self.directory/'service.grype.json')
        rewrite(self.directory/'scan-gate.json',gate)
        (self.directory/'release-manifest.json').unlink();(self.directory/'provenance.json').unlink()
        create_manifest(self.directory,REPO,TAG,COMMIT,'42',{'first_release':True,'previous':None})
        with patch('console_assets.run'),patch('verify.cosign_arguments',return_value=['current-pinned-cosign']),patch('verify.verify_statement'):
            with self.assertRaisesRegex(ValueError,'SCANNER_CONFIGURATION'):
                verify_previous(self.directory,Path('/tools'),REPO,TAG,COMMIT)
    def test_authenticated_previous_uses_historical_policies_without_weakening_install(self):
        # Synthetic older release, not a real signature. Only the cryptographic
        # boundary is mocked; actual old policy, scanner, hashes and OCI checks run.
        old = NOW - dt.timedelta(days=1)
        tools = load(self.directory/'tools.lock.json')
        tools['tools']['grype']['version'] = '0.119.0'
        rewrite(self.directory/'tools.lock.json', tools)
        for name in ('debian-security.lock.json', 'console-security.lock.json'):
            lock = load(self.directory/name)
            lock['reviewed_at'] = (old - dt.timedelta(hours=1)).isoformat()
            lock['review_expires_at'] = (old + dt.timedelta(hours=1)).isoformat()
            rewrite(self.directory/name, lock)
        for name in NAMES:
            report = load(self.directory/(name+'.grype.json'))
            report['descriptor']['version'] = '0.119.0'
            report['descriptor']['db']['status'] = database_status(old-dt.timedelta(hours=1))
            rewrite(self.directory/(name+'.grype.json'), report)
        rewrite(self.directory/'database.json', database_status(old-dt.timedelta(hours=1)))
        rewrite(self.directory/'scan-gate.json', {'version':1,'evaluated_at':old.isoformat(),'blocked':[], 'reports':{name:sha(self.directory/(name+'.grype.json')) for name in NAMES}, 'policy_sha256':sha(self.directory/'risk-exceptions.json')})
        (self.directory/'release-manifest.json').unlink(); (self.directory/'provenance.json').unlink()
        with patch('build.now',return_value=old): create_manifest(self.directory, REPO,TAG,COMMIT,'42',{'first_release':True,'previous':None})
        with self.assertRaisesRegex(ValueError, 'UNREVIEWED_TOOL_LOCK'):
            verify_candidate(self.directory, REPO,TAG,COMMIT,NOW)
        with patch('console_assets.run') as crypto, patch('verify.cosign_arguments', return_value=['current-pinned-cosign']), patch('verify.verify_statement'):
            previous = verify_previous(self.directory,Path('/tools'),REPO,TAG,COMMIT)
        self.assertEqual(previous['created_at'],old.isoformat())
        crypto.assert_called_once_with(['current-pinned-cosign'],timeout=60)
        self.assertFalse((self.directory/'deployment-lock.json').exists())
        with self.assertRaisesRegex(ValueError, 'HISTORICAL_RELEASE_TIME_REQUIRED'):
            verify_candidate(self.directory,REPO,TAG,COMMIT,NOW,historical=True)
        for script in ('verify.py','install.py','preflight.py'):
            proc=subprocess.run([sys.executable,str(ROOT/script),'--historical'],capture_output=True)
            self.assertNotEqual(proc.returncode,0)
            self.assertNotIn('historical', subprocess.run([sys.executable,str(ROOT/script),'--help'],capture_output=True,text=True).stdout)
    def test_console_security_patch_inventory_cannot_be_forged_by_npm_coverage(self):
        report = load(self.directory/'console.syft.json')
        report['artifacts'] = [p for p in report['artifacts'] if p['type'] != 'apk']
        rewrite(self.directory/'console.syft.json',report)
        with self.assertRaisesRegex(ValueError,'CONSOLE_SECURITY_UPDATE_MISSING_FROM_SBOM'):
            validate_sboms(self.directory,NOW)
    def test_staged_build_retains_hash_verified_assets_and_nonpublic_lock_inventory(self):
        files=image_files(self.directory/'console');manifest=asset_manifest(files)
        source=ROOT.parent.parent
        stage_context(source,self.directory/'staged',files)
        self.assertEqual((self.directory/'staged/console/release-assets/assets/index-fixture.js').read_bytes(),b'fixture')
        self.assertEqual(len(list((self.directory/'staged/console/release-assets/npm-inventory').glob('*/package-lock.json'))),1)
        self.assertFalse((self.directory/'staged/.local').exists())
        files['usr/share/nginx/html/assets/index-fixture.js']=b'tampered'
        with self.assertRaisesRegex(ValueError,'CONSOLE_ASSET_HASH'):stage_context(source,self.directory/'tampered-stage',files)
    def test_selected_image_links_and_traversal_are_rejected_even_with_valid_blob_hash(self):
        import hashlib
        original=self.directory/'console';idx=load(original/'index.json');m=load(original/'blobs/sha256'/idx['manifests'][0]['digest'][7:])
        for filename,kind in [('usr/share/nginx/html/assets/index-fixture.js','link'),('../outside','path'),('.wh.usr','whiteout')]:
            body=io.BytesIO()
            with tarfile.open(fileobj=body,mode='w') as archive:
                e=tarfile.TarInfo(filename)
                if kind=='link':e.type=tarfile.SYMTYPE;e.linkname='/etc/passwd'
                archive.addfile(e)
            data=body.getvalue();h=hashlib.sha256(data).hexdigest();(original/'blobs/sha256'/h).write_bytes(data)
            m['layers']=[{'mediaType':'application/vnd.oci.image.layer.v1.tar','digest':'sha256:'+h,'size':len(data)}]
            desc=blob(original,m,'application/vnd.oci.image.manifest.v1+json');rewrite(original/'index.json',{'schemaVersion':2,'manifests':[desc]})
            with self.assertRaisesRegex(ValueError,'CONSOLE_LAYER_'):image_files(original)
    def test_downloader_authenticates_small_metadata_before_fetching_candidate_files(self):
        names=release_file_names()|{'release-manifest.json','release-manifest.sigstore.json','provenance.json'}
        release={'draft':False,'tag_name':TAG,'assets':[{'name':n,'size':1} for n in names]}
        def execute(args,**kwargs):
            if args[0]=='cosign':raise ValueError('SIGNATURE_REJECTED')
        with patch('download_previous.github',return_value=release),patch('download_previous.tool',return_value='gh'),patch('download_previous.cosign_arguments',return_value=['cosign']),patch('download_previous.run',side_effect=execute) as runner,patch('download_previous.load') as reader,self.assertRaisesRegex(ValueError,'SIGNATURE_REJECTED'):
            download(self.directory/'download',Path('/tools'),REPO,TAG,COMMIT)
        reader.assert_not_called()
        self.assertEqual(runner.call_count,2)
        first=runner.call_args_list[0].args[0]
        self.assertNotIn('console.oci.tar',first)
        self.assertIn('release-manifest.sigstore.json',first)

    def test_controlled_filename_and_buildargs_have_no_arbitrary_override(self):
        with patch('build.run') as command:
            build_artifact(['buildctl','build'],self.directory,None,self.directory/'test-local',local=True,filename='deploy/console/Dockerfile',buildargs={'SANDBOX_CONSOLE_FIRST_RELEASE':'true'})
            self.assertIn('filename=deploy/console/Dockerfile',command.call_args.args[0])
            self.assertIn('build-arg:SANDBOX_CONSOLE_FIRST_RELEASE=true',command.call_args.args[0])
        for filename,args in [('evil/Dockerfile',{}),('deploy/console/Dockerfile',{}),('deploy/console/Dockerfile',{'ARBITRARY':'true'}),('Dockerfile',{'SANDBOX_CONSOLE_FIRST_RELEASE':'true'})]:
            with self.assertRaises(ValueError):build_artifact([],self.directory,None,self.directory/'unused',local=True,filename=filename,buildargs=args)


if __name__=='__main__':unittest.main()
