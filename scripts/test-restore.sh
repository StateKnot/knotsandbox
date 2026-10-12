#!/usr/bin/env bash
# Reproducible private acceptance: ordinary Cargo, fresh named local PG per case.
# No DROP/FORCE/SQLx ledger fabrication and no cloud apply/delete.
set -euo pipefail
set +x
restore_env_file="${1:-.local/dev.env}"
restore_case="${2:-all}"
if [[ ! -f "$restore_env_file" ]]; then
  echo "Missing private environment file; run scripts/dev-dependencies.sh first." >&2
  exit 2
fi
set -a
source "$restore_env_file"
set +a
export RESTORE_TEST_CASE="$restore_case"
export CARGO_INCREMENTAL=0
python3 - <<'PY'
import datetime,hashlib,json,os,pathlib,re,secrets,stat,subprocess,sys,urllib.parse
root=pathlib.Path.cwd()
if not (root/'Cargo.toml').exists(): raise SystemExit('Run from repository root.')
cases={'start':'restore::tests::signed_available_source_atomic_cross_project_restore_acceptance_and_revocation','delete':'restore::tests::restored_workspace_never_started_delete_preserves_source_and_releases_only_proven_storage','gc':'restore::tests::restored_temporary_storage_gc_then_first_start_keeps_fixed_filesystem_and_source','gc_guards':'restore::tests::restore_gc_direct_results_and_event_wait_cannot_bypass_current_claim','admission':'restore::tests::restore_admission_job_config_pod_current_authority_and_one_shot_creation','gc_admission':'restore::tests::restore_gc_metadata_admission_requires_closed_exact_resources_and_live_claim','control':'restore::tests::restore_historical_control_cleanup_and_job_status_require_exact_recorded_authority','storage_mapping':'restore::tests::restore_storage_mapping_atomic_authority_and_actual_http_drift','raw_parent':'restore::tests::restore_raw_parent_initial_create_pending_uid_and_earlyintent_are_atomic','node_topology':'restore::tests::node_topology::owner_topology_uses_real_enrollment_and_signed_observations_without_mutating_source','raw_selected_node':'restore::tests::node_topology::selected::raw_selected_node_metadata_requires_current_authority_and_live_unassigned_pod','raw_vendor_match':'restore::tests::node_topology::selected::bound_authority::disk_collector::report_matched::registered_expected_report_matches_normal_source14_and_still_refuses_vendor_publication'}
selected=os.environ['RESTORE_TEST_CASE']
if selected not in ('all',*cases): raise SystemExit('Supported cases: all, start, delete, gc, gc_guards, admission, gc_admission, control, storage_mapping, raw_parent, node_topology, raw_selected_node, raw_vendor_match. These are private acceptance, never production activation.')
variables=['TEST_DATABASE_URL','TEST_MIGRATION_DATABASE_URL','TEST_WORKER_DATABASE_URL','TEST_GATEWAY_DATABASE_URL','TEST_ADMISSION_DATABASE_URL','TEST_TERMINATION_DATABASE_URL','TEST_FENCING_DATABASE_URL','TEST_VOLUME_DELETER_DATABASE_URL','TEST_BACKUP_DATABASE_URL','TEST_RESTORE_GC_DATABASE_URL']
for name in variables:
 value=os.environ.get(name)
 if not value: raise SystemExit('Required private environment variable missing: '+name)
 url=urllib.parse.urlsplit(value)
 if url.hostname not in ('127.0.0.1','localhost','::1') or url.scheme not in ('postgres','postgresql'):
  raise SystemExit('Private acceptance requires loopback PostgreSQL: '+name)
evidence_dir=root/'.local/evidence/restore';evidence_dir.mkdir(parents=True,exist_ok=True)
snapshot_nonce=str(int(datetime.datetime.now(datetime.timezone.utc).timestamp()))+f'{secrets.randbelow(10**8):08d}'
snapshot=evidence_dir/f'source-{snapshot_nonce}';snapshot.mkdir()
# Only public Git files, including new untracked source. Ignored caches,
# local credentials and build products never enter an acceptance snapshot.
paths=subprocess.run(['git','ls-files','--cached','--others','--exclude-standard','-z'],check=True,capture_output=True).stdout.split(b'\0')
files=sorted({os.fsdecode(value) for value in paths if value})
manifest=[];digest=hashlib.sha256()
for relative in files:
 path=pathlib.PurePosixPath(relative)
 if path.is_absolute() or '..' in path.parts or path.parts[0] in ('.git','.local') or path.suffix=='.env':
  raise SystemExit('Private/unsafe file must not enter public acceptance source: '+relative)
 source=root/relative;target=snapshot/relative
 fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode): raise SystemExit('Public source must be a regular file: '+relative)
  chunks=[]
  while True:
   chunk=os.read(fd,1024*1024)
   if not chunk: break
   chunks.append(chunk)
  content=b''.join(chunks);expected=hashlib.sha256(content).hexdigest();mode=stat.S_IMODE(before.st_mode)
  target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(content);target.chmod(mode)
  os.lseek(fd,0,os.SEEK_SET);after_hash=hashlib.sha256()
  while True:
   chunk=os.read(fd,1024*1024)
   if not chunk: break
   after_hash.update(chunk)
  after=os.fstat(fd);named=source.lstat()
  if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_mode)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_mode) or (named.st_dev,named.st_ino,named.st_mode)!=(after.st_dev,after.st_ino,after.st_mode) or after_hash.hexdigest()!=expected or hashlib.sha256(target.read_bytes()).hexdigest()!=expected or stat.S_IMODE(target.stat().st_mode)!=mode:
   raise SystemExit('Public source changed while capturing: '+relative)
 finally: os.close(fd)
 manifest.append({'path':relative,'sha256':expected,'mode':format(mode,'04o')})
 digest.update(relative.encode()+b'\0'+mode.to_bytes(4,'big')+bytes.fromhex(expected))
sha=digest.hexdigest()
actual=sorted(p.relative_to(snapshot).as_posix() for p in snapshot.rglob('*') if p.is_file())
if actual!=files: raise SystemExit('Acceptance snapshot has missing or extra source files.')
manifest_path=evidence_dir/f'source-{snapshot_nonce}-manifest.json'
manifest_path.write_text(json.dumps({'source_sha256':sha,'files':manifest,'source_snapshot':str(snapshot.relative_to(root))},indent=2)+'\n')
docker=['docker']
config=os.environ.get('RESTORE_TEST_DOCKER_CONFIG')
if config: docker+=['--config',config]
host=os.environ.get('RESTORE_TEST_DOCKER_HOST')
if host: docker+=['--host',host]
container=os.environ.get('RESTORE_TEST_PG_CONTAINER','sandbox-platform-dev-postgres-1')
for label in (cases if selected=='all' else [selected]):
 nonce=str(int(datetime.datetime.now(datetime.timezone.utc).timestamp()))+f'{secrets.randbelow(10**8):08d}'
 database='sandbox_restore_acceptance_'+nonce+'_test'
 assert re.fullmatch(r'sandbox_restore_acceptance_[0-9]{1,20}_test',database)
 # Validated fresh identifier only. Preserve every prior database.
 subprocess.run(docker+['exec',container,'psql','-X','-v','ON_ERROR_STOP=1','-U','sandbox_dev_admin','-d','postgres','-c',f'CREATE DATABASE "{database}" OWNER sandbox_owner'],check=True,stdout=subprocess.DEVNULL)
 env=os.environ.copy()
 env['CARGO_TARGET_DIR']=str(root/'target')
 for name in variables:
  parsed=urllib.parse.urlsplit(env[name]);env[name]=urllib.parse.urlunsplit(parsed._replace(path='/'+database))
 log=evidence_dir/f'{label}-{nonce}.log'
 record={'database':database,'case':cases[label],'source_sha256':sha,'source_snapshot':str(snapshot.relative_to(root)),'source_manifest':str(manifest_path.relative_to(root)),'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'normal_cargo':True,'production_activation':False,'log':str(log.relative_to(root))}
 with log.open('x') as out:
  out.write(json.dumps(record)+'\n');out.flush()
  result=subprocess.run(['cargo','test','--locked','--offline','--lib',cases[label],'--','--ignored','--exact','--nocapture','--test-threads=1'],cwd=snapshot,env=env,stdout=out,stderr=subprocess.STDOUT)
 record['exit_code']=result.returncode
 with (evidence_dir/'runs.jsonl').open('a') as out:out.write(json.dumps(record)+'\n')
 print(json.dumps(record),flush=True)
 if result.returncode: raise SystemExit(result.returncode)
PY
