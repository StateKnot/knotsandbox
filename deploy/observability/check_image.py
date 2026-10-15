#!/usr/bin/env python3
"""Local pinned-image protocol/WAL test. Network disabled; never pulls or publishes an image."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
import yaml
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tests'))
from test_observability import fixture
from test_credentials import tls_fixture
from observability import LOCK,prometheus,require
from fixture_cleanup import fixture_directory


def run(args):
    p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
    if p.returncode:
        # This checker uses only public synthetic inputs, never deployment
        # settings or cloud credentials. Keep failures bounded and diagnosable.
        sys.stderr.buffer.write((p.stdout+p.stderr)[:8192])
    require(p.returncode==0,'PINNED_IMAGE_CHECK_FAILED')
    return p.stdout


def main():
    with fixture_directory('sandbox-metrics-check-', ('wal', 'wal-samples')) as t:
        path=Path(t)
        # Linux bind mounts preserve the root directory's mode. The pinned
        # image's non-root user must traverse this ephemeral fixture directory;
        # credential source-file modes and production Secret modes stay intact.
        path.chmod(0o755)
        tls_fixture(path)
        for d in ('writer','scraper','wal','wal-samples'):(path/d).mkdir(mode=0o777);(path/d).chmod(0o777)
        for name,target in [('username','writer/username'),('password','writer/password'),('client-cert','scraper/tls.crt'),('client-key','scraper/tls.key'),('server-ca','scraper/ca.crt')]:
            (path/target).write_bytes((path/name).read_bytes());(path/target).chmod(0o444)
        s,tf,u=fixture()
        for r in ('a','b'):(path/f'{r}.yaml').write_text(yaml.safe_dump(prometheus(s,r,u)))
        for node in s['nodes']:node['image_profile_sha256']='a'*64
        for r in ('a','b'):(path/f'image-{r}.yaml').write_text(yaml.safe_dump(prometheus(s,r,u)))
        base=['docker','run','--rm','--pull=never','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges']
        binds=['--mount',f'type=bind,src={path},dst=/test,readonly','--mount',f'type=bind,src={path}/writer,dst=/etc/writer,readonly','--mount',f'type=bind,src={path}/scraper,dst=/etc/scraper,readonly']
        run(base+binds+['--entrypoint=/bin/promtool',LOCK['prometheus_image'],'check','config','--agent','/test/a.yaml','/test/b.yaml','/test/image-a.yaml','/test/image-b.yaml'])
        # First start uses the unmodified production-shaped TLS config and an
        # on-disk bind WAL. No mock collector/remote write can be reached.
        def start(config, wal, extra=()):
            name='sandbox-metrics-check-'+uuid.uuid4().hex
            args=base[:2]+['-d','--name',name]+base[2:]+binds+['--mount',f'type=bind,src={path}/{wal},dst=/prometheus',LOCK['prometheus_image'],'--agent','--config.file=/test/'+config,'--storage.agent.path=/prometheus','--storage.agent.wal-compression','--storage.agent.retention.max-time=6h','--storage.remote.flush-deadline=1s','--web.listen-address=127.0.0.1:9090',*extra]
            run(args)
            try:
                ready=False
                for _ in range(50):
                    state=run(['docker','inspect','--format={{.State.Running}}',name]).strip()
                    require(state==b'true','AGENT_START_FAILED')
                    probe=subprocess.run(['docker','exec',name,'/bin/wget','-q','-O','-','http://127.0.0.1:9090/-/ready'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3)
                    if probe.returncode==0:ready=True;break
                    time.sleep(0.1)
                require(ready,'AGENT_NOT_READY')
                if config == 'wal-test.yaml':
                    recorded=False
                    for _ in range(20):
                        metrics=run(['docker','exec',name,'/bin/wget','-q','-O','-','http://127.0.0.1:9090/metrics']).decode()
                        active=next(float(line.split()[1]) for line in metrics.splitlines() if line.startswith('prometheus_agent_active_series '))
                        if active>0:recorded=True;break
                        time.sleep(0.5)
                    require(recorded,'SAMPLE_NOT_SCRAPED')
                else:
                    time.sleep(0.2)
            finally:
                subprocess.run(['docker','stop','--time=5',name],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
                subprocess.run(['docker','rm','-f',name],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        start('a.yaml','wal')
        start('image-a.yaml','wal')
        require(any((path/'wal'/'wal').glob('[0-9]*')),'WAL_NOT_PERSISTED')
        # A separate local-only protocol fixture scrapes this agent's own HTTP
        # counters. It proves sample WAL survives restart, not real node TLS.
        local={'global':{'scrape_interval':'1s'},'scrape_configs':[{'job_name':'offline-wal-test','static_configs':[{'targets':['127.0.0.1:9090']}]}], 'remote_write':[{'url':'http://127.0.0.1:1/write','queue_config':{'max_shards':1}}]}
        (path/'wal-test.yaml').write_text(yaml.safe_dump(local))
        start('wal-test.yaml','wal-samples')
        first={f.name:f.stat().st_size for f in (path/'wal-samples'/'wal').glob('[0-9]*')}
        require(first and sum(first.values())>64,'SAMPLE_WAL_EMPTY')
        start('wal-test.yaml','wal-samples')
        second={f.name:f.stat().st_size for f in (path/'wal-samples'/'wal').glob('[0-9]*')}
        require(all(name in second and second[name]>=size for name,size in first.items()),'WAL_NOT_REPLAYED')
    print('PASS pinned Prometheus: full agent config/TLS-file validation, production-shaped startup, retained sample WAL across restart. Offline protocol only; no Managed Prometheus/CSI/Kata certification.')


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,subprocess.SubprocessError) as error:
        print(f'OBSERVABILITY_IMAGE_CHECK_FAILED: {type(error).__name__}: {error}',file=sys.stderr);sys.exit(1)
