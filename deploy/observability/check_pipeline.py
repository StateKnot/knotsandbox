#!/usr/bin/env python3
"""Actual local Prometheus→mTLS fixture→remote-write→Prometheus protocol test. No cloud endpoint."""
import base64
from datetime import datetime, timedelta, timezone
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import platform
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tests'))
from test_observability import fixture
from observability import LOCK,SELF_METRICS,prometheus,require
from fixture_cleanup import fixture_directory

RAW_VALUES = {
    'sandbox_vm_cpu_capacity_cores': 0.75,
    'sandbox_vm_memory_capacity_bytes': 268435456,
    'sandbox_vm_memory_bytes': 4096,
    'sandbox_vm_cpu_throttled_periods_total': 3,
    'sandbox_vm_cpu_throttled_seconds_total': 2.5,
    'sandbox_vm_memory_anon_bytes': 1024,
    'sandbox_vm_memory_file_bytes': 2048,
    'sandbox_vm_memory_oom_events_total': 2,
    'sandbox_vm_memory_oom_kills_total': 0,
}
NODE_SCALARS = (
    'sandbox_node_image_inventory_observation_success',
    'sandbox_node_image_filesystem_observation_success',
    'sandbox_node_image_observed_at_seconds',
    'sandbox_node_image_inventory_count',
    'sandbox_node_image_compressed_logical_bytes',
)
NODE_FILESYSTEMS = (
    'sandbox_node_image_filesystem_reported_at_seconds',
    'sandbox_node_image_filesystem_used_bytes',
    'sandbox_node_image_filesystem_inodes_used',
)
NODE_IDENTITY = ('deployment', 'cluster_epoch', 'node_uid', 'host_boot_id',
                 'profile_sha256', 'source', 'completeness')
NODE_REPLICA = (*NODE_IDENTITY, 'collector_replica', 'job', 'instance')
NODE_QUERY_VALUES = (NODE_SCALARS[3], NODE_SCALARS[4], *NODE_FILESYSTEMS[1:])


def selector(metric, labels):
    return metric + '{' + ','.join(key + '=' + json.dumps(value) for key, value in labels.items()) + '}'


def image_identity(settings, node):
    return {'deployment': settings['deployment'], 'cluster_epoch': settings['cluster_epoch'],
            'node_uid': node['node_uid'], 'host_boot_id': node['host_boot_id'],
            'profile_sha256': node['image_profile_sha256'],
            'source': 'RUNTIME_REPORTED', 'completeness': 'UNKNOWN'}


def fresh_report(vector):
    # Both the original report gauge and the retained Prometheus sample must
    # be fresh. A new scrape timestamp cannot refresh an old runtime report.
    return '(' + vector + ' > 0 and ' + vector + ' >= time() - 60 and ' + vector + ' <= time() + 5 and time() - timestamp(' + vector + ') <= 60)'


def node_image_query(settings, metric):
    """Fixed fixture query: filter each HA source before taking its maximum.

    The installation operator API is a separate P0c delivery. This exercises
    actual PromQL semantics on the real receiver, not a substitute query API.
    """
    require(metric in NODE_QUERY_VALUES, 'NODE_IMAGE_QUERY_FIXED_METRIC_REQUIRED')
    filesystem = metric in NODE_FILESYSTEMS
    sources = []
    for node in settings['nodes']:
        if 'image_profile_sha256' not in node:
            continue
        labels = {**image_identity(settings, node), 'job': 'node-images-' + node['node_uid']}
        vector = selector(metric, labels)
        success = selector(NODE_SCALARS[1 if filesystem else 0], labels)
        observed = selector(NODE_SCALARS[2], labels)
        on = ','.join(NODE_REPLICA)
        valid = '(' + vector + ' and on(' + on + ') (' + success + ' == 1) and on(' + on + ') ' + fresh_report(observed)
        if filesystem:
            reported = selector(NODE_FILESYSTEMS[0], labels)
            valid += ' and on(' + on + ',filesystem_id) ' + fresh_report(reported)
        up = selector('up', {'deployment': settings['deployment'], 'cluster_epoch': settings['cluster_epoch'],
                            'job': labels['job'], 'scrape_node_uid': node['node_uid'],
                            'scrape_host_boot_id': node['host_boot_id'],
                            'scrape_profile_sha256': node['image_profile_sha256']})
        valid += ' and on(deployment,cluster_epoch,collector_replica,job,instance) (' + up + ' == 1 and time() - timestamp(' + up + ') <= 60))'
        sources.append(valid)
    require(sources, 'NODE_IMAGE_QUERY_OPT_IN_REQUIRED')
    return 'max without(collector_replica,job,instance) (' + ' or '.join(sources) + ')'


def node_fixture_rows(settings, replica, clock, *, stale=False, unknown=False):
    """Only this public protocol fixture can inject invalid runtime reports."""
    rows = []
    def sample(metric, labels, value):
        # The exposition timestamp is deliberately old; collection timestamps
        # must still be assigned by the real agent (honor_timestamps=false).
        text = ','.join(key + '=' + json.dumps(value) for key, value in labels.items())
        rows.append(metric + '{' + text + '} ' + str(value) + ' 1600000000000')
    for i, node in enumerate(settings['nodes']):
        labels = {**image_identity(settings, node), 'collector_replica': 'rogue',
                  'tenant_id': str(uuid.UUID(int=101)), 'project_id': str(uuid.UUID(int=102)),
                  'instance_id': str(uuid.UUID(int=200 + i)), 'generation': '1',
                  'launch_id': str(uuid.UUID(int=300 + i)), 'secret_label': 'MUST_BE_REMOVED'}
        sample(NODE_SCALARS[0], labels, 0 if unknown else 1)
        sample(NODE_SCALARS[1], labels, 0 if unknown else 1)
        if unknown:
            continue
        stale_replica = stale and i == 1 and replica == 'b'
        sample(NODE_SCALARS[2], labels, clock - 120 if stale_replica else clock)
        sample(NODE_SCALARS[3], labels, 999999 if stale_replica else 7)
        sample(NODE_SCALARS[4], labels, 999999 if stale_replica else 10789)
        fs = {**labels, 'filesystem_id': format(i + 101, '064x')}
        report = clock - 120 if stale and i == 0 else clock - 5
        sample(NODE_FILESYSTEMS[0], fs, report)
        sample(NODE_FILESYSTEMS[1], fs, 999999 if stale_replica else 4096 * (i + 1))
        sample(NODE_FILESYSTEMS[2], fs, 999999 if stale_replica else 3 * (i + 1))
        # Reject mismatched origin identities before remote-write, rather than
        # merely stripping the fields and accepting a poisoned value.
        for key, bad in [('deployment', 'sandbox-other'), ('cluster_epoch', str(uuid.UUID(int=999))),
                         ('node_uid', str(uuid.UUID(int=998))), ('host_boot_id', str(uuid.UUID(int=997))),
                         ('profile_sha256', 'f' * 64), ('source', 'KUBERNETES_API_READBACK'),
                         ('completeness', 'COMPLETE')]:
            invalid = {**labels, key: bad}
            sample(NODE_SCALARS[3], invalid, -424242)
            sample(NODE_FILESYSTEMS[1], {**invalid, 'filesystem_id': fs['filesystem_id']}, -424242)
        for bad in ('', 'not-an-opaque-filesystem', 'A' * 64, 'a' * 63, 'a' * 65):
            sample(NODE_FILESYSTEMS[1], {**labels, 'filesystem_id': bad}, -424242)
        sample('sandbox_node_image_capacity_bytes', labels, -424242)
    return rows


def run(args):
    p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
    require(p.returncode==0,'LOCAL_PIPELINE_COMMAND_FAILED')
    return p.stdout


def pki(path,nodes):
    now=datetime.now(timezone.utc)
    def issue(name,ca=None,key=None,sans=None):
        private=ec.generate_private_key(ec.SECP256R1());subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])
        builder=x509.CertificateBuilder().subject_name(subject).issuer_name(ca.subject if ca else subject).public_key(private.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=ca is None,path_length=None),True)
        if ca:
            builder=builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if sans else ExtendedKeyUsageOID.CLIENT_AUTH]),False)
        if sans:builder=builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]),False)
        cert=builder.sign(key or private,hashes.SHA256())
        (path/(name+'.crt')).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (path/(name+'.key')).write_bytes(private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        return cert,private
    ca,key=issue('server-root');issue('server',ca,key,['host.docker.internal']+[n['node_uid']+'.nodeguard.sandbox.internal' for n in nodes])
    ca,key=issue('scraper-root');issue('client',ca,key)


def main():
    names=[];server=None;thread=None
    with fixture_directory('sandbox-prometheus-pipeline-', ('receiver', 'agent-a', 'agent-b')) as tmp:
        path=Path(tmp)
        # The non-root pinned image reads /fixture through a Linux bind mount.
        # Only this ephemeral fixture root becomes traversable; file modes and
        # production credential/container configuration remain unchanged.
        path.chmod(0o755)
        s,tf,url=fixture()
        for i,node in enumerate(s['nodes']):node['image_profile_sha256']=format(i+1,'064x')
        pki(path,s['nodes'])
        for folder in ['receiver','agent-a','agent-b']:(path/folder).mkdir(mode=0o777);(path/folder).chmod(0o777)
        (path/'receiver.yml').write_text('global:\n  scrape_interval: 15s\nscrape_configs: []\n')
        (path/'username').write_text('offline_writer');(path/'password').write_text('OFFLINE_PROTOCOL_ONLY')
        base=['docker','run','-d','--rm','--pull=never','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges']
        prefix='sandbox-observe-protocol-'+uuid.uuid4().hex[:12]
        receiver=prefix+'-receiver';names.append(receiver)
        try:
            run(base+['--name',receiver,'-p','127.0.0.1::9090','--mount',f'type=bind,src={path},dst=/fixture,readonly','--mount',f'type=bind,src={path}/receiver,dst=/data',LOCK['prometheus_image'],'--config.file=/fixture/receiver.yml','--storage.tsdb.path=/data','--web.enable-remote-write-receiver','--web.listen-address=0.0.0.0:9090','--log.level=error'])
            inspect=json.loads(run(['docker','inspect',receiver]))[0]
            receiver_port=int(inspect['NetworkSettings']['Ports']['9090/tcp'][0]['HostPort'])
            accepted=threading.Event();scrapes=threading.Event();metrics_fault=threading.Event();writes=[0];fault_scrapes=[0]
            image_scrapes=threading.Event();image_fault=threading.Event();image_unknown=threading.Event();image_stale=threading.Event();image_fault_scrapes=[0]
            image_clock=int(time.time())
            class Handler(BaseHTTPRequestHandler):
                def log_message(self,*args):pass
                def answer(self,status,body=b'',content='text/plain; version=0.0.4; charset=utf-8'):
                    self.send_response(status);self.send_header('Content-Type',content);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
                def do_GET(self):
                    request=urllib.parse.urlsplit(self.path)
                    if request.path=='/metrics/node-images':
                        params=urllib.parse.parse_qs(request.query,strict_parsing=True)
                        if set(params)!={'fixture_replica'} or params['fixture_replica'] not in (['a'],['b']):self.answer(400);return
                        if image_fault.is_set():image_fault_scrapes[0]+=1;self.answer(503);return
                        rows=node_fixture_rows(s,params['fixture_replica'][0],image_clock,stale=image_stale.is_set(),unknown=image_unknown.is_set())
                        image_scrapes.set();self.answer(200,('\n'.join(rows)+'\n').encode());return
                    if self.path!='/metrics':self.answer(404);return
                    if metrics_fault.is_set():fault_scrapes[0]+=1;self.answer(503);return
                    rows=[]
                    for i,node in enumerate(s['nodes']):
                        labels={'tenant_id':str(uuid.UUID(int=101)),'project_id':str(uuid.UUID(int=102)),'instance_id':str(uuid.UUID(int=200+i)),'generation':'1','launch_id':str(uuid.UUID(int=300+i)),'cluster_epoch':s['cluster_epoch'],'node_uid':node['node_uid'],'host_boot_id':node['host_boot_id'],'deployment':s['deployment'],'collector_replica':'rogue','secret_label':'MUST_BE_REMOVED'}
                        label_text=','.join(k+'="'+v+'"' for k,v in labels.items())
                        for metric,value in RAW_VALUES.items():
                            rows.append(metric+'{'+label_text+'} '+str(value)+' 1600000000000')
                        rows.append('unapproved_guest_secret{'+label_text+'} 99')
                        spoof=label_text+',job="sandbox-agent"'
                        for metric in ('up',*SELF_METRICS):rows.append(metric+'{'+spoof+'} -424242')
                        # Invalid tenant identity and a stale exporter epoch
                        # must fail before remote-write, for every new metric.
                        bad_tenant={**labels,'tenant_id':str(uuid.UUID(int=0))}
                        bad_tenant_text=','.join(k+'="'+v+'"' for k,v in bad_tenant.items())
                        for metric in RAW_VALUES:rows.append(metric+'{'+bad_tenant_text+'} -424242')
                        labels['cluster_epoch']=str(uuid.UUID(int=999));label_text=','.join(k+'="'+v+'"' for k,v in labels.items())
                        for metric in RAW_VALUES:rows.append(metric+'{'+label_text+'} -424242')
                        rows.append('sandbox_vm_tasks{'+label_text+'} 99')
                    scrapes.set();self.answer(200,('\n'.join(rows)+'\n').encode())
                def do_POST(self):
                    if self.path!='/api/prom_write':self.answer(404);return
                    if self.headers.get('Authorization')!='Basic '+base64.b64encode(b'offline_writer:OFFLINE_PROTOCOL_ONLY').decode():self.answer(401);return
                    n=int(self.headers.get('Content-Length','0'))
                    if not 0<n<8*1024*1024:self.answer(413);return
                    body=self.rfile.read(n);writes[0]+=1
                    if writes[0]<=2:self.answer(503);return
                    connection=http.client.HTTPConnection('127.0.0.1',receiver_port,timeout=5)
                    try:
                        connection.request('POST','/api/v1/write',body,{k:v for k,v in self.headers.items() if k.lower() in ('content-type','content-encoding','x-prometheus-remote-write-version')})
                        response=connection.getresponse();data=response.read(1024*1024)
                        if response.status//100==2:accepted.set()
                        self.answer(response.status,data)
                    finally:connection.close()
            server=ThreadingHTTPServer(('0.0.0.0',0),Handler)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(path/'server.crt',path/'server.key');context.verify_mode=ssl.CERT_REQUIRED;context.load_verify_locations(path/'scraper-root.crt');server.socket=context.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            for replica in ('a','b'):
                config=prometheus(s,replica,url)
                for job in config['scrape_configs']:
                    job['scrape_interval']='1s'
                    job['scrape_timeout']='1s'
                    if job['job_name'].startswith('nodeguard-'):
                        job['static_configs'][0]['targets']=[f'host.docker.internal:{server.server_port}'];job['scrape_timeout']='1s'
                        job['tls_config'].update(ca_file='/fixture/server-root.crt',cert_file='/fixture/client.crt',key_file='/fixture/client.key')
                    elif job['job_name'].startswith('node-images-'):
                        require(job['metrics_path']=='/metrics/node-images' and 'params' not in job,'NODE_IMAGE_FIXED_PATH_CHANGED')
                        job['static_configs'][0]['targets']=[f'host.docker.internal:{server.server_port}']
                        job['params']={'fixture_replica':[replica]}
                        job['tls_config'].update(ca_file='/fixture/server-root.crt',cert_file='/fixture/client.crt',key_file='/fixture/client.key')
                    else:
                        require(job['job_name']=='sandbox-agent' and job['static_configs']==[{'targets':['127.0.0.1:9090']}] and 'tls_config' not in job and 'basic_auth' not in job,'SELF_TARGET_CHANGED')
                writer=config['remote_write'][0];writer['url']=f'https://host.docker.internal:{server.server_port}/api/prom_write';writer['basic_auth']={'username_file':'/fixture/username','password_file':'/fixture/password'}
                writer['tls_config'].update(ca_file='/fixture/server-root.crt',cert_file='/fixture/client.crt',key_file='/fixture/client.key');writer['queue_config']['batch_send_deadline']='1s'
                (path/(replica+'.yaml')).write_text(yaml.safe_dump(config))
                name=prefix+'-'+replica;names.append(name)
                host_args=['--add-host=host.docker.internal:host-gateway'] if platform.system()=='Linux' else []
                run(base+host_args+['--name',name,'--mount',f'type=bind,src={path},dst=/fixture,readonly','--mount',f'type=bind,src={path}/agent-{replica},dst=/data',LOCK['prometheus_image'],'--agent','--config.file=/fixture/'+replica+'.yaml','--storage.agent.path=/data','--storage.remote.flush-deadline=1s','--log.level=error'])
            def query(expr):
                c=http.client.HTTPConnection('127.0.0.1',receiver_port,timeout=3)
                try:
                    c.request('GET','/api/v1/query?'+urllib.parse.urlencode({'query':expr}));r=c.getresponse();b=r.read(1024*1024);require(r.status==200,'RECEIVER_QUERY');return json.loads(b)['data']['result']
                finally:c.close()
            target=f'host.docker.internal:{server.server_port}'
            def identity(metric,replica):
                return {'__name__':metric,'deployment':s['deployment'],'cluster_epoch':s['cluster_epoch'],'collector_replica':replica}
            raw=[];node_up=[];image_up=[];image_raw={metric:[] for metric in (*NODE_SCALARS,*NODE_FILESYSTEMS)};self_up=[];self_metrics=[]
            for replica in ('a','b'):
                for i,node in enumerate(s['nodes']):
                    job='nodeguard-'+node['node_uid']
                    raw.append({**identity('sandbox_vm_memory_bytes',replica),'job':job,'instance':target,'node_uid':node['node_uid'],'host_boot_id':node['host_boot_id'],
                                'tenant_id':str(uuid.UUID(int=101)),'project_id':str(uuid.UUID(int=102)),'instance_id':str(uuid.UUID(int=200+i)),'launch_id':str(uuid.UUID(int=300+i)),'generation':'1'})
                    node_up.append({**identity('up',replica),'job':job,'instance':target,'scrape_node_uid':node['node_uid'],'scrape_host_boot_id':node['host_boot_id']})
                    image_up.append({**identity('up',replica),'job':'node-images-'+node['node_uid'],'instance':target,'scrape_node_uid':node['node_uid'],'scrape_host_boot_id':node['host_boot_id'],'scrape_profile_sha256':node['image_profile_sha256']})
                    for metric in (*NODE_SCALARS,*NODE_FILESYSTEMS):
                        labels={**image_identity(s,node),'__name__':metric,'collector_replica':replica,'job':'node-images-'+node['node_uid'],'instance':target}
                        if metric in NODE_FILESYSTEMS:labels['filesystem_id']=format(i+101,'064x')
                        image_raw[metric].append(labels)
                self_up.append({**identity('up',replica),'job':'sandbox-agent','instance':'127.0.0.1:9090'})
                for metric in SELF_METRICS:self_metrics.append({**identity(metric,replica),'job':'sandbox-agent','instance':'127.0.0.1:9090'})
            def labelset(rows):return {tuple(sorted(row.items())) for row in rows}
            def matches(rows,expected,value=None):
                return len(rows)==len(expected) and labelset([r['metric'] for r in rows])==labelset(expected) and all(float(r['value'][1])>=0 if value is None else float(r['value'][1])==value for r in rows)
            raw_sets={metric:[{**row,'__name__':metric} for row in raw] for metric in RAW_VALUES}
            deadline=time.monotonic()+35
            def wait_series(expr,expected,value,code):
                while time.monotonic()<deadline:
                    rows=query(expr)
                    if matches(rows,expected,value):
                        require(time.monotonic()<deadline,code);return rows
                    time.sleep(0.25)
                require(False,code)
            def wait_values(expr,expected,values,code):
                required={tuple(sorted(labels.items())):float(value) for labels,value in zip(expected,values,strict=True)}
                while time.monotonic()<deadline:
                    rows=query(expr)
                    if matches(rows,expected) and all(float(row['value'][1])==required[tuple(sorted(row['metric'].items()))] for row in rows):
                        require(time.monotonic()<deadline,code);return rows
                    time.sleep(0.25)
                require(False,code)
            def image_value(metric,row,stale=False):
                index=next(i for i,node in enumerate(s['nodes']) if node['node_uid']==row['node_uid'])
                bad=stale and index==1 and row.get('collector_replica')=='b'
                return {NODE_SCALARS[0]:1,NODE_SCALARS[1]:1,NODE_SCALARS[2]:image_clock-120 if bad else image_clock,
                        NODE_SCALARS[3]:999999 if bad else 7,NODE_SCALARS[4]:999999 if bad else 10789,
                        NODE_FILESYSTEMS[0]:image_clock-120 if stale and index==0 else image_clock-5,
                        NODE_FILESYSTEMS[1]:999999 if bad else 4096*(index+1),NODE_FILESYSTEMS[2]:999999 if bad else 3*(index+1)}[metric]
            def wait_image_raw(stale=False):
                for metric,expected in image_raw.items():
                    wait_values(metric,expected,[image_value(metric,row,stale) for row in expected],'NODE_IMAGE_RAW_IDENTITY_VALUE_OR_FILTER')
            def wait_image_queries(stale=False,empty=False):
                for metric in NODE_QUERY_VALUES:
                    expected=[]
                    for i,node in enumerate(s['nodes']):
                        if empty or stale and metric in NODE_FILESYSTEMS and i==0:continue
                        row=image_identity(s,node)
                        if metric in NODE_FILESYSTEMS:row['filesystem_id']=format(i+101,'064x')
                        expected.append(row)
                    wait_values(node_image_query(s,metric),expected,[image_value(metric,row) for row in expected],'NODE_IMAGE_FILTER_BEFORE_HA_MAX')
            result=wait_series('sandbox_vm_memory_bytes',raw,4096,'RAW_IDENTITY_OR_VALUE')
            require(len(result)==4 and scrapes.is_set() and accepted.is_set() and writes[0]>2,'PIPELINE_INCOMPLETE')
            require({r['metric']['collector_replica'] for r in result}=={'a','b'},'HA_REPLICA_DROPPED')
            require(all(float(r['value'][1])==4096 and 'secret_label' not in r['metric'] and 'exported_collector_replica' not in r['metric'] for r in result),'METRIC_LABEL_OR_VALUE')
            for metric,value in RAW_VALUES.items():
                rows=wait_series(metric,raw_sets[metric],value,'PRESSURE_IDENTITY_OR_VALUE')
                require(len(rows)==4 and {r['metric']['collector_replica'] for r in rows}=={'a','b'},'PRESSURE_HA_REPLICA_DROPPED')
                require(all('secret_label' not in r['metric'] and 'exported_collector_replica' not in r['metric'] for r in rows),'PRESSURE_PRIVATE_LABEL_WRITTEN')
            require(query('unapproved_guest_secret')==[] and query('sandbox_vm_tasks')==[],'UNAPPROVED_DATA_WRITTEN')
            observed=query('timestamp(sandbox_vm_memory_bytes)');require(len(observed)==4 and all(time.time()-float(r['value'][1])<15 for r in observed),'SOURCE_TIMESTAMP_OVERRIDE')
            wait_series('up',node_up+image_up+self_up,1,'UP_IDENTITY_OR_VALUE')
            native='{__name__=~"'+'|'.join(SELF_METRICS)+'"}'
            wait_series(native,self_metrics,None,'SELF_IDENTITY_OR_GUEST_METRIC')

            # Node samples have no VM identity. They traverse the same actual
            # authenticated remote writer while retaining independent jobs,
            # origins and HA labels; no synthetic node data enters the VM job.
            wait_image_raw()
            require(image_scrapes.is_set(),'NODE_IMAGE_ENDPOINT_NOT_SCRAPED')
            require(query('sandbox_node_image_capacity_bytes')==[],'NODE_IMAGE_UNMEASURED_CAPACITY_WRITTEN')
            require(query('{__name__=~"sandbox_node_image_.*"} < 0')==[],'NODE_IMAGE_INVALID_ORIGIN_WRITTEN')
            wait_image_queries()
            # Every raw series retains both agents, while the filtered query
            # returns each node/FS exactly once rather than summing replicas.
            image_stale.set()
            wait_image_raw(stale=True)
            fresh_scrape=query('timestamp('+NODE_SCALARS[2]+')')
            require(len(fresh_scrape)==4 and all(time.time()-float(row['value'][1])<15 for row in fresh_scrape),'NODE_IMAGE_SCRAPE_TIMESTAMP_NOT_FRESH')
            reported=query(NODE_FILESYSTEMS[0]+'{node_uid="'+s['nodes'][0]['node_uid']+'"}')
            require(len(reported)==2 and all(float(row['value'][1])==image_clock-120 for row in reported),'NODE_IMAGE_ORIGINAL_REPORT_TIME_CHANGED')
            # node 0 has a stale FS report under a fresh collector observation.
            # node 1's replica b has stale observed_at but a fresh FS report and
            # a poisonous larger value; max-before-filter would pick it.
            wait_image_queries(stale=True)

            image_unknown.set()
            for metric in NODE_SCALARS[:2]:wait_series(metric,image_raw[metric],0,'NODE_IMAGE_UNKNOWN_MUST_KEEP_ZERO_SUCCESS')
            for metric in (*NODE_SCALARS[2:],*NODE_FILESYSTEMS):wait_series(metric,[],None,'NODE_IMAGE_UNKNOWN_RETAINED_OR_ZERO_FILLED_VALUE')
            wait_image_queries(empty=True)
            wait_series('up{job=~"node-images-.*"}',image_up,1,'NODE_IMAGE_UNKNOWN_IS_NOT_HTTP_FAILURE')
            wait_series('sandbox_vm_memory_bytes',raw,4096,'NODE_IMAGE_UNKNOWN_BROKE_VM_USAGE')
            image_stale.clear();image_unknown.clear()
            wait_image_raw();wait_image_queries()

            image_fault.set()
            wait_series('up{job=~"node-images-.*"}',image_up,0,'NODE_IMAGE_HTTP_FAILURE_NOT_WRITTEN')
            require(image_fault_scrapes[0]>0,'NODE_IMAGE_HTTP_FAILURE_NOT_REACHED')
            for metric in (*NODE_SCALARS,*NODE_FILESYSTEMS):wait_series(metric,[],None,'NODE_IMAGE_FAILED_SCRAPE_RETAINED_VALUE')
            wait_image_queries(empty=True)
            wait_series('sandbox_vm_memory_bytes',raw,4096,'NODE_IMAGE_HTTP_FAILURE_BROKE_VM_USAGE')
            wait_series('up{job="sandbox-agent"}',self_up,1,'NODE_IMAGE_HTTP_FAILURE_BROKE_SELF_SCRAPE')
            image_fault.clear()
            wait_series('up{job=~"node-images-.*"}',image_up,1,'NODE_IMAGE_HTTP_RECOVERY_NOT_WRITTEN')
            wait_image_raw();wait_image_queries()

            metrics_fault.set()
            wait_series('up{job=~"nodeguard-.*"}',node_up,0,'FAILED_SCRAPE_UP_NOT_ZERO')
            require(fault_scrapes[0]>0,'NODE_FAILURE_NOT_REACHED')
            wait_series('up{job="sandbox-agent"}',self_up,1,'SELF_FAILED_WITH_NODE')
            wait_image_queries()
            # Failed scrapes remove instant samples, preserving genuine raw
            # history (including a real zero OOM-kill counter, never zero-fill).
            for metric,value in RAW_VALUES.items():
                wait_series(metric,[],None,'FAILED_SCRAPE_RETAINED_INSTANT_USAGE')
                held=query('last_over_time('+metric+'[1m])')
                require(len(held)==4 and labelset([{k:v for k,v in r['metric'].items() if k!='__name__'} for r in held])==labelset([{k:v for k,v in r.items() if k!='__name__'} for r in raw_sets[metric]]) and all(float(r['value'][1])==value for r in held),'FAILED_SCRAPE_FABRICATED_USAGE')
                if value!=0:require(query(metric+' == 0')==[],'FAILED_SCRAPE_FABRICATED_ZERO')
            metrics_fault.clear()
            wait_series('up{job=~"nodeguard-.*"}',node_up,1,'SCRAPE_RECOVERY_NOT_WRITTEN')
            for metric,value in RAW_VALUES.items():
                wait_series(metric,raw_sets[metric],value,'RAW_RECOVERY_CHANGED_IDENTITY_OR_VALUE')
            wait_series(native,self_metrics,None,'SELF_AFTER_RECOVERY_CHANGED')
        finally:
            for name in reversed(names):
                subprocess.run(['docker','stop','--time=3',name],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
                subprocess.run(['docker','rm','-f',name],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
            if server:server.shutdown();server.server_close()
            if thread:thread.join(timeout=5)
    print('PASS actual local Prometheus agents: mTLS scrape, BasicAuth remote write, 503 retry, separate HA replicas, six pressure metrics with genuine zero and throttle-unit values, strict raw-metric/identity/label filters, native up and raw-series failure/recovery, genuine self counters and guest spoof rejection, collector timestamps; independent node-image jobs, original report freshness before HA max, exact origin/FS/label rejection, UNKNOWN without zero-filled quantities, node/VM independent failure and recovery. Protocol fixture only, no native-containerd whole-chain, operator or cloud certification.')


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError,http.client.HTTPException):
        print('OBSERVABILITY_PIPELINE_CHECK_FAILED',file=sys.stderr);sys.exit(1)
