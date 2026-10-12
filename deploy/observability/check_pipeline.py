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
import tempfile
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

RAW_VALUES = {
    'sandbox_vm_memory_bytes': 4096,
    'sandbox_vm_cpu_throttled_periods_total': 3,
    'sandbox_vm_cpu_throttled_seconds_total': 2.5,
    'sandbox_vm_memory_anon_bytes': 1024,
    'sandbox_vm_memory_file_bytes': 2048,
    'sandbox_vm_memory_oom_events_total': 2,
    'sandbox_vm_memory_oom_kills_total': 0,
}


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
    with tempfile.TemporaryDirectory(prefix='sandbox-prometheus-pipeline-') as tmp:
        path=Path(tmp)
        # The non-root pinned image reads /fixture through a Linux bind mount.
        # Only this ephemeral fixture root becomes traversable; file modes and
        # production credential/container configuration remain unchanged.
        path.chmod(0o755)
        s,tf,url=fixture();pki(path,s['nodes'])
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
            class Handler(BaseHTTPRequestHandler):
                def log_message(self,*args):pass
                def answer(self,status,body=b'',content='text/plain; version=0.0.4; charset=utf-8'):
                    self.send_response(status);self.send_header('Content-Type',content);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
                def do_GET(self):
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
            raw=[];node_up=[];self_up=[];self_metrics=[]
            for replica in ('a','b'):
                for i,node in enumerate(s['nodes']):
                    job='nodeguard-'+node['node_uid']
                    raw.append({**identity('sandbox_vm_memory_bytes',replica),'job':job,'instance':target,'node_uid':node['node_uid'],'host_boot_id':node['host_boot_id'],
                                'tenant_id':str(uuid.UUID(int=101)),'project_id':str(uuid.UUID(int=102)),'instance_id':str(uuid.UUID(int=200+i)),'launch_id':str(uuid.UUID(int=300+i)),'generation':'1'})
                    node_up.append({**identity('up',replica),'job':job,'instance':target,'scrape_node_uid':node['node_uid'],'scrape_host_boot_id':node['host_boot_id']})
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
            wait_series('up',node_up+self_up,1,'UP_IDENTITY_OR_VALUE')
            native='{__name__=~"'+'|'.join(SELF_METRICS)+'"}'
            wait_series(native,self_metrics,None,'SELF_IDENTITY_OR_GUEST_METRIC')
            metrics_fault.set()
            wait_series('up{job=~"nodeguard-.*"}',node_up,0,'FAILED_SCRAPE_UP_NOT_ZERO')
            require(fault_scrapes[0]>0,'NODE_FAILURE_NOT_REACHED')
            wait_series('up{job="sandbox-agent"}',self_up,1,'SELF_FAILED_WITH_NODE')
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
    print('PASS actual local Prometheus agents: mTLS scrape, BasicAuth remote write, 503 retry, separate HA replicas, six pressure metrics with genuine zero and throttle-unit values, strict raw-metric/identity/label filters, native up and raw-series failure/recovery, genuine self counters and guest spoof rejection, collector timestamps. Protocol fixture only, no cloud certification.')


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError,http.client.HTTPException):
        print('OBSERVABILITY_PIPELINE_CHECK_FAILED',file=sys.stderr);sys.exit(1)
