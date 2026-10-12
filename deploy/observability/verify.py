#!/usr/bin/env python3
"""Explicit read-only live prerequisite check; never installs or exchanges cloud credentials."""
import argparse
import hashlib
import http.client
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from observability import decode, load, validate, require, write_private


def kube(context, *args):
    p=subprocess.run(['kubectl','--context',context,'--request-timeout=10s',*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=False)
    require(p.returncode==0 and len(p.stdout)<=8*1024*1024,'KUBERNETES_READ_FAILED')
    return decode(p.stdout)


def check_nodes(settings, tf, nodes, csinodes, cilium):
    require(cilium.get('enable-node-selector-labels')=='true' and cilium.get('policy-default-local-cluster')=='true','CILIUM_NODE_SELECTORS')
    require(not cilium.get('policy-cidr-match-mode'),'UNREVIEWED_CIDR_MATCH_MODE')
    by_name={n['metadata']['name']:n for n in nodes}
    drivers={n['metadata']['name']:{d['name'] for d in n['spec']['drivers']} for n in csinodes}
    expected={n['name']:n for n in settings['nodes']}
    platform_zones=set()
    for name, inventory in tf['node_inventory'].items():
        if inventory['role'] not in ('kata','platform'):continue
        node=by_name.get(name);require(node is not None,'NODE_MISSING')
        labels=node['metadata'].get('labels',{})
        require(labels.get('sandbox.platform/node-pool')==inventory['role'] and labels.get('kubernetes.io/hostname')==name and labels.get('topology.kubernetes.io/zone')==inventory['zone'],'NODE_LABELS')
        require(not node['metadata'].get('deletionTimestamp') and any(c['type']=='Ready' and c['status']=='True' for c in node['status']['conditions']),'NODE_NOT_READY')
        ips={a['address'] for a in node['status']['addresses'] if a['type']=='InternalIP'}
        require(ips=={inventory['private_ip']},'NODE_ADDRESS')
        require('diskplugin.csi.alibabacloud.com' in drivers.get(name,set()),'CSI_NODE_PLUGIN_MISSING')
        if name in expected:
            require(node['metadata']['uid']==expected[name]['node_uid'] and node['status']['nodeInfo']['bootID']==expected[name]['host_boot_id'],'NODE_IDENTITY')
        else:
            require(not node['spec'].get('unschedulable') and labels.get('kubernetes.io/arch')=='amd64','PLATFORM_NOT_SCHEDULABLE')
            require(not any(t.get('effect') in ('NoSchedule','NoExecute') for t in node['spec'].get('taints',[])),'PLATFORM_TAINT')
            platform_zones.add(labels['topology.kubernetes.io/zone'])
    require(len(platform_zones)>=2,'PLATFORM_ZONES')


def scrape(settings,node,ca,cert,key):
    context=ssl.create_default_context(cafile=str(ca));context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert),str(key))
    connection=http.client.HTTPConnection(node['private_ip'],9445,timeout=5)
    connection.sock=context.wrap_socket(socket.create_connection((node['private_ip'],9445),timeout=5),server_hostname=node['node_uid']+'.nodeguard.sandbox.internal')
    try:
        connection.request('GET','/metrics',headers={'Host':node['node_uid']+'.nodeguard.sandbox.internal'})
        response=connection.getresponse();body=response.read(2*1024*1024+1)
        require(response.status==200 and len(body)<=2*1024*1024,'METRICS_SCRAPE_FAILED')
        text=body.decode('ascii')
        for line in text.splitlines():
            if not line or line.startswith('#'):continue
            for k,v in [('deployment',settings['deployment']),('cluster_epoch',settings['cluster_epoch']),('node_uid',node['node_uid']),('host_boot_id',node['host_boot_id'])]:
                require(f'{k}="{v}"' in line,'METRICS_IDENTITY')
    finally:connection.close()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for field in ['settings','terraform-output','remote-write-url-file','context','server-ca','client-cert','client-key','output']:
        p.add_argument('--'+field,required=True)
    a=p.parse_args();settings=decode(load(a.settings));terraform=decode(load(a.terraform_output));remote=load(a.remote_write_url_file,True).decode('ascii').strip();tf=validate(settings,terraform,remote)
    conf=kube(a.context,'config','view','--minify','-o','json')
    cluster=conf['clusters'][0]['cluster'];expected=tf['private_entrances']['kubernetes']
    require(not cluster.get('insecure-skip-tls-verify') and cluster['server']==f"https://{expected['address']}:{expected['port']}",'KUBERNETES_TLS_ENDPOINT')
    nodes=kube(a.context,'get','nodes','-o','json')['items'];csi=kube(a.context,'get','csinodes','-o','json')['items'];cm=kube(a.context,'-n','kube-system','get','configmap','cilium-config','-o','json')['data']
    check_nodes(settings,tf,nodes,csi,cm)
    # No outbound cloud operation: only enrolled private nodeguard endpoints.
    load(a.client_key,True)
    for node in settings['nodes']:scrape(settings,node,a.server_ca,a.client_cert,a.client_key)
    result={'kind':'observability-private-prerequisites/v1','observed_at':datetime.now(timezone.utc).isoformat(),'settings_sha256':hashlib.sha256(json.dumps(settings,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'node_count':len(settings['nodes']),'private_scrape_verified':True,'managed_remote_write_verified':False,'persistent_csi_wal_verified':False,'production_acceptance':False}
    write_private(a.output,json.dumps(result,indent=2).encode())
    print('Read-only private prerequisites verified; Managed Prometheus writes and CSI WAL acceptance remain separate.')


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError,UnicodeError,subprocess.SubprocessError,http.client.HTTPException):
        print('OBSERVABILITY_LIVE_PREREQUISITES_REJECTED',file=sys.stderr);sys.exit(1)
