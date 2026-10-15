#!/usr/bin/env python3
"""Explicit read-only live prerequisite check; never installs or exchanges cloud credentials."""
import argparse
import hashlib
import http.client
import json
import math
import re
from pathlib import Path
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from observability import decode, load, validate, require, write_private, NODE_IMAGE_SCALARS, NODE_IMAGE_FILESYSTEM_METRICS, NODE_IMAGE_SAMPLE_LIMIT, NODE_IMAGE_MAX_FILESYSTEMS


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


def check_image_status(settings, node, body):
    expected = {'node_name': node['name'], 'node_uid': node['node_uid'],
                'boot_id': node['host_boot_id'], 'cluster_epoch': settings['cluster_epoch'],
                'profile_sha256': node['image_profile_sha256']}
    require(isinstance(body, dict) and body.get('enabled') is True
            and body.get('node') == expected and body.get('source') == 'RUNTIME_REPORTED'
            and body.get('completeness') == 'UNKNOWN', 'NODE_IMAGE_PREREQUISITE_IDENTITY')


def check_image_metrics(settings, node, text):
    """Validate this product's closed exposition, not arbitrary Prometheus text."""
    code='NODE_IMAGE_PREREQUISITE_SERIES'
    expected={'deployment':settings['deployment'],'cluster_epoch':settings['cluster_epoch'],
              'node_uid':node['node_uid'],'host_boot_id':node['host_boot_id'],
              'profile_sha256':node['image_profile_sha256'],'source':'RUNTIME_REPORTED','completeness':'UNKNOWN'}
    require(isinstance(text,str) and text.isascii() and len(text)<=64*1024,code)
    samples={}; filesystems=set()
    for line in text.splitlines():
        if not line or line.startswith('#'):continue
        match=re.fullmatch(r'([a-zA-Z_:][a-zA-Z0-9_:]*)\{([^{}]*)\} ([0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)',line)
        require(match is not None,code)
        name, encoded, number=match.groups()
        require(name in (*NODE_IMAGE_SCALARS,*NODE_IMAGE_FILESYSTEM_METRICS),code)
        labels={}
        for field in encoded.split(','):
            # All current exporter labels have bounded alphabets without quotes,
            # backslashes or commas. Reject unsupported encodings and duplicates.
            pair=re.fullmatch(r'([a-zA-Z_][a-zA-Z0-9_]*)="([^"\\]*)"',field)
            require(pair is not None,code)
            key,value=pair.groups();require(key not in labels,code);labels[key]=value
        filesystem=None
        if name in NODE_IMAGE_FILESYSTEM_METRICS:
            filesystem=labels.pop('filesystem_id',None)
            require(isinstance(filesystem,str) and re.fullmatch(r'[0-9a-f]{64}',filesystem),code)
            filesystems.add(filesystem)
        require(labels==expected,code)
        identity=(name,filesystem)
        require(identity not in samples and math.isfinite(float(number)),code)
        samples[identity]=float(number)
    require(len(samples)<=NODE_IMAGE_SAMPLE_LIMIT and len(filesystems)<=NODE_IMAGE_MAX_FILESYSTEMS,code)
    inventory=samples.get((NODE_IMAGE_SCALARS[0],None))
    filesystem=samples.get((NODE_IMAGE_SCALARS[1],None))
    require(inventory in (0,1) and filesystem in (0,1),code)
    for name in NODE_IMAGE_SCALARS[3:]:
        require(((name,None) in samples)==bool(inventory),code)
    observed=samples.get((NODE_IMAGE_SCALARS[2],None))
    require((observed is not None)==bool(inventory or filesystem),code)
    require(observed is None or observed>0,code)
    require(not filesystems or filesystem==1,code)
    for identity in filesystems:
        require(samples.get((NODE_IMAGE_FILESYSTEM_METRICS[0],identity),0)>0,code)


def node_get(node, ca, cert, key, path, limit):
    context=ssl.create_default_context(cafile=str(ca));context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert),str(key))
    connection=http.client.HTTPConnection(node['private_ip'],9445,timeout=5)
    try:
        connection.sock=context.wrap_socket(socket.create_connection((node['private_ip'],9445),timeout=5),server_hostname=node['node_uid']+'.nodeguard.sandbox.internal')
        connection.request('GET',path,headers={'Host':node['node_uid']+'.nodeguard.sandbox.internal'})
        response=connection.getresponse();body=response.read(limit+1)
        require(response.status==200 and len(body)<=limit,'METRICS_SCRAPE_FAILED')
        return body
    finally:connection.close()


def scrape(settings,node,ca,cert,key):
    def identity(text, expected):
        for line in text.splitlines():
            if not line or line.startswith('#'):continue
            for k,v in expected:
                require(f'{k}="{v}"' in line,'METRICS_IDENTITY')
    expected = [('deployment',settings['deployment']),('cluster_epoch',settings['cluster_epoch']),
                ('node_uid',node['node_uid']),('host_boot_id',node['host_boot_id'])]
    identity(node_get(node,ca,cert,key,'/metrics',2*1024*1024).decode('ascii'), expected)
    if 'image_profile_sha256' in node:
        status=decode(node_get(node,ca,cert,key,'/v1/node-image-status',64*1024))
        check_image_status(settings,node,status)
        text=node_get(node,ca,cert,key,'/metrics/node-images',64*1024).decode('ascii')
        check_image_metrics(settings,node,text)


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
    result={'kind':'observability-private-prerequisites/v1','observed_at':datetime.now(timezone.utc).isoformat(),'settings_sha256':hashlib.sha256(json.dumps(settings,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'node_count':len(settings['nodes']),'private_scrape_verified':True,'node_image_opt_in_count':sum('image_profile_sha256' in n for n in settings['nodes']),'managed_remote_write_verified':False,'persistent_csi_wal_verified':False,'production_acceptance':False}
    write_private(a.output,json.dumps(result,indent=2).encode())
    print('Read-only private prerequisites verified; Managed Prometheus writes and CSI WAL acceptance remain separate.')


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError,UnicodeError,subprocess.SubprocessError,http.client.HTTPException):
        print('OBSERVABILITY_LIVE_PREREQUISITES_REJECTED',file=sys.stderr);sys.exit(1)
