"""Concrete native Kubernetes deployment for the pinned identity proxy."""
import base64
import hashlib
import json
import ssl
from identity import resource, peer, require, kubectl, private_file
from proxy import configuration


def objects(s):
    ns=s['proxy_namespace'];p=s['proxy'];labels=s['proxy_labels']
    volumes=[{'name':'identity-config','configMap':{'name':p['configmap']}},
             {'name':'identity-tls','secret':{'secretName':'identity-proxy-tls','defaultMode':0o440}}]
    container={'name':'haproxy','image':p['image'],'imagePullPolicy':'IfNotPresent',
        'args':['-W','-db','-f','/usr/local/etc/haproxy/haproxy.cfg'],
        'ports':[{'name':'public','containerPort':8443},{'name':'admin','containerPort':9443}],
        'volumeMounts':[{'name':'identity-config','mountPath':'/usr/local/etc/haproxy','readOnly':True},
                        {'name':'identity-tls','mountPath':'/run/identity-tls','readOnly':True}],
        'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},
        'resources':{'requests':{'cpu':'100m','memory':'128Mi'},'limits':{'cpu':'1','memory':'256Mi'}},
        'readinessProbe':{'tcpSocket':{'port':8443},'initialDelaySeconds':1,'periodSeconds':5},
        'livenessProbe':{'tcpSocket':{'port':8443},'initialDelaySeconds':5,'periodSeconds':10}}
    pod={'serviceAccountName':'identity-proxy','automountServiceAccountToken':False,'enableServiceLinks':False,
         'hostNetwork':False,'hostPID':False,'hostIPC':False,'terminationGracePeriodSeconds':60,
         'securityContext':{'runAsNonRoot':True,'runAsUser':10001,'runAsGroup':10001,'fsGroup':10001,
                            'seccompProfile':{'type':'RuntimeDefault'}},
         'nodeSelector':s['platform_node_selector'],
         'affinity':{'nodeAffinity':{'requiredDuringSchedulingIgnoredDuringExecution':{'nodeSelectorTerms':[
             {'matchExpressions':[{'key':'topology.kubernetes.io/zone','operator':'In','values':s['zones']}]}]}},
         'podAntiAffinity':{'requiredDuringSchedulingIgnoredDuringExecution':[
             {'labelSelector':{'matchLabels':labels},'topologyKey':'kubernetes.io/hostname'}]}},
         'topologySpreadConstraints':[{'maxSkew':1,'minDomains':3,'topologyKey':'topology.kubernetes.io/zone',
             'whenUnsatisfiable':'DoNotSchedule','labelSelector':{'matchLabels':labels}}],
         'containers':[container],'volumes':volumes}
    deployment=resource('apps/v1','Deployment',p['deployment'],ns,
        {'replicas':3,'selector':{'matchLabels':labels},'strategy':{'type':'RollingUpdate','rollingUpdate':{'maxUnavailable':1,'maxSurge':1}},
         'template':{'metadata':{'labels':labels},'spec':pod}})
    result=[resource('v1','Namespace',ns,None,metadata={'name':ns,'labels':{'pod-security.kubernetes.io/enforce':'restricted',
            'sandbox.platform/trust':'identity-proxy'}}),
        resource('v1','ServiceAccount','identity-proxy',ns,automountServiceAccountToken=False),
        resource('v1','ConfigMap',p['configmap'],ns,immutable=True,data={'haproxy.cfg':configuration(s)}), deployment,
        resource('policy/v1','PodDisruptionBudget','identity-proxy',ns,{'minAvailable':2,'selector':{'matchLabels':labels}})]
    for name,target in [(p['public_service'],8443),(p['admin_service'],9443)]:
        result.append(resource('v1','Service',name,ns,{'type':'ClusterIP','selector':labels,
            'ports':[{'name':'https','port':443,'targetPort':target,'protocol':'TCP'}]}))
    def ports(values):return [{'port':n,'protocol':'TCP'} for n in values]
    result += [resource('networking.k8s.io/v1','NetworkPolicy','identity-proxy-default-deny',ns,
        {'podSelector':{},'policyTypes':['Ingress','Egress']}),
        resource('networking.k8s.io/v1','NetworkPolicy','identity-proxy-traffic',ns,
            {'podSelector':{'matchLabels':labels},'policyTypes':['Ingress','Egress'],
             'ingress':[{'from':[{'ipBlock':{'cidr':c}} for c in s['public_client_cidrs']], 'ports':ports([8443])},
                        {'from':[{'ipBlock':{'cidr':c}} for c in s['admin_cidrs']], 'ports':ports([9443])}],
             'egress':[{'to':[peer(s['namespace'],{'app':'keycloak','app.kubernetes.io/component':'server'})], 'ports':ports([8443])},
                       {'to':[peer('kube-system',{'k8s-app':'kube-dns'})],
                        'ports':[{'port':53,'protocol':p} for p in ('TCP','UDP')]}]})]
    for obj in result:
        obj['metadata'].setdefault('labels',{})['app.kubernetes.io/managed-by']='sandbox-identity'
    return result


def subset(expected,actual):
    if isinstance(expected,dict):
        return isinstance(actual,dict) and all(k in actual and subset(v,actual[k]) for k,v in expected.items())
    if isinstance(expected,list):
        return isinstance(actual,list) and len(expected)==len(actual) and all(subset(a,b) for a,b in zip(expected,actual))
    return expected==actual


def install(s,material):
    docs=objects(s);ns=s['proxy_namespace']
    # Every existing managed object's supplied fields must match. No force/adoption/update/secret rotation here.
    for obj in docs:
        args=['get',obj['kind'],obj['metadata']['name'],'--ignore-not-found','-o','json']
        if obj['kind']!='Namespace':args += ['-n',ns]
        found=kubectl(args)
        if found:
            current=json.loads(found)
            require(subset(obj,current),'existing proxy object ownership/spec drift; explicit reviewed upgrade required')
        else:
            # Namespace, policy and credentials precede workload creation below.
            if obj['kind']=='Namespace':kubectl(['create','-f','-'],obj)
    cert=material['keycloak-tls']
    data={'frontend.pem':cert['tls.crt']+b'\n'+cert['tls.key'],
          'backend-ca.pem':private_file(s['proxy_backend_ca_file'])}
    ssl.create_default_context(cafile=s['proxy_backend_ca_file'])
    secret=resource('v1','Secret','identity-proxy-tls',ns,type='Opaque',data={k:base64.b64encode(v).decode() for k,v in data.items()})
    secret['metadata']['labels']={'app.kubernetes.io/managed-by':'sandbox-identity'}
    found=kubectl(['get','secret','identity-proxy-tls','-n',ns,'--ignore-not-found','-o','json'])
    if found:require(subset(secret,json.loads(found)),'proxy TLS secret drift; use explicit rotation')
    else:kubectl(['create','-f','-'],secret)
    # Default deny first; Deployment last. TCP readiness deliberately does not depend on Keycloak's existence.
    ordered=sorted((o for o in docs if o['kind']!='Namespace'),key=lambda o: 0 if o['kind']=='NetworkPolicy' else 2 if o['kind']=='Deployment' else 1)
    for obj in ordered:
        found=kubectl(['get',obj['kind'],obj['metadata']['name'],'-n',ns,'--ignore-not-found','-o','json'])
        if not found:kubectl(['create','-f','-'],obj)
    kubectl(['rollout','status','deployment/'+s['proxy']['deployment'],'-n',ns,'--timeout=120s'])
