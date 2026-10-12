"""Fail-closed verification of the platform-owned identity TLS proxy."""
import ipaddress
import json
import ssl
from urllib import request, error
from urllib.parse import urlsplit
from identity import require, kubectl
from proxy import configuration
from verify import NoRedirect


def preflight(s):
    p = s['proxy']
    ns = s['proxy_namespace']
    def get(kind, name):
        return json.loads(kubectl(['get', kind, name, '-n', ns, '-o', 'json']))
    deployment = get('deployment', p['deployment'])
    require(not deployment['metadata'].get('deletionTimestamp'), 'proxy is deleting')
    require(deployment.get('status', {}).get('observedGeneration') == deployment['metadata'].get('generation')
            and deployment.get('status', {}).get('availableReplicas', 0) >= 2, 'proxy requires two observed available replicas')
    podspec = deployment['spec']['template']['spec']
    require(not podspec.get('hostNetwork') and len(podspec['containers']) == 1 and
            podspec['containers'][0]['image'] == p['image'], 'proxy image/host network drift')
    container = podspec['containers'][0]
    require(container.get('args') == ['-W','-db','-f','/usr/local/etc/haproxy/haproxy.cfg'], 'proxy must execute the reviewed config')
    require(not container.get('command') and not container.get('env') and not container.get('envFrom'),
            'unexpected proxy command/environment override')
    require({'name':'identity-config','mountPath':'/usr/local/etc/haproxy','readOnly':True} in container.get('volumeMounts', []),
            'proxy config mount drift')
    require({'name':'identity-config','configMap':{'name':p['configmap']}} in podspec.get('volumes',[]), 'proxy config source drift')
    config = get('configmap', p['configmap'])
    require(config.get('immutable') is True and config.get('data', {}).get('haproxy.cfg') == configuration(s), 'live proxy config differs from generated contract')
    for name, target in [(p['public_service'],8443), (p['admin_service'],9443)]:
        svc = get('service',name)['spec']
        require(svc.get('type','ClusterIP') == 'ClusterIP' and not svc.get('externalIPs') and
                svc.get('selector') == s['proxy_labels'] and len(svc['ports']) == 1 and
                svc['ports'][0]['port'] == 443 and svc['ports'][0]['targetPort'] == target and
                not svc['ports'][0].get('nodePort'), 'identity proxy service exposes an unexpected listener')
    selector = ','.join(f'{k}={v}' for k,v in sorted(s['proxy_labels'].items()))
    pods = json.loads(kubectl(['get','pods','-n',ns,'-l',selector,'-o','json']))['items']
    ready = 0
    for pod in pods:
        require(not pod['metadata'].get('deletionTimestamp') and not pod['spec'].get('hostNetwork'), 'proxy pod identity drift')
        require(pod['spec']['containers'][0]['image'] == p['image'], 'proxy pod image drift')
        ip = ipaddress.ip_address(pod.get('status',{}).get('podIP','0.0.0.0'))
        require(any(ip in ipaddress.ip_network(c) for c in s['proxy_cidrs']), 'proxy source outside trusted range')
        if any(c['type']=='Ready' and c['status']=='True' for c in pod.get('status',{}).get('conditions',[])): ready += 1
    require(ready >= 2, 'two Ready proxy Pods required')


def verify_namespace_roles(s, generated):
    expected = {x['metadata']['name']: (x['roleRef'],x.get('subjects',[]))
                for x in generated['operator.json']['items'] if x['kind']=='RoleBinding'}
    observed = json.loads(kubectl(['get','rolebindings','-n',s['namespace'],'-o','json']))['items']
    for obj in observed:
        require((obj['roleRef'], obj.get('subjects',[])) == expected.get(obj['metadata']['name']),
                'unexpected identity namespace role binding; review namespace administrator access')


def verify_endpoints(s):
    # Explicit CA file: neither no-verify nor insecure/ambient proxy fallbacks are available.
    context = ssl.create_default_context(cafile=s['proxy_ca_file'])
    opener = request.build_opener(request.ProxyHandler({}), request.HTTPSHandler(context=context), NoRedirect())
    def get(url, headers=None):
        try:
            with opener.open(request.Request(url, headers=headers or {}), timeout=10) as response:
                body = response.read(131073)
                require(len(body)<=131072, 'identity metadata too large')
                return response.status, body
        except error.HTTPError as exc:
            return exc.code, b''
    issuer = s['public_url']+'/realms/'+s['realm']
    status, data = get(issuer+'/.well-known/openid-configuration')
    require(status==200, 'public identity discovery unavailable over verified TLS')
    doc = json.loads(data)
    require(doc.get('issuer')==issuer and doc.get('jwks_uri')==issuer+'/protocol/openid-connect/certs', 'issuer/JWKS drift')
    for path in ['/admin/', '/realms/master/.well-known/openid-configuration', '/health',
                 '/realms/'+s['realm']+'/../../admin/', '/realms/'+s['realm']+'/%2e%2e/%2e%2e/admin/']:
        require(get(s['public_url']+path)[0] in (400,403,404), 'public proxy exposed private or ambiguous path')
    require(get(issuer+'/.well-known/openid-configuration', {'Host': urlsplit(s['admin_url']).hostname})[0] in (400,403,404),
            'public listener accepts forged admin Host')
    status, data = get(s['admin_url']+'/realms/master/.well-known/openid-configuration')
    require(status==200, 'private management route unavailable over verified TLS')
    master=json.loads(data); prefix=s['admin_url']+'/realms/master'
    require(master.get('issuer')==prefix and master.get('authorization_endpoint')==prefix+'/protocol/openid-connect/auth'
            and master.get('token_endpoint')==prefix+'/protocol/openid-connect/token'
            and master.get('jwks_uri')==prefix+'/protocol/openid-connect/certs',
            'master login endpoints escape private origin; initialize its native frontendUrl')
