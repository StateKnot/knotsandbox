import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import identity
import ingress
import proxy
from test_identity import fixture


def live_fixture():
    s = fixture(); p = s['proxy']
    pod = {'containers':[{'name':'haproxy','image':p['image'],
        'args':['-W','-db','-f','/usr/local/etc/haproxy/haproxy.cfg'],
        'volumeMounts':[{'name':'identity-config','mountPath':'/usr/local/etc/haproxy','readOnly':True}]}],
        'volumes':[{'name':'identity-config','configMap':{'name':p['configmap']}}]}
    objs = {
        'deployment': {'metadata':{'generation':1}, 'status':{'observedGeneration':1,'availableReplicas':2},
                       'spec':{'template':{'spec':pod}}},
        'configmap': {'immutable':True,'data':{'haproxy.cfg':proxy.configuration(s)}},
        'pods': {'items':[{'metadata':{}, 'spec':copy.deepcopy(pod),
                 'status':{'podIP':ip,'conditions':[{'type':'Ready','status':'True'}]}}
                 for ip in ('10.32.4.10','10.32.4.11')]},
        p['public_service']: {'spec':{'type':'ClusterIP','selector':s['proxy_labels'],
                                    'ports':[{'port':443,'targetPort':8443}]}},
        p['admin_service']: {'spec':{'type':'ClusterIP','selector':s['proxy_labels'],
                                   'ports':[{'port':443,'targetPort':9443}]}}}
    return s,objs


class IngressTests(unittest.TestCase):
    def test_preflight_uses_live_config_pods_and_separate_internal_services(self):
        s,objs=live_fixture()
        def kubectl(args): return json.dumps(objs[args[2] if args[1]=='service' else args[1]]).encode()
        with patch.object(ingress,'kubectl',side_effect=kubectl): ingress.preflight(s)

    def test_preflight_rejects_proxy_drift_before_install(self):
        changes = [lambda o:o['deployment']['spec']['template']['spec'].update(hostNetwork=True),
                   lambda o:o['deployment']['status'].update(availableReplicas=1),
                   lambda o:o['configmap']['data'].update({'haproxy.cfg':'frontend public\n bind :80'}),
                   lambda o:o['configmap'].update(immutable=False),
                   lambda o:o['pods']['items'][0]['status'].update(podIP='10.99.1.2'),
                   lambda o:o['identity-admin']['spec'].update(type='LoadBalancer'),
                   lambda o:o['identity-admin']['spec']['ports'][0].update(targetPort=8443),
                   lambda o:o['deployment']['spec']['template']['spec']['containers'][0].update(command=['sh','-c','other'])]
        for change in changes:
            s,objs=live_fixture();change(objs)
            def kubectl(args): return json.dumps(objs[args[2] if args[1]=='service' else args[1]]).encode()
            with patch.object(ingress,'kubectl',side_effect=kubectl), self.assertRaises(ValueError): ingress.preflight(s)

    def test_unknown_namespace_subject_is_rejected(self):
        s=fixture();generated=identity.render(s)
        roles=[x for x in generated['operator.json']['items'] if x['kind']=='RoleBinding']
        with patch.object(ingress,'kubectl',return_value=json.dumps({'items':roles}).encode()):
            ingress.verify_namespace_roles(s,generated)
        bad=copy.deepcopy(roles);bad[0]['subjects'][0]['namespace']='tenant-project'
        with patch.object(ingress,'kubectl',return_value=json.dumps({'items':bad}).encode()), self.assertRaises(ValueError):
            ingress.verify_namespace_roles(s,generated)

    def test_real_certificate_san_key_and_validity_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            def generate(stem, host):
                subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','8',
                    '-subj','/CN='+host,'-addext','subjectAltName=DNS:'+host+',DNS:identity-admin.internal.example.com',
                    '-keyout',str(root/(stem+'.key')),'-out',str(root/(stem+'.crt'))],check=True,capture_output=True)
                for ext in ('.key','.crt'): (root/(stem+ext)).chmod(0o600)
            generate('good','login.example.com');generate('bad','other.example.com')
            s=fixture()
            for name,files in s['secret_files'].items():
                for key in files:
                    path=root/(name+'-'+key)
                    path.write_text('keycloak_prod' if name=='keycloak-db' and key=='username' else
                                    'initial-operator' if key=='username' else 'x'*32)
                    path.chmod(0o600);files[key]=str(path)
            s['secret_files']['keycloak-tls']={'tls.crt':str(root/'good.crt'),'tls.key':str(root/'good.key')}
            s['secret_files']['keycloak-trust']={'rds.pem':str(root/'good.crt')}
            identity.validate_secret_material(s)
            s['secret_files']['keycloak-tls']['tls.key']=str(root/'bad.key')
            with self.assertRaises(ValueError):identity.validate_secret_material(s)
            s['secret_files']['keycloak-tls']={'tls.crt':str(root/'bad.crt'),'tls.key':str(root/'bad.key')}
            with self.assertRaises(ValueError):identity.validate_secret_material(s)


if __name__=='__main__':unittest.main()
