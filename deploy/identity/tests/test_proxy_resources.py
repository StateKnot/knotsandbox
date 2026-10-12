import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import proxy_resources
from test_identity import fixture

class ProxyResourcesTests(unittest.TestCase):
    def test_complete_proxy_deployment_is_nonroot_tls_only_and_three_az(self):
        docs=proxy_resources.objects(fixture())
        self.assertEqual(len(docs),9)
        d=next(x for x in docs if x['kind']=='Deployment')
        self.assertEqual(d['spec']['replicas'],3)
        pod=d['spec']['template']['spec']
        self.assertFalse(pod['automountServiceAccountToken'])
        self.assertFalse(pod['hostNetwork'])
        self.assertTrue(pod['securityContext']['runAsNonRoot'])
        self.assertTrue(pod['containers'][0]['securityContext']['readOnlyRootFilesystem'])
        self.assertEqual(pod['containers'][0]['securityContext']['capabilities']['drop'],['ALL'])
        self.assertEqual(pod['containers'][0]['readinessProbe']['tcpSocket']['port'],8443)
        self.assertEqual(pod['topologySpreadConstraints'][0]['minDomains'],3)
        self.assertTrue(next(x for x in docs if x['kind']=='ConfigMap')['immutable'])
        admin=next(x for x in docs if x['kind']=='Service' and x['metadata']['name']=='identity-admin')
        self.assertEqual(admin['spec']['type'],'ClusterIP')
        traffic=next(x for x in docs if x['kind']=='NetworkPolicy' and x['metadata']['name']=='identity-proxy-traffic')
        self.assertNotIn('0.0.0.0/0',json.dumps(traffic['spec']['ingress'][1]))

    def test_existing_objects_are_not_adopted_or_overwritten(self):
        s=fixture();d=next(x for x in proxy_resources.objects(s) if x['kind']=='Deployment')
        for mutate in [lambda x:x['metadata']['labels'].update({'app.kubernetes.io/managed-by':'other'}),
                       lambda x:x['spec']['template']['spec']['containers'][0].update(image='haproxy:latest'),
                       lambda x:x['spec']['template']['spec'].update(automountServiceAccountToken=True)]:
            current=copy.deepcopy(d);mutate(current);calls=[]
            def kubectl(args,payload=None):
                calls.append((args,payload))
                return json.dumps(current).encode() if args[:3]==['get','Deployment','identity-proxy'] else b''
            with patch.object(proxy_resources,'kubectl',side_effect=kubectl),self.assertRaises(ValueError):
                proxy_resources.install(s,{'keycloak-tls':{'tls.crt':b'cert','tls.key':b'key'}})
            self.assertFalse(any(payload and payload.get('kind')=='Deployment' for _,payload in calls))

    def test_default_deny_secret_and_config_precede_deployment_and_no_apply(self):
        calls=[]
        def kubectl(args,payload=None):calls.append((args,payload));return b''
        with patch.object(proxy_resources,'kubectl',side_effect=kubectl),patch.object(proxy_resources,'private_file',return_value=b'ca'),patch('ssl.create_default_context'):
            proxy_resources.install(fixture(),{'keycloak-tls':{'tls.crt':b'cert','tls.key':b'key'}})
        kinds=[payload['kind'] for _,payload in calls if payload]
        self.assertLess(kinds.index('NetworkPolicy'),kinds.index('Deployment'))
        self.assertLess(kinds.index('Secret'),kinds.index('Deployment'))
        self.assertLess(kinds.index('ConfigMap'),kinds.index('Deployment'))
        self.assertFalse(any(args[0]=='apply' for args,_ in calls))

if __name__=='__main__':unittest.main()
