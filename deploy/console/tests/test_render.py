import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('console_renderer',Path(__file__).parents[1]/'render.py')
renderer=importlib.util.module_from_spec(spec);spec.loader.exec_module(renderer)
CA=(Path(__file__).parents[3]/'tests/fixtures/admission/server-ca.pem').read_text()
class ConsoleDeployment(unittest.TestCase):
 def test_security_and_same_origin_proxy(self):
  c=renderer.configuration('https://console.example.com','sandbox-api.sandbox-system.svc.cluster.local:8080')
  self.assertIn("if ($host != 'console.example.com')",c)
  self.assertIn('proxy_next_upstream off',c);self.assertIn('proxy_buffering off',c)
  self.assertIn('client_max_body_size 1m',c);self.assertIn('client_max_body_size 64k',c)
  self.assertIn("frame-ancestors 'none'",c);self.assertIn('ssl_protocols TLSv1.2 TLSv1.3',c)
  self.assertIn('proxy_ssl_verify on',c);self.assertIn('proxy_ssl_trusted_certificate /api-ca/ca.crt',c)
  self.assertIn('proxy_ssl_name sandbox-api.sandbox-system.svc.cluster.local',c)
  self.assertIn('proxy_ssl_server_name on',c);self.assertIn('proxy_ssl_protocols TLSv1.2 TLSv1.3',c)
  self.assertNotIn('proxy_pass http:',c);self.assertNotIn('proxy_ssl_verify off',c)
  self.assertNotIn('$request_uri',c);self.assertNotIn('$args',c);self.assertNotIn('$http_cookie',c)
  self.assertIn('error_log /dev/null',c)
  # Cache policy uses a server-level map; location add_header would drop the
  # inherited security headers on the HTML document and immutable assets.
  self.assertIn('add_header Cache-Control $console_cache always',c)
  for line in c.splitlines():
   if 'location ' in line:self.assertNotIn('add_header',line)
 def test_rejects_external_ambiguous_or_injected_upstream(self):
  for origin in ['http://console.example.com','https://user@console.example.com','https://console.example.com/path','https://console.example.com?return=x','https://console.example.com:8443','https://console.example.com;evil']:
   with self.assertRaises(ValueError):renderer.configuration(origin,'sandbox-api.sandbox-system.svc.cluster.local:8080')
  for api in ['https://upstream.example.com','sandbox-api:80','api.ns.svc.cluster.local:99999','api.ns.svc.cluster.local:8080;evil']:
   with self.assertRaises(ValueError):renderer.configuration('https://console.example.com',api)
 def test_nonroot_replicated_digest_locked_readonly_workload(self):
  x=renderer.manifests('https://console.example.com','sandbox-api.sandbox-system.svc.cluster.local:8443','example.com/console@sha256:'+'a'*64,'sandbox-system','console-tls',CA,['10.80.1.10/32'])
  d=next(i for i in x['items'] if i['kind']=='Deployment');p=d['spec']['template']['spec'];c=p['containers'][0]
  self.assertEqual(d['spec']['replicas'],2);self.assertFalse(p['automountServiceAccountToken']);self.assertEqual(p['securityContext']['runAsUser'],101)
  self.assertTrue(c['securityContext']['readOnlyRootFilesystem']);self.assertFalse(c['securityContext']['allowPrivilegeEscalation'])
  self.assertEqual(c['securityContext']['capabilities']['drop'],['ALL'])
  self.assertEqual(p['nodeSelector'],{'sandbox.platform/node-pool':'platform'})
  for probe in ['readinessProbe','livenessProbe']:
   self.assertEqual(c[probe]['httpGet'],{'scheme':'HTTPS','path':'/health/live','port':'https','httpHeaders':[{'name':'Host','value':'console.example.com'}]})
  bundle=next(i for i in x['items'] if i['kind']=='ConfigMap' and 'ca.crt' in i['data'])
  self.assertTrue(bundle['immutable']);self.assertEqual(bundle['data']['ca.crt'],CA)
  self.assertIn({'name':'api-ca','mountPath':'/api-ca','readOnly':True},c['volumeMounts'])
  with self.assertRaises(ValueError):renderer.manifests('https://console.example.com','sandbox-api.sandbox-system.svc.cluster.local:8443','console:latest','ns','tls',CA)
 def test_requires_bounded_public_ca_without_private_key(self):
  for value in ['', 'invalid', '-----BEGIN PRIVATE KEY-----', CA*17, 'x'*65537]:
   with self.assertRaises(ValueError):renderer.ca_bundle(value)

class ConsolePolicy(unittest.TestCase):
 def test_only_dns_api_and_reviewed_entrypoints_no_world_or_metadata(self):
  x=renderer.manifests('https://console.example.com','sandbox-api.sandbox-system.svc.cluster.local:8443','example.com/console@sha256:'+'a'*64,'sandbox-system','console-tls',CA,[],['ingress-system/ingress-nginx'])
  policy=next(i for i in x['items'] if i['kind']=='CiliumNetworkPolicy')['spec']
  self.assertEqual(len(policy['egress']),2)
  self.assertNotIn('toFQDNs',str(policy));self.assertNotIn('100.100.100.200',str(policy));self.assertNotIn('world',str(policy))
  self.assertEqual(policy['egress'][1]['toPorts'][0]['ports'],[{'port':'8443','protocol':'TCP'}])
  for ns,api,cidrs,proxies in [('other','sandbox-api.sandbox-system.svc.cluster.local:8443',['10.1.1.1/32'],[]),('sandbox-system','sandbox-api.sandbox-system.svc.cluster.local:8080',['10.1.1.1/32'],[]),('sandbox-system','sandbox-api.sandbox-system.svc.cluster.local:8443',['0.0.0.0/0'],[]),('sandbox-system','sandbox-api.sandbox-system.svc.cluster.local:8443',[],[])]:
   with self.assertRaises(ValueError):renderer.manifests('https://console.example.com',api,'example.com/console@sha256:'+'a'*64,ns,'console-tls',CA,cidrs,proxies)

if __name__=='__main__': unittest.main()
