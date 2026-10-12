import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from test_render import fixture,renderer
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('api_policy_boundary',ROOT.parent/'policy_boundary.py');gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
sys.path.insert(0,str(ROOT.parent/'cluster'))
spec=importlib.util.spec_from_file_location('api_bootstrap_policies',ROOT.parent/'cluster/render.py');cluster=importlib.util.module_from_spec(spec);spec.loader.exec_module(cluster)

class ActualComponentBoundary(unittest.TestCase):
 def check(self,objects,bootstrap):
  deployment=next(v for v in objects if v['kind']=='Deployment');policy=next(v for v in objects if v['kind']=='CiliumNetworkPolicy')
  desired=deployment['spec']['template']
  return gate.analyze(policy,'sandbox-system',{},desired['metadata']['labels'],desired['spec']['serviceAccountName'],[{'items':[policy,*bootstrap]}], endpoint_labels={**{'k8s:'+k:v for k,v in desired['metadata']['labels'].items()},'k8s:io.kubernetes.pod.namespace':'sandbox-system','k8s:io.cilium.k8s.policy.serviceaccount':desired['spec']['serviceAccountName'],'k8s:io.cilium.k8s.policy.cluster':'default'})
 def test_api_and_console_excluded_from_current_broad_bootstrap(self):
  bootstrap=cluster.policies({'node_inventory':{'node':{'private_ip':'10.80.1.10'}}},{'enterprise_cidrs':['10.1.0.0/24'],'trusted_egress_cidrs':['10.80.0.0/16'],'service_cidr':'10.96.0.0/12'})
  api=renderer.render(fixture())['items']
  spec=importlib.util.spec_from_file_location('api_test_console',ROOT.parent/'console/render.py');console=importlib.util.module_from_spec(spec);spec.loader.exec_module(console)
  browser=console.manifests('https://console.example.test','sandbox-api.sandbox-system.svc.cluster.local:8443','registry.example.test/console@sha256:'+'a'*64,'sandbox-system','console-tls',fixture()['tls']['ca_pem'],['10.80.1.10/32'])['items']
  for objects in [api,browser]:
   report=self.check(objects,bootstrap);self.assertEqual(report['configuration_overlap'],'PASS');self.assertEqual(report['runtime_enforcement'],'NOT_VERIFIED')
   old=copy.deepcopy(bootstrap)
   old[0]['spec']['endpointSelector']['matchExpressions']=[rule for rule in old[0]['spec']['endpointSelector']['matchExpressions'] if rule['key']!='k8s:sandbox.platform/network-policy']
   with self.assertRaises(gate.BoundaryError):self.check(objects,old)
if __name__=='__main__':unittest.main()
