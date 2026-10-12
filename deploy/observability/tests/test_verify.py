import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from verify import check_nodes
from test_observability import fixture
from observability import validate


def live_fixture():
    s,tf,u=fixture();v=validate(s,tf,u);bound={n['name']:n for n in s['nodes']};nodes=[];csi=[]
    for name,n in v['node_inventory'].items():
        identity=bound.get(name,{'node_uid':'unused-platform-id','host_boot_id':'unused-platform-boot'})
        nodes.append({'metadata':{'name':name,'uid':identity['node_uid'],'labels':{'kubernetes.io/hostname':name,'sandbox.platform/node-pool':n['role'],'topology.kubernetes.io/zone':n['zone'],'kubernetes.io/arch':'amd64'}},'spec':{},'status':{'nodeInfo':{'bootID':identity['host_boot_id']},'addresses':[{'type':'InternalIP','address':n['private_ip']}],'conditions':[{'type':'Ready','status':'True'}]}})
        csi.append({'metadata':{'name':name},'spec':{'drivers':[{'name':'diskplugin.csi.alibabacloud.com'}]}})
    cm={'enable-node-selector-labels':'true','policy-default-local-cluster':'true'}
    return s,v,nodes,csi,cm


class VerifyTest(unittest.TestCase):
    def test_current_nodes_and_persistent_storage_prerequisites(self):
        check_nodes(*live_fixture())
        for mutate in [lambda a:a[2][0]['metadata'].update(uid='foreign'),lambda a:a[2][0]['status']['nodeInfo'].update(bootID='foreign'),lambda a:a[2][0]['status']['conditions'][0].update(status='False'),lambda a:a[3].pop(),lambda a:a[4].update({'enable-node-selector-labels':'false'}),lambda a:a[4].update({'policy-cidr-match-mode':'nodes'}),lambda a:a[2][-1]['spec'].update(taints=[{'effect':'NoSchedule'}])]:
            args=list(copy.deepcopy(live_fixture()));mutate(args)
            with self.assertRaises(ValueError):check_nodes(*args)


if __name__=='__main__':unittest.main()
