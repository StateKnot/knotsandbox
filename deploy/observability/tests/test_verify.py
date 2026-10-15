import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from verify import check_nodes, check_image_status, check_image_metrics
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


    def test_node_image_prerequisite_binds_opt_in_to_exact_enrolled_profile(self):
        settings, _, _ = fixture()
        node = {**settings['nodes'][0], 'image_profile_sha256': 'a' * 64}
        body = {'enabled': True, 'node': {'node_name': node['name'], 'node_uid': node['node_uid'],
                'boot_id': node['host_boot_id'], 'cluster_epoch': settings['cluster_epoch'],
                'profile_sha256': node['image_profile_sha256']},
                'source': 'RUNTIME_REPORTED', 'completeness': 'UNKNOWN'}
        check_image_status(settings, node, body)
        mutations = [lambda b:b.update(enabled=False), lambda b:b.update(enabled=1),
                     lambda b:b.update(source='MEASURED'), lambda b:b.update(completeness='COMPLETE')]
        for key in body['node']:
            mutations.append(lambda b, key=key:b['node'].update({key: 'foreign'}))
        for mutate in mutations:
            candidate = copy.deepcopy(body); mutate(candidate)
            with self.assertRaisesRegex(ValueError, '^NODE_IMAGE_PREREQUISITE_IDENTITY$'):
                check_image_status(settings, node, candidate)
        for bad in [None, [], {}, {**body, 'node': None}]:
            with self.assertRaisesRegex(ValueError, '^NODE_IMAGE_PREREQUISITE_IDENTITY$'):
                check_image_status(settings, node, bad)

    def test_node_metric_identity_uses_exact_label_keys_not_suffixes(self):
        settings, _, _ = fixture()
        node = {**settings['nodes'][0], 'image_profile_sha256': 'a' * 64}
        labels = {'deployment': settings['deployment'], 'cluster_epoch': settings['cluster_epoch'],
                  'node_uid': node['node_uid'], 'host_boot_id': node['host_boot_id'],
                  'profile_sha256': 'a' * 64, 'source': 'RUNTIME_REPORTED', 'completeness': 'UNKNOWN'}
        def wire(values):
            text=','.join(key+'="'+value+'"' for key,value in values.items())
            return '\n'.join('sandbox_node_image_'+name+'{'+text+'} 0' for name in
                             ('inventory_observation_success','filesystem_observation_success'))+'\n'
        check_image_metrics(settings,node,wire(labels))
        for key in labels:
            wrong=dict(labels);wrong['wrong_'+key]=wrong.pop(key)
            with self.assertRaisesRegex(ValueError, '^NODE_IMAGE_PREREQUISITE_SERIES$'):
                check_image_metrics(settings,node,wire(wrong))
        valid=wire(labels)
        for invalid in [valid+valid,valid.replace('profile_sha256=', 'profile_sha256="'+('a'*64)+'",profile_sha256=',1),
                        valid.replace(' 0',' NaN'),valid+'sandbox_node_image_capacity_bytes{} 0\n',
                        valid+'sandbox_node_image_inventory_count{'+','.join(key+'="'+value+'"' for key,value in labels.items())+'} 0\n']:
            with self.assertRaisesRegex(ValueError, '^NODE_IMAGE_PREREQUISITE_SERIES$'):
                check_image_metrics(settings,node,invalid)


if __name__=='__main__':unittest.main()
