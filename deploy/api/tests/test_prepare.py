import copy
import importlib.util
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from test_render import fixture
spec=importlib.util.spec_from_file_location('api_prepare',ROOT/'prepare.py');preparer=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparer)

def fixture_inputs():
    full=fixture(); settings={key:value for key,value in full.items() if key not in {'deployment','zones','files','output','storage'}}
    settings['database']={key:full['database'][key] for key in ['secret','ca_pem']};settings['storage_enabled']=True;settings['max_file_bytes']=104857600
    outputs={'vpc_id':'vpc-test','deployment_identity':{'cloud_account_id':'1234567890123456','region':'cn-hangzhou','deployment':'sbx-test','environment':'test'},
             'subnets':{},'private_entrances':{},'workload_oidc_provider_arn':'acs:ram::1234567890123456:oidc-provider/sbx-test','workspace_kms_key_id':'test',
             'node_inventory':{f'platform-{index}':{'id':f'i-test-{index}','private_ip':f'10.80.1.{index+10}','role':'platform','zone':full['zones'][index%3]} for index in range(4)},
             'database':{'id':'rds-test','endpoint':'database.example.test','port':5432,'engine':'PostgreSQL','major_version':17},
             'object_storage':{'temporary':{'bucket':full['files']['bucket'],'internal_endpoint':full['files']['endpoint'][8:],'kms_key_id':full['files']['kms_key_id']},
                               'output':{'bucket':full['output']['bucket'],'internal_endpoint':full['output']['bucket']+'.'+full['output']['endpoint'][8:],'kms_key_id':full['output']['kms_key_id']}},
             'workload_roles':full['storage']['workload_roles']}
    return settings,outputs

class ApiPrepare(unittest.TestCase):
    def test_binds_real_output_shape_cloud_identity_and_spare_platform_hosts(self):
        settings,outputs=fixture_inputs(); result=preparer.prepare(settings,outputs)
        self.assertEqual(result,fixture())
        wrapped={key:{'value':value,'sensitive':False,'type':'fixture'} for key,value in outputs.items()}
        self.assertEqual(preparer.prepare(settings,wrapped),result)
    def test_cannot_guess_cloud_or_hide_no_surge_capacity_or_control_nodes(self):
        mutations=[lambda s,o:o['node_inventory'].pop('platform-3'),lambda s,o:o['node_inventory']['platform-3'].update(role='control'),
                   lambda s,o:o['node_inventory']['platform-2'].update(zone='cn-hangzhou-h'),
                   lambda s,o:o['database'].update(engine='MySQL'),lambda s,o:o['object_storage']['temporary'].update(internal_endpoint='evil.example.test'),
                   lambda s,o:s['database'].update(host='guessed.example.test'),lambda s,o:o['deployment_identity'].update(cloud_account_id='9999999999999999')]
        for mutate in mutations:
            settings,outputs=fixture_inputs();mutate(settings,outputs)
            with self.assertRaises((ValueError,KeyError)):preparer.prepare(settings,outputs)
    def test_explicit_bearer_only_no_storage_can_be_prepared_without_cloud_roles(self):
        settings,outputs=fixture_inputs();settings.update(storage_enabled=False,max_file_bytes=None,browser=None,metrics=None)
        outputs['workload_roles']={};outputs['object_storage']={}
        result=preparer.prepare(settings,outputs);self.assertIsNone(result['storage']);self.assertIsNone(result['files']);self.assertIsNone(result['output'])
if __name__=='__main__':unittest.main()
