import copy
import configparser
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
from datetime import datetime,timezone,timedelta
import shutil
import yaml

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT.parent/'cluster/tests'))
import nodeguard
import host_profile
import certification
from test_cluster import fixture
from cluster import generate


def settings():
    return {'cluster_epoch':str(uuid.uuid4()),'certification_id':'test-only-certification',
            'binary_file':'/tmp/test-only-binary','binary_sha256':hashlib.sha256(b'test-binary').hexdigest(),
            'nodeguard_server_ca_file':'/tmp/test-only-server-ca','controller_client_ca_file':'/tmp/test-only-controller-ca',
            'nodes':{f'kata-{i}':{'node_uid':str(uuid.uuid4()),'server_certificate_file':f'/tmp/test-only-{i}.crt','server_key_file':f'/tmp/test-only-{i}.key'} for i in range(3)}}


def configs():
    kata={'hypervisor':{'qemu':{'enable_annotations':[],'enable_debug':False,'shared_fs':'virtio-fs','path':'/opt/kata/bin/qemu-system-x86_64','virtio_fs_daemon':'/opt/kata/libexec/virtiofsd'}},'runtime':{'sandbox_cgroup_only':True,'disable_new_netns':False},'factory':{'enable_template':False,'vm_cache_number':0}}
    containerd={'version':4,'disabled_plugins':['io.containerd.monitor.container.v1.restart'],'plugins':{'io.containerd.cri.v1.runtime':{'containerd':{'default_runtime_name':'runc','runtimes':{'runc':{'options':{'SystemdCgroup':True}},'kata-qemu':{'runtime_type':'io.containerd.kata.v2','options':{'ConfigPath':str(host_profile.KATA_CONFIG)}}}}}}}
    kubelet='containerRuntimeEndpoint: unix:///run/sandbox-nodeguard/cri.sock\nimageServiceEndpoint: unix:///run/containerd/containerd.sock\ncgroupDriver: systemd\n'
    return kata,containerd,kubelet


class NodeguardPlanTests(unittest.TestCase):
    def create(self,directory):
        path=Path(directory);tf,cluster_settings=fixture()
        tf['deployment_identity']={'sensitive':False,'value':{'cloud_account_id':'1234567890123456','region':cluster_settings['region'],'deployment':cluster_settings['deployment'],'environment':'preproduction'}}
        (path/'tf.json').write_text(json.dumps(tf));(path/'settings.json').write_text(json.dumps(cluster_settings))
        generate(path/'tf.json',path/'settings.json',path/'bootstrap')
        value=settings();(path/'guard.json').write_text(json.dumps(value))
        return path,value

    def test_offline_plan_changes_only_kata_endpoints_and_preserves_quarantine(self):
        with tempfile.TemporaryDirectory() as directory:
            path,value=self.create(directory)
            result=nodeguard.plan(path/'bootstrap',path/'guard.json',path/'guarded',check_files=False)
            for name,host in result['all']['hosts'].items():
                if name.startswith('kata-'):
                    self.assertEqual(host['cri_socket'],host_profile.RUNTIME_ENDPOINT)
                    self.assertEqual(host['kubelet_config_extra_args']['imageServiceEndpoint'],host_profile.IMAGE_ENDPOINT)
                    self.assertIn('sandbox.platform/unverified=true:NoSchedule',host['node_taints'])
                    self.assertEqual(len(host['containerd_additional_runtimes']),1)
                else:self.assertNotIn('cri_socket',host)
            self.assertFalse(any(p.name.endswith('.key') for p in (path/'guarded').rglob('*')))
            with self.assertRaises(ValueError):nodeguard.plan(path/'bootstrap',path/'guard.json',path/'guarded',check_files=False)

    def test_missing_node_changed_inventory_and_duplicate_uid_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path,value=self.create(directory)
            for mutation in [lambda s:s['nodes'].pop('kata-0'),lambda s:s['nodes']['kata-1'].update(node_uid=s['nodes']['kata-0']['node_uid']),lambda s:s.update(binary_sha256='g'*64),lambda s:s.update(cluster_epoch=str(uuid.UUID(int=0))),lambda s:s.update(skip_verify=True)]:
                changed=copy.deepcopy(value);mutation(changed)
                with self.assertRaises(ValueError):nodeguard.validate_inputs(path/'bootstrap',changed,False)
            with (path/'bootstrap/inventory.yaml').open('a') as stream:stream.write('\n# drift\n')
            with self.assertRaises(ValueError):nodeguard.validate_inputs(path/'bootstrap',value,False)

    def test_bootstrap_inputs_side_file_drift_is_rejected_before_enrollment(self):
        with tempfile.TemporaryDirectory() as directory:
            path, value = self.create(directory)
            inputs = path/'bootstrap/inputs.json'
            changed = json.loads(inputs.read_text())
            changed['settings']['trusted_egress_cidrs'] = ['0.0.0.0/0']
            inputs.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, 'installation file changed after review: inputs.json'):
                nodeguard.validate_inputs(path/'bootstrap', value, False)

    def test_actual_configuration_rejects_bypass_reuse_and_extra_runtime(self):
        kata,containerd,kubelet=configs()
        self.assertEqual(host_profile.validate_configurations(kata,containerd,kubelet)['shared_fs'],'virtio-fs')
        for mutation in [lambda k,c:(k['factory'].update(enable_template=True)),lambda k,c:k['hypervisor']['qemu'].update(enable_annotations=['.*']),lambda k,c:k['runtime'].update(sandbox_cgroup_only=False),lambda k,c:c['plugins']['io.containerd.cri.v1.runtime']['containerd']['runtimes'].update({'kata-alt':{}}),lambda k,c:c.update(version=3),lambda k,c:c.pop('disabled_plugins')]:
            k,c=copy.deepcopy(kata),copy.deepcopy(containerd);mutation(k,c)
            with self.assertRaises(ValueError):host_profile.validate_configurations(k,c,kubelet)
        for altered in [kubelet.replace(host_profile.RUNTIME_ENDPOINT,host_profile.IMAGE_ENDPOINT),kubelet+'containerRuntimeEndpoint: unix:///other.sock\n',kubelet.replace('imageServiceEndpoint','missingEndpoint')]:
            with self.assertRaises(ValueError):host_profile.validate_configurations(kata,containerd,altered)

    def test_host_installation_never_removes_quarantine_or_creates_runtimeclass(self):
        play=yaml.safe_load((ROOT/'install.yaml').read_text())[0]
        serialized=json.dumps(play)
        self.assertNotIn('label nodes',serialized)
        self.assertNotIn('RuntimeClass',serialized)
        commands=[t.get('ansible.builtin.command',{}).get('argv',[]) for t in play['tasks']]
        self.assertIn(['/usr/local/libexec/sandbox-nodeguard','--initialize-journal'],commands)
        self.assertNotIn('PrivateMounts=yes',(ROOT/'sandbox-nodeguard.service').read_text())
        self.assertNotIn('ProtectSystem=',(ROOT/'sandbox-nodeguard.service').read_text())

    def test_service_stop_preserves_the_process_while_durable_work_is_draining(self):
        unit=configparser.ConfigParser(interpolation=None)
        unit.read(ROOT/'sandbox-nodeguard.service')
        service=unit['Service']
        self.assertEqual(service['TimeoutStopSec'],'infinity')
        self.assertEqual(service['KillMode'],'mixed')
        self.assertFalse(service.getboolean('SendSIGKILL'))
        self.assertEqual(service['Restart'],'on-failure')
        self.assertNotIn('ExecStop',service)
        self.assertNotIn('RuntimeMaxSec',service)
        self.assertNotIn('WatchdogSec',service)

    def test_real_certificate_requires_exact_node_san_key_and_private_permissions(self):
        fixtures=ROOT.parents[1]/'tests/fixtures/nodeguard'
        with tempfile.TemporaryDirectory() as directory:
            key=Path(directory)/'server.key';shutil.copyfile(fixtures/'server.key',key);key.chmod(0o600)
            nodeguard.verify_certificate(fixtures/'server.pem',key,fixtures/'server-ca.pem','10000000-0000-4000-8000-000000000001')
            with self.assertRaises(Exception):nodeguard.verify_certificate(fixtures/'server.pem',key,fixtures/'server-ca.pem',str(uuid.uuid4()))
            key.chmod(0o644)
            with self.assertRaises(ValueError):nodeguard.verify_certificate(fixtures/'server.pem',key,fixtures/'server-ca.pem','10000000-0000-4000-8000-000000000001')

    def test_scraper_ca_requires_own_authority_and_cannot_reuse_controller_or_server(self):
        fixtures=ROOT.parents[1]/'tests/fixtures'
        server,control=fixtures/'nodeguard/server-ca.pem',fixtures/'nodeguard/client-ca.pem'
        scraper=fixtures/'admission/apiserver-ca.pem'
        nodeguard.verify_scraper_ca(scraper,server,control)
        for bad in [server,control,fixtures/'admission/apiserver.pem']:
            with self.assertRaises(ValueError):nodeguard.verify_scraper_ca(bad,server,control)
        with tempfile.TemporaryDirectory() as directory:
            combined=Path(directory)/'combined.pem';combined.write_bytes(scraper.read_bytes()+control.read_bytes())
            with self.assertRaises(ValueError):nodeguard.verify_scraper_ca(combined,server,control)

    def test_certification_report_binds_every_check_release_identity_and_node(self):
        now=datetime.now(timezone.utc)
        node={'cluster_epoch':str(uuid.uuid4()),'node_uid':str(uuid.uuid4()),'node_name':'kata-test','boot_id':str(uuid.uuid4()),'profile_sha256':hashlib.sha256(b'profile').hexdigest()}
        report={'protocol':1,'certification_id':'test-evidence','cluster_epoch':node['cluster_epoch'],'versions_lock_sha256':hashlib.sha256(b'versions').hexdigest(),'nodeguard_binary_sha256':hashlib.sha256(b'binary').hexdigest(),'reviewed_at':(now-timedelta(hours=1)).isoformat(),'expires_at':(now+timedelta(days=1)).isoformat(),'nodes':[{'node':node,'cloud_instance_id':'i-test','private_ip':'10.0.1.2'}],'checks':{key:{'status':'PASS','evidence_sha256':hashlib.sha256(key.encode()).hexdigest()} for key in certification.CHECKS}}
        raw=json.dumps(report).encode();config={key:report[key] for key in ['cluster_epoch','certification_id','versions_lock_sha256','nodeguard_binary_sha256']};config['certification_report_sha256']=hashlib.sha256(raw).hexdigest()
        self.assertEqual(certification.validate_report(report,raw,config),report)
        for mutation in [lambda r:r['checks'].pop('cloud_fence_prevents_revival'),lambda r:r['checks']['workspace_single_writer'].update(status='SKIPPED'),lambda r:r.update(expires_at=(now-timedelta(seconds=1)).isoformat()),lambda r:r['nodes'][0].update(private_ip='127.0.0.1'),lambda r:r['nodes'].append(copy.deepcopy(r['nodes'][0]))]:
            changed=copy.deepcopy(report);mutation(changed);data=json.dumps(changed).encode();config_changed={**config,'certification_report_sha256':hashlib.sha256(data).hexdigest()}
            with self.assertRaises(ValueError):certification.validate_report(changed,data,config_changed)
        with self.assertRaises(ValueError):certification.validate_report(report,raw+b' ',config)

    def test_valid_receipt_is_only_consistency_evidence_and_cannot_enable_missing_capability(self):
        import subprocess
        now=datetime.now(timezone.utc)
        node={'cluster_epoch':str(uuid.uuid4()),'node_uid':str(uuid.uuid4()),'node_name':'kata-test','boot_id':str(uuid.uuid4()),'profile_sha256':hashlib.sha256(b'profile').hexdigest()}
        artifact={'protocol':1,'node':node,'cloud_account_id':'1234567890123456','region':'cn-hangzhou','cloud_instance_id':'i-test','private_ip':'10.0.1.2','guard_port':9444,'certification_id':'test-certification'}
        artifact_raw=json.dumps(artifact).encode();tf_raw=b'{"fixture":"not a live terraform verification"}'
        report={'protocol':1,'certification_id':artifact['certification_id'],'cluster_epoch':node['cluster_epoch'],'versions_lock_sha256':hashlib.sha256((ROOT.parent/'cluster/versions.lock.json').read_bytes()).hexdigest(),'nodeguard_binary_sha256':hashlib.sha256(b'binary').hexdigest(),'reviewed_at':(now-timedelta(hours=1)).isoformat(),'expires_at':(now+timedelta(days=1)).isoformat(),'nodes':[{'node':node,'cloud_instance_id':'i-test','private_ip':'10.0.1.2'}],'checks':{key:{'status':'PASS','evidence_sha256':hashlib.sha256(key.encode()).hexdigest()} for key in certification.CHECKS}}
        report_raw=json.dumps(report).encode()
        receipt={**artifact,'enrollment_id':str(uuid.uuid4()),'runtime_node_id':str(uuid.uuid4()),'certification_report_sha256':hashlib.sha256(report_raw).hexdigest(),'artifact_sha256':hashlib.sha256(artifact_raw).hexdigest(),'terraform_output_sha256':hashlib.sha256(tf_raw).hexdigest(),'registered_at':now.isoformat(),'changed':True,'enabled':True}
        certification.validate_receipt(artifact,artifact_raw,receipt,tf_raw,report,report_raw)
        with self.assertRaises(ValueError):certification.validate_receipt(artifact,artifact_raw,{**receipt,'enabled':False},tf_raw,report,report_raw)
        with self.assertRaises(ValueError):certification.validate_receipt(artifact,artifact_raw,receipt,tf_raw+b' ',report,report_raw)
        config={key:report[key] for key in ['cluster_epoch','certification_id','versions_lock_sha256','nodeguard_binary_sha256']};config['certification_report_sha256']=hashlib.sha256(report_raw).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)
            data={'artifact':artifact_raw,'receipt':json.dumps(receipt).encode(),'terraform-output':tf_raw,'cluster-settings':json.dumps(config).encode(),'certification-report':report_raw}
            args=[]
            for name,value in data.items():
                (base/name).write_bytes(value);args.extend(['--'+name,str(base/name)])
            verified=subprocess.run([sys.executable,str(ROOT/'nodeguard.py'),'verify-enrollment',*args],capture_output=True,text=True)
            self.assertEqual(verified.returncode,0,verified.stderr)
            enabled=subprocess.run([sys.executable,str(ROOT/'nodeguard.py'),'enable',*args],capture_output=True,text=True)
            self.assertNotEqual(enabled.returncode,0)
            self.assertIn('release capability unavailable',enabled.stderr)

if __name__=='__main__':unittest.main()
