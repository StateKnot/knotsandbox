import copy
import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup
import deploy


def fixture():
    now = dt.datetime.now(dt.timezone.utc)
    job = {k: str(uuid.uuid4()) for k in ('tenant_id', 'project_id', 'backup_id', 'source_instance_id', 'source_pvc_uid', 'snapshot_content_uid', 'clone_pvc_uid', 'seal_attempt_id', 'cluster_epoch')}
    job.update({'protocol': 1, 'source_generation': 2, 'size_bytes': 20 * 1024**3,
        'data_timestamp': (now - dt.timedelta(minutes=2)).isoformat(), 'consistency': 'CRASH_CONSISTENT',
        'retention_until': (now + dt.timedelta(days=31)).isoformat(), 'key_ref': 'kms:backup-repo:version-1',
        'region': 'cn-hangzhou', 'account_id': '1234567890123456', 'bucket': 'fixture-backup', 'vault_bucket': 'fixture-backup-vault',
        'kms_key_id': 'fixture-repo-key', 'vault_kms_key_id': 'fixture-vault-key', 'issuer': 'https://oidc.fixture.invalid',
        'oidc_provider_arn': 'acs:ram::1234567890123456:oidc-provider/fixture',
        'roles': {r: {'arn': 'acs:ram::1234567890123456:role/fixture-' + r, 'subject': 'system:serviceaccount:sandbox-system:sandbox-' + r}
                  for r in ('backup', 'backup-export', 'restore')},
        'deadline': (now + dt.timedelta(hours=1)).isoformat(), 'template_digest': 'sha256:' + 'a' * 64,
        'runtime_certification_sha256': 'b' * 64})
    settings = json.loads((Path(__file__).resolve().parents[1] / 'settings.example.json').read_text())
    settings['image'] = 'registry.fixture.invalid/sandbox/backup@sha256:' + 'c' * 64
    settings['certification_report_sha256'] = 'b' * 64
    return settings, job


class Deployment(unittest.TestCase):
    def test_python_renderer_matches_shared_rust_golden_contract(self):
        fixture = json.loads((Path(__file__).with_name('manifest-fixture.json')).read_text())
        for stage in ('capture', 'seal', 'restore'):
            values = deploy.resources(fixture['settings'], fixture['job'], stage, fixture['volume'], fixture['expected_manifest'],
                attempt_id=fixture['attempt_id'], cluster_epoch=fixture['cluster_epoch'], deadline_seconds=fixture['deadline_seconds'])
            self.assertEqual(values, fixture['objects'][stage])

    def test_strict_config_and_no_generic_cloud_endpoint(self):
        settings, job = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.json'
            path.write_text(json.dumps(job))
            self.assertEqual(backup.config(path), job)
            for field, value in [('bucket', 'https://evil.invalid'), ('region', 'localhost:8080'),
                                 ('size_bytes', 513), ('deadline', '2000-01-01T00:00:00Z')]:
                altered = {**job, field: value}
                path.write_text(json.dumps(altered))
                with self.assertRaises(ValueError):
                    backup.config(path)

    def test_three_stage_credentials_and_devices_are_separate(self):
        settings, job = fixture()
        for stage in ('capture', 'seal', 'restore'):
            values = deploy.resources(settings, job, stage, 'derived-only', 'd' * 64, attempt_id=str(uuid.uuid4()), cluster_epoch=str(uuid.uuid4()))
            spec = values[-1]['spec']
            self.assertTrue(spec['suspend'])
            self.assertEqual(spec['backoffLimit'], 0)
            pod = spec['template']['spec']
            self.assertEqual(pod['runtimeClassName'], 'kata-backup-qemu')
            self.assertFalse(pod['automountServiceAccountToken'])
            self.assertFalse(pod['hostNetwork'])
            container = pod['containers'][0]
            self.assertEqual(container['securityContext']['capabilities']['drop'], ['ALL'])
            secrets = [x['secret']['secretName'] for x in pod['volumes'] if 'secret' in x]
            self.assertEqual('volumeDevices' in container, stage != 'seal')
            self.assertEqual(settings['secrets']['signing_private'] in secrets, stage == 'seal')
            self.assertNotIn('hostPath', str(pod))
            if stage == 'capture':
                volume = next(v for v in pod['volumes'] if v['name'] == 'data')
                self.assertTrue(volume['persistentVolumeClaim']['readOnly'])

    def test_session_policy_exact_prefix_and_roles(self):
        _, job = fixture()
        for role in ('backup', 'backup-export', 'restore'):
            policy = backup.session_policy(job, role)
            text = json.dumps(policy)
            self.assertNotIn('oss:*', text.replace('acs:oss:*:*:', ''))
            self.assertIn(job['backup_id'], text)
            if role != 'backup':
                self.assertNotIn('oss:DeleteObject', text)
            if role == 'restore':
                self.assertNotIn('oss:PutObject', text)
                self.assertNotIn('kms:GenerateDataKey', text)

    def test_raw_clone_foreign_snapshot_and_mode_drift_rejected(self):
        settings, c = fixture()
        source = {'metadata': {'uid': c['source_pvc_uid'], 'name': 'source', 'namespace': 'tenant'}, 'spec': {}}
        source_pv = {'metadata': {}, 'spec': {'claimRef': {'uid': c['source_pvc_uid']}, 'csi': {'volumeHandle': 'd-original'}}}
        content = {'metadata': {'uid': c['snapshot_content_uid'], 'annotations': {'snapshot.storage.kubernetes.io/allow-volume-mode-change': 'true'}},
            'spec': {'driver': 'diskplugin.csi.alibabacloud.com', 'sourceVolumeMode': 'Filesystem', 'volumeSnapshotRef': {'name': 'delegated', 'namespace': 'sandbox-system'}},
            'status': {'readyToUse': True}}
        clone = {'metadata': {'uid': c['clone_pvc_uid'], 'namespace': 'sandbox-system'},
            'spec': {'volumeMode': 'Block', 'storageClassName': settings['storage_class'], 'dataSource': {'apiGroup': 'snapshot.storage.k8s.io', 'kind': 'VolumeSnapshot', 'name': 'delegated'}}, 'status': {'phase': 'Bound'}}
        pv = {'metadata': {}, 'spec': {'claimRef': {'uid': c['clone_pvc_uid']}, 'volumeMode': 'Block',
            'csi': {'driver': 'diskplugin.csi.alibabacloud.com', 'volumeHandle': 'd-clone'}, 'persistentVolumeReclaimPolicy': 'Retain'}}
        runtime = {'metadata': {'name': 'kata-backup-qemu'}, 'handler': 'kata-qemu'}
        values = [source, source_pv, content, clone, pv, runtime]
        deploy.verify_storage(settings, c, *values)
        for index, path, wrong in [(2, ('metadata', 'annotations'), {}), (3, ('spec', 'volumeMode'), 'Filesystem'),
                                    (3, ('metadata', 'uid'), str(uuid.uuid4())), (4, ('spec', 'persistentVolumeReclaimPolicy'), 'Delete'),
                                    (4, ('spec', 'csi', 'volumeHandle'), 'd-original'), (5, ('handler',), 'runc')]:
            altered = copy.deepcopy(values)
            cursor = altered[index]
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] = wrong
            with self.assertRaises(ValueError):
                deploy.verify_storage(settings, c, *altered)

    def test_restore_needs_only_new_target_and_rejects_reused_source(self):
        s, _ = fixture()
        pvc_uid, pv_uid = str(uuid.uuid4()), str(uuid.uuid4())
        pvc = {'metadata': {'uid': pvc_uid, 'name': 'new-target', 'namespace': 'sandbox-system'},
               'spec': {'volumeMode': 'Block', 'storageClassName': s['storage_class']}, 'status': {'phase': 'Bound'}}
        pv = {'metadata': {'uid': pv_uid}, 'spec': {'volumeMode': 'Block', 'persistentVolumeReclaimPolicy': 'Retain',
              'claimRef': {'uid': pvc_uid, 'name': 'new-target', 'namespace': 'sandbox-system'},
              'csi': {'driver': 'diskplugin.csi.alibabacloud.com', 'volumeHandle': 'd-new'}}}
        runtime = {'metadata': {'name': s['runtime_class']}, 'handler': 'kata-qemu'}
        deploy.verify_restore_storage(s, pvc, pv, runtime, pvc_uid, pv_uid, 'd-new')
        with self.assertRaises(ValueError):
            deploy.verify_restore_storage(s, pvc, pv, runtime, pvc_uid, pv_uid, 'd-other')
        pvc['spec']['dataSource'] = {'kind': 'VolumeSnapshot', 'name': 'old-source'}
        with self.assertRaises(ValueError):
            deploy.verify_restore_storage(s, pvc, pv, runtime, pvc_uid, pv_uid, 'd-new')


if __name__ == '__main__':
    unittest.main()
