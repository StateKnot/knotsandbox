import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
import unittest
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import controller
import profile as backup_profile
from backup import canonical
from test_reader_credentials import settings as reader


def fixture():
    r = reader()
    r['role_arn'] = 'acs:ram::1234567890123456:role/sandbox-backup-reader'
    return {'protocol': 1, 'deployment': 'sandbox', 'controller_image': 'registry.fixture.invalid/platform@sha256:' + 'a'*64,
            'backup_image': 'registry.fixture.invalid/backup@sha256:' + 'b'*64,
            'database_secret': 'backup-database', 'database_ca_secret': 'database-ca',
            'nodeguard_server_ca_secret': 'nodeguard-ca', 'nodeguard_client_identity_secret': 'backup-nodeguard-client',
            'signing_public_secret': 'sbx-bkey-public', 'password_secret': 'sbx-bkey-password', 'signing_private_secret': 'sbx-bkey-private', 'vault': {'endpoint': 'https://oss-cn-hangzhou-internal.aliyuncs.com', 'bucket': r['vault_bucket'], 'region': r['region'], 'account_id': r['account_id']},
            'reader': r, 'concurrency': 2, 'projects': ['project-fixture'],
            'clone_storage_class': 'sandbox-backup-retain', 'snapshot_class': 'sandbox-snapshot-retain', 'clone_kms_key_id': 'clone-kms',
            'job_controller': {'kind': 'control_plane', 'username': 'system:kube-controller-manager'}}


def terraform_fixture():
    c = fixture()
    r = c['reader']
    values = {
        'deployment_identity': {'deployment': c['deployment'], 'cloud_account_id': r['account_id'], 'region': r['region']},
        'workspace_kms_key_id': c['clone_kms_key_id'],
        'workload_roles': {'backup-reader': {'subject': 'system:serviceaccount:sandbox-system:sandbox-backup-controller', 'audience': 'sts.aliyuncs.com', 'issuer': r['issuer'], 'arn': r['role_arn']}},
        'object_storage': {'backup-vault': {'bucket': r['vault_bucket'], 'kms_key_id': r['vault_kms_key_id']}},
        'workload_oidc_provider_arn': r['oidc_provider_arn'],
    }
    return {k: {'value': v, 'sensitive': False, 'type': 'fixture'} for k, v in values.items()}


def profile_fixture():
    now = dt.datetime.now(dt.timezone.utc)
    cloud = {'deployment': 'fixture', 'signing_key_sha256': 'a'*64, 'vault_endpoint': 'https://oss-cn-hangzhou-internal.aliyuncs.com', 'clone_kms_key_id': 'clone-kms', 'vault_retention_days': 31,
             'key_ref': 'vault/password/v1', 'region': 'cn-hangzhou', 'account_id': '1234567890123456', 'bucket': 'fixture-source', 'vault_bucket': 'fixture-vault', 'kms_key_id': 'source-kms', 'vault_kms_key_id': 'vault-kms', 'issuer': 'https://issuer.fixture.invalid',
             'oidc_provider_arn': 'acs:ram::1234567890123456:oidc-provider/fixture', 'roles': {r: {'arn': 'acs:ram::1234567890123456:role/fixture-'+r, 'subject': 'system:serviceaccount:sandbox-system:sandbox-'+r} for r in ['backup', 'backup-export', 'restore']}}
    p = {'protocol': 1, 'profile_id': str(uuid.uuid4()), 'cluster_epoch': str(uuid.uuid4()), 'enabled': False, 'certification_report_sha256': '0'*64,
         'certified_until': (now+dt.timedelta(days=1)).isoformat(), 'image': fixture()['backup_image'], 'snapshot_class': 'sandbox-snapshot-retain', 'clone_storage_class': 'sandbox-backup-retain', 'password_secret': 'sbx-bkey-password', 'signing_private_secret': 'sbx-bkey-private', 'signing_public_secret': 'sbx-bkey-public', 'settings': cloud}
    cloud['secret_bindings'] = {purpose: {'name':p[field], 'uid':str(uuid.uuid4()), 'content_sha256':'c'*64} for purpose,field in [('password','password_secret'),('signing_private','signing_private_secret'),('signing_public','signing_public_secret')]}
    binding = {k: p.get(k, cloud.get(k)) for k in backup_profile.BINDINGS}
    binding['versions_lock_sha256'] = hashlib.sha256(Path(backup_profile.__file__).with_name('versions.lock.json').read_bytes()).hexdigest()
    binding['profile_spec_sha256'] = hashlib.sha256(canonical({k: v for k, v in p.items() if k != 'certification_report_sha256'})).hexdigest()
    report = {'protocol': 1, 'bindings': binding, 'reviewed_at': now.isoformat(), 'expires_at': p['certified_until'], 'checks': {k: {'result': 'PASS', 'evidence_sha256': 'b'*64, 'observed_at': now.isoformat()} for k in backup_profile.CHECKS}}
    raw = canonical(report);p['certification_report_sha256'] = hashlib.sha256(raw).hexdigest()
    return p, raw


class Controller(unittest.TestCase):
    def test_real_role_command_and_credential_mount_separation(self):
        values = controller.resources(fixture())
        spec = next(x for x in values if x['kind']=='Deployment')['spec']['template']['spec']
        app, reader_sidecar = spec['containers']
        identities = [v for v in app['env'] if v['name'] == 'SANDBOX_PROCESS_POD_UID']
        self.assertEqual(identities, [{'name': 'SANDBOX_PROCESS_POD_UID', 'valueFrom': {'fieldRef': {'apiVersion': 'v1', 'fieldPath': 'metadata.uid'}}}])
        for auxiliary in [reader_sidecar, *spec['initContainers']]:
            self.assertNotIn('SANDBOX_PROCESS_POD_UID', {v['name'] for v in auxiliary.get('env', [])})
        self.assertEqual(app['args'], ['--role', 'backup'])
        self.assertEqual(spec['securityContext']['runAsUser'], 10001)
        self.assertFalse(spec['automountServiceAccountToken'])
        self.assertEqual(spec['initContainers'][0]['args'][-1], '--once')
        self.assertEqual(spec['initContainers'][0]['image'], reader_sidecar['image'])
        self.assertNotIn('reader-oidc', {m['name'] for m in app['volumeMounts']})
        self.assertNotIn('kube-api', {m['name'] for m in reader_sidecar['volumeMounts']})
        credentials = next(m for m in app['volumeMounts'] if m['name']=='reader-credentials')
        self.assertTrue(credentials['readOnly'])
        roles = [x for x in values if x['kind'] in ('Role','ClusterRole')]
        for role in roles:
            for rule in role['rules']:
                self.assertNotIn('*', rule['verbs'])
                if 'secrets' in rule['resources'] and rule['verbs'] == ['get']:
                    self.assertEqual(role['kind'], 'Role')
                    self.assertEqual(set(rule['resourceNames']), {'sbx-bkey-password','sbx-bkey-private','sbx-bkey-public'})
                elif 'secrets' in rule['resources']:
                    self.assertEqual(rule['verbs'], ['create'])
                    self.assertEqual(role['metadata']['name'], 'sandbox-backup-key-install')
                self.assertNotIn('pods/exec', rule['resources'])
                self.assertFalse('delete' in rule['verbs'] and 'persistentvolumeclaims' in rule['resources'])
        sc = next(x for x in values if x['kind']=='StorageClass')
        self.assertEqual(sc['parameters'], {'type':'cloud_essd','encrypted':'true','kmsKeyId':'clone-kms','diskTags/Deployment':'sandbox'})
        self.assertEqual(sc['reclaimPolicy'], 'Retain')
        snapshot = next(x for x in values if x['kind']=='VolumeSnapshotClass')
        self.assertEqual(snapshot['parameters'], {'snapshotTags/Deployment':'sandbox'})
    def test_terraform_binding_rejects_wrong_kms_tag_account_region_and_reader_before_install(self):
        c, tf = fixture(), terraform_fixture()
        self.assertEqual(controller.validate_infrastructure(c, tf), c)
        cases = [('workspace_kms_key_id', None, 'ungranted-key'),
                 ('deployment_identity', 'deployment', 'foreign-deployment'),
                 ('deployment_identity', 'region', 'cn-beijing'),
                 ('deployment_identity', 'cloud_account_id', '1234567890123457'),
                 ('workload_oidc_provider_arn', None, 'acs:ram::1234567890123456:oidc-provider/other')]
        from unittest.mock import patch
        for field, nested, value in cases:
            changed = copy.deepcopy(tf)
            if nested:
                changed[field]['value'][nested] = value
            else:
                changed[field]['value'] = value
            with self.subTest(field=field, nested=nested), patch.object(controller, 'kubectl') as command:
                with self.assertRaises(ValueError):controller.install(c, changed)
                command.assert_not_called()
        for invalid in ({k:v['value'] for k,v in tf.items()}, tf | {'unexpected': {'value':'secret','sensitive':True}}):
            with self.assertRaises(ValueError):controller.validate_infrastructure(c, invalid)
    def test_webhook_rules_added_without_mutating_other_contract(self):
        base={'kind':'ValidatingWebhookConfiguration','metadata':{'name':'sandbox-runtime-protection'},'webhooks':[{'name':'runtime.sandbox.platform','failurePolicy':'Fail','clientConfig':{'caBundle':'fixture','service':{'namespace':'sandbox-system','name':'sandbox-admission','path':'/validate','port':443}},'rules':[]} ]}
        result=controller.hook_with_backup(base)
        self.assertEqual(len(result['webhooks'][0]['rules']),5)
        self.assertEqual(base['webhooks'][0]['rules'],[])
        self.assertEqual(controller.hook_with_backup(result),result)
        for key,value in [('failurePolicy','Ignore'),('namespaceSelector',{'matchLabels':{'skip':'true'}}),('objectSelector',{'matchLabels':{'backup':'true'}}),('matchConditions',[{'name':'bypass','expression':'false'}])]:
            changed=copy.deepcopy(base);changed['webhooks'][0][key]=value
            with self.assertRaises(ValueError):controller.hook_with_backup(changed)
    def test_invalid_identity_images_and_cloud_config_rejected(self):
        for field,value in [('deployment',''),('deployment','Bad Tag'),('clone_storage_class','sandbox-workspace'),('controller_image','example:latest'),('backup_image','example:latest'),('concurrency',0),('job_controller',{'kind':'control_plane','username':'system:masters'}),('projects',['kube-system'])]:
            with self.assertRaises(ValueError):controller.resources(fixture()|{field:value})
    def test_static_profile_never_claims_live_or_enabled(self):
        p,raw=profile_fixture();result=backup_profile.validate(p,raw)
        self.assertFalse(result['registration_enabled']);self.assertFalse(result['live_activation_verified'])
        with self.assertRaises(ValueError):backup_profile.validate(p|{'enabled':True},raw)
    def test_full_profile_binding_rejects_report_reuse(self):
        p,raw=profile_fixture()
        for key,value in [('password_secret','other-secret'),('clone_storage_class','other-class')]:
            with self.assertRaises(ValueError):backup_profile.validate(p|{key:value},raw)
        for key,value in [('deployment','other-installation'),('issuer','https://other.invalid'),('key_ref','another/key')]:
            changed=copy.deepcopy(p);changed['settings'][key]=value
            with self.assertRaises(ValueError):backup_profile.validate(changed,raw)
        changed=copy.deepcopy(p);changed['settings']['vault_retention_days']=30
        with self.assertRaises(ValueError):backup_profile.validate(changed,raw)
        old=copy.deepcopy(p);del old['settings']['deployment']
        with self.assertRaises(ValueError):backup_profile.validate(old,raw)
