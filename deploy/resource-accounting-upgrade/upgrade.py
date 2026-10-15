#!/usr/bin/env python3
"""Fail-closed resource-accounting maintenance upgrade; explicit cluster only."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import parse_qs, unquote, urlsplit
import uuid

DENIED = 'SANDBOX_RESOURCE_UPGRADE_IMAGE_DENIED'
CLOSED = 'SANDBOX_RESOURCE_UPGRADE_MAINTENANCE'
OWNER = 'sandbox-resource-accounting-upgrade'
ROLES = ['sandbox_app', 'sandbox_worker', 'sandbox_gateway', 'sandbox_admission',
         'sandbox_termination', 'sandbox_fencing', 'sandbox_volume_deleter',
         'sandbox_backup', 'sandbox_automation']
WRITER_ACCOUNTS = ['sandbox-api', 'sandbox-worker', 'sandbox-gateway', 'sandbox-admission',
                   'sandbox-termination', 'sandbox-fencing', 'sandbox-volume-deleter',
                   'sandbox-backup-controller', 'sandbox-automation']
IMAGE = re.compile(r'[a-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9/_-]+@sha256:[a-f0-9]{64}\Z')
NAME = re.compile(r'[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')


class Rejected(Exception):
    pass


class CompletedWithCleanupFailure(Rejected):
    """The approved action completed; its final operational cleanup did not."""
    pass


def require(condition, category):
    if not condition:
        raise Rejected(category)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def database_target(raw, name):
    require(isinstance(raw, str) and len(raw) <= 8192 and not any(ord(c) < 32 for c in raw), 'VERIFIED_DATABASE_URL')
    target = urlsplit(raw)
    query = parse_qs(target.query)
    require(target.scheme in ('postgres', 'postgresql') and target.hostname and target.username
            and not target.fragment and target.path == '/' + name
            and set(query) == {'sslmode', 'sslrootcert'} and query.get('sslmode') == ['verify-full']
            and len(query.get('sslrootcert', [])) == 1,
            'DEDICATED_VERIFIED_TLS_OBSERVER_REQUIRED')
    role = unquote(target.username, errors='strict')
    require(role and not any(ord(c) < 32 or ord(c) == 127 for c in role), 'DATABASE_ROLE_INVALID')
    return (target.hostname, target.port or 5432, target.path, query['sslrootcert'][0]), role


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    require(len(raw.encode()) <= 1024 * 1024, 'JSON_BOUND')
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Rejected('NONFINITE_JSON')))


def validate(value):
    require(isinstance(value, dict) and set(value) == {'schema_version', 'namespace', 'cluster_uid',
            'writers', 'workloads', 'sandboxd', 'sandboxd_sha256', 'database_name'}, 'PLAN_FIELDS')
    require(type(value['schema_version']) is int and value['schema_version'] == 1, 'PLAN_VERSION')
    require(isinstance(value['namespace'], str) and NAME.fullmatch(value['namespace']), 'NAMESPACE')
    require(isinstance(value['cluster_uid'], str) and str(uuid.UUID(value['cluster_uid'])) == value['cluster_uid'], 'CLUSTER_UID')
    writers = value['writers']
    require(isinstance(writers, dict) and 1 <= len(writers) <= 16, 'WRITER_BOUND')
    for account, slots in writers.items():
        require(account in WRITER_ACCOUNTS, 'DEDICATED_WRITER_SERVICE_ACCOUNT')
        require(isinstance(slots, dict) and set(slots) == {'containers', 'init_containers'}, 'WRITER_FIELDS')
        for field in slots:
            values = slots[field]
            require(isinstance(values, dict) and len(values) <= 16 and (field != 'containers' or values), 'CONTAINER_BOUND')
            require(all(NAME.fullmatch(name) and isinstance(image, str) and IMAGE.fullmatch(image)
                        for name, image in values.items()), 'APPROVED_CONTAINER_IMAGE')
        require(set(slots['containers']).isdisjoint(slots['init_containers']), 'DISTINCT_CONTAINER_NAMES')
    workloads = value['workloads']
    require(isinstance(workloads, list) and 1 <= len(workloads) <= 32, 'WORKLOAD_BOUND')
    seen = set()
    accounts = set()
    for workload in workloads:
        require(isinstance(workload, dict) and set(workload) == {'kind', 'name', 'service_account', 'replicas'}, 'WORKLOAD_FIELDS')
        require(workload['kind'] in ('Deployment', 'StatefulSet') and NAME.fullmatch(workload['name'])
                and workload['service_account'] in writers and type(workload['replicas']) is int
                and 1 <= workload['replicas'] <= 32, 'REVIEWED_WORKLOAD')
        key = (workload['kind'], workload['name'])
        require(key not in seen, 'DUPLICATE_WORKLOAD')
        seen.add(key)
        accounts.add(workload['service_account'])
    require(accounts == set(writers), 'EVERY_WRITER_HAS_WORKLOAD')
    require(isinstance(value['database_name'], str) and re.fullmatch(r'[a-z][a-z0-9_]{0,62}', value['database_name']), 'DATABASE_NAME')
    require(isinstance(value['sandboxd'], str) and Path(value['sandboxd']).is_absolute()
            and Path(value['sandboxd']).name == 'sandboxd', 'EXACT_SANDBOXD_EXECUTABLE')
    require(isinstance(value['sandboxd_sha256'], str) and re.fullmatch('[a-f0-9]{64}', value['sandboxd_sha256']), 'SANDBOXD_DIGEST')
    return copy.deepcopy(value)


def policy_name(plan):
    return 'sandbox-resource-' + sha(plan['namespace'].encode())[:16]


def manifests(plan, closed=False):
    plan = validate(plan)
    name = policy_name(plan)
    writers = canonical(plan['writers'])
    slots = 'variables.approved[object.spec.serviceAccountName]'
    regular = f'object.spec.containers.size() == {slots}.containers.size() && object.spec.containers.all(c, c.name in {slots}.containers && c.image == {slots}.containers[c.name])'
    initial = f'(!has(object.spec.initContainers) ? {slots}.init_containers.size() == 0 : object.spec.initContainers.size() == {slots}.init_containers.size() && object.spec.initContainers.all(c, c.name in {slots}.init_containers && c.image == {slots}.init_containers[c.name]))'
    metadata = {'name': name, 'labels': {'app.kubernetes.io/managed-by': OWNER},
                'annotations': {'sandbox.platform/upgrade-plan-sha256': sha(canonical(plan).encode()),
                                'sandbox.platform/upgrade-state': 'CLOSED' if closed else 'APPROVED'}}
    return [{'apiVersion': 'admissionregistration.k8s.io/v1', 'kind': 'ValidatingAdmissionPolicy',
             'metadata': metadata, 'spec': {
                 'failurePolicy': 'Fail',
                 'matchConstraints': {'matchPolicy': 'Equivalent', 'resourceRules': [{
                     'apiGroups': [''], 'apiVersions': ['v1'], 'operations': ['CREATE', 'UPDATE'],
                     'resources': ['pods', 'pods/ephemeralcontainers'], 'scope': 'Namespaced'}]},
                 'matchConditions': [{'name': 'exact-namespace', 'expression': 'request.namespace == ' + canonical(plan['namespace'])},
                     {'name': 'dedicated-writer', 'expression': 'has(object.spec.serviceAccountName) && object.spec.serviceAccountName in ' + canonical(WRITER_ACCOUNTS)}],
                 'variables': [{'name': 'approved', 'expression': writers}],
                 'validations': [{'expression': 'false' if closed else f'object.spec.serviceAccountName in variables.approved && ({regular}) && ({initial}) && (!has(object.spec.ephemeralContainers) || object.spec.ephemeralContainers.size() == 0)',
                                  'message': CLOSED if closed else DENIED}]}},
            {'apiVersion': 'admissionregistration.k8s.io/v1', 'kind': 'ValidatingAdmissionPolicyBinding',
             'metadata': copy.deepcopy(metadata), 'spec': {'policyName': name, 'validationActions': ['Deny']}}]


class Gate:
    def __init__(self, plan, kubeconfig, context, evidence):
        self.plan = validate(plan)
        self.kube = ['kubectl', '--kubeconfig', str(kubeconfig), '--context', context, '--request-timeout=15s']
        self.evidence = Path(evidence)
        self.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.evidence.chmod(0o700)
        self.record = {'plan_sha256': sha(canonical(self.plan).encode()), 'stages': [], 'status': 'STARTED'}
        self.probes = []
        self.maintenance = False
        self.operation_lock = None

    def acquire_operation_lock(self):
        """The API server, rather than a client-side check, arbitrates owners."""
        name = policy_name(self.plan) + '-operation'
        operation = uuid.uuid4().hex
        document = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
            'name': name, 'namespace': self.plan['namespace'],
            'labels': {'app.kubernetes.io/managed-by': OWNER},
            'annotations': {'sandbox.platform/upgrade-operation': operation,
                            'sandbox.platform/upgrade-plan-sha256': self.record['plan_sha256']}},
            'immutable': True,
            'data': {'recovery': 'No automatic expiry or takeover. Confirm the old executor has stopped before operator removal.'}}
        try:
            actual = strict_json(self.kubectl(['create', '-f', '-', '-o', 'json'], document).stdout.decode())
        except Rejected as error:
            raise Rejected('UPGRADE_OPERATION_LOCK_NOT_ACQUIRED') from error
        metadata = actual['metadata']
        require(metadata['name'] == name and metadata['namespace'] == self.plan['namespace']
                and metadata.get('annotations', {}).get('sandbox.platform/upgrade-operation') == operation
                and metadata.get('labels', {}).get('app.kubernetes.io/managed-by') == OWNER
                and str(uuid.UUID(metadata['uid'])) == metadata['uid'], 'UPGRADE_OPERATION_LOCK_RESPONSE_INVALID')
        self.operation_lock = {'name': name, 'uid': metadata['uid'], 'operation': operation}
        self.note('OPERATION_LOCK_ACQUIRED', name=name, uid=metadata['uid'], operation=operation)

    def release_operation_lock(self):
        lock = self.operation_lock
        require(lock is not None, 'UPGRADE_OPERATION_LOCK_NOT_OWNED')
        actual = self.get('configmaps', lock['name'])['metadata']
        require(actual['uid'] == lock['uid']
                and actual.get('labels', {}).get('app.kubernetes.io/managed-by') == OWNER
                and actual.get('annotations', {}).get('sandbox.platform/upgrade-operation') == lock['operation'],
                'UPGRADE_OPERATION_LOCK_OWNER_CHANGED')
        path = '/api/v1/namespaces/' + self.plan['namespace'] + '/configmaps/' + lock['name']
        self.kubectl(['delete', '--raw', path, '-f', '-'], {
            'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': lock['uid']}})
        self.operation_lock = None
        self.note('OPERATION_LOCK_RELEASED', name=lock['name'], uid=lock['uid'])

    def note(self, stage, **details):
        self.record['stages'].append({'stage': stage, **details})
        self.save()

    def save(self):
        path = self.evidence / 'record.json'
        temporary = self.evidence / 'record.tmp'
        temporary.write_text(canonical(self.record) + '\n')
        temporary.chmod(0o600)
        temporary.replace(path)

    def command(self, args, value=None, *, expected=0, marker=None, env=None, timeout=30):
        result = subprocess.run(args, input=None if value is None else canonical(value).encode(),
                                capture_output=True, env=env, timeout=timeout, check=False)
        require(len(result.stdout) <= 8 * 1024 * 1024 and len(result.stderr) <= 1024 * 1024, 'CHILD_OUTPUT_BOUND')
        if expected == 0:
            if result.returncode:
                self.note('CHILD_FAILURE', executable=Path(args[0]).name if Path(args[0]).name in ('kubectl', 'sandboxd') else 'OTHER',
                          exit_code=result.returncode, stdout_sha256=sha(result.stdout), stderr_sha256=sha(result.stderr),
                          stdout_bytes=len(result.stdout), stderr_bytes=len(result.stderr))
            require(result.returncode == 0, 'COMMAND_FAILED')
        else:
            require(result.returncode != 0 and marker and marker.encode() in result.stderr, 'EXPECTED_ACTUAL_ADMISSION_DENIAL_MISSING')
        return result

    def kubectl(self, args, value=None, **kw):
        return self.command(self.kube + args, value, **kw)

    def get(self, resource, name=None):
        args = ['get', resource] + ([name] if name else []) + ['-o', 'json']
        if resource not in ('namespaces', 'validatingadmissionpolicies', 'validatingadmissionpolicybindings'):
            args += ['-n', self.plan['namespace']]
        return strict_json(self.kubectl(args).stdout.decode())

    def identity(self):
        actual = self.get('namespaces', 'kube-system')['metadata']['uid']
        require(actual == self.plan['cluster_uid'], 'ACTUAL_CLUSTER_UID_MISMATCH')
        self.get('namespaces', self.plan['namespace'])

    def install(self, closed=False):
        self.identity()
        self.kubectl(['apply', '--server-side', '--field-manager=' + OWNER, '-f', '-'],
                     {'apiVersion': 'v1', 'kind': 'List', 'items': manifests(self.plan, closed)})
        deadline = time.monotonic() + 30
        while True:
            policy = self.get('validatingadmissionpolicies', policy_name(self.plan))
            status = policy.get('status', {})
            warnings = status.get('typeChecking', {}).get('expressionWarnings', [])
            require(not warnings, 'ADMISSION_CEL_TYPE_WARNING')
            if status.get('observedGeneration') == policy['metadata']['generation']:
                break
            require(time.monotonic() < deadline, 'ADMISSION_OBSERVATION_TIMEOUT')
            time.sleep(0.2)
        self.note('ADMISSION_INSTALLED', state='CLOSED' if closed else 'APPROVED')

    def installed(self, closed):
        expected = manifests(self.plan, closed)
        for kind, wanted in zip(['validatingadmissionpolicies', 'validatingadmissionpolicybindings'], expected):
            actual = self.get(kind, policy_name(self.plan))
            require(actual['metadata'].get('labels', {}).get('app.kubernetes.io/managed-by') == OWNER,
                    'ADMISSION_INSTALLATION_OWNER_DRIFT')
            spec = copy.deepcopy(actual['spec'])
            if kind == 'validatingadmissionpolicies':
                for key in ('namespaceSelector', 'objectSelector'):
                    if spec['matchConstraints'].get(key) == {}:
                        spec['matchConstraints'].pop(key)
            elif 'matchResources' in spec:
                require(spec['matchResources'] in ({}, {'matchPolicy': 'Equivalent', 'namespaceSelector': {}, 'objectSelector': {}}),
                        'ADMISSION_BINDING_SELECTOR_DRIFT')
                spec.pop('matchResources')
            require(spec == wanted['spec'], 'ACTUAL_ADMISSION_SPEC_DRIFT')

    def probe(self, account):
        slots = self.plan['writers'][account]
        security = {'runAsNonRoot': True, 'runAsUser': 10001, 'allowPrivilegeEscalation': False,
                    'capabilities': {'drop': ['ALL']}, 'seccompProfile': {'type': 'RuntimeDefault'}}
        def containers(values):
            return [{'name': name, 'image': image, 'command': ['/not-executed'], 'securityContext': security,
                     'resources': {'requests': {'cpu': '1m', 'memory': '1Mi'}, 'limits': {'cpu': '1m', 'memory': '1Mi'}}}
                    for name, image in values.items()]
        return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {
            'name': 'resource-upgrade-probe-' + uuid.uuid4().hex, 'namespace': self.plan['namespace'],
            'labels': {'app.kubernetes.io/managed-by': OWNER}}, 'spec': {
                'serviceAccountName': account, 'automountServiceAccountToken': False, 'restartPolicy': 'Never',
                'terminationGracePeriodSeconds': 0,
                'nodeName': 'resource-upgrade-probe-does-not-exist',
                'containers': containers(slots['containers']), 'initContainers': containers(slots['init_containers'])}}

    def admission_probe(self, args, value, *, expected=0, marker=None):
        # Policy observation precedes admission-controller cache convergence.
        # These requests cannot create or mutate an object. Proceed only after
        # the real API returns the exact expected decision, within a deadline.
        require('--dry-run=server' in args or any('/ephemeralcontainers?dryRun=All' in part for part in args),
                'ADMISSION_RETRY_REQUIRES_SERVER_DRY_RUN')
        deadline = time.monotonic() + 20
        while True:
            try:
                return self.kubectl(args, value, expected=expected, marker=marker)
            except Rejected as error:
                if str(error) not in ('COMMAND_FAILED', 'EXPECTED_ACTUAL_ADMISSION_DENIAL_MISSING') or time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)

    def verify(self, closed=False):
        self.identity()
        self.installed(closed)
        count = 0
        for account in self.plan['writers']:
            pod = self.probe(account)
            if closed:
                self.admission_probe(['create', '--dry-run=server', '-f', '-'], pod, expected=1, marker=CLOSED)
                count += 1
                continue
            self.admission_probe(['create', '--dry-run=server', '-f', '-'], pod)
            count += 1
            for slot in ['containers', 'initContainers']:
                for index in range(len(pod['spec'][slot])):
                    bad = copy.deepcopy(pod)
                    original = bad['spec'][slot][index]['image']
                    replacement = '0' * 64 if not original.endswith('0' * 64) else '1' * 64
                    bad['spec'][slot][index]['image'] = original.split('@')[0] + '@sha256:' + replacement
                    self.admission_probe(['create', '--dry-run=server', '-f', '-'], bad, expected=1, marker=DENIED)
                    count += 1
            # An unscheduled, tokenless owned Pod exercises actual UPDATE and
            # ephemeralcontainers admission, without starting a guest process.
            actual = strict_json(self.kubectl(['create', '-f', '-', '-o', 'json'], pod).stdout.decode())
            self.probes.append((actual['metadata']['name'], actual['metadata']['uid']))
            bad = copy.deepcopy(actual)
            bad['spec']['containers'][0]['image'] = 'registry.invalid/old@sha256:' + '0' * 64
            self.admission_probe(['replace', '--dry-run=server', '-f', '-'], bad, expected=1, marker=DENIED)
            ephemeral = copy.deepcopy(actual)
            ephemeral['spec']['ephemeralContainers'] = [{'name': 'blocked-debug', 'image': next(iter(self.plan['writers'][account]['containers'].values())),
                                                       'command': ['/not-executed']}]
            path = '/api/v1/namespaces/' + self.plan['namespace'] + '/pods/' + actual['metadata']['name'] + '/ephemeralcontainers?dryRun=All'
            self.admission_probe(['replace', '--raw', path, '-f', '-'], ephemeral, expected=1, marker=DENIED)
            count += 2
        excluded = self.probe(next(iter(self.plan['writers'])))
        excluded['spec']['serviceAccountName'] = 'default'
        self.admission_probe(['create', '--dry-run=server', '-f', '-'], excluded)
        self.clean_probes()
        self.note('ACTUAL_ADMISSION_VERIFIED', state='CLOSED' if closed else 'APPROVED', cases=count + 1,
                  non_writer_unaffected=True, actual_server_dry_run=True)

    def clean_probes(self):
        for name, uid in self.probes:
            actual = self.get('pods', name)
            require(actual['metadata']['uid'] == uid and actual['metadata']['labels'].get('app.kubernetes.io/managed-by') == OWNER,
                    'PROBE_IDENTITY_CHANGED')
            # Eviction carries an atomic UID precondition. A same-name
            # replacement between observation and deletion is never removed.
            path = '/api/v1/namespaces/' + self.plan['namespace'] + '/pods/' + name + '/eviction'
            eviction = {'apiVersion': 'policy/v1', 'kind': 'Eviction',
                        'metadata': {'name': name, 'namespace': self.plan['namespace']},
                        'deleteOptions': {'gracePeriodSeconds': 0, 'preconditions': {'uid': uid}}}
            self.kubectl(['create', '--raw', path, '-f', '-'], eviction)
            self.kubectl(['wait', '--for=delete', 'pod/' + name, '-n', self.plan['namespace'], '--timeout=20s'])
        self.probes.clear()

    def workloads(self):
        expected = {(w['kind'], w['name']): w for w in self.plan['workloads']}
        actual = {}
        for resource in ['deployments', 'statefulsets', 'daemonsets', 'jobs', 'cronjobs']:
            for item in self.get(resource).get('items', []):
                spec = item['spec']
                pod = spec['jobTemplate']['spec']['template']['spec'] if item['kind'] == 'CronJob' else spec['template']['spec']
                if pod.get('serviceAccountName', 'default') not in WRITER_ACCOUNTS:
                    continue
                key = (item['kind'], item['metadata']['name'])
                require(key in expected and pod.get('serviceAccountName') == expected[key]['service_account'], 'UNREVIEWED_WRITER_WORKLOAD')
                actual[key] = item
        require(set(actual) == set(expected), 'WRITER_WORKLOAD_MISSING')
        return actual

    def scale(self, replicas):
        for w in self.plan['workloads']:
            self.kubectl(['scale', w['kind'].lower() + '/' + w['name'], '-n', self.plan['namespace'],
                          '--replicas=' + str(w['replicas'] if replicas else 0)])

    def database_clear(self):
        raw = os.environ.get('SANDBOX_UPGRADE_OBSERVER_DATABASE_URL', '')
        _, observer_role = database_target(raw, self.plan['database_name'])
        # This operational observer must see every tenant, independently of the
        # application-supplied tenant context. No runtime role gains this access.
        sql = """BEGIN READ ONLY;
SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='3s';
SELECT json_build_object(
 'observer_complete',(SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user),
 'sessions',(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND usename=ANY(ARRAY[%s])),
 'leases',(SELECT count(*) FROM public.operations WHERE lease_until>clock_timestamp())
  +(SELECT count(*) FROM public.node_fence_incidents WHERE lease_until>clock_timestamp())
  +(SELECT count(*) FROM public.automation_claims WHERE lease_until>clock_timestamp())
  +(SELECT count(*) FROM public.automation_runs WHERE lease_until>clock_timestamp()));
COMMIT;""" % ','.join("'" + role + "'" for role in ROLES)
        target = urlsplit(raw)
        env = {key: value for key, value in os.environ.items() if not key.startswith('PG')}
        env.update(PGHOST=target.hostname, PGPORT=str(target.port or 5432), PGDATABASE=self.plan['database_name'],
                   PGUSER=observer_role, PGPASSWORD=unquote(target.password or ''),
                   PGSSLMODE='verify-full', PGSSLROOTCERT=parse_qs(target.query)['sslrootcert'][0],
                   PGCONNECT_TIMEOUT='5', PGAPPNAME=OWNER)
        result = subprocess.run(['psql', '-X', '-q', '-At', '-v', 'ON_ERROR_STOP=1'], input=sql.encode(),
                                capture_output=True, env=env, timeout=15, check=False)
        require(result.returncode == 0 and len(result.stdout) < 4096, 'DATABASE_DRAIN_OBSERVATION_FAILED')
        data = strict_json(result.stdout.decode())
        require(data.get('observer_complete') is True, 'OBSERVER_CANNOT_VERIFY_ALL_TENANTS')
        return data['sessions'] == 0 and data['leases'] == 0

    def drain(self):
        deadline = time.monotonic() + 180
        while True:
            self.identity()
            pods = [pod for pod in self.get('pods').get('items', [])
                    if pod['spec'].get('serviceAccountName', 'default') in WRITER_ACCOUNTS]
            if not pods and self.database_clear():
                self.note('WRITERS_DRAINED', actual_pods=0, actual_runtime_sessions=0, active_leases=0)
                return
            require(time.monotonic() < deadline, 'ACTUAL_WRITER_DRAIN_TIMEOUT')
            time.sleep(1)

    def executable(self):
        path = Path(self.plan['sandboxd'])
        require(path.is_file() and not path.is_symlink() and all(not p.is_symlink() for p in path.parents)
                and os.access(path, os.X_OK) and sha(path.read_bytes()) == self.plan['sandboxd_sha256'], 'ACTUAL_SANDBOXD_DIGEST_MISMATCH')
        return str(path)

    def maintain(self):
        self.workloads()
        # CLOSED survives failures. There is no rollback/restore-old command.
        self.maintenance = True
        self.install(closed=True)
        self.verify(closed=True)
        self.scale(False)
        self.drain()
        binary = self.executable()
        owner = os.environ.get('SANDBOX_UPGRADE_MIGRATION_DATABASE_URL', '')
        runtime = os.environ.get('SANDBOX_UPGRADE_PREFLIGHT_DATABASE_URL', '')
        require(owner and runtime and owner != runtime, 'SEPARATE_MIGRATION_AND_PREFLIGHT_IDENTITIES_REQUIRED')
        observation_target, observer_role = database_target(os.environ.get('SANDBOX_UPGRADE_OBSERVER_DATABASE_URL', ''), self.plan['database_name'])
        owner_target, owner_role = database_target(owner, self.plan['database_name'])
        app_target, app_role = database_target(runtime, self.plan['database_name'])
        require(owner_target == app_target == observation_target and app_role == 'sandbox_app'
                and owner_role not in ROLES and len({observer_role, owner_role, app_role}) == 3,
                'SAME_DATABASE_DISTINCT_OWNER_OBSERVER_APP_REQUIRED')
        self.command([binary, '--role', 'migrate'], env=dict(os.environ, SANDBOX_DATABASE_URL=owner), timeout=330)
        self.note('NORMAL_OWNER_MIGRATION_COMPLETED')
        require(self.database_clear(), 'WRITERS_RETURNED_DURING_MIGRATION')
        self.executable()
        self.command([binary, 'resource-accounting-check'], env=dict(os.environ, SANDBOX_DATABASE_URL=runtime), timeout=30)
        self.note('ACTUAL_NEW_BINARY_PREFLIGHT_COMPLETED')
        for w in self.plan['workloads']:
            resource = w['kind'].lower() + '/' + w['name']
            actual = self.get(w['kind'].lower(), w['name'])
            slots = self.plan['writers'][w['service_account']]
            spec = actual['spec']['template']['spec']
            for field, source in [('containers', 'containers'), ('initContainers', 'init_containers')]:
                require({v['name'] for v in spec.get(field, [])} == set(slots[source]), 'WORKLOAD_CONTAINER_SET_DRIFT')
            patch = {'spec': {'template': {'spec': {'containers': [{'name': n, 'image': v} for n, v in slots['containers'].items()],
                                                   'initContainers': [{'name': n, 'image': v} for n, v in slots['init_containers'].items()]}}}}
            self.kubectl(['patch', resource, '-n', self.plan['namespace'], '--type=strategic', '-p', canonical(patch)])
        self.install(closed=False)
        self.verify(closed=False)
        require(self.database_clear(), 'WRITERS_RETURNED_BEFORE_RESUME')
        self.scale(True)
        for w in self.plan['workloads']:
            self.kubectl(['rollout', 'status', w['kind'].lower() + '/' + w['name'], '-n', self.plan['namespace'], '--timeout=180s'], timeout=190)
        self.note('APPROVED_NEW_WRITERS_RESUMED')

    def run(self, action):
        try:
            self.identity()
            self.acquire_operation_lock()
            if action == 'maintain':
                # Prove the approved policy before closing writes, including on
                # fresh installation; never reopen an interrupted CLOSED plan.
                existing = self.kubectl(['get', 'validatingadmissionpolicies', policy_name(self.plan), '--ignore-not-found', '-o', 'json']).stdout
                if existing.strip():
                    old = strict_json(existing.decode())
                    require(old['metadata'].get('annotations', {}).get('sandbox.platform/upgrade-plan-sha256') == self.record['plan_sha256'], 'INSTALLED_PLAN_DIFFERS')
                    closed = old['metadata']['annotations'].get('sandbox.platform/upgrade-state') == 'CLOSED'
                else:
                    closed = False
                if not closed:
                    self.install(False)
                    self.verify(False)
                self.maintain()
            elif action == 'install':
                existing = self.kubectl(['get', 'validatingadmissionpolicies', policy_name(self.plan), '--ignore-not-found', '-o', 'json']).stdout
                require(not existing.strip(), 'POLICY_ALREADY_INSTALLED_USE_VERIFY_OR_MAINTAIN')
                self.install(False)
                self.verify(False)
            else:
                actual = self.get('validatingadmissionpolicies', policy_name(self.plan))
                require(actual['metadata'].get('annotations', {}).get('sandbox.platform/upgrade-plan-sha256') == self.record['plan_sha256'], 'INSTALLED_PLAN_DIFFERS')
                self.verify(actual['metadata']['annotations'].get('sandbox.platform/upgrade-state') == 'CLOSED')
            self.record['status'] = 'PASS'
        except BaseException as error:
            self.record['status'] = 'FAIL'
            self.record['failure_category'] = str(error) if isinstance(error, Rejected) and re.fullmatch('[A-Z][A-Z0-9_]{0,127}', str(error)) else 'EXTERNAL_FAILURE'
            if self.maintenance:
                try:
                    self.install(True)
                    self.verify(True)
                    self.scale(False)
                    self.record['maintenance_left_closed'] = True
                except BaseException:
                    self.record['maintenance_left_closed'] = 'UNCONFIRMED'
            raise
        finally:
            action_completed = self.record['status'] == 'PASS'
            try:
                self.finalize(action, action_completed)
            except BaseException as error:
                if action_completed:
                    # Evidence writes can fail too (for example disk full).
                    # Preserve the real completed terminal state even when no
                    # receipt can be persisted; main still reports exit 2.
                    self.record['status'] = 'COMPLETED_WITH_CLEANUP_FAILURE'
                    self.record['completed_action'] = action
                    raise CompletedWithCleanupFailure('COMPLETED_FINALIZATION_UNCONFIRMED') from error
                raise

    def finalize(self, action, action_completed):
        try:
            self.clean_probes()
            self.record['owned_probe_cleanup_confirmed'] = True
        except BaseException as error:
            self.record['owned_probe_cleanup_confirmed'] = False
            self.record['status'] = 'COMPLETED_WITH_CLEANUP_FAILURE' if action_completed else 'FAIL'
            self.record['completed_action'] = action if action_completed else None
            if self.operation_lock:
                self.record['operation_lock_released'] = False
                self.record['operation_lock_requires_operator_recovery'] = True
            self.save()
            if action_completed:
                raise CompletedWithCleanupFailure('COMPLETED_PROBE_CLEANUP_UNCONFIRMED') from error
            raise
        if self.operation_lock:
            if self.record['status'] == 'PASS' or self.record.get('maintenance_left_closed') is True:
                try:
                    self.release_operation_lock()
                    self.record['operation_lock_released'] = True
                except BaseException as error:
                    self.record['operation_lock_released'] = False
                    self.record['operation_lock_requires_operator_recovery'] = True
                    # DELETE may have reached the server before its ACK was
                    # lost. Another owner could already hold a new lock, so
                    # never refence or resume from this finalization path.
                    self.record['status'] = 'COMPLETED_WITH_CLEANUP_FAILURE' if action_completed else 'FAIL'
                    self.record['completed_action'] = action if action_completed else None
                    self.save()
                    if action_completed:
                        raise CompletedWithCleanupFailure('COMPLETED_OPERATION_LOCK_CLEANUP_UNCONFIRMED') from error
                    raise
            else:
                self.record['operation_lock_released'] = False
                self.record['operation_lock_requires_operator_recovery'] = True
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install', 'verify', 'maintain'])
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--kubeconfig', type=Path, required=True)
    parser.add_argument('--context', required=True)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    args = parser.parse_args()
    try:
        plan = validate(strict_json(args.plan.read_text()))
        Gate(plan, args.kubeconfig, args.context, args.evidence_dir).run(args.action)
    except CompletedWithCleanupFailure:
        parser.exit(2, 'RESOURCE_ACCOUNTING_UPGRADE_ACTION_COMPLETED; OPERATIONAL_CLEANUP_UNCONFIRMED; inspect private receipts before operator recovery\n')
    except (Rejected, ValueError, OSError, subprocess.SubprocessError, KeyError, TypeError):
        parser.exit(1, 'RESOURCE_ACCOUNTING_UPGRADE_REJECTED; inspect private stage receipts\n')
    print('PASS actual resource-accounting upgrade gate; no cloud certification')


if __name__ == '__main__':
    main()
