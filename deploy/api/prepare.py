#!/usr/bin/env python3
"""Bind nonsecret API settings to reviewed Alibaba Terraform outputs, without apply."""
import argparse
from pathlib import Path
from render import canonical, fields, load, require, validate


OUTPUTS = {'vpc_id', 'deployment_identity', 'subnets', 'node_inventory', 'private_entrances', 'database',
           'object_storage', 'workload_roles', 'workload_oidc_provider_arn', 'workspace_kms_key_id'}
SETTINGS = {'schema_version', 'namespace', 'service_name', 'image', 'replicas', 'tls', 'cursor_secret', 'database',
            'oidc', 'browser', 'metrics', 'callers', 'default_ttl_seconds', 'max_ttl_seconds', 'db_max_connections',
            'storage_enabled', 'max_file_bytes'}


def prepare(settings, outputs):
    fields(settings, SETTINGS, 'API_SETTINGS_FIELDS')
    fields(outputs, OUTPUTS, 'TERRAFORM_OUTPUT_FIELDS')
    if all(isinstance(value, dict) and 'value' in value for value in outputs.values()):
        outputs = {name: value['value'] for name, value in outputs.items()}
    identity = fields(outputs['deployment_identity'], ['cloud_account_id', 'region', 'deployment', 'environment'], 'DEPLOYMENT_IDENTITY')
    database = fields(outputs['database'], ['id', 'endpoint', 'port', 'engine', 'major_version'], 'RDS_OUTPUT_FIELDS')
    require(database['engine'] == 'PostgreSQL' and database['port'] == 5432, 'RDS_POSTGRES_IDENTITY')
    fields(settings['database'], ['secret', 'ca_pem'], 'DATABASE_SETTINGS_NO_CLOUD_OVERRIDES')
    require(isinstance(outputs['node_inventory'], dict) and type(settings['replicas']) is int, 'NODE_INVENTORY')
    platform = []
    for node in outputs['node_inventory'].values():
        fields(node, ['id', 'private_ip', 'role', 'zone'], 'NODE_FIELDS')
        if node['role'] == 'platform':
            platform.append(node)
    # Required hostname anti-affinity + maxUnavailable=0/maxSurge=1 needs an
    # actual spare platform host to avoid a rolling-update scheduling deadlock.
    require(len(platform) >= settings['replicas'] + 1
            and len({node['id'] for node in platform}) == len(platform), 'PLATFORM_CAPACITY_FOR_HA_AND_ROLLING_SURGE')
    zones = sorted({node['zone'] for node in platform})
    require(len(zones) >= 2, 'AT_LEAST_TWO_PLATFORM_ZONES')
    # maxSkew=1 also constrains the surge Pod. A spare host concentrated in
    # one zone cannot make a required balanced placement schedulable.
    capacities = [sum(node['zone'] == zone for node in platform) for zone in zones]
    per_zone = (settings['replicas'] + 1) // len(zones)
    require(min(capacities) >= per_zone
            and sum(min(capacity, per_zone + 1) for capacity in capacities) >= settings['replicas'] + 1,
            'BALANCED_ZONE_CAPACITY_FOR_ROLLING_SURGE')
    result = {key: value for key, value in settings.items() if key not in {'storage_enabled', 'max_file_bytes'}}
    result.update({'deployment': identity['deployment'], 'zones': zones,
                   'database': dict(settings['database'], host=database['endpoint'], port=database['port'])})
    require(type(settings['storage_enabled']) is bool, 'EXPLICIT_STORAGE_ENABLEMENT')
    if settings['storage_enabled']:
        scopes = ['file-upload', 'file-reader', 'output-reader']
        roles = {purpose: outputs['workload_roles'][purpose] for purpose in scopes}
        result['storage'] = {'deployment': identity['deployment'], 'account_id': identity['cloud_account_id'], 'region': identity['region'], 'workload_roles': roles}
        for feature, purpose in [('files', 'temporary'), ('output', 'output')]:
            source = fields(outputs['object_storage'][purpose], ['bucket', 'internal_endpoint', 'kms_key_id'], 'OSS_OUTPUT_FIELDS')
            # Terraform provider can return a bucket-qualified OSS endpoint;
            # the native Rust OSS configuration requires the regional base.
            endpoint = 'https://oss-' + identity['region'] + '-internal.aliyuncs.com'
            require(source['internal_endpoint'] in [endpoint, endpoint[8:], source['bucket'] + '.' + endpoint[8:],
                                                    'https://' + source['bucket'] + '.' + endpoint[8:]], 'EXACT_REGIONAL_OSS_OUTPUT')
            result[feature] = {'endpoint': endpoint, 'bucket': source['bucket'], 'kms_key_id': source['kms_key_id']}
        result['files']['max_file_bytes'] = settings['max_file_bytes']
    else:
        require(settings['max_file_bytes'] is None, 'DISABLED_STORAGE_HAS_NO_LIMIT_CONFIG')
        result.update({'files': None, 'output': None, 'storage': None})
    return validate(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings', type=Path, required=True)
    parser.add_argument('--terraform-output', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = prepare(load(args.settings), load(args.terraform_output))
        with args.output.open('xb') as target:
            target.write(canonical(result).encode() + b'\n')
    except (ValueError, TypeError, KeyError, OSError):
        parser.exit(1, 'API_PREPARE_REJECTED\n')


if __name__ == '__main__':
    main()
