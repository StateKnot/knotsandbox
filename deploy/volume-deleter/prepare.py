#!/usr/bin/env python3
"""Bind volume controller settings to observed Terraform outputs; no cloud calls."""
import argparse
from pathlib import Path
from render import canonical, fields, load, require, validate

OUTPUTS = {'vpc_id', 'deployment_identity', 'subnets', 'node_inventory', 'private_entrances', 'database',
           'object_storage', 'workload_roles', 'workload_oidc_provider_arn', 'workspace_kms_key_id'}
SETTINGS = {'schema_version', 'image', 'replicas', 'database', 'storage_class', 'certification_id',
            'projects', 'concurrency', 'requests_per_second', 'max_in_flight', 'db_max_connections'}


def prepare(settings, outputs):
    fields(settings, SETTINGS, 'VOLUME_SETTINGS_FIELDS')
    fields(outputs, OUTPUTS, 'TERRAFORM_OUTPUT_FIELDS')
    wrapped = [isinstance(value, dict) and 'value' in value for value in outputs.values()]
    if any(wrapped):
        require(all(wrapped), 'NO_MIXED_TERRAFORM_OUTPUT_SHAPE')
        for value in outputs.values():
            require(value.get('sensitive') is False, 'PUBLIC_TERRAFORM_OUTPUTS_REQUIRED')
        outputs = {key: value['value'] for key, value in outputs.items()}
    identity = fields(outputs['deployment_identity'], ['cloud_account_id', 'region', 'deployment', 'environment'], 'DEPLOYMENT_IDENTITY')
    database = fields(outputs['database'], ['id', 'endpoint', 'port', 'engine', 'major_version'], 'RDS_OUTPUT_FIELDS')
    require(database['engine'] == 'PostgreSQL' and type(database['major_version']) is int
            and database['major_version'] == 17 and type(database['port']) is int and database['port'] == 5432, 'RDS_POSTGRES_17_IDENTITY')
    fields(settings['database'], ['secret', 'ca_pem'], 'DATABASE_SETTINGS_NO_OVERRIDES')
    require(isinstance(outputs['workload_roles'], dict), 'OBSERVED_WORKLOAD_ROLES')
    role = fields(outputs['workload_roles']['volume-deleter'], ['arn', 'role_id', 'subject', 'issuer', 'audience'], 'OBSERVED_VOLUME_ROLE')
    require(isinstance(outputs['node_inventory'], dict), 'OBSERVED_NODE_INVENTORY')
    platform = []
    ids = set()
    for hostname, node in outputs['node_inventory'].items():
        fields(node, ['id', 'private_ip', 'role', 'zone'], 'NODE_FIELDS')
        require(isinstance(node['id'], str) and node['id'] not in ids, 'UNIQUE_OBSERVED_NODE_IDS')
        ids.add(node['id'])
        require(node['role'] in {'control', 'platform', 'kata'}, 'NODE_ROLE')
        if node['role'] == 'platform':
            platform.append({'hostname': hostname, 'zone': node['zone']})
    configuration = {'cloud': {
        'account_id': identity['cloud_account_id'], 'region': identity['region'],
        'deployment': identity['deployment'], 'role_arn': role['arn'], 'role_id': role['role_id'],
        'oidc_provider_arn': outputs['workload_oidc_provider_arn'], 'oidc_issuer': role['issuer'],
        'oidc_audience': role['audience'], 'oidc_subject': role['subject'],
        'oidc_token_file': '/var/run/sandbox-cloud/token',
        'requests_per_second': settings['requests_per_second'], 'max_in_flight': settings['max_in_flight']},
        'storage': {'storage_class': settings['storage_class'], 'kms_key_id': outputs['workspace_kms_key_id'],
            'deployment': identity['deployment'], 'zones': sorted({node['zone'] for node in platform}),
            'certification_id': settings['certification_id']}, 'concurrency': settings['concurrency']}
    return validate({'schema_version': settings['schema_version'], 'image': settings['image'],
        'replicas': settings['replicas'], 'platform_nodes': platform, 'configuration': configuration,
        'database': dict(settings['database'], host=database['endpoint'], port=database['port']),
        'projects': settings['projects'], 'db_max_connections': settings['db_max_connections']})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings', type=Path, required=True)
    parser.add_argument('--terraform-output', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        value = prepare(load(args.settings), load(args.terraform_output))
        with args.output.open('x') as target:
            target.write(canonical(value) + '\n')
    except (ValueError, TypeError, KeyError, OSError):
        parser.exit(1, 'VOLUME_PREPARE_REJECTED\n')


if __name__ == '__main__':
    main()
