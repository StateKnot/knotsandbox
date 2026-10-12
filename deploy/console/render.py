#!/usr/bin/env python3
"""Offline renderer. A fixed same-origin TLS proxy owns the browser boundary."""
import argparse
import hashlib
import ipaddress
import json
import re
import ssl
from pathlib import Path
from urllib.parse import urlsplit


def require(value, message):
    if not value:
        raise ValueError(message)


def configuration(origin, api_upstream):
    u = urlsplit(origin)
    require(u.scheme == 'https' and u.hostname and not u.username and not u.password
            and u.path in ('', '/') and not u.query and not u.fragment and u.port in (None, 443)
            and re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', u.hostname)
            and '.' in u.hostname and '..' not in u.hostname, 'exact HTTPS public origin required')
    require(re.fullmatch(r'[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*\.svc\.cluster\.local:[1-9][0-9]{1,4}', api_upstream),
            'fixed private Kubernetes API service endpoint required')
    require(1 <= int(api_upstream.rsplit(':', 1)[1]) <= 65535, 'invalid API service port')
    host = u.hostname
    api_name = api_upstream.rsplit(':', 1)[0]
    return f'''worker_processes auto;
pid /tmp/nginx.pid;
error_log /dev/null crit;
events {{ worker_connections 1024; }}
http {{
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  server_tokens off;
  map '$status:$uri' $console_cache {{ default 'no-store'; ~^(200|304):/assets/ 'public, max-age=31536000, immutable'; }}
  log_format safe '$time_iso8601 method=$request_method path=$uri status=$status bytes=$body_bytes_sent request_id=$upstream_http_x_request_id';
  access_log /dev/stdout safe;
  client_body_temp_path /tmp/client_temp;
  proxy_temp_path /tmp/proxy_temp;
  fastcgi_temp_path /tmp/fastcgi_temp;
  scgi_temp_path /tmp/scgi_temp;
  uwsgi_temp_path /tmp/uwsgi_temp;
  client_body_timeout 20s;
  client_header_timeout 10s;
  send_timeout 20s;
  keepalive_timeout 30s;
  large_client_header_buffers 2 8k;
  gzip off;
  upstream sandbox_api {{ server {api_upstream}; keepalive 32; }}
  server {{
    listen 8443 ssl;
    server_name {host};
    if ($host != '{host}') {{ return 421; }}
    ssl_certificate /tls/tls.crt;
    ssl_certificate_key /tls/tls.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    ssl_session_cache shared:TLS:10m;
    root /usr/share/nginx/html;
    client_max_body_size 64k;
    add_header Cache-Control $console_cache always;
    add_header Strict-Transport-Security 'max-age=31536000' always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;
    add_header Content-Security-Policy "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'" always;
    add_header Permissions-Policy 'camera=(), microphone=(), geolocation=()' always;
    proxy_http_version 1.1;
    proxy_ssl_verify on;
    proxy_ssl_verify_depth 8;
    proxy_ssl_trusted_certificate /api-ca/ca.crt;
    proxy_ssl_server_name on;
    proxy_ssl_name {api_name};
    proxy_ssl_protocols TLSv1.2 TLSv1.3;
    proxy_ssl_session_reuse off;
    proxy_set_header Host {host};
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header Connection '';
    proxy_connect_timeout 5s;
    proxy_send_timeout 20s;
    proxy_read_timeout 320s;
    proxy_buffering off;
    proxy_request_buffering on;
    proxy_next_upstream off;
    proxy_redirect off;
    location = /auth/login {{ proxy_pass https://sandbox_api; }}
    location = /auth/session {{ proxy_pass https://sandbox_api; }}
    location = /auth/logout {{ proxy_pass https://sandbox_api; }}
    location = /auth/callback {{ proxy_pass https://sandbox_api; }}
    location ~ '^/v1/file-transfers/[0-9a-f-]{{36}}/content/[0-9]{{1,2}}$' {{ client_max_body_size 1m; proxy_pass https://sandbox_api; }}
    location /v1/ {{ proxy_pass https://sandbox_api; }}
    location = /health/live {{ access_log off; return 204; }}
    location = / {{ try_files /index.html =404; }}
    location = /index.html {{ try_files /index.html =404; }}
    location /assets/ {{ try_files $uri =404; }}
    location / {{ return 404; }}
  }}
}}
'''


def ca_bundle(value):
    require(isinstance(value, str) and 0 < len(value.encode()) <= 65536
            and 1 <= value.count('-----BEGIN CERTIFICATE-----') <= 16
            and 'PRIVATE' not in value, 'bounded public API CA PEM required')
    try:
        ssl.create_default_context(cadata=value)
    except (ssl.SSLError, ValueError):
        raise ValueError('valid public API CA PEM required') from None
    return value


def manifests(origin, api, image, namespace, tls_secret, api_ca, ingress_cidrs=(), ingress_proxies=()):
    require(namespace == 'sandbox-system', 'reviewed sandbox-system namespace required')
    require(api == 'sandbox-api.sandbox-system.svc.cluster.local:8443', 'production API Service DNS/8443 must match the API renderer')
    require(1 <= len(ingress_cidrs) + len(ingress_proxies) <= 8, 'exact reviewed LB/client CIDRs or ingress proxy identities required')
    networks = []
    for value in ingress_cidrs:
        net = ipaddress.ip_network(value, strict=True)
        require(net.prefixlen >= (24 if net.version == 4 else 64) and not net.is_multicast
                and not net.is_link_local and not net.is_loopback, 'bounded reviewed ingress CIDR required')
        networks.append(str(net))
    proxies = []
    for value in ingress_proxies:
        require(isinstance(value, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,62}/[a-z][a-z0-9-]{0,62}', value), 'exact proxy namespace/app identity required')
        ns, app = value.split('/')
        require(not ns.startswith(('sbx-', 'tenant-', 'sandbox-runtime')), 'untrusted runtime ingress proxy forbidden')
        proxies.append({'matchLabels': {'k8s:io.kubernetes.pod.namespace': ns, 'k8s:app.kubernetes.io/name': app}})
    require(re.fullmatch(r'[a-z][a-z0-9-]{0,62}', tls_secret), 'invalid TLS secret name')
    require(re.fullmatch(r'[a-z0-9./:_-]+@sha256:[a-f0-9]{64}', image), 'console image must use a verified digest')
    config = configuration(origin, api)
    config_name = 'sandbox-console-' + hashlib.sha256(config.encode()).hexdigest()[:12]
    api_ca = ca_bundle(api_ca)
    ca_name = 'sandbox-console-api-ca-' + hashlib.sha256(api_ca.encode()).hexdigest()[:12]
    labels = {'app.kubernetes.io/name': 'sandbox-console', 'sandbox.platform/network-policy': 'console-v1'}
    def meta(name):
        return {'name': name, 'namespace': namespace}
    return {'apiVersion': 'v1', 'kind': 'List', 'items': [
        {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': meta(config_name), 'immutable': True,
         'data': {'nginx.conf': config}},
        {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': meta(ca_name), 'immutable': True,
         'data': {'ca.crt': api_ca}},
        {'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': meta('sandbox-console'), 'automountServiceAccountToken': False},
        {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': meta('sandbox-console'),
         'spec': {'replicas': 2, 'revisionHistoryLimit': 3,
                  'strategy': {'type': 'RollingUpdate', 'rollingUpdate': {'maxUnavailable': 0, 'maxSurge': 1}},
                  'selector': {'matchLabels': labels}, 'template': {'metadata': {'labels': labels}, 'spec': {
                      'serviceAccountName': 'sandbox-console', 'automountServiceAccountToken': False,
                      'terminationGracePeriodSeconds': 30,
                      'dnsConfig': {'options': [{'name': 'ndots', 'value': '1'}]},
                      'nodeSelector': {'sandbox.platform/node-pool':'platform'},
                      'securityContext': {'runAsUser': 101, 'runAsGroup': 101, 'runAsNonRoot': True, 'fsGroup': 101,
                                          'seccompProfile': {'type': 'RuntimeDefault'}},
                      'containers': [{'name': 'console', 'image': image, 'imagePullPolicy': 'IfNotPresent',
                                      'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                                          'capabilities': {'drop': ['ALL']}},
                                      'ports': [{'containerPort': 8443, 'name': 'https'}],
                                      'resources': {'requests': {'cpu': '100m', 'memory': '64Mi'},
                                                    'limits': {'cpu': '500m', 'memory': '128Mi'}},
                                      'readinessProbe': {'httpGet': {'scheme':'HTTPS','path':'/health/live','port':'https','httpHeaders':[{'name':'Host','value':urlsplit(origin).hostname}]}, 'periodSeconds': 5},
                                      'livenessProbe': {'httpGet': {'scheme':'HTTPS','path':'/health/live','port':'https','httpHeaders':[{'name':'Host','value':urlsplit(origin).hostname}]}, 'periodSeconds': 10},
                                      'volumeMounts': [{'name': 'config', 'mountPath': '/etc/sandbox', 'readOnly': True},
                                                       {'name': 'tls', 'mountPath': '/tls', 'readOnly': True},
                                                       {'name': 'api-ca', 'mountPath': '/api-ca', 'readOnly': True},
                                                       {'name': 'tmp', 'mountPath': '/tmp'}]}],
                      'volumes': [{'name': 'config', 'configMap': {'name': config_name}},
                                  {'name': 'tls', 'secret': {'secretName': tls_secret, 'defaultMode': 288}},
                                  {'name': 'api-ca', 'configMap': {'name': ca_name, 'defaultMode': 292}},
                                  {'name': 'tmp', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '32Mi'}}],
                      'topologySpreadConstraints': [{'maxSkew': 1, 'topologyKey': 'kubernetes.io/hostname',
                                                     'whenUnsatisfiable': 'DoNotSchedule', 'labelSelector': {'matchLabels': labels}}]}}}},
        {'apiVersion': 'v1', 'kind': 'Service', 'metadata': meta('sandbox-console'),
         'spec': {'type': 'ClusterIP', 'selector': labels,
                  'ports': [{'name': 'https', 'port': 443, 'targetPort': 'https'}]}},
        {'apiVersion': 'policy/v1', 'kind': 'PodDisruptionBudget', 'metadata': meta('sandbox-console'),
         'spec': {'minAvailable': 1, 'selector': {'matchLabels': labels}}},
        {'apiVersion': 'cilium.io/v2', 'kind': 'CiliumNetworkPolicy', 'metadata': meta('sandbox-console'),
         'spec': {'endpointSelector': {'matchLabels': {'k8s:app.kubernetes.io/name': 'sandbox-console', 'k8s:sandbox.platform/network-policy': 'console-v1'}},
                  'ingress': [{'fromEntities': ['host'], 'toPorts': [{'ports': [{'port': '8443', 'protocol': 'TCP'}]}]}]
                    + ([{'fromCIDR': networks, 'toPorts': [{'ports': [{'port': '8443', 'protocol': 'TCP'}]}]}] if networks else [])
                    + ([{'fromEndpoints': proxies, 'toPorts': [{'ports': [{'port': '8443', 'protocol': 'TCP'}]}]}] if proxies else []),
                  'egress': [
                      {'toEndpoints': [{'matchLabels': {'k8s:io.kubernetes.pod.namespace': 'kube-system', 'k8s:k8s-app': 'kube-dns'}}],
                       'toPorts': [{'ports': [{'port': '53', 'protocol': 'ANY'}], 'rules': {'dns': [{'matchName': 'sandbox-api.sandbox-system.svc.cluster.local'}]}}]},
                      {'toEndpoints': [{'matchLabels': {'k8s:io.kubernetes.pod.namespace': 'sandbox-system', 'k8s:app.kubernetes.io/name': 'sandbox-api', 'k8s:sandbox.platform/network-policy': 'api-v1'}}],
                       'toPorts': [{'ports': [{'port': '8443', 'protocol': 'TCP'}]}]}
                  ]}}
    ]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--public-origin', required=True)
    p.add_argument('--api-upstream', required=True)
    p.add_argument('--image')
    p.add_argument('--namespace', default='sandbox-system')
    p.add_argument('--tls-secret', default='sandbox-console-tls')
    p.add_argument('--api-ca-file', type=Path, help='reviewed public CA PEM for the fixed API upstream')
    p.add_argument('--ingress-cidr', action='append', default=[], help='reviewed LB/client source CIDR, minimum /24 IPv4 or /64 IPv6')
    p.add_argument('--ingress-proxy', action='append', default=[], help='reviewed ingress namespace/app.kubernetes.io/name')
    p.add_argument('--nginx-only', action='store_true')
    a = p.parse_args()
    try:
        if a.nginx_only:
            print(configuration(a.public_origin, a.api_upstream), end='')
        else:
            require(a.image, '--image with digest required')
            require(a.api_ca_file, '--api-ca-file required')
            with a.api_ca_file.open('rb') as source:
                api_ca = source.read(65537).decode('ascii')
            print(json.dumps(manifests(a.public_origin, a.api_upstream, a.image, a.namespace, a.tls_secret, api_ca, a.ingress_cidr, a.ingress_proxy), indent=2))
    except (ValueError, OSError, UnicodeError) as exc:
        p.error(str(exc))


if __name__ == '__main__':
    main()
