"""Native HAProxy re-encryption contract for the platform-owned ingress tier."""
from urllib.parse import urlsplit


def configuration(s):
    public = urlsplit(s['public_url']).hostname
    admin = urlsplit(s['admin_url']).hostname
    # Platform ingress mounts a cert/key PEM covering both names and the backend CA.
    # Separate listeners prevent public ingress routing from reaching admin paths.
    common = '''  http-request del-header Forwarded
  http-request del-header X-Forwarded-For
  http-request del-header X-Forwarded-Proto
  http-request del-header X-Forwarded-Host
  http-request del-header X-Forwarded-Port
  http-request del-header X-Forwarded-Prefix
  http-request del-header X-Original-Forwarded-For
  http-request del-header X-Original-URL
  http-request del-header X-Original-Method
  http-request del-header X-Forwarded-Access-Token
  http-request del-header X-Real-IP
  http-request del-header traceparent
  http-request del-header tracestate
  http-request del-header baggage
  http-request set-header X-Forwarded-For %[src]
  http-request set-header X-Forwarded-Proto https
  http-request set-header X-Forwarded-Port 443
'''
    return f'''# Rendered production contract; validate with the deployed HAProxy binary: haproxy -c -f this-file.
# No PROXY protocol or forwarded input is trusted. The fronting LB must preserve source addresses.
# Public LB -> 8443; private administration LB -> 9443; neither proxies Keycloak management 9000.
global
  log stdout format raw local0
  maxconn 4096
  ssl-default-bind-options ssl-min-ver TLSv1.2
  ssl-default-server-options ssl-min-ver TLSv1.2

defaults
  mode http
  log global
  log-format "%ci:%cp [%t] %ft %b/%s %ST %B %HM"
  timeout connect 5s
  timeout client 60s
  timeout server 60s
  timeout http-request 10s
  timeout http-keep-alive 10s

resolvers kube
  parse-resolv-conf
  timeout resolve 2s
  timeout retry 1s
  hold valid 10s

frontend identity_public
  bind :8443 ssl crt /run/identity-tls/frontend.pem alpn h2,http/1.1
  http-request deny deny_status 400 unless {{ hdr(host) -i {public} {public}:443 }}
  # Reject ambiguous encodings/separators before an exact ASCII realm path allowlist.
  http-request deny deny_status 400 if {{ path -m sub % ; }}
  http-request deny deny_status 400 if {{ path -m reg [\\\\] }}
  http-request deny deny_status 400 if {{ path -m reg /[.][.]?(/|$) }}
  http-request deny deny_status 404 unless {{ path_beg /realms/{s['realm']}/ /resources/ }}
{common}  http-request set-header X-Forwarded-Host {public}
  default_backend keycloak_tls

frontend identity_admin
  bind :9443 ssl crt /run/identity-tls/frontend.pem alpn h2,http/1.1
  http-request deny deny_status 403 unless {{ src {' '.join(s['admin_cidrs'])} }}
  http-request deny deny_status 400 unless {{ hdr(host) -i {admin} {admin}:443 }}
{common}  http-request set-header X-Forwarded-Host {admin}
  default_backend keycloak_tls

backend keycloak_tls
  # CA validation AND fixed hostname verification; no insecure backend mode.
  server keycloak keycloak-service.{s['namespace']}.svc.cluster.local:8443 ssl verify required ca-file /run/identity-tls/backend-ca.pem verifyhost {public} sni str({public}) check resolvers kube init-addr last,libc,none
'''
