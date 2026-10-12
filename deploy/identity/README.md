# Production identity package

See [identity-production.md](../../docs/identity-production.md) for prerequisites, exact installation order, operational controls and verification limits.

- `identity.py render`: strict two-mode configuration; no cluster changes or secret reads.
- `identity.py install --execute`: verified official Operator, guarded Secret creation, TLS and installed-proxy checks. Add `--initialize-realm` **only for the initial realm**. This does not bootstrap cloud infrastructure.
- `verify.py`: read-only Keycloak Admin REST policy verification through the private TLS origin; no email is sent.
- `Dockerfile.proxy` / `prepare_proxy.py`: pinned upstream-source, offline proxy image build; installer creates proxy Kubernetes resources before Keycloak. `check-proxy-image.sh` verifies non-root/read-only TLS config loading.
- `check.sh`: 19 unit/negative tests plus official Kubernetes/Keycloak/Cilium schema validation; uses the existing locked cluster Python environment/schema cache.
- `live-test.sh` with `IDENTITY_ADMIN_CHAIN=true HAPROXY_BIN=/path/to/haproxy`: actual Keycloak+HAProxy private master frontend/login chain; no shared database.
- `live-test.sh`: disposable local Keycloak **26.8.0**, native TLS and isolated test database; no shared PostgreSQL. Requires the pinned image already cached; removes its container on exit.
- `tests/live_proxy.py /absolute/path/haproxy`: actual HAProxy **3.2.25** dual-hop TLS and path/header rejection checks, using loopback only.

`settings.example.json` intentionally contains an invalid proxy image placeholder and nonexistent credential paths. A production installation must provide a reviewed digest and actual independent secrets. It will not silently use sample passwords, download a mutable image, disable TLS, or install an unverified ingress controller.

Upstream Keycloak 26.8.0 resources are verbatim under `vendor/26.8.0`, licensed under Apache-2.0 (`LICENSE.txt`). Renderer changes only the installation namespace, image references, and operator scheduling. The Cilium CRD is vendored solely for offline schema validation, not installed by this package. All vendored bytes are SHA256 pinned in `versions.lock.json`.
