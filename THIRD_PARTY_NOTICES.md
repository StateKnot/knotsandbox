# Third-party notices

KnotSandbox's original code, documentation and configuration are licensed under
the root [MIT License](LICENSE). This does not replace licenses attached to
third-party source, generated code, schemas or dependencies.

## Kubernetes Container Runtime Interface

`vendor/cri/v0.36.4/api.proto` is from Kubernetes CRI API v0.36.4.
Copyright 2020 The Kubernetes Authors. It retains the Apache License 2.0;
see [the bundled license](vendor/cri/v0.36.4/LICENSE) and
[provenance](vendor/cri/v0.36.4/README.md).

`src/nodeguard/generated/runtime.v1.rs` is generated from that upstream protocol
definition and is included in this third-party attribution. The generation tool
is project code; the upstream definition and its derived generated content
retain their Apache-2.0 provenance.

## containerd native metadata protocol

`vendor/containerd/v2.3.5/` retains the official containerd images/content
protocol definitions, their notices and [Apache License 2.0](vendor/containerd/v2.3.5/LICENSE).
[Provenance and fixed digests](vendor/containerd/v2.3.5/README.md) identify the
unchanged inputs. The derived `containerd.*.rs` messages in
`src/nodeguard/generated/` retain that attribution. Generated `google.protobuf.rs`
well-known types derive from the fixed Google protobuf definitions in
`vendor/protobuf/protoc-bin-vendored-3.2.0/`; their original copyright,
BSD three-clause conditions and disclaimer are retained in the definitions and
[bundled license](vendor/protobuf/protoc-bin-vendored-3.2.0/LICENSE). Project MIT does not
replace these third-party licenses.

## Keycloak schemas

`deploy/identity/vendor/26.8.0/` contains upstream Keycloak resources used for
offline validation. Their original notices and
[Apache License 2.0](deploy/identity/vendor/26.8.0/LICENSE.txt) remain in place.
Sources and digests are recorded in `deploy/identity/versions.lock.json`.

## CiliumNetworkPolicy schema

`deploy/identity/vendor/cilium-1.20.2-cnp.yaml` is the upstream CiliumNetworkPolicy
CRD used for offline validation. Copyright Authors of Cilium.
License: [Apache-2.0](licenses/Apache-2.0.txt). The upstream CRD bytes remain
unchanged; source and digest are recorded in `deploy/identity/versions.lock.json`.

Upstream: [Cilium v1.20.2](https://github.com/cilium/cilium/tree/v1.20.2),
[license](https://github.com/cilium/cilium/blob/v1.20.2/LICENSE),
[CRD](https://github.com/cilium/cilium/blob/v1.20.2/pkg/k8s/apis/cilium.io/client/crds/v2/ciliumnetworkpolicies.yaml).

## Build and runtime dependencies

`vendor/sqlx-postgres/` contains the published SQLx Postgres 0.8.6 crate with a
narrow backport of the upstream cancelled-BEGIN rollback fix. The original
[MIT](vendor/sqlx-postgres/LICENSE-MIT) and
[Apache-2.0](vendor/sqlx-postgres/LICENSE-APACHE) notices are retained.
[Patch provenance](vendor/sqlx-postgres/KNOTSANDBOX-PATCH.md) and the complete
[source digest inventory](vendor/sqlx-postgres/upstream.lock.json) identify the
original package and the single modified source file. The crate keeps its
original version and license; project MIT does not replace them.

Rust, JavaScript and deployment dependencies retain their own licenses and
copyrights, including applicable MIT, Apache, BSD, MPL and Unicode licenses.
The lockfiles identify dependency versions. This source repository does not
relicense dependencies or distribute build caches, `node_modules` or container
images. Binary and container distributions must include the notices required by
their actual dependency sets.
