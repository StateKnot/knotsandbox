# Fixed containerd native metadata protocol

Official tag: `containerd/containerd v2.3.5`. These are unchanged upstream
Apache-2.0 sources; copyright notices remain in each file and LICENSE is kept.

| File | Official source | SHA256 |
| --- | --- | --- |
| `api/services/images/v1/images.proto` | https://github.com/containerd/containerd/blob/v2.3.5/api/services/images/v1/images.proto | `f7943198b308917555040e524251f06d9262b917f856a771159253c51635b056` |
| `api/services/content/v1/content.proto` | https://github.com/containerd/containerd/blob/v2.3.5/api/services/content/v1/content.proto | `70aadb447ff3157da276afecc355a5a58ef2e322eb7530d5c2868734d626eea8` |
| `api/types/descriptor.proto` | https://github.com/containerd/containerd/blob/v2.3.5/api/types/descriptor.proto | `f98bec409b5e535e2a8d81dacc549180e1dadb31bd6ac46f7aedc6ab0020e447` |
| `api/services/snapshots/v1/snapshots.proto` | https://github.com/containerd/containerd/blob/v2.3.5/api/services/snapshots/v1/snapshots.proto | `6e23ec19b971e1088f3984b7a07ee4238d6ad56b85173750c38b0c911803bc23` |
| `api/types/mount.proto` | https://github.com/containerd/containerd/blob/v2.3.5/api/types/mount.proto | `c7a31fa848f002cead05a23adfdd9e29a459cd01ae573b7b61b060b3056754d7` |
| `LICENSE` | https://github.com/containerd/containerd/blob/v2.3.5/LICENSE | `4bbe3b885e8cd1907ab4cf9a41e862e74e24b5422297a4f2fe524e6a30ada2b4` |

Regenerate offline with the existing independent locked tool:

```sh
cargo run --locked --offline --manifest-path tools/cri-codegen/Cargo.toml -- --containerd
```

The tool pins prost-build 0.14.4, tonic-prost-build 0.14.6 and
protoc-bin-vendored 3.2.0. It generates messages and the required well-known
protobuf types into `src/nodeguard/generated`; normal product builds do not
generate code, download sources or require a runtime prost-types dependency.
Generated native messages remain private inside `native_image_metadata`.
There is no generated Images/Content/Snapshots client or server: production can
call only the adapter's fixed read paths, including Snapshots.Stat. Mount messages
are derived protocol dependencies, not permission to mount or prepare snapshots.

Images.Get supplies shallow name/target metadata, not a guarantee that image
content or snapshots exist. Content.Read uses a byte range, not an expected
object length; the adapter therefore checks Content.Info and the complete
bounded stream, then uses the shared OCI metadata verifier. Namespace is the
fixed `containerd-namespace: k8s.io` header. No lease, pull, unpack, mutation,
layer payload or preparation authority is provided.
