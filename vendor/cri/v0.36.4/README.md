Kubernetes CRI v1 interface, official tag `kubernetes/cri-api/v0.36.4`.

- Source: https://github.com/kubernetes/cri-api/blob/v0.36.4/pkg/apis/runtime/v1/api.proto
- SHA256: `6d130c2651d335bfc755d25efc63072a1cd1eba3591ead6422dc0a27f20167f3`
- Copyright 2020 The Kubernetes Authors, Apache-2.0 (the notice remains in api.proto).
- Generated Rust: `src/nodeguard/generated/runtime.v1.rs`.
- Regenerate offline: `cargo run --locked --offline --manifest-path tools/cri-codegen/Cargo.toml`.
- CI regeneration checks the pinned input SHA256, regenerates with the independent locked toolchain, and requires a clean generated-file diff. Normal product builds never run a generator or contact the network.
