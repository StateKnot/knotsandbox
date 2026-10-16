# Fixed protobuf well-known definitions

These three unchanged definitions are from the `include/google/protobuf/`
directory distributed in the locked `protoc-bin-vendored-*-3.2.0` crates.
The version here identifies the Rust distribution package, not the protobuf
schema version. The independent generator's `Cargo.lock` records those crate
checksums. All locally available platform distributions were compared and
contain identical bytes for these inputs.

`sources.sha256.json` records the individual source digests. Each source retains
Google's original copyright, BSD three-clause conditions and disclaimer;
`LICENSE` reproduces the common header. The native generator explicitly uses
these committed definitions, rather than ambient host protoc includes.
Their derived `google.protobuf.rs` is included in this attribution.

Upstream distribution: [protoc-bin-vendored 3.2.0](https://crates.io/crates/protoc-bin-vendored/3.2.0).
