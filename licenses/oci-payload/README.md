# OCI payload decoder licenses

These five files are exact, unmodified upstream MIT license texts, including all
original copyright notices. This distribution selects MIT from each crate's
available license alternatives. The root project license does not replace them.

Each text was copied from the locally cached published crate and independently
matched to that `.crate` archive member. SHA-256 of the archive matches its
registry entry in Cargo.lock. No crate source or license text was edited.

| Crate | Upstream license expression | Selected original file | Bundled file | License SHA-256 |
| --- | --- | --- | --- | --- |
| flate2 1.1.10 | MIT OR Apache-2.0 | LICENSE-MIT | [flate2-1.1.10-MIT.txt](flate2-1.1.10-MIT.txt) | `025436edff4cfcdde17a5811fdea78892d8482efd1abdec5a17872d07a4f2112` |
| crc32fast 1.5.2 | MIT OR Apache-2.0 | LICENSE-MIT | [crc32fast-1.5.2-MIT.txt](crc32fast-1.5.2-MIT.txt) | `61d383b05b87d78f94d2937e2580cce47226d17823c0430fbcad09596537efcf` |
| miniz_oxide 0.9.1 | MIT OR Zlib OR Apache-2.0 | LICENSE-MIT.md | [miniz_oxide-0.9.1-MIT.txt](miniz_oxide-0.9.1-MIT.txt) | `799e9ca9d179295ef372f25d3769cdda7d25bb2668add6a6a1e22d1e4c678b8d` |
| adler2 2.0.1 | 0BSD OR MIT OR Apache-2.0 | LICENSE-MIT | [adler2-2.0.1-MIT.txt](adler2-2.0.1-MIT.txt) | `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3` |
| simd-adler32 0.3.10 | MIT | LICENSE.md | [simd-adler32-0.3.10-MIT.txt](simd-adler32-0.3.10-MIT.txt) | `42a35170233e83e18856792e748de4c1ce4a63b2afce9a370c89ef3fe23f9f2d` |

Published archive sources and SHA-256:

- [flate2 1.1.10](https://static.crates.io/crates/flate2/flate2-1.1.10.crate): `6e634e2e0ebac1ee034020da1ca582e17ffe4e0f5e985823721e168928136dcb`
- [crc32fast 1.5.2](https://static.crates.io/crates/crc32fast/crc32fast-1.5.2.crate): `01a7799fd6b852db0e61728dde9a204c423b44d689dbd432522543614b490e78`
- [miniz_oxide 0.9.1](https://static.crates.io/crates/miniz_oxide/miniz_oxide-0.9.1.crate): `b63fbc4a50860e98e7b2aa7804ded1db5cbc3aff9193adaff57a6931bf7c4b4c`
- [adler2 2.0.1](https://static.crates.io/crates/adler2/adler2-2.0.1.crate): `320119579fcad9c21884f5c4861d16174d0e06250625266f50fe6898340abefa`
- [simd-adler32 0.3.10](https://static.crates.io/crates/simd-adler32/simd-adler32-0.3.10.crate): `3a219298ac11a56ea9a6d2120044824d6f01aeb034955e7af7bc16858527deea`

The dedicated release producer checks these fixed versions, registry origin and
archive checksums against the source Cargo.lock, and authenticates the full
selected license bytes before emitting `oci-payload-notices.json`. Release v5
requires that notice in its signed inventory and installed artifact directory.
Both host-binary export paths and both runtime image paths include this directory
and the generated notice. Existing SQLx and native protocol notices keep their
separate contracts.
