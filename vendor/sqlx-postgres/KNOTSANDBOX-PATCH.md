# SQLx Postgres cancellation fix

This is the published sqlx-postgres 0.8.6 crate, verified against the original Cargo.lock archive SHA-256. Only `src/transaction.rs` differs: reserve transaction depth before awaiting BEGIN and undo it when BEGIN did not enter a transaction. The narrow backport follows [upstream commit f1e94ec34dd5f11ad6488a3a8ac7988439a3f757](https://github.com/transact-rs/sqlx/commit/f1e94ec34dd5f11ad6488a3a8ac7988439a3f757).

The crate version remains 0.8.6; the path dependency is intentionally visible in Cargo.lock. `upstream.lock.json` records the original archive and every original file digest, plus the one patched digest. Run `python3 scripts/verify-sqlx-postgres-patch.py` before building. MIT and Apache-2.0 notices are retained. Runtime images retain the notices and patch provenance.

The required TLS PostgreSQL regression confirms a real cancelled BEGIN on the same physical ordinary-role connection, return to idle, subsequent autocommit visibility and transaction lock release. A dependency upgrade may replace this backport only after it contains the upstream fix and passes that regression and the complete product gates.
