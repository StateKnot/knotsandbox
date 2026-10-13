# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Verified OCI index digests; update only through the release validation pipeline.
ARG RUST_IMAGE=rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e
ARG RUNTIME_IMAGE=debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
ARG SERVICE_IMAGE=gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2

FROM ${RUST_IMAGE} AS builder
ARG TARGETARCH
ARG SOURCE_DATE_EPOCH
ENV RUSTUP_TOOLCHAIN=1.98.1
ENV CARGO_BUILD_JOBS=1
WORKDIR /build
COPY . .
RUN test "${TARGETARCH}" = amd64 \
    && printf '%s  %s\n' 714d457d580922dbf1d0be8bd35ba236a842b50b0072ae791582a19adef772a5 /etc/ssl/certs/ca-certificates.crt | sha256sum -c - \
    && python3 /build/scripts/verify-sqlx-postgres-patch.py
# SQLite is linked from independently verified official source. Never probe an
# ambient system library or fall back to the older source in libsqlite3-sys.
ADD --checksum=sha256:0e9483900e92cd5de8fd48d16bf9200145a61f7fd5be542a5ac81d8a9516eb9c https://www.sqlite.org/2026/sqlite-autoconf-3530400.tar.gz /tmp/sqlite-source.tar.gz
RUN --network=none python3 /build/scripts/release/sqlite_build.py --archive /tmp/sqlite-source.tar.gz --destination /opt/sandbox-sqlite \
    && rm /tmp/sqlite-source.tar.gz
ENV SANDBOX_PRODUCTION_NATIVE=1
ENV LIBSQLITE3_SYS_USE_PKG_CONFIG=1 SQLITE3_NO_PKG_CONFIG=1 SQLITE3_STATIC=1
ENV SQLITE3_LIB_DIR=/opt/sandbox-sqlite/lib SQLITE3_INCLUDE_DIR=/opt/sandbox-sqlite/include
# External native archives are not tracked by libsqlite3-sys's build script.
# Invalidate that one rlib before a new build stage; it must embed this archive.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/target,id=sandbox-rust-1.98.1-${TARGETARCH},sharing=locked \
    cargo fetch --locked --target x86_64-unknown-linux-gnu \
    && cargo clean --locked --offline --release -p libsqlite3-sys \
    && cargo build --locked --release --bin sandboxd --bin sandbox-admin --bin sandbox-admission --bin sandbox-runner --bin sandbox-nodeguard --bin sandbox-backup-worm --bin sandbox-credentials --bin sandbox-automation --message-format=json-render-diagnostics > /opt/sandbox-sqlite/evidence/production-cargo.json \
    && mkdir -p /artifacts \
    && cp target/release/sandboxd target/release/sandbox-admin target/release/sandbox-admission target/release/sandbox-runner target/release/sandbox-nodeguard target/release/sandbox-backup-worm target/release/sandbox-credentials target/release/sandbox-automation /artifacts/ \
    && python3 /build/scripts/release/sqlite_build.py --capture-link-output --destination /opt/sandbox-sqlite/evidence

# Export the host service binary with buildx --target nodeguard-export --output.
# It runs under systemd on certified Kata nodes, not inside an application Pod.
FROM scratch AS nodeguard-export
COPY --from=builder /artifacts/sandbox-nodeguard /sandbox-nodeguard
COPY vendor/sqlx-postgres/LICENSE-MIT vendor/sqlx-postgres/LICENSE-APACHE vendor/sqlx-postgres/upstream.lock.json vendor/sqlx-postgres/KNOTSANDBOX-PATCH.md /licenses/sqlx-postgres/

FROM scratch AS binaries-export
COPY --from=builder /artifacts/ /
COPY Cargo.lock /Cargo.lock
COPY vendor/sqlx-postgres/LICENSE-MIT vendor/sqlx-postgres/LICENSE-APACHE vendor/sqlx-postgres/upstream.lock.json vendor/sqlx-postgres/KNOTSANDBOX-PATCH.md /licenses/sqlx-postgres/

FROM ${RUNTIME_IMAGE} AS runner
# Reviewed security fixes are content-addressed; dpkg uses no package resolver/network.
ADD --checksum=sha256:ff16bc048bcd7d1b256094450b79c77947d8e76fe2a24bd99b91021d591fa074 https://security.debian.org/debian-security/pool/updates/main/o/openssl/libssl3t64_3.5.7-1~deb13u3_amd64.deb /tmp/security/libssl3t64_3.5.7-1~deb13u3_amd64.deb
ADD --checksum=sha256:c12e0266c4780749a4702b8959ac979689f4182e18eed85a8a5eb90ed0e16eab https://security.debian.org/debian-security/pool/updates/main/o/openssl/openssl-provider-legacy_3.5.7-1~deb13u3_amd64.deb /tmp/security/openssl-provider-legacy_3.5.7-1~deb13u3_amd64.deb
ADD --checksum=sha256:e226f661d918f04daf38cdbc4806b7ed7d6ef95c7eb0ade692fc350e31970040 https://security.debian.org/debian-security/pool/updates/main/p/pcre2/libpcre2-8-0_10.46-1~deb13u3_amd64.deb /tmp/security/libpcre2-8-0_10.46-1~deb13u3_amd64.deb
RUN --network=none dpkg -i /tmp/security/*.deb \
    && test "$(dpkg-query -W -f='${Version}' libssl3t64)" = '3.5.7-1~deb13u3' \
    && test "$(dpkg-query -W -f='${Version}' openssl-provider-legacy)" = '3.5.7-1~deb13u3' \
    && test "$(dpkg-query -W -f='${Version}' libpcre2-8-0)" = '10.46-1~deb13u3' \
    && rm -rf /tmp/security
COPY scripts/release/debian-security.lock.json /usr/share/sandbox-platform/debian-security.lock.json
RUN test "$(dpkg-query -W -f='${Version}' libgcc-s1)" = '14.2.0-19' \
    && groupadd --gid 1000 sandbox \
    && useradd --uid 1000 --gid 1000 --no-create-home --shell /usr/sbin/nologin sandbox \
    && mkdir -p /workspace \
    && chown 1000:1000 /workspace
COPY --from=builder --chown=root:root /artifacts/sandbox-runner /usr/local/bin/sandbox-runner
COPY Cargo.lock /usr/share/sandbox-platform/Cargo.lock
COPY vendor/sqlx-postgres/LICENSE-MIT vendor/sqlx-postgres/LICENSE-APACHE vendor/sqlx-postgres/upstream.lock.json vendor/sqlx-postgres/KNOTSANDBOX-PATCH.md /usr/share/sandbox-platform/licenses/sqlx-postgres/
RUN chmod 0555 /usr/local/bin/sandbox-runner
USER 1000:1000
WORKDIR /workspace
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/sandbox-runner"]
CMD ["idle"]

# The control plane needs no shell, package manager, Perl or login utilities.
# Keep upstream package metadata; scanners must still see every library.
FROM ${SERVICE_IMAGE} AS runtime
COPY --from=builder --chown=root:root /artifacts/sandboxd /usr/local/bin/sandboxd
COPY --from=builder --chown=root:root /artifacts/sandbox-admin /usr/local/bin/sandbox-admin
COPY --from=builder --chown=root:root /artifacts/sandbox-admission /usr/local/bin/sandbox-admission
COPY --from=builder --chown=root:root /artifacts/sandbox-backup-worm /usr/local/bin/sandbox-backup-worm
COPY --from=builder --chown=root:root /artifacts/sandbox-credentials /usr/local/bin/sandbox-credentials
COPY --from=builder --chown=root:root /artifacts/sandbox-automation /usr/local/bin/sandbox-automation
COPY Cargo.lock /usr/share/sandbox-platform/Cargo.lock
COPY vendor/sqlx-postgres/LICENSE-MIT vendor/sqlx-postgres/LICENSE-APACHE vendor/sqlx-postgres/upstream.lock.json vendor/sqlx-postgres/KNOTSANDBOX-PATCH.md /usr/share/sandbox-platform/licenses/sqlx-postgres/
USER 10001:10001
WORKDIR /tmp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/sandboxd"]
