# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS runtime-files
# Use the already locked Debian Python/OpenSSL packages; no apt, pip or runtime download.
RUN mkdir -p /out/usr/local/bin /out/usr/bin /out/usr/lib \
 && cp /usr/bin/python3.11 /out/usr/local/bin/python3 \
 && cp /usr/bin/openssl /out/usr/bin/openssl \
 && cp -a /usr/lib/python3.11 /out/usr/lib/ \
 && { ldd /usr/bin/python3.11; ldd /usr/bin/openssl; find /usr/lib/python3.11/lib-dynload -name '*.so' -exec ldd '{}' ';'; } \
    | awk '/=> \// {print $3} /^\// {print $1}' | sort -u > /tmp/python-libs \
 && while read -r library; do target_dir="$(readlink -f "$(dirname "$library")")"; mkdir -p "/out$target_dir"; cp -L "$library" "/out$target_dir/$(basename "$library")"; done < /tmp/python-libs \
 && find /out -name __pycache__ -type d -prune -exec rm -rf '{}' '+'
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS python-runtime
COPY --from=runtime-files /out/ /
COPY --from=runtime-files /etc/ssl/certs/ /etc/ssl/certs/
COPY --from=runtime-files /etc/ssl/openssl.cnf /usr/lib/ssl/openssl.cnf
COPY --from=runtime-files /usr/share/doc/python3.11/copyright /usr/share/doc/sandbox-backup/python-copyright
COPY --from=runtime-files /usr/share/doc/openssl/copyright /usr/share/doc/sandbox-backup/openssl-copyright
ENV PYTHONDONTWRITEBYTECODE=1 SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
RUN /usr/local/bin/python3 -c 'import ssl,hashlib,json,fcntl,selectors,sqlite3; assert ssl.create_default_context().cert_store_stats()["x509_ca"] > 0' \
 && /usr/bin/openssl version
FROM python-runtime
COPY --chmod=0555 restic rclone /usr/local/bin/
COPY --chmod=0444 backup.py inventory.py reader_credentials.py /app/
COPY --chmod=0444 licenses/ /usr/share/doc/sandbox-backup/licenses/
RUN /usr/local/bin/python3 -c 'import ssl,hashlib,json,fcntl,selectors,sqlite3' \
 && /usr/local/bin/restic version && /usr/local/bin/rclone version && /usr/bin/openssl version
# UID 0 only in the certified Kata guest; capabilities ALL dropped, no mounts/syscalls privilege.
USER 0:0
ENTRYPOINT ["/usr/local/bin/python3", "/app/backup.py"]
