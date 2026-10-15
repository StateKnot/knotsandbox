# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df AS build
WORKDIR /build/console
COPY console/package.json console/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY sdk/typescript/src/schema.d.ts sdk/typescript/src/resource-observation.ts \
     sdk/typescript/src/events.ts sdk/typescript/src/event-message.ts \
     sdk/typescript/src/sse.ts sdk/typescript/src/transport.ts /build/sdk/typescript/src/
COPY console/index.html console/tsconfig.json console/vite.config.ts ./
COPY console/src ./src
COPY console/scripts/prepare-assets.mjs ./scripts/prepare-assets.mjs
COPY console/release-assets ./release-assets
ARG SANDBOX_CONSOLE_FIRST_RELEASE=false
RUN mkdir -p release-assets/npm-inventory && npm run build && node scripts/prepare-assets.mjs dist release-assets "${SANDBOX_CONSOLE_FIRST_RELEASE}"
FROM nginxinc/nginx-unprivileged:1.30.5-alpine-slim@sha256:3af0c10d960cc2502427fe1219c52989d309e7d65596869c60a34fd2fa2406f0
ADD --checksum=sha256:63aeea03c15a2f9018f81805cfc8aa926bdf5cd68921f22149c2fbb5d0ee9f47 https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/zlib-1.3.2-r1.apk /tmp/security/x86_64-zlib-1.3.2-r1.apk
ADD --checksum=sha256:1f77a542ac6634761b9fe38d8bdca19b154071dcfa25432e73f2bc8a0740a33f https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/zlib-1.3.2-r1.apk /tmp/security/aarch64-zlib-1.3.2-r1.apk
ARG TARGETARCH
USER 0:0
RUN --network=none case "$TARGETARCH" in \
    amd64) apk_arch=x86_64; test -f "/etc/apk/keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub" ;; \
    arm64) apk_arch=aarch64; test -f "/etc/apk/keys/alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub" ;; \
    *) exit 1 ;; esac \
    && apk add --no-network --repositories-file /dev/null "/tmp/security/${apk_arch}-zlib-1.3.2-r1.apk" \
    && test "$(apk --no-network --repositories-file /dev/null info -v | sed -n '/^zlib-[0-9]/p')" = "zlib-1.3.2-r1" \
    && rm -rf /tmp/security
COPY --from=build /build/console/dist/ /usr/share/nginx/html/
COPY --from=build /build/console/package.json /build/console/package-lock.json /usr/share/sandbox-console/
COPY --from=build /build/console/release-assets/npm-inventory/ /usr/share/sandbox-console/retained/
USER 101:101
EXPOSE 8443
ENTRYPOINT ["nginx"]
CMD ["-g", "daemon off;", "-c", "/etc/sandbox/nginx.conf"]
