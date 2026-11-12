# syntax=docker/dockerfile:1.7
#
# RedForge — multi-stage image.
#
#   builder  : full toolchain (node + dev types) compiles the Vite bundle
#   runtime  : nginx-unprivileged serving the static bundle on :8080
#
# The app is 100 % client-side: no API, no database, no secret to inject.
# The final image therefore contains only static files and an nginx binary.

# ---------------------------------------------------------------------------
# Stage 1 — dependencies
# ---------------------------------------------------------------------------
FROM node:22-alpine AS deps

WORKDIR /app

# `npm ci` needs both the manifest and the lockfile, nothing else, so this
# layer is cached until a dependency actually changes.
COPY package.json package-lock.json ./

# --ignore-scripts keeps third-party install hooks from running in the build
# sandbox; none of these packages need one.
RUN --mount=type=cache,target=/root/.npm \
    npm ci --ignore-scripts --no-audit --no-fund

# ---------------------------------------------------------------------------
# Stage 2 — build
# ---------------------------------------------------------------------------
FROM node:22-alpine AS builder

WORKDIR /app

ENV NODE_ENV=production \
    CI=true

COPY --from=deps /app/node_modules ./node_modules
COPY package.json package-lock.json tsconfig.json vite.config.ts index.html ./
COPY public ./public
COPY src ./src
COPY scripts ./scripts

# `npm run build` invokes `tsc -b` first: a type error fails the image build
# rather than shipping broken output.
RUN npm run build \
 && test -f dist/index.html \
 && test -d dist/assets

# ---------------------------------------------------------------------------
# Stage 3 — runtime
# ---------------------------------------------------------------------------
FROM nginxinc/nginx-unprivileged:1.27-alpine AS runtime

LABEL org.opencontainers.image.title="RedForge" \
      org.opencontainers.image.description="Offline red-team toolkit — 77 browser-side tools for recon, exploitation, credentials, crypto, encoding, social engineering and reporting." \
      org.opencontainers.image.source="https://github.com/redforge/toolkit" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="nginxinc/nginx-unprivileged:1.27-alpine"

# The unprivileged image already runs as uid 101 and listens on 8080.
# mode 0644 is required: the container runs as uid 101 with every capability
# dropped, and a 0600 source file would be unreadable to that user.
COPY --chmod=0644 nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder --chown=101:101 /app/dist /usr/share/nginx/html

# Everything is baked in; nothing is written at run time.
ENV NGINX_ENTRYPOINT_QUIET_LOGS=1

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://127.0.0.1:8080/healthz || exit 1

STOPSIGNAL SIGQUIT

CMD ["nginx", "-g", "daemon off;"]
