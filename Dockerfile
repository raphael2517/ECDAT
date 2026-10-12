# ECDAT - single image, two roles.
#   target `builder`  -> venv with every dependency
#   target `runtime`  -> final image (default)
#
# Written for the LEGACY docker builder: no --mount, no heredocs, no
# conditional COPY. This host has no buildx, so BuildKit syntax fails.
#
# Python 3.11 is deliberate: it is the newest version for which every pin in
# scanner/requirements.txt publishes a wheel. pydantic-core 2.9.x has no
# 3.12/3.13/3.14 wheels, so a newer base forces a source build.
#
# Build: docker build -t ecdat:latest .
# Run:   docker run --rm -v "$PWD/output:/app/output" ecdat:latest scan <target>

ARG PYTHON_VERSION=3.11-slim-bookworm
ARG NODE_VERSION=20-alpine

# ---------------------------------------------------------------------------
# STAGE 1 - builder: native build deps + venv
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION} AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/venv \
    PATH="/venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /venv

WORKDIR /build

# liboqs wheel is copied first so that layer caches independently
COPY bin/wheels/ /build/wheels/
COPY scanner/requirements.txt /build/requirements.txt

# "Zero external dependencies" is a RUNTIME guarantee, not a build-time one.
# --find-links resolves liboqs-python from the vendored wheelhouse; the rest
# comes from PyPI while the image is being built.
RUN /venv/bin/pip install --find-links /build/wheels -r /build/requirements.txt

COPY api/requirements.txt /build/api-requirements.txt
RUN /venv/bin/pip install -r /build/api-requirements.txt


# ---------------------------------------------------------------------------
# STAGE 2 - UI bundle (React + Vite)
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION} AS ui-builder

WORKDIR /ui
# Manifest first so `npm ci` is cached independently of source edits.
COPY ui/package.json ui/package-lock.json* ./
RUN npm install --no-audit --no-fund --loglevel=error
COPY ui/ ./
# vite.config.ts proxies /api in dev; in production nginx does it instead.
RUN npm run build


# ---------------------------------------------------------------------------
# STAGE 3 - runtime
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION} AS runtime

LABEL org.opencontainers.image.title="ECDAT" \
      org.opencontainers.image.description="Enterprise Cryptographic Discovery & Analysis Tool" \
      org.opencontainers.image.version="1.0.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/venv/bin:$PATH" \
    OQS_INSTALL_PATH=/opt/oqs \
    SEMGREP_BIN=/venv/bin/semgrep \
    SYFT_BIN=/usr/local/bin/syft \
    OUTPUT_DIR=/app/output \
    SCANNER_RULES_PATH=/app/scanner/rules \
    PYTHONPATH=/app \
    Z_ESTIMATE=15

# git is a hard runtime dependency, not a build-time one: ingesting a Git URL
# is a primary input type, and GitPython raises at import when git is absent
# from PATH (it does not fail gracefully on first use).
#
# Note there is no libssl/libbrotli/libzstd here. liboqs is built with
# OQS_USE_OPENSSL=OFF specifically so its .so links only libc; otherwise it
# records the build host's libcrypto symbol version and fails to load here.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        nginx \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /venv /venv

# Native liboqs. The liboqs-python wheel is pure Python: it ctypes-loads
# liboqs.so from $OQS_INSTALL_PATH at import time and silently falls back to
# `git clone && cmake` if it cannot find it, which needs network we do not have
# at runtime.
COPY bin/liboqs/ /opt/oqs/
COPY bin/syft /usr/local/bin/syft

COPY scanner/ /app/scanner/
COPY api/ /app/api/
COPY docker/ /app/docker/
COPY --from=ui-builder /ui/dist /var/www/html

COPY docker/nginx.conf /etc/nginx/nginx.conf

WORKDIR /app
RUN mkdir -p /app/output && chmod +x /app/docker/entrypoint.sh

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=3).status==200 else 1)" || exit 0

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["api"]
