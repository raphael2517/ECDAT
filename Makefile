# ECDAT - Enterprise Cryptographic Discovery & Analysis Tool
#
# Docker-first: everything the scanner needs is baked into the image. The only
# thing `setup` fetches is what must match the HOST architecture.

SHELL := /bin/bash
IMAGE   := ecdat:latest

# Compose is optional. This host has Docker but no Compose plugin, and plain
# `docker run` needs nothing extra - so the Makefile drives the container
# directly and compose is only a convenience for multi-service setups.
# docker-compose.yml still ships for users who prefer it.
COMPOSE := $(shell if docker compose version >/dev/null 2>&1; then echo "docker compose"; elif command -v docker-compose >/dev/null 2>&1; then echo "docker-compose"; else echo ""; fi)

# --- host architecture (drives which prebuilt binaries we need) --------------
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
  LIBOQS_PLATFORM := x86_64
else ifeq ($(ARCH),aarch64)
  LIBOQS_PLATFORM := arm64
else
  $(error Unsupported architecture: $(ARCH). ECDAT targets x86_64 and aarch64.)
endif

# --- config -----------------------------------------------------------------
ENV_FILE := .env
ifneq ($(wildcard $(ENV_FILE)),)
  include $(ENV_FILE)
  export
endif

OUTPUT_DIR    ?= ./output
Z_ESTIMATE    ?= 15
SCAN_TARGET   ?= .
# UI_PORT maps to nginx inside the container (which listens on 80). It is not
# 80 by default because host :80 is commonly taken and needs privileges.
UI_PORT       ?= 8080
API_PORT      ?= 8000
SEMGREP_VER   := 1.178.0
SYFT_VER      := 1.15.0
LIBOQS_VER    := 0.16.0
LIBOQS_KEMS   := KEM_ml_kem_768
# Must cover every mechanism REPLACEMENTS in recommender.py points at, or the
# recommendation table advertises something we cannot actually benchmark.
LIBOQS_SIGS   := SIG_ml_dsa_65;SIG_ml_dsa_87

# Artifacts the Dockerfile COPYs into the image. Only bin/liboqs is tracked in
# git (it is under 1 MB); bin/syft is a 43 MB linux/amd64 binary that is
# deliberately gitignored and fetched by `make setup`. Declaring this list on
# EVERY target that reaches `docker build` is what stops a fresh clone from
# failing at `COPY bin/syft /usr/local/bin/syft`.
VENDORED := bin/syft \
            bin/liboqs/lib/liboqs.so.0.16.0 \
            bin/wheels/liboqs_python-$(LIBOQS_VER)-py3-none-any.whl

.PHONY: help setup build up down scan rerisk logs health shell shell-scanner test test-unit test-e2e clean distclean verify

help:
	@echo "ECDAT - Enterprise Cryptographic Discovery & Analysis Tool"
	@echo ""
	@echo "  make setup     fetch host binaries + build the image"
	@echo "  make build     build the container image"
	@echo "  make up        start the API on http://localhost:8000"
	@echo "  make down      stop"
	@echo "  make scan      run one scan   (SCAN_TARGET=... make scan)"
	@echo "  make rerisk    re-rank a scan (ID=... Z=10 make rerisk)"
	@echo "  make test      run all tests in the container"
	@echo "  make logs      follow container logs"
	@echo "  make health    print the health payload"
	@echo "  make verify    check every required artifact is present"
	@echo "  make clean     remove generated CBOMs"
	@echo "  make distclean remove the image and downloaded binaries"
	@echo ""

# ---------------------------------------------------------------------------
# setup
# ---------------------------------------------------------------------------
setup: $(VENDORED) build
	@echo ""
	@echo "setup complete. Next:  make up"

bin/syft:
	@echo ">> fetching syft $(SYFT_VER) for linux_amd64"
	@mkdir -p bin
	curl -fsSL "https://github.com/anchore/syft/releases/download/v$(SYFT_VER)/syft_$(SYFT_VER)_linux_amd64.tar.gz" \
		| tar -xz -C bin syft
	@chmod +x bin/syft

# liboqs is compiled here, not downloaded, because the manylinux wheel does not
# exist for it. BUILD_SHARED_LIBS is required: liboqs-python is a pure-Python
# ctypes wrapper and cannot use the static liboqs.a.
# liboqs is compiled here, not downloaded, because no manylinux wheel exists
# for it. Two flags are load-bearing:
#   BUILD_SHARED_LIBS=ON - liboqs-python is a pure-Python ctypes wrapper and
#     cannot use the static liboqs.a.
#   OQS_USE_OPENSSL=OFF  - otherwise liboqs.so links the *build host's*
#     libcrypto and records its symbol version. Building on a host with
#     OpenSSL 3.3 and running in python:3.11-slim (OpenSSL 3.0) then fails at
#     load with "version `OPENSSL_3.3.0' not found". Disabling it makes the
#     artifact genuinely self-contained, which is the point of bin/liboqs/.
#     ML-KEM and ML-DSA use liboqs' own SHA-3 regardless.
bin/liboqs/lib/liboqs.so.0.16.0:
	@echo ">> building liboqs $(LIBOQS_VER) as a shared library (no OpenSSL)"
	@mkdir -p bin/liboqs
	@rm -rf /tmp/ecdat-liboqs
	@git clone --quiet --depth 1 --branch $(LIBOQS_VER) https://github.com/open-quantum-safe/liboqs.git /tmp/ecdat-liboqs
	@cd /tmp/ecdat-liboqs && mkdir -p build && cd build && \
		cmake -DCMAKE_BUILD_TYPE=Release \
		      -DBUILD_SHARED_LIBS=ON \
		      -DOQS_USE_OPENSSL=OFF \
		      -DCMAKE_INSTALL_PREFIX=/tmp/ecdat-oqs-stage \
		      -DOQS_MINIMAL_BUILD="$(LIBOQS_KEMS);$(LIBOQS_SIGS)" .. && \
		make -j$$(nproc) && make install
	@echo ">> verifying the shared lib has no unmet runtime deps"
	@ldd bin/liboqs/lib/liboqs.so.0.16.0 | grep -q "not found" && \
		{ echo "ERROR: liboqs.so has unresolved dependencies:"; \
		  ldd bin/liboqs/lib/liboqs.so.0.16.0 | grep "not found"; exit 1; } || true
	@cp -a /tmp/ecdat-oqs-stage/lib/liboqs.so* bin/liboqs/lib/
	@mkdir -p bin/liboqs/include bin/liboqs/lib/pkgconfig
	@cp -a /tmp/ecdat-oqs-stage/include/oqs bin/liboqs/include/
	@cp -a /tmp/ecdat-oqs-stage/lib/pkgconfig/liboqs.pc bin/liboqs/lib/pkgconfig/
	@rm -rf /tmp/ecdat-liboqs /tmp/ecdat-oqs-stage

bin/wheels/liboqs_python-$(LIBOQS_VER)-py3-none-any.whl:
	@echo ">> building liboqs-python wheel (pure python, $(LIBOQS_VER))"
	@mkdir -p bin/wheels
	@rm -rf /tmp/ecdat-liboqs-py
	@git clone --quiet --depth 1 --branch $(LIBOQS_VER) https://github.com/open-quantum-safe/liboqs-python.git /tmp/ecdat-liboqs-py
	@cd /tmp/ecdat-liboqs-py && python3 -m pip wheel --no-deps -w $(CURDIR)/bin/wheels . || \
	 pip wheel --no-deps -w $(CURDIR)/bin/wheels .
	@rm -rf /tmp/ecdat-liboqs-py

# ---------------------------------------------------------------------------
# image + lifecycle
# ---------------------------------------------------------------------------
build: $(VENDORED)
	@echo ">> building $(IMAGE)"
	@if [ -n "$(COMPOSE)" ]; then $(COMPOSE) build; else docker build -t $(IMAGE) --target runtime .; fi

up:
	@echo ">> starting ecdat"
	@if [ -n "$(COMPOSE)" ]; then \
		$(COMPOSE) up -d; \
	else \
		docker rm -f ecdat >/dev/null 2>&1 || true; \
		docker run -d --name ecdat \
			-p $(API_PORT):8000 \
			-p $(UI_PORT):80 \
			-v "$(CURDIR)/$(OUTPUT_DIR):/app/output" \
			-e Z_ESTIMATE=$(Z_ESTIMATE) \
			--restart unless-stopped \
			$(IMAGE) api >/dev/null; \
	fi
	@echo "   UI    http://localhost:$(UI_PORT)"
	@echo "   API   http://localhost:$(API_PORT)"
	@echo "   docs  http://localhost:$(API_PORT)/docs"

down:
	@if [ -n "$(COMPOSE)" ]; then $(COMPOSE) down; else docker rm -f ecdat >/dev/null 2>&1 || true; fi
	@echo ">> stopped"

logs:
	@if [ -n "$(COMPOSE)" ]; then $(COMPOSE) logs -f; else docker logs -f ecdat; fi

health:
	@curl -fsS http://localhost:8000/health | python3 -m json.tool

shell:
	@if [ -n "$(COMPOSE)" ]; then $(COMPOSE) exec ecdat /bin/sh; else docker exec -it ecdat /bin/sh; fi

shell-scanner:
	@if [ -n "$(COMPOSE)" ]; then $(COMPOSE) exec ecdat /bin/sh; else docker exec -it ecdat /bin/sh; fi

# ---------------------------------------------------------------------------
# tests
#
# pytest is not baked into the runtime image; it is installed into the
# throwaway container at test time. That needs network, which is fine: the
# air-gap guarantee is about `make up` / `make scan`, not about the test run.
# ---------------------------------------------------------------------------
test: test-unit test-e2e

test-unit:
	@echo ">> unit tests (no docker)"
	@cd scanner && OQS_INSTALL_PATH=$(CURDIR)/bin/liboqs \
		$(if $(wildcard .venv),../.venv/bin/python,python3) -m pytest \
		tests/test_scanner.py tests/test_target_guard.py -q

test-e2e:
	@echo ">> integration tests (in image)"
	@docker run --rm -v "$(CURDIR):/w" -w /w --entrypoint /bin/sh $(IMAGE) -c \
		'/venv/bin/pip install -q -r /w/scanner/requirements-dev.txt && \
		 OQS_INSTALL_PATH=/opt/oqs /venv/bin/python -m pytest \
		 scanner/tests/test_integration.py scanner/tests/test_api_auth.py -q'

# ---------------------------------------------------------------------------
# scanning
# ---------------------------------------------------------------------------
# Runs in a throwaway container so the long-lived API is never blocked by a scan.
# SCAN_ID must be computed once: $(shell ...) is expanded per-occurrence, so
# calling it twice in one recipe would produce two different timestamps and
# orphan the report next to the CBOM.
SCAN_ID ?= $(shell date +%s)

scan:
	@echo ">> scanning $(SCAN_TARGET)"
	@mkdir -p $(OUTPUT_DIR)/$(SCAN_ID)
	@docker run --rm \
		-v "$(CURDIR)/$(OUTPUT_DIR):/app/output" \
		--entrypoint /app/docker/entrypoint.sh \
		$(IMAGE) scan "$(SCAN_TARGET)" \
			--z-estimate $(Z_ESTIMATE) \
			--output "/app/output/$(SCAN_ID)/cbom.json" \
			--report "/app/output/$(SCAN_ID)/report.json"
	@echo ">> results in $(OUTPUT_DIR)/$(SCAN_ID)/"

rerisk:
	@test -n "$(ID)" || (echo "usage: ID=<scan_id> Z=<years> make rerisk"; exit 1)
	@docker run --rm \
		-v "$(CURDIR)/$(OUTPUT_DIR):/app/output" \
		--entrypoint /app/docker/entrypoint.sh \
		$(IMAGE) rerisk "/app/output/$(ID)/report.json" --z-estimate $(or $(Z),15) \
			--output "/app/output/$(ID)/rerisk_z$(or $(Z),15).json"

# ---------------------------------------------------------------------------
# housekeeping
# ---------------------------------------------------------------------------
verify:
	@fail=0; \
	check() { if [ -e "$$1" ]; then echo "  ok   $$1"; else echo "  MISS $$1"; fail=1; fi; }; \
	echo "verifying ecdat:"; \
	check bin/syft; \
	check bin/liboqs/lib/liboqs.so.0.16.0; \
	check bin/wheels/liboqs_python-$(LIBOQS_VER)-py3-none-any.whl; \
	check scanner/rules/crypto-detection.yaml; \
	check scanner/src/__main__.py; \
	check api/src/main.py; \
	check Dockerfile; \
	check docker-compose.yml; \
	echo ""; \
	if [ "$$fail" = "0" ]; then echo "all required artifacts present"; else echo "SOME ARTIFACTS MISSING"; exit 1; fi

clean:
	rm -rf $(OUTPUT_DIR)/*
	@echo "cleaned $(OUTPUT_DIR)"

distclean: clean down
	rm -f bin/syft
	rm -rf bin/liboqs
	rm -f bin/wheels/*.whl
	-docker image rm $(IMAGE) 2>/dev/null || true
	@echo "distclean complete - re-run 'make setup'"
