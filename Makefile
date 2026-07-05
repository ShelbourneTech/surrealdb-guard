# surrealdb-guard Makefile
# See SPEC.md for full design rationale and AGENTS.md for development guidance.

# ── Tool versions ──────────────────────────────────────────────────────────────
# Update these and §13 / CI image tags together (see SPEC §13).
SURREALDB_MIN_VERSION := 3.1.5
GO_MIN_VERSION        := 1.22
PYTHON_MIN_VERSION    := 3.11

# ── Phony targets ──────────────────────────────────────────────────────────────
.PHONY: setup build lint fmt \
        test test-unit test-integration test-conformance test-multiuser \
        help

# Default target
help:
	@echo "Available targets:"
	@echo "  setup             Validate / install all local dev prerequisites (macOS)"
	@echo "  build             Build the surrealdb-guard binary"
	@echo "  lint              Run golangci-lint (Go) and ruff (Python)"
	@echo "  fmt               Format Go and Python sources"
	@echo "  test              Run layers 1 + 2 + 4 (safe on any host)"
	@echo "  test-unit         Layer 1 — unit tests, no SurrealDB required"
	@echo "  test-integration  Layer 2 — integration tests, starts surreal in-memory"
	@echo "  test-conformance  Layer 4 — cross-client conformance tests"
	@echo "  test-multiuser    Layer 3 — ONLY inside a disposable VM/container (see SPEC §12)"

# ── Setup (macOS) ──────────────────────────────────────────────────────────────
# Validates that all required tools are present and at acceptable versions.
# Installs missing tools via Homebrew where safe to do so.
# Does NOT install system-level packages that would affect your host OS.
setup:
	@echo "==> Checking prerequisites for surrealdb-guard development (macOS)"
	@echo ""
	@# ── Homebrew ──
	@command -v brew >/dev/null 2>&1 || { \
	  echo "ERROR: Homebrew not found. Install it from https://brew.sh then re-run make setup."; \
	  exit 1; \
	}
	@echo "[ok] brew"
	@# ── Go ──
	@if command -v go >/dev/null 2>&1; then \
	  GO_VER=$$(go version | awk '{print $$3}' | sed 's/go//'); \
	  echo "[ok] go $$GO_VER (need >= $(GO_MIN_VERSION))"; \
	else \
	  echo "[missing] go — installing via brew..."; \
	  brew install go; \
	fi
	@# ── Python ──
	@if command -v python3 >/dev/null 2>&1; then \
	  PY_VER=$$(python3 --version | awk '{print $$2}'); \
	  echo "[ok] python3 $$PY_VER (need >= $(PYTHON_MIN_VERSION))"; \
	else \
	  echo "[missing] python3 — installing via brew..."; \
	  brew install python@3.12; \
	fi
	@# ── surreal CLI ──
	@if command -v surreal >/dev/null 2>&1; then \
	  SURREAL_VER=$$(surreal version 2>/dev/null | head -1 | awk '{print $$2}' | sed 's/^v//'); \
	  echo "[ok] surreal $$SURREAL_VER (need >= $(SURREALDB_MIN_VERSION))"; \
	else \
	  echo "[missing] surreal CLI — installing via brew..."; \
	  brew install surrealdb/tap/surreal; \
	fi
	@# ── golangci-lint ──
	@if command -v golangci-lint >/dev/null 2>&1; then \
	  LINT_VER=$$(golangci-lint --version 2>/dev/null | awk '{print $$4}'); \
	  echo "[ok] golangci-lint $$LINT_VER"; \
	else \
	  echo "[missing] golangci-lint — installing via brew..."; \
	  brew install golangci-lint; \
	fi
	@# ── ruff ──
	@if command -v ruff >/dev/null 2>&1; then \
	  RUFF_VER=$$(ruff --version 2>/dev/null | awk '{print $$2}'); \
	  echo "[ok] ruff $$RUFF_VER"; \
	else \
	  echo "[missing] ruff — installing via brew..."; \
	  brew install ruff; \
	fi
	@# ── Podman (for layer-3 tests in a disposable container) ──
	@if command -v podman >/dev/null 2>&1; then \
	  PODMAN_VER=$$(podman --version | awk '{print $$3}'); \
	  echo "[ok] podman $$PODMAN_VER"; \
	else \
	  echo "[missing] podman — installing via brew..."; \
	  brew install podman; \
	fi
	@if command -v podman-compose >/dev/null 2>&1; then \
	  echo "[ok] podman-compose"; \
	else \
	  echo "[missing] podman-compose — installing via brew..."; \
	  brew install podman-compose; \
	fi
	@echo ""
	@echo "==> Setup complete. Run 'make test' to validate your environment."
	@echo "    Layer-3 multi-user tests require a disposable container — see SPEC §12."

# ── Build ──────────────────────────────────────────────────────────────────────
build:
	go build ./cmd/surrealdb-guard/...

# ── Lint / format ──────────────────────────────────────────────────────────────
lint:
	golangci-lint run ./...
	ruff check client-python/

fmt:
	gofmt -w .
	ruff format client-python/

# ── Tests ──────────────────────────────────────────────────────────────────────
test: test-unit test-integration test-conformance

test-unit:
	go test ./...
	cd client-python && python3 -m pytest tests/

test-integration:
	@echo "Starting SurrealDB in-memory for integration tests..."
	go test ./tests/integration/...

test-conformance:
	go test ./tests/conformance/...

# Layer 3: ONLY run inside a disposable container.
# The sentinel file /etc/surrealdb-guard-test-host must exist on the target host.
# To create a disposable test container:
#   podman run --rm -it --privileged \
#     -v $(PWD):/workspace:z \
#     --name surrealdb-guard-test \
#     debian:bookworm bash
# Then inside the container: touch /etc/surrealdb-guard-test-host && make test-multiuser
test-multiuser:
	@if [ ! -f /etc/surrealdb-guard-test-host ]; then \
	  echo ""; \
	  echo "ERROR: Layer-3 multi-user tests must only run inside a disposable container or VM."; \
	  echo "       Create /etc/surrealdb-guard-test-host on the target host to confirm."; \
	  echo ""; \
	  echo "       To start a disposable Podman container:"; \
	  echo "         podman run --rm -it --privileged -v \$$(pwd):/workspace:z debian:bookworm bash"; \
	  echo "       Then inside the container:"; \
	  echo "         touch /etc/surrealdb-guard-test-host && make test-multiuser"; \
	  echo ""; \
	  exit 1; \
	fi
	go test ./tests/multiuser/...
