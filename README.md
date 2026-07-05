# surrealdb-guard

A small daemon that sits between OS-level identities and a SurrealDB instance, using Unix sockets (one per identity, kernel-permissioned) as the caller-identity mechanism, and enforcing per-identity table-group write policy before forwarding anything to the database.

See [SPEC.md](SPEC.md) for full design rationale, threat model, protocol specification, and roadmap.

---

## Status

Design phase. Not yet implemented.

---

## Proposed Directory Structure

```
surrealdb-guard/
│
├── .github/
│   └── workflows/
│       ├── ci.yml               # Build, unit tests, integration tests, linting
│       └── release.yml          # Build and publish binaries on tag push
│
├── .gitignore
│
├── LICENSE
├── README.md                    # This file
├── SPEC.md                      # Full design specification
├── SECURITY.md                  # Vulnerability disclosure, sharp-edge warnings
├── CHANGELOG.md                 # Version history
│
├── go.mod                       # Go module definition (github.com/shelbournetech/surrealdb-guard)
├── go.sum                       # Dependency lockfile
│
├── Makefile                     # build, test, lint, run, init-schema targets
│
├── cmd/
│   └── surrealdb-guard/
│       └── main.go              # Binary entrypoint: serve, init-schema, validate-config subcommands
│
├── client/                      # Go client library — public, importable by users
│   ├── client.go                # Connect, one method per protocol method (Query, Create, Update, ...)
│   ├── client_test.go           # Unit tests against a fake socket listener
│   └── types.go                 # Exported request/response/error types
│
├── internal/                    # Daemon internals — not importable outside this module
│   │
│   ├── config/                  # Config file loading and validation (SPEC §7.1)
│   │
│   ├── protocol/                # Framing, request/response types, error codes (SPEC §6)
│   │
│   ├── policy/                  # Tier semantics, grant resolution, per-call policy checks (SPEC §4)
│   │
│   ├── dba/                     # dba_execute keyword screen (SPEC §3, §4.1)
│   │
│   ├── socket/                  # Unix socket lifecycle and permission assertion (SPEC §5)
│   │
│   ├── db/                      # SurrealDB HTTP client, schema init, group/grant cache (SPEC §7.2, §8)
│   │
│   └── proxy/                   # Request dispatch and handler (SPEC §6.3)
│
├── schema/
│   └── init.surql               # Idempotent DDL for _access_group and _access_grant (SPEC §8)
│
├── deploy/                      # Reference deployment files (SPEC §11)
│   ├── surrealdb-guard.service  # systemd unit with EnvironmentFile=
│   ├── surrealdb-guard.conf     # tmpfiles.d entry for the socket directory
│   └── README.md                # Socket ownership notes, credential file setup, SurrealDB version caveats
│
├── client-python/               # Python client — self-contained project root (SPEC §9)
│   ├── pyproject.toml
│   ├── README.md
│   ├── surrealdb_guard_client/
│   │   └── __init__.py
│   └── tests/
│
└── tests/                       # Test layers requiring external coordination (SPEC §12)
    ├── integration/             # Layer 2: real SurrealDB in-memory (surreal start memory)
    ├── multiuser/               # Layer 3: root-owned sockets, real separate OS users (disposable VM/container)
    ├── conformance/             # Layer 4: Go and Python clients against the same proxy instance
    └── harness/                 # Standing tier×operation validation script (SPEC §12)
        └── validate.sh
```

---

## Test Layers

| Layer | Needs root | Needs SurrealDB | Where it runs |
|---|---|---|---|
| 1 — Unit | No | No (mocked) | Anywhere, including CI |
| 2 — Integration | No | Yes (in-memory) | CI (SurrealDB service container) |
| 3 — Multi-user host | Yes | Yes | Disposable VM or container |
| 4 — Cross-client conformance | No | Yes (in-memory) | CI alongside layer 2 |

Layer 1 unit tests live alongside the code they test (`*_test.go`, `tests/test_*.py`). Layers 2–4 live under `tests/`.

---

## CI

| Workflow | Trigger | What it does |
|---|---|---|
| `ci.yml` | Push, pull request | Build, unit tests (Go + Python), integration tests (SurrealDB service container), linting (`golangci-lint`, `ruff`) |
| `release.yml` | Tag push (`v*`) | Build static binaries for Linux amd64/arm64, publish to GitHub Releases; publish Python client to PyPI |

---

## Platform notes

- The **daemon runs on Linux only** (requires systemd, `tmpfiles.d`, `/run`).
- **macOS developers** can run test layers 1, 2, and 4 natively. Layer 3 (multi-user host tests) requires Linux; use a disposable Podman container rather than your host.
- **Windows** is out of scope.

---

## Reference links

### Upstream SurrealDB issues motivating this project

- [`surrealdb/surrealdb#1614`](https://github.com/surrealdb/surrealdb/issues/1614) — Unix-socket transport (open since January 2023). If this ships, re-evaluate whether the proxy's identity mechanism still needs to differ.
- [`surrealdb/surrealdb#7092`](https://github.com/surrealdb/surrealdb/issues/7092) — Table-level `DEFINE USER` permissions (open). If this ships, re-evaluate the proxy's reason for existing.

### Security advisory

- [`GHSA-4vgr-h27g-cf9p`](https://github.com/advisories/GHSA-4vgr-h27g-cf9p) — HTTP RPC Session Race Condition / Privilege Escalation in SurrealDB. This advisory does **not** apply to deployments using this proxy with SurrealDB ≥ 3.1.5 (the minimum required version — see SPEC §13).

### SurrealDB documentation

- [REST API reference](https://surrealdb.com/docs/surrealdb/integration/http) — `/sql` and `/rpc` endpoints used by the proxy.
- [Authentication & users](https://surrealdb.com/docs/surrealdb/security/authentication) — `OWNER`/`EDITOR`/`VIEWER` system-user roles.
- [SurrealQL reference](https://surrealdb.com/docs/surrealql) — grammar reference for the target SurrealDB version; relevant to the `dba_execute` keyword screen (SPEC Appendix C) and record-ID syntax (SPEC Appendix A).

### Reference implementation

- [`github.com/surrealdb/surrealdb.go`](https://github.com/surrealdb/surrealdb.go) — the official Go SurrealDB client. Useful as a reference for HTTP wire behaviour. The proxy hand-rolls its own HTTP client to keep the dependency tree tight (SPEC §14).

### Python client naming

The Python client is published to PyPI as **`surrealdb-guard-client`** and imported as **`surrealdb_guard_client`** — the standard Python packaging convention (hyphenated distribution name, underscored import name). Install with `pip install surrealdb-guard-client`.
