# AGENTS.md — surrealdb-guard

Guidance for AI coding agents working on this repository. Read this before making any changes.

---

## Ground rules (override any default instinct)

1. **Never interpolate a caller-supplied string into SurrealQL text.** Bound parameters only, always. See SPEC §6.4. A single interpolation gap is a policy bypass.
2. **Never add a proxy method that issues `DEFINE USER`, `DEFINE ACCESS`, `REMOVE USER`, `REMOVE ACCESS`, or any identity-management statement.** The structural exclusion in SPEC §4.1 is a guarantee, not a suggestion. There is no method for identity management in this project — not even behind a flag.
3. **Never widen the `dba_execute` keyword screen.** Additions to the reject list (SPEC Appendix C) are welcome; removals require a filed issue, explicit rationale, and human review. The screen over-rejects on purpose.
4. **Never add a TCP listener, WebSocket listener, or any transport on the caller side that is not a Unix domain socket.** The Unix socket is the identity mechanism — a TCP or WebSocket listener destroys it. If a change seems to require one, stop and ask.
5. **Never log full request payloads, credential values, or bound-parameter contents at any level below debug.** SPEC §14.
6. **Do not generate or modify `SPEC.md`, `SECURITY.md`, `CHANGELOG.md`, or this file (`AGENTS.md`) *proactively*.** Those are human-maintained. "Proactively" means without being asked: it is fine — expected, even — to edit any of these files, including this one, when a human explicitly asks for it in the conversation. Update `SPEC.md` in the same commit as a behaviour change, but only for the specific section(s) affected.

---

## Security-sensitive files

Changes to the following files require a commit message that cites the relevant SPEC.md section:

- `internal/socket/*` — socket lifecycle, permission assertion (SPEC §5)
- `internal/policy/*` — tier semantics, grant resolution, multi-target checks (SPEC §4)
- `internal/dba/*` — `dba_execute` keyword screen (SPEC §3, §4.1, Appendix C)
- `internal/db/credentials*` (or whichever file holds the two SurrealDB credentials) — SPEC §7.2
- `schema/init.surql` — proxy-owned database schema (SPEC §8)

Example commit message suffix: `(SPEC §5 — socket permission assertion)`.

---

## How to run each test layer

| Layer | Command | When to run | Requirements |
|---|---|---|---|
| 1 — Unit | `make test-unit` | Always safe; run on every change | None — no external services |
| 2 — Integration | `make test-integration` | Safe on any developer machine | `surreal` binary on PATH; starts in-memory SurrealDB on a random port, leaves nothing behind |
| 3 — Multi-user host | `make test-multiuser` | **Only inside a disposable container or VM** — never on your real host | Linux with multiple real OS users; see sentinel-file requirement below |
| 4 — Cross-client conformance | `make test-conformance` | Safe; starts its own layer-2 proxy | `surreal` binary on PATH |

**Layer-3 sentinel:** `make test-multiuser` will refuse to run unless `/etc/surrealdb-guard-test-host` exists on the current host. Create this file inside a disposable Podman container:

```sh
podman run --rm -it --privileged -v $(pwd):/workspace:z debian:bookworm bash
# inside the container:
touch /etc/surrealdb-guard-test-host
cd /workspace && make test-multiuser
```

---

## Local dev prerequisites

Install everything with `make setup` (macOS, requires Homebrew). The target validates versions and installs missing tools.

| Tool | Minimum version | Purpose |
|---|---|---|
| Go | 1.22 | Daemon and Go client |
| Python | 3.11 | Python client |
| `surreal` CLI | 3.1.5 | Layer-2 and layer-4 integration tests (`surreal start memory`) |
| `golangci-lint` | any recent | Go linting |
| `ruff` | any recent | Python linting and formatting |
| Podman | any recent | Disposable containers for layer-3 tests |
| `podman-compose` | any recent | Multi-container test setups |

---

## Build, lint, format, and test commands

```sh
make setup            # First-time setup: validate / install prerequisites (macOS)
make build            # Compile the surrealdb-guard binary
make lint             # golangci-lint (Go) + ruff check (Python)
make fmt              # gofmt (Go) + ruff format (Python)
make test             # Layers 1 + 2 + 4 (safe anywhere)
make test-unit        # Layer 1 only
make test-integration # Layer 2 only
make test-conformance # Layer 4 only
make test-multiuser   # Layer 3 — disposable container/VM only
```

---

## The SurrealDB version pin and how to change it

The minimum required version is **SurrealDB 3.1.5** (SPEC §13). This pin exists to exclude all versions affected by `GHSA-4vgr-h27g-cf9p`. Changing it requires updating **all four** of:

1. `SPEC.md` §13 — the minimum version statement.
2. The version probe in the layer-2 integration tests (SPEC §12).
3. The service-container image tag in `.github/workflows/ci.yml`.
4. `Makefile` — `SURREALDB_MIN_VERSION` variable.

Do not change any one of these without changing the others.

---

## External state to watch

The upstream issues and advisory motivating this project, and why the design depends on them, are listed in README.md ("Reference links") and SPEC §1/§13/§16. If any of them change — especially `surrealdb/surrealdb#1614` (Unix-socket transport) or `#7092` (table-level `DEFINE USER`) shipping, or a new advisory in the same class as `GHSA-4vgr-h27g-cf9p` — update SPEC §1 and §13 and reconsider whether the design premise still holds.

---

## Before-you-commit checklist

- [ ] `SPEC.md` updated for any behaviour change (same commit, relevant section cited in commit message).
- [ ] The tier × operation matrix in `tests/harness/validate.sh` covers any new or changed methods.
- [ ] No new dependencies added to `internal/` without justification. The daemon's attack surface is its dependency tree (SPEC §14).
- [ ] If the `result` shape of any method changed: the cross-client conformance tests (layer 4) still pass and SPEC §6.2 is updated.
- [ ] Security-sensitive files (see above): commit message cites the SPEC section.

---

## What NOT to do proactively

- Do not create additional documentation files unless a human explicitly asks for one. The maintained set is: `README.md`, `SPEC.md`, `SECURITY.md`, `CHANGELOG.md`, `AGENTS.md`.
- Do not add example clients beyond Go (`client/`) and Python (`client-python/`).
- Do not add REPL support, batched `transact`, or live-query support — those are SPEC §16 roadmap items.
- Do not add a `--allow-tcp` or similar flag that re-opens the identity problem the project is built to solve.

---

## Source of truth

**`SPEC.md` is the source of truth for all behaviour.** When in doubt, defer to it. Update it in the same commit as any behavioural change.
