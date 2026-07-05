# surrealdb-guard — Pre-development Review

*Reviewer: opencode (claude-opus-4-7)*
*Date: 2026-07-04*
*Inputs read: `README.md`, `SPEC.md` (both at HEAD).*
*External sources consulted: `surrealdb/surrealdb#1614`, `surrealdb/surrealdb#7092`, SurrealDB docs (users, roles, HTTP/RPC protocol), GitHub Security Advisory `GHSA-4vgr-h27g-cf9p`.*

---

## 1. Is the project sufficiently specified to begin development?

**Mostly yes**, but not entirely. `SPEC.md` is unusually thorough — it defines the threat model, protocol wire format, method set, policy semantics, config schema, DB schema, deployment shape, and a four-layer test strategy. A competent Go developer could start writing `cmd/surrealdb-guard/main.go`, `internal/protocol`, `internal/socket`, and `internal/policy` today from what's on the page.

What's still missing or vague enough to cause meaningful rework is enumerated in §2 below.

---

## 2. What else is required before development begins?

### 2.1 The structured `where` grammar (SPEC §6.4)

Described as "deliberately small" (field paths, comparison/containment operators, parameter-bound values) but never actually enumerated. This is the single largest under-specified surface — it's a mini-language, and until the exact operators, field-path syntax (nested? array indexing? record links?), and null/undefined/type-coercion rules are pinned down, `update`/`delete` cannot be implemented consistently across the CLI, Go client, and Python client.

*Recommendation:* one page of BNF (or a JSON Schema) enumerating:

- Field paths: identifier, dotted path, array index, record-link traversal (`.`, `->`, `<-`)?
- Operators: `=`, `!=`, `<`, `<=`, `>`, `>=`, `IN`, `CONTAINS`, `CONTAINSANY`, `CONTAINSALL`, `IS NULL`, `IS NOT NULL`?
- Boolean composition: `AND`, `OR`, `NOT`, nesting depth cap?
- Value types accepted as bound parameters, and how nulls/undefined map.

<!--Draft a proposed grammar in an appropriately named/organized file. Keep it simple.-->

### 2.2 The `target`/`targets` grammar (SPEC §6.4)

Described as "a bare table identifier or a record ID" with a "strict grammar," but the grammar itself is not written down. SurrealDB record IDs allow objects, arrays, ranges, and UUID/ULID literals as the ID part. The spec must say which of these are accepted, and specifically which are rejected as `INVALID_PARAMS`.

<!--Draft a proposed grammar in an appropriately named/organized file. Keep it simple.-->

### 2.3 The `dba_execute` keyword screen (SPEC §3, §4.1)

Described as "over-rejects on purpose" but the actual keyword list is not specified. This is a security-critical component; the reject list needs to be enumerated (at minimum: `DEFINE USER`, `DEFINE ACCESS`, `REMOVE USER`, `REMOVE ACCESS`, presumably `DEFINE TOKEN`, and any equivalents in future SurrealQL versions), and the tokenization rules (comment stripping, string-literal skipping, case handling, whitespace, backtick-quoted identifiers) need a written definition.

<!--Draft a proposed keyword list in an appropriately named/organized file. Keep it simple.-->

### 2.4 Response `result` shape (SPEC §6.2)

`"result": [ ... ]` is described as an array but the per-method contents are not defined. SurrealDB's `/sql` returns an array-of-statement-results wrapper (`[{status, time, result}]`); is the proxy passing that through verbatim, unwrapping single statements, or normalizing? Both clients need to agree, and the answer affects error surface too.

<!--Draft a proposed definition in an appropriately named/organized file. Keep it simple.-->

### 2.5 `insert` and `upsert` semantics

SurrealDB has `INSERT INTO ... ON DUPLICATE KEY UPDATE`, `UPSERT ... WHERE ...`, and other conditional forms. The spec does not say which of these are exposed and how they flow through as bound parameters.

<!--Draft a proposed approach in an appropriately named/organized file. Keep it simple.-->

### 2.6 Reload behaviour beyond the cache (SPEC §8)

SIGHUP re-reads `config.yml`, but:

- What happens to in-flight requests on a socket whose identity was just removed?
- What happens if `socket_dir` changes on reload — fail, or hot-swap?
- What happens if a tier changes for an existing identity mid-connection?

<!--Draft a proposed behaviour specification in an appropriately named/organized file. Keep it simple.-->

### 2.7 Logging format

SPEC §5 and §14 mention "one structured log line per call" but neither the schema (fields, types) nor the destination (stderr? syslog? JSON to stdout via journald?) is fixed. This blocks writing a test that asserts the audit line's shape.

<!--Move all audit logging to future enhancements.-->

### 2.8 Concrete SurrealDB version pin

SPEC §13 says "2.x and 3.x" but pinning a specific minimum (e.g., 2.3.3, which is already referenced in §6) matters for CI, for the read-only-role probe, and — critically — for the CVE noted in §3.3 below.

<!--Pin to SurrealDB 3.1.5 or later. This removes concerns about the CVE.-->

---

## 3. Do the ideas, patterns, and specifications adhere to conventions?

Broadly, **yes**, with some frictions.

### 3.1 What's idiomatic

- **Go module layout** (`cmd/`, `internal/`, top-level `client/` importable as `github.com/shelbournetech/surrealdb-guard/client`) is idiomatic. Keeping daemon internals under `internal/` and the client outside is correct.
- **Unix-socket identity via kernel file permissions** is a legitimate, well-established pattern (systemd's socket activation, PostgreSQL's `unix_socket_permissions`, Docker's socket group). The root-owned socket with `group=identity, mode=0660` is defensible.
- **systemd + tmpfiles.d + EnvironmentFile** is the correct Linux-daemon convention.
- **Python packaging** (`pyproject.toml`, snake_case import name) is idiomatic.
- **`DEFINE TABLE IF NOT EXISTS ... SCHEMAFULL`** (§8) is valid SurrealQL 2.x.

### 3.2 Deviations worth naming explicitly

- **`SO_PEERCRED` / `getpeereid()` is the more conventional identity mechanism** on Linux/BSD — one socket for everyone, kernel tells you the connecting UID via a syscall. The spec's "one socket per identity" approach is *equivalent in security* but is a deliberate deviation from the more common pattern. The rationale ("the socket path is the identity") is sound (it avoids a code path where identity is derived from a syscall that must not be forgotten), but it should be acknowledged explicitly in §5 as the road-not-taken, with the reasoning, so reviewers stop asking. <!--Edit the spec to acknowledge this.-->
- **JSON-RPC-ish line-delimited framing** (§6.1) is fine but slightly non-standard. Real JSON-RPC 2.0 has `jsonrpc: "2.0"`; NDJSON is common. The spec's framing is a subset of neither. Either commit to JSON-RPC 2.0 (small tax, huge library support in every language, well-known error-code semantics) or explicitly say "this is a bespoke framing, not JSON-RPC." Right now it's ambiguous. <!--Update the spec to specify JSON-RPC 2.0-->
- **Directory naming** — `client-python/` housing `surrealdb_guard_client/` — the dash-vs-underscore split is fine but the distribution name (on PyPI) may differ from the import name; state this explicitly to avoid churn. <!--Ideally published to pypi.org/project/surrealdb-guard-client although the import will be surrealdb_guard_client - confirm this is conventional for pypi - then update the spec.-->

### 3.3 The one real problem: HTTP transport to SurrealDB and `GHSA-4vgr-h27g-cf9p`

This is the most significant conventions/design concern in the entire spec.

As of 2025, there is a **live, HIGH-severity CVSS 8.1 advisory** against SurrealDB:

> **GHSA-4vgr-h27g-cf9p — HTTP RPC Session Race Condition Allows Privilege Escalation.**
> "The HTTP /rpc handler does not bind each incoming request to an isolated session context. Instead, concurrent requests share mutable authentication state. When an authenticated request sets the session context and an unauthenticated request races in before it is cleared, the unauthenticated request executes with the authenticated user's privileges."

The proxy's *entire design* — one `OWNER` credential and one `VIEWER` credential in flight concurrently against the same SurrealDB instance — is precisely the scenario this bug describes. If an unpatched SurrealDB is in use, the proxy could serve a `query` (VIEWER) call under OWNER privileges. See also `surrealdb/surrealdb#7384` (the same class of bug: "HTTP RPC client leaks an attached server session").

**Required actions:**

1. Pin an explicit minimum SurrealDB version that contains the fix.
2. Add a standing regression test (layer 2) that hammers concurrent `query` (VIEWER) and typed-write (OWNER) requests and asserts no cross-contamination — the check the CVE describes, run continuously.
3. Consider WebSocket `/rpc` (persistent authenticated session per socket) as an alternative or fallback transport. The CVE root cause is specific to HTTP's request-scoped session binding; a WebSocket connection holds a session for its lifetime, sidestepping the TOCTOU shape. Two long-lived WS connections (one per credential) would also amortize auth cost.

<!--Pin to SurrealDB 3.1.5 or later. This removes concerns about the CVE.-->

### 3.4 Minor: missing index

`_access_grant` (§8) lacks an index on `username`, which every write policy check will filter by. Trivial addition:

<!--Add this to the spec-->

```surql
DEFINE INDEX access_grant_username ON _access_grant FIELDS username;
DEFINE INDEX access_group_name    ON _access_group  FIELDS name UNIQUE;
```

---

## 4. What should change

Ordered by priority. Items 1–4 are blocking; 5+ are cleanups.

<!--Confirm that all these will be addressed by your changes based on my comments above.-->

1. **Pin a SurrealDB minimum version** that contains the GHSA-4vgr-h27g-cf9p fix, in §13.
2. **Write down the three grammars** (`where` condition, `target`/`targets`, `dba_execute` reject-list + tokenization) as an appendix to §6.
3. **Add a concurrency cross-contamination test** to §12 layer 2's list of standing regressions.
4. **Define the response `result` shape** per method in §6.
5. **Decide JSON-RPC-2.0-vs-bespoke** and state it in §6.1.
6. **Acknowledge `SO_PEERCRED`** as the road-not-taken in §5.
7. **Add indexes** to §8.
8. **Specify the log-line schema** in §14 (or a new §14.x).
9. **Specify reload semantics for in-flight state** in §8 and §7.1.
10. **State the OS platform contract**: daemon is Linux-only in practice (systemd, tmpfiles.d, `/run`); layers 1/2/4 of tests are portable, layer 3 is Linux-only. Add to §11 or §12.

---

## 5. Resources required for development and local testing

### Documentation

- SurrealDB HTTP `/sql` and `/rpc` endpoint reference (`surrealdb.com/docs/reference/rest-api/*`). <!--Does the documentation live in a public Git repo? If so then include it here using git submodule. In either case, include the precise URL in the README.-->
- SurrealDB authentication & users (`surrealdb.com/docs/learn/security/authentication/*`) — for the OWNER/EDITOR/VIEWER contract. <!--Same-->
- SurrealQL grammar reference for the target version — for the `dba_execute` reject list and for record-ID syntax. <!--Same-->
- The two upstream issues that motivate the project: <!--Include precise URLs of both issues in the README.-->
  - `surrealdb/surrealdb#1614` (Unix-socket transport, open since Jan 2023).
  - `surrealdb/surrealdb#7092` (table-level `DEFINE USER`, still open).
- The active advisory: `GHSA-4vgr-h27g-cf9p`, and its fix commit(s). <!--Include the precise URL in the README with a note that it does not apply because we are pinning to SurrealDB 3.1+-->

### Toolchain

<!--Generate a script or Make target for a MacOS user to safely validate/install everything required.-->

- **Go** — a pinned minimum (1.22+ is a reasonable modern floor; `t.TempDir()` and `net/http/httptest` are stable well before that).
- **Python** — 3.11+ recommended (for `tomllib`, `ExceptionGroup`, modern asyncio).
- **`surreal` CLI** for layer-2 tests (`surreal start memory`).
- **`golangci-lint`** with a checked-in config.
- **`ruff`** with a checked-in config.
- Optionally **`mise`** or **`asdf`** with a `.tool-versions` to make the above reproducible.

### Reference implementation

- **`github.com/surrealdb/surrealdb.go`** — useful as a reference for HTTP wire behaviour, though the proxy will likely hand-roll its client to keep the dependency tree tight (§14 attack-surface concern). <!--Mention it in the README-->

### Test infrastructure

- A disposable Linux VM/container recipe for layer-3 multi-user tests. Reasonable options: a `Dockerfile` with several `useradd` calls and a systemd-in-container base (e.g. `jrei/systemd-debian`), or a Multipass/Vagrant recipe. It must be trivially disposable and clearly marked as not-for-your-host. <!--Include podman and podman compose in the toolchain script/target (above) - developer can fill in implementation details later.-->

### Platform expectations

- Daemon runs on Linux only (needs systemd, tmpfiles.d, `/run`). <!--Note in README.-->
- macOS developers can run test layers 1, 2, and 4; layer 3 requires Linux. <!--Note in README. Layer 3 testing can use podman.-->
- Windows is out of scope. <!--Note in README.-->

---

## 6. Does this project need a specialized `AGENTS.md`?

**Yes, strongly.** Three reasons make this project unusually well-suited to (and unusually hurt by not having) explicit agent guidance:

1. **The whole project exists to constrain agents.** An agent working on the codebase itself, without instruction, is very likely to reach for exactly the anti-patterns the design is built to prevent: interpolating SurrealQL strings, adding "convenience" methods that bypass the typed write surface, taking shortcuts around the keyword screen, or "helpfully" exposing a WebSocket for a wire-compatible endpoint.
2. **The security-critical parts** (identity model, `dba_execute` screen, read-only-role assumption, socket permission assertions) **are not marked as such in the source layout.** An agent that treats those files like any others — refactoring for elegance, extracting helpers, relaxing "over-strict" validation — silently regresses the guarantees.
3. **The four test layers have very different environmental requirements**, and an agent that runs layer-3 tests unprompted on a developer's real host (or skips layer-3 because it doesn't have root) will either damage the host or produce a false green build.

---

## 7. What the `AGENTS.md` should include

<!--Generate AGENTS.md-->

### 7.1 Ground rules that override defaults

- Never introduce a code path that interpolates any caller-supplied string into SurrealQL text. Bound parameters only. Cite SPEC §6.4.
- Never add a proxy method that issues `DEFINE USER` / `DEFINE ACCESS` / `REMOVE USER`, etc. — the structural exclusion in §4.1 is a guarantee, not a suggestion.
- Never widen the `dba_execute` screen (removals from the reject list). Additions to the reject list are welcome; removals require an issue and human review.
- Do not add a TCP listener, a WebSocket listener on the caller side, or any transport that isn't a Unix socket. If one seems necessary, stop and ask.
- Never log full request payloads, credentials, or bound-parameter values at info level.
- Never generate `AGENTS.md`, `SPEC.md`, or `SECURITY.md` proactively; those are human-maintained.

### 7.2 Security-sensitive files (explicit list)

`internal/socket/*`, `internal/policy/*`, `internal/dba/*`, `internal/db/credentials*` (whatever holds the two SurrealDB credentials), and `schema/init.surql`.

Rule: *changes to these files require a rationale in the commit message linking back to a SPEC.md section.*

### 7.3 How to run each test layer, and when not to

- **Layer 1** (`make test-unit`) — always safe, no side effects.
- **Layer 2** (`make test-integration`) — starts `surreal start memory` on a random port; leaves nothing behind.
- **Layer 3** (`make test-multiuser`) — **only inside a disposable VM/container.** Provide the exact `docker run` / `vagrant up` invocation. Refuse to run on a host that isn't marked disposable (a sentinel file, e.g. `/etc/surrealdb-guard-test-host`).
- **Layer 4** (`make test-conformance`) — needs a running layer-2 proxy; the harness starts one.

### 7.4 Local dev prerequisites

Go version, Python version, `surreal` binary path, `golangci-lint`, `ruff`, and how to install them (a `.tool-versions` file if using `mise`/`asdf`).

### 7.5 Build / lint / format commands verbatim

`make build`, `make lint`, `make fmt`, `go test ./...`, `pytest client-python/tests`, etc. — so the agent stops guessing.

### 7.6 The SurrealDB version pin and how to change it

Changing the pin must update:
- The version probe in layer-2 tests.
- The compatibility note in SPEC §13.
- The CI service-container image tag in `.github/workflows/ci.yml`.

### 7.7 External state to watch

If any of the following change state, update SPEC §1 and §13 and consider whether the design premise still holds:

- `surrealdb/surrealdb#1614` — Unix-socket transport.
- `surrealdb/surrealdb#7092` — table-level DEFINE USER.
- `GHSA-4vgr-h27g-cf9p` — HTTP RPC session TOCTOU.

### 7.8 Before-you-commit checklist

- SPEC.md updated for any behaviour change.
- The tier × operation matrix in `tests/harness/validate.sh` covers new methods.
- No new dependencies in `internal/` without justification (the daemon's attack surface *is* its dependency tree — §14).
- Structured log-line schema unchanged, or SPEC §14.x updated.

### 7.9 What NOT to do proactively

- Don't create additional docs (there's already `README.md`, `SPEC.md`, `SECURITY.md`, `CHANGELOG.md`).
- Don't add "example clients" beyond Go and Python.
- Don't add a REPL, batched `transact`, or live-query support — those are SPEC §16 roadmap items with their own future issues.

### 7.10 Source of truth

`SPEC.md` is the source of truth for behaviour. Update it in the same commit as any behavioural change.

---

## 8. Summary

Before development starts, resolve four concrete gaps:

1. Write down the `where` condition grammar and the `target`/`targets` grammar (one page of BNF is enough).
2. Enumerate the `dba_execute` keyword-screen reject list and tokenization rules.
3. Pin a minimum SurrealDB version that contains the fix for `GHSA-4vgr-h27g-cf9p`, and add a standing concurrency-cross-contamination probe to the layer-2 test list in §12.
4. Author `AGENTS.md` along the lines of §7 above.

The rest of the SPEC is in unusually good shape for a design-phase document and does not block starting the daemon skeleton, protocol package, and socket-permission-assertion code today.
