# SPEC.md review

Reviewer pass over `SPEC.md` (design-phase, unimplemented). Each item is a red flag, an inaccuracy against upstream documentation, or an internal inconsistency that should be resolved *before* implementation begins. External claims were cross-checked against SurrealDB's own docs and the referenced advisory. Items are ordered roughly by severity.

**Verdict: not clear to begin development.** Several items below (R1, R2, R6, R7) invalidate concrete claims in the design; they can each be fixed with a spec revision but should not be deferred until code lands.

---

## R1 — The `dba_execute` keyword screen has a trivial documented bypass via `eval::surql`

**Where:** §3 sharp edges, §4.1 layer 2, Appendix C (C.1, C.4).

**Problem.** SurrealDB ships `eval::surql(...)` and `eval::gql(...)` — [built-in functions that evaluate a query string at runtime](https://surrealdb.com/docs/learn/security/authorization/capabilities#eval-queries), available since 3.2.0 and gated by `--allow-eval-query`. Appendix C.1 explicitly commits to *not inspecting the contents of string literals* ("The screen does not inspect the *contents* of string literals or backtick-quoted identifiers — a string value of `\"DEFINE USER\"` never triggers a rejection"). Consequence: a `dba`-tier caller submits `RETURN eval::surql("DEFINE USER attacker ON DATABASE PASSWORD '...' ROLES OWNER")` and the screen sees `[RETURN, EVAL, ::, SURQL, (, STRING_LITERAL, )]`, none of which match the reject list.

This is not the "theoretical scripting construct" caveat in §C.4. It is a documented, first-class SurrealDB feature that pipes an arbitrary string through the query executor. The screen as specified cannot detect it without either (a) rejecting `eval` unconditionally, or (b) recursively parsing string literals when they are used as arguments to `eval::*` — which is exactly the parsing problem §6 says the whole design exists to avoid.

**What actually saves the design here** is the `EDITOR`-credential IAM exclusion (§7.2 layer 3). That is genuinely enforced by SurrealDB's own RBAC ([confirmed in the DEFINE USER docs](https://surrealdb.com/docs/reference/query-language/statements/define/user#roles): "EDITOR can view and edit any resource on the user's level or below, but not users or token (IAM) resources"). But then the framing in §3 that the screen is "defence in depth on top of the `EDITOR` credential" is backwards for the identity-management case: it is the *only* layer, and it does not hold. The screen is a real defence against typos in a `dba`-tier admin's own SurrealQL, not against a `dba`-tier identity constructing a bypass.

**Fix options.** Any of:
1. Add `EVAL` (and `SURQL`, `GQL`, or the two-token adjacencies `EVAL ::`, `:: SURQL`, `:: GQL`) to Appendix C.2's reject list, and document that `eval::*` is unreachable via `dba_execute`.
2. Reject any `dba_execute` statement containing `::` followed by an identifier in the `eval` family, and note this is deliberately over-rejecting.
3. Rewrite §3 to state plainly that the screen does not defend the identity-management surface — only the `EDITOR` credential does — and reserve the screen for its other functions (blocking accidental DDL, catching typos).

Recommend option 1 combined with option 3. Also require the layer-2 regression probe (§13) to include `eval::surql("DEFINE USER ...")` and assert `DENIED` from the proxy *before* the request reaches the database.

---

## R2 — SPEC misrepresents which SurrealDB version fixes GHSA-4vgr-h27g-cf9p

**Where:** §13.

**Problem.** SPEC states "SurrealDB 3.1.5 contains the fix; no version below it is supported for use with this proxy." The [GHSA-4vgr-h27g-cf9p advisory](https://github.com/advisories/GHSA-4vgr-h27g-cf9p) affects `< 3.1.0` and is **patched in 3.1.0**, not 3.1.5.

Pinning the minimum at 3.1.5 rather than 3.1.0 is defensible (pick up subsequent 3.1.x fixes as well), but the SPEC's language implies the fix landed in 3.1.5 specifically. That is factually wrong and matters because someone reviewing the SPEC to understand *why* 3.1.5 is the floor will be misled about the fix's location in history.

**Fix.** Reword §13 to distinguish the fix (3.1.0) from the pin (3.1.5, on top of the fix, for further defence-in-depth patches). List any additional 3.1.x advisories that motivated advancing the pin past 3.1.0, if any exist; if none, say so and note the pin is precautionary.

---

## R3 — SPEC calls SurrealDB's `/rpc` "stateless"; it isn't

**Where:** §13 ("The proxy talks to SurrealDB over its stable HTTP surface (`/sql` for `query`/`dba_execute`, the stateless `/rpc` endpoint for bound-parameter typed writes).")

**Problem.** SurrealDB's [RPC protocol](https://surrealdb.com/docs/reference/rest-api/rpc-protocol) is session-scoped, not stateless: session variables set by `let`, the current namespace/database set by `use`, authentication set by `signin`, and — the point of GHSA-4vgr-h27g-cf9p — the request-processing context are all bound to a session identifier. The [official Rust HTTP engine module doc](https://docs.rs/surrealdb/latest/surrealdb/engine/remote/http/) says "While HTTP is traditionally a stateless protocol, this implementation supports stateful sessions by maintaining server-side session state and using session IDs in requests."

The GHSA advisory itself describes the bug as concurrent HTTP `/rpc` requests sharing mutable authentication state — i.e. the endpoint is *not* stateless; that was precisely the problem the 3.1.0 fix addressed by allocating a fresh UUID per request.

**Fix.** Delete the word "stateless" from §13, or replace with a more accurate note that per-request session isolation was added in 3.1.0 (per the advisory).

---

## R4 — The typed-write protocol shape does not cleanly map onto any single SurrealDB endpoint

**Where:** §6.3 (methods table), §6.4 (bound parameters), §7.2 ("two credentials"), Appendix B (`where` conditions on `update`/`delete`).

**Problem.** The SPEC gives two concrete places the proxy talks to SurrealDB: `/sql` (for `query`/`dba_execute`) and `/rpc` (for "bound-parameter typed writes"). But the RPC surface published by SurrealDB (verified against the [official RPC protocol docs](https://surrealdb.com/docs/reference/rest-api/rpc-protocol)) does not match the proxy's typed-method surface:

- **RPC `update [thing, data]`** replaces a record (or all rows in a table) by ID. It has no `where` parameter. The proxy's `update` method (§6.3) takes `where?` and `mode: merge|patch|replace`. To honour that, the proxy must either (a) fall back to `/sql` and construct `UPDATE <table> MERGE $data WHERE <compiled>` itself (which is fine — bound parameters still travel out-of-band per §6.4) or (b) use RPC `merge`/`patch` methods and prefilter with a `query`. The SPEC doesn't say which, and the two have different transactional and performance properties.
- **RPC `delete [thing]`** has no `where` parameter either. Same fork.
- **RPC `upsert [thing, data]`** doesn't accept a `mode`. SurrealQL `UPSERT ... MERGE` is a `/sql` construct.
- **RPC `relate [in, relation, out, data?]`** takes single `in`/`out` records, not the SPEC's `from_ids[] × with_ids[]` cross product. To implement the SPEC's `relate`, the proxy must either loop over `from_ids × with_ids` issuing multiple RPC calls, or compose a `RELATE` statement over `/sql`.

None of this is impossible — the proxy is free to compile typed methods down to `/sql` with bound parameters, and §6.4 already requires bound-parameter travel — but the SPEC's phrasing "the stateless `/rpc` endpoint for bound-parameter typed writes" (§13) and "the proxy constructs the statement text itself and never treats caller data as anything but a typed, bound value" (§6.4) suggests a particular routing that doesn't match SurrealDB's actual surface.

**Fix.** Pick a lane and document it explicitly in §6.3 and §13:
- Either "the proxy translates every typed method into a parameterised `POST /sql` call under the read-write credential; RPC methods are not used at all," or
- A per-method routing table specifying which typed methods go via `/rpc` and which via `/sql`, and why.

Option 1 is simpler and eliminates the entire class of RPC-shape-mismatch questions above. It also makes the read/write separation cleaner: both credentials talk to the same endpoint, and the only thing that differs is which credential is presented. If option 1 is chosen, then the `/rpc` endpoint (and thus the GHSA-4vgr-h27g-cf9p attack surface) is not used at all — a much easier property to hold.

---

## R5 — `_access_grant.username` is a plain string but `config.yml` identities are OS usernames; no explicit rule guards Unicode / edge cases

**Where:** §7.1 (`username` in `identities`), §8 (`_access_grant.username` is `TYPE string`), §5 (socket path derives from identity name).

**Problem.** OS usernames on Linux/POSIX are typically `[A-Za-z_][A-Za-z0-9_-]{0,31}` but not universally so; some systems permit dots, some permit longer names, and container images sometimes ship users like `_apt`. The socket-per-identity design uses the username as a file path component (`<username>.sock`), and the `_access_grant` schema doesn't constrain it. Two concrete gaps:

1. **Path traversal / socket-directory escape.** If a `config.yml` writer supplies `username: ../foo`, the proxy would attempt to `bind` at `/run/surrealdb-guard/../foo.sock`. §5 doesn't specify what character set is validated. This is a purely internal config-writer trust concern (out of scope per §15, as long as `config.yml` is root-owned), but the SPEC should still commit to a grammar for `username` — e.g. `[a-z_][a-z0-9_-]{0,31}` — and reject anything else at config load.
2. **Case-sensitivity of `_access_grant` join.** SurrealDB strings are case-sensitive. If a config-management system writes `Alice` on one host and `alice` on another, the grant lookup silently fails. The SPEC should either specify case-folding on read or state that usernames are byte-exact.

**Fix.** Add a `username` grammar to §7.1 (or §5) and require the proxy to reject invalid identities at config load. State the case-sensitivity policy explicitly.

---

## R6 — Appendix C.2 rejects bare `SIGNIN`/`SIGNUP` as identifiers; this over-rejects legitimate DDL

**Where:** Appendix C.2 (reject list, `SIGNIN` and `SIGNUP` entries).

**Problem.** The reject list marks bare `SIGNIN` and `SIGNUP` tokens as always-reject. These keywords appear in `DEFINE ACCESS ... TYPE RECORD SIGNIN ( ... ) SIGNUP ( ... )` — which is already covered by the `DEFINE ACCESS` two-token rule ahead of them. But the C.2 rules are described as position-insensitive two-token adjacency checks, and the `SIGNIN`/`SIGNUP` rows are *single-token* rules with no position constraint (unlike the `ACCESS` row, which is explicitly position-sensitive).

This means any DDL that names a field or parameter `signin` — plausible in an application storing web-auth records, e.g. `DEFINE FIELD signin ON user TYPE datetime` — would be rejected by the screen. That is genuinely over-rejecting in a way that hurts real DBA workflows.

**Fix.** Either (a) drop the bare `SIGNIN`/`SIGNUP` entries (they are subsumed by `DEFINE ACCESS` rejection) or (b) mark them position-sensitive like the `ACCESS` row — reject only when they appear at a statement's first-token position (of which there are none in current SurrealDB syntax, so this makes the rule inert but harmless). Recommend (a).

---

## R7 — Appendix A permits schemaless-looking record IDs but Appendix A syntax doesn't match SurrealDB's actual grammar

**Where:** Appendix A.

**Problem.** Appendix A says `record_id = ident ":" id_part`, where `id_part` can be integer, string literal, ULID, UUID. SurrealDB's real record-ID syntax is [broader and more permissive](https://surrealdb.com/docs/reference/query-language/language-primitives/data-types/record-ids). The SPEC calls out ranges/objects/arrays as "NOT accepted in v1," which is fine, but the grammar as written also excludes:

- **Bare identifier IDs**: `person:tobie` — a very common SurrealDB idiom. The grammar shown accepts `integer | string_literal | ulid_literal | uuid_literal`, none of which cover an unquoted identifier. Yet §7.2 examples and every SurrealDB doc use `person:tobie` freely.
- **Alphanumeric non-ULID/UUID IDs**: `invoice:a1b2c3d4` — 8 chars, not a valid ULID (26 chars) or UUID (specific hyphenation). Rejected by the grammar shown.

Consequence: a caller trying `create person:tobie` gets `INVALID_PARAMS`, and has to know to write `create person:'tobie'` instead. That's a real ergonomic wart and will surface immediately in the conformance tests (§12, layer 4).

**Fix.** Extend Appendix A's `id_part` to include a bare-identifier form: `id_part = ident | integer | string_literal | ulid_literal | uuid_literal`. Explicitly note that record IDs containing colons, spaces, or other punctuation must be quoted — same rule SurrealDB itself applies. Add a test case to `tests/harness/validate.sh` covering `create person:tobie`.

---

## R8 — Concurrent-request cross-contamination probe (§12 layer 2, §13) targets the wrong endpoint

**Where:** §12 layer 2 probe, §13 concurrency-cross-contamination bullet.

**Problem.** Both bullets describe hammering "concurrent `query` (VIEWER credential) and typed-write (EDITOR credential) requests" and asserting no cross-contamination. That directly regresses GHSA-4vgr-h27g-cf9p — good — but the advisory is specifically about the `/rpc` endpoint. If R4 above is resolved by routing everything through `/sql` (option 1), the probe as written is not exercising the code path the advisory affects, and the "standing regression check" becomes theatre.

**Fix.** Once the endpoint-routing question in R4 is settled:
- If any typed method routes to `/rpc`, the probe must target `/rpc` specifically with concurrent authenticated + unauthenticated (or two different-credential) requests, matching the advisory's attack shape.
- If everything routes to `/sql`, the probe should assert `/rpc` is not touched by the proxy under any code path, and add a separate probe over `/sql` for concurrent-credential correctness.

---

## R9 — Reload behaviour: the `dba_execute`-triggered cache reload has an unstated race

**Where:** §8 ("the proxy reloads its group/grant cache after every `dba_execute` call").

**Problem.** If two `dba`-tier callers issue concurrent `dba_execute` calls that each modify `_access_*`, and each triggers a post-call reload, the ordering of the two reloads relative to each other and to the two commits is not specified. A reload could observe a partial state (one commit visible, the other not) and cache it briefly, until the periodic reload picks up the settled state 60 s later.

This is not a security bug — the periodic reload backstops it, and the direction of the drift is toward `DENIED` rather than false-`ALLOW` — but it's a correctness rough edge worth pinning down before implementation.

**Fix.** Specify one of:
- Serialise `dba_execute`-triggered reloads through a single-flight mutex.
- Guarantee "at least one reload strictly after each `dba_execute` commit" by re-reading the cache under a version cursor.
- Explicitly document the "up to one reload interval of stale-grant drift after a burst of concurrent `dba_execute` writes" property, and leave it there.

---

## R10 — `config.yml` reload behaviour on tier change lets an in-flight request finish under the old tier

**Where:** §8 reload-semantics table ("A tier changes for an existing identity on reload").

**Problem.** The rule says "in-flight requests that were already dispatched … complete under the tier that was in effect when the request was accepted." That's a defensible choice, but it has a security-adjacent implication: a downgrade from `dba` to `contributor` doesn't take effect for calls already in the goroutine pool. If the downgrade was triggered by an active compromise (an operator noticing bad behaviour and demoting the identity), the in-flight requests continue with `dba` authority until they complete, up to the §6.5 per-request timeout (30 s).

For most reload triggers this is fine. For a security-motivated tier demotion, the caller wants the demotion to take effect immediately — including on in-flight calls. There's no way to express "revoke everything, now" in the current spec except by removing the identity entirely (which does close the socket, but likewise lets in-flight goroutines complete).

**Fix.** Add a note that a security-motivated demotion should be paired with `SIGTERM` (or a documented "hard reload" trigger) that cancels in-flight goroutines. Or: change the rule so tier changes are re-checked before each SurrealDB call, not just at `accept()`. Either is fine — the SPEC just shouldn't leave it implicit.

---

## R11 — §14 says "audit logging is a future enhancement"; combined with §3, this leaves no forensic trail for denied writes

**Where:** §14, §16 audit-logging item.

**Problem.** §3 asserts the threat model handles callers who "attempt to write to a table it has no business touching," and the enforcement is a `DENIED` response. But if the v1 daemon has no committed log schema (per §14) and audit logging is deferred, there is no reliable record of the denial after the fact. That's fine as a v1 scope choice, but it collides with the framing: this proxy exists in part *because* application-layer enforcement is trivially bypassed and unaudited, and shipping v1 without any structured record of `DENIED` outcomes reproduces the same problem one layer over.

**Fix.** Commit to a minimal always-on log schema in §14 for v1: at least one line per `DENIED` outcome, containing `{timestamp, identity, method, target, tier, reason}`. Defer the richer audit-log surface (metrics, retention, alerting) to §16, but the bare-minimum denial log should not be deferred — it's a few lines of code and it closes the observability gap the whole project exists to close.

---

## R12 — SPEC §7.2 uses the URL `https://surrealdb.com/docs/reference/query-language/statements/define/user` but the current canonical path differs

**Where:** §7.2 external-doc link.

**Problem.** The link works today (SurrealDB serves both `/docs/reference/…` and `/docs/surrealdb/…` paths for the same content). It's a minor point — not a design issue — but the SPEC is committing to a URL that will need occasional maintenance. Same concern applies to any inline links; AGENTS.md and README.md handle this more gracefully by consolidating links.

**Fix.** Consolidate all external `surrealdb.com` links into README.md's "Reference links" section (which already exists) and refer to it from SPEC by section number rather than embedding URLs in prose.

---

## What is *not* a red flag (verified against upstream)

For completeness — several things in the SPEC that could sound suspicious on a first read but are correct:

- The `EDITOR` role genuinely excludes IAM per SurrealDB's own docs. §4.1 layer 3 and §7.2 hold.
- Issue [#1614](https://github.com/surrealdb/surrealdb/issues/1614) (Unix socket transport) is still open — the motivation stated in §1 is current.
- Issue [#7092](https://github.com/surrealdb/surrealdb/issues/7092) (table-level `DEFINE USER`) is still open — likewise.
- The `--deny-arbitrary-query` capability is group-granular (`guest`/`record`/`system`), as §13 asserts. The dismissal of that flag as insufficient is accurate.
- The design's core premise — that a Unix-socket-per-identity proxy is the only kernel-attested identity mechanism available today for a shared SurrealDB — is sound.

---

## Suggested next step

Address R1, R2, R3, R4 in one SPEC revision commit. R1 in particular changes the trust story of the `dba` tier and should be settled before any code is written that people will later rely on for that trust story. Once those four are done, the remaining items (R5–R12) are refinements that can land in follow-up spec revisions without invalidating any implementation work already in progress.
