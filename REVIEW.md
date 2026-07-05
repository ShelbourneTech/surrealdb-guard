# SPEC.md Review — Pre-Development

Final review of `SPEC.md` before implementation begins. Ordered by severity.

---

## Red flags — security design

### 1. Appendix C reject list misses `ALTER USER` (confirmed against current docs)

Current SurrealQL has `ALTER USER` and a broader `ALTER` statement family (`ALTER TABLE`, `ALTER NAMESPACE`, `ALTER DATABASE`, `ALTER SYSTEM`, ...) — see
https://surrealdb.com/docs/reference/query-language/statements/alter/user.

A `dba`-tier caller could run `ALTER USER` to change the proxy's own credentials' roles or password without ever tripping the keyword screen. The reject list (Appendix C.2) needs at minimum `ALTER USER`, and the 3.x grammar should be audited for `ALTER ACCESS` and any other identity-adjacent `ALTER` forms. The screen appears to have been derived from the 2.x-era statement set (§6 still cites "confirmed against the SurrealDB v2.3.3 grammar") while the version pin (§13) is 3.1.5 — the two need to be reconciled.

### 2. `_access_*` tables are writable by the `writer` tier via typed writes

§8 states these tables are "writable only through `dba_execute`," but §6.3 says `writer`/`dba` tiers "skip the group check entirely" for all typed writes. Nothing in the spec enforces the §8 claim — a `writer`-tier identity can `create`/`update`/`delete` an `_access_grant` row directly through the typed write surface, i.e. perform access management from a non-`dba` tier.

Related gap: nothing forbids an `_access_group` row's `tables` array from containing `_access_*` table names, which would let a `contributor` with a grant on that group write to the access-control tables directly.

**Suggested fix:** hard-deny `_access_*` as a target of all typed writes regardless of tier (only `dba_execute` may touch them), and reject any `_access_group` row whose `tables` field contains an `_access_*` name on reload (§8's existing "fails loudly" reload-validation path is the natural place for this).

### 3. The read-write credential is `OWNER`, undermining the "structural exclusion" claim

§4.1 calls the absence of identity-management capability "a structural property," but the credential that executes `dba_execute` holds full `OWNER` authority — including identity management. The only thing preventing a `dba`-tier caller from managing identities is the keyword screen, which §3 itself disclaims as "not a formal guarantee."

SurrealDB's `EDITOR` role is documented to exclude user/access definitions while still permitting other resource-level DDL. If `EDITOR` grants sufficient authority for the DDL surface `dba_execute` needs to expose (§Appendix C.3: `DEFINE/REMOVE TABLE`, `FIELD`, `INDEX`, `EVENT`, `FUNCTION`, `PARAM`, `ANALYZER`, `NAMESPACE`, `DATABASE`, `API`) on SurrealDB 3.1.5, switching the read-write credential from `OWNER` to `EDITOR` would let the *database itself* enforce the identity-management exclusion, demoting the keyword screen to defence-in-depth rather than the sole guarantee.

This needs verification against 3.1.5 specifically (role semantics have changed across SurrealDB versions), but if confirmed it is the single largest hardening available at zero design complexity cost, and §7.2 should be updated accordingly.

---

## Red flags — internal contradictions

### 4. §6.3 vs Appendix A on multi-table targets

- §6.3: "`UPDATE`/`DELETE` accept multiple targets that **may span tables** ... every named table must be in the write set."
- Appendix A: "mixing tables in a single `update` or `delete` targets array is **not supported** (issue one call per table)."

These directly contradict each other. Appendix A's version is simpler to implement and to reason about for policy checking — recommend resolving in favor of it and correcting §6.3.

### 5. §C.1 vs §C.4 on comment stripping

- §C.1 (step 2) strips block comments (`/* ... */`) *before* keyword screening.
- §C.4 then gives `DEFINE/**/USER` as an example that "would defeat" the screen.

If comment removal substitutes a space for the stripped comment, that example is already caught by the screen and the caveat is wrong. If it substitutes nothing, `DEFINEUSER` becomes a single token and the bypass is real — but then that's a real, current bypass, not a hypothetical "sharp edge," and belongs in §3/§14 rather than as a caveat. The spec needs to state explicitly which behavior is intended. Substituting a space when stripping comments closes this bypass class for free and is the recommended fix.

### 6. §C.1 normalization order is not implementable as written

Comment stripping (steps 1–2) is specified to happen before any string-literal-aware handling, but you cannot correctly strip `--` or `/* */` sequences without knowing whether they're inside a string literal — e.g. a string containing the literal text `"a -- not a comment"` or a JSON/string value containing `/*` would be corrupted by a naive strip-then-tokenize pass. The string-literal exemption in §C.1's closing paragraph needs to be part of a single string-aware tokenization pass, not a separate step applied after comment stripping. Worth flagging explicitly in `internal/dba/` as a correctness requirement, not just a style note.

### 7. §4.2 vs §8 on the one-group invariant

- §4.2: every table should belong to exactly one group; the proxy "fails loudly" if this doesn't hold.
- §8: a table in *two* groups → error + writes to it refused (matches §4.2). A table in *no* group → only a **warning**, writes simply denied to `contributor`s by construction.

§8's actual behavior is reasonable (and correctly reasoned), but §4.2's summary overstates it as a hard invariant enforced identically in both directions. Recommend softening §4.2's wording to match §8, or cross-referencing §8 directly instead of restating a stricter rule.

---

## Red flags — protocol

### 8. §6.2 violates JSON-RPC 2.0 while claiming conformance

JSON-RPC 2.0 requires `error.code` to be an **integer**; the spec's error codes are strings (`DENIED`, `DB_ERROR`, `INVALID_PARAMS`, `UNKNOWN_METHOD`). Off-the-shelf JSON-RPC libraries — the stated motivation for adopting the JSON-RPC framing in §6.1 — will not accept these responses as spec-conformant.

**Suggested fix:** use integer error codes per JSON-RPC convention (e.g. reserved/implementation-defined range) and carry the symbolic name in `error.data` or embed it in `error.message`, or explicitly document this project's framing as "JSON-RPC-inspired" rather than JSON-RPC 2.0 conformant.

Also unspecified:
- §6.1 restricts request `id` to string in the example; JSON-RPC 2.0 allows numbers and null (with different semantics for null). State explicitly what's accepted.
- Batch requests and notifications (requests with no `id`, which JSON-RPC 2.0 permits and expects no response for) are not addressed at all — this needs an explicit "not supported, rejected as `INVALID_PARAMS`" statement rather than being left as an unspecified code path.

### 9. No message-size or resource limits

§6.1's newline-delimited framing has no stated maximum line length, no per-connection concurrency limit, and no request timeout. A single caller can send one unterminated line and exhaust daemon memory, or open unbounded concurrent in-flight requests on one socket. Needs a stated cap and a defined behavior on breach (`INVALID_PARAMS` + disconnect, most likely).

### 10. Appendix A's `string_literal` grammar is underspecified

`string_literal = "'" <chars> "'" | '"' <chars> '"'` leaves `<chars>` unbounded with no statement about embedded quotes, backslashes, escape sequences, or newlines. Since `target`/`targets` is the one caller-supplied value that plausibly ends up in statement-adjacent position (rather than purely as a bound parameter — see §6.4), this grammar is the closest thing in the spec to a §6.4 violation waiting to happen if implemented loosely. Needs exact escaping rules, or — more robust — a conservative character allowlist that sidesteps escaping entirely.

---

## Minor / hygiene

- **Stale 2.x references.** §16 roadmap lists "SurrealDB 3.x compatibility testing... alongside 2.x," which contradicts §13's stated minimum of 3.1.5 (i.e. 2.x is already unsupported, not a parallel target). §6's "confirmed against the SurrealDB v2.3.3 grammar" claim (re: subquery-based write hiding) should be re-verified against the 3.x grammar the project actually targets.
- **Version-pin change checklist mismatch.** SPEC §13 lists three artifacts to update when changing the version pin: (a) §13 itself, (b) the layer-2 version probe, (c) the CI service-container image tag. AGENTS.md's checklist lists SPEC.md §13, `.github/workflows/ci.yml`, and `Makefile`'s `SURREALDB_MIN_VERSION`. The two lists should be unioned so both documents name all four artifacts consistently.
- **`_access_grant` schema.** No unique index on `(username, group_name)` in `schema/init.surql` (§8) — duplicate grant rows are harmless but add noise/drift. Cheap to add a composite unique index up front.
- **Client identity default via `$USER`.** §9's default socket path is derived from the calling process's own username via (presumably) an environment variable. Harmless from a security standpoint (the kernel-enforced socket permission is the actual check, not the client's self-reported identity), but deriving the default path from `getuid()` → passwd lookup instead of the spoofable `$USER` env var would avoid confusing failure modes when `$USER` is unset or wrong in a given shell/container.
- **Appendix B.4 footgun.** An empty `and` array compiles to `TRUE` (matches everything). On a `delete` call, a programmatically-built empty condition object therefore wipes the entire table. This is consistent with omitting `where` entirely, but is worth a deliberate design decision (e.g. requiring an explicit, distinguishable "match all" signal for destructive operations) rather than falling out incidentally from the general `and`/`or` compilation rule.

---

## Verdict

The core architecture — socket-per-identity as the caller-identity mechanism, a small typed write surface with bound parameters only, the two-credential (read-write / read-only) split, and fail-closed reload semantics — is sound, and the threat model in §3 is stated honestly rather than oversold.

However, items **1–3** each puncture a guarantee the spec claims elsewhere (the keyword screen's coverage, the exclusivity of `dba_execute` as the write path to `_access_*`, and the "structural" nature of the identity-management exclusion), and items **4–6** mean an implementer following the spec literally will hit either a contradiction or a real bug in security-sensitive code (`internal/dba/`, `internal/policy/`).

Recommend resolving 1–8 in `SPEC.md` itself before writing any implementation code — all are cheap to fix at the design stage and materially more expensive once the conformance test suite (layer 4) and the tier×operation validation harness (`tests/harness/validate.sh`) have calcified the current protocol shape.
