# surrealdb-guard — Specification

*Status: design, unimplemented.*

---

## 1. Motivation

SurrealDB's system-user model (`DEFINE USER ... ROLES OWNER|EDITOR|VIEWER`) grants roles at the level of an entire namespace or database. There is no built-in way to say "this identity may write to tables A and B, and only those." Two consequences follow for any team or product that lets more than one OS-level identity reach a shared SurrealDB instance directly (a shared build/agent host, a set of internal services, a set of shell users):

- Every identity with write access effectively has write access to everything, unless enforcement is bolted on somewhere else (application code, code review, convention) — which is enforcement in name only, since it's trivially bypassed by anyone who can run a different command.
- SurrealDB has no Unix-domain-socket transport (`surrealdb/surrealdb#1614`, open since January 2023), so there's no kernel-attested way to know *which* OS identity is calling without inventing one.

This isn't a hypothetical gap. `surrealdb/surrealdb#7092` ("Table-level permissions for `DEFINE USER`"), filed independently by another user, describes exactly this problem — "In a multi-service architecture where multiple services share a single SurrealDB database, it is desirable to restrict each service to only the tables it needs" — and names the current workaround as "access control enforced at the application layer rather than the database layer," i.e. the non-solution above. As of this writing both issues remain open.

`surrealdb-guard` closes this gap without needing SurrealDB itself to change: it is a small daemon that sits between OS-level identities and SurrealDB, using Unix sockets (one per identity, kernel-permissioned) as the caller-identity mechanism, and enforcing per-identity table-group write policy before forwarding anything to the database. Reads are unrestricted SurrealQL, so nothing about SurrealDB's query power is lost for exploration — only the write surface is mediated.

## 2. Goals and non-goals

**Goals:**

- Let several OS-level identities on the same host reach one SurrealDB instance, each restricted to writing only an assigned subset of tables, with no way to bypass the restriction by choosing a different client or query shape.
- Make the restriction mechanically enforced (kernel file permissions + typed operations), not convention-based.
- Keep read access simple and unrestricted: every identity can run arbitrary SurrealQL reads.
- Support a small number of privilege tiers (three — see §4.1) rather than a full custom RBAC system.
- Be usable and testable without root, without a real deployment, and without a running SurrealDB instance for the bulk of the test suite.

**Non-goals:**

- **Not a wire-compatible SurrealDB endpoint.** Existing SurrealDB SDKs and the `surreal` CLI cannot point at this proxy; see §6 for why, and what a thin client instead provides.
- **Not row-level or field-level access control.** Table-group granularity only. A caller with write access to a table can write any row and any field of it.
- **Not a general-purpose connection pooler or query cache.** It exists to enforce identity-scoped write policy; anything else is incidental.
- **Not a replacement for SurrealDB's record-user model.** Record users (`DEFINE ACCESS` / scopes) solve a different problem — end-user application auth — and can coexist with this proxy, which targets shared-host, system-user-style access.
- **Not encryption in transit.** The proxy assumes a trusted localhost link to SurrealDB and a trusted host for the Unix socket. It is not a substitute for host hardening.
- **Not a defence against a fully compromised host.** See §14.

## 3. Threat model

State this precisely, because it is easy to oversell a tool like this:

**Defends against:** an identity that is behaviourally trusted but should not have unrestricted database authority — a script, a service account, or an AI agent running under its own OS user, that might (through a bug, a bad prompt, a misconfiguration, or a wrong assumption) attempt to write to a table it has no business touching. The identity is not assumed to be trying to defeat the proxy; it's assumed to be capable of running *any* command under its own UID, including a hand-written client of the wire protocol, and the enforcement must hold regardless.

**Does not defend against:**
- A process with root or the ability to escalate to root on the same host (root can read the proxy's SurrealDB credentials directly, or bypass the proxy entirely).
- A deliberately adversarial identity actively trying to find and exploit a bug in the proxy itself, versus one that simply runs an unexpected command. The proxy is not a hardened security boundary against a skilled, motivated attacker with local code execution under one of the mediated identities — it is a mechanical policy gate against ordinary mistakes and ordinary scripts.
- Anything upstream or downstream of the proxy: SurrealDB's own vulnerabilities (the proxy inherits whatever SurrealDB's HTTP surface is exposed to), host compromise, supply-chain issues in dependencies.

**Known sharp edges that must be documented loudly wherever this tool is described, not buried:**
- The `dba_execute` escape hatch (§4.1, tier `dba`) screens for identity-management statements with a **keyword screen over statement text, not a full SurrealQL parse** (§6.4's rule that caller-supplied values are always bound parameters, never interpolated SurrealQL text, explains why a full parse is the harder problem this tool otherwise avoids by using typed operations for the *regular* write surface). The screen over-rejects on purpose; it is not a formal guarantee against a determined DBA-tier identity trying to construct a bypass. It runs as defence in depth on top of the `EDITOR` credential's own IAM exclusion (§7.2, §4.1).
- The read-only (`query`) channel's correctness depends entirely on the underlying SurrealDB `VIEWER` role actually being read-only. This must be verified against the specific SurrealDB version in use before relying on it (§13).

## 4. Core concepts

### 4.1 Identities and tiers

Every caller connects through exactly one Unix socket, and the socket determines the caller's identity (§5). Each identity is assigned exactly one of three fixed tiers:

| Tier | Read | Write | Schema (DDL) | Identity management |
|---|---|---|---|---|
| `contributor` | all tables | only tables in groups granted to this identity (§4.2) | no | no |
| `writer` | all tables | all tables | no | no |
| `dba` | all tables | all tables | yes, via `dba_execute` | no (structurally excluded — see below) |

The ladder is a strict progression: `dba` ⊇ `writer` ⊇ `contributor`. None of the three tiers can manage identities (create, delete, or reassign the tier of any identity) — that capability doesn't exist anywhere in the proxy's own request surface at all; it lives entirely in whatever renders the proxy's configuration file (§7), which is deliberately outside this project's scope (§15). This exclusion is enforced at three independent layers:

1. **No proxy method issues identity-management SurrealQL.** No handler in the proxy constructs `DEFINE USER`, `ALTER USER`, `REMOVE USER`, `DEFINE ACCESS`, `ALTER ACCESS`, `REMOVE ACCESS`, or `ACCESS ... GRANT/REVOKE/PURGE` under any code path.
2. **The `dba_execute` keyword screen** (§3, §6.3, Appendix C) rejects any caller-supplied statement containing an identity-management keyword before it reaches the database.
3. **SurrealDB's own RBAC** rejects any identity-management statement that reaches the database, because the proxy's read-write credential is `EDITOR`, not `OWNER` — the `EDITOR` role is documented to exclude user and access-method resources (§7.2). Even if layers 1 and 2 were both bypassed, layer 3 refuses.

The tier ladder is fixed at exactly these three levels in this version and is not user-extensible; see §16 if your access model needs a different shape.

Tier names were chosen to describe capability rather than to match any particular organization's role vocabulary, and deliberately avoid colliding with SurrealDB's own `OWNER`/`EDITOR`/`VIEWER` system-user roles (which this proxy uses internally, at a different layer — §7.2). Adopters are free to map their own organizational roles onto these three tiers however makes sense (e.g. "read-only human," "on-call engineer," "CI service account" might all reasonably map to `contributor` with different grants).

### 4.2 Table groups and grants

Write access for `contributor`-tier identities is managed at the granularity of **table groups**, not individual tables:

- A table group is a named set of tables.
- Every table SurrealDB knows about is expected to belong to at most one group. §8 defines the exact reload-time behaviour for the edge cases: a table appearing in two or more groups is a hard error (writes to it refused, logged at error level), and a table in no group at all is a warning (writes to it are simply denied for `contributor`-tier callers by construction, since it's in nobody's grant set). The two directions are not symmetric — see §8 for the rationale.
- Write access is granted or revoked on a group as a whole — not on individual tables within it.
- Any number of identities may hold write access to a given group; an identity's grants are a set of group names with no ordering or precedence.
- A newly configured `contributor` identity has no grants and can write nothing until the `dba` tier (or whatever process seeds initial state) grants one or more groups.

Groups and grants are stored in the database itself (§8), not in the proxy's configuration file, specifically so that granting or revoking access takes effect immediately without restarting or reconfiguring the proxy.

## 5. Architecture

```
  OS identity (e.g. alice, uid=1001)
             │
             │  Unix socket (kernel-enforced file permissions = the auth)
             │  /run/surrealdb-guard/alice.sock
             │  owner: root, group: alice, mode: 0660
             ▼
  ┌──────────────────────────────────────────────────────┐
  │  surrealdb-guard  (daemon, typically root-owned)     │
  │  Go                                                  │
  │                                                       │
  │  - One socket per identity; identity = socket path    │
  │  - Tier config from a root-owned config file         │
  │  - Groups/grants read from _access_* tables in the DB │
  │  - reads  → arbitrary SurrealQL, read-only credential │
  │  - writes → typed ops, policy check, read-write cred. │
  │  - dba_execute → arbitrary SurrealQL (dba tier only)  │
  └──────────────────────────────────────────────────────┘
             │
             │  HTTP (loopback or private network)
             │  two credentials: read-write + read-only
             ▼
  ┌──────────────────────────────────────────────────────┐
  │  SurrealDB                                           │
  │  (mediated identities hold no credentials at all)    │
  └──────────────────────────────────────────────────────┘
```

**Why a Unix socket per identity, specifically:** the socket path *is* the identity. A connection accepted on `<name>.sock` is attributed to `<name>` because the kernel's permission check on `connect()` guarantees only that user (or root) could have connected — there is no additional handshake, token, or credential exchange. Socket files are root-owned (`0660`, group = the identity), and the socket directory is root-owned (`0755`), so no mediated identity can `chmod`, `chown`, delete, or recreate its own socket, or anyone else's. The proxy asserts the expected owner/group/mode of every socket at startup and on each reload, and refuses to serve any socket whose permissions have drifted (fail closed, log loudly).

**Why the daemon talks HTTP to SurrealDB rather than something more exotic:** the socket's only job is establishing caller identity for the hop that otherwise has none (an OS shell has no notion of "which identity" beyond its own UID); SurrealDB's HTTP API is simply the transport SurrealDB itself speaks. The proxy authenticates to SurrealDB under its own two service credentials (§7.2) and never carries the caller's identity across that hop — enforcement happens entirely on the socket side.

**Why the proxy needs to run with elevated privilege:** creating sockets owned by multiple different Unix groups requires it. The proxy performs no other privileged operation — all request handling is ordinary goroutine-per-connection concurrency, and SurrealDB access is over plain HTTP to a service the proxy doesn't otherwise control.

**Road not taken — `SO_PEERCRED` / `getpeereid()`:** the conventional Unix identity mechanism for a shared socket is `SO_PEERCRED` (Linux) or `getpeereid()` (BSD/macOS): a single socket accepts connections from all callers, and the daemon calls `getsockopt(SO_PEERCRED)` on each accepted connection to learn the connecting UID/GID. This approach is used by systemd's socket activation, PostgreSQL's `unix_socket_permissions`, Docker's socket group, and similar infrastructure. It is equivalent in security to the one-socket-per-identity approach taken here. The reason for the deviation: with `SO_PEERCRED`, the identity of an accepted connection is determined by a syscall that **must not be forgotten or incorrectly skipped** in the request-handling path. The one-socket-per-identity approach makes identity a structural property of which socket file was connected to — the identity is established at `accept()`, before any application code runs, and there is no code path in which it could be omitted. The tradeoff is a more complex socket lifecycle (create, `chown`, permission-assert, tear down per identity) in exchange for eliminating the possibility of a handler goroutine that silently skips the credential check.

## 6. Protocol

The proxy speaks a small line-delimited JSON-RPC protocol over each socket: one JSON object per request line, one per response line. No streaming, no multiplexing.

**Why not a wire-compatible SurrealDB endpoint?** Three reasons:

1. No existing SurrealDB SDK or the `surreal` CLI supports Unix-domain-socket transport (they select transport from a `ws://`/`http://` connection URL), so wire compatibility would not deliver drop-in client support anyway — reaching the socket at all requires custom client code regardless of protocol shape. A TCP listener would restore drop-in compatibility but destroys the entire identity mechanism (a TCP connection on localhost carries no attested caller identity).
2. Enforcing write policy on arbitrary, unparsed SurrealQL is a parsing problem, and a single parsing gap is a policy bypass. Concretely: SurrealQL subqueries are legal in `WHERE` and `SET`/`CONTENT` expression positions and can themselves contain `CREATE`/`UPDATE`/`DELETE`/`INSERT`/`RELATE`/`UPSERT` and even DDL — the `Subquery` AST in the SurrealDB 3.x grammar admits all of these. A write can hide several subqueries deep inside a clause that looks like a read. This is why the write surface is a small typed operation set instead (§6.3) — policy enforcement becomes a set-membership check on a structured field, not a parse of arbitrary text.
3. Reads don't have this problem, so reads aren't restricted at all: `query` accepts arbitrary SurrealQL and runs it under a read-only database credential, so read-only-ness is enforced by SurrealDB's own RBAC rather than by the proxy inspecting the query text. No parsing, no coverage gaps, full SurrealQL expressiveness (graph traversal, vector/full-text search, aggregations, schemaless tables, `INFO FOR ...`, `SHOW CHANGES`) for the fully-permitted read surface.

### 6.1 Transport and framing

Unix domain socket, `SOCK_STREAM`. Each request and response is exactly one JSON object followed by a newline (`\n`). No fragmentation handling beyond standard newline-delimited buffering is required in v1.

**Protocol framing:** the proxy uses **JSON-RPC 2.0** as its framing standard. Every request must include `"jsonrpc": "2.0"` and a non-null `"id"`. Every response includes `"jsonrpc": "2.0"` and echoes the same `"id"`. This aligns the framing with a well-known, widely-understood standard and gives every language ecosystem at least one off-the-shelf JSON-RPC library to build on; SurrealDB's existing clients using `ws://`/`http://` URLs are still not directly usable because they do not support Unix-domain-socket transport (§6, reason 1).

**Request `id`:** JSON-RPC 2.0 permits an `id` of type string, number, or null (with special semantics for null). This proxy accepts a `string` or a `number` (JSON integer or floating-point; the proxy echoes back the exact JSON scalar received) and rejects `null` and any other type with `INVALID_PARAMS`. A missing `id` field is treated as a notification (see below).

**Notifications and batch requests: not supported.** JSON-RPC 2.0 permits notifications (requests with no `id` field, to which the server sends no response) and batch requests (a JSON array of request objects). This proxy supports neither in v1:

- A request object with no `id` field, or with `"id": null`, is rejected with an error response bearing `id: null` and error code `INVALID_PARAMS`.
- A top-level JSON array (a batch request) is rejected with an error response bearing `id: null` and error code `INVALID_PARAMS`.

Both restrictions are explicit design decisions rather than unspecified code paths: notifications provide no way to surface a `DENIED` or `DB_ERROR` result, which is unacceptable for a policy-enforcement layer; batch requests complicate the policy check (each element could target a different table under a different tier decision) with no compensating benefit, given the read-then-write-by-ID idiom already needs a `query` before the write. A batched `transact` operation is on the roadmap (§16) but is a typed method with its own semantics, not JSON-RPC batching.

**Message-size and concurrency limits** are specified in §6.5.

### 6.2 Request/response schema

**Request:**

```json
{
  "jsonrpc": "2.0",
  "id": "<string or number — caller-chosen, echoed back verbatim>",
  "method": "<query | create | update | upsert | delete | insert | relate | dba_execute>",
  "params": { ... }
}
```

**Response (success):**

```json
{ "jsonrpc": "2.0", "id": "...", "result": [ ... ] }
```

**Response (error):**

```json
{
  "jsonrpc": "2.0",
  "id": "<same as request, or null if id was unparseable>",
  "error": {
    "code": <integer>,
    "message": "<human-readable string>",
    "data": { "symbol": "<DENIED | DB_ERROR | INVALID_PARAMS | UNKNOWN_METHOD | INTERNAL_ERROR | PARSE_ERROR>" }
  }
}
```

**Error codes.** JSON-RPC 2.0 requires `error.code` to be an integer. The proxy uses the reserved JSON-RPC codes where they apply and the implementation-defined server-error range (`-32000` to `-32099`) for the rest. The symbolic name is carried in `error.data.symbol` so clients can branch on a stable identifier without hard-coding the integer:

| Symbolic name | Integer code | Meaning | Trigger |
|---|---|---|---|
| `PARSE_ERROR` | `-32700` | Malformed JSON (reserved JSON-RPC code) | Request line is not valid JSON |
| `INVALID_PARAMS` | `-32602` | Request shape is invalid (reserved JSON-RPC code) | Missing/wrong `jsonrpc`/`id`/`method`/`params`; batch or notification; parameter grammar violation |
| `UNKNOWN_METHOD` | `-32601` | Method does not exist (reserved JSON-RPC code, "Method not found") | `method` is not one of the eight listed in §6.3 |
| `INTERNAL_ERROR` | `-32603` | Proxy bug (reserved JSON-RPC code) | Unexpected internal failure in the proxy itself, not attributable to the caller or SurrealDB |
| `DENIED` | `-32000` | Policy denial (server-defined) | Caller lacks tier/grant for this operation, `_access_*` hard-denial, `dba_execute` keyword screen |
| `DB_ERROR` | `-32001` | SurrealDB returned an error (server-defined) | SurrealDB HTTP call failed or returned a statement error |

Clients should treat any code in the reserved JSON-RPC range as protocol-level; codes in the server range (`-32000` to `-32099`) are proxy-defined and identified by `error.data.symbol`.

**`result` shape per method:**

The `result` field is always an array. Its contents depend on the method:

| Method | `result` contents |
|---|---|
| `query` | An array of statement results, each `{"status": "OK"\|"ERR", "time": "<duration>", "result": <value>}` — SurrealDB's `/sql` response format passed through verbatim. Multi-statement SurrealQL produces multiple array entries, one per statement. |
| `create` | A single-element array containing the created record object (SurrealDB's `/rpc` `create` response). |
| `update` | An array of updated record objects (one per affected record). |
| `upsert` | A single-element array containing the upserted record object. |
| `delete` | An array of deleted record objects (one per deleted record). |
| `insert` | An array of inserted record objects (one per inserted row). |
| `relate` | A single-element array containing the created edge record. |
| `dba_execute` | Same shape as `query` — an array of statement results in SurrealDB's `/sql` format. |

**Empty result arrays** (`[]`) are valid and indicate zero rows were affected (e.g. a `delete` where the `where` condition matched nothing). They are not errors.

### 6.3 Methods

| Method | Params | Credential used | Policy check |
|---|---|---|---|
| `query` | `surql`, `params?` | read-only | None — the database enforces read-only |
| `create` | `target`, `content` | read-write | Target table vs. caller's effective write set |
| `update` | `targets`, `where?`, `content`, `mode: merge\|patch\|replace` | read-write | Checked |
| `upsert` | `target`, `content`, `mode?` | read-write | Checked |
| `delete` | `targets`, `where?` | read-write | Checked |
| `insert` | `target`, `values[]` | read-write | Checked |
| `relate` | `from_ids`, `with_ids`, `table`, `content?` | read-write | Relation table and both endpoint tables all checked |
| `dba_execute` | `surql` | read-write | Caller tier must be `dba`; identity-management statements rejected (§3, §4.1) |

For write methods, the proxy extracts the target table(s) from the structured `target`/`targets` parameter and checks every one against the caller's effective write set (union of `tables` across all groups the caller is granted — §4.2, §8). `update` and `delete` accept a `targets` array, but every element in a single call **must refer to the same table** (Appendix A) — this keeps the policy check a single-table decision and eliminates the need to reason about partial denials on a mixed-table call. Callers wanting to touch multiple tables must issue one call per table. `relate` names three tables (the relation table plus both endpoints); **every** named table must be in the write set, or the whole call is `DENIED`, naming the caller and the offending table.

`writer` and `dba` tier callers skip the group check entirely (write-all is their tier semantic). `dba_execute` is available only to `dba`-tier callers.

**Hard denial for `_access_*` tables (all tiers):** any typed write method whose `target`/`targets` refers to a table whose name begins with `_access_` is rejected with `DENIED` *before* the tier and group checks are consulted, regardless of caller tier. The `_access_group` and `_access_grant` tables (§8) are the proxy's own bookkeeping state; `dba_execute` is their only sanctioned write path. This is a hard rule — not overridable by tier — so that a bug in tier assignment or grant resolution cannot itself become an access-management escalation. Reads are unaffected: `query` can `SELECT` from `_access_*` freely.

Multi-statement transactions are not supported in v1; see §16 for a batched `transact` operation as a candidate future addition.

### 6.4 Caller-supplied expressions are data, never SurrealQL text

The protocol never interpolates a caller-supplied string into the SurrealQL it constructs — this is what makes the typed write surface safe under a shared read-write credential:

- **Targets** (`target`/`targets`) must match a strict grammar — a bare table identifier or a record ID — validated before use. Anything else is `INVALID_PARAMS`.
- **`content`/`values`** travel as bound parameters in the request body to SurrealDB's `/rpc` endpoint; the proxy constructs the statement text itself and never treats caller data as anything but a typed, bound value. This applies even to schemaless (`SCHEMALESS`) tables: a caller with write access can set arbitrary field names via `content`, exactly as with a hand-written statement — field-level restriction is explicitly out of scope for this tool (§2), so that's expected, not a gap.
- **`where`** accepts a structured condition object (field paths, comparison/containment operators, parameter-bound values), which the proxy compiles into a `WHERE` clause itself. The condition grammar is deliberately small. When selection logic needs more than it expresses, the idiom is **read-then-write-by-ID**: resolve the record set with a full-SurrealQL `query` call (read-only credential, so any write hiding in a subquery is rejected by the database itself), then issue the typed write against the explicit record IDs returned. This two-step is not transactional (§16 lists a batched `transact` operation as a way to close that gap later).

**`insert` semantics:** `insert` maps to SurrealDB's `INSERT INTO <table> <values>`. The `values` field is an array of content objects; the proxy forwards them as a single bulk `INSERT` under a bound parameter. `INSERT INTO ... ON DUPLICATE KEY UPDATE` (upsert-on-conflict) is **not** exposed through this method — callers that need upsert semantics should use `upsert`. Duplicate-ID conflicts on a plain `insert` surface as a `DB_ERROR`.

**`upsert` semantics:** `upsert` maps to SurrealDB's `UPSERT <target> CONTENT <content>`. The `mode` parameter controls the merge behaviour:

| `mode` | SurrealDB statement | Effect |
|---|---|---|
| `replace` (default) | `UPSERT <target> CONTENT <content>` | Replaces the entire record if it exists; creates it if not. |
| `merge` | `UPSERT <target> MERGE <content>` | Merges the supplied fields into the existing record (existing fields not in `content` are preserved). |

Conditional forms (`UPSERT ... WHERE ...`) are not exposed in v1. If conditional upsert logic is required, use the read-then-write-by-ID idiom: resolve the record set with a `query`, then `upsert` by explicit record ID.

`RELATE` writes only the edge record (endpoints are referenced, not modified — the proxy still checks all three tables involved, conservatively). Schema-defined machinery such as `DEFINE EVENT` or `DEFINE FIELD ... VALUE` can cause one statement to write other tables as a side effect — acceptable, because defining such machinery is itself a `dba_execute`-gated act.

### 6.5 Resource limits

The proxy imposes the following limits per connection. Exceeding any of them results in a `INVALID_PARAMS` error response (when the offending message boundary is still recoverable) followed by the daemon closing the connection. A closed connection is not re-established automatically; clients are expected to reconnect.

| Limit | Default | Rationale |
|---|---|---|
| Maximum request line length | **1 MiB** (1 048 576 bytes, including the terminating newline) | Bounds memory per unterminated line; large enough for a reasonable `insert` batch or a moderately complex `query`. |
| Maximum response line length | Unbounded (a well-formed SurrealDB result may exceed 1 MiB) | The proxy trusts SurrealDB's own response; if a response exceeds the client's buffer, that's a client concern. |
| Maximum concurrent in-flight requests per connection | **8** | Bounds goroutine/thread creation per socket. A 9th concurrent request is rejected with `INVALID_PARAMS`; the connection stays open. |
| Per-request timeout | **30 s** | Wall-clock from request receipt to response send. On timeout, the proxy cancels the in-flight SurrealDB HTTP call, responds with `DB_ERROR` naming "timeout" in `error.message`, and keeps the connection open. |
| Maximum idle time between requests | **300 s** | Idle connections older than this are closed by the proxy. Clients are expected to reconnect on their next request. |

**Line-length breach behaviour.** When a request line exceeds the maximum, the proxy stops reading further bytes as soon as the limit is hit (i.e. does not buffer the tail of the malformed line). It sends a single error response with `id: null`, `code: -32602`, `error.data.symbol: "INVALID_PARAMS"`, `error.message` naming "request line too long", and then closes the connection. This avoids the pathological case of a caller streaming an unterminated line to exhaust proxy memory.

**Configurability.** The defaults above are compiled in and can be overridden in `config.yml` under a `limits:` block (schema TBD in implementation). Overrides are logged at startup so a deployment's effective limits are visible.

## 7. Configuration

### 7.1 `config.yml`

A single YAML file, read at startup and on reload (SIGHUP or a periodic timer):

```yaml
socket_dir: /run/surrealdb-guard
identities:
  - username: alice
    tier: writer
  - username: bob
    tier: dba
  - username: carol
    tier: contributor
  - username: dave
    tier: contributor
surrealdb:
  endpoint: http://127.0.0.1:8000
  namespace: myapp
  database: production
  # credentials come from the environment file below, not from this file
```

This file is the entire interface between the proxy and whatever system assigns identities and tiers (an org's provisioning tooling, a config-management system, a hand-edited file for small deployments). The proxy does not care how this file came to exist or how it's kept in sync with reality — that's explicitly out of scope (§15).

### 7.2 Credentials

The proxy holds exactly two SurrealDB credentials, defined as ordinary SurrealDB system users (unrelated to any of the mediated OS identities, which hold no SurrealDB credentials at all):

| Credential | SurrealDB role | Used for |
|---|---|---|
| Read-write | `EDITOR` | typed writes, `dba_execute` |
| Read-only | `VIEWER` | the `query` channel |

Both live in a root-owned environment file (mode `0600`), loaded via the proxy's process manager (e.g. systemd's `EnvironmentFile=`) rather than the YAML config, so that config files can be committed to version control without leaking secrets.

**Why `EDITOR` and not `OWNER` for the read-write credential.** SurrealDB's built-in `EDITOR` role, per the [official documentation for `DEFINE USER`](https://surrealdb.com/docs/reference/query-language/statements/define/user), "can view and edit any resource on the user's level or below, but not users or token (IAM) resources." It grants full DDL for tables, fields, indexes, events, functions, params, analyzers, and (at namespace/root scope) databases and namespaces — everything the `dba_execute` allow-list in Appendix C.3 exposes — while structurally excluding `DEFINE USER`, `ALTER USER`, `REMOVE USER`, `DEFINE ACCESS`, `ALTER ACCESS`, `REMOVE ACCESS`, and the `ACCESS ... GRANT/REVOKE/PURGE` statement family. With this choice, the identity-management exclusion §4.1 calls "structural" is enforced by SurrealDB itself: any identity-management statement reaching the database is rejected by the database's own RBAC, independent of whether the keyword screen (§3, Appendix C) caught it. The keyword screen becomes defence in depth — a fast client-side rejection with a clean error message — rather than the sole guarantee.

**Trade-off:** creating a database-scoped `EDITOR` (the recommended level; see §7.1's `namespace`/`database` fields) does not allow the proxy to create new namespaces or databases via `dba_execute`. A `dba`-tier caller can still issue `DEFINE / REMOVE TABLE` and every other DDL statement in Appendix C.3 within the configured namespace and database. If a deployment genuinely needs runtime `DEFINE NAMESPACE` or `DEFINE DATABASE` (uncommon — these are usually one-shot deployment operations), the read-write credential can be provisioned at namespace or root level as `EDITOR`; it still holds no identity-management authority. Provisioning it as `OWNER` is not supported and would silently reintroduce the identity-management surface this design exists to exclude.

**Version pin dependency.** The `EDITOR` role's exclusion of IAM resources is documented for SurrealDB 3.x. The version probe in the layer-2 tests (§12, §13) must include a standing check that `EDITOR` cannot issue `DEFINE USER`, `ALTER USER`, `REMOVE USER`, `DEFINE ACCESS`, `ALTER ACCESS`, `REMOVE ACCESS`, or `ACCESS ... GRANT`, alongside the existing check that `VIEWER` cannot write. If a future SurrealDB release ever widens `EDITOR`'s authority, the probe fails loudly rather than silently regressing the identity-management exclusion.

## 8. Database schema owned by the proxy

Two tables, prefixed `_access_` to mark them as belonging to the access-control mechanism itself rather than to any adopter's own schema:

```surql
DEFINE TABLE IF NOT EXISTS _access_group SCHEMAFULL;
DEFINE FIELD name   ON _access_group TYPE string;
DEFINE FIELD tables ON _access_group TYPE array<string>;
DEFINE INDEX IF NOT EXISTS access_group_name ON _access_group FIELDS name UNIQUE;

DEFINE TABLE IF NOT EXISTS _access_grant SCHEMAFULL;
DEFINE FIELD username   ON _access_grant TYPE string;
DEFINE FIELD group_name ON _access_grant TYPE string;
DEFINE INDEX IF NOT EXISTS access_grant_username ON _access_grant FIELDS username;
DEFINE INDEX IF NOT EXISTS access_grant_unique ON _access_grant FIELDS username, group_name UNIQUE;
```

The composite `UNIQUE` index on `(username, group_name)` prevents duplicate grant rows. Duplicates would be harmless — the proxy's grant-lookup code takes the set union — but they add drift and noise; rejecting them at write time keeps `_access_grant` clean.

This DDL is fixed and identical for every deployment — it's the proxy's own bookkeeping state, not something each adopter should have to hand-copy from documentation. The proxy ships an idempotent schema-initialization step (a CLI subcommand and/or a startup check) that issues this DDL under the read-write credential. These two tables are readable by everyone (like all tables, via `query`) and writable only through `dba_execute` — the hard-denial rule in §6.3 rejects any typed write targeting a table whose name begins with `_access_`, regardless of caller tier, and the reload-time validation described later in this section refuses to load any `_access_group` row whose `tables` array names such a table.

Groups and grants live in the database rather than in `config.yml` specifically so that a `dba`-tier identity can grant or revoke access at runtime, with immediate effect, without restarting or reconfiguring the proxy:

```surql
-- Create a group
INSERT INTO _access_group { name: "reports", tables: ["invoice", "payment"] };

-- Grant / revoke
INSERT INTO _access_grant { username: "carol", group_name: "reports" };
DELETE _access_grant WHERE username = "carol" AND group_name = "reports";
```

**Reload behaviour:** because every grant change necessarily flows through the proxy itself (`dba_execute` is the only write path to `_access_*`), the proxy reloads its group/grant cache after every `dba_execute` call, with a periodic reload (e.g. every 60s) and a signal handler as backstops for out-of-band changes.

**Invariant enforcement:** on each reload, the proxy builds a `table → group` map and enforces the following:

- If any table appears in two or more groups' `tables` arrays, the proxy fails loudly (refusing all writes to the affected tables, logging at error level).
- If any `_access_group` row's `tables` array contains a name beginning with `_access_` (i.e. an attempt to make the access-control tables themselves writable through the group/grant mechanism), the offending group is rejected: the entire group is treated as if it had no tables, writes to any table listed under it are denied, and the condition is logged at error level. This complements the hard-denial rule in §6.3 — the proxy refuses to load a policy that would encode such a grant even if a `dba_execute` bypass or direct database mutation ever succeeded in creating one.
- A table present in the database but named in no group is logged as a warning; writes to it are denied for `contributor`-tier callers by construction, since it's in nobody's grant set.

**A known rough edge:** Unix usernames appear as plain strings in `_access_grant` rows, so removing or renaming an identity in `config.yml` leaves orphaned rows behind. This is benign by construction — an orphaned grant matches no live socket, so it's simply inert — but it is drift, and the proxy logs orphaned rows as warnings on each reload rather than silently ignoring them. See §16 for a dedicated cleanup tool as a candidate addition.

**Reload semantics for in-flight requests and structural changes:**

A reload is triggered by SIGHUP, the periodic timer, or the post-`dba_execute` hook. The following rules govern edge cases:

| Event | Behaviour |
|---|---|
| An identity is removed from `config.yml` on reload | Its socket is closed and removed from the listening set. In-flight requests on that socket (i.e. requests already accepted and dispatched to a goroutine before the reload) complete normally; the socket is not torn down until the goroutine returns. New `connect()` calls on the old socket path fail at the kernel level once the socket file is removed. |
| `socket_dir` changes on reload | **Fail the reload loudly; do not hot-swap.** A `socket_dir` change requires a restart. The proxy logs an error and continues serving under the original `socket_dir`. |
| A tier changes for an existing identity on reload | The new tier takes effect for all new requests on that identity's socket after the reload completes. In-flight requests that were already dispatched (accepted from the socket, goroutine started) complete under the tier that was in effect when the request was accepted. |
| Groups or grants change (via `dba_execute` path or out-of-band) | The in-memory cache is atomically swapped at the point the reload completes. In-flight requests complete under the cache version that was current when they started (the goroutine holds a snapshot reference). |
| A `config.yml` parse error on reload | The reload is aborted entirely; the previous config remains active. The error is logged at error level. No sockets are changed. |

## 9. Client libraries

Two reference clients ship as part of this project, both exposing one method per protocol method (§6.3) and both connecting to a Unix socket whose default path is derived from the calling process's own effective UID — specifically, `getuid()` followed by a passwd lookup to resolve the UID to a username, yielding `/run/surrealdb-guard/<username>.sock`. An environment variable (`SURREALDB_GUARD_SOCKET`) overrides the default path for tests and non-standard setups.

**Why `getuid()` rather than `$USER`.** The environment variable `$USER` is spoofable (any caller can `USER=someone-else` in their shell or systemd unit) and unreliable (unset in minimal containers, or wrong when a user has switched via `su` without `-` / `--login`). This is not a security concern — the kernel-enforced socket permission is the actual identity check, not the client's self-reported identity — but a `$USER`-derived default produces confusing failure modes (permission denied on a socket the caller doesn't own, when they could have connected fine to a different socket). Deriving the default from `getuid()` matches the identity the kernel is going to enforce anyway, so the client either succeeds or fails for a reason the caller can diagnose from their own UID.

- **Go**, package `surrealdb_guard/client`, in the same module as the daemon. This is the primary reference implementation: since it lives alongside the server, the wire protocol and this client evolve together and it is the first to reflect any protocol change. The CLI (§10) is built on top of it.
- **Python**, package `surrealdb_guard_client` (import name), distributed via PyPI as `surrealdb-guard-client` (distribution name). This dash-vs-underscore split is standard Python packaging convention: PyPI distribution names use hyphens, import names use underscores. `pip install surrealdb-guard-client` installs a package that callers import as `import surrealdb_guard_client`. The `client-python/` directory in the repository uses a hyphenated name by convention; the `pyproject.toml` `[project] name` field is `surrealdb-guard-client`.

Both clients are thin: connect, encode a request per §6.2, write the line, read and decode the response line, surface `error.code`/`error.message` as a typed exception/error value. Neither client contains any policy logic — enforcement is entirely server-side — so keeping the two in sync is a matter of matching the protocol schema, not replicating behavior.

The protocol itself (§6) is documented well enough that a client in any other language can be implemented without depending on either of these packages; the Go and Python clients are the two this project maintains, not the only two that can exist.

## 10. Command-line interface

A minimal CLI ships as part of the Go module, built on the Go client (§9): it reads SurrealQL (for `query`) or a JSON request body (for typed writes and `dba_execute`) from argv or stdin, and prints the JSON response. Shipping it as a single Go binary means it can be dropped onto a host and run with no runtime dependencies (no interpreter, no virtualenv). This is the primary hand-verification tool for any deployment — confirming a grant took effect, or that a write is correctly denied, is a single command rather than something that requires writing a throwaway script.

An interactive REPL (statement history, completion, routing simple writes to the right typed method) is deliberately deferred — see §16.

## 11. Deployment (reference notes)

This project does not ship deployment automation (no Ansible role, Terraform module, or Helm chart) — see §15 for why that's out of scope. It does ship a minimal, clearly-labelled reference example (in a `deploy/` or `contrib/` directory) covering the pieces every deployment needs regardless of orchestration tool:

- An example systemd unit running the proxy as a root-owned system service, with `EnvironmentFile=` pointing at the credentials file (§7.2).
- `tmpfiles.d` configuration for the socket directory, since `/run` (or equivalent) is typically a tmpfs that doesn't survive a reboot.
- A note on socket ownership: whatever creates OS-level identities (user provisioning) must also ensure the proxy's socket directory is writable only by root, and that each identity's Unix group exists before the proxy tries to `chown` its socket to it.

Everything else — how identities are provisioned, how `config.yml` gets rendered, how the credentials file is populated and rotated — is the deploying organization's own concern.

## 12. Testing strategy

Four layers, escalating in fidelity; only the multi-user layer needs a real multi-user host, and none of them requires a privileged or long-lived daemon on a developer's own machine:

1. **Unit tests (runnable anywhere, no root, no SurrealDB).** Unix sockets are ordinary files: the Go test suite starts the proxy in-process, binding sockets under a per-test temp directory (`t.TempDir()`) under the developer's own UID. SurrealDB is replaced with a mocked HTTP transport (`net/http/httptest`). This layer covers the protocol (framing, error mapping), the entire policy algebra (tier semantics, grant unions, multi-target checks, the `dba_execute` keyword screen, condition compilation), and config loading. The Go client also has its own unit tests (encode/decode, error mapping) run against a fake socket listener rather than a full proxy instance.
2. **Local integration tests (still unprivileged).** SurrealDB's own in-memory single-process mode (`surreal start memory`) runs as a plain, disposable, user-owned process on a random localhost port. This layer exercises real query execution, credential RBAC (a standing regression check that `VIEWER` truly can't write, and a standing regression check that `EDITOR` truly can't issue identity-management statements — see §13's caveats), and bound-parameter behaviour. It also includes a **standing concurrency cross-contamination probe** that hammers concurrent `query` (VIEWER credential) and typed-write (EDITOR credential) requests and asserts that no `query` response contains data that could only have been produced under the EDITOR session. This probe directly regresses the class of bug described in `GHSA-4vgr-h27g-cf9p` and must remain green across every SurrealDB version the project supports.
3. **Multi-user host tests (needs a disposable VM or container with real separate OS users).** The pieces the first two layers can't reach — root-owned sockets across genuinely different Unix users, service-manager ordering, `tmpfiles`-style directory setup — are validated here. This is the only layer that needs anything resembling a deployment, and it should be fully disposable (a throwaway container or VM, torn down after the run).
4. **Cross-client conformance (unprivileged, any layer above a running proxy).** Because the Go and Python clients are independent implementations of the same protocol (§9), both are run against the same live proxy instance (in-process for layer 1, or the layer-2 setup) exercising the identical matrix of calls, asserting identical results. This catches drift between the two clients directly, rather than relying on each client's own unit tests to indirectly agree with each other.

A standing validation harness (a script exercising the full tier × operation matrix — reads, granted writes, denied writes, `dba_execute` allow/deny, identity-management-statement rejection) should accompany the project and be runnable against any of the four layers above.

**Platform contract:** the daemon runs on **Linux only** (requires systemd, `tmpfiles.d`, `/run`). Test layers 1, 2, and 4 are portable and run on macOS and Linux. Layer 3 (multi-user host) requires Linux; macOS developers should use a disposable container via Podman (see §5 resource notes) rather than running layer-3 tests on their host. Windows is out of scope.

## 13. SurrealDB version compatibility

**Minimum supported version: SurrealDB 3.1.5.**

SurrealDB 3.1.5 is the minimum required version. This pin exists primarily to exclude all versions affected by `GHSA-4vgr-h27g-cf9p` (HTTP RPC Session Race Condition / Privilege Escalation — see `https://github.com/advisories/GHSA-4vgr-h27g-cf9p`). That advisory describes a race condition in the HTTP `/rpc` handler where concurrent requests can share mutable authentication state, causing an unauthenticated request to execute under an authenticated session's privileges. The proxy's design — two credentials (`EDITOR` and `VIEWER`) making concurrent calls against the same SurrealDB instance — is precisely the scenario the advisory describes. SurrealDB 3.1.5 contains the fix; no version below it is supported for use with this proxy.

The proxy talks to SurrealDB over its stable HTTP surface (`/sql` for `query`/`dba_execute`, the stateless `/rpc` endpoint for bound-parameter typed writes). This surface is expected to remain compatible across SurrealDB 3.x. Two version-specific things need explicit, version-pinned verification rather than an assumption that they "still work":

- **The read-only role must actually be read-only.** Verify with a clean, hand-crafted probe (fresh credentials, explicit response assertions, including a write hidden in a subquery) against every SurrealDB version this project claims to support, and keep that probe as a standing regression check — don't rely on documentation alone.
- **The `EDITOR` role must actually exclude identity-management resources.** The read-write credential is `EDITOR`, not `OWNER` (§7.2), and the "structural" exclusion of identity management in §4.1 depends on SurrealDB's own RBAC refusing `DEFINE USER`, `ALTER USER`, `REMOVE USER`, `DEFINE ACCESS`, `ALTER ACCESS`, `REMOVE ACCESS`, and `ACCESS ... GRANT/REVOKE/PURGE` when issued under `EDITOR` credentials. A standing regression probe issues each of these statements under the read-write credential and asserts each is rejected by SurrealDB.
- **Concurrency cross-contamination.** A standing concurrency cross-contamination probe (§12, layer 2) must continuously hammer concurrent `query` (VIEWER) and typed-write (EDITOR) requests and assert no cross-contamination; this directly regresses `GHSA-4vgr-h27g-cf9p`'s class of bug.
- **SurrealDB 3.x's `--deny-arbitrary-query` flag does not replace this proxy.** It's group-granular (`guest`/`record`/`system`), not per-user, so it cannot distinguish the proxy's own credential from any other system user without also blocking every other system user (including whatever holds schema authority). `DEFINE API` (3.x) likewise doesn't solve the caller-identity problem this proxy solves, because SurrealDB still has no Unix-socket transport (`surrealdb/surrealdb#1614`) and therefore no kernel-attested identity to branch enforcement on inside a `DEFINE API` endpoint — the credential is just a string in the caller's environment. Both are worth revisiting if upstream ever ships per-user query capabilities or a Unix-socket bind; neither currently obsoletes this project.

**Changing the version pin** requires updating all four of the following in the same commit:

1. This section (§13) — the minimum-version statement.
2. The version probe in the layer-2 integration tests (§12).
3. The service-container image tag in `.github/workflows/ci.yml`.
4. The `SURREALDB_MIN_VERSION` variable in the top-level `Makefile`.

`AGENTS.md` mirrors this list; keep the two documents in sync.

## 14. Security considerations

- **Audit logging is a future enhancement** (§16). The v1 daemon does not commit to a specific structured log-line schema. Callers should not depend on log output format. See §16 for the planned richer audit capability.
- **Report vulnerabilities privately**, not as public issues, until a fix is available. (A concrete disclosure contact/process should be added here once the project has a home — email alias, GitHub Security Advisories, etc.)
- **The `dba_execute` keyword screen is not a formal guarantee** (§3). Treat the `dba` tier as a trusted-operator tier, not as a boundary that holds against a `dba`-tier identity actively trying to defeat it.
- **The read-only channel's safety is an assumption about SurrealDB's own RBAC**, not something this proxy independently verifies at runtime beyond what's practical to probe at startup. Pin and test against specific SurrealDB versions (§13).
- **This proxy does not encrypt or authenticate the hop to SurrealDB beyond SurrealDB's own credential check.** Deploying the proxy and SurrealDB on the same host over loopback is the assumed baseline; anything else (a remote SurrealDB instance) needs its own transport security, which is outside this project's scope.
- **A compromised proxy process is equivalent to a compromised `EDITOR` database credential.** The proxy's own attack surface (its socket listeners, its JSON parsing, its dependency tree) should be held to the same scrutiny as anything else that holds live database credentials. Because the read-write credential is `EDITOR` and not `OWNER` (§7.2), a compromised proxy still cannot manage SurrealDB identities — but it can read and write every non-`_access_*` table and issue every non-identity-management DDL statement within the configured namespace/database.

## 15. Relationship to your own provisioning system (out of scope)

**Litmus test for what belongs in this project versus your own deployment:** would a stranger deploying this against their own SurrealDB, their own tables, and their own users need this code? If yes, it belongs here. If it encodes *your* identities, *your* tables, or *your* deployment mechanics, it does not.

Concretely, **not** part of this project, by design:

- Where identities and their tiers come from, and how `config.yml` gets rendered — bring your own provisioning system (a config-management tool, a hand-maintained file, a small internal script). The YAML schema in §7.1 is the entire contract.
- The actual content of your table groups and grants (§8) — that's your schema and your access policy, seeded through `dba_execute` or the CLI (§10) however you like.
- Deployment orchestration beyond the reference notes in §11 (no Ansible role, Terraform module, or Kubernetes manifest is maintained here).
- A declarative "read a file, populate `_access_group`/`_access_grant` rows" seeding tool. This is a plausible convenience (§16) but isn't included in v1 — seeding is a handful of `INSERT`/`DELETE` statements through `dba_execute`, achievable today with the CLI, and a bespoke config format for it isn't justified until someone actually needs one.
- Any generalization of the fixed three-tier model (§4.1) into something pluggable. Ships as-is until a second real deployment demonstrates a need for a different shape.

## 16. Roadmap


Recorded so each has a rationale on file and doesn't need re-litigating when its time comes; none of these block a first release.

- **Loopback firewall rule (documentation, not code).** A host-level rule (e.g. an iptables `OUTPUT`-chain rule matching non-root UIDs) closing direct access to SurrealDB's port entirely. Pure defence in depth on top of §14 — mediated identities hold no credentials, so a direct connection already gets them nothing beyond unauthenticated health endpoints, but a firewall rule removes even that. Documented as a deployment recommendation, not shipped as project code, since it's host/firewall-tooling-specific.
- **Batched `transact` operation.** A typed method carrying a list of write operations executed in one transaction, closing the non-atomicity of the read-then-write-by-ID idiom (§6.4). Policy check: union of all target tables across the batch.
- **Live-query support.** A server-initiated push channel over the Unix socket, with the proxy holding a WebSocket to SurrealDB under the read-only credential and forwarding notifications. Until then, `SHOW CHANGES` polling through `query` is the substitute.
- **Audit logging.** One structured log line per call (identity, method, target table(s), policy outcome, latency), plus metrics export (denial counts, per-identity latency), structured query logging with retention, and alerting on repeated denials. The log-line schema and destination (stderr, syslog, JSON-to-stdout) are to be defined when this work is picked up. This is intentionally deferred so the schema can be specified once, correctly, rather than committed to prematurely.
- **Grant snapshots / config-as-code export.** A periodic job exporting effective `_access_group`/`_access_grant` state to a file, so runtime grant drift from any seeded defaults is reviewable in version control — recovering an as-code property for the one store that must stay runtime-mutable (§8).
- **Multi-instance / high availability.** Running more than one proxy instance against the same SurrealDB (e.g. one per host in a multi-host deployment), sharing the same groups/grants state. No structural blocker anticipated; not validated yet.
- **Interactive REPL** on top of the CLI (§10): statement history, completion, and routing simple write statements to the correct typed method automatically.
- **Continuous SurrealDB 3.x version-matrix testing.** Once CI is running (§12, layer 2), extend it to run against every published SurrealDB 3.x point release ≥ 3.1.5, so that the read-only-role regression check and the concurrency cross-contamination probe fire against every version the project claims to support, not just the pinned one.
- **Orphaned-grant cleanup tooling.** A command that lists (and optionally deletes) `_access_grant` rows whose `username` matches no identity in the current `config.yml`, rather than requiring a hand-written `DELETE` (§8).
- **Declarative groups/grants seeding tool.** See §15 — deferred until demonstrated need.

---

## Appendix A. Grammar for `target` / `targets`

The `target` (single) and `targets` (array) fields accepted by the typed write methods must match one of the following forms. Anything else is rejected with `INVALID_PARAMS` before any policy check or SurrealDB call is made.

```
target     = table_id | record_id

table_id   = ident
record_id  = ident ":" id_part

ident      = [A-Za-z_][A-Za-z0-9_]*

id_part    = integer
           | string_literal          -- single- or double-quoted
           | ulid_literal            -- ULID (26-char base32 string)
           | uuid_literal            -- UUID (8-4-4-4-12 hex form)
           | "{" ... "}"             -- object key — NOT accepted in v1
           | "[" ... "]"             -- array key — NOT accepted in v1
           | range_expr              -- NOT accepted in v1

integer         = [0-9]+
string_literal  = "'" <chars> "'" | '"' <chars> '"'
                  -- see §C.5 for the exact grammar of <chars>, including
                  -- backslash-escape and doubled-quote-escape rules;
                  -- newlines are permitted inside the literal.
ulid_literal    = [0-9A-Z]{26}       -- Crockford base32, 26 characters
uuid_literal    = <8hex> "-" <4hex> "-" <4hex> "-" <4hex> "-" <12hex>
```

**Additional restriction on `id_part` string literals.** Even though §C.5 permits arbitrary Unicode inside a string literal (subject to escape rules), the `id_part` position in a `target` value is restricted further: the *decoded* string content must contain only Unicode code points that are (a) not C0 or C1 control characters (`U+0000`–`U+001F`, `U+007F`–`U+009F`), (b) not the Unicode `Cn`/`Cs` categories (unassigned or surrogate). This is a conservative allowlist chosen to sidestep any downstream ambiguity in log lines or record-ID display without requiring the proxy to decode SurrealQL semantics. A record whose ID key part violates this restriction is rare in practice and can still be reached via a `query` call; the typed write methods just require it to be selected and rewritten by a well-formed record ID first.

**What is accepted:** a bare table name (`invoice`), or a record ID with an integer (`invoice:42`), string (`invoice:'abc'`, `invoice:"abc"`), ULID (`invoice:01HXYZ...`), or UUID (`invoice:018f5e...`) key part.

**What is rejected:** object keys (`invoice:{city:"NYC"}`), array keys (`invoice:[1,2,3]`), ranges (`invoice:1..10`), quoted-identifier table names (`` `my table` ``), and any whitespace in the `target` value. Record IDs with these key forms can still be *selected* via a full-SurrealQL `query` call; the typed write methods simply require an explicit, already-resolved record ID when targeting a specific row.

**`targets` (plural):** an array of `target` strings following the same grammar. All elements must refer to the same table — mixing tables in a single `update` or `delete` `targets` array is not supported and is rejected with `INVALID_PARAMS`. Callers wanting to touch multiple tables issue one call per table. The policy check is applied to the single table name shared by all elements; a caller with write access to that table can therefore issue a single call affecting any subset of its rows.

---

## Appendix B. Grammar for `where` condition objects

The `where` parameter accepted by `update` and `delete` is a structured JSON object, not a SurrealQL string. The proxy compiles it into a `WHERE` clause using only bound parameters — no caller-supplied text is ever interpolated.

### B.1 Grammar

```
condition   = comparison | containment | null_check
            | { "and": [ condition, ... ] }
            | { "or":  [ condition, ... ] }
            | { "not": condition }

comparison  = {
    "field": field_path,
    "op":    "=" | "!=" | "<" | "<=" | ">" | ">=",
    "value": scalar
}

containment = {
    "field": field_path,
    "op":    "IN" | "NOT IN" | "CONTAINS" | "CONTAINS ANY" | "CONTAINS ALL",
    "value": scalar | [ scalar, ... ]
}

null_check  = {
    "field": field_path,
    "op":    "IS NULL" | "IS NOT NULL"
}

field_path  = ident ( "." ident )*
              -- dotted paths only; array indexing and record-link traversal
              -- (-> / <-) are not supported in v1.

scalar      = string | number | boolean | null
```

### B.2 Depth limit

`and`/`or`/`not` nesting is capped at **8 levels**. Deeper trees are rejected with `INVALID_PARAMS`.

### B.3 Null / type coercion

- `null` in a `value` position is a typed JSON null, passed as a bound parameter. The database applies its own null/undefined semantics.
- No implicit type coercion is performed by the proxy. A `number` value is forwarded as a number, a `string` as a string, etc.
- Using `"op": "IS NULL"` or `"op": "IS NOT NULL"` ignores any `"value"` key present.

### B.4 Empty `and`/`or` arrays

An empty `and` array compiles to `TRUE` (no restriction); an empty `or` array compiles to `FALSE` (matches nothing). Both are accepted rather than rejected, to allow callers to build conditions programmatically without special-casing the zero-element case, **with one exception**: on a `delete` call, an empty `and` (or any `where` that compiles to `TRUE`) is rejected with `INVALID_PARAMS`. Omitting `where` entirely is likewise rejected on `delete`. To delete every row in a table, callers must pass an explicit sentinel: `{"match_all": true}` at the top level of the `where` parameter.

**Rationale.** A programmatically-built empty condition on a `delete` would otherwise wipe the entire table with no visible red flag in the calling code — the caller's own bug would silently produce a destructive result. Requiring an explicit `match_all` sentinel means the caller must have intended a table-wide delete; a bug producing an empty condition object surfaces as `INVALID_PARAMS` rather than as data loss. The rule applies only to `delete`; `update` with an empty `and` is permitted (setting a field on every row is not destructive in the same way — the previous values are still present in whatever backup/audit log exists, and the intent is clearer from the payload).

### B.5 Compile output

The proxy compiles the condition object into a SurrealQL `WHERE` clause using only bound parameters. Field paths become dotted identifiers (`ident.ident.ident`), scalars become `$p1`, `$p2`, ... in the emitted text with their values in the request-body parameter map. No caller-supplied string is ever interpolated into the emitted `WHERE` clause text.

---

## Appendix C. `dba_execute` keyword screen

The `dba_execute` method passes arbitrary SurrealQL to SurrealDB but first applies a **keyword screen** that rejects any statement containing identity-management or access-control keywords, regardless of context. The screen is intentionally over-rejecting: it is a safety net against accidental misuse of the `dba` tier, not a formal parse of SurrealQL.

### C.1 Tokenization before screening

Before checking keywords, the proxy normalises the statement text with a **single string-aware tokenization pass**. A separate strip-then-tokenize sequence is not implementable correctly: comment delimiters (`--`, `/*`, `*/`) inside string literals or backtick-quoted identifiers must be treated as ordinary characters, and detecting that requires string-literal tracking, which in turn is the tokenizer's job. The pass is therefore specified as one state machine, not a pipeline:

The tokenizer scans the input left-to-right with a small state (`normal | in_single_quote | in_double_quote | in_backtick | in_line_comment | in_block_comment`) and emits tokens as it goes:

- In `normal` state:
  - `--` (not inside any quoting state) enters `in_line_comment`; the tokenizer consumes characters until end-of-line, then emits a single space (see below) and returns to `normal`.
  - `/*` (not inside any quoting state) enters `in_block_comment`; the tokenizer consumes characters until the matching `*/` (non-nested), then emits a single space and returns to `normal`. An unterminated block comment (EOF before `*/`) is a hard error: the request is rejected with `INVALID_PARAMS`.
  - `'`, `"`, and `` ` `` enter the corresponding quoted state. The opening delimiter, the entire content (including any `--`, `/*`, `*/`, whitespace, or embedded quotes escaped per §C.5), and the closing delimiter are emitted together as a single opaque `STRING_LITERAL` or `QUOTED_IDENT` token, with its content preserved verbatim. The screen does not inspect the *contents* of string literals or backtick-quoted identifiers — a string value of `"DEFINE USER"` never triggers a rejection — but the token itself is still present in the stream, so it acts as a separator between surrounding tokens.
  - Whitespace runs (space, tab, newline, carriage-return) emit a single space and are otherwise consumed.
  - Punctuation characters `;`, `(`, `)`, `,` each emit as their own token and also act as statement/token boundaries; `;` in particular is the statement boundary used by the position-sensitive `ACCESS` rule in §C.2.
  - Everything else is accumulated into the current identifier/keyword token until a boundary character (whitespace, punctuation, quote, comment-open) is seen; the accumulated token is then upper-cased and emitted.
- In `in_single_quote` / `in_double_quote` / `in_backtick`: characters are accumulated into the current opaque token; the state exits when the matching closing delimiter is seen, per §C.5 escaping rules. An unterminated string literal (EOF while still in a quoted state) is a hard error: `INVALID_PARAMS`.
- In `in_line_comment`: characters are consumed until end-of-line; the comment is replaced with a single space in the output stream.
- In `in_block_comment`: characters are consumed until `*/`; the comment is replaced with a single space in the output stream.

**Why comments become a space, not nothing.** Replacing a stripped comment with a single space guarantees that any two tokens separated by a comment remain lexically separated after stripping. The prior naive-strip approach would render `DEFINE/**/USER` as `DEFINEUSER` — a single token that does not match the `DEFINE USER` two-token adjacency rule, i.e. a real bypass. Replacing the comment with a space renders it as `DEFINE USER`, which does match. This closes the class of bypasses that motivated the caveat in earlier drafts of this appendix.

After tokenization, the proxy has a flat list of upper-cased tokens (with `STRING_LITERAL` and `QUOTED_IDENT` as opaque, uninspected token types, and `;` as an explicit statement boundary), which is then screened per §C.2.

### C.2 Reject list

A `dba_execute` call is rejected with `DENIED` if the normalised token stream contains any of the following two-token sequences or single tokens:

**Identity and access management (always rejected):**

| Token sequence / token | Notes |
|---|---|
| `DEFINE USER` | All forms, including `DEFINE USER IF NOT EXISTS` and `DEFINE USER OVERWRITE` — the `DEFINE USER` pair is still adjacent |
| `ALTER USER` | Available since SurrealDB 3.0.5; can change roles, password, session/token durations |
| `REMOVE USER` | All forms |
| `DEFINE ACCESS` | Replaces `DEFINE SCOPE`/`DEFINE TOKEN` in SurrealDB 2.x+ |
| `ALTER ACCESS` | Available since SurrealDB 3.0.5; can change `AUTHENTICATE` expression and durations |
| `REMOVE ACCESS` | |
| `ACCESS` | The `ACCESS <name> GRANT / SHOW / REVOKE / PURGE` statement (SurrealDB 2.2+) manages bearer-token grants — a form of identity issuance |
| `DEFINE SCOPE` | Legacy SurrealDB 1.x form; reject for defence in depth |
| `REMOVE SCOPE` | |
| `DEFINE TOKEN` | Legacy SurrealDB 1.x form |
| `REMOVE TOKEN` | |
| `SIGNUP` | Embedded in SurrealQL `DEFINE ACCESS ... WITH SIGNUP` blocks |
| `SIGNIN` | Embedded in SurrealQL `DEFINE ACCESS ... WITH SIGNIN` blocks |

The `ACCESS` single-token entry is intentionally coarse: unlike the two-token sequences above, it matches the statement's leading keyword directly and therefore also rejects any statement that happens to name a field, alias, or parameter `access` at the start of a token position (e.g. a hypothetical `SELECT access FROM ...` written without whitespace-noise, which the token-splitter would render as `[SELECT, ACCESS, FROM, ...]` and *not* trigger the rule, since `ACCESS` is not the first token). The rule fires only when `ACCESS` is the first token of a statement (post-normalisation, following `;` or start-of-input). Implementations should track statement boundaries in the token stream and evaluate the `ACCESS` rule position-sensitively; all other rules in this table are position-insensitive two-token adjacency checks.

**Additions to the reject list** are welcome (raise a PR, no issue required). **Removals** require an issue, explicit rationale, and human review before merging — they widen the DBA tier's authority.

### C.3 What is permitted

All DDL not in §C.2 is permitted for `dba`-tier callers, including:

- `DEFINE / REMOVE TABLE`, `DEFINE / REMOVE FIELD`, `DEFINE / REMOVE INDEX`, `DEFINE / REMOVE EVENT`, `DEFINE / REMOVE FUNCTION`, `DEFINE / REMOVE PARAM`, `DEFINE / REMOVE ANALYZER`
- `DEFINE / REMOVE NAMESPACE`, `DEFINE / REMOVE DATABASE`
- `DEFINE / REMOVE API` (SurrealDB 3.x)
- Arbitrary DML: `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `RELATE`, `UPSERT`
- Transactions: `BEGIN TRANSACTION` / `COMMIT TRANSACTION` / `CANCEL TRANSACTION`
- `INFO FOR ...`, `SHOW CHANGES`, `LIVE SELECT` (live queries not supported end-to-end in v1 — see §16)

### C.4 Caveats

The screen operates on a single-pass, string-aware tokenizer (§C.1) that treats comments as a single space. Constructions that previously would have defeated a naive strip-then-tokenize implementation — `DEFINE/**/USER`, `DEFINE-- comment\nUSER`, or a comment-hidden identity-management statement — are all normalised into token streams that the §C.2 rules match. The remaining known limitation is that the reject list matches on statement-level keywords, not on statements semantically equivalent to identity management. For example, a hypothetical scripting construct that indirectly creates a user without literally containing the tokens `DEFINE USER` (or any other rejected pair) would evade the screen. No such construct is known in SurrealDB 3.1.5, but the `dba` tier remains a trusted-operator tier (§3) and the defence-in-depth layer (`EDITOR` credential — §7.2) exists precisely because this screen is not a formal proof.

### C.5 String literal and quoted identifier syntax

String literals and backtick-quoted identifiers in caller-supplied SurrealQL follow the SurrealDB grammar. The tokenizer needs precise entry/exit rules to correctly delimit them:

- **Single-quoted strings** (`'...'`): open with `'`, close with the next unescaped `'`. A backslash `\` escapes the following character (so `\'` is a literal single quote inside the string, `\\` is a literal backslash). A single quote can also be included by doubling it (`''`), matching the SQL convention.
- **Double-quoted strings** (`"..."`): open with `"`, close with the next unescaped `"`. Same escape rules as single-quoted: `\"` and `""` are both literal double quotes; `\\` is a literal backslash.
- **Backtick-quoted identifiers** (`` `...` ``): open with `` ` ``, close with the next `` ` ``. SurrealDB does not currently document a backslash escape inside backticks; the tokenizer treats every character inside as literal until the closing backtick. This matches SurrealDB's own behaviour.
- **Newlines are permitted** inside all three quoted forms.

An unterminated quoted form is a hard error: `INVALID_PARAMS`. The tokenizer does not attempt recovery.

These rules are consumed only by the tokenizer and by Appendix A's `string_literal` production; the proxy does not itself interpret escape sequences or decode string contents, since it never forwards raw statement text containing caller-supplied strings to SurrealDB — every caller-supplied value travels as a bound parameter (§6.4). The tokenizer needs the rules only to know where a string ends, not what its value is.
