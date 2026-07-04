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
- The `dba_execute` escape hatch (§4.1, tier `dba`) screens for identity-management statements with a **keyword screen over statement text, not a full SurrealQL parse** (§6.5's discussion of caller-supplied expressions explains why a full parse is the harder problem this tool otherwise avoids by using typed operations for the *regular* write surface). The screen over-rejects on purpose; it is not a formal guarantee against a determined DBA-tier identity trying to construct a bypass.
- The read-only (`query`) channel's correctness depends entirely on the underlying SurrealDB `VIEWER` role actually being read-only. This must be verified against the specific SurrealDB version in use before relying on it (§13).

## 4. Core concepts

### 4.1 Identities and tiers

Every caller connects through exactly one Unix socket, and the socket determines the caller's identity (§5). Each identity is assigned exactly one of three fixed tiers:

| Tier | Read | Write | Schema (DDL) | Identity management |
|---|---|---|---|---|
| `contributor` | all tables | only tables in groups granted to this identity (§4.2) | no | no |
| `writer` | all tables | all tables | no | no |
| `dba` | all tables | all tables | yes, via `dba_execute` | no (structurally excluded — see below) |

The ladder is a strict progression: `dba` ⊇ `writer` ⊇ `contributor`. None of the three tiers can manage identities (create, delete, or reassign the tier of any identity) — that capability doesn't exist anywhere in the proxy's own request surface at all; it lives entirely in whatever renders the proxy's configuration file (§7), which is deliberately outside this project's scope (§15). This is a structural property, not a policy choice that could be misconfigured: there is no proxy method that issues `DEFINE USER`, and `dba_execute` explicitly screens out and rejects any identity-management statement even from a `dba`-tier caller (§3, §6.3).

The tier ladder is fixed at exactly these three levels in this version and is not user-extensible; see §16 if your access model needs a different shape.

Tier names were chosen to describe capability rather than to match any particular organization's role vocabulary, and deliberately avoid colliding with SurrealDB's own `OWNER`/`EDITOR`/`VIEWER` system-user roles (which this proxy uses internally, at a different layer — §7.2). Adopters are free to map their own organizational roles onto these three tiers however makes sense (e.g. "read-only human," "on-call engineer," "CI service account" might all reasonably map to `contributor` with different grants).

### 4.2 Table groups and grants

Write access for `contributor`-tier identities is managed at the granularity of **table groups**, not individual tables:

- A table group is a named set of tables.
- Every table SurrealDB knows about should belong to exactly one group; the proxy validates this on each policy reload (§8) and fails loudly (not silently) if it doesn't hold.
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
  │  - Structured log line per call                       │
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

## 6. Protocol

The proxy speaks a small line-delimited JSON-RPC protocol over each socket: one JSON object per request line, one per response line. No streaming, no multiplexing.

**Why not a wire-compatible SurrealDB endpoint?** Three reasons:

1. No existing SurrealDB SDK or the `surreal` CLI supports Unix-domain-socket transport (they select transport from a `ws://`/`http://` connection URL), so wire compatibility would not deliver drop-in client support anyway — reaching the socket at all requires custom client code regardless of protocol shape. A TCP listener would restore drop-in compatibility but destroys the entire identity mechanism (a TCP connection on localhost carries no attested caller identity).
2. Enforcing write policy on arbitrary, unparsed SurrealQL is a parsing problem, and a single parsing gap is a policy bypass. Concretely: SurrealQL subqueries are legal in `WHERE` and `SET`/`CONTENT` expression positions and can themselves contain `CREATE`/`UPDATE`/`DELETE`/`INSERT`/`RELATE`/`UPSERT` and even DDL (confirmed against the SurrealDB v2.3.3 grammar — the `Subquery` AST in `crates/core/src/sql/subquery.rs` admits all of these). A write can hide several subqueries deep inside a clause that looks like a read. This is why the write surface is a small typed operation set instead (§6.3) — policy enforcement becomes a set-membership check on a structured field, not a parse of arbitrary text.
3. Reads don't have this problem, so reads aren't restricted at all: `query` accepts arbitrary SurrealQL and runs it under a read-only database credential, so read-only-ness is enforced by SurrealDB's own RBAC rather than by the proxy inspecting the query text. No parsing, no coverage gaps, full SurrealQL expressiveness (graph traversal, vector/full-text search, aggregations, schemaless tables, `INFO FOR ...`, `SHOW CHANGES`) for the fully-permitted read surface.

### 6.1 Transport and framing

Unix domain socket, `SOCK_STREAM`. Each request and response is exactly one JSON object followed by a newline. No fragmentation handling beyond standard newline-delimited buffering is required in v1.

### 6.2 Request/response schema

**Request:**

```json
{
  "id": "<string — caller-chosen, echoed back>",
  "method": "<query | create | update | upsert | delete | insert | relate | dba_execute>",
  "params": { ... }
}
```

**Response (success):** `{"id": "...", "result": [ ... ]}`

**Response (error):**

```json
{
  "id": "<same as request>",
  "error": {
    "code": "<DENIED | DB_ERROR | INVALID_PARAMS | UNKNOWN_METHOD>",
    "message": "<human-readable string>"
  }
}
```

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

For write methods, the proxy extracts the target table(s) from the structured `target`/`targets` parameter and checks every one against the caller's effective write set (union of `tables` across all groups the caller is granted — §4.2, §8). `UPDATE`/`DELETE` accept multiple targets that may span tables, and `relate` names three tables (the relation table plus both endpoints); **every** named table must be in the write set, or the whole call is `DENIED`, naming the caller and the offending table.

`writer` and `dba` tier callers skip the group check entirely (write-all is their tier semantic). `dba_execute` is available only to `dba`-tier callers.

Multi-statement transactions are not supported in v1; see §16 for a batched `transact` operation as a candidate future addition.

### 6.4 Caller-supplied expressions are data, never SurrealQL text

The protocol never interpolates a caller-supplied string into the SurrealQL it constructs — this is what makes the typed write surface safe under a shared read-write credential:

- **Targets** (`target`/`targets`) must match a strict grammar — a bare table identifier or a record ID — validated before use. Anything else is `INVALID_PARAMS`.
- **`content`/`values`** travel as bound parameters in the request body to SurrealDB's `/rpc` endpoint; the proxy constructs the statement text itself and never treats caller data as anything but a typed, bound value. This applies even to schemaless (`SCHEMALESS`) tables: a caller with write access can set arbitrary field names via `content`, exactly as with a hand-written statement — field-level restriction is explicitly out of scope for this tool (§2), so that's expected, not a gap.
- **`where`** accepts a structured condition object (field paths, comparison/containment operators, parameter-bound values), which the proxy compiles into a `WHERE` clause itself. The condition grammar is deliberately small. When selection logic needs more than it expresses, the idiom is **read-then-write-by-ID**: resolve the record set with a full-SurrealQL `query` call (read-only credential, so any write hiding in a subquery is rejected by the database itself), then issue the typed write against the explicit record IDs returned. This two-step is not transactional (§16 lists a batched `transact` operation as a way to close that gap later).

`RELATE` writes only the edge record (endpoints are referenced, not modified — the proxy still checks all three tables involved, conservatively). Schema-defined machinery such as `DEFINE EVENT` or `DEFINE FIELD ... VALUE` can cause one statement to write other tables as a side effect — acceptable, because defining such machinery is itself a `dba_execute`-gated act.

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
| Read-write | `OWNER` (broader than `EDITOR`, since it must also issue DDL via `dba_execute`) | typed writes, `dba_execute` |
| Read-only | `VIEWER`, exactly | the `query` channel |

Both live in a root-owned environment file (mode `0600`), loaded via the proxy's process manager (e.g. systemd's `EnvironmentFile=`) rather than the YAML config, so that config files can be committed to version control without leaking secrets.

## 8. Database schema owned by the proxy

Two tables, prefixed `_access_` to mark them as belonging to the access-control mechanism itself rather than to any adopter's own schema:

```surql
DEFINE TABLE IF NOT EXISTS _access_group SCHEMAFULL;
DEFINE FIELD name   ON _access_group TYPE string;
DEFINE FIELD tables ON _access_group TYPE array<string>;

DEFINE TABLE IF NOT EXISTS _access_grant SCHEMAFULL;
DEFINE FIELD username   ON _access_grant TYPE string;
DEFINE FIELD group_name ON _access_grant TYPE string;
```

This DDL is fixed and identical for every deployment — it's the proxy's own bookkeeping state, not something each adopter should have to hand-copy from documentation. The proxy ships an idempotent schema-initialization step (a CLI subcommand and/or a startup check) that issues this DDL under the read-write credential. These two tables are readable by everyone (like all tables, via `query`) and writable only through `dba_execute`.

Groups and grants live in the database rather than in `config.yml` specifically so that a `dba`-tier identity can grant or revoke access at runtime, with immediate effect, without restarting or reconfiguring the proxy:

```surql
-- Create a group
INSERT INTO _access_group { name: "reports", tables: ["invoice", "payment"] };

-- Grant / revoke
INSERT INTO _access_grant { username: "carol", group_name: "reports" };
DELETE _access_grant WHERE username = "carol" AND group_name = "reports";
```

**Reload behaviour:** because every grant change necessarily flows through the proxy itself (`dba_execute` is the only write path to `_access_*`), the proxy reloads its group/grant cache after every `dba_execute` call, with a periodic reload (e.g. every 60s) and a signal handler as backstops for out-of-band changes.

**Invariant enforcement:** on each reload, the proxy builds a `table → group` map and fails loudly (refusing writes to the affected tables, logging at error level) if any table appears in two groups. A table in no group at all is logged as a warning; writes to it are denied for `contributor`-tier callers by construction, since it's in nobody's grant set.

**A known rough edge:** Unix usernames appear as plain strings in `_access_grant` rows, so removing or renaming an identity in `config.yml` leaves orphaned rows behind. This is benign by construction — an orphaned grant matches no live socket, so it's simply inert — but it is drift, and the proxy logs orphaned rows as warnings on each reload rather than silently ignoring them. See §16 for a dedicated cleanup tool as a candidate addition.

## 9. Client libraries

Two reference clients ship as part of this project, both exposing one method per protocol method (§6.3) and both connecting to a Unix socket whose default path is derived from the calling process's own username (`/run/surrealdb-guard/$USER.sock`), with an environment variable override for tests and non-standard setups:

- **Go**, package `surrealdb_guard/client`, in the same module as the daemon. This is the primary reference implementation: since it lives alongside the server, the wire protocol and this client evolve together and it is the first to reflect any protocol change. The CLI (§10) is built on top of it.
- **Python**, package `surrealdb_guard_client` (name TBD, distributed separately, e.g. via PyPI), for identities and services that are themselves Python — the common case of a Python-based script, service, or agent that needs to reach the proxy without shelling out to the Go CLI.

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
2. **Local integration tests (still unprivileged).** SurrealDB's own in-memory single-process mode (`surreal start memory`) runs as a plain, disposable, user-owned process on a random localhost port. This layer exercises real query execution, read-only-credential RBAC (including a standing regression check that the read-only role truly can't write — see §13's caveat), and bound-parameter behaviour.
3. **Multi-user host tests (needs a disposable VM or container with real separate OS users).** The pieces the first two layers can't reach — root-owned sockets across genuinely different Unix users, service-manager ordering, `tmpfiles`-style directory setup — are validated here. This is the only layer that needs anything resembling a deployment, and it should be fully disposable (a throwaway container or VM, torn down after the run).
4. **Cross-client conformance (unprivileged, any layer above a running proxy).** Because the Go and Python clients are independent implementations of the same protocol (§9), both are run against the same live proxy instance (in-process for layer 1, or the layer-2 setup) exercising the identical matrix of calls, asserting identical results. This catches drift between the two clients directly, rather than relying on each client's own unit tests to indirectly agree with each other.

A standing validation harness (a script exercising the full tier × operation matrix — reads, granted writes, denied writes, `dba_execute` allow/deny, identity-management-statement rejection) should accompany the project and be runnable against any of the four layers above.

## 13. SurrealDB version compatibility

The proxy talks to SurrealDB over its stable HTTP surface (`/sql` for `query`/`dba_execute`, the stateless `/rpc` endpoint for bound-parameter typed writes), which is expected to remain compatible across SurrealDB 2.x and 3.x. Two version-specific things need explicit, version-pinned verification rather than an assumption that they "still work":

- **The read-only role must actually be read-only.** Verify with a clean, hand-crafted probe (fresh credentials, explicit response assertions, including a write hidden in a subquery) against every SurrealDB version this project claims to support, and keep that probe as a standing regression check — don't rely on documentation alone.
- **SurrealDB 3.x's `--deny-arbitrary-query` flag does not replace this proxy.** It's group-granular (`guest`/`record`/`system`), not per-user, so it cannot distinguish the proxy's own credential from any other system user without also blocking every other system user (including whatever holds schema authority). `DEFINE API` (3.x) likewise doesn't solve the caller-identity problem this proxy solves, because SurrealDB still has no Unix-socket transport (`surrealdb/surrealdb#1614`) and therefore no kernel-attested identity to branch enforcement on inside a `DEFINE API` endpoint — the credential is just a string in the caller's environment. Both are worth revisiting if upstream ever ships per-user query capabilities or a Unix-socket bind; neither currently obsoletes this project.

## 14. Security considerations

- **Report vulnerabilities privately**, not as public issues, until a fix is available. (A concrete disclosure contact/process should be added here once the project has a home — email alias, GitHub Security Advisories, etc.)
- **The `dba_execute` keyword screen is not a formal guarantee** (§3). Treat the `dba` tier as a trusted-operator tier, not as a boundary that holds against a `dba`-tier identity actively trying to defeat it.
- **The read-only channel's safety is an assumption about SurrealDB's own RBAC**, not something this proxy independently verifies at runtime beyond what's practical to probe at startup. Pin and test against specific SurrealDB versions (§13).
- **This proxy does not encrypt or authenticate the hop to SurrealDB beyond SurrealDB's own credential check.** Deploying the proxy and SurrealDB on the same host over loopback is the assumed baseline; anything else (a remote SurrealDB instance) needs its own transport security, which is outside this project's scope.
- **A compromised proxy process is equivalent to a compromised read-write database credential.** The proxy's own attack surface (its socket listeners, its JSON parsing, its dependency tree) should be held to the same scrutiny as anything else that holds live database credentials.

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
- **Richer audit.** Metrics export (denial counts, per-identity latency), structured query logging with retention, alerting on repeated denials. The baseline (one structured log line per call) is deliberately minimal.
- **Grant snapshots / config-as-code export.** A periodic job exporting effective `_access_group`/`_access_grant` state to a file, so runtime grant drift from any seeded defaults is reviewable in version control — recovering an as-code property for the one store that must stay runtime-mutable (§8).
- **Multi-instance / high availability.** Running more than one proxy instance against the same SurrealDB (e.g. one per host in a multi-host deployment), sharing the same groups/grants state. No structural blocker anticipated; not validated yet.
- **Interactive REPL** on top of the CLI (§10): statement history, completion, and routing simple write statements to the correct typed method automatically.
- **SurrealDB 3.x compatibility testing** as a first-class, continuously-tested target alongside 2.x, once the project has CI (§13).
- **Orphaned-grant cleanup tooling.** A command that lists (and optionally deletes) `_access_grant` rows whose `username` matches no identity in the current `config.yml`, rather than requiring a hand-written `DELETE` (§8).
- **Declarative groups/grants seeding tool.** See §15 — deferred until demonstrated need.
