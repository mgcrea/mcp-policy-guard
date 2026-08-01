# mcp-guard

Per-caller authentication and authorization for MCP servers.

An MCP server is the last place a request passes before it reaches real data, and the first
place where *who is asking* and *what they are asking for* are both known. That makes it the
only honest place to enforce per-user access. The decision is made against the arguments the
model emitted — after any prompt injection has already had its say — so nothing can talk its
way past it.

This package **decides nothing on its own**. It verifies callers against your OIDC issuer and
asks a policy decision point (PDP) of your own for every decision, caching the answers so an
outage degrades instead of failing. The PDP is any HTTP service implementing the two
endpoints in [Policy decision point contract](#policy-decision-point-contract).

## What it does

- **Verifies** the caller's access token against the issuer's JWKS, located by OIDC discovery.
- **Binds** the resulting principal to a contextvar that survives `asyncio.to_thread`.
- **Asks** your decision point whether this caller may touch these resources.
- **Caches** each caller's flattened policy so a backend outage degrades instead of failing,
  bounded — then fails closed.
- **Audits** every call with the caller, the decision and the resources.

## Install

```toml
dependencies = ["mcp-guard>=0.2"]
```

## Wiring a server

Wrap the MCP app, not the whole Starlette app — a readiness probe hits `/healthz` and must
not be asked for a bearer token:

```python
from mcp_guard import Guard, GuardMiddleware

guard = Guard()

routes = [
    Route("/healthz", healthz),
    Route("/", root),
    Mount("/", app=GuardMiddleware(mcp.streamable_http_app(), guard.config)),
]
if guard.config.sse_allowed:
    routes.append(Mount("/", app=mcp.sse_app()))
```

That `if` is not optional politeness. Under SSE the long-lived connection that carried the
`Authorization` header is not the request that carries a tool call, so the principal
established at connect time cannot be attributed to the call. `sse_allowed` is `False`
whenever `MCP_REQUIRE_AUTH` is on, because mounting it anyway would leave a second,
unauthenticated door into the same tools.

## Guarding a tool

```python
from mcp_guard import PolicyDenied, Resource, audit_call

def _sync_query(query: str) -> str:
    with audit_call("mssql_query", {"query": query}) as record:
        validate_readonly_query(query)                 # deny-list, unchanged
        tables = extract_referenced_tables(query)      # allow-list input
        record["resources"] = sorted(tables)

        try:
            decision = guard.require("mssql_query", [Resource("sql_table", t) for t in tables])
        except PolicyDenied as denied:
            record["decision"] = "deny"
            return f"Error: {denied}"

        record["decision"] = decision.decision
        return execute(query)
```

Two rules for the resources you pass:

1. **Normalize them the way rules are authored** — lowercase `schema.table`. Matching is
   textual, so a rule denying `dbo.payroll` cannot recognise `[Payroll]` as the same thing.
2. **Enumerate completely, or fail.** Guessing a smaller set than the query actually reads
   is a breach; guessing a larger one is an annoyed user. Whatever extracts your resources
   must fail closed when it is unsure.

## Discovery must hide, not refuse

A listing that said "3 tables hidden", or a `describe` that distinguished *denied* from *not
found*, is an enumeration oracle — the caller learns the exact names of what they cannot
reach, which is often the interesting half of the secret.

```python
visible = guard.filter_resources("sql_table", all_tables, function_name="mssql_list_tables")
```

For a single-item lookup, authorize *before* querying and return the same "not found"
string the tool already returns for an absent object. Log the real reason to audit; tell the
model nothing.

The opposite applies to a query tool: the model already named the table, so there is no
oracle to protect, and an explicit "you do not have access to dbo.payroll" stops it
retrying.

## Configuration

**The names are a contract** with whatever provisions this server's environment — renaming
one on either side silently disables the corresponding control.

| Variable | Meaning |
| --- | --- |
| `MCP_REQUIRE_AUTH` | Reject unauthenticated requests. Also disables SSE. |
| `MCP_AUTH_ISSUER` | OIDC issuer URL. The JWKS endpoint is resolved from it by discovery. |
| `MCP_AUTH_AUDIENCE` | Optional `aud` check. Leave unset where one issuer mints tokens for several clients. |
| `MCP_TOOL_ID` | This server's tool id; how the PDP resolves which policy applies. |
| `MCP_POLICY_URL` | Base URL of the decision point, e.g. `http://backend:3000/api/policy`. |
| `MCP_POLICY_FAIL_MODE` | `closed` (default) or `open`. |
| `MCP_POLICY_STALE_MAX_SECONDS` | How long a cached snapshot may keep answering during an outage. Default 300. |
| `MCP_POLICY_TTL_SECONDS` | Revalidation interval while healthy. Default 30. |
| `MCP_POLICY_TIMEOUT_SECONDS` | HTTP timeout to the PDP and to OIDC discovery. Default 5. |
| `MCP_CORRELATION_HEADER` | Incoming correlation-id header. Default `x-mcp-correlation-id`. |
| `MCP_CALLER_ID_HEADER` | Incoming caller-id header. Default `x-mcp-caller-id`. |

Both header names are lowercased when read, because ASGI hands header names down lowercased
— so `X-Trace-Id` and `x-trace-id` behave identically.

The caller id is recorded for audit and **never used in a policy decision**: the caller
asserts it and nothing verifies it, so a policy that read it would be taking the word of the
party it is meant to constrain.

Authentication and authorization are configured independently. A server with
`MCP_REQUIRE_AUTH` but no `MCP_POLICY_URL` verifies its caller and then allows — the
intended intermediate state during a rollout, and exactly how the tool behaved before policy
existed.

`MCP_REQUIRE_AUTH=true` with no `MCP_AUTH_ISSUER` **refuses to start**. A guard that
requires auth but cannot verify anything would accept every caller while the operator
believed it was on.

## Authentication

The token is taken from `Authorization: Bearer`, falling back to
`X-Auth-Request-Access-Token` for deployments behind oauth2-proxy, which consumes the
original header itself.

The signing key set is located with OIDC discovery: `GET {issuer}/.well-known/openid-configuration`,
whose `jwks_uri` is used **only if the document's own `issuer` matches the configured one**.
Without that check, anything able to influence the discovery response would get to nominate
the key set this process trusts. If discovery is unreachable, malformed, mismatched, or has
no `jwks_uri`, the guard falls back to `{issuer}/protocol/openid-connect/certs` rather than
refusing to start. Resolution happens once per issuer, behind the JWKS client cache.

Claims are read in Keycloak's shape — `realm_access.roles` for roles, `groups`, `azp` for
the client id — and a `typ` payload claim of anything other than `Bearer` is rejected, which
is what keeps an ID token out. Absent `typ` is accepted, since it is a Keycloak convention
rather than an RFC 9068 guarantee.

## Policy decision point contract

Everything under `MCP_POLICY_URL`. Both endpoints receive **the caller's own token**, not a
server credential, so the PDP re-verifies the identity itself rather than trusting an
identity this server asserts — that is what keeps a compromised MCP server from voting on
its own permissions.

### `POST {MCP_POLICY_URL}/evaluate`

The hot path: one call per guarded tool invocation.

```http
POST /api/policy/evaluate
Authorization: Bearer <the caller's access token>

{ "tool": "tool-mssql",
  "function": "mssql_query",
  "resources": [{"kind": "sql_table", "value": "dbo.orders"}],
  "correlationId": "corr-123" }
```

```json
{ "decision": "allow",
  "effect": "allow",
  "enforcing": true,
  "reason": "matched rule-sales",
  "policyVersion": 7,
  "matchedRuleId": "rule-sales",
  "resourceDecisions": [{"resource": {"kind": "sql_table", "value": "dbo.orders"}, "effect": "allow"}] }
```

`decision` is what policy says and is what gets audited; `effect` is what the caller should
*do*. In shadow mode they differ — `effect` is always `allow` — which is what makes it
possible to author rules against production traffic without blocking anyone.

Status codes are load-bearing: **`401`, `403` and `404` mean denied**, and no cached
snapshot may answer for a caller the PDP just declined to confirm. Any other `>= 400` is
treated as an outage and falls back to the cached snapshot.

### `GET {MCP_POLICY_URL}/snapshot?tool=&function=`

The caller's whole policy in one round trip, for scoping discovery listings and for
answering during an outage. Send `If-None-Match` with the previous `ETag`; a `304` means
unchanged and re-stamps freshness.

```json
{ "policySetId": "set-1",
  "version": 7,
  "enforcing": true,
  "defaultEffect": "deny",
  "resourceRules": [
    {"kind": "sql_table", "pattern": "dbo.orders*", "effect": "allow", "ruleId": "rule-sales"},
    {"kind": "sql_table", "pattern": "dbo.payroll*", "effect": "deny", "ruleId": "rule-payroll"}
  ],
  "callEffect": "allow",
  "callRuleId": "rule-sales" }
```

Two obligations on whoever implements this:

1. **The snapshot is already filtered to the caller.** It is cached under the caller's
   identity fingerprint; a snapshot that was not caller-specific would hand one user's
   permissions to another.
2. **`resourceRules` is already precedence-flattened.** Subject matching, priority ordering
   and the deny-wins tiebreak are resolved server-side, because this package walks the list
   first-match-wins and will not re-sort it. Glob semantics must match
   [matching.py](src/mcp_guard/matching.py) — `test_matching.py` pins the shared cases.

## Failure behaviour

| Situation | Result |
| --- | --- |
| PDP reachable | Authoritative decision, audited by the backend. |
| PDP down, snapshot fresh enough | Decided locally from last-known-good. |
| PDP down, snapshot too stale | `PolicyUnavailable` — the call is refused. |
| PDP returns 401 | Refused. Not an outage: the PDP declined to confirm this caller, so a cached snapshot must not answer for them. |
| PDP returns 404 | Refused. `MCP_TOOL_ID` names no known tool, so no policy applies. |
| `MCP_POLICY_FAIL_MODE=open` | Allowed, loudly logged. Never the default. |

`PolicyUnavailable` subclasses `PolicyDenied` on purpose, so a tool that only remembered to
handle denials also handles the outage.

## Why the decision point, and not local evaluation

The backend flattens rule precedence before serving a snapshot, so this package never
re-implements the semantics. That is deliberate: two implementations of a security-critical
ordering are free to drift, and the one that drifts is the one nobody is testing. The hot
path asks the backend, which also means every decision lands in its audit log with the
caller, the resources and the matched rule.

## Audit

One JSON record per call on stdout, for whatever log pipeline is already collecting it —
deliberately not a write to an audit database, since the server holds no such credential and
granting one would be a larger grant than the thing being audited.

Each record carries `subject`, `email`, `groups`, `client_id`, `correlation_id`, `caller_id`,
the `decision`, the `reason`, the `resources` and the redacted `params`. Secret-looking
parameter keys (`password`, `apiKey`, `connectionString`, …) are masked by whole-word
matching, which is what keeps `secretary` and `monkey` readable.

## Upgrading to 0.2

Breaking changes, all mechanical:

- `current_worker_id()` → `current_caller_id()`.
- The audit field `calling_worker_id` → `caller_id`. Update any log query that reads it.
- The default headers are now `x-mcp-correlation-id` and `x-mcp-caller-id`. If your caller
  already mints differently-named headers, name them instead of changing the caller:
  `MCP_CORRELATION_HEADER` / `MCP_CALLER_ID_HEADER`.
- The JWKS endpoint is discovered rather than assumed. Keycloak deployments are unaffected —
  discovery returns the same URL the old code hardcoded, and the hardcoded path remains the
  fallback.

## Development

```bash
make install
make spec     # pytest
make lint
make format
```

The token tests sign and verify real JWTs against a real key set. A mocked verifier would
pass just as happily against a verifier that checked nothing.
