# mcp-policy-guard

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
dependencies = ["mcp-policy-guard>=0.5"]
```

## Wiring a server

Two pieces, and **both are required**. `GuardMiddleware` establishes who is calling for each
HTTP request; `@guarded` makes the tool handler read *that* caller rather than whoever opened
the MCP session (see [Why two pieces](#why-two-pieces)).

```python
from mcp_policy_guard import Guard, routes

guard = Guard()

app = Starlette(
    routes=routes(
        mcp,
        guard.config,
        extra_routes=[
            Route("/healthz", healthz),
            Route("/", root),
        ],
    )
)
```

`routes()` mounts the guarded streamable app at the catch-all and SSE — only when
`config.sse_allowed` — at its own path ahead of it. Build the list by hand and it is easy to
write two `Mount("/")` entries, where Starlette returns on the first `Match.FULL` and the
second is unreachable dead code.

`extra_routes` stay unguarded, which is the point: a readiness probe must not be asked for a
bearer token.

SSE is refused whenever `MCP_REQUIRE_AUTH` is on. Under SSE the long-lived connection that
carried the `Authorization` header is not the request that carries a tool call, so the
principal established at connect time cannot be attributed to the call; mounting it anyway
would leave a second, unauthenticated door into the same tools.

### Transport options

Because `routes()` builds the SDK's apps, it is also where their arguments go. `app_kwargs`
and `sse_app_kwargs` are forwarded verbatim; this package does not interpret them.

On **1.x** leave both empty — transport options belong on the server constructor, and the
builders read them back from `settings`:

```python
mcp = FastMCP(name=NAME, transport_security=security, streamable_http_path="/mcp")
app = Starlette(routes=routes(mcp, guard.config))
```

On **2.x** those options were removed from the constructor and from `Settings`. They survive
only as arguments to the builders, so they have to come through here:

```python
app = Starlette(
    routes=routes(
        mcp,
        guard.config,
        app_kwargs={
            "transport_security": security,
            "streamable_http_path": "/mcp",
        },
    )
)
```

Passing nothing on 2.x is a live footgun and the guard logs
`transport_defaults_to_localhost` when you do: `host` defaults to `127.0.0.1`, which
auto-enables DNS-rebinding protection with a localhost-only allow-list, so a server behind an
ingress answers `421 Invalid Host header` to every real request. The guard warns rather than
choosing for you — quietly widening an allow-list is not a decision a guard should make.

## Guarding a tool

```python
from mcp_policy_guard import PolicyDenied, Resource, audit_call, guarded


@mcp.tool()
@guarded
async def mssql_query(query: str) -> str:
    return await asyncio.to_thread(_sync_query, query)


def _sync_query(query: str) -> str:
    with audit_call("mssql_query", {"query": query}) as record:
        validate_readonly_query(query)  # deny-list, unchanged
        tables = extract_referenced_tables(query)  # allow-list input
        record["resources"] = sorted(tables)

        try:
            decision = guard.require("mssql_query", [Resource("sql_table", t) for t in tables])
        except PolicyDenied as denied:
            record["decision"] = "deny"
            if denied.is_outage:
                return "Error: authorization is temporarily unavailable, please retry."
            return f"Error: {denied}"

        record["decision"] = decision.decision
        return execute(query)
```

`@guarded` goes **under** `@mcp.tool()`, so the SDK registers the wrapper. It reads the
message's own request from the SDK's per-message context, so your handler needs no extra
parameter and its published schema is unchanged.

Check `denied.is_outage` when wording the message. `PolicyUnavailable` subclasses
`PolicyDenied` so the fail-closed path cannot be forgotten, but telling a user "you do not
have access to dbo.orders" during a backend outage sends them to raise an access request for
a permission they already have.

Three rules for the resources you pass:

1. **Normalize them the way rules are authored** — lowercase `schema.table`. Matching is
   textual, so a rule denying `dbo.payroll` cannot recognise `[Payroll]` as the same thing.
2. **Enumerate completely, or fail.** Guessing a smaller set than the query actually reads
   is a breach; guessing a larger one is an annoyed user.
3. **Say so when you cannot enumerate.** Pass `UNDETERMINED` rather than `[]` — the empty
   list means "this call touches nothing" and is decided by the function-level rule alone,
   so an extractor that failed would have its failure converted into an allow.

```python
from mcp_policy_guard import UNDETERMINED

try:
    tables = extract_referenced_tables(query)
except TableExtractionError:
    guard.require("mssql_query", UNDETERMINED)  # denies while enforcing, and audits why
```

## Why two pieces

The ASGI middleware knows exactly who is calling — but on MCP SDK 1.x a tool handler does not
run in the ASGI request task. A stateful streamable-HTTP session dispatches every message
inside one task spawned when `initialize` arrived, and Python copies the *spawning* task's
context. Bind the principal to a contextvar in the middleware alone and every later
`tools/call` reads whoever opened the session, forever: with two users sharing a session, the
second is authorized against the first one's grants.

So the principal travels on the **ASGI scope**, which belongs to one HTTP request and cannot
be captured by a task spawned earlier, and `@guarded` re-binds it around each message.
`src/tests/test_session_binding.py` drives a real server over the real protocol and asserts
both halves — including an executable statement of the bug, so the decorator cannot quietly
become a no-op.

As defence in depth, `guard.evaluate()` and `guard.require()` prefer the principal on the
message's scope over the contextvar, and log `principal_binding_disagreement` when they
differ. A handler missing `@guarded` therefore still authorizes the right caller; it loses
correct audit attribution rather than leaking data.

## MCP SDK compatibility

Both generations are supported and both are tested in CI. The SDK is deliberately **not** a
dependency of this package — a guard should not drag in a server framework — so it is
detected at runtime.

| | SDK 1.x | SDK 2.x |
| --- | --- | --- |
| Is the session leak present? | **Yes** | No — each message is dispatched in its own task |
| `@guarded` | **Required.** Reads the SDK's per-message `request_ctx` | Safe no-op; leaves the already-correct binding in place |
| `GuardServerMiddleware` | Not available (no context-tier middleware) | **Preferred.** One registration covers every tool |
| Scope-preferred resolution in `evaluate()` | Active | Falls through to the contextvar, which is correct there |
| Transport options (`transport_security`, `host`, `json_response`, the `*_path` options) | On the server constructor | Removed from the constructor; pass them through `routes(app_kwargs=...)` |

```python
# 2.x — one registration, nothing to forget
mcp = MCPServer("my-server", middleware=[GuardServerMiddleware()])
```

The rule that makes `@guarded` portable: when no per-message request can be found, it
**leaves the existing binding alone** instead of clearing it. Rebinding is only correct when
there is something better to rebind to. Clearing it on 2.x — where the ASGI middleware's
binding is already this message's caller — would answer every call with
`AuthenticationRequired`: fail-closed, but the whole server bricked. That is pinned by
`TestGuardedIsSafeOnBothGenerations`.

If you are on 1.x, `TestTheLeakIsReal` asserts the bug still exists without the decorator, so
it cannot quietly become a no-op on the generation where it matters. It skips on 2.x.

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

## The MCP handshake is not authenticated

Distinct from the section above, which is about hiding *resources* from a caller who is
already known. This is about the protocol handshake — `initialize`, `tools/list` — by which
a client learns the server exists at all.

Under `MCP_REQUIRE_AUTH` those messages are admitted **without a bearer**. Everything else
still needs one.

The reason is that a client which forwards its *caller's* token holds no token at startup,
which is when discovery happens: the token belongs to a request that has not arrived yet.
Refusing the handshake secures nothing, because `tools/call` is refused on its own merits
either way. What it does is make the server *invisible* — a runtime that cannot enumerate it
drops it, usually for the lifetime of the process, and the operator sees a tool that is
simply absent rather than a tool that said no. Silent on both sides.

Admitted unauthenticated, and nothing else — the list is an allow-list so that a method
nobody has considered is refused rather than admitted:

`initialize`, `notifications/initialized`, `ping`, `tools/list`, `resources/list`,
`resources/templates/list`, `prompts/list`

Every one returns names and schemas; none returns row data, file contents, or a side effect.
`resources/list` is included and `resources/read` is not, for exactly that reason.

Four things worth knowing:

- **A batch is allowed only if every message in it is.** JSON-RPC permits an array, so
  `[initialize, tools/call]` is one request whose first message looks harmless.
- **It is a hole in authentication, never in authorization.** No principal is bound on this
  path, so a handler reached through it still fails every policy check.
- **`POST` only.** An anonymous `GET` or `DELETE` on `/mcp` is refused. Both carry no
  JSON-RPC body to classify, and neither is innocuous: a `GET` attaches to the
  server→client stream of whatever session `Mcp-Session-Id` names and a `DELETE` ends it,
  so admitting them would put a second unauthenticated door onto an *authenticated*
  caller's session. Refusing costs discovery nothing — the Python SDK runs its GET stream
  as a background task whose errors are swallowed and retried, and `terminate_session`
  tolerates any non-2xx; neither reaches `initialize` or `tools/list`.
- **An anonymous `initialize` creates a session** on a stateful server. Everything reachable
  without a bearer is caller-independent, so riding someone else's session id gains nothing,
  but sessions accumulate — prefer `stateless_http=True`, or seal discovery.

Set `MCP_DISCOVERY_REQUIRES_AUTH=true` to seal it again, for a server whose tool *names* are
themselves sensitive. Clients must then be able to authenticate at startup, which a
caller-token-forwarding client cannot.

If your `tools/list` is scoped per caller, decide what an anonymous listing returns before
leaving discovery open: on this path there is no principal to scope it by.

## Configuration

**The names are a contract** with whatever provisions this server's environment — renaming
one on either side silently disables the corresponding control.

| Variable | Meaning |
| --- | --- |
| `MCP_REQUIRE_AUTH` | Reject unauthenticated requests. Also disables SSE. The MCP discovery handshake is exempt — see above. |
| `MCP_DISCOVERY_REQUIRES_AUTH` | Require a bearer for `initialize`/`tools/list` too. Default false. |
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
| `MCP_POLICY_CACHE_MAX_ENTRIES` | Cached snapshots before LRU eviction. Default 512. |
| `MCP_POLICY_RETRIES` | Extra attempts for a transient PDP failure. Default 1. |

Two combinations **refuse to start**, because each is a security control that would silently
do nothing:

- `MCP_REQUIRE_AUTH=true` with no `MCP_AUTH_ISSUER` — a guard that requires auth but cannot
  verify anything would accept every caller while the operator believed it was on.
- `MCP_POLICY_URL` without `MCP_REQUIRE_AUTH` — policy is evaluated per caller, so with no
  verified caller there is nothing to decide against. Every check would raise, leaving the
  tool either wholly broken or, if a handler catches broadly, wholly open.

`MCP_POLICY_STALE_MAX_SECONDS` below `MCP_POLICY_TTL_SECONDS` is also refused: entries would
expire before they were ever revalidated, and the guard would fail closed on every call after
the first while looking like a PDP outage.

Setting **neither** `MCP_REQUIRE_AUTH` nor `MCP_AUTH_ISSUER` starts, but logs a
`guard_unconfigured` warning. The guard is then inert: every request is served
unauthenticated, and a bearer presented by a caller is ignored rather than refused. That is
the state a server is in the moment it adds the dependency, so it cannot be an error — but
from the outside it is indistinguishable from a guard that is working, which is why it is not
silent either.

Both header names are lowercased when read, because ASGI hands header names down lowercased
— so `X-Trace-Id` and `x-trace-id` behave identically.

The caller id is recorded for audit and **never used in a policy decision**: the caller
asserts it and nothing verifies it, so a policy that read it would be taking the word of the
party it is meant to constrain.

A server with `MCP_REQUIRE_AUTH` but no `MCP_POLICY_URL` verifies its caller and then allows
— the intended intermediate state during a rollout, and exactly how the tool behaved before
policy existed. The reverse is not permitted, as above.

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
   [matching.py](src/mcp_policy_guard/matching.py) — `test_matching.py` pins the shared cases.

## Failure behaviour

| Situation | Result |
| --- | --- |
| PDP reachable | Authoritative decision, audited by the backend. |
| PDP down, snapshot fresh enough | Decided locally from last-known-good. |
| PDP down, snapshot too stale | `PolicyUnavailable` — the call is refused. |
| PDP returns 401/403/404 | Refused, on **both** the evaluate and snapshot paths. Not an outage: the PDP declined to confirm this caller, so a cached snapshot must not answer for them. A 404 means `MCP_TOOL_ID` names no known tool, so no policy applies. |
| PDP returns an unparseable body | Refused. A malformed response is neither an HTTP error nor a denial, so left alone it would escape both the fallback and every `except PolicyDenied`. |
| More than 200 resources in one call | Refused. Over the PDP's cap the request 400s, which would read as an outage and silently degrade to local evaluation. |
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
matching, which is what keeps `secretary` and `monkey` readable, and redaction **recurses**
into nested dicts and lists — `{"config": {"password": "…"}}` is where the credential
actually lives.

The identity fields are written last and cannot be overridden by keyword arguments to
`emit()`. The one field a caller must not be able to set is the one naming them.

`caller_id` is recorded from the caller's own header and is **never used in a policy
decision**: nothing verifies it, so a policy reading it would be taking the word of the party
it is meant to constrain.

## Upgrading to 0.5.1

**An unconfigured guard now ignores a bearer instead of refusing it.** With neither
`MCP_REQUIRE_AUTH` nor `MCP_AUTH_ISSUER` set, a request carrying `Authorization: Bearer …`
used to be answered `401 {"error":"unauthorized","reason":"Guard has no issuer configured"}`,
while the same request without the header was served normally. Any caller in the habit of
sending a token it did not strictly need — an API key for some other hop, a leftover header —
broke the moment a server picked up the guard, typically through an automatic dependency
update rather than a decision anyone made.

A missing issuer is a property of the deployment, not a defect in the caller's token: with no
JWKS there is nothing to check it against, so there is no judgement to report. The request is
now treated exactly as it would have been had the header been absent, and no principal is
bound — so every policy check still fails closed.

This narrows only the *unconfigured* case. Once `MCP_AUTH_ISSUER` is set the guard can judge
a token, and a present-but-invalid one is still refused whether or not `MCP_REQUIRE_AUTH` is
on — unchanged from 0.5.0. The new `guard_unconfigured` startup warning names the inert state
so it stops being invisible.

## Upgrading to 0.5

**`MCP_REQUIRE_AUTH=true` no longer 401s the MCP discovery handshake.** `initialize`,
`notifications/initialized`, `ping`, `tools/list`, `resources/list`,
`resources/templates/list` and `prompts/list` are served without a bearer; see "The MCP
handshake is not authenticated" for why, and for the batch and `POST`-only rules.

Nothing else changes. `tools/call`, `resources/read`, `prompts/get`, any method not on that
list, an anonymous `GET`/`DELETE`, and a present-but-invalid token are all refused exactly as
in 0.4. Set `MCP_DISCOVERY_REQUIRES_AUTH=true` to restore 0.4 behaviour byte for byte.

Worth doing before you upgrade: if your server is stateful, an anonymous `initialize` now
creates a session, so consider `stateless_http=True`. And if `tools/list` is scoped per
caller, decide what it returns with no principal bound.

## Upgrading to 0.2

**Security fix — action required.** Add `@guarded` to every tool handler (or register
`GuardServerMiddleware` on SDK 2.x). Without it, on a stateful session every call is
authorized against whoever sent `initialize`. See [Why two pieces](#why-two-pieces).

Also breaking, all mechanical:

- `current_worker_id()` → `current_caller_id()`.
- The audit field `calling_worker_id` → `caller_id`. Update any log query that reads it.
- The default headers are now `x-mcp-correlation-id` and `x-mcp-caller-id`. If your caller
  already mints differently-named headers, name them instead of changing the caller:
  `MCP_CORRELATION_HEADER` / `MCP_CALLER_ID_HEADER`.
- The JWKS endpoint is discovered rather than assumed. Keycloak deployments are unaffected —
  discovery returns the same URL the old code hardcoded, and the hardcoded path remains the
  fallback.
- `MCP_POLICY_URL` without `MCP_REQUIRE_AUTH` now refuses to start. If you were relying on
  that combination, it was not enforcing anything.
- `filter_resources()` now raises `PolicyDenied` when the caller may not invoke the function
  at all, instead of returning a filtered list.
- `Guard.close()` no longer closes an `httpx.Client` you injected; it only closes one it
  created.
- Token verification runs off the event loop, so `GuardMiddleware` no longer stalls the
  worker during a cold-start JWKS or discovery fetch.

## Development

```bash
make install
make spec     # pytest
make lint
make format
```

The token tests sign and verify real JWTs against a real key set. A mocked verifier would
pass just as happily against a verifier that checked nothing.
