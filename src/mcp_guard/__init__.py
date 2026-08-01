"""mcp-guard — per-caller authorization for MCP servers.

An MCP server is the last place a request passes before it reaches real data, and the first
place where "who is asking" and "what are they asking for" are both known. That makes it the
only honest place to enforce per-user access: the model's intent is irrelevant here, because
the decision is made against the *arguments it emitted*, after any prompt injection has
already had its say.

Typical wiring, in a server's `server.py`:

    from mcp_guard import Guard, GuardMiddleware

    guard = Guard()

    routes = [
        Route("/healthz", healthz),
        Mount("/", app=GuardMiddleware(mcp.streamable_http_app(), guard.config)),
    ]
    if guard.config.sse_allowed:
        routes.append(Mount("/", app=mcp.sse_app()))

and in a tool handler:

    from mcp_guard import Resource, audit_call

    with audit_call("mssql_query", {"query": query}) as record:
        tables = extract_referenced_tables(query)
        record["resources"] = sorted(tables)
        decision = guard.require("mssql_query", [Resource("sql_table", t) for t in tables])
        record["decision"] = decision.decision
        ...
"""

from .audit import audit_call, emit, redact
from .config import GuardConfig
from .errors import (
    AuthenticationRequired,
    GuardConfigurationError,
    GuardError,
    PolicyDenied,
    PolicyUnavailable,
)
from .middleware import GuardMiddleware
from .policy import Decision, Guard, Resource
from .principal import (
    Principal,
    current_caller_id,
    current_correlation_id,
    current_principal,
    require_principal,
)
from .snapshot import PolicySnapshot

__version__ = "0.2.0"

__all__ = [
    "AuthenticationRequired",
    "Decision",
    "Guard",
    "GuardConfig",
    "GuardConfigurationError",
    "GuardError",
    "GuardMiddleware",
    "PolicyDenied",
    "PolicySnapshot",
    "PolicyUnavailable",
    "Principal",
    "Resource",
    "audit_call",
    "current_caller_id",
    "current_correlation_id",
    "current_principal",
    "emit",
    "redact",
    "require_principal",
]
