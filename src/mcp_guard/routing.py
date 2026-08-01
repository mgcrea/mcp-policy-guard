"""Building the route list correctly, because the obvious version silently does nothing.

The wiring this package used to document mounts two apps at the same path:

    Mount("/", app=GuardMiddleware(mcp.streamable_http_app(), guard.config)),
    Mount("/", app=mcp.sse_app()),          # unreachable

Starlette's router returns on the first `Match.FULL`, and `Mount("/")` matches *every*
path — so the second mount is dead code. When `sse_allowed` is False that is harmless luck;
when it is True the operator believes SSE is served and it is not. Either way the guard's
central transport decision was being made by list ordering rather than by policy.

`routes()` builds the list so the decision is explicit: the guarded streamable app at the
catch-all, and SSE — when permitted — at its own path *before* it, where it can actually be
reached.
"""

from __future__ import annotations

from typing import Any, Sequence

import structlog

from .config import GuardConfig
from .middleware import GuardMiddleware

logger = structlog.get_logger()


def routes(
    mcp: Any,
    config: GuardConfig,
    *,
    extra_routes: Sequence[Any] = (),
    sse_path: str = "/sse",
) -> list[Any]:
    """The route list for a guarded MCP server.

    `extra_routes` — health probes, a root handler — are placed first and stay unguarded,
    which is the point: a readiness probe must not be asked for a bearer token.

    SSE is mounted only when `config.sse_allowed`, and never when `MCP_REQUIRE_AUTH` is on:
    under SSE the long-lived connection that carried the `Authorization` header is not the
    request that carries a tool call, so a call cannot be attributed to a caller. Mounting it
    anyway would leave a second, unauthenticated door into the same tools.
    """
    from starlette.routing import Mount  # imported here so Starlette stays a soft dependency

    built: list[Any] = list(extra_routes)

    if config.sse_allowed:
        # Its own path, and ahead of the catch-all: mounted after it, it would never match.
        built.append(Mount(sse_path, app=mcp.sse_app()))
        logger.info("sse_mounted", path=sse_path, reason="MCP_REQUIRE_AUTH is not set")

    built.append(Mount("/", app=GuardMiddleware(mcp.streamable_http_app(), config)))
    return built


__all__ = ["routes"]
