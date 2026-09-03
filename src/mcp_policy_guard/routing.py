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

Building the apps here also means owning the arguments they are built with. On SDK 1.x that
was nothing to own: transport options came off the server constructor. On 2.x they were moved
onto these builders, so calling them bare is a decision — and the default one strands the
server on localhost. Hence `app_kwargs`.
"""

from __future__ import annotations

import inspect
from typing import Any, Mapping, Sequence

import structlog

from .config import GuardConfig
from .middleware import GuardMiddleware

logger = structlog.get_logger()

#: Keys whose presence in `app_kwargs` means the caller has thought about DNS-rebinding
#: protection on 2.x — either by supplying settings outright or by naming a non-default host.
_TRANSPORT_SECURITY_KEYS = frozenset({"transport_security", "host"})


def _sdk_major() -> int | None:
    """The installed MCP SDK's major version, or None when it cannot be determined.

    The SDK is deliberately not a dependency of this package, so this has to degrade to
    "say nothing" rather than raise: a guard that cannot import the server framework is a
    guard doing its job, not a broken one.
    """
    try:
        from importlib.metadata import version

        return int(version("mcp").split(".", 1)[0])
    except Exception:
        return None


#: The SDK's own default SSE stream path, on both generations.
DEFAULT_SSE_PATH = "/sse"


def _accepts_kwarg(fn: Any, name: str) -> bool:
    """Whether `fn` will accept `name` as a keyword argument.

    The two SDK generations disagree about how the SSE stream path is set, and guessing
    wrong raises `TypeError` at import time in every server that uses this package.
    """
    try:
        signature = inspect.signature(fn)
    except (TypeError, ValueError):  # pragma: no cover - builtins and C callables
        return False
    params = signature.parameters
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return True
    return name in params


def routes(
    mcp: Any,
    config: GuardConfig,
    *,
    extra_routes: Sequence[Any] = (),
    sse_path: str = "/sse",
    app_kwargs: Mapping[str, Any] | None = None,
    sse_app_kwargs: Mapping[str, Any] | None = None,
) -> list[Any]:
    """The route list for a guarded MCP server.

    `extra_routes` — health probes, a root handler — are placed first and stay unguarded,
    which is the point: a readiness probe must not be asked for a bearer token.

    SSE is mounted only when `config.sse_allowed`, and never when `MCP_REQUIRE_AUTH` is on:
    under SSE the long-lived connection that carried the `Authorization` header is not the
    request that carries a tool call, so a call cannot be attributed to a caller. Mounting it
    anyway would leave a second, unauthenticated door into the same tools.

    `app_kwargs` and `sse_app_kwargs` are forwarded verbatim to the SDK's app builders, and
    which options they accept is the caller's SDK generation to know — this package does not
    depend on the SDK and does not translate between the two. The distinction that matters:

    * On **1.x** transport options live on the `FastMCP` constructor, which writes
      `settings`, which the no-argument builders read. Leave both empty and keep configuring
      the server object.
    * On **2.x** those options were removed from the constructor *and* from `Settings`; they
      survive only as keyword arguments here. Leave `app_kwargs` empty and `host` defaults to
      `127.0.0.1`, which auto-enables DNS-rebinding protection with a localhost-only
      allow-list — so every request arriving through an ingress under its real hostname is
      answered `421 Invalid Host header`, with no way for the caller to intervene.
    """
    from starlette.routing import Mount  # imported here so Starlette stays a soft dependency

    app_kwargs = app_kwargs or {}
    sse_app_kwargs = sse_app_kwargs or {}

    major = _sdk_major()
    # `>= 2` rather than `== 2`: 1.x is the generation with the constructor seam, so every
    # later one inherits the trap until something says otherwise.
    if major is not None and major >= 2 and _TRANSPORT_SECURITY_KEYS.isdisjoint(app_kwargs):
        # Warn, never decide: silently widening an allow-list is not a guard's call to make.
        logger.warning(
            "transport_defaults_to_localhost",
            sdk_major=major,
            detail=(
                "streamable_http_app() defaulted host to 127.0.0.1, which auto-enables "
                "DNS-rebinding protection allowing localhost only; requests bearing any "
                "other Host header will be answered 421."
            ),
            fix="pass app_kwargs={'transport_security': ...} or app_kwargs={'host': ...}",
        )

    built: list[Any] = list(extra_routes)

    if config.sse_allowed:
        # Splice the SSE app's own routes in rather than mounting it under `sse_path`.
        #
        # `sse_app()` is a Starlette app that already serves its stream at `/sse` and its
        # message endpoint at `/messages/`, on both SDK generations. Mounting it at "/sse"
        # therefore nested the two into `/sse/sse` and `/sse/messages/`, so the path this
        # function logs — and that every server's `/` endpoint advertises — answered 404.
        #
        # Re-prefixing is not an option either: the transport bakes the message path into
        # the `endpoint` event it sends the client at connect time, so a mount prefix makes
        # the server advertise a URL it does not serve. Lifting the routes out keeps the
        # absolute paths the SDK intends, while still placing them ahead of the catch-all
        # mount below — which is the half the old hand-built route lists got wrong, leaving
        # SSE reachable at no path at all.
        sse_kwargs = dict(sse_app_kwargs)
        if "sse_path" not in sse_kwargs:
            # 2.x takes the stream path as a builder argument; 1.x reads it from the
            # settings the server was constructed with and offers no way to override it
            # here. Forward it where it is accepted so `sse_path` keeps meaning what it
            # says, and say so plainly where it cannot be honoured rather than logging a
            # path the server does not serve.
            if sse_path == DEFAULT_SSE_PATH:
                # Nothing to say: this is the SDK's own default. Passing it anyway would
                # override a path a 1.x server was deliberately constructed with, which is
                # the "invent no defaults" rule the transport kwargs already follow.
                pass
            elif _accepts_kwarg(mcp.sse_app, "sse_path"):
                sse_kwargs["sse_path"] = sse_path
            else:
                logger.warning(
                    "sse_path_not_applied",
                    requested=sse_path,
                    detail=(
                        "this MCP SDK takes the SSE path from the server's own settings, "
                        "so the requested path was ignored"
                    ),
                )

        sse_app = mcp.sse_app(**sse_kwargs)
        if getattr(sse_app, "user_middleware", None):
            # Only reachable if the SDK's own auth is configured, which `sse_allowed`
            # already precludes. Say so rather than drop it silently.
            logger.warning(
                "sse_middleware_not_preserved",
                detail="the SDK's SSE app carries middleware that splicing its routes does not apply",
            )
        built.extend(sse_app.routes)
        logger.info(
            "sse_mounted",
            paths=[getattr(route, "path", None) for route in sse_app.routes],
            reason="MCP_REQUIRE_AUTH is not set",
        )

    built.append(Mount("/", app=GuardMiddleware(mcp.streamable_http_app(**app_kwargs), config)))
    return built


__all__ = ["routes"]
