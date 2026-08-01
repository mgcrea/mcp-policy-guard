"""ASGI middleware that establishes the caller for each request.

Wrapping the MCP app rather than passing `middleware=[...]` to `Starlette(...)` is
deliberate: a Kubernetes readiness probe hits `/healthz`, and a Starlette-level middleware
would demand a bearer token from the kubelet. Mount it around the MCP app only —

    Mount("/", app=GuardMiddleware(mcp.streamable_http_app(), guard))

— and the probe route stays open while every path that can reach a tool is covered.
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable

import structlog

from .config import GuardConfig
from .errors import AuthenticationRequired
from .jwt_verify import verify_token
from .principal import set_caller_id, set_correlation_id, set_principal

logger = structlog.get_logger()

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]

# oauth2-proxy exposes the caller's access token here (via `pass_access_token`) when the
# server is reached through a public ingress. Checked as a fallback because on that path
# `Authorization` has been consumed by the proxy itself.
ACCESS_TOKEN_HEADER = "x-auth-request-access-token"


def _headers(scope: Scope) -> dict[str, str]:
    return {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in scope.get("headers", [])}


def _bearer(headers: dict[str, str]) -> str | None:
    raw = headers.get("authorization")
    if raw:
        parts = raw.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
    forwarded = headers.get(ACCESS_TOKEN_HEADER)
    if forwarded:
        return forwarded.strip()
    return None


class GuardMiddleware:
    """Verifies the bearer on each request and binds the principal to the context."""

    def __init__(self, app: Any, config: GuardConfig | None = None) -> None:
        self.app = app
        self.config = config or GuardConfig.from_env()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            # Websocket/lifespan pass straight through. Note there is no authenticated
            # websocket path by design — see GuardConfig.sse_allowed.
            await self.app(scope, receive, send)
            return

        headers = _headers(scope)

        # Bound to the context *before* the auth check, so a 401 still logs under the
        # correlation id of the turn that caused it.
        set_correlation_id(headers.get(self.config.correlation_header))
        set_caller_id(headers.get(self.config.caller_id_header))

        token = _bearer(headers)

        if token is None:
            if self.config.require_auth:
                await _unauthorized(send, "Missing bearer token")
                return
            # Not enforcing: no principal, and every later policy check will say so rather
            # than inventing an anonymous identity that policy could accidentally match.
            set_principal(None)
            await self.app(scope, receive, send)
            return

        try:
            principal = verify_token(token, self.config)
        except AuthenticationRequired as exc:
            if self.config.require_auth:
                await _unauthorized(send, exc.reason)
                return
            # A *present but invalid* token is never accepted as anonymous, even when not
            # enforcing: it means the caller believes it is authenticated, and letting the
            # call through unattributed would file its actions under nobody.
            await _unauthorized(send, exc.reason)
            return

        set_principal(principal)
        logger.debug(
            "request_authenticated",
            subject=principal.subject,
            client_id=principal.client_id,
            groups=list(principal.groups),
        )
        await self.app(scope, receive, send)


async def _unauthorized(send: Send, reason: str) -> None:
    body = json.dumps({"error": "unauthorized", "reason": reason}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                # Tells an MCP client this is an auth problem it could fix, not a dead
                # endpoint to retry forever.
                (b"www-authenticate", b'Bearer realm="mcp"'),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
