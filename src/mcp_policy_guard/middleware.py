"""ASGI middleware that establishes the caller for each request.

Wrapping the MCP app rather than passing `middleware=[...]` to `Starlette(...)` is
deliberate: a Kubernetes readiness probe hits `/healthz`, and a Starlette-level middleware
would demand a bearer token from the kubelet. Mount it around the MCP app only —

    Mount("/", app=GuardMiddleware(mcp.streamable_http_app(), guard.config))

— and the probe route stays open while every path that can reach a tool is covered. Note it
takes the `GuardConfig`, not the `Guard`; passing the latter fails on the first request.

**This middleware is half the story.** It establishes who is calling for one HTTP request;
`mcp_policy_guard.request` is what makes a tool handler read *that* caller rather than whoever
opened the MCP session. Neither is sufficient alone.
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable

import anyio.to_thread
import structlog

from .config import GuardConfig
from .discovery import MAX_PEEK_BYTES, buffer_body, is_discovery_payload, replay
from .errors import AuthenticationRequired
from .jwt_verify import verify_token
from .principal import (
    reset_caller_id,
    reset_correlation_id,
    reset_principal,
    set_caller_id,
    set_correlation_id,
    set_principal,
)
from .request import SCOPE_CALLER_ID, SCOPE_CORRELATION_ID, SCOPE_PRINCIPAL

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

        correlation_id = headers.get(self.config.correlation_header)
        caller_id = headers.get(self.config.caller_id_header)

        # The scope is the source of truth: it belongs to *this* HTTP request, so a task
        # spawned by an earlier request cannot have captured it. See `request.py`.
        scope[SCOPE_CORRELATION_ID] = correlation_id
        scope[SCOPE_CALLER_ID] = caller_id
        scope[SCOPE_PRINCIPAL] = None

        # Also bound to the context here, *before* the auth check, so a 401 logs under the
        # correlation id of the turn that caused it, and so non-MCP callers that never reach
        # `GuardServerMiddleware` still see the caller. Reset on the way out: whether this
        # task is reused is the server's business, not ours, and a binding left behind is
        # one an unrelated later caller could read.
        correlation_token = set_correlation_id(correlation_id)
        caller_token = set_caller_id(caller_id)
        principal_token = set_principal(None)
        try:
            await self._dispatch(scope, receive, send, headers)
        finally:
            reset_principal(principal_token)
            reset_caller_id(caller_token)
            reset_correlation_id(correlation_token)

    async def _allow_discovery(self, scope: Scope, receive: Receive, headers: dict[str, str]) -> tuple[bool, Receive]:
        """Whether this bearer-less request is part of the MCP discovery handshake.

        Returns the `receive` to use downstream alongside the verdict, because classifying a
        POST means consuming its body and handing back a replay of it.

        **`POST` only.** A `GET` or `DELETE` on `/mcp` carries no JSON-RPC body, so there is
        no method to classify and the package's rule for input it cannot classify is to
        refuse. Nor are they free to admit: under streamable HTTP a `GET` attaches to the
        server→client stream of whatever session `Mcp-Session-Id` names, and a `DELETE` ends
        it — so admitting them anonymously would put a second, unauthenticated door onto an
        *authenticated* caller's session, which is the same shape of hole `sse_allowed`
        already refuses to open. Refusing them costs discovery nothing: in the Python SDK
        the GET stream is a background task (`tg.start_soon(handle_get_stream, ...)`) whose
        errors are swallowed and retried, and `terminate_session` logs a warning on any
        non-2xx; neither failure reaches `initialize` or `tools/list`.

        The refusal stays a 401 rather than a 405 on purpose — an OAuth-capable client
        branches on 401 to start its auth flow, and reads 405 as "this server has no such
        endpoint".

        Buffering happens **only here**, on the path that was about to 401 anyway. An
        authenticated request never touches `receive` and keeps streaming exactly as before.
        """
        if str(scope.get("method", "")).upper() != "POST":
            return False, receive

        # Refuse on the declared length before reading a single byte, so an oversized body
        # costs nothing to turn away.
        declared = headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > MAX_PEEK_BYTES:
            return False, receive

        buffered = await buffer_body(receive, MAX_PEEK_BYTES)
        if buffered is None:
            return False, receive

        body, messages = buffered
        if not is_discovery_payload(body):
            return False, receive
        return True, replay(messages, receive)

    async def _dispatch(self, scope: Scope, receive: Receive, send: Send, headers: dict[str, str]) -> None:
        token = _bearer(headers)

        if token is not None and not self.config.require_auth and not self.config.issuer:
            # An unconfigured guard has no opinion about a token it was never given the means
            # to check. Falling through to `verify_token` would refuse it with "Guard has no
            # issuer configured" — a *deployment* state reported as if the caller's token were
            # at fault, and a hard 401 for a header this server never asked for.
            #
            # This is not the "present but invalid" case below. That one presumes a guard that
            # *can* judge a token and found it wanting; here there is no issuer, no JWKS and no
            # judgement to make, so the only honest reading of the request is the one it would
            # have got had the header been absent. `require_auth` is off, so nothing is being
            # enforced either way, and no principal is bound — every policy check still fails
            # closed.
            #
            # Silently dropping a bearer would be the wrong default for a guard that *is*
            # configured, which is why this is narrowed to `not issuer`. See the startup
            # warning in `GuardConfig.from_env`: this state is legitimate but worth saying out
            # loud, because it means the tool is serving every caller unauthenticated.
            logger.debug("unconfigured_guard_ignored_bearer", path=scope.get("path"))
            token = None

        if token is None:
            if self.config.require_auth:
                if not self.config.discovery_requires_auth:
                    allowed, receive = await self._allow_discovery(scope, receive, headers)
                    if allowed:
                        # Through with no principal: `scope[SCOPE_PRINCIPAL]` stays None and
                        # the contextvar stays unset, so a handler reached this way still
                        # fails every policy check. Discovery is a hole in authentication
                        # only, never in authorization.
                        logger.debug("discovery_allowed_unauthenticated", path=scope.get("path"))
                        await self.app(scope, receive, send)
                        return
                await _unauthorized(send, "Missing bearer token")
                return
            # Not enforcing: no principal, and every later policy check will say so rather
            # than inventing an anonymous identity that policy could accidentally match.
            await self.app(scope, receive, send)
            return

        try:
            # Off the event loop: verification can fetch the discovery document and the key
            # set, both blocking `httpx`/`urllib` calls. Run inline they would stall every
            # other request on this worker for the duration of a cold start.
            principal = await anyio.to_thread.run_sync(verify_token, token, self.config)
        except AuthenticationRequired as exc:
            if self.config.require_auth:
                await _unauthorized(send, exc.reason)
                return
            # A *present but invalid* token is never accepted as anonymous, even when not
            # enforcing: it means the caller believes it is authenticated, and letting the
            # call through unattributed would file its actions under nobody.
            await _unauthorized(send, exc.reason)
            return

        scope[SCOPE_PRINCIPAL] = principal
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
