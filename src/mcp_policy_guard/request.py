"""Carrying the caller from the HTTP request to the handler that acts on it.

**This module exists because the obvious approach is wrong.** The ASGI middleware verifies a
token and knows exactly who is calling — but on MCP SDK 1.x an MCP tool handler does not run
in the ASGI request task. On a stateful streamable-HTTP session the handler runs in a task
spawned once, when `initialize` arrived, and Python copies the *spawning* task's context.
Bind the principal to a contextvar in the middleware and every later `tools/call` on that
session reads whoever opened it, forever. Two users sharing one session means the second is
authorized against the first one's grants, which is the precise failure this package exists
to prevent. Verified against a real server on mcp 1.26: user B's call is answered with user
A's identity.

The fix is to carry the principal on the **ASGI scope**, which belongs to one HTTP request
and so cannot be captured by a task spawned earlier, and to re-bind it around each inbound
message from the per-message request the SDK already tracks.

Both SDK generations are supported and both are exercised in CI, because they differ exactly
here:

* **1.x** keeps a `request_ctx` contextvar holding a `RequestContext` whose `.request` is
  this message's HTTP request. It is set and reset around each message, so reading it inside
  a handler is correct even though the surrounding task is shared. `guarded` uses it, and on
  this generation `guarded` is what makes the guard correct at all.
* **2.x** dispatches each message in its own task with the context already correct — the bug
  does not reproduce there — and exposes no ambient per-message request. It adds a
  context-tier middleware tier instead, which `GuardServerMiddleware` registers on so the
  binding is established once for every tool rather than per decorated handler. `guarded`
  degrades to a no-op that leaves the correct binding untouched.

The SDK is not a dependency of this package; it is detected at runtime, and every lookup into
it is defensive.

A namespaced scope key rather than `Request.state`, so no framework layer in between can
reset it out from under the guard.
"""

from __future__ import annotations

import contextlib
import functools
from collections.abc import Awaitable, Callable, Iterator
from typing import Any, TypeVar

import structlog

from .errors import AuthenticationRequired
from .principal import (
    Principal,
    current_principal,
    reset_caller_id,
    reset_correlation_id,
    reset_principal,
    set_caller_id,
    set_correlation_id,
    set_principal,
)

logger = structlog.get_logger()

#: Where `GuardMiddleware` records the verified caller for one HTTP request.
SCOPE_PRINCIPAL = "mcp_policy_guard.principal"
SCOPE_CORRELATION_ID = "mcp_policy_guard.correlation_id"
SCOPE_CALLER_ID = "mcp_policy_guard.caller_id"

#: Distinguishes "no request argument given" from an explicit `None`, which means "there is
#: genuinely no request here" and must not silently fall back to the ambient one.
_UNSET: Any = object()

F = TypeVar("F", bound=Callable[..., Any])


def principal_from_scope(scope: dict[str, Any] | None) -> Principal | None:
    """The caller recorded on an ASGI scope, if any."""
    if not scope:
        return None
    principal = scope.get(SCOPE_PRINCIPAL)
    return principal if isinstance(principal, Principal) else None


def _scope_of(request: Any) -> dict[str, Any] | None:
    """The ASGI scope behind whatever per-message request object the SDK handed us.

    Deliberately duck-typed. The attribute is stable across SDK generations even as the
    surrounding class is renamed and re-homed, and a hard import would couple this package
    to a specific SDK version for the sake of one attribute lookup.
    """
    scope = getattr(request, "scope", None)
    return scope if isinstance(scope, dict) else None


def current_message_request() -> Any | None:
    """This message's HTTP request, from the SDK's own per-message context.

    On MCP SDK 1.x the low-level server sets a `request_ctx` contextvar around every inbound
    message and resets it afterwards, so it names the current message even inside the
    long-lived session task that makes the naive binding wrong. That is what lets `guarded`
    work on 1.x without the handler having to declare a `ctx` parameter.

    Imported lazily and defensively: `mcp` is not a dependency of this package (a guard
    should not drag in a server framework), the module path moved between SDK generations,
    and outside a message there is simply nothing to look up.
    """
    try:
        from mcp.server.lowlevel.server import request_ctx
    except Exception:  # pragma: no cover - SDK absent or re-homed
        return None

    try:
        return getattr(request_ctx.get(), "request", None)
    except LookupError:
        # Not inside an MCP message — a plain HTTP route, or a direct unit-test call.
        return None


@contextlib.contextmanager
def bind_request_principal(request: Any = _UNSET, *, required: bool = False) -> Iterator[Principal | None]:
    """Bind the caller of one inbound message, and unbind it again on the way out.

    The reset is not hygiene, it is the fix: the task this runs in outlives the message, so
    a binding left in place would be read by the next message whose own binding did not
    happen. `finally` rather than a plain trailing call, because a handler that raises must
    not leave its identity behind for the next caller.

    `required=True` raises `AuthenticationRequired` when no verified caller can be found at
    all. That is for callers that want the loud failure here rather than at the first policy
    check.

    Omit `request` to take it from the SDK's own per-message context.

    **When no request can be found, the existing binding is left alone rather than cleared.**
    That is what makes this safe on SDK 2.x, which exposes no ambient per-message request:
    there the ASGI middleware's binding is already this message's caller, and overwriting it
    with `None` would answer every call with `AuthenticationRequired` — failing closed, but
    with the whole server bricked. Rebinding is only correct when there is something better
    to rebind *to*.
    """
    if request is _UNSET:
        request = current_message_request()

    scope = _scope_of(request)

    if scope is None:
        # Nothing authoritative to bind from. Whatever is already bound is the best answer
        # available, and on 2.x it is the right one.
        existing = current_principal()
        if existing is None and required:
            raise AuthenticationRequired("No authenticated caller on this message")
        yield existing
        return

    principal = principal_from_scope(scope)

    if principal is None and required:
        raise AuthenticationRequired("No authenticated caller on this message")

    principal_token = set_principal(principal)
    correlation_token = set_correlation_id(scope.get(SCOPE_CORRELATION_ID))
    caller_token = set_caller_id(scope.get(SCOPE_CALLER_ID))
    try:
        yield principal
    finally:
        reset_caller_id(caller_token)
        reset_correlation_id(correlation_token)
        reset_principal(principal_token)


class GuardServerMiddleware:
    """MCP context-tier middleware binding the caller of every inbound message.

    Register it on the server rather than decorating handlers one at a time:

        MCPServer("my-server", middleware=[GuardServerMiddleware()])

    A decorator would have to be remembered on every tool, and the one it was forgotten on
    would be the one still reading the session opener's identity — a security control that
    fails silently and only under concurrent use. Registering once covers every tool, every
    resource and every prompt, including ones added later.

    Pairs with `GuardMiddleware`, which is what puts the principal on the scope. Without it
    every message binds `None` and each policy check raises `AuthenticationRequired`.
    """

    def __init__(self, *, required: bool = False) -> None:
        self.required = required

    async def __call__(self, ctx: Any, call_next: Callable[[Any], Awaitable[Any]]) -> Any:
        # The context's own request, not the ambient one: on 2.x this middleware *is* the
        # per-message seam, so taking it from the argument keeps it exact.
        with bind_request_principal(getattr(ctx, "request", None), required=self.required):
            return await call_next(ctx)


def guarded(fn: F) -> F:
    """Bind the caller around one tool handler. **Required on MCP SDK 1.x.**

    Apply it under the tool registration, so the SDK registers the wrapper:

        @mcp.tool()
        @guarded
        async def mssql_query(query: str) -> str:
            ...

    The request is taken from the SDK's own per-message context, so the handler needs no
    extra parameter and its published schema is unchanged. `functools.wraps` preserves
    `__wrapped__` and `__annotations__` deliberately: the SDK builds each tool's JSON schema
    from `inspect.signature`, and a decorator that flattened the signature to
    `(*args, **kwargs)` would publish a tool that accepts nothing.

    On 2.x prefer `GuardServerMiddleware` — one registration covers every tool, including
    the one somebody forgets to decorate.
    """

    @functools.wraps(fn)
    async def _wrapper(*args: Any, **kwargs: Any) -> Any:
        with bind_request_principal():
            return await fn(*args, **kwargs)

    # Lets a server assert that every tool it registered is guarded. Forgetting the
    # decorator on one handler is the realistic failure — it is invisible in review and
    # only misbehaves under concurrent use — so it should be something a test can catch.
    _wrapper.__mcp_policy_guard_guarded__ = True  # type: ignore[attr-defined]
    return _wrapper  # type: ignore[return-value]


def is_guarded(fn: Any) -> bool:
    """Whether `fn` was wrapped by `guarded`."""
    return getattr(fn, "__mcp_policy_guard_guarded__", False) is True


def audit_principal_disagreement(scope_principal: Principal | None) -> None:
    """Log when the bound principal disagrees with the one on the request scope.

    That disagreement is the fingerprint of the bug this module fixes: it means the
    contextvar is answering for a different caller than the message actually came from.
    Loud, because it is unfalsifiable from the outside — the wrong answer looks exactly like
    the right one.
    """
    bound = current_principal()
    if scope_principal is not None and bound is not None and bound.subject != scope_principal.subject:
        logger.error(
            "principal_binding_disagreement",
            bound_subject=bound.subject,
            request_subject=scope_principal.subject,
        )


__all__ = [
    "SCOPE_CALLER_ID",
    "SCOPE_CORRELATION_ID",
    "SCOPE_PRINCIPAL",
    "GuardServerMiddleware",
    "bind_request_principal",
    "guarded",
    "is_guarded",
    "principal_from_scope",
]
