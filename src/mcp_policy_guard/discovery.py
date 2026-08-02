"""Which MCP messages an unauthenticated caller may send, and how to tell.

An MCP client learns a server's tools by *asking the server* — `initialize`, then
`tools/list`. That handshake happens when the client starts up, which for an agent runtime
is long before any end user is on the line. A server whose tools are called with the
**caller's** bearer therefore has no token to present at discovery time and never will:
the token belongs to a request that has not arrived yet.

Refusing that handshake does not secure anything, because `tools/call` is refused on its
own merits either way. What it does is make the tool *invisible*: a runtime that cannot
enumerate the server drops it, usually permanently, and the operator sees a tool that
simply is not there rather than a tool that said no. That failure is silent on both sides.

So the catalog is readable without a bearer and everything that returns data or performs an
action is not. The allow-list below is the whole of the exception, and it is an allow-list
precisely so that a method nobody thought about is refused rather than admitted.
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable

Receive = Callable[[], Awaitable[dict[str, Any]]]

#: Methods an unauthenticated caller may send. Every one of them returns *names and
#: schemas* — never row data, file contents, or a side effect.
#:
#: `resources/list` earns its place the same way `tools/list` does: a client that
#: enumerates tools generally enumerates resources on the same session, and refusing the
#: second half of the handshake strands it just as completely as refusing the first.
DISCOVERY_METHODS = frozenset(
    {
        "initialize",
        "notifications/initialized",
        "ping",
        "tools/list",
        "resources/list",
        "resources/templates/list",
        "prompts/list",
    }
)

#: Ceiling on how much of an unauthenticated body the guard will hold in memory to classify
#: it. A discovery message is a few hundred bytes; anything approaching this is not one.
#: Without the cap, an anonymous caller could make the server buffer without limit — the
#: request has not been authenticated yet, so there is nobody to hold responsible for it.
MAX_PEEK_BYTES = 64 * 1024


def _is_discovery_message(message: Any) -> bool:
    if not isinstance(message, dict):
        return False
    method = message.get("method")
    return isinstance(method, str) and method in DISCOVERY_METHODS


def is_discovery_payload(body: bytes) -> bool:
    """Whether every JSON-RPC message in `body` is one an anonymous caller may send.

    Fails closed on anything it cannot positively identify: malformed JSON, a payload that
    is neither an object nor an array, a message with no `method`, or a method absent from
    `DISCOVERY_METHODS`.

    **A batch is allowed only if every message in it is.** JSON-RPC permits an array, so
    `[initialize, tools/call]` is one HTTP request whose first element looks harmless; a
    check that stopped at the first message would admit the second. An empty array is
    refused because it asks for nothing and is not part of any handshake.
    """
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return False

    if isinstance(payload, list):
        return bool(payload) and all(_is_discovery_message(message) for message in payload)
    return _is_discovery_message(payload)


async def buffer_body(receive: Receive, limit: int = MAX_PEEK_BYTES) -> tuple[bytes, list[dict]] | None:
    """Drain the request body, returning it with the messages needed to replay it.

    ASGI bodies are consumed once. Reading one to look at it therefore means keeping the
    original messages so the wrapped app can still receive them — see `replay`.

    Returns `None` when the body must not be classified at all: the client disconnected
    mid-send, or it exceeded `limit`. Both are refusals, so the caller stops and never
    reaches the app; the partially-consumed stream is not replayed to anyone.
    """
    messages: list[dict] = []
    body = bytearray()

    while True:
        message = await receive()
        messages.append(message)

        if message["type"] == "http.disconnect":
            return None

        body.extend(message.get("body", b"") or b"")
        if len(body) > limit:
            return None

        if not message.get("more_body", False):
            return bytes(body), messages


def replay(messages: list[dict], receive: Receive) -> Receive:
    """A `receive` that yields `messages` in order and then delegates to `receive`.

    **Delegating rather than reporting a disconnect is load-bearing, and the bug it avoids
    is invisible in a unit test.** The MCP SDK answers `POST /mcp` with an
    `sse_starlette.EventSourceResponse` (it only returns a plain JSON body when the server
    is built with `json_response=True`, which `routes()` never does). That response runs
    `_listen_for_disconnect(receive)` in a task group alongside the task streaming the body,
    under `cancel_on_finish` — so the first `http.disconnect` it reads cancels the response
    mid-flight. A replay that synthesised a disconnect once the buffer ran dry would
    therefore truncate the reply to every anonymous `initialize`, and it would look like the
    guard rejecting the request rather than the transport being hung up on.

    Handing back the original `receive` reproduces the un-buffered semantics exactly: the
    app sees the body it would have seen, and then the same disconnect signal, at the same
    time, that the server would have given it.
    """
    remaining = list(messages)

    async def replaying() -> dict[str, Any]:
        if remaining:
            return remaining.pop(0)
        return await receive()

    return replaying


__all__ = ["DISCOVERY_METHODS", "MAX_PEEK_BYTES", "buffer_body", "is_discovery_payload", "replay"]
