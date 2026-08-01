"""The principal must belong to the message, not to the session.

This pins the package's central promise. An MCP session is long-lived and established by
whoever sent `initialize`; every later `tools/call` on it may come from a different user. On
MCP SDK 1.x the low-level server dispatches every message of a stateful session inside one
task spawned when `initialize` arrived, and Python copies the *spawning* task's context. So
a principal bound to a contextvar in the ASGI middleware is the session opener's, forever:
User B's call gets authorized against User A's grants, silently, and only when a session
outlives one caller.

Driven through the real MCP wire protocol against a real `FastMCP`, because the failure
lives precisely in the seam between the ASGI request task and the task the handler runs in.
Nothing here stubs that seam.
"""

from __future__ import annotations

import contextlib
import json
from typing import Any

import httpx
import pytest
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import LATEST_PROTOCOL_VERSION

from mcp_guard.middleware import GuardMiddleware
from mcp_guard.principal import current_principal
from mcp_guard.request import guarded

JSON_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


@contextlib.asynccontextmanager
async def _client(config, *, stateless: bool, guard_handler: bool = True):
    """A client wired to a FastMCP whose one tool reports the principal it can see.

    `guard_handler=False` builds the same server with the fix removed, so a test can assert
    the leak is real rather than hypothetical.
    """
    mcp = FastMCP("binding-probe")

    async def _whoami_impl() -> str:
        principal = current_principal()
        return principal.subject if principal else "anonymous"

    mcp.tool(name="whoami")(guarded(_whoami_impl) if guard_handler else _whoami_impl)

    mcp.settings.streamable_http_path = "/mcp"
    mcp.settings.json_response = True
    mcp.settings.stateless_http = stateless
    # Irrelevant to what is under test, and it rejects the synthetic Host ASGITransport sends.
    mcp.settings.transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    inner = mcp.streamable_http_app()

    guarded_app = GuardMiddleware(inner, config)

    # The session manager's task group is started by the app's lifespan, so it has to run
    # for the stateful path to work at all.
    async with inner.router.lifespan_context(inner):
        transport = httpx.ASGITransport(app=guarded_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            yield client


def _rpc(method: str, params: dict[str, Any] | None = None, request_id: int | None = 1) -> dict[str, Any]:
    body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if request_id is not None:
        body["id"] = request_id
    if params is not None:
        body["params"] = params
    return body


def _result(response: httpx.Response) -> dict[str, Any]:
    """The JSON-RPC payload, whether it came back as JSON or as a one-event SSE stream."""
    if response.headers.get("content-type", "").startswith("text/event-stream"):
        for line in response.text.splitlines():
            if line.startswith("data:"):
                return json.loads(line[len("data:") :].strip())
        raise AssertionError(f"no data frame in SSE response: {response.text!r}")
    return response.json()


async def _initialize(client: httpx.AsyncClient, token: str) -> str | None:
    response = await client.post(
        "/mcp",
        headers={**JSON_HEADERS, "Authorization": f"Bearer {token}"},
        json=_rpc(
            "initialize",
            {
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "binding-probe", "version": "1"},
            },
        ),
    )
    assert response.status_code == 200, response.text
    session_id = response.headers.get("mcp-session-id")

    headers = {**JSON_HEADERS, "Authorization": f"Bearer {token}"}
    if session_id:
        headers["mcp-session-id"] = session_id
    await client.post("/mcp", headers=headers, json=_rpc("notifications/initialized", request_id=None))
    return session_id


async def _whoami(client: httpx.AsyncClient, token: str, session_id: str | None) -> str:
    headers = {**JSON_HEADERS, "Authorization": f"Bearer {token}"}
    if session_id:
        headers["mcp-session-id"] = session_id
        headers["mcp-protocol-version"] = LATEST_PROTOCOL_VERSION

    response = await client.post(
        "/mcp",
        headers=headers,
        json=_rpc("tools/call", {"name": "whoami", "arguments": {}}, request_id=2),
    )
    assert response.status_code == 200, response.text
    payload = _result(response)
    assert "error" not in payload, payload
    return payload["result"]["content"][0]["text"]


@pytest.mark.parametrize("stateless", [False, True], ids=["stateful", "stateless"])
class TestPerMessagePrincipal:
    async def test_a_second_caller_is_not_served_the_first_callers_identity(self, config, make_token, stateless):
        """The regression test for the cross-user leak."""
        async with _client(config, stateless=stateless) as client:
            session_id = await _initialize(client, make_token(sub="user-a-sub"))

            assert await _whoami(client, make_token(sub="user-a-sub"), session_id) == "user-a-sub"
            assert await _whoami(client, make_token(sub="user-b-sub"), session_id) == "user-b-sub"
            # Back to A: the binding must track each message, not latch onto the last one.
            assert await _whoami(client, make_token(sub="user-a-sub"), session_id) == "user-a-sub"

    async def test_the_principal_does_not_leak_out_of_the_call(self, config, make_token, stateless):
        """The binding must be reset when the message finishes.

        The task the handler runs in outlives the message, so a binding left set is the same
        leak wearing a different hat: the next message would find a stale principal already
        in place if its own binding ever failed to happen.
        """
        async with _client(config, stateless=stateless) as client:
            session_id = await _initialize(client, make_token(sub="user-a-sub"))
            await _whoami(client, make_token(sub="user-a-sub"), session_id)

        assert current_principal() is None


class TestTheLeakIsReal:
    """Without the per-message binding the guard hands one caller another's identity.

    Kept as an executable statement of the bug, so `guarded` cannot quietly become a no-op.
    MCP SDK 2.x dispatches each message in its own task and does not leak; when this package
    moves to it, this test fails, and that failure is the signal to re-examine whether the
    decorator is still load-bearing rather than to delete it on a hunch.
    """

    async def test_an_unguarded_handler_sees_the_session_opener(self, config, make_token):
        async with _client(config, stateless=False, guard_handler=False) as client:
            session_id = await _initialize(client, make_token(sub="user-a-sub"))

            assert await _whoami(client, make_token(sub="user-a-sub"), session_id) == "user-a-sub"
            # The bug, stated plainly: B asked, A answered.
            assert await _whoami(client, make_token(sub="user-b-sub"), session_id) == "user-a-sub"
