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

from mcp_policy_guard.middleware import GuardMiddleware
from mcp_policy_guard.principal import current_principal
from mcp_policy_guard.request import guarded

from ._mcp_compat import IS_V1, PROTOCOL_VERSION, build_app, build_server, register_tool

LATEST_PROTOCOL_VERSION = PROTOCOL_VERSION

JSON_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


@contextlib.asynccontextmanager
async def _client(config, *, stateless: bool, guard_handler: bool = True):
    """A client wired to a server whose one tool reports the principal it can see.

    `guard_handler=False` builds the same server with the fix removed, so a test can assert
    the leak is real rather than hypothetical.
    """
    mcp = build_server("binding-probe")

    async def _whoami_impl() -> str:
        principal = current_principal()
        return principal.subject if principal else "anonymous"

    register_tool(mcp, "whoami", guarded(_whoami_impl) if guard_handler else _whoami_impl)

    inner = build_app(mcp, stateless=stateless)
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


@pytest.mark.skipif(not IS_V1, reason="2.x dispatches each message in its own task and does not leak")
class TestTheLeakIsReal:
    """Without the per-message binding, SDK 1.x hands one caller another's identity.

    Kept as an executable statement of the bug, so `guarded` cannot quietly become a no-op on
    the generation where it is load-bearing. Skipped on 2.x, where the SDK fixed it upstream.
    """

    async def test_an_unguarded_handler_sees_the_session_opener(self, config, make_token):
        async with _client(config, stateless=False, guard_handler=False) as client:
            session_id = await _initialize(client, make_token(sub="user-a-sub"))

            assert await _whoami(client, make_token(sub="user-a-sub"), session_id) == "user-a-sub"
            # The bug, stated plainly: B asked, A answered.
            assert await _whoami(client, make_token(sub="user-b-sub"), session_id) == "user-a-sub"


class TestGuardedIsSafeOnBothGenerations:
    """`@guarded` must never make things worse than not using it.

    On 2.x there is no ambient per-message request to read, so a naive implementation binds
    `None` and blanks the caller the ASGI middleware already established correctly — every
    call then fails with `AuthenticationRequired`. Fails closed, but the server is bricked.
    The binding therefore only replaces what is bound when it has something better to put
    there.
    """

    async def test_a_guarded_handler_still_sees_its_caller(self, config, make_token):
        async with _client(config, stateless=False) as client:
            session_id = await _initialize(client, make_token(sub="user-a-sub"))
            assert await _whoami(client, make_token(sub="user-a-sub"), session_id) != "anonymous"

    def test_binding_without_a_request_preserves_the_existing_caller(self):
        from mcp_policy_guard.principal import Principal, set_principal
        from mcp_policy_guard.request import bind_request_principal

        someone = Principal(subject="already-bound", token="t")
        set_principal(someone)
        try:
            with bind_request_principal(None) as bound:
                assert bound is someone
                assert current_principal() is someone
        finally:
            set_principal(None)

    def test_binding_without_a_request_can_still_be_required(self):
        from mcp_policy_guard.errors import AuthenticationRequired
        from mcp_policy_guard.principal import set_principal
        from mcp_policy_guard.request import bind_request_principal

        set_principal(None)
        with pytest.raises(AuthenticationRequired):
            with bind_request_principal(None, required=True):
                pass
