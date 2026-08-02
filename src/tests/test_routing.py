"""The route list: its ordering invariant, and the transport options it forwards.

Two things are pinned here. The first is ordering — SSE ahead of the `Mount("/")` catch-all,
`extra_routes` ahead of both — because Starlette returns on the first `Match.FULL` and a list
built in the wrong order fails silently rather than loudly.

The second is that `routes()` builds the SDK's apps, so it decides what they are built with.
On 1.x that decision was inert: transport options came off the server constructor and the
builders read them from `settings`. On 2.x the constructor lost them, so building bare pins
`host` to `127.0.0.1` and the server answers `421` to every request that reaches it under a
real hostname. The last test drives that over the wire, because a mock cannot tell you
whether a Host header is actually accepted.
"""

from __future__ import annotations

import contextlib
from dataclasses import replace
from typing import Any

import httpx
import pytest
from starlette.applications import Starlette
from starlette.routing import Mount, Route

from mcp_policy_guard.middleware import GuardMiddleware
from mcp_policy_guard.routing import routes

from ._mcp_compat import IS_V1, PROTOCOL_VERSION, build_server, register_tool


class FakeServer:
    """Records what the app builders were handed, and nothing else.

    `routes()` types its server `Any` and only ever calls these two methods, so this is the
    whole contract — which is what lets one test run unchanged on both SDK generations.
    """

    def __init__(self) -> None:
        self.app_kwargs: dict[str, Any] | None = None
        self.sse_app_kwargs: dict[str, Any] | None = None

    async def _app(self, scope, receive, send):  # pragma: no cover - never dispatched
        raise AssertionError("the fake app should not be called")

    def streamable_http_app(self, **kwargs: Any):
        self.app_kwargs = kwargs
        return self._app

    def sse_app(self, **kwargs: Any):
        self.sse_app_kwargs = kwargs
        return self._app


@pytest.fixture
def permissive(config):
    """A config that allows SSE — i.e. `MCP_REQUIRE_AUTH` off."""
    return replace(config, require_auth=False)


class TestOrdering:
    def test_sse_is_mounted_before_the_catch_all(self, permissive):
        built = routes(FakeServer(), permissive)

        # Reversed, `Mount("/")` would match /sse first and SSE would be dead code.
        assert [type(r) for r in built] == [Mount, Mount]
        assert built[0].path == "/sse"
        assert built[1].path == ""  # Starlette normalises the catch-all "/" to ""

    def test_extra_routes_come_first_and_stay_unguarded(self, permissive):
        async def healthz(request):  # pragma: no cover - never dispatched
            raise AssertionError

        probe = Route("/healthz", healthz)
        built = routes(FakeServer(), permissive, extra_routes=[probe])

        assert built[0] is probe  # forwarded untouched: a kubelet must not need a token
        assert isinstance(built[-1].app, GuardMiddleware)

    def test_sse_path_is_configurable(self, permissive):
        built = routes(FakeServer(), permissive, sse_path="/events")

        assert built[0].path == "/events"

    def test_sse_is_absent_when_auth_is_required(self, config):
        built = routes(FakeServer(), config)

        assert len(built) == 1
        assert isinstance(built[0].app, GuardMiddleware)


class TestTransportOptions:
    def test_nothing_is_invented_when_no_kwargs_are_given(self, permissive):
        server = FakeServer()

        routes(server, permissive)

        # Bare on purpose: on 1.x the constructor already configured the server, and
        # inventing a default here would silently override it.
        assert server.app_kwargs == {}
        assert server.sse_app_kwargs == {}

    def test_kwargs_reach_the_builders_verbatim(self, permissive):
        server = FakeServer()
        security = object()  # opaque to this package — it never inspects the value

        routes(
            server,
            permissive,
            app_kwargs={"transport_security": security, "streamable_http_path": "/mcp"},
            sse_app_kwargs={"message_path": "/messages/"},
        )

        assert server.app_kwargs == {"transport_security": security, "streamable_http_path": "/mcp"}
        assert server.sse_app_kwargs == {"message_path": "/messages/"}

    def test_the_two_kwarg_sets_do_not_bleed_into_each_other(self, permissive):
        server = FakeServer()

        routes(server, permissive, app_kwargs={"json_response": True})

        assert server.sse_app_kwargs == {}  # sse_app() has no json_response to accept


class TestLocalhostWarning:
    """The 2.x default is a trap, so it gets said out loud — and only then."""

    def _warnings(self, records) -> list[dict[str, Any]]:
        return [r for r in records if r["event"] == "transport_defaults_to_localhost"]

    @pytest.mark.skipif(IS_V1, reason="1.x takes transport options on the constructor")
    def test_warns_when_transport_is_left_at_the_default(self, permissive, captured_audit):
        routes(FakeServer(), permissive)

        assert len(self._warnings(captured_audit)) == 1

    @pytest.mark.skipif(IS_V1, reason="1.x takes transport options on the constructor")
    @pytest.mark.parametrize("kwargs", [{"transport_security": object()}, {"host": "0.0.0.0"}])
    def test_silent_once_the_caller_has_decided(self, permissive, captured_audit, kwargs):
        routes(FakeServer(), permissive, app_kwargs=kwargs)

        assert self._warnings(captured_audit) == []

    @pytest.mark.skipif(not IS_V1, reason="the trap does not exist on 1.x")
    def test_never_warns_on_1x(self, permissive, captured_audit):
        routes(FakeServer(), permissive)

        assert self._warnings(captured_audit) == []


@contextlib.asynccontextmanager
async def _serve(config, **kwargs: Any):
    """A real MCP server behind the real route list, driven over the real wire."""
    mcp = build_server("routing-probe")
    app = Starlette(routes=routes(mcp, config, **kwargs))

    # The app whose lifespan starts the session manager is the one `routes()` built, and the
    # only handle on it is the mount it was placed in — Starlette does not run the lifespan
    # of a mounted sub-application.
    inner = app.routes[-1].app.app
    async with inner.router.lifespan_context(inner):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://probe.test") as client:
            yield client


async def _initialize(client: httpx.AsyncClient, host: str) -> httpx.Response:
    return await client.post(
        "/mcp",
        headers={
            "Host": host,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "routing-probe", "version": "1"},
            },
        },
    )


@contextlib.asynccontextmanager
async def _serve_enforcing(config):
    """A real enforcing server, driven over the wire, on the **SSE** response path.

    Deliberately does not set `json_response`: `EventSourceResponse` is what the SDK returns
    from `POST /mcp` by default, and it is the only path that runs a disconnect listener
    concurrently with the body. A replay that fabricated an `http.disconnect` once its
    buffer drained would cancel that response mid-flight, and every unit test in
    `test_middleware.py` would still pass. This is the one that would not.
    """
    from mcp.server.transport_security import TransportSecuritySettings

    security = TransportSecuritySettings(enable_dns_rebinding_protection=False)

    mcp = build_server("discovery-probe")

    def probe_tool() -> str:
        return "ok"

    register_tool(mcp, "probe_tool", probe_tool)

    if IS_V1:
        mcp.settings.transport_security = security
        app = Starlette(routes=routes(mcp, config))
    else:
        app = Starlette(routes=routes(mcp, config, app_kwargs={"transport_security": security}))

    inner = app.routes[-1].app.app
    async with inner.router.lifespan_context(inner):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://probe.test") as client:
            yield client


_MCP_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


class TestAnonymousDiscoveryEndToEnd:
    """The handshake an agent runtime actually performs, with no bearer, against a real server.

    Worth more than the unit tests: it is the only thing here that exercises the SDK's own
    response machinery, which is where a plausible-looking replay goes wrong.
    """

    async def test_completes_the_handshake_and_lists_tools(self, config):
        async with _serve_enforcing(config) as client:
            initialize = await client.post(
                "/mcp",
                headers=_MCP_HEADERS,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "discovery-probe", "version": "1"},
                    },
                },
            )
            assert initialize.status_code == 200
            # Non-empty is the assertion that matters: a cancelled EventSourceResponse
            # returns 200 with nothing in it.
            assert initialize.text.strip()
            assert "protocolVersion" in initialize.text

            session_id = initialize.headers.get("mcp-session-id")
            session_headers = {**_MCP_HEADERS}
            if session_id:
                session_headers["mcp-session-id"] = session_id

            initialized = await client.post(
                "/mcp",
                headers=session_headers,
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            )
            assert initialized.status_code == 202

            listed = await client.post(
                "/mcp",
                headers=session_headers,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            )
            assert listed.status_code == 200
            assert "probe_tool" in listed.text

    async def test_still_refuses_the_tool_call_that_discovery_advertised(self, config):
        async with _serve_enforcing(config) as client:
            response = await client.post(
                "/mcp",
                headers=_MCP_HEADERS,
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "probe_tool"}},
            )
        assert response.status_code == 401

    async def test_still_refuses_a_batch_smuggling_a_tool_call(self, config):
        async with _serve_enforcing(config) as client:
            response = await client.post(
                "/mcp",
                headers=_MCP_HEADERS,
                json=[
                    {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "probe_tool"}},
                ],
            )
        assert response.status_code == 401

    async def test_still_refuses_an_anonymous_stream_attach(self, config):
        async with _serve_enforcing(config) as client:
            response = await client.get("/mcp", headers=_MCP_HEADERS)
        assert response.status_code == 401


@pytest.mark.skipif(IS_V1, reason="only 2.x moved transport options onto the app builders")
class TestHostHeaderOnSdk2:
    """The regression this whole change exists for, asserted end to end.

    Without the pass-through there is no argument a caller can supply that changes either
    outcome — which is the difference between an awkward API and a broken one.
    """

    async def test_ingress_hostname_is_refused_by_the_bare_defaults(self, permissive):
        async with _serve(permissive) as client:
            response = await _initialize(client, "mcp.example.com")

        assert response.status_code == 421
        assert "Invalid Host header" in response.text

    async def test_ingress_hostname_is_served_once_settings_are_passed(self, permissive):
        from mcp.server.transport_security import TransportSecuritySettings

        security = TransportSecuritySettings(enable_dns_rebinding_protection=False)

        async with _serve(permissive, app_kwargs={"transport_security": security}) as client:
            response = await _initialize(client, "mcp.example.com")

        assert response.status_code == 200
