"""The ASGI middleware, exercised as ASGI rather than through a web framework."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from mcp_policy_guard.config import DEFAULT_STALE_MAX_SECONDS, GuardConfig
from mcp_policy_guard.discovery import MAX_PEEK_BYTES
from mcp_policy_guard.errors import GuardConfigurationError
from mcp_policy_guard.middleware import GuardMiddleware
from mcp_policy_guard.principal import current_caller_id, current_correlation_id, current_principal


class RecordingApp:
    """Downstream app that records the context it was called in."""

    def __init__(self) -> None:
        self.calls = 0
        self.subject: str | None = None
        self.correlation_id: str | None = None
        self.caller_id: str | None = None

    async def __call__(self, scope, receive, send):
        self.calls += 1
        principal = current_principal()
        self.subject = principal.subject if principal else None
        self.correlation_id = current_correlation_id()
        self.caller_id = current_caller_id()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


class BodyRecordingApp(RecordingApp):
    """Also records the body as the wrapped app actually receives it.

    The guard has to consume an unauthenticated body to classify it, so "did the app still
    get the bytes" is the thing worth asserting, not merely "did it run".
    """

    def __init__(self) -> None:
        super().__init__()
        self.body = b""

    async def __call__(self, scope, receive, send):
        chunks: list[bytes] = []
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            chunks.append(message.get("body", b"") or b"")
            if not message.get("more_body", False):
                break
        self.body = b"".join(chunks)
        await super().__call__(scope, receive, send)


def rpc(method: str, **extra) -> bytes:
    """A JSON-RPC request body for `method`."""
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, **extra}).encode()


async def call(
    middleware,
    headers: dict[str, str] | None = None,
    path: str = "/mcp",
    method: str = "POST",
    body: bytes = b"",
    chunks: list[bytes] | None = None,
    tail: dict | None = None,
):
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
    }
    sent: list[dict] = []

    if chunks is None:
        pending = [{"type": "http.request", "body": body, "more_body": False}]
    else:
        pending = [{"type": "http.request", "body": c, "more_body": True} for c in chunks]
        pending[-1]["more_body"] = False

    async def receive():
        if pending:
            return pending.pop(0)
        return tail if tail is not None else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    await middleware(scope, receive, send)
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, body, sent


class TestEnforcing:
    async def test_rejects_a_request_with_no_token(self, config):
        app = RecordingApp()
        status, body, _ = await call(GuardMiddleware(app, config))
        assert status == 401
        assert json.loads(body)["error"] == "unauthorized"
        # The downstream app must never run: a tool that is reached and then denied has
        # already opened a database connection.
        assert app.calls == 0

    async def test_rejects_an_invalid_token(self, config):
        app = RecordingApp()
        status, _, _ = await call(GuardMiddleware(app, config), {"Authorization": "Bearer nonsense"})
        assert status == 401
        assert app.calls == 0

    async def test_advertises_bearer_auth_on_a_401(self, config):
        _, _, sent = await call(GuardMiddleware(RecordingApp(), config))
        headers = dict(next(m for m in sent if m["type"] == "http.response.start")["headers"])
        assert headers[b"www-authenticate"] == b'Bearer realm="mcp"'

    async def test_binds_the_principal_for_the_downstream_app(self, config, make_token):
        app = RecordingApp()
        status, _, _ = await call(GuardMiddleware(app, config), {"Authorization": f"Bearer {make_token()}"})
        assert status == 200
        assert app.subject == "user-a-sub"

    async def test_accepts_the_oauth2_proxy_forwarded_token(self, config, make_token):
        # On the public-ingress path oauth2-proxy consumes `Authorization` itself and
        # re-exposes the access token here.
        app = RecordingApp()
        status, _, _ = await call(GuardMiddleware(app, config), {"X-Auth-Request-Access-Token": make_token()})
        assert status == 200
        assert app.subject == "user-a-sub"

    async def test_ignores_a_non_bearer_authorization_scheme(self, config):
        status, _, _ = await call(GuardMiddleware(RecordingApp(), config), {"Authorization": "Basic dXNlcjpwYXNz"})
        assert status == 401

    async def test_binds_correlation_and_caller_ids(self, config, make_token):
        app = RecordingApp()
        await call(
            GuardMiddleware(app, config),
            {
                "Authorization": f"Bearer {make_token()}",
                "X-MCP-Correlation-Id": "corr-123",
                "X-MCP-Caller-Id": "agent-abc",
            },
        )
        assert app.correlation_id == "corr-123"
        assert app.caller_id == "agent-abc"


class TestHeaderNaming:
    """The header names are configurable, so a caller that already mints its own can be
    adopted without changing either side's code."""

    async def test_honours_configured_header_names(self, config, make_token):
        app = RecordingApp()
        renamed = replace(config, correlation_header="x-trace-id", caller_id_header="x-agent-id")
        await call(
            GuardMiddleware(app, renamed),
            {
                "Authorization": f"Bearer {make_token()}",
                "X-Trace-Id": "trace-1",
                "X-Agent-Id": "agent-1",
                # The defaults must no longer be consulted once an override is configured.
                "X-MCP-Correlation-Id": "ignored",
            },
        )
        assert app.correlation_id == "trace-1"
        assert app.caller_id == "agent-1"

    def test_lowercases_a_configured_header_name(self, monkeypatch):
        # ASGI hands header names down lowercased and the middleware looks them up that
        # way, so an override written in title case would silently never match.
        monkeypatch.delenv("MCP_REQUIRE_AUTH", raising=False)
        monkeypatch.setenv("MCP_CORRELATION_HEADER", "X-Trace-Id")
        monkeypatch.setenv("MCP_CALLER_ID_HEADER", "X-Agent-Id")
        resolved = GuardConfig.from_env()
        assert resolved.correlation_header == "x-trace-id"
        assert resolved.caller_id_header == "x-agent-id"

    async def test_a_mixed_case_override_still_matches(self, config, make_token, monkeypatch):
        monkeypatch.delenv("MCP_REQUIRE_AUTH", raising=False)
        monkeypatch.setenv("MCP_CORRELATION_HEADER", "X-Trace-Id")
        app = RecordingApp()
        renamed = replace(config, correlation_header=GuardConfig.from_env().correlation_header)
        await call(
            GuardMiddleware(app, renamed),
            {"Authorization": f"Bearer {make_token()}", "X-Trace-Id": "trace-2"},
        )
        assert app.correlation_id == "trace-2"

    def test_defaults_to_the_generic_header_names(self, monkeypatch):
        for key in ("MCP_REQUIRE_AUTH", "MCP_CORRELATION_HEADER", "MCP_CALLER_ID_HEADER"):
            monkeypatch.delenv(key, raising=False)
        resolved = GuardConfig.from_env()
        assert resolved.correlation_header == "x-mcp-correlation-id"
        assert resolved.caller_id_header == "x-mcp-caller-id"


class TestNotEnforcing:
    async def test_lets_an_anonymous_request_through(self, config):
        app = RecordingApp()
        status, _, _ = await call(GuardMiddleware(app, replace(config, require_auth=False)))
        assert status == 200
        assert app.calls == 1
        assert app.subject is None

    async def test_still_rejects_a_present_but_invalid_token(self, config):
        # A caller sending a token believes it is authenticated. Letting the call through
        # unattributed would file its actions under nobody, which is worse than a 401 —
        # the audit trail would show an anonymous read of the payroll table.
        app = RecordingApp()
        status, _, _ = await call(
            GuardMiddleware(app, replace(config, require_auth=False)),
            {"Authorization": "Bearer nonsense"},
        )
        assert status == 401
        assert app.calls == 0

    async def test_still_binds_a_valid_token(self, config, make_token):
        app = RecordingApp()
        await call(
            GuardMiddleware(app, replace(config, require_auth=False)),
            {"Authorization": f"Bearer {make_token()}"},
        )
        assert app.subject == "user-a-sub"


class TestNonHttpScopes:
    async def test_passes_lifespan_through(self, config):
        seen: list[str] = []

        async def app(scope, _receive, _send):
            seen.append(scope["type"])

        await GuardMiddleware(app, config)({"type": "lifespan"}, None, None)
        # Startup must not require a bearer token.
        assert seen == ["lifespan"]


class TestTransportPolicy:
    def test_sse_is_refused_whenever_auth_is_required(self):
        # The hole this closes: under SSE the connection that carried the token is not the
        # request that carries a tool call, so the principal cannot be attributed to the
        # call. Mounting it anyway leaves a second, unauthenticated door to the same tools.
        enforcing = GuardConfig(
            require_auth=True,
            issuer="https://idp.test/realms/demo",
            audience=None,
            tool_id=None,
            policy_url=None,
            fail_mode="closed",
            stale_max_seconds=DEFAULT_STALE_MAX_SECONDS,
            snapshot_ttl_seconds=30.0,
            timeout_seconds=5.0,
        )
        assert enforcing.sse_allowed is False
        assert replace(enforcing, require_auth=False).sse_allowed is True


class TestDiscoveryWithoutAToken:
    """The catalog is readable unauthenticated; nothing that returns data or acts is.

    A client that forwards its *caller's* bearer has none at startup, when discovery
    happens. Refusing the handshake does not protect the tools — `tools/call` is refused
    regardless — it just makes the server invisible to that client, permanently and
    silently.
    """

    async def test_allows_initialize(self, config):
        app = BodyRecordingApp()
        status, _, _ = await call(GuardMiddleware(app, config), body=rpc("initialize"))
        assert status == 200
        assert app.calls == 1

    async def test_allows_tools_list(self, config):
        app = BodyRecordingApp()
        status, _, _ = await call(GuardMiddleware(app, config), body=rpc("tools/list"))
        assert status == 200

    async def test_allows_resources_list(self, config):
        # The second half of a client's startup pass. Refusing it strands the client just as
        # completely as refusing `tools/list`.
        app = BodyRecordingApp()
        status, _, _ = await call(GuardMiddleware(app, config), body=rpc("resources/list"))
        assert status == 200

    async def test_refuses_a_tool_call(self, config):
        app = BodyRecordingApp()
        status, _, _ = await call(GuardMiddleware(app, config), body=rpc("tools/call"))
        assert status == 401
        assert app.calls == 0

    async def test_refuses_reading_a_resource(self, config):
        # `resources/list` returns names; `resources/read` returns content. Only the first is
        # a catalog.
        app = BodyRecordingApp()
        status, _, _ = await call(GuardMiddleware(app, config), body=rpc("resources/read"))
        assert status == 401
        assert app.calls == 0

    async def test_refuses_a_method_it_does_not_recognise(self, config):
        # The allow-list exists so that a method nobody considered is refused rather than
        # admitted. A future SDK adding `tools/execute` must not be open by default.
        app = BodyRecordingApp()
        status, _, _ = await call(GuardMiddleware(app, config), body=rpc("tools/execute"))
        assert status == 401
        assert app.calls == 0

    async def test_allows_a_batch_that_is_entirely_discovery(self, config):
        body = json.dumps(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            ]
        ).encode()
        status, _, _ = await call(GuardMiddleware(BodyRecordingApp(), config), body=body)
        assert status == 200

    async def test_refuses_a_batch_smuggling_a_tool_call(self, config):
        # JSON-RPC allows an array, so this is *one* HTTP request whose first message looks
        # harmless. A check that stopped at the first message would admit the second.
        app = BodyRecordingApp()
        body = json.dumps(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "mssql_query"}},
            ]
        ).encode()
        status, _, _ = await call(GuardMiddleware(app, config), body=body)
        assert status == 401
        assert app.calls == 0

    async def test_refuses_an_empty_batch(self, config):
        status, _, _ = await call(GuardMiddleware(BodyRecordingApp(), config), body=b"[]")
        assert status == 401

    @pytest.mark.parametrize("body", [b"", b"not json", b'{"no": "method"}', b'"a string"', b"null"])
    async def test_refuses_a_body_it_cannot_classify(self, config, body):
        status, _, _ = await call(GuardMiddleware(BodyRecordingApp(), config), body=body)
        assert status == 401

    async def test_refuses_a_body_over_the_peek_cap(self, config):
        # The request is unauthenticated, so there is nobody to hold responsible for making
        # the server buffer. Anything near the cap is not a discovery message anyway.
        app = BodyRecordingApp()
        status, _, _ = await call(
            GuardMiddleware(app, config),
            body=rpc("initialize", padding="x" * (MAX_PEEK_BYTES + 1)),
        )
        assert status == 401
        assert app.calls == 0

    async def test_replays_the_body_it_consumed(self, config):
        # The guard reads the body to classify it, and ASGI bodies are consumed once. If the
        # replay were wrong the handshake would hang or see an empty body.
        app = BodyRecordingApp()
        body = rpc("initialize")
        await call(GuardMiddleware(app, config), body=body)
        assert app.body == body

    async def test_replays_a_chunked_body_in_order(self, config):
        app = BodyRecordingApp()
        body = rpc("tools/list")
        third = len(body) // 3
        chunks = [body[:third], body[third : 2 * third], body[2 * third :]]
        status, _, _ = await call(GuardMiddleware(app, config), chunks=chunks)
        assert status == 200
        assert app.body == body

    async def test_delegates_to_the_real_receive_once_the_replay_is_drained(self, config):
        """The replay must not synthesise a disconnect when the buffer runs dry.

        The MCP SDK answers POST /mcp with an `EventSourceResponse`, which runs a disconnect
        listener in a task group alongside the task streaming the body, under
        `cancel_on_finish`. A synthetic `http.disconnect` after the buffer would cancel the
        response mid-flight and truncate the reply to every anonymous `initialize` — while
        looking like the guard refusing the request. Nothing else in this file would notice,
        which is exactly why this test exists.
        """
        seen: list[dict] = []

        class DrainingApp(RecordingApp):
            async def __call__(self, scope, receive, send):
                for _ in range(3):
                    seen.append(await receive())
                await super().__call__(scope, receive, send)

        sentinel = {"type": "http.request", "body": b"from-the-real-receive", "more_body": False}
        status, _, _ = await call(
            GuardMiddleware(DrainingApp(), config),
            body=rpc("initialize"),
            tail=sentinel,
        )
        assert status == 200
        assert seen[0]["body"] == rpc("initialize")
        # Past the buffer the app must reach the underlying receive, not a fabricated
        # disconnect.
        assert seen[1] is sentinel
        assert seen[2] is sentinel

    async def test_refuses_a_client_that_disconnects_mid_body(self, config):
        app = BodyRecordingApp()
        scope = {"type": "http", "method": "POST", "path": "/mcp", "headers": []}
        pending = [
            {"type": "http.request", "body": b'{"method":', "more_body": True},
            {"type": "http.disconnect"},
        ]
        sent: list[dict] = []

        async def receive():
            return pending.pop(0) if pending else {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)

        await GuardMiddleware(app, config)(scope, receive, send)
        assert next(m["status"] for m in sent if m["type"] == "http.response.start") == 401
        assert app.calls == 0

    @pytest.mark.parametrize("method", ["GET", "DELETE", "PUT"])
    async def test_refuses_every_method_but_post(self, config, method):
        # A GET attaches to the server->client stream of whatever session `Mcp-Session-Id`
        # names and a DELETE ends it, so admitting them anonymously would be a second,
        # unauthenticated door onto an *authenticated* caller's session. Refusing costs
        # discovery nothing: the SDK runs the GET stream as a background task whose errors
        # are swallowed, and tolerates any non-2xx on the DELETE.
        app = BodyRecordingApp()
        status, _, _ = await call(GuardMiddleware(app, config), method=method, body=rpc("initialize"))
        assert status == 401
        assert app.calls == 0

    async def test_refuses_a_declared_length_over_the_cap_without_reading_it(self, config):
        # Turned away on the header alone — an oversized anonymous body must not cost a read.
        app = BodyRecordingApp()
        status, _, _ = await call(
            GuardMiddleware(app, config),
            {"Content-Length": str(MAX_PEEK_BYTES + 1)},
            body=rpc("initialize"),
        )
        assert status == 401
        assert app.calls == 0

    async def test_leaves_the_principal_unset(self, config):
        # Discovery is a hole in *authentication* only. The downstream app must still see no
        # principal, so any handler reached this way fails every policy check.
        app = BodyRecordingApp()
        await call(GuardMiddleware(app, config), body=rpc("initialize"))
        assert app.subject is None

    async def test_still_refuses_a_present_but_invalid_token(self, config):
        # Unchanged: a caller that believes it is authenticated is never downgraded to
        # anonymous, discovery or not.
        app = BodyRecordingApp()
        status, _, _ = await call(
            GuardMiddleware(app, config),
            {"Authorization": "Bearer nonsense"},
            body=rpc("initialize"),
        )
        assert status == 401
        assert app.calls == 0

    async def test_honours_discovery_requires_auth(self, config):
        sealed = replace(config, discovery_requires_auth=True)
        app = BodyRecordingApp()
        status, _, _ = await call(GuardMiddleware(app, sealed), body=rpc("initialize"))
        assert status == 401
        assert app.calls == 0


def _enforcing(monkeypatch):
    """The minimum env for a config that is allowed to have a policy URL."""
    monkeypatch.setenv("MCP_REQUIRE_AUTH", "true")
    monkeypatch.setenv("MCP_AUTH_ISSUER", "https://idp.test/realms/demo")
    for key in ("MCP_POLICY_TTL_SECONDS", "MCP_POLICY_STALE_MAX_SECONDS"):
        monkeypatch.delenv(key, raising=False)


class TestConfigFromEnv:
    def test_refuses_to_start_enforcing_without_an_issuer(self, monkeypatch):
        # A guard that requires auth but cannot verify anything would accept every caller
        # while the operator believed it was on. Stop the process instead.
        monkeypatch.setenv("MCP_REQUIRE_AUTH", "true")
        monkeypatch.delenv("MCP_AUTH_ISSUER", raising=False)
        with pytest.raises(GuardConfigurationError):
            GuardConfig.from_env()

    def test_defaults_to_fail_closed(self, monkeypatch):
        for key in ("MCP_REQUIRE_AUTH", "MCP_AUTH_ISSUER", "MCP_POLICY_FAIL_MODE"):
            monkeypatch.delenv(key, raising=False)
        assert GuardConfig.from_env().fail_mode == "closed"

    def test_rejects_a_fail_mode_it_does_not_understand(self, monkeypatch):
        # Not "fall back to closed and warn": a typo in a security-relevant setting must be
        # loud, because the operator meant *something* by it.
        monkeypatch.delenv("MCP_REQUIRE_AUTH", raising=False)
        monkeypatch.setenv("MCP_POLICY_FAIL_MODE", "fail-safe")
        with pytest.raises(GuardConfigurationError):
            GuardConfig.from_env()

    def test_policy_is_disabled_unless_both_url_and_tool_id_are_present(self, monkeypatch):
        _enforcing(monkeypatch)
        monkeypatch.setenv("MCP_POLICY_URL", "http://backend/api/policy")
        monkeypatch.delenv("MCP_TOOL_ID", raising=False)
        assert GuardConfig.from_env().policy_enabled is False

    def test_strips_a_trailing_slash_from_the_policy_url(self, monkeypatch):
        _enforcing(monkeypatch)
        monkeypatch.setenv("MCP_POLICY_URL", "http://backend/api/policy/")
        monkeypatch.setenv("MCP_TOOL_ID", "tool-1")
        assert GuardConfig.from_env().policy_url == "http://backend/api/policy"

    def test_refuses_policy_without_authentication(self, monkeypatch):
        # Policy is evaluated per caller. With no verified caller there is nothing to decide
        # against, so every check would raise — the tool is either wholly broken or, if a
        # handler catches broadly, wholly open. Neither is what the operator asked for.
        monkeypatch.delenv("MCP_REQUIRE_AUTH", raising=False)
        monkeypatch.setenv("MCP_POLICY_URL", "http://backend/api/policy")
        monkeypatch.setenv("MCP_TOOL_ID", "tool-1")
        with pytest.raises(GuardConfigurationError) as excinfo:
            GuardConfig.from_env()
        # The message must name both variables: the operator has to know which to change.
        assert "MCP_POLICY_URL" in str(excinfo.value)
        assert "MCP_REQUIRE_AUTH" in str(excinfo.value)

    def test_discovery_is_open_by_default(self, monkeypatch):
        # The default is the whole point of the fix: an operator who never heard of this
        # variable must get a server their agents can still enumerate.
        _enforcing(monkeypatch)
        monkeypatch.delenv("MCP_DISCOVERY_REQUIRES_AUTH", raising=False)
        assert GuardConfig.from_env().discovery_requires_auth is False

    def test_discovery_can_be_sealed(self, monkeypatch):
        _enforcing(monkeypatch)
        monkeypatch.setenv("MCP_DISCOVERY_REQUIRES_AUTH", "true")
        assert GuardConfig.from_env().discovery_requires_auth is True

    def test_refuses_a_staleness_ceiling_below_the_revalidation_interval(self, monkeypatch):
        # Entries would expire before ever being refreshed: the guard fails closed on every
        # call after the first, and reads as a PDP outage that examining the PDP cannot
        # explain.
        _enforcing(monkeypatch)
        monkeypatch.setenv("MCP_POLICY_TTL_SECONDS", "300")
        monkeypatch.setenv("MCP_POLICY_STALE_MAX_SECONDS", "30")
        with pytest.raises(GuardConfigurationError):
            GuardConfig.from_env()
