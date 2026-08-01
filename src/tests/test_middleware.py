"""The ASGI middleware, exercised as ASGI rather than through a web framework."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from mcp_policy_guard.config import DEFAULT_STALE_MAX_SECONDS, GuardConfig
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


async def call(middleware, headers: dict[str, str] | None = None, path: str = "/mcp"):
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
    }
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

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

    def test_refuses_a_staleness_ceiling_below_the_revalidation_interval(self, monkeypatch):
        # Entries would expire before ever being refreshed: the guard fails closed on every
        # call after the first, and reads as a PDP outage that examining the PDP cannot
        # explain.
        _enforcing(monkeypatch)
        monkeypatch.setenv("MCP_POLICY_TTL_SECONDS", "300")
        monkeypatch.setenv("MCP_POLICY_STALE_MAX_SECONDS", "30")
        with pytest.raises(GuardConfigurationError):
            GuardConfig.from_env()
