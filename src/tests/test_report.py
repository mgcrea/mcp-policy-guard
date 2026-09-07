"""Reporting a call that failed before policy could decide it.

The behaviour under test is mostly *absence of behaviour*: this runs on a path that is
already failing, so nothing it does may raise, retry, or turn into a denial.
"""

from __future__ import annotations

from dataclasses import replace

import httpx

from mcp_policy_guard.errors import PolicyDenied, PolicyNotEvaluated
from mcp_policy_guard.policy import Guard, Resource
from mcp_policy_guard.principal import Principal

USER_A = Principal(subject="user-a", token="token-a", groups=("/ops-sales",))
ORDERS = Resource("sql_table", "dbo.orders")


def guard(config, handler, **overrides) -> Guard:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return Guard(replace(config, **overrides), client=client)


class TestReportNotEvaluated:
    def test_posts_the_reason_to_the_report_route(self, config):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["body"] = request.read().decode()
            seen["user_agent"] = request.headers.get("user-agent")
            seen["auth"] = request.headers.get("authorization")
            return httpx.Response(204)

        guard(config, handler).report_not_evaluated("mssql_query", "Login failed for user 'svc'", principal=USER_A)

        assert seen["url"].endswith("/report")
        assert "Login failed" in seen["body"]
        assert seen["auth"] == "Bearer token-a"

    # The platform reads the guard version out of this header. A tool whose FIRST contact is a
    # report would otherwise keep a null version, which `guardSupportsRowFilters` reads as
    # "cannot apply predicates" — so its row-scoped resources get denied rather than narrowed.
    def test_sends_the_user_agent_so_the_heartbeat_learns_the_version(self, config):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["user_agent"] = request.headers.get("user-agent")
            return httpx.Response(204)

        guard(config, handler).report_not_evaluated("mssql_query", "unreachable", principal=USER_A)

        assert seen["user_agent"].startswith("mcp-policy-guard/")

    # A platform too old to serve this route answers 404. Routed through `raise_if_refused`
    # that becomes `PolicyUnavailable`, which IS a `PolicyDenied` — turning a reportable
    # failure into a denial, for a call that had already failed for another reason.
    def test_a_404_from_an_older_platform_does_not_become_a_denial(self, config):
        try:
            guard(config, lambda _r: httpx.Response(404)).report_not_evaluated(
                "mssql_query", "unreachable", principal=USER_A
            )
        except PolicyDenied as exc:  # pragma: no cover - the assertion is the point
            raise AssertionError(f"reporting raised a denial: {exc}") from exc

    def test_a_transport_failure_is_swallowed(self, config):
        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route to host")

        # The original failure is what the caller must see; a reporting bug must not replace it.
        guard(config, handler).report_not_evaluated("mssql_query", "unreachable", principal=USER_A)

    def test_it_does_not_retry(self, config):
        calls = {"n": 0}

        def handler(_request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            raise httpx.ConnectError("no route to host")

        guard(config, handler).report_not_evaluated("mssql_query", "unreachable", principal=USER_A)

        assert calls["n"] == 1

    def test_is_a_no_op_when_no_policy_endpoint_is_configured(self, config):
        def handler(_request: httpx.Request) -> httpx.Response:  # pragma: no cover
            raise AssertionError("should not have been called")

        guard(config, handler, policy_url=None).report_not_evaluated("mssql_query", "unreachable", principal=USER_A)

    def test_truncates_a_long_reason(self, config):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["body"] = request.read().decode()
            return httpx.Response(204)

        guard(config, handler).report_not_evaluated("mssql_query", "x" * 5000, principal=USER_A)

        assert seen["body"].count("x") == 500

    def test_sends_resources_when_the_guard_got_that_far(self, config):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["body"] = request.read().decode()
            return httpx.Response(204)

        guard(config, handler).report_not_evaluated("mssql_query", "unreachable", [ORDERS], principal=USER_A)

        assert "dbo.orders" in seen["body"]


class TestPolicyNotEvaluatedException:
    # `PolicyUnavailable` subclasses `PolicyDenied` so a tool's fail-closed path cannot be
    # forgotten. This one must NOT, because every `except PolicyDenied` in tool code words its
    # message as an access decision — which is the confusion being fixed.
    def test_is_not_a_policy_denial(self):
        assert not issubclass(PolicyNotEvaluated, PolicyDenied)

    def test_carries_its_reason(self):
        assert PolicyNotEvaluated("database unreachable").reason == "database unreachable"


class TestPrincipalResolution:
    # Nothing to report as, and nothing the platform could attribute the row to — it
    # authenticates this route with the caller's own forwarded token.
    def test_is_a_no_op_with_no_principal_in_context(self, config):
        def handler(_request: httpx.Request) -> httpx.Response:  # pragma: no cover
            raise AssertionError("should not have been called")

        guard(config, handler).report_not_evaluated("mssql_query", "unreachable")
