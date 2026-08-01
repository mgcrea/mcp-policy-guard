"""The Guard facade: decisions, shadow mode, denials, and discovery filtering."""

from __future__ import annotations

from dataclasses import replace

import httpx
import pytest

from mcp_policy_guard.errors import PolicyDenied, PolicyUnavailable
from mcp_policy_guard.policy import Guard, Resource
from mcp_policy_guard.principal import Principal, set_principal

from .conftest import snapshot_body

USER_A = Principal(subject="user-a", token="token-a", groups=("/ops-sales",))

ORDERS = Resource("sql_table", "dbo.orders")
PAYROLL = Resource("sql_table", "dbo.payroll")


def evaluate_body(**overrides):
    body = {
        "decision": "allow",
        "effect": "allow",
        "enforcing": True,
        "policyVersion": 7,
        "matchedRuleId": "rule-sales",
        "reason": "all requested resources are granted",
        "resourceDecisions": [],
    }
    body.update(overrides)
    return body


def guard(config, handler, **overrides) -> Guard:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return Guard(replace(config, **overrides), client=client)


class TestEvaluate:
    def test_allows_a_permitted_call(self, config):
        decision = guard(config, lambda _r: httpx.Response(200, json=evaluate_body())).evaluate(
            "mssql_query", [ORDERS], principal=USER_A
        )
        assert decision.allowed is True
        assert decision.policy_version == 7

    def test_denies_and_reports_which_resource(self, config):
        body = evaluate_body(
            decision="deny",
            effect="deny",
            reason="rule rule-payroll denies sql_table dbo.payroll",
            matchedRuleId="rule-payroll",
            resourceDecisions=[
                {"resource": {"kind": "sql_table", "value": "dbo.orders"}, "effect": "allow"},
                {"resource": {"kind": "sql_table", "value": "dbo.payroll"}, "effect": "deny"},
            ],
        )
        decision = guard(config, lambda _r: httpx.Response(200, json=body)).evaluate(
            "mssql_query", [ORDERS, PAYROLL], principal=USER_A
        )
        assert decision.allowed is False
        # The PM's case: a join cannot launder access. Reading Orders alongside Payroll is
        # a Payroll read, and the whole call fails.
        assert decision.denied_resources == (PAYROLL,)

    def test_forwards_the_callers_token_not_a_server_credential(self, config):
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers["authorization"])
            return httpx.Response(200, json=evaluate_body())

        guard(config, handler).evaluate("mssql_query", [ORDERS], principal=USER_A)
        assert seen == ["Bearer token-a"]

    def test_sends_the_tool_id_and_resources(self, config):
        seen: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            import json

            seen.append(json.loads(request.content))
            return httpx.Response(200, json=evaluate_body())

        guard(config, handler).evaluate("mssql_query", [ORDERS, PAYROLL], principal=USER_A)
        assert seen[0]["tool"] == "tool-mssql"
        assert seen[0]["function"] == "mssql_query"
        assert seen[0]["resources"] == [
            {"kind": "sql_table", "value": "dbo.orders"},
            {"kind": "sql_table", "value": "dbo.payroll"},
        ]

    def test_shadow_mode_reports_the_real_decision_but_allows(self, config):
        body = evaluate_body(decision="deny", effect="allow", enforcing=False, reason="would deny")
        decision = guard(config, lambda _r: httpx.Response(200, json=body)).evaluate(
            "mssql_query", [PAYROLL], principal=USER_A
        )
        # This is what makes it safe to author rules against production traffic: the audit
        # log fills with what *would* have been blocked while nobody is blocked.
        assert decision.decision == "deny"
        assert decision.allowed is True
        assert decision.enforcing is False

    def test_behaves_as_before_policy_when_no_pdp_is_configured(self, config):
        def handler(_request: httpx.Request) -> httpx.Response:
            raise AssertionError("must not call the PDP when none is configured")

        decision = guard(config, handler, policy_url=None, tool_id=None).evaluate(
            "mssql_query", [PAYROLL], principal=USER_A
        )
        assert decision.allowed is True


class TestRequire:
    def test_raises_on_a_denial(self, config):
        body = evaluate_body(
            decision="deny",
            effect="deny",
            reason="rule rule-payroll denies sql_table dbo.payroll",
            resourceDecisions=[{"resource": {"kind": "sql_table", "value": "dbo.payroll"}, "effect": "deny"}],
        )
        with pytest.raises(PolicyDenied) as excinfo:
            guard(config, lambda _r: httpx.Response(200, json=body)).require("mssql_query", [PAYROLL], principal=USER_A)
        assert excinfo.value.resources == ("sql_table:dbo.payroll",)

    def test_returns_the_decision_when_allowed(self, config):
        decision = guard(config, lambda _r: httpx.Response(200, json=evaluate_body())).require(
            "mssql_query", [ORDERS], principal=USER_A
        )
        assert decision.allowed is True

    def test_reads_the_principal_from_the_context_when_not_given_one(self, config, make_token):
        from mcp_policy_guard.jwt_verify import verify_token

        set_principal(verify_token(make_token(), config))
        try:
            decision = guard(config, lambda _r: httpx.Response(200, json=evaluate_body())).require(
                "mssql_query", [ORDERS]
            )
            assert decision.allowed is True
        finally:
            set_principal(None)

    def test_a_pdp_404_is_a_denial_not_an_outage(self, config):
        # MCP_TOOL_ID naming no tool the backend knows cannot resolve to any project's
        # policy. Falling back to a cached snapshot would apply someone else's rules.
        with pytest.raises(PolicyDenied):
            guard(config, lambda _r: httpx.Response(404, json={"error": "Unknown tool"})).require(
                "mssql_query", [ORDERS], principal=USER_A
            )


class TestOutageFallback:
    def _handler(self, state):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/evaluate"):
                if state["evaluate_down"]:
                    raise httpx.ConnectError("evaluate unreachable")
                return httpx.Response(200, json=evaluate_body())
            if state["snapshot_down"]:
                raise httpx.ConnectError("snapshot unreachable")
            return httpx.Response(200, json=snapshot_body())

        return handler

    def test_falls_back_to_the_snapshot_when_evaluate_is_unreachable(self, config):
        state = {"evaluate_down": True, "snapshot_down": False}
        decision = guard(config, self._handler(state)).evaluate("mssql_query", [ORDERS], principal=USER_A)
        assert decision.allowed is True
        assert "PDP unreachable" in decision.reason

    def test_the_snapshot_fallback_still_denies(self, config):
        state = {"evaluate_down": True, "snapshot_down": False}
        decision = guard(config, self._handler(state)).evaluate("mssql_query", [PAYROLL], principal=USER_A)
        assert decision.allowed is False
        assert decision.denied_resources == (PAYROLL,)

    def test_the_join_rule_holds_on_the_fallback_path_too(self, config):
        # The semantics must not soften during an outage — that is exactly when someone
        # would notice they can suddenly read more.
        state = {"evaluate_down": True, "snapshot_down": False}
        decision = guard(config, self._handler(state)).evaluate("mssql_query", [ORDERS, PAYROLL], principal=USER_A)
        assert decision.allowed is False

    def test_fails_closed_when_both_are_unreachable(self, config):
        state = {"evaluate_down": True, "snapshot_down": True}
        with pytest.raises(PolicyUnavailable):
            guard(config, self._handler(state)).require("mssql_query", [ORDERS], principal=USER_A)

    def test_policy_unavailable_is_caught_by_except_policy_denied(self, config):
        # Deliberate subclassing: a tool handler that only remembered to handle denials
        # still handles the outage, instead of leaking a stack trace to the model.
        state = {"evaluate_down": True, "snapshot_down": True}
        with pytest.raises(PolicyDenied):
            guard(config, self._handler(state)).require("mssql_query", [ORDERS], principal=USER_A)


class TestDiscoveryFiltering:
    def test_hides_denied_names_rather_than_refusing(self, config):
        visible = guard(config, lambda _r: httpx.Response(200, json=snapshot_body())).filter_resources(
            "sql_table",
            ["dbo.orders", "dbo.orders_2024", "dbo.payroll", "dbo.unknown"],
            function_name="mssql_list_tables",
            principal=USER_A,
        )
        # No count, no placeholder, no "3 hidden" — a denied name must not be inferable
        # from the response at all.
        assert visible == ["dbo.orders", "dbo.orders_2024"]

    def test_returns_everything_in_shadow_mode(self, config):
        visible = guard(config, lambda _r: httpx.Response(200, json=snapshot_body(enforcing=False))).filter_resources(
            "sql_table", ["dbo.orders", "dbo.payroll"], function_name="mssql_list_tables", principal=USER_A
        )
        assert visible == ["dbo.orders", "dbo.payroll"]

    def test_can_filter_rows_via_a_key(self, config):
        rows = [("Orders", 100), ("Payroll", 5)]
        visible = guard(config, lambda _r: httpx.Response(200, json=snapshot_body())).filter_resources(
            "sql_table",
            rows,
            function_name="mssql_list_tables",
            principal=USER_A,
            key=lambda row: f"dbo.{row[0].lower()}",
        )
        assert visible == [("Orders", 100)]
