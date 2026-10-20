"""The Guard facade: decisions, shadow mode, denials, and discovery filtering."""

from __future__ import annotations

from dataclasses import replace

import httpx
import pytest

from mcp_policy_guard import ViaHop
from mcp_policy_guard.errors import PolicyDenied, PolicyUnavailable
from mcp_policy_guard.policy import Guard, Resource, RowFilter, scope_notice
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


class TestRowFilters:
    """Predicates the caller must apply before returning rows.

    A tool that receives one and ignores it returns every row, and the result is
    indistinguishable from a correctly scoped one — so these paths matter more than their
    line count suggests.
    """

    def test_carries_the_predicate_off_an_allowed_resource(self, config):
        body = evaluate_body(
            resourceDecisions=[
                {
                    "resource": {"kind": "sql_table", "value": "dbo.perfevents"},
                    "effect": "allow",
                    "matchedRuleId": "rule-districts",
                    "filters": [{"column": "district", "operator": "in_", "values": ["D775"]}],
                }
            ]
        )
        g = guard(config, lambda request: httpx.Response(200, json=body))
        set_principal(USER_A)

        decision = g.evaluate("mssql_query", [Resource("sql_table", "dbo.perfevents")])

        assert len(decision.filters) == 1
        applied = decision.filters[0]
        assert (applied.column, applied.operator, applied.values) == ("district", "in_", ("D775",))
        assert applied.resource == Resource("sql_table", "dbo.perfevents")

    def test_never_reads_a_predicate_off_a_denial(self, config):
        # A denied resource yields no rows to narrow, and honouring a predicate on one would
        # be a way to turn a deny into a filtered allow.
        body = evaluate_body(
            decision="deny",
            effect="deny",
            resourceDecisions=[
                {
                    "resource": {"kind": "sql_table", "value": "dbo.payroll"},
                    "effect": "deny",
                    "matchedRuleId": "rule-payroll",
                    "filters": [{"column": "district", "operator": "in_", "values": ["D775"]}],
                }
            ],
        )
        g = guard(config, lambda request: httpx.Response(200, json=body))
        set_principal(USER_A)

        assert g.evaluate("mssql_query", [PAYROLL]).filters == ()

    def test_a_body_without_filters_yields_none(self, config):
        # An older platform, or simply a call nothing narrows. The tool must behave exactly as
        # it did before predicates existed.
        g = guard(config, lambda request: httpx.Response(200, json=evaluate_body()))
        set_principal(USER_A)

        assert g.evaluate("mssql_query", [ORDERS]).filters == ()

    def test_filters_for_selects_by_resource(self, config):
        body = evaluate_body(
            resourceDecisions=[
                {
                    "resource": {"kind": "sql_table", "value": "dbo.perfevents"},
                    "effect": "allow",
                    "matchedRuleId": "r1",
                    "filters": [{"column": "district", "operator": "in_", "values": ["D775"]}],
                },
                {
                    "resource": {"kind": "sql_table", "value": "dbo.orders"},
                    "effect": "allow",
                    "matchedRuleId": "r2",
                    "filters": [],
                },
            ]
        )
        g = guard(config, lambda request: httpx.Response(200, json=body))
        set_principal(USER_A)

        decision = g.evaluate("mssql_query", [Resource("sql_table", "dbo.perfevents"), ORDERS])

        assert len(decision.filters_for(Resource("sql_table", "dbo.perfevents"))) == 1
        assert decision.filters_for(ORDERS) == ()

    def test_predicates_survive_a_pdp_outage(self, config):
        # Without this, an unreachable PDP turns every scoped query into a full-table read —
        # the exact failure this layer exists to prevent, arriving through the fallback.
        snapshot = snapshot_body(
            resourceRules=[
                {
                    "kind": "sql_table",
                    "pattern": "dbo.perfevents",
                    "effect": "allow",
                    "ruleId": "rule-districts",
                    "filters": [
                        {
                            "pattern": "dbo.perfevents",
                            "column": "district",
                            "operator": "in_",
                            "values": ["D775"],
                        }
                    ],
                }
            ]
        )

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/snapshot"):
                return httpx.Response(200, json=snapshot)
            raise httpx.ConnectError("PDP down")

        g = guard(config, handler, policy_retries=0)
        set_principal(USER_A)

        decision = g.evaluate("mssql_query", [Resource("sql_table", "dbo.perfevents")])

        assert decision.allowed
        assert decision.filters[0].values == ("D775",)

    def test_an_outage_denial_carries_no_predicates(self, config):
        snapshot = snapshot_body(
            resourceRules=[{"kind": "sql_table", "pattern": "dbo.payroll", "effect": "deny", "ruleId": "rule-payroll"}]
        )

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/snapshot"):
                return httpx.Response(200, json=snapshot)
            raise httpx.ConnectError("PDP down")

        g = guard(config, handler, policy_retries=0)
        set_principal(USER_A)

        decision = g.evaluate("mssql_query", [PAYROLL])
        assert not decision.allowed
        assert decision.filters == ()


# ---------------------------------------------------------------------------
# scope_notice
# ---------------------------------------------------------------------------


def test_scope_notice_is_empty_when_nothing_narrows():
    """No filters means no notice — an unscoped result must not claim to be scoped."""
    assert scope_notice(()) == ""


def test_scope_notice_names_the_predicate_applied_to_this_caller():
    notice = scope_notice(
        (
            RowFilter(
                resource=Resource("sql_table", "dbo.tbdat_timesheet"),
                column="Employee_DistrictID",
                operator="in_",
                values=("155",),
            ),
        )
    )
    assert "dbo.tbdat_timesheet.Employee_DistrictID in (155)" in notice
    # The point of the notice: an empty result must not read as missing data.
    assert "your access rather than missing data" in notice


def test_scope_notice_joins_several_predicates():
    notice = scope_notice(
        (
            RowFilter(
                resource=Resource("sql_table", "dbo.tbdat_employees"),
                column="DistrictID",
                operator="in_",
                values=("155", "506"),
            ),
            RowFilter(
                resource=Resource("sql_table", "dbo.tbdat_timesheet"),
                column="Employee_DistrictID",
                operator="in_",
                values=("155",),
            ),
        )
    )
    assert "dbo.tbdat_employees.DistrictID in (155, 506)" in notice
    assert "dbo.tbdat_timesheet.Employee_DistrictID in (155)" in notice
    assert notice.count(";") == 1


# ---------------------------------------------------------------------------
# in_via
# ---------------------------------------------------------------------------

HOP_OPERATION = {"table": "public.t_operation", "key": "ope_id_operation", "column": "ope_id_agence"}
HOP_AGENCE = {"table": "public.t_agence", "key": "age_id_agence", "column": "age_code"}
OPU = Resource("sql_table", "public.tj_operation_utilisateur")


def via_body(raw_filter):
    return evaluate_body(
        resourceDecisions=[
            {
                "resource": {"kind": "sql_table", "value": "public.tj_operation_utilisateur"},
                "effect": "allow",
                "matchedRuleId": "r1",
                "filters": [raw_filter],
            }
        ]
    )


def in_via_filter(**overrides):
    raw = {
        "column": "opu_id_operation",
        "operator": "in_via",
        "values": ["775"],
        "via": [HOP_OPERATION, HOP_AGENCE],
    }
    raw.update(overrides)
    return {k: v for k, v in raw.items() if v is not None}


class TestInVia:
    def evaluate(self, config, raw_filter):
        g = guard(config, lambda request: httpx.Response(200, json=via_body(raw_filter)))
        set_principal(USER_A)
        return g.evaluate("postgres_query", [OPU])

    def test_filters_from_reads_in_via_path(self, config):
        decision = self.evaluate(config, in_via_filter())
        assert decision.filters[0].via == (
            ViaHop("public.t_operation", "ope_id_operation", "ope_id_agence"),
            ViaHop("public.t_agence", "age_id_agence", "age_code"),
        )
        assert decision.filters[0].operator == "in_via"
        assert decision.filters[0].values == ("775",)

    def test_in_via_without_path_is_unusable(self, config):
        with pytest.raises(PolicyUnavailable):
            self.evaluate(config, in_via_filter(via=None))

    @pytest.mark.parametrize(
        "via",
        [
            [],
            [HOP_OPERATION, HOP_AGENCE, HOP_OPERATION, HOP_AGENCE],
            None,
            "public.t_agence",
            [HOP_OPERATION, "x"],
            [{"table": "public.t_agence", "key": "age_id_agence"}],
            [{"table": "public.t_agence", "key": "", "column": "age_code"}],
            [{"table": "public.t_agence", "key": "k", "column": 3}],
        ],
        ids=["empty", "four-hops", "null", "string", "non-dict", "missing-field", "empty-field", "non-string"],
    )
    def test_in_via_with_a_bad_path_is_unusable(self, config, via):
        raw = in_via_filter()
        raw["via"] = via
        with pytest.raises(PolicyUnavailable):
            self.evaluate(config, raw)

    def test_in_via_with_four_hops_is_unusable(self, config):
        with pytest.raises(PolicyUnavailable):
            self.evaluate(config, in_via_filter(via=[HOP_OPERATION, HOP_AGENCE, HOP_OPERATION, HOP_AGENCE]))

    def test_via_on_other_operator_is_unusable(self, config):
        with pytest.raises(PolicyUnavailable):
            self.evaluate(config, in_via_filter(operator="in_"))

    def test_existing_filters_unchanged(self, config):
        decision = self.evaluate(config, in_via_filter(operator="in_", via=None))
        assert decision.filters[0].via == ()

    def test_snapshot_fallback_carries_the_path(self, config):
        snapshot = snapshot_body(
            resourceRules=[
                {
                    "kind": "sql_table",
                    "pattern": "public.tj_operation_utilisateur",
                    "effect": "allow",
                    "ruleId": "r1",
                    "filters": [{"pattern": "public.tj_operation_utilisateur", **in_via_filter()}],
                }
            ]
        )

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/snapshot"):
                return httpx.Response(200, json=snapshot)
            raise httpx.ConnectError("PDP down")

        g = guard(config, handler, policy_retries=0)
        set_principal(USER_A)
        decision = g.evaluate("postgres_query", [OPU])
        assert decision.allowed
        assert len(decision.filters[0].via) == 2

    def test_snapshot_fallback_never_allows_a_malformed_row(self, config):
        snapshot = snapshot_body(
            resourceRules=[
                {
                    "kind": "sql_table",
                    "pattern": "public.tj_operation_utilisateur",
                    "effect": "allow",
                    "ruleId": "r1",
                    "filters": [{"pattern": "public.tj_operation_utilisateur", **in_via_filter(via=None)}],
                }
            ]
        )

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/snapshot"):
                return httpx.Response(200, json=snapshot)
            raise httpx.ConnectError("PDP down")

        g = guard(config, handler, policy_retries=0)
        set_principal(USER_A)
        with pytest.raises(PolicyUnavailable):
            g.evaluate("postgres_query", [OPU])


def test_scope_notice_renders_chain():
    notice = scope_notice(
        (
            RowFilter(
                resource=OPU,
                column="opu_id_operation",
                operator="in_via",
                values=("775",),
                via=(
                    ViaHop("public.t_operation", "ope_id_operation", "ope_id_agence"),
                    ViaHop("public.t_agence", "age_id_agence", "age_code"),
                ),
            ),
        )
    )
    assert "tj_operation_utilisateur.opu_id_operation" in notice
    assert "public.t_agence.age_code" in notice
    assert "(775)" in notice
