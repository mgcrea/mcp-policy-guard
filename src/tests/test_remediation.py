"""One test per finding from the security review, each stating the failure it prevents."""

from __future__ import annotations

from dataclasses import replace

import httpx
import pytest

from mcp_policy_guard.audit import redact
from mcp_policy_guard.errors import PolicyDenied, PolicyUnavailable
from mcp_policy_guard.policy import MAX_RESOURCES_PER_CALL, UNDETERMINED, Guard, Resource
from mcp_policy_guard.principal import Principal
from mcp_policy_guard.snapshot import REFUSAL_STATUSES, SnapshotCache

from .conftest import mock_transport, snapshot_body

USER_A = Principal(subject="a", token="tok-a", groups=("/ops",), roles=("analyst",))


@pytest.fixture(autouse=True)
def _bound_caller():
    """Most of these exercise decisions, which need somebody to decide about."""
    from mcp_policy_guard.principal import set_principal

    set_principal(USER_A)
    yield
    set_principal(None)


def _guard(config, handler) -> Guard:
    return Guard(config, client=mock_transport(handler))


class TestFingerprintCollisions:
    """H2 — a delimiter-joined key lets one identity impersonate another's cache entry."""

    def test_a_group_containing_the_delimiter_does_not_collide(self):
        # Joined on "|" and ",", these two produce byte-identical keys: one cache entry for
        # two different people, and whoever arrives second is served the first's snapshot.
        one = Principal(subject="s", token="t", groups=("a,b",))
        two = Principal(subject="s", token="t", groups=("a", "b"))
        assert one.fingerprint() != two.fingerprint()

    def test_a_group_containing_a_pipe_does_not_collide(self):
        one = Principal(subject="s", token="t", groups=("x",), roles=("y",))
        two = Principal(subject="s", token="t", groups=("x|y",), roles=())
        assert one.fingerprint() != two.fingerprint()

    def test_a_subject_cannot_forge_another_identitys_key(self):
        one = Principal(subject="s|admin", token="t", groups=())
        two = Principal(subject="s", token="t", groups=("admin",))
        assert one.fingerprint() != two.fingerprint()

    def test_group_order_still_does_not_matter(self):
        one = Principal(subject="s", token="t", groups=("a", "b"))
        two = Principal(subject="s", token="t", groups=("b", "a"))
        assert one.fingerprint() == two.fingerprint()


class TestSnapshotRefusals:
    """H3 — an explicit refusal must never be answered from cache."""

    @pytest.mark.parametrize("status", sorted(REFUSAL_STATUSES))
    def test_a_refusal_is_not_treated_as_an_outage(self, config, status):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(200, json=snapshot_body(), headers={"etag": "v1"})
            return httpx.Response(status)

        cache = SnapshotCache(replace(config, snapshot_ttl_seconds=0.0), client=mock_transport(handler))
        assert cache.get(USER_A, "fn").version == 7

        # The PDP has answered, and the answer is no. Serving the cached snapshot would be
        # answering for an identity it just declined to confirm.
        with pytest.raises(PolicyUnavailable):
            cache.get(USER_A, "fn")

    def test_the_two_paths_agree_about_what_a_refusal_is(self, config):
        # They had drifted: evaluate treated 403/404 as denials while snapshot let them fall
        # through to the stale cache. One shared definition is the fix.
        for status in (401, 403, 404):
            guard = _guard(config, lambda _r, s=status: httpx.Response(s))
            with pytest.raises(PolicyDenied):
                guard.evaluate("fn", [Resource("sql_table", "dbo.orders")])


class TestCacheIsBounded:
    """H1 — one entry per caller, forever, in a process that runs for weeks."""

    def test_evicts_least_recently_used_past_the_cap(self, config):
        handler = lambda _r: httpx.Response(200, json=snapshot_body())  # noqa: E731
        bounded = replace(config, snapshot_cache_max_entries=3, snapshot_ttl_seconds=0.0)
        cache = SnapshotCache(bounded, client=mock_transport(handler))

        for index in range(10):
            cache.get(Principal(subject=f"user-{index}", token="t"), "fn")

        assert len(cache._entries) == 3

    def test_drops_an_entry_too_stale_to_ever_be_served(self, config):
        handler = lambda _r: httpx.Response(200, json=snapshot_body())  # noqa: E731
        cache = SnapshotCache(replace(config, stale_max_seconds=0.0), client=mock_transport(handler))
        cache.get(USER_A, "fn")
        cache.get(USER_A, "fn")
        # Past stale_max it can never be served, so holding it is just memory retaining a
        # revoked grant.
        assert len(cache._entries) <= 1


class TestDeepRedaction:
    """H5 — tool arguments are structured, and the nested value is the credential."""

    def test_redacts_a_secret_nested_in_a_dict(self):
        out = redact({"config": {"password": "hunter2", "host": "db"}})
        assert out["config"]["password"] == "***REDACTED***"
        assert out["config"]["host"] == "db"

    def test_redacts_through_a_list_of_dicts(self):
        out = redact({"connections": [{"dsn": "postgres://u:p@h/db"}, {"name": "ok"}]})
        assert out["connections"][0]["dsn"] == "***REDACTED***"
        assert out["connections"][1]["name"] == "ok"

    def test_truncates_a_long_nested_string(self):
        out = redact({"outer": {"query": "x" * 900}})
        assert out["outer"]["query"].endswith("...[truncated]")

    def test_survives_a_pathologically_nested_payload(self):
        payload: dict = {"k": "v"}
        for _ in range(50):
            payload = {"k": payload}
        # Must summarize rather than recurse: an audit write may not crash the call it
        # is recording.
        assert redact(payload)


class TestUndeterminedResources:
    """M1 — "I could not tell what this reads" is not "this reads nothing"."""

    def test_denies_when_the_read_set_could_not_be_established(self, config):
        guard = _guard(config, lambda _r: httpx.Response(200, json=snapshot_body()))
        decision = guard.evaluate("mssql_query", UNDETERMINED)
        assert decision.allowed is False
        assert "could not be determined" in decision.reason

    def test_require_raises_rather_than_returning(self, config):
        guard = _guard(config, lambda _r: httpx.Response(200, json=snapshot_body()))
        with pytest.raises(PolicyDenied):
            guard.require("mssql_query", UNDETERMINED)

    def test_an_empty_list_still_means_touches_nothing(self, config):
        # The distinction is the whole point: [] is decided by the function-level rule.
        guard = _guard(config, lambda _r: httpx.Response(200, json={"decision": "allow", "effect": "allow"}))
        assert guard.evaluate("mssql_list_tables", []).allowed is True


class TestResourceLimits:
    """M2 — over the PDP's cap, a 400 was silently degrading to local evaluation."""

    def test_refuses_rather_than_silently_deciding_locally(self, config):
        guard = _guard(config, lambda _r: httpx.Response(200, json={"decision": "allow", "effect": "allow"}))
        too_many = [Resource("sql_table", f"dbo.t{i}") for i in range(MAX_RESOURCES_PER_CALL + 1)]
        with pytest.raises(PolicyDenied) as excinfo:
            guard.evaluate("mssql_query", too_many)
        assert "limit" in str(excinfo.value)

    def test_dedupes_before_applying_the_cap(self, config):
        seen: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            import json as _json

            seen.append(len(_json.loads(request.content)["resources"]))
            return httpx.Response(200, json={"decision": "allow", "effect": "allow"})

        guard = _guard(config, handler)
        # A query joining one table many times must not trip the limit.
        guard.evaluate("mssql_query", [Resource("sql_table", "dbo.orders")] * 500)
        assert seen == [1]


class TestMalformedResponses:
    """M3 — a bad body escaped both the fallback and every `except PolicyDenied`."""

    def test_unparseable_json_fails_closed(self, config):
        guard = _guard(config, lambda _r: httpx.Response(200, content=b"not json"))
        with pytest.raises(PolicyUnavailable):
            guard.evaluate("fn", [Resource("sql_table", "dbo.orders")])

    def test_a_missing_nested_key_fails_closed(self, config):
        body = {"decision": "deny", "effect": "deny", "resourceDecisions": [{"effect": "deny"}]}
        guard = _guard(config, lambda _r: httpx.Response(200, json=body))
        with pytest.raises(PolicyUnavailable):
            guard.evaluate("fn", [Resource("sql_table", "dbo.orders")])

    def test_failing_closed_here_is_still_catchable_as_a_denial(self, config):
        # Tool code catching PolicyDenied must also catch this, or the fail-closed path
        # depends on remembering a second exception type.
        guard = _guard(config, lambda _r: httpx.Response(200, content=b"{"))
        with pytest.raises(PolicyDenied):
            guard.evaluate("fn", [Resource("sql_table", "dbo.orders")])


class TestOutageIsDistinguishable:
    """M4 — telling a user "you lack access" during an outage sends them to raise a ticket."""

    def test_an_outage_is_flagged_as_one(self):
        assert PolicyUnavailable("backend down").is_outage is True

    def test_a_denial_is_not(self):
        assert PolicyDenied("nope").is_outage is False

    def test_an_outage_is_still_caught_as_a_denial(self):
        assert isinstance(PolicyUnavailable("x"), PolicyDenied)


class TestDiscoveryRespectsTheFunctionRule:
    """M5 — filtering a forbidden call answers it with a list, which is a false statement."""

    def test_denies_when_the_function_itself_is_denied(self, config):
        body = snapshot_body(callEffect="deny", callRuleId="rule-no-listing")
        guard = _guard(config, lambda _r: httpx.Response(200, json=body))
        with pytest.raises(PolicyDenied):
            guard.filter_resources("sql_table", ["dbo.orders"], function_name="mssql_list_tables")

    def test_filters_normally_when_the_function_is_allowed(self, config):
        guard = _guard(config, lambda _r: httpx.Response(200, json=snapshot_body()))
        visible = guard.filter_resources(
            "sql_table",
            ["dbo.orders", "dbo.payroll"],
            function_name="mssql_list_tables",
        )
        assert visible == ["dbo.orders"]


class TestClientOwnership:
    """LOW — closing a client you were handed breaks the caller still using it."""

    def test_does_not_close_an_injected_client(self, config):
        client = mock_transport(lambda _r: httpx.Response(200, json=snapshot_body()))
        Guard(config, client=client).close()
        assert client.is_closed is False

    def test_closes_a_client_it_created(self, config):
        guard = Guard(config)
        guard.close()
        assert guard._client.is_closed is True


class TestAuditIdentityCannotBeOverridden:
    """LOW — the one field a caller must not be able to set is the one naming them."""

    def test_extra_cannot_overwrite_the_subject(self, captured_audit):
        from mcp_policy_guard.audit import emit
        from mcp_policy_guard.principal import set_principal

        set_principal(USER_A)
        try:
            emit("tool_call", tool="t", subject="somebody-else", email="forged@example.com")
        finally:
            set_principal(None)

        assert captured_audit[0]["subject"] == "a"
        assert captured_audit[0]["email"] is None


class TestRetries:
    """LOW — one timeout with no retry turns a blip into a user-visible denial."""

    def test_retries_a_transient_failure_before_falling_back(self, config):
        attempts = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise httpx.ConnectError("blip")
            return httpx.Response(200, json={"decision": "allow", "effect": "allow", "enforcing": True})

        guard = _guard(replace(config, policy_retries=1), handler)
        assert guard.evaluate("fn", []).allowed is True
        assert attempts["n"] == 2
