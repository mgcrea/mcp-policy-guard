"""Snapshot caching, revalidation, and the fail-closed boundary."""

from __future__ import annotations

from dataclasses import replace

import httpx
import pytest

from mcp_policy_guard.errors import PolicyUnavailable
from mcp_policy_guard.principal import Principal
from mcp_policy_guard.snapshot import PolicySnapshot, SnapshotCache

from .conftest import snapshot_body

USER_A = Principal(subject="user-a", token="token-a", groups=("/ops-sales",))
USER_B = Principal(subject="user-b", token="token-b", groups=("/ops-payroll",))


def cache(config, handler, **overrides) -> SnapshotCache:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return SnapshotCache(replace(config, **overrides), client=client)


class TestFetching:
    def test_fetches_and_parses_a_snapshot(self, config):
        cached = cache(config, lambda _r: httpx.Response(200, json=snapshot_body()))
        snapshot = cached.get(USER_A, "mssql_query")
        assert snapshot.version == 7
        assert snapshot.enforcing is True
        assert len(snapshot.resource_rules) == 2

    def test_sends_the_callers_own_token(self, config):
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers["authorization"])
            return httpx.Response(200, json=snapshot_body())

        cache(config, handler).get(USER_A, "mssql_query")
        # Not a server credential: the PDP re-verifies the end user, so this server cannot
        # ask for permissions on behalf of someone it has not authenticated.
        assert seen == ["Bearer token-a"]

    def test_names_the_tool_and_function(self, config):
        seen: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(dict(request.url.params))
            return httpx.Response(200, json=snapshot_body())

        cache(config, handler).get(USER_A, "mssql_query")
        assert seen == [{"tool": "tool-mssql", "function": "mssql_query"}]


class TestCaching:
    def test_serves_from_cache_within_the_ttl(self, config):
        calls = 0

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(200, json=snapshot_body())

        cached = cache(config, handler)
        for _ in range(5):
            cached.get(USER_A, "mssql_query")
        assert calls == 1

    def test_never_serves_one_callers_snapshot_to_another(self, config):
        # The failure this whole system exists to prevent. A snapshot is already filtered to
        # one principal, so a cache keyed on the tool alone would hand User A's permissions
        # to User B.
        def handler(request: httpx.Request) -> httpx.Response:
            token = request.headers["authorization"]
            allowed = "dbo.orders*" if token.endswith("token-a") else "dbo.payroll*"
            return httpx.Response(
                200,
                json=snapshot_body(
                    resourceRules=[{"kind": "sql_table", "pattern": allowed, "effect": "allow", "ruleId": "r"}]
                ),
            )

        cached = cache(config, handler)
        assert cached.get(USER_A, "mssql_query").allows("sql_table", "dbo.orders") is True
        assert cached.get(USER_B, "mssql_query").allows("sql_table", "dbo.orders") is False
        assert cached.get(USER_B, "mssql_query").allows("sql_table", "dbo.payroll") is True

    def test_the_same_user_with_different_groups_is_a_different_cache_entry(self, config):
        # Group membership changes at the issuer without the subject changing. If the
        # fingerprint ignored groups, a promoted or demoted user would keep their old
        # permissions until the TTL expired.
        promoted = Principal(subject="user-a", token="token-a", groups=("/ops-sales", "/ops-payroll"))
        assert USER_A.fingerprint() != promoted.fingerprint()

    def test_group_order_does_not_split_the_cache(self):
        one = Principal(subject="u", token="t", groups=("/a", "/b"))
        other = Principal(subject="u", token="t", groups=("/b", "/a"))
        assert one.fingerprint() == other.fingerprint()

    def test_revalidates_with_if_none_match_after_the_ttl(self, config):
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.headers.get("if-none-match") == 'W/"set-1:7:abc"':
                return httpx.Response(304)
            return httpx.Response(200, json=snapshot_body(), headers={"ETag": 'W/"set-1:7:abc"'})

        cached = cache(config, handler, snapshot_ttl_seconds=0)
        first = cached.get(USER_A, "mssql_query")
        second = cached.get(USER_A, "mssql_query")

        assert len(requests) == 2
        assert requests[1].headers["if-none-match"] == 'W/"set-1:7:abc"'
        # A 304 must return the cached body, not an empty snapshot.
        assert second == first
        assert second.version == 7

    def test_a_304_refreshes_staleness(self, config):
        # Otherwise a policy that simply never changes would age past
        # MCP_POLICY_STALE_MAX_SECONDS and start failing closed while the backend was
        # perfectly healthy — an outage caused by nothing happening.
        state = {"fail": False}

        def handler(request: httpx.Request) -> httpx.Response:
            if state["fail"]:
                raise httpx.ConnectError("backend down")
            if request.headers.get("if-none-match"):
                return httpx.Response(304)
            return httpx.Response(200, json=snapshot_body(), headers={"ETag": 'W/"e"'})

        cached = cache(config, handler, snapshot_ttl_seconds=0, stale_max_seconds=60)
        cached.get(USER_A, "mssql_query")
        cached.get(USER_A, "mssql_query")  # 304, re-stamps freshness

        state["fail"] = True
        assert cached.get(USER_A, "mssql_query").version == 7


class TestFailureModes:
    def test_serves_last_known_good_through_a_brief_outage(self, config):
        state = {"fail": False}

        def handler(_request: httpx.Request) -> httpx.Response:
            if state["fail"]:
                raise httpx.ConnectError("backend down")
            return httpx.Response(200, json=snapshot_body())

        cached = cache(config, handler, snapshot_ttl_seconds=0, stale_max_seconds=300)
        cached.get(USER_A, "mssql_query")
        state["fail"] = True
        # A backend rollout must not take every tool down with it.
        assert cached.get(USER_A, "mssql_query").version == 7

    def test_fails_closed_once_the_cache_is_too_stale(self, config):
        state = {"fail": False}

        def handler(_request: httpx.Request) -> httpx.Response:
            if state["fail"]:
                raise httpx.ConnectError("backend down")
            return httpx.Response(200, json=snapshot_body())

        cached = cache(config, handler, snapshot_ttl_seconds=0, stale_max_seconds=0)
        cached.get(USER_A, "mssql_query")
        state["fail"] = True
        # Serving a cached grant forever means a revoked grant is never actually revoked.
        with pytest.raises(PolicyUnavailable):
            cached.get(USER_A, "mssql_query")

    def test_fails_closed_with_no_cache_at_all(self, config):
        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("backend down")

        with pytest.raises(PolicyUnavailable):
            cache(config, handler).get(USER_A, "mssql_query")

    def test_fails_closed_on_a_server_error(self, config):
        with pytest.raises(PolicyUnavailable):
            cache(config, lambda _r: httpx.Response(500)).get(USER_A, "mssql_query")

    def test_a_401_is_never_covered_by_a_stale_cache(self, config):
        # Not an outage: the PDP answered, and it refused to confirm this caller. Serving a
        # cached snapshot would answer for an identity that was just rejected.
        state = {"reject": False}

        def handler(_request: httpx.Request) -> httpx.Response:
            if state["reject"]:
                return httpx.Response(401, json={"error": "Invalid or expired token"})
            return httpx.Response(200, json=snapshot_body())

        cached = cache(config, handler, snapshot_ttl_seconds=0, stale_max_seconds=300)
        cached.get(USER_A, "mssql_query")
        state["reject"] = True
        with pytest.raises(PolicyUnavailable):
            cached.get(USER_A, "mssql_query")

    def test_fail_open_requires_an_explicit_opt_in(self, config):
        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("backend down")

        allowed = cache(config, handler, fail_mode="open").get(USER_A, "mssql_query")
        assert allowed.default_effect == "allow"
        assert allowed.enforcing is False

    def test_fails_closed_when_no_policy_url_is_configured(self, config):
        # Distinct from an outage: nothing was ever configured. `Guard` short-circuits this
        # case to pre-policy behaviour before reaching the cache, so if it ever gets here
        # the guard has been used in a way it does not support.
        with pytest.raises(PolicyUnavailable):
            cache(config, lambda _r: httpx.Response(200), policy_url=None).get(USER_A, None)


class TestDecisions:
    def test_first_matching_rule_wins(self):
        snapshot = PolicySnapshot.from_json(
            snapshot_body(
                resourceRules=[
                    {"kind": "sql_table", "pattern": "dbo.*", "effect": "allow", "ruleId": "broad"},
                    {"kind": "sql_table", "pattern": "dbo.payroll", "effect": "deny", "ruleId": "narrow"},
                ]
            )
        )
        # Precedence was already resolved by the backend; the guard must not re-sort.
        assert snapshot.decide_resource("sql_table", "dbo.payroll") == ("allow", "broad")

    def test_falls_through_to_the_default_effect(self):
        snapshot = PolicySnapshot.from_json(snapshot_body())
        assert snapshot.decide_resource("sql_table", "dbo.unknown") == ("deny", None)

    def test_kind_must_match_too(self):
        snapshot = PolicySnapshot.from_json(
            snapshot_body(
                resourceRules=[{"kind": "sql_schema", "pattern": "dbo.orders", "effect": "allow", "ruleId": "r"}]
            )
        )
        # A schema grant is not a table grant.
        assert snapshot.allows("sql_table", "dbo.orders") is False
