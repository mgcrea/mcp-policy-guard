"""Audit records: identity, decision, and redaction."""

from __future__ import annotations

import pytest
import structlog

from mcp_policy_guard.audit import audit_call, emit, is_secret_key, redact
from mcp_policy_guard.principal import Principal, set_caller_id, set_correlation_id, set_principal

USER_A = Principal(
    subject="user-a-sub",
    token="token-a",
    email="user-a@example.com",
    groups=("/ops-sales",),
    client_id="open-webui",
)


@pytest.fixture
def captured():
    structlog.configure(
        processors=[structlog.testing.LogCapture()],
        wrapper_class=structlog.BoundLogger,
        cache_logger_on_first_use=False,
    )
    entries = structlog.get_config()["processors"][0].entries
    entries.clear()
    yield entries
    structlog.reset_defaults()


@pytest.fixture(autouse=True)
def _clear_context():
    set_principal(None)
    set_correlation_id(None)
    set_caller_id(None)
    yield
    set_principal(None)
    set_correlation_id(None)
    set_caller_id(None)


class TestIdentity:
    def test_records_who_made_the_call(self, captured):
        set_principal(USER_A)
        emit("tool_call", tool="mssql_query", decision="allow")
        record = captured[0]
        assert record["subject"] == "user-a-sub"
        assert record["email"] == "user-a@example.com"
        assert record["groups"] == ["/ops-sales"]
        assert record["client_id"] == "open-webui"

    def test_records_the_correlation_id_that_joins_systems(self, captured):
        # The same id travels with every hop of one turn, so a question asked of this log
        # can be answered from the caller's traces and the backend's audit rows.
        set_principal(USER_A)
        set_correlation_id("corr-abc")
        emit("tool_call", tool="mssql_query")
        assert captured[0]["correlation_id"] == "corr-abc"

    def test_records_the_asserted_caller_id(self, captured):
        # Audit only. The caller asserts this and nothing verifies it, so it is recorded
        # for tracing and must never reach a policy decision.
        set_principal(USER_A)
        set_caller_id("agent-abc")
        emit("tool_call", tool="mssql_query")
        assert captured[0]["caller_id"] == "agent-abc"

    def test_an_unauthenticated_call_is_recorded_as_such(self, captured):
        emit("tool_call", tool="mssql_query")
        # Null, not a placeholder identity — an unattributed row is honest, a wrong one is
        # not.
        assert captured[0]["subject"] is None
        assert captured[0]["groups"] == []


class TestDecisionRecording:
    def test_emits_one_record_on_success(self, captured):
        set_principal(USER_A)
        with audit_call("mssql_query", {"query": "SELECT 1"}) as record:
            record["decision"] = "allow"
            record["resources"] = ["dbo.orders"]
        assert len(captured) == 1
        assert captured[0]["decision"] == "allow"
        assert captured[0]["resources"] == ["dbo.orders"]
        assert captured[0]["success"] is True

    def test_a_denied_call_still_records_what_it_wanted(self, captured):
        # The record must survive the exception that ends the call, and must name the
        # resources — a denial with no resources tells an auditor nothing.
        set_principal(USER_A)
        from mcp_policy_guard.errors import PolicyDenied

        with pytest.raises(PolicyDenied):
            with audit_call("mssql_query", {"query": "SELECT * FROM Payroll"}) as record:
                record["resources"] = ["dbo.payroll"]
                record["decision"] = "deny"
                raise PolicyDenied("denied")

        assert len(captured) == 1
        assert captured[0]["decision"] == "deny"
        assert captured[0]["resources"] == ["dbo.payroll"]
        assert captured[0]["error_type"] == "PolicyDenied"

    def test_records_duration(self, captured):
        with audit_call("mssql_query", {"query": "SELECT 1"}):
            pass
        assert captured[0]["duration_ms"] >= 0


class TestRedaction:
    @pytest.mark.parametrize(
        "key",
        ["password", "Password", "api_key", "apiKey", "APIKey", "secret", "authorization", "dsn", "connectionString"],
    )
    def test_redacts_secret_keys(self, key):
        assert is_secret_key(key)

    @pytest.mark.parametrize("key", ["secretary", "monkey", "query", "schema", "table_name", "author"])
    def test_leaves_innocent_keys_alone(self, key):
        # Substring matching would flag `secretary` (secret) and `monkey` (key). Word
        # splitting is what keeps ordinary parameters readable in the audit trail.
        assert not is_secret_key(key)

    def test_masks_the_value_not_the_key(self):
        assert redact({"password": "hunter2"}) == {"password": "***REDACTED***"}

    def test_truncates_long_values(self):
        out = redact({"query": "x" * 900})
        assert out["query"].endswith("...[truncated]")
        assert len(out["query"]) == 500 + len("...[truncated]")

    def test_keeps_short_values_verbatim(self):
        assert redact({"query": "SELECT 1"}) == {"query": "SELECT 1"}
