"""Structured audit for tool calls.

Replaces the ad-hoc per-tool audit logging that records the tool name and arguments but has
no idea who was calling. The addition here is the principal, the decision and the resources
— the three fields that turn a log line into an answer to "who read the payroll table".

Emission is to stdout as JSON, for whatever log pipeline is already collecting it. It is
deliberately *not* a write to an audit database: the MCP server holds no such credential,
and giving it one so it could write its own audit rows would be a far larger grant than the
thing being audited.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

import structlog

from .principal import current_caller_id, current_correlation_id, current_principal

logger = structlog.get_logger()

# Word-level secret detection. Matching on whole words rather than substrings is what keeps
# `secretary` and `monkey` out of the redaction set while still catching `api_key` and
# `apiKey`.
_SECRET_WORDS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "credential",
        "credentials",
        "authorization",
        "auth",
        "cookie",
        "dsn",
    }
)
_SECRET_COMPOUNDS = ("apikey", "privatekey", "secretkey", "accesskey", "connectionstring")

_MAX_VALUE_CHARS = 500

_NON_ALNUM = re.compile(r"[^A-Za-z0-9]+")


def _split_words(key: str) -> list[str]:
    """`apiKey_v2` -> ['api', 'key', 'v', '2']."""
    spaced = []
    for index, char in enumerate(key):
        if char.isupper() and index > 0 and (key[index - 1].islower() or key[index - 1].isdigit()):
            spaced.append(" ")
        spaced.append(char)
    normalized = "".join(spaced)
    return [word.lower() for word in _NON_ALNUM.split(normalized) if word]


def is_secret_key(key: str) -> bool:
    words = _split_words(key)
    if any(word in _SECRET_WORDS for word in words):
        return True
    collapsed = "".join(words)
    return any(compound in collapsed for compound in _SECRET_COMPOUNDS)


def redact(params: dict[str, Any]) -> dict[str, Any]:
    """Mask secret-looking values and truncate long ones."""
    out: dict[str, Any] = {}
    for key, value in params.items():
        if is_secret_key(key):
            out[key] = "***REDACTED***"
        elif isinstance(value, str) and len(value) > _MAX_VALUE_CHARS:
            out[key] = value[:_MAX_VALUE_CHARS] + "...[truncated]"
        else:
            out[key] = value
    return out


def _identity_fields() -> dict[str, Any]:
    principal = current_principal()
    return {
        "subject": principal.subject if principal else None,
        "email": principal.email if principal else None,
        "groups": list(principal.groups) if principal else [],
        "client_id": principal.client_id if principal else None,
        "correlation_id": current_correlation_id(),
        "caller_id": current_caller_id(),
    }


def emit(
    event: str,
    *,
    tool: str,
    decision: str | None = None,
    reason: str | None = None,
    resources: tuple[str, ...] | list[str] = (),
    params: dict[str, Any] | None = None,
    duration_ms: float | None = None,
    **extra: Any,
) -> None:
    """Write one audit record."""
    record: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "decision": decision,
        "reason": reason,
        "resources": list(resources),
        **_identity_fields(),
        **extra,
    }
    if params is not None:
        record["params"] = redact(params)
    if duration_ms is not None:
        record["duration_ms"] = round(duration_ms, 2)
    logger.info(event, **record)


@contextmanager
def audit_call(tool: str, params: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Wrap a tool call, emitting exactly one record however it ends.

    Yields a mutable dict the body fills in as it learns things — the decision, the
    resources it turned out to touch — so a call that is denied halfway through still
    produces a record naming what it was denied.
    """
    started = time.perf_counter()
    context: dict[str, Any] = {"decision": None, "reason": None, "resources": []}
    try:
        yield context
    except Exception as exc:
        emit(
            "tool_call_failed",
            tool=tool,
            params=params,
            duration_ms=(time.perf_counter() - started) * 1000,
            success=False,
            error=str(exc),
            error_type=type(exc).__name__,
            decision=context.get("decision"),
            reason=context.get("reason"),
            resources=context.get("resources", []),
        )
        raise
    emit(
        "tool_call",
        tool=tool,
        params=params,
        duration_ms=(time.perf_counter() - started) * 1000,
        success=True,
        decision=context.get("decision"),
        reason=context.get("reason"),
        resources=context.get("resources", []),
    )
