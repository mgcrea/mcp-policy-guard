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

#: How far `redact` descends before summarizing. Bounded so a cyclic or hostile payload
#: cannot turn writing an audit record into a stack overflow.
_MAX_REDACT_DEPTH = 6

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


def redact(params: dict[str, Any], *, _depth: int = 0) -> dict[str, Any]:
    """Mask secret-looking values and truncate long ones, at any nesting depth.

    Recursive because tool arguments are frequently structured: a connection object, an
    options dict, a list of row filters. A top-level-only pass sends
    `{"config": {"password": "..."}}` to the log pipeline verbatim, which is the one thing
    this function exists to prevent — and the shape most likely to carry a credential.

    A key marked secret is masked wholesale rather than descended into: if the key says
    `credentials`, nothing underneath it needs inspecting.
    """
    return {key: _redact_value(key, value, _depth) for key, value in params.items()}


def _redact_value(key: str, value: Any, depth: int) -> Any:
    if is_secret_key(key):
        return "***REDACTED***"
    if depth >= _MAX_REDACT_DEPTH:
        # Deep enough to be a cycle or a pathological payload. Summarize rather than
        # recurse: an audit record is not obliged to reproduce the whole input, and a
        # stack overflow here would take down the call it is meant to be recording.
        return "...[too deeply nested]"
    if isinstance(value, dict):
        return redact(value, _depth=depth + 1)
    if isinstance(value, (list, tuple)):
        # The key belongs to the container, so each element is re-tested under it: a list
        # under `passwords` is masked element-wise by the check above.
        return [_redact_value(key, item, depth + 1) for item in value]
    if isinstance(value, str) and len(value) > _MAX_VALUE_CHARS:
        return value[:_MAX_VALUE_CHARS] + "...[truncated]"
    return value


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
        **extra,
        # Last on purpose. Identity is the one thing in an audit record that a caller must
        # not be able to set: merged before `**extra`, a stray `subject=` keyword — or a
        # tool that splats user-influenced data in — would file one caller's actions under
        # another's name, in the log that exists to answer exactly that question.
        **_identity_fields(),
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
