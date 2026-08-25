"""The User-Agent the guard reports to the policy decision point.

Pinned as text because it is a **wire contract with the platform**, parsed there with
`/mcp-policy-guard\\/([\\w.+-]+)/i` to decide whether this guard may be handed a row predicate.
Until 0.6.1 no User-Agent was sent at all, so that check could never pass and every
row-filtered resource was denied — silently, and in the safe direction, which is exactly why it
went unnoticed. These assertions are the half of the coupling that lives in this repo.
"""

from __future__ import annotations

import re

import httpx

from mcp_policy_guard import USER_AGENT, __version__
from mcp_policy_guard.policy import Guard
from mcp_policy_guard.principal import Principal

# The platform's parser, copied verbatim from routes/policy.ts.
PLATFORM_PATTERN = re.compile(r"mcp-policy-guard/([\w.+-]+)", re.IGNORECASE)


def test_the_platform_regex_extracts_our_version():
    match = PLATFORM_PATTERN.search(USER_AGENT)
    assert match is not None, f"platform could not parse {USER_AGENT!r}"
    assert match.group(1) == __version__


def test_version_is_three_part_so_the_platform_can_compare_it():
    # guardSupportsRowFilters() refuses anything with fewer than three numeric parts, so a
    # two-part version would be read as unparseable and denied.
    parts = __version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)


def _captured_headers(handler_status: int = 200):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen[request.url.path] = dict(request.headers)
        return httpx.Response(
            handler_status,
            json={
                "decision": "allow",
                "effect": "allow",
                "enforcing": True,
                "reason": "ok",
                "resourceDecisions": [],
            },
        )

    return seen, httpx.Client(transport=httpx.MockTransport(handler))


def test_evaluate_sends_it_even_on_an_injected_client(config):
    # `Guard(client=...)` is supported, and a caller-supplied client is exactly where a
    # header set only on the client we construct would go missing.
    seen, client = _captured_headers()
    guard = Guard(config, client=client)
    guard.evaluate("fn", [], principal=Principal(subject="s", token="t"))
    assert seen["/api/policy/evaluate"]["user-agent"] == USER_AGENT
