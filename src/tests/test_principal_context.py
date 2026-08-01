"""The principal must survive the hop into the thread pool.

An MCP tool is typically `async def` wrapping `asyncio.to_thread(...)`, so the principal is
established on the event loop and read on a different thread. Contextvars do
propagate through `to_thread` — it copies the current context — but that is a library
guarantee this package's correctness depends on completely, and its failure mode is silent:
`current_principal()` returns None and, in a naive implementation, the call proceeds
unattributed. Pin it.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import threading

import pytest

from mcp_policy_guard.errors import AuthenticationRequired
from mcp_policy_guard.principal import (
    Principal,
    current_principal,
    require_principal,
    set_principal,
)

ALICE = Principal(subject="alice", token="token-alice", groups=("/ops-sales",))
BOB = Principal(subject="bob", token="token-bob", groups=("/ops-payroll",))


def _read_subject() -> str | None:
    principal = current_principal()
    return principal.subject if principal else None


async def test_principal_propagates_through_asyncio_to_thread():
    set_principal(ALICE)
    assert await asyncio.to_thread(_read_subject) == "alice"


async def test_the_thread_really_is_a_different_thread():
    # Guards against the assertion above passing for the boring reason.
    set_principal(ALICE)
    main = threading.get_ident()
    worker = await asyncio.to_thread(threading.get_ident)
    assert worker != main


async def test_require_principal_raises_in_a_thread_with_no_caller():
    set_principal(None)
    with pytest.raises(AuthenticationRequired):
        await asyncio.to_thread(require_principal)


async def test_concurrent_callers_do_not_see_each_others_identity():
    # The scenario this package is built for: one agent, one MCP server, two users at
    # once. If the principal leaked across tasks, User B's query would be authorized
    # against User A's grants.
    async def run(principal: Principal) -> str | None:
        set_principal(principal)
        await asyncio.sleep(0)
        return await asyncio.to_thread(_read_subject)

    results = await asyncio.gather(*(run(p) for p in (ALICE, BOB, ALICE, BOB)))
    assert results == ["alice", "bob", "alice", "bob"]


async def test_nested_to_thread_still_carries_the_principal():
    def outer() -> str | None:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            # A plain executor does NOT copy context — a tool that hands work to its own
            # pool loses the principal. Documented here so the next author sees it before
            # discovering it in production.
            return pool.submit(_read_subject).result()

    set_principal(ALICE)
    assert await asyncio.to_thread(outer) is None


async def test_context_can_be_carried_into_a_plain_executor_explicitly():
    import contextvars

    def outer() -> str | None:
        ctx = contextvars.copy_context()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(ctx.run, _read_subject).result()

    set_principal(ALICE)
    assert await asyncio.to_thread(outer) == "alice"
