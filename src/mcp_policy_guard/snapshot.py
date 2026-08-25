"""The policy snapshot: a per-caller, first-match-wins decision table.

The backend flattens rule precedence — subject matching, priority ordering, the deny-wins
tiebreak — before serving this, so the logic below is only ever "walk the list, first match
wins". That is the point, and it is an obligation on whoever implements the snapshot
endpoint: the security-critical ordering has exactly one implementation, in the place that
is tested for it, and this package cannot drift from it.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

import httpx
import structlog

from ._version import USER_AGENT
from .config import GuardConfig
from .errors import PolicyUnavailable
from .matching import glob_matches
from .principal import Principal

logger = structlog.get_logger()

#: Statuses that mean the PDP answered and the answer is *no*. Not an outage, so a cached
#: snapshot must never be served past one of these: the decision point has actively declined
#: to confirm this caller, and last-known-good would be answering on behalf of an identity it
#: just refused. 404 is here because an unknown `MCP_TOOL_ID` resolves to no policy at all,
#: and guessing would mean applying somebody else's rules.
REFUSAL_STATUSES = frozenset({401, 403, 404})


def raise_if_refused(status_code: int, what: str) -> None:
    """Turn an explicit refusal into `PolicyUnavailable`, which fails closed.

    One definition shared by the evaluate and snapshot paths. They had drifted — evaluate
    treated 403/404 as denials while snapshot let them fall through to the stale-cache
    fallback — and a divergence here is invisible until the day it matters.
    """
    if status_code in REFUSAL_STATUSES:
        raise PolicyUnavailable(f"{what}: decision point refused the request (HTTP {status_code})")


@dataclass(frozen=True)
class SnapshotFilter:
    """A row predicate carried on a snapshot row, values already resolved for this caller.

    `pattern` is **not** redundant with the row's own. A rule allowing `dbo.*` may carry a
    predicate that narrows only `dbo.perfevents`, and both end up on the same flattened row —
    so this pattern is re-checked against the resource in hand, or reading `dbo.orders` would
    silently acquire a predicate meant for another table.
    """

    kind: str
    pattern: str
    column: str
    operator: str
    values: tuple[str, ...]

    def covers(self, kind: str, value: str) -> bool:
        return self.kind == kind and glob_matches(self.pattern, value)


@dataclass(frozen=True)
class ResourceRule:
    kind: str
    pattern: str
    effect: str
    rule_id: str
    filters: tuple[SnapshotFilter, ...] = ()


@dataclass(frozen=True)
class PolicySnapshot:
    policy_set_id: str
    version: int
    enforcing: bool
    default_effect: str
    resource_rules: tuple[ResourceRule, ...]
    call_effect: str
    call_rule_id: str | None

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> PolicySnapshot:
        rules = tuple(
            ResourceRule(
                kind=str(entry["kind"]),
                pattern=str(entry["pattern"]),
                effect=str(entry["effect"]),
                rule_id=str(entry["ruleId"]),
                # Absent on a snapshot from an older platform, and on any row nothing narrows.
                filters=tuple(
                    SnapshotFilter(
                        kind=str(entry["kind"]),
                        pattern=str(raw.get("pattern", entry["pattern"])),
                        column=str(raw["column"]),
                        operator=str(raw["operator"]),
                        values=tuple(str(value) for value in raw.get("values", [])),
                    )
                    for raw in entry.get("filters", []) or []
                ),
            )
            for entry in payload.get("resourceRules", [])
        )
        return cls(
            policy_set_id=str(payload.get("policySetId", "")),
            version=int(payload.get("version", 0)),
            enforcing=bool(payload.get("enforcing", False)),
            default_effect=str(payload.get("defaultEffect", "allow")),
            resource_rules=rules,
            call_effect=str(payload.get("callEffect", "allow")),
            call_rule_id=payload.get("callRuleId"),
        )

    def decide_resource(self, kind: str, value: str) -> tuple[str, str | None]:
        """`(effect, rule_id)` for one resource. First matching row wins."""
        rule = self._match(kind, value)
        return (rule.effect, rule.rule_id) if rule else (self.default_effect, None)

    def filters_for(self, kind: str, value: str) -> tuple[SnapshotFilter, ...]:
        """The predicates the winning row imposes on this resource, if any.

        Read off the **same** row `decide_resource` returns, never scanned across the table:
        a predicate belongs to the rule that granted the resource, and picking one up from a
        row that did not decide anything would apply a narrowing nobody authored for it.
        """
        rule = self._match(kind, value)
        if rule is None or rule.effect != "allow":
            return ()
        return tuple(f for f in rule.filters if f.covers(kind, value))

    def _match(self, kind: str, value: str) -> ResourceRule | None:
        for rule in self.resource_rules:
            if rule.kind == kind and glob_matches(rule.pattern, value):
                return rule
        return None

    def allows(self, kind: str, value: str) -> bool:
        return self.decide_resource(kind, value)[0] == "allow"


@dataclass
class _CacheEntry:
    snapshot: PolicySnapshot
    etag: str | None
    #: Monotonic time of the last successful exchange with the PDP, including a 304. This
    #: is what staleness is measured from — not the time the body last changed, since an
    #: unchanged policy that keeps revalidating is perfectly fresh.
    validated_at: float


class SnapshotCache:
    """Fetches and caches snapshots, one entry per (caller, tool, function).

    **Keyed by the caller's identity fingerprint, never by tool alone.** A snapshot is
    already filtered to one principal, so a cache that ignored identity would hand User A's
    permissions to User B — the exact failure this package exists to prevent.
    """

    def __init__(self, config: GuardConfig, client: httpx.Client | None = None) -> None:
        self._config = config
        self._client = client or httpx.Client(timeout=config.timeout_seconds)
        #: Bounded and LRU-ordered. One entry per (caller, tool, function), so an unbounded
        #: dict grows with every distinct user the server ever sees and never forgets the
        #: ones who left — a slow leak in a process designed to run for weeks.
        self._entries: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._lock = threading.Lock()

    def _key(self, principal: Principal, function_name: str | None) -> str:
        return f"{principal.fingerprint()}|{self._config.tool_id}|{function_name or '*'}"

    def get(self, principal: Principal, function_name: str | None) -> PolicySnapshot:
        """The caller's current snapshot, refreshing it if the TTL has elapsed.

        Raises `PolicyUnavailable` when the PDP is unreachable and no cached snapshot
        remains within `MCP_POLICY_STALE_MAX_SECONDS`.
        """
        if not self._config.policy_url or not self._config.tool_id:
            raise PolicyUnavailable("Guard has no policy URL configured")

        key = self._key(principal, function_name)
        now = time.monotonic()

        with self._lock:
            entry = self._entries.get(key)
            if entry is not None:
                if now - entry.validated_at > self._config.stale_max_seconds:
                    # Older than it could ever be served, so it is not a cache entry any
                    # more — just memory holding a revoked grant.
                    del self._entries[key]
                    entry = None
                else:
                    self._entries.move_to_end(key)

        if entry is not None and now - entry.validated_at < self._config.snapshot_ttl_seconds:
            return entry.snapshot

        try:
            refreshed = self._fetch(principal, function_name, entry)
        except httpx.HTTPError as exc:
            return self._fall_back(key, entry, reason=str(exc))

        with self._lock:
            self._entries[key] = refreshed
            self._entries.move_to_end(key)
            while len(self._entries) > self._config.snapshot_cache_max_entries:
                evicted, _ = self._entries.popitem(last=False)
                logger.debug("policy_snapshot_evicted", cache_key=evicted)
        return refreshed.snapshot

    def _fetch(self, principal: Principal, function_name: str | None, entry: _CacheEntry | None) -> _CacheEntry:
        params: dict[str, str] = {"tool": str(self._config.tool_id)}
        if function_name:
            params["function"] = function_name

        headers = {"Authorization": f"Bearer {principal.token}", "User-Agent": USER_AGENT}
        if entry is not None and entry.etag:
            headers["If-None-Match"] = entry.etag

        response = self._client.get(
            f"{self._config.policy_url}/snapshot",
            params=params,
            headers=headers,
            timeout=self._config.timeout_seconds,
        )

        if response.status_code == 304 and entry is not None:
            # Unchanged. Re-stamp freshness: the PDP answered, which is what staleness
            # measures. Without this a stable policy would age out and fail closed while
            # the backend was perfectly healthy.
            return _CacheEntry(entry.snapshot, entry.etag, time.monotonic())

        raise_if_refused(response.status_code, "Policy snapshot")

        if response.status_code >= 400:
            raise httpx.HTTPError(f"Policy snapshot returned HTTP {response.status_code}")

        return _CacheEntry(
            snapshot=PolicySnapshot.from_json(response.json()),
            etag=response.headers.get("etag"),
            validated_at=time.monotonic(),
        )

    def _fall_back(self, key: str, entry: _CacheEntry | None, *, reason: str) -> PolicySnapshot:
        """Last-known-good, bounded — then closed.

        Serving a cached decision through a brief backend outage is the difference between
        a rollout being invisible and a rollout taking every tool down. Serving it
        *indefinitely* means a revoked grant never actually gets revoked, so the window is
        bounded and the guard then denies. It never fails open on its own; only an explicit
        `MCP_POLICY_FAIL_MODE=open` does that, which an operator has to type.
        """
        age = None if entry is None else time.monotonic() - entry.validated_at

        if entry is not None and age is not None and age <= self._config.stale_max_seconds:
            logger.warning(
                "policy_snapshot_stale_served",
                reason=reason,
                age_seconds=round(age, 1),
                stale_max_seconds=self._config.stale_max_seconds,
            )
            return entry.snapshot

        if self._config.fail_mode == "open":
            logger.error("policy_unavailable_failing_open", reason=reason, cache_key=key)
            return _ALLOW_ALL

        logger.error(
            "policy_unavailable_failing_closed",
            reason=reason,
            age_seconds=None if age is None else round(age, 1),
        )
        raise PolicyUnavailable(
            "Policy could not be evaluated and no recent decision was cached. Refusing the call rather than guessing."
        )

    def invalidate(self) -> None:
        with self._lock:
            self._entries.clear()

    def close(self) -> None:
        """No-op on the shared client: `Guard` owns its lifecycle and knows whether it may
        be closed. Kept so existing callers of `SnapshotCache.close()` still work."""
        self.invalidate()


#: Only ever returned under an explicit `MCP_POLICY_FAIL_MODE=open`.
_ALLOW_ALL = PolicySnapshot(
    policy_set_id="fail-open",
    version=0,
    enforcing=False,
    default_effect="allow",
    resource_rules=(),
    call_effect="allow",
    call_rule_id=None,
)


#: Used when no PDP is configured at all — the pre-policy behaviour of every tool.
UNCONFIGURED = PolicySnapshot(
    policy_set_id="unconfigured",
    version=0,
    enforcing=False,
    default_effect="allow",
    resource_rules=(),
    call_effect="allow",
    call_rule_id=None,
)
