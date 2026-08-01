"""The guard: authenticate a caller, then decide what that caller may touch."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Sequence

import httpx
import structlog

from .config import GuardConfig
from .errors import PolicyDenied, PolicyUnavailable
from .principal import Principal, current_correlation_id, require_principal
from .snapshot import UNCONFIGURED, PolicySnapshot, SnapshotCache

logger = structlog.get_logger()


@dataclass(frozen=True)
class Resource:
    """One thing a call wants to touch, in the vocabulary the policy store uses.

    `kind` is one of the selector kinds your policy store recognises — `sql_table`,
    `sql_schema`, `mongo_collection`, `http_host`, `path_prefix`, or whatever your rules are
    written against. `value` must already be normalized the
    way rules are authored (lowercase `schema.table` for SQL), because matching is textual:
    a rule denying `dbo.payroll` cannot recognise `[Payroll]` as the same thing.
    """

    kind: str
    value: str

    def __str__(self) -> str:
        return f"{self.kind}:{self.value}"


@dataclass(frozen=True)
class Decision:
    decision: str
    effect: str
    enforcing: bool
    reason: str
    policy_version: int | None = None
    matched_rule_id: str | None = None
    denied_resources: tuple[Resource, ...] = ()

    @property
    def allowed(self) -> bool:
        """What the caller should *do*.

        Reads `effect`, not `decision`. In shadow mode the two differ: `decision` is what
        policy says and is what gets audited, `effect` is always allow. Auditing the real
        answer while obeying the shadow one is what makes it possible to author rules
        against production traffic without blocking anyone.
        """
        return self.effect == "allow"


class Guard:
    """Authorization for one MCP server.

    Construct once at import time and share it; it is thread-safe, which matters because
    MCP tool handlers run in `asyncio.to_thread`.
    """

    def __init__(self, config: GuardConfig | None = None, *, client: httpx.Client | None = None) -> None:
        self.config = config or GuardConfig.from_env()
        self._client = client or httpx.Client(timeout=self.config.timeout_seconds)
        self._snapshots = SnapshotCache(self.config, client=self._client)

    # -- decisions ---------------------------------------------------------------

    def evaluate(
        self,
        function_name: str | None,
        resources: Sequence[Resource] = (),
        *,
        principal: Principal | None = None,
    ) -> Decision:
        """Ask the decision point whether this call may proceed.

        **The PDP is the hot path, not local evaluation.** The snapshot exists for outage
        fallback and for scoping discovery listings, but a normal call asks the backend —
        which means every decision lands in the backend's audit log with the caller, the
        resources and the matched rule, and means one implementation of the semantics
        decides. A round trip to a nearby PDP costs far less than the query it guards.

        Falls back to the cached snapshot when the PDP is unreachable, and past
        `MCP_POLICY_STALE_MAX_SECONDS` raises `PolicyUnavailable`.
        """
        if not self.config.policy_enabled:
            # No PDP configured: behave exactly as this tool did before policy existed.
            return Decision(
                decision="allow",
                effect="allow",
                enforcing=False,
                reason="no policy decision point configured",
            )

        caller = principal or require_principal()

        try:
            return self._evaluate_remote(caller, function_name, resources)
        except httpx.HTTPError as exc:
            logger.warning("policy_evaluate_unreachable", error=str(exc))
            return self._evaluate_from_snapshot(caller, function_name, resources, reason=str(exc))

    def _evaluate_remote(self, caller: Principal, function_name: str | None, resources: Sequence[Resource]) -> Decision:
        payload: dict[str, Any] = {
            "tool": self.config.tool_id,
            "function": function_name,
            "resources": [{"kind": r.kind, "value": r.value} for r in resources],
        }
        correlation_id = current_correlation_id()
        if correlation_id:
            payload["correlationId"] = correlation_id

        response = self._client.post(
            f"{self.config.policy_url}/evaluate",
            json=payload,
            headers={"Authorization": f"Bearer {caller.token}"},
            timeout=self.config.timeout_seconds,
        )

        if response.status_code in (401, 403, 404):
            # Not an outage — the PDP answered, and the answer is no. A 404 means this
            # server's MCP_TOOL_ID names no tool the backend knows, which cannot be
            # resolved to any policy set; guessing would mean applying someone else's
            # rules.
            raise PolicyDenied(f"Policy decision point refused the request (HTTP {response.status_code})")
        if response.status_code >= 400:
            raise httpx.HTTPError(f"Policy evaluate returned HTTP {response.status_code}")

        body = response.json()
        denied = tuple(
            Resource(kind=str(entry["resource"]["kind"]), value=str(entry["resource"]["value"]))
            for entry in body.get("resourceDecisions", [])
            if entry.get("effect") == "deny"
        )
        return Decision(
            decision=str(body.get("decision", "deny")),
            effect=str(body.get("effect", "deny")),
            enforcing=bool(body.get("enforcing", False)),
            reason=str(body.get("reason", "")),
            policy_version=body.get("policyVersion"),
            matched_rule_id=body.get("matchedRuleId"),
            denied_resources=denied,
        )

    def _evaluate_from_snapshot(
        self,
        caller: Principal,
        function_name: str | None,
        resources: Sequence[Resource],
        *,
        reason: str,
    ) -> Decision:
        snapshot = self._snapshots.get(caller, function_name)

        if not resources:
            return Decision(
                decision=snapshot.call_effect,
                effect=snapshot.call_effect if snapshot.enforcing else "allow",
                enforcing=snapshot.enforcing,
                reason=f"decided from cached policy (PDP unreachable: {reason})",
                policy_version=snapshot.version,
                matched_rule_id=snapshot.call_rule_id,
            )

        denied: list[Resource] = []
        matched: str | None = None
        for resource in resources:
            effect, rule_id = snapshot.decide_resource(resource.kind, resource.value)
            if effect == "deny":
                denied.append(resource)
                # Report the FIRST denial, matching the backend's evaluator.
                if matched is None:
                    matched = rule_id

        # Every requested resource must be allowed. One unmatched resource denies the whole
        # call — a query joining Orders and Payroll *is* a Payroll read, and deciding
        # resources independently would let a join launder access.
        decision = "deny" if denied else "allow"
        return Decision(
            decision=decision,
            effect=decision if snapshot.enforcing else "allow",
            enforcing=snapshot.enforcing,
            reason=f"decided from cached policy (PDP unreachable: {reason})",
            policy_version=snapshot.version,
            matched_rule_id=matched,
            denied_resources=tuple(denied),
        )

    def require(
        self,
        function_name: str | None,
        resources: Sequence[Resource] = (),
        *,
        principal: Principal | None = None,
    ) -> Decision:
        """`evaluate`, but raise `PolicyDenied` unless the call may proceed.

        The form tool code should normally use: it makes the denial impossible to ignore by
        forgetting to check a return value.
        """
        decision = self.evaluate(function_name, resources, principal=principal)
        if not decision.allowed:
            raise PolicyDenied(
                decision.reason or "Access denied by policy",
                resources=tuple(str(r) for r in decision.denied_resources),
                matched_rule_id=decision.matched_rule_id,
                policy_version=decision.policy_version,
            )
        return decision

    # -- discovery ---------------------------------------------------------------

    def snapshot(self, function_name: str | None = None, *, principal: Principal | None = None) -> PolicySnapshot:
        """The caller's flattened policy, for scoping a listing in one round trip."""
        if not self.config.policy_enabled:
            return UNCONFIGURED
        return self._snapshots.get(principal or require_principal(), function_name)

    def filter_resources(
        self,
        kind: str,
        values: Iterable[str],
        *,
        function_name: str | None = None,
        principal: Principal | None = None,
        key: Any = None,
    ) -> list[Any]:
        """Keep only the values this caller may see.

        **Discovery must hide, not refuse.** A `list_tables` that returned "3 tables
        hidden", or a `describe_table` that distinguished "denied" from "not found", would
        be an enumeration oracle: the model — or whoever is steering it — learns the exact
        names of what it cannot reach, which is often the interesting half of the secret.
        Filtering silently means a caller's view of the database is simply smaller.

        `key` extracts the resource string from each item when the caller is filtering rows
        rather than bare names.
        """
        snapshot = self.snapshot(function_name, principal=principal)
        if not snapshot.enforcing:
            return list(values)

        extract = key or (lambda item: item)
        return [item for item in values if snapshot.allows(kind, str(extract(item)))]

    # -- lifecycle ---------------------------------------------------------------

    def invalidate(self) -> None:
        self._snapshots.invalidate()

    def close(self) -> None:
        self._snapshots.close()


__all__ = [
    "Decision",
    "Guard",
    "PolicyDenied",
    "PolicyUnavailable",
    "Resource",
]
