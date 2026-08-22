"""The guard: authenticate a caller, then decide what that caller may touch."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Sequence

import httpx
import structlog

from .config import GuardConfig
from .errors import PolicyDenied, PolicyUnavailable
from .principal import Principal, current_correlation_id, current_principal, require_principal
from .request import current_message_request, principal_from_scope
from .snapshot import UNCONFIGURED, PolicySnapshot, SnapshotCache, raise_if_refused

logger = structlog.get_logger()


def _resolve_principal(explicit: Principal | None) -> Principal:
    """Whose grants this call is decided against, most trustworthy source first.

    The request scope outranks the contextvar deliberately. The contextvar is only correct
    if something bound it for *this* message — `guarded` or `GuardServerMiddleware` — and a
    handler where that was forgotten would otherwise be decided against whoever opened the
    session. Reading the message's own scope here means the guard still authorizes the right
    caller even when the binding is missing, so a forgotten decorator costs correct audit
    attribution rather than someone else's data.

    A disagreement between the two is logged loudly: it is the fingerprint of exactly that
    mistake, and it is invisible from the outside because the wrong answer looks like the
    right one.
    """
    if explicit is not None:
        return explicit

    scoped = principal_from_scope(getattr(current_message_request(), "scope", None))
    bound = current_principal()

    if scoped is not None:
        if bound is not None and bound.subject != scoped.subject:
            logger.error(
                "principal_binding_disagreement",
                bound_subject=bound.subject,
                request_subject=scoped.subject,
                hint="the message's caller was not bound; is @guarded missing on this handler?",
            )
        return scoped

    return require_principal()


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


def _filters_from(resource_decisions: Iterable[dict[str, Any]]) -> tuple[RowFilter, ...]:
    """Row predicates out of a decision body.

    Only ALLOWED resources can carry one: a denied resource yields no rows to narrow, and
    reading a predicate off a denial would be a way to turn a deny into a filtered allow.

    A body with no `filters` anywhere — an older platform, or simply a call nothing narrows —
    produces an empty tuple and the tool behaves exactly as it did before predicates existed.
    """
    filters: list[RowFilter] = []
    for entry in resource_decisions:
        if entry.get("effect") != "allow":
            continue
        resource = Resource(kind=str(entry["resource"]["kind"]), value=str(entry["resource"]["value"]))
        for raw in entry.get("filters", []) or []:
            filters.append(
                RowFilter(
                    resource=resource,
                    column=str(raw["column"]),
                    operator=str(raw["operator"]),
                    values=tuple(str(value) for value in raw.get("values", [])),
                )
            )
    return tuple(filters)


class _Undetermined:
    """Sentinel: the read set could not be established.

    Distinct from `[]`, which means "this call touches nothing" and is decided by the
    function-level rule alone. Without a way to say *I do not know*, a resource extractor
    that failed would pass an empty list and quietly get the answer for a call that reads
    nothing — the extractor's failure converted into an allow. Passing `UNDETERMINED`
    denies whenever policy is enforcing, and says so in the audit record.
    """

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "UNDETERMINED"


#: Pass as `resources` when enumeration failed. See `_Undetermined`.
UNDETERMINED = _Undetermined()

#: The PDP's own cap on a single request's resource list. Exceeding it is a 400, which would
#: otherwise be read as an outage and silently degrade to local snapshot evaluation.
MAX_RESOURCES_PER_CALL = 200


@dataclass(frozen=True)
class RowFilter:
    """A predicate the caller must apply to one resource before returning its rows.

    Values arrive **already resolved for this caller** — the PDP substitutes them, so there is
    no attribute key here and nothing for a tool worker to look up or get wrong. `resource`
    names what the predicate applies to, in the same `kind:value` vocabulary the decision uses,
    because one call may narrow several tables differently.

    A tool that receives these and ignores them returns unscoped rows, which is why the PDP
    refuses to send them at all to a guard older than the release that added this class.
    """

    resource: Resource
    column: str
    operator: str
    values: tuple[str, ...]


@dataclass(frozen=True)
class Decision:
    decision: str
    effect: str
    enforcing: bool
    reason: str
    policy_version: int | None = None
    matched_rule_id: str | None = None
    denied_resources: tuple[Resource, ...] = ()
    #: Predicates that MUST be applied to the allowed resources. Empty when nothing narrows
    #: them. A tool that cannot apply one must refuse the call rather than return everything.
    filters: tuple[RowFilter, ...] = ()

    def filters_for(self, resource: Resource) -> tuple[RowFilter, ...]:
        """Every predicate that applies to one resource."""
        return tuple(f for f in self.filters if f.resource == resource)

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
        #: Only a client we created may be closed by `close()`. An injected one belongs to
        #: the caller, who may still be using it.
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=self.config.timeout_seconds)
        self._snapshots = SnapshotCache(self.config, client=self._client)

    # -- decisions ---------------------------------------------------------------

    def evaluate(
        self,
        function_name: str | None,
        resources: Sequence[Resource] | _Undetermined = (),
        *,
        principal: Principal | None = None,
    ) -> Decision:
        """Ask the decision point whether this call may proceed.

        **The PDP is the hot path, not local evaluation.** The snapshot exists for outage
        fallback and for scoping discovery listings, but a normal call asks the backend —
        which means every decision lands in the backend's audit log with the caller, the
        resources and the matched rule, and means one implementation of the semantics
        decides. A round trip to a nearby PDP costs far less than the query it guards.

        Pass `UNDETERMINED` for `resources` when the read set could not be established; it
        denies while enforcing rather than being mistaken for a call that reads nothing.

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

        caller = _resolve_principal(principal)

        if isinstance(resources, _Undetermined):
            return self._deny_undetermined(caller, function_name)

        resources = self._prepare_resources(resources)

        last_error: httpx.HTTPError | None = None
        # One extra attempt by default. A single timeout with no retry turns a momentary
        # blip — a rolling PDP restart — into a denial the user sees and reports.
        for attempt in range(self.config.policy_retries + 1):
            try:
                return self._evaluate_remote(caller, function_name, resources)
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt < self.config.policy_retries:
                    logger.debug("policy_evaluate_retrying", attempt=attempt + 1, error=str(exc))

        logger.warning("policy_evaluate_unreachable", error=str(last_error))
        return self._evaluate_from_snapshot(caller, function_name, resources, reason=str(last_error))

    def _deny_undetermined(self, caller: Principal, function_name: str | None) -> Decision:
        """Refuse a call whose read set could not be established.

        Shadow mode still reports `effect="allow"`: the point of shadow mode is that nothing
        is blocked while rules are being authored, and an extractor that cannot enumerate is
        a fact about the tool rather than about the caller's permissions.
        """
        enforcing = self._enforcing_for(caller, function_name)
        logger.warning("policy_resources_undetermined", function=function_name, subject=caller.subject)
        return Decision(
            decision="deny",
            effect="deny" if enforcing else "allow",
            enforcing=enforcing,
            reason="the resources this call would touch could not be determined",
        )

    def _enforcing_for(self, caller: Principal, function_name: str | None) -> bool:
        """Whether policy is enforcing for this caller, tolerating an unreachable PDP.

        A deny still has to be issued when the backend is down, so an outage here is not
        allowed to turn into an allow: unknown means enforcing.
        """
        try:
            return self._snapshots.get(caller, function_name).enforcing
        except (PolicyUnavailable, httpx.HTTPError):
            return True

    def _prepare_resources(self, resources: Sequence[Resource]) -> Sequence[Resource]:
        """Dedupe, and refuse rather than silently degrade past the PDP's cap.

        Over the cap the PDP answers 400, which reads as an outage and falls back to local
        snapshot evaluation — losing the authoritative decision and its audit row without a
        word to anyone. Deduping first is what keeps a query joining the same table twenty
        times from tripping it.
        """
        deduped = list(dict.fromkeys(resources))
        if len(deduped) > MAX_RESOURCES_PER_CALL:
            logger.error(
                "policy_resource_limit_exceeded",
                count=len(deduped),
                limit=MAX_RESOURCES_PER_CALL,
            )
            raise PolicyDenied(
                f"This call names {len(deduped)} resources, above the decision point's limit "
                f"of {MAX_RESOURCES_PER_CALL}. Refusing rather than deciding on part of it."
            )
        return deduped

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

        # Shared with the snapshot path so the two cannot disagree about what counts as a
        # refusal rather than an outage.
        raise_if_refused(response.status_code, "Policy evaluate")
        if response.status_code >= 400:
            raise httpx.HTTPError(f"Policy evaluate returned HTTP {response.status_code}")

        try:
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
                filters=_filters_from(body.get("resourceDecisions", [])),
            )
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            # A malformed body is neither an `httpx.HTTPError` nor a `PolicyDenied`, so left
            # alone it escapes both the snapshot fallback and every `except PolicyDenied` in
            # tool code — an authorization layer failing *open* through the type system.
            logger.error("policy_evaluate_malformed_response", error=str(exc))
            raise PolicyUnavailable(f"Policy decision point returned an unusable response: {exc}") from exc

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
        filters: list[RowFilter] = []
        for resource in resources:
            effect, rule_id = snapshot.decide_resource(resource.kind, resource.value)
            if effect == "deny":
                denied.append(resource)
                # Report the FIRST denial, matching the backend's evaluator.
                if matched is None:
                    matched = rule_id
                continue

            # Predicates survive the outage too. Without this an unreachable PDP would turn
            # every scoped query into a full-table read — the failure the whole layer exists
            # to prevent, arriving through the fallback rather than through a rule. The
            # backend flattens an unresolvable predicate into a `deny` row, so a caller whose
            # attribute is empty is already handled by the branch above.
            filters.extend(
                RowFilter(
                    resource=resource,
                    column=snapshot_filter.column,
                    operator=snapshot_filter.operator,
                    values=snapshot_filter.values,
                )
                for snapshot_filter in snapshot.filters_for(resource.kind, resource.value)
            )

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
            filters=() if denied else tuple(filters),
        )

    def require(
        self,
        function_name: str | None,
        resources: Sequence[Resource] | _Undetermined = (),
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
        return self._snapshots.get(_resolve_principal(principal), function_name)

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

        Raises `PolicyDenied` when the caller may not invoke the function at all. Filtering
        alone would answer a forbidden call with a (possibly empty) list, which reads as
        "you may list, there is simply nothing here" — a different and false statement.
        """
        snapshot = self.snapshot(function_name, principal=principal)
        if not snapshot.enforcing:
            return list(values)

        if snapshot.call_effect != "allow":
            raise PolicyDenied(
                "Access denied by policy",
                matched_rule_id=snapshot.call_rule_id,
                policy_version=snapshot.version,
            )

        extract = key or (lambda item: item)
        return [item for item in values if snapshot.allows(kind, str(extract(item)))]

    # -- lifecycle ---------------------------------------------------------------

    def invalidate(self) -> None:
        self._snapshots.invalidate()

    def close(self) -> None:
        if self._owns_client:
            self._client.close()


__all__ = [
    "Decision",
    "Guard",
    "PolicyDenied",
    "PolicyUnavailable",
    "Resource",
]
