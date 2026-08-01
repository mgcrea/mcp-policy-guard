"""Guard exception hierarchy.

Kept in one small module with no imports so every other module can raise these without
creating a cycle.
"""


class GuardError(Exception):
    """Base class for everything this package raises."""


class GuardConfigurationError(GuardError):
    """The guard cannot run as configured.

    Raised at startup, never per request. A misconfigured guard must stop the process
    rather than serve traffic it cannot police — an authorization layer that silently
    disables itself is worse than none, because the operator believes it is on.
    """


class AuthenticationRequired(GuardError):
    """No valid caller identity on a request that requires one.

    Distinct from `PolicyDenied`: this is "I do not know who you are" (HTTP 401), not
    "I know who you are and the answer is no" (a tool-level denial).
    """

    def __init__(self, reason: str = "Missing or invalid bearer token") -> None:
        super().__init__(reason)
        self.reason = reason


class PolicyDenied(GuardError):
    """Policy says no.

    Carries the denied resources so the caller can decide how much to reveal — which is a
    per-tool judgement, not the guard's. A query tool should name the table (the model
    already named it, so there is no oracle to protect, and naming it stops a retry loop);
    a discovery tool must not (see `mcp_guard.policy.Guard.filter_resources`).
    """

    #: False here, True on `PolicyUnavailable`. Lets a tool word its message correctly
    #: without an `isinstance` check against a subclass it would have to import and
    #: remember exists — see that class for why the distinction matters to users.
    is_outage = False

    def __init__(
        self,
        reason: str,
        *,
        resources: tuple[str, ...] = (),
        matched_rule_id: str | None = None,
        policy_version: int | None = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.resources = resources
        self.matched_rule_id = matched_rule_id
        self.policy_version = policy_version


class PolicyUnavailable(PolicyDenied):
    """The decision point could not be reached and no usable cached policy remained.

    A subclass of `PolicyDenied` on purpose. Every `except PolicyDenied` in a tool handler
    therefore also catches an outage, so the fail-closed path cannot be forgotten by a
    caller who only remembered to handle denials.

    But *reporting* it as a denial is wrong: telling a user "you do not have access to
    dbo.orders" during a backend outage sends them to raise an access request for a
    permission they already have. Check `is_outage` when wording the message — the
    fail-closed behaviour is identical either way, only the sentence changes.
    """

    is_outage = True

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
