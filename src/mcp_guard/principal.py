"""The authenticated caller, and the context it travels in."""

from __future__ import annotations

import contextvars
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

# Header carrying the id minted upstream and threaded through every hop of one turn, so an
# audit row here, a trace in the agent runtime and a log line in the calling service can be
# joined. Lowercase because ASGI gives header names lowercased; override with
# `MCP_CORRELATION_HEADER` when the caller mints a differently-named header.
DEFAULT_CORRELATION_HEADER = "x-mcp-correlation-id"

# Identifies the calling agent or service, forwarded by the caller. **Audit only — never a
# policy input.** The caller asserts this value and nothing verifies it, so a policy that
# read it would be taking the word of the party it is meant to constrain. Override with
# `MCP_CALLER_ID_HEADER`.
DEFAULT_CALLER_ID_HEADER = "x-mcp-caller-id"


@dataclass(frozen=True)
class Principal:
    """A caller whose token this process has verified.

    `token` is retained deliberately: the guard forwards it to the decision point so the
    PDP re-verifies the caller itself rather than trusting an identity this server asserts.
    That is what keeps a compromised MCP server from voting on its own permissions.
    """

    subject: str
    token: str = field(repr=False)
    email: str | None = None
    groups: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    client_id: str | None = None

    def fingerprint(self) -> str:
        """A stable cache key for this caller's effective identity.

        Sorted, because a token's `groups` array has no guaranteed order and two orderings
        of one identity must not become two cache entries — or worse, let a lookup miss and
        refetch under a key another caller could collide with.

        Hashed over a JSON encoding rather than joined with separators, because separators
        are forgeable. Joining on `|` and `,` means a caller in group `a,b` produces the same
        key as a caller in groups `a` and `b`: two different identities, one cache entry,
        and whichever arrives second is served the first one's permissions. JSON escapes the
        delimiters instead of trusting them not to appear, so no group name can impersonate
        a structural boundary.
        """
        encoded = json.dumps(
            [self.subject, sorted(self.groups), sorted(self.roles)],
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @classmethod
    def from_claims(cls, claims: dict[str, Any], token: str) -> Principal:
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise ValueError("Token has no subject")

        realm_access = claims.get("realm_access")
        roles: tuple[str, ...] = ()
        if isinstance(realm_access, dict):
            raw_roles = realm_access.get("roles")
            if isinstance(raw_roles, list):
                roles = tuple(str(role) for role in raw_roles)

        raw_groups = claims.get("groups")
        groups = tuple(str(group) for group in raw_groups) if isinstance(raw_groups, list) else ()

        email = claims.get("email")
        azp = claims.get("azp")

        return cls(
            subject=subject,
            token=token,
            email=email if isinstance(email, str) else None,
            groups=groups,
            roles=roles,
            client_id=azp if isinstance(azp, str) else None,
        )


_current_principal: contextvars.ContextVar[Principal | None] = contextvars.ContextVar(
    "mcp_guard_principal", default=None
)
_current_correlation_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "mcp_guard_correlation_id", default=None
)
_current_caller_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("mcp_guard_caller_id", default=None)


def set_principal(principal: Principal | None) -> contextvars.Token[Principal | None]:
    return _current_principal.set(principal)


def reset_principal(token: contextvars.Token[Principal | None]) -> None:
    _current_principal.reset(token)


def current_principal() -> Principal | None:
    """The caller for the current request, or None outside one."""
    return _current_principal.get()


def require_principal() -> Principal:
    """The caller, or raise.

    Tool handlers run several frames and one thread hop away from the middleware that set
    this, so "there is no principal here" is a real possibility that must be a loud error
    rather than a silent `None` flowing into a policy check.
    """
    from .errors import AuthenticationRequired

    principal = _current_principal.get()
    if principal is None:
        raise AuthenticationRequired("No authenticated caller in this context")
    return principal


def set_correlation_id(value: str | None) -> contextvars.Token[str | None]:
    return _current_correlation_id.set(value)


def reset_correlation_id(token: contextvars.Token[str | None]) -> None:
    _current_correlation_id.reset(token)


def current_correlation_id() -> str | None:
    return _current_correlation_id.get()


def set_caller_id(value: str | None) -> contextvars.Token[str | None]:
    return _current_caller_id.set(value)


def reset_caller_id(token: contextvars.Token[str | None]) -> None:
    _current_caller_id.reset(token)


def current_caller_id() -> str | None:
    """The calling agent or service, as it asserted itself. Audit only."""
    return _current_caller_id.get()
