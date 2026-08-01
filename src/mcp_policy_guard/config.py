"""Guard configuration, read from the process environment.

The variable names here are a **contract with whatever provisions this server's
environment** — a deployment manifest, a compose file, an orchestrating control plane.
Renaming one on this side silently disables the corresponding control: the provisioner
keeps setting the old name, the guard keeps reading the new one and finds nothing. Change
both together.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal

from .errors import GuardConfigurationError
from .principal import DEFAULT_CALLER_ID_HEADER, DEFAULT_CORRELATION_HEADER

FailMode = Literal["closed", "open"]

# How long a cached snapshot may keep answering after the PDP stops responding. Past this,
# the guard denies. Five minutes is long enough to ride out a backend rollout and short
# enough that a revoked grant does not outlive the coffee break in which it was revoked.
DEFAULT_STALE_MAX_SECONDS = 300.0

# Revalidation interval while the PDP is healthy. Cheap: revalidation is a conditional GET
# that returns 304 with no body whenever policy has not changed.
DEFAULT_SNAPSHOT_TTL_SECONDS = 30.0

DEFAULT_TIMEOUT_SECONDS = 5.0

# Enough for a busy server's working set of concurrent callers, small enough that the cache
# cannot become the reason a long-lived process runs out of memory.
DEFAULT_SNAPSHOT_CACHE_MAX_ENTRIES = 512

# One retry, not three: the PDP call sits in front of every guarded tool call, and a caller
# waiting on a denied query would rather hear "no" than wait out a retry storm.
DEFAULT_POLICY_RETRIES = 1


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("true", "1", "yes", "on")


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise GuardConfigurationError(f"{name} must be a number, got {raw!r}") from exc
    if value < 0:
        raise GuardConfigurationError(f"{name} must not be negative, got {value}")
    return value


def _env_str(name: str) -> str | None:
    raw = os.environ.get(name)
    if raw is None:
        return None
    stripped = raw.strip()
    return stripped or None


def _env_header(name: str, default: str) -> str:
    """A header name from the environment, lowercased.

    ASGI hands header names down lowercased, and the middleware looks them up that way, so
    an override written `X-Trace-Id` would never match anything. Normalizing here rather
    than at every lookup means the mistake is impossible to make.
    """
    return (_env_str(name) or default).lower()


@dataclass(frozen=True)
class GuardConfig:
    """Everything the guard needs, resolved once at startup."""

    require_auth: bool
    issuer: str | None
    audience: str | None
    tool_id: str | None
    policy_url: str | None
    fail_mode: FailMode
    stale_max_seconds: float
    snapshot_ttl_seconds: float
    timeout_seconds: float
    #: Incoming header names, already lowercased. Defaulted so existing construction sites
    #: need no change and so a caller that mints differently-named headers is a config
    #: change rather than a fork.
    correlation_header: str = DEFAULT_CORRELATION_HEADER
    caller_id_header: str = DEFAULT_CALLER_ID_HEADER
    #: Ceiling on cached per-caller snapshots. One entry per (caller, tool, function), so
    #: without a bound the cache grows with every distinct user the process ever serves.
    snapshot_cache_max_entries: int = DEFAULT_SNAPSHOT_CACHE_MAX_ENTRIES
    #: Bounded retries for a PDP call that failed transiently. One timeout with no retry
    #: turns a blip into a user-visible denial.
    policy_retries: int = DEFAULT_POLICY_RETRIES

    @property
    def policy_enabled(self) -> bool:
        """Whether this server has a decision point to consult at all.

        Authentication and authorization are configured independently: a server may verify
        its caller while no PDP is reachable yet. That is the intended intermediate state
        during rollout, and it behaves exactly as the tool did before policy existed.
        """
        return bool(self.policy_url and self.tool_id)

    @property
    def sse_allowed(self) -> bool:
        """Whether the SSE transport may be mounted.

        **False whenever authentication is required, and this is not a configuration knob.**
        The guard authenticates a *request*; under SSE the long-lived connection that
        carried the `Authorization` header is not the request that carries a tool call, so
        the principal established at connect time cannot be attributed to the call. Mounting
        it anyway would leave a second, unauthenticated door into the same tools — the
        precise shape of bug this package exists to remove. A server that needs SSE must run
        without `MCP_REQUIRE_AUTH`, which is a visible choice rather than a silent hole.
        """
        return not self.require_auth

    @classmethod
    def from_env(cls) -> GuardConfig:
        require_auth = _env_bool("MCP_REQUIRE_AUTH")
        issuer = _env_str("MCP_AUTH_ISSUER")

        if require_auth and not issuer:
            raise GuardConfigurationError(
                "MCP_REQUIRE_AUTH is true but MCP_AUTH_ISSUER is unset — the guard has no "
                "JWKS endpoint and could not verify any token. Refusing to start rather "
                "than accept every caller while appearing to enforce."
            )

        raw_fail_mode = (_env_str("MCP_POLICY_FAIL_MODE") or "closed").lower()
        if raw_fail_mode not in ("closed", "open"):
            raise GuardConfigurationError(f"MCP_POLICY_FAIL_MODE must be 'closed' or 'open', got {raw_fail_mode!r}")

        policy_url = (_env_str("MCP_POLICY_URL") or "").rstrip("/") or None
        if policy_url and not require_auth:
            # Authorization without authentication decides nothing: with no verified caller
            # every policy check raises `AuthenticationRequired`, so the tool is either
            # wholly broken or — worse, if a handler catches broadly — wholly open. The
            # operator meant one of the two, and neither is what they get.
            raise GuardConfigurationError(
                "MCP_POLICY_URL is set but MCP_REQUIRE_AUTH is not. Policy is evaluated per "
                "caller, so there is nothing to decide against without authentication. Set "
                "MCP_REQUIRE_AUTH=true, or unset MCP_POLICY_URL to run without policy."
            )

        stale_max_seconds = _env_float("MCP_POLICY_STALE_MAX_SECONDS", DEFAULT_STALE_MAX_SECONDS)
        snapshot_ttl_seconds = _env_float("MCP_POLICY_TTL_SECONDS", DEFAULT_SNAPSHOT_TTL_SECONDS)
        if stale_max_seconds < snapshot_ttl_seconds:
            # A staleness ceiling below the revalidation interval means entries expire before
            # they are ever refreshed: the guard fails closed on every call after the first
            # and reads as a PDP outage that no amount of staring at the PDP explains.
            raise GuardConfigurationError(
                f"MCP_POLICY_STALE_MAX_SECONDS ({stale_max_seconds}) is below "
                f"MCP_POLICY_TTL_SECONDS ({snapshot_ttl_seconds}); cached policy would "
                "expire before it is ever revalidated."
            )

        return cls(
            require_auth=require_auth,
            issuer=issuer,
            audience=_env_str("MCP_AUTH_AUDIENCE"),
            tool_id=_env_str("MCP_TOOL_ID"),
            policy_url=policy_url,
            fail_mode=raw_fail_mode,  # type: ignore[arg-type]
            stale_max_seconds=stale_max_seconds,
            snapshot_ttl_seconds=snapshot_ttl_seconds,
            timeout_seconds=_env_float("MCP_POLICY_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS),
            correlation_header=_env_header("MCP_CORRELATION_HEADER", DEFAULT_CORRELATION_HEADER),
            caller_id_header=_env_header("MCP_CALLER_ID_HEADER", DEFAULT_CALLER_ID_HEADER),
            snapshot_cache_max_entries=int(
                _env_float("MCP_POLICY_CACHE_MAX_ENTRIES", DEFAULT_SNAPSHOT_CACHE_MAX_ENTRIES)
            ),
            policy_retries=int(_env_float("MCP_POLICY_RETRIES", DEFAULT_POLICY_RETRIES)),
        )
