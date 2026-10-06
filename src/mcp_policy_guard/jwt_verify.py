"""OIDC access-token verification.

The signing key set is located by OIDC Discovery, so any standards-compliant issuer works.
The `typ` check below is Keycloak-specific; its reasoning is not self-evident and is
reproduced in full so this file can be reviewed on its own.

Two kinds of bearer are accepted, told apart by their unverified `iss` and then verified on
entirely separate paths: an access token from `MCP_AUTH_ISSUER`, and — only when
`MCP_PLATFORM_CREDENTIAL_ISSUER` is set — the platform's per-request tool credential. The
second exists for callers who hold no session at the identity provider and so have no access
token to forward; the platform vouches for them instead, one request and one tool at a time.
"""

from __future__ import annotations

import heapq
import threading
import time
from typing import Any

import httpx
import jwt
import structlog
from jwt import PyJWKClient

from .config import GuardConfig
from .errors import AuthenticationRequired
from .principal import Principal

logger = structlog.get_logger()

# JWKS keys are cached by PyJWKClient for this long.
_JWKS_LIFESPAN_SECONDS = 3600

# Where an issuer that predates or ignores discovery keeps its key set. Keycloak's layout,
# used only when discovery does not answer usably.
_FALLBACK_JWKS_PATH = "/protocol/openid-connect/certs"

_clients: dict[str, PyJWKClient] = {}
_clients_lock = threading.Lock()

# The one message every refusal carries. See `verify_token` for why it never varies.
_REFUSED = "Invalid or expired token"

# The platform mints credentials that live 120 s. Anything claiming longer than this was not
# minted by the code this guard was written against, and a long-lived credential is exactly
# the "one fixed secret" shape the per-request design exists to replace — so it is refused
# even when its signature is good. Generous enough to absorb a deliberate bump on the
# platform side without a lockstep guard release.
PLATFORM_CREDENTIAL_MAX_LIFETIME_SECONDS = 300

# How long past `exp` a spent `jti` is remembered. PyJWT and the replay cache each read the
# clock separately, so a replay arriving in the instant between PyJWT's "not yet expired"
# and the cache's purge would find the original entry gone and be accepted. A token past
# `exp` is refused by signature verification anyway, so remembering a little longer costs a
# few entries and closes the gap.
_REPLAY_GRACE_SECONDS = 5.0


def _fetch_discovery_document(issuer: str, timeout: float) -> dict[str, Any] | None:
    """`GET {issuer}/.well-known/openid-configuration`, or None if it cannot be read.

    A module-level function rather than an inline request so tests have a seam to stand in
    front of, the same way they stand in front of `PyJWKClient.fetch_data`.
    """
    url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    try:
        response = httpx.get(url, timeout=timeout)
        response.raise_for_status()
        document = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("oidc_discovery_failed", url=url, error=str(exc))
        return None
    return document if isinstance(document, dict) else None


def _resolve_jwks_uri(issuer: str, timeout: float) -> str:
    """The issuer's JWKS endpoint, discovered if possible.

    The document's own `issuer` must equal the configured one. That check is what makes
    discovery safe to trust: without it, anything that could influence the response would
    get to nominate the key set this process verifies signatures against, which is the
    whole game. On any doubt — unreachable, malformed, mismatched, no `jwks_uri` — fall
    back to the well-known path rather than failing startup, so an issuer that serves no
    discovery document keeps working.
    """
    document = _fetch_discovery_document(issuer, timeout)
    fallback = f"{issuer.rstrip('/')}{_FALLBACK_JWKS_PATH}"

    if document is None:
        return fallback

    declared = document.get("issuer")
    if declared != issuer:
        logger.warning("oidc_discovery_issuer_mismatch", configured=issuer, declared=declared)
        return fallback

    jwks_uri = document.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri:
        logger.warning("oidc_discovery_missing_jwks_uri", issuer=issuer)
        return fallback

    return jwks_uri


def _jwk_client(issuer: str, timeout: float) -> PyJWKClient:
    """One JWKS client per issuer, shared across threads.

    Tool handlers run in `asyncio.to_thread`, so this is reached concurrently from the
    thread pool. Building a client per call would refetch the key set on every request and
    turn a signature check into a network round trip.

    Discovery happens under the lock on purpose: it makes a burst of concurrent
    first-verifies collapse into one discovery request instead of one per thread, at the
    cost of briefly serializing them.
    """
    with _clients_lock:
        client = _clients.get(issuer)
        if client is None:
            url = _resolve_jwks_uri(issuer, timeout)
            client = PyJWKClient(url, lifespan=_JWKS_LIFESPAN_SECONDS)
            _clients[issuer] = client
            logger.info("jwks_client_initialized", jwks_url=url)
        return client


def reset_jwk_clients() -> None:
    """Test-only: drop cached JWKS clients, and with them the resolved JWKS URIs."""
    with _clients_lock:
        _clients.clear()


def _assert_bearer_token(claims: dict[str, Any]) -> None:
    """Reject a token that identifies itself as something other than an access token.

    `aud` often cannot be enforced: where one issuer serves several clients, tokens arrive
    minted for different audiences and `MCP_AUTH_AUDIENCE` has to be left unset. Signature
    and issuer are then nearly the whole check, and an **ID token** satisfies both: same
    issuer, same signing key, same subject. ID tokens are handed to browsers and routinely
    sit in web storage, so treating one as a bearer widens the blast radius of any
    client-side leak for no benefit.

    Keycloak distinguishes them with a `typ` **payload claim** — "Bearer" for access tokens,
    "ID" for id tokens, "Refresh" for refresh tokens. This is not the JOSE *header* `typ`,
    which is set to "JWT" on every token; pinning it there would reject everything.

    Absent `typ` is allowed: the claim is a Keycloak convention rather than something RFC
    9068 guarantees, so issuers that omit it must still be able to authenticate.
    """
    typ = claims.get("typ")
    if isinstance(typ, str) and typ.lower() != "bearer":
        logger.warning("rejected_non_access_token", typ=typ)
        raise AuthenticationRequired("Invalid or expired token")


class _ReplayCache:
    """Credential ids (`jti`) already accepted by this process, each kept until it expires.

    A platform credential is a bearer: anything that sees it in flight — a proxy log, a
    debugging dump, a compromised hop — could otherwise present it again for the rest of its
    lifetime. Accepting each `jti` once is what makes "signed per request" true at the
    receiving end rather than only at the minting end.

    **Per process, by design and with a known limit.** A replica — or a second uvicorn worker
    — keeps its own set, so a stolen credential replayed at a *different* process inside its
    120 s is accepted once there. It is still bound to this one tool by `aud` and to that
    window by `exp`; closing it fully needs shared state this library does not want to own.

    **Unbounded on purpose.** An entry is only ever added for a credential whose signature
    already verified, so the size is set by how fast the platform mints for this tool, times
    the lifetime — not by anything a caller controls. Evicting a live entry to save memory
    would silently reopen replay for it, which is the one thing this exists to prevent.

    Thread-safe: verification runs on the thread pool (`anyio.to_thread`), and two copies of
    one credential arriving together is precisely the race that must not admit both.
    """

    def __init__(self) -> None:
        self._seen: set[str] = set()
        # (forget_at, jti), so the soonest-to-expire is always at the front and a purge
        # touches only what it removes.
        self._expiries: list[tuple[float, str]] = []
        self._lock = threading.Lock()

    def claim(self, jti: str, exp: float, now: float | None = None) -> bool:
        """Record `jti` as spent. False if it already was — a replay."""
        current = time.time() if now is None else now
        with self._lock:
            while self._expiries and self._expiries[0][0] <= current:
                _, expired = heapq.heappop(self._expiries)
                self._seen.discard(expired)
            if jti in self._seen:
                return False
            self._seen.add(jti)
            heapq.heappush(self._expiries, (exp + _REPLAY_GRACE_SECONDS, jti))
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()
            self._expiries.clear()


_replay_cache = _ReplayCache()


def reset_replay_cache() -> None:
    """Test-only: forget every spent credential id."""
    _replay_cache.clear()


def _unverified_issuer(token: str) -> str | None:
    """The token's `iss`, read **without** checking anything — used only to choose a path.

    Safe because nothing is trusted on the strength of it: each path then verifies the
    signature against *its own* issuer's keys and pins `iss` again. A token lying about its
    issuer just walks down a path whose keys did not sign it. Anything unreadable returns
    None and takes the access-token path, where it fails exactly as it always has.
    """
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.exceptions.PyJWTError:
        return None
    issuer = claims.get("iss")
    return issuer if isinstance(issuer, str) else None


def _verify_platform_credential(token: str, config: GuardConfig, issuer: str) -> Principal:
    """Verify a platform tool credential: short-lived, bound to this tool, usable once.

    Stricter than the access-token path on every axis, because it is meant to be:

    - **ES256 only.** The platform signs with one key of one type. An access token's broader
      list exists to accommodate an issuer we do not control; this one we do, and every
      extra algorithm is surface for an algorithm-confusion bug and nothing else.
    - **`aud` is required and must be exactly `MCP_TOOL_ID`** (`strict_aud`: a string, not a
      list containing it). That is what makes a credential for one tool worthless at
      another. `MCP_AUTH_AUDIENCE` plays no part — it exists because Keycloak `aud` varies
      by client, which is not true here. No tool id means nothing to bind to, so refuse.
    - **`exp`, `iat`, `jti` required, and `exp - iat` at most 300 s.** A credential that
      outlives minutes is the fixed secret this design replaces.
    - **Each `jti` accepted once** per process; see `_ReplayCache`.

    The principal carries no groups or roles: the credential has none to give, so a policy
    keyed on IdP groups will not match these callers. The PDP resolves platform groups and
    attributes from the `sub` itself when it re-verifies the credential.
    """
    if not config.tool_id:
        logger.warning("platform_credential_without_tool_id")
        raise AuthenticationRequired(_REFUSED)

    try:
        signing_key = _jwk_client(issuer, config.timeout_seconds).get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["ES256"],
            issuer=issuer,
            audience=config.tool_id,
            options={"strict_aud": True, "require": ["exp", "iat", "jti", "aud", "iss", "sub"]},
        )
    except jwt.exceptions.PyJWTError as exc:
        logger.warning("platform_credential_verification_failed", error=str(exc))
        raise AuthenticationRequired(_REFUSED) from exc

    # PyJWT has already refused a non-integer `exp`/`iat`, so these conversions cannot fail.
    exp, iat = int(claims["exp"]), int(claims["iat"])
    if exp - iat > PLATFORM_CREDENTIAL_MAX_LIFETIME_SECONDS:
        logger.warning("platform_credential_lifetime_too_long", lifetime=exp - iat)
        raise AuthenticationRequired(_REFUSED)

    jti = claims["jti"]
    if not isinstance(jti, str) or not jti:
        logger.warning("platform_credential_invalid_jti")
        raise AuthenticationRequired(_REFUSED)

    _assert_bearer_token(claims)

    try:
        principal = Principal.from_claims(claims, token, kind="platform_credential")
    except ValueError as exc:
        logger.warning("token_missing_subject")
        raise AuthenticationRequired(_REFUSED) from exc

    # Last, so only a credential that is otherwise acceptable is ever recorded. That keeps
    # the cache's size a function of what the platform mints for this tool, which is the
    # bound `_ReplayCache` relies on in place of an eviction policy.
    if not _replay_cache.claim(jti, exp):
        logger.warning("platform_credential_replayed", jti=jti, subject=principal.subject)
        raise AuthenticationRequired(_REFUSED)

    logger.debug("platform_credential_accepted", jti=jti, subject=principal.subject, client_id=principal.client_id)
    return principal


def verify_token(token: str, config: GuardConfig) -> Principal:
    """Verify a bearer token and build the principal it names.

    Raises `AuthenticationRequired` on any failure. The message is deliberately identical
    across causes — expired, wrong issuer, bad signature, wrong token type, a replayed
    credential — because a caller learning *why* their token was refused learns about the
    deployment.

    With `platform_credential_issuer` unset this is exactly the access-token check it has
    always been; the token is not even peeked at.
    """
    platform_issuer = config.platform_credential_issuer
    if platform_issuer and _unverified_issuer(token) == platform_issuer:
        return _verify_platform_credential(token, config, platform_issuer)

    if not config.issuer:
        raise AuthenticationRequired("Guard has no issuer configured")

    try:
        signing_key = _jwk_client(config.issuer, config.timeout_seconds).get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384"],
            issuer=config.issuer,
            audience=config.audience,
            # Audience is only checked when one is configured, since access-token `aud`
            # varies by client on issuers that serve more than one.
            options={"verify_aud": config.audience is not None, "require": ["exp", "iat"]},
        )
    except jwt.exceptions.PyJWTError as exc:
        logger.warning("token_verification_failed", error=str(exc))
        raise AuthenticationRequired("Invalid or expired token") from exc

    _assert_bearer_token(claims)

    try:
        return Principal.from_claims(claims, token)
    except ValueError as exc:
        logger.warning("token_missing_subject")
        raise AuthenticationRequired("Invalid or expired token") from exc
