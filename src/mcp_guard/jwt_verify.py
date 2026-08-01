"""OIDC access-token verification.

The signing key set is located by OIDC Discovery, so any standards-compliant issuer works.
The `typ` check below is Keycloak-specific; its reasoning is not self-evident and is
reproduced in full so this file can be reviewed on its own.
"""

from __future__ import annotations

import threading
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


def verify_token(token: str, config: GuardConfig) -> Principal:
    """Verify a bearer token and build the principal it names.

    Raises `AuthenticationRequired` on any failure. The message is deliberately identical
    across causes — expired, wrong issuer, bad signature, wrong token type — because a
    caller learning *why* their token was refused learns about the deployment.
    """
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
