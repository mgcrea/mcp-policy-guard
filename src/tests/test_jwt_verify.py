"""Token verification, against real signatures."""

from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_guard.errors import AuthenticationRequired
from mcp_guard.jwt_verify import _jwk_client, verify_token

from .conftest import ISSUER, JWKS_URI, KID


class TestAcceptedTokens:
    def test_verifies_a_well_formed_access_token(self, make_token, config):
        principal = verify_token(make_token(), config)
        assert principal.subject == "user-a-sub"
        assert principal.email == "user-a@example.com"
        assert principal.client_id == "open-webui"

    def test_lifts_groups_and_realm_roles_into_the_principal(self, make_token, config):
        token = make_token(
            groups=["/ops-sales", "/ops-payroll"],
            realm_access={"roles": ["analyst", "default-roles-demo"]},
        )
        principal = verify_token(token, config)
        assert principal.groups == ("/ops-sales", "/ops-payroll")
        assert principal.roles == ("analyst", "default-roles-demo")

    def test_accepts_a_token_with_no_typ_claim(self, make_token, config):
        # `typ` is a Keycloak convention, not an RFC 9068 guarantee, and this guard verifies
        # tokens minted for several clients. Absent is allowed; wrong is not.
        token = make_token()
        claims = jwt.decode(token, options={"verify_signature": False})
        del claims["typ"]
        assert verify_token(_resign(claims), config).subject == "user-a-sub"

    def test_retains_the_raw_token_for_forwarding(self, make_token, config):
        token = make_token()
        # The PDP re-verifies the caller itself rather than trusting this server's word,
        # which is only possible because the original token is kept.
        assert verify_token(token, config).token == token

    def test_tolerates_a_missing_groups_claim(self, make_token, config):
        claims = jwt.decode(make_token(), options={"verify_signature": False})
        del claims["groups"]
        assert verify_token(_resign(claims), config).groups == ()


class TestRejectedTokens:
    def test_rejects_an_id_token(self, make_token, config):
        # Same realm, same signing key, same subject — so signature and issuer both pass.
        # Only the `typ` payload claim separates it from an access token, and ID tokens sit
        # in browser storage where a leak is far more likely.
        with pytest.raises(AuthenticationRequired):
            verify_token(make_token(typ="ID"), config)

    def test_rejects_a_refresh_token(self, make_token, config):
        with pytest.raises(AuthenticationRequired):
            verify_token(make_token(typ="Refresh"), config)

    def test_rejects_an_expired_token(self, make_token, config):
        past = int(time.time()) - 60
        with pytest.raises(AuthenticationRequired):
            verify_token(make_token(exp=past, iat=past - 300), config)

    def test_rejects_a_token_from_another_issuer(self, make_token, config):
        with pytest.raises(AuthenticationRequired):
            verify_token(make_token(iss="https://evil.test/realms/demo"), config)

    def test_rejects_a_token_signed_by_another_key(self, config):
        # The whole point of JWKS verification: a syntactically perfect token whose
        # signature the realm did not produce.
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = other.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        now = int(time.time())
        forged = jwt.encode(
            {"sub": "attacker", "iss": ISSUER, "typ": "Bearer", "iat": now, "exp": now + 300},
            pem,
            algorithm="RS256",
            headers={"kid": KID},
        )
        with pytest.raises(AuthenticationRequired):
            verify_token(forged, config)

    def test_rejects_an_unsigned_token(self, config):
        now = int(time.time())
        none_token = jwt.encode(
            {"sub": "attacker", "iss": ISSUER, "typ": "Bearer", "iat": now, "exp": now + 300},
            key="",
            algorithm="none",
        )
        with pytest.raises(AuthenticationRequired):
            verify_token(none_token, config)

    def test_rejects_a_token_with_no_subject(self, make_token, config):
        claims = jwt.decode(make_token(), options={"verify_signature": False})
        del claims["sub"]
        with pytest.raises(AuthenticationRequired):
            verify_token(_resign(claims), config)

    def test_rejects_garbage(self, config):
        with pytest.raises(AuthenticationRequired):
            verify_token("not-a-jwt", config)

    def test_gives_the_same_message_whatever_the_cause(self, make_token, config):
        # A caller who learns *why* their token was refused learns about the deployment.
        messages = set()
        for token in (make_token(typ="ID"), make_token(iss="https://evil.test"), "garbage"):
            try:
                verify_token(token, config)
            except AuthenticationRequired as exc:
                messages.add(exc.reason)
        assert messages == {"Invalid or expired token"}


class TestAudience:
    def test_enforces_audience_when_one_is_configured(self, make_token, config):
        configured = _with(config, audience="example-api")
        with pytest.raises(AuthenticationRequired):
            verify_token(make_token(aud="something-else"), configured)

    def test_accepts_the_configured_audience(self, make_token, config):
        configured = _with(config, audience="example-api")
        assert verify_token(make_token(aud="example-api"), configured).subject == "user-a-sub"

    def test_ignores_audience_when_none_is_configured(self, make_token, config):
        # MCP_AUTH_AUDIENCE is normally left unset, because an issuer serving several
        # clients mints tokens with different audiences that must all be accepted.
        assert verify_token(make_token(aud="open-webui"), config).subject == "user-a-sub"


class TestDiscovery:
    """The JWKS endpoint is located by OIDC discovery, so any compliant issuer works."""

    def test_uses_the_discovered_jwks_uri(self, monkeypatch, make_token, config):
        monkeypatch.setattr(
            "mcp_guard.jwt_verify._fetch_discovery_document",
            lambda issuer, timeout: {"issuer": issuer, "jwks_uri": "https://idp.test/custom/keys"},
        )
        assert verify_token(make_token(), config).subject == "user-a-sub"
        assert _jwk_client(ISSUER, 5.0).uri == "https://idp.test/custom/keys"

    def test_falls_back_when_discovery_is_unreachable(self, monkeypatch, make_token, config):
        # An issuer that serves no discovery document must keep working rather than take
        # the server down at first verify.
        monkeypatch.setattr("mcp_guard.jwt_verify._fetch_discovery_document", lambda issuer, timeout: None)
        assert verify_token(make_token(), config).subject == "user-a-sub"
        assert _jwk_client(ISSUER, 5.0).uri == JWKS_URI

    def test_refuses_a_document_that_names_another_issuer(self, monkeypatch, make_token, config):
        # Without this check, whatever could influence the discovery response would get to
        # nominate the key set this process trusts — which is the whole game.
        monkeypatch.setattr(
            "mcp_guard.jwt_verify._fetch_discovery_document",
            lambda issuer, timeout: {"issuer": "https://evil.test", "jwks_uri": "https://evil.test/keys"},
        )
        assert verify_token(make_token(), config).subject == "user-a-sub"
        assert _jwk_client(ISSUER, 5.0).uri == JWKS_URI

    def test_falls_back_when_the_document_has_no_jwks_uri(self, monkeypatch, make_token, config):
        monkeypatch.setattr(
            "mcp_guard.jwt_verify._fetch_discovery_document",
            lambda issuer, timeout: {"issuer": issuer},
        )
        assert verify_token(make_token(), config).subject == "user-a-sub"
        assert _jwk_client(ISSUER, 5.0).uri == JWKS_URI

    def test_discovers_once_per_issuer(self, monkeypatch, make_token, config):
        # Resolution sits behind the client cache, so a hot path of tool calls does not
        # turn every signature check into two network round trips.
        calls: list[str] = []

        def _record(issuer, timeout):
            calls.append(issuer)
            return {"issuer": issuer, "jwks_uri": JWKS_URI}

        monkeypatch.setattr("mcp_guard.jwt_verify._fetch_discovery_document", _record)
        verify_token(make_token(), config)
        verify_token(make_token(), config)
        assert calls == [ISSUER]


_RESIGN_PEM: bytes | None = None


@pytest.fixture(autouse=True)
def _capture_pem(private_pem):
    global _RESIGN_PEM
    _RESIGN_PEM = private_pem
    yield


def _resign(claims: dict) -> str:
    assert _RESIGN_PEM is not None
    return jwt.encode(claims, _RESIGN_PEM, algorithm="RS256", headers={"kid": KID})


def _with(config, **overrides):
    from dataclasses import replace

    return replace(config, **overrides)
