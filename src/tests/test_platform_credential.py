"""The platform's per-request tool credential, against real ES256 signatures.

Same approach as `test_jwt_verify`: real keys, a real key set, real `jwt.decode`. The keys
here are the platform's — an EC P-256 pair served at the platform issuer's own JWKS — beside
the Keycloak RSA pair `conftest` already serves, so every test runs with both issuers live
and proves the two paths do not leak into each other.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import replace
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from mcp_policy_guard.config import GuardConfig
from mcp_policy_guard.errors import AuthenticationRequired, GuardConfigurationError
from mcp_policy_guard.jwt_verify import _jwk_client, _ReplayCache, verify_token

from .conftest import ISSUER, KID

PLATFORM_ISSUER = "http://backend.test/api/tool-credentials"
PLATFORM_JWKS_URI = f"{PLATFORM_ISSUER}/jwks"
PLATFORM_KID = "platform-key-1"
# An RSA key the platform issuer *also* publishes, so the algorithm pin is tested against a
# token that is otherwise perfectly signed by the issuer — not merely one signed by a stranger.
PLATFORM_RSA_KID = "platform-rsa-1"
TOOL_ID = "tool-mssql"


def _pem(private_key: Any) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture(scope="module")
def platform_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="module")
def platform_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(autouse=True)
def _serve_platform_jwks(monkeypatch, jwks_body, platform_key, platform_rsa_key):
    """Serve each issuer its own key set, chosen by the URL the client was built for.

    Layered over `conftest._serve_jwks`, which serves the Keycloak set to every client. Here
    the platform issuer gets a distinct set, so a token can only verify on the path whose
    keys actually signed it.
    """
    ec_jwk = ECAlgorithm.to_jwk(platform_key.public_key(), as_dict=True)
    rsa_jwk = RSAAlgorithm.to_jwk(platform_rsa_key.public_key(), as_dict=True)
    platform_jwks = {
        "keys": [
            {**ec_jwk, "kid": PLATFORM_KID, "use": "sig", "alg": "ES256"},
            {**rsa_jwk, "kid": PLATFORM_RSA_KID, "use": "sig", "alg": "RS256"},
        ]
    }
    keycloak_jwks = json.loads(jwks_body)

    monkeypatch.setattr(
        "jwt.PyJWKClient.fetch_data",
        lambda self: platform_jwks if self.uri == PLATFORM_JWKS_URI else keycloak_jwks,
    )

    def _discovery(issuer: str, timeout: float) -> dict[str, Any]:
        # The platform's discovery document names `<issuer>/jwks`, not Keycloak's layout —
        # which is why the guard must discover it rather than assume the fallback path.
        if issuer == PLATFORM_ISSUER:
            return {"issuer": issuer, "jwks_uri": PLATFORM_JWKS_URI}
        return {"issuer": issuer, "jwks_uri": f"{issuer.rstrip('/')}/protocol/openid-connect/certs"}

    monkeypatch.setattr("mcp_policy_guard.jwt_verify._fetch_discovery_document", _discovery)


@pytest.fixture
def make_credential(platform_key):
    def _make(*, key: Any = None, algorithm: str = "ES256", kid: str = PLATFORM_KID, **overrides: Any) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": PLATFORM_ISSUER,
            "sub": "user-a-sub",
            "email": "user-a@example.com",
            "aud": TOOL_ID,
            "iat": now,
            "exp": now + 120,
            "jti": str(uuid.uuid4()),
            "typ": "Bearer",
            "azp": "chatrgis-credential",
        }
        for name, value in overrides.items():
            if value is _ABSENT:
                claims.pop(name, None)
            else:
                claims[name] = value
        signer = _pem(key if key is not None else platform_key)
        return jwt.encode(claims, signer, algorithm=algorithm, headers={"kid": kid})

    return _make


_ABSENT = object()


@pytest.fixture
def platform_config(config) -> GuardConfig:
    return replace(config, platform_credential_issuer=PLATFORM_ISSUER, tool_id=TOOL_ID)


def _refused(token: str, config: GuardConfig) -> str:
    with pytest.raises(AuthenticationRequired) as caught:
        verify_token(token, config)
    return caught.value.reason


class TestAcceptedCredential:
    def test_verifies_a_well_formed_credential(self, make_credential, platform_config):
        principal = verify_token(make_credential(), platform_config)
        assert principal.subject == "user-a-sub"
        assert principal.email == "user-a@example.com"
        assert principal.client_id == "chatrgis-credential"
        assert principal.kind == "platform_credential"

    def test_carries_no_groups_or_roles(self, make_credential, platform_config):
        # The credential names a user, not their IdP groups: a policy keyed on `idp_group`
        # does not match these callers, and the PDP resolves platform groups from the `sub`.
        principal = verify_token(make_credential(), platform_config)
        assert principal.groups == ()
        assert principal.roles == ()

    def test_retains_the_raw_credential_for_the_pdp(self, make_credential, platform_config):
        # The PDP re-verifies this exact credential rather than trusting the guard's word.
        token = make_credential()
        assert verify_token(token, platform_config).token == token

    def test_discovers_the_platform_key_set(self, make_credential, platform_config):
        verify_token(make_credential(), platform_config)
        assert _jwk_client(PLATFORM_ISSUER, 5.0).uri == PLATFORM_JWKS_URI

    def test_accepts_the_maximum_lifetime(self, make_credential, platform_config):
        now = int(time.time())
        assert verify_token(make_credential(iat=now, exp=now + 300), platform_config).subject == "user-a-sub"


class TestAudience:
    def test_refuses_a_credential_for_another_tool(self, make_credential, platform_config):
        # Signed by the platform, in date, unused — and minted for a different tool. This is
        # the property that keeps one tool's credential worthless at every other.
        _refused(make_credential(aud="tool-postgres"), platform_config)

    def test_refuses_an_audience_list_that_includes_this_tool(self, make_credential, platform_config):
        # A list containing this tool would be one credential good at several. `strict_aud`
        # requires a single string equal to the tool id.
        _refused(make_credential(aud=[TOOL_ID, "tool-postgres"]), platform_config)

    def test_refuses_a_credential_with_no_audience(self, make_credential, platform_config):
        _refused(make_credential(aud=_ABSENT), platform_config)

    def test_refuses_every_credential_when_the_tool_id_is_unset(self, make_credential, platform_config):
        # Nothing to bind `aud` to, so nothing can be accepted — not even a credential whose
        # `aud` happens to be empty or absent.
        unbound = replace(platform_config, tool_id=None)
        _refused(make_credential(), unbound)
        _refused(make_credential(aud=_ABSENT), unbound)

    def test_ignores_mcp_auth_audience(self, make_credential, platform_config):
        # `MCP_AUTH_AUDIENCE` is the Keycloak path's knob. The credential is bound to the tool
        # id, whatever the access-token audience is set to.
        configured = replace(platform_config, audience="rgis-workers")
        assert verify_token(make_credential(), configured).subject == "user-a-sub"


class TestReplay:
    def test_refuses_the_second_use_of_a_credential(self, make_credential, platform_config):
        token = make_credential()
        verify_token(token, platform_config)
        assert _refused(token, platform_config) == "Invalid or expired token"

    def test_a_fresh_credential_for_the_same_user_is_accepted(self, make_credential, platform_config):
        verify_token(make_credential(), platform_config)
        verify_token(make_credential(), platform_config)

    def test_refuses_a_reissued_jti(self, make_credential, platform_config):
        # Re-signed with new times but the same id: still a replay as far as the id goes.
        verify_token(make_credential(jti="fixed"), platform_config)
        _refused(make_credential(jti="fixed"), platform_config)

    def test_a_refused_credential_does_not_spend_its_id(self, make_credential, platform_config):
        # A credential refused for another reason must not poison the id, so that the order
        # of checks never decides whether a later legitimate use goes through.
        _refused(make_credential(jti="shared", aud="tool-postgres"), platform_config)
        verify_token(make_credential(jti="shared"), platform_config)

    def test_concurrent_copies_admit_exactly_one(self, make_credential, platform_config):
        token = make_credential()
        accepted: list[bool] = []
        barrier = threading.Barrier(8)

        def _attempt() -> None:
            barrier.wait()
            try:
                verify_token(token, platform_config)
                accepted.append(True)
            except AuthenticationRequired:
                accepted.append(False)

        threads = [threading.Thread(target=_attempt) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert accepted.count(True) == 1

    def test_refuses_a_credential_with_no_jti(self, make_credential, platform_config):
        _refused(make_credential(jti=_ABSENT), platform_config)

    def test_refuses_an_empty_jti(self, make_credential, platform_config):
        _refused(make_credential(jti=""), platform_config)


class TestReplayCache:
    def test_forgets_an_id_once_it_has_expired(self):
        cache = _ReplayCache()
        assert cache.claim("a", exp=100.0, now=50.0)
        assert not cache.claim("a", exp=100.0, now=99.0)
        # Past `exp` plus the grace, the entry is gone — and the credential itself would
        # already be refused as expired, so forgetting it reopens nothing.
        assert cache.claim("a", exp=200.0, now=106.0)

    def test_remembers_an_id_briefly_past_exp(self):
        # Closes the instant between PyJWT's expiry check and the cache's own clock read.
        cache = _ReplayCache()
        assert cache.claim("a", exp=100.0, now=50.0)
        assert not cache.claim("a", exp=100.0, now=100.5)

    def test_purges_expired_entries_as_it_goes(self):
        cache = _ReplayCache()
        for index in range(10):
            cache.claim(f"old-{index}", exp=100.0, now=50.0)
        cache.claim("new", exp=400.0, now=300.0)
        assert len(cache) == 1


class TestRejectedCredential:
    def test_refuses_a_lifetime_over_five_minutes(self, make_credential, platform_config):
        # Validly signed, in date, unused — and minted to last an hour. That is a standing
        # secret, which is what the per-request design exists to replace.
        now = int(time.time())
        _refused(make_credential(iat=now, exp=now + 301), platform_config)
        _refused(make_credential(iat=now, exp=now + 3600), platform_config)

    def test_refuses_an_rs256_credential_from_the_platform_issuer(
        self, make_credential, platform_config, platform_rsa_key
    ):
        # Signed by a key the platform issuer really publishes, so signature and issuer are
        # both genuine. Only the algorithm pin refuses it.
        token = make_credential(key=platform_rsa_key, algorithm="RS256", kid=PLATFORM_RSA_KID)
        _refused(token, platform_config)

    def test_refuses_a_credential_signed_by_the_keycloak_key(self, platform_config, private_pem):
        # The Keycloak key is trusted — for Keycloak's issuer. Claiming the platform issuer
        # routes the token to the platform's keys, which did not sign it.
        now = int(time.time())
        claims = {
            "iss": PLATFORM_ISSUER,
            "sub": "attacker",
            "aud": TOOL_ID,
            "iat": now,
            "exp": now + 120,
            "jti": "x",
            "typ": "Bearer",
        }
        _refused(jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": KID}), platform_config)

    def test_refuses_a_credential_signed_by_a_stranger(self, make_credential, platform_config):
        stranger = ec.generate_private_key(ec.SECP256R1())
        _refused(make_credential(key=stranger), platform_config)

    def test_refuses_an_expired_credential(self, make_credential, platform_config):
        past = int(time.time()) - 10
        _refused(make_credential(iat=past - 120, exp=past), platform_config)

    def test_refuses_a_credential_issued_in_the_future(self, make_credential, platform_config):
        future = int(time.time()) + 60
        _refused(make_credential(iat=future, exp=future + 120), platform_config)

    @pytest.mark.parametrize("claim", ["exp", "iat", "sub"])
    def test_refuses_a_credential_missing_a_required_claim(self, make_credential, platform_config, claim):
        _refused(make_credential(**{claim: _ABSENT}), platform_config)

    def test_refuses_a_non_access_token_typ(self, make_credential, platform_config):
        _refused(make_credential(typ="ID"), platform_config)

    def test_gives_the_same_message_whatever_the_cause(self, make_credential, platform_config, platform_rsa_key):
        now = int(time.time())
        replayed = make_credential()
        verify_token(replayed, platform_config)
        reasons = {
            _refused(make_credential(aud="tool-postgres"), platform_config),
            _refused(make_credential(iat=now, exp=now + 3600), platform_config),
            _refused(make_credential(key=platform_rsa_key, algorithm="RS256", kid=PLATFORM_RSA_KID), platform_config),
            _refused(replayed, platform_config),
            _refused("garbage", platform_config),
        }
        assert reasons == {"Invalid or expired token"}


class TestIssuerUnset:
    def test_refuses_a_credential_when_the_feature_is_off(self, make_credential, config):
        # With no platform issuer configured the credential is just a token from an issuer
        # the guard does not trust, and takes the access-token path to its refusal.
        assert config.platform_credential_issuer is None
        _refused(make_credential(), config)


class TestKeycloakPathUnchanged:
    """With the platform issuer configured, an access token is treated exactly as before."""

    def test_verifies_an_access_token(self, make_token, platform_config):
        principal = verify_token(make_token(), platform_config)
        assert principal.subject == "user-a-sub"
        assert principal.groups == ("/ops-sales",)
        assert principal.client_id == "open-webui"
        assert principal.kind == "keycloak"

    def test_access_tokens_need_no_jti_and_are_not_replay_checked(self, make_token, platform_config):
        # The replay cache belongs to the credential path. An access token is legitimately
        # presented on every request for its whole lifetime.
        token = make_token()
        verify_token(token, platform_config)
        assert verify_token(token, platform_config).subject == "user-a-sub"

    def test_access_token_audience_is_still_unenforced(self, make_token, platform_config):
        # `aud` = `MCP_TOOL_ID` is the credential's rule. An access token minted for another
        # client must keep working when `MCP_AUTH_AUDIENCE` is unset.
        assert verify_token(make_token(aud="open-webui"), platform_config).subject == "user-a-sub"

    def test_access_token_lifetime_is_not_capped(self, make_token, platform_config):
        now = int(time.time())
        assert verify_token(make_token(iat=now, exp=now + 3600), platform_config).subject == "user-a-sub"

    def test_an_access_token_claiming_the_platform_issuer_is_refused(self, make_token, platform_config):
        # Keycloak-signed, so it would pass the Keycloak path — but `iss` names the platform,
        # whose keys did not sign it.
        _refused(make_token(iss=PLATFORM_ISSUER, aud=TOOL_ID, jti="k"), platform_config)

    def test_a_credential_claiming_the_keycloak_issuer_is_refused(self, make_credential, platform_config):
        # The mirror case: platform-signed, but claiming Keycloak's issuer, so it is checked
        # against Keycloak's keys and refused.
        _refused(make_credential(iss=ISSUER), platform_config)


class TestConfigFromEnv:
    @pytest.fixture(autouse=True)
    def _env(self, monkeypatch):
        for name in ("MCP_POLICY_URL", "MCP_TOOL_ID", "MCP_PLATFORM_CREDENTIAL_ISSUER", "MCP_AUTH_AUDIENCE"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("MCP_REQUIRE_AUTH", "true")
        monkeypatch.setenv("MCP_AUTH_ISSUER", ISSUER)

    def test_reads_the_platform_issuer(self, monkeypatch):
        monkeypatch.setenv("MCP_PLATFORM_CREDENTIAL_ISSUER", PLATFORM_ISSUER)
        monkeypatch.setenv("MCP_TOOL_ID", TOOL_ID)
        assert GuardConfig.from_env().platform_credential_issuer == PLATFORM_ISSUER

    def test_defaults_to_off(self):
        assert GuardConfig.from_env().platform_credential_issuer is None

    def test_refuses_one_issuer_for_both_paths(self, monkeypatch):
        # Every access token would be routed to the credential path and refused.
        monkeypatch.setenv("MCP_PLATFORM_CREDENTIAL_ISSUER", ISSUER)
        with pytest.raises(GuardConfigurationError):
            GuardConfig.from_env()

    def test_starts_without_a_tool_id_and_says_so(self, monkeypatch, captured_audit):
        # Fails closed — every credential is refused — so it is a warning, not a refusal to
        # start that would also take the Keycloak path down.
        monkeypatch.setenv("MCP_PLATFORM_CREDENTIAL_ISSUER", PLATFORM_ISSUER)
        config = GuardConfig.from_env()
        assert config.tool_id is None
        assert any(entry.get("event") == "platform_credential_without_tool_id" for entry in captured_audit)


class TestThroughTheMiddleware:
    """The credential as a real request carries it: one HTTP request, one credential."""

    async def test_serves_a_credential_once_and_refuses_the_copy(self, make_credential, platform_config):
        from mcp_policy_guard.middleware import GuardMiddleware

        from .test_middleware import RecordingApp, call

        app = RecordingApp()
        middleware = GuardMiddleware(app, platform_config)
        headers = {"Authorization": f"Bearer {make_credential()}"}

        status, _, _ = await call(middleware, headers)
        assert status == 200
        assert app.subject == "user-a-sub"

        status, body, _ = await call(middleware, headers)
        assert status == 401
        # Same body as any other refusal, and the tool never runs a second time.
        assert json.loads(body) == {"error": "unauthorized", "reason": "Invalid or expired token"}
        assert app.calls == 1


class TestAudit:
    def test_records_the_principal_kind(self, make_credential, make_token, platform_config, captured_audit):
        from mcp_policy_guard.audit import emit
        from mcp_policy_guard.principal import set_principal

        for principal in (
            verify_token(make_credential(), platform_config),
            verify_token(make_token(), platform_config),
        ):
            set_principal(principal)
            try:
                emit("tool_call", tool="mssql_query", decision="allow")
            finally:
                set_principal(None)

        records = [entry for entry in captured_audit if entry.get("tool") == "mssql_query"]
        assert [r["principal_kind"] for r in records] == ["platform_credential", "keycloak"]
        assert records[0]["client_id"] == "chatrgis-credential"
