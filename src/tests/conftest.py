"""Shared fixtures — chiefly a real RSA keypair and a real JWKS endpoint.

The token tests sign and verify actual JWTs rather than monkey-patching `jwt.decode`. A
mocked verifier would pass just as happily against a verifier that checked nothing, which
is exactly the bug worth catching here.
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_guard.config import GuardConfig
from mcp_guard.jwt_verify import reset_jwk_clients

ISSUER = "https://idp.test/realms/demo"
JWKS_URI = f"{ISSUER}/protocol/openid-connect/certs"
KID = "test-key-1"


@pytest.fixture(scope="session")
def keypair() -> tuple[Any, Any]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


@pytest.fixture(scope="session")
def private_pem(keypair) -> bytes:
    private_key, _ = keypair
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture(scope="session")
def jwks_body(keypair) -> str:
    _, public_key = keypair
    numbers = public_key.public_numbers()

    def b64(value: int) -> str:
        import base64

        length = (value.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(value.to_bytes(length, "big")).decode().rstrip("=")

    return json.dumps(
        {"keys": [{"kty": "RSA", "kid": KID, "use": "sig", "alg": "RS256", "n": b64(numbers.n), "e": b64(numbers.e)}]}
    )


@pytest.fixture(autouse=True)
def _serve_jwks(monkeypatch, jwks_body):
    """Serve the in-memory key set and a discovery document instead of reaching the network.

    Patched at `fetch_data` — the seam between "get the bytes" and "verify with them" — so
    everything downstream of it, including signature checking against the real key set, runs
    for real. Discovery is stubbed alongside it so every token test exercises the discovery
    path rather than only the fallback.
    """
    reset_jwk_clients()
    monkeypatch.setattr(
        "jwt.PyJWKClient.fetch_data",
        lambda self: json.loads(jwks_body),
    )
    monkeypatch.setattr(
        "mcp_guard.jwt_verify._fetch_discovery_document",
        lambda issuer, timeout: {"issuer": issuer, "jwks_uri": f"{issuer.rstrip('/')}/protocol/openid-connect/certs"},
    )
    yield
    reset_jwk_clients()


@pytest.fixture
def make_token(private_pem):
    def _make(**overrides: Any) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "sub": "user-a-sub",
            "iss": ISSUER,
            "typ": "Bearer",
            "azp": "open-webui",
            "email": "user-a@example.com",
            "groups": ["/ops-sales"],
            "realm_access": {"roles": ["default-roles-demo"]},
            "iat": now,
            "exp": now + 300,
        }
        claims.update(overrides)
        return jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": KID})

    return _make


@pytest.fixture
def config() -> GuardConfig:
    return GuardConfig(
        require_auth=True,
        issuer=ISSUER,
        audience=None,
        tool_id="tool-mssql",
        policy_url="http://backend.test/api/policy",
        fail_mode="closed",
        stale_max_seconds=300.0,
        snapshot_ttl_seconds=30.0,
        timeout_seconds=5.0,
    )


def snapshot_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "policySetId": "set-1",
        "version": 7,
        "enforcing": True,
        "defaultEffect": "deny",
        "resourceRules": [
            {"kind": "sql_table", "pattern": "dbo.orders*", "effect": "allow", "ruleId": "rule-sales"},
            {"kind": "sql_table", "pattern": "dbo.payroll*", "effect": "deny", "ruleId": "rule-payroll"},
        ],
        "callEffect": "allow",
        "callRuleId": "rule-sales",
    }
    body.update(overrides)
    return body


def mock_transport(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), base_url="http://backend.test")
