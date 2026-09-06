"""Shared test fixtures for GCP BigQuery MCP Server test suite."""

from __future__ import annotations

import datetime
from typing import Generator
from unittest.mock import MagicMock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from config.settings import SecurityConfig, Settings, ServerConfig
from src.entra_auth import EntraTokenValidator


@pytest.fixture()
def rsa_key_pair():
    """Generate a fresh RSA key pair for JWT signing/verification."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture()
def mock_jwks_client(rsa_key_pair):
    """Create a mock JWKS client pre-loaded with the test public key."""
    _, public_key = rsa_key_pair
    mock_client = MagicMock()
    mock_signing_key = MagicMock()
    mock_signing_key.key = public_key
    mock_client.get_signing_key_from_jwt.return_value = mock_signing_key
    return mock_client


@pytest.fixture()
def security_config():
    """Default SecurityConfig for testing with auth enabled."""
    return SecurityConfig(
        enable_auth=True,
        tenant_id="test-tenant-123",
        client_id="test-client-abc",
        jwks_cache_ttl_seconds=3600,
    )


@pytest.fixture()
def token_validator(security_config, mock_jwks_client):
    """EntraTokenValidator wired to mock JWKS client."""
    return EntraTokenValidator(
        config=security_config,
        jwks_client=mock_jwks_client,
    )


def create_test_token(
    private_key,
    *,
    sub: str = "user-001",
    upn: str = "analyst@company.com",
    aud: str = "test-client-abc",
    iss: str = "https://login.microsoftonline.com/test-tenant-123/v2.0",
    kid: str = "key-1",
    expired: bool = False,
    extra_claims: dict | None = None,
) -> str:
    """Helper to create a signed JWT token for testing."""
    now = datetime.datetime.now(datetime.timezone.utc)
    exp = now - datetime.timedelta(minutes=5) if expired else now + datetime.timedelta(hours=1)

    payload = {
        "sub": sub,
        "upn": upn,
        "aud": aud,
        "iss": iss,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid, "alg": "RS256"})
