"""Unit and integration tests for Inbound Gateway Authentication and SSO user identity forwarding."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest
from pydantic import SecretStr
from starlette.testclient import TestClient

from config.settings import GatewayAuthConfig, Settings, load_settings
from src.auth import GatewayAuthMiddleware, current_user_email
from src.client import BigQueryClientManager
from src.server import create_app


@pytest.fixture
def mock_settings_auth_disabled():
    """Settings fixture with gateway_auth explicitly disabled."""
    settings = load_settings()
    settings.gateway_auth.enabled = False
    return settings


@pytest.fixture
def mock_settings_auth_enabled():
    """Settings fixture with gateway_auth enabled with a test secret."""
    settings = load_settings()
    settings.gateway_auth.enabled = True
    settings.gateway_auth.header_name = "X-Hawkeye-Key"
    settings.gateway_auth.secret_key = SecretStr("test-hawkeye-secret-12345")
    settings.gateway_auth.user_email_header = "X-User-Email"
    return settings


class TestGatewayAuthMiddleware:
    """Test suite for GatewayAuthMiddleware."""

    def test_auth_disabled_allows_all_requests(self, mock_settings_auth_disabled):
        """When gateway_auth.enabled is False, requests should succeed without any key."""
        app = create_app(settings=mock_settings_auth_disabled)
        with TestClient(app) as client:
            # Health check succeeds
            r_health = client.get("/health")
            assert r_health.status_code == 200

            # Root succeeds
            r_root = client.get("/")
            assert r_root.status_code == 200

    def test_exempt_endpoints_bypass_auth_when_enabled(self, mock_settings_auth_enabled):
        """Endpoints /health, /healthz, and / must bypass auth even when enabled."""
        app = create_app(settings=mock_settings_auth_enabled)
        with TestClient(app) as client:
            r1 = client.get("/health")
            assert r1.status_code == 200

            r2 = client.get("/healthz")
            assert r2.status_code == 200

            r3 = client.get("/")
            assert r3.status_code == 200

    def test_cors_options_preflight_bypasses_auth(self, mock_settings_auth_enabled):
        """HTTP OPTIONS requests (CORS preflight) must bypass authentication."""
        app = create_app(settings=mock_settings_auth_enabled)
        with TestClient(app) as client:
            resp = client.options("/mcp", headers={"Origin": "https://example.com"})
            # Should not be rejected with 401
            assert resp.status_code != 401

    def test_auth_enabled_rejects_missing_key(self, mock_settings_auth_enabled):
        """Requests without the configured secret key header must be rejected with 401."""
        app = create_app(settings=mock_settings_auth_enabled)
        with TestClient(app) as client:
            resp = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            assert resp.status_code == 401
            body = resp.json()
            assert body["error"] == "Unauthorized"
            assert "X-Hawkeye-Key" in body["detail"]
            assert "WWW-Authenticate" in resp.headers

    def test_auth_enabled_rejects_invalid_key(self, mock_settings_auth_enabled):
        """Requests with an incorrect secret key must be rejected with 401."""
        app = create_app(settings=mock_settings_auth_enabled)
        with TestClient(app) as client:
            resp = client.post(
                "/mcp",
                headers={"X-Hawkeye-Key": "wrong-secret-key"},
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            )
            assert resp.status_code == 401
            body = resp.json()
            assert body["error"] == "Unauthorized"

    def test_auth_enabled_accepts_valid_header_key(self, mock_settings_auth_enabled):
        """Requests with the correct secret key must pass through authentication."""
        app = create_app(settings=mock_settings_auth_enabled)
        with TestClient(app) as client:
            resp = client.post(
                "/mcp",
                headers={
                    "X-Hawkeye-Key": "test-hawkeye-secret-12345",
                    "Accept": "application/json, text/event-stream",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "test-client", "version": "1.0"},
                    },
                },
            )
            # The request must reach the FastMCP endpoint (status 200 or 202, NOT 401)
            assert resp.status_code in (200, 202)

    def test_auth_enabled_accepts_bearer_token_fallback(self, mock_settings_auth_enabled):
        """Requests passing the secret key as Authorization: Bearer <key> should be accepted."""
        app = create_app(settings=mock_settings_auth_enabled)
        with TestClient(app) as client:
            resp = client.post(
                "/mcp",
                headers={
                    "Authorization": "Bearer test-hawkeye-secret-12345",
                    "Accept": "application/json, text/event-stream",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "test-client", "version": "1.0"},
                    },
                },
            )
            assert resp.status_code in (200, 202)

    def test_fail_closed_when_secret_not_configured(self):
        """When auth is enabled but secret_key is empty/None, server must fail closed with 500."""
        settings = load_settings()
        settings.gateway_auth.enabled = True
        settings.gateway_auth.secret_key = None

        app = create_app(settings=settings)
        with TestClient(app) as client:
            resp = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
            assert resp.status_code == 500
            body = resp.json()
            assert body["error"] == "Server Configuration Error"

    def test_custom_header_names(self):
        """Custom header names for auth key and user email should be respected."""
        settings = load_settings()
        settings.gateway_auth.enabled = True
        settings.gateway_auth.header_name = "X-Custom-Auth-Secret"
        settings.gateway_auth.secret_key = SecretStr("custom-secret-777")
        settings.gateway_auth.user_email_header = "X-Custom-User-Email"

        app = create_app(settings=settings)
        with TestClient(app) as client:
            # Missing custom header -> 401
            r_fail = client.post("/mcp", headers={"X-Hawkeye-Key": "custom-secret-777"})
            assert r_fail.status_code == 401

            # Valid custom header -> passes auth
            r_ok = client.post(
                "/mcp",
                headers={
                    "X-Custom-Auth-Secret": "custom-secret-777",
                    "X-Custom-User-Email": "alice@company.com",
                    "Accept": "application/json, text/event-stream",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "test-client", "version": "1.0"},
                    },
                },
            )
            assert r_ok.status_code in (200, 202)


class TestUserEmailPropagationAndJobLabels:
    """Test suite for SSO user identity propagation and BigQuery job label tagging."""

    def test_user_email_injected_into_bigquery_job_labels(self):
        """When an authenticated user email is present in context, it must be added to job labels."""
        settings = load_settings()
        manager = BigQueryClientManager(config=settings.bigquery)

        # Set user email in contextvar
        token = current_user_email.set("jane.doe@company.com")
        try:
            labels = manager.build_job_labels()
            assert "user_email" in labels
            # Value must be sanitized for BigQuery label regex ^[a-z0-9_-]+$
            assert labels["user_email"] == "jane_doe_company_com"
            assert labels["bq_mcp_ext"] == "true"
        finally:
            current_user_email.reset(token)

    def test_user_email_not_present_when_contextvar_empty(self):
        """When no user email is in context, user_email label is not added."""
        settings = load_settings()
        manager = BigQueryClientManager(config=settings.bigquery)

        token = current_user_email.set(None)
        try:
            labels = manager.build_job_labels()
            assert "user_email" not in labels
            assert labels["bq_mcp_ext"] == "true"
        finally:
            current_user_email.reset(token)


class TestGatewayAuthConfigEnvOverrides:
    """Test environment variable overrides for GatewayAuthConfig."""

    def test_env_variable_overrides(self):
        env = {
            "GATEWAY_AUTH_ENABLED": "true",
            "GATEWAY_AUTH_HEADER_NAME": "X-Custom-Key",
            "HAWKEYE_INTERNAL_SECRET": "secret-from-env-999",
            "GATEWAY_AUTH_USER_EMAIL_HEADER": "X-Forwarded-Email",
        }
        with patch.dict(os.environ, env):
            settings = load_settings()
            assert settings.gateway_auth.enabled is True
            assert settings.gateway_auth.header_name == "X-Custom-Key"
            assert settings.gateway_auth.secret_key.get_secret_value() == "secret-from-env-999"
            assert settings.gateway_auth.user_email_header == "X-Forwarded-Email"


class TestAuthRateLimiterIdentityPropagation:
    """Integration tests: SSO user email propagates from auth middleware to rate limiter."""

    def _make_settings(self):
        """Create settings with auth enabled and a tight rate limit for testing."""
        settings = load_settings()
        settings.gateway_auth.enabled = True
        settings.gateway_auth.header_name = "X-Hawkeye-Key"
        settings.gateway_auth.secret_key = SecretStr("integration-test-key-42")
        settings.gateway_auth.user_email_header = "X-User-Email"
        settings.rate_limit.enabled = True
        settings.rate_limit.requests_per_minute = 2
        settings.rate_limit.window_seconds = 60
        return settings

    def test_authenticated_users_rate_limited_by_email_not_ip(self):
        """Two different SSO users behind the same IP should have independent rate limits."""
        from src.rate_limiter import RateLimiter

        settings = self._make_settings()
        rate_limiter = RateLimiter(requests_per_minute=2, window_seconds=60)
        app = create_app(settings=settings, rate_limiter=rate_limiter)

        mcp_body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"},
            },
        }

        with TestClient(app) as client:
            # User A exhausts their 2-request limit
            for _ in range(2):
                resp = client.post(
                    "/mcp",
                    headers={
                        "X-Hawkeye-Key": "integration-test-key-42",
                        "X-User-Email": "alice@company.com",
                        "Accept": "application/json, text/event-stream",
                    },
                    json=mcp_body,
                )
                assert resp.status_code in (200, 202)

            # User A's 3rd request should be rate-limited
            resp_blocked = client.post(
                "/mcp",
                headers={
                    "X-Hawkeye-Key": "integration-test-key-42",
                    "X-User-Email": "alice@company.com",
                    "Accept": "application/json, text/event-stream",
                },
                json=mcp_body,
            )
            assert resp_blocked.status_code == 429

            # User B (different email, same "IP") should NOT be blocked
            resp_user_b = client.post(
                "/mcp",
                headers={
                    "X-Hawkeye-Key": "integration-test-key-42",
                    "X-User-Email": "bob@company.com",
                    "Accept": "application/json, text/event-stream",
                },
                json=mcp_body,
            )
            assert resp_user_b.status_code in (200, 202)

    def test_unauthenticated_falls_back_to_ip_rate_limit(self):
        """When auth is disabled, rate limiting should fall back to IP-based keys."""
        from src.rate_limiter import RateLimiter

        settings = load_settings()
        settings.gateway_auth.enabled = False
        settings.rate_limit.enabled = True
        settings.rate_limit.requests_per_minute = 2
        settings.rate_limit.window_seconds = 60

        rate_limiter = RateLimiter(requests_per_minute=2, window_seconds=60)
        app = create_app(settings=settings, rate_limiter=rate_limiter)

        mcp_body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"},
            },
        }

        with TestClient(app) as client:
            # First 2 requests succeed
            for _ in range(2):
                resp = client.post(
                    "/mcp",
                    headers={"Accept": "application/json, text/event-stream"},
                    json=mcp_body,
                )
                assert resp.status_code in (200, 202)

            # 3rd request should be blocked (same IP, no user identity)
            resp_blocked = client.post(
                "/mcp",
                headers={"Accept": "application/json, text/event-stream"},
                json=mcp_body,
            )
            assert resp_blocked.status_code == 429

