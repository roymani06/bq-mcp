"""Inbound Gateway Authentication Middleware for Hawkeye Gateway and Claude Desktop.

Enforces timing-safe secret key verification on inbound requests and propagates
the authenticated SSO user identity to downstream execution handlers and BigQuery job labels.
"""

from __future__ import annotations

import logging
import secrets
from contextvars import ContextVar
from typing import Optional, Set

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from config.settings import SETTINGS, GatewayAuthConfig, Settings

logger = logging.getLogger(__name__)

# Thread-safe and async-task-safe ContextVar to store authenticated user email
current_user_email: ContextVar[Optional[str]] = ContextVar("current_user_email", default=None)

# Operational endpoints exempt from authentication checks
EXEMPT_PATHS: Set[str] = {"/health", "/healthz", "/"}


class GatewayAuthMiddleware(BaseHTTPMiddleware):
    """Starlette middleware verifying inbound Hawkeye Gateway secret key and extracting SSO user claims."""

    def __init__(self, app, settings: Optional[Settings] = None) -> None:
        super().__init__(app)
        self.settings = settings or SETTINGS
        self.config: GatewayAuthConfig = self.settings.gateway_auth

    async def dispatch(self, request: Request, call_next) -> Response:
        # 1. Bypass authentication if disabled in configuration
        if not self.config.enabled:
            return await call_next(request)

        # 2. Bypass CORS preflight requests (OPTIONS)
        if request.method == "OPTIONS":
            return await call_next(request)

        # 3. Bypass operational health checks and landing page
        if request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        # 4. Fail-closed if auth is enabled but secret key is missing or blank
        expected_secret: Optional[str] = (
            self.config.secret_key.get_secret_value() if self.config.secret_key else None
        )
        if not expected_secret:
            logger.critical(
                "Gateway authentication is enabled, but no valid secret_key is configured. "
                "Rejecting request to prevent unauthenticated access."
            )
            return JSONResponse(
                {
                    "error": "Server Configuration Error",
                    "detail": "Gateway authentication is enabled on the server, but secret_key is not configured.",
                },
                status_code=500,
            )

        # 5. Extract secret key from configured header (e.g. X-Hawkeye-Key)
        header_key = self.config.header_name.lower()
        provided_secret = request.headers.get(header_key)

        # Fallback: support Authorization: Bearer <key> if passed as an auth bearer
        if not provided_secret and "authorization" in request.headers:
            auth_val = request.headers["authorization"]
            if auth_val.startswith("Bearer "):
                provided_secret = auth_val[7:].strip()

        # 6. Constant-time comparison (prevents timing side-channel attacks)
        if not provided_secret or not secrets.compare_digest(provided_secret, expected_secret):
            client_ip = request.client.host if request.client else "unknown"
            logger.warning(
                "Unauthorized access attempt to %s from client %s: missing or invalid '%s' header",
                request.url.path,
                client_ip,
                self.config.header_name,
            )
            return JSONResponse(
                {
                    "error": "Unauthorized",
                    "detail": f"Missing or invalid '{self.config.header_name}' authentication header.",
                },
                status_code=401,
                headers={"WWW-Authenticate": f"ApiKey realm='Hawkeye', header='{self.config.header_name}'"},
            )

        # 7. Extract forwarded SSO user email if present
        email_header_key = self.config.user_email_header.lower()
        user_email: Optional[str] = request.headers.get(email_header_key)
        if user_email:
            user_email = user_email.strip()
            request.state.user_email = user_email

        # 8. Set contextvar for the duration of this request
        token = current_user_email.set(user_email)
        try:
            return await call_next(request)
        finally:
            current_user_email.reset(token)
