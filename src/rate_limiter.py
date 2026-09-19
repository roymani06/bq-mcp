"""Sliding-window rate limiting engine and Starlette middleware for MCP endpoints."""

from __future__ import annotations

import collections
import logging
import math
import threading
import time
from typing import Deque, Dict, Optional, Tuple

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from config.settings import SETTINGS, RateLimitConfig, Settings

logger = logging.getLogger(__name__)


class RateLimiter:
    """Thread-safe sliding-window log rate limiter."""

    def __init__(
        self,
        requests_per_minute: int = 60,
        window_seconds: int = 60,
        max_clients: int = 10000,
    ) -> None:
        self.requests_per_minute = max(1, requests_per_minute)
        self.window_seconds = max(1, window_seconds)
        self.max_clients = max_clients
        self._clients: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()
        self._request_count: int = 0

    def is_allowed(self, client_key: str) -> Tuple[bool, int, int]:
        """Check if request for client_key is allowed under sliding window.

        Returns:
            Tuple of (allowed: bool, retry_after_seconds: int, remaining_requests: int)
        """
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            self._request_count += 1

            # Periodic cleanup: when tracking table grows large OR every 1000 requests
            if len(self._clients) > self.max_clients or self._request_count % 1000 == 0:
                self._purge_stale_clients(cutoff)

            if client_key not in self._clients:
                self._clients[client_key] = collections.deque()

            timestamps = self._clients[client_key]

            # Drop timestamps older than sliding window
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            if len(timestamps) < self.requests_per_minute:
                timestamps.append(now)
                remaining = max(0, self.requests_per_minute - len(timestamps))
                return True, 0, remaining
            else:
                oldest = timestamps[0]
                retry_after = max(1, math.ceil((oldest + self.window_seconds) - now))
                return False, retry_after, 0

    def _purge_stale_clients(self, cutoff: float) -> None:
        """Evict clients with no active requests in the current window."""
        stale_keys = [
            k for k, timestamps in self._clients.items()
            if not timestamps or timestamps[-1] <= cutoff
        ]
        for k in stale_keys:
            self._clients.pop(k, None)

    def clear(self) -> None:
        """Reset all rate limiter records (useful in tests)."""
        with self._lock:
            self._clients.clear()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Starlette middleware enforcing sliding-window rate limits on MCP endpoints."""

    def __init__(
        self,
        app: Starlette,
        settings: Optional[Settings] = None,
        rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        super().__init__(app)
        self.settings = settings or SETTINGS
        self.config: RateLimitConfig = self.settings.rate_limit
        self.rate_limiter = rate_limiter or RateLimiter(
            requests_per_minute=self.config.requests_per_minute,
            window_seconds=self.config.window_seconds,
        )

    def _extract_client_key(self, request: Request) -> str:
        """Derive client key prioritizing authenticated SSO user email over client IP."""
        # 1. Check authenticated SSO user email from GatewayAuthMiddleware
        user_email = getattr(request.state, "user_email", None)
        if user_email and isinstance(user_email, str):
            return f"user:{user_email.strip()}"

        # 2. Check authenticated user identity from request state (legacy dict format)
        user = getattr(request.state, "user", None)
        if isinstance(user, dict):
            identity = (
                user.get("identity")
                or user.get("sub")
                or user.get("oid")
                or user.get("upn")
            )
            if identity:
                return f"user:{identity}"

        # 3. Check X-Forwarded-For header if behind proxy/load balancer
        xff = request.headers.get("x-forwarded-for")
        if xff:
            client_ip = xff.split(",")[0].strip()
            if client_ip:
                return f"ip:{client_ip}"

        # 4. Direct socket client host
        if request.client and request.client.host:
            return f"ip:{request.client.host}"

        return "ip:unknown"

    async def dispatch(self, request: Request, call_next) -> Response:
        # 1. If rate limiting is disabled by configuration, pass through
        if not self.config.enabled:
            return await call_next(request)

        # 2. Health check endpoints bypass rate limiting
        if request.url.path in ("/health", "/healthz"):
            return await call_next(request)

        # 3. CORS preflight OPTIONS bypass rate limiting
        if request.method == "OPTIONS":
            return await call_next(request)

        # 4. Check client rate limit
        client_key = self._extract_client_key(request)
        allowed, retry_after, remaining = self.rate_limiter.is_allowed(client_key)

        if not allowed:
            logger.warning(
                "Rate limit exceeded for %s on %s: retry_after=%ds",
                client_key,
                request.url.path,
                retry_after,
            )
            return JSONResponse(
                {
                    "error": "Too Many Requests",
                    "detail": (
                        f"Rate limit exceeded: maximum {self.config.requests_per_minute} "
                        f"requests per {self.config.window_seconds}s. "
                        f"Please retry after {retry_after} seconds."
                    ),
                    "retry_after": retry_after,
                },
                status_code=429,
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(self.config.requests_per_minute),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(retry_after),
                },
            )

        # 5. Forward request and attach rate limit metadata headers to response
        response: Response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.config.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
