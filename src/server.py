"""ASGI Server and Microsoft Entra ID Authentication Middleware for FastMCP."""

from __future__ import annotations

import logging
from typing import Optional

import uvicorn
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from config.settings import SETTINGS, Settings
from src.entra_auth import AuthenticationError, EntraTokenValidator, TOKEN_VALIDATOR
from src.rate_limiter import RateLimiter, RateLimitMiddleware
from src.tools import build_mcp_server, mcp

# Configure root logger
logging.basicConfig(
    level=getattr(logging, SETTINGS.server.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("bq_mcp_server")


class EntraAuthMiddleware(BaseHTTPMiddleware):
    """Middleware enforcing Microsoft Entra ID JWT verification on inbound HTTP calls."""

    def __init__(
        self,
        app: Starlette,
        validator: Optional[EntraTokenValidator] = None,
        settings: Optional[Settings] = None,
    ) -> None:
        super().__init__(app)
        self.settings = settings or SETTINGS
        self.validator = validator or TOKEN_VALIDATOR

    async def dispatch(self, request: Request, call_next):
        # 1. Root & Health check endpoints bypass authentication
        if request.url.path in ("/", "/health", "/healthz"):
            if request.url.path in ("/health", "/healthz"):
                return JSONResponse(
                    {
                        "status": "healthy",
                        "service": "gcp-bigquery-mcp-server",
                        "auth_enabled": self.settings.security.enable_auth,
                        "rate_limit_enabled": self.settings.rate_limit.enabled,
                        "endpoint": self.settings.server.endpoint_path,
                    },
                    status_code=200,
                )
            # Root path '/' falls through to root_handler
            return await call_next(request)

        # 2. Allow CORS preflight requests without authentication
        if request.method == "OPTIONS":
            return await call_next(request)

        # 3. Check if authentication is bypassed by configuration (dev mode)
        if not self.settings.security.enable_auth:
            mock_claims = self.validator.validate_token("")
            request.state.user = mock_claims
            logger.debug("Auth disabled: bypassed authentication for path %s", request.url.path)
            return await call_next(request)

        # 4. Extract Authorization: Bearer <token>
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            logger.warning("Unauthorized access attempt to %s: Missing Authorization header", request.url.path)
            return JSONResponse(
                {
                    "error": "Unauthorized",
                    "detail": "Missing Authorization header. Expected format: 'Authorization: Bearer <token>'",
                },
                status_code=401,
            )

        parts = auth_header.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            logger.warning("Malformed Authorization header received: %s", parts[0])
            return JSONResponse(
                {
                    "error": "Unauthorized",
                    "detail": "Malformed Authorization header. Format must be 'Bearer <token>'",
                },
                status_code=401,
            )

        token = parts[1].strip()

        # 5. Cryptographic token validation against Entra JWKS
        try:
            claims = self.validator.validate_token(token)
            request.state.user = claims
            logger.debug("Authorized request for principal: %s", claims.get("identity"))
        except AuthenticationError as e:
            logger.warning("Entra ID authentication failed: %s", e.message)
            return JSONResponse(
                {
                    "error": "Unauthorized" if e.status_code == 401 else "Forbidden",
                    "detail": e.message,
                },
                status_code=e.status_code,
            )
        except Exception as e:
            logger.error("Unexpected error during authentication: %s", e)
            return JSONResponse(
                {
                    "error": "Internal Server Error",
                    "detail": "Authentication system error occurred",
                },
                status_code=500,
            )

        return await call_next(request)


def create_app(
    settings: Optional[Settings] = None,
    validator: Optional[EntraTokenValidator] = None,
    rate_limiter: Optional[RateLimiter] = None,
) -> Starlette:
    """Construct the Starlette ASGI application hosting FastMCP over Streamable HTTP."""
    cfg = settings or SETTINGS
    val = validator or (TOKEN_VALIDATOR if cfg == SETTINGS else EntraTokenValidator(config=cfg.security))
    server_mcp = mcp if cfg == SETTINGS else build_mcp_server(settings=cfg)

    # Mount Streamable HTTP at configured endpoint (default: /mcp)
    asgi_app = server_mcp.http_app(
        path=cfg.server.endpoint_path,
        transport="streamable-http",
    )

    # Attach Rate Limiting middleware (runs after EntraAuth so user identity is available)
    asgi_app.add_middleware(
        RateLimitMiddleware,
        settings=cfg,
        rate_limiter=rate_limiter,
    )

    # Attach Entra ID authentication middleware
    asgi_app.add_middleware(
        EntraAuthMiddleware,
        validator=val,
        settings=cfg,
    )

    # Attach CORS middleware for cross-origin browser clients / Inspector
    asgi_app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Attach informational root landing endpoint for web browsers
    async def root_handler(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "service": "GCP BigQuery MCP Server",
                "status": "running",
                "transport": "streamable-http",
                "mcp_endpoint": cfg.server.endpoint_path,
                "health": "/health",
                "auth_enabled": cfg.security.enable_auth,
                "rate_limit_enabled": cfg.rate_limit.enabled,
                "documentation": "https://modelcontextprotocol.io",
                "message": (
                    f"Connect your MCP client (Claude Desktop, Cursor, or MCP Inspector) "
                    f"to {cfg.server.endpoint_path}"
                ),
            },
            status_code=200,
        )

    asgi_app.add_route("/", root_handler, methods=["GET"])

    return asgi_app


# Root ASGI application instance for Uvicorn
app = create_app()


def main() -> None:
    """Server entrypoint for direct CLI invocation."""
    logger.info(
        "Starting GCP BigQuery FastMCP Server on %s:%d (endpoint: %s, auth_enabled: %s)",
        SETTINGS.server.host,
        SETTINGS.server.port,
        SETTINGS.server.endpoint_path,
        SETTINGS.security.enable_auth,
    )
    uvicorn.run(
        "src.server:app",
        host=SETTINGS.server.host,
        port=SETTINGS.server.port,
        log_level=SETTINGS.server.log_level.lower(),
        reload=False,
    )


if __name__ == "__main__":
    main()
