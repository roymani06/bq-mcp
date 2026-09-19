"""ASGI Server for FastMCP over Streamable HTTP."""

from __future__ import annotations

import logging
from typing import Optional

import uvicorn
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from config.settings import SETTINGS, Settings
from src.auth import GatewayAuthMiddleware
from src.rate_limiter import RateLimiter, RateLimitMiddleware
from src.tools import build_mcp_server, mcp

# Configure root logger
logging.basicConfig(
    level=getattr(logging, SETTINGS.server.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("bq_mcp_server")


def create_app(
    settings: Optional[Settings] = None,
    rate_limiter: Optional[RateLimiter] = None,
) -> Starlette:
    """Construct the Starlette ASGI application hosting FastMCP over Streamable HTTP."""
    cfg = settings or SETTINGS
    server_mcp = mcp if cfg == SETTINGS else build_mcp_server(settings=cfg)

    # Mount Streamable HTTP at configured endpoint (default: /mcp)
    asgi_app = server_mcp.http_app(
        path=cfg.server.endpoint_path,
        transport="streamable-http",
    )

    # 1. Attach Rate Limiting middleware (runs after auth)
    asgi_app.add_middleware(
        RateLimitMiddleware,
        settings=cfg,
        rate_limiter=rate_limiter,
    )

    # 2. Attach Inbound Gateway Authentication middleware (runs before rate limiter)
    asgi_app.add_middleware(
        GatewayAuthMiddleware,
        settings=cfg,
    )

    # 3. Attach CORS middleware for cross-origin browser clients / Inspector (outermost)
    asgi_app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Health check endpoints
    async def health_handler(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "healthy",
                "service": "gcp-bigquery-mcp-server",
                "rate_limit_enabled": cfg.rate_limit.enabled,
                "endpoint": cfg.server.endpoint_path,
            },
            status_code=200,
        )

    asgi_app.add_route("/health", health_handler, methods=["GET"])
    asgi_app.add_route("/healthz", health_handler, methods=["GET"])

    # Attach informational root landing endpoint for web browsers
    async def root_handler(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "service": "GCP BigQuery MCP Server",
                "status": "running",
                "transport": "streamable-http",
                "mcp_endpoint": cfg.server.endpoint_path,
                "health": "/health",
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
        "Starting GCP BigQuery FastMCP Server on %s:%d (endpoint: %s)",
        SETTINGS.server.host,
        SETTINGS.server.port,
        SETTINGS.server.endpoint_path,
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
