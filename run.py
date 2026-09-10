#!/usr/bin/env python3
"""Convenience launcher for the GCP BigQuery MCP Server."""

from __future__ import annotations

import argparse
import os
import uvicorn

from config.settings import SETTINGS


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Launch the GCP BigQuery FastMCP Server",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to custom YAML configuration file (default: config/config.yaml)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default=SETTINGS.server.host,
        help="Host address to bind to",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=SETTINGS.server.port,
        help="Port to listen on",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        default=False,
        help="Enable auto-reload for development",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=SETTINGS.server.log_level.lower(),
        choices=["debug", "info", "warning", "error"],
        help="Logging level",
    )
    return parser.parse_args()


def print_banner(host: str, port: int) -> None:
    display_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    banner = (
        "=" * 70 + "\n"
        "  GCP BigQuery MCP Server (FastMCP + Streamable HTTP)\n"
        "=" * 70 + "\n"
        f"  • Transport URL:   http://{display_host}:{port}{SETTINGS.server.endpoint_path}\n"
        f"  • Healthcheck:     http://{display_host}:{port}/health\n"
        f"  • Rate Limiting:   {SETTINGS.rate_limit.enabled} ({SETTINGS.rate_limit.requests_per_minute} req/{SETTINGS.rate_limit.window_seconds}s)\n"
        f"  • Cost Ceiling:    {SETTINGS.bigquery.max_bytes_billed / (1024**3):.1f} GB per query\n"
        "=" * 70 + "\n"
        "  Press CTRL+C to stop the server\n"
    )
    print(banner, flush=True)


def main() -> None:
    args = parse_args()
    if args.config:
        os.environ["CONFIG_PATH"] = args.config
    print_banner(args.host, args.port)
    uvicorn.run(
        "src.server:app",
        host=args.host,
        port=args.port,
        log_level=args.log_level,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
