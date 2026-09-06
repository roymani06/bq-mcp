"""Dynamic Model Context Protocol (MCP) tool definitions and registration for BigQuery."""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from google.api_core import exceptions as gcp_api_exceptions
from google.cloud import exceptions as gcp_cloud_exceptions

from config.settings import SETTINGS, Settings
from src.cache import CACHE, cached
from src.client import BQ_MANAGER, BigQueryClientManager

logger = logging.getLogger(__name__)


def _sanitize_message(raw: str) -> str:
    """Strip internal URLs, credentials paths, and superfluous noise from error messages."""
    cleaned = re.sub(r"(?:GET|POST|PUT|DELETE|PATCH)\s+https?://\S+", "", raw)
    cleaned = re.sub(r"https?://\S+", "", cleaned)
    cleaned = re.sub(r"\s*Location:\s*\S+", "", cleaned)
    cleaned = re.sub(r"\s*Job ID:\s*\S+", "", cleaned)
    cleaned = re.sub(r"\s*;\s*reason:\s*\w+", "", cleaned)
    cleaned = re.sub(r"message:\s*", "", cleaned)
    cleaned = re.sub(r"\s+:\s+", ": ", cleaned)
    cleaned = re.sub(r"^\s*:\s*", "", cleaned)
    cleaned = re.sub(r"\s{2,}", " ", cleaned).strip()
    return cleaned or "BigQuery request failed."


def handle_tool_error(tool_name: str, exc: Exception) -> ToolError:
    """Map internal BigQuery and validation exceptions into clean, sanitized ToolErrors.

    Ensures that raw internal GCP endpoints, project names, credentials paths,
    and server-side stack traces are logged internally but never leaked to clients.
    """
    if isinstance(exc, ToolError):
        return exc

    if isinstance(exc, (gcp_api_exceptions.NotFound, gcp_cloud_exceptions.NotFound)):
        raw_msg = getattr(exc, "message", None) or str(exc)
        logger.warning("Tool %s: BigQuery resource not found: %s", tool_name, raw_msg)
        return ToolError(f"BigQuery resource not found: {_sanitize_message(raw_msg)}")

    if isinstance(exc, (gcp_api_exceptions.Forbidden, gcp_cloud_exceptions.Forbidden)):
        raw_msg = getattr(exc, "message", None) or str(exc)
        logger.warning("Tool %s: BigQuery access forbidden: %s", tool_name, raw_msg)
        return ToolError("BigQuery access denied: Insufficient permissions to perform this operation.")

    if isinstance(exc, (gcp_api_exceptions.BadRequest, gcp_cloud_exceptions.BadRequest)):
        raw_msg = getattr(exc, "message", None) or str(exc)
        logger.warning("Tool %s: BigQuery bad request: %s", tool_name, raw_msg)
        return ToolError(f"BigQuery request invalid: {_sanitize_message(raw_msg)}")

    if isinstance(exc, (gcp_api_exceptions.GoogleAPICallError, gcp_cloud_exceptions.GoogleCloudError)):
        raw_msg = getattr(exc, "message", None) or str(exc)
        logger.error("Tool %s: BigQuery API call error: %s", tool_name, raw_msg, exc_info=True)
        return ToolError(f"BigQuery API error: {_sanitize_message(raw_msg)}")

    if isinstance(exc, ValueError):
        err_str = str(exc)
        if any(kw in err_str.lower() for kw in ("pem", "private_key", "certificate", "credentials")):
            logger.critical("Tool %s: Service account credentials parsing error: %s", tool_name, exc)
            return ToolError(
                "BigQuery credentials error: Service account key configuration is invalid or private key is unreadable."
            )
        logger.warning("Tool %s: Query validation failed: %s", tool_name, exc)
        return ToolError(f"Query validation failed: {err_str}")

    if isinstance(exc, FileNotFoundError):
        logger.critical("Tool %s: GCP credentials file not found on host", tool_name)
        return ToolError(
            "BigQuery credentials error: Service account key configuration is invalid or missing on the server."
        )

    logger.exception("Tool %s: Unexpected internal error: %s", tool_name, exc)
    return ToolError("An unexpected server error occurred while processing the BigQuery request.")


def build_mcp_server(
    settings: Optional[Settings] = None,
    bq_manager: Optional[BigQueryClientManager] = None,
) -> FastMCP:
    """Instantiate and configure the FastMCP server with dynamic tool registration."""
    cfg = settings or SETTINGS
    manager = bq_manager or BQ_MANAGER

    mcp = FastMCP("GCP BigQuery MCP Server")

    # -------------------------------------------------------------------------
    # Tool 1: bq_list_datasets
    # -------------------------------------------------------------------------
    if cfg.tools.enable_bq_list_datasets:
        logger.info("Registering tool: bq_list_datasets")

        @mcp.tool(
            name="bq_list_datasets",
            description=(
                "List BigQuery datasets available in the specified or default GCP project. "
                "Returns dataset identifiers, project bindings, and dataset labels."
            ),
        )
        @cached(prefix="bq_list_datasets", cache_instance=CACHE)
        def bq_list_datasets(project_id: Optional[str] = None) -> List[Dict[str, Any]]:
            """List BigQuery datasets in a GCP project."""
            try:
                return manager.list_datasets(project_id=project_id)
            except Exception as exc:
                raise handle_tool_error("bq_list_datasets", exc) from None

    else:
        logger.info("Tool bq_list_datasets is disabled in configuration.")

    # -------------------------------------------------------------------------
    # Tool 2: bq_list_tables
    # -------------------------------------------------------------------------
    if cfg.tools.enable_bq_list_tables:
        logger.info("Registering tool: bq_list_tables")

        @mcp.tool(
            name="bq_list_tables",
            description=(
                "List all tables, views, and materialized views inside a BigQuery dataset. "
                "Returns table names, types, creation times, and expiration timestamps."
            ),
        )
        @cached(prefix="bq_list_tables", cache_instance=CACHE)
        def bq_list_tables(
            dataset_id: str,
            project_id: Optional[str] = None,
        ) -> List[Dict[str, Any]]:
            """List tables in a specified BigQuery dataset."""
            try:
                return manager.list_tables(dataset_id=dataset_id, project_id=project_id)
            except Exception as exc:
                raise handle_tool_error("bq_list_tables", exc) from None

    else:
        logger.info("Tool bq_list_tables is disabled in configuration.")

    # -------------------------------------------------------------------------
    # Tool 3: bq_table_metadata
    # -------------------------------------------------------------------------
    if cfg.tools.enable_bq_table_metadata:
        logger.info("Registering tool: bq_table_metadata")

        @mcp.tool(
            name="bq_table_metadata",
            description=(
                "Retrieve comprehensive schema and storage metadata for a BigQuery table. "
                "Includes column names, data types, modes, field descriptions, total row count, "
                "storage size in bytes, time/range partitioning details, and clustering keys."
            ),
        )
        @cached(prefix="bq_table_metadata", cache_instance=CACHE)
        def bq_table_metadata(
            dataset_id: str,
            table_id: str,
            project_id: Optional[str] = None,
        ) -> Dict[str, Any]:
            """Retrieve schema and storage metadata for a BigQuery table."""
            try:
                return manager.get_table_metadata(
                    dataset_id=dataset_id, table_id=table_id, project_id=project_id
                )
            except Exception as exc:
                raise handle_tool_error("bq_table_metadata", exc) from None

    else:
        logger.info("Tool bq_table_metadata is disabled in configuration.")

    # -------------------------------------------------------------------------
    # Tool 4: bq_query_execution
    # -------------------------------------------------------------------------
    if cfg.tools.enable_bq_query_execution:
        logger.info("Registering tool: bq_query_execution")

        @mcp.tool(
            name="bq_query_execution",
            description=(
                "Execute a strictly read-only SQL query on Google Cloud BigQuery. "
                "Enforces read-only AST and regex checks (blocking INSERT, UPDATE, DELETE, DROP, etc.), "
                "applies a maximum_bytes_billed cost ceiling, and paginates results to prevent container OOM. "
                "Set dry_run=True to validate syntax and estimate bytes processed without running or billing. "
                "If limit or number of rows is not defined in the tool call or query, defaults to pulling default_rows_returned from config.yaml."
            ),
        )
        def bq_query_execution(
            query: str,
            dry_run: bool = False,
            limit: Optional[int] = None,
        ) -> Dict[str, Any]:
            """Execute a guarded read-only query on Google Cloud BigQuery."""
            try:
                return manager.execute_query(query=query, dry_run=dry_run, limit=limit)
            except Exception as exc:
                raise handle_tool_error("bq_query_execution", exc) from None

    else:
        logger.info("Tool bq_query_execution is disabled in configuration.")

    return mcp


# Default server instance
mcp = build_mcp_server()

