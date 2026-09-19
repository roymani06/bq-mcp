"""Unit tests for BigQuery Request Tags and Hybrid Metadata Engine.

Covers:
1. BigQuery Request Tags:
   - Configurable job labels from config.yaml
   - Request tag name management (default 'bq_mcp_ext')
   - Dynamic tag and context injection into QueryJobConfig.labels
   - Label key and value sanitization conforming to GCP constraints
   - Environment variable overrides (BIGQUERY_REQUEST_TAG_NAME, BIGQUERY_JOB_LABELS)
2. Hybrid Metadata Engine:
   - Free BigQuery REST API preference for table & dataset discovery (0 query bytes)
   - Reserving dataset-scoped INFORMATION_SCHEMA strictly for cross-table column search
   - Scanned data minimization (dataset qualification, minimal projection, parameterization, LIMIT)
   - bq_search_metadata tool integration and caching
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest
from google.cloud import bigquery
from google.cloud.bigquery import QueryJobConfig

from config.settings import BigQueryConfig, Settings, ToolsConfig, load_settings
from src.client import (
    BigQueryClientManager,
    sanitize_bq_label_key,
    sanitize_bq_label_val,
    sanitize_bq_labels,
)
from src.tools import build_mcp_server


# ==============================================================================
# 1. BigQuery Request Tags & Label Sanitization Tests
# ==============================================================================

class TestBigQueryRequestTags:
    """Test suite for BigQuery Request Tags and job label injection."""

    def test_label_key_sanitization(self) -> None:
        """Label keys must be lowercase, start with letter, contain only [a-z0-9_-], max 63 chars."""
        assert sanitize_bq_label_key("bq_mcp_ext") == "bq_mcp_ext"
        assert sanitize_bq_label_key("BQ_MCP_EXT") == "bq_mcp_ext"
        assert sanitize_bq_label_key("tag.with.dots:and/slashes") == "tag_with_dots_and_slashes"
        # Keys starting with a number must be prefixed
        assert sanitize_bq_label_key("123_tag") == "k_123_tag"
        # Length capped at 63
        long_key = "a" * 80
        assert len(sanitize_bq_label_key(long_key)) == 63

    def test_label_value_sanitization(self) -> None:
        """Label values must be lowercase, contain only [a-z0-9_-], max 63 chars."""
        assert sanitize_bq_label_val("prod-us-east") == "prod-us-east"
        assert sanitize_bq_label_val("Request#123:456") == "request_123_456"
        assert sanitize_bq_label_val(None) == ""
        long_val = "v" * 100
        assert len(sanitize_bq_label_val(long_val)) == 63

    def test_sanitize_bq_labels_dict(self) -> None:
        """Dictionary sanitization normalizes all keys and values."""
        raw = {
            "ENV": "PRODUCTION",
            "1st_caller": "agent-007",
            "tag.name": "custom/value",
        }
        sanitized = sanitize_bq_labels(raw)
        assert sanitized["env"] == "production"
        assert sanitized["k_1st_caller"] == "agent-007"
        assert sanitized["tag_name"] == "custom_value"

    def test_default_job_labels_from_config(self) -> None:
        """Default labels must contain configured request_tag_name ('bq_mcp_ext')."""
        cfg = BigQueryConfig(
            request_tag_name="bq_mcp_ext",
            job_labels={"bq_mcp_ext": "true", "environment": "dev"},
        )
        manager = BigQueryClientManager(config=cfg)
        labels = manager.build_job_labels()

        assert labels["bq_mcp_ext"] == "true"
        assert labels["environment"] == "dev"

    def test_custom_request_tag_name_from_config(self) -> None:
        """Tag name is configurable via config.yaml (e.g. bq_mcp_ext_custom)."""
        cfg = BigQueryConfig(
            request_tag_name="bq_mcp_ext_analytics",
            job_labels={"bq_mcp_ext_analytics": "v1"},
        )
        manager = BigQueryClientManager(config=cfg)
        labels = manager.build_job_labels()

        assert "bq_mcp_ext_analytics" in labels
        assert labels["bq_mcp_ext_analytics"] == "v1"

    def test_runtime_request_tag_override(self) -> None:
        """Passing request_tag overrides the default tag value in job labels."""
        cfg = BigQueryConfig(
            request_tag_name="bq_mcp_ext",
            job_labels={"bq_mcp_ext": "true"},
        )
        manager = BigQueryClientManager(config=cfg)
        labels = manager.build_job_labels(request_tag="report_generation_task")

        assert labels["bq_mcp_ext"] == "report_generation_task"

    def test_runtime_request_context_injection(self) -> None:
        """Passing request_context dict merges and sanitizes dynamic context labels."""
        cfg = BigQueryConfig(request_tag_name="bq_mcp_ext")
        manager = BigQueryClientManager(config=cfg)
        context = {
            "request_id": "req-98765",
            "client_type": "claude-desktop",
        }
        labels = manager.build_job_labels(request_context=context)

        assert labels["bq_mcp_ext"] == "true"
        assert labels["request_id"] == "req-98765"
        assert labels["client_type"] == "claude-desktop"

    def test_execute_query_injects_labels_into_query_job_config(self) -> None:
        """execute_query must attach labels to QueryJobConfig passed to client.query."""
        mock_bq = MagicMock(spec=bigquery.Client)
        mock_bq.project = "test-project"

        mock_job = MagicMock()
        mock_job.total_bytes_billed = 1000
        mock_job.total_bytes_processed = 2000
        mock_job.cache_hit = False
        mock_job.schema = [bigquery.SchemaField("col", "STRING")]
        mock_row = MagicMock()
        mock_row.items.return_value = [("col", "val")]
        mock_job.result.return_value = [mock_row]
        mock_job.total_rows = 1
        mock_bq.query.return_value = mock_job

        cfg = BigQueryConfig(
            request_tag_name="bq_mcp_ext",
            job_labels={"bq_mcp_ext": "true", "team": "analytics"},
        )
        manager = BigQueryClientManager(config=cfg, client=mock_bq)

        result = manager.execute_query(
            "SELECT col FROM `test-project.dataset.tbl`",
            request_tag="custom_query_tag",
            request_context={"caller": "test_agent"},
        )

        assert result["dry_run"] is False
        assert result["job_labels"]["bq_mcp_ext"] == "custom_query_tag"
        assert result["job_labels"]["team"] == "analytics"
        assert result["job_labels"]["caller"] == "test_agent"

        # Verify QueryJobConfig.labels
        call_kwargs = mock_bq.query.call_args[1]
        job_config: QueryJobConfig = call_kwargs["job_config"]
        assert job_config.labels["bq_mcp_ext"] == "custom_query_tag"
        assert job_config.labels["team"] == "analytics"
        assert job_config.labels["caller"] == "test_agent"

    def test_dry_run_injects_job_labels(self) -> None:
        """Dry run query execution also attaches job labels."""
        mock_bq = MagicMock(spec=bigquery.Client)
        mock_bq.project = "test-project"

        mock_job = MagicMock()
        mock_job.total_bytes_billed = 0
        mock_job.total_bytes_processed = 500
        mock_job.cache_hit = False
        mock_job.schema = []
        mock_bq.query.return_value = mock_job

        cfg = BigQueryConfig(request_tag_name="bq_mcp_ext")
        manager = BigQueryClientManager(config=cfg, client=mock_bq)

        result = manager.execute_query("SELECT 1", dry_run=True, request_tag="dry_run_tag")

        assert result["dry_run"] is True
        assert result["job_labels"]["bq_mcp_ext"] == "dry_run_tag"

        call_kwargs = mock_bq.query.call_args[1]
        job_config = call_kwargs["job_config"]
        assert job_config.labels["bq_mcp_ext"] == "dry_run_tag"

    def test_env_variable_overrides_for_labels(self) -> None:
        """Environment variables BIGQUERY_REQUEST_TAG_NAME and BIGQUERY_JOB_LABELS override config."""
        env = {
            "BIGQUERY_REQUEST_TAG_NAME": "bq_mcp_ext_env",
            "BIGQUERY_JOB_LABELS": '{"bq_mcp_ext_env": "v2", "env": "staging"}',
        }
        with patch.dict(os.environ, env, clear=False):
            settings = load_settings()
            assert settings.bigquery.request_tag_name == "bq_mcp_ext_env"
            assert settings.bigquery.job_labels["bq_mcp_ext_env"] == "v2"
            assert settings.bigquery.job_labels["env"] == "staging"


# ==============================================================================
# 2. Hybrid Metadata Engine Tests
# ==============================================================================

class TestHybridMetadataEngine:
    """Test suite for Hybrid Metadata Engine preferring free REST APIs over INFORMATION_SCHEMA."""

    def test_table_search_uses_free_rest_api_without_sql_query(self) -> None:
        """Searching tables must use free REST API list_tables and never execute BigQuery SQL queries."""
        mock_bq = MagicMock(spec=bigquery.Client)
        mock_bq.project = "test-project"

        # Mock list_datasets (REST API)
        mock_ds = MagicMock()
        mock_ds.dataset_id = "analytics"
        mock_ds.project = "test-project"
        mock_ds.full_dataset_id = "test-project:analytics"
        mock_ds.labels = {}
        mock_bq.list_datasets.return_value = [mock_ds]

        # Mock list_tables (REST API)
        mock_t1 = MagicMock()
        mock_t1.table_id = "orders_daily"
        mock_t1.project = "test-project"
        mock_t1.dataset_id = "analytics"
        mock_t1.table_type = "TABLE"
        mock_t1.created = None
        mock_t1.expires = None

        mock_t2 = MagicMock()
        mock_t2.table_id = "users"
        mock_t2.project = "test-project"
        mock_t2.dataset_id = "analytics"
        mock_t2.table_type = "TABLE"
        mock_t2.created = None
        mock_t2.expires = None
        mock_bq.list_tables.return_value = [mock_t1, mock_t2]

        cfg = BigQueryConfig(project_id="test-project")
        manager = BigQueryClientManager(config=cfg, client=mock_bq)

        result = manager.search_metadata(query="orders", search_type="tables")

        # Must find orders_daily
        assert result["total_matches"] == 1
        assert len(result["tables"]) == 1
        assert result["tables"][0]["table_id"] == "orders_daily"
        assert result["tables"][0]["source"] == "rest_api"
        assert result["bytes_billed"] == 0
        assert result["engine_used"] == "rest_api"

        # Crucial requirement: mock_bq.query must NOT have been called (0 bytes billed)
        mock_bq.query.assert_not_called()

    def test_column_search_reserves_information_schema_with_dataset_scoping(self) -> None:
        """Cross-table column search uses dataset-scoped INFORMATION_SCHEMA with minimal projection."""
        mock_bq = MagicMock(spec=bigquery.Client)
        mock_bq.project = "test-project"

        # Mock INFORMATION_SCHEMA query job
        mock_job = MagicMock()
        mock_job.total_bytes_billed = 10485760
        mock_job.cache_hit = False

        class MockInfoRow:
            def __init__(self, data: dict):
                self._data = data

            def items(self):
                return self._data.items()

            def get(self, k, default=None):
                return self._data.get(k, default)

        mock_job.result.return_value = [
            MockInfoRow({
                "table_catalog": "test-project",
                "table_schema": "sales",
                "table_name": "orders",
                "column_name": "order_amount",
                "data_type": "NUMERIC",
                "is_nullable": "YES",
            })
        ]
        mock_bq.query.return_value = mock_job

        cfg = BigQueryConfig(
            project_id="test-project",
            request_tag_name="bq_mcp_ext",
            job_labels={"bq_mcp_ext": "true"},
        )
        manager = BigQueryClientManager(config=cfg, client=mock_bq)

        result = manager.search_metadata(
            query="order_amount",
            dataset_id="sales",
            search_type="columns",
            limit=25,
        )

        assert result["total_matches"] == 1
        assert len(result["columns"]) == 1
        col = result["columns"][0]
        assert col["table_name"] == "orders"
        assert col["column_name"] == "order_amount"
        assert col["source"] == "information_schema"
        assert result["engine_used"] == "information_schema"

        # Verify minimal data scanning guardrails:
        mock_bq.query.assert_called_once()
        sql_query = mock_bq.query.call_args[0][0]
        call_kwargs = mock_bq.query.call_args[1]

        # 1. Dataset-scoped qualification
        assert "`test-project`.`sales`.INFORMATION_SCHEMA.COLUMNS" in sql_query

        # 2. Minimal column projection (no SELECT *)
        assert "SELECT table_catalog, table_schema, table_name, column_name, data_type, is_nullable" in sql_query
        assert "SELECT *" not in sql_query

        # 3. Parameterized WHERE and LIMIT
        assert "WHERE LOWER(column_name) LIKE @pattern" in sql_query
        assert "LIMIT @limit_val" in sql_query

        # 4. Injected job labels
        job_config = call_kwargs["job_config"]
        assert job_config.labels["bq_mcp_ext"] == "metadata_search"

    def test_hybrid_search_combines_rest_and_information_schema(self) -> None:
        """search_type='both' returns matching tables from REST API and matching columns from INFORMATION_SCHEMA."""
        mock_bq = MagicMock(spec=bigquery.Client)
        mock_bq.project = "test-project"

        # Mock list_datasets
        mock_ds = MagicMock()
        mock_ds.dataset_id = "crm"
        mock_ds.project = "test-project"
        mock_ds.full_dataset_id = "test-project:crm"
        mock_ds.labels = {}
        mock_bq.list_datasets.return_value = [mock_ds]

        # Mock list_tables for REST table discovery
        mock_tbl = MagicMock()
        mock_tbl.table_id = "customer_accounts"
        mock_tbl.project = "test-project"
        mock_tbl.dataset_id = "crm"
        mock_tbl.table_type = "TABLE"
        mock_tbl.created = None
        mock_tbl.expires = None
        mock_bq.list_tables.return_value = [mock_tbl]

        # Mock INFORMATION_SCHEMA query job for column discovery
        mock_job = MagicMock()
        mock_job.total_bytes_billed = 5000000

        class MockRow:
            def __init__(self, data: dict):
                self._data = data

            def items(self):
                return self._data.items()

            def get(self, k, default=None):
                return self._data.get(k, default)

        mock_job.result.return_value = [
            MockRow({
                "table_catalog": "test-project",
                "table_schema": "crm",
                "table_name": "customer_accounts",
                "column_name": "customer_id",
                "data_type": "INT64",
                "is_nullable": "NO",
            })
        ]
        mock_bq.query.return_value = mock_job

        cfg = BigQueryConfig(project_id="test-project")
        manager = BigQueryClientManager(config=cfg, client=mock_bq)

        result = manager.search_metadata(query="customer", search_type="both")

        assert result["total_matches"] == 2
        assert len(result["tables"]) == 1
        assert result["tables"][0]["source"] == "rest_api"
        assert len(result["columns"]) == 1
        assert result["columns"][0]["source"] == "information_schema"
        assert result["engine_used"] == "hybrid"

    @pytest.mark.asyncio
    async def test_bq_search_metadata_tool_invocation(self) -> None:
        """Test invoking bq_search_metadata via the FastMCP server."""
        mock_manager = MagicMock(spec=BigQueryClientManager)
        mock_manager.search_metadata.return_value = {
            "query": "transactions",
            "search_type": "tables",
            "tables": [{"table_id": "transactions_2026", "source": "rest_api"}],
            "columns": [],
            "total_matches": 1,
            "engine_used": "rest_api",
            "bytes_billed": 0,
            "job_labels": {"bq_mcp_ext": "true"},
        }

        settings = Settings(
            tools=ToolsConfig(enable_bq_search_metadata=True)
        )
        server = build_mcp_server(settings=settings, bq_manager=mock_manager)

        res = await server.call_tool("bq_search_metadata", {"query": "transactions"})
        assert res is not None
        mock_manager.search_metadata.assert_called_once()
