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

from config.settings import BigQueryConfig, SanitizerConfig, Settings, ToolsConfig, load_settings
from src.client import (
    BigQueryClientManager,
    sanitize_bq_label_key,
    sanitize_bq_label_val,
    sanitize_bq_labels,
)
from src.sanitizer import SQLSanitizer
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
# 2. INFORMATION_SCHEMA Restriction & Free REST API Metadata Tests
# ==============================================================================

class TestInformationSchemaRestriction:
    """Verify queries to INFORMATION_SCHEMA are strictly restricted in the backend."""

    @pytest.mark.parametrize(
        "query",
        [
            "SELECT * FROM dataset.INFORMATION_SCHEMA.COLUMNS",
            "SELECT table_name FROM `project.dataset.INFORMATION_SCHEMA.TABLES`",
            "SELECT * FROM `region-us`.INFORMATION_SCHEMA.JOBS_BY_PROJECT",
            "SELECT column_name, data_type FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name = 'users'",
            "WITH meta AS (SELECT * FROM my_dataset.INFORMATION_SCHEMA.TABLES) SELECT * FROM meta",
            "SELECT id FROM orders WHERE id IN (SELECT table_name FROM INFORMATION_SCHEMA.TABLES)",
            "SELECT a.id FROM tbl a JOIN dataset.INFORMATION_SCHEMA.TABLES b ON a.id = b.table_id",
        ],
    )
    def test_information_schema_queries_blocked(self, query: str) -> None:
        """Any query attempting to access INFORMATION_SCHEMA must be rejected."""
        sanitizer = SQLSanitizer()
        with pytest.raises(ValueError) as exc:
            sanitizer.validate(query)
        assert "INFORMATION_SCHEMA are restricted" in str(exc.value)
        assert "bq_list_datasets, bq_list_tables, bq_table_metadata" in str(exc.value)

    def test_information_schema_regex_mode_blocks(self) -> None:
        """Regex mode alone blocks INFORMATION_SCHEMA."""
        cfg = SanitizerConfig(enabled=True, mode="regex", restrict_information_schema=True)
        sanitizer = SQLSanitizer(config=cfg)
        with pytest.raises(ValueError) as exc:
            sanitizer.validate("SELECT * FROM dataset.INFORMATION_SCHEMA.TABLES")
        assert "INFORMATION_SCHEMA are restricted" in str(exc.value)

    def test_information_schema_ast_mode_blocks(self) -> None:
        """AST mode alone blocks INFORMATION_SCHEMA."""
        cfg = SanitizerConfig(enabled=True, mode="ast", restrict_information_schema=True)
        sanitizer = SQLSanitizer(config=cfg)
        with pytest.raises(ValueError) as exc:
            sanitizer.validate("SELECT * FROM dataset.INFORMATION_SCHEMA.TABLES")
        assert "INFORMATION_SCHEMA are restricted" in str(exc.value)

    def test_information_schema_restriction_can_be_disabled(self) -> None:
        """If restrict_information_schema is set to False, valid read-only queries pass."""
        cfg = SanitizerConfig(enabled=True, mode="both", restrict_information_schema=False)
        sanitizer = SQLSanitizer(config=cfg)
        res = sanitizer.validate("SELECT column_name FROM dataset.INFORMATION_SCHEMA.COLUMNS")
        assert "INFORMATION_SCHEMA" in res

    def test_execute_query_blocks_information_schema(self) -> None:
        """Manager execute_query rejects INFORMATION_SCHEMA queries before hitting BigQuery."""
        mock_bq = MagicMock(spec=bigquery.Client)
        manager = BigQueryClientManager(client=mock_bq)

        with pytest.raises(ValueError) as exc:
            manager.execute_query("SELECT * FROM dataset.INFORMATION_SCHEMA.TABLES")
        assert "INFORMATION_SCHEMA are restricted" in str(exc.value)
        mock_bq.query.assert_not_called()

    def test_free_rest_api_metadata_methods_succeed_without_sql(self) -> None:
        """Free REST APIs (list_datasets, list_tables, get_table_metadata) work without calling client.query."""
        mock_bq = MagicMock(spec=bigquery.Client)
        mock_bq.project = "test-project"

        # Mock list_datasets
        mock_ds = MagicMock()
        mock_ds.dataset_id = "analytics"
        mock_ds.project = "test-project"
        mock_ds.full_dataset_id = "test-project:analytics"
        mock_ds.labels = {"env": "prod"}
        mock_bq.list_datasets.return_value = [mock_ds]

        # Mock list_tables
        mock_tbl = MagicMock()
        mock_tbl.table_id = "orders"
        mock_tbl.project = "test-project"
        mock_tbl.dataset_id = "analytics"
        mock_tbl.table_type = "TABLE"
        mock_tbl.created = None
        mock_tbl.expires = None
        mock_bq.list_tables.return_value = [mock_tbl]

        # Mock get_table
        mock_table_obj = MagicMock()
        mock_table_obj.project = "test-project"
        mock_table_obj.dataset_id = "analytics"
        mock_table_obj.table_id = "orders"
        mock_table_obj.table_type = "TABLE"
        mock_table_obj.num_rows = 5000
        mock_table_obj.num_bytes = 1048576
        mock_table_obj.schema = [bigquery.SchemaField("order_id", "STRING")]
        mock_table_obj.time_partitioning = None
        mock_table_obj.range_partitioning = None
        mock_table_obj.clustering_fields = None
        mock_table_obj.description = "Orders table"
        mock_table_obj.created = None
        mock_table_obj.modified = None
        mock_table_obj.location = "US"
        mock_bq.get_table.return_value = mock_table_obj

        manager = BigQueryClientManager(client=mock_bq)

        datasets = manager.list_datasets()
        assert len(datasets) == 1
        assert datasets[0]["dataset_id"] == "analytics"

        tables = manager.list_tables("analytics")
        assert len(tables) == 1
        assert tables[0]["table_id"] == "orders"

        meta = manager.get_table_metadata("analytics", "orders")
        assert meta["num_rows"] == 5000
        assert meta["schema"][0]["name"] == "order_id"

        # All of these are 100% free REST APIs: mock_bq.query must NOT have been called
        mock_bq.query.assert_not_called()
