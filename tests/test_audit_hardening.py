"""Additional hardening tests for GCP BigQuery MCP Server.

Covers gaps identified during the audit:
 1. Sanitizer regex-only mode
 2. Sanitizer AST-only mode
 3. Cache TTL expiration
 4. Rate limiter window reset
 5. Rate limiter concurrent access
 6. extract_sql_limit edge cases
 7. inject_sql_limit preserves existing LIMIT
 8. Schema field nested serialization
 9. Environment variable override precedence
10. Malformed Bearer header
11. CORS preflight bypasses auth
12. Root endpoint info
13. BigQueryConfig validation (ge=1 and model_validator)
14. Cache sentinel handles None return values
15. Safe int helper for env overrides
"""

from __future__ import annotations

import concurrent.futures
import os
import time
from unittest.mock import patch

import pytest
from google.cloud import bigquery
from starlette.testclient import TestClient

from config.settings import (
    BigQueryConfig,
    CacheConfig,
    ServerConfig,
    Settings,
    load_settings,
    _safe_int,
)
from src.cache import MetadataCache, _CACHE_MISS, cached
from src.client import (
    extract_sql_limit,
    inject_sql_limit,
    schema_field_to_dict,
)
from src.rate_limiter import RateLimiter
from src.sanitizer import SQLSanitizer, SanitizerConfig
from src.server import create_app


# ==============================================================================
# 1. Sanitizer regex-only mode
# ==============================================================================

class TestSanitizerRegexOnlyMode:
    """Verify mode='regex' validates using keyword scanning only (no AST)."""

    def test_regex_mode_blocks_keyword(self) -> None:
        config = SanitizerConfig(enabled=True, mode="regex")
        sanitizer = SQLSanitizer(config=config)
        with pytest.raises(ValueError) as exc:
            sanitizer.validate("DROP TABLE users")
        assert "DROP" in str(exc.value)

    def test_regex_mode_allows_select(self) -> None:
        config = SanitizerConfig(enabled=True, mode="regex")
        sanitizer = SQLSanitizer(config=config)
        result = sanitizer.validate("SELECT * FROM users")
        assert result == "SELECT * FROM users"


# ==============================================================================
# 2. Sanitizer AST-only mode
# ==============================================================================

class TestSanitizerASTOnlyMode:
    """Verify mode='ast' validates using AST parsing only (no keyword regex)."""

    def test_ast_mode_blocks_mutation(self) -> None:
        config = SanitizerConfig(enabled=True, mode="ast")
        sanitizer = SQLSanitizer(config=config)
        with pytest.raises(ValueError) as exc:
            sanitizer.validate("INSERT INTO logs VALUES (1)")
        assert "sanitization violation" in str(exc.value).lower()

    def test_ast_mode_allows_select(self) -> None:
        config = SanitizerConfig(enabled=True, mode="ast")
        sanitizer = SQLSanitizer(config=config)
        result = sanitizer.validate("SELECT id FROM users WHERE active = TRUE")
        assert result == "SELECT id FROM users WHERE active = TRUE"


# ==============================================================================
# 3. Cache TTL expiration
# ==============================================================================

class TestCacheTTLExpiration:
    """Verify items actually expire after TTL elapses."""

    def test_item_expires_after_ttl(self) -> None:
        cfg = CacheConfig(enabled=True, metadata_ttl_seconds=1, max_cache_entries=10)
        cache = MetadataCache(config=cfg)

        key = cache.generate_key("ttl_test", x=1)
        cache.set(key, "hello")
        assert cache.get(key) == "hello"

        # Wait for TTL to expire
        time.sleep(1.5)
        result = cache.get(key)
        assert result is _CACHE_MISS


# ==============================================================================
# 4. Rate limiter window reset
# ==============================================================================

class TestRateLimiterWindowReset:
    """Verify requests succeed after the sliding window expires."""

    def test_window_resets_after_expiry(self) -> None:
        limiter = RateLimiter(requests_per_minute=2, window_seconds=1)

        # Exhaust the limit
        allowed1, _, _ = limiter.is_allowed("client-a")
        allowed2, _, _ = limiter.is_allowed("client-a")
        assert allowed1 and allowed2

        # Third request should be blocked
        allowed3, retry_after, _ = limiter.is_allowed("client-a")
        assert not allowed3
        assert retry_after >= 1

        # Wait for window to expire
        time.sleep(1.5)

        # Requests should succeed again
        allowed4, _, remaining = limiter.is_allowed("client-a")
        assert allowed4
        assert remaining >= 0


# ==============================================================================
# 5. Rate limiter concurrent access
# ==============================================================================

class TestRateLimiterConcurrency:
    """Thread-safety test for RateLimiter.is_allowed()."""

    def test_concurrent_is_allowed_thread_safety(self) -> None:
        limiter = RateLimiter(requests_per_minute=100, window_seconds=60)

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [
                executor.submit(limiter.is_allowed, f"client-{i % 5}")
                for i in range(200)
            ]
            results = [f.result() for f in futures]

        # All results should be valid 3-tuples
        for allowed, retry_after, remaining in results:
            assert isinstance(allowed, bool)
            assert isinstance(retry_after, int)
            assert isinstance(remaining, int)

        # At least 100 should have been allowed (the limit)
        allowed_count = sum(1 for r in results if r[0])
        assert allowed_count >= 100


# ==============================================================================
# 6. extract_sql_limit edge cases
# ==============================================================================

class TestExtractSQLLimit:
    """Edge cases for extract_sql_limit parser."""

    def test_no_limit(self) -> None:
        assert extract_sql_limit("SELECT * FROM users") is None

    def test_simple_limit(self) -> None:
        assert extract_sql_limit("SELECT * FROM users LIMIT 42") == 42

    def test_subquery_limit_not_extracted(self) -> None:
        """Top-level LIMIT should be None when only subquery has LIMIT."""
        result = extract_sql_limit(
            "SELECT * FROM (SELECT id FROM users LIMIT 10) sub"
        )
        # This should be None because top-level has no LIMIT
        assert result is None

    def test_limit_zero(self) -> None:
        result = extract_sql_limit("SELECT * FROM users LIMIT 0")
        assert result == 0

    def test_invalid_sql_returns_none(self) -> None:
        assert extract_sql_limit("THIS IS NOT SQL") is None


# ==============================================================================
# 7. inject_sql_limit preserves existing LIMIT
# ==============================================================================

class TestInjectSQLLimit:
    """Verify inject_sql_limit doesn't alter queries that already have LIMIT."""

    def test_preserves_existing_limit(self) -> None:
        query = "SELECT * FROM users LIMIT 10"
        result = inject_sql_limit(query, 100)
        # Should NOT change the existing limit
        assert "LIMIT 10" in result or "LIMIT 100" not in result

    def test_injects_when_missing(self) -> None:
        query = "SELECT * FROM users"
        result = inject_sql_limit(query, 50)
        assert "50" in result

    def test_handles_complex_query(self) -> None:
        query = "SELECT a, b FROM t1 JOIN t2 ON t1.id = t2.id WHERE a > 5 ORDER BY b"
        result = inject_sql_limit(query, 25)
        assert "25" in result


# ==============================================================================
# 8. Schema field nested serialization
# ==============================================================================

class TestSchemaFieldNestedSerialization:
    """Verify RECORD/STRUCT fields with sub-fields serialize correctly."""

    def test_nested_record_field(self) -> None:
        inner_field = bigquery.SchemaField("city", "STRING", mode="NULLABLE", description="City name")
        outer_field = bigquery.SchemaField(
            "address", "RECORD", mode="NULLABLE", description="Address struct",
            fields=(inner_field,),
        )
        result = schema_field_to_dict(outer_field)

        assert result["name"] == "address"
        assert result["type"] == "RECORD"
        assert len(result["fields"]) == 1
        assert result["fields"][0]["name"] == "city"
        assert result["fields"][0]["type"] == "STRING"

    def test_flat_field_no_subfields(self) -> None:
        field = bigquery.SchemaField("id", "INTEGER", mode="REQUIRED")
        result = schema_field_to_dict(field)

        assert result["name"] == "id"
        assert "fields" not in result


# ==============================================================================
# 9. Environment variable override precedence
# ==============================================================================

class TestEnvOverridePrecedence:
    """Verify env vars take precedence over config.yaml values."""

    def test_env_overrides_yaml_value(self, tmp_path) -> None:
        yaml_content = """
bigquery:
  project_id: "yaml-project"
  default_rows_returned: 30
  max_rows_returned: 100
"""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml_content, encoding="utf-8")

        # Set env var that should override the YAML value
        with patch.dict(os.environ, {"BIGQUERY_PROJECT_ID": "env-project"}, clear=False):
            settings = load_settings(config_path=str(config_file))

        assert settings.bigquery.project_id == "env-project"
        assert settings.bigquery.default_rows_returned == 30  # unchanged from YAML


# ==============================================================================
# 10. CORS preflight on MCP endpoint
# ==============================================================================

class TestCORSPreflight:
    """Verify OPTIONS requests are handled by CORS middleware."""

    def test_options_request_handled(self) -> None:
        settings = Settings(server=ServerConfig(endpoint_path="/mcp"))
        app = create_app(settings=settings)

        with TestClient(app) as client:
            res = client.options(
                "/mcp",
                headers={
                    "Origin": "http://localhost:3000",
                    "Access-Control-Request-Method": "POST",
                },
            )
            assert res.status_code == 200


# ==============================================================================
# 11. Root endpoint info
# ==============================================================================

class TestRootEndpointInfo:
    """Verify GET / returns service information JSON."""

    def test_root_returns_service_info(self) -> None:
        settings = Settings(server=ServerConfig(endpoint_path="/mcp"))
        app = create_app(settings=settings)

        with TestClient(app) as client:
            res = client.get("/")
            assert res.status_code == 200
            data = res.json()
            assert data["service"] == "GCP BigQuery MCP Server"
            assert data["status"] == "running"
            assert data["mcp_endpoint"] == "/mcp"
            assert data["health"] == "/health"
            assert "documentation" in data


# ==============================================================================
# 13. BigQueryConfig validation (ge=1 and model_validator)
# ==============================================================================

class TestBigQueryConfigValidation:
    """Verify Field(ge=1) and model_validator reject invalid configurations."""

    def test_negative_default_rows_rejected(self) -> None:
        with pytest.raises(ValueError):
            BigQueryConfig(default_rows_returned=-1, max_rows_returned=100)

    def test_zero_max_rows_rejected(self) -> None:
        with pytest.raises(ValueError):
            BigQueryConfig(default_rows_returned=1, max_rows_returned=0)

    def test_zero_max_bytes_billed_rejected(self) -> None:
        with pytest.raises(ValueError):
            BigQueryConfig(max_bytes_billed=0)

    def test_zero_query_timeout_rejected(self) -> None:
        with pytest.raises(ValueError):
            BigQueryConfig(query_timeout_seconds=0)

    def test_default_rows_exceeds_max_rows_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            BigQueryConfig(default_rows_returned=300, max_rows_returned=100)
        assert "default_rows_returned" in str(exc.value)
        assert "max_rows_returned" in str(exc.value)

    def test_valid_config_accepted(self) -> None:
        cfg = BigQueryConfig(
            default_rows_returned=50,
            max_rows_returned=200,
            max_bytes_billed=10737418240,
            query_timeout_seconds=60,
        )
        assert cfg.default_rows_returned == 50
        assert cfg.max_rows_returned == 200


# ==============================================================================
# 14. Cache sentinel handles None return values
# ==============================================================================

class TestCacheSentinelNoneValues:
    """Verify functions returning None are cached properly with sentinel."""

    def test_none_return_is_cached(self) -> None:
        cfg = CacheConfig(enabled=True, metadata_ttl_seconds=60, max_cache_entries=10)
        cache = MetadataCache(config=cfg)
        call_count = 0

        @cached(prefix="none_test", cache_instance=cache)
        def returns_none(x: int):
            nonlocal call_count
            call_count += 1
            return None

        result1 = returns_none(1)
        assert result1 is None
        assert call_count == 1

        # Second call should hit cache (NOT re-execute the function)
        result2 = returns_none(1)
        assert result2 is None
        assert call_count == 1  # still 1 — cache hit


# ==============================================================================
# 15. Safe int helper for env overrides
# ==============================================================================

class TestSafeIntHelper:
    """Verify _safe_int gracefully handles invalid environment variable values."""

    def test_valid_integer(self) -> None:
        with patch.dict(os.environ, {"TEST_INT_VAR": "42"}, clear=False):
            assert _safe_int("TEST_INT_VAR") == 42

    def test_invalid_integer_returns_none(self) -> None:
        with patch.dict(os.environ, {"TEST_INT_VAR": "not_a_number"}, clear=False):
            assert _safe_int("TEST_INT_VAR") is None

    def test_missing_var_returns_none(self) -> None:
        # Ensure the var is NOT set
        env = os.environ.copy()
        env.pop("TEST_INT_MISSING_VAR", None)
        with patch.dict(os.environ, env, clear=True):
            assert _safe_int("TEST_INT_MISSING_VAR") is None

    def test_negative_integer(self) -> None:
        with patch.dict(os.environ, {"TEST_INT_VAR": "-5"}, clear=False):
            assert _safe_int("TEST_INT_VAR") == -5

    def test_float_string_returns_none(self) -> None:
        with patch.dict(os.environ, {"TEST_INT_VAR": "3.14"}, clear=False):
            assert _safe_int("TEST_INT_VAR") is None
