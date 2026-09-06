"""Comprehensive test suite for GCP BigQuery MCP Server.

Tests:
1. Microsoft Entra ID (Azure AD) JWT validator with public JWKS mocking.
2. SQL Sanitizer (Regex keywords, BigQuery AST analysis, CTE mutation checks, query chaining).
3. Metadata TTLCache manager (SHA-256 key hashing, expiration, and caching decorator).
4. BigQuery client manager (guardrails, cost ceiling, pagination, type serialization).
5. Dynamic FastMCP tool registration matrix.
6. ASGI Streamable HTTP server & authentication middleware (health bypass, 401/403 errors, dev mode).
"""

from __future__ import annotations

import datetime
import concurrent.futures
import decimal
import time
from unittest.mock import MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastmcp.exceptions import ToolError
from google.api_core import exceptions as gcp_api_exceptions
from google.cloud import bigquery
from starlette.testclient import TestClient

from config.settings import (
    BigQueryConfig,
    CacheConfig,
    RateLimitConfig,
    SanitizerConfig,
    SecurityConfig,
    ServerConfig,
    Settings,
    ToolsConfig,
)
from src.cache import MetadataCache, _CACHE_MISS, cached
from src.client import BigQueryClientManager, serialize_bq_value
from src.entra_auth import AuthenticationError, EntraTokenValidator
from src.rate_limiter import RateLimiter, RateLimitMiddleware
from src.sanitizer import SQLSanitizer
from src.server import EntraAuthMiddleware, create_app
from src.tools import _sanitize_message, build_mcp_server, handle_tool_error


# ==============================================================================
# 1. Microsoft Entra ID Token Validation Tests
# ==============================================================================

class TestEntraAuth:
    """Test suite for Microsoft Entra ID authentication and JWKS validation."""

    @pytest.fixture(autouse=True)
    def setup_keys(self) -> None:
        """Generate test RSA key pair and mock JWKS client."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()

        self.mock_jwks_client = MagicMock()
        mock_signing_key = MagicMock()
        mock_signing_key.key = self.public_key
        self.mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        self.security_config = SecurityConfig(
            enable_auth=True,
            tenant_id="test-tenant-123",
            client_id="test-client-abc",
            jwks_cache_ttl_seconds=3600,
        )
        self.validator = EntraTokenValidator(
            config=self.security_config,
            jwks_client=self.mock_jwks_client,
        )

    def _create_token(
        self,
        claims: dict | None = None,
        kid: str = "key-1",
        expired: bool = False,
        wrong_audience: bool = False,
        wrong_issuer: bool = False,
    ) -> str:
        now = datetime.datetime.now(datetime.timezone.utc)
        exp = now - datetime.timedelta(minutes=5) if expired else now + datetime.timedelta(hours=1)
        aud = "wrong-client" if wrong_audience else "test-client-abc"
        iss = (
            "https://evil.issuer.com/v2.0"
            if wrong_issuer
            else "https://login.microsoftonline.com/test-tenant-123/v2.0"
        )

        payload = {
            "sub": "user-001",
            "upn": "analyst@company.com",
            "email": "analyst@company.com",
            "oid": "11111111-1111-1111-1111-111111111111",
            "aud": aud,
            "iss": iss,
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
        }
        if claims:
            payload.update(claims)

        headers = {"kid": kid, "alg": "RS256"}
        return jwt.encode(payload, self.private_key, algorithm="RS256", headers=headers)

    def test_valid_token_success(self) -> None:
        token = self._create_token()
        claims = self.validator.validate_token(token)
        assert claims["sub"] == "user-001"
        assert claims["upn"] == "analyst@company.com"
        assert claims["identity"] == "analyst@company.com"

    def test_valid_token_api_audience(self) -> None:
        token = self._create_token({"aud": "api://test-client-abc"})
        claims = self.validator.validate_token(token)
        assert claims["aud"] == "api://test-client-abc"

    def test_expired_token_fails(self) -> None:
        token = self._create_token(expired=True)
        with pytest.raises(AuthenticationError) as exc:
            self.validator.validate_token(token)
        assert "Token has expired" in str(exc.value)
        assert exc.value.status_code == 401

    def test_wrong_audience_fails(self) -> None:
        token = self._create_token(wrong_audience=True)
        with pytest.raises(AuthenticationError) as exc:
            self.validator.validate_token(token)
        assert "audience mismatch" in str(exc.value)
        assert exc.value.status_code == 403

    def test_wrong_issuer_fails(self) -> None:
        token = self._create_token(wrong_issuer=True)
        with pytest.raises(AuthenticationError) as exc:
            self.validator.validate_token(token)
        assert "issuer mismatch" in str(exc.value)
        assert exc.value.status_code == 403

    def test_missing_kid_header_fails(self) -> None:
        now = datetime.datetime.now(datetime.timezone.utc)
        payload = {
            "sub": "user-001",
            "aud": "test-client-abc",
            "iss": "https://login.microsoftonline.com/test-tenant-123/v2.0",
            "exp": int((now + datetime.timedelta(hours=1)).timestamp()),
        }
        token_no_kid = jwt.encode(payload, self.private_key, algorithm="RS256", headers={"alg": "RS256"})
        with pytest.raises(AuthenticationError) as exc:
            self.validator.validate_token(token_no_kid)
        assert "missing required 'kid'" in str(exc.value)

    def test_auth_disabled_bypass_mode(self) -> None:
        disabled_config = SecurityConfig(enable_auth=False)
        validator = EntraTokenValidator(config=disabled_config)
        claims = validator.validate_token("")
        assert claims["auth_disabled"] is True
        assert claims["sub"] == "dev-user-001"
        assert claims["upn"] == "dev@local.internal"


# ==============================================================================
# 2. SQL Sanitizer Tests
# ==============================================================================

class TestSQLSanitizer:
    """Test suite for Regex and AST SQL sanitization."""

    @pytest.fixture(autouse=True)
    def setup_sanitizer(self) -> None:
        self.sanitizer = SQLSanitizer()

    @pytest.mark.parametrize(
        "query",
        [
            "SELECT * FROM `project.dataset.table`",
            "SELECT id, count(1) FROM sales GROUP BY id HAVING count(1) > 5",
            "WITH regional AS (SELECT * FROM data WHERE region = 'US') SELECT * FROM regional",
            "SELECT a FROM t1 UNION ALL SELECT b FROM t2",
            "SELECT * FROM tbl WHERE name LIKE '%test%' AND active = TRUE ORDER BY created_at DESC LIMIT 50",
        ],
    )
    def test_valid_queries_pass(self, query: str) -> None:
        result = self.sanitizer.validate(query)
        assert result == query.strip()

    @pytest.mark.parametrize(
        "query,blocked_op",
        [
            ("DROP TABLE users", "DROP"),
            ("INSERT INTO logs (event) VALUES ('login')", "INSERT"),
            ("DELETE FROM customers WHERE id = 10", "DELETE"),
            ("UPDATE users SET is_admin = true WHERE id = 1", "UPDATE"),
            ("ALTER TABLE orders ADD COLUMN status STRING", "ALTER"),
            ("TRUNCATE TABLE audit_log", "TRUNCATE"),
            ("CREATE TABLE new_tbl (id INT64)", "CREATE"),
            ("MERGE dataset.target T USING dataset.source S ON T.id = S.id WHEN MATCHED THEN UPDATE SET v = S.v", "MERGE"),
            ("CALL my_procedure()", "CALL"),
        ],
    )
    def test_mutation_statements_blocked(self, query: str, blocked_op: str) -> None:
        with pytest.raises(ValueError) as exc:
            self.sanitizer.validate(query)
        assert "sanitization violation" in str(exc.value).lower()

    def test_multi_statement_chaining_blocked(self) -> None:
        chained = "SELECT 1; DROP TABLE users;"
        with pytest.raises(ValueError) as exc:
            self.sanitizer.validate(chained)
        assert "multi-statement" in str(exc.value).lower() or "blocked keyword" in str(exc.value).lower()

    def test_mutation_in_cte_blocked(self) -> None:
        cte_injection = "WITH cte AS (INSERT INTO users VALUES (1)) SELECT * FROM cte"
        with pytest.raises(ValueError) as exc:
            self.sanitizer.validate(cte_injection)
        assert "sanitization violation" in str(exc.value).lower()

    def test_empty_query_blocked(self) -> None:
        with pytest.raises(ValueError) as exc:
            self.sanitizer.validate("   ")
        assert "empty or whitespace" in str(exc.value).lower()

    def test_sanitizer_disabled_allows_all(self) -> None:
        disabled_config = SanitizerConfig(enabled=False)
        sanitizer = SQLSanitizer(config=disabled_config)
        assert sanitizer.validate("DROP TABLE users") == "DROP TABLE users"


# ==============================================================================
# 3. Metadata TTLCache Tests
# ==============================================================================

class TestMetadataCache:
    """Test suite for TTLCache with SHA-256 key hashing."""

    def test_key_hashing_determinism(self) -> None:
        cache = MetadataCache()
        k1 = cache.generate_key("test", dataset_id="ds1", project_id="p1")
        k2 = cache.generate_key("test", project_id="p1", dataset_id="ds1")
        k3 = cache.generate_key("test", dataset_id="ds2", project_id="p1")

        assert k1 == k2  # Dict key order agnostic
        assert k1 != k3
        assert k1.startswith("test:")

    def test_cache_set_get_clear(self) -> None:
        cfg = CacheConfig(enabled=True, metadata_ttl_seconds=60, max_cache_entries=10)
        cache = MetadataCache(config=cfg)

        key = cache.generate_key("table", table_id="t1")
        assert cache.get(key) is _CACHE_MISS

        cache.set(key, {"num_rows": 500})
        assert cache.get(key) == {"num_rows": 500}
        assert len(cache) == 1

        cache.clear()
        assert cache.get(key) is _CACHE_MISS
        assert len(cache) == 0

    def test_cached_decorator_sync_and_async(self) -> None:
        cache = MetadataCache()
        call_count = 0

        @cached(prefix="test_fn", cache_instance=cache)
        def compute_value(x: int) -> int:
            nonlocal call_count
            call_count += 1
            return x * 10

        assert compute_value(5) == 50
        assert call_count == 1

        # Second call should hit cache
        assert compute_value(5) == 50
        assert call_count == 1

        # Different argument executes function
        assert compute_value(6) == 60
        assert call_count == 2

    def test_disabled_cache_bypasses(self) -> None:
        cfg = CacheConfig(enabled=False)
        cache = MetadataCache(config=cfg)
        assert not cache.is_enabled

        call_count = 0

        @cached(prefix="disabled_fn", cache_instance=cache)
        def func() -> str:
            nonlocal call_count
            call_count += 1
            return "fresh"

        assert func() == "fresh"
        assert func() == "fresh"
        assert call_count == 2


# ==============================================================================
# 4. BigQuery Client Manager & Serialization Tests
# ==============================================================================

class TestBigQueryClient:
    """Test suite for BigQuery client guardrails and safe execution."""

    def test_value_serialization(self) -> None:
        now = datetime.datetime(2026, 9, 5, 12, 0, 0, tzinfo=datetime.timezone.utc)
        today = datetime.date(2026, 9, 5)
        dec = decimal.Decimal("12345.67")
        raw_bytes = b"sample_bytes"

        data = {
            "dt": now,
            "date": today,
            "decimal": dec,
            "bytes": raw_bytes,
            "nested": {"val": dec, "list": [now, 42]},
        }
        serialized = serialize_bq_value(data)

        assert serialized["dt"] == "2026-09-05T12:00:00+00:00"
        assert serialized["date"] == "2026-09-05"
        assert serialized["decimal"] == 12345.67
        assert isinstance(serialized["bytes"], str)
        assert serialized["nested"]["list"][0] == "2026-09-05T12:00:00+00:00"

    def test_query_execution_safeguards(self) -> None:
        mock_bq = MagicMock(spec=bigquery.Client)
        mock_bq.project = "test-project"

        mock_job = MagicMock()
        mock_job.total_bytes_billed = 10485760
        mock_job.total_bytes_processed = 20971520
        mock_job.cache_hit = False
        mock_job.total_rows = 2
        mock_job.schema = [
            bigquery.SchemaField("id", "INTEGER"),
            bigquery.SchemaField("name", "STRING"),
        ]

        class MockRow:
            def __init__(self, data: dict) -> None:
                self._data = data

            def items(self):
                return self._data.items()

        mock_job.result.return_value = [
            MockRow({"id": 1, "name": "Alpha"}),
            MockRow({"id": 2, "name": "Beta"}),
        ]
        mock_bq.query.return_value = mock_job

        cfg = BigQueryConfig(
            project_id="test-project",
            max_rows_returned=100,
            max_bytes_billed=10737418240,
            query_timeout_seconds=30,
        )
        manager = BigQueryClientManager(config=cfg, client=mock_bq)

        result = manager.execute_query("SELECT id, name FROM `test-project.dataset.users`", limit=10)

        assert result["dry_run"] is False
        assert result["row_count"] == 2
        assert result["rows"] == [{"id": 1, "name": "Alpha"}, {"id": 2, "name": "Beta"}]
        assert result["effective_limit"] == 10

        # Verify QueryJobConfig maximum_bytes_billed matches settings
        call_args, call_kwargs = mock_bq.query.call_args
        job_config = call_kwargs["job_config"]
        assert job_config.maximum_bytes_billed == 10737418240
        assert not job_config.dry_run

        # Verify result pagination limit
        mock_job.result.assert_called_once_with(max_results=10, timeout=30)

    def test_dry_run_execution(self) -> None:
        mock_bq = MagicMock(spec=bigquery.Client)
        mock_bq.project = "test-project"

        mock_job = MagicMock()
        mock_job.total_bytes_billed = 0
        mock_job.total_bytes_processed = 524288000
        mock_job.cache_hit = False
        mock_job.schema = [bigquery.SchemaField("id", "INTEGER")]
        mock_bq.query.return_value = mock_job

        cfg = BigQueryConfig(max_bytes_billed=5000000)
        manager = BigQueryClientManager(config=cfg, client=mock_bq)

        result = manager.execute_query("SELECT id FROM table", dry_run=True)

        assert result["dry_run"] is True
        assert result["total_bytes_processed"] == 524288000
        mock_job.result.assert_not_called()  # Result must not be fetched on dry run

    def test_query_execution_defaults_to_config_default_rows_returned(self) -> None:
        """When neither limit nor SQL LIMIT is defined, default to config.default_rows_returned."""
        mock_bq = MagicMock(spec=bigquery.Client)
        mock_job = MagicMock()
        mock_job.schema = [bigquery.SchemaField("id", "INTEGER")]
        mock_job.total_bytes_billed = 1000
        mock_job.total_bytes_processed = 2000
        mock_job.cache_hit = False

        mock_row = MagicMock()
        mock_row.items.return_value = [("id", 1)]
        mock_res = MagicMock()
        mock_res.__iter__.return_value = [mock_row]
        mock_res.total_rows = 1
        mock_job.result.return_value = mock_res
        mock_bq.query.return_value = mock_job

        cfg = BigQueryConfig(
            default_rows_returned=45,
            max_rows_returned=100,
        )
        manager = BigQueryClientManager(config=cfg, client=mock_bq)

        result = manager.execute_query("SELECT id FROM `dataset.table`")

        assert result["effective_limit"] == 45
        mock_job.result.assert_called_once_with(max_results=45, timeout=60)

    def test_query_execution_uses_sql_query_limit_if_provided(self) -> None:
        """When query has LIMIT defined in SQL and limit arg is None, use query LIMIT."""
        mock_bq = MagicMock(spec=bigquery.Client)
        mock_job = MagicMock()
        mock_job.schema = []
        mock_job.total_bytes_billed = 0
        mock_job.total_bytes_processed = 0
        mock_job.cache_hit = False

        mock_res = MagicMock()
        mock_res.__iter__.return_value = []
        mock_res.total_rows = 0
        mock_job.result.return_value = mock_res
        mock_bq.query.return_value = mock_job

        cfg = BigQueryConfig(
            default_rows_returned=50,
            max_rows_returned=200,
        )
        manager = BigQueryClientManager(config=cfg, client=mock_bq)

        result = manager.execute_query("SELECT id FROM `dataset.table` LIMIT 15")

        assert result["effective_limit"] == 15
        mock_job.result.assert_called_once_with(max_results=15, timeout=60)

    def test_query_execution_caps_sql_limit_at_max_rows_returned(self) -> None:
        """When query has LIMIT > max_rows_returned, cap at max_rows_returned."""
        mock_bq = MagicMock(spec=bigquery.Client)
        mock_job = MagicMock()
        mock_job.schema = []
        mock_job.total_bytes_billed = 0
        mock_job.total_bytes_processed = 0
        mock_job.cache_hit = False

        mock_res = MagicMock()
        mock_res.__iter__.return_value = []
        mock_res.total_rows = 0
        mock_job.result.return_value = mock_res
        mock_bq.query.return_value = mock_job

        cfg = BigQueryConfig(
            default_rows_returned=50,
            max_rows_returned=100,
        )
        manager = BigQueryClientManager(config=cfg, client=mock_bq)

        result = manager.execute_query("SELECT id FROM `dataset.table` LIMIT 500")

        assert result["effective_limit"] == 100
        mock_job.result.assert_called_once_with(max_results=100, timeout=60)


# ==============================================================================
# 5. Dynamic Tool Registration Matrix Tests
# ==============================================================================

class TestDynamicToolRegistration:
    """Test dynamic tool enablement based on configuration switches."""

    @pytest.mark.asyncio
    async def test_all_tools_enabled(self) -> None:
        settings = Settings(
            tools=ToolsConfig(
                enable_bq_list_datasets=True,
                enable_bq_list_tables=True,
                enable_bq_table_metadata=True,
                enable_bq_query_execution=True,
            )
        )
        server = build_mcp_server(settings=settings)
        tools = await server.list_tools()
        names = {t.name for t in tools}
        assert names == {
            "bq_list_datasets",
            "bq_list_tables",
            "bq_table_metadata",
            "bq_query_execution",
        }

    @pytest.mark.asyncio
    async def test_selective_tools_disabled(self) -> None:
        settings = Settings(
            tools=ToolsConfig(
                enable_bq_list_datasets=True,
                enable_bq_list_tables=False,
                enable_bq_table_metadata=False,
                enable_bq_query_execution=True,
            )
        )
        server = build_mcp_server(settings=settings)
        tools = await server.list_tools()
        names = {t.name for t in tools}
        assert names == {"bq_list_datasets", "bq_query_execution"}
        assert "bq_list_tables" not in names
        assert "bq_table_metadata" not in names


# ==============================================================================
# 6. ASGI Server & Entra ID Middleware Tests
# ==============================================================================

class TestASGIServer:
    """Test suite for ASGI HTTP transport, healthcheck bypass, and Entra ID auth."""

    @pytest.fixture(autouse=True)
    def setup_server(self) -> None:
        # Generate RSA key for auth testing
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

        mock_jwks = MagicMock()
        mock_signing_key = MagicMock()
        mock_signing_key.key = self.public_key
        mock_jwks.get_signing_key_from_jwt.return_value = mock_signing_key

        self.sec_cfg = SecurityConfig(
            enable_auth=True,
            tenant_id="server-tenant",
            client_id="server-client",
        )
        self.validator = EntraTokenValidator(
            config=self.sec_cfg,
            jwks_client=mock_jwks,
        )

        self.settings = Settings(
            server=ServerConfig(endpoint_path="/mcp"),
            security=self.sec_cfg,
        )
        self.app = create_app(settings=self.settings, validator=self.validator)

    def _create_bearer_token(self) -> str:
        now = datetime.datetime.now(datetime.timezone.utc)
        payload = {
            "sub": "test-analyst",
            "upn": "analyst@org.com",
            "aud": "server-client",
            "iss": "https://login.microsoftonline.com/server-tenant/v2.0",
            "exp": int((now + datetime.timedelta(hours=1)).timestamp()),
        }
        return jwt.encode(payload, self.private_key, algorithm="RS256", headers={"kid": "k1"})

    def test_health_endpoints_bypass_auth(self) -> None:
        with TestClient(self.app) as client:
            res_health = client.get("/health")
            assert res_health.status_code == 200
            assert res_health.json()["status"] == "healthy"

            res_healthz = client.get("/healthz")
            assert res_healthz.status_code == 200
            assert res_healthz.json()["status"] == "healthy"

    def test_unauthenticated_mcp_returns_401(self) -> None:
        with TestClient(self.app) as client:
            res = client.post("/mcp")
            assert res.status_code == 401
            assert "Unauthorized" in res.json()["error"]

    def test_invalid_bearer_token_returns_error(self) -> None:
        with TestClient(self.app) as client:
            res = client.post("/mcp", headers={"Authorization": "Bearer invalid.jwt.token"})
            assert res.status_code == 401
            assert "Unauthorized" in res.json()["error"]

    def test_valid_token_authorizes_mcp(self) -> None:
        token = self._create_bearer_token()
        with TestClient(self.app) as client:
            res = client.post(
                "/mcp",
                headers={
                    "Authorization": f"Bearer {token}",
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
            assert res.status_code == 200
            assert "result" in res.text

    def test_auth_disabled_config_allows_access(self) -> None:
        disabled_settings = Settings(
            server=ServerConfig(endpoint_path="/mcp"),
            security=SecurityConfig(enable_auth=False),
        )
        disabled_app = create_app(settings=disabled_settings)
        with TestClient(disabled_app) as client:
            # Without any Authorization header, request succeeds
            res = client.post(
                "/mcp",
                headers={"Accept": "application/json, text/event-stream"},
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "test-client", "version": "1.0"},
                    },
                },
            )
            assert res.status_code == 200
            assert "result" in res.text


# ==============================================================================
# 7. BigQueryClientManager Concurrency & Race Condition Tests
# ==============================================================================

class TestBigQueryClientConcurrency:
    """Verify thread-safe lazy initialization of BigQueryClientManager.client."""

    def test_lazy_client_init_thread_safety(self) -> None:
        """Simulate concurrent threads initializing .client simultaneously."""
        create_calls = 0
        mock_client_instance = MagicMock(spec=bigquery.Client)

        def mock_create_client():
            nonlocal create_calls
            create_calls += 1
            # Artificial sleep to widen the race condition window
            time.sleep(0.05)
            return mock_client_instance

        manager = BigQueryClientManager()
        assert manager._client is None

        with patch.object(manager, "_create_client", side_effect=mock_create_client):
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(lambda: manager.client) for _ in range(10)]
                results = [f.result() for f in futures]

        for res in results:
            assert res is mock_client_instance

        # _create_client must have been executed exactly once
        assert create_calls == 1


# ==============================================================================
# 8. Tool Error Handling & Error Sanitization Tests
# ==============================================================================

class TestToolErrorHandling:
    """Verify try/except error shielding across MCP tool functions."""

    def test_sanitize_message_utility(self) -> None:
        raw = "404 Not Found: https://bigquery.googleapis.com/bigquery/v2/projects/secret-proj/datasets/ds1 : Dataset missing"
        sanitized = _sanitize_message(raw)
        assert "https://" not in sanitized
        assert "bigquery.googleapis.com" not in sanitized
        assert "Dataset missing" in sanitized

    @pytest.mark.asyncio
    async def test_bq_list_datasets_handles_not_found(self) -> None:
        mock_manager = MagicMock(spec=BigQueryClientManager)
        mock_manager.list_datasets.side_effect = gcp_api_exceptions.NotFound(
            "Project not found at https://bigquery.googleapis.com/v2/projects/my-secret"
        )
        server = build_mcp_server(bq_manager=mock_manager)

        with pytest.raises(ToolError) as exc_info:
            await server.call_tool("bq_list_datasets", {"project_id": "missing-proj"})

        err_msg = str(exc_info.value)
        assert "BigQuery resource not found" in err_msg
        assert "https://" not in err_msg

    @pytest.mark.asyncio
    async def test_bq_list_tables_handles_forbidden(self) -> None:
        mock_manager = MagicMock(spec=BigQueryClientManager)
        mock_manager.list_tables.side_effect = gcp_api_exceptions.Forbidden(
            "403 Access Denied: User lacks bigquery.tables.list permission"
        )
        server = build_mcp_server(bq_manager=mock_manager)

        with pytest.raises(ToolError) as exc_info:
            await server.call_tool("bq_list_tables", {"dataset_id": "locked_ds"})

        err_msg = str(exc_info.value)
        assert "BigQuery access denied: Insufficient permissions" in err_msg

    @pytest.mark.asyncio
    async def test_bq_table_metadata_handles_bad_request(self) -> None:
        mock_manager = MagicMock(spec=BigQueryClientManager)
        mock_manager.get_table_metadata.side_effect = gcp_api_exceptions.BadRequest(
            "400 Invalid table ID format: https://bigquery.googleapis.com/v2/..."
        )
        server = build_mcp_server(bq_manager=mock_manager)

        with pytest.raises(ToolError) as exc_info:
            await server.call_tool(
                "bq_table_metadata", {"dataset_id": "ds", "table_id": "invalid!name"}
            )

        err_msg = str(exc_info.value)
        assert "BigQuery request invalid" in err_msg
        assert "https://" not in err_msg

    @pytest.mark.asyncio
    async def test_bq_query_execution_handles_value_error(self) -> None:
        mock_manager = MagicMock(spec=BigQueryClientManager)
        mock_manager.execute_query.side_effect = ValueError(
            "Forbidden SQL keyword detected: DROP"
        )
        server = build_mcp_server(bq_manager=mock_manager)

        with pytest.raises(ToolError) as exc_info:
            await server.call_tool("bq_query_execution", {"query": "DROP TABLE users"})

        err_msg = str(exc_info.value)
        assert "Query validation failed: Forbidden SQL keyword detected: DROP" in err_msg

    @pytest.mark.asyncio
    async def test_bq_query_execution_handles_credentials_not_found(self) -> None:
        mock_manager = MagicMock(spec=BigQueryClientManager)
        mock_manager.execute_query.side_effect = FileNotFoundError(
            "/root/secrets/service-account.json not found"
        )
        server = build_mcp_server(bq_manager=mock_manager)

        with pytest.raises(ToolError) as exc_info:
            await server.call_tool("bq_query_execution", {"query": "SELECT 1"})

        err_msg = str(exc_info.value)
        assert "BigQuery credentials error" in err_msg
        assert "/root/secrets" not in err_msg

    @pytest.mark.asyncio
    async def test_bq_query_execution_masks_unexpected_exceptions(self) -> None:
        mock_manager = MagicMock(spec=BigQueryClientManager)
        mock_manager.execute_query.side_effect = RuntimeError(
            "Internal memory corruption pointer 0xDEADBEEF"
        )
        server = build_mcp_server(bq_manager=mock_manager)

        with pytest.raises(ToolError) as exc_info:
            await server.call_tool("bq_query_execution", {"query": "SELECT 1"})

        err_msg = str(exc_info.value)
        assert "An unexpected server error occurred while processing the BigQuery request." in err_msg
        assert "0xDEADBEEF" not in err_msg


# ==============================================================================
# 9. MCP Endpoint Rate Limiting Tests
# ==============================================================================

class TestRateLimiting:
    """Verify in-memory sliding-window rate limiting on the MCP endpoint."""

    @pytest.fixture(autouse=True)
    def setup_limiter(self) -> None:
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

        mock_jwks = MagicMock()
        mock_signing_key = MagicMock()
        mock_signing_key.key = self.public_key
        mock_jwks.get_signing_key_from_jwt.return_value = mock_signing_key

        self.sec_cfg = SecurityConfig(
            enable_auth=True,
            tenant_id="rate-tenant",
            client_id="rate-client",
        )
        self.validator = EntraTokenValidator(
            config=self.sec_cfg,
            jwks_client=mock_jwks,
        )

    def _create_token_for_user(self, user_id: str) -> str:
        now = datetime.datetime.now(datetime.timezone.utc)
        payload = {
            "sub": user_id,
            "upn": f"{user_id}@org.com",
            "aud": "rate-client",
            "iss": "https://login.microsoftonline.com/rate-tenant/v2.0",
            "exp": int((now + datetime.timedelta(hours=1)).timestamp()),
        }
        return jwt.encode(payload, self.private_key, algorithm="RS256", headers={"kid": "k1"})

    def test_requests_within_rate_limit_succeed(self) -> None:
        rate_limiter = RateLimiter(requests_per_minute=5, window_seconds=60)
        settings = Settings(
            server=ServerConfig(endpoint_path="/mcp"),
            security=self.sec_cfg,
            rate_limit=RateLimitConfig(enabled=True, requests_per_minute=5, window_seconds=60),
        )
        app = create_app(settings=settings, validator=self.validator, rate_limiter=rate_limiter)
        token = self._create_token_for_user("user-alice")

        with TestClient(app) as client:
            for i in range(3):
                res = client.post(
                    "/mcp",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/json, text/event-stream",
                    },
                    json={
                        "jsonrpc": "2.0",
                        "id": i + 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "test", "version": "1.0"},
                        },
                    },
                )
                assert res.status_code == 200
                assert res.headers["X-RateLimit-Limit"] == "5"
                assert int(res.headers["X-RateLimit-Remaining"]) == 5 - (i + 1)

    def test_rate_limit_exceeded_returns_429(self) -> None:
        rate_limiter = RateLimiter(requests_per_minute=3, window_seconds=60)
        settings = Settings(
            server=ServerConfig(endpoint_path="/mcp"),
            security=self.sec_cfg,
            rate_limit=RateLimitConfig(enabled=True, requests_per_minute=3, window_seconds=60),
        )
        app = create_app(settings=settings, validator=self.validator, rate_limiter=rate_limiter)
        token = self._create_token_for_user("user-bob")

        with TestClient(app) as client:
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json, text/event-stream",
            }
            body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
            }
            # First 3 requests succeed
            for _ in range(3):
                res = client.post("/mcp", headers=headers, json=body)
                assert res.status_code == 200

            # 4th request must be rejected with 429
            blocked = client.post("/mcp", headers=headers, json=body)
            assert blocked.status_code == 429
            assert "Retry-After" in blocked.headers
            assert blocked.headers["X-RateLimit-Remaining"] == "0"
            data = blocked.json()
            assert data["error"] == "Too Many Requests"
            assert "Rate limit exceeded" in data["detail"]
            assert data["retry_after"] > 0

    def test_health_endpoints_bypass_rate_limiting(self) -> None:
        rate_limiter = RateLimiter(requests_per_minute=1, window_seconds=60)
        settings = Settings(
            server=ServerConfig(endpoint_path="/mcp"),
            security=self.sec_cfg,
            rate_limit=RateLimitConfig(enabled=True, requests_per_minute=1, window_seconds=60),
        )
        app = create_app(settings=settings, validator=self.validator, rate_limiter=rate_limiter)
        token = self._create_token_for_user("user-charlie")

        with TestClient(app) as client:
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json, text/event-stream",
            }
            body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
            }
            # Exhaust rate limit
            client.post("/mcp", headers=headers, json=body)
            blocked = client.post("/mcp", headers=headers, json=body)
            assert blocked.status_code == 429

            # Health check endpoints must still return 200
            res_health = client.get("/health")
            assert res_health.status_code == 200
            assert res_health.json()["rate_limit_enabled"] is True

            res_healthz = client.get("/healthz")
            assert res_healthz.status_code == 200

    def test_user_isolation_in_rate_limiting(self) -> None:
        rate_limiter = RateLimiter(requests_per_minute=2, window_seconds=60)
        settings = Settings(
            server=ServerConfig(endpoint_path="/mcp"),
            security=self.sec_cfg,
            rate_limit=RateLimitConfig(enabled=True, requests_per_minute=2, window_seconds=60),
        )
        app = create_app(settings=settings, validator=self.validator, rate_limiter=rate_limiter)

        token_user1 = self._create_token_for_user("user-1")
        token_user2 = self._create_token_for_user("user-2")

        with TestClient(app) as client:
            body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
            }
            # User 1 exhausts their 2 requests
            client.post("/mcp", headers={"Authorization": f"Bearer {token_user1}"}, json=body)
            client.post("/mcp", headers={"Authorization": f"Bearer {token_user1}"}, json=body)
            user1_blocked = client.post(
                "/mcp", headers={"Authorization": f"Bearer {token_user1}"}, json=body
            )
            assert user1_blocked.status_code == 429

            # User 2 must NOT be blocked despite User 1 hitting the limit
            user2_res = client.post(
                "/mcp", headers={"Authorization": f"Bearer {token_user2}"}, json=body
            )
            assert user2_res.status_code == 200

    def test_disabled_rate_limit_allows_unrestricted_requests(self) -> None:
        settings = Settings(
            server=ServerConfig(endpoint_path="/mcp"),
            security=SecurityConfig(enable_auth=False),
            rate_limit=RateLimitConfig(enabled=False, requests_per_minute=2),
        )
        app = create_app(settings=settings)

        with TestClient(app) as client:
            body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
            }
            for _ in range(5):
                res = client.post("/mcp", json=body)
                assert res.status_code == 200


# ==============================================================================
# 10. Strictly Config-Driven Architecture Tests
# ==============================================================================

class TestConfigDrivenArchitecture:
    """Verify that every server component dynamically honors config without hardcoded values."""

    @pytest.mark.asyncio
    async def test_all_parameters_strictly_config_driven(self, tmp_path) -> None:
        custom_yaml = """
server:
  host: "127.0.0.99"
  port: 9999
  endpoint_path: "/custom_mcp"
  log_level: "DEBUG"

security:
  enable_auth: true
  tenant_id: "custom-tenant-uuid"
  client_id: "custom-client-uuid"
  jwks_cache_ttl_seconds: 12345

auth:
  service_account_key_path: "custom-key.json"

bigquery:
  project_id: "custom-org-project-id"
  location: "europe-west1"
  default_rows_returned: 17
  max_rows_returned: 33
  max_bytes_billed: 5000000
  query_timeout_seconds: 45

sanitizer:
  enabled: true
  mode: "regex"
  blocked_keywords:
    - "SUPER_BLOCKED"

tools:
  enable_bq_list_datasets: true
  enable_bq_list_tables: false
  enable_bq_table_metadata: true
  enable_bq_query_execution: true

cache:
  enabled: true
  metadata_ttl_seconds: 333
  max_cache_entries: 555

rate_limit:
  enabled: true
  requests_per_minute: 12
  window_seconds: 30
"""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(custom_yaml, encoding="utf-8")

        from config.settings import load_settings
        from src.sanitizer import SQLSanitizer
        from src.cache import MetadataCache
        from src.rate_limiter import RateLimiter

        settings = load_settings(config_path=str(config_file))

        # 1. Config loading assertions
        assert settings.server.host == "127.0.0.99"
        assert settings.server.port == 9999
        assert settings.server.endpoint_path == "/custom_mcp"
        assert settings.server.log_level == "DEBUG"
        assert settings.security.tenant_id == "custom-tenant-uuid"
        assert settings.security.client_id == "custom-client-uuid"
        assert settings.security.jwks_cache_ttl_seconds == 12345
        assert settings.bigquery.project_id == "custom-org-project-id"
        assert settings.bigquery.location == "europe-west1"
        assert settings.bigquery.default_rows_returned == 17
        assert settings.bigquery.max_rows_returned == 33
        assert settings.bigquery.max_bytes_billed == 5000000
        assert settings.bigquery.query_timeout_seconds == 45
        assert settings.tools.enable_bq_list_tables is False
        assert settings.cache.metadata_ttl_seconds == 333
        assert settings.cache.max_cache_entries == 555
        assert settings.rate_limit.requests_per_minute == 12
        assert settings.rate_limit.window_seconds == 30

        # 2. Sanitizer honors custom blocked keywords
        sanitizer = SQLSanitizer(config=settings.sanitizer)
        with pytest.raises(ValueError) as exc:
            sanitizer.validate("SELECT * FROM table WHERE action = 'SUPER_BLOCKED'")
        assert "SUPER_BLOCKED" in str(exc.value)

        # 3. Cache honors custom maxsize and ttl
        cache = MetadataCache(config=settings.cache)
        assert cache._cache.maxsize == 555
        assert cache._cache.ttl == 333

        # 4. RateLimiter honors custom rate parameters
        rate_limiter = RateLimiter(
            requests_per_minute=settings.rate_limit.requests_per_minute,
            window_seconds=settings.rate_limit.window_seconds,
        )
        assert rate_limiter.requests_per_minute == 12
        assert rate_limiter.window_seconds == 30

        # 5. MCP server dynamically disables tools per YAML
        custom_mcp = build_mcp_server(settings=settings)
        tools = await custom_mcp.list_tools()
        tool_names = [t.name for t in tools]
        assert "bq_list_datasets" in tool_names
        assert "bq_table_metadata" in tool_names
        assert "bq_query_execution" in tool_names
        assert "bq_list_tables" not in tool_names


