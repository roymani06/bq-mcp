"""Configuration engine for the BigQuery MCP Server.

Loads configuration from config/config.yaml with hierarchical support for
environment variables (.env) and runtime overrides.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field, model_validator

# Load environment variables from .env if present
load_dotenv()


class ServerConfig(BaseModel):
    """Server and HTTP transport settings."""
    host: str = Field(default="0.0.0.0", description="Bind address for the ASGI server")
    port: int = Field(default=8000, description="Listening port for the ASGI server")
    endpoint_path: str = Field(default="/mcp", description="Endpoint path for Streamable HTTP MCP transport")
    log_level: str = Field(default="INFO", description="Log level: DEBUG, INFO, WARNING, ERROR")



class AuthConfig(BaseModel):
    """Google Cloud backend service account authentication."""
    service_account_key_path: Optional[str] = Field(
        default="service-account.json",
        description="Relative or absolute path to GCP Service Account JSON key credentials. Can be null for ADC."
    )


class BigQueryConfig(BaseModel):
    """BigQuery execution guardrails and connection options."""
    project_id: Optional[str] = Field(
        default=None,
        description="GCP project ID. If null, auto-detected from service-account.json"
    )
    location: Optional[str] = Field(
        default=None,
        description="Geographic location for BigQuery datasets and jobs. If null, auto-detected by BigQuery per dataset"
    )
    default_rows_returned: int = Field(
        default=50, ge=1,
        description="Default number of rows pulled when limit is not specified in tool call or query"
    )
    max_rows_returned: int = Field(
        default=200, ge=1,
        description="Maximum rows serialized to prevent container OOM"
    )
    max_bytes_billed: int = Field(
        default=10737418240, ge=1,  # 10 GB
        description="Hard cost-ceiling limit on bytes billed per query execution"
    )
    query_timeout_seconds: int = Field(
        default=60, ge=1,
        description="Timeout in seconds for BigQuery query execution"
    )
    request_tag_name: str = Field(
        default="bq_mcp_ext",
        description="BigQuery job label key used for request tagging (managed via config.yaml)",
    )
    job_labels: Dict[str, str] = Field(
        default_factory=lambda: {"bq_mcp_ext": "true"},
        description="Configurable default job labels injected into QueryJobConfig.labels",
    )

    @model_validator(mode="after")
    def _validate_row_limits(self) -> "BigQueryConfig":
        if self.default_rows_returned > self.max_rows_returned:
            raise ValueError(
                f"default_rows_returned ({self.default_rows_returned}) must be "
                f"<= max_rows_returned ({self.max_rows_returned})"
            )
        return self


class SanitizerConfig(BaseModel):
    """SQL sanitizer and read-only query guardrails."""
    enabled: bool = Field(default=True, description="Whether to enforce SQL sanitization")
    mode: Literal["regex", "ast", "both"] = Field(
        default="both",
        description="Sanitizer mode: 'regex', 'ast', or 'both'"
    )
    blocked_keywords: List[str] = Field(
        default_factory=lambda: [
            "INSERT",
            "UPDATE",
            "DELETE",
            "DROP",
            "ALTER",
            "TRUNCATE",
            "CREATE",
            "MERGE",
            "GRANT",
            "REVOKE",
            "EXECUTE",
            "CALL",
        ],
        description="List of forbidden SQL keywords (case-insensitive)"
    )


class ToolsConfig(BaseModel):
    """Dynamic tool enablement matrix."""
    enable_bq_list_datasets: bool = Field(default=True, description="Enable bq_list_datasets tool")
    enable_bq_list_tables: bool = Field(default=True, description="Enable bq_list_tables tool")
    enable_bq_table_metadata: bool = Field(default=True, description="Enable bq_table_metadata tool")
    enable_bq_query_execution: bool = Field(default=True, description="Enable bq_query_execution tool")
    enable_bq_search_metadata: bool = Field(default=True, description="Enable bq_search_metadata tool")


class CacheConfig(BaseModel):
    """In-memory metadata caching (TTLCache)."""
    enabled: bool = Field(default=True, description="Enable TTLCache for metadata operations")
    metadata_ttl_seconds: int = Field(default=900, description="TTL for cached metadata responses (15 min)")
    max_cache_entries: int = Field(default=1024, description="Maximum number of cached entries in TTLCache")


class RateLimitConfig(BaseModel):
    """MCP endpoint rate limiting guardrails."""
    enabled: bool = Field(default=True, description="Enable rate limiting on MCP endpoint")
    requests_per_minute: int = Field(default=60, description="Maximum allowed requests per window per client")
    window_seconds: int = Field(default=60, description="Rate limit sliding window duration in seconds")


class Settings(BaseModel):
    """Root configuration model aggregating all functional settings."""
    server: ServerConfig = Field(default_factory=ServerConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    bigquery: BigQueryConfig = Field(default_factory=BigQueryConfig)
    sanitizer: SanitizerConfig = Field(default_factory=SanitizerConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)


def _find_config_file(custom_path: Optional[str] = None) -> Optional[Path]:
    """Resolve configuration file location."""
    if custom_path:
        p = Path(custom_path)
        if p.is_file():
            return p

    env_config = os.getenv("CONFIG_PATH")
    if env_config:
        p = Path(env_config)
        if p.is_file():
            return p

    candidates = [
        Path("config/config.yaml"),
        Path("config.yaml"),
        Path(__file__).parent / "config.yaml",
        Path(__file__).parent.parent / "config" / "config.yaml",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None


_settings_logger = logging.getLogger(__name__)


def _safe_int(env_var: str) -> Optional[int]:
    """Safely parse an integer from an environment variable, returning None on failure."""
    raw = os.environ.get(env_var)
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        _settings_logger.warning(
            "Invalid integer value for environment variable %s: '%s' — ignoring override",
            env_var, raw,
        )
        return None


def _apply_env_overrides(data: dict[str, Any]) -> dict[str, Any]:
    """Apply environment variable overrides to parsed dictionary."""
    if "auth" not in data:
        data["auth"] = {}
    if "bigquery" not in data:
        data["bigquery"] = {}
    if "server" not in data:
        data["server"] = {}

    # Service account override
    if "SERVICE_ACCOUNT_KEY_PATH" in os.environ:
        data["auth"]["service_account_key_path"] = os.environ["SERVICE_ACCOUNT_KEY_PATH"]

    # BigQuery overrides
    if "BIGQUERY_PROJECT_ID" in os.environ:
        data["bigquery"]["project_id"] = os.environ["BIGQUERY_PROJECT_ID"]
    if "BIGQUERY_LOCATION" in os.environ:
        data["bigquery"]["location"] = os.environ["BIGQUERY_LOCATION"]
    val = _safe_int("BIGQUERY_DEFAULT_ROWS_RETURNED")
    if val is not None:
        data["bigquery"]["default_rows_returned"] = val
    val = _safe_int("BIGQUERY_MAX_ROWS_RETURNED")
    if val is not None:
        data["bigquery"]["max_rows_returned"] = val
    val = _safe_int("BIGQUERY_MAX_BYTES_BILLED")
    if val is not None:
        data["bigquery"]["max_bytes_billed"] = val
    val = _safe_int("BIGQUERY_QUERY_TIMEOUT_SECONDS")
    if val is not None:
        data["bigquery"]["query_timeout_seconds"] = val
    if "BIGQUERY_REQUEST_TAG_NAME" in os.environ:
        data["bigquery"]["request_tag_name"] = os.environ["BIGQUERY_REQUEST_TAG_NAME"]
    if "BIGQUERY_JOB_LABELS" in os.environ:
        raw_labels = os.environ["BIGQUERY_JOB_LABELS"]
        try:
            import json
            parsed = json.loads(raw_labels)
            if isinstance(parsed, dict):
                data["bigquery"]["job_labels"] = {str(k): str(v) for k, v in parsed.items()}
        except Exception:
            parsed = {}
            for pair in raw_labels.split(","):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    parsed[k.strip()] = v.strip()
            if parsed:
                data["bigquery"]["job_labels"] = parsed

    # Server overrides
    if "SERVER_HOST" in os.environ:
        data["server"]["host"] = os.environ["SERVER_HOST"]
    val = _safe_int("SERVER_PORT")
    if val is not None:
        data["server"]["port"] = val
    if "SERVER_ENDPOINT_PATH" in os.environ:
        data["server"]["endpoint_path"] = os.environ["SERVER_ENDPOINT_PATH"]
    if "SERVER_LOG_LEVEL" in os.environ:
        data["server"]["log_level"] = os.environ["SERVER_LOG_LEVEL"]

    # Rate limiting overrides
    if "rate_limit" not in data:
        data["rate_limit"] = {}
    if "RATE_LIMIT_ENABLED" in os.environ:
        data["rate_limit"]["enabled"] = os.environ["RATE_LIMIT_ENABLED"].lower() in ("true", "1", "yes")
    val = _safe_int("RATE_LIMIT_REQUESTS_PER_MINUTE")
    if val is not None:
        data["rate_limit"]["requests_per_minute"] = val
    val = _safe_int("RATE_LIMIT_WINDOW_SECONDS")
    if val is not None:
        data["rate_limit"]["window_seconds"] = val

    # Cache overrides
    if "cache" not in data:
        data["cache"] = {}
    if "CACHE_ENABLED" in os.environ:
        data["cache"]["enabled"] = os.environ["CACHE_ENABLED"].lower() in ("true", "1", "yes")
    val = _safe_int("CACHE_METADATA_TTL_SECONDS")
    if val is not None:
        data["cache"]["metadata_ttl_seconds"] = val
    val = _safe_int("CACHE_MAX_CACHE_ENTRIES")
    if val is not None:
        data["cache"]["max_cache_entries"] = val

    # Sanitizer overrides
    if "sanitizer" not in data:
        data["sanitizer"] = {}
    if "SANITIZER_ENABLED" in os.environ:
        data["sanitizer"]["enabled"] = os.environ["SANITIZER_ENABLED"].lower() in ("true", "1", "yes")
    if "SANITIZER_MODE" in os.environ:
        data["sanitizer"]["mode"] = os.environ["SANITIZER_MODE"]

    # Tools enablement overrides
    if "tools" not in data:
        data["tools"] = {}
    if "ENABLE_BQ_LIST_DATASETS" in os.environ:
        data["tools"]["enable_bq_list_datasets"] = os.environ["ENABLE_BQ_LIST_DATASETS"].lower() in ("true", "1", "yes")
    if "ENABLE_BQ_LIST_TABLES" in os.environ:
        data["tools"]["enable_bq_list_tables"] = os.environ["ENABLE_BQ_LIST_TABLES"].lower() in ("true", "1", "yes")
    if "ENABLE_BQ_TABLE_METADATA" in os.environ:
        data["tools"]["enable_bq_table_metadata"] = os.environ["ENABLE_BQ_TABLE_METADATA"].lower() in ("true", "1", "yes")
    if "ENABLE_BQ_QUERY_EXECUTION" in os.environ:
        data["tools"]["enable_bq_query_execution"] = os.environ["ENABLE_BQ_QUERY_EXECUTION"].lower() in ("true", "1", "yes")
    if "ENABLE_BQ_SEARCH_METADATA" in os.environ:
        data["tools"]["enable_bq_search_metadata"] = os.environ["ENABLE_BQ_SEARCH_METADATA"].lower() in ("true", "1", "yes")

    return data


def load_settings(config_path: Optional[str] = None) -> Settings:
    """Load settings from config.yaml, applied with environment overrides."""
    file_path = _find_config_file(config_path)
    raw_data: dict[str, Any] = {}
    if file_path and file_path.exists():
        with open(file_path, "r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
            if isinstance(loaded, dict):
                raw_data = loaded

    data = _apply_env_overrides(raw_data)
    return Settings.model_validate(data)


# Global singleton settings instance
SETTINGS = load_settings()
