"""Direct Google Cloud BigQuery client with cost safeguards, pagination, and type serialization."""

from __future__ import annotations

import base64
import collections.abc
import datetime
import decimal
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import sqlglot
from google.cloud import bigquery
from google.cloud.bigquery import QueryJobConfig

from config.settings import SETTINGS, BigQueryConfig
from src.sanitizer import SANITIZER

logger = logging.getLogger(__name__)


def sanitize_bq_label_key(key: str) -> str:
    """Sanitize and format a string into a valid BigQuery job label key.

    GCP BigQuery label key constraints:
    - Must be 1 to 63 characters long.
    - Must start with a lowercase letter or international character.
    - Can only contain lowercase letters, numeric characters, underscores (_), and hyphens (-).
    """
    k = str(key).lower().strip()
    k = re.sub(r"[^a-z0-9_-]", "_", k)
    if not k or not (k[0].isalpha() and k[0].isascii()):
        k = f"k_{k}"
    return k[:63]


def sanitize_bq_label_val(val: Any) -> str:
    """Sanitize and format a value into a valid BigQuery job label value.

    GCP BigQuery label value constraints:
    - Up to 63 characters long.
    - Can only contain lowercase letters, numeric characters, underscores (_), and hyphens (-).
    """
    if val is None:
        return ""
    v = str(val).lower().strip()
    v = re.sub(r"[^a-z0-9_-]", "_", v)
    return v[:63]


def sanitize_bq_labels(labels: Dict[str, Any]) -> Dict[str, str]:
    """Sanitize a dictionary of key-value pairs into valid BigQuery job labels."""
    sanitized: Dict[str, str] = {}
    for k, v in labels.items():
        sk = sanitize_bq_label_key(k)
        sv = sanitize_bq_label_val(v)
        sanitized[sk] = sv
    return sanitized


def extract_sql_limit(query: str) -> Optional[int]:
    """Attempt to extract top-level LIMIT clause from a SQL query using AST parsing."""
    try:
        parsed = sqlglot.parse(query, read="bigquery")
        if parsed:
            limit_node = parsed[0].args.get("limit")
            if limit_node and hasattr(limit_node, "expression"):
                val_str = limit_node.expression.sql()
                if val_str.isdigit():
                    return int(val_str)
    except Exception:
        pass
    return None


def inject_sql_limit(query: str, limit_val: int) -> str:
    """Inject a top-level LIMIT clause into a SQL query if one is not already present.

    Prevents full table materialization of billions of rows on TB-scale production tables.
    """
    try:
        parsed = sqlglot.parse(query, read="bigquery")
        if parsed and len(parsed) == 1:
            root = parsed[0]
            if root.args.get("limit") is None:
                return root.limit(limit_val).sql(dialect="bigquery")
    except Exception:
        pass
    return query


def serialize_bq_value(val: Any) -> Any:
    """Recursively serialize BigQuery data types into JSON-compatible values."""
    if val is None:
        return None
    if isinstance(val, (datetime.datetime, datetime.date, datetime.time)):
        return val.isoformat()
    if isinstance(val, decimal.Decimal):
        return float(val)
    if isinstance(val, bytes):
        return base64.b64encode(val).decode("utf-8")
    if isinstance(val, (dict, collections.abc.Mapping)):
        return {str(k): serialize_bq_value(v) for k, v in val.items()}
    if isinstance(val, (list, tuple, set)):
        return [serialize_bq_value(item) for item in val]
    if isinstance(val, (int, float, bool, str)):
        return val
    return str(val)


def schema_field_to_dict(field: bigquery.SchemaField) -> Dict[str, Any]:
    """Convert BigQuery SchemaField to dictionary."""
    field_dict: Dict[str, Any] = {
        "name": field.name,
        "type": field.field_type,
        "mode": field.mode,
        "description": field.description,
    }
    if field.fields:
        field_dict["fields"] = [schema_field_to_dict(subfield) for subfield in field.fields]
    return field_dict


class BigQueryClientManager:
    """Direct 2-legged Service Account BigQuery client manager with guardrails."""

    def __init__(
        self,
        config: Optional[BigQueryConfig] = None,
        service_account_path: Optional[str] = None,
        client: Optional[bigquery.Client] = None,
    ) -> None:
        self.config = config or SETTINGS.bigquery
        self.service_account_path = service_account_path or SETTINGS.auth.service_account_key_path
        self._client = client
        self._client_lock = threading.Lock()

    @property
    def client(self) -> bigquery.Client:
        """Lazy-initialize or return existing BigQuery client in a thread-safe manner."""
        if self._client is None:
            with self._client_lock:
                if self._client is None:
                    self._client = self._create_client()
        return self._client

    def _create_client(self) -> bigquery.Client:
        """Create a BigQuery client using direct Service Account credentials or Application Default Credentials (ADC)."""
        sa_path: Optional[Path] = None

        # 1. Check configured service account path if provided
        if self.service_account_path:
            candidate = Path(self.service_account_path)
            if candidate.is_file():
                sa_path = candidate
            else:
                repo_candidate = Path(__file__).parent.parent / self.service_account_path
                if repo_candidate.is_file():
                    sa_path = repo_candidate

        # 2. Check GOOGLE_APPLICATION_CREDENTIALS environment variable
        if sa_path is None and "GOOGLE_APPLICATION_CREDENTIALS" in os.environ:
            env_candidate = Path(os.environ["GOOGLE_APPLICATION_CREDENTIALS"])
            if env_candidate.is_file():
                sa_path = env_candidate

        # If a valid service account file was found, initialize from it
        if sa_path is not None:
            logger.info(
                "Initializing BigQuery client from service account JSON: %s (project: %s, location: %s)",
                sa_path,
                self.config.project_id or "auto-detect",
                self.config.location,
            )
            return bigquery.Client.from_service_account_json(
                json_credentials_path=str(sa_path.resolve()),
                project=self.config.project_id,
                location=self.config.location,
            )

        # 3. Fall back to Application Default Credentials (ADC) / Workload Identity for Cloud Run, GKE, VM, etc.
        logger.info(
            "Initializing BigQuery client using Application Default Credentials (ADC) / Workload Identity (project: %s, location: %s)",
            self.config.project_id or "auto-detect",
            self.config.location,
        )
        try:
            return bigquery.Client(
                project=self.config.project_id,
                location=self.config.location,
            )
        except Exception as exc:
            raise FileNotFoundError(
                f"GCP credentials not found. Could not find service account key at '{self.service_account_path}', "
                f"and Application Default Credentials (ADC) / Workload Identity failed: {exc}. "
                f"Please place your GCP Service Account JSON key at the configured path, set GOOGLE_APPLICATION_CREDENTIALS, "
                f"or authenticate with 'gcloud auth application-default login'."
            ) from exc

    def list_datasets(self, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List BigQuery datasets in the target project."""
        target_project = project_id or self.config.project_id or self.client.project
        logger.info("Listing datasets for project: %s", target_project)
        datasets = list(self.client.list_datasets(project=target_project))
        return [
            {
                "dataset_id": d.dataset_id,
                "project": d.project,
                "full_dataset_id": d.full_dataset_id,
                "labels": d.labels or {},
            }
            for d in datasets
        ]

    def list_tables(
        self, dataset_id: str, project_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List tables within a specified dataset."""
        target_project = project_id or self.config.project_id or self.client.project
        dataset_ref = bigquery.DatasetReference(target_project, dataset_id)
        logger.info("Listing tables for dataset: %s.%s", target_project, dataset_id)

        tables = list(self.client.list_tables(dataset_ref))
        return [
            {
                "table_id": t.table_id,
                "project": t.project,
                "dataset_id": t.dataset_id,
                "table_type": t.table_type,
                "created": t.created.isoformat() if t.created else None,
                "expires": t.expires.isoformat() if t.expires else None,
            }
            for t in tables
        ]

    def get_table_metadata(
        self, dataset_id: str, table_id: str, project_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Fetch full table schema, row count, partitioning, and clustering metadata."""
        target_project = project_id or self.config.project_id or self.client.project
        table_ref = bigquery.TableReference(
            bigquery.DatasetReference(target_project, dataset_id), table_id
        )
        logger.info("Fetching metadata for table: %s.%s.%s", target_project, dataset_id, table_id)

        table = self.client.get_table(table_ref)

        time_partitioning = None
        if table.time_partitioning:
            time_partitioning = {
                "type": table.time_partitioning.type_,
                "field": table.time_partitioning.field,
                "expiration_ms": table.time_partitioning.expiration_ms,
                "require_partition_filter": table.time_partitioning.require_partition_filter,
            }

        range_partitioning = None
        if table.range_partitioning:
            range_partitioning = {
                "field": table.range_partitioning.field,
                "start": table.range_partitioning.range_.start if table.range_partitioning.range_ else None,
                "end": table.range_partitioning.range_.end if table.range_partitioning.range_ else None,
                "interval": table.range_partitioning.range_.interval if table.range_partitioning.range_ else None,
            }

        return {
            "project": table.project,
            "dataset_id": table.dataset_id,
            "table_id": table.table_id,
            "full_table_id": f"{table.project}.{table.dataset_id}.{table.table_id}",
            "table_type": table.table_type,
            "num_rows": table.num_rows,
            "num_bytes": table.num_bytes,
            "schema": [schema_field_to_dict(f) for f in table.schema],
            "time_partitioning": time_partitioning,
            "range_partitioning": range_partitioning,
            "clustering_fields": table.clustering_fields,
            "description": table.description,
            "created": table.created.isoformat() if table.created else None,
            "modified": table.modified.isoformat() if table.modified else None,
            "location": table.location,
        }

    def build_job_labels(
        self,
        request_context: Optional[Dict[str, Any] | str] = None,
        request_tag: Optional[str] = None,
    ) -> Dict[str, str]:
        """Construct validated BigQuery QueryJobConfig.labels from config.yaml and request context.

        Combines:
        1. Configured static labels from config.yaml (`config.job_labels`).
        2. Configurable request tag (key managed via `config.request_tag_name`, default 'bq_mcp_ext').
        3. Dynamic request context (request_id, client_id, caller tag).
        """
        raw_labels: Dict[str, Any] = {}

        # 1. Base labels from config.yaml
        if getattr(self.config, "job_labels", None):
            raw_labels.update(self.config.job_labels)

        # 2. Configurable request tag name (default 'bq_mcp_ext')
        tag_key = getattr(self.config, "request_tag_name", "bq_mcp_ext") or "bq_mcp_ext"

        # Priority for tag value: explicit request_tag > request_context (if string) > existing config label > "true"
        if request_tag:
            raw_labels[tag_key] = request_tag
        elif isinstance(request_context, str) and request_context.strip():
            raw_labels[tag_key] = request_context.strip()
        elif tag_key not in raw_labels:
            raw_labels[tag_key] = "true"

        # 3. Dynamic request context dictionary (e.g. request_id, client, trace)
        if isinstance(request_context, dict):
            for ck, cv in request_context.items():
                raw_labels[ck] = cv

        # 4. Authenticated SSO user email from GatewayAuthMiddleware contextvar
        try:
            from src.auth import current_user_email
            auth_user = current_user_email.get()
            if auth_user and "user_email" not in raw_labels:
                raw_labels["user_email"] = auth_user
        except Exception:
            pass

        # Sanitize and cap to GCP BigQuery maximum limit of 64 labels per job
        sanitized = sanitize_bq_labels(raw_labels)
        if len(sanitized) > 64:
            sanitized = dict(list(sanitized.items())[:64])
        return sanitized

    def execute_query(
        self,
        query: str,
        dry_run: bool = False,
        limit: Optional[int] = None,
        request_context: Optional[Dict[str, Any] | str] = None,
        request_tag: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute a read-only SQL query with billing safeguards, pagination, and request labels.

        Args:
            query: The SQL query string.
            dry_run: If True, returns query cost estimates without execution.
            limit: Custom maximum row limit (capped by config.max_rows_returned).
            request_context: Dynamic request context or dict of caller attributes.
            request_tag: Custom request tag value for the configured request_tag_name ('bq_mcp_ext').

        Returns:
            Dictionary with query results, stats, schema, and applied job labels.
        """
        # Enforce read-only SQL sanitizer
        sanitized_query = SANITIZER.validate(query)

        # Determine effective row limit:
        # 1. Explicit tool argument 'limit' if specified and positive
        # 2. LIMIT clause defined directly within the SQL query
        # 3. Default to default_rows_returned from config.yaml (capped at max_rows_returned)
        query_limit = extract_sql_limit(sanitized_query)
        if limit is not None and limit > 0:
            effective_limit = min(limit, self.config.max_rows_returned)
        elif query_limit is not None and query_limit > 0:
            effective_limit = min(query_limit, self.config.max_rows_returned)
        else:
            effective_limit = min(self.config.default_rows_returned, self.config.max_rows_returned)

        # For execution on TB-scale tables, if no LIMIT is in the query, inject it server-side
        # so BigQuery's query planner halts execution early rather than materializing millions of rows.
        execution_query = sanitized_query
        if not dry_run and query_limit is None:
            execution_query = inject_sql_limit(sanitized_query, effective_limit)

        # Construct and validate BigQuery job labels including request tag
        effective_labels = self.build_job_labels(
            request_context=request_context,
            request_tag=request_tag,
        )

        # Configure QueryJobConfig with hard cost ceiling, dry-run flag, and request labels
        job_config = QueryJobConfig(
            maximum_bytes_billed=self.config.max_bytes_billed,
            dry_run=dry_run,
            use_query_cache=True,
            labels=effective_labels,
        )

        if dry_run:
            logger.info(
                "Submitting BigQuery query (dry_run=True, max_bytes_billed=%d, labels=%s): %s",
                self.config.max_bytes_billed,
                effective_labels,
                execution_query[:200],
            )
        else:
            logger.info(
                "Submitting BigQuery query (dry_run=False, max_bytes_billed=%d, effective_limit=%d, labels=%s): %s",
                self.config.max_bytes_billed,
                effective_limit,
                effective_labels,
                execution_query[:200],
            )

        start_time = time.perf_counter()
        query_job = self.client.query(
            execution_query,
            job_config=job_config,
            location=self.config.location,
        )

        # Dry run response returns metadata and bytes estimates without row execution
        if dry_run:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            schema = (
                [schema_field_to_dict(f) for f in query_job.schema]
                if query_job.schema
                else []
            )
            return {
                "dry_run": True,
                "total_bytes_processed": query_job.total_bytes_processed,
                "total_bytes_billed": query_job.total_bytes_billed,
                "cache_hit": query_job.cache_hit,
                "schema": schema,
                "execution_time_ms": duration_ms,
                "job_labels": effective_labels,
            }

        logger.debug("Fetching up to %d rows with timeout=%ds", effective_limit, self.config.query_timeout_seconds)

        rows_iterator = query_job.result(
            max_results=effective_limit,
            timeout=self.config.query_timeout_seconds,
        )

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Serialize rows
        serialized_rows: List[Dict[str, Any]] = []
        for row in rows_iterator:
            row_dict = dict(row.items())
            serialized_rows.append(serialize_bq_value(row_dict))

        raw_schema = getattr(rows_iterator, "schema", None) or getattr(query_job, "schema", None)
        schema = (
            [schema_field_to_dict(f) for f in raw_schema]
            if raw_schema
            else []
        )

        # Read total rows from RowIterator if available, falling back safely
        total_rows = getattr(
            rows_iterator,
            "total_rows",
            getattr(query_job, "total_rows", len(serialized_rows)),
        )

        return {
            "dry_run": False,
            "rows": serialized_rows,
            "row_count": len(serialized_rows),
            "effective_limit": effective_limit,
            "total_rows_available": total_rows,
            "total_bytes_billed": query_job.total_bytes_billed,
            "total_bytes_processed": query_job.total_bytes_processed,
            "cache_hit": query_job.cache_hit,
            "execution_time_ms": duration_ms,
            "schema": schema,
            "job_labels": effective_labels,
        }


# Global BigQuery manager instance
BQ_MANAGER = BigQueryClientManager()
