"""SQL Sanitizer enforcing read-only query execution via regex and AST analysis."""

from __future__ import annotations

import logging
import re
from typing import Optional, Tuple, Type

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError

from config.settings import SETTINGS, SanitizerConfig

logger = logging.getLogger(__name__)

# Disallowed AST expression types that perform mutations or DDL
FORBIDDEN_EXPRESSIONS: Tuple[Type[exp.Expression], ...] = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Drop,
    exp.Alter,
    exp.Create,
    exp.Merge,
    exp.Command,
    exp.Transaction,
    exp.Commit,
    exp.Rollback,
    exp.Set,
    exp.TruncateTable,
)


class SQLSanitizer:
    """Read-only SQL validator combining fast regex filtering and deep AST parsing."""

    def __init__(self, config: Optional[SanitizerConfig] = None) -> None:
        self.config = config or SETTINGS.sanitizer
        self._regex_pattern: Optional[re.Pattern[str]] = None
        if self.config.blocked_keywords:
            pattern_str = rf"\b({'|'.join(re.escape(k) for k in self.config.blocked_keywords)})\b"
            self._regex_pattern = re.compile(pattern_str, re.IGNORECASE)

    def validate(self, query: str) -> str:
        """Validate that the query is safe, read-only BigQuery SQL.

        Args:
            query: The raw SQL string.

        Returns:
            The stripped SQL string if valid.

        Raises:
            ValueError: If the query violates read-only rules or cannot be safely parsed.
        """
        if not self.config.enabled:
            return query.strip()

        cleaned_query = query.strip()
        if not cleaned_query:
            raise ValueError("SQL query cannot be empty or whitespace.")

        mode = self.config.mode.lower()

        # 1. Regex validation
        if mode in ("regex", "both"):
            self._validate_regex(cleaned_query)

        # 2. AST validation
        if mode in ("ast", "both"):
            self._validate_ast(cleaned_query)

        return cleaned_query

    def _validate_regex(self, query: str) -> None:
        """Scan query for blocked SQL keywords and restricted schemas."""
        if getattr(self.config, "restrict_information_schema", True):
            if re.search(r"\binformation_schema\b", query, re.IGNORECASE):
                raise ValueError(
                    "SQL sanitization violation: Direct queries to INFORMATION_SCHEMA are restricted. "
                    "Please use dedicated BigQuery metadata tools (bq_list_datasets, bq_list_tables, bq_table_metadata) instead."
                )

        if not self._regex_pattern:
            return

        match = self._regex_pattern.search(query)
        if match:
            keyword = match.group(0).upper()
            raise ValueError(
                f"SQL sanitization violation: Blocked keyword '{keyword}' detected in query."
            )

    def _validate_ast(self, query: str) -> None:
        """Parse query with BigQuery dialect and verify it is strictly a read-only query."""
        try:
            parsed = sqlglot.parse(query, read="bigquery")
        except ParseError as e:
            raise ValueError(f"SQL parsing failed under BigQuery dialect: {e}") from e
        except Exception as e:
            raise ValueError(f"Unexpected error during SQL parsing: {e}") from e

        if not parsed:
            raise ValueError("SQL query could not be parsed into valid statements.")

        # Reject multiple statements to prevent query chaining / injection
        if len(parsed) > 1:
            raise ValueError(
                f"SQL sanitization violation: Chained or multi-statement queries ({len(parsed)} statements) are not allowed."
            )

        root = parsed[0]

        # Ensure the root statement is a SELECT or UNION query
        if not isinstance(root, (exp.Select, exp.Union)):
            root_type = type(root).__name__
            raise ValueError(
                f"SQL sanitization violation: Only SELECT or UNION statements are allowed. Found root statement type: '{root_type}'."
            )

        # Enforce restriction against querying INFORMATION_SCHEMA
        if getattr(self.config, "restrict_information_schema", True):
            for table_node in root.find_all(exp.Table):
                if "information_schema" in table_node.sql().lower():
                    raise ValueError(
                        "SQL sanitization violation: Direct queries to INFORMATION_SCHEMA are restricted. "
                        "Please use dedicated BigQuery metadata tools (bq_list_datasets, bq_list_tables, bq_table_metadata) instead."
                    )

        # Deep search the AST tree for any forbidden mutation / DDL expressions
        mutations = list(root.find_all(FORBIDDEN_EXPRESSIONS))
        if mutations:
            forbidden_names = sorted({type(m).__name__ for m in mutations})
            raise ValueError(
                f"SQL sanitization violation: Forbidden mutation/DDL operation detected in query AST: {', '.join(forbidden_names)}."
            )


# Global sanitizer instance
SANITIZER = SQLSanitizer()
