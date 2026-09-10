"""Shared test fixtures for GCP BigQuery MCP Server test suite."""

from __future__ import annotations

import pytest

from config.settings import ServerConfig, Settings


@pytest.fixture()
def test_settings() -> Settings:
    """Default test settings fixture."""
    return Settings(server=ServerConfig(endpoint_path="/mcp"))
