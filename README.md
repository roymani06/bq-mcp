# GCP BigQuery MCP Server (FastMCP + Microsoft Entra ID SSO)

A production-ready, enterprise-grade Model Context Protocol (MCP) server built in Python using **FastMCP**, **Streamable HTTP over `/mcp`**, and **Google Cloud BigQuery**.

---

## Architecture Overview

```
[ Developer / Claude Desktop / IDE / Inspector ]
│
│ 1. Client authenticates via Microsoft Entra ID (Azure AD SSO)
│    Sends Entra JWT: Authorization: Bearer <ACCESS_TOKEN>
▼
┌────────────────────────────────────────────────────────────────────────┐
│                   GCP BigQuery MCP Server (FastMCP)                    │
│ - Streamable HTTP mounted at configured endpoint (default: /mcp)       │
│ - Entra ID Auth Middleware:                                            │
│   • Configurable toggle: security.enable_auth (true/false)             │
│   • Fetches & caches Entra JWKS keys (login.microsoftonline.com)       │
│   • Validates RS256 signature, audience, accepted issuers & expiration │
│   • Extracts user identity (upn / email / oid)                         │
│ - Dynamically exposes ONLY the tools toggled ON in config.yaml         │
│ - Enforces Dual SQL Sanitizer (Regex keywords + AST syntax tree)       │
│ - Connects to BigQuery directly via Service Account JSON key credentials│
│ - Binds queries to max_bytes_billed and safe max_results pagination   │
│ - In-memory TTLCache with SHA-256 hashed keys for metadata queries     │
└───────────────────────────────────┬────────────────────────────────────┘
│
│ 2. Direct Machine-to-Machine 2-Legged Auth
│    (bigquery.Client.from_service_account_json)
▼
┌────────────────────────────────────────────────────────────────────────┐
│                       Google Cloud BigQuery                            │
│ - Enforces permissions via Service Account IAM & Dataset ACLs          │
│ - Executes read queries strictly within max_bytes_billed limit         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Key Features

1. **Inbound SSO with Microsoft Entra ID (Azure AD)**:
   - Cryptographic verification against Microsoft's public JWKS endpoint.
   - Validates RS256 signature, audience (`<client_id>` or `api://<client_id>`), v1.0 and v2.0 token issuers, and expiration.
   - **Configurable Auth Toggle (`security.enable_auth`)**: Easily toggle off auth (`false`) for local debugging and MCP Inspector testing, or enforce it in production (`true`).
2. **Direct BigQuery Service Account Integration**:
   - Zero interactive OAuth overhead; 2-legged server-to-server authentication directly initialized from the JSON service account key.
   - Dataset and column-level security enforced natively on Google Cloud.
3. **Execution Guardrails & Cost Ceiling**:
   - `max_bytes_billed` hard cost limit attached to `QueryJobConfig` (default: 10 GB).
   - `dry_run=True` simulation mode calculating query cost and cache hits with zero billing.
   - Container OOM protection by passing `max_results` into `query_job.result()`.
4. **Dual SQL Sanitizer**:
   - Enforces read-only query execution through both fast word-boundary regex filtering and deep BigQuery AST parsing (`sqlglot`).
   - Blocks `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `TRUNCATE`, `CREATE`, `MERGE`, `GRANT`, `REVOKE`, `EXECUTE`, `CALL`, multi-query chaining, and mutations nested inside CTEs/subqueries.
5. **Dynamic Tool Enablement & Sanitized Error Shielding**:
   - Each BigQuery tool (`bq_list_datasets`, `bq_list_tables`, `bq_table_metadata`, `bq_query_execution`) can be selectively enabled or disabled via `config/config.yaml`.
   - All tool invocations are shielded with `try/except` mapping Google API and internal errors to sanitized `fastmcp.exceptions.ToolError` instances, preventing internal GCP endpoints, tracebacks, credentials paths, and queries from leaking to clients.
6. **Metadata Caching & Concurrency Hardening**:
   - In-memory `TTLCache` with deterministic SHA-256 key hashing to minimize BigQuery API metadata calls.
   - Thread-safe double-checked locking on `BigQueryClientManager.client` eliminates race conditions during lazy client initialization.
7. **Sliding-Window Rate Limiting**:
   - Built-in `RateLimitMiddleware` enforces sliding-window rate limits on the `/mcp` transport endpoint.
   - Identifies callers by Microsoft Entra ID principal identity (`sub`/`oid`/`upn`) or client IP, returning standard HTTP 429 and `Retry-After` headers while exempting health checks.

---

## File Layout

```text
bq_mcp/
├── config/
│   ├── config.yaml              # Centralized configuration (Entra ID, SA path, tools, rate limit)
│   └── settings.py              # Pydantic Settings loader for config.yaml + .env
├── src/
│   ├── __init__.py
│   ├── entra_auth.py            # Microsoft Entra ID JWT validation (JWKS + claims)
│   ├── cache.py                 # TTLCache manager with SHA-256 key hashing
│   ├── sanitizer.py             # Configurable SQL Sanitizer (Regex + AST)
│   ├── client.py                # Thread-safe BigQuery client manager & execution guardrails
│   ├── tools.py                 # Dynamic FastMCP tool definitions with error shielding
│   ├── rate_limiter.py          # Sliding-window rate limiter & Starlette middleware
│   └── server.py                # Entra ID middleware & Streamable HTTP ASGI app
├── tests/
│   ├── __init__.py
│   └── test_tools.py            # Unit & integration tests (auth, concurrency, tools, rate limit)
├── service-account.json         # BigQuery Service Account JSON key
├── .env.example                 # Optional environment overrides
├── Dockerfile                   # Hardened Python 3.12 non-root container
├── requirements.txt             # Dependency manifest
├── run.py                       # Root CLI launcher with auto-reload and options
└── README.md                    # Entra ID setup, Inspector testing, and client configs
```

---

## Configuration Specification

All operational parameters are defined in `config/config.yaml` and can be overridden via environment variables or `.env`:

```yaml
# Server & HTTP Transport Settings
server:
  host: "0.0.0.0"
  port: 8000
  endpoint_path: "/mcp"
  log_level: "INFO"

# Inbound SSO Authentication: Microsoft Entra ID (Azure AD)
security:
  enable_auth: true                      # If false, bypasses JWT validation (dev mode)
  tenant_id: "your-azure-tenant-id"      # Entra Directory (tenant) ID
  client_id: "your-app-client-id"        # Entra Application (client) ID / Audience (aud)
  jwks_cache_ttl_seconds: 86400          # 24 hours cache for Microsoft public keys
  accepted_issuers:
    - "https://login.microsoftonline.com/{tenant_id}/v2.0"
    - "https://sts.windows.net/{tenant_id}/"

# Google Cloud Service Account Authentication (Direct Backend Auth)
auth:
  service_account_key_path: "service-account.json"

# BigQuery Execution Guardrails
bigquery:
  project_id: null                       # null auto-detects from service-account.json
  location: "us-east4"
  max_rows_returned: 200                 # Maximum rows serialized to prevent OOM
  max_bytes_billed: 10737418240          # 10 GB hard cost-ceiling per query
  query_timeout_seconds: 60
  # BigQuery Request Tags & Job Labels
  request_tag_name: "bq_mcp_ext"         # Tag name for tracking jobs in BigQuery
  job_labels:                            # Configurable static job labels injected into BigQuery jobs
    bq_mcp_ext: "true"

# SQL Sanitizer (Enforce Read-Only Queries)
sanitizer:
  enabled: true                          # Enforce read-only checks
  mode: "both"                           # Options: "regex", "ast", "both"
  restrict_information_schema: true      # Restrict direct queries to INFORMATION_SCHEMA (enforces free REST API metadata)
  blocked_keywords:
    - "INSERT"
    - "UPDATE"
    - "DELETE"
    - "DROP"
    - "ALTER"
    - "TRUNCATE"
    - "CREATE"
    - "MERGE"
    - "GRANT"
    - "REVOKE"
    - "EXECUTE"
    - "CALL"

# Dynamic Tool Enablement Matrix
tools:
  enable_bq_list_datasets: true
  enable_bq_list_tables: true
  enable_bq_table_metadata: true
  enable_bq_query_execution: true

# In-Memory Metadata Caching (TTLCache)
cache:
  enabled: true
  metadata_ttl_seconds: 900              # 15 minutes
  max_cache_entries: 1024

# MCP Endpoint Rate Limiting Guardrails
rate_limit:
  enabled: true                          # Enable client rate limiting on MCP endpoint
  requests_per_minute: 60                # Max requests per sliding window
  window_seconds: 60                     # Sliding window duration in seconds
```

### Environment Variable Overrides (`.env`)

| Variable | Target Config | Description |
| :--- | :--- | :--- |
| `AZURE_TENANT_ID` | `security.tenant_id` | Microsoft Entra Directory (tenant) ID |
| `AZURE_CLIENT_ID` | `security.client_id` | Entra Application (client) ID |
| `SECURITY_ENABLE_AUTH` | `security.enable_auth` | Set to `false` to disable JWT check for dev mode |
| `SERVICE_ACCOUNT_KEY_PATH`| `auth.service_account_key_path`| Filepath to GCP credentials JSON |
| `BIGQUERY_PROJECT_ID` | `bigquery.project_id` | Target Google Cloud project ID |
| `BIGQUERY_LOCATION` | `bigquery.location` | Geographic dataset location (e.g. `US`, `EU`) |
| `SERVER_HOST` | `server.host` | Host binding IP (default: `0.0.0.0`) |
| `SERVER_PORT` | `server.port` | HTTP listening port (default: `8000`) |
| `SERVER_ENDPOINT_PATH` | `server.endpoint_path` | MCP transport route (default: `/mcp`) |
| `RATE_LIMIT_ENABLED` | `rate_limit.enabled` | Set to `false` to disable MCP endpoint rate limiting |
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | `rate_limit.requests_per_minute` | Max requests per sliding window per client (default: `60`) |
| `RATE_LIMIT_WINDOW_SECONDS` | `rate_limit.window_seconds` | Rate limit sliding window duration in seconds (default: `60`) |

---

## Setup & Prerequisites

### 1. Microsoft Entra ID (Azure AD) Setup

1. Log in to the [Azure Portal](https://portal.azure.com/) and navigate to **Microsoft Entra ID**.
2. Go to **App registrations** > **New registration**.
   - Name: `GCP BigQuery MCP Server`
   - Supported account types: *Accounts in this organizational directory only*
3. Note down the **Application (client) ID** and **Directory (tenant) ID**.
4. Go to **Expose an API**:
   - Set the Application ID URI to `api://<client_id>`.
   - Add a scope (e.g., `BigQuery.Read`).
5. In `config/config.yaml` or `.env`, set:
   ```yaml
   security:
     tenant_id: "<your-tenant-id>"
     client_id: "<your-client-id>"
   ```

### 2. Google Cloud BigQuery Setup

1. Open [Google Cloud Console](https://console.cloud.google.com/).
2. Navigate to **IAM & Admin** > **Service Accounts** > **Create Service Account**.
3. Grant the service account the required IAM roles:
   - **BigQuery Data Viewer** (`roles/bigquery.dataViewer`): Read access to dataset tables and schemas.
   - **BigQuery Job User** (`roles/bigquery.jobUser`): Permission to submit query jobs.
4. Create and download a new **JSON key**.
5. Save the file as `service-account.json` in the root of the project (or specify the path in `config/config.yaml`).

---

## Installation & Local Execution

### 1. Create Virtual Environment and Install Dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run Test Suite

Run the full pytest suite covering Entra ID token validation, SQL AST sanitization, caching, and BigQuery execution:

```bash
pytest tests/ -v
```

### 3. Start the Server

You can launch the server using the `run.py` launcher:

```bash
# Default launch (reads config/config.yaml and .env)
python run.py

# Optional CLI flags
python run.py --port 8000 --host 0.0.0.0 --reload --log-level debug
```

Or via direct module invocation:
```bash
python -m src.server
```

The server starts on `http://0.0.0.0:8000` with the Streamable HTTP transport mounted at `http://0.0.0.0:8000/mcp`.

---

## Docker Deployment (Hardened Non-Root Container)

The included `Dockerfile` builds a minimal, secure container running as a non-root system user (`appuser:10001`):

```bash
# Build Docker image
docker build -t bq-mcp-server:latest .

# Run container with volume mount for service account credentials
docker run -d \
  --name bq-mcp-server \
  -p 8000:8000 \
  -v $(pwd)/service-account.json:/app/service-account.json:ro \
  -e AZURE_TENANT_ID="your-tenant-id" \
  -e AZURE_CLIENT_ID="your-client-id" \
  -e SECURITY_ENABLE_AUTH="true" \
  bq-mcp-server:latest
```

Check health status:
```bash
curl http://localhost:8000/health
```

---

## Client Integration & Verification Guide

### 1. Test via MCP Inspector

For rapid local testing and schema inspection, you can test with or without auth.

#### A. Dev Mode (Auth Disabled)
In `config/config.yaml`, set `security.enable_auth: false` (or launch with `SECURITY_ENABLE_AUTH=false`), then run:

```bash
# Terminal 1: Run the MCP Server
python -m src.server

# Terminal 2: Launch MCP Inspector
npx @modelcontextprotocol/inspector
```

- **Transport**: `Streamable HTTP`
- **URL**: `http://localhost:8000/mcp`
- Click **Connect**.

#### B. Production Mode (With Entra ID Bearer Token)
- **Transport**: `Streamable HTTP`
- **URL**: `http://localhost:8000/mcp`
- **Custom Headers**:
  ```json
  {
    "Authorization": "Bearer <YOUR_ENTRA_ACCESS_TOKEN>"
  }
  ```

### 2. Claude Desktop Integration

Add the server to your `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`):

#### A. Local Development (Auth Disabled - Recommended for Quick Testing)
Set `security.enable_auth: false` in `config/config.yaml` (or `SECURITY_ENABLE_AUTH=false` in `.env`). The `--header` argument can be completely omitted:

```json
{
  "mcpServers": {
    "bigquery": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "http://127.0.0.1:8000/mcp"
      ]
    }
  }
}
```

#### B. Production / Authenticated Mode (With Microsoft Entra ID Token)
When `security.enable_auth: true`, obtain a token via the Azure CLI:
```bash
az login --tenant "<YOUR_AZURE_TENANT_ID>"
az account get-access-token --resource "<YOUR_AZURE_APP_CLIENT_ID>" --query accessToken -o tsv
```

Then supply the Bearer token in the `--header` argument:
```json
{
  "mcpServers": {
    "bigquery": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "http://127.0.0.1:8000/mcp",
        "--header",
        "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."
      ]
    }
  }
}
```

### 3. IDE Integration (Cursor / VS Code / Windsurf)

In your workspace `.cursor/mcp.json` or IDE MCP settings:

#### A. Local Development (Auth Disabled)
```json
{
  "mcpServers": {
    "bigquery": {
      "url": "http://127.0.0.1:8000/mcp"
    }
  }
}
```

#### B. Production / Authenticated Mode
```json
{
  "mcpServers": {
    "bigquery": {
      "url": "http://127.0.0.1:8000/mcp",
      "headers": {
        "Authorization": "Bearer eyJhbGciOiJSUzI1NiIs..."
      }
    }
  }
}
```

---

## Exposed MCP Tools

| Tool | Parameters | Description |
| :--- | :--- | :--- |
| `bq_list_datasets` | `project_id?: str` | Lists BigQuery datasets with identifiers and labels via free REST API ($0.00). Cached in TTLCache. |
| `bq_list_tables` | `dataset_id: str`, `project_id?: str` | Lists tables, views, and materialized views via free REST API ($0.00). Cached in TTLCache. |
| `bq_table_metadata`| `dataset_id: str`, `table_id: str`, `project_id?: str` | Returns column schema, row counts, storage size, partition details, and clustering keys via free REST API ($0.00). Cached in TTLCache. |
| `bq_query_execution`| `query: str`, `dry_run?: bool`, `limit?: int`, `request_tag?: str` | Executes read-only SQL queries with AST validation, `max_bytes_billed` billing cap, pagination, and injected job labels (`bq_mcp_ext`). |

---

## Security Guardrails

- **AST Mutation Blocking**: Uses `sqlglot` to parse the BigQuery abstract syntax tree. Disallows query chaining (`;`), stored procedure executions (`CALL`), table drops (`DROP`), and data mutations (`INSERT`, `UPDATE`, `DELETE`, `MERGE`), including those obscured within CTEs or subqueries.
- **INFORMATION_SCHEMA Restriction**: Blocks queries accessing `INFORMATION_SCHEMA` in `bq_query_execution` via regex and AST checks, enforcing the use of free BigQuery REST API metadata endpoints.
- **Cost Ceilings (`maximum_bytes_billed`)**: Protects against unexpected high-cost queries by enforcing a hard upper bound on bytes scanned.
- **Container Memory Safeguards**: Automatically sets `max_results` on BigQuery result iteration to prevent container memory exhaustion and out-of-memory crashes.
- **Principle of Least Privilege**: Inbound client auth verifies Entra ID identity, while BigQuery machine-to-machine auth is locked down via Google Cloud IAM.
# bq-mcp
