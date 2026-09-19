# GCP BigQuery MCP Server (FastMCP + Hawkeye Gateway SSO)

A production-ready, enterprise-grade Model Context Protocol (MCP) server built in Python using **FastMCP**, **Streamable HTTP over `/mcp`**, and **Google Cloud BigQuery**, protected by **Hawkeye Gateway** secret-key authentication with SSO user identity forwarding.

---

## Architecture Overview

```
[ Developer / Claude Desktop / IDE / Inspector ]
│
│ 1. User authenticates via Company SSO (Okta / Microsoft Entra ID)
│    Hawkeye Gateway validates session, forwards:
│    ├── X-Hawkeye-Key: <GATEWAY_SECRET>
│    └── X-User-Email: jane.doe@company.com
▼
┌────────────────────────────────────────────────────────────────────────┐
│                   GCP BigQuery MCP Server (FastMCP)                    │
│ - Streamable HTTP mounted at configured endpoint (default: /mcp)       │
│ - Gateway Auth Middleware (src/auth.py):                               │
│   • Configurable toggle: gateway_auth.enabled (true/false)             │
│   • Validates X-Hawkeye-Key via timing-safe secrets.compare_digest     │
│   • Extracts SSO user email from X-User-Email header                   │
│   • Propagates identity to BigQuery job labels via ContextVar          │
│ - Rate Limiting by SSO user identity (not just IP)                     │
│ - Dynamically exposes ONLY the tools toggled ON in config.yaml         │
│ - Enforces Dual SQL Sanitizer (Regex keywords + AST syntax tree)       │
│ - Connects to BigQuery directly via Service Account JSON key / ADC     │
│ - Binds queries to max_bytes_billed and safe max_results pagination   │
│ - In-memory TTLCache with SHA-256 hashed keys for metadata queries     │
└───────────────────────────────────┬────────────────────────────────────┘
│
│ 2. Direct Machine-to-Machine 2-Legged Auth
│    (bigquery.Client.from_service_account_json / ADC)
▼
┌────────────────────────────────────────────────────────────────────────┐
│                       Google Cloud BigQuery                            │
│ - Enforces permissions via Service Account IAM & Dataset ACLs          │
│ - Executes read queries strictly within max_bytes_billed limit         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Key Features

1. **Inbound Gateway Authentication (Hawkeye)**:
   - Secret-key validation via timing-safe `secrets.compare_digest` (prevents timing side-channel attacks).
   - Fail-closed design: if auth is enabled but no secret key is configured, the server rejects all requests with `500`.
   - SSO user identity forwarded from gateway via `X-User-Email` header, propagated to BigQuery job labels for full audit trails.
   - Supports both custom header (`X-Hawkeye-Key`) and `Authorization: Bearer <key>` fallback.
   - **Configurable Auth Toggle (`gateway_auth.enabled`)**: Toggle off (`false`) for local debugging and MCP Inspector testing, or enforce in production (`true`).
2. **Direct BigQuery Service Account Integration**:
   - Zero interactive OAuth overhead; 2-legged server-to-server authentication directly initialized from the JSON service account key or Application Default Credentials (ADC).
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
   - Identifies callers by **SSO user email** (from gateway auth), with fallback to `X-Forwarded-For` or client IP, returning standard HTTP 429 and `Retry-After` headers while exempting health checks.

---

## File Layout

```text
bq_mcp/
├── config/
│   ├── config.yaml              # Centralized configuration (gateway auth, SA path, tools, rate limit)
│   └── settings.py              # Pydantic Settings loader for config.yaml + .env
├── src/
│   ├── __init__.py
│   ├── auth.py                  # Hawkeye Gateway authentication middleware & SSO identity propagation
│   ├── cache.py                 # TTLCache manager with SHA-256 key hashing
│   ├── sanitizer.py             # Configurable SQL Sanitizer (Regex + AST)
│   ├── client.py                # Thread-safe BigQuery client manager & execution guardrails
│   ├── tools.py                 # Dynamic FastMCP tool definitions with error shielding
│   ├── rate_limiter.py          # Sliding-window rate limiter & Starlette middleware
│   └── server.py                # Middleware stack & Streamable HTTP ASGI app
├── tests/
│   ├── __init__.py
│   ├── conftest.py              # Shared test fixtures
│   ├── test_tools.py            # Unit & integration tests (sanitizer, cache, client, tools, rate limit)
│   ├── test_auth.py             # Gateway auth middleware & SSO identity propagation tests
│   ├── test_audit_hardening.py  # Edge case hardening tests (TTL, concurrency, validation)
│   └── test_request_tags_and_metadata.py  # BigQuery job labels & INFORMATION_SCHEMA restriction tests
├── service-account.json         # BigQuery Service Account JSON key (gitignored)
├── .env.example                 # Optional environment overrides
├── pytest.ini                   # Pytest configuration (asyncio_mode = auto)
├── Dockerfile                   # Hardened Python 3.12 non-root container
├── requirements.txt             # Dependency manifest
├── run.py                       # Root CLI launcher with auto-reload and options
├── ARCHITECTURE.md              # Deep-dive codebase architecture & file guide
└── README.md                    # Setup, client integration, and security documentation
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

# Google Cloud Service Account Authentication (Direct Backend Auth)
auth:
  service_account_key_path: "service-account.json"

# BigQuery Execution Guardrails
bigquery:
  project_id: null                       # null auto-detects from service-account.json
  location: null                         # null auto-detects location per dataset
  default_rows_returned: 50              # Default rows pulled when limit is not specified
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
  restrict_information_schema: true      # Restrict direct queries to INFORMATION_SCHEMA
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

# Inbound Gateway Authentication (Hawkeye / Claude Desktop SSO)
gateway_auth:
  enabled: false                         # Enable key-based gateway authentication
  header_name: "X-Hawkeye-Key"           # Header containing the internal gateway secret
  secret_key: "${HAWKEYE_INTERNAL_SECRET:-}"  # Injected from environment; empty = fail-closed
  user_email_header: "X-User-Email"      # Header forwarded by Hawkeye containing SSO user email
```

### Environment Variable Overrides (`.env`)

| Variable | Target Config | Description |
| :--- | :--- | :--- |
| `GATEWAY_AUTH_ENABLED` | `gateway_auth.enabled` | Set to `true` to enforce gateway secret key validation |
| `GATEWAY_AUTH_HEADER_NAME` | `gateway_auth.header_name` | Name of header containing the secret key (default: `X-Hawkeye-Key`) |
| `HAWKEYE_INTERNAL_SECRET` | `gateway_auth.secret_key` | Secret key expected from Hawkeye Gateway |
| `GATEWAY_AUTH_SECRET_KEY` | `gateway_auth.secret_key` | Fallback env var for gateway secret key |
| `GATEWAY_AUTH_USER_EMAIL_HEADER` | `gateway_auth.user_email_header` | Header containing SSO user email (default: `X-User-Email`) |
| `SERVICE_ACCOUNT_KEY_PATH`| `auth.service_account_key_path`| Filepath to GCP credentials JSON |
| `BIGQUERY_PROJECT_ID` | `bigquery.project_id` | Target Google Cloud project ID |
| `BIGQUERY_LOCATION` | `bigquery.location` | Geographic dataset location (e.g. `US`, `EU`) |
| `BIGQUERY_DEFAULT_ROWS_RETURNED` | `bigquery.default_rows_returned` | Default rows returned when no limit specified (default: `50`) |
| `BIGQUERY_MAX_ROWS_RETURNED` | `bigquery.max_rows_returned` | Maximum rows serialized per query (default: `200`) |
| `BIGQUERY_MAX_BYTES_BILLED` | `bigquery.max_bytes_billed` | Hard cost-ceiling limit in bytes per query (default: `10 GB`) |
| `BIGQUERY_QUERY_TIMEOUT_SECONDS` | `bigquery.query_timeout_seconds` | Query execution timeout in seconds (default: `60`) |
| `BIGQUERY_REQUEST_TAG_NAME` | `bigquery.request_tag_name` | Label key used for BigQuery job tagging (default: `bq_mcp_ext`) |
| `SERVER_HOST` | `server.host` | Host binding IP (default: `0.0.0.0`) |
| `SERVER_PORT` | `server.port` | HTTP listening port (default: `8000`) |
| `SERVER_ENDPOINT_PATH` | `server.endpoint_path` | MCP transport route (default: `/mcp`) |
| `RATE_LIMIT_ENABLED` | `rate_limit.enabled` | Set to `false` to disable MCP endpoint rate limiting |
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | `rate_limit.requests_per_minute` | Max requests per sliding window per client (default: `60`) |
| `RATE_LIMIT_WINDOW_SECONDS` | `rate_limit.window_seconds` | Rate limit sliding window duration in seconds (default: `60`) |

---

## Setup & Prerequisites

### 1. Google Cloud BigQuery Setup

1. Open [Google Cloud Console](https://console.cloud.google.com/).
2. Navigate to **IAM & Admin** > **Service Accounts** > **Create Service Account**.
3. Grant the service account the required IAM roles:
   - **BigQuery Data Viewer** (`roles/bigquery.dataViewer`): Read access to dataset tables and schemas.
   - **BigQuery Job User** (`roles/bigquery.jobUser`): Permission to submit query jobs.
4. Create and download a new **JSON key**.
5. Save the file as `service-account.json` in the root of the project (or specify the path in `config/config.yaml`).

### 2. Hawkeye Gateway Setup

1. Obtain the **internal gateway secret key** from your Hawkeye administrator.
2. Set the secret as an environment variable:
   ```bash
   export HAWKEYE_INTERNAL_SECRET="your-hawkeye-secret-key"
   export GATEWAY_AUTH_ENABLED="true"
   ```
3. The Hawkeye gateway handles Company SSO (Okta / Microsoft Entra ID) and forwards:
   - `X-Hawkeye-Key`: The internal gateway secret for server-side validation.
   - `X-User-Email`: The authenticated SSO user's email for audit trails.

---

## Installation & Local Execution

### 1. Create Virtual Environment and Install Dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run Test Suite

Run the full pytest suite covering gateway auth, SQL AST sanitization, caching, rate limiting, and BigQuery execution:

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
  -e HAWKEYE_INTERNAL_SECRET="your-hawkeye-secret-key" \
  -e GATEWAY_AUTH_ENABLED="true" \
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
In `config/config.yaml`, set `gateway_auth.enabled: false` (or launch with `GATEWAY_AUTH_ENABLED=false`), then run:

```bash
# Terminal 1: Run the MCP Server
python -m src.server

# Terminal 2: Launch MCP Inspector
npx @modelcontextprotocol/inspector
```

- **Transport**: `Streamable HTTP`
- **URL**: `http://localhost:8000/mcp`
- Click **Connect**.

#### B. Production Mode (With Hawkeye Gateway Key)
- **Transport**: `Streamable HTTP`
- **URL**: `http://localhost:8000/mcp`
- **Custom Headers**:
  ```json
  {
    "X-Hawkeye-Key": "your-hawkeye-secret-key"
  }
  ```

### 2. Claude Desktop Integration

Add the server to your `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`):

#### A. Local Development (Auth Disabled — Recommended for Quick Testing)
Set `gateway_auth.enabled: false` in `config/config.yaml` (or `GATEWAY_AUTH_ENABLED=false` in `.env`):

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

#### B. Production Mode (Via Hawkeye Gateway)
When deployed behind Hawkeye, Claude Desktop connects through the gateway URL. The gateway handles SSO authentication and injects the secret key automatically:

```json
{
  "mcpServers": {
    "bigquery": {
      "url": "https://hawkeye-gateway.yourcompany.com/mcp"
    }
  }
}
```

#### C. Direct Connection with Gateway Key (Testing/Staging)
For direct connection with the secret key header:

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
        "X-Hawkeye-Key: your-hawkeye-secret-key"
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
        "X-Hawkeye-Key": "your-hawkeye-secret-key"
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

- **Gateway Authentication**: Timing-safe secret key validation via `secrets.compare_digest`. Fail-closed design prevents unauthenticated access when misconfigured. SSO user email injected into BigQuery job labels for audit trails.
- **AST Mutation Blocking**: Uses `sqlglot` to parse the BigQuery abstract syntax tree. Disallows query chaining (`;`), stored procedure executions (`CALL`), table drops (`DROP`), and data mutations (`INSERT`, `UPDATE`, `DELETE`, `MERGE`), including those obscured within CTEs or subqueries.
- **INFORMATION_SCHEMA Restriction**: Blocks queries accessing `INFORMATION_SCHEMA` in `bq_query_execution` via regex and AST checks, enforcing the use of free BigQuery REST API metadata endpoints.
- **Cost Ceilings (`maximum_bytes_billed`)**: Protects against unexpected high-cost queries by enforcing a hard upper bound on bytes scanned.
- **Container Memory Safeguards**: Automatically sets `max_results` on BigQuery result iteration to prevent container memory exhaustion and out-of-memory crashes.
- **Error Sanitization**: All internal GCP URLs, credential paths, and stack traces are scrubbed from client-facing error messages.
- **Per-User Rate Limiting**: SSO-authenticated users are rate-limited by email identity (not just IP), preventing abuse from shared gateways.
- **Principle of Least Privilege**: Inbound client auth verifies gateway identity and SSO user, while BigQuery machine-to-machine auth is locked down via Google Cloud IAM.
