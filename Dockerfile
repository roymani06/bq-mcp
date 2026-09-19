# ==============================================================================
# Hardened Non-Root Production Container for GCP BigQuery MCP Server
# ==============================================================================

FROM python:3.12-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install minimal OS dependencies for security and healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root system group and user
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -d /app -M appuser

# Set up application workspace
WORKDIR /app

# Copy dependency manifest and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code, configuration, and launcher
COPY config/ config/
COPY src/ src/
COPY run.py .

# NOTE: Service account credentials should NOT be baked into the image.
# For production, mount credentials at runtime via:
#   - Kubernetes Secrets / Cloud Run secret mounts
#   - Workload Identity (preferred on GKE/Cloud Run — no key file needed)
#   - Docker secrets: docker run -v /path/to/key.json:/app/service-account.json:ro ...
# The line below is for LOCAL DEVELOPMENT convenience only:
COPY service-account.json* ./

# Ensure correct file permissions for non-root user
RUN chown -R appuser:appgroup /app

# Drop root privileges
USER 10001:10001

# Expose Streamable HTTP port
EXPOSE 8000

# Container healthcheck against /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Launch via the canonical run.py entrypoint (prints banner + starts uvicorn)
ENTRYPOINT ["python", "run.py"]
