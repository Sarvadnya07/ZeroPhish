# ==============================================================================
# ZeroPhish Backend — Hardened Multi-Stage Production Dockerfile
# ==============================================================================

# --- Stage 1: Build & Dependencies ---
FROM python:3.13-slim AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install build dependencies required for compiling native wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment to isolate installed dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --extra-index-url https://download.pytorch.org/whl/cpu -r requirements.txt

# --- Stage 2: Hardened Runtime ---
FROM python:3.13-slim AS runner

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ZEROPHISH_ENV=production \
    PATH="/opt/venv/bin:$PATH"

# Install only minimal runtime dependencies (curl for container health checks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Principle of Least Privilege: Create unprivileged application user & group (UID 10001)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/bash -m appuser

# Copy virtual environment from builder stage
COPY --from=builder --chown=appuser:appgroup /opt/venv /opt/venv

# Copy application source code with unprivileged ownership
COPY --chown=appuser:appgroup . .

# Create writable data directory for storage / caches
RUN mkdir -p /app/data && chown -R appuser:appgroup /app/data

# Drop privileges to non-root
USER appuser

EXPOSE 8001

# Container liveness & readiness health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8001/gateway/health || exit 1

# Production gateway launch with multi-worker ASGI server
CMD ["uvicorn", "gateway:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "4"]
