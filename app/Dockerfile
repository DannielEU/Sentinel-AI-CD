# ── Build stage ───────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .

RUN python -m pip install --upgrade pip setuptools wheel && \
    python -m pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Sentinel-AI-CD Deployment Gate"
LABEL org.opencontainers.image.description="Intelligent CI/CD security gate for container images"
LABEL org.opencontainers.image.vendor="Sentinel-AI-CD"
LABEL org.opencontainers.image.version="2.0.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy entire app directory (hexagonal structure)
COPY app/ ./

# Copy schema.sql so /schema endpoint can serve it
COPY schema.sql /schema.sql

# Persistent data directory for SQLite
RUN mkdir -p /app/data

# Create non-root user
RUN useradd -r -u 1000 -s /sbin/nologin gateuser && \
    chown -R gateuser:gateuser /app

RUN chmod 755 /app

USER gateuser

EXPOSE 8000

HEALTHCHECK --interval=20s --timeout=5s --retries=3 --start-period=15s \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "web.main:app", "--host", "0.0.0.0", "--port", "8000"]
