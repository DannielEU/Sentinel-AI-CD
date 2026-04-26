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

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy entire app directory (hexagonal structure)
COPY app/ ./

# Copy schema.sql so /schema endpoint can serve it
COPY schema.sql /schema.sql

# ── Security hardening ────────────────────────────────────────────────────────
# Step 1: Apply all available Debian security patches (resolves medium/low CVEs)
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# Step 2: Remove packages with HIGH CVEs that have no upstream fix yet and are
# not required by a headless FastAPI server.
#   ncurses*      — interactive terminal support, not needed for a server process
#   libnghttp2-14 — C nghttp2 lib; httpx/h2 uses pure-Python HTTP/2, not this
#   libsystemd0   — systemd library, irrelevant inside a container
#   libudev1      — udev device manager library, irrelevant inside a container
# Using ; separators so that partial dep conflicts don't abort the build.
RUN apt-get update \
 ; apt-get purge -y --auto-remove \
       libncursesw6 libtinfo6 ncurses-base ncurses-bin \
       libnghttp2-14 \
       libsystemd0 libudev1 \
 ; apt-get autoremove -y \
 ; rm -rf /var/lib/apt/lists/*

# Persistent data directory for SQLite and permissions
RUN mkdir -p /app/data && \
    useradd -r -u 1000 -s /sbin/nologin gateuser && \
    chown -R gateuser:gateuser /app && \
    chmod 755 /app

USER gateuser

EXPOSE 8000

HEALTHCHECK --interval=20s --timeout=5s --retries=3 --start-period=15s \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "web.main:app", "--host", "0.0.0.0", "--port", "8000"]
