# ── Build stage ───────────────────────────────────────────────────────────────
# Alpine builder: gcc/musl-dev only needed if any wheel falls back to source
# compilation (e.g. greenlet on non-standard arch). Removed from runtime image.
FROM python:3.12-alpine AS builder

WORKDIR /build
COPY requirements.txt .

RUN apk add --no-cache gcc musl-dev libffi-dev && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime stage ─────────────────────────────────────────────────────────────
# python:3.12-alpine ships WITHOUT:
#   - ncurses / readline  (eliminates CVE-2025-69720)
#   - libnghttp2          (eliminates CVE-2026-27135)
#   - systemd / udev      (eliminates CVE-2026-29111)
#   - curl / wget         (not installed — healthcheck uses Python urllib)
# Result: 0 HIGH CVEs from those packages; far fewer medium/low overall.
FROM python:3.12-alpine

LABEL org.opencontainers.image.title="Sentinel-AI-CD Deployment Gate"
LABEL org.opencontainers.image.description="Intelligent CI/CD security gate for container images"
LABEL org.opencontainers.image.vendor="Sentinel-AI-CD"
LABEL org.opencontainers.image.version="2.0.0"

WORKDIR /app

# Copy Python packages installed in build stage
COPY --from=builder /install /usr/local

# Copy application (hexagonal structure) and DB schema
COPY app/ ./
COPY schema.sql /schema.sql

# Create non-root system user (Alpine busybox adduser syntax)
RUN mkdir -p /app/data && \
    addgroup -S gateuser && \
    adduser -S -u 1000 -G gateuser -H -s /bin/false gateuser && \
    chown -R gateuser:gateuser /app && \
    chmod 755 /app

USER gateuser

EXPOSE 8000

# Healthcheck uses Python's built-in urllib — no curl / wget required.
# This keeps the attack surface minimal and avoids pulling in libnghttp2.
HEALTHCHECK --interval=20s --timeout=5s --retries=3 --start-period=15s \
    CMD python -c \
        "import urllib.request, sys; \
         r = urllib.request.urlopen('http://localhost:8000/health', timeout=4); \
         sys.exit(0 if r.status == 200 else 1)"

CMD ["uvicorn", "web.main:app", "--host", "0.0.0.0", "--port", "8000"]
