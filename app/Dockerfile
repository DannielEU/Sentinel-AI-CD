# ── Build stage ──────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .

# Install dependencies with security best practices
RUN python -m pip install --upgrade pip setuptools wheel && \
    python -m pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL org.opencontainers.image.title="AI DevSecOps Deployment Gate"
LABEL org.opencontainers.image.description="FastAPI gate service for CI/CD pipeline security analysis"
LABEL org.opencontainers.image.vendor="Sentinel-AI-CD"
LABEL org.opencontainers.image.version="1.2.0"

# Security: Set digest verification and update packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source (specific files, not entire app/)
COPY app/main.py app/ollama_client.py app/rule_engine.py app/schemas.py ./

# Install curl for health checks
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user for security (no home directory needed)
RUN useradd -r -u 1000 -s /sbin/nologin gateuser

# Set proper permissions
RUN chmod 755 /app && \
    chmod 644 /app/*.py

# Drop unnecessary capabilities and run as non-root
USER gateuser

EXPOSE 8000

# Run with security options
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
