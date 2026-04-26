"""
AI DevSecOps Deployment Gate
============================
FastAPI service that acts as an intelligent CI/CD gate for container images.

Flow
----
1. Receive a security report (POST /analyze-image).
2. Run the deterministic rule engine.
   - If a rule fires  → return the decision immediately (no LLM call).
3. If no rule fires   → forward the report to the local Ollama/Mistral model.
4. Return a structured GateDecision JSON to the pipeline.

Run
---
    uvicorn main:app --reload --port 8000
"""

import logging
import os
import secrets
import hashlib
import time
from datetime import datetime, timedelta

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import rule_engine
import ollama_client
from schemas import GateDecision, ImageReport

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

AI_DISABLED = os.getenv("AI_DISABLED", "false").lower() in {"1", "true", "yes", "on"}
GATE_AUTH_TOKEN = os.getenv("GATE_AUTH_TOKEN")

# Rate limiting configuration
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))  # requests per minute
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # seconds
AUTH_FAILURE_LIMIT = int(os.getenv("AUTH_FAILURE_LIMIT", "5"))  # failed attempts
AUTH_FAILURE_WINDOW = int(os.getenv("AUTH_FAILURE_WINDOW", "300"))  # seconds (5 min)

# In-memory tracking for rate limiting and auth failures
request_timestamps: dict[str, list[float]] = {}
auth_failures: dict[str, list[float]] = {}


def _get_client_ip(request: Request) -> str:
    """Extract real client IP, accounting for proxies"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _check_rate_limit(client_ip: str) -> bool:
    """Check if client has exceeded rate limit"""
    now = time.time()

    if client_ip not in request_timestamps:
        request_timestamps[client_ip] = []

    # Remove old timestamps outside window
    request_timestamps[client_ip] = [
        ts for ts in request_timestamps[client_ip]
        if now - ts < RATE_LIMIT_WINDOW
    ]

    # Check limit
    if len(request_timestamps[client_ip]) >= RATE_LIMIT_REQUESTS:
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        return False

    # Add current timestamp
    request_timestamps[client_ip].append(now)
    return True


def _check_auth_failures(client_ip: str) -> bool:
    """Check if client has exceeded auth failure limit"""
    now = time.time()

    if client_ip not in auth_failures:
        auth_failures[client_ip] = []

    # Remove old failures outside window
    auth_failures[client_ip] = [
        ts for ts in auth_failures[client_ip]
        if now - ts < AUTH_FAILURE_WINDOW
    ]

    # Check limit
    if len(auth_failures[client_ip]) >= AUTH_FAILURE_LIMIT:
        logger.warning(f"Auth failure limit exceeded for IP: {client_ip}")
        return False

    return True


def _record_auth_failure(client_ip: str) -> None:
    """Record an authentication failure"""
    now = time.time()
    if client_ip not in auth_failures:
        auth_failures[client_ip] = []
    auth_failures[client_ip].append(now)
    logger.warning(f"Auth failure recorded for IP: {client_ip}")


def _hash_token(token: str) -> str:
    """Hash token using SHA-256 (for secure comparison)"""
    return hashlib.sha256(token.encode()).hexdigest()


def _require_token(authorization: str | None, client_ip: str) -> None:
    """Validate bearer token with rate limiting"""
    if not GATE_AUTH_TOKEN:
        return

    # Check auth failure limit first
    if not _check_auth_failures(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many authentication failures. Please try again later."
        )

    if not authorization or not authorization.startswith("Bearer "):
        _record_auth_failure(client_ip)
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid bearer token format"
        )

    provided_token = authorization.removeprefix("Bearer ").strip()

    # Use constant-time comparison with hashed tokens
    provided_hash = _hash_token(provided_token)
    expected_hash = _hash_token(GATE_AUTH_TOKEN)

    if not secrets.compare_digest(provided_hash, expected_hash):
        _record_auth_failure(client_ip)
        raise HTTPException(
            status_code=403,
            detail="Invalid authentication token"
        )

    # Clear auth failures on success
    if client_ip in auth_failures:
        auth_failures[client_ip] = []

app = FastAPI(
    title="AI DevSecOps Deployment Gate",
    description=(
        "Intelligent CI/CD gate that analyses container-image security reports "
        "using deterministic rules and a local LLM (via Ollama) to decide "
        "whether a deployment should be APPROVED, trigger a WARNING, or be REJECTED."
    ),
    version="1.3.0",
    docs_url=None if os.getenv("DISABLE_DOCS", "false").lower() in {"1", "true"} else "/docs",
    redoc_url=None,
)

# Rate limiting is handled manually in the route handlers

# Configure CORS for CI/CD pipelines (restrict to localhost/CI environment)
allowed_origins = os.getenv("CORS_ORIGINS", "http://localhost,http://localhost:8000,http://localhost:8080").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_REQUESTS)
    response.headers["X-RateLimit-Window"] = str(RATE_LIMIT_WINDOW)
    return response


@app.get("/", tags=["health"])
def root():
    return {"status": "ok", "service": "AI DevSecOps Deployment Gate", "ai_disabled": AI_DISABLED}


@app.get("/health", tags=["health"])
def health():
    return {"status": "ok", "ai_disabled": AI_DISABLED}


@app.post(
    "/analyze-image",
    response_model=GateDecision,
    tags=["gate"],
    summary="Analyse a container image security report and return a deployment decision",
)
async def analyze_image(
    report: ImageReport,
    request: Request,
    authorization: str | None = Header(default=None),
):
    """
    Receive a container-image security report from the CI/CD pipeline and
    return a gate decision.

    ### Authentication
    Include Bearer token in Authorization header:
    ```
    Authorization: Bearer <your-token>
    ```

    ### Rate Limiting
    - Default: 100 requests per 60 seconds per IP
    - Headers: X-RateLimit-Limit, X-RateLimit-Window

    ### Decision values
    | Value      | Pipeline behaviour            |
    |------------|-------------------------------|
    | `APPROVED` | Continue deployment normally  |
    | `WARNING`  | Continue but log alert        |
    | `REJECTED` | Abort deployment with error   |

    ### Example request body
    ```json
    {
      "image_name": "myapp:1.2.3",
      "image_size_mb": 320,
      "vulnerabilities": {
        "critical": 0,
        "high": 2,
        "medium": 8,
        "low": 15,
        "unknown": 1
      },
      "base_image": "python:3.11-slim",
      "os_family": "debian"
    }
    ```
    """
    client_ip = _get_client_ip(request)

    # Check rate limit
    if not _check_rate_limit(client_ip):
        logger.warning("Rate limit exceeded for IP: %s", client_ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Max {RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_WINDOW} seconds."
        )

    # Validate authentication
    _require_token(authorization, client_ip)

    # Validate report data
    total_vulns = sum([
        report.vulnerabilities.critical,
        report.vulnerabilities.high,
        report.vulnerabilities.medium,
        report.vulnerabilities.low,
        report.vulnerabilities.unknown,
    ])
    if total_vulns > 100000:
        logger.warning("Suspicious report with %d vulnerabilities from %s (%s)",
                      total_vulns, report.image_name, client_ip)
        raise HTTPException(status_code=400, detail="Invalid vulnerability counts")

    logger.info("Received report for image: %s from %s", report.image_name, client_ip)

    # ── 1. Deterministic rule engine ────────────────────────────────────────
    rule_result = rule_engine.evaluate(report)

    if rule_result is not None:
        logger.info(
            "Rule engine decision for %s: %s", report.image_name, rule_result.decision
        )

        # For WARNING decisions, try to get AI-enriched summary if AI is enabled
        ai_summary = rule_result.summary
        if (
            rule_result.decision == "WARNING"
            and not AI_DISABLED
        ):
            try:
                ai_generated_summary = await ollama_client.generate_summary(
                    report, rule_result.decision, rule_result.reason
                )
                if ai_generated_summary:
                    ai_summary = ai_generated_summary
                    logger.info("AI enriched summary for %s (Ollama responded successfully)", report.image_name)
                else:
                    logger.warning(
                        "Ollama did not return a summary for %s — using rule engine fallback",
                        report.image_name,
                    )
            except Exception as exc:
                logger.warning(
                    "AI summary generation failed for %s (continuing with fallback): %s",
                    report.image_name,
                    exc,
                )
                # Service continues — using rule_result.summary as fallback

        return GateDecision(
            decision=rule_result.decision,
            reason=rule_result.reason,
            recommendations=rule_result.recommendations,
            summary=ai_summary,
            source="rule_engine",
            image_name=report.image_name,
        )

    # ── 2. AI model analysis (Ollama / Mistral) ──────────────────────────────
    if AI_DISABLED:
        logger.info(
            "AI disabled; approving %s after deterministic checks.",
            report.image_name,
        )
        return GateDecision(
            decision="APPROVED",
            reason="No deterministic rule fired and AI fallback is disabled for this environment.",
            recommendations=[
                "Keep scheduled image scanning enabled in CI.",
                "Review warning thresholds periodically as the image evolves.",
            ],
            source="rule_engine",
            image_name=report.image_name,
        )

    logger.info("No rule fired for %s - forwarding to AI model.", report.image_name)
    try:
        decision = await ollama_client.analyze(report)
        logger.info(
            "AI model decision for %s: %s", report.image_name, decision.decision
        )
        return decision

    except httpx.ConnectError:
        logger.error("Cannot reach Ollama at %s", ollama_client.OLLAMA_BASE_URL)
        raise HTTPException(
            status_code=503,
            detail=(
                f"Ollama service is not reachable at {ollama_client.OLLAMA_BASE_URL}. "
                "Make sure `ollama serve` is running and the model is pulled "
                f"(`ollama pull {ollama_client.OLLAMA_MODEL}`)."
            ),
        )
    except httpx.HTTPStatusError as exc:
        logger.error("Ollama returned HTTP %s", exc.response.status_code)
        raise HTTPException(
            status_code=502,
            detail=f"Ollama returned an error: {exc.response.text[:300]}",
        )
    except Exception as exc:
        logger.exception("Unexpected error during AI analysis")
        raise HTTPException(status_code=500, detail=str(exc))


# ── Global exception handler ────────────────────────────────────────────────
@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    logger.exception("Unhandled exception")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
