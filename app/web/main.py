"""
Sentinel-AI-CD — Web entry point (FastAPI)
==========================================
Thin controller layer: authentication, rate limiting, routing.
All business logic lives in application.gate_service.GateService.

Run:
    uvicorn web.main:app --reload --port 8000
"""

import hashlib
import logging
import os
import secrets
import time
import urllib.parse
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from application.gate_service import GateService
from domain.entities import CVEException, GateDecision, ImageReport, ScanRecord
from infrastructure.ai.factory import create_ai_provider
from infrastructure.persistence.factory import create_repository

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
GATE_AUTH_TOKEN = os.getenv("GATE_AUTH_TOKEN")
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))
AUTH_FAILURE_LIMIT = int(os.getenv("AUTH_FAILURE_LIMIT", "5"))
AUTH_FAILURE_WINDOW = int(os.getenv("AUTH_FAILURE_WINDOW", "300"))

# In-memory rate-limit / auth-failure tracking
_request_timestamps: dict[str, list[float]] = {}
_auth_failures: dict[str, list[float]] = {}

# Shared service instance (set in lifespan)
_gate_service: GateService | None = None
_repo = None


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _gate_service, _repo

    ai_provider = create_ai_provider()
    _repo = await create_repository()
    _gate_service = GateService(ai_provider=ai_provider, repository=_repo)

    logger.info("Sentinel-AI-CD gate ready")
    yield
    # Cleanup (nothing needed currently)


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Sentinel-AI-CD Deployment Gate",
    description=(
        "Intelligent CI/CD security gate for container images. "
        "Combines deterministic OWASP rules, secrets detection, CVE whitelist, "
        "and an optional AI provider (Ollama / OpenAI / Anthropic)."
    ),
    version="2.0.0",
    docs_url=None if os.getenv("DISABLE_DOCS", "false").lower() in {"1", "true"} else "/docs",
    redoc_url=None,
    lifespan=lifespan,
)

allowed_origins = os.getenv(
    "CORS_ORIGINS",
    "http://localhost,http://localhost:8000,http://localhost:8080",
).split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)


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


# ── Auth / rate-limit helpers ─────────────────────────────────────────────────

def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _check_rate_limit(ip: str) -> bool:
    now = time.time()
    ts = _request_timestamps.setdefault(ip, [])
    _request_timestamps[ip] = [t for t in ts if now - t < RATE_LIMIT_WINDOW]
    if len(_request_timestamps[ip]) >= RATE_LIMIT_REQUESTS:
        return False
    _request_timestamps[ip].append(now)
    return True


def _check_auth_failures(ip: str) -> bool:
    now = time.time()
    fs = _auth_failures.setdefault(ip, [])
    _auth_failures[ip] = [t for t in fs if now - t < AUTH_FAILURE_WINDOW]
    return len(_auth_failures[ip]) < AUTH_FAILURE_LIMIT


def _record_auth_failure(ip: str) -> None:
    _auth_failures.setdefault(ip, []).append(time.time())


def _require_token(authorization: str | None, ip: str) -> None:
    if not GATE_AUTH_TOKEN:
        return
    if not _check_auth_failures(ip):
        raise HTTPException(status_code=429, detail="Too many authentication failures.")
    if not authorization or not authorization.startswith("Bearer "):
        _record_auth_failure(ip)
        raise HTTPException(status_code=401, detail="Missing or invalid bearer token format")
    provided = authorization.removeprefix("Bearer ").strip()
    if not secrets.compare_digest(
        hashlib.sha256(provided.encode()).hexdigest(),
        hashlib.sha256(GATE_AUTH_TOKEN.encode()).hexdigest(),
    ):
        _record_auth_failure(ip)
        raise HTTPException(status_code=403, detail="Invalid authentication token")
    _auth_failures[ip] = []


# ── Health / info endpoints ───────────────────────────────────────────────────

@app.get("/", tags=["health"])
def root():
    db_available = _repo.is_available if _repo else False
    return {
        "status": "ok",
        "service": "Sentinel-AI-CD Deployment Gate",
        "version": "2.0.0",
        "db_enabled": db_available,
    }


@app.get("/health", tags=["health"])
def health():
    db_available = _repo.is_available if _repo else False
    return {"status": "ok", "db_enabled": db_available}


# ── Main gate endpoint ────────────────────────────────────────────────────────

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
    return a gate decision (APPROVED / WARNING / REJECTED).

    ### Pipeline
    1. Secrets detected in Dockerfile → **REJECTED** (secrets_detector)
    2. CVE whitelist loaded from DB (if configured)
    3. Deterministic OWASP rule engine
    4. Optional AI enrichment (Ollama / OpenAI / Anthropic)

    ### Decision values
    | Value      | Pipeline behaviour            |
    |------------|-------------------------------|
    | `APPROVED` | Continue deployment normally  |
    | `WARNING`  | Continue but log alert        |
    | `REJECTED` | Abort deployment with error   |
    """
    ip = _client_ip(request)

    if not _check_rate_limit(ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded: max {RATE_LIMIT_REQUESTS} req/{RATE_LIMIT_WINDOW}s.",
        )

    _require_token(authorization, ip)

    total_vulns = sum([
        report.vulnerabilities.critical,
        report.vulnerabilities.high,
        report.vulnerabilities.medium,
        report.vulnerabilities.low,
        report.vulnerabilities.unknown,
    ])
    if total_vulns > 100_000:
        raise HTTPException(status_code=400, detail="Invalid vulnerability counts")

    logger.info("Received report for %s from %s", report.image_name, ip)

    gate_base_url = str(request.base_url).rstrip("/")

    try:
        return await _gate_service.analyze(report, gate_base_url=gate_base_url)
    except httpx.ConnectError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"AI provider not reachable: {exc}",
        )
    except httpx.TimeoutException as exc:
        raise HTTPException(
            status_code=504,
            detail=f"AI provider timed out: {exc}",
        )
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"AI provider returned HTTP {exc.response.status_code}",
        )
    except Exception as exc:
        logger.exception("Unexpected error during gate analysis")
        raise HTTPException(status_code=500, detail=str(exc) or "Internal error")


# ── History endpoint ──────────────────────────────────────────────────────────

@app.get("/history/{image_name}", response_model=list[ScanRecord], tags=["history"])
async def get_history(
    image_name: str,
    limit: int = 20,
    authorization: str | None = Header(default=None),
    request: Request = None,
):
    """Return the scan history for a specific image (requires DB)."""
    _require_token(authorization, _client_ip(request) if request else "unknown")
    if not _repo.is_available:
        raise HTTPException(
            status_code=503,
            detail="Database not configured. Set DATABASE_URL to enable history.",
        )
    decoded = urllib.parse.unquote(image_name)
    return await _repo.get_history(decoded, limit=min(limit, 100))


# ── CVE exception (whitelist) endpoints ──────────────────────────────────────

@app.get("/exceptions", response_model=list[CVEException], tags=["whitelist"])
async def list_exceptions(
    authorization: str | None = Header(default=None),
    request: Request = None,
):
    """List all active CVE exceptions (whitelist)."""
    _require_token(authorization, _client_ip(request) if request else "unknown")
    if not _repo.is_available:
        raise HTTPException(
            status_code=503,
            detail="Database not configured. Set DATABASE_URL to enable whitelist.",
        )
    return await _repo.get_active_exceptions()


@app.post("/exceptions", status_code=201, tags=["whitelist"])
async def add_exception(
    exc: CVEException,
    authorization: str | None = Header(default=None),
    request: Request = None,
):
    """Add or update a CVE exception (whitelist entry)."""
    _require_token(authorization, _client_ip(request) if request else "unknown")
    if not _repo.is_available:
        raise HTTPException(
            status_code=503,
            detail="Database not configured. Set DATABASE_URL to enable whitelist.",
        )
    await _repo.add_exception(exc)
    logger.info("CVE exception added: %s (approved_by=%s)", exc.cve_id, exc.approved_by)
    return {"status": "created", "cve_id": exc.cve_id.upper()}


@app.delete("/exceptions/{cve_id}", status_code=204, tags=["whitelist"])
async def delete_exception(
    cve_id: str,
    authorization: str | None = Header(default=None),
    request: Request = None,
):
    """Deactivate a CVE exception."""
    _require_token(authorization, _client_ip(request) if request else "unknown")
    if not _repo.is_available:
        raise HTTPException(
            status_code=503,
            detail="Database not configured.",
        )
    await _repo.delete_exception(cve_id)
    logger.info("CVE exception deactivated: %s", cve_id)


# ── Schema endpoint ───────────────────────────────────────────────────────────

@app.get("/schema", response_class=PlainTextResponse, tags=["info"])
def get_schema():
    """Return the database SQL schema."""
    schema_path = Path(__file__).parent.parent.parent / "schema.sql"
    if schema_path.exists():
        return schema_path.read_text()
    return "-- schema.sql not found"


# ── Dashboard ─────────────────────────────────────────────────────────────────

def _decision_color(d: str) -> str:
    return {"APPROVED": "#22c55e", "WARNING": "#f59e0b", "REJECTED": "#ef4444"}.get(d, "#6b7280")


def _trend_badge(records: list[ScanRecord]) -> str:
    if len(records) < 2:
        return ""
    latest = records[0]
    older = records[-1]
    latest_score = latest.critical_vulns * 100 + latest.high_vulns * 10 + latest.medium_vulns
    older_score = older.critical_vulns * 100 + older.high_vulns * 10 + older.medium_vulns
    if latest_score < older_score:
        return '<span style="color:#22c55e;font-size:1.2em">&#8203;IMPROVING ↓</span>'
    if latest_score > older_score:
        return '<span style="color:#ef4444;font-size:1.2em">WORSENING ↑</span>'
    return '<span style="color:#6b7280">STABLE →</span>'


def _render_dashboard(title: str, records: list[ScanRecord], exceptions: list[CVEException]) -> str:
    rows = ""
    for r in records:
        color = _decision_color(r.decision)
        ts = r.scanned_at.strftime("%Y-%m-%d %H:%M UTC") if r.scanned_at else "—"
        secrets_badge = (
            f'<span style="color:#ef4444"> ⚠ {r.secrets_found} secret(s)</span>'
            if r.secrets_found
            else ""
        )
        rows += (
            f"<tr>"
            f"<td>{ts}</td>"
            f"<td style='color:{color};font-weight:bold'>{r.decision}</td>"
            f"<td>{r.image_name}</td>"
            f"<td>{r.critical_vulns} / {r.high_vulns} / {r.medium_vulns}</td>"
            f"<td>{r.source}{secrets_badge}</td>"
            f"<td style='font-size:0.85em;color:#6b7280'>{r.reason[:80]}...</td>"
            f"</tr>\n"
        )

    exc_rows = ""
    for e in exceptions:
        exp = e.expires_at.strftime("%Y-%m-%d") if e.expires_at else "Never"
        exc_rows += (
            f"<tr>"
            f"<td><code>{e.cve_id}</code></td>"
            f"<td>{e.reason}</td>"
            f"<td>{e.approved_by or '—'}</td>"
            f"<td>{exp}</td>"
            f"</tr>\n"
        )

    trend = _trend_badge(records)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sentinel — {title}</title>
<style>
  body {{font-family:system-ui,sans-serif;margin:0;padding:24px;background:#0f172a;color:#e2e8f0}}
  h1 {{color:#38bdf8;margin-bottom:4px}}
  h2 {{color:#94a3b8;font-size:1rem;font-weight:normal;margin-top:0}}
  h3 {{color:#cbd5e1;border-bottom:1px solid #334155;padding-bottom:8px}}
  table {{width:100%;border-collapse:collapse;margin-bottom:32px}}
  th {{background:#1e293b;color:#94a3b8;padding:10px 12px;text-align:left;font-size:0.85rem}}
  td {{padding:9px 12px;border-bottom:1px solid #1e293b;font-size:0.9rem;vertical-align:top}}
  tr:hover td {{background:#1e293b}}
  .badge {{display:inline-block;padding:2px 10px;border-radius:9999px;font-size:0.8rem}}
  .no-data {{color:#475569;font-style:italic;padding:16px 0}}
  code {{background:#1e293b;padding:2px 6px;border-radius:4px;font-size:0.85em}}
  .trend {{font-size:1.1rem;margin-bottom:16px}}
</style>
</head>
<body>
<h1>&#128737; Sentinel-AI-CD</h1>
<h2>{title}</h2>

<div class="trend">{trend}</div>

<h3>Scan History</h3>
{"<table><thead><tr><th>Date</th><th>Decision</th><th>Image</th><th>C/H/M</th><th>Source</th><th>Reason</th></tr></thead><tbody>" + rows + "</tbody></table>" if rows else '<p class="no-data">No scan records yet.</p>'}

<h3>Active CVE Exceptions (Whitelist)</h3>
{"<table><thead><tr><th>CVE ID</th><th>Reason</th><th>Approved By</th><th>Expires</th></tr></thead><tbody>" + exc_rows + "</tbody></table>" if exc_rows else '<p class="no-data">No active exceptions.</p>'}

<p style="color:#475569;font-size:0.8rem;margin-top:32px">
  Sentinel-AI-CD v2.0 &bull; <a href="/docs" style="color:#38bdf8">API Docs</a>
  &bull; <a href="/schema" style="color:#38bdf8">DB Schema</a>
</p>
</body>
</html>"""


@app.get("/dashboard", response_class=HTMLResponse, tags=["dashboard"])
async def dashboard_overview():
    """Overall security dashboard — recent scans across all images."""
    if not _repo.is_available:
        return HTMLResponse(
            content="<h1>Dashboard unavailable</h1><p>Set DATABASE_URL to enable the dashboard.</p>",
            status_code=503,
        )
    records = await _repo.get_all_recent(limit=50)
    exceptions = await _repo.get_active_exceptions()
    return _render_dashboard("Security Overview", records, exceptions)


@app.get("/dashboard/{image_name}", response_class=HTMLResponse, tags=["dashboard"])
async def dashboard_image(image_name: str):
    """Security dashboard for a specific image — history and trend."""
    if not _repo.is_available:
        return HTMLResponse(
            content="<h1>Dashboard unavailable</h1><p>Set DATABASE_URL to enable the dashboard.</p>",
            status_code=503,
        )
    decoded = urllib.parse.unquote(image_name)
    records = await _repo.get_history(decoded, limit=30)
    exceptions = await _repo.get_active_exceptions()
    return _render_dashboard(f"Image: {decoded}", records, exceptions)


# ── Global exception handler ──────────────────────────────────────────────────

@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    logger.exception("Unhandled exception")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
