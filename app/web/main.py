"""
Sentinel-AI-CD — Web entry point (FastAPI)
==========================================
Thin controller layer: authentication, rate limiting, routing.
All business logic lives in application.gate_service.GateService.

Run:
    uvicorn web.main:app --reload --port 8000
"""

import hashlib
import html as _html
import logging
import os
import re
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

# Dashboard optional auth — falls back to GATE_AUTH_TOKEN if not set separately
_DASHBOARD_TOKEN_RAW: str | None = os.getenv("DASHBOARD_TOKEN") or GATE_AUTH_TOKEN
_DASHBOARD_TOKEN_HASH: str | None = (
    hashlib.sha256(_DASHBOARD_TOKEN_RAW.encode()).hexdigest() if _DASHBOARD_TOKEN_RAW else None
)

# Allowed characters in image names (same regex used in Pydantic model)
IMAGE_NAME_SAFE = re.compile(r"^[a-zA-Z0-9.:/_\-]+$")

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
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_REQUESTS)
    response.headers["X-RateLimit-Window"] = str(RATE_LIMIT_WINDOW)
    if request.url.path.startswith("/dashboard"):
        # Server-rendered page: allow inline styles/scripts (we control them),
        # block all external resources, restrict form submissions to self.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'unsafe-inline'; "
            "style-src 'unsafe-inline'; "
            "img-src 'self' data:; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
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


def _require_dashboard_token(request: Request) -> None:
    """Protect the dashboard when DASHBOARD_TOKEN or GATE_AUTH_TOKEN is set.

    Accepts the token via ?token= query param (browser-friendly) or
    Authorization: Bearer header (script-friendly).
    """
    if not _DASHBOARD_TOKEN_HASH:
        return
    ip = _client_ip(request)
    if not _check_auth_failures(ip):
        raise HTTPException(status_code=429, detail="Too many authentication failures.")
    provided = request.query_params.get("token", "")
    if not provided:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            provided = auth.removeprefix("Bearer ").strip()
    if not provided:
        _record_auth_failure(ip)
        raise HTTPException(
            status_code=401,
            detail="Dashboard requires authentication. Provide ?token= or Authorization: Bearer header.",
        )
    if not secrets.compare_digest(
        hashlib.sha256(provided.encode()).hexdigest(),
        _DASHBOARD_TOKEN_HASH,
    ):
        _record_auth_failure(ip)
        raise HTTPException(status_code=403, detail="Invalid dashboard token")
    _auth_failures[ip] = []


def _esc(value: object) -> str:
    """HTML-escape a value to prevent XSS in server-rendered templates."""
    return _html.escape(str(value), quote=True)


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
        return await _gate_service.analyze(report, gate_base_url=gate_base_url)  # type: ignore[union-attr]
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
    request: Request,
    limit: int = 20,
    authorization: str | None = Header(default=None),
):
    """Return the scan history for a specific image (requires DB)."""
    _require_token(authorization, _client_ip(request))
    if not _repo or not _repo.is_available:
        raise HTTPException(
            status_code=503,
            detail="Database not configured. Set DATABASE_URL to enable history.",
        )
    decoded = urllib.parse.unquote(image_name)
    return await _repo.get_history(decoded, limit=min(limit, 100))


# ── CVE exception (whitelist) endpoints ──────────────────────────────────────

@app.get("/exceptions", response_model=list[CVEException], tags=["whitelist"])
async def list_exceptions(
    request: Request,
    authorization: str | None = Header(default=None),
):
    """List all active CVE exceptions (whitelist)."""
    _require_token(authorization, _client_ip(request))
    if not _repo or not _repo.is_available:
        raise HTTPException(
            status_code=503,
            detail="Database not configured. Set DATABASE_URL to enable whitelist.",
        )
    return await _repo.get_active_exceptions()


@app.post("/exceptions", status_code=201, tags=["whitelist"])
async def add_exception(
    exc: CVEException,
    request: Request,
    authorization: str | None = Header(default=None),
):
    """Add or update a CVE exception (whitelist entry)."""
    _require_token(authorization, _client_ip(request))
    if not _repo or not _repo.is_available:
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
    request: Request,
    authorization: str | None = Header(default=None),
):
    """Deactivate a CVE exception."""
    _require_token(authorization, _client_ip(request))
    if not _repo or not _repo.is_available:
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
        return '<span style="color:#22c55e">IMPROVING &#8595;</span>'
    if latest_score > older_score:
        return '<span style="color:#ef4444">WORSENING &#8593;</span>'
    return '<span style="color:#6b7280">STABLE &#8594;</span>'


def _bar_chart_svg(records: list[ScanRecord]) -> str:
    """Render an SVG bar chart of the vulnerability score per scan (last 20)."""
    chart_data = list(reversed(records[:20]))
    n = len(chart_data)
    if n == 0:
        return '<p class="no-data">No chart data available.</p>'

    W, H = 760, 180
    ML, MR, MT, MB = 50, 16, 16, 36
    cw, ch = W - ML - MR, H - MT - MB

    scores = [r.critical_vulns * 100 + r.high_vulns * 10 + r.medium_vulns for r in chart_data]
    max_score = max(scores) if any(s > 0 for s in scores) else 1

    bw = cw / n
    bar_gap = max(1.0, bw * 0.25)
    bw_actual = bw - bar_gap

    parts: list[str] = []
    for frac in (0.25, 0.5, 0.75, 1.0):
        gy = MT + ch * (1 - frac)
        label = str(int(max_score * frac))
        parts.append(
            f'<line x1="{ML}" y1="{gy:.1f}" x2="{W - MR}" y2="{gy:.1f}"'
            f' stroke="#1e293b" stroke-width="1"/>'
            f'<text x="{ML - 4}" y="{gy + 4:.1f}" fill="#475569" font-size="9"'
            f' text-anchor="end">{label}</text>'
        )

    for i, (r, score) in enumerate(zip(chart_data, scores)):
        x = ML + i * bw + bar_gap / 2
        bh = int(score / max_score * ch) if max_score > 0 else 0
        if bh == 0 and score > 0:
            bh = 2
        y = MT + ch - bh
        color = _decision_color(r.decision)
        ts = r.scanned_at.strftime("%m/%d") if r.scanned_at else ""
        tip = _esc(
            f"{r.image_name} | {r.decision} | C:{r.critical_vulns} H:{r.high_vulns} M:{r.medium_vulns}"
        )
        parts.append(
            f'<rect x="{x:.1f}" y="{y}" width="{bw_actual:.1f}" height="{max(bh, 2)}"'
            f' fill="{color}" rx="2" opacity="0.85"><title>{tip}</title></rect>'
        )
        if n <= 6 or i % max(1, n // 6) == 0 or i == n - 1:
            parts.append(
                f'<text x="{x + bw_actual / 2:.1f}" y="{H - 4}" fill="#475569"'
                f' font-size="9" text-anchor="middle">{_esc(ts)}</text>'
            )

    parts.append(
        f'<line x1="{ML}" y1="{MT}" x2="{ML}" y2="{MT + ch}" stroke="#334155" stroke-width="1"/>'
        f'<line x1="{ML}" y1="{MT + ch}" x2="{W - MR}" y2="{MT + ch}"'
        f' stroke="#334155" stroke-width="1"/>'
    )
    return (
        f'<svg viewBox="0 0 {W} {H}" style="width:100%;display:block">\n'
        + "\n".join(parts)
        + "\n</svg>"
    )


def _render_dashboard(title: str, records: list[ScanRecord], exceptions: list[CVEException]) -> str:
    safe_title = _esc(title)
    total = len(records)
    approved = sum(1 for r in records if r.decision == "APPROVED")
    warning = sum(1 for r in records if r.decision == "WARNING")
    rejected = sum(1 for r in records if r.decision == "REJECTED")

    def _pct(count: int) -> str:
        return f"{count / total * 100:.0f}%" if total > 0 else "0%"

    rows = ""
    for r in records:
        color = _decision_color(r.decision)
        ts = _esc(r.scanned_at.strftime("%Y-%m-%d %H:%M UTC") if r.scanned_at else "—")
        secrets_badge = (
            f'<span style="color:#ef4444;margin-left:6px">! {r.secrets_found} secret(s)</span>'
            if r.secrets_found
            else ""
        )
        reason_text = r.reason or ""
        reason_short = _esc(reason_text[:80])
        reason_full = _esc(reason_text)
        ellipsis = "&#8230;" if len(reason_text) > 80 else ""
        reason_cell = (
            f'<details><summary style="list-style:none;cursor:pointer;color:#94a3b8;font-size:0.85em">'
            f'{reason_short}{ellipsis}</summary>'
            f'<div style="color:#e2e8f0;padding-top:4px;font-size:0.85em">{reason_full}</div></details>'
        )
        rows += (
            f'<tr data-row>'
            f'<td>{ts}</td>'
            f'<td><span style="color:{color};font-weight:700">{_esc(r.decision)}</span></td>'
            f'<td style="font-family:monospace;font-size:0.83em">{_esc(r.image_name)}</td>'
            f'<td>'
            f'<span style="color:#ef4444">{r.critical_vulns}</span>&#8202;/&#8202;'
            f'<span style="color:#f59e0b">{r.high_vulns}</span>&#8202;/&#8202;'
            f'<span style="color:#eab308">{r.medium_vulns}</span>'
            f'</td>'
            f'<td>{_esc(r.source)}{secrets_badge}</td>'
            f'<td>{reason_cell}</td>'
            f'</tr>\n'
        )

    exc_rows = ""
    for e in exceptions:
        exp = _esc(e.expires_at.strftime("%Y-%m-%d") if e.expires_at else "Never")
        exc_rows += (
            f'<tr>'
            f'<td><code>{_esc(e.cve_id)}</code></td>'
            f'<td>{_esc(e.reason)}</td>'
            f'<td>{_esc(e.approved_by or "—")}</td>'
            f'<td>{exp}</td>'
            f'</tr>\n'
        )

    trend = _trend_badge(records)
    chart_svg = _bar_chart_svg(records)
    chart_count = min(total, 20)

    scan_section = (
        f'<input id="search-input" type="text"'
        f' placeholder="Filter by image, decision, source&#8230;"'
        f' style="width:100%;padding:10px 14px;background:#0f172a;border:1px solid #334155;'
        f'border-radius:8px;color:#e2e8f0;font-size:0.9rem;margin-bottom:12px;outline:none">'
        f'<table id="scan-table"><thead><tr>'
        f'<th>Date</th><th>Decision</th><th>Image</th>'
        f'<th>C&#8202;/&#8202;H&#8202;/&#8202;M</th><th>Source</th><th>Reason</th>'
        f'</tr></thead><tbody>{rows}</tbody></table>'
    ) if rows else '<p class="no-data">No scan records yet.</p>'

    exc_section = (
        f'<table><thead><tr>'
        f'<th>CVE ID</th><th>Reason</th><th>Approved By</th><th>Expires</th>'
        f'</tr></thead><tbody>{exc_rows}</tbody></table>'
    ) if exc_rows else '<p class="no-data">No active exceptions.</p>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sentinel &#8212; {safe_title}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box }}
  body {{ font-family: system-ui, -apple-system, sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; min-height: 100vh }}
  a {{ color: #38bdf8; text-decoration: none }}
  a:hover {{ text-decoration: underline }}
  .topbar {{ background: #020817; border-bottom: 1px solid #1e293b; padding: 14px 32px; display: flex; align-items: center; gap: 16px; flex-wrap: wrap }}
  .topbar h1 {{ color: #38bdf8; margin: 0; font-size: 1.3rem; white-space: nowrap }}
  .topbar .subtitle {{ color: #475569; font-size: 0.88rem; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap }}
  .topbar .trend {{ margin-left: auto; font-size: 0.95rem; white-space: nowrap }}
  .container {{ padding: 28px 32px; max-width: 1440px; margin: 0 auto }}
  .img-search {{ display: flex; gap: 10px; margin-bottom: 28px; background: #1e293b; padding: 16px 20px; border-radius: 12px; align-items: center }}
  .img-search input {{ flex: 1; padding: 9px 14px; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #e2e8f0; font-size: 0.9rem; outline: none }}
  .img-search input:focus {{ border-color: #38bdf8 }}
  .btn {{ padding: 9px 18px; border: none; border-radius: 8px; cursor: pointer; font-size: 0.88rem; white-space: nowrap }}
  .btn-primary {{ background: #0284c7; color: #fff }}
  .btn-primary:hover {{ background: #0369a1 }}
  .btn-ghost {{ background: #334155; color: #cbd5e1 }}
  .btn-ghost:hover {{ background: #475569 }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-bottom: 32px }}
  .stat-card {{ background: #1e293b; border-radius: 12px; padding: 18px 20px; border-left: 4px solid var(--accent) }}
  .stat-label {{ color: #64748b; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.07em }}
  .stat-value {{ color: var(--accent); font-size: 1.9rem; font-weight: 700; margin: 5px 0 2px }}
  .stat-pct {{ color: #475569; font-size: 0.78rem }}
  .section {{ margin-bottom: 40px }}
  h3 {{ color: #94a3b8; font-size: 0.82rem; text-transform: uppercase; letter-spacing: 0.09em; border-bottom: 1px solid #1e293b; padding-bottom: 10px; margin: 0 0 16px }}
  .chart-box {{ background: #1e293b; border-radius: 12px; padding: 20px 20px 14px }}
  .chart-legend {{ display: flex; gap: 20px; margin-top: 12px; font-size: 0.78rem; color: #64748b; flex-wrap: wrap }}
  .ldot {{ width: 10px; height: 10px; border-radius: 2px; display: inline-block; margin-right: 4px; vertical-align: middle }}
  table {{ width: 100%; border-collapse: collapse }}
  th {{ background: #1e293b; color: #64748b; padding: 10px 14px; text-align: left; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em }}
  td {{ padding: 10px 14px; border-bottom: 1px solid #0f172a; font-size: 0.88rem; vertical-align: top }}
  tbody tr:hover td {{ background: rgba(30,41,59,0.4) }}
  .no-data {{ color: #334155; font-style: italic; padding: 16px 0 }}
  code {{ background: #1e293b; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; font-family: monospace }}
  details summary::-webkit-details-marker {{ display: none }}
  details summary::marker {{ display: none }}
</style>
</head>
<body>
<div class="topbar">
  <h1>&#128737; Sentinel-AI-CD</h1>
  <span class="subtitle">{safe_title}</span>
  <span class="trend">{trend}</span>
</div>
<div class="container">

  <div class="img-search">
    <input id="img-input" type="text" placeholder="Image name (e.g. nginx:latest) &#8212; press Enter to view history">
    <button class="btn btn-primary" id="btn-view">View Image</button>
    <button class="btn btn-ghost" id="btn-overview">&#8592; Overview</button>
  </div>

  <div class="stats-grid">
    <div class="stat-card" style="--accent:#38bdf8">
      <div class="stat-label">Total Scans</div>
      <div class="stat-value">{total}</div>
    </div>
    <div class="stat-card" style="--accent:#22c55e">
      <div class="stat-label">Approved</div>
      <div class="stat-value">{approved}</div>
      <div class="stat-pct">{_pct(approved)}</div>
    </div>
    <div class="stat-card" style="--accent:#f59e0b">
      <div class="stat-label">Warning</div>
      <div class="stat-value">{warning}</div>
      <div class="stat-pct">{_pct(warning)}</div>
    </div>
    <div class="stat-card" style="--accent:#ef4444">
      <div class="stat-label">Rejected</div>
      <div class="stat-value">{rejected}</div>
      <div class="stat-pct">{_pct(rejected)}</div>
    </div>
  </div>

  <div class="section">
    <h3>Vulnerability Trend &#8212; last {chart_count} scans</h3>
    <div class="chart-box">
      {chart_svg}
      <div class="chart-legend">
        <span><span class="ldot" style="background:#22c55e"></span>Approved</span>
        <span><span class="ldot" style="background:#f59e0b"></span>Warning</span>
        <span><span class="ldot" style="background:#ef4444"></span>Rejected</span>
        <span style="margin-left:auto">Height = C&#215;100 + H&#215;10 + M</span>
      </div>
    </div>
  </div>

  <div class="section">
    <h3>Scan History</h3>
    {scan_section}
  </div>

  <div class="section">
    <h3>Active CVE Exceptions</h3>
    {exc_section}
  </div>

  <p style="color:#1e293b;font-size:0.78rem;margin-top:24px;border-top:1px solid #1e293b;padding-top:16px">
    Sentinel-AI-CD v2.0
    &bull; <a href="/docs">API Docs</a>
    &bull; <a href="/schema">DB Schema</a>
  </p>
</div>
<script>
(function () {{
  var tok = new URLSearchParams(window.location.search).get('token') || '';
  function withTok(url) {{
    return tok ? url + (url.indexOf('?') === -1 ? '?' : '&') + 'token=' + encodeURIComponent(tok) : url;
  }}

  var imgInput = document.getElementById('img-input');
  var filterInput = document.getElementById('search-input');

  function goToImage() {{
    var v = imgInput.value.trim();
    if (v) window.location.href = withTok('/dashboard/' + encodeURIComponent(v));
  }}

  document.getElementById('btn-view').addEventListener('click', goToImage);
  document.getElementById('btn-overview').addEventListener('click', function () {{
    window.location.href = withTok('/dashboard');
  }});
  imgInput.addEventListener('keydown', function (e) {{
    if (e.key === 'Enter') goToImage();
  }});

  if (filterInput) {{
    filterInput.addEventListener('input', function () {{
      var q = this.value.toLowerCase();
      document.querySelectorAll('#scan-table tbody tr[data-row]').forEach(function (row) {{
        row.style.display = row.textContent.toLowerCase().indexOf(q) !== -1 ? '' : 'none';
      }});
    }});
  }}
}})();
</script>
</body>
</html>"""


@app.get("/dashboard", response_class=HTMLResponse, tags=["dashboard"])
async def dashboard_overview(request: Request):
    """Overall security dashboard — recent scans across all images."""
    _require_dashboard_token(request)
    if not _repo or not _repo.is_available:
        return HTMLResponse(
            content="<h1>Dashboard unavailable</h1><p>Set DATABASE_URL to enable the dashboard.</p>",
            status_code=503,
        )
    records = await _repo.get_all_recent(limit=50)
    exceptions = await _repo.get_active_exceptions()
    return _render_dashboard("Security Overview", records, exceptions)


@app.get("/dashboard/{image_name}", response_class=HTMLResponse, tags=["dashboard"])
async def dashboard_image(image_name: str, request: Request):
    """Security dashboard for a specific image — history and trend."""
    _require_dashboard_token(request)
    if not _repo or not _repo.is_available:
        return HTMLResponse(
            content="<h1>Dashboard unavailable</h1><p>Set DATABASE_URL to enable the dashboard.</p>",
            status_code=503,
        )
    decoded = urllib.parse.unquote(image_name)
    if not IMAGE_NAME_SAFE.match(decoded):
        raise HTTPException(status_code=400, detail="Invalid image name format")
    records = await _repo.get_history(decoded, limit=30)
    exceptions = await _repo.get_active_exceptions()
    return _render_dashboard(f"Image: {decoded}", records, exceptions)


# ── Global exception handler ──────────────────────────────────────────────────

@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    logger.exception("Unhandled exception")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
