"""
HexaFlow — Web entry point (FastAPI)
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

from application.code_gate_service import CodeGateService
from application.gate_service import GateService
from domain.code_entities import CodeScanDecision, CodeScanRecord, CodeScanReport
from domain.entities import CVEException, GateDecision, ImageReport, ScanRecord
from infrastructure.ai.factory import create_ai_provider, create_code_analyzer
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

# Shared service instances (set in lifespan)
_gate_service: GateService | None = None
_code_gate_service: CodeGateService | None = None
_repo = None


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _gate_service, _code_gate_service, _repo

    ai_provider = create_ai_provider()
    code_analyzer = create_code_analyzer()
    _repo = await create_repository()
    _gate_service = GateService(ai_provider=ai_provider, repository=_repo)
    _code_gate_service = CodeGateService(code_analyzer=code_analyzer, repository=_repo)

    logger.info("HexaFlow gate ready (image + code analysis)")
    yield


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="HexaFlow Deployment Gate",
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
        "service": "HexaFlow Deployment Gate",
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


# ── Code analysis endpoint ───────────────────────────────────────────────────

@app.post(
    "/analyze-code",
    response_model=CodeScanDecision,
    tags=["code-gate"],
    summary="Analyse source code files for security vulnerabilities and return a gate decision",
)
async def analyze_code(
    report: CodeScanReport,
    request: Request,
    authorization: str | None = Header(default=None),
):
    """
    Receive source code files and return a security gate decision (PASSED / WARNING / BLOCKED).

    ### Pipeline
    1. Each file is analyzed via the configured AI provider (Ollama / OpenAI / Anthropic)
    2. OWASP Top 10 vulnerabilities are identified with severity: CRITICAL | HIGH | MEDIUM | LOW
    3. Deterministic threshold rules determine the final decision
    4. Result is persisted to the database if configured

    ### Decision values
    | Value     | Pipeline behaviour                     |
    |-----------|----------------------------------------|
    | `PASSED`  | No critical or high findings — proceed |
    | `WARNING` | Medium/high findings — review required |
    | `BLOCKED` | Critical/high findings — push blocked  |
    """
    ip = _client_ip(request)

    if not _check_rate_limit(ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded: max {RATE_LIMIT_REQUESTS} req/{RATE_LIMIT_WINDOW}s.",
        )

    _require_token(authorization, ip)

    logger.info(
        "Code scan request: project='%s' files=%d from %s",
        report.project_name,
        len(report.files),
        ip,
    )

    try:
        return await _code_gate_service.analyze(report)  # type: ignore[union-attr]
    except httpx.ConnectError as exc:
        raise HTTPException(status_code=503, detail=f"AI provider not reachable: {exc}")
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail=f"AI provider timed out: {exc}")
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"AI provider returned HTTP {exc.response.status_code}",
        )
    except Exception as exc:
        logger.exception("Unexpected error during code gate analysis")
        raise HTTPException(status_code=500, detail=str(exc) or "Internal error")


# ── Code history endpoint ─────────────────────────────────────────────────────

@app.get("/code-history/{project_name}", response_model=list[CodeScanRecord], tags=["code-gate"])
async def get_code_history(
    project_name: str,
    request: Request,
    limit: int = 20,
    authorization: str | None = Header(default=None),
):
    """Return the code scan history for a specific project (requires DB)."""
    _require_token(authorization, _client_ip(request))
    if not _repo or not _repo.is_available:
        raise HTTPException(
            status_code=503,
            detail="Database not configured. Set DATABASE_URL to enable history.",
        )
    return await _repo.get_code_history(project_name, limit=min(limit, 100))


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

_DASHBOARD_CSS = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d0b1e;--bg2:#13102a;--card:#1a1635;--card2:#231e42;
  --border:#474080;--border2:#2e2955;
  --primary:#1E00FF;--primary-l:#4d35ff;
  --gold:#FFBD00;--yellow:#FFFB00;
  --muted:#808066;--text:#F0EEFF;--text2:#b8b0d8;
  --ok:#4ade80;--warn:#FFBD00;--err:#f87171;
  --r:12px;--rs:8px;
}
html{scroll-behavior:smooth}
body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;line-height:1.5}
a{color:var(--gold);text-decoration:none}
a:hover{color:var(--yellow);text-decoration:underline}
code{font-family:'JetBrains Mono','Fira Code',monospace;font-size:.85em;background:var(--card2);padding:2px 6px;border-radius:4px}
/* Topbar */
.topbar{background:var(--bg2);border-bottom:2px solid var(--border);padding:0 28px;display:flex;align-items:center;gap:20px;flex-wrap:wrap;min-height:64px;position:sticky;top:0;z-index:100;box-shadow:0 2px 20px rgba(30,0,255,.18)}
.logo-wrap{display:flex;align-items:center;gap:10px;text-decoration:none;flex-shrink:0;cursor:pointer}
.logo-hex{width:38px;height:38px}
.logo-text{font-size:1.35rem;font-weight:800;color:var(--text);letter-spacing:-.02em}
.logo-text span{color:var(--gold)}
.topbar-sub{color:var(--muted);font-size:.85rem;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.topbar-actions{display:flex;align-items:center;gap:10px;margin-left:auto;flex-wrap:wrap}
/* Trend */
.badge-improving{color:var(--ok);background:rgba(74,222,128,.1);padding:4px 10px;border-radius:20px;border:1px solid rgba(74,222,128,.3);font-size:.85rem;font-weight:600}
.badge-worsening{color:var(--err);background:rgba(248,113,113,.1);padding:4px 10px;border-radius:20px;border:1px solid rgba(248,113,113,.3);font-size:.85rem;font-weight:600}
.badge-stable{color:var(--muted);background:rgba(128,128,102,.1);padding:4px 10px;border-radius:20px;border:1px solid rgba(128,128,102,.3);font-size:.85rem;font-weight:600}
/* Container */
.container{padding:28px;max-width:1440px;margin:0 auto}
/* Buttons */
.btn{display:inline-flex;align-items:center;gap:6px;padding:9px 18px;border:none;border-radius:var(--rs);cursor:pointer;font-size:.88rem;font-weight:600;transition:all .15s;white-space:nowrap;text-decoration:none;line-height:1}
.btn:active{transform:scale(.97)}
.btn-primary{background:var(--primary);color:#fff;box-shadow:0 2px 12px rgba(30,0,255,.35)}
.btn-primary:hover{background:var(--primary-l);box-shadow:0 4px 20px rgba(30,0,255,.5)}
.btn-gold{background:var(--gold);color:#13102a;font-weight:700}
.btn-gold:hover{background:var(--yellow)}
.btn-ghost{background:var(--card2);color:var(--text2);border:1px solid var(--border2)}
.btn-ghost:hover{background:var(--card);border-color:var(--border);color:var(--text)}
.btn-danger{background:rgba(248,113,113,.12);color:var(--err);border:1px solid rgba(248,113,113,.3)}
.btn-danger:hover{background:rgba(248,113,113,.22)}
.btn-sm{padding:5px 12px;font-size:.78rem}
.btn-icon{padding:8px 14px}
/* Image search */
.img-search{display:flex;gap:10px;margin-bottom:28px;background:var(--card);padding:16px 20px;border-radius:var(--r);align-items:center;border:1px solid var(--border2);flex-wrap:wrap}
.img-search input{flex:1;min-width:200px;padding:9px 14px;background:var(--bg);border:1px solid var(--border2);border-radius:var(--rs);color:var(--text);font-size:.9rem;outline:none;transition:border-color .15s}
.img-search input:focus{border-color:var(--primary)}
.img-search-lbl{color:var(--muted);font-size:.85rem;white-space:nowrap}
/* Stats */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:16px;margin-bottom:32px}
.stat-card{background:var(--card);border-radius:var(--r);padding:20px;border-top:3px solid var(--ac);position:relative;overflow:hidden;transition:transform .15s,box-shadow .15s}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;bottom:0;background:linear-gradient(135deg,var(--ac) 0%,transparent 60%);opacity:.05;pointer-events:none}
.stat-card:hover{transform:translateY(-2px);box-shadow:0 4px 24px rgba(30,0,255,.12)}
.stat-label{color:var(--muted);font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;font-weight:600}
.stat-value{color:var(--ac);font-size:2.2rem;font-weight:800;line-height:1.1;margin:6px 0 4px}
.stat-pct{color:var(--text2);font-size:.8rem;font-weight:500}
.stat-icon{position:absolute;top:16px;right:16px;font-size:1.5rem;opacity:.15}
/* Sections */
.section{margin-bottom:40px}
.section-header{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:16px;flex-wrap:wrap}
.section-title{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.12em;font-weight:700;border-left:3px solid var(--primary);padding-left:10px}
/* Chart carousel */
.chart-nav{display:flex;align-items:center;gap:10px}
.chart-page-info{color:var(--muted);font-size:.82rem;min-width:44px;text-align:center}
.chart-panel{display:none}
.chart-panel.active{display:block}
.chart-box{background:var(--card);border-radius:var(--r);padding:24px;border:1px solid var(--border2)}
.chart-title{color:var(--text2);font-size:.88rem;font-weight:600;margin-bottom:16px}
.chart-legend{display:flex;gap:20px;margin-top:14px;font-size:.78rem;color:var(--muted);flex-wrap:wrap;align-items:center}
.ldot{width:10px;height:10px;border-radius:2px;display:inline-block;margin-right:4px;vertical-align:middle;flex-shrink:0}
.chart-donut-wrap{display:flex;align-items:center;justify-content:center;gap:40px;flex-wrap:wrap}
.donut-stats{display:flex;flex-direction:column;gap:14px}
.donut-stat{display:flex;align-items:center;gap:10px}
.donut-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0}
.donut-val{font-size:1.4rem;font-weight:700;line-height:1}
.donut-lbl{font-size:.78rem;color:var(--muted)}
/* Tables */
.table-wrapper{overflow-x:auto;border-radius:var(--r);border:1px solid var(--border2)}
table{width:100%;border-collapse:collapse;min-width:580px}
thead th{background:var(--card2);color:var(--muted);padding:12px 14px;text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.08em;font-weight:700;white-space:nowrap}
tbody td{padding:12px 14px;border-bottom:1px solid var(--border2);font-size:.875rem;vertical-align:middle;color:var(--text)}
tbody tr:last-child td{border-bottom:none}
.scan-row{cursor:pointer;transition:background .12s}
.scan-row:hover td{background:rgba(30,0,255,.06)}
.scan-row:hover .exp-icon{color:var(--gold)}
.detail-row td{padding:0}
.detail-content{background:var(--bg2);padding:20px 28px;border-top:1px solid var(--border2);border-bottom:1px solid var(--border2)}
.detail-section{margin-bottom:12px}
.detail-section strong{color:var(--gold);font-size:.78rem;text-transform:uppercase;letter-spacing:.06em}
.detail-section p{color:var(--text2);font-size:.875rem;margin-top:6px;line-height:1.6;white-space:pre-wrap;word-break:break-word}
.detail-meta{display:flex;flex-wrap:wrap;gap:16px;font-size:.8rem;color:var(--text2);padding-top:10px;border-top:1px solid var(--border2)}
.detail-meta strong{color:var(--text)}
.exp-icon{color:var(--muted);font-size:.7rem;transition:transform .2s,color .15s}
.exp-icon.open{transform:rotate(180deg);color:var(--gold)}
/* Badges */
.dec-badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:.75rem;font-weight:700;letter-spacing:.04em}
.badge-secret{color:var(--err);background:rgba(248,113,113,.1);padding:2px 8px;border-radius:10px;font-size:.78rem;margin-left:6px}
.cve-code{color:var(--yellow)}
.vuln-c{color:var(--err);font-weight:600}
.vuln-h{color:var(--gold);font-weight:600}
.vuln-m{color:var(--yellow)}
.vuln-l{color:#60a5fa}
/* Search */
.search-input{width:100%;padding:11px 16px;background:var(--card);border:1px solid var(--border2);border-radius:var(--rs);color:var(--text);font-size:.9rem;outline:none;transition:border-color .15s;margin-bottom:14px}
.search-input:focus{border-color:var(--primary)}
/* Pagination */
.pagination{display:flex;align-items:center;justify-content:center;gap:8px;padding:16px 0;flex-wrap:wrap}
.page-btn{background:var(--card);border:1px solid var(--border2);color:var(--text2);padding:7px 13px;border-radius:var(--rs);cursor:pointer;font-size:.83rem;transition:all .12s}
.page-btn:hover,.page-btn.active{background:var(--primary);border-color:var(--primary);color:#fff}
.page-info{color:var(--muted);font-size:.82rem;padding:0 4px}
/* Whitelist form */
.wl-form{background:var(--card);border-radius:var(--r);padding:24px;border:1px solid var(--border2);margin-bottom:24px}
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:16px}
.form-group{display:flex;flex-direction:column;gap:6px}
.form-label{color:var(--muted);font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.07em}
.form-input{padding:9px 14px;background:var(--bg);border:1px solid var(--border2);border-radius:var(--rs);color:var(--text);font-size:.88rem;outline:none;transition:border-color .15s;width:100%}
.form-input:focus{border-color:var(--primary)}
.form-input::placeholder{color:var(--muted)}
.form-actions{display:flex;gap:10px;flex-wrap:wrap}
.alert{padding:12px 16px;border-radius:var(--rs);font-size:.875rem;margin-top:12px;display:none}
.alert-ok{background:rgba(74,222,128,.1);border:1px solid rgba(74,222,128,.3);color:var(--ok)}
.alert-err{background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.3);color:var(--err)}
/* no-data */
.no-data{color:var(--border);font-style:italic;padding:20px 0}
/* footer */
.footer{color:var(--border2);font-size:.78rem;margin-top:24px;border-top:1px solid var(--border2);padding-top:20px;display:flex;gap:16px;flex-wrap:wrap;align-items:center}
.footer a{color:var(--border)}
.footer a:hover{color:var(--muted)}
/* Responsive */
@media(max-width:900px){.container{padding:16px}.topbar{padding:0 16px;gap:12px}.stats-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:600px){.topbar{min-height:52px}.topbar-sub{display:none}.stats-grid{gap:10px}.stat-value{font-size:1.7rem}.img-search{flex-direction:column}.img-search input{min-width:unset;width:100%}.form-grid{grid-template-columns:1fr}.chart-donut-wrap{flex-direction:column}.col-date{display:none}.detail-meta{flex-direction:column;gap:8px}}
@media(max-width:400px){.stat-value{font-size:1.5rem}}
/* ── Light theme ───────────────────────────────────────────────────────── */
html{transition:background-color .2s,color .2s}
[data-theme="light"]{
  --bg:#f4f2ff;--bg2:#ebe8f9;--card:#fff;--card2:#f0eeff;
  --border:#b0a8e0;--border2:#cec8f0;
  --text:#0d0b1e;--text2:#474080;--muted:#6b6080;
  --gold:#92400e;--yellow:#78350f;
  --ok:#15803d;--err:#b91c1c;
}
[data-theme="light"] .topbar{box-shadow:0 2px 12px rgba(30,0,255,.08)}
[data-theme="light"] .scan-row:hover td{background:rgba(30,0,255,.04)}
[data-theme="light"] .vuln-l{color:#1d4ed8}
[data-theme="light"] .dec-badge{filter:brightness(0.75)}
[data-theme="light"] .btn-gold{background:#FFBD00;color:#13102a}
[data-theme="light"] .btn-gold:hover{background:#FFFB00}
[data-theme="light"] .logo-text span{color:#FFBD00}
/* Theme button */
.theme-btn{background:none;border:1px solid var(--border2);border-radius:var(--rs);padding:6px 12px;cursor:pointer;color:var(--text2);display:inline-flex;align-items:center;gap:6px;font-size:.8rem;font-weight:600;transition:all .15s;line-height:1}
.theme-btn:hover{background:var(--card2);border-color:var(--border);color:var(--text)}
.theme-btn svg{flex-shrink:0}
/* Stat icon SVG */
.stat-icon{position:absolute;top:14px;right:14px;opacity:.2;color:var(--ac);display:flex}
.stat-icon svg{width:26px;height:26px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
/* Search icon wrapper */
.img-search-lbl{display:inline-flex;align-items:center;gap:6px;color:var(--muted);font-size:.85rem;white-space:nowrap}
.img-search-lbl svg{flex-shrink:0;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
"""

_DASHBOARD_JS = """
(function(){
  /* ── Theme toggle ─────────────────────────────────────── */
  var isDark=(localStorage.getItem('hf-theme')||'dark')==='dark';
  function applyTheme(dark){
    document.documentElement.setAttribute('data-theme',dark?'dark':'light');
    localStorage.setItem('hf-theme',dark?'dark':'light');
    isDark=dark;
    var lbl=document.getElementById('theme-lbl');
    if(lbl)lbl.textContent=dark?'Light':'Dark';
  }
  applyTheme(isDark);
  var themeBtn=document.getElementById('theme-btn');
  if(themeBtn)themeBtn.addEventListener('click',function(){applyTheme(!isDark);});

  var tok=new URLSearchParams(window.location.search).get('token')||'';
  function withTok(u){return tok?u+(u.indexOf('?')===-1?'?':'&')+'token='+encodeURIComponent(tok):u;}
  function authHdr(){return tok?{'Authorization':'Bearer '+tok,'Content-Type':'application/json'}:{'Content-Type':'application/json'};}

  /* Image navigation */
  var imgInput=document.getElementById('img-input');
  window.goOverview=function(){window.location.href=withTok('/dashboard');};
  function goToImage(){var v=imgInput.value.trim();if(v)window.location.href=withTok('/dashboard/'+encodeURIComponent(v));}
  document.getElementById('btn-view').addEventListener('click',goToImage);
  document.getElementById('btn-overview').addEventListener('click',window.goOverview);
  imgInput.addEventListener('keydown',function(e){if(e.key==='Enter')goToImage();});

  /* Chart carousel */
  var curChart=1,totalCharts=3;
  function showChart(n){
    document.getElementById('chart-'+curChart).classList.remove('active');
    curChart=((n-1+totalCharts)%totalCharts)+1;
    document.getElementById('chart-'+curChart).classList.add('active');
    document.getElementById('chart-page-info').textContent=curChart+' / '+totalCharts;
  }
  document.getElementById('chart-prev').addEventListener('click',function(){showChart(curChart-1);});
  document.getElementById('chart-next').addEventListener('click',function(){showChart(curChart+1);});

  /* Expandable rows */
  window.toggleRow=function(id){
    var det=document.getElementById(id);if(!det)return;
    var isOpen=det.style.display!=='none';
    det.style.display=isOpen?'none':'table-row';
    var prev=det.previousElementSibling;
    if(prev){var ico=prev.querySelector('.exp-icon');if(ico)ico.classList.toggle('open',!isOpen);}
  };

  /* Search filter */
  var si=document.getElementById('search-input');
  function applyFilter(){
    var q=(si?si.value:'').toLowerCase();
    document.querySelectorAll('#scan-table tbody .scan-row').forEach(function(row){
      var ok=!q||row.textContent.toLowerCase().indexOf(q)!==-1;
      if(ok){row.classList.remove('filter-hidden');}else{row.classList.add('filter-hidden');row.style.display='none';}
      var det=row.nextElementSibling;
      if(det&&det.classList.contains('detail-row')){det.style.display='none';var ic=row.querySelector('.exp-icon');if(ic)ic.classList.remove('open');}
    });
    applyPage(1);
  }
  if(si)si.addEventListener('input',applyFilter);

  /* Pagination */
  var PAGE=10,curPage=1;
  function visRows(){return Array.from(document.querySelectorAll('#scan-table tbody .scan-row')).filter(function(r){return !r.classList.contains('filter-hidden');});}
  function applyPage(p){
    var rows=visRows(),tp=Math.max(1,Math.ceil(rows.length/PAGE));
    curPage=Math.min(Math.max(1,p),tp);
    var s=(curPage-1)*PAGE,e=s+PAGE;
    rows.forEach(function(row,i){
      var show=i>=s&&i<e;
      row.style.display=show?'':'none';
      var det=row.nextElementSibling;
      if(det&&det.classList.contains('detail-row')&&!show){det.style.display='none';var ic=row.querySelector('.exp-icon');if(ic)ic.classList.remove('open');}
    });
    renderPg(tp);
  }
  function renderPg(tp){
    var pg=document.getElementById('scan-pagination');if(!pg)return;
    if(tp<=1){pg.innerHTML='';return;}
    var h='',s=Math.max(1,curPage-2),e=Math.min(tp,curPage+2);
    if(curPage>1)h+='<button class="page-btn" onclick="goPage('+(curPage-1)+')">&#8592;</button>';
    if(s>1){h+='<button class="page-btn" onclick="goPage(1)">1</button>';if(s>2)h+='<span class="page-info">&#8230;</span>';}
    for(var i=s;i<=e;i++)h+='<button class="page-btn'+(i===curPage?' active':'')+'" onclick="goPage('+i+')">'+i+'</button>';
    if(e<tp){if(e<tp-1)h+='<span class="page-info">&#8230;</span>';h+='<button class="page-btn" onclick="goPage('+tp+')">'+tp+'</button>';}
    if(curPage<tp)h+='<button class="page-btn" onclick="goPage('+(curPage+1)+')">&#8594;</button>';
    pg.innerHTML=h;
  }
  window.goPage=function(p){applyPage(p);var sec=document.querySelectorAll('.section');if(sec[1])window.scrollTo({top:sec[1].getBoundingClientRect().top+window.scrollY-80,behavior:'smooth'});};
  applyPage(1);

  /* Add whitelist */
  var wlBtn=document.getElementById('wl-submit');
  var wlClr=document.getElementById('wl-clear');
  if(wlBtn){
    wlBtn.addEventListener('click',function(){
      var cve=document.getElementById('wl-cve').value.trim().toUpperCase();
      var reason=document.getElementById('wl-reason').value.trim();
      var appr=document.getElementById('wl-approved').value.trim()||null;
      var exp=document.getElementById('wl-expires').value||null;
      var errEl=document.getElementById('wl-error'),okEl=document.getElementById('wl-ok');
      errEl.style.display='none';okEl.style.display='none';
      if(!cve||!reason){errEl.textContent='CVE ID and Reason are required.';errEl.style.display='block';return;}
      if(!/^CVE-\\d{4}-\\d+$/i.test(cve)){errEl.textContent='CVE ID must match format CVE-YYYY-NNNNN.';errEl.style.display='block';return;}
      fetch('/exceptions',{method:'POST',headers:authHdr(),body:JSON.stringify({cve_id:cve,reason:reason,approved_by:appr,expires_at:exp?exp+'T00:00:00Z':null,is_active:true})})
        .then(function(r){
          if(r.ok){okEl.style.display='block';setTimeout(function(){window.location.reload();},1200);}
          else return r.json().then(function(d){throw new Error(d.detail||'Server error');});
        })
        .catch(function(e){errEl.textContent=e.message;errEl.style.display='block';});
    });
    wlClr.addEventListener('click',function(){
      ['wl-cve','wl-reason','wl-approved','wl-expires'].forEach(function(id){document.getElementById(id).value='';});
      document.getElementById('wl-error').style.display='none';
      document.getElementById('wl-ok').style.display='none';
    });
  }

  /* Delete exception */
  window.deleteException=function(id){
    if(!confirm('Revoke exception for '+id+'?'))return;
    fetch('/exceptions/'+encodeURIComponent(id),{method:'DELETE',headers:authHdr()})
      .then(function(r){if(r.ok||r.status===204)window.location.reload();else alert('Failed to revoke exception.');})
      .catch(function(){alert('Network error.');});
  };
})();
"""


def _decision_color(d: str) -> str:
    return {"APPROVED": "#4ade80", "WARNING": "#FFBD00", "REJECTED": "#f87171"}.get(d, "#808066")


def _trend_badge(records: list[ScanRecord]) -> str:
    if len(records) < 2:
        return ""
    latest = records[0]
    older = records[-1]
    latest_score = latest.critical_vulns * 100 + latest.high_vulns * 10 + latest.medium_vulns
    older_score = older.critical_vulns * 100 + older.high_vulns * 10 + older.medium_vulns
    if latest_score < older_score:
        return '<span class="badge-improving">&#8595; IMPROVING</span>'
    if latest_score > older_score:
        return '<span class="badge-worsening">&#8593; WORSENING</span>'
    return '<span class="badge-stable">&#8594; STABLE</span>'


def _bar_chart_svg(records: list[ScanRecord]) -> str:
    chart_data = list(reversed(records[:20]))
    n = len(chart_data)
    if n == 0:
        return '<p class="no-data">No chart data available.</p>'
    W, H = 760, 200
    ML, MR, MT, MB = 52, 16, 20, 40
    cw, ch = W - ML - MR, H - MT - MB
    scores = [r.critical_vulns * 100 + r.high_vulns * 10 + r.medium_vulns for r in chart_data]
    max_score = max(scores) if any(s > 0 for s in scores) else 1
    bw = cw / n
    bar_gap = max(1.5, bw * 0.2)
    bw_actual = bw - bar_gap
    parts: list[str] = []
    for frac in (0.25, 0.5, 0.75, 1.0):
        gy = MT + ch * (1 - frac)
        label = str(int(max_score * frac))
        parts.append(
            f'<line x1="{ML}" y1="{gy:.1f}" x2="{W - MR}" y2="{gy:.1f}"'
            f' style="stroke:var(--border)" stroke-width="1" stroke-dasharray="4,3"/>'
            f'<text x="{ML - 6}" y="{gy + 4:.1f}" style="fill:var(--muted)" font-size="10"'
            f' text-anchor="end">{label}</text>'
        )
    for i, (r, score) in enumerate(zip(chart_data, scores)):
        x = ML + i * bw + bar_gap / 2
        bh = int(score / max_score * ch) if max_score > 0 else 0
        if bh == 0 and score > 0:
            bh = 3
        y = MT + ch - bh
        color = _decision_color(r.decision)
        ts = r.scanned_at.strftime("%m/%d") if r.scanned_at else ""
        tip = _esc(f"{r.image_name} | {r.decision} | C:{r.critical_vulns} H:{r.high_vulns} M:{r.medium_vulns}")
        parts.append(
            f'<rect x="{x:.1f}" y="{y}" width="{bw_actual:.1f}" height="{max(bh, 3)}"'
            f' fill="{color}" rx="3" opacity="0.9"><title>{tip}</title></rect>'
        )
        if n <= 8 or i % max(1, n // 8) == 0 or i == n - 1:
            parts.append(
                f'<text x="{x + bw_actual / 2:.1f}" y="{H - 6}" style="fill:var(--muted)"'
                f' font-size="9" text-anchor="middle">{_esc(ts)}</text>'
            )
    parts.append(
        f'<line x1="{ML}" y1="{MT}" x2="{ML}" y2="{MT + ch}" style="stroke:var(--border)" stroke-width="1.5"/>'
        f'<line x1="{ML}" y1="{MT + ch}" x2="{W - MR}" y2="{MT + ch}" style="stroke:var(--border)" stroke-width="1.5"/>'
    )
    return f'<svg viewBox="0 0 {W} {H}" style="width:100%;display:block;overflow:visible">\n' + "\n".join(parts) + "\n</svg>"


def _donut_chart_svg(approved: int, warning: int, rejected: int) -> str:
    total = approved + warning + rejected
    if total == 0:
        return '<p class="no-data">No scan data available.</p>'
    cx, cy, r, sw = 110, 110, 75, 30
    circ = 3.14159265 * 2 * r
    segs = [
        (approved, "#4ade80", "Approved"),
        (warning, "#FFBD00", "Warning"),
        (rejected, "#f87171", "Rejected"),
    ]
    parts = [f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" style="stroke:var(--bg2)" stroke-width="{sw}"/>']
    offset = 0.0
    for count, color, label in segs:
        if count == 0:
            continue
        dash = (count / total) * circ
        gap = circ - dash
        pct = int(count / total * 100)
        parts.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" stroke-width="{sw}" '
            f'stroke-dasharray="{dash:.2f} {gap:.2f}" stroke-dashoffset="{-offset:.2f}" '
            f'transform="rotate(-90 {cx} {cy})"><title>{label}: {count} ({pct}%)</title></circle>'
        )
        offset += dash
    parts.append(
        f'<text x="{cx}" y="{cy - 10}" text-anchor="middle" fill="#FFBD00" font-size="28" font-weight="800">{total}</text>'
        f'<text x="{cx}" y="{cy + 16}" text-anchor="middle" style="fill:var(--muted)" font-size="12">Total Scans</text>'
    )
    for i, (count, color, label) in enumerate(segs):
        ly = 235 + i * 18
        pct = int(count / total * 100) if total > 0 else 0
        parts.append(
            f'<rect x="10" y="{ly}" width="14" height="14" rx="3" fill="{color}"/>'
            f'<text x="28" y="{ly + 11}" style="fill:var(--muted)" font-size="11">{label} {pct}%</text>'
        )
    return (
        f'<svg viewBox="0 0 220 285" style="width:100%;max-width:240px;display:block;margin:0 auto">\n'
        + "\n".join(parts)
        + "\n</svg>"
    )


def _vuln_breakdown_svg(records: list[ScanRecord]) -> str:
    chart_data = list(reversed(records[:15]))
    n = len(chart_data)
    if n == 0:
        return '<p class="no-data">No data available.</p>'
    W, H = 760, 200
    ML, MR, MT, MB = 52, 16, 20, 40
    cw, ch = W - ML - MR, H - MT - MB
    max_val = max(
        (r.critical_vulns + r.high_vulns + r.medium_vulns + r.low_vulns for r in chart_data),
        default=1,
    ) or 1
    bw = cw / n
    bar_gap = max(2.0, bw * 0.2)
    bw_actual = bw - bar_gap
    parts: list[str] = []
    for frac in (0.25, 0.5, 0.75, 1.0):
        gy = MT + ch * (1 - frac)
        parts.append(
            f'<line x1="{ML}" y1="{gy:.1f}" x2="{W - MR}" y2="{gy:.1f}" style="stroke:var(--border)" stroke-width="1" stroke-dasharray="4,3"/>'
            f'<text x="{ML - 6}" y="{gy + 4:.1f}" style="fill:var(--muted)" font-size="10" text-anchor="end">{int(max_val * frac)}</text>'
        )
    for i, r in enumerate(chart_data):
        x = ML + i * bw + bar_gap / 2
        ts = r.scanned_at.strftime("%m/%d") if r.scanned_at else ""
        current_y = float(MT + ch)
        tip = _esc(f"C:{r.critical_vulns} H:{r.high_vulns} M:{r.medium_vulns} L:{r.low_vulns}")
        for count, color in [
            (r.low_vulns, "#60a5fa"),
            (r.medium_vulns, "#FFFB00"),
            (r.high_vulns, "#FFBD00"),
            (r.critical_vulns, "#f87171"),
        ]:
            if count <= 0:
                continue
            bh = max(int(count / max_val * ch), 2)
            current_y -= bh
            parts.append(
                f'<rect x="{x:.1f}" y="{current_y:.1f}" width="{bw_actual:.1f}" height="{bh}"'
                f' fill="{color}" rx="2" opacity="0.9"><title>{tip}</title></rect>'
            )
        if n <= 8 or i % max(1, n // 8) == 0 or i == n - 1:
            parts.append(
                f'<text x="{x + bw_actual / 2:.1f}" y="{H - 6}" style="fill:var(--muted)" font-size="9" text-anchor="middle">{_esc(ts)}</text>'
            )
    parts.append(
        f'<line x1="{ML}" y1="{MT}" x2="{ML}" y2="{MT + ch}" style="stroke:var(--border)" stroke-width="1.5"/>'
        f'<line x1="{ML}" y1="{MT + ch}" x2="{W - MR}" y2="{MT + ch}" style="stroke:var(--border)" stroke-width="1.5"/>'
    )
    return (
        f'<svg viewBox="0 0 {W} {H}" style="width:100%;display:block;overflow:visible">\n'
        + "\n".join(parts)
        + "\n</svg>"
    )


def _render_vuln_cards(vulns: list) -> str:
    if not vulns:
        return '<p class="no-data" style="margin:8px 0">No vulnerability details stored.</p>'

    sev_colors = {
        "CRITICAL": ("#ef4444", "#450a0a"),
        "HIGH":     ("#ea580c", "#431407"),
        "MEDIUM":   ("#d97706", "#451a03"),
        "LOW":      ("#3b82f6", "#172554"),
    }
    cards = ""
    for v in vulns:
        sev = v.severity if hasattr(v, "severity") else v.get("severity", "LOW")
        vtype = v.type if hasattr(v, "type") else v.get("type", "Unknown")
        desc = v.description if hasattr(v, "description") else v.get("description", "")
        snippet = (v.code_snippet if hasattr(v, "code_snippet") else v.get("code_snippet")) or ""
        suggestion = (v.suggestion if hasattr(v, "suggestion") else v.get("suggestion")) or ""
        cwe = (v.cwe_id if hasattr(v, "cwe_id") else v.get("cwe_id")) or ""
        fname = v.filename if hasattr(v, "filename") else v.get("filename", "")
        line = v.line_number if hasattr(v, "line_number") else v.get("line_number")

        fg, bg = sev_colors.get(sev, ("#808066", "#1a1a1a"))
        file_line = f"{_esc(fname)}:{line}" if line else _esc(fname)

        cards += (
            f'<div style="border-left:4px solid {fg};background:{bg}22;'
            f'border-radius:6px;padding:10px 14px;margin:6px 0">'
            f'<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">'
            f'<span style="background:{fg};color:#000;font-size:.72rem;font-weight:700;'
            f'padding:2px 8px;border-radius:4px">{_esc(sev)}</span>'
            f'<strong style="color:{fg};font-size:.9rem">{_esc(vtype)}</strong>'
            f'<code style="color:var(--muted);font-size:.78rem">{file_line}</code>'
            f'{f"<code style=\"color:var(--muted);font-size:.75rem\">{_esc(cwe)}</code>" if cwe else ""}'
            f'</div>'
            f'<p style="color:var(--text2);font-size:.85rem;margin:4px 0">{_esc(desc)}</p>'
        )
        if snippet:
            cards += f'<pre style="background:var(--bg);padding:6px 10px;border-radius:4px;font-size:.78rem;overflow-x:auto;margin:6px 0">{_esc(snippet)}</pre>'
        if suggestion:
            cards += f'<p style="color:var(--ok);font-size:.82rem;margin:4px 0"><strong>Fix:</strong> {_esc(suggestion)}</p>'
        cards += "</div>"
    return cards


def _render_code_scan_rows(code_records: list[CodeScanRecord]) -> str:
    if not code_records:
        return '<p class="no-data">No code scan records yet.</p>'

    decision_colors = {"PASSED": "#4ade80", "WARNING": "#FFBD00", "BLOCKED": "#f87171"}
    rows = ""
    for idx, r in enumerate(code_records):
        color = decision_colors.get(r.decision, "#808066")
        ts = _esc(r.scanned_at.strftime("%Y-%m-%d %H:%M UTC") if r.scanned_at else "—")
        sha = _esc(r.commit_sha[:8] if r.commit_sha else "—")
        branch = _esc(r.branch or "—")
        project = _esc(r.project_name)
        ai = _esc(r.ai_provider or "—")
        rid = f"cdr-{idx}"
        vuln_cards = _render_vuln_cards(r.vulnerabilities)
        rows += (
            f'<tr class="scan-row" onclick="toggleRow(\'{rid}\')">'
            f'<td class="col-date">{ts}</td>'
            f'<td><span class="dec-badge" style="background:{color}20;color:{color};border:1px solid {color}40">{_esc(r.decision)}</span></td>'
            f'<td><code>{project}</code></td>'
            f'<td><code>{sha}</code> / {branch}</td>'
            f'<td><span class="vuln-c">{r.critical_count}</span>&#8202;/&#8202;'
            f'<span class="vuln-h">{r.high_count}</span>&#8202;/&#8202;'
            f'<span class="vuln-m">{r.medium_count}</span>&#8202;/&#8202;'
            f'<span class="vuln-l">{r.low_count}</span></td>'
            f'<td><span class="exp-icon">&#9660;</span></td>'
            f'</tr>'
            f'<tr id="{rid}" class="detail-row" style="display:none">'
            f'<td colspan="6"><div class="detail-content">'
            f'<div class="detail-meta" style="margin-bottom:12px">'
            f'<span><strong>Files analyzed:</strong> {r.files_analyzed}</span>'
            f'<span><strong>AI:</strong> {ai}</span>'
            f'<span><strong>Commit:</strong> {_esc(r.commit_sha or "—")}</span>'
            f'<span><strong>Branch:</strong> {branch}</span>'
            f'</div>'
            f'<div class="detail-section"><strong>Vulnerabilities</strong>'
            f'<div style="margin-top:8px">{vuln_cards}</div>'
            f'</div>'
            f'</div></td></tr>\n'
        )
    return (
        '<div class="table-wrapper"><table><thead><tr>'
        '<th>Date</th><th>Decision</th><th>Project</th><th>Commit / Branch</th>'
        '<th>C&#8202;/&#8202;H&#8202;/&#8202;M&#8202;/&#8202;L</th><th></th>'
        f'</tr></thead><tbody>{rows}</tbody></table></div>'
    )


def _render_dashboard(title: str, records: list[ScanRecord], exceptions: list[CVEException], code_records: list[CodeScanRecord] | None = None) -> str:
    safe_title = _esc(title)
    total = len(records)
    approved = sum(1 for r in records if r.decision == "APPROVED")
    warning = sum(1 for r in records if r.decision == "WARNING")
    rejected = sum(1 for r in records if r.decision == "REJECTED")
    num_exc = len(exceptions)

    def _pct(count: int) -> str:
        return f"{count / total * 100:.0f}%" if total > 0 else "0%"

    # Build scan rows (clickable, expandable)
    rows_html = ""
    for idx, r in enumerate(records):
        color = _decision_color(r.decision)
        ts = _esc(r.scanned_at.strftime("%Y-%m-%d %H:%M UTC") if r.scanned_at else "—")
        sbadge = (
            f'<span class="badge-secret">! {r.secrets_found} secret(s)</span>'
            if r.secrets_found else ""
        )
        reason_full = _esc(r.reason or "—")
        ai_prov = _esc(r.ai_provider or "—")
        rid = f"dr-{idx}"
        rows_html += (
            f'<tr class="scan-row" data-row onclick="toggleRow(\'{rid}\')">'
            f'<td class="col-date">{ts}</td>'
            f'<td><span class="dec-badge" style="background:{color}20;color:{color};border:1px solid {color}40">{_esc(r.decision)}</span></td>'
            f'<td><code>{_esc(r.image_name)}</code></td>'
            f'<td><span class="vuln-c">{r.critical_vulns}</span>&#8202;/&#8202;'
            f'<span class="vuln-h">{r.high_vulns}</span>&#8202;/&#8202;'
            f'<span class="vuln-m">{r.medium_vulns}</span>&#8202;/&#8202;'
            f'<span class="vuln-l">{r.low_vulns}</span></td>'
            f'<td>{_esc(r.source)}{sbadge}</td>'
            f'<td><span class="exp-icon">&#9660;</span></td>'
            f'</tr>'
            f'<tr id="{rid}" class="detail-row" style="display:none">'
            f'<td colspan="6" class="detail-cell">'
            f'<div class="detail-content">'
            f'<div class="detail-section"><strong>Analysis / Reason</strong>'
            f'<p>{reason_full}</p></div>'
            f'<div class="detail-meta">'
            f'<span><strong>Source:</strong> {_esc(r.source)}</span>'
            f'<span><strong>AI Provider:</strong> {ai_prov}</span>'
            f'<span><strong>Image Size:</strong> {r.image_size_mb:.1f} MB</span>'
            f'<span><strong>Secrets Found:</strong> {r.secrets_found}</span>'
            f'</div></div></td></tr>\n'
        )

    # Build exception rows
    exc_rows_html = ""
    for e in exceptions:
        exp = _esc(e.expires_at.strftime("%Y-%m-%d") if e.expires_at else "Never")
        cve_safe = _esc(e.cve_id)
        exc_rows_html += (
            f'<tr>'
            f'<td><code class="cve-code">{cve_safe}</code></td>'
            f'<td>{_esc(e.reason)}</td>'
            f'<td>{_esc(e.approved_by or "—")}</td>'
            f'<td>{exp}</td>'
            f'<td><button class="btn btn-danger btn-sm" onclick="deleteException(\'{cve_safe}\')">Revoke</button></td>'
            f'</tr>\n'
        )

    trend = _trend_badge(records)
    chart_svg1 = _bar_chart_svg(records)
    chart_svg2 = _donut_chart_svg(approved, warning, rejected)
    chart_svg3 = _vuln_breakdown_svg(records)
    chart_count = min(total, 20)

    code_records = code_records or []
    code_section_html = _render_code_scan_rows(code_records)

    scan_section_html = (
        '<input id="search-input" type="text" class="search-input"'
        ' placeholder="Filter by image, decision, source&#8230;">'
        '<div class="table-wrapper"><table id="scan-table"><thead><tr>'
        '<th>Date</th><th>Decision</th><th>Image</th>'
        '<th>C&#8202;/&#8202;H&#8202;/&#8202;M&#8202;/&#8202;L</th><th>Source</th><th></th>'
        f'</tr></thead><tbody>{rows_html}</tbody></table></div>'
        '<div class="pagination" id="scan-pagination"></div>'
    ) if rows_html else '<p class="no-data">No scan records yet.</p>'

    exc_section_html = (
        '<div class="table-wrapper"><table id="exc-table"><thead><tr>'
        '<th>CVE ID</th><th>Reason</th><th>Approved By</th><th>Expires</th><th>Action</th>'
        f'</tr></thead><tbody>{exc_rows_html}</tbody></table></div>'
    ) if exc_rows_html else '<p class="no-data">No active exceptions.</p>'

    css = _DASHBOARD_CSS
    js = _DASHBOARD_JS

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HexaFlow &#8212; {safe_title}</title>
<style>{css}</style>
<script>(function(){{var t=localStorage.getItem('hf-theme')||'dark';document.documentElement.setAttribute('data-theme',t);}})();</script>
</head>
<body>

<header class="topbar">
  <div class="logo-wrap" onclick="goOverview()">
    <svg class="logo-hex" viewBox="0 0 44 44" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <polygon points="22,2 40,12 40,32 22,42 4,32 4,12" fill="none" stroke="#474080" stroke-width="3.5" stroke-linejoin="round"/>
      <path d="M8,32 C8,32 10,22 20,18 L28,18 C33,18 33,12 28,12 L36,8" fill="none" stroke="#FFBD00" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
      <polyline points="33,6 38,9 34,13" fill="none" stroke="#FFBD00" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
      <line x1="8" y1="32" x2="12" y2="38" stroke="#FFBD00" stroke-width="3" stroke-linecap="round"/>
      <polyline points="9,37 14,38 13,43" fill="none" stroke="#FFBD00" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <span class="logo-text">Hexa<span>Flow</span></span>
  </div>
  <span class="topbar-sub">{safe_title}</span>
  <div class="topbar-actions">
    <span>{trend}</span>
    <button id="theme-btn" class="theme-btn" title="Switch theme">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
      <span id="theme-lbl">Light</span>
    </button>
  </div>
</header>

<main class="container">

  <div class="img-search">
    <span class="img-search-lbl"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Image history:</span>
    <input id="img-input" type="text" placeholder="nginx:latest, myapp:v1.2.3 &#8212; press Enter">
    <button class="btn btn-primary" id="btn-view">View History</button>
    <button class="btn btn-ghost" id="btn-overview">&#8592; Overview</button>
  </div>

  <div class="stats-grid">
    <div class="stat-card" style="--ac:#60a5fa">
      <div class="stat-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><path d="M7 17v-4M11 17V9M15 17v-6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></div>
      <div class="stat-label">Total Scans</div>
      <div class="stat-value">{total}</div>
      <div class="stat-pct">all time</div>
    </div>
    <div class="stat-card" style="--ac:#4ade80">
      <div class="stat-icon"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M8 12l3 3 5-5"/></svg></div>
      <div class="stat-label">Approved</div>
      <div class="stat-value">{approved}</div>
      <div class="stat-pct">{_pct(approved)}</div>
    </div>
    <div class="stat-card" style="--ac:#FFBD00">
      <div class="stat-icon"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></div>
      <div class="stat-label">Warning</div>
      <div class="stat-value">{warning}</div>
      <div class="stat-pct">{_pct(warning)}</div>
    </div>
    <div class="stat-card" style="--ac:#f87171">
      <div class="stat-icon"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg></div>
      <div class="stat-label">Rejected</div>
      <div class="stat-value">{rejected}</div>
      <div class="stat-pct">{_pct(rejected)}</div>
    </div>
    <div class="stat-card" style="--ac:#c084fc">
      <div class="stat-icon"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
      <div class="stat-label">CVE Exceptions</div>
      <div class="stat-value">{num_exc}</div>
      <div class="stat-pct">active</div>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <span class="section-title">Security Analytics</span>
      <div class="chart-nav">
        <button class="btn btn-ghost btn-icon" id="chart-prev">&#8592;</button>
        <span id="chart-page-info" class="chart-page-info">1 / 3</span>
        <button class="btn btn-ghost btn-icon" id="chart-next">&#8594;</button>
      </div>
    </div>
    <div class="chart-panel active" id="chart-1">
      <div class="chart-box">
        <div class="chart-title">Vulnerability Score Trend &#8212; last {chart_count} scans
          <span style="color:var(--muted);font-weight:400;font-size:.8em">&nbsp;(C&#215;100 + H&#215;10 + M)</span>
        </div>
        {chart_svg1}
        <div class="chart-legend">
          <span><span class="ldot" style="background:#4ade80"></span>Approved</span>
          <span><span class="ldot" style="background:#FFBD00"></span>Warning</span>
          <span><span class="ldot" style="background:#f87171"></span>Rejected</span>
        </div>
      </div>
    </div>
    <div class="chart-panel" id="chart-2">
      <div class="chart-box">
        <div class="chart-title">Decision Distribution</div>
        <div class="chart-donut-wrap">
          {chart_svg2}
          <div class="donut-stats">
            <div class="donut-stat">
              <div class="donut-dot" style="background:#4ade80"></div>
              <div><div class="donut-val" style="color:#4ade80">{approved}</div><div class="donut-lbl">Approved ({_pct(approved)})</div></div>
            </div>
            <div class="donut-stat">
              <div class="donut-dot" style="background:#FFBD00"></div>
              <div><div class="donut-val" style="color:#FFBD00">{warning}</div><div class="donut-lbl">Warning ({_pct(warning)})</div></div>
            </div>
            <div class="donut-stat">
              <div class="donut-dot" style="background:#f87171"></div>
              <div><div class="donut-val" style="color:#f87171">{rejected}</div><div class="donut-lbl">Rejected ({_pct(rejected)})</div></div>
            </div>
          </div>
        </div>
      </div>
    </div>
    <div class="chart-panel" id="chart-3">
      <div class="chart-box">
        <div class="chart-title">Vulnerability Type Breakdown &#8212; last {min(total, 15)} scans</div>
        {chart_svg3}
        <div class="chart-legend">
          <span><span class="ldot" style="background:#f87171"></span>Critical</span>
          <span><span class="ldot" style="background:#FFBD00"></span>High</span>
          <span><span class="ldot" style="background:#FFFB00"></span>Medium</span>
          <span><span class="ldot" style="background:#60a5fa"></span>Low</span>
        </div>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <span class="section-title">Scan History &amp; Feedback</span>
    </div>
    {scan_section_html}
  </div>

  <div class="section">
    <div class="section-header">
      <span class="section-title">CVE Whitelist / Exceptions</span>
    </div>
    <div class="wl-form">
      <div style="color:var(--text2);font-size:.88rem;font-weight:600;margin-bottom:14px">Add Exception</div>
      <div class="form-grid">
        <div class="form-group">
          <label class="form-label" for="wl-cve">CVE ID *</label>
          <input class="form-input" id="wl-cve" type="text" placeholder="CVE-2024-12345" autocomplete="off">
        </div>
        <div class="form-group">
          <label class="form-label" for="wl-reason">Reason *</label>
          <input class="form-input" id="wl-reason" type="text" placeholder="Not exploitable in our context">
        </div>
        <div class="form-group">
          <label class="form-label" for="wl-approved">Approved By</label>
          <input class="form-input" id="wl-approved" type="text" placeholder="security-team">
        </div>
        <div class="form-group">
          <label class="form-label" for="wl-expires">Expires (optional)</label>
          <input class="form-input" id="wl-expires" type="date">
        </div>
      </div>
      <div class="form-actions">
        <button class="btn btn-gold" id="wl-submit">&#43; Add to Whitelist</button>
        <button class="btn btn-ghost" id="wl-clear">Clear</button>
      </div>
      <div class="alert alert-ok" id="wl-ok">Exception added successfully. Reloading&#8230;</div>
      <div class="alert alert-err" id="wl-error">Error</div>
    </div>
    {exc_section_html}
  </div>

  <div class="section">
    <div class="section-header">
      <span class="section-title">Code Scan History</span>
    </div>
    {code_section_html}
  </div>

  <div class="footer">
    <span>HexaFlow Security Gate v2.0</span>
    <a href="/docs">API Docs</a>
    <a href="/schema">DB Schema</a>
  </div>

</main>
<script>{js}</script>
</body>
</html>"""


@app.get("/dashboard", response_class=HTMLResponse, tags=["dashboard"])
async def dashboard_overview(request: Request):
    """Overall security dashboard — recent scans across all images and code projects."""
    _require_dashboard_token(request)
    if not _repo or not _repo.is_available:
        return HTMLResponse(
            content="<h1>Dashboard unavailable</h1><p>Set DATABASE_URL to enable the dashboard.</p>",
            status_code=503,
        )
    records = await _repo.get_all_recent(limit=50)
    exceptions = await _repo.get_active_exceptions()
    code_records = await _repo.get_all_recent_code_scans(limit=20)
    return _render_dashboard("Security Overview", records, exceptions, code_records)


@app.get("/dashboard/{image_name:path}", response_class=HTMLResponse, tags=["dashboard"])
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
    code_records = await _repo.get_all_recent_code_scans(limit=10)
    return _render_dashboard(f"Image: {decoded}", records, exceptions, code_records)


# ── Global exception handler ──────────────────────────────────────────────────

@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    logger.exception("Unhandled exception")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
