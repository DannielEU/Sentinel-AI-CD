# Sentinel-AI-CD

<div align="center">

![Python](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi)
![License](https://img.shields.io/badge/License-MIT-green)
![Architecture](https://img.shields.io/badge/Architecture-Hexagonal-blueviolet)

</div>

Intelligent security gate for CI/CD pipelines. Analyses Docker container images and decides whether a deployment should be **APPROVED**, **WARNING**, or **REJECTED** — combining deterministic OWASP rules, Dockerfile secrets detection, a CVE whitelist, scan history, and an optional AI provider (Ollama, OpenAI, or Anthropic).

```
CI/CD pipeline
    └─ trivy scan
        └─ POST /analyze-image
            ├─ Secrets detector  → REJECTED if hardcoded credentials found
            ├─ CVE whitelist     → loaded from DB (optional)
            ├─ Rule engine       → OWASP-aligned deterministic rules
            └─ AI provider       → Ollama / OpenAI / Anthropic (optional)
```

---

## Features

| Feature | Description |
|---|---|
| **Secrets detection** | Scans Dockerfiles for hardcoded API keys, passwords, tokens, private keys — auto-REJECTED |
| **OWASP rule engine** | Deterministic: critical→REJECTED, high→WARNING/REJECTED, size/medium→WARNING |
| **CVE whitelist** | Accept known CVEs with expiry via DB — downgrades REJECTED to WARNING |
| **Scan history** | Every decision persisted in DB; trend tracking per image (IMPROVING/WORSENING/STABLE) |
| **Dashboard** | HTML security dashboard at `/dashboard` and `/dashboard/{image}` |
| **Multi-AI provider** | Ollama (local, free), OpenAI GPT-4o-mini, Anthropic Claude — swappable via env var |
| **No-DB mode** | Works without a database — history and whitelist simply disabled, logs clearly say so |
| **Hexagonal architecture** | Domain / Application / Infrastructure / Web layers, fully decoupled |
| **Auth + rate limiting** | Bearer token, SHA-256 constant-time comparison, 100 req/min, auth-failure backoff |

---

## Quick Start

### With Docker Compose (Ollama + SQLite)

```bash
git clone <repo>
cd Sentinel-AI-CD
docker compose up -d

# Check status
curl http://localhost:8000/health
# → {"status":"ok","db_enabled":true}

# Open dashboard
open http://localhost:8000/dashboard
```

### Local Python (no DB, no AI — fastest for testing)

```bash
pip install -r requirements.txt

AI_PROVIDER=disabled uvicorn web.main:app --port 8000
```

### Scan an image

```bash
# 1. Scan with Trivy
trivy image --format json -o report.json myapp:1.2.3

# 2. Send to gate (pass Dockerfile to enable secrets detection)
python pipeline/trivy_to_gate.py \
    --report     report.json \
    --image      myapp:1.2.3 \
    --gate       http://localhost:8000 \
    --dockerfile ./Dockerfile
```

---

## Configuration

All settings are environment variables.

### AI Provider

| Variable | Default | Description |
|---|---|---|
| `AI_PROVIDER` | `ollama` | `ollama` \| `openai` \| `anthropic` \| `disabled` |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `neural-chat` | Ollama model name |
| `OPENAI_API_KEY` | — | Required when `AI_PROVIDER=openai` |
| `OPENAI_MODEL` | `gpt-4o-mini` | OpenAI model |
| `ANTHROPIC_API_KEY` | — | Required when `AI_PROVIDER=anthropic` |
| `ANTHROPIC_MODEL` | `claude-haiku-4-5-20251001` | Anthropic model |

The factory detects the provider **at startup**, before any model pull or external API call. Missing credentials for cloud providers cause an immediate startup error with a clear message.

### Database

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///./data/sentinel.db` | DB connection. Leave empty to disable. |

```bash
# SQLite (default in docker-compose)
DATABASE_URL=sqlite+aiosqlite:///./data/sentinel.db

# PostgreSQL
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/dbname
```

When `DATABASE_URL` is empty, the gate runs without persistence — history and whitelist are disabled, clearly logged at startup:

```
INFO | Database: not configured (DATABASE_URL not set) — history and whitelist disabled
INFO | Mode: rules + AI only, no persistence
```

### Rule Engine Thresholds

| Variable | Default | Trigger |
|---|---|---|
| `MAX_IMAGE_SIZE_MB` | `1200` | WARNING if image > N MB |
| `MAX_HIGH_VULNS` | `10` | REJECTED if HIGH > N |
| `MAX_MEDIUM_VULNS` | `30` | WARNING if MEDIUM > N |

### Auth & Security

| Variable | Default | Description |
|---|---|---|
| `GATE_AUTH_TOKEN` | — | Bearer token (optional) |
| `RATE_LIMIT_REQUESTS` | `100` | Max requests per window |
| `RATE_LIMIT_WINDOW` | `60` | Window in seconds |
| `AUTH_FAILURE_LIMIT` | `5` | Max failed auth attempts before lockout |
| `AUTH_FAILURE_WINDOW` | `300` | Auth failure window (s) |

---

## Decision Pipeline

```
POST /analyze-image
        │
        ▼
1. Dockerfile secrets scan
   └─ Any found? → REJECTED (source: secrets_detector) → persist → return
        │ none
        ▼
2. Load CVE whitelist from DB (if DATABASE_URL is set)
        │
        ▼
3. Deterministic rule engine
   ├── Critical > 0          → REJECTED (hard stop, AI cannot override)
   ├── High > MAX_HIGH_VULNS → REJECTED (unless whitelisted CVEs reduce count below threshold)
   ├── High 1..MAX           → WARNING  → delegate to AI (if enabled)
   ├── Size > MAX_SIZE_MB    → WARNING  → delegate to AI
   ├── Medium > MAX_MEDIUM   → WARNING  → delegate to AI
   └── No rule fires         → AI analysis or APPROVED (if AI disabled)
        │
        ▼
4. AI provider (Ollama / OpenAI / Anthropic)
   └─ Can confirm WARNING, escalate to REJECTED, or downgrade to APPROVED
        │
        ▼
5. Persist ScanRecord to DB (if available)
        │
        ▼
6. Return GateDecision + dashboard_url (if DB enabled)
```

---

## Secrets Detection

The gate scans the `dockerfile_content` field for hardcoded credentials **before any other check**. An immediate `REJECTED` with `source=secrets_detector` is returned — no AI is consulted.

| Pattern | Example match |
|---|---|
| AWS Access Key ID | `AKIA0123456789ABCDEF` |
| AWS Secret Key | `aws_secret_access_key=abc123...` |
| OpenAI API Key | `sk-` + 48 alphanumeric chars |
| GitHub Token | `ghp_` + 36 chars |
| GitLab Token | `glpat-...` |
| Private Keys | `-----BEGIN RSA PRIVATE KEY-----` |
| Hardcoded Passwords | `password=mysecretpassword` |
| Hardcoded API Keys | `api_key=abcdef012345678901234` |
| Auth Tokens | `auth_token=...` (20+ chars) |

Comment lines (`#`) are excluded from scanning.

**Always pass `--dockerfile ./Dockerfile`** to `trivy_to_gate.py` to enable this check.

---

## CVE Whitelist

Accept known CVEs — for example when no patch is available — with a reason and optional expiry date:

```bash
# Add an exception
curl -X POST http://localhost:8000/exceptions \
  -H "Content-Type: application/json" \
  -d '{
    "cve_id": "CVE-2023-1234",
    "reason": "No fix available; mitigated at runtime via WAF rule",
    "approved_by": "security-team",
    "expires_at": "2025-12-31T00:00:00"
  }'

# List active exceptions
curl http://localhost:8000/exceptions

# Deactivate an exception
curl -X DELETE http://localhost:8000/exceptions/CVE-2023-1234
```

Whitelisted CVEs are loaded per-request from the DB. If the whitelist reduces the effective HIGH count below `MAX_HIGH_VULNS`, the decision is downgraded from REJECTED to WARNING with an audit note listing which CVEs were accepted.

---

## Dashboard

| Endpoint | Description |
|---|---|
| `GET /dashboard` | Overall view — recent scans across all images |
| `GET /dashboard/{image_name}` | Per-image history with trend badge |

The dashboard shows:
- Scan history table (timestamp, decision, C/H/M counts, source, reason)
- Trend badge: **IMPROVING ↓** / **STABLE →** / **WORSENING ↑** (based on vulnerability score over time)
- Active whitelist entries

When `dashboard_url` is returned in the gate response, `trivy_to_gate.py` prints it and emits a machine-readable marker for CI scripts:

```
  Dashboard  : http://gate:8000/dashboard/myapp:1.2.3

::sentinel-dashboard::http://gate:8000/dashboard/myapp:1.2.3
```

---

## CI/CD Integration

### Exit Codes

| Code | Meaning | Recommended pipeline action |
|---|---|---|
| `0` | APPROVED | Deploy normally |
| `1` | REJECTED | Abort deployment — fix vulnerabilities or secrets |
| `2` | WARNING | Deploy with caution, create remediation ticket |
| `3` | Error | Gate unreachable — fail safe (block) |

### GitHub Actions

```yaml
name: CI/CD with Sentinel Security Gate

on: [push, pull_request]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t ${{ github.repository }}:${{ github.sha }} .

      - name: Scan with Trivy
        run: |
          trivy image --format json \
            -o trivy_report.json \
            ${{ github.repository }}:${{ github.sha }}

      - name: Run Sentinel gate
        id: gate
        env:
          GATE_TOKEN: ${{ secrets.GATE_TOKEN }}
        run: |
          result=$(python pipeline/trivy_to_gate.py \
            --report     trivy_report.json \
            --image      ${{ github.repository }}:${{ github.sha }} \
            --gate       ${{ vars.GATE_URL }} \
            --dockerfile ./Dockerfile \
            --token      $GATE_TOKEN 2>&1)
          echo "result<<EOF" >> $GITHUB_OUTPUT
          echo "$result"     >> $GITHUB_OUTPUT
          echo "EOF"         >> $GITHUB_OUTPUT

      - name: Post PR comment with dashboard link
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const output = `${{ steps.gate.outputs.result }}`;
            const dashboard = output.match(/::sentinel-dashboard::(.+)/)?.[1] || '';
            const dashLink = dashboard
              ? `\n\n[🔍 View Security Dashboard](${dashboard})`
              : '';
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## 🛡️ Security Gate\n\`\`\`\n${output}\n\`\`\`${dashLink}`
            });

      - name: Deploy (only on APPROVED or WARNING)
        if: steps.gate.outcome == 'success'
        run: docker push ${{ github.repository }}:${{ github.sha }}
```

### GitLab CI

```yaml
security-gate:
  stage: security
  script:
    - trivy image --format json -o report.json $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    - python pipeline/trivy_to_gate.py
        --report report.json
        --image  $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
        --gate   $GATE_URL
        --dockerfile ./Dockerfile
        --token  $GATE_TOKEN
```

---

## Switching AI Providers

```bash
# Local Ollama — free, private, no data leaves your network
AI_PROVIDER=ollama OLLAMA_MODEL=mistral docker compose up

# OpenAI GPT-4o-mini — fast, paid
AI_PROVIDER=openai OPENAI_API_KEY=sk-... docker compose up gate

# Anthropic Claude — fast, paid
AI_PROVIDER=anthropic ANTHROPIC_API_KEY=sk-ant-... docker compose up gate

# No AI — deterministic rules only (fastest, zero cost)
AI_PROVIDER=disabled docker compose up gate
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/analyze-image` | Main gate — analyse image and return decision |
| `GET` | `/health` | Health check |
| `GET` | `/history/{image_name}` | Scan history for an image (requires DB) |
| `GET` | `/dashboard` | Overall HTML security dashboard |
| `GET` | `/dashboard/{image_name}` | Per-image HTML dashboard with trend |
| `GET` | `/exceptions` | List active CVE exceptions |
| `POST` | `/exceptions` | Add or update a CVE exception |
| `DELETE` | `/exceptions/{cve_id}` | Deactivate a CVE exception |
| `GET` | `/schema` | Database SQL schema |
| `GET` | `/docs` | Swagger UI (disable with `DISABLE_DOCS=true`) |

### Gate Decision Schema

```json
{
  "decision": "WARNING",
  "reason": "2 high-severity vulnerabilities detected.",
  "recommendations": [
    "Update libssl to patched version (CVE-2023-1234).",
    "Run trivy image --severity HIGH myapp:1.2.3 for details."
  ],
  "summary": "Image myapp:1.2.3 has 2 HIGH vulns...",
  "source": "ai_model",
  "image_name": "myapp:1.2.3",
  "dashboard_url": "http://localhost:8000/dashboard/myapp:1.2.3"
}
```

`source` values: `rule_engine` | `ai_model` | `secrets_detector`

---

## Project Structure

```
app/
├── domain/                         # Core — no external dependencies
│   ├── entities.py                 # ImageReport, GateDecision, ScanRecord, CVEException
│   ├── rules.py                    # Deterministic OWASP rule engine + whitelist support
│   └── ports/
│       ├── ai_provider.py          # AIProviderPort Protocol
│       └── repository.py           # RepositoryPort Protocol
├── application/
│   └── gate_service.py             # Orchestrator: secrets → whitelist → rules → AI → persist
├── infrastructure/
│   ├── ai/
│   │   ├── factory.py              # Provider detection at startup (before model pull)
│   │   ├── ollama.py               # Local Ollama adapter
│   │   ├── openai_provider.py      # OpenAI REST adapter (no SDK, uses httpx)
│   │   ├── anthropic_provider.py   # Anthropic REST adapter (no SDK, uses httpx)
│   │   ├── prompt.py               # Shared prompt builder
│   │   └── parser.py               # Shared AI response JSON parser
│   ├── persistence/
│   │   ├── factory.py              # DB detection at startup
│   │   ├── null_repository.py      # No-op adapter (DATABASE_URL not set)
│   │   └── sql_repository.py       # SQLAlchemy async (SQLite + PostgreSQL)
│   └── security/
│       └── secrets_detector.py     # Regex-based Dockerfile secret scanner
└── web/
    └── main.py                     # FastAPI thin controller, all endpoints

pipeline/
├── trivy_to_gate.py                # Trivy JSON → Gate adapter (CI/CD script)
└── gate_check.sh                   # Universal shell wrapper

schema.sql                          # Database schema (SQLite + PostgreSQL compatible)
docker-compose.yml
requirements.txt
```

---

## Database Schema

Documented in [`schema.sql`](schema.sql) and available at `GET /schema`.

```sql
scan_history    -- one row per gate decision
  id, image_name, decision, reason, source,
  critical_vulns, high_vulns, medium_vulns, low_vulns,
  image_size_mb, secrets_found, ai_provider, scanned_at

cve_exceptions  -- CVE whitelist with optional expiry
  id, cve_id, reason, approved_by, expires_at, created_at, is_active
```

---

## Security Notes

- `REJECTED` from the secrets detector or rule engine is **never overridden by AI** — safety stays deterministic
- Bearer token comparison uses SHA-256 + `secrets.compare_digest` (constant-time, timing-attack safe)
- Rate limiting: 100 req/min per IP with configurable window
- Auth-failure backoff: locked after 5 failed attempts in 5 minutes
- Container runs as non-root (`gateuser:1000`)
- No data sent to third parties when using Ollama
- CVE exceptions require a human-readable `reason` field and can include an expiry date
