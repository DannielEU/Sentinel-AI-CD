# Sentinel-AI-CD

<div align="center">

![Python](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi)
![License](https://img.shields.io/badge/License-MIT-green)
![Architecture](https://img.shields.io/badge/Architecture-Hexagonal-blueviolet)

</div>

Intelligent security gate for CI/CD pipelines. Analyses Docker container images and decides whether a deployment should be **APPROVED**, **WARNING**, or **REJECTED** — combining deterministic OWASP rules, Dockerfile secrets detection, a CVE whitelist, scan history, and an optional AI provider (Ollama, OpenAI, or Anthropic).

```mermaid
flowchart LR
  A[CI/CD Pipeline] --> B[Trivy Scan]
  B --> C[POST /analyze-image]
  C --> D[Secrets Detector]
  C --> E[CVE Whitelist]
  C --> F[Rule Engine OWASP]
  C --> G[AI Provider Optional]

  D --> H{Secrets Found?}
  H -->|Yes| I[REJECTED]
  H -->|No| E

  E --> F
  F --> J{Needs AI Context?}
  J -->|Yes| G
  J -->|No| K[Deterministic Decision]
  G --> L[Final Gate Decision]
  K --> L
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

## Topologia y Arquitectura

### 1) Topologia de ejecucion (runtime)

```mermaid
flowchart TB
  subgraph CI[CI/CD Runner]
    P1[Build Image]
    P2[Trivy]
    P3[trivy_to_gate.py]
  end

  subgraph Gate[Sentinel Gate - FastAPI]
    API[/POST analyze-image/]
    APP[Gate Service]
    SEC[Secrets Detector]
    RULES[Rule Engine]
    AI[AI Adapter]
    REPO[Repository Adapter]
  end

  subgraph Data[Persistence]
    DB[(SQLite/PostgreSQL)]
    WL[(CVE Exceptions)]
    HIST[(Scan History)]
  end

  subgraph Models[AI Backends]
    OLL[Ollama Local]
    OAI[OpenAI]
    ANT[Anthropic]
  end

  P1 --> P2 --> P3 --> API
  API --> APP
  APP --> SEC
  APP --> RULES
  APP --> AI
  APP --> REPO
  REPO --> DB
  DB --> WL
  DB --> HIST
  AI --> OLL
  AI --> OAI
  AI --> ANT
```

### 2) Arquitectura hexagonal del proyecto

```mermaid
flowchart LR
  subgraph Web[Web Layer]
    CTRL[FastAPI Controllers]
  end

  subgraph App[Application Layer]
    SVC[GateService Orchestrator]
  end

  subgraph Domain[Domain Layer]
    ENT[Entities]
    POL[Security Policies and Rules]
    PORTS[Ports / Protocols]
  end

  subgraph Infra[Infrastructure Layer]
    AIP[AI Providers]
    PERS[SQL/Null Repository]
    DET[Secrets Detector]
  end

  CTRL --> SVC
  SVC --> ENT
  SVC --> POL
  SVC --> PORTS
  PORTS --> AIP
  PORTS --> PERS
  SVC --> DET
```

### 3) Flujo de decision de seguridad

```mermaid
sequenceDiagram
  autonumber
  participant CI as CI Pipeline
  participant G as Sentinel API
  participant S as Secrets Detector
  participant R as Rule Engine
  participant A as AI Provider
  participant D as Database

  CI->>G: POST /analyze-image (Trivy + Dockerfile)
  G->>S: Scan Dockerfile
  alt Secrets found
    S-->>G: REJECTED
    G->>D: Persist decision
    G-->>CI: REJECTED
  else No secrets
    G->>D: Load CVE whitelist
    G->>R: Evaluate deterministic rules
    alt Critical or hard threshold reached
      R-->>G: REJECTED
      G->>D: Persist decision
      G-->>CI: REJECTED
    else Warning or ambiguous context
      G->>A: Request contextual analysis
      A-->>G: APPROVED/WARNING/REJECTED
      G->>D: Persist decision
      G-->>CI: Final decision
    end
  end
```

### 4) Flujo de integracion CI/CD a despliegue

```mermaid
flowchart LR
  A[Commit or Pull Request] --> B[Build Docker Image]
  B --> C[Trivy Scan]
  C --> D[Send report to Sentinel]
  D --> E{Gate Decision}
  E -->|APPROVED| F[Deploy]
  E -->|WARNING| G[Deploy with remediation ticket]
  E -->|REJECTED| H[Block release and fix issues]
  F --> I[Dashboard and historical trace]
  G --> I
  H --> I
```

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

```mermaid
flowchart TD
    A[POST /analyze-image] --> B[1. Secrets Scan]
    B --> C{Secrets Found?}
    C -->|Yes| D[REJECTED: secrets_detector]
    C -->|No| E[2. Load CVE Whitelist]

    E --> F[3. Rule Engine]
    F --> G{Critical or hard threshold?}
    G -->|Yes| H[REJECTED: rule_engine]
    G -->|No| I{Warning context or no hit?}

    I -->|AI Disabled| J[Deterministic APPROVED/WARNING]
    I -->|AI Enabled| K[4. AI Analysis]
    K --> L[AI can confirm/escalate/downgrade]

    D --> M[5. Persist ScanRecord if DB enabled]
    H --> M
    J --> M
    L --> M
    M --> N[6. Return GateDecision + dashboard_url]
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

```mermaid
flowchart TB
  ROOT[Sentinel-AI-CD]
  ROOT --> APP[app]
  ROOT --> PIPE[pipeline]
  ROOT --> SCHEMA[schema.sql]
  ROOT --> DC[docker-compose.yml]
  ROOT --> REQ[requirements.txt]

  APP --> D1[domain]
  APP --> A1[application]
  APP --> I1[infrastructure]
  APP --> W1[web]

  D1 --> D2[entities.py]
  D1 --> D3[rules.py]
  D1 --> D4[ports]

  A1 --> A2[gate_service.py]

  I1 --> I2[ai]
  I1 --> I3[persistence]
  I1 --> I4[security]

  I2 --> I2A[factory.py]
  I2 --> I2B[ollama.py]
  I2 --> I2C[openai_provider.py]
  I2 --> I2D[anthropic_provider.py]
  I2 --> I2E[prompt.py]
  I2 --> I2F[parser.py]

  I3 --> I3A[factory.py]
  I3 --> I3B[null_repository.py]
  I3 --> I3C[sql_repository.py]

  I4 --> I4A[secrets_detector.py]

  W1 --> W2[main.py]

  PIPE --> P1[trivy_to_gate.py]
  PIPE --> P2[gate_check.sh]
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

---

## Por Que Sentinel Es Diferente y Mejor

- Security by design: combina reglas deterministicas con IA contextual, pero mantiene hard-stops que la IA no puede sobreescribir.
- Menos falsos positivos operativos: whitelist de CVEs con expiracion y trazabilidad para excepciones justificadas.
- Listo para entornos reales: funciona con o sin base de datos y con IA local o cloud sin cambiar el contrato del API.
- Integracion CI/CD directa: salida con codigos de retorno claros, marcador para dashboard y adaptador dedicado para Trivy.
- Trazabilidad completa: historial por imagen, tendencia de riesgo y evidencia centralizada para auditoria tecnica.
- Flexibilidad arquitectonica: diseño hexagonal que facilita pruebas, evolucion de proveedores y mantenimiento.

## Creadores

- Daniel Eduardo Useche
- Juan Diego Rodriguez
