# Sentinel — AI DevSecOps Deployment Gate

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111%2B-009485?logo=fastapi&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-24%2B-2496ED?logo=docker&logoColor=white)
![Trivy](https://img.shields.io/badge/Trivy-0.50%2B-1DA1F2?logo=aquasecurity&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

**Puerta de seguridad inteligente para pipelines CI/CD**

[Instalación](#instalación) · [Documentación](#tabla-de-contenidos) · [GitHub](https://github.com/DannielEU/Sentinel-AI-CD)

</div>

---

## ¿Qué es Sentinel?

Puerta de seguridad inteligente para pipelines CI/CD. Analiza imágenes de contenedor con **Trivy**, aplica un motor de reglas determinístico alineado con **OWASP** y —opcionalmente— consulta a **Mistral vía Ollama** (o **Neural-Chat**, especializado en seguridad Docker) para decidir si un despliegue debe ser `APPROVED`, `WARNING` o `REJECTED`.

**Compatible con:** Azure Container Instances · App Service · Render · Railway · Fly.io · Kubernetes · On-premise

---

## Características clave

- **Motor de reglas OWASP-aligned** — bloquea vulnerabilidades críticas, controla severidad
- **AI contextual opcional** — Mistral/Neural-Chat analiza imágenes complejas sin enviar datos a terceros
- **Integración trivial** — un script Python + variables de entorno en cualquier CI/CD
- **Autenticación de token** — protege el endpoint si lo expones públicamente
- **Rápido** — decisión inmediata en modo reglas puras (~<100ms)
- **Sin dependencias de servicios externos** — Ollama es local, sin costos de API

---

## Quick Start

```bash
# 1. Clonar y levantar con Docker Compose
git clone https://github.com/DannielEU/Sentinel-AI-CD.git
cd Sentinel-AI-CD
docker compose up -d

# 2. Escanear una imagen
docker build -t miapp:1.0.0 .
trivy image --format json --output report.json miapp:1.0.0

# 3. Enviar al gate
python pipeline/trivy_to_gate.py \
  --report report.json \
  --image miapp:1.0.0 \
  --dockerfile ./Dockerfile

# Resultado: APPROVED | WARNING | REJECTED
```

**APIs disponibles:** 
- Swagger: http://localhost:8000/docs
- Gate: http://localhost:8000/analyze-image (POST)
- Health: http://localhost:8000/health (GET)

---

## Tabla de contenidos

1. [Características clave](#características-clave)
2. [Tecnología](#tecnología)
3. [Instalación](#instalación)
4. [Configuración](#configuración)
5. [Flujo del pipeline](#flujo-del-pipeline)
6. [Motor de reglas (OWASP)](#motor-de-reglas-owasp)
7. [API Reference](#api-reference)
8. [Manual de usuario](#manual-de-usuario)
9. [Despliegue](#despliegue)
10. [GitHub Actions](#ejemplo-completo-de-github-actions)
11. [Troubleshooting](#troubleshooting)

---

## Tecnología

| Componente | Tecnología | Versión mínima |
|---|---|---|
| API Gateway | [FastAPI](https://fastapi.tiangolo.com/) | 0.111 |
| Servidor ASGI | [Uvicorn](https://www.uvicorn.org/) | 0.29 |
| Validación de datos | [Pydantic v2](https://docs.pydantic.dev/) | 2.7 |
| Cliente HTTP | [HTTPX](https://www.python-httpx.org/) | 0.27 |
| Escáner de vulnerabilidades | [Trivy](https://trivy.dev/) (Aqua Security) | 0.50 |
| Modelo de lenguaje local | [Neural-Chat](https://huggingface.co/Intel/neural-chat-7b) o [Mistral 7B](https://mistral.ai/) via [Ollama](https://ollama.com/) | 0.1.x |
| Contenedores | Docker + Docker Compose | 24.x |
| Runtime | Python | 3.11 |
| Nube | Azure Container Instances, App Service, on-premise | - |

### ¿Por qué estas tecnologías?

- **FastAPI** — tipado estricto, documentación automática (Swagger/OpenAPI), rendimiento asíncrono nativo.
- **Trivy** — escáner open-source líder del sector, soporta imágenes OCI, filesystems, repos y SBOMs.
- **Ollama + Neural-Chat** — LLM local, sin enviar datos a terceros, sin costos de API. Neural-Chat está optimizado para análisis técnico y seguridad Docker (mejor que Mistral para este caso de uso).
- **Pydantic v2** — validación de entrada con errores claros; evita que reportes malformados lleguen al motor.

---

## Instalación

### Requisitos previos

```bash
# Verificar versiones
python --version      # >= 3.11
docker --version      # >= 24.x
docker compose version # >= 2.x

# Instalar Trivy (Linux/macOS)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b /usr/local/bin

# Instalar Ollama (solo si usas AI_DISABLED=false)
# https://ollama.com/download
ollama pull mistral
```

### Opción A — Docker Compose (recomendado para desarrollo)

Levanta Sentinel + Ollama con un solo comando. Ollama descarga Mistral automáticamente (~4 GB la primera vez).

```bash
git clone https://github.com/DannielEU/Sentinel-AI-CD.git
cd Sentinel-AI-CD
```

| Servicio | URL |
|---|---|
| Sentinel API | http://localhost:8000 |
| Swagger UI | http://localhost:8000/docs |
| Ollama | http://localhost:11434 |

### Opción B — Ejecución local sin Docker

```bash
git clone https://github.com/DannielEU/Sentinel-AI-CD.git
cd Sentinel-AI-CD
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. (Opcional) Iniciar Ollama
ollama serve &
ollama pull mistral

# 4. Iniciar Sentinel
cd app
uvicorn main:app --reload --port 8000
```

### Opción C — Solo el gate (sin Ollama, modo reglas)

Útil en CI/CD donde no hay GPU ni recursos para un LLM.

```bash
cd app
AI_DISABLED=true uvicorn main:app --port 8000
```

Con `AI_DISABLED=true` el servicio aplica únicamente el motor de reglas determinístico. Si ninguna regla se activa, devuelve `APPROVED` directamente sin llamar a Ollama.

---

## Configuración

### Variables de entorno

| Variable | Default | Descripción |
|---|---|---|
| `OLLAMA_URL` | `http://localhost:11434` | URL base del servidor Ollama |
| `AI_DISABLED` | `false` | `true` desactiva Ollama; solo se usa el motor de reglas |
| `GATE_AUTH_TOKEN` | _(vacío)_ | Si se define, todos los requests deben incluir `Authorization: Bearer <token>` |

### Umbrales del motor de reglas

Edita `app/rule_engine.py`:

```python
MAX_IMAGE_SIZE_MB  = 1200   # MB — WARNING si se supera
MAX_HIGH_VULNS     = 10     # REJECTED si high > este valor; WARNING si high >= 1
MAX_MEDIUM_VULNS   = 30     # WARNING si se supera
```

### Autenticación (opcional)

```bash
# Generar un token seguro
python -c "import secrets; print(secrets.token_hex(32))"

# Exportar antes de iniciar el servicio
export GATE_AUTH_TOKEN=tu_token_aqui
uvicorn main:app --port 8000

# Llamar al gate con el token
curl -H "Authorization: Bearer tu_token_aqui" \
     -X POST http://localhost:8000/analyze-image \
     -d @payload.json
```

---

## Flujo del pipeline

```
┌──────────────────────────────────────────────────────────────────┐
│                         CI/CD PIPELINE                           │
│                                                                  │
│  1. git push / pull_request                                      │
│  2. docker build -t myapp:sha .                                  │
│  3. trivy image --format json -o report.json myapp:sha           │
│  4. python trivy_to_gate.py --report report.json --image myapp   │
│                      │                                           │
│            POST /analyze-image                                   │
│                      │                                           │
│         ┌────────────▼────────────┐                              │
│         │      Rule Engine        │                              │
│         │   (determinístico)      │                              │
│         └────────────┬────────────┘                              │
│              fires?  │  no fires                                 │
│            ┌─────────┴──────────┐                                │
│            │                    ▼                                │
│       decisión            Ollama / Mistral                       │
│       inmediata          (AI_DISABLED=false)                     │
│            │                    │                                │
│            └──────────┬─────────┘                                │
│                       ▼                                          │
│          { decision, reason, recommendations }                   │
│                       │                                          │
│          ┌────────────┼────────────┐                             │
│       exit 0       exit 2       exit 1                           │
│      APPROVED      WARNING     REJECTED                          │
│     continúa     continúa+log  pipeline falla                    │
│     deploy        deploy       deploy bloqueado                  │
└──────────────────────────────────────────────────────────────────┘
```

### Lógica interna del gate

```
POST /analyze-image
        │
        ▼
   Rule Engine
   ├─ critical > 0          ──► REJECTED
   ├─ high > 10             ──► REJECTED
   ├─ high 1..10            ──► WARNING
   ├─ size_mb > 1200        ──► WARNING
   └─ medium > 30           ──► WARNING
        │
    no rule fires
        │
        ▼
   AI_DISABLED=true?
   ├─ sí  ──► APPROVED (rule-engine fallback)
   └─ no  ──► Ollama / Mistral ──► GateDecision
```

---

## Motor de reglas (OWASP)

Las reglas implementadas están alineadas con las guías de **OWASP Docker Security** y **OWASP Top 10 CI/CD Security Risks**:

| Regla | Condición | Decisión | Referencia OWASP |
|---|---|---|---|
| Vulnerabilidades críticas | `critical > 0` | `REJECTED` | CICD-SEC-4: Poisoned Pipeline Execution |
| Exceso de vulns altas | `high > 10` | `REJECTED` | CICD-SEC-6: Insufficient Credential Hygiene |
| Vulns altas moderadas | `high 1..10` | `WARNING` | OWASP Docker Top 10: D02 |
| Imagen sobredimensionada | `size_mb > 1200` | `WARNING` | OWASP Docker Top 10: D06 |
| Exceso de vulns medias | `medium > 30` | `WARNING` | CICD-SEC-4 |
| Sin regla activa | — | → AI model | — |

### OWASP CI/CD Security Risks cubiertos

- **CICD-SEC-1** (Insufficient Flow Control) — el gate bloquea el pipeline ante REJECTED, impidiendo despliegues no autorizados.
- **CICD-SEC-4** (Poisoned Pipeline Execution) — Trivy detecta dependencias comprometidas antes del despliegue.
- **CICD-SEC-6** (Insufficient Credential Hygiene) — el token de autenticación opcional protege el endpoint del gate.
- **CICD-SEC-8** (Ungoverned Usage of 3rd Party Services) — todas las dependencias se escanean antes de llegar a producción.

---

## Detección estática (SAST)

Sentinel puede complementarse con herramientas de análisis estático de código fuente antes del escaneo de imagen. Se recomienda añadir los siguientes pasos al pipeline **antes** del `docker build`:

### Bandit — análisis de seguridad Python

```bash
pip install bandit
bandit -r . -ll -ii --exit-zero
# -ll  → solo severidad MEDIUM o superior
# -ii  → solo confianza MEDIUM o superior
```

### Semgrep — reglas OWASP y CWE

```bash
pip install semgrep
semgrep --config=p/owasp-top-ten --config=p/python .
```

### Integración en GitHub Actions

```yaml
- name: SAST — Bandit
  run: |
    pip install bandit
    bandit -r . -ll -ii -f json -o bandit_report.json || true

- name: SAST — Semgrep
  uses: returntocorp/semgrep-action@v1
  with:
    config: >-
      p/owasp-top-ten
      p/python
      p/secrets
```

### Trivy como SAST de dependencias

Trivy también puede escanear el filesystem (no solo la imagen) para detectar vulnerabilidades en dependencias antes del build:

```bash
trivy fs . --format json --output fs_report.json
```

---

## API Reference

### `POST /analyze-image`

Recibe un reporte de seguridad y devuelve una decisión de despliegue.

**Headers**

```
Content-Type: application/json
Authorization: Bearer <token>   # solo si GATE_AUTH_TOKEN está configurado
```

**Request body**

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
  "os_family": "debian",
  "dockerfile_content": "FROM python:3.11-slim\n...",
  "scanner_output": "{ ...raw trivy JSON truncado a 4000 chars... }"
}
```

| Campo | Tipo | Requerido | Descripción |
|---|---|---|---|
| `image_name` | string | ✅ | Nombre completo de la imagen |
| `image_size_mb` | float > 0 | ✅ | Tamaño en MB |
| `vulnerabilities` | objeto | — | Conteos por severidad (default: todos 0) |
| `base_image` | string | — | Imagen base del `FROM` |
| `os_family` | string | — | SO dentro de la imagen |
| `dockerfile_content` | string | — | Contenido del Dockerfile (max 4000 chars) |
| `scanner_output` | string | — | Salida cruda del escáner (max 4000 chars) |

**Response body**

```json
{
  "decision": "WARNING",
  "reason": "Image has 2 high-severity vulnerabilities.",
  "recommendations": [
    "Review and patch high-severity vulnerabilities soon.",
    "Schedule a remediation sprint for the next release."
  ],
  "source": "rule_engine",
  "image_name": "myapp:1.2.3"
}
```

| Campo | Valores |
|---|---|
| `decision` | `APPROVED` · `WARNING` · `REJECTED` |
| `source` | `rule_engine` · `ai_model` |

**Códigos HTTP**

| Código | Significado |
|---|---|
| 200 | Decisión emitida correctamente |
| 401 | Token ausente |
| 403 | Token inválido |
| 503 | Ollama no disponible |

### `GET /health`

```json
{ "status": "ok", "ai_disabled": false }
```

### `GET /`

```json
{ "status": "ok", "service": "AI DevSecOps Deployment Gate", "ai_disabled": false }
```

---

## Manual de usuario

### 1. Verificar que el servicio está activo

```bash
curl http://localhost:8000/health
# { "status": "ok", "ai_disabled": true }
```

### 2. Escanear una imagen con Trivy

```bash
docker build -t miapp:1.0.0 .

trivy image \
  --format json \
  --output trivy_report.json \
  --exit-code 0 \
  miapp:1.0.0
```

### 3. Enviar el reporte al gate

```bash
python pipeline/trivy_to_gate.py \
  --report     trivy_report.json \
  --image      miapp:1.0.0 \
  --gate       http://localhost:8000 \
  --dockerfile ./Dockerfile
```

Salida esperada:

```
Parsing Trivy report: trivy_report.json
Sending report to gate: http://localhost:8000
  Vulns → critical=0 high=2 medium=8 low=15

============================================================
  ⚠️   GATE DECISION: WARNING
============================================================
  Image  : miapp:1.0.0
  Source : rule_engine
  Reason : Image has 2 high-severity vulnerability/ies.

  Recommendations:
    • Review and patch high-severity vulnerabilities soon.
    • Schedule a remediation sprint for the next release.
============================================================
```

### 4. Usar el script shell (alternativa)

```bash
export IMAGE_NAME=miapp:1.0.0
export GATE_URL=http://localhost:8000
export DOCKERFILE=./Dockerfile

chmod +x pipeline/gate_check.sh
./pipeline/gate_check.sh

# exit 0 → APPROVED  → continúa el pipeline
# exit 1 → REJECTED  → el pipeline falla aquí
# exit 2 → WARNING   → el pipeline continúa con alerta
```

### 5. Interpretar la decisión

| Decisión | Exit code | Qué hacer |
|---|---|---|
| `APPROVED` | 0 | Proceder con `docker push` y despliegue |
| `WARNING` | 2 | Desplegar pero abrir ticket de remediación |
| `REJECTED` | 1 | No desplegar; corregir vulnerabilidades primero |

### 6. Llamada directa a la API (curl)

```bash
curl -s -X POST http://localhost:8000/analyze-image \
  -H "Content-Type: application/json" \
  -d '{
    "image_name": "miapp:1.0.0",
    "image_size_mb": 250,
    "vulnerabilities": {
      "critical": 0, "high": 1, "medium": 5, "low": 10, "unknown": 0
    }
  }' | python -m json.tool
```

---

## Despliegue

### Docker Compose (local / servidor propio)

```bash
# Producción con Ollama
docker compose up -d --build

# Solo gate, sin Ollama
AI_DISABLED=true docker compose up -d gate
```

### Dockerfile standalone

```bash
docker build -f app/Dockerfile -t sentinel-gate:latest .

docker run -d \
  --name sentinel \
  -p 8000:8000 \
  -e AI_DISABLED=true \
  -e GATE_AUTH_TOKEN=mi_token_secreto \
  sentinel-gate:latest
```

### Variables de entorno en producción

```bash
# .env (no commitear)
OLLAMA_URL=http://ollama-server:11434
AI_DISABLED=false
GATE_AUTH_TOKEN=token_generado_con_secrets_token_hex_32
```

### Render / Railway / Fly.io

1. Conectar el repositorio.
2. Configurar las variables de entorno en el dashboard.
3. Comando de inicio: `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Health check path: `/health`

> **Nota:** En plataformas SaaS sin GPU, usar `AI_DISABLED=true`. El motor de reglas no requiere Ollama.

---

## SaaS / Uso como servicio externo

Sentinel puede desplegarse como servicio centralizado y ser consumido por múltiples proyectos/equipos.

### Arquitectura multi-proyecto

```
Proyecto A  ──┐
Proyecto B  ──┼──► POST https://sentinel.tu-empresa.com/analyze-image
Proyecto C  ──┘         (token por proyecto en Authorization header)
```

### Configurar autenticación por proyecto

```bash
# Generar token único por proyecto
python -c "import secrets; print(secrets.token_hex(32))"

# En el servidor Sentinel
export GATE_AUTH_TOKEN=token_proyecto_a

# En el pipeline del proyecto A
curl -H "Authorization: Bearer token_proyecto_a" \
     -X POST https://sentinel.tu-empresa.com/analyze-image \
     -d @trivy_report_payload.json
```

### Llamada desde trivy_to_gate.py contra servidor remoto

```bash
python pipeline/trivy_to_gate.py \
  --report     trivy_report.json \
  --image      miapp:1.0.0 \
  --gate       https://sentinel.tu-empresa.com \
  --dockerfile ./Dockerfile
```

---

## Ejemplo completo de GitHub Actions

El archivo completo vive en [`pipeline/github-actions-example.yml`](https://github.com/DannielEU/Sentinel-AI-CD/blob/main/pipeline/github-actions-example.yml). 

**Pasos principales:**
1. Copiar a `.github/workflows/ci.yml` en tu proyecto
2. Ajustar variables (IMAGE_NAME, GATE_URL, RENDER_DEPLOY_HOOK_URL)
3. Cambiar la rama de Sentinel a la que uses (`ref: main`)

**Flujo del workflow:**

```
┌────────┐     ┌──────────────┐     ┌────────┐
│ Tests  │────→│ Security Gate│────→│ Deploy │
└────────┘     └──────────────┘     └────────┘
               (Trivy + Sentinel)
                - exit 0: APPROVED ✓ 
                - exit 2: WARNING ⚠
                - exit 1: REJECTED ✗
```

**Características clave:**

- **Tests primero**: Valida coverage >= 80%
- **Security Gate**: Ejecuta Trivy + Sentinel con `AI_DISABLED=true` (sin GPU)
- **Comentario en PR**: Publica automáticamente un reporte de vulnerabilidades en la PR
- **Deploy condicional**: Solo a `main` si todos los jobs pasaron
- **Exit codes semánticos**: `0` (APPROVED), `2` (WARNING), `1` (REJECTED)

Ver archivo completo en [`pipeline/github-actions-example.yml`](https://github.com/DannielEU/Sentinel-AI-CD/blob/main/pipeline/github-actions-example.yml) para la implementación detallada.

---

## Ejemplos de respuesta

### REJECTED — vulnerabilidad crítica (rule engine)

```json
{
  "decision": "REJECTED",
  "reason": "Image has 1 critical vulnerability/ies. Deployment is blocked.",
  "recommendations": [
    "Update base image to a patched version.",
    "Run `trivy image --severity CRITICAL <image>` to list affected packages.",
    "Pin vulnerable packages to fixed versions in the Dockerfile."
  ],
  "source": "rule_engine",
  "image_name": "myapp:1.2.3"
}
```

### WARNING — análisis contextual de Mistral (ai_model)

```json
{
  "decision": "WARNING",
  "reason": "The image has 2 high and 8 medium vulnerabilities; no critical issues but remediation is recommended before next release.",
  "recommendations": [
    "Upgrade python:3.11-slim base image to latest patch.",
    "Enable Dependabot for automatic dependency updates.",
    "Consider switching to distroless for a smaller attack surface.",
    "Run `pip audit` as part of the build to catch Python package CVEs."
  ],
  "source": "ai_model",
  "image_name": "myapp:1.2.3"
}
```

### APPROVED — imagen limpia (ai_model)

```json
{
  "decision": "APPROVED",
  "reason": "No critical or high vulnerabilities found; image size and dependency posture are acceptable.",
  "recommendations": [
    "Continue monitoring for new CVEs with scheduled Trivy scans.",
    "Consider adding a SBOM generation step to the pipeline."
  ],
  "source": "ai_model",
  "image_name": "myapp:1.2.3"
}
```

---

## Estructura del proyecto

```
sentinel-ai-cd/
├── app/
│   ├── main.py            # FastAPI app — endpoints y orquestación
│   ├── schemas.py         # Modelos Pydantic (ImageReport, GateDecision)
│   ├── rule_engine.py     # Motor de reglas determinístico (OWASP-aligned)
│   ├── ollama_client.py   # Cliente HTTP para Ollama + construcción de prompt
│   └── Dockerfile         # Imagen de producción (non-root)
├── pipeline/
│   ├── trivy_to_gate.py            # Adaptador: parsea Trivy JSON y llama a /analyze-image
│   ├── gate_check.sh               # Script shell universal (GitLab, Jenkins, Bitbucket, etc.)
│   └── github-actions-example.yml  # Plantilla lista para copiar a .github/workflows/
├── requirements.txt
├── docker-compose.yml
└── README.md
```

### ¿Para qué sirve cada archivo de `pipeline/`?

| Archivo | Propósito |
|---|---|
| `trivy_to_gate.py` | Convierte el JSON de Trivy al formato que espera la API y llama a `/analyze-image`. Es el núcleo del adaptador. |
| `gate_check.sh` | Script shell que orquesta todo: corre Trivy, llama a `trivy_to_gate.py` e interpreta el exit code. Funciona en **cualquier CI** (GitLab CI, Jenkins, Bitbucket Pipelines, etc.) con solo exportar 3 variables. |
| `github-actions-example.yml` | Plantilla de workflow completa para GitHub Actions. **No se ejecuta automáticamente** (vive en `pipeline/`, no en `.github/workflows/`). Es el ejemplo que copias y adaptas en tu propio proyecto. |

---

## Troubleshooting

### El gate no inicia — "Failed to connect to Ollama"

**Causa:** `OLLAMA_URL` apunta a un servidor que no está activo.

**Solución:**
```bash
# Verificar que Ollama está corriendo
curl http://localhost:11434

# Si no, iniciar Ollama
ollama serve &

# Si usas Docker Compose, verificar que el servicio está up
docker compose ps
```

### Trivy devuelve "database is locked"

**Causa:** Múltiples procesos de Trivy accediendo la BD simultáneamente.

**Solución:** Usar `--exit-code 0` en el comando trivy para no fallar, o agregar un pequeño delay entre escaneos.

```bash
trivy image --format json --exit-code 0 --output report.json miapp:1.0.0
```

### El gate devuelve "503 Service Unavailable"

**Causa:** Ollama no responde (GPU agotada, timeout, crash).

**Solución:**
```bash
# Ver logs de Ollama
docker compose logs ollama

# Reiniciar el servicio
docker compose restart ollama

# O desactivar AI y usar solo reglas
AI_DISABLED=true docker compose up -d
```

### El script `trivy_to_gate.py` dice "connection refused"

**Causa:** El gate no está escuchando en el puerto especificado.

**Solución:**
```bash
# Verificar que el gate está activo
curl http://localhost:8000/health

# Si no, iniciar el gate
cd app && uvicorn main:app --port 8000
```

### La autenticación con token no funciona

**Verificar:** El token debe incluirse en el header `Authorization: Bearer <token>`. Asegúrate de:

```bash
# Generar un token válido
export GATE_AUTH_TOKEN=$(python -c "import secrets; print(secrets.token_hex(32))")

# Incluirlo en la llamada
curl -H "Authorization: Bearer $GATE_AUTH_TOKEN" \
     -X POST http://localhost:8000/analyze-image \
     -d @payload.json
```

### La imagen se aprueba pero debería ser rechazada

**Verificar:**
1. Los umbrales en `app/rule_engine.py` son los esperados.
2. El payload JSON incluye los conteos de vulnerabilidades correctos.
3. Si `AI_DISABLED=false`, el modelo IA puede dar una decisión diferente que las reglas.

**Debug:** Envía el payload manualmente y revisa el campo `source` en la respuesta para saber si vino del `rule_engine` o del `ai_model`.

---

<p align="center">
  Hecho con FastAPI · Trivy · Ollama · Mistral
</p>
