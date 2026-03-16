# AI DevSecOps Deployment Gate

Servicio REST construido con **FastAPI** que actúa como puerta de validación inteligente dentro de un pipeline de CI/CD. Recibe reportes de seguridad de imágenes de contenedor, aplica reglas determinísticas y —si es necesario— consulta al modelo **Mistral** ejecutado localmente mediante **Ollama** para obtener un análisis contextual. Devuelve una decisión estructurada (`APPROVED`, `WARNING` o `REJECTED`) que el pipeline puede consumir directamente.

---

## Tabla de contenidos

1. [Arquitectura](#arquitectura)
2. [Estructura del proyecto](#estructura-del-proyecto)
3. [Requisitos](#requisitos)
4. [Instalación y arranque](#instalación-y-arranque)
5. [Flujo completo del pipeline](#flujo-completo-del-pipeline)
6. [API Reference](#api-reference)
7. [Motor de reglas](#motor-de-reglas)
8. [Integración con Ollama / Mistral](#integración-con-ollama--mistral)
9. [Variables de entorno](#variables-de-entorno)
10. [Integración CI/CD](#integración-cicd)
11. [Ejemplos de respuesta](#ejemplos-de-respuesta)

---

## Arquitectura

```
┌──────────────────────────────────────────────────────────────┐
│                        CI/CD PIPELINE                        │
│                                                              │
│  1. git push                                                 │
│  2. docker build -t myapp:1.2.3 .                           │
│  3. trivy image --format json -o report.json myapp:1.2.3    │
│  4. ./pipeline/gate_check.sh          (adapter + API call)  │
│                    │                                         │
│          ┌─────────▼─────────┐                              │
│          │  POST /analyze-   │                              │
│          │      image        │                              │
│          └─────────┬─────────┘                              │
│                    │                                         │
│         ┌──────────▼──────────┐                             │
│         │   Rule Engine       │ ◄── reglas rápidas          │
│         │  (determinístico)   │     sin LLM                 │
│         └──────────┬──────────┘                             │
│            fires?  │  no fires                              │
│           ┌────────┴──────────┐                             │
│           │                   ▼                             │
│     decisión              Ollama / Mistral                  │
│     inmediata            (análisis contextual)              │
│           │                   │                             │
│           └────────┬──────────┘                             │
│                    ▼                                         │
│         { "decision": "APPROVED"                            │
│           "reason":   "...",                                │
│           "recommendations": [...] }                        │
│                    │                                         │
│       ┌────────────┼────────────┐                           │
│    exit 0       exit 2       exit 1                         │
│   APPROVED      WARNING     REJECTED                        │
│  docker push  continúa+log  pipeline falla                  │
└──────────────────────────────────────────────────────────────┘
```

---

## Estructura del proyecto

```
.
├── app/
│   ├── main.py            # FastAPI app — endpoints y orquestación
│   ├── schemas.py         # Modelos Pydantic (ImageReport, GateDecision)
│   ├── rule_engine.py     # Motor de reglas determinístico
│   ├── ollama_client.py   # Cliente HTTP para Ollama + construcción de prompt
│   └── Dockerfile         # Imagen de producción (multi-stage, non-root)
├── pipeline/
│   ├── trivy_to_gate.py   # Adaptador Trivy JSON → ImageReport + llama a la API
│   ├── gate_check.sh      # Script shell para usar en cualquier CI
│   └── github-actions-example.yml  # Workflow de GitHub Actions listo para usar
├── requirements.txt
├── docker-compose.yml     # Levanta Gate + Ollama juntos
└── README.md
```

---

## Requisitos

| Herramienta | Versión mínima | Para qué |
|-------------|---------------|---------|
| Python      | 3.11          | Ejecutar el servicio |
| Ollama      | 0.1.x         | Servir el modelo Mistral localmente |
| Docker      | 24.x          | Construir y escanear imágenes |
| Trivy       | 0.50.x        | Escáner de vulnerabilidades |

---

## Instalación y arranque

### Opción A — Docker Compose (recomendado)

Levanta el servicio Gate y Ollama con un solo comando. Ollama descarga Mistral automáticamente en el primer arranque (~4 GB).

```bash
docker compose up --build
```

| Servicio | URL                    |
|---------|------------------------|
| Gate API | http://localhost:8000  |
| Swagger UI | http://localhost:8000/docs |
| Ollama   | http://localhost:11434 |

### Opción B — Ejecución local

```bash
# 1. Instalar dependencias
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Iniciar Ollama y descargar el modelo (solo primera vez)
ollama serve &
ollama pull mistral

# 3. Iniciar el servicio
cd app
uvicorn main:app --reload --port 8000
```

---

## Flujo completo del pipeline

### Paso a paso

```
1. git push  →  dispara el pipeline

2. docker build -t myapp:1.2.3 .
   └─ construye la imagen de la aplicación

3. trivy image --format json --output trivy_report.json myapp:1.2.3
   └─ genera el reporte de vulnerabilidades en JSON

4. pipeline/gate_check.sh
   ├─ llama a trivy_to_gate.py
   │   ├─ parsea trivy_report.json
   │   ├─ obtiene tamaño de la imagen via docker inspect
   │   ├─ extrae base image del Dockerfile (opcional)
   │   └─ POST /analyze-image  →  GateDecision
   └─ interpreta el exit code:
       exit 0 (APPROVED)  →  docker push / deploy
       exit 1 (REJECTED)  →  pipeline falla, despliegue bloqueado
       exit 2 (WARNING)   →  pipeline continúa, alerta registrada

5. docker push  (solo si APPROVED o WARNING)
```

### Lógica interna del gate

```
POST /analyze-image
        │
        ▼
   Rule Engine ──── critical > 0 ──────────────► REJECTED
        │         ├─ high > 10 ──────────────── REJECTED
        │         ├─ high 1..10 ───────────────► WARNING
        │         ├─ size > 1200 MB ───────────► WARNING
        │         └─ medium > 30 ─────────────► WARNING
        │
    no rule fires
        │
        ▼
   Ollama / Mistral
   (análisis contextual del reporte completo)
        │
        ▼
   GateDecision { decision, reason, recommendations, source }
```

---

## API Reference

### `POST /analyze-image`

Recibe un reporte de seguridad y devuelve una decisión de despliegue.

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
  "scanner_output": "{ ...raw trivy JSON... }"
}
```

| Campo | Tipo | Requerido | Descripción |
|-------|------|-----------|-------------|
| `image_name` | string | ✅ | Nombre completo de la imagen |
| `image_size_mb` | float > 0 | ✅ | Tamaño en MB |
| `vulnerabilities` | objeto | — | Conteos por severidad (default: todos 0) |
| `base_image` | string | — | Imagen base del `FROM` |
| `os_family` | string | — | Sistema operativo dentro de la imagen |
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

| Campo | Valores posibles |
|-------|-----------------|
| `decision` | `APPROVED` · `WARNING` · `REJECTED` |
| `source` | `rule_engine` · `ai_model` |

### `GET /health`

```json
{ "status": "ok" }
```

---

## Motor de reglas

Las reglas se evalúan en orden. La primera que se activa devuelve la decisión sin llamar al modelo.

| Regla | Condición | Decisión |
|-------|-----------|----------|
| Vulnerabilidades críticas | `critical > 0` | `REJECTED` |
| Muchas vulnerabilidades altas | `high > 10` | `REJECTED` |
| Pocas vulnerabilidades altas | `high 1..10` | `WARNING` |
| Imagen demasiado grande | `size_mb > 1200` | `WARNING` |
| Muchas vulnerabilidades medias | `medium > 30` | `WARNING` |
| Ninguna regla activa | — | → pasa al modelo AI |

Los umbrales se configuran en [app/rule_engine.py](app/rule_engine.py):

```python
MAX_IMAGE_SIZE_MB  = 1200
MAX_HIGH_VULNS     = 10
MAX_MEDIUM_VULNS   = 30
```

---

## Integración con Ollama / Mistral

Cuando ninguna regla del motor se activa, el servicio construye un prompt estructurado y lo envía a Ollama:

```
POST http://localhost:11434/api/generate
{
  "model": "mistral",
  "stream": false,
  "options": { "temperature": 0.2, "num_predict": 512 },
  "prompt": "You are a senior DevSecOps engineer..."
}
```

El prompt incluye todos los campos del reporte e indica al modelo que responda únicamente con un JSON de tres campos: `decision`, `reason`, `recommendations`.

El cliente de Ollama ([app/ollama_client.py](app/ollama_client.py)) limpia la respuesta del modelo (elimina markdown, code fences, texto extra) antes de parsear el JSON.

---

## Variables de entorno

| Variable | Default | Descripción |
|----------|---------|-------------|
| `OLLAMA_URL` | `http://localhost:11434` | URL base del servidor Ollama |

Con Docker Compose la variable se inyecta automáticamente (`http://ollama:11434`).

---

## Integración CI/CD

### Script universal (`gate_check.sh`)

```bash
export IMAGE_NAME=myapp:1.2.3
export GATE_URL=http://localhost:8000   # opcional
export DOCKERFILE=./Dockerfile          # opcional

./pipeline/gate_check.sh
# exit 0 → APPROVED
# exit 1 → REJECTED (el pipeline fallará aquí)
# exit 2 → WARNING
```

### GitHub Actions

Ver el workflow completo en [pipeline/github-actions-example.yml](pipeline/github-actions-example.yml).

Fragmento clave:

```yaml
- name: Run AI Security Gate
  run: |
    IMAGE_NAME=${{ env.IMAGE_NAME }} \
    GATE_URL=${{ env.GATE_URL }} \
    ./pipeline/gate_check.sh

- name: Push to registry
  if: success()   # solo si el gate no falló (exit 0 o 2)
  run: docker push ${{ env.IMAGE_NAME }}
```

### GitLab CI

```yaml
security-gate:
  stage: test
  script:
    - export IMAGE_NAME=$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    - ./pipeline/gate_check.sh
  allow_failure: false   # REJECTED bloquea el pipeline
```

### Uso manual del adaptador

```bash
# Generar reporte con Trivy
trivy image --format json --output trivy_report.json myapp:1.2.3

# Enviar al gate directamente
python pipeline/trivy_to_gate.py \
  --report     trivy_report.json \
  --image      myapp:1.2.3 \
  --gate       http://localhost:8000 \
  --dockerfile ./Dockerfile
```

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
