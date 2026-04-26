# Sentinel AI-CD — Prueba Local

Entorno completo para probar Sentinel en tu máquina: **Trivy + Gate (Sentinel API) + Ollama (IA)** — sin necesidad de CI/CD ni nube.

---

## Requisitos previos

| Herramienta | Versión mínima | Para qué |
|---|---|---|
| Docker Desktop / Engine | 24+ | Ejecutar todos los servicios |
| Docker Compose | v2 | Orquestar servicios |
| Python 3.10+ | — | Ejecutar `scan.sh` / `trivy_to_gate.py` |
| 6 GB RAM libres | — | Ollama + modelo mistral (~4 GB) |

> **Sin Python:** puedes enviar el reporte Trivy directamente con `curl` (ver sección avanzada al final).

---

## Inicio rápido

### 1. Configurar variables de entorno

```bash
cd Sentinel-AI-CD/local
cp .env.example .env
# Edita .env si quieres cambiar puertos, modelo o proveedor de IA
```

### 2. Levantar los servicios

```bash
docker compose up -d
```

Esto inicia:
- `sentinel-local-ollama` → puerto `11434`
- `sentinel-local-gate`   → puerto `8000`

Verificar que todo está corriendo:

```bash
docker compose ps
docker compose logs -f gate   # Ctrl+C para salir
```

### 3. Descargar el modelo de IA (solo la primera vez)

Espera a que Ollama esté listo (~30 segundos) y luego descarga el modelo:

```bash
docker exec sentinel-local-ollama ollama pull mistral
```

> `mistral` pesa ~4 GB. Con `neural-chat` o `llama3` también funciona pero el análisis es menos preciso.
> Puedes verificar que está listo: `docker exec sentinel-local-ollama ollama list`

### 4. Verificar que el gate responde

```bash
curl http://localhost:8000/health
# Respuesta esperada: {"status":"ok", ...}
```

Interfaz web (Swagger UI): [http://localhost:8000/docs](http://localhost:8000/docs)

---

## Escanear una imagen — Flujo completo

### Opción A: Script automático (recomendado)

```bash
# Escanear una imagen pública
./scan.sh nginx:latest

# Escanear tu propia imagen + incluir Dockerfile (detecta secretos)
./scan.sh mi-app:1.0.0 ../Dockerfile

# Con token de autenticación
GATE_TOKEN=mi-token ./scan.sh mi-app:1.0.0
```

El script hace los 3 pasos internamente y muestra el resultado final.

---

### Opción B: Paso a paso manual

#### Paso 1 — Escanear con Trivy

Trivy se ejecuta como contenedor Docker (sin instalación):

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd):/output" \
  aquasec/trivy:latest image \
  --format json \
  --output /output/trivy_report.json \
  nginx:latest
```

Esto genera `trivy_report.json` en el directorio actual.

#### Paso 2 — Enviar a Sentinel Gate

```bash
python3 ../pipeline/trivy_to_gate.py \
  --report trivy_report.json \
  --image  nginx:latest \
  --gate   http://localhost:8000
```

Con Dockerfile (análisis de secretos + contexto para la IA):

```bash
python3 ../pipeline/trivy_to_gate.py \
  --report     trivy_report.json \
  --image      mi-app:1.0.0 \
  --gate       http://localhost:8000 \
  --dockerfile ../Dockerfile
```

#### Paso 3 — Ver el resultado

El script imprime la decisión de Sentinel:

```
══════════════════════════════════════════════════════════════════════
  ✅  GATE DECISION: APPROVED
══════════════════════════════════════════════════════════════════════
  Image  : nginx:latest
  Source : rule-engine
  Reason : Image passed all security checks.
  ...
  Dashboard : http://localhost:8000/dashboard/nginx%3Alatest
══════════════════════════════════════════════════════════════════════
```

**Códigos de salida:**
| Código | Significado |
|---|---|
| `0` | APPROVED — imagen aprobada |
| `1` | REJECTED — imagen rechazada (bloquea el deploy) |
| `2` | WARNING  — aprobada con advertencias |
| `3` | ERROR    — fallo de comunicación con el gate |

---

## Dashboard web

Accede al historial de escaneos en el navegador:

```
http://localhost:8000/dashboard
http://localhost:8000/dashboard/<imagen>   # reporte específico
```

---

## Cambiar proveedor de IA

Edita `.env` y reinicia el gate:

```bash
# Sin IA (solo motor de reglas, más rápido)
AI_PROVIDER=disabled

# Con OpenAI
AI_PROVIDER=openai
OPENAI_API_KEY=sk-...

# Con Anthropic
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
```

```bash
docker compose restart gate
```

---

## Usar PostgreSQL en lugar de SQLite

SQLite es suficiente para pruebas locales. Para probar con PostgreSQL:

```bash
# 1. Levantar con el perfil postgres
docker compose --profile postgres up -d

# 2. Actualizar DATABASE_URL en .env
DATABASE_URL=postgresql+asyncpg://sentinel:sentinel@db:5432/sentinel

# 3. Reiniciar el gate para que use la nueva DB
docker compose restart gate
```

---

## Generar un token de autenticación

```bash
python3 ../scripts/generate_token.py
```

Copia el token en `.env`:
```
GATE_AUTH_TOKEN=el-token-generado
```

Úsalo en el escaneo:
```bash
GATE_TOKEN=el-token-generado ./scan.sh nginx:latest
```

---

## Sección avanzada — envío con curl (sin Python)

Si no tienes Python, puedes construir el JSON manualmente y enviarlo con curl:

```bash
curl -X POST http://localhost:8000/analyze-image \
  -H "Content-Type: application/json" \
  -d '{
    "image_name": "nginx:latest",
    "image_size_mb": 187,
    "vulnerabilities": {
      "critical": 0,
      "high": 2,
      "medium": 15,
      "low": 40,
      "unknown": 0
    }
  }'
```

---

## Parar y limpiar

```bash
# Parar servicios (conserva datos)
docker compose down

# Parar y borrar volúmenes (borra BD y modelos descargados)
docker compose down -v
```

---

## Solución de problemas

| Problema | Solución |
|---|---|
| `gate` no arranca | `docker compose logs gate` — revisar errores de build |
| Timeout en análisis IA | El modelo está cargando por primera vez; espera 2-3 min |
| `trivy: permission denied` | Asegúrate de que Docker Desktop tiene acceso al socket |
| `Cannot connect to gate` | Verificar `docker compose ps` y que el puerto 8000 no esté ocupado |
| Ollama usa mucha RAM | Cambiar a `OLLAMA_MODEL=neural-chat` en `.env` y reiniciar |
