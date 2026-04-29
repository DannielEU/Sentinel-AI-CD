# Prompt Profesional — Presentación Sentinel AI-CD

> Usa este prompt en ChatGPT, Claude o cualquier LLM para generar el contenido
> de cada diapositiva. Pega el bloque completo como un solo mensaje.

---

## PROMPT

```
Eres un diseñador de presentaciones ejecutivas especializado en ciberseguridad y DevSecOps.
Tu tarea es generar el contenido completo, diapositiva por diapositiva, de una presentación
de 10 minutos para un comité evaluador de ciberseguridad (perfil: docentes/jurado técnico
de un seminario universitario de Fundamentos de Seguridad de la Información).

El proyecto se llama SENTINEL AI-CD.
Tema oficial asignado: "Aplicación de IA para detección temprana de vulnerabilidades en pipelines CI/CD"
y también cubre: "Seguridad en pipelines de despliegue continuo (CD)" y
"SCA y gestión de vulnerabilidades en dependencias en CI/CD".

────────────────────────────────────────────────────────────────────────────────
CONTEXTO TÉCNICO COMPLETO DEL PROYECTO (usa esto como fuente de verdad)
────────────────────────────────────────────────────────────────────────────────

QUÉ ES SENTINEL:
Sentinel AI-CD es un microservicio REST (FastAPI + Python 3.11) que actúa como
puerta de seguridad inteligente en pipelines CI/CD. Se inserta ANTES del despliegue
de cualquier imagen de contenedor. Recibe el reporte JSON de Trivy, lo evalúa con
un motor de reglas determinístico alineado con OWASP, y opcionalmente consulta a
Mistral 7B (via Ollama, corriendo LOCAL) para emitir una decisión estructurada:
APPROVED, WARNING o REJECTED — con exit codes estándar (0/1/2) que el pipeline
consume directamente.

FLUJO TÉCNICO:
git push → docker build → trivy image --format json → POST /analyze-image →
{ decision, reason, recommendations, dashboard_url } → exit 0/1/2 →
deploy continúa o pipeline falla

STACK TECNOLÓGICO:
- FastAPI 0.111 + Uvicorn 0.29 (API async, Swagger automático)
- Pydantic v2 (validación estricta de toda entrada)
- Trivy (Aqua Security) — escáner open-source líder, soporta OCI/SBOM/filesystem
- Mistral 7B via Ollama — LLM LOCAL, sin envío de datos a terceros, sin costo de API
- SQLAlchemy async + aiosqlite/asyncpg — historial de escaneos y whitelist de CVEs
- Docker multi-stage build + usuario non-root (gateuser UID 1000)
- GitHub Actions workflow completo (test → security-gate → deploy)

MOTOR DE REGLAS (determinístico, siempre activo, OWASP-aligned):
- critical > 0 → REJECTED (OWASP CICD-SEC-4)
- high > 10 → REJECTED (OWASP Docker D02)
- high 1..10 → WARNING (OWASP Docker D02)
- size_mb > 1200 → WARNING (OWASP Docker D06)
- medium > 30 → WARNING (OWASP CICD-SEC-4)
- Sin regla activa → Mistral analiza contexto completo (Dockerfile, OS, scanner output)

INNOVACIÓN / DIFERENCIADORES:
1. LLM LOCAL (Mistral 7B via Ollama): los reportes de seguridad NUNCA salen de la
   infraestructura del equipo. Cero dependencia de APIs externas de pago.
2. Arquitectura dual: reglas determinísticas + AI contextual. El LLM solo actúa
   cuando las reglas no se disparan — un modelo comprometido NO puede aprobar
   una imagen con critical > 0.
3. Agnóstico de CI: funciona con GitHub Actions, GitLab CI, Jenkins, Bitbucket
   con el mismo script shell (gate_check.sh) exportando 3 variables.
4. Modo SaaS: un Sentinel centralizado para múltiples proyectos/equipos con
   tokens Bearer por cliente.
5. Dashboard web integrado: historial de escaneos, tendencia de vulnerabilidades,
   whitelist de CVEs, gráfico SVG de evolución — sin dependencias de frontend.
6. Auto-evaluación continua: Sentinel pasa por su propio gate antes de desplegarse
   (dogfooding de seguridad). El pipeline de CI de Sentinel escanea la imagen de
   Sentinel con Trivy + su propio motor de reglas.

ANÁLISIS ESTÁTICO (SAST) — RESULTADOS REALES:
- Ruff (calidad/estilo): 2362 líneas analizadas → All checks passed (0 errores tras autofix)
- Bandit (seguridad Python): 0 High, 0 Medium, 0 Low tras correcciones aplicadas
  (los 5 hallazgos originales eran falsos positivos documentados con #nosec)
- Mypy (tipado estático): 27 archivos revisados → 0 errores tras correcciones mínimas
  (se corrigieron anotaciones de tipo, guards de None, y migración a async_sessionmaker)
- Trivy (dependencias): la propia imagen de Sentinel se escanea en cada CI run

SENTINEL ES SEGURO — EVIDENCIA EN CÓDIGO:
1. secrets.compare_digest() para comparación de tokens (evita timing attacks — OWASP A07)
2. Pydantic v2 con Field(ge=0), Field(gt=0) — toda entrada validada antes de procesarse (OWASP A03)
3. Dockerfile: USER gateuser (UID 1000) — proceso non-root (OWASP Docker D01)
4. Multi-stage build — imagen de producción sin pip ni compiladores (OWASP Docker D09)
5. generic_exception_handler devuelve "Internal server error" — sin stack traces al cliente (OWASP A05)
6. Fail-safe: si Mistral devuelve respuesta inválida → WARNING, nunca APPROVED (OWASP A04)
7. Reglas determinísticas se ejecutan ANTES del LLM — LLM comprometido no puede aprobar critical > 0
8. Rate limiting (slowapi): 100 req/min por IP + bloqueo tras 5 fallos de auth en 5 min
9. Security headers en todas las respuestas: X-Content-Type-Options, X-Frame-Options,
   Strict-Transport-Security, Content-Security-Policy
10. CORS configurado explícitamente (no wildcard)

OWASP CI/CD SECURITY RISKS CUBIERTOS:
- CICD-SEC-1: Gate bloquea pipeline con exit 1 en REJECTED — deploy no ocurre
- CICD-SEC-3: Trivy detecta CVEs en dependencias antes del despliegue
- CICD-SEC-4: critical > 0 → REJECTED siempre, sin excepción
- CICD-SEC-7: Non-root, multi-stage, healthcheck, security headers
- CICD-SEC-8: Ollama local — ningún dato sale de la infraestructura

ALTA DISPONIBILIDAD Y RESILIENCIA EN EL PIPELINE:
- Doble ejecución por diseño: trigger push + pull_request → 2 runners independientes
  Si uno falla por problema transitorio, el otro corre en runner diferente
- if: always() en steps críticos: reporte y artifact se generan incluso si gate da REJECTED
- Dependencia secuencial estructural: deploy solo ocurre si test AND security-gate pasan
- Artifact de auditoría: security_report.md + trivy_report.json retenidos 30 días por run
- Comentario sticky en PR: tabla de CVEs publicada siempre, incluso en REJECTED

REQUISITOS DE INTEGRACIÓN:
- Python 3.11+ / Docker 24.x+ / Trivy 0.50+
- Ollama (opcional, solo si se usa análisis AI — AI_DISABLED=true para modo solo reglas)
- Variables de entorno: GATE_AUTH_TOKEN, AI_DISABLED, OLLAMA_URL
- Integración en 3 pasos: checkout Sentinel → trivy scan → python trivy_to_gate.py

ARQUITECTURA (v2.0 — hexagonal):
app/
  domain/         → entities, rules, ports (interfaces)
  application/    → gate_service (orquestación)
  infrastructure/ → ai/ (Ollama, OpenAI, Anthropic), persistence/ (SQL), security/ (secrets_detector)
  web/            → FastAPI endpoints, dashboard, rate limiting, auth

────────────────────────────────────────────────────────────────────────────────
INSTRUCCIONES PARA LA PRESENTACIÓN
────────────────────────────────────────────────────────────────────────────────

FORMATO: 10 diapositivas máximo. 10 minutos de exposición.
TONO: Pitch de venta técnico ante jurado de ciberseguridad. Conciso, impactante,
      con evidencia real. Estilo "esto ya funciona y está en producción".
AUDIENCIA: Docentes/evaluadores de ciberseguridad. Conocen OWASP, DevSecOps,
           pipelines CI/CD. No necesitan explicaciones básicas — necesitan evidencia.

ESTRUCTURA OBLIGATORIA (en este orden):

DIAPOSITIVA 1 — PORTADA
- Nombre: SENTINEL AI-CD
- Subtítulo: "Puerta de seguridad inteligente para pipelines CI/CD"
- Tema: "Aplicación de IA para detección temprana de vulnerabilidades en pipelines CI/CD"
- Nombres del equipo
- [IMAGEN: logo del proyecto o ícono de escudo/candado sobre fondo oscuro tipo terminal]

DIAPOSITIVA 2 — EL PROBLEMA (datos reales, impacto)
- Dato 1: El 83% de las organizaciones sufrieron al menos una brecha de seguridad
  relacionada con vulnerabilidades en contenedores en 2023 (fuente: Sysdig)
- Dato 2: El tiempo promedio para detectar una vulnerabilidad en producción es 197 días
- Dato 3: El 60% de los equipos de desarrollo no tienen un gate de seguridad automatizado
  en su pipeline CI/CD
- Mensaje central: "El código llega a producción con vulnerabilidades conocidas
  porque nadie lo detiene automáticamente"
- [IMAGEN: captura de pantalla de un pipeline de GitHub Actions fallando / alerta de CVE crítico]

DIAPOSITIVA 3 — LA SOLUCIÓN: SENTINEL AI-CD
- Una línea: "Sentinel es la puerta que ninguna imagen vulnerada puede cruzar"
- Diagrama del flujo: git push → build → trivy scan → POST /analyze-image → APPROVED/WARNING/REJECTED → deploy o bloqueo
- Tres modos de decisión: Motor de reglas (determinístico) / AI Mistral (contextual) / Fail-safe
- [IMAGEN: diagrama de flujo del pipeline con Sentinel como checkpoint — puede ser el ASCII del README convertido a visual]

DIAPOSITIVA 4 — INNOVACIÓN TÉCNICA
Cuatro diferenciadores en formato de tarjetas:
1. 🧠 IA LOCAL: Mistral 7B via Ollama — sin APIs externas, sin costos, sin fuga de datos
2. 🔒 DUAL ENGINE: Reglas OWASP determinísticas + AI contextual. El LLM nunca puede
   aprobar lo que las reglas rechazan
3. 🔌 AGNÓSTICO DE CI: GitHub Actions, GitLab CI, Jenkins, Bitbucket — mismo script
4. 📊 DASHBOARD INTEGRADO: historial, tendencias, whitelist de CVEs — sin frontend adicional
- [IMAGEN: captura del dashboard web de Sentinel mostrando gráfico de tendencias y tabla de CVEs]

DIAPOSITIVA 5 — SENTINEL ES SEGURO (OWASP sobre el propio proyecto)
Título: "Aplicamos a nosotros mismos lo que exigimos a los demás"
Tabla de 5 controles con evidencia en código:
| Control | Archivo | OWASP |
|---------|---------|-------|
| secrets.compare_digest() — timing-safe auth | app/web/main.py | A07 |
| Pydantic v2 Field(ge=0) — validación estricta | app/domain/entities.py | A03 |
| USER gateuser UID 1000 — non-root | app/Dockerfile | Docker D01 |
| generic_exception_handler — sin stack traces | app/web/main.py | A05 |
| Fail-safe: LLM inválido → WARNING | app/infrastructure/ai/parser.py | A04 |
Mensaje: "No es teoría — es código auditado y verificado"
- [IMAGEN: fragmento de código real de main.py mostrando secrets.compare_digest o el Dockerfile con USER gateuser]

DIAPOSITIVA 6 — ANÁLISIS ESTÁTICO (SAST) — RESULTADOS REALES
Título: "El proyecto se auto-evaluó y fue autor de su propia mejora continua"
Tres herramientas, tres resultados:
- ✅ Ruff (calidad/estilo): 2362 líneas → All checks passed
- ✅ Bandit (seguridad Python): 0 High · 0 Medium · 0 Low (tras correcciones aplicadas)
- ✅ Mypy (tipado estático): 27 archivos → 0 errores (tras correcciones mínimas)
- ✅ Trivy (dependencias): imagen de Sentinel escaneada en cada CI run
Mensaje clave: "Sentinel no solo detecta vulnerabilidades en otros proyectos —
detectó y corrigió las suyas propias durante su desarrollo"
- [IMAGEN: captura del output real de Bandit o Mypy mostrando "No issues identified" / "All checks passed"]

DIAPOSITIVA 7 — CÓMO SE INTEGRA (3 pasos)
Título: "Integración en menos de 5 minutos"
Paso 1 — Checkout Sentinel en tu pipeline:
  uses: actions/checkout@v4
  with: { repository: DannielEU/Sentinel-AI-CD }
Paso 2 — Escanear con Trivy:
  trivy image --format json --output trivy_report.json $IMAGE
Paso 3 — Enviar al gate:
  python3 Sentinel-AI-CD/pipeline/trivy_to_gate.py --report trivy_report.json --image $IMAGE
Resultado: exit 0 (APPROVED) / exit 1 (REJECTED — pipeline falla) / exit 2 (WARNING)
Requisitos: Python 3.11+ · Docker 24.x+ · Trivy 0.50+ · 3 variables de entorno
- [IMAGEN: captura del output real de trivy_to_gate.py en terminal mostrando "GATE DECISION: APPROVED" o "REJECTED"]

DIAPOSITIVA 8 — ALTA DISPONIBILIDAD Y RESILIENCIA
Título: "Diseñado para no fallar silenciosamente"
Cuatro mecanismos:
1. Doble ejecución: trigger push + pull_request → 2 runners independientes en paralelo
2. if: always() — reporte y artifact se generan incluso cuando el gate rechaza
3. Dependencia estructural: deploy solo si test AND security-gate pasan (no hay bypass)
4. Artifact de auditoría: security_report.md + trivy_report.json retenidos 30 días
Mensaje: "Ninguna decisión de seguridad se pierde — hay trazabilidad completa"
- [IMAGEN: diagrama del workflow de GitHub Actions mostrando los 3 jobs (test → security-gate → deploy) con flechas de dependencia]

DIAPOSITIVA 9 — ARQUITECTURA Y PORTABILIDAD
Título: "Arquitectura hexagonal — limpia, extensible, portable"
Diagrama de capas:
  Web (FastAPI) → Application (GateService) → Domain (Rules + Entities)
                                            ↓
                              Infrastructure: AI (Ollama/OpenAI/Anthropic) |
                                             Persistence (SQLite/PostgreSQL) |
                                             Security (SecretsDetector)
Portabilidad:
- Modo 1: Docker Compose (Sentinel + Ollama) — local/servidor propio
- Modo 2: AI_DISABLED=true — solo motor de reglas, sin GPU, sin Ollama
- Modo 3: SaaS centralizado — un Sentinel para múltiples proyectos con tokens por cliente
- Modo 4: Cloud (Render/Railway/Fly.io) — comando de inicio: uvicorn web.main:app
- [IMAGEN: diagrama de arquitectura hexagonal o el docker-compose.yml con los dos servicios]

DIAPOSITIVA 10 — CIERRE Y LLAMADA A LA ACCIÓN
Título grande: "¿Cuántas imágenes vulneradas llegaron a tu producción esta semana?"
Tres propuestas de valor finales:
✅ Automatiza la seguridad — sin cambiar tu pipeline actual
✅ Gana eficiencia sin perder control — decisiones en < 100ms (motor de reglas)
✅ IA local, datos seguros — Mistral corre en tu infraestructura
CTA: "Sentinel está disponible hoy en github.com/DannielEU/Sentinel-AI-CD"
Frase de cierre: "No es un escáner más. Es la puerta que decide si tu código
merece llegar a producción."
- [IMAGEN: QR code al repositorio de GitHub + captura del README o del dashboard]

────────────────────────────────────────────────────────────────────────────────
INSTRUCCIONES DE DISEÑO VISUAL
────────────────────────────────────────────────────────────────────────────────

PALETA DE COLORES:
- Fondo: #0f172a (azul muy oscuro, tipo terminal)
- Acento principal: #38bdf8 (azul cielo — color del dashboard de Sentinel)
- APPROVED: #22c55e (verde)
- WARNING: #f59e0b (ámbar)
- REJECTED: #ef4444 (rojo)
- Texto: #e2e8f0 (blanco suave)
- Texto secundario: #64748b (gris)

TIPOGRAFÍA: System UI / Inter / Roboto Mono para código
ESTILO: Dark mode, minimalista, con íconos de seguridad (🛡️ 🔒 ⚠️ ✅ ❌)
MÁXIMO de texto por diapositiva: 5 bullets o 1 tabla pequeña + 1 imagen
NO usar fondos blancos. NO usar más de 3 colores por diapositiva.

────────────────────────────────────────────────────────────────────────────────
GENERA: El contenido completo de cada diapositiva con:
- Título exacto
- Bullets/texto (máximo 5 por slide)
- Nota del presentador (1-2 frases de lo que se dice en voz alta)
- Indicación de imagen/visual recomendado
────────────────────────────────────────────────────────────────────────────────
```

---

## IMÁGENES QUE DEBES CAPTURAR / PREPARAR

Estas son las capturas y recursos visuales que necesitas tener listos antes de armar el PPT:

### 📸 Capturas de pantalla del proyecto (tomar del repo/terminal)

| # | Qué capturar | Dónde encontrarlo | Para qué slide |
|---|---|---|---|
| 1 | Output de `trivy_to_gate.py` en terminal con decisión `APPROVED` o `REJECTED` | Correr `python pipeline/trivy_to_gate.py --report sample_payloads.json ...` | Slide 7 |
| 2 | Output de Bandit: `No issues identified` / métricas finales | `python -m bandit -r app/ -ll -ii` | Slide 6 |
| 3 | Output de Mypy: `Success: no issues found` | `python -m mypy app/ --ignore-missing-imports` | Slide 6 |
| 4 | Output de Ruff: `All checks passed!` | `python -m ruff check app/` | Slide 6 |
| 5 | Dashboard web de Sentinel (gráfico de tendencias + tabla de CVEs) | Levantar con `docker compose up` → `http://localhost:8000/dashboard` | Slide 4 |
| 6 | Fragmento de código: `secrets.compare_digest` en `app/web/main.py` línea ~190 | Abrir el archivo en VS Code con tema oscuro | Slide 5 |
| 7 | Fragmento de código: `USER gateuser` en `app/Dockerfile` | Abrir el Dockerfile | Slide 5 |
| 8 | GitHub Actions workflow corriendo (jobs: test → security-gate → deploy) | Ir a la pestaña Actions del repo en GitHub | Slide 8 |
| 9 | Comentario sticky en PR con tabla de CVEs generado por Sentinel | Abrir una PR en el repo con el workflow activo | Slide 3 o 8 |
| 10 | README del repo (sección del flujo o motor de reglas) | `github.com/DannielEU/Sentinel-AI-CD` | Slide 10 |

### 🎨 Recursos visuales a crear/descargar

| # | Recurso | Cómo obtenerlo |
|---|---|---|
| A | QR code al repositorio GitHub | Generar en `qr-code-generator.com` con URL `https://github.com/DannielEU/Sentinel-AI-CD` |
| B | Diagrama de flujo del pipeline (git push → Sentinel → deploy) | Crear en draw.io / Excalidraw con los colores del proyecto |
| C | Diagrama de arquitectura hexagonal (domain/application/infrastructure/web) | Crear en draw.io con las 4 capas |
| D | Diagrama de jobs de GitHub Actions (test → security-gate → deploy con flechas) | Captura del YAML o diagrama en Excalidraw |
| E | Ícono/logo de Sentinel | Usar un escudo (🛡️) sobre fondo #0f172a o buscar en Flaticon "shield security" |

### 💡 Tip para las capturas de código
Usa VS Code con tema **One Dark Pro** o **GitHub Dark** y la extensión **Polacode** o **CodeSnap** para generar capturas de código con bordes redondeados y fondo oscuro — se ven profesionales en presentaciones.

---

*Sentinel AI-CD · Prompt de presentación · Abril 2026*
