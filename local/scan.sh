#!/usr/bin/env bash
# scan.sh — Escanea una imagen Docker con Trivy y la envía a Sentinel Gate
#
# Uso:
#   ./scan.sh <imagen>                         # solo imagen
#   ./scan.sh <imagen> <ruta/al/Dockerfile>    # imagen + Dockerfile (detección de secretos)
#
# Variables de entorno:
#   GATE_URL    URL del gate Sentinel  (default: http://localhost:8000)
#   GATE_TOKEN  Bearer token del gate  (default: vacío)
#
# Ejemplos:
#   ./scan.sh nginx:latest
#   ./scan.sh mi-app:1.0.0 ../Dockerfile
#   GATE_URL=http://localhost:8000 GATE_TOKEN=mytoken ./scan.sh nginx:latest

set -euo pipefail

IMAGE="${1:?ERROR: debes indicar la imagen. Uso: ./scan.sh <imagen> [dockerfile]}"
DOCKERFILE="${2:-}"
GATE_URL="${GATE_URL:-http://localhost:8000}"
REPORT_FILE="trivy_report_$(date +%s).json"

# ── Colores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Sentinel AI-CD — Escaneo Local${RESET}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
echo -e "  Imagen : ${YELLOW}${IMAGE}${RESET}"
echo -e "  Gate   : ${GATE_URL}"
[ -n "$DOCKERFILE" ] && echo -e "  Dockerfile : ${DOCKERFILE}"
echo ""

# ── 1. Verificar que el gate esté activo ──────────────────────────────────────
echo -e "${BOLD}[1/3] Verificando gate Sentinel...${RESET}"
if ! curl -sf "${GATE_URL}/health" > /dev/null 2>&1; then
    echo -e "${RED}ERROR: No se puede conectar al gate en ${GATE_URL}${RESET}"
    echo -e "       Asegúrate de haber ejecutado: ${BOLD}docker compose up -d${RESET}"
    exit 3
fi
echo -e "  ${GREEN}Gate activo${RESET}"

# ── 2. Escanear con Trivy ─────────────────────────────────────────────────────
echo -e "\n${BOLD}[2/3] Escaneando con Trivy...${RESET}"
echo -e "  Imagen: ${IMAGE}"

docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$(pwd):/output" \
    aquasec/trivy:latest image \
    --format json \
    --output "/output/${REPORT_FILE}" \
    --timeout 10m \
    "${IMAGE}"

echo -e "  ${GREEN}Reporte generado: ${REPORT_FILE}${RESET}"

# ── 3. Enviar a Sentinel Gate ─────────────────────────────────────────────────
echo -e "\n${BOLD}[3/3] Enviando al gate Sentinel...${RESET}"

ARGS=(
    "--report" "${REPORT_FILE}"
    "--image"  "${IMAGE}"
    "--gate"   "${GATE_URL}"
)

[ -n "$DOCKERFILE" ]  && ARGS+=("--dockerfile" "$DOCKERFILE")
[ -n "${GATE_TOKEN:-}" ] && ARGS+=("--token" "${GATE_TOKEN}")

python3 ../pipeline/trivy_to_gate.py "${ARGS[@]}"
EXIT_CODE=$?

# ── Limpieza ──────────────────────────────────────────────────────────────────
rm -f "${REPORT_FILE}"

case $EXIT_CODE in
    0) echo -e "\n${GREEN}${BOLD}RESULTADO: APPROVED ✅${RESET}" ;;
    1) echo -e "\n${RED}${BOLD}RESULTADO: REJECTED ❌${RESET}" ;;
    2) echo -e "\n${YELLOW}${BOLD}RESULTADO: WARNING ⚠️${RESET}" ;;
    *) echo -e "\n${RED}RESULTADO: ERROR (código $EXIT_CODE)${RESET}" ;;
esac

exit $EXIT_CODE
