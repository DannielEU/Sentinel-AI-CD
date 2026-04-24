#!/usr/bin/env bash
# gate_check.sh — CI/CD step: scan image and call the deployment gate
#
# Usage:
#   export IMAGE_NAME=myapp:1.2.3
#   export GATE_URL=http://localhost:8000   # optional, default shown
#   ./gate_check.sh
#
# The script:
#   1. Runs Trivy to produce a JSON vulnerability report
#   2. Calls trivy_to_gate.py to send the report to the gate API
#   3. Exits 0 (APPROVED), 1 (REJECTED), or 2 (WARNING)
#
# In your pipeline:
#   - exit 1 → pipeline fails → deployment blocked
#   - exit 2 → pipeline continues but logs a warning (handle as needed)
#   - exit 0 → proceed to docker push / deploy

set -euo pipefail

IMAGE_NAME="${IMAGE_NAME:?'IMAGE_NAME env var is required'}"
GATE_URL="${GATE_URL:-http://localhost:8000}"
DOCKERFILE="${DOCKERFILE:-./Dockerfile}"
REPORT_FILE="trivy_report.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AI DevSecOps Deployment Gate"
echo "  Image : $IMAGE_NAME"
echo "  Gate  : $GATE_URL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── 1. Scan with Trivy ───────────────────────────────────────────────────────
echo "[1/2] Scanning image with Trivy..."

if ! command -v trivy &>/dev/null; then
  echo "ERROR: trivy is not installed. Install it from https://github.com/aquasecurity/trivy"
  exit 3
fi

trivy image \
--format json \
--output "$REPORT_FILE" \
--exit-code 0 \
"$IMAGE_NAME"

echo "      Report saved to $REPORT_FILE"

# ── 2. Call the gate ─────────────────────────────────────────────────────────
echo "[2/2] Sending report to deployment gate..."

args=(
  --report "$REPORT_FILE"
  --image "$IMAGE_NAME"
  --gate "$GATE_URL"
)

if [[ -f "$DOCKERFILE" ]]; then
  args+=(--dockerfile "$DOCKERFILE")
fi

set +e
python3 "$SCRIPT_DIR/trivy_to_gate.py" "${args[@]}"
EXIT_CODE=$?
set -e

# ── 3. Interpret result ──────────────────────────────────────────────────────
case $EXIT_CODE in
  0) echo "GATE: APPROVED — proceeding with deployment." ;;
  1) echo "GATE: REJECTED — deployment blocked."; exit 1 ;;
  2) echo "GATE: WARNING  — proceeding with caution."; exit 0;;
  3) echo "GATE: ERROR    — could not reach gate service."; exit 3  ;;
  *) echo "GATE: UNKNOWN RESULT - failing safely." exit 3 ;;
 esac
