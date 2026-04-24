"""
AI DevSecOps Deployment Gate
============================
FastAPI service that acts as an intelligent CI/CD gate for container images.

Flow
----
1. Receive a security report (POST /analyze-image).
2. Run the deterministic rule engine.
   - If a rule fires  → return the decision immediately (no LLM call).
3. If no rule fires   → forward the report to the local Ollama/Mistral model.
4. Return a structured GateDecision JSON to the pipeline.

Run
---
    uvicorn main:app --reload --port 8000
"""

import logging
import os
import secrets

import httpx
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

import rule_engine
import ollama_client
from schemas import GateDecision, ImageReport

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

AI_DISABLED = os.getenv("AI_DISABLED", "false").lower() in {"1", "true", "yes", "on"}
GATE_AUTH_TOKEN = os.getenv("GATE_AUTH_TOKEN")

app = FastAPI(
    title="AI DevSecOps Deployment Gate",
    description=(
        "Intelligent CI/CD gate that analyses container-image security reports "
        "using deterministic rules and a local Mistral LLM (via Ollama) to decide "
        "whether a deployment should be APPROVED, trigger a WARNING, or be REJECTED."
    ),
    version="1.1.0",
)


def _require_token(authorization: str | None) -> None:
    if not GATE_AUTH_TOKEN:
        return

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    provided_token = authorization.removeprefix("Bearer ").strip()
    if not secrets.compare_digest(provided_token, GATE_AUTH_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid bearer token")


@app.get("/", tags=["health"])
def root():
    return {"status": "ok", "service": "AI DevSecOps Deployment Gate", "ai_disabled": AI_DISABLED}


@app.get("/health", tags=["health"])
def health():
    return {"status": "ok", "ai_disabled": AI_DISABLED}


@app.post(
    "/analyze-image",
    response_model=GateDecision,
    tags=["gate"],
    summary="Analyse a container image security report and return a deployment decision",
)
async def analyze_image(
    report: ImageReport,
    authorization: str | None = Header(default=None),
):
    """
    Receive a container-image security report from the CI/CD pipeline and
    return a gate decision.

    ### Decision values
    | Value      | Pipeline behaviour            |
    |------------|-------------------------------|
    | `APPROVED` | Continue deployment normally  |
    | `WARNING`  | Continue but log alert        |
    | `REJECTED` | Abort deployment with error   |

    ### Example request body
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
      "os_family": "debian"
    }
    ```
    """
    _require_token(authorization)
    logger.info("Received report for image: %s", report.image_name)

    # ── 1. Deterministic rule engine ────────────────────────────────────────
    rule_result = rule_engine.evaluate(report)

    if rule_result is not None:
        logger.info(
            "Rule engine decision for %s: %s", report.image_name, rule_result.decision
        )
        return GateDecision(
            decision=rule_result.decision,
            reason=rule_result.reason,
            recommendations=rule_result.recommendations,
            source="rule_engine",
            image_name=report.image_name,
        )

    # ── 2. AI model analysis (Ollama / Mistral) ──────────────────────────────
    if AI_DISABLED:
        logger.info(
            "AI disabled; approving %s after deterministic checks.",
            report.image_name,
        )
        return GateDecision(
            decision="APPROVED",
            reason="No deterministic rule fired and AI fallback is disabled for this environment.",
            recommendations=[
                "Keep scheduled image scanning enabled in CI.",
                "Review warning thresholds periodically as the image evolves.",
            ],
            source="rule_engine",
            image_name=report.image_name,
        )

    logger.info("No rule fired for %s - forwarding to AI model.", report.image_name)
    try:
        decision = await ollama_client.analyze(report)
        logger.info(
            "AI model decision for %s: %s", report.image_name, decision.decision
        )
        return decision

    except httpx.ConnectError:
        logger.error("Cannot reach Ollama at %s", ollama_client.OLLAMA_BASE_URL)
        raise HTTPException(
            status_code=503,
            detail=(
                f"Ollama service is not reachable at {ollama_client.OLLAMA_BASE_URL}. "
                "Make sure `ollama serve` is running and the model is pulled "
                f"(`ollama pull {ollama_client.OLLAMA_MODEL}`)."
            ),
        )
    except httpx.HTTPStatusError as exc:
        logger.error("Ollama returned HTTP %s", exc.response.status_code)
        raise HTTPException(
            status_code=502,
            detail=f"Ollama returned an error: {exc.response.text[:300]}",
        )
    except Exception as exc:
        logger.exception("Unexpected error during AI analysis")
        raise HTTPException(status_code=500, detail=str(exc))


# ── Global exception handler ────────────────────────────────────────────────
@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    logger.exception("Unhandled exception")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
