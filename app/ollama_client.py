"""
Ollama client — builds a structured prompt from an ImageReport and calls the
local Ollama API to obtain an AI-powered gate decision.
"""

import json
import os
import re
import httpx

from schemas import ImageReport, GateDecision


OLLAMA_BASE_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = "mistral"
REQUEST_TIMEOUT = 120  # seconds — Mistral can be slow on first token


def _build_prompt(report: ImageReport) -> str:
    vulns = report.vulnerabilities
    extra_sections: list[str] = []

    if report.base_image:
        extra_sections.append(f"- Base image     : {report.base_image}")
    if report.os_family:
        extra_sections.append(f"- OS family      : {report.os_family}")
    if report.dockerfile_content:
        extra_sections.append(
            f"\n### Dockerfile\n```\n{report.dockerfile_content[:3000]}\n```"
        )
    if report.scanner_output:
        extra_sections.append(
            f"\n### Scanner output (truncated)\n```\n{report.scanner_output[:3000]}\n```"
        )

    extra = "\n".join(extra_sections)

    return f"""You are a senior DevSecOps engineer responsible for approving or rejecting container image deployments in a CI/CD pipeline.

Analyse the following security report for a container image and provide a structured deployment decision.

## Image report

- Image name     : {report.image_name}
- Image size     : {report.image_size_mb:.1f} MB
- Critical vulns : {vulns.critical}
- High vulns     : {vulns.high}
- Medium vulns   : {vulns.medium}
- Low vulns      : {vulns.low}
- Unknown vulns  : {vulns.unknown}
{extra}

## Instructions

Based on the information above, respond ONLY with a valid JSON object (no markdown, no code fences) with exactly these three keys:

  "decision"        — one of: APPROVED, WARNING, REJECTED
  "reason"          — a single sentence explaining the decision
  "recommendations" — a JSON array of short, actionable strings (max 5 items)

Example format:
{{"decision": "WARNING", "reason": "...", "recommendations": ["...", "..."]}}
"""


def _parse_response(raw: str) -> dict:
    """Extract the JSON object from Ollama's raw text response.

    The model sometimes wraps the JSON in markdown code fences or adds extra
    prose — this function strips those artefacts before parsing.
    """
    # Strip markdown code fences if present
    clean = re.sub(r"```(?:json)?\s*", "", raw).strip()

    # Try to find the first {...} block
    match = re.search(r"\{.*\}", clean, re.DOTALL)
    if match:
        clean = match.group(0)

    try:
        data = json.loads(clean)
    except json.JSONDecodeError:
        # Fallback: return a WARNING with the raw model output as reason
        return {
            "decision": "WARNING",
            "reason": "AI model returned an unparseable response. Manual review required.",
            "recommendations": [
                "Review the raw scanner output manually.",
                f"Raw model output: {raw[:400]}",
            ],
        }

    # Normalise decision to uppercase
    data["decision"] = str(data.get("decision", "WARNING")).upper()
    if data["decision"] not in {"APPROVED", "WARNING", "REJECTED"}:
        data["decision"] = "WARNING"

    # Ensure recommendations is a list of strings
    recs = data.get("recommendations", [])
    if not isinstance(recs, list):
        recs = [str(recs)]
    data["recommendations"] = [str(r) for r in recs]

    return data


async def analyze(report: ImageReport) -> GateDecision:
    """Send *report* to Ollama and return a :class:`GateDecision`."""
    prompt = _build_prompt(report)

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,   # low temperature for consistent, factual output
            "num_predict": 512,
        },
    }

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        response = await client.post(f"{OLLAMA_BASE_URL}/api/generate", json=payload)
        response.raise_for_status()

    ollama_data = response.json()
    raw_text: str = ollama_data.get("response", "")

    parsed = _parse_response(raw_text)

    return GateDecision(
        decision=parsed["decision"],
        reason=parsed["reason"],
        recommendations=parsed["recommendations"],
        source="ai_model",
        image_name=report.image_name,
    )
