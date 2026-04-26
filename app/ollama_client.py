"""
Ollama client — builds a structured prompt from an ImageReport and calls the
local Ollama API to obtain an AI-powered gate decision.
"""

import json
import logging
import os
import re
import httpx

from schemas import ImageReport, GateDecision

logger = logging.getLogger(__name__)


OLLAMA_BASE_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "neural-chat")
REQUEST_TIMEOUT = 120  # seconds — neural-chat optimized for Docker/security analysis


def _build_prompt(report: ImageReport) -> str:
    vulns = report.vulnerabilities
    extra_sections: list[str] = []

    if report.base_image:
        extra_sections.append(f"- Base image     : {report.base_image}")
    if report.os_family:
        extra_sections.append(f"- OS family      : {report.os_family}")

    # Add HIGH vulnerability details if available
    if report.high_vulnerabilities_details:
        high_vulns_text = "\n## Critical HIGH Vulnerabilities\n"
        for i, vuln in enumerate(report.high_vulnerabilities_details, 1):
            high_vulns_text += f"\n**{i}. {vuln.id} - {vuln.package}**\n"
            high_vulns_text += f"   Title: {vuln.title}\n"
            if vuln.description:
                high_vulns_text += f"   {vuln.description[:200]}\n"
        extra_sections.append(high_vulns_text)

    if report.dockerfile_content:
        extra_sections.append(
            f"\n### Dockerfile\n```\n{report.dockerfile_content[:3000]}\n```"
        )
    if report.scanner_output:
        extra_sections.append(
            f"\n### Scanner output (truncated)\n```\n{report.scanner_output[:3000]}\n```"
        )

    extra = "\n".join(extra_sections)

    return f"""You are a senior DevSecOps and Container Security Engineer with expertise in:
- Docker/Container security best practices
- CVE analysis and severity assessment
- CI/CD pipeline security gates
- Kubernetes and container orchestration security
- Supply chain security and container image provenance

Your role is to approve or reject container image deployments in a CI/CD pipeline based on security analysis.

## Analysis Guidelines

**CRITICAL (0 found → APPROVED, >0 → REJECTED):**
- Critical vulnerabilities require immediate remediation
- If found, reject the deployment regardless of other factors
- Recommend immediate patching or base image update

**HIGH Severity (1-10 → WARNING, >10 → REJECTED):**
- Between 1-10: Allow with warnings, schedule remediation
- Over 10: Reject the deployment, too many unpatched vulnerabilities
- Consider base image and package versions

**MEDIUM Severity (≤30 → APPROVED, >30 → WARNING):**
- Acceptable in most cases if below threshold
- Monitor and plan remediation for next sprint
- Review if exploitability is high for critical systems

**Image Size Considerations:**
- Under 500MB: Excellent
- 500-1000MB: Good
- 1000-1200MB: Acceptable but review for optimization
- Over 1200MB: Consider multi-stage builds, minimal base images

**Base Image Quality:**
- Prefer: alpine, distroless, ubuntu:latest, debian:bookworm-slim
- Review: centos, ubuntu:old-lts (outdated), custom/unverified images
- Flag: deprecated, unsupported, or unknown base images

**Dockerfile Quality Concerns:**
- Running as root → Security risk
- Missing healthchecks → Operational risk
- Large image sizes → Review for unnecessary dependencies

## Image Report

- Image name     : {report.image_name}
- Image size     : {report.image_size_mb:.1f} MB
- Critical vulns : {vulns.critical} {"❌ REJECT" if vulns.critical > 0 else "✅ PASS"}
- High vulns     : {vulns.high} {"❌ REJECT" if vulns.high > 10 else "⚠️ WARNING" if vulns.high > 0 else "✅ PASS"}
- Medium vulns   : {vulns.medium} {"⚠️ WARNING" if vulns.medium > 30 else "✅ PASS"}
- Low vulns      : {vulns.low}
- Unknown vulns  : {vulns.unknown}
{extra}

## Decision Rules (Summary)

1. If Critical > 0 → **REJECTED** (no exceptions)
2. If High > 10 → **REJECTED** (too many high-severity issues)
3. If High 1-10 → **WARNING** (acceptable but monitor)
4. If Medium > 30 → **WARNING** (schedule remediation)
5. If Image Size > 1200MB → **WARNING** (optimization recommended)
6. Otherwise → **APPROVED**

## Response Format

Respond ONLY with valid JSON (no markdown code fences, no extra text):

{{"decision": "APPROVED|WARNING|REJECTED", "reason": "Single sentence explaining decision", "recommendations": ["action1", "action2", "action3"]}}

## Examples

REJECTED case: {{"decision": "REJECTED", "reason": "Contains 3 critical vulnerabilities in base libraries; deployment blocked.", "recommendations": ["Update base image to latest security patch", "Run vulnerability scanner and review fixed versions", "Consider using distroless image for reduced surface area"]}}

WARNING case: {{"decision": "WARNING", "reason": "5 high-severity vulnerabilities detected; acceptable to deploy but remediation required.", "recommendations": ["Schedule security patch for next sprint", "Update python and pip packages", "Review and update dependencies"]}}

APPROVED case: {{"decision": "APPROVED", "reason": "Image passes security thresholds with minimal vulnerabilities and good practices.", "recommendations": ["Continue monitoring for new vulnerabilities", "Enable automatic dependency updates"]}}
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


async def generate_summary(report: ImageReport, decision: str, reason: str) -> str | None:
    """Call Ollama to generate a contextual summary for a WARNING decision from rule engine.

    Returns the AI-generated summary text, or None if Ollama fails or is unavailable.
    Non-blocking: failures do not raise exceptions and are logged as warnings.

    Timeout: 30 seconds (Ollama may need time for inference)
    Retry: None (fail-fast to not block the pipeline)
    """
    prompt = (
        f"You are a DevSecOps assistant reviewing a container security gate decision.\n\n"
        f"Image: {report.image_name}\n"
        f"Decision: {decision}\n"
        f"Reason: {reason}\n"
        f"Vulnerabilities: critical={report.vulnerabilities.critical}, "
        f"high={report.vulnerabilities.high}, medium={report.vulnerabilities.medium}\n"
        f"Base image: {report.base_image or 'unknown'}\n"
        f"Image size: {report.image_size_mb:.1f} MB\n\n"
        f"Write a 2-3 sentence professional summary for the development team explaining "
        f"the security implications and recommended next steps. Be specific, concise, and actionable. "
        f"Respond with plain text only—no JSON, no markdown, no extra formatting."
    )

    try:
        payload = {
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.3,
                "num_predict": 150,
            },
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json=payload,
            )
            response.raise_for_status()

        ollama_data = response.json()
        text = ollama_data.get("response", "").strip()
        if text:
            logger.info(
                "✅ OLLAMA SUCCESS: Generated summary for %s (%d chars)",
                report.image_name,
                len(text),
            )
            return text
        else:
            logger.warning(
                "⚠️  OLLAMA EMPTY: Returned empty response for summary of %s",
                report.image_name,
            )
            return None

    except httpx.TimeoutException:
        logger.error(
            "❌ OLLAMA TIMEOUT: Exceeded 30s while generating summary for %s — Ollama may be busy, unresponsive, or not running",
            report.image_name,
        )
        return None

    except httpx.ConnectError:
        logger.error(
            "❌ OLLAMA UNREACHABLE: Cannot reach Ollama at %s while generating summary for %s — service is down or not accessible",
            OLLAMA_BASE_URL,
            report.image_name,
        )
        return None

    except httpx.HTTPStatusError as exc:
        logger.error(
            "❌ OLLAMA HTTP ERROR: Status %s while generating summary for %s — %s",
            exc.response.status_code,
            report.image_name,
            exc.response.text[:200],
        )
        return None

    except Exception as exc:
        logger.error(
            "❌ OLLAMA ERROR: Unexpected error generating summary for %s: %s",
            report.image_name,
            exc,
        )
        return None


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
